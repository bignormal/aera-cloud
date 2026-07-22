package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	operationReservePlatformDefinition  = "reserve_platform_definition"
	operationCreatePlatformDraft        = "create_platform_draft"
	operationUpdatePlatformDraft        = "update_platform_draft"
	operationSubmitPlatformDraft        = "submit_platform_draft"
	operationWithdrawPlatformSubmission = "withdraw_platform_submission"
	operationReviewPlatformSubmission   = "review_platform_submission"
)

var _ PlatformRepository = (*PostgresRepository)(nil)

func (r *PostgresRepository) EnsurePlatform(
	ctx context.Context,
	command EnsurePlatformCommand,
) (PlatformPolicySnapshot, error) {
	if r == nil || r.postgres == nil || !validEnsurePlatformCommand(command) {
		return PlatformPolicySnapshot{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	defer rollback(tx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO platforms (id, platform_key, display_name, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', $4, $4)
		ON CONFLICT (id) DO NOTHING
	`, command.PlatformID, command.PlatformKey, command.PlatformDisplayName, command.EnsuredAt.UTC()); err != nil {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	var platformKey, displayName, status string
	if err := tx.QueryRow(ctx, `
		SELECT platform_key, display_name, status FROM platforms WHERE id = $1 FOR UPDATE
	`, command.PlatformID).Scan(&platformKey, &displayName, &status); err != nil {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	if platformKey != command.PlatformKey || displayName != command.PlatformDisplayName || status != "active" {
		return PlatformPolicySnapshot{}, ErrInvalidRepositoryCommand
	}

	current, found, err := loadLatestPlatformPolicy(ctx, tx, command.PlatformID)
	if err != nil {
		return PlatformPolicySnapshot{}, err
	}
	version := int64(1)
	if found {
		version = current.Version
	}
	desired, err := command.BuildPolicy(version)
	if err != nil {
		return PlatformPolicySnapshot{}, err
	}
	if !validPlatformPolicyMaterial(desired, version) {
		return PlatformPolicySnapshot{}, ErrInvalidRepositoryCommand
	}
	if found && desired.PolicyDigest == current.PolicyDigest {
		return commitPlatformPolicy(ctx, tx, current)
	}
	if found {
		version++
		desired, err = command.BuildPolicy(version)
		if err != nil {
			return PlatformPolicySnapshot{}, err
		}
		if !validPlatformPolicyMaterial(desired, version) {
			return PlatformPolicySnapshot{}, ErrInvalidRepositoryCommand
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform_agent_policy_snapshots (
			id, platform_id, version, canonical_policy, policy_digest,
			signature_key_id, signature, created_at
		) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
	`, desired.ID, command.PlatformID, desired.Version, string(desired.CanonicalPolicy),
		desired.PolicyDigest[:], desired.SigningKeyID, desired.Signature, command.EnsuredAt.UTC()); err != nil {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	created, err := loadPlatformPolicy(ctx, tx, command.PlatformID, desired.ID)
	if err != nil {
		return PlatformPolicySnapshot{}, err
	}
	return commitPlatformPolicy(ctx, tx, created)
}

func (r *PostgresRepository) ReservePlatformDefinition(
	ctx context.Context,
	command ReservePlatformDefinitionRepositoryCommand,
) (PlatformDefinitionReservation, error) {
	if r == nil || r.postgres == nil || !validReservePlatformDefinitionCommand(command) {
		return PlatformDefinitionReservation{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PlatformDefinitionReservation{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, found, err := lockAndReadPlatformIdempotency(
		ctx, tx, command.PlatformID, operationReservePlatformDefinition, command.Idempotency,
	)
	if err != nil {
		return PlatformDefinitionReservation{}, err
	}
	if found {
		value, err := loadPlatformReservation(ctx, tx, command.PlatformID, response.DefinitionID)
		if err != nil {
			return PlatformDefinitionReservation{}, err
		}
		value.Replayed = true
		return commitPlatformReservation(ctx, tx, value)
	}
	if err := requireActivePlatform(ctx, tx, command.PlatformID, false); err != nil {
		return PlatformDefinitionReservation{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_definitions (
			id, tenant_id, owner_scope, owner_id, workspace_id, organization_id, platform_id,
			display_name, icon_media_type, icon_data, status, latest_version_id,
			created_by, created_by_admin_id, created_at, updated_at
		) VALUES ($1, NULL, 'PLATFORM', NULL, NULL, NULL, $2, $3, NULLIF($4, ''), $5,
		          'active', NULL, NULL, $6, $7, $7)
	`, command.DefinitionID, command.PlatformID, command.DisplayName, command.IconMediaType,
		nilIfEmptyBytes(command.IconData), command.Actor.AdminID, command.CreatedAt.UTC()); err != nil {
		return PlatformDefinitionReservation{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{DefinitionID: command.DefinitionID}
	if err := insertPlatformIdempotency(
		ctx, tx, command.PlatformID, operationReservePlatformDefinition, command.Idempotency,
		"platform_definition", command.DefinitionID, response, command.CreatedAt,
	); err != nil {
		return PlatformDefinitionReservation{}, err
	}
	if err := recordPlatformAudit(
		ctx, tx, command.Actor, command.PlatformID, command.Audit,
		"official_definition_reserved", "platform_definition", command.DefinitionID,
		command.CreatedAt, map[string]string{"display_name_digest": digestHex([]byte(command.DisplayName))},
	); err != nil {
		return PlatformDefinitionReservation{}, err
	}
	value, err := loadPlatformReservation(ctx, tx, command.PlatformID, command.DefinitionID)
	if err != nil {
		return PlatformDefinitionReservation{}, err
	}
	return commitPlatformReservation(ctx, tx, value)
}

func (r *PostgresRepository) CreatePlatformDraft(
	ctx context.Context,
	command CreatePlatformDraftRepositoryCommand,
) (PlatformAgentDraft, error) {
	if r == nil || r.postgres == nil || !validCreatePlatformDraftCommand(command) {
		return PlatformAgentDraft{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, found, err := lockAndReadPlatformIdempotency(
		ctx, tx, command.PlatformID, operationCreatePlatformDraft, command.Idempotency,
	)
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	if found {
		value, err := loadPlatformDraft(ctx, tx, command.PlatformID, response.DraftID, false)
		if err != nil {
			return PlatformAgentDraft{}, err
		}
		value.Replayed = true
		return commitPlatformDraft(ctx, tx, value)
	}
	if err := requireActivePlatform(ctx, tx, command.PlatformID, false); err != nil {
		return PlatformAgentDraft{}, err
	}
	if err := requirePlatformDraftTarget(ctx, tx, command.PlatformID, command.Canonical.Package, false); err != nil {
		return PlatformAgentDraft{}, err
	}
	version, err := CanonicalizeVersion(command.Canonical.Package.Manifest, command.Canonical.Package.Bundle)
	if err != nil {
		return PlatformAgentDraft{}, ErrInvalidRepositoryCommand
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform_agent_drafts (
			id, platform_id, definition_id, base_version_id, kind, display_name,
			icon_media_type, icon_data, canonical_manifest, bundle, manifest_digest,
			bundle_digest, content_digest, revision, status, last_editor_admin_id,
			last_editor_role, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9::jsonb, $10::jsonb,
		          $11, $12, $13, 1, 'active', $14, 'developer', $15, $15)
	`, command.DraftID, command.PlatformID, command.Canonical.Package.DefinitionID,
		nullUUID(command.Canonical.Package.BaseVersionID), command.Canonical.Package.Kind,
		command.Canonical.Package.DisplayName, command.Canonical.Package.IconMediaType,
		nilIfEmptyBytes(command.Canonical.Package.IconData), string(version.ManifestJSON), string(version.BundleJSON),
		command.Canonical.ManifestDigest[:], command.Canonical.BundleDigest[:], command.Canonical.ContentDigest[:],
		command.Actor.AdminID, command.CreatedAt.UTC()); err != nil {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{DefinitionID: command.Canonical.Package.DefinitionID, DraftID: command.DraftID}
	if err := insertPlatformIdempotency(
		ctx, tx, command.PlatformID, operationCreatePlatformDraft, command.Idempotency,
		"platform_draft", command.DraftID, response, command.CreatedAt,
	); err != nil {
		return PlatformAgentDraft{}, err
	}
	if err := recordPlatformAudit(
		ctx, tx, command.Actor, command.PlatformID, command.Audit,
		"official_draft_created", "platform_draft", command.DraftID, command.CreatedAt,
		map[string]string{"content_digest": digestArrayHex(command.Canonical.ContentDigest), "revision": "1"},
	); err != nil {
		return PlatformAgentDraft{}, err
	}
	value, err := loadPlatformDraft(ctx, tx, command.PlatformID, command.DraftID, false)
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	return commitPlatformDraft(ctx, tx, value)
}

func (r *PostgresRepository) UpdatePlatformDraft(
	ctx context.Context,
	command UpdatePlatformDraftRepositoryCommand,
) (PlatformAgentDraft, error) {
	if r == nil || r.postgres == nil || !validUpdatePlatformDraftEnvelope(command) {
		return PlatformAgentDraft{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, found, err := lockAndReadPlatformIdempotency(
		ctx, tx, command.PlatformID, operationUpdatePlatformDraft, command.Idempotency,
	)
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	if found {
		value, err := loadPlatformDraft(ctx, tx, command.PlatformID, response.DraftID, false)
		if err != nil {
			return PlatformAgentDraft{}, err
		}
		value.Replayed = true
		return commitPlatformDraft(ctx, tx, value)
	}
	current, err := loadPlatformDraft(ctx, tx, command.PlatformID, command.DraftID, true)
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	if current.Status != PlatformDraftActive || current.Revision != command.ExpectedRevision {
		return PlatformAgentDraft{}, ErrOfficialSubmissionConflict
	}
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: current.DefinitionID, BaseVersionID: command.BaseVersionID, Kind: command.Kind,
		DisplayName: command.DisplayName, IconMediaType: command.IconMediaType, IconData: command.IconData,
		Manifest: command.Manifest, Bundle: command.Bundle,
	})
	if err != nil || len(ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle))) != 0 {
		return PlatformAgentDraft{}, ErrInvalidRepositoryCommand
	}
	if err := requirePlatformDraftTarget(ctx, tx, command.PlatformID, canonical.Package, true); err != nil {
		return PlatformAgentDraft{}, err
	}
	version, err := CanonicalizeVersion(canonical.Package.Manifest, canonical.Package.Bundle)
	if err != nil {
		return PlatformAgentDraft{}, ErrInvalidRepositoryCommand
	}
	var revision int64
	if err := tx.QueryRow(ctx, `
		UPDATE platform_agent_drafts
		SET base_version_id = $4, kind = $5, display_name = $6, icon_media_type = NULLIF($7, ''),
		    icon_data = $8, canonical_manifest = $9::jsonb, bundle = $10::jsonb,
		    manifest_digest = $11, bundle_digest = $12, content_digest = $13,
		    revision = revision + 1, last_editor_admin_id = $14,
		    last_editor_role = 'developer', updated_at = $15
		WHERE id = $1 AND platform_id = $2 AND revision = $3 AND status = 'active'
		RETURNING revision
	`, command.DraftID, command.PlatformID, command.ExpectedRevision,
		nullUUID(canonical.Package.BaseVersionID), canonical.Package.Kind, canonical.Package.DisplayName,
		canonical.Package.IconMediaType, nilIfEmptyBytes(canonical.Package.IconData), string(version.ManifestJSON),
		string(version.BundleJSON), canonical.ManifestDigest[:], canonical.BundleDigest[:], canonical.ContentDigest[:],
		command.Actor.AdminID, command.UpdatedAt.UTC()).Scan(&revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PlatformAgentDraft{}, ErrOfficialSubmissionConflict
		}
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	if revision != command.ExpectedRevision+1 {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{DefinitionID: current.DefinitionID, DraftID: command.DraftID}
	if err := insertPlatformIdempotency(
		ctx, tx, command.PlatformID, operationUpdatePlatformDraft, command.Idempotency,
		"platform_draft", command.DraftID, response, command.UpdatedAt,
	); err != nil {
		return PlatformAgentDraft{}, err
	}
	if err := recordPlatformAudit(
		ctx, tx, command.Actor, command.PlatformID, command.Audit,
		"official_draft_updated", "platform_draft", command.DraftID, command.UpdatedAt,
		map[string]string{"content_digest": digestArrayHex(canonical.ContentDigest), "revision": strconv.FormatInt(revision, 10)},
	); err != nil {
		return PlatformAgentDraft{}, err
	}
	value, err := loadPlatformDraft(ctx, tx, command.PlatformID, command.DraftID, false)
	if err != nil {
		return PlatformAgentDraft{}, err
	}
	return commitPlatformDraft(ctx, tx, value)
}

func (r *PostgresRepository) SubmitPlatformDraft(
	ctx context.Context,
	command SubmitPlatformDraftRepositoryCommand,
) (PlatformAgentSubmission, error) {
	if r == nil || r.postgres == nil || !validSubmitPlatformDraftCommand(command) {
		return PlatformAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, found, err := lockAndReadPlatformIdempotency(
		ctx, tx, command.PlatformID, operationSubmitPlatformDraft, command.Idempotency,
	)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	if found {
		value, err := loadPlatformSubmission(ctx, tx, command.PlatformID, response.SubmissionID, false)
		if err != nil {
			return PlatformAgentSubmission{}, err
		}
		value.Replayed = true
		return commitPlatformSubmission(ctx, tx, value)
	}
	draft, err := loadPlatformDraft(ctx, tx, command.PlatformID, command.DraftID, true)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	if draft.Status != PlatformDraftActive || draft.Revision != command.ExpectedRevision {
		return PlatformAgentSubmission{}, ErrOfficialSubmissionConflict
	}
	canonical, err := canonicalFromPlatformDraft(draft)
	if err != nil {
		return PlatformAgentSubmission{}, ErrOfficialVersionIntegrityFailed
	}
	if findings := ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle)); len(findings) != 0 {
		return PlatformAgentSubmission{}, &PlatformPublicationDLPError{Findings: cloneExperienceCandidateFindings(findings)}
	}
	if err := requirePlatformDraftTarget(ctx, tx, command.PlatformID, canonical.Package, true); err != nil {
		return PlatformAgentSubmission{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE platform_agent_submissions
		SET status = 'superseded', revision = revision + 1, terminal_at = $3, updated_at = $3
		WHERE platform_id = $1 AND draft_id = $2 AND status = 'pending'
	`, command.PlatformID, command.DraftID, command.SubmittedAt.UTC()); err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	version, err := CanonicalizeVersion(canonical.Package.Manifest, canonical.Package.Bundle)
	if err != nil {
		return PlatformAgentSubmission{}, ErrOfficialVersionIntegrityFailed
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform_agent_submissions (
			id, platform_id, draft_id, draft_revision, definition_id, base_version_id,
			kind, display_name, icon_media_type, icon_data, canonical_manifest, bundle,
			manifest_digest, bundle_digest, content_digest, submitted_by_admin_id,
			submitted_by_role, status, revision, submitted_at, terminal_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11::jsonb,
		          $12::jsonb, $13, $14, $15, $16, 'developer', 'pending', 1, $17, NULL, $17)
	`, command.SubmissionID, command.PlatformID, command.DraftID, draft.Revision,
		canonical.Package.DefinitionID, nullUUID(canonical.Package.BaseVersionID), canonical.Package.Kind,
		canonical.Package.DisplayName, canonical.Package.IconMediaType, nilIfEmptyBytes(canonical.Package.IconData),
		string(version.ManifestJSON), string(version.BundleJSON), canonical.ManifestDigest[:],
		canonical.BundleDigest[:], canonical.ContentDigest[:], command.Actor.AdminID, command.SubmittedAt.UTC()); err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{DefinitionID: canonical.Package.DefinitionID, DraftID: command.DraftID, SubmissionID: command.SubmissionID}
	if err := insertPlatformIdempotency(
		ctx, tx, command.PlatformID, operationSubmitPlatformDraft, command.Idempotency,
		"platform_submission", command.SubmissionID, response, command.SubmittedAt,
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	if err := recordPlatformAudit(
		ctx, tx, command.Actor, command.PlatformID, command.Audit,
		"official_draft_submitted", "platform_submission", command.SubmissionID, command.SubmittedAt,
		map[string]string{"content_digest": digestArrayHex(canonical.ContentDigest), "revision": "1"},
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	value, err := loadPlatformSubmission(ctx, tx, command.PlatformID, command.SubmissionID, false)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	return commitPlatformSubmission(ctx, tx, value)
}

func (r *PostgresRepository) WithdrawPlatformSubmission(
	ctx context.Context,
	command TerminalPlatformSubmissionRepositoryCommand,
) (PlatformAgentSubmission, error) {
	if r == nil || r.postgres == nil || !validTerminalPlatformSubmissionCommand(command) {
		return PlatformAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, found, err := lockAndReadPlatformIdempotency(
		ctx, tx, command.PlatformID, operationWithdrawPlatformSubmission, command.Idempotency,
	)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	if found {
		value, err := loadPlatformSubmission(ctx, tx, command.PlatformID, response.SubmissionID, false)
		if err != nil {
			return PlatformAgentSubmission{}, err
		}
		value.Replayed = true
		return commitPlatformSubmission(ctx, tx, value)
	}
	current, err := loadPlatformSubmission(ctx, tx, command.PlatformID, command.SubmissionID, true)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	if current.Status != PlatformSubmissionPending || current.Revision != command.ExpectedRevision {
		return PlatformAgentSubmission{}, ErrOfficialSubmissionConflict
	}
	if current.SubmittedByAdminID != command.Actor.AdminID {
		return PlatformAgentSubmission{}, ErrPlatformForbidden
	}
	if err := transitionPlatformSubmission(
		ctx, tx, command.PlatformID, command.SubmissionID, command.ExpectedRevision,
		PlatformSubmissionWithdrawn, command.TerminalAt,
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	response = idempotencyResponse{DefinitionID: current.DefinitionID, DraftID: current.DraftID, SubmissionID: current.ID}
	if err := insertPlatformIdempotency(
		ctx, tx, command.PlatformID, operationWithdrawPlatformSubmission, command.Idempotency,
		"platform_submission", current.ID, response, command.TerminalAt,
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	if err := recordPlatformAudit(
		ctx, tx, command.Actor, command.PlatformID, command.Audit,
		"official_submission_withdrawn", "platform_submission", current.ID, command.TerminalAt,
		map[string]string{"content_digest": digestArrayHex(current.ContentDigest), "revision": strconv.FormatInt(current.Revision+1, 10)},
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	value, err := loadPlatformSubmission(ctx, tx, command.PlatformID, current.ID, false)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	return commitPlatformSubmission(ctx, tx, value)
}

func (r *PostgresRepository) ReviewPlatformSubmission(
	ctx context.Context,
	command ReviewPlatformSubmissionRepositoryCommand,
) (PlatformAgentSubmission, error) {
	if r == nil || r.postgres == nil || !validReviewPlatformSubmissionCommand(command) {
		return PlatformAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	response, found, err := lockAndReadPlatformIdempotency(
		ctx, tx, command.PlatformID, operationReviewPlatformSubmission, command.Idempotency,
	)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	if found {
		value, err := loadPlatformSubmission(ctx, tx, command.PlatformID, response.SubmissionID, false)
		if err != nil {
			return PlatformAgentSubmission{}, err
		}
		value.Replayed = true
		return commitPlatformSubmission(ctx, tx, value)
	}
	if err := requireActivePlatform(ctx, tx, command.PlatformID, true); err != nil {
		return PlatformAgentSubmission{}, err
	}
	current, err := loadPlatformSubmission(ctx, tx, command.PlatformID, command.SubmissionID, true)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	if current.Status != PlatformSubmissionPending || current.Revision != command.ExpectedRevision {
		return PlatformAgentSubmission{}, ErrOfficialSubmissionConflict
	}
	if current.SubmittedByAdminID == command.Actor.AdminID {
		return PlatformAgentSubmission{}, ErrOfficialSubmissionSelfReview
	}
	if _, err := loadPlatformDraft(ctx, tx, command.PlatformID, current.DraftID, true); err != nil {
		return PlatformAgentSubmission{}, err
	}
	canonical, err := canonicalFromPlatformSubmission(current)
	if err != nil {
		return PlatformAgentSubmission{}, ErrOfficialVersionIntegrityFailed
	}
	if findings := ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle)); len(findings) != 0 {
		return PlatformAgentSubmission{}, &PlatformPublicationDLPError{Findings: cloneExperienceCandidateFindings(findings)}
	}
	policy, found, err := loadLatestPlatformPolicy(ctx, tx, command.PlatformID)
	if err != nil || !found {
		if err != nil {
			return PlatformAgentSubmission{}, err
		}
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	policyDocument, err := decodePlatformPolicy(policy)
	if err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	if command.Decision == PlatformReviewApprove && !channelsAllowed(command.InitialReleases, policyDocument.PermittedChannels) {
		return PlatformAgentSubmission{}, ErrOfficialRolloutInvalid
	}
	var versionNumber int64
	if command.Decision == PlatformReviewApprove {
		versionNumber, err = lockPlatformPublicationTarget(ctx, tx, command.PlatformID, canonical.Package)
		if err != nil {
			return PlatformAgentSubmission{}, err
		}
	}

	reasonCode := command.ReasonCode
	if command.Decision == PlatformReviewApprove {
		reasonCode = "approved"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform_agent_reviews (
			id, platform_id, submission_id, reviewer_admin_id, reviewer_role, decision,
			reason_code, safe_note, reviewed_content_digest, platform_policy_snapshot_id,
			platform_policy_version, reviewed_at
		) VALUES ($1, $2, $3, $4, 'super_admin', $5, $6, NULLIF($7, ''), $8, $9, $10, $11)
	`, command.ReviewID, command.PlatformID, command.SubmissionID, command.Actor.AdminID,
		command.Decision, reasonCode, command.SafeNote, current.ContentDigest[:],
		policy.ID, policy.Version, command.ReviewedAt.UTC()); err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}

	var versionID uuid.UUID
	if command.Decision == PlatformReviewApprove {
		material, err := command.BuildVersion(canonical, versionNumber)
		if err != nil {
			return PlatformAgentSubmission{}, err
		}
		expectedVersion, canonicalErr := CanonicalizeVersion(canonical.Package.Manifest, canonical.Package.Bundle)
		if canonicalErr != nil || !validVersionMaterial(material, versionNumber) ||
			material.ContentDigest != canonical.ContentDigest ||
			!bytes.Equal(material.CanonicalManifest, expectedVersion.ManifestJSON) ||
			!bytes.Equal(material.Bundle, expectedVersion.BundleJSON) {
			return PlatformAgentSubmission{}, ErrOfficialVersionIntegrityFailed
		}
		if err := insertPlatformVersion(
			ctx, tx, command.PlatformID, current, policy, command.Actor, material, command.ReviewedAt,
		); err != nil {
			return PlatformAgentSubmission{}, err
		}
		if err := updatePlatformDefinitionHead(
			ctx, tx, command.PlatformID, canonical, material.ID, command.ReviewedAt,
		); err != nil {
			return PlatformAgentSubmission{}, err
		}
		for _, initial := range command.InitialReleases {
			if err := insertInitialOfficialRelease(
				ctx, tx, command.PlatformID, current.DefinitionID, material.ID,
				material.RuntimeMinimumVersion, initial, command.RolloutKeyID, command.Actor, command.ReviewedAt,
			); err != nil {
				return PlatformAgentSubmission{}, err
			}
		}
		versionID = material.ID
	}
	status := PlatformSubmissionRejected
	if command.Decision == PlatformReviewApprove {
		status = PlatformSubmissionApproved
	}
	if err := transitionPlatformSubmission(
		ctx, tx, command.PlatformID, command.SubmissionID, command.ExpectedRevision,
		status, command.ReviewedAt,
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	response = idempotencyResponse{
		DefinitionID: current.DefinitionID, DraftID: current.DraftID,
		SubmissionID: current.ID, ReviewID: command.ReviewID, VersionID: versionID,
	}
	if err := insertPlatformIdempotency(
		ctx, tx, command.PlatformID, operationReviewPlatformSubmission, command.Idempotency,
		"platform_submission", current.ID, response, command.ReviewedAt,
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	metadata := map[string]string{
		"content_digest":     digestArrayHex(current.ContentDigest),
		"revision":           strconv.FormatInt(current.Revision+1, 10),
		"decision":           string(command.Decision),
		"policy_snapshot_id": policy.ID.String(),
		"policy_version":     strconv.FormatInt(policy.Version, 10),
	}
	if versionID != uuid.Nil {
		metadata["agent_version_id"] = versionID.String()
	}
	if err := recordPlatformAudit(
		ctx, tx, command.Actor, command.PlatformID, command.Audit,
		"official_submission_reviewed", "platform_submission", current.ID,
		command.ReviewedAt, metadata,
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	value, err := loadPlatformSubmission(ctx, tx, command.PlatformID, current.ID, false)
	if err != nil {
		return PlatformAgentSubmission{}, err
	}
	return commitPlatformSubmission(ctx, tx, value)
}

func (r *PostgresRepository) GetPlatformDraft(
	ctx context.Context,
	platformID uuid.UUID,
	draftID uuid.UUID,
) (PlatformAgentDraft, bool, error) {
	if r == nil || r.postgres == nil || platformID == uuid.Nil || draftID == uuid.Nil {
		return PlatformAgentDraft{}, false, ErrInvalidRepositoryCommand
	}
	value, err := loadPlatformDraft(ctx, r.postgres, platformID, draftID, false)
	if errors.Is(err, ErrNotFound) {
		return PlatformAgentDraft{}, false, nil
	}
	if err != nil {
		return PlatformAgentDraft{}, false, err
	}
	return value, true, nil
}

func (r *PostgresRepository) GetPlatformSubmission(
	ctx context.Context,
	platformID uuid.UUID,
	submissionID uuid.UUID,
) (PlatformAgentSubmission, bool, error) {
	if r == nil || r.postgres == nil || platformID == uuid.Nil || submissionID == uuid.Nil {
		return PlatformAgentSubmission{}, false, ErrInvalidRepositoryCommand
	}
	value, err := loadPlatformSubmission(ctx, r.postgres, platformID, submissionID, false)
	if errors.Is(err, ErrNotFound) {
		return PlatformAgentSubmission{}, false, nil
	}
	if err != nil {
		return PlatformAgentSubmission{}, false, err
	}
	return value, true, nil
}

func (r *PostgresRepository) ListPlatformDefinitions(
	ctx context.Context,
	platformID uuid.UUID,
	page PageRequest,
) (PlatformDefinitionPage, error) {
	if r == nil || r.postgres == nil || platformID == uuid.Nil || !validRepositoryPage(page) {
		return PlatformDefinitionPage{}, ErrInvalidRepositoryCommand
	}
	rows, err := r.postgres.Query(ctx, platformDefinitionSelect+`
		AND ($2::uuid IS NULL OR definition.id > $2)
		ORDER BY definition.id
		LIMIT $3
	`, platformID, nullUUID(page.After), page.Limit+1)
	if err != nil {
		return PlatformDefinitionPage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	items := make([]PlatformDefinitionDetail, 0, page.Limit+1)
	for rows.Next() {
		value, err := scanPlatformDefinition(rows)
		if err != nil {
			return PlatformDefinitionPage{}, ErrServiceUnavailable
		}
		items = append(items, value)
	}
	if rows.Err() != nil {
		return PlatformDefinitionPage{}, ErrServiceUnavailable
	}
	result := PlatformDefinitionPage{Items: items}
	if len(result.Items) > page.Limit {
		result.Next = result.Items[page.Limit-1].Definition.ID
		result.Items = result.Items[:page.Limit]
	}
	return result, nil
}

func (r *PostgresRepository) GetPlatformDefinition(
	ctx context.Context,
	platformID uuid.UUID,
	definitionID uuid.UUID,
) (PlatformDefinitionDetail, bool, error) {
	if r == nil || r.postgres == nil || platformID == uuid.Nil || definitionID == uuid.Nil {
		return PlatformDefinitionDetail{}, false, ErrInvalidRepositoryCommand
	}
	value, err := scanPlatformDefinition(r.postgres.QueryRow(
		ctx, platformDefinitionSelect+` AND definition.id = $2`, platformID, definitionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformDefinitionDetail{}, false, nil
	}
	if err != nil {
		return PlatformDefinitionDetail{}, false, ErrServiceUnavailable
	}
	return value, true, nil
}

func (r *PostgresRepository) ListPlatformDrafts(
	ctx context.Context,
	platformID uuid.UUID,
	page PageRequest,
) (PlatformDraftPage, error) {
	if r == nil || r.postgres == nil || platformID == uuid.Nil || !validRepositoryPage(page) {
		return PlatformDraftPage{}, ErrInvalidRepositoryCommand
	}
	rows, err := r.postgres.Query(ctx, platformDraftSelect+`
		WHERE draft.platform_id = $1 AND ($2::uuid IS NULL OR draft.id > $2)
		ORDER BY draft.id LIMIT $3
	`, platformID, nullUUID(page.After), page.Limit+1)
	if err != nil {
		return PlatformDraftPage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	items := make([]PlatformAgentDraft, 0, page.Limit+1)
	for rows.Next() {
		value, err := scanPlatformDraft(rows)
		if err != nil {
			return PlatformDraftPage{}, ErrServiceUnavailable
		}
		items = append(items, value)
	}
	if rows.Err() != nil {
		return PlatformDraftPage{}, ErrServiceUnavailable
	}
	result := PlatformDraftPage{Items: items}
	if len(result.Items) > page.Limit {
		result.Next = result.Items[page.Limit-1].ID
		result.Items = result.Items[:page.Limit]
	}
	return result, nil
}

func (r *PostgresRepository) ListPlatformSubmissions(
	ctx context.Context,
	platformID uuid.UUID,
	filter PlatformSubmissionFilter,
) (PlatformSubmissionPage, error) {
	page := normalizePageRequest(filter.Page)
	if r == nil || r.postgres == nil || platformID == uuid.Nil ||
		!validPlatformSubmissionFilter(filter) || !validRepositoryPage(page) {
		return PlatformSubmissionPage{}, ErrInvalidRepositoryCommand
	}
	rows, err := r.postgres.Query(ctx, platformSubmissionSelect+`
		WHERE submission.platform_id = $1
		  AND ($2 = '' OR submission.status = $2)
		  AND ($3::uuid IS NULL OR submission.id > $3)
		ORDER BY submission.id LIMIT $4
	`, platformID, filter.Status, nullUUID(page.After), page.Limit+1)
	if err != nil {
		return PlatformSubmissionPage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	items := make([]PlatformAgentSubmission, 0, page.Limit+1)
	for rows.Next() {
		value, err := scanPlatformSubmission(rows)
		if err != nil {
			return PlatformSubmissionPage{}, ErrServiceUnavailable
		}
		items = append(items, value)
	}
	if rows.Err() != nil {
		return PlatformSubmissionPage{}, ErrServiceUnavailable
	}
	result := PlatformSubmissionPage{Items: items}
	if len(result.Items) > page.Limit {
		result.Next = result.Items[page.Limit-1].ID
		result.Items = result.Items[:page.Limit]
	}
	return result, nil
}

func (r *PostgresRepository) ListPlatformVersions(
	ctx context.Context,
	platformID uuid.UUID,
	page PageRequest,
) (PlatformVersionPage, error) {
	if r == nil || r.postgres == nil || platformID == uuid.Nil || !validRepositoryPage(page) {
		return PlatformVersionPage{}, ErrInvalidRepositoryCommand
	}
	rows, err := r.postgres.Query(ctx, platformVersionSelect+`
		AND ($2::uuid IS NULL OR version.id > $2)
		ORDER BY version.id LIMIT $3
	`, platformID, nullUUID(page.After), page.Limit+1)
	if err != nil {
		return PlatformVersionPage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	items := make([]Version, 0, page.Limit+1)
	for rows.Next() {
		value, err := scanVersion(rows)
		if err != nil {
			return PlatformVersionPage{}, ErrServiceUnavailable
		}
		items = append(items, value)
	}
	if rows.Err() != nil {
		return PlatformVersionPage{}, ErrServiceUnavailable
	}
	result := PlatformVersionPage{Items: items}
	if len(result.Items) > page.Limit {
		result.Next = result.Items[page.Limit-1].ID
		result.Items = result.Items[:page.Limit]
	}
	return result, nil
}

func (r *PostgresRepository) GetPlatformVersion(
	ctx context.Context,
	platformID uuid.UUID,
	versionID uuid.UUID,
) (Version, bool, error) {
	if r == nil || r.postgres == nil || platformID == uuid.Nil || versionID == uuid.Nil {
		return Version{}, false, ErrInvalidRepositoryCommand
	}
	value, err := scanVersion(r.postgres.QueryRow(
		ctx, platformVersionSelect+` AND version.id = $2`, platformID, versionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, false, nil
	}
	if err != nil {
		return Version{}, false, ErrServiceUnavailable
	}
	return value, true, nil
}

const platformDefinitionSelect = `
	SELECT definition.id, definition.display_name, COALESCE(definition.icon_media_type, ''),
	       definition.icon_data, definition.status, definition.latest_version_id,
	       definition.created_at, definition.updated_at, definition.platform_id,
	       definition.created_by_admin_id
	FROM agent_definitions definition
	WHERE definition.owner_scope = 'PLATFORM' AND definition.platform_id = $1
`

const platformVersionSelect = `
	SELECT version.id, version.definition_id, version.version_number,
	       version.canonical_manifest::text, version.bundle::text, version.content_digest,
	       version.signing_key_id, version.signature, version.runtime_minimum_version,
	       COALESCE(version.runtime_maximum_version_exclusive, ''), version.published_at
	FROM agent_versions version
	WHERE version.owner_scope = 'PLATFORM' AND version.platform_id = $1
`

const platformDraftSelect = `
	SELECT draft.id, draft.platform_id, draft.definition_id, draft.base_version_id,
	       draft.kind, draft.display_name, COALESCE(draft.icon_media_type, ''), draft.icon_data,
	       draft.canonical_manifest::text, draft.bundle::text, draft.manifest_digest,
	       draft.bundle_digest, draft.content_digest, draft.revision, draft.status,
	       draft.last_editor_admin_id, draft.last_editor_role, draft.created_at, draft.updated_at
	FROM platform_agent_drafts draft
`

const platformSubmissionSelect = `
	SELECT submission.id, submission.platform_id, submission.draft_id,
	       submission.draft_revision, submission.definition_id, submission.base_version_id,
	       submission.kind, submission.display_name, COALESCE(submission.icon_media_type, ''),
	       submission.icon_data, submission.canonical_manifest::text, submission.bundle::text,
	       submission.manifest_digest, submission.bundle_digest, submission.content_digest,
	       submission.submitted_by_admin_id, submission.submitted_by_role, submission.status,
	       submission.revision, submission.submitted_at, submission.terminal_at, submission.updated_at,
	       review.id, review.reviewer_admin_id, review.reviewer_role, review.decision,
	       review.reason_code, review.safe_note, review.reviewed_content_digest,
	       review.platform_policy_snapshot_id, review.platform_policy_version, review.reviewed_at
	FROM platform_agent_submissions submission
	LEFT JOIN platform_agent_reviews review ON review.submission_id = submission.id
`

func loadPlatformReservation(
	ctx context.Context,
	queryer queryRower,
	platformID uuid.UUID,
	definitionID uuid.UUID,
) (PlatformDefinitionReservation, error) {
	detail, err := scanPlatformDefinition(queryer.QueryRow(
		ctx, platformDefinitionSelect+` AND definition.id = $2`, platformID, definitionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformDefinitionReservation{}, ErrNotFound
	}
	if err != nil {
		return PlatformDefinitionReservation{}, ErrServiceUnavailable
	}
	return PlatformDefinitionReservation{
		ID: detail.Definition.ID, PlatformID: detail.PlatformID,
		DisplayName: detail.Definition.DisplayName, IconMediaType: detail.Definition.IconMediaType,
		IconData: bytes.Clone(detail.Definition.IconData), Status: detail.Definition.Status,
		CreatedByAdminID: detail.CreatedByAdminID, CreatedAt: detail.Definition.CreatedAt,
		UpdatedAt: detail.Definition.UpdatedAt,
	}, nil
}

func scanPlatformDefinition(row rowScanner) (PlatformDefinitionDetail, error) {
	var value PlatformDefinitionDetail
	var latest pgtype.UUID
	if err := row.Scan(
		&value.Definition.ID, &value.Definition.DisplayName, &value.Definition.IconMediaType,
		&value.Definition.IconData, &value.Definition.Status, &latest,
		&value.Definition.CreatedAt, &value.Definition.UpdatedAt,
		&value.PlatformID, &value.CreatedByAdminID,
	); err != nil {
		return PlatformDefinitionDetail{}, err
	}
	if value.Definition.ID == uuid.Nil || value.PlatformID == uuid.Nil || value.CreatedByAdminID == uuid.Nil ||
		!validText(value.Definition.DisplayName, 1, 100) || !validIcon(value.Definition.IconMediaType, value.Definition.IconData) ||
		(value.Definition.Status != definitionStatusActive && value.Definition.Status != definitionStatusArchived) {
		return PlatformDefinitionDetail{}, ErrServiceUnavailable
	}
	if latest.Valid {
		id := uuid.UUID(latest.Bytes)
		value.Definition.LatestVersionID = &id
	}
	value.Definition.IconData = bytes.Clone(value.Definition.IconData)
	value.Definition.CreatedAt = value.Definition.CreatedAt.UTC()
	value.Definition.UpdatedAt = value.Definition.UpdatedAt.UTC()
	return value, nil
}

func loadPlatformDraft(
	ctx context.Context,
	queryer queryRower,
	platformID uuid.UUID,
	draftID uuid.UUID,
	forUpdate bool,
) (PlatformAgentDraft, error) {
	query := platformDraftSelect + ` WHERE draft.platform_id = $1 AND draft.id = $2`
	if forUpdate {
		query += ` FOR UPDATE OF draft`
	}
	value, err := scanPlatformDraft(queryer.QueryRow(ctx, query, platformID, draftID))
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformAgentDraft{}, ErrNotFound
	}
	if err != nil {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	return value, nil
}

func scanPlatformDraft(row rowScanner) (PlatformAgentDraft, error) {
	var value PlatformAgentDraft
	var baseVersion pgtype.UUID
	var kind, status string
	var manifestJSON, bundleJSON []byte
	var manifestDigest, bundleDigest, contentDigest []byte
	if err := row.Scan(
		&value.ID, &value.PlatformID, &value.DefinitionID, &baseVersion,
		&kind, &value.DisplayName, &value.IconMediaType, &value.IconData,
		&manifestJSON, &bundleJSON, &manifestDigest, &bundleDigest, &contentDigest,
		&value.Revision, &status, &value.LastEditorAdminID, &value.LastEditorRole,
		&value.CreatedAt, &value.UpdatedAt,
	); err != nil {
		return PlatformAgentDraft{}, err
	}
	if value.ID == uuid.Nil || value.PlatformID == uuid.Nil || value.DefinitionID == uuid.Nil ||
		value.LastEditorAdminID == uuid.Nil || value.LastEditorRole != "developer" || value.Revision <= 0 ||
		len(manifestDigest) != sha256.Size || len(bundleDigest) != sha256.Size || len(contentDigest) != sha256.Size {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	value.Kind = PlatformDraftKind(kind)
	value.Status = PlatformDraftStatus(status)
	if baseVersion.Valid {
		value.BaseVersionID = uuid.UUID(baseVersion.Bytes)
	}
	copy(value.ManifestDigest[:], manifestDigest)
	copy(value.BundleDigest[:], bundleDigest)
	copy(value.ContentDigest[:], contentDigest)
	manifest, err := DecodeManifest(manifestJSON)
	if err != nil {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	bundle, err := DecodeBundle(bundleJSON)
	if err != nil {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: value.DefinitionID, BaseVersionID: value.BaseVersionID, Kind: value.Kind,
		DisplayName: value.DisplayName, IconMediaType: value.IconMediaType, IconData: value.IconData,
		Manifest: manifest, Bundle: bundle,
	})
	if err != nil || canonical.ManifestDigest != value.ManifestDigest ||
		canonical.BundleDigest != value.BundleDigest || canonical.ContentDigest != value.ContentDigest ||
		(value.Status != PlatformDraftActive && value.Status != PlatformDraftArchived) {
		return PlatformAgentDraft{}, ErrServiceUnavailable
	}
	value.IconData = bytes.Clone(canonical.Package.IconData)
	value.Manifest = canonical.Package.Manifest
	value.Bundle = canonical.Package.Bundle
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	return value, nil
}

func loadPlatformSubmission(
	ctx context.Context,
	queryer queryRower,
	platformID uuid.UUID,
	submissionID uuid.UUID,
	forUpdate bool,
) (PlatformAgentSubmission, error) {
	query := platformSubmissionSelect + ` WHERE submission.platform_id = $1 AND submission.id = $2`
	if forUpdate {
		query += ` FOR UPDATE OF submission`
	}
	value, err := scanPlatformSubmission(queryer.QueryRow(ctx, query, platformID, submissionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformAgentSubmission{}, ErrNotFound
	}
	if err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	return value, nil
}

func scanPlatformSubmission(row rowScanner) (PlatformAgentSubmission, error) {
	var value PlatformAgentSubmission
	var baseVersion pgtype.UUID
	var kind, status string
	var manifestJSON, bundleJSON []byte
	var manifestDigest, bundleDigest, contentDigest []byte
	var terminalAt pgtype.Timestamptz
	var reviewID, reviewerID, policyID pgtype.UUID
	var reviewerRole, decision, reasonCode, safeNote pgtype.Text
	var reviewedDigest []byte
	var policyVersion pgtype.Int8
	var reviewedAt pgtype.Timestamptz
	if err := row.Scan(
		&value.ID, &value.PlatformID, &value.DraftID, &value.DraftRevision,
		&value.DefinitionID, &baseVersion, &kind, &value.DisplayName,
		&value.IconMediaType, &value.IconData, &manifestJSON, &bundleJSON,
		&manifestDigest, &bundleDigest, &contentDigest, &value.SubmittedByAdminID,
		&value.SubmittedByRole, &status, &value.Revision, &value.SubmittedAt,
		&terminalAt, &value.UpdatedAt, &reviewID, &reviewerID, &reviewerRole,
		&decision, &reasonCode, &safeNote, &reviewedDigest, &policyID,
		&policyVersion, &reviewedAt,
	); err != nil {
		return PlatformAgentSubmission{}, err
	}
	if value.ID == uuid.Nil || value.PlatformID == uuid.Nil || value.DraftID == uuid.Nil ||
		value.DefinitionID == uuid.Nil || value.SubmittedByAdminID == uuid.Nil ||
		value.SubmittedByRole != "developer" || value.DraftRevision <= 0 || value.Revision <= 0 ||
		len(manifestDigest) != sha256.Size || len(bundleDigest) != sha256.Size || len(contentDigest) != sha256.Size {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	value.Kind = PlatformDraftKind(kind)
	value.Status = PlatformSubmissionStatus(status)
	if baseVersion.Valid {
		value.BaseVersionID = uuid.UUID(baseVersion.Bytes)
	}
	copy(value.ManifestDigest[:], manifestDigest)
	copy(value.BundleDigest[:], bundleDigest)
	copy(value.ContentDigest[:], contentDigest)
	manifest, err := DecodeManifest(manifestJSON)
	if err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	bundle, err := DecodeBundle(bundleJSON)
	if err != nil {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: value.DefinitionID, BaseVersionID: value.BaseVersionID, Kind: value.Kind,
		DisplayName: value.DisplayName, IconMediaType: value.IconMediaType, IconData: value.IconData,
		Manifest: manifest, Bundle: bundle,
	})
	if err != nil || canonical.ManifestDigest != value.ManifestDigest ||
		canonical.BundleDigest != value.BundleDigest || canonical.ContentDigest != value.ContentDigest {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	value.IconData = bytes.Clone(canonical.Package.IconData)
	value.Manifest = canonical.Package.Manifest
	value.Bundle = canonical.Package.Bundle
	value.SubmittedAt = value.SubmittedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	if terminalAt.Valid {
		terminal := terminalAt.Time.UTC()
		value.TerminalAt = &terminal
	}
	if !validPlatformSubmissionState(value) {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	if reviewID.Valid {
		if !reviewerID.Valid || !reviewerRole.Valid || !decision.Valid || !reasonCode.Valid ||
			!policyID.Valid || !policyVersion.Valid || !reviewedAt.Valid || len(reviewedDigest) != sha256.Size {
			return PlatformAgentSubmission{}, ErrServiceUnavailable
		}
		review := PlatformAgentReview{
			ID: uuid.UUID(reviewID.Bytes), PlatformID: value.PlatformID, SubmissionID: value.ID,
			ReviewerAdminID: uuid.UUID(reviewerID.Bytes), ReviewerRole: reviewerRole.String,
			Decision: PlatformReviewDecision(decision.String), ReasonCode: reasonCode.String,
			PlatformPolicySnapshotID: uuid.UUID(policyID.Bytes), PlatformPolicyVersion: policyVersion.Int64,
			ReviewedAt: reviewedAt.Time.UTC(),
		}
		if safeNote.Valid {
			review.SafeNote = safeNote.String
		}
		copy(review.ReviewedContentDigest[:], reviewedDigest)
		if review.ReviewerRole != "super_admin" || review.ReviewedContentDigest != value.ContentDigest ||
			review.PlatformPolicyVersion <= 0 || review.ReviewerAdminID == uuid.Nil {
			return PlatformAgentSubmission{}, ErrServiceUnavailable
		}
		switch review.Decision {
		case PlatformReviewApprove:
			if review.ReasonCode != "approved" || review.SafeNote != "" {
				return PlatformAgentSubmission{}, ErrServiceUnavailable
			}
		case PlatformReviewReject:
			if !platformReasonPattern.MatchString(review.ReasonCode) ||
				(review.SafeNote != "" && !validOrganizationReviewNote(review.SafeNote)) {
				return PlatformAgentSubmission{}, ErrServiceUnavailable
			}
		default:
			return PlatformAgentSubmission{}, ErrServiceUnavailable
		}
		value.Review = &review
	}
	if (value.Status == PlatformSubmissionApproved || value.Status == PlatformSubmissionRejected) != (value.Review != nil) {
		return PlatformAgentSubmission{}, ErrServiceUnavailable
	}
	return value, nil
}

func validPlatformSubmissionState(value PlatformAgentSubmission) bool {
	switch value.Status {
	case PlatformSubmissionPending:
		return value.Revision == 1 && value.TerminalAt == nil && value.Review == nil
	case PlatformSubmissionApproved, PlatformSubmissionRejected:
		return value.Revision == 2 && value.TerminalAt != nil
	case PlatformSubmissionWithdrawn, PlatformSubmissionSuperseded:
		return value.Revision == 2 && value.TerminalAt != nil && value.Review == nil
	default:
		return false
	}
}

func canonicalFromPlatformSubmission(value PlatformAgentSubmission) (CanonicalPlatformDraft, error) {
	canonical, err := CanonicalizePlatformDraft(PlatformDraftPackage{
		DefinitionID: value.DefinitionID, BaseVersionID: value.BaseVersionID, Kind: value.Kind,
		DisplayName: value.DisplayName, IconMediaType: value.IconMediaType, IconData: value.IconData,
		Manifest: value.Manifest, Bundle: value.Bundle,
	})
	if err != nil || canonical.ManifestDigest != value.ManifestDigest ||
		canonical.BundleDigest != value.BundleDigest || canonical.ContentDigest != value.ContentDigest {
		return CanonicalPlatformDraft{}, ErrOfficialVersionIntegrityFailed
	}
	return canonical, nil
}

func loadLatestPlatformPolicy(
	ctx context.Context,
	queryer queryRower,
	platformID uuid.UUID,
) (PlatformPolicySnapshot, bool, error) {
	value, err := scanPlatformPolicy(queryer.QueryRow(ctx, `
		SELECT id, platform_id, version, canonical_policy::text, policy_digest,
		       signature_key_id, signature, created_at
		FROM platform_agent_policy_snapshots
		WHERE platform_id = $1 ORDER BY version DESC LIMIT 1
	`, platformID))
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformPolicySnapshot{}, false, nil
	}
	if err != nil {
		return PlatformPolicySnapshot{}, false, ErrServiceUnavailable
	}
	return value, true, nil
}

func loadPlatformPolicy(
	ctx context.Context,
	queryer queryRower,
	platformID uuid.UUID,
	policyID uuid.UUID,
) (PlatformPolicySnapshot, error) {
	value, err := scanPlatformPolicy(queryer.QueryRow(ctx, `
		SELECT id, platform_id, version, canonical_policy::text, policy_digest,
		       signature_key_id, signature, created_at
		FROM platform_agent_policy_snapshots
		WHERE platform_id = $1 AND id = $2
	`, platformID, policyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformPolicySnapshot{}, ErrNotFound
	}
	if err != nil {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	return value, nil
}

func scanPlatformPolicy(row rowScanner) (PlatformPolicySnapshot, error) {
	var value PlatformPolicySnapshot
	var storedJSON string
	var digest []byte
	if err := row.Scan(
		&value.ID, &value.PlatformID, &value.Version, &storedJSON, &digest,
		&value.SigningKeyID, &value.Signature, &value.CreatedAt,
	); err != nil {
		return PlatformPolicySnapshot{}, err
	}
	if value.ID == uuid.Nil || value.PlatformID == uuid.Nil || value.Version <= 0 ||
		len(digest) != sha256.Size || !validToken(value.SigningKeyID, 128) || len(value.Signature) != 64 {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	var document PlatformAgentPolicyV1
	if err := decodeStrictJSON([]byte(storedJSON), &document); err != nil || !validPlatformPolicyDocument(document) {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	value.CanonicalPolicy = canonical
	copy(value.PolicyDigest[:], digest)
	if sha256.Sum256(canonical) != value.PolicyDigest {
		return PlatformPolicySnapshot{}, ErrServiceUnavailable
	}
	value.Signature = bytes.Clone(value.Signature)
	value.CreatedAt = value.CreatedAt.UTC()
	return value, nil
}

func decodePlatformPolicy(value PlatformPolicySnapshot) (PlatformAgentPolicyV1, error) {
	var document PlatformAgentPolicyV1
	if err := decodeStrictJSON(value.CanonicalPolicy, &document); err != nil || !validPlatformPolicyDocument(document) ||
		sha256.Sum256(value.CanonicalPolicy) != value.PolicyDigest {
		return PlatformAgentPolicyV1{}, ErrServiceUnavailable
	}
	return document, nil
}

func requireActivePlatform(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	forUpdate bool,
) error {
	query := `SELECT status FROM platforms WHERE id = $1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var status string
	if err := tx.QueryRow(ctx, query, platformID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return ErrServiceUnavailable
	}
	if status != "active" {
		return ErrPlatformForbidden
	}
	return nil
}

func requirePlatformDraftTarget(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	input PlatformDraftPackage,
	forUpdate bool,
) error {
	query := `
		SELECT definition.status, definition.latest_version_id
		FROM agent_definitions definition
		WHERE definition.id = $1 AND definition.owner_scope = 'PLATFORM' AND definition.platform_id = $2
	`
	if forUpdate {
		query += ` FOR UPDATE OF definition`
	}
	var status string
	var latest pgtype.UUID
	if err := tx.QueryRow(ctx, query, input.DefinitionID, platformID).Scan(&status, &latest); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return ErrServiceUnavailable
	}
	if status != definitionStatusActive {
		return ErrDefinitionArchived
	}
	switch input.Kind {
	case PlatformDraftInitial:
		if latest.Valid || input.BaseVersionID != uuid.Nil {
			return ErrVersionConflict
		}
	case PlatformDraftNext:
		if !latest.Valid || uuid.UUID(latest.Bytes) != input.BaseVersionID {
			return ErrVersionConflict
		}
	default:
		return ErrInvalidRepositoryCommand
	}
	return nil
}

func lockPlatformPublicationTarget(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	input PlatformDraftPackage,
) (int64, error) {
	var status string
	var latest pgtype.UUID
	var latestNumber pgtype.Int8
	if err := tx.QueryRow(ctx, `
		SELECT definition.status, definition.latest_version_id, version.version_number
		FROM agent_definitions definition
		LEFT JOIN agent_versions version
		  ON version.id = definition.latest_version_id
		 AND version.owner_scope = 'PLATFORM'
		 AND version.platform_id = definition.platform_id
		WHERE definition.id = $1 AND definition.owner_scope = 'PLATFORM' AND definition.platform_id = $2
		FOR UPDATE OF definition
	`, input.DefinitionID, platformID).Scan(&status, &latest, &latestNumber); errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	} else if err != nil {
		return 0, ErrServiceUnavailable
	}
	if status != definitionStatusActive {
		return 0, ErrDefinitionArchived
	}
	switch input.Kind {
	case PlatformDraftInitial:
		if latest.Valid || latestNumber.Valid || input.BaseVersionID != uuid.Nil {
			return 0, ErrVersionConflict
		}
		return 1, nil
	case PlatformDraftNext:
		if !latest.Valid || !latestNumber.Valid || uuid.UUID(latest.Bytes) != input.BaseVersionID || latestNumber.Int64 <= 0 {
			return 0, ErrVersionConflict
		}
		return latestNumber.Int64 + 1, nil
	default:
		return 0, ErrInvalidRepositoryCommand
	}
}

func insertPlatformVersion(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	submission PlatformAgentSubmission,
	policy PlatformPolicySnapshot,
	actor PlatformAdminActor,
	material VersionMaterial,
	publishedAt time.Time,
) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_versions (
			id, definition_id, tenant_id, owner_scope, owner_id, workspace_id,
			organization_id, platform_id, version_number, canonical_manifest, bundle,
			content_digest, signing_key_id, signature, runtime_minimum_version,
			runtime_maximum_version_exclusive, published_by, published_at,
			organization_submission_id, organization_policy_snapshot_id,
			platform_submission_id, platform_policy_snapshot_id, published_by_admin_id
		) VALUES (
			$1, $2, NULL, 'PLATFORM', NULL, NULL, NULL, $3, $4, $5::jsonb, $6::jsonb,
			$7, $8, $9, $10, NULLIF($11, ''), NULL, $12, NULL, NULL, $13, $14, $15
		)
	`, material.ID, submission.DefinitionID, platformID, material.VersionNumber,
		string(material.CanonicalManifest), string(material.Bundle), material.ContentDigest[:],
		material.SigningKeyID, material.Signature, material.RuntimeMinimumVersion,
		material.RuntimeMaximumVersionExclusive, publishedAt.UTC(), submission.ID, policy.ID,
		actor.AdminID); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func updatePlatformDefinitionHead(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	canonical CanonicalPlatformDraft,
	versionID uuid.UUID,
	updatedAt time.Time,
) error {
	result, err := tx.Exec(ctx, `
		UPDATE agent_definitions
		SET display_name = $3, icon_media_type = NULLIF($4, ''), icon_data = $5,
		    latest_version_id = $6, updated_at = $7
		WHERE id = $1 AND owner_scope = 'PLATFORM' AND platform_id = $2 AND status = 'active'
	`, canonical.Package.DefinitionID, platformID, canonical.Package.DisplayName,
		canonical.Package.IconMediaType, nilIfEmptyBytes(canonical.Package.IconData), versionID, updatedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return ErrServiceUnavailable
	}
	return nil
}

func insertInitialOfficialRelease(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	definitionID uuid.UUID,
	versionID uuid.UUID,
	minimumDesktopVersion string,
	initial InitialOfficialRelease,
	rolloutKeyID string,
	actor PlatformAdminActor,
	createdAt time.Time,
) error {
	result, err := tx.Exec(ctx, `
		INSERT INTO official_releases (
			id, platform_id, definition_id, channel, current_release_revision_id,
			head_revision, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, 1, $6, $6)
		ON CONFLICT (platform_id, definition_id, channel) DO NOTHING
	`, initial.ReleaseID, platformID, definitionID, initial.Channel, initial.RevisionID, createdAt.UTC())
	if err != nil {
		return ErrServiceUnavailable
	}
	if result.RowsAffected() == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO official_release_revisions (
			id, release_id, revision_number, agent_version_id, state,
			rollout_basis_points, minimum_desktop_version, bucket_algorithm_version,
			rollout_key_id, action, previous_revision_id, rollback_target_revision_id,
			actor_admin_id, actor_admin_role, reason_code, ticket_reference, created_at
		) VALUES ($1, $2, 1, $3, 'paused', 0, $4, '1', $5, 'initial', NULL, NULL,
		          $6, $7, 'initial_release', NULL, $8)
	`, initial.RevisionID, initial.ReleaseID, versionID, minimumDesktopVersion,
		rolloutKeyID, actor.AdminID, actor.Role, createdAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func transitionPlatformSubmission(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	submissionID uuid.UUID,
	expectedRevision int64,
	status PlatformSubmissionStatus,
	terminalAt time.Time,
) error {
	var revision int64
	if err := tx.QueryRow(ctx, `
		UPDATE platform_agent_submissions
		SET status = $4, revision = revision + 1, terminal_at = $5, updated_at = $5
		WHERE id = $1 AND platform_id = $2 AND revision = $3 AND status = 'pending'
		RETURNING revision
	`, submissionID, platformID, expectedRevision, status, terminalAt.UTC()).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
		return ErrOfficialSubmissionConflict
	} else if err != nil || revision != expectedRevision+1 {
		return ErrServiceUnavailable
	}
	return nil
}

func channelsAllowed(initial []InitialOfficialRelease, allowed []OfficialChannel) bool {
	if len(initial) == 0 || len(initial) > 2 {
		return false
	}
	allowedSet := make(map[OfficialChannel]struct{}, len(allowed))
	for _, channel := range allowed {
		allowedSet[channel] = struct{}{}
	}
	seen := make(map[OfficialChannel]struct{}, len(initial))
	for _, release := range initial {
		if release.ReleaseID == uuid.Nil || release.RevisionID == uuid.Nil || release.ReleaseID == release.RevisionID {
			return false
		}
		if _, exists := allowedSet[release.Channel]; !exists {
			return false
		}
		if _, exists := seen[release.Channel]; exists {
			return false
		}
		seen[release.Channel] = struct{}{}
	}
	return true
}

func lockAndReadPlatformIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	operation string,
	evidence IdempotencyEvidence,
) (idempotencyResponse, bool, error) {
	lockID := platformIdempotencyLockID(platformID, operation, evidence.KeyHash)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	var requestHash, encoded []byte
	err := tx.QueryRow(ctx, `
		SELECT request_hash, response_document
		FROM agent_control_idempotency_keys
		WHERE owner_scope = 'PLATFORM' AND platform_id = $1
		  AND operation = $2 AND key_hash = $3
	`, platformID, operation, evidence.KeyHash[:]).Scan(&requestHash, &encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return idempotencyResponse{}, false, nil
	}
	if err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	if len(requestHash) != sha256.Size || subtle.ConstantTimeCompare(requestHash, evidence.RequestHash[:]) != 1 {
		return idempotencyResponse{}, false, ErrIdempotencyConflict
	}
	var response idempotencyResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	return response, true, nil
}

func insertPlatformIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	operation string,
	evidence IdempotencyEvidence,
	resourceType string,
	resourceID uuid.UUID,
	response idempotencyResponse,
	createdAt time.Time,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_control_idempotency_keys (
			id, tenant_id, owner_scope, owner_id, workspace_id, organization_id, platform_id,
			operation, key_hash, request_hash, resource_type, resource_id,
			response_document, created_at, expires_at
		) VALUES ($1, NULL, 'PLATFORM', NULL, NULL, NULL, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
	`, evidence.ID, platformID, operation, evidence.KeyHash[:], evidence.RequestHash[:],
		resourceType, resourceID, string(encoded), createdAt.UTC(), evidence.ExpiresAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func platformIdempotencyLockID(
	platformID uuid.UUID,
	operation string,
	keyHash [sha256.Size]byte,
) int64 {
	payload := append([]byte("PLATFORM\x00"+platformID.String()+"\x00"+operation+"\x00"), keyHash[:]...)
	digest := sha256.Sum256(payload)
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func recordPlatformAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor PlatformAdminActor,
	platformID uuid.UUID,
	evidence AuditEvidence,
	eventType string,
	objectType string,
	objectID uuid.UUID,
	occurredAt time.Time,
	metadata map[string]string,
) error {
	bounded := map[string]string{
		"owner_scope":      string(OwnerScopePlatform),
		"platform_id":      platformID.String(),
		"actor_admin_id":   actor.AdminID.String(),
		"actor_admin_role": actor.Role,
	}
	for key, value := range metadata {
		bounded[key] = value
	}
	encoded, err := json.Marshal(bounded)
	if err != nil {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, device_id, object_type, object_id,
			outcome, reason_code, request_id, ip_hmac, metadata, created_at, organization_id
		) VALUES ($1, $2, NULL, NULL, $3, $4, 'success', NULL, $5, NULL, $6::jsonb, $7, NULL)
	`, evidence.EventID, eventType, objectType, objectID, evidence.RequestID,
		string(encoded), occurredAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func validEnsurePlatformCommand(command EnsurePlatformCommand) bool {
	return command.PlatformID != uuid.Nil && platformKeyPattern.MatchString(command.PlatformKey) &&
		validPlatformDisplayName(command.PlatformDisplayName) && command.BuildPolicy != nil && !command.EnsuredAt.IsZero()
}

func validPlatformActor(actor PlatformAdminActor, action platformAction) bool {
	return actor.AdminID != uuid.Nil && validRequestID(actor.RequestID) && platformRoleAllowed(actor.Role, action)
}

func validReservePlatformDefinitionCommand(command ReservePlatformDefinitionRepositoryCommand) bool {
	return command.DefinitionID != uuid.Nil && command.PlatformID != uuid.Nil &&
		validPlatformActor(command.Actor, platformActionDraftWrite) &&
		validPlatformDisplayName(command.DisplayName) &&
		validIcon(command.IconMediaType, command.IconData) && !command.CreatedAt.IsZero() &&
		validIdempotency(command.Idempotency, command.CreatedAt) && validAuditEvidence(command.Audit)
}

func validCreatePlatformDraftCommand(command CreatePlatformDraftRepositoryCommand) bool {
	if command.DraftID == uuid.Nil || command.PlatformID == uuid.Nil ||
		!validPlatformActor(command.Actor, platformActionDraftWrite) || command.CreatedAt.IsZero() ||
		!validIdempotency(command.Idempotency, command.CreatedAt) || !validAuditEvidence(command.Audit) {
		return false
	}
	canonical, err := CanonicalizePlatformDraft(command.Canonical.Package)
	return err == nil && canonical.ManifestDigest == command.Canonical.ManifestDigest &&
		canonical.BundleDigest == command.Canonical.BundleDigest && canonical.ContentDigest == command.Canonical.ContentDigest &&
		canonicalPlatformPackagesEqual(canonical.Package, command.Canonical.Package) &&
		len(ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle))) == 0
}

func validUpdatePlatformDraftEnvelope(command UpdatePlatformDraftRepositoryCommand) bool {
	return command.DraftID != uuid.Nil && command.PlatformID != uuid.Nil && command.ExpectedRevision > 0 &&
		validPlatformActor(command.Actor, platformActionDraftWrite) && !command.UpdatedAt.IsZero() &&
		validIdempotency(command.Idempotency, command.UpdatedAt) && validAuditEvidence(command.Audit)
}

func validSubmitPlatformDraftCommand(command SubmitPlatformDraftRepositoryCommand) bool {
	return command.SubmissionID != uuid.Nil && command.PlatformID != uuid.Nil && command.DraftID != uuid.Nil &&
		command.ExpectedRevision > 0 && validPlatformActor(command.Actor, platformActionDraftWrite) &&
		!command.SubmittedAt.IsZero() && validIdempotency(command.Idempotency, command.SubmittedAt) &&
		validAuditEvidence(command.Audit)
}

func validTerminalPlatformSubmissionCommand(command TerminalPlatformSubmissionRepositoryCommand) bool {
	return command.PlatformID != uuid.Nil && command.SubmissionID != uuid.Nil && command.ExpectedRevision > 0 &&
		validPlatformActor(command.Actor, platformActionDraftWrite) && !command.TerminalAt.IsZero() &&
		validIdempotency(command.Idempotency, command.TerminalAt) && validAuditEvidence(command.Audit)
}

func validReviewPlatformSubmissionCommand(command ReviewPlatformSubmissionRepositoryCommand) bool {
	if command.ReviewID == uuid.Nil || command.PlatformID == uuid.Nil || command.SubmissionID == uuid.Nil ||
		command.ExpectedRevision <= 0 || !validPlatformActor(command.Actor, platformActionReview) ||
		command.ReviewedAt.IsZero() || !validIdempotency(command.Idempotency, command.ReviewedAt) ||
		!validAuditEvidence(command.Audit) {
		return false
	}
	switch command.Decision {
	case PlatformReviewApprove:
		return command.ReasonCode == "" && command.SafeNote == "" && command.BuildVersion != nil &&
			validToken(command.RolloutKeyID, 64) && channelsAllowed(
			command.InitialReleases, []OfficialChannel{OfficialChannelInternal, OfficialChannelStable},
		)
	case PlatformReviewReject:
		return command.BuildVersion == nil && len(command.InitialReleases) == 0 && command.RolloutKeyID == "" &&
			platformReasonPattern.MatchString(command.ReasonCode) &&
			(command.SafeNote == "" || validOrganizationReviewNote(command.SafeNote))
	default:
		return false
	}
}

func validPlatformPolicyMaterial(material PlatformPolicyMaterial, version int64) bool {
	if material.ID == uuid.Nil || material.Version != version || version <= 0 ||
		len(material.CanonicalPolicy) == 0 || len(material.CanonicalPolicy) > MaxManifestBytes ||
		!validToken(material.SigningKeyID, 128) || len(material.Signature) != 64 ||
		sha256.Sum256(material.CanonicalPolicy) != material.PolicyDigest {
		return false
	}
	var document PlatformAgentPolicyV1
	if err := decodeStrictJSON(material.CanonicalPolicy, &document); err != nil || !validPlatformPolicyDocument(document) {
		return false
	}
	canonical, err := json.Marshal(document)
	return err == nil && bytes.Equal(canonical, material.CanonicalPolicy)
}

func validPlatformPolicyDocument(document PlatformAgentPolicyV1) bool {
	defaultPolicy := DefaultPlatformAgentPolicyV1()
	if document.SchemaVersion != defaultPolicy.SchemaVersion ||
		document.ManifestSchemaVersion != defaultPolicy.ManifestSchemaVersion ||
		document.DLPVersion != defaultPolicy.DLPVersion ||
		document.ModelConstraintMode != defaultPolicy.ModelConstraintMode ||
		document.ToolConstraintMode != defaultPolicy.ToolConstraintMode ||
		document.RuntimeCompatibilityMode != defaultPolicy.RuntimeCompatibilityMode ||
		document.DependencyMode != defaultPolicy.DependencyMode ||
		document.MaximumAssetCount != defaultPolicy.MaximumAssetCount ||
		document.MaximumAssetBytes != defaultPolicy.MaximumAssetBytes ||
		document.MaximumBundleBytes != defaultPolicy.MaximumBundleBytes ||
		document.MaximumManifestBytes != defaultPolicy.MaximumManifestBytes ||
		document.MaximumIconBytes != defaultPolicy.MaximumIconBytes ||
		document.MaximumRolloutBasisPts != defaultPolicy.MaximumRolloutBasisPts ||
		len(document.PermittedChannels) != len(defaultPolicy.PermittedChannels) {
		return false
	}
	for index := range defaultPolicy.PermittedChannels {
		if document.PermittedChannels[index] != defaultPolicy.PermittedChannels[index] {
			return false
		}
	}
	return true
}

func validRepositoryPage(page PageRequest) bool {
	return page.Limit > 0 && page.Limit <= platformDraftPageLimitMax
}

func nullUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}

func canonicalPlatformPackagesEqual(left, right PlatformDraftPackage) bool {
	if left.DefinitionID != right.DefinitionID || left.BaseVersionID != right.BaseVersionID ||
		left.Kind != right.Kind || left.DisplayName != right.DisplayName ||
		left.IconMediaType != right.IconMediaType || !bytes.Equal(left.IconData, right.IconData) {
		return false
	}
	leftManifest, leftManifestErr := json.Marshal(left.Manifest)
	rightManifest, rightManifestErr := json.Marshal(right.Manifest)
	leftBundle, leftBundleErr := json.Marshal(left.Bundle)
	rightBundle, rightBundleErr := json.Marshal(right.Bundle)
	return leftManifestErr == nil && rightManifestErr == nil && leftBundleErr == nil && rightBundleErr == nil &&
		bytes.Equal(leftManifest, rightManifest) && bytes.Equal(leftBundle, rightBundle)
}

func commitPlatformPolicy(ctx context.Context, tx pgx.Tx, value PlatformPolicySnapshot) (PlatformPolicySnapshot, error) {
	if err := commitTransaction(ctx, tx); err != nil {
		return PlatformPolicySnapshot{}, err
	}
	return value, nil
}

func commitPlatformReservation(ctx context.Context, tx pgx.Tx, value PlatformDefinitionReservation) (PlatformDefinitionReservation, error) {
	if err := commitTransaction(ctx, tx); err != nil {
		return PlatformDefinitionReservation{}, err
	}
	return value, nil
}

func commitPlatformDraft(ctx context.Context, tx pgx.Tx, value PlatformAgentDraft) (PlatformAgentDraft, error) {
	if err := commitTransaction(ctx, tx); err != nil {
		return PlatformAgentDraft{}, err
	}
	return value, nil
}

func commitPlatformSubmission(ctx context.Context, tx pgx.Tx, value PlatformAgentSubmission) (PlatformAgentSubmission, error) {
	if err := commitTransaction(ctx, tx); err != nil {
		return PlatformAgentSubmission{}, err
	}
	return value, nil
}
