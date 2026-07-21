package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/bignormal/aera-cloud/internal/organization"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrOrganizationSubmissionConflict   = errors.New("organization submission conflict")
	ErrOrganizationSubmissionSelfReview = errors.New("organization submission self review")
	ErrOrganizationSubmissionSuperseded = errors.New("organization submission superseded")
)

const (
	operationSubmitOrganizationAgent   = "submit_organization_agent"
	operationWithdrawOrganizationAgent = "withdraw_organization_agent"
	operationReviewOrganizationAgent   = "review_organization_agent"
)

type SubmitOrganizationAgentCommand struct {
	SubmissionID   uuid.UUID
	OrganizationID uuid.UUID
	Principal      Principal
	Canonical      CanonicalOrganizationSubmission
	Idempotency    IdempotencyEvidence
	Audit          AuditEvidence
	SubmittedAt    time.Time
}

type WithdrawOrganizationAgentCommand struct {
	OrganizationID   uuid.UUID
	SubmissionID     uuid.UUID
	ExpectedRevision int64
	Principal        Principal
	Idempotency      IdempotencyEvidence
	Audit            AuditEvidence
	WithdrawnAt      time.Time
}

type ReviewOrganizationAgentCommand struct {
	ReviewID         uuid.UUID
	OrganizationID   uuid.UUID
	SubmissionID     uuid.UUID
	ExpectedRevision int64
	Principal        Principal
	Decision         OrganizationReviewDecision
	ReasonCode       string
	SafeNote         string
	BuildVersion     func(CanonicalOrganizationSubmission, int64) (VersionMaterial, error)
	Idempotency      IdempotencyEvidence
	Audit            AuditEvidence
	ReviewedAt       time.Time
}

type OrganizationSubmissionSupersededError struct {
	Submission OrganizationAgentSubmission
}

func (err *OrganizationSubmissionSupersededError) Error() string {
	return ErrOrganizationSubmissionSuperseded.Error()
}

func (err *OrganizationSubmissionSupersededError) Unwrap() error {
	return ErrOrganizationSubmissionSuperseded
}

func (r *PostgresRepository) SubmitOrganizationAgent(
	ctx context.Context,
	command SubmitOrganizationAgentCommand,
) (OrganizationAgentSubmission, error) {
	if r == nil || r.postgres == nil || !validSubmitOrganizationAgentCommand(command) {
		return OrganizationAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	defer rollback(tx)

	access, err := requireOrganizationAgentAccess(
		ctx, tx, command.Principal, command.OrganizationID, organizationAgentPublish, false,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	response, found, err := lockAndReadOrganizationAgentIdempotency(
		ctx, tx, command.OrganizationID, operationSubmitOrganizationAgent, command.Idempotency,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if found {
		if response.SubmissionID == uuid.Nil {
			return OrganizationAgentSubmission{}, ErrServiceUnavailable
		}
		submission, err := loadOrganizationAgentSubmission(ctx, tx, command.OrganizationID, response.SubmissionID)
		if err != nil {
			return OrganizationAgentSubmission{}, err
		}
		submission.Replayed = true
		return submission, commitTransaction(ctx, tx)
	}
	if err := validateAgainstCurrentOrganizationPolicy(command.Canonical, access.PolicyDocument); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if err := lockOrganizationSubmissionTarget(ctx, tx, command); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	version, err := CanonicalizeVersion(command.Canonical.Package.Manifest, command.Canonical.Package.Bundle)
	if err != nil {
		return OrganizationAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	var baseVersion any
	if command.Canonical.Package.BaseVersionID != uuid.Nil {
		baseVersion = command.Canonical.Package.BaseVersionID
	}
	var displayName any
	if command.Canonical.Package.DisplayName != "" {
		displayName = command.Canonical.Package.DisplayName
	}
	var iconMediaType any
	if command.Canonical.Package.IconMediaType != "" {
		iconMediaType = command.Canonical.Package.IconMediaType
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_agent_submissions (
			id, organization_id, kind, definition_id, base_version_id, display_name,
			icon_media_type, icon_data, canonical_manifest, bundle, manifest_digest,
			bundle_digest, content_digest, submitted_by_user_id, status, revision,
			submitted_at, terminal_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11, $12,
			$13, $14, 'pending', 1, $15, NULL, $15
		)
	`, command.SubmissionID, command.OrganizationID, command.Canonical.Package.Kind,
		command.Canonical.Package.DefinitionID, baseVersion, displayName, iconMediaType,
		nilIfEmptyBytes(command.Canonical.Package.IconData), string(version.ManifestJSON),
		string(version.BundleJSON), command.Canonical.ManifestDigest[:], command.Canonical.BundleDigest[:],
		command.Canonical.ContentDigest[:], command.Principal.UserID, command.SubmittedAt.UTC()); err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	response = idempotencyResponse{SubmissionID: command.SubmissionID}
	if err := insertOrganizationAgentIdempotency(
		ctx, tx, command.OrganizationID, operationSubmitOrganizationAgent, command.Idempotency,
		"organization_agent_submission", command.SubmissionID, response, command.SubmittedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if err := recordOrganizationAgentSubmissionAudit(
		ctx, tx, command.Principal, command.OrganizationID, command.Audit,
		"organization_agent_submission_created", command.SubmissionID,
		command.Canonical.ContentDigest, OrganizationSubmissionPending, 1, "", 0,
		access, command.SubmittedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	submission, err := loadOrganizationAgentSubmission(ctx, tx, command.OrganizationID, command.SubmissionID)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	return submission, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) ListOrganizationAgentSubmissions(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
) ([]OrganizationAgentSubmission, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireOrganizationAgentAccess(
		ctx, tx, principal, organizationID, organizationAgentReviewRead, true,
	); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, organizationSubmissionSelect+`
		WHERE submission.organization_id = $1
		ORDER BY submission.submitted_at DESC, submission.id DESC
	`, organizationID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rows.Close()
	result := make([]OrganizationAgentSubmission, 0)
	for rows.Next() {
		value, err := scanOrganizationAgentSubmission(rows)
		if err != nil {
			return nil, ErrServiceUnavailable
		}
		result = append(result, value)
	}
	if rows.Err() != nil {
		return nil, ErrServiceUnavailable
	}
	if err := commitTransaction(ctx, tx); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *PostgresRepository) FindOrganizationAgentSubmission(
	ctx context.Context,
	principal Principal,
	organizationID uuid.UUID,
	submissionID uuid.UUID,
) (OrganizationAgentSubmission, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) ||
		organizationID == uuid.Nil || submissionID == uuid.Nil {
		return OrganizationAgentSubmission{}, false, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return OrganizationAgentSubmission{}, false, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireOrganizationAgentAccess(
		ctx, tx, principal, organizationID, organizationAgentReviewRead, true,
	); err != nil {
		return OrganizationAgentSubmission{}, false, err
	}
	value, err := scanOrganizationAgentSubmission(tx.QueryRow(
		ctx, organizationSubmissionSelect+`
			WHERE submission.organization_id = $1 AND submission.id = $2
		`, organizationID, submissionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationAgentSubmission{}, false, commitTransaction(ctx, tx)
	}
	if err != nil {
		return OrganizationAgentSubmission{}, false, ErrServiceUnavailable
	}
	return value, true, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) WithdrawOrganizationAgentSubmission(
	ctx context.Context,
	command WithdrawOrganizationAgentCommand,
) (OrganizationAgentSubmission, error) {
	if r == nil || r.postgres == nil || !validWithdrawOrganizationAgentCommand(command) {
		return OrganizationAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	access, err := requireOrganizationAgentAccess(
		ctx, tx, command.Principal, command.OrganizationID, organizationAgentPublish, false,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	response, found, err := lockAndReadOrganizationAgentIdempotency(
		ctx, tx, command.OrganizationID, operationWithdrawOrganizationAgent, command.Idempotency,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if found {
		value, err := loadOrganizationAgentSubmission(ctx, tx, command.OrganizationID, response.SubmissionID)
		if err != nil {
			return OrganizationAgentSubmission{}, err
		}
		value.Replayed = true
		return value, commitTransaction(ctx, tx)
	}
	current, err := loadOrganizationAgentSubmissionForUpdate(ctx, tx, command.OrganizationID, command.SubmissionID)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if current.Status != OrganizationSubmissionPending || current.Revision != command.ExpectedRevision {
		return OrganizationAgentSubmission{}, ErrOrganizationSubmissionConflict
	}
	if current.SubmittedByUserID != command.Principal.UserID {
		return OrganizationAgentSubmission{}, ErrOrganizationAgentForbidden
	}
	if err := transitionOrganizationAgentSubmission(
		ctx, tx, command.OrganizationID, command.SubmissionID, command.ExpectedRevision,
		OrganizationSubmissionWithdrawn, command.WithdrawnAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	response = idempotencyResponse{SubmissionID: command.SubmissionID}
	if err := insertOrganizationAgentIdempotency(
		ctx, tx, command.OrganizationID, operationWithdrawOrganizationAgent, command.Idempotency,
		"organization_agent_submission", command.SubmissionID, response, command.WithdrawnAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if err := recordOrganizationAgentSubmissionAudit(
		ctx, tx, command.Principal, command.OrganizationID, command.Audit,
		"organization_agent_submission_withdrawn", command.SubmissionID, current.ContentDigest,
		OrganizationSubmissionWithdrawn, command.ExpectedRevision+1,
		current.Status, current.Revision, access, command.WithdrawnAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	value, err := loadOrganizationAgentSubmission(ctx, tx, command.OrganizationID, command.SubmissionID)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	return value, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) ReviewOrganizationAgentSubmission(
	ctx context.Context,
	command ReviewOrganizationAgentCommand,
) (OrganizationAgentSubmission, error) {
	if command.Decision == OrganizationReviewApprove {
		return r.approveOrganizationAgentSubmission(ctx, command)
	}
	if r == nil || r.postgres == nil || !validRejectOrganizationAgentCommand(command) {
		return OrganizationAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	access, err := requireOrganizationAgentAccess(
		ctx, tx, command.Principal, command.OrganizationID, organizationAgentReview, false,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	response, found, err := lockAndReadOrganizationAgentIdempotency(
		ctx, tx, command.OrganizationID, operationReviewOrganizationAgent, command.Idempotency,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if found {
		value, err := loadOrganizationAgentSubmission(ctx, tx, command.OrganizationID, response.SubmissionID)
		if err != nil {
			return OrganizationAgentSubmission{}, err
		}
		value.Replayed = true
		return value, commitTransaction(ctx, tx)
	}
	current, err := loadOrganizationAgentSubmissionForUpdate(ctx, tx, command.OrganizationID, command.SubmissionID)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if current.Status != OrganizationSubmissionPending || current.Revision != command.ExpectedRevision {
		return OrganizationAgentSubmission{}, ErrOrganizationSubmissionConflict
	}
	if current.SubmittedByUserID == command.Principal.UserID {
		return OrganizationAgentSubmission{}, ErrOrganizationSubmissionSelfReview
	}
	var safeNote any
	if command.SafeNote != "" {
		safeNote = command.SafeNote
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_agent_reviews (
			id, organization_id, submission_id, reviewer_user_id, decision, reason_code,
			safe_note, organization_policy_snapshot_id, organization_policy_version,
			reviewed_content_digest, reviewed_at
		) VALUES ($1, $2, $3, $4, 'reject', $5, $6, $7, $8, $9, $10)
	`, command.ReviewID, command.OrganizationID, command.SubmissionID, command.Principal.UserID,
		command.ReasonCode, safeNote, access.PolicySnapshotID, access.PolicyVersion,
		current.ContentDigest[:], command.ReviewedAt.UTC()); err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	if err := transitionOrganizationAgentSubmission(
		ctx, tx, command.OrganizationID, command.SubmissionID, command.ExpectedRevision,
		OrganizationSubmissionRejected, command.ReviewedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	response = idempotencyResponse{SubmissionID: command.SubmissionID, ReviewID: command.ReviewID}
	if err := insertOrganizationAgentIdempotency(
		ctx, tx, command.OrganizationID, operationReviewOrganizationAgent, command.Idempotency,
		"organization_agent_submission", command.SubmissionID, response, command.ReviewedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if err := recordOrganizationAgentSubmissionAudit(
		ctx, tx, command.Principal, command.OrganizationID, command.Audit,
		"organization_agent_submission_rejected", command.SubmissionID, current.ContentDigest,
		OrganizationSubmissionRejected, command.ExpectedRevision+1,
		current.Status, current.Revision, access, command.ReviewedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	value, err := loadOrganizationAgentSubmission(ctx, tx, command.OrganizationID, command.SubmissionID)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	return value, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) approveOrganizationAgentSubmission(
	ctx context.Context,
	command ReviewOrganizationAgentCommand,
) (OrganizationAgentSubmission, error) {
	if r == nil || r.postgres == nil || !validApproveOrganizationAgentCommand(command) {
		return OrganizationAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	defer rollback(tx)
	reviewer, err := requireOrganizationAgentAccess(
		ctx, tx, command.Principal, command.OrganizationID, organizationAgentReview, false,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	response, found, err := lockAndReadOrganizationAgentIdempotency(
		ctx, tx, command.OrganizationID, operationReviewOrganizationAgent, command.Idempotency,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if found {
		value, err := loadOrganizationAgentSubmission(ctx, tx, command.OrganizationID, response.SubmissionID)
		if err != nil {
			return OrganizationAgentSubmission{}, err
		}
		value.Replayed = true
		if err := commitTransaction(ctx, tx); err != nil {
			return OrganizationAgentSubmission{}, err
		}
		if value.Status == OrganizationSubmissionSuperseded {
			return OrganizationAgentSubmission{}, &OrganizationSubmissionSupersededError{Submission: value}
		}
		return value, nil
	}
	submission, err := loadOrganizationAgentSubmissionForUpdate(
		ctx, tx, command.OrganizationID, command.SubmissionID,
	)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if submission.Status != OrganizationSubmissionPending || submission.Revision != command.ExpectedRevision {
		return OrganizationAgentSubmission{}, ErrOrganizationSubmissionConflict
	}
	if submission.SubmittedByUserID == command.Principal.UserID {
		return OrganizationAgentSubmission{}, ErrOrganizationSubmissionSelfReview
	}
	if err := requireCurrentOrganizationPublisher(
		ctx, tx, command.OrganizationID, submission.SubmittedByUserID,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	canonical, err := recanonicalizeStoredOrganizationSubmission(submission)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	findings := ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle))
	if len(findings) != 0 {
		return OrganizationAgentSubmission{}, &OrganizationPublicationDLPError{
			Findings: cloneExperienceCandidateFindings(findings),
		}
	}
	if err := validateAgainstCurrentOrganizationPolicy(canonical, reviewer.PolicyDocument); err != nil {
		return OrganizationAgentSubmission{}, err
	}

	versionNumber := int64(1)
	if submission.Kind == OrganizationSubmissionInitial {
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM agent_definitions WHERE id = $1)
		`, submission.DefinitionID).Scan(&exists); err != nil {
			return OrganizationAgentSubmission{}, ErrServiceUnavailable
		}
		if exists {
			return OrganizationAgentSubmission{}, ErrOrganizationSubmissionConflict
		}
	} else {
		currentVersionID, currentVersionNumber, err := lockOrganizationDefinitionVersion(
			ctx, tx, command.OrganizationID, submission.DefinitionID,
		)
		if err != nil {
			return OrganizationAgentSubmission{}, err
		}
		if currentVersionID != submission.BaseVersionID {
			result, err := markOrganizationSubmissionSuperseded(ctx, tx, submission, reviewer, command)
			if err != nil {
				return OrganizationAgentSubmission{}, err
			}
			if err := commitTransaction(ctx, tx); err != nil {
				return OrganizationAgentSubmission{}, err
			}
			return OrganizationAgentSubmission{}, &OrganizationSubmissionSupersededError{
				Submission: cloneOrganizationAgentSubmission(result),
			}
		}
		versionNumber = currentVersionNumber + 1
	}
	material, err := command.BuildVersion(canonical, versionNumber)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if !validOrganizationVersionMaterial(material, canonical, versionNumber) {
		return OrganizationAgentSubmission{}, ErrInvalidRepositoryCommand
	}
	if err := persistApprovedOrganizationPublication(
		ctx, tx, submission, canonical, material, reviewer, command,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	result, err := loadOrganizationAgentSubmission(ctx, tx, command.OrganizationID, command.SubmissionID)
	if err != nil {
		return OrganizationAgentSubmission{}, err
	}
	return result, commitTransaction(ctx, tx)
}

func validSubmitOrganizationAgentCommand(command SubmitOrganizationAgentCommand) bool {
	if command.SubmissionID == uuid.Nil || command.OrganizationID == uuid.Nil ||
		!validPrincipal(command.Principal) || command.SubmittedAt.IsZero() ||
		!validIdempotency(command.Idempotency, command.SubmittedAt) || !validAuditEvidence(command.Audit) {
		return false
	}
	canonical, err := CanonicalizeOrganizationSubmission(command.Canonical.Package)
	if err != nil || canonical.ManifestDigest != command.Canonical.ManifestDigest ||
		canonical.BundleDigest != command.Canonical.BundleDigest ||
		canonical.ContentDigest != command.Canonical.ContentDigest ||
		len(ScanAgentPublication(publicationTextAssets(canonical.Package.Bundle))) != 0 {
		return false
	}
	if canonical.Package.Kind != command.Canonical.Package.Kind ||
		canonical.Package.DefinitionID != command.Canonical.Package.DefinitionID ||
		canonical.Package.BaseVersionID != command.Canonical.Package.BaseVersionID ||
		canonical.Package.DisplayName != command.Canonical.Package.DisplayName ||
		canonical.Package.IconMediaType != command.Canonical.Package.IconMediaType ||
		!bytes.Equal(canonical.Package.IconData, command.Canonical.Package.IconData) {
		return false
	}
	canonicalManifest, err := json.Marshal(canonical.Package.Manifest)
	if err != nil {
		return false
	}
	providedManifest, err := json.Marshal(command.Canonical.Package.Manifest)
	if err != nil {
		return false
	}
	canonicalBundle, err := json.Marshal(canonical.Package.Bundle)
	if err != nil {
		return false
	}
	providedBundle, err := json.Marshal(command.Canonical.Package.Bundle)
	return err == nil && bytes.Equal(canonicalManifest, providedManifest) &&
		bytes.Equal(canonicalBundle, providedBundle)
}

func validWithdrawOrganizationAgentCommand(command WithdrawOrganizationAgentCommand) bool {
	return command.OrganizationID != uuid.Nil && command.SubmissionID != uuid.Nil &&
		command.ExpectedRevision > 0 && validPrincipal(command.Principal) && !command.WithdrawnAt.IsZero() &&
		validIdempotency(command.Idempotency, command.WithdrawnAt) && validAuditEvidence(command.Audit)
}

func validRejectOrganizationAgentCommand(command ReviewOrganizationAgentCommand) bool {
	return command.ReviewID != uuid.Nil && command.OrganizationID != uuid.Nil && command.SubmissionID != uuid.Nil &&
		command.ExpectedRevision > 0 && validPrincipal(command.Principal) &&
		command.Decision == OrganizationReviewReject && organizationReviewReasonPattern.MatchString(command.ReasonCode) &&
		(command.SafeNote == "" || validOrganizationReviewNote(command.SafeNote)) && !command.ReviewedAt.IsZero() &&
		validIdempotency(command.Idempotency, command.ReviewedAt) && validAuditEvidence(command.Audit)
}

func validApproveOrganizationAgentCommand(command ReviewOrganizationAgentCommand) bool {
	return command.ReviewID != uuid.Nil && command.OrganizationID != uuid.Nil && command.SubmissionID != uuid.Nil &&
		command.ExpectedRevision > 0 && validPrincipal(command.Principal) &&
		command.Decision == OrganizationReviewApprove && command.ReasonCode == "" && command.SafeNote == "" &&
		command.BuildVersion != nil && !command.ReviewedAt.IsZero() &&
		validIdempotency(command.Idempotency, command.ReviewedAt) && validAuditEvidence(command.Audit)
}

func requireCurrentOrganizationPublisher(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	userID uuid.UUID,
) error {
	var role string
	err := tx.QueryRow(ctx, `
		SELECT membership.role
		FROM organization_memberships membership
		JOIN users account ON account.id = membership.user_id AND account.status = 'active'
		WHERE membership.organization_id = $1 AND membership.user_id = $2
		FOR SHARE OF membership, account
	`, organizationID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOrganizationAgentForbidden
	}
	if err != nil {
		return ErrServiceUnavailable
	}
	if role != "owner" && role != "admin" {
		return ErrOrganizationAgentForbidden
	}
	return nil
}

func recanonicalizeStoredOrganizationSubmission(
	submission OrganizationAgentSubmission,
) (CanonicalOrganizationSubmission, error) {
	canonical, err := CanonicalizeOrganizationSubmission(OrganizationSubmissionPackage{
		Kind: submission.Kind, DefinitionID: submission.DefinitionID, BaseVersionID: submission.BaseVersionID,
		DisplayName: submission.DisplayName, IconMediaType: submission.IconMediaType,
		IconData: submission.IconData, Manifest: submission.Manifest, Bundle: submission.Bundle,
	})
	if err != nil || canonical.ManifestDigest != submission.ManifestDigest ||
		canonical.BundleDigest != submission.BundleDigest || canonical.ContentDigest != submission.ContentDigest {
		return CanonicalOrganizationSubmission{}, ErrInvalidAgentContent
	}
	return canonical, nil
}

func lockOrganizationDefinitionVersion(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	definitionID uuid.UUID,
) (uuid.UUID, int64, error) {
	var versionID uuid.UUID
	var versionNumber int64
	err := tx.QueryRow(ctx, `
		SELECT definition.latest_version_id, version.version_number
		FROM agent_definitions definition
		JOIN agent_versions version ON version.id = definition.latest_version_id
		WHERE definition.id = $1 AND definition.owner_scope = 'ORGANIZATION'
		  AND definition.organization_id = $2 AND definition.status = 'active'
		  AND version.owner_scope = 'ORGANIZATION' AND version.organization_id = $2
		FOR UPDATE OF definition
	`, definitionID, organizationID).Scan(&versionID, &versionNumber)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, 0, ErrOrganizationAgentNotFound
	}
	if err != nil || versionID == uuid.Nil || versionNumber <= 0 {
		return uuid.Nil, 0, ErrServiceUnavailable
	}
	return versionID, versionNumber, nil
}

func validOrganizationVersionMaterial(
	material VersionMaterial,
	canonical CanonicalOrganizationSubmission,
	versionNumber int64,
) bool {
	version, err := CanonicalizeVersion(canonical.Package.Manifest, canonical.Package.Bundle)
	return err == nil && validVersionMaterial(material, versionNumber) &&
		bytes.Equal(material.CanonicalManifest, version.ManifestJSON) &&
		bytes.Equal(material.Bundle, version.BundleJSON) && material.ContentDigest == version.ContentDigest
}

func persistApprovedOrganizationPublication(
	ctx context.Context,
	tx pgx.Tx,
	submission OrganizationAgentSubmission,
	canonical CanonicalOrganizationSubmission,
	material VersionMaterial,
	reviewer OrganizationAgentAccess,
	command ReviewOrganizationAgentCommand,
) error {
	if submission.Kind == OrganizationSubmissionInitial {
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_definitions (
				id, tenant_id, owner_scope, owner_id, workspace_id, organization_id,
				display_name, icon_media_type, icon_data, status, latest_version_id,
				created_by, created_at, updated_at
			) VALUES ($1, NULL, 'ORGANIZATION', NULL, NULL, $2, $3, NULLIF($4, ''), $5,
			          'active', NULL, $6, $7, $7)
		`, submission.DefinitionID, submission.OrganizationID, submission.DisplayName,
			submission.IconMediaType, nilIfEmptyBytes(submission.IconData), submission.SubmittedByUserID,
			command.ReviewedAt.UTC()); err != nil {
			return ErrServiceUnavailable
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_versions (
			id, definition_id, tenant_id, owner_scope, owner_id, workspace_id, organization_id,
			organization_submission_id, organization_policy_snapshot_id, version_number,
			canonical_manifest, bundle, content_digest, signing_key_id, signature,
			runtime_minimum_version, runtime_maximum_version_exclusive, published_by, published_at
		) VALUES ($1, $2, NULL, 'ORGANIZATION', NULL, NULL, $3, $4, $5, $6,
		          $7::jsonb, $8::jsonb, $9, $10, $11, $12, NULLIF($13, ''), $14, $15)
	`, material.ID, submission.DefinitionID, submission.OrganizationID, submission.ID,
		reviewer.PolicySnapshotID, material.VersionNumber, string(material.CanonicalManifest),
		string(material.Bundle), material.ContentDigest[:], material.SigningKeyID, material.Signature,
		material.RuntimeMinimumVersion, material.RuntimeMaximumVersionExclusive,
		command.Principal.UserID, command.ReviewedAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	result, err := tx.Exec(ctx, `
		UPDATE agent_definitions
		SET latest_version_id = $3, updated_at = $4
		WHERE id = $1 AND owner_scope = 'ORGANIZATION' AND organization_id = $2 AND status = 'active'
	`, submission.DefinitionID, submission.OrganizationID, material.ID, command.ReviewedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return ErrServiceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_agent_reviews (
			id, organization_id, submission_id, reviewer_user_id, decision, reason_code,
			safe_note, organization_policy_snapshot_id, organization_policy_version,
			reviewed_content_digest, reviewed_at
		) VALUES ($1, $2, $3, $4, 'approve', NULL, NULL, $5, $6, $7, $8)
	`, command.ReviewID, submission.OrganizationID, submission.ID, command.Principal.UserID,
		reviewer.PolicySnapshotID, reviewer.PolicyVersion, canonical.ContentDigest[:],
		command.ReviewedAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	if err := transitionOrganizationAgentSubmission(
		ctx, tx, submission.OrganizationID, submission.ID, command.ExpectedRevision,
		OrganizationSubmissionApproved, command.ReviewedAt,
	); err != nil {
		return err
	}
	response := idempotencyResponse{
		DefinitionID: submission.DefinitionID, VersionID: material.ID,
		SubmissionID: submission.ID, ReviewID: command.ReviewID,
	}
	if err := insertOrganizationAgentIdempotency(
		ctx, tx, submission.OrganizationID, operationReviewOrganizationAgent, command.Idempotency,
		"organization_agent_submission", submission.ID, response, command.ReviewedAt,
	); err != nil {
		return err
	}
	return recordOrganizationAgentSubmissionAudit(
		ctx, tx, command.Principal, submission.OrganizationID, command.Audit,
		"organization_agent_submission_approved", submission.ID, canonical.ContentDigest,
		OrganizationSubmissionApproved, command.ExpectedRevision+1,
		submission.Status, submission.Revision, reviewer, command.ReviewedAt,
	)
}

func markOrganizationSubmissionSuperseded(
	ctx context.Context,
	tx pgx.Tx,
	submission OrganizationAgentSubmission,
	reviewer OrganizationAgentAccess,
	command ReviewOrganizationAgentCommand,
) (OrganizationAgentSubmission, error) {
	if err := transitionOrganizationAgentSubmission(
		ctx, tx, submission.OrganizationID, submission.ID, command.ExpectedRevision,
		OrganizationSubmissionSuperseded, command.ReviewedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	response := idempotencyResponse{DefinitionID: submission.DefinitionID, SubmissionID: submission.ID}
	if err := insertOrganizationAgentIdempotency(
		ctx, tx, submission.OrganizationID, operationReviewOrganizationAgent, command.Idempotency,
		"organization_agent_submission", submission.ID, response, command.ReviewedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if err := recordOrganizationAgentSubmissionAudit(
		ctx, tx, command.Principal, submission.OrganizationID, command.Audit,
		"organization_agent_submission_superseded", submission.ID, submission.ContentDigest,
		OrganizationSubmissionSuperseded, command.ExpectedRevision+1,
		submission.Status, submission.Revision, reviewer, command.ReviewedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	return loadOrganizationAgentSubmission(ctx, tx, submission.OrganizationID, submission.ID)
}

func validateAgainstCurrentOrganizationPolicy(
	canonical CanonicalOrganizationSubmission,
	policy organization.PolicyDocument,
) error {
	if _, err := IntersectOrganizationAgentPolicy(
		organization.DefaultPolicyDocument(), policy, AgentPolicyConstraints{
			AllowedProviders: canonical.Package.Manifest.ModelConstraints.AllowedProviders,
			AllowedModels:    canonical.Package.Manifest.ModelConstraints.AllowedModels,
			AllowedTools:     canonical.Package.Manifest.Tools.Allowed,
		},
	); err != nil {
		return ErrOrganizationPublicationPolicyBlocked
	}
	return nil
}

func lockOrganizationSubmissionTarget(
	ctx context.Context,
	tx pgx.Tx,
	command SubmitOrganizationAgentCommand,
) error {
	switch command.Canonical.Package.Kind {
	case OrganizationSubmissionInitial:
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM agent_definitions WHERE id = $1
				UNION ALL
				SELECT 1 FROM organization_agent_submissions WHERE definition_id = $1
			)
		`, command.Canonical.Package.DefinitionID).Scan(&exists); err != nil {
			return ErrServiceUnavailable
		}
		if exists {
			return ErrOrganizationSubmissionConflict
		}
		return nil
	case OrganizationSubmissionNext:
		var latest pgtype.UUID
		err := tx.QueryRow(ctx, `
			SELECT latest_version_id
			FROM agent_definitions
			WHERE id = $1 AND owner_scope = 'ORGANIZATION' AND organization_id = $2 AND status = 'active'
			FOR UPDATE
		`, command.Canonical.Package.DefinitionID, command.OrganizationID).Scan(&latest)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOrganizationAgentNotFound
		}
		if err != nil || !latest.Valid {
			return ErrServiceUnavailable
		}
		if uuid.UUID(latest.Bytes) != command.Canonical.Package.BaseVersionID {
			return ErrOrganizationSubmissionConflict
		}
		return nil
	default:
		return ErrInvalidRepositoryCommand
	}
}

func transitionOrganizationAgentSubmission(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	submissionID uuid.UUID,
	expectedRevision int64,
	status OrganizationSubmissionStatus,
	terminalAt time.Time,
) error {
	var revision int64
	var storedStatus string
	err := tx.QueryRow(ctx, `
		UPDATE organization_agent_submissions
		SET status = $4, revision = revision + 1, terminal_at = $5, updated_at = $5
		WHERE id = $1 AND organization_id = $2 AND revision = $3 AND status = 'pending'
		RETURNING revision, status
	`, submissionID, organizationID, expectedRevision, status, terminalAt.UTC()).Scan(&revision, &storedStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOrganizationSubmissionConflict
	}
	if err != nil || revision != expectedRevision+1 || storedStatus != string(status) {
		return ErrServiceUnavailable
	}
	return nil
}

const organizationSubmissionSelect = `
	SELECT submission.id, submission.organization_id, submission.kind, submission.definition_id,
	       submission.base_version_id, submission.display_name, submission.icon_media_type,
	       submission.icon_data, submission.canonical_manifest, submission.bundle,
	       submission.manifest_digest, submission.bundle_digest, submission.content_digest,
	       submission.submitted_by_user_id, submission.status, submission.revision,
	       submission.submitted_at, submission.terminal_at, submission.updated_at,
	       review.id, review.reviewer_user_id, review.decision, review.reason_code,
	       review.safe_note, review.organization_policy_snapshot_id,
	       review.organization_policy_version, review.reviewed_content_digest, review.reviewed_at
	FROM organization_agent_submissions submission
	LEFT JOIN organization_agent_reviews review ON review.submission_id = submission.id
`

func loadOrganizationAgentSubmission(
	ctx context.Context,
	queryer interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	organizationID uuid.UUID,
	submissionID uuid.UUID,
) (OrganizationAgentSubmission, error) {
	value, err := scanOrganizationAgentSubmission(queryer.QueryRow(
		ctx, organizationSubmissionSelect+`
			WHERE submission.organization_id = $1 AND submission.id = $2
		`, organizationID, submissionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationAgentSubmission{}, ErrOrganizationAgentNotFound
	}
	if err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	return value, nil
}

func loadOrganizationAgentSubmissionForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	submissionID uuid.UUID,
) (OrganizationAgentSubmission, error) {
	value, err := scanOrganizationAgentSubmission(tx.QueryRow(
		ctx, organizationSubmissionSelect+`
			WHERE submission.organization_id = $1 AND submission.id = $2
			FOR UPDATE OF submission
		`, organizationID, submissionID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationAgentSubmission{}, ErrOrganizationAgentNotFound
	}
	if err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	return value, nil
}

func scanOrganizationAgentSubmission(row rowScanner) (OrganizationAgentSubmission, error) {
	var value OrganizationAgentSubmission
	var kind, status string
	var baseVersion pgtype.UUID
	var displayName, iconMediaType pgtype.Text
	var iconData, manifestJSON, bundleJSON []byte
	var manifestDigest, bundleDigest, contentDigest []byte
	var terminalAt pgtype.Timestamptz
	var reviewID, reviewerID, policyID pgtype.UUID
	var decision, reasonCode, safeNote pgtype.Text
	var policyVersion pgtype.Int8
	var reviewedDigest []byte
	var reviewedAt pgtype.Timestamptz
	if err := row.Scan(
		&value.ID, &value.OrganizationID, &kind, &value.DefinitionID, &baseVersion,
		&displayName, &iconMediaType, &iconData, &manifestJSON, &bundleJSON,
		&manifestDigest, &bundleDigest, &contentDigest, &value.SubmittedByUserID,
		&status, &value.Revision, &value.SubmittedAt, &terminalAt, &value.UpdatedAt,
		&reviewID, &reviewerID, &decision, &reasonCode, &safeNote, &policyID,
		&policyVersion, &reviewedDigest, &reviewedAt,
	); err != nil {
		return OrganizationAgentSubmission{}, err
	}
	if value.ID == uuid.Nil || value.OrganizationID == uuid.Nil || value.DefinitionID == uuid.Nil ||
		value.SubmittedByUserID == uuid.Nil || value.Revision <= 0 ||
		len(manifestDigest) != sha256.Size || len(bundleDigest) != sha256.Size || len(contentDigest) != sha256.Size {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	value.Kind = OrganizationSubmissionKind(kind)
	value.Status = OrganizationSubmissionStatus(status)
	if baseVersion.Valid {
		value.BaseVersionID = uuid.UUID(baseVersion.Bytes)
	}
	if displayName.Valid {
		value.DisplayName = displayName.String
	}
	if iconMediaType.Valid {
		value.IconMediaType = iconMediaType.String
	}
	value.IconData = bytes.Clone(iconData)
	copy(value.ManifestDigest[:], manifestDigest)
	copy(value.BundleDigest[:], bundleDigest)
	copy(value.ContentDigest[:], contentDigest)
	manifest, err := DecodeManifest(manifestJSON)
	if err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	bundle, err := DecodeBundle(bundleJSON)
	if err != nil {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	canonical, err := CanonicalizeOrganizationSubmission(OrganizationSubmissionPackage{
		Kind: value.Kind, DefinitionID: value.DefinitionID, BaseVersionID: value.BaseVersionID,
		DisplayName: value.DisplayName, IconMediaType: value.IconMediaType, IconData: value.IconData,
		Manifest: manifest, Bundle: bundle,
	})
	if err != nil || canonical.ManifestDigest != value.ManifestDigest ||
		canonical.BundleDigest != value.BundleDigest || canonical.ContentDigest != value.ContentDigest {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	value.Manifest = canonical.Package.Manifest
	value.Bundle = canonical.Package.Bundle
	value.SubmittedAt = value.SubmittedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	if terminalAt.Valid {
		timeValue := terminalAt.Time.UTC()
		value.TerminalAt = &timeValue
	}
	if !validOrganizationSubmissionState(value) {
		return OrganizationAgentSubmission{}, ErrServiceUnavailable
	}
	if reviewID.Valid {
		if !reviewerID.Valid || !decision.Valid || !policyID.Valid || !policyVersion.Valid ||
			!reviewedAt.Valid || len(reviewedDigest) != sha256.Size {
			return OrganizationAgentSubmission{}, ErrServiceUnavailable
		}
		review := OrganizationAgentReview{
			ID: reviewIDUUID(reviewID), OrganizationID: value.OrganizationID, SubmissionID: value.ID,
			ReviewerUserID: uuid.UUID(reviewerID.Bytes), Decision: OrganizationReviewDecision(decision.String),
			OrganizationPolicySnapshotID: uuid.UUID(policyID.Bytes), OrganizationPolicyVersion: policyVersion.Int64,
			ReviewedAt: reviewedAt.Time.UTC(),
		}
		if reasonCode.Valid {
			review.ReasonCode = reasonCode.String
		}
		if safeNote.Valid {
			review.SafeNote = safeNote.String
		}
		copy(review.ReviewedContentDigest[:], reviewedDigest)
		if review.ReviewedContentDigest != value.ContentDigest || !validOrganizationAgentReview(review) {
			return OrganizationAgentSubmission{}, ErrServiceUnavailable
		}
		value.Review = &review
	}
	return value, nil
}

func reviewIDUUID(value pgtype.UUID) uuid.UUID {
	return uuid.UUID(value.Bytes)
}

func validOrganizationSubmissionState(value OrganizationAgentSubmission) bool {
	switch value.Kind {
	case OrganizationSubmissionInitial:
		if value.BaseVersionID != uuid.Nil || value.DisplayName == "" {
			return false
		}
	case OrganizationSubmissionNext:
		if value.BaseVersionID == uuid.Nil || value.DisplayName != "" ||
			value.IconMediaType != "" || len(value.IconData) != 0 {
			return false
		}
	default:
		return false
	}
	switch value.Status {
	case OrganizationSubmissionPending:
		return value.TerminalAt == nil && value.Revision == 1
	case OrganizationSubmissionApproved, OrganizationSubmissionRejected,
		OrganizationSubmissionWithdrawn, OrganizationSubmissionSuperseded:
		return value.TerminalAt != nil && value.Revision >= 2
	default:
		return false
	}
}

func validOrganizationAgentReview(review OrganizationAgentReview) bool {
	if review.ID == uuid.Nil || review.OrganizationID == uuid.Nil || review.SubmissionID == uuid.Nil ||
		review.ReviewerUserID == uuid.Nil || review.OrganizationPolicySnapshotID == uuid.Nil ||
		review.OrganizationPolicyVersion <= 0 || review.ReviewedAt.IsZero() || zeroDigest(review.ReviewedContentDigest) {
		return false
	}
	switch review.Decision {
	case OrganizationReviewApprove:
		return review.ReasonCode == "" && review.SafeNote == ""
	case OrganizationReviewReject:
		return organizationReviewReasonPattern.MatchString(review.ReasonCode) &&
			(review.SafeNote == "" || validOrganizationReviewNote(review.SafeNote))
	default:
		return false
	}
}

func lockAndReadOrganizationAgentIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	operation string,
	evidence IdempotencyEvidence,
) (idempotencyResponse, bool, error) {
	lockID := organizationAgentIdempotencyLockID(organizationID, operation, evidence.KeyHash)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return idempotencyResponse{}, false, ErrServiceUnavailable
	}
	var requestHash, encoded []byte
	err := tx.QueryRow(ctx, `
		SELECT request_hash, response_document
		FROM agent_control_idempotency_keys
		WHERE owner_scope = 'ORGANIZATION' AND organization_id = $1
		  AND operation = $2 AND key_hash = $3
	`, organizationID, operation, evidence.KeyHash[:]).Scan(&requestHash, &encoded)
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

func insertOrganizationAgentIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
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
			id, tenant_id, owner_scope, owner_id, workspace_id, organization_id,
			operation, key_hash, request_hash, resource_type, resource_id,
			response_document, created_at, expires_at
		) VALUES ($1, NULL, 'ORGANIZATION', NULL, NULL, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
	`, evidence.ID, organizationID, operation, evidence.KeyHash[:], evidence.RequestHash[:],
		resourceType, resourceID, string(encoded), createdAt.UTC(), evidence.ExpiresAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func organizationAgentIdempotencyLockID(
	organizationID uuid.UUID,
	operation string,
	keyHash [sha256.Size]byte,
) int64 {
	payload := append([]byte("ORGANIZATION\x00"+organizationID.String()+"\x00"+operation+"\x00"), keyHash[:]...)
	digest := sha256.Sum256(payload)
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func recordOrganizationAgentSubmissionAudit(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	organizationID uuid.UUID,
	evidence AuditEvidence,
	eventType string,
	submissionID uuid.UUID,
	digest [sha256.Size]byte,
	status OrganizationSubmissionStatus,
	revision int64,
	previousStatus OrganizationSubmissionStatus,
	previousRevision int64,
	access OrganizationAgentAccess,
	occurredAt time.Time,
) error {
	recorder, err := audit.NewRecorder(tx)
	if err != nil {
		return ErrServiceUnavailable
	}
	metadata := map[string]string{
		"organization_id":    organizationID.String(),
		"content_digest":     hex.EncodeToString(digest[:]),
		"status":             string(status),
		"revision":           strconv.FormatInt(revision, 10),
		"policy_snapshot_id": access.PolicySnapshotID.String(),
		"policy_version":     strconv.FormatInt(access.PolicyVersion, 10),
	}
	if previousStatus != "" {
		metadata["previous_status"] = string(previousStatus)
		metadata["previous_revision"] = strconv.FormatInt(previousRevision, 10)
	}
	actor := principal.UserID
	device := principal.DeviceID
	if err := recorder.Record(ctx, audit.Event{
		ID: evidence.EventID, EventType: eventType, ActorUserID: &actor, DeviceID: &device,
		OrganizationID: &organizationID, ObjectType: "organization_agent_submission",
		ObjectID: &submissionID, Outcome: audit.OutcomeSuccess, RequestID: evidence.RequestID,
		Metadata: metadata, OccurredAt: occurredAt.UTC(),
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}
