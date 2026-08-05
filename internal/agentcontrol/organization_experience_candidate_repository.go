package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type SubmitOrganizationExperienceCandidateCommand struct {
	CandidateID     uuid.UUID
	OrganizationID  uuid.UUID
	DefinitionID    uuid.UUID
	SourceVersionID uuid.UUID
	SkillName       string
	Canonical       CanonicalExperienceCandidate
	DLPVersion      string
	Idempotency     IdempotencyEvidence
	Audit           AuditEvidence
	CreatedAt       time.Time
}

type OrganizationExperienceCandidate struct {
	ID                    uuid.UUID
	OrganizationID        uuid.UUID
	AgentDefinitionID     uuid.UUID
	SourceAgentVersionID  uuid.UUID
	SubmittedByUserID     *uuid.UUID
	SubmittedFromDeviceID *uuid.UUID
	SkillName             string
	DLPContractVersion    string
	ContentDigest         [sha256.Size]byte
	Bundle                ExperienceCandidateBundleV1
	CreatedAt             time.Time
	Review                *ExperienceCandidateReview
}

func (r *PostgresRepository) SubmitOrganizationExperienceCandidate(
	ctx context.Context,
	principal Principal,
	command SubmitOrganizationExperienceCandidateCommand,
) (OrganizationExperienceCandidate, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) ||
		!validSubmitOrganizationExperienceCandidate(command) {
		return OrganizationExperienceCandidate{}, false, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return OrganizationExperienceCandidate{}, false, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireOrganizationAgentAccess(
		ctx, tx, principal, command.OrganizationID, organizationAgentInstall, false,
	); err != nil {
		return OrganizationExperienceCandidate{}, false, err
	}
	response, found, err := lockAndReadIdempotency(
		ctx, tx, principal, operationSubmitOrganizationExperienceCandidate, command.Idempotency,
	)
	if err != nil {
		return OrganizationExperienceCandidate{}, false, err
	}
	if found {
		candidate, err := loadOrganizationExperienceCandidate(
			ctx, tx, command.OrganizationID, response.CandidateID,
		)
		if err != nil {
			return OrganizationExperienceCandidate{}, false, err
		}
		return candidate, true, commitTransaction(ctx, tx)
	}
	if err := requireOrganizationCandidateSourceInstallation(ctx, tx, principal, command); err != nil {
		return OrganizationExperienceCandidate{}, false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_experience_candidates (
			id, organization_id, agent_definition_id, source_agent_version_id,
			submitted_by_user_id, submitted_from_device_id, kind, skill_name,
			schema_version, dlp_contract_version, content_digest, bundle_document, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'SKILL', $7, $8, $9, $10, $11::jsonb, $12)
	`, command.CandidateID, command.OrganizationID, command.DefinitionID, command.SourceVersionID,
		principal.UserID, principal.DeviceID, command.SkillName, ExperienceCandidateSchemaVersion,
		command.DLPVersion, command.Canonical.ContentDigest[:], string(command.Canonical.CanonicalJSON),
		command.CreatedAt.UTC()); err != nil {
		return OrganizationExperienceCandidate{}, false, ErrServiceUnavailable
	}
	response = idempotencyResponse{CandidateID: command.CandidateID}
	if err := insertIdempotency(
		ctx, tx, principal, operationSubmitOrganizationExperienceCandidate, command.Idempotency,
		"organization_experience_candidate", command.CandidateID, response, command.CreatedAt,
	); err != nil {
		return OrganizationExperienceCandidate{}, false, err
	}
	if err := recordOrganizationExperienceCandidateAudit(
		ctx, tx, principal, command.Audit, command.CandidateID, command.OrganizationID,
		command.Canonical.ContentDigest, command.CreatedAt,
	); err != nil {
		return OrganizationExperienceCandidate{}, false, err
	}
	candidate, err := loadOrganizationExperienceCandidate(
		ctx, tx, command.OrganizationID, command.CandidateID,
	)
	if err != nil {
		return OrganizationExperienceCandidate{}, false, err
	}
	return candidate, false, commitTransaction(ctx, tx)
}

func requireOrganizationCandidateSourceInstallation(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	command SubmitOrganizationExperienceCandidateCommand,
) error {
	var definitionStatus string
	err := tx.QueryRow(ctx, `
		SELECT definition.status
		FROM agent_definitions definition
		JOIN agent_versions version
		  ON version.id = $3
		 AND version.definition_id = definition.id
		 AND version.owner_scope = 'ORGANIZATION'
		 AND version.organization_id = definition.organization_id
		JOIN installations installation
		  ON installation.tenant_id = $4
		 AND installation.owner_scope = 'USER'
		 AND installation.owner_id = $5
		 AND installation.device_id = $6
		 AND installation.definition_id = definition.id
		 AND installation.selected_version_id = version.id
		 AND installation.status = 'active'
		 AND installation.runtime_profile_id IS NOT NULL
		JOIN personal_spaces personal_space
		  ON personal_space.id = installation.tenant_id
		 AND personal_space.owner_user_id = $5
		 AND personal_space.status = 'active'
		JOIN devices device
		  ON device.id = installation.device_id
		 AND device.user_id = $5
		 AND device.installation_id = installation.device_installation_id
		 AND device.status = 'active'
		WHERE definition.id = $2
		  AND definition.owner_scope = 'ORGANIZATION'
		  AND definition.organization_id = $1
		FOR UPDATE OF definition, installation, personal_space, device
	`, command.OrganizationID, command.DefinitionID, command.SourceVersionID,
		principal.PersonalSpaceID, principal.UserID, principal.DeviceID).Scan(&definitionStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOrganizationAgentNotFound
	}
	if err != nil {
		return ErrServiceUnavailable
	}
	if definitionStatus == definitionStatusArchived {
		return ErrDefinitionArchived
	}
	if definitionStatus != definitionStatusActive {
		return ErrServiceUnavailable
	}
	return nil
}

const organizationExperienceCandidateSelect = `
	SELECT candidate.id, candidate.organization_id, candidate.agent_definition_id,
		candidate.source_agent_version_id, candidate.submitted_by_user_id,
		candidate.submitted_from_device_id, candidate.skill_name,
		candidate.dlp_contract_version, candidate.content_digest,
		candidate.bundle_document::text, candidate.created_at,
		review.id, review.reviewed_by_user_id, review.decision,
		review.reason_code, review.safe_note, review.reviewed_at
	FROM organization_experience_candidates candidate
	LEFT JOIN organization_experience_candidate_reviews review ON review.candidate_id = candidate.id
`

func loadOrganizationExperienceCandidate(
	ctx context.Context,
	queryer queryRower,
	organizationID uuid.UUID,
	candidateID uuid.UUID,
) (OrganizationExperienceCandidate, error) {
	candidate, err := scanOrganizationExperienceCandidate(queryer.QueryRow(
		ctx,
		organizationExperienceCandidateSelect+` WHERE candidate.organization_id = $1 AND candidate.id = $2`,
		organizationID,
		candidateID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationExperienceCandidate{}, ErrOrganizationAgentNotFound
	}
	if err != nil {
		return OrganizationExperienceCandidate{}, ErrServiceUnavailable
	}
	return candidate, nil
}

func scanOrganizationExperienceCandidate(row rowScanner) (OrganizationExperienceCandidate, error) {
	var candidate OrganizationExperienceCandidate
	var submitter pgtype.UUID
	var device pgtype.UUID
	var digest []byte
	var bundleDocument string
	var reviewID pgtype.UUID
	var reviewer pgtype.UUID
	var decision pgtype.Text
	var reasonCode pgtype.Text
	var safeNote pgtype.Text
	var reviewedAt pgtype.Timestamptz
	if err := row.Scan(
		&candidate.ID,
		&candidate.OrganizationID,
		&candidate.AgentDefinitionID,
		&candidate.SourceAgentVersionID,
		&submitter,
		&device,
		&candidate.SkillName,
		&candidate.DLPContractVersion,
		&digest,
		&bundleDocument,
		&candidate.CreatedAt,
		&reviewID,
		&reviewer,
		&decision,
		&reasonCode,
		&safeNote,
		&reviewedAt,
	); err != nil {
		return OrganizationExperienceCandidate{}, err
	}
	if len(digest) != sha256.Size || candidate.DLPContractVersion != ExperienceCandidateDLPVersion {
		return OrganizationExperienceCandidate{}, ErrServiceUnavailable
	}
	copy(candidate.ContentDigest[:], digest)
	var bundle ExperienceCandidateBundleV1
	if err := decodeStrictJSON([]byte(bundleDocument), &bundle); err != nil {
		return OrganizationExperienceCandidate{}, ErrServiceUnavailable
	}
	canonical, err := CanonicalizeExperienceCandidate(bundle)
	if err != nil || canonical.ContentDigest != candidate.ContentDigest ||
		canonical.Bundle.SkillName != candidate.SkillName {
		return OrganizationExperienceCandidate{}, ErrServiceUnavailable
	}
	candidate.Bundle = canonical.Bundle
	if submitter.Valid {
		value := uuid.UUID(submitter.Bytes)
		candidate.SubmittedByUserID = &value
	}
	if device.Valid {
		value := uuid.UUID(device.Bytes)
		candidate.SubmittedFromDeviceID = &value
	}
	if reviewID.Valid {
		if !decision.Valid || !reviewedAt.Valid {
			return OrganizationExperienceCandidate{}, ErrServiceUnavailable
		}
		review := ExperienceCandidateReview{
			ID:         uuid.UUID(reviewID.Bytes),
			Decision:   ExperienceCandidateDecision(decision.String),
			ReviewedAt: reviewedAt.Time,
		}
		if reviewer.Valid {
			value := uuid.UUID(reviewer.Bytes)
			review.ReviewedByUserID = &value
		}
		if reasonCode.Valid {
			review.ReasonCode = reasonCode.String
		}
		if safeNote.Valid {
			review.SafeNote = safeNote.String
		}
		candidate.Review = &review
	}
	return candidate, nil
}

func validSubmitOrganizationExperienceCandidate(command SubmitOrganizationExperienceCandidateCommand) bool {
	if command.CandidateID == uuid.Nil || command.OrganizationID == uuid.Nil ||
		command.DefinitionID == uuid.Nil || command.SourceVersionID == uuid.Nil ||
		command.SkillName != command.Canonical.Bundle.SkillName ||
		command.DLPVersion != ExperienceCandidateDLPVersion || command.CreatedAt.IsZero() ||
		!validIdempotency(command.Idempotency, command.CreatedAt) || !validAuditEvidence(command.Audit) ||
		len(ScanExperienceCandidate(command.Canonical)) != 0 {
		return false
	}
	canonical, err := CanonicalizeExperienceCandidate(command.Canonical.Bundle)
	return err == nil && canonical.ContentDigest == command.Canonical.ContentDigest &&
		bytes.Equal(canonical.CanonicalJSON, command.Canonical.CanonicalJSON)
}

func recordOrganizationExperienceCandidateAudit(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	evidence AuditEvidence,
	candidateID uuid.UUID,
	organizationID uuid.UUID,
	digest [sha256.Size]byte,
	occurredAt time.Time,
) error {
	recorder, err := audit.NewRecorder(tx)
	if err != nil {
		return ErrServiceUnavailable
	}
	actor := principal.UserID
	device := principal.DeviceID
	if err := recorder.Record(ctx, audit.Event{
		ID:             evidence.EventID,
		EventType:      "organization_experience_candidate_submitted",
		ActorUserID:    &actor,
		DeviceID:       &device,
		OrganizationID: &organizationID,
		ObjectType:     "organization_experience_candidate",
		ObjectID:       &candidateID,
		Outcome:        audit.OutcomeSuccess,
		RequestID:      evidence.RequestID,
		Metadata: map[string]string{
			"organization_id": organizationID.String(),
			"content_digest":  hex.EncodeToString(digest[:]),
		},
		OccurredAt: occurredAt.UTC(),
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}
