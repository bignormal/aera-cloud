package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrExperienceCandidateAlreadyReviewed = errors.New("ExperienceCandidate review is terminal")
	experienceCandidateReasonPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type SubmitExperienceCandidateCommand struct {
	CandidateID     uuid.UUID
	WorkspaceID     uuid.UUID
	DefinitionID    uuid.UUID
	SourceVersionID uuid.UUID
	SkillName       string
	Canonical       CanonicalExperienceCandidate
	DLPVersion      string
	Idempotency     IdempotencyEvidence
	Audit           AuditEvidence
	CreatedAt       time.Time
}

type ReviewExperienceCandidateCommand struct {
	ReviewID    uuid.UUID
	WorkspaceID uuid.UUID
	CandidateID uuid.UUID
	Decision    ExperienceCandidateDecision
	ReasonCode  string
	SafeNote    string
	Idempotency IdempotencyEvidence
	Audit       AuditEvidence
	ReviewedAt  time.Time
}

func (r *PostgresRepository) SubmitExperienceCandidate(
	ctx context.Context,
	principal Principal,
	command SubmitExperienceCandidateCommand,
) (ExperienceCandidate, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || !validSubmitExperienceCandidate(command) {
		return ExperienceCandidate{}, false, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ExperienceCandidate{}, false, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireWorkspaceAgentAccess(
		ctx, tx, principal, command.WorkspaceID, workspaceAgentContribute, true,
	); err != nil {
		return ExperienceCandidate{}, false, err
	}
	response, found, err := lockAndReadIdempotency(
		ctx, tx, principal, operationSubmitExperienceCandidate, command.Idempotency,
	)
	if err != nil {
		return ExperienceCandidate{}, false, err
	}
	if found {
		candidate, err := loadExperienceCandidate(ctx, tx, command.WorkspaceID, response.CandidateID)
		if err != nil {
			return ExperienceCandidate{}, false, err
		}
		return candidate, true, commitTransaction(ctx, tx)
	}
	if err := requireCandidateSourceInstallation(ctx, tx, principal, command); err != nil {
		return ExperienceCandidate{}, false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO experience_candidates (
			id, workspace_id, agent_definition_id, source_agent_version_id,
			submitted_by_user_id, submitted_from_device_id, kind, skill_name,
			schema_version, dlp_contract_version, content_digest, bundle_document, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'SKILL', $7, $8, $9, $10, $11::jsonb, $12)
	`, command.CandidateID, command.WorkspaceID, command.DefinitionID, command.SourceVersionID,
		principal.UserID, principal.DeviceID, command.SkillName, ExperienceCandidateSchemaVersion,
		command.DLPVersion, command.Canonical.ContentDigest[:], string(command.Canonical.CanonicalJSON),
		command.CreatedAt.UTC()); err != nil {
		return ExperienceCandidate{}, false, ErrServiceUnavailable
	}
	response = idempotencyResponse{CandidateID: command.CandidateID}
	if err := insertIdempotency(
		ctx, tx, principal, operationSubmitExperienceCandidate, command.Idempotency,
		"experience_candidate", command.CandidateID, response, command.CreatedAt,
	); err != nil {
		return ExperienceCandidate{}, false, err
	}
	if err := recordExperienceCandidateAudit(
		ctx, tx, principal, command.Audit, "agent_experience_candidate_submitted",
		audit.OutcomeSuccess, "", command.CandidateID, command.WorkspaceID, command.DefinitionID,
		command.SourceVersionID, command.Canonical.ContentDigest, "", "", command.CreatedAt,
	); err != nil {
		return ExperienceCandidate{}, false, err
	}
	candidate, err := loadExperienceCandidate(ctx, tx, command.WorkspaceID, command.CandidateID)
	if err != nil {
		return ExperienceCandidate{}, false, err
	}
	return candidate, false, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) ListOwnExperienceCandidates(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]ExperienceCandidate, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || workspaceID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	return r.listExperienceCandidates(ctx, principal, workspaceID, false)
}

func (r *PostgresRepository) ListWorkspaceExperienceCandidates(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]ExperienceCandidate, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || workspaceID == uuid.Nil {
		return nil, ErrInvalidRepositoryCommand
	}
	return r.listExperienceCandidates(ctx, principal, workspaceID, true)
}

func (r *PostgresRepository) listExperienceCandidates(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	reviewer bool,
) ([]ExperienceCandidate, error) {
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rollback(tx)
	mode := workspaceAgentRead
	if reviewer {
		mode = workspaceAgentReview
	}
	if _, err := requireWorkspaceAgentAccess(ctx, tx, principal, workspaceID, mode, false); err != nil {
		return nil, err
	}
	query := experienceCandidateSelect + ` WHERE candidate.workspace_id = $1`
	arguments := []any{workspaceID}
	if !reviewer {
		query += ` AND candidate.submitted_by_user_id = $2`
		arguments = append(arguments, principal.UserID)
	}
	query += ` ORDER BY candidate.created_at DESC, candidate.id`
	rows, err := tx.Query(ctx, query, arguments...)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	candidates := make([]ExperienceCandidate, 0)
	for rows.Next() {
		candidate, scanErr := scanExperienceCandidate(rows)
		if scanErr != nil {
			rows.Close()
			return nil, ErrServiceUnavailable
		}
		candidates = append(candidates, candidate)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, ErrServiceUnavailable
	}
	if err := commitTransaction(ctx, tx); err != nil {
		return nil, err
	}
	return candidates, nil
}

func (r *PostgresRepository) FindExperienceCandidate(
	ctx context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	candidateID uuid.UUID,
	auditEvidence AuditEvidence,
	accessedAt time.Time,
) (ExperienceCandidate, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || workspaceID == uuid.Nil ||
		candidateID == uuid.Nil || !validAuditEvidence(auditEvidence) || accessedAt.IsZero() {
		return ExperienceCandidate{}, false, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ExperienceCandidate{}, false, ErrServiceUnavailable
	}
	defer rollback(tx)
	role, err := requireWorkspaceAgentAccess(ctx, tx, principal, workspaceID, workspaceAgentRead, false)
	if err != nil {
		return ExperienceCandidate{}, false, err
	}
	query := experienceCandidateSelect + ` WHERE candidate.workspace_id = $1 AND candidate.id = $2`
	arguments := []any{workspaceID, candidateID}
	if role == "member" {
		query += ` AND candidate.submitted_by_user_id = $3`
		arguments = append(arguments, principal.UserID)
	}
	candidate, err := scanExperienceCandidate(tx.QueryRow(ctx, query, arguments...))
	if errors.Is(err, pgx.ErrNoRows) {
		if commitErr := commitTransaction(ctx, tx); commitErr != nil {
			return ExperienceCandidate{}, false, commitErr
		}
		return ExperienceCandidate{}, false, nil
	}
	if err != nil {
		return ExperienceCandidate{}, false, ErrServiceUnavailable
	}
	if role == "owner" || role == "admin" {
		if err := recordExperienceCandidateAudit(
			ctx, tx, principal, auditEvidence, "agent_experience_candidate_detail_accessed",
			audit.OutcomeSuccess, "", candidate.ID, candidate.WorkspaceID, candidate.AgentDefinitionID,
			candidate.SourceAgentVersionID, candidate.ContentDigest, "", "", accessedAt,
		); err != nil {
			return ExperienceCandidate{}, false, err
		}
	}
	return candidate, true, commitTransaction(ctx, tx)
}

func (r *PostgresRepository) ReviewExperienceCandidate(
	ctx context.Context,
	principal Principal,
	command ReviewExperienceCandidateCommand,
) (ExperienceCandidate, bool, error) {
	if r == nil || r.postgres == nil || !validPrincipal(principal) || !validReviewExperienceCandidate(command) {
		return ExperienceCandidate{}, false, ErrInvalidRepositoryCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ExperienceCandidate{}, false, ErrServiceUnavailable
	}
	defer rollback(tx)
	if _, err := requireWorkspaceAgentAccess(
		ctx, tx, principal, command.WorkspaceID, workspaceAgentReview, true,
	); err != nil {
		return ExperienceCandidate{}, false, err
	}
	response, found, err := lockAndReadIdempotency(
		ctx, tx, principal, operationReviewExperienceCandidate, command.Idempotency,
	)
	if err != nil {
		return ExperienceCandidate{}, false, err
	}
	if found {
		candidate, err := loadExperienceCandidate(ctx, tx, command.WorkspaceID, response.CandidateID)
		if err != nil {
			return ExperienceCandidate{}, false, err
		}
		return candidate, true, commitTransaction(ctx, tx)
	}
	if err := lockExperienceCandidate(ctx, tx, command.WorkspaceID, command.CandidateID); err != nil {
		return ExperienceCandidate{}, false, err
	}
	candidate, err := loadExperienceCandidate(ctx, tx, command.WorkspaceID, command.CandidateID)
	if err != nil {
		return ExperienceCandidate{}, false, err
	}
	if candidate.Review != nil {
		if err := recordExperienceCandidateAudit(
			ctx, tx, principal, command.Audit, "agent_experience_candidate_review_conflicted",
			audit.OutcomeDenied, "candidate_already_reviewed", candidate.ID, candidate.WorkspaceID,
			candidate.AgentDefinitionID, candidate.SourceAgentVersionID, candidate.ContentDigest,
			string(command.Decision), "candidate_already_reviewed", command.ReviewedAt,
		); err != nil {
			return ExperienceCandidate{}, false, err
		}
		if err := commitTransaction(ctx, tx); err != nil {
			return ExperienceCandidate{}, false, err
		}
		return ExperienceCandidate{}, false, ErrExperienceCandidateAlreadyReviewed
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO experience_candidate_reviews (
			id, candidate_id, workspace_id, decision, reviewed_by_user_id,
			reason_code, safe_note, reviewed_at
		) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), $8)
	`, command.ReviewID, command.CandidateID, command.WorkspaceID, command.Decision,
		principal.UserID, command.ReasonCode, command.SafeNote, command.ReviewedAt.UTC()); err != nil {
		return ExperienceCandidate{}, false, ErrServiceUnavailable
	}
	response = idempotencyResponse{CandidateID: command.CandidateID, ReviewID: command.ReviewID}
	if err := insertIdempotency(
		ctx, tx, principal, operationReviewExperienceCandidate, command.Idempotency,
		"experience_candidate_review", command.ReviewID, response, command.ReviewedAt,
	); err != nil {
		return ExperienceCandidate{}, false, err
	}
	eventType := "agent_experience_candidate_review_approved"
	if command.Decision == ExperienceCandidateRejected {
		eventType = "agent_experience_candidate_review_rejected"
	}
	if err := recordExperienceCandidateAudit(
		ctx, tx, principal, command.Audit, eventType, audit.OutcomeSuccess, command.ReasonCode,
		candidate.ID, candidate.WorkspaceID, candidate.AgentDefinitionID, candidate.SourceAgentVersionID,
		candidate.ContentDigest, string(command.Decision), command.ReasonCode, command.ReviewedAt,
	); err != nil {
		return ExperienceCandidate{}, false, err
	}
	candidate, err = loadExperienceCandidate(ctx, tx, command.WorkspaceID, command.CandidateID)
	if err != nil {
		return ExperienceCandidate{}, false, err
	}
	return candidate, false, commitTransaction(ctx, tx)
}

func requireCandidateSourceInstallation(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	command SubmitExperienceCandidateCommand,
) error {
	var definitionStatus string
	err := tx.QueryRow(ctx, `
		SELECT definition.status
		FROM agent_definitions definition
		JOIN agent_versions version
		  ON version.id = $3
		 AND version.definition_id = definition.id
		 AND version.owner_scope = 'WORKSPACE'
		 AND version.workspace_id = definition.workspace_id
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
		  AND definition.owner_scope = 'WORKSPACE'
		  AND definition.workspace_id = $1
		FOR UPDATE OF definition, installation, personal_space, device
	`, command.WorkspaceID, command.DefinitionID, command.SourceVersionID, principal.PersonalSpaceID,
		principal.UserID, principal.DeviceID).Scan(&definitionStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
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

func lockExperienceCandidate(ctx context.Context, tx pgx.Tx, workspaceID, candidateID uuid.UUID) error {
	var lockedID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM experience_candidates
		WHERE workspace_id = $1 AND id = $2
		FOR UPDATE
	`, workspaceID, candidateID).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil || lockedID != candidateID {
		return ErrServiceUnavailable
	}
	return nil
}

const experienceCandidateSelect = `
	SELECT candidate.id, candidate.workspace_id, candidate.agent_definition_id,
		candidate.source_agent_version_id, candidate.submitted_by_user_id,
		candidate.submitted_from_device_id, candidate.skill_name,
		candidate.dlp_contract_version, candidate.content_digest,
		candidate.bundle_document::text, candidate.created_at,
		review.id, review.reviewed_by_user_id, review.decision,
		review.reason_code, review.safe_note, review.reviewed_at
	FROM experience_candidates candidate
	LEFT JOIN experience_candidate_reviews review ON review.candidate_id = candidate.id
`

func loadExperienceCandidate(
	ctx context.Context,
	queryer queryRower,
	workspaceID uuid.UUID,
	candidateID uuid.UUID,
) (ExperienceCandidate, error) {
	candidate, err := scanExperienceCandidate(queryer.QueryRow(
		ctx, experienceCandidateSelect+` WHERE candidate.workspace_id = $1 AND candidate.id = $2`,
		workspaceID, candidateID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return ExperienceCandidate{}, ErrNotFound
	}
	if err != nil {
		return ExperienceCandidate{}, ErrServiceUnavailable
	}
	return candidate, nil
}

func scanExperienceCandidate(row rowScanner) (ExperienceCandidate, error) {
	var candidate ExperienceCandidate
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
		&candidate.ID, &candidate.WorkspaceID, &candidate.AgentDefinitionID,
		&candidate.SourceAgentVersionID, &submitter, &device, &candidate.SkillName,
		&candidate.DLPContractVersion, &digest, &bundleDocument, &candidate.CreatedAt,
		&reviewID, &reviewer, &decision, &reasonCode, &safeNote, &reviewedAt,
	); err != nil {
		return ExperienceCandidate{}, err
	}
	if len(digest) != sha256.Size || candidate.DLPContractVersion != ExperienceCandidateDLPVersion {
		return ExperienceCandidate{}, ErrServiceUnavailable
	}
	copy(candidate.ContentDigest[:], digest)
	var bundle ExperienceCandidateBundleV1
	if err := decodeStrictJSON([]byte(bundleDocument), &bundle); err != nil {
		return ExperienceCandidate{}, ErrServiceUnavailable
	}
	canonical, err := CanonicalizeExperienceCandidate(bundle)
	if err != nil || canonical.ContentDigest != candidate.ContentDigest || canonical.Bundle.SkillName != candidate.SkillName {
		return ExperienceCandidate{}, ErrServiceUnavailable
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
			return ExperienceCandidate{}, ErrServiceUnavailable
		}
		review := ExperienceCandidateReview{
			ID: uuid.UUID(reviewID.Bytes), Decision: ExperienceCandidateDecision(decision.String),
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

func validSubmitExperienceCandidate(command SubmitExperienceCandidateCommand) bool {
	if command.CandidateID == uuid.Nil || command.WorkspaceID == uuid.Nil || command.DefinitionID == uuid.Nil ||
		command.SourceVersionID == uuid.Nil || command.SkillName != command.Canonical.Bundle.SkillName ||
		command.DLPVersion != ExperienceCandidateDLPVersion || command.CreatedAt.IsZero() ||
		!validIdempotency(command.Idempotency, command.CreatedAt) || !validAuditEvidence(command.Audit) ||
		len(ScanExperienceCandidate(command.Canonical)) != 0 {
		return false
	}
	canonical, err := CanonicalizeExperienceCandidate(command.Canonical.Bundle)
	return err == nil && canonical.ContentDigest == command.Canonical.ContentDigest &&
		bytes.Equal(canonical.CanonicalJSON, command.Canonical.CanonicalJSON)
}

func validReviewExperienceCandidate(command ReviewExperienceCandidateCommand) bool {
	if command.ReviewID == uuid.Nil || command.WorkspaceID == uuid.Nil || command.CandidateID == uuid.Nil ||
		command.ReviewedAt.IsZero() || !validIdempotency(command.Idempotency, command.ReviewedAt) ||
		!validAuditEvidence(command.Audit) {
		return false
	}
	switch command.Decision {
	case ExperienceCandidateApproved:
		return command.ReasonCode == "" && command.SafeNote == ""
	case ExperienceCandidateRejected:
		return experienceCandidateReasonPattern.MatchString(command.ReasonCode) &&
			(command.SafeNote == "" || validToken(command.SafeNote, 240))
	default:
		return false
	}
}

func recordExperienceCandidateAudit(
	ctx context.Context,
	tx pgx.Tx,
	principal Principal,
	evidence AuditEvidence,
	eventType string,
	outcome audit.Outcome,
	eventReason string,
	candidateID uuid.UUID,
	workspaceID uuid.UUID,
	definitionID uuid.UUID,
	versionID uuid.UUID,
	digest [sha256.Size]byte,
	decision string,
	metadataReason string,
	occurredAt time.Time,
) error {
	recorder, err := audit.NewRecorder(tx)
	if err != nil {
		return ErrServiceUnavailable
	}
	metadata := map[string]string{
		"owner_scope":             string(OwnerScopeWorkspace),
		"workspace_id":            workspaceID.String(),
		"agent_definition_id":     definitionID.String(),
		"agent_version_id":        versionID.String(),
		"experience_candidate_id": candidateID.String(),
		"content_digest":          hex.EncodeToString(digest[:]),
	}
	if decision != "" {
		metadata["decision"] = decision
	}
	if metadataReason != "" {
		metadata["reason_code"] = metadataReason
	}
	actor := principal.UserID
	device := principal.DeviceID
	if err := recorder.Record(ctx, audit.Event{
		ID: evidence.EventID, EventType: eventType, ActorUserID: &actor, DeviceID: &device,
		ObjectType: "experience_candidate", ObjectID: &candidateID, Outcome: outcome,
		ReasonCode: eventReason, RequestID: evidence.RequestID, Metadata: metadata,
		OccurredAt: occurredAt.UTC(),
	}); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}
