package officialquality

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	qualityOperationKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	qualityServiceSubjectPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)
	qualityReasonPattern         = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
)

type proposalAggregateSource struct {
	ID                uuid.UUID
	PlatformID        uuid.UUID
	DefinitionID      uuid.UUID
	VersionID         uuid.UUID
	ReleaseID         uuid.UUID
	ReleaseRevisionID uuid.UUID
}

func (r *PostgresRepository) CreateProposal(
	ctx context.Context,
	command CreateProposalRepositoryCommand,
) (Proposal, error) {
	if r == nil || r.postgres == nil || !validCreateProposalRepositoryCommand(command) {
		return Proposal{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replayed, found, err := readQualityOperationReplay(ctx, tx, command.Actor, qualityActionProposalCreate, uuid.Nil); err != nil {
		return Proposal{}, err
	} else if found {
		return commitLoadedProposal(ctx, tx, replayed)
	}
	sources, err := loadProposalAggregateSources(
		ctx, tx, command.PlatformID, command.AggregateIDs, command.MinimumSubjects,
	)
	if err != nil {
		return Proposal{}, err
	}
	first := sources[0]
	proof := command.Actor.Operation
	var ticket any
	if proof.TicketReference != "" {
		ticket = proof.TicketReference
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO official_quality_proposals (
			id, platform_id, definition_id, version_id, release_id, release_revision_id,
			problem_categories, improvement_objective, created_by_admin_id, created_by_role,
			status, revision, reason_code, ticket_reference, linked_draft_id,
			created_at, updated_at, terminal_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'developer',
			'open', 1, $10, $11, NULL, $12, $12, NULL)
	`, command.ProposalID, first.PlatformID, first.DefinitionID, first.VersionID,
		first.ReleaseID, first.ReleaseRevisionID, command.ProblemCategories,
		command.ImprovementObjective, command.Actor.AdminID, proof.ReasonCode, ticket,
		command.CreatedAt.UTC()); err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	for position, source := range command.AggregateIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO official_quality_proposal_aggregates (
				proposal_id, aggregate_id, position, created_at
			) VALUES ($1, $2, $3, $4)
		`, command.ProposalID, source, position+1, command.CreatedAt.UTC()); err != nil {
			return Proposal{}, ErrServiceUnavailable
		}
	}
	if err := recordQualityMutation(
		ctx, tx, command.Actor, qualityActionProposalCreate, command.ProposalID,
		ProposalStatusOpen, 1, "", uuid.Nil, command.CreatedAt,
	); err != nil {
		return Proposal{}, err
	}
	value, err := loadProposal(ctx, tx, command.PlatformID, command.ProposalID, false)
	if err != nil {
		return Proposal{}, err
	}
	return commitLoadedProposal(ctx, tx, value)
}

func (r *PostgresRepository) SubmitProposal(
	ctx context.Context,
	command SubmitProposalRepositoryCommand,
) (Proposal, error) {
	if r == nil || r.postgres == nil || command.PlatformID == uuid.Nil || command.ProposalID == uuid.Nil ||
		command.ExpectedRevision <= 0 || command.SubmittedAt.IsZero() ||
		!validQualityMutationActor(command.Actor, qualityActionProposalSubmit, command.ProposalID, command.ExpectedRevision) {
		return Proposal{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replayed, found, err := readQualityOperationReplay(ctx, tx, command.Actor, qualityActionProposalSubmit, command.ProposalID); err != nil {
		return Proposal{}, err
	} else if found {
		return commitLoadedProposal(ctx, tx, replayed)
	}
	current, err := loadProposal(ctx, tx, command.PlatformID, command.ProposalID, true)
	if err != nil {
		return Proposal{}, err
	}
	if current.Status != ProposalStatusOpen || current.Revision != command.ExpectedRevision {
		return Proposal{}, ErrProposalStateConflict
	}
	if _, err := tx.Exec(ctx, `
		UPDATE official_quality_proposals
		SET status = 'submitted', revision = revision + 1, updated_at = $4
		WHERE id = $1 AND platform_id = $2 AND revision = $3 AND status = 'open'
	`, command.ProposalID, command.PlatformID, command.ExpectedRevision, command.SubmittedAt.UTC()); err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	resultRevision := command.ExpectedRevision + 1
	if err := recordQualityMutation(
		ctx, tx, command.Actor, qualityActionProposalSubmit, command.ProposalID,
		ProposalStatusSubmitted, resultRevision, "", uuid.Nil, command.SubmittedAt,
	); err != nil {
		return Proposal{}, err
	}
	value, err := loadProposal(ctx, tx, command.PlatformID, command.ProposalID, false)
	if err != nil {
		return Proposal{}, err
	}
	return commitLoadedProposal(ctx, tx, value)
}

func (r *PostgresRepository) ReviewProposal(
	ctx context.Context,
	command ReviewProposalRepositoryCommand,
) (Proposal, error) {
	if r == nil || r.postgres == nil || command.ReviewID == uuid.Nil || command.PlatformID == uuid.Nil ||
		command.ProposalID == uuid.Nil || command.ExpectedRevision <= 0 || command.ReviewedAt.IsZero() ||
		(command.Decision != ProposalReviewApprove && command.Decision != ProposalReviewReject) ||
		!validQualityMutationActor(command.Actor, qualityActionProposalReview, command.ProposalID, command.ExpectedRevision) {
		return Proposal{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replayed, found, err := readQualityOperationReplay(ctx, tx, command.Actor, qualityActionProposalReview, command.ProposalID); err != nil {
		return Proposal{}, err
	} else if found {
		return commitLoadedProposal(ctx, tx, replayed)
	}
	current, err := loadProposal(ctx, tx, command.PlatformID, command.ProposalID, true)
	if err != nil {
		return Proposal{}, err
	}
	if current.Status != ProposalStatusSubmitted || current.Revision != command.ExpectedRevision {
		return Proposal{}, ErrProposalStateConflict
	}
	if current.CreatedByAdminID == command.Actor.AdminID {
		return Proposal{}, ErrAdminForbidden
	}
	proof := command.Actor.Operation
	var ticket any
	if proof.TicketReference != "" {
		ticket = proof.TicketReference
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO official_quality_proposal_reviews (
			id, platform_id, proposal_id, reviewer_admin_id, reviewer_role,
			decision, reviewed_revision, reason_code, ticket_reference, reviewed_at
		) VALUES ($1, $2, $3, $4, 'super_admin', $5, $6, $7, $8, $9)
	`, command.ReviewID, command.PlatformID, command.ProposalID, command.Actor.AdminID,
		command.Decision, command.ExpectedRevision, proof.ReasonCode, ticket, command.ReviewedAt.UTC()); err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	status := ProposalStatusApproved
	if command.Decision == ProposalReviewReject {
		status = ProposalStatusRejected
	}
	if _, err := tx.Exec(ctx, `
		UPDATE official_quality_proposals
		SET status = $4, revision = revision + 1, updated_at = $5, terminal_at = $5
		WHERE id = $1 AND platform_id = $2 AND revision = $3 AND status = 'submitted'
	`, command.ProposalID, command.PlatformID, command.ExpectedRevision, status, command.ReviewedAt.UTC()); err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	resultRevision := command.ExpectedRevision + 1
	if err := recordQualityMutation(
		ctx, tx, command.Actor, qualityActionProposalReview, command.ProposalID,
		status, resultRevision, command.Decision, uuid.Nil, command.ReviewedAt,
	); err != nil {
		return Proposal{}, err
	}
	value, err := loadProposal(ctx, tx, command.PlatformID, command.ProposalID, false)
	if err != nil {
		return Proposal{}, err
	}
	return commitLoadedProposal(ctx, tx, value)
}

func (r *PostgresRepository) LinkProposalDraft(
	ctx context.Context,
	command LinkProposalDraftRepositoryCommand,
) (Proposal, error) {
	if r == nil || r.postgres == nil || command.PlatformID == uuid.Nil || command.ProposalID == uuid.Nil ||
		command.DraftID == uuid.Nil || command.ExpectedRevision <= 0 || command.LinkedAt.IsZero() ||
		!validQualityMutationActor(command.Actor, qualityActionDraftClone, command.ProposalID, command.ExpectedRevision) {
		return Proposal{}, ErrInvalidRequest
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replayed, found, err := readQualityOperationReplay(ctx, tx, command.Actor, qualityActionDraftClone, command.ProposalID); err != nil {
		return Proposal{}, err
	} else if found {
		return commitLoadedProposal(ctx, tx, replayed)
	}
	current, err := loadProposal(ctx, tx, command.PlatformID, command.ProposalID, true)
	if err != nil {
		return Proposal{}, err
	}
	if current.Status != ProposalStatusApproved || current.Revision != command.ExpectedRevision {
		return Proposal{}, ErrProposalStateConflict
	}
	var draftMatches bool
	if err := tx.QueryRow(ctx, `
		SELECT draft.platform_id = proposal.platform_id
		   AND draft.definition_id = proposal.definition_id
		   AND draft.base_version_id = proposal.version_id
		   AND draft.kind = 'next'
		   AND draft.status = 'active'
		   AND draft.content_digest = version.content_digest
		FROM platform_agent_drafts draft
		JOIN official_quality_proposals proposal ON proposal.id = $2
		JOIN agent_versions version ON version.id = proposal.version_id
		WHERE draft.id = $1 AND draft.platform_id = $3
	`, command.DraftID, command.ProposalID, command.PlatformID).Scan(&draftMatches); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Proposal{}, ErrProposalStateConflict
		}
		return Proposal{}, ErrServiceUnavailable
	}
	if !draftMatches {
		return Proposal{}, ErrProposalStateConflict
	}
	if _, err := tx.Exec(ctx, `
		UPDATE official_quality_proposals
		SET status = 'draft_linked', linked_draft_id = $4,
			revision = revision + 1, updated_at = $5
		WHERE id = $1 AND platform_id = $2 AND revision = $3 AND status = 'approved'
	`, command.ProposalID, command.PlatformID, command.ExpectedRevision,
		command.DraftID, command.LinkedAt.UTC()); err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	resultRevision := command.ExpectedRevision + 1
	if err := recordQualityMutation(
		ctx, tx, command.Actor, qualityActionDraftClone, command.ProposalID,
		ProposalStatusDraftLinked, resultRevision, "", command.DraftID, command.LinkedAt,
	); err != nil {
		return Proposal{}, err
	}
	value, err := loadProposal(ctx, tx, command.PlatformID, command.ProposalID, false)
	if err != nil {
		return Proposal{}, err
	}
	return commitLoadedProposal(ctx, tx, value)
}

func (r *PostgresRepository) GetProposal(
	ctx context.Context,
	platformID uuid.UUID,
	proposalID uuid.UUID,
) (Proposal, error) {
	if r == nil || r.postgres == nil || platformID == uuid.Nil || proposalID == uuid.Nil {
		return Proposal{}, ErrInvalidRequest
	}
	return loadProposal(ctx, r.postgres, platformID, proposalID, false)
}

func (r *PostgresRepository) ListProposals(
	ctx context.Context,
	filter ProposalFilter,
	page ProposalPageRequest,
) (ProposalPage, error) {
	if r == nil || r.postgres == nil || filter.PlatformID == uuid.Nil || !validProposalStatusFilter(filter.Status) ||
		page.Limit < 1 || page.Limit > 100 {
		return ProposalPage{}, ErrInvalidRequest
	}
	args := []any{filter.PlatformID}
	query := `SELECT id FROM official_quality_proposals WHERE platform_id = $1`
	if filter.Status != "" {
		args = append(args, filter.Status)
		query += ` AND status = $2`
	}
	if page.After != uuid.Nil {
		args = append(args, page.After)
		query += fmt.Sprintf(" AND id < $%d", len(args))
	}
	args = append(args, page.Limit+1)
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))
	rows, err := r.postgres.Query(ctx, query, args...)
	if err != nil {
		return ProposalPage{}, ErrServiceUnavailable
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0, page.Limit+1)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return ProposalPage{}, ErrServiceUnavailable
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return ProposalPage{}, ErrServiceUnavailable
	}
	next := uuid.Nil
	if len(ids) > page.Limit {
		next = ids[page.Limit-1]
		ids = ids[:page.Limit]
	}
	items := make([]Proposal, 0, len(ids))
	for _, id := range ids {
		value, err := loadProposal(ctx, r.postgres, filter.PlatformID, id, false)
		if err != nil {
			return ProposalPage{}, err
		}
		items = append(items, value)
	}
	return ProposalPage{Items: items, Next: next}, nil
}

type proposalQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadProposal(
	ctx context.Context,
	queryer proposalQueryer,
	platformID uuid.UUID,
	proposalID uuid.UUID,
	forUpdate bool,
) (Proposal, error) {
	query := `
		SELECT id, platform_id, definition_id, version_id, release_id, release_revision_id,
			problem_categories, improvement_objective, created_by_admin_id, created_by_role,
			status, revision, reason_code, ticket_reference, linked_draft_id,
			created_at, updated_at, terminal_at
		FROM official_quality_proposals
		WHERE platform_id = $1 AND id = $2
	`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var value Proposal
	var ticket pgtype.Text
	var linked pgtype.UUID
	var terminal pgtype.Timestamptz
	if err := queryer.QueryRow(ctx, query, platformID, proposalID).Scan(
		&value.ID, &value.PlatformID, &value.DefinitionID, &value.VersionID,
		&value.ReleaseID, &value.ReleaseRevisionID, &value.ProblemCategories,
		&value.ImprovementObjective, &value.CreatedByAdminID, &value.CreatedByRole,
		&value.Status, &value.Revision, &value.ReasonCode, &ticket, &linked,
		&value.CreatedAt, &value.UpdatedAt, &terminal,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Proposal{}, ErrProposalNotFound
		}
		return Proposal{}, ErrServiceUnavailable
	}
	if ticket.Valid {
		value.TicketReference = ticket.String
	}
	if linked.Valid {
		value.LinkedDraftID = uuid.UUID(linked.Bytes)
	}
	if terminal.Valid {
		terminalTime := terminal.Time.UTC()
		value.TerminalAt = &terminalTime
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	rows, err := queryer.Query(ctx, `
		SELECT aggregate_id
		FROM official_quality_proposal_aggregates
		WHERE proposal_id = $1
		ORDER BY position
	`, proposalID)
	if err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	value.AggregateIDs = make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return Proposal{}, ErrServiceUnavailable
		}
		value.AggregateIDs = append(value.AggregateIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Proposal{}, ErrServiceUnavailable
	}
	rows.Close()
	var review ProposalReview
	var reviewTicket pgtype.Text
	err = queryer.QueryRow(ctx, `
		SELECT id, reviewer_admin_id, reviewer_role, decision, reviewed_revision,
			reason_code, ticket_reference, reviewed_at
		FROM official_quality_proposal_reviews
		WHERE platform_id = $1 AND proposal_id = $2
	`, platformID, proposalID).Scan(
		&review.ID, &review.ReviewerAdminID, &review.ReviewerRole, &review.Decision,
		&review.ReviewedRevision, &review.ReasonCode, &reviewTicket, &review.ReviewedAt,
	)
	if err == nil {
		if reviewTicket.Valid {
			review.TicketReference = reviewTicket.String
		}
		review.ReviewedAt = review.ReviewedAt.UTC()
		value.Review = &review
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Proposal{}, ErrServiceUnavailable
	}
	if value.ProblemCategories == nil {
		value.ProblemCategories = []string{}
	}
	return value, nil
}

func loadProposalAggregateSources(
	ctx context.Context,
	tx pgx.Tx,
	platformID uuid.UUID,
	ids []uuid.UUID,
	minimumSubjects int,
) ([]proposalAggregateSource, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, platform_id, definition_id, version_id, release_id, release_revision_id
		FROM official_quality_daily_aggregates
		WHERE id = ANY($1::uuid[]) AND platform_id = $2
		  AND is_suppressed = FALSE AND distinct_subject_count >= $3
		FOR SHARE
	`, ids, platformID, minimumSubjects)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer rows.Close()
	byID := make(map[uuid.UUID]proposalAggregateSource, len(ids))
	for rows.Next() {
		var value proposalAggregateSource
		if err := rows.Scan(
			&value.ID, &value.PlatformID, &value.DefinitionID, &value.VersionID,
			&value.ReleaseID, &value.ReleaseRevisionID,
		); err != nil {
			return nil, ErrServiceUnavailable
		}
		byID[value.ID] = value
	}
	if err := rows.Err(); err != nil || len(byID) != len(ids) {
		return nil, ErrInvalidRequest
	}
	result := make([]proposalAggregateSource, len(ids))
	for index, id := range ids {
		value, ok := byID[id]
		if !ok {
			return nil, ErrInvalidRequest
		}
		if index > 0 {
			first := result[0]
			if value.PlatformID != first.PlatformID || value.DefinitionID != first.DefinitionID ||
				value.VersionID != first.VersionID || value.ReleaseID != first.ReleaseID ||
				value.ReleaseRevisionID != first.ReleaseRevisionID {
				return nil, ErrInvalidRequest
			}
		}
		result[index] = value
	}
	return result, nil
}

func readQualityOperationReplay(
	ctx context.Context,
	tx pgx.Tx,
	actor QualityAdminActor,
	action string,
	targetID uuid.UUID,
) (Proposal, bool, error) {
	proof := actor.Operation
	rows, err := tx.Query(ctx, `
		SELECT operation_id, idempotency_key_id, idempotency_key_hmac,
			request_fingerprint, service_subject, actor_admin_id, actor_admin_role,
			request_id, action, target_type, target_id, expected_revision,
			result_revision, status, reason_code, ticket_reference
		FROM admin_operations
		WHERE operation_id = $1
		   OR (idempotency_key_id = $2 AND idempotency_key_hmac = $3)
		FOR UPDATE
	`, proof.OperationID, proof.IdempotencyKeyID, proof.IdempotencyKeyHMAC)
	if err != nil {
		return Proposal{}, false, ErrServiceUnavailable
	}
	defer rows.Close()
	type operation struct {
		ID, ActorID, TargetID                                               uuid.UUID
		KeyID, Subject, Role, RequestID, Action, TargetType, Status, Reason string
		KeyHMAC, Fingerprint                                                []byte
		Expected, Result                                                    int64
		Ticket                                                              pgtype.Text
	}
	var operations []operation
	for rows.Next() {
		var value operation
		if err := rows.Scan(
			&value.ID, &value.KeyID, &value.KeyHMAC, &value.Fingerprint,
			&value.Subject, &value.ActorID, &value.Role, &value.RequestID,
			&value.Action, &value.TargetType, &value.TargetID, &value.Expected,
			&value.Result, &value.Status, &value.Reason, &value.Ticket,
		); err != nil {
			return Proposal{}, false, ErrServiceUnavailable
		}
		operations = append(operations, value)
	}
	if err := rows.Err(); err != nil {
		return Proposal{}, false, ErrServiceUnavailable
	}
	if len(operations) == 0 {
		return Proposal{}, false, nil
	}
	if len(operations) != 1 {
		return Proposal{}, false, ErrConflict
	}
	stored := operations[0]
	ticket := ""
	if stored.Ticket.Valid {
		ticket = stored.Ticket.String
	}
	if stored.ID != proof.OperationID || stored.KeyID != proof.IdempotencyKeyID ||
		!bytes.Equal(stored.KeyHMAC, proof.IdempotencyKeyHMAC) ||
		!bytes.Equal(stored.Fingerprint, proof.RequestFingerprint) ||
		stored.Subject != proof.ServiceSubject || stored.ActorID != actor.AdminID ||
		stored.Role != actor.Role || stored.RequestID != actor.RequestID || stored.Action != action ||
		stored.TargetType != "official_quality_proposal" || stored.Expected != proof.ExpectedRevision ||
		stored.Status != "succeeded" || stored.Result <= 0 || stored.Reason != proof.ReasonCode ||
		ticket != proof.TicketReference || (targetID != uuid.Nil && stored.TargetID != targetID) {
		return Proposal{}, false, ErrConflict
	}
	var platformID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT platform_id FROM official_quality_proposals WHERE id = $1
	`, stored.TargetID).Scan(&platformID); err != nil {
		return Proposal{}, false, ErrServiceUnavailable
	}
	value, err := loadProposal(ctx, tx, platformID, stored.TargetID, false)
	if err != nil {
		return Proposal{}, false, err
	}
	value.Replayed = true
	return value, true, nil
}

func recordQualityMutation(
	ctx context.Context,
	tx pgx.Tx,
	actor QualityAdminActor,
	action string,
	proposalID uuid.UUID,
	status ProposalStatus,
	resultRevision int64,
	decision string,
	draftID uuid.UUID,
	occurredAt time.Time,
) error {
	proof := actor.Operation
	metadata := map[string]any{
		"actor_admin_id": actor.AdminID.String(), "actor_admin_role": actor.Role,
		"status": status, "revision": resultRevision,
	}
	if decision != "" {
		metadata["decision"] = decision
	}
	if draftID != uuid.Nil {
		metadata["linked_draft_id"] = draftID.String()
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return ErrServiceUnavailable
	}
	eventType := map[string]string{
		qualityActionProposalCreate: "official_quality_proposal_created",
		qualityActionProposalSubmit: "official_quality_proposal_submitted",
		qualityActionProposalReview: "official_quality_proposal_reviewed",
		qualityActionDraftClone:     "official_quality_draft_cloned",
	}[action]
	if eventType == "" {
		return ErrInvalidRequest
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, object_type, object_id, outcome, reason_code,
			request_id, metadata, created_at
		) VALUES ($1, $2, 'official_quality_proposal', $3, 'success', $4, $5, $6::jsonb, $7)
	`, uuid.New(), eventType, proposalID, proof.ReasonCode, actor.RequestID,
		string(encoded), occurredAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	var ticket any
	if proof.TicketReference != "" {
		ticket = proof.TicketReference
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_operations (
			operation_id, idempotency_key_id, idempotency_key_hmac, request_fingerprint,
			service_subject, actor_admin_id, actor_admin_role, approval_id, request_id,
			action, target_type, target_id, expected_revision, result_revision, status,
			reason_code, ticket_reference, created_at, updated_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8,
			$9, 'official_quality_proposal', $10, $11, $12, 'succeeded',
			$13, $14, $15, $15, $15)
	`, proof.OperationID, proof.IdempotencyKeyID, proof.IdempotencyKeyHMAC,
		proof.RequestFingerprint, proof.ServiceSubject, actor.AdminID, actor.Role,
		actor.RequestID, action, proposalID, proof.ExpectedRevision, resultRevision,
		proof.ReasonCode, ticket, occurredAt.UTC()); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func commitLoadedProposal(ctx context.Context, tx pgx.Tx, value Proposal) (Proposal, error) {
	if err := tx.Commit(ctx); err != nil {
		return Proposal{}, ErrServiceUnavailable
	}
	return cloneProposal(value), nil
}

func validCreateProposalRepositoryCommand(command CreateProposalRepositoryCommand) bool {
	aggregateIDs, idsOK := validAggregateIDs(command.AggregateIDs)
	categories, categoriesOK := canonicalProblemCategories(command.ProblemCategories)
	return command.ProposalID != uuid.Nil && command.PlatformID != uuid.Nil && idsOK && categoriesOK &&
		slices.Equal(aggregateIDs, command.AggregateIDs) && slices.Equal(categories, command.ProblemCategories) &&
		validQualityText(command.ImprovementObjective, 20, 2000) && command.MinimumSubjects >= 10 &&
		MinimizedScanner{}.Scan([]byte(command.ImprovementObjective)) == nil &&
		!command.CreatedAt.IsZero() &&
		validQualityMutationActor(command.Actor, qualityActionProposalCreate, command.ProposalID, 1)
}

func validQualityMutationActor(actor QualityAdminActor, action string, targetID uuid.UUID, expectedRevision int64) bool {
	if !qualityActorAllowed(actor, action) || actor.Operation == nil {
		return false
	}
	proof := actor.Operation
	return proof.OperationID != uuid.Nil && proof.Action == action &&
		proof.TargetType == "official_quality_proposal" && proof.TargetID == targetID &&
		proof.ExpectedRevision == expectedRevision && qualityServiceSubjectPattern.MatchString(proof.ServiceSubject) &&
		qualityOperationKeyIDPattern.MatchString(proof.IdempotencyKeyID) &&
		len(proof.IdempotencyKeyHMAC) == 32 && len(proof.RequestFingerprint) == 32 &&
		qualityReasonPattern.MatchString(proof.ReasonCode) &&
		(proof.TicketReference == "" || validQualityText(proof.TicketReference, 1, 128))
}

func validProposalStatusFilter(status ProposalStatus) bool {
	switch status {
	case "", ProposalStatusOpen, ProposalStatusSubmitted, ProposalStatusApproved,
		ProposalStatusRejected, ProposalStatusDraftLinked, ProposalStatusClosed:
		return true
	default:
		return false
	}
}

func cloneProposal(value Proposal) Proposal {
	value.AggregateIDs = slices.Clone(value.AggregateIDs)
	value.ProblemCategories = slices.Clone(value.ProblemCategories)
	if value.Review != nil {
		review := *value.Review
		value.Review = &review
	}
	if value.TerminalAt != nil {
		terminal := *value.TerminalAt
		value.TerminalAt = &terminal
	}
	return value
}
