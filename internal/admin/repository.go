package admin

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	postgres *pgxpool.Pool
}

func NewPostgresRepository(postgres *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{postgres: postgres}
}

func (r *PostgresRepository) DisableAccount(ctx context.Context, mutation Mutation) error {
	if r == nil || r.postgres == nil || !validUserMutation(mutation) {
		return ErrInvalidCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockTargetUser(ctx, tx, mutation.TargetUserID); err != nil {
		return err
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR UPDATE`, mutation.TargetUserID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return ErrUnavailable
	}
	if status != "active" {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET status = 'disabled', administratively_disabled = TRUE, updated_at = $2 WHERE id = $1
	`, mutation.TargetUserID, mutation.OccurredAt); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE personal_spaces SET status = 'disabled', updated_at = $2 WHERE owner_user_id = $1
	`, mutation.TargetUserID, mutation.OccurredAt); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2), updated_at = $2
		WHERE user_id = $1
	`, mutation.TargetUserID, mutation.OccurredAt); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2),
			revoked_reason = COALESCE(revoked_reason, 'account_admin_disabled')
		WHERE user_id = $1
	`, mutation.TargetUserID, mutation.OccurredAt); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE offline_entitlement_issuances SET revoked_at = COALESCE(revoked_at, $2) WHERE user_id = $1
	`, mutation.TargetUserID, mutation.OccurredAt); err != nil {
		return ErrUnavailable
	}
	if err := insertOperatorAudit(ctx, tx, mutation, "account_disabled", "user", mutation.TargetUserID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *PostgresRepository) EnableAccount(ctx context.Context, mutation Mutation) error {
	if r == nil || r.postgres == nil || !validUserMutation(mutation) {
		return ErrInvalidCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockTargetUser(ctx, tx, mutation.TargetUserID); err != nil {
		return err
	}
	var status string
	var administrativelyDisabled bool
	var deletionFinalized bool
	if err := tx.QueryRow(ctx, `
		SELECT status, administratively_disabled, deletion_finalized_at IS NOT NULL
		FROM users WHERE id = $1 FOR UPDATE
	`, mutation.TargetUserID).Scan(&status, &administrativelyDisabled, &deletionFinalized); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return ErrUnavailable
	}
	if status != "disabled" || !administrativelyDisabled || deletionFinalized {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET status = 'active', administratively_disabled = FALSE, updated_at = $2 WHERE id = $1
	`, mutation.TargetUserID, mutation.OccurredAt); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `
		UPDATE personal_spaces SET status = 'active', updated_at = $2 WHERE owner_user_id = $1
	`, mutation.TargetUserID, mutation.OccurredAt); err != nil {
		return ErrUnavailable
	}
	if err := insertOperatorAudit(ctx, tx, mutation, "account_enabled", "user", mutation.TargetUserID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *PostgresRepository) RevokeSession(ctx context.Context, mutation Mutation) error {
	if r == nil || r.postgres == nil || !validSessionMutation(mutation) {
		return ErrInvalidCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var userID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT user_id FROM sessions WHERE id = $1`, mutation.SessionID).Scan(&userID); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return ErrUnavailable
	}
	if err := lockTargetUser(ctx, tx, userID); err != nil {
		return err
	}
	var lockedUserID, familyID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT user_id, family_id FROM sessions WHERE id = $1 FOR UPDATE
	`, mutation.SessionID).Scan(&lockedUserID, &familyID); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return ErrUnavailable
	}
	if lockedUserID != userID {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2),
			revoked_reason = COALESCE(revoked_reason, 'admin_revoked')
		WHERE family_id = $1
	`, familyID, mutation.OccurredAt); err != nil {
		return ErrUnavailable
	}
	mutation.TargetUserID = userID
	if err := insertOperatorAudit(ctx, tx, mutation, "session_admin_revoked", "session", mutation.SessionID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *PostgresRepository) Audit(ctx context.Context, query AuditQuery) ([]RedactedAuditEvent, error) {
	if r == nil || r.postgres == nil || !validAuditQuery(query) {
		return nil, ErrInvalidCommand
	}
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockTargetUser(ctx, tx, query.TargetUserID); err != nil {
		return nil, err
	}
	var eligible bool
	if err := tx.QueryRow(ctx, `
		SELECT deletion_finalized_at IS NULL FROM users WHERE id = $1 FOR SHARE
	`, query.TargetUserID).Scan(&eligible); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, ErrUnavailable
	}
	if !eligible {
		return nil, ErrNotFound
	}
	rows, err := tx.Query(ctx, `
		SELECT id, event_type, outcome, COALESCE(reason_code, ''), COALESCE(object_type, ''), created_at
		FROM audit_events
		WHERE subject_user_id = $1 OR actor_user_id = $1 OR (object_type = 'user' AND object_id = $1)
		ORDER BY created_at DESC, id
		LIMIT $2
	`, query.TargetUserID, query.Limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	events := make([]RedactedAuditEvent, 0)
	for rows.Next() {
		var event RedactedAuditEvent
		if err := rows.Scan(&event.ID, &event.EventType, &event.Outcome, &event.ReasonCode, &event.ObjectType, &event.OccurredAt); err != nil {
			rows.Close()
			return nil, ErrUnavailable
		}
		events = append(events, event)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	mutation := Mutation{
		Operator: query.Operator, TargetUserID: query.TargetUserID,
		AuditEventID: query.AuditEventID, OccurredAt: query.OccurredAt,
	}
	if err := insertOperatorAudit(ctx, tx, mutation, "admin_audit_lookup", "user", query.TargetUserID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrUnavailable
	}
	return events, nil
}

func insertOperatorAudit(
	ctx context.Context,
	tx pgx.Tx,
	mutation Mutation,
	eventType string,
	objectType string,
	objectID uuid.UUID,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, operator_identity, subject_user_id, object_type, object_id,
			outcome, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'success', '{}'::jsonb, $7)
	`, mutation.AuditEventID, eventType, mutation.Operator, mutation.TargetUserID,
		objectType, objectID, mutation.OccurredAt)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func validUserMutation(mutation Mutation) bool {
	_, operatorOK := normalizeOperator(mutation.Operator)
	return operatorOK && mutation.TargetUserID != uuid.Nil && mutation.AuditEventID != uuid.Nil && !mutation.OccurredAt.IsZero()
}

func validSessionMutation(mutation Mutation) bool {
	_, operatorOK := normalizeOperator(mutation.Operator)
	return operatorOK && mutation.SessionID != uuid.Nil && mutation.AuditEventID != uuid.Nil && !mutation.OccurredAt.IsZero()
}

func validAuditQuery(query AuditQuery) bool {
	_, operatorOK := normalizeOperator(query.Operator)
	return operatorOK && query.TargetUserID != uuid.Nil && query.AuditEventID != uuid.Nil &&
		!query.OccurredAt.IsZero() && query.Limit >= 1 && query.Limit <= 200
}

func lockTargetUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	lockID := int64(binary.BigEndian.Uint64(userID[:8]))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return ErrUnavailable
	}
	return nil
}
