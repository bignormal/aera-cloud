package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/account"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	selfRevocationNonceRetention = 24 * time.Hour
	verificationReceiptRetention = 11 * time.Minute
	deletionRecoveryWindow       = 7 * 24 * time.Hour
	deletionBatchSize            = 100
	workspaceCleanupBatchSize    = 500
	organizationCleanupBatchSize = 500
)

var ErrMaintenanceUnavailable = errors.New("maintenance storage is unavailable")

type DeletionFinalizer interface {
	FinalizeDeletion(context.Context, uuid.UUID, uuid.UUID, time.Time) error
}

type PostgresMaintenance struct {
	postgres  *pgxpool.Pool
	finalizer DeletionFinalizer
}

func NewPostgresMaintenance(postgres *pgxpool.Pool, finalizer DeletionFinalizer) (*PostgresMaintenance, error) {
	if postgres == nil || finalizer == nil {
		return nil, errors.New("PostgreSQL maintenance dependencies are required")
	}
	return &PostgresMaintenance{postgres: postgres, finalizer: finalizer}, nil
}

// Run works exclusively on cloud database rows. It has no filesystem or
// runtime dependency, so account cleanup cannot enumerate or mutate Hermes
// sessions, Memory, skills, files, profiles, or other desktop state.
func (m *PostgresMaintenance) Run(ctx context.Context, now time.Time) error {
	if m == nil || m.postgres == nil || m.finalizer == nil || now.IsZero() {
		return ErrMaintenanceUnavailable
	}
	now = now.UTC()
	if err := m.cleanupExpiredRows(ctx, now); err != nil {
		return err
	}
	userIDs, err := m.dueDeletionUserIDs(ctx, now)
	if err != nil {
		return err
	}
	for _, userID := range userIDs {
		auditEventID, err := uuid.NewRandom()
		if err != nil {
			return ErrMaintenanceUnavailable
		}
		err = m.finalizer.FinalizeDeletion(ctx, userID, auditEventID, now)
		if errors.Is(err, account.ErrAccountNotFound) || errors.Is(err, account.ErrDeletionWindowExpired) {
			// The account may have been recovered after the due-user snapshot.
			continue
		}
		if err != nil {
			return ErrMaintenanceUnavailable
		}
	}
	return nil
}

func (m *PostgresMaintenance) cleanupExpiredRows(ctx context.Context, now time.Time) error {
	tx, err := m.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrMaintenanceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	statements := []struct {
		query string
		args  []any
	}{
		{`WITH due AS (
			SELECT id
			FROM workspace_invitations
			WHERE status = 'pending' AND expires_at <= $1
			ORDER BY expires_at, id
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE workspace_invitations invitation
		SET status = 'expired'
		FROM due
		WHERE invitation.id = due.id`, []any{now, workspaceCleanupBatchSize}},
		{`WITH due AS (
			SELECT actor_user_id, operation, key_digest
			FROM workspace_idempotency_records
			WHERE expires_at <= $1
			ORDER BY expires_at, actor_user_id, operation, key_digest
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM workspace_idempotency_records record
		USING due
		WHERE record.actor_user_id = due.actor_user_id
		  AND record.operation = due.operation
		  AND record.key_digest = due.key_digest`, []any{now, workspaceCleanupBatchSize}},
		{`WITH due AS (
			SELECT id
			FROM organization_invitations
			WHERE status = 'pending' AND expires_at <= $1
			ORDER BY expires_at, id
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE organization_invitations invitation
		SET status = 'expired'
		FROM due
		WHERE invitation.id = due.id`, []any{now, organizationCleanupBatchSize}},
		{`WITH due AS (
			SELECT actor_user_id, operation, key_digest
			FROM organization_idempotency_records
			WHERE expires_at <= $1
			ORDER BY expires_at, actor_user_id, operation, key_digest
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM organization_idempotency_records record
		USING due
		WHERE record.actor_user_id = due.actor_user_id
		  AND record.operation = due.operation
		  AND record.key_digest = due.key_digest`, []any{now, organizationCleanupBatchSize}},
		{`DELETE FROM verification_challenges
			WHERE receipt_consumed_at IS NOT NULL
			   OR (consumed_at IS NULL AND expires_at <= $1)
			   OR consumed_at <= $2`, []any{now, now.Add(-verificationReceiptRetention)}},
		{`DELETE FROM authorization_codes WHERE expires_at <= $1`, []any{now}},
		{`DELETE FROM oauth_requests WHERE expires_at <= $1`, []any{now}},
		{`DELETE FROM sessions WHERE expires_at <= $1`, []any{now}},
		{`DELETE FROM device_self_revocation_nonces WHERE used_at <= $1`, []any{now.Add(-selfRevocationNonceRetention)}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			return ErrMaintenanceUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrMaintenanceUnavailable
	}
	return nil
}

func (m *PostgresMaintenance) dueDeletionUserIDs(ctx context.Context, now time.Time) ([]uuid.UUID, error) {
	rows, err := m.postgres.Query(ctx, `
		SELECT id
		FROM users
		WHERE status = 'pending_deletion' AND deletion_requested_at <= $1
		ORDER BY deletion_requested_at, id
		LIMIT $2
	`, now.Add(-deletionRecoveryWindow), deletionBatchSize)
	if err != nil {
		return nil, ErrMaintenanceUnavailable
	}
	defer rows.Close()
	userIDs := make([]uuid.UUID, 0)
	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return nil, ErrMaintenanceUnavailable
		}
		userIDs = append(userIDs, userID)
	}
	if rows.Err() != nil {
		return nil, ErrMaintenanceUnavailable
	}
	return userIDs, nil
}
