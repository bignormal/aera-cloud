package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/bignormal/aera-cloud/internal/account"
	"github.com/bignormal/aera-cloud/internal/encryptedbackup"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	selfRevocationNonceRetention    = 24 * time.Hour
	verificationReceiptRetention    = 11 * time.Minute
	deletionRecoveryWindow          = 7 * 24 * time.Hour
	deletionBatchSize               = 100
	workspaceCleanupBatchSize       = 500
	organizationCleanupBatchSize    = 500
	encryptedBackupCleanupBatchSize = 25
	encryptedBackupRetentionCount   = 3
	encryptedBackupOperationLease   = 10 * time.Minute
	encryptedBackupRetryBase        = 5 * time.Minute
	encryptedBackupRetryMaximum     = time.Hour
)

var ErrMaintenanceUnavailable = errors.New("maintenance storage is unavailable")

type DeletionFinalizer interface {
	FinalizeDeletion(context.Context, uuid.UUID, uuid.UUID, time.Time) error
}

type EncryptedBackupObjectDeleter interface {
	DeleteCiphertexts(context.Context, []encryptedbackup.CiphertextObjectRef) error
}

type EncryptedBackupMaintenance struct {
	postgres *pgxpool.Pool
	objects  EncryptedBackupObjectDeleter
}

func NewEncryptedBackupMaintenance(
	postgres *pgxpool.Pool,
	objects EncryptedBackupObjectDeleter,
) (*EncryptedBackupMaintenance, error) {
	if postgres == nil || objects == nil {
		return nil, errors.New("encrypted backup maintenance dependencies are required")
	}
	return &EncryptedBackupMaintenance{postgres: postgres, objects: objects}, nil
}

func (maintenance *EncryptedBackupMaintenance) Run(
	ctx context.Context,
	now time.Time,
) error {
	if maintenance == nil || maintenance.postgres == nil ||
		maintenance.objects == nil || now.IsZero() {
		return ErrMaintenanceUnavailable
	}
	now = now.UTC()
	if err := maintenance.stageExpiredUploads(ctx, now); err != nil {
		return err
	}
	if err := maintenance.stageRetentionPruning(ctx, now); err != nil {
		return err
	}
	return maintenance.processObjectCleanup(ctx, now)
}

func (maintenance *EncryptedBackupMaintenance) stageExpiredUploads(
	ctx context.Context,
	now time.Time,
) error {
	tx, err := maintenance.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrMaintenanceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	rows, err := tx.Query(ctx, `
		SELECT id, user_id
		FROM encrypted_profile_backups
		WHERE state IN ('initiated', 'uploading')
		  AND upload_expires_at <= $1
		ORDER BY upload_expires_at, id
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`, now, encryptedBackupCleanupBatchSize)
	if err != nil {
		return ErrMaintenanceUnavailable
	}
	type dueUpload struct {
		backupID uuid.UUID
		userID   uuid.UUID
	}
	var due []dueUpload
	for rows.Next() {
		var item dueUpload
		if err := rows.Scan(&item.backupID, &item.userID); err != nil {
			rows.Close()
			return ErrMaintenanceUnavailable
		}
		due = append(due, item)
	}
	rows.Close()
	if rows.Err() != nil {
		return ErrMaintenanceUnavailable
	}
	for _, item := range due {
		objectIDs, err := backupObjectIDs(ctx, tx, item.backupID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE encrypted_profile_backups
			SET state = 'expired',
			    recovery_root_key_envelope = NULL,
			    wrapped_data_key = NULL,
			    deletion_started_at = $2,
			    deleted_at = $2,
			    updated_at = $2
			WHERE id = $1 AND state IN ('initiated', 'uploading')
		`, item.backupID, now); err != nil {
			return ErrMaintenanceUnavailable
		}
		if _, err := tx.Exec(ctx, `
			UPDATE encrypted_backup_key_envelopes
			SET root_key_envelope = NULL,
			    destroyed_at = COALESCE(destroyed_at, $2)
			WHERE backup_id = $1 AND root_key_envelope IS NOT NULL
		`, item.backupID, now); err != nil {
			return ErrMaintenanceUnavailable
		}
		if err := stageBackupOperation(
			ctx,
			tx,
			item.userID,
			item.backupID,
			"expire_upload",
			objectIDs,
			now,
		); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrMaintenanceUnavailable
	}
	return nil
}

func (maintenance *EncryptedBackupMaintenance) stageRetentionPruning(
	ctx context.Context,
	now time.Time,
) error {
	tx, err := maintenance.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrMaintenanceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	rows, err := tx.Query(ctx, `
		SELECT id, user_id
		FROM (
			SELECT id, user_id, sealed_at,
			       row_number() OVER (
			           PARTITION BY user_id, profile_lineage_id
			           ORDER BY sealed_at DESC, id DESC
			       ) AS retention_rank
			FROM encrypted_profile_backups
			WHERE state = 'sealed'
		) AS ranked
		WHERE retention_rank > $1
		ORDER BY sealed_at, id
		LIMIT $2
	`, encryptedBackupRetentionCount, encryptedBackupCleanupBatchSize)
	if err != nil {
		return ErrMaintenanceUnavailable
	}
	type prunableBackup struct {
		backupID uuid.UUID
		userID   uuid.UUID
	}
	var due []prunableBackup
	for rows.Next() {
		var item prunableBackup
		if err := rows.Scan(&item.backupID, &item.userID); err != nil {
			rows.Close()
			return ErrMaintenanceUnavailable
		}
		due = append(due, item)
	}
	rows.Close()
	if rows.Err() != nil {
		return ErrMaintenanceUnavailable
	}
	for _, item := range due {
		objectRows, err := tx.Query(ctx, `
			SELECT object_key
			FROM begin_encrypted_profile_backup_deletion($1, $2, $3)
		`, item.backupID, item.userID, now)
		if err != nil {
			return ErrMaintenanceUnavailable
		}
		var objectIDs []string
		for objectRows.Next() {
			var objectID string
			if err := objectRows.Scan(&objectID); err != nil {
				objectRows.Close()
				return ErrMaintenanceUnavailable
			}
			objectIDs = append(objectIDs, objectID)
		}
		objectRows.Close()
		if objectRows.Err() != nil {
			return ErrMaintenanceUnavailable
		}
		if err := stageBackupOperation(
			ctx,
			tx,
			item.userID,
			item.backupID,
			"prune_lineage",
			objectIDs,
			now,
		); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrMaintenanceUnavailable
	}
	return nil
}

func (maintenance *EncryptedBackupMaintenance) processObjectCleanup(
	ctx context.Context,
	now time.Time,
) error {
	operations, err := maintenance.dueBackupOperations(ctx, now)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		attempt, err := maintenance.beginBackupOperationAttempt(ctx, operation.id, now)
		if err != nil {
			return err
		}
		refs := make([]encryptedbackup.CiphertextObjectRef, 0, len(operation.objectIDs))
		for _, objectID := range operation.objectIDs {
			ref, err := encryptedbackup.NewCiphertextObjectRef(
				operation.userID,
				operation.backupID,
				objectID,
			)
			if err != nil {
				if recordErr := maintenance.failBackupOperation(
					ctx,
					operation.id,
					attempt,
					now,
					"invalid_object_reference",
				); recordErr != nil {
					return recordErr
				}
				return ErrMaintenanceUnavailable
			}
			refs = append(refs, ref)
		}
		if err := maintenance.objects.DeleteCiphertexts(ctx, refs); err != nil {
			if recordErr := maintenance.failBackupOperation(
				ctx,
				operation.id,
				attempt,
				now,
				"object_store_unavailable",
			); recordErr != nil {
				return recordErr
			}
			return ErrMaintenanceUnavailable
		}
		if err := maintenance.completeBackupOperation(
			ctx,
			operation,
			now,
		); err != nil {
			return err
		}
	}
	return nil
}

type dueBackupOperation struct {
	id        uuid.UUID
	userID    uuid.UUID
	backupID  uuid.UUID
	operation string
	objectIDs []string
}

func (maintenance *EncryptedBackupMaintenance) dueBackupOperations(
	ctx context.Context,
	now time.Time,
) ([]dueBackupOperation, error) {
	rows, err := maintenance.postgres.Query(ctx, `
		SELECT id, user_id, backup_id, operation, object_keys
		FROM encrypted_backup_operations
		WHERE (
		        state = 'pending'
		        AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
		      )
		   OR (
		        state = 'running'
		        AND updated_at <= $2
		      )
		ORDER BY created_at, id
		LIMIT $3
	`, now, now.Add(-encryptedBackupOperationLease), encryptedBackupCleanupBatchSize)
	if err != nil {
		return nil, ErrMaintenanceUnavailable
	}
	defer rows.Close()
	operations := make([]dueBackupOperation, 0)
	for rows.Next() {
		var operation dueBackupOperation
		if err := rows.Scan(
			&operation.id,
			&operation.userID,
			&operation.backupID,
			&operation.operation,
			&operation.objectIDs,
		); err != nil {
			return nil, ErrMaintenanceUnavailable
		}
		operations = append(operations, operation)
	}
	if rows.Err() != nil {
		return nil, ErrMaintenanceUnavailable
	}
	return operations, nil
}

func (maintenance *EncryptedBackupMaintenance) beginBackupOperationAttempt(
	ctx context.Context,
	operationID uuid.UUID,
	now time.Time,
) (int, error) {
	var attempt int
	err := maintenance.postgres.QueryRow(ctx, `
		UPDATE encrypted_backup_operations
		SET state = 'running',
		    attempt_count = attempt_count + 1,
		    next_attempt_at = NULL,
		    updated_at = $2
		WHERE id = $1 AND state IN ('pending', 'running')
		RETURNING attempt_count
	`, operationID, now).Scan(&attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrMaintenanceUnavailable
	}
	if err != nil {
		return 0, ErrMaintenanceUnavailable
	}
	return attempt, nil
}

func (maintenance *EncryptedBackupMaintenance) failBackupOperation(
	ctx context.Context,
	operationID uuid.UUID,
	attempt int,
	now time.Time,
	errorCode string,
) error {
	nextAttemptAt := now.Add(encryptedBackupRetryDelay(attempt))
	result, err := maintenance.postgres.Exec(ctx, `
		UPDATE encrypted_backup_operations
		SET state = 'pending',
		    next_attempt_at = $3,
		    last_error_code = $4,
		    updated_at = $2
		WHERE id = $1 AND state = 'running'
	`, operationID, now, nextAttemptAt, errorCode)
	if err != nil || result.RowsAffected() != 1 {
		return ErrMaintenanceUnavailable
	}
	return nil
}

func (maintenance *EncryptedBackupMaintenance) completeBackupOperation(
	ctx context.Context,
	operation dueBackupOperation,
	now time.Time,
) error {
	tx, err := maintenance.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrMaintenanceUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if operation.operation == "delete_backup" ||
		operation.operation == "prune_lineage" {
		if _, err := tx.Exec(ctx, `
			UPDATE encrypted_profile_backups
			SET state = 'deleted', deleted_at = $3, updated_at = $3
			WHERE id = $1 AND user_id = $2 AND state = 'deleting'
		`, operation.backupID, operation.userID, now); err != nil {
			return ErrMaintenanceUnavailable
		}
	}
	result, err := tx.Exec(ctx, `
		UPDATE encrypted_backup_operations
		SET state = 'completed',
		    next_attempt_at = NULL,
		    last_error_code = NULL,
		    completed_at = $2,
		    updated_at = $2
		WHERE id = $1 AND state = 'running'
	`, operation.id, now)
	if err != nil || result.RowsAffected() != 1 {
		return ErrMaintenanceUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrMaintenanceUnavailable
	}
	return nil
}

func backupObjectIDs(
	ctx context.Context,
	tx pgx.Tx,
	backupID uuid.UUID,
) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT object_key
		FROM (
			SELECT manifest_object_key AS object_key
			FROM encrypted_profile_backups
			WHERE id = $1 AND manifest_object_key IS NOT NULL
			UNION ALL
			SELECT object_key
			FROM encrypted_backup_chunks
			WHERE backup_id = $1
		) AS objects
		ORDER BY object_key
	`, backupID)
	if err != nil {
		return nil, ErrMaintenanceUnavailable
	}
	defer rows.Close()
	var objectIDs []string
	for rows.Next() {
		var objectID string
		if err := rows.Scan(&objectID); err != nil {
			return nil, ErrMaintenanceUnavailable
		}
		objectIDs = append(objectIDs, objectID)
	}
	if rows.Err() != nil {
		return nil, ErrMaintenanceUnavailable
	}
	return objectIDs, nil
}

func stageBackupOperation(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	backupID uuid.UUID,
	operation string,
	objectIDs []string,
	now time.Time,
) error {
	var operationID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id
		FROM encrypted_backup_operations
		WHERE backup_id = $1 AND operation = $2
		  AND state IN ('pending', 'running')
		FOR UPDATE
	`, backupID, operation).Scan(&operationID)
	if err == nil {
		if _, err := tx.Exec(ctx, `
			UPDATE encrypted_backup_operations
			SET object_keys = $2, state = 'pending',
			    next_attempt_at = $3, updated_at = $3
			WHERE id = $1
		`, operationID, objectIDs, now); err != nil {
			return ErrMaintenanceUnavailable
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ErrMaintenanceUnavailable
	}
	operationID, err = secure.RandomUUID()
	if err != nil {
		return ErrMaintenanceUnavailable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO encrypted_backup_operations (
			id, user_id, backup_id, operation, state, object_keys,
			attempt_count, next_attempt_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, 0, $6, $6, $6)
	`, operationID, userID, backupID, operation, objectIDs, now); err != nil {
		return ErrMaintenanceUnavailable
	}
	return nil
}

func encryptedBackupRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := encryptedBackupRetryBase
	for index := 1; index < attempt && delay < encryptedBackupRetryMaximum; index++ {
		delay *= 2
	}
	if delay > encryptedBackupRetryMaximum {
		return encryptedBackupRetryMaximum
	}
	return delay
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
