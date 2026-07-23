package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/encryptedbackup"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresMaintenanceExpiresOnlyDueWorkspaceRowsInBoundedTransaction(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate workspace maintenance fixture: %v", err)
	}
	now := time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
	ownerID := uuid.New()
	workspaceID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, nickname, status, created_at, updated_at)
		VALUES ($1, 'Maintenance Owner', 'active', $2, $2)
	`, ownerID, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("insert workspace maintenance user: %v", err)
	}
	tx, err := postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin workspace maintenance fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Maintenance Workspace', 'active', 1, $3, $3)
	`, workspaceID, ownerID, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("insert workspace: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, workspaceID, ownerID, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("insert workspace Owner: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit workspace fixture: %v", err)
	}
	dueInvitationID := uuid.New()
	validInvitationID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO workspace_invitations (
			id, workspace_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES
			($1, $3, $4, $6, 'pending', $7, $8),
			($2, $3, $5, $6, 'pending', $9, $10)
	`, dueInvitationID, validInvitationID, workspaceID, bytes.Repeat([]byte{0xb1}, 32), bytes.Repeat([]byte{0xb2}, 32),
		ownerID, now.Add(-8*24*time.Hour), now.Add(-24*time.Hour), now, now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("insert workspace invitations: %v", err)
	}
	dueKey := bytes.Repeat([]byte{0xb3}, 32)
	validKey := bytes.Repeat([]byte{0xb4}, 32)
	if _, err := postgres.Exec(ctx, `
		INSERT INTO workspace_idempotency_records (
			actor_user_id, workspace_id, operation, key_digest, request_digest,
			resource_type, resource_id, created_at, expires_at
		) VALUES
			($1, $2, 'workspace_create', $3, $5, 'workspace', $2, $7, $8),
			($1, $2, 'workspace_invitation_create', $4, $6, 'workspace_invitation', $9, $10, $11)
	`, ownerID, workspaceID, dueKey, validKey, bytes.Repeat([]byte{0xb5}, 32), bytes.Repeat([]byte{0xb6}, 32),
		now.Add(-25*time.Hour), now.Add(-time.Hour), validInvitationID, now, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert workspace idempotency rows: %v", err)
	}
	bulkTx, err := postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin bounded cleanup fixture: %v", err)
	}
	defer func() { _ = bulkTx.Rollback(context.Background()) }()
	for index := 1; index < workspaceCleanupBatchSize+1; index++ {
		invitationDigest := sha256.Sum256([]byte(fmt.Sprintf("due-invitation-%d", index)))
		invitationCreatedAt := now.Add(-8*24*time.Hour - time.Duration(index)*time.Second)
		if _, err := bulkTx.Exec(ctx, `
			INSERT INTO workspace_invitations (
				id, workspace_id, token_digest, created_by_user_id, status, created_at, expires_at
			) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
		`, uuid.New(), workspaceID, invitationDigest[:], ownerID, invitationCreatedAt,
			invitationCreatedAt.Add(7*24*time.Hour)); err != nil {
			t.Fatalf("insert due invitation %d: %v", index, err)
		}
		keyDigest := sha256.Sum256([]byte(fmt.Sprintf("due-idempotency-key-%d", index)))
		requestDigest := sha256.Sum256([]byte(fmt.Sprintf("due-idempotency-request-%d", index)))
		idempotencyCreatedAt := now.Add(-25*time.Hour - time.Duration(index)*time.Second)
		if _, err := bulkTx.Exec(ctx, `
			INSERT INTO workspace_idempotency_records (
				actor_user_id, workspace_id, operation, key_digest, request_digest,
				resource_type, resource_id, created_at, expires_at
			) VALUES ($1, $2, 'workspace_create', $3, $4, 'workspace', $2, $5, $6)
		`, ownerID, workspaceID, keyDigest[:], requestDigest[:], idempotencyCreatedAt,
			idempotencyCreatedAt.Add(24*time.Hour)); err != nil {
			t.Fatalf("insert due idempotency %d: %v", index, err)
		}
	}
	if err := bulkTx.Commit(ctx); err != nil {
		t.Fatalf("commit bounded cleanup fixture: %v", err)
	}

	maintenance, err := NewPostgresMaintenance(postgres, &fakeDeletionFinalizer{})
	if err != nil {
		t.Fatalf("NewPostgresMaintenance() error = %v", err)
	}
	if err := maintenance.Run(ctx, now); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var validStatus string
	if err := postgres.QueryRow(ctx, `SELECT status FROM workspace_invitations WHERE id = $1`, validInvitationID).Scan(&validStatus); err != nil {
		t.Fatalf("read valid invitation: %v", err)
	}
	var expiredInvitationCount int
	var overduePendingInvitationCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM workspace_invitations WHERE expires_at <= $1 AND status = 'expired'`, now).Scan(&expiredInvitationCount); err != nil {
		t.Fatalf("count expired invitations: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM workspace_invitations WHERE expires_at <= $1 AND status = 'pending'`, now).Scan(&overduePendingInvitationCount); err != nil {
		t.Fatalf("count overdue pending invitations: %v", err)
	}
	if expiredInvitationCount != workspaceCleanupBatchSize || overduePendingInvitationCount != 1 || validStatus != "pending" {
		t.Fatalf("invitation states expired=%d overdue_pending=%d valid=%s", expiredInvitationCount, overduePendingInvitationCount, validStatus)
	}
	var overdueIdempotencyCount int
	var validCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM workspace_idempotency_records WHERE expires_at <= $1`, now).Scan(&overdueIdempotencyCount); err != nil {
		t.Fatalf("count overdue idempotency: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM workspace_idempotency_records WHERE key_digest = $1`, validKey).Scan(&validCount); err != nil {
		t.Fatalf("count valid idempotency: %v", err)
	}
	if overdueIdempotencyCount != 1 || validCount != 1 {
		t.Fatalf("idempotency rows overdue=%d valid=%d", overdueIdempotencyCount, validCount)
	}
}

func TestPostgresMaintenanceExpiresOnlyDueOrganizationRowsInBoundedTransaction(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate Organization maintenance fixture: %v", err)
	}
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	ownerID := uuid.New()
	organizationID := uuid.New()
	policyID := uuid.New()
	dissolvedOrganizationID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, nickname, status, created_at, updated_at)
		VALUES ($1, 'Organization Maintenance Owner', 'active', $2, $2)
	`, ownerID, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("insert Organization maintenance user: %v", err)
	}
	tx, err := postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin Organization maintenance fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO organizations (
			id, display_name, status, revision, current_policy_snapshot_id, created_at, updated_at
		) VALUES ($1, 'Maintenance Organization', 'active', 1, $2, $3, $3)
	`, organizationID, policyID, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("insert Organization: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_memberships (organization_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, organizationID, ownerID, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("insert Organization Owner: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_policy_snapshots (
			id, organization_id, policy_version, schema_version, policy_document, content_digest,
			issuer, signing_key_id, signature, issued_by_user_id, created_at
		) VALUES ($1, $2, 1, 1, '{}'::jsonb, $3, 'https://accounts.example.com', 'organization-v1', $4, $5, $6)
	`, policyID, organizationID, bytes.Repeat([]byte{0xc1}, 32), bytes.Repeat([]byte{0xc2}, 64), ownerID,
		now.Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("insert Organization policy: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organizations (
			id, display_name, status, revision, created_at, updated_at, archived_at, dissolved_at
		) VALUES ($1, 'Dissolved Organization', 'dissolved', 2, $2, $2, $2, $2)
	`, dissolvedOrganizationID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert dissolved Organization: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit Organization fixture: %v", err)
	}

	dueInvitationID := uuid.New()
	validInvitationID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO organization_invitations (
			id, organization_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES
			($1, $3, $4, $6, 'pending', $7, $8),
			($2, $3, $5, $6, 'pending', $9, $10)
	`, dueInvitationID, validInvitationID, organizationID, bytes.Repeat([]byte{0xd1}, 32), bytes.Repeat([]byte{0xd2}, 32),
		ownerID, now.Add(-8*24*time.Hour), now.Add(-24*time.Hour), now, now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("insert Organization invitations: %v", err)
	}
	dueKey := bytes.Repeat([]byte{0xd3}, 32)
	dissolutionKey := bytes.Repeat([]byte{0xd4}, 32)
	if _, err := postgres.Exec(ctx, `
		INSERT INTO organization_idempotency_records (
			actor_user_id, organization_id, operation, key_digest, request_digest,
			resource_type, resource_id, created_at, expires_at
		) VALUES
			($1, $2, 'organization_create', $3, $5, 'organization', $2, $7, $8),
			($1, $4, 'organization_dissolve', $6, $9, 'organization', $4, $10, $11)
	`, ownerID, organizationID, dueKey, dissolvedOrganizationID, bytes.Repeat([]byte{0xd5}, 32), dissolutionKey,
		now.Add(-25*time.Hour), now.Add(-time.Hour), bytes.Repeat([]byte{0xd6}, 32), now.Add(-23*time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatalf("insert Organization idempotency rows: %v", err)
	}
	bulkTx, err := postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin bounded Organization cleanup fixture: %v", err)
	}
	defer func() { _ = bulkTx.Rollback(context.Background()) }()
	for index := 1; index < 501; index++ {
		invitationDigest := sha256.Sum256([]byte(fmt.Sprintf("due-organization-invitation-%d", index)))
		invitationCreatedAt := now.Add(-8*24*time.Hour - time.Duration(index)*time.Second)
		if _, err := bulkTx.Exec(ctx, `
			INSERT INTO organization_invitations (
				id, organization_id, token_digest, created_by_user_id, status, created_at, expires_at
			) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
		`, uuid.New(), organizationID, invitationDigest[:], ownerID, invitationCreatedAt,
			invitationCreatedAt.Add(7*24*time.Hour)); err != nil {
			t.Fatalf("insert due Organization invitation %d: %v", index, err)
		}
		keyDigest := sha256.Sum256([]byte(fmt.Sprintf("due-organization-idempotency-key-%d", index)))
		requestDigest := sha256.Sum256([]byte(fmt.Sprintf("due-organization-idempotency-request-%d", index)))
		idempotencyCreatedAt := now.Add(-25*time.Hour - time.Duration(index)*time.Second)
		if _, err := bulkTx.Exec(ctx, `
			INSERT INTO organization_idempotency_records (
				actor_user_id, organization_id, operation, key_digest, request_digest,
				resource_type, resource_id, created_at, expires_at
			) VALUES ($1, $2, 'organization_create', $3, $4, 'organization', $2, $5, $6)
		`, ownerID, organizationID, keyDigest[:], requestDigest[:], idempotencyCreatedAt,
			idempotencyCreatedAt.Add(24*time.Hour)); err != nil {
			t.Fatalf("insert due Organization idempotency %d: %v", index, err)
		}
	}
	if err := bulkTx.Commit(ctx); err != nil {
		t.Fatalf("commit bounded Organization cleanup fixture: %v", err)
	}

	maintenance, err := NewPostgresMaintenance(postgres, &fakeDeletionFinalizer{})
	if err != nil {
		t.Fatalf("NewPostgresMaintenance() error = %v", err)
	}
	if err := maintenance.Run(ctx, now); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var validStatus string
	if err := postgres.QueryRow(ctx, `SELECT status FROM organization_invitations WHERE id = $1`, validInvitationID).Scan(&validStatus); err != nil {
		t.Fatalf("read valid Organization invitation: %v", err)
	}
	var expiredInvitationCount int
	var overduePendingInvitationCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM organization_invitations WHERE expires_at <= $1 AND status = 'expired'`, now).Scan(&expiredInvitationCount); err != nil {
		t.Fatalf("count expired Organization invitations: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM organization_invitations WHERE expires_at <= $1 AND status = 'pending'`, now).Scan(&overduePendingInvitationCount); err != nil {
		t.Fatalf("count overdue pending Organization invitations: %v", err)
	}
	if expiredInvitationCount != 500 || overduePendingInvitationCount != 1 || validStatus != "pending" {
		t.Fatalf("Organization invitation states expired=%d overdue_pending=%d valid=%s", expiredInvitationCount, overduePendingInvitationCount, validStatus)
	}
	var overdueIdempotencyCount int
	var dissolutionReplayCount int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM organization_idempotency_records WHERE expires_at <= $1`, now).Scan(&overdueIdempotencyCount); err != nil {
		t.Fatalf("count overdue Organization idempotency: %v", err)
	}
	if err := postgres.QueryRow(ctx, `
		SELECT count(*) FROM organization_idempotency_records
		WHERE organization_id = $1 AND operation = 'organization_dissolve' AND key_digest = $2
	`, dissolvedOrganizationID, dissolutionKey).Scan(&dissolutionReplayCount); err != nil {
		t.Fatalf("count retained dissolution replay: %v", err)
	}
	if overdueIdempotencyCount != 1 || dissolutionReplayCount != 1 {
		t.Fatalf("Organization idempotency overdue=%d dissolution_replay=%d", overdueIdempotencyCount, dissolutionReplayCount)
	}
}

func TestEncryptedBackupMaintenanceExpiresUploadAfterDestroyingEnvelopes(t *testing.T) {
	fixture := newBackupMaintenanceFixture(t)
	dueID := fixture.insertBackup(t, backupMaintenanceRecord{
		state: "initiated", lineageID: uuid.New(),
		createdAt:       fixture.now.Add(-25 * time.Hour),
		uploadExpiresAt: fixture.now.Add(-time.Hour),
	})
	validID := fixture.insertBackup(t, backupMaintenanceRecord{
		state: "uploading", lineageID: uuid.New(),
		createdAt:       fixture.now.Add(-time.Hour),
		uploadExpiresAt: fixture.now.Add(23 * time.Hour),
	})
	objects := &recordingBackupObjectDeleter{
		postgres: fixture.postgres, expectedBackupID: dueID,
	}
	maintenance, err := NewEncryptedBackupMaintenance(fixture.postgres, objects)
	if err != nil {
		t.Fatalf("NewEncryptedBackupMaintenance() error = %v", err)
	}
	if err := maintenance.Run(fixture.ctx, fixture.now); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !objects.sawDestroyedEnvelopes || len(objects.deletedObjectIDs) != 2 {
		t.Fatalf("object cleanup ordering/objects = %v/%v",
			objects.sawDestroyedEnvelopes, objects.deletedObjectIDs)
	}
	assertBackupState(t, fixture, dueID, "expired")
	assertBackupState(t, fixture, validID, "uploading")
	var operationState string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT state FROM encrypted_backup_operations
		WHERE backup_id = $1 AND operation = 'expire_upload'
	`, dueID).Scan(&operationState); err != nil {
		t.Fatalf("read expire operation: %v", err)
	}
	if operationState != "completed" {
		t.Fatalf("expire operation state = %q", operationState)
	}
}

func TestEncryptedBackupMaintenancePrunesOnlyOldestBeyondThreePerLineage(t *testing.T) {
	fixture := newBackupMaintenanceFixture(t)
	lineageID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		ALTER TABLE encrypted_profile_backups
		DISABLE TRIGGER encrypted_profile_backup_guard_trigger
	`); err != nil {
		t.Fatalf("disable quota trigger for defensive retention fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = fixture.postgres.Exec(context.Background(), `
			ALTER TABLE encrypted_profile_backups
			ENABLE TRIGGER encrypted_profile_backup_guard_trigger
		`)
	})
	backupIDs := make([]uuid.UUID, 0, 4)
	for index := range 4 {
		backupIDs = append(backupIDs, fixture.insertBackup(t, backupMaintenanceRecord{
			state: "sealed", lineageID: lineageID,
			createdAt:       fixture.now.Add(time.Duration(index-10) * time.Hour),
			uploadExpiresAt: fixture.now.Add(time.Duration(index+14) * time.Hour),
		}))
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		ALTER TABLE encrypted_profile_backups
		ENABLE TRIGGER encrypted_profile_backup_guard_trigger
	`); err != nil {
		t.Fatalf("re-enable quota trigger: %v", err)
	}
	objects := &recordingBackupObjectDeleter{postgres: fixture.postgres}
	maintenance, err := NewEncryptedBackupMaintenance(fixture.postgres, objects)
	if err != nil {
		t.Fatalf("NewEncryptedBackupMaintenance() error = %v", err)
	}
	if err := maintenance.Run(fixture.ctx, fixture.now); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertBackupState(t, fixture, backupIDs[0], "deleted")
	for _, backupID := range backupIDs[1:] {
		assertBackupState(t, fixture, backupID, "sealed")
	}
	if len(objects.deletedObjectIDs) != 2 {
		t.Fatalf("pruned object count = %d, want oldest manifest and chunk", len(objects.deletedObjectIDs))
	}
}

func TestEncryptedBackupMaintenanceRetriesDeletionWithoutRestoringEnvelopes(t *testing.T) {
	fixture := newBackupMaintenanceFixture(t)
	backupID := fixture.insertBackup(t, backupMaintenanceRecord{
		state: "sealed", lineageID: uuid.New(),
		createdAt:       fixture.now.Add(-time.Hour),
		uploadExpiresAt: fixture.now.Add(23 * time.Hour),
	})
	rows, err := fixture.postgres.Query(fixture.ctx, `
		SELECT object_key
		FROM begin_encrypted_profile_backup_deletion($1, $2, $3)
	`, backupID, fixture.userID, fixture.now)
	if err != nil {
		t.Fatalf("begin deleting fixture: %v", err)
	}
	var objectIDs []string
	for rows.Next() {
		var objectID string
		if err := rows.Scan(&objectID); err != nil {
			t.Fatalf("scan deleting fixture object: %v", err)
		}
		objectIDs = append(objectIDs, objectID)
	}
	rows.Close()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO encrypted_backup_operations (
			id, user_id, backup_id, operation, state, object_keys,
			attempt_count, next_attempt_at, created_at, updated_at
		) VALUES ($1, $2, $3, 'delete_backup', 'pending', $4, 0, $5, $5, $5)
	`, uuid.New(), fixture.userID, backupID, objectIDs, fixture.now); err != nil {
		t.Fatalf("insert pending deletion operation: %v", err)
	}
	objects := &recordingBackupObjectDeleter{
		postgres: fixture.postgres, expectedBackupID: backupID,
		err: errors.New("object store temporarily unavailable"),
	}
	maintenance, err := NewEncryptedBackupMaintenance(fixture.postgres, objects)
	if err != nil {
		t.Fatalf("NewEncryptedBackupMaintenance() error = %v", err)
	}
	if err := maintenance.Run(fixture.ctx, fixture.now); !errors.Is(err, ErrMaintenanceUnavailable) {
		t.Fatalf("first Run() error = %v, want ErrMaintenanceUnavailable", err)
	}
	assertBackupState(t, fixture, backupID, "deleting")
	assertBackupEnvelopesDestroyed(t, fixture, backupID)
	var operationState string
	var attemptCount int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT state, attempt_count FROM encrypted_backup_operations
		WHERE backup_id = $1 AND operation = 'delete_backup'
	`, backupID).Scan(&operationState, &attemptCount); err != nil {
		t.Fatalf("read failed deletion operation: %v", err)
	}
	if operationState != "pending" || attemptCount != 1 {
		t.Fatalf("failed deletion operation = %s/%d", operationState, attemptCount)
	}

	objects.err = nil
	if err := maintenance.Run(fixture.ctx, fixture.now.Add(15*time.Minute)); err != nil {
		t.Fatalf("retry Run() error = %v", err)
	}
	assertBackupState(t, fixture, backupID, "deleted")
	assertBackupEnvelopesDestroyed(t, fixture, backupID)
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT state, attempt_count FROM encrypted_backup_operations
		WHERE backup_id = $1 AND operation = 'delete_backup'
	`, backupID).Scan(&operationState, &attemptCount); err != nil {
		t.Fatalf("read completed deletion operation: %v", err)
	}
	if operationState != "completed" || attemptCount != 2 {
		t.Fatalf("completed deletion operation = %s/%d", operationState, attemptCount)
	}
}

type backupMaintenanceFixture struct {
	ctx            context.Context
	postgres       *pgxpool.Pool
	now            time.Time
	userID         uuid.UUID
	deviceID       uuid.UUID
	installationID uuid.UUID
	definitionID   uuid.UUID
	versionID      uuid.UUID
	backupDeviceID uuid.UUID
}

type backupMaintenanceRecord struct {
	state           string
	lineageID       uuid.UUID
	createdAt       time.Time
	uploadExpiresAt time.Time
}

func newBackupMaintenanceFixture(t *testing.T) *backupMaintenanceFixture {
	t.Helper()
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	t.Cleanup(postgres.Close)
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate backup maintenance fixture: %v", err)
	}
	fixture := &backupMaintenanceFixture{
		ctx: ctx, postgres: postgres,
		now:    time.Date(2026, 7, 23, 5, 0, 0, 0, time.UTC),
		userID: uuid.New(), deviceID: uuid.New(), installationID: uuid.New(),
		definitionID: uuid.New(), versionID: uuid.New(), backupDeviceID: uuid.New(),
	}
	spaceID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, status, created_at, updated_at)
		VALUES ($1, 'active', $2, $2)
	`, fixture.userID, fixture.now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("seed backup maintenance user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (
			id, owner_user_id, display_name, status, created_at, updated_at
		) VALUES ($1, $2, 'Backup maintenance', 'active', $3, $3)
	`, spaceID, fixture.userID, fixture.now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("seed backup maintenance personal space: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform,
			app_version, status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Maintenance Mac', 'darwin',
			'0.7.3', 'active', $5, $5, $5)
	`, fixture.deviceID, fixture.userID, uuid.New(),
		bytes.Repeat([]byte{0x81}, 32), fixture.now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("seed backup maintenance identity: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO agent_definitions (
			id, tenant_id, owner_scope, owner_id, display_name, status,
			created_by, created_at, updated_at
		) VALUES ($1, $2, 'USER', $3, 'Maintenance Agent', 'active', $3, $4, $4)
	`, fixture.definitionID, spaceID, fixture.userID,
		fixture.now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("seed backup maintenance definition: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO agent_versions (
			id, definition_id, tenant_id, owner_scope, owner_id, version_number,
			canonical_manifest, bundle, content_digest, signing_key_id, signature,
			runtime_minimum_version, published_by, published_at
		) VALUES (
			$1, $2, $3, 'USER', $4, 1, '{"schema_version":1}'::jsonb,
			'{"assets":[]}'::jsonb, $5, 'maintenance', $6,
			'0.18.2-agentera.1', $4, $7
		)
	`, fixture.versionID, fixture.definitionID, spaceID, fixture.userID,
		bytes.Repeat([]byte{0x82}, 32), bytes.Repeat([]byte{0x83}, 64),
		fixture.now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("seed backup maintenance version: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO installations (
			id, tenant_id, owner_scope, owner_id, device_id,
			device_installation_id, definition_id, selected_version_id,
			update_policy, status, created_by, created_at, updated_at
		) VALUES (
			$1, $2, 'USER', $3, $4, $5, $6, $7,
			'manual', 'pending', $3, $8, $8
		)
	`, fixture.installationID, spaceID, fixture.userID, fixture.deviceID,
		uuid.New(), fixture.definitionID, fixture.versionID,
		fixture.now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("seed backup maintenance USER-owned agent: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO backup_devices (
			id, user_id, device_id, key_epoch, public_key,
			registration_signature, revision, status, created_at, updated_at
		) VALUES ($1, $2, $3, 1, $4, $5, 1, 'active', $6, $6)
	`, fixture.backupDeviceID, fixture.userID, fixture.deviceID,
		bytes.Repeat([]byte{0x84}, 32), bytes.Repeat([]byte{0x85}, 64),
		fixture.now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("seed backup maintenance device key: %v", err)
	}
	return fixture
}

func (fixture *backupMaintenanceFixture) insertBackup(
	t *testing.T,
	record backupMaintenanceRecord,
) uuid.UUID {
	t.Helper()
	backupID := uuid.New()
	manifestKey := fmt.Sprintf("%064x", backupID.ID())
	chunkKeyDigest := sha256.Sum256([]byte("chunk-" + backupID.String()))
	chunkKey := fmt.Sprintf("%x", chunkKeyDigest[:])
	insertState := record.state
	if record.state == "sealed" {
		insertState = "initiated"
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO encrypted_profile_backups (
			id, user_id, source_device_id, source_installation_id,
			source_definition_id, source_version_id, profile_lineage_id,
			format_version, cipher_suite, state, chunk_count, total_ciphertext_size,
			manifest_object_key, manifest_ciphertext_digest, manifest_ciphertext_size,
			public_envelope_digest, public_signature, recovery_salt,
			recovery_memory_kib, recovery_iterations, recovery_parallelism,
			recovery_root_key_envelope, wrapped_data_key,
			created_at, updated_at, upload_expires_at, sealed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, 1, $8, $9, 1, 64,
			$10, $11, 48, $12, $13, $14, 65536, 3, 1,
			$15, $16, $17, $17, $18, NULL
		)
	`, backupID, fixture.userID, fixture.deviceID, fixture.installationID,
		fixture.definitionID, fixture.versionID, record.lineageID,
		encryptedbackup.BackupCipherSuite, insertState, manifestKey,
		bytes.Repeat([]byte{0x91}, 32), bytes.Repeat([]byte{0x92}, 32),
		bytes.Repeat([]byte{0x93}, 64), bytes.Repeat([]byte{0x94}, 16),
		bytes.Repeat([]byte{0x95}, 64), bytes.Repeat([]byte{0x96}, 64),
		record.createdAt, record.uploadExpiresAt); err != nil {
		t.Fatalf("insert backup maintenance metadata: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO encrypted_backup_chunks (
			backup_id, chunk_index, object_key, ciphertext_digest,
			ciphertext_size, created_at
		) VALUES ($1, 0, $2, $3, 64, $4)
	`, backupID, chunkKey, bytes.Repeat([]byte{0x97}, 32), record.createdAt); err != nil {
		t.Fatalf("insert backup maintenance chunk: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO encrypted_backup_key_envelopes (
			id, backup_id, backup_device_id, key_epoch,
			root_key_envelope, root_key_envelope_digest, created_at
		) VALUES ($1, $2, $3, 1, $4, $5, $6)
	`, uuid.New(), backupID, fixture.backupDeviceID,
		bytes.Repeat([]byte{0x98}, 64), bytes.Repeat([]byte{0x99}, 32),
		record.createdAt); err != nil {
		t.Fatalf("insert backup maintenance key envelope: %v", err)
	}
	if record.state == "sealed" {
		sealedAt := record.createdAt.Add(time.Minute)
		if _, err := fixture.postgres.Exec(fixture.ctx, `
			UPDATE encrypted_profile_backups
			SET state = 'sealed', sealed_at = $2, updated_at = $2
			WHERE id = $1
		`, backupID, sealedAt); err != nil {
			t.Fatalf("seal backup maintenance record: %v", err)
		}
	}
	return backupID
}

type recordingBackupObjectDeleter struct {
	postgres              *pgxpool.Pool
	expectedBackupID      uuid.UUID
	deletedObjectIDs      []string
	sawDestroyedEnvelopes bool
	err                   error
}

func (deleter *recordingBackupObjectDeleter) DeleteCiphertexts(
	ctx context.Context,
	refs []encryptedbackup.CiphertextObjectRef,
) error {
	if deleter.expectedBackupID != uuid.Nil {
		var remaining int
		if err := deleter.postgres.QueryRow(ctx, `
			SELECT
				(CASE WHEN recovery_root_key_envelope IS NULL
					AND wrapped_data_key IS NULL THEN 0 ELSE 1 END)
				+ (SELECT count(*) FROM encrypted_backup_key_envelopes
				   WHERE backup_id = $1 AND root_key_envelope IS NOT NULL)
			FROM encrypted_profile_backups
			WHERE id = $1
		`, deleter.expectedBackupID).Scan(&remaining); err == nil && remaining == 0 {
			deleter.sawDestroyedEnvelopes = true
		}
	}
	for _, ref := range refs {
		deleter.deletedObjectIDs = append(deleter.deletedObjectIDs, ref.ObjectID())
	}
	return deleter.err
}

func assertBackupState(
	t *testing.T,
	fixture *backupMaintenanceFixture,
	backupID uuid.UUID,
	expected string,
) {
	t.Helper()
	var state string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT state FROM encrypted_profile_backups WHERE id = $1
	`, backupID).Scan(&state); err != nil {
		t.Fatalf("read backup %s state: %v", backupID, err)
	}
	if state != expected {
		t.Fatalf("backup %s state = %q, want %q", backupID, state, expected)
	}
}

func assertBackupEnvelopesDestroyed(
	t *testing.T,
	fixture *backupMaintenanceFixture,
	backupID uuid.UUID,
) {
	t.Helper()
	var remaining int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT
			(CASE WHEN recovery_root_key_envelope IS NULL
				AND wrapped_data_key IS NULL THEN 0 ELSE 1 END)
			+ (SELECT count(*) FROM encrypted_backup_key_envelopes
			   WHERE backup_id = $1 AND root_key_envelope IS NOT NULL)
		FROM encrypted_profile_backups
		WHERE id = $1
	`, backupID).Scan(&remaining); err != nil {
		t.Fatalf("inspect destroyed envelopes: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("backup %s retained %d key envelopes", backupID, remaining)
	}
}
