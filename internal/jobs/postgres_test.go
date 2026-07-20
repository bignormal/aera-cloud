package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
