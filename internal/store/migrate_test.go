package store

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestApplyMigrationsCreatesAuthSchemaAndIsIdempotent(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()

	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("second ApplyMigrations() error = %v", err)
	}

	tables := []string{
		"users",
		"identities",
		"password_credentials",
		"personal_spaces",
		"devices",
		"sessions",
		"verification_challenges",
		"oauth_requests",
		"authorization_codes",
		"offline_entitlement_issuances",
		"audit_events",
		"legal_acceptances",
		"device_self_revocation_nonces",
		"agent_definitions",
		"agent_versions",
		"agent_version_revocations",
		"installations",
		"policy_snapshots",
		"runtime_binding_records",
		"agent_control_idempotency_keys",
		"workspaces",
		"workspace_memberships",
		"workspace_invitations",
		"workspace_idempotency_records",
		"experience_candidates",
		"experience_candidate_reviews",
	}
	for _, table := range tables {
		var exists bool
		if err := postgres.QueryRow(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s does not exist", table)
		}
	}

	assertUniqueConstraint(t, ctx, postgres, "identities", "identities_kind_lookup_hmac_key", []string{"kind", "lookup_hmac"})
	assertUniqueConstraint(t, ctx, postgres, "devices", "devices_installation_id_key", []string{"installation_id"})
	assertUniqueConstraint(t, ctx, postgres, "identities", "identities_user_id_kind_key", []string{"user_id", "kind"})
	assertUniqueConstraint(t, ctx, postgres, "agent_versions", "agent_versions_definition_version_key", []string{"definition_id", "version_number"})
	assertUniqueConstraint(t, ctx, postgres, "agent_version_revocations", "agent_version_revocations_version_key", []string{"version_id"})
	assertUniqueConstraint(t, ctx, postgres, "policy_snapshots", "policy_snapshots_installation_version_key", []string{"installation_id", "policy_version"})
	assertUniqueConstraint(t, ctx, postgres, "experience_candidates", "experience_candidates_id_workspace_key", []string{"id", "workspace_id"})
	assertUniqueConstraint(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_candidate_id_key", []string{"candidate_id"})
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_content_digest_length_check", "octet_length(content_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_signature_length_check", "octet_length(signature) = 64")
	assertCheckConstraintContains(t, ctx, postgres, "policy_snapshots", "policy_snapshots_content_digest_length_check", "octet_length(content_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "policy_snapshots", "policy_snapshots_signature_length_check", "octet_length(signature) = 64")
	assertCheckConstraintContains(t, ctx, postgres, "runtime_binding_records", "runtime_binding_records_tool_digest_length_check", "octet_length(tool_permission_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_key_hash_length_check", "octet_length(key_hash) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_request_hash_length_check", "octet_length(request_hash) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "installations", "installations_lifecycle_check", "runtime_profile_id")
	assertCheckConstraintExcludes(t, ctx, postgres, "installations", "installations_lifecycle_check", "policy_snapshot_id IS NULL")
	assertCheckConstraintContains(t, ctx, postgres, "installations", "installations_status_check", "pending")
	assertCheckConstraintContains(t, ctx, postgres, "installations", "installations_update_policy_check", "manual")
	assertCheckConstraintContains(t, ctx, postgres, "workspaces", "workspaces_display_name_check", "char_length(btrim(display_name))")
	assertCheckConstraintContains(t, ctx, postgres, "workspaces", "workspaces_lifecycle_check", "archived_at")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_memberships", "workspace_memberships_role_check", "owner")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_token_digest_length_check", "octet_length(token_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_expiry_check", "expires_at")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_lifecycle_check", "accepted_by_user_id")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_idempotency_records", "workspace_idempotency_key_digest_length_check", "octet_length(key_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_idempotency_records", "workspace_idempotency_request_digest_length_check", "octet_length(request_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "workspace_idempotency_records", "workspace_idempotency_expiry_check", "expires_at")
	assertCheckConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_owner_variant_check", "WORKSPACE")
	assertCheckConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_owner_variant_check", "workspace_id")
	assertCheckConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_owner_variant_check", "WORKSPACE")
	assertCheckConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_owner_variant_check", "WORKSPACE")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_kind_check", "SKILL")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_skill_name_check", "char_length(skill_name)")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_schema_version_check", "schema_version = 1")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_dlp_contract_version_check", "experience-candidate-dlp-v1")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_content_digest_length_check", "octet_length(content_digest) = 32")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_bundle_document_check", "jsonb_typeof(bundle_document)")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_decision_check", "APPROVED")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_decision_check", "REJECTED")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_rejection_check", "reason_code")
	assertCheckConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_rejection_check", "safe_note")

	assertForeignKeyConstraintContains(t, ctx, postgres, "workspaces", "workspaces_owner_user_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "workspace_memberships", "workspace_memberships_workspace_fk", "ON DELETE CASCADE")
	assertForeignKeyConstraintContains(t, ctx, postgres, "workspace_memberships", "workspace_memberships_user_fk", "ON DELETE CASCADE")
	assertForeignKeyConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_created_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "workspace_invitations", "workspace_invitations_accepted_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_definitions", "agent_definitions_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_versions", "agent_versions_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_workspace_fk", "ON DELETE CASCADE")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_definition_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_source_version_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_submitted_by_user_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidates", "experience_candidates_submitted_from_device_fk", "ON DELETE SET NULL")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_candidate_workspace_fk", "ON DELETE RESTRICT")
	assertForeignKeyConstraintContains(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_reviewed_by_user_fk", "ON DELETE SET NULL")

	assertIndexDefinitionContains(t, ctx, postgres, "workspace_memberships_one_owner_idx", "UNIQUE", "workspace_id", "WHERE", "owner")
	assertIndexDefinitionContains(t, ctx, postgres, "workspaces_owner_active_idx", "owner_user_id", "WHERE", "active")
	assertIndexDefinitionContains(t, ctx, postgres, "workspace_memberships_user_list_idx", "user_id", "workspace_id")
	assertIndexDefinitionContains(t, ctx, postgres, "workspace_invitations_pending_idx", "workspace_id", "expires_at", "pending")
	assertIndexDefinitionContains(t, ctx, postgres, "workspace_idempotency_expiry_idx", "expires_at")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_control_idempotency_user_operation_key", "UNIQUE", "tenant_id", "owner_id", "operation", "key_hash", "USER")
	assertIndexDefinitionContains(t, ctx, postgres, "agent_control_idempotency_workspace_operation_key", "UNIQUE", "workspace_id", "operation", "key_hash", "WORKSPACE")
	assertIndexDefinitionContains(t, ctx, postgres, "experience_candidates_workspace_created_idx", "workspace_id", "created_at", "id")
	assertIndexDefinitionContains(t, ctx, postgres, "experience_candidates_submitter_created_idx", "submitted_by_user_id", "created_at")
	assertIndexDefinitionContains(t, ctx, postgres, "experience_candidates_definition_created_idx", "agent_definition_id", "created_at")
	assertIndexDefinitionContains(t, ctx, postgres, "experience_candidate_reviews_workspace_reviewed_idx", "workspace_id", "reviewed_at", "candidate_id")

	assertColumns(t, ctx, postgres, "agent_definitions", []string{
		"id", "tenant_id", "owner_scope", "owner_id", "display_name", "icon_media_type", "icon_data",
		"status", "latest_version_id", "created_by", "created_at", "updated_at", "workspace_id",
	})
	assertColumns(t, ctx, postgres, "agent_versions", []string{
		"id", "definition_id", "tenant_id", "owner_scope", "owner_id", "version_number",
		"canonical_manifest", "bundle", "content_digest", "signing_key_id", "signature",
		"runtime_minimum_version", "runtime_maximum_version_exclusive", "published_by", "published_at", "workspace_id",
	})
	assertColumns(t, ctx, postgres, "agent_control_idempotency_keys", []string{"workspace_id"})
	for _, table := range []string{"agent_definitions", "agent_versions", "agent_control_idempotency_keys"} {
		assertColumnNullable(t, ctx, postgres, table, "tenant_id", true)
		assertColumnNullable(t, ctx, postgres, table, "owner_id", true)
		assertColumnNullable(t, ctx, postgres, table, "workspace_id", true)
	}
	assertColumns(t, ctx, postgres, "installations", []string{
		"id", "tenant_id", "owner_scope", "owner_id", "device_id", "device_installation_id",
		"definition_id", "selected_version_id", "runtime_profile_id", "policy_snapshot_id", "update_policy",
		"status", "created_by", "created_at", "updated_at", "activated_at", "archived_at",
	})
	assertColumns(t, ctx, postgres, "workspaces", []string{
		"id", "owner_user_id", "display_name", "status", "revision", "created_at", "updated_at", "archived_at",
	})
	assertColumns(t, ctx, postgres, "workspace_memberships", []string{
		"workspace_id", "user_id", "role", "revision", "joined_at", "updated_at",
	})
	assertColumns(t, ctx, postgres, "workspace_invitations", []string{
		"id", "workspace_id", "token_digest", "created_by_user_id", "status", "accepted_by_user_id",
		"created_at", "expires_at", "accepted_at", "revoked_at",
	})
	assertColumns(t, ctx, postgres, "workspace_idempotency_records", []string{
		"actor_user_id", "workspace_id", "operation", "key_digest", "request_digest", "resource_type",
		"resource_id", "created_at", "expires_at",
	})
	assertColumns(t, ctx, postgres, "experience_candidates", []string{
		"id", "workspace_id", "agent_definition_id", "source_agent_version_id", "submitted_by_user_id",
		"submitted_from_device_id", "kind", "skill_name", "schema_version", "dlp_contract_version",
		"content_digest", "bundle_document", "created_at",
	})
	assertColumns(t, ctx, postgres, "experience_candidate_reviews", []string{
		"id", "candidate_id", "workspace_id", "decision", "reviewed_by_user_id", "reason_code",
		"safe_note", "reviewed_at",
	})
	assertColumnNullable(t, ctx, postgres, "experience_candidates", "submitted_by_user_id", true)
	assertColumnNullable(t, ctx, postgres, "experience_candidates", "submitted_from_device_id", true)
	assertColumnNullable(t, ctx, postgres, "experience_candidate_reviews", "reviewed_by_user_id", true)

	for table, trigger := range map[string]string{
		"agent_versions":            "agent_versions_immutable_trigger",
		"policy_snapshots":          "policy_snapshots_immutable_trigger",
		"agent_version_revocations": "agent_version_revocations_immutable_trigger",
		"runtime_binding_records":   "runtime_binding_records_immutable_trigger",
	} {
		assertTriggerExists(t, ctx, postgres, table, trigger)
	}
	assertTriggerExists(t, ctx, postgres, "workspaces", "workspaces_owner_user_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "workspace_invitations", "workspace_invitations_lifecycle_trigger")
	assertTriggerExists(t, ctx, postgres, "experience_candidates", "experience_candidates_immutable_trigger")
	assertTriggerExists(t, ctx, postgres, "experience_candidate_reviews", "experience_candidate_reviews_immutable_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "workspaces", "workspaces_owner_membership_constraint_trigger")
	assertDeferredConstraintTrigger(t, ctx, postgres, "workspace_memberships", "workspace_memberships_owner_constraint_trigger")

	var applied int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if applied != 11 {
		t.Fatalf("applied migration count = %d, want 11", applied)
	}
	var receiptConsumedColumn bool
	if err := postgres.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name = 'verification_challenges'
			  AND column_name = 'receipt_consumed_at'
		)
	`).Scan(&receiptConsumedColumn); err != nil {
		t.Fatalf("check receipt_consumed_at: %v", err)
	}
	if !receiptConsumedColumn {
		t.Fatal("verification_challenges.receipt_consumed_at does not exist")
	}
	var oauthMetadataColumns int
	if err := postgres.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'oauth_requests'
		  AND column_name IN (
			'state_encryption_key_id', 'state_nonce', 'device_display_name', 'device_platform', 'app_version'
		  )
	`).Scan(&oauthMetadataColumns); err != nil {
		t.Fatalf("check OAuth metadata columns: %v", err)
	}
	if oauthMetadataColumns != 5 {
		t.Fatalf("OAuth metadata column count = %d, want 5", oauthMetadataColumns)
	}
	var administrativeDisableColumn bool
	if err := postgres.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'users'
			  AND column_name = 'administratively_disabled'
		)
	`).Scan(&administrativeDisableColumn); err != nil {
		t.Fatalf("check administratively_disabled: %v", err)
	}
	if !administrativeDisableColumn {
		t.Fatal("users.administratively_disabled does not exist")
	}
	var adminAuditColumns int
	if err := postgres.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'audit_events'
		  AND column_name IN ('operator_identity', 'subject_user_id')
	`).Scan(&adminAuditColumns); err != nil {
		t.Fatalf("check restricted audit columns: %v", err)
	}
	if adminAuditColumns != 2 {
		t.Fatalf("restricted audit column count = %d, want 2", adminAuditColumns)
	}
}

func assertColumnNullable(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	column string,
	want bool,
) {
	t.Helper()
	var nullable string
	if err := postgres.QueryRow(ctx, `
		SELECT is_nullable
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
	`, table, column).Scan(&nullable); err != nil {
		t.Fatalf("read nullable state for %s.%s: %v", table, column, err)
	}
	got := nullable == "YES"
	if got != want {
		t.Fatalf("nullable state for %s.%s = %t, want %t", table, column, got, want)
	}
}

func TestWorkspaceOwnerInvariantRejectsMissingOrMismatchedOwnerAtCommit(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}

	ownerID := uuid.New()
	otherID := uuid.New()
	now := time.Date(2026, 7, 20, 8, 30, 0, 0, time.UTC)
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, status, created_at, updated_at)
		VALUES ($1, 'active', $3, $3), ($2, 'active', $3, $3)
	`, ownerID, otherID, now); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	defer func() {
		_, _ = postgres.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1, $2)`, ownerID, otherID)
	}()
	defer func() {
		_, _ = postgres.Exec(context.Background(), `DELETE FROM workspaces WHERE owner_user_id = $1`, ownerID)
	}()

	validWorkspaceID := uuid.New()
	valid, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin valid workspace transaction: %v", err)
	}
	defer func() { _ = valid.Rollback(context.Background()) }()
	if _, err := valid.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Valid workspace', 'active', 1, $3, $3)
	`, validWorkspaceID, ownerID, now); err != nil {
		t.Fatalf("insert valid workspace: %v", err)
	}
	if _, err := valid.Exec(ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, validWorkspaceID, ownerID, now); err != nil {
		t.Fatalf("insert valid Owner membership: %v", err)
	}
	if err := valid.Commit(ctx); err != nil {
		t.Fatalf("commit valid workspace: %v", err)
	}

	if _, err := postgres.Exec(ctx, `UPDATE workspaces SET owner_user_id = $2 WHERE id = $1`, validWorkspaceID, otherID); err == nil {
		t.Fatal("owner_user_id update succeeded, want immutable Owner rejection")
	}

	missingOwner, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin missing-Owner transaction: %v", err)
	}
	defer func() { _ = missingOwner.Rollback(context.Background()) }()
	if _, err := missingOwner.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Missing Owner', 'active', 1, $3, $3)
	`, uuid.New(), ownerID, now); err != nil {
		t.Fatalf("insert missing-Owner workspace before deferred check: %v", err)
	}
	if err := missingOwner.Commit(ctx); err == nil {
		t.Fatal("workspace without Owner membership committed")
	}

	mismatchedOwner, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin mismatched-Owner transaction: %v", err)
	}
	defer func() { _ = mismatchedOwner.Rollback(context.Background()) }()
	mismatchedWorkspaceID := uuid.New()
	if _, err := mismatchedOwner.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Mismatched Owner', 'active', 1, $3, $3)
	`, mismatchedWorkspaceID, ownerID, now); err != nil {
		t.Fatalf("insert mismatched workspace: %v", err)
	}
	if _, err := mismatchedOwner.Exec(ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, mismatchedWorkspaceID, otherID, now); err != nil {
		t.Fatalf("insert mismatched Owner membership before deferred check: %v", err)
	}
	if err := mismatchedOwner.Commit(ctx); err == nil {
		t.Fatal("workspace with mismatched Owner membership committed")
	}
}

func TestWorkspaceInvitationTerminalStateCannotTransitionAgain(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}

	ownerID := uuid.New()
	workspaceID := uuid.New()
	invitationID := uuid.New()
	now := time.Date(2026, 7, 20, 8, 45, 0, 0, time.UTC)
	if _, err := postgres.Exec(ctx, `INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)`, ownerID, now); err != nil {
		t.Fatalf("insert invitation owner: %v", err)
	}
	defer func() { _, _ = postgres.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, ownerID) }()
	defer func() {
		_, _ = postgres.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, workspaceID)
	}()

	tx, err := postgres.Begin(ctx)
	if err != nil {
		t.Fatalf("begin invitation fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Invitation workspace', 'active', 1, $3, $3)
	`, workspaceID, ownerID, now); err != nil {
		t.Fatalf("insert invitation workspace: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, workspaceID, ownerID, now); err != nil {
		t.Fatalf("insert invitation Owner membership: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit invitation workspace: %v", err)
	}

	if _, err := postgres.Exec(ctx, `
		INSERT INTO workspace_invitations (
			id, workspace_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
	`, invitationID, workspaceID, bytes.Repeat([]byte{0x42}, 32), ownerID, now, now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("insert pending invitation: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		UPDATE workspace_invitations
		SET status = 'accepted', accepted_by_user_id = $2, accepted_at = $3
		WHERE id = $1
	`, invitationID, ownerID, now.Add(time.Hour)); err != nil {
		t.Fatalf("accept pending invitation: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		UPDATE workspace_invitations
		SET status = 'revoked', accepted_by_user_id = NULL, accepted_at = NULL, revoked_at = $2
		WHERE id = $1
	`, invitationID, now.Add(2*time.Hour)); err == nil {
		t.Fatal("accepted invitation transitioned to revoked")
	}
}

func assertColumns(t *testing.T, ctx context.Context, postgres *pgxpool.Pool, table string, expected []string) {
	t.Helper()
	rows, err := postgres.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
	`, table)
	if err != nil {
		t.Fatalf("read columns for %s: %v", table, err)
	}
	defer rows.Close()
	actual := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan column for %s: %v", table, err)
		}
		actual[column] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns for %s: %v", table, err)
	}
	for _, column := range expected {
		if _, ok := actual[column]; !ok {
			t.Errorf("table %s is missing column %s", table, column)
		}
	}
}

func assertCheckConstraintContains(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
	expected string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname = $1 AND c.conname = $2 AND c.contype = 'c'
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read check constraint %s: %v", name, err)
	}
	if !strings.Contains(definition, expected) {
		t.Fatalf("check constraint %s = %q, want it to contain %q", name, definition, expected)
	}
}

func assertCheckConstraintExcludes(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
	forbidden string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname = $1 AND c.conname = $2 AND c.contype = 'c'
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read check constraint %s: %v", name, err)
	}
	if strings.Contains(definition, forbidden) {
		t.Fatalf("check constraint %s = %q, want it to exclude %q", name, definition, forbidden)
	}
}

func assertTriggerExists(t *testing.T, ctx context.Context, postgres *pgxpool.Pool, table, name string) {
	t.Helper()
	var enabled string
	err := postgres.QueryRow(ctx, `
		SELECT tg.tgenabled::text
		FROM pg_trigger tg
		JOIN pg_class tbl ON tbl.oid = tg.tgrelid
		WHERE tbl.relname = $1 AND tg.tgname = $2 AND NOT tg.tgisinternal
	`, table, name).Scan(&enabled)
	if err != nil {
		t.Fatalf("read trigger %s: %v", name, err)
	}
	if enabled != "O" {
		t.Fatalf("trigger %s enabled state = %q, want O", name, enabled)
	}
}

func assertForeignKeyConstraintContains(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
	expected string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class tbl ON tbl.oid = c.conrelid
		WHERE tbl.relname = $1 AND c.conname = $2 AND c.contype = 'f'
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read foreign key constraint %s: %v", name, err)
	}
	if !strings.Contains(definition, expected) {
		t.Fatalf("foreign key constraint %s = %q, want it to contain %q", name, definition, expected)
	}
}

func assertIndexDefinitionContains(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	name string,
	expected ...string,
) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_indexdef(i.indexrelid)
		FROM pg_index i
		JOIN pg_class idx ON idx.oid = i.indexrelid
		WHERE idx.relname = $1
	`, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read index %s: %v", name, err)
	}
	for _, fragment := range expected {
		if !strings.Contains(strings.ToLower(definition), strings.ToLower(fragment)) {
			t.Fatalf("index %s = %q, want it to contain %q", name, definition, fragment)
		}
	}
}

func assertDeferredConstraintTrigger(
	t *testing.T,
	ctx context.Context,
	postgres *pgxpool.Pool,
	table string,
	name string,
) {
	t.Helper()
	var deferrable bool
	var initiallyDeferred bool
	err := postgres.QueryRow(ctx, `
		SELECT tg.tgdeferrable, tg.tginitdeferred
		FROM pg_trigger tg
		JOIN pg_class tbl ON tbl.oid = tg.tgrelid
		WHERE tbl.relname = $1 AND tg.tgname = $2 AND NOT tg.tgisinternal
	`, table, name).Scan(&deferrable, &initiallyDeferred)
	if err != nil {
		t.Fatalf("read deferred constraint trigger %s: %v", name, err)
	}
	if !deferrable || !initiallyDeferred {
		t.Fatalf(
			"constraint trigger %s deferrable/initially deferred = %t/%t, want true/true",
			name,
			deferrable,
			initiallyDeferred,
		)
	}
}

func TestApplyMigrationsSerializesConcurrentRunners(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()

	errorsByRunner := make(chan error, 2)
	var runners sync.WaitGroup
	for range 2 {
		runners.Add(1)
		go func() {
			defer runners.Done()
			errorsByRunner <- ApplyMigrations(ctx, postgres)
		}()
	}
	runners.Wait()
	close(errorsByRunner)
	for err := range errorsByRunner {
		if err != nil {
			t.Errorf("concurrent ApplyMigrations() error = %v", err)
		}
	}
}

func assertUniqueConstraint(t *testing.T, ctx context.Context, postgres *pgxpool.Pool, table, name string, columns []string) {
	t.Helper()
	var definition string
	err := postgres.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname = $1 AND c.conname = $2
	`, table, name).Scan(&definition)
	if err != nil {
		t.Fatalf("read constraint %s: %v", name, err)
	}
	if !strings.HasPrefix(definition, "UNIQUE") {
		t.Fatalf("constraint %s = %q, want UNIQUE", name, definition)
	}
	for _, column := range columns {
		if !strings.Contains(definition, column) {
			t.Errorf("constraint %s = %q, missing %s", name, definition, column)
		}
	}
}
