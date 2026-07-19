package store

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/testkit"
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
	assertUniqueConstraint(t, ctx, postgres, "agent_control_idempotency_keys", "agent_control_idempotency_owner_operation_key", []string{
		"tenant_id", "owner_scope", "owner_id", "operation", "key_hash",
	})

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

	assertColumns(t, ctx, postgres, "agent_definitions", []string{
		"id", "tenant_id", "owner_scope", "owner_id", "display_name", "icon_media_type", "icon_data",
		"status", "latest_version_id", "created_by", "created_at", "updated_at",
	})
	assertColumns(t, ctx, postgres, "agent_versions", []string{
		"id", "definition_id", "tenant_id", "owner_scope", "owner_id", "version_number",
		"canonical_manifest", "bundle", "content_digest", "signing_key_id", "signature",
		"runtime_minimum_version", "runtime_maximum_version_exclusive", "published_by", "published_at",
	})
	assertColumns(t, ctx, postgres, "installations", []string{
		"id", "tenant_id", "owner_scope", "owner_id", "device_id", "device_installation_id",
		"definition_id", "selected_version_id", "runtime_profile_id", "policy_snapshot_id", "update_policy",
		"status", "created_by", "created_at", "updated_at", "activated_at", "archived_at",
	})

	for table, trigger := range map[string]string{
		"agent_versions":            "agent_versions_immutable_trigger",
		"policy_snapshots":          "policy_snapshots_immutable_trigger",
		"agent_version_revocations": "agent_version_revocations_immutable_trigger",
		"runtime_binding_records":   "runtime_binding_records_immutable_trigger",
	} {
		assertTriggerExists(t, ctx, postgres, table, trigger)
	}

	var applied int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if applied != 8 {
		t.Fatalf("applied migration count = %d, want 8", applied)
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
