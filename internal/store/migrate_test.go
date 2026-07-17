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

	var applied int
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if applied != 6 {
		t.Fatalf("applied migration count = %d, want 6", applied)
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
