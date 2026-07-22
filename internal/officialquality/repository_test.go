package officialquality

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualitySchema(t *testing.T) (context.Context, *pgxpool.Pool) {
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
	return ctx, postgres
}

func TestOfficialQualityEventSchemaContainsOnlySanitizedColumns(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	rows, err := postgres.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'official_quality_events'
		ORDER BY ordinal_position
	`)
	if err != nil {
		t.Fatalf("query official quality columns: %v", err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan official quality column: %v", err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate official quality columns: %v", err)
	}
	want := []string{
		"event_id", "protocol_version", "consent_version", "platform_id",
		"definition_id", "version_id", "release_id", "release_revision_id",
		"desktop_version", "runtime_version", "event_day", "subject_pseudonym",
		"binding_proof_digest", "event_kind", "result_code", "latency_bucket",
		"total_token_bucket", "crash_code", "feedback_rating",
		"feedback_reason_codes", "device_signature", "created_at",
	}
	if !slices.Equal(columns, want) {
		t.Fatalf("official quality event columns = %v, want %v", columns, want)
	}
	for _, column := range columns {
		lower := strings.ToLower(column)
		for _, forbidden := range []string{
			"user", "account", "device_id", "installation", "profile", "session",
			"conversation", "runtime_binding", "ip_address", "user_agent", "request_body",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("official quality event column %q contains forbidden identifier %q", column, forbidden)
			}
		}
	}
}

func TestOfficialQualitySchemaPinsPrivacyEnumsAndImmutableSources(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	rows, err := postgres.Query(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'official_quality_events'::regclass
		ORDER BY conname
	`)
	if err != nil {
		t.Fatalf("query official quality constraints: %v", err)
	}
	defer rows.Close()
	var definitions strings.Builder
	for rows.Next() {
		var definition string
		if err := rows.Scan(&definition); err != nil {
			t.Fatalf("scan official quality constraint: %v", err)
		}
		definitions.WriteString(definition)
		definitions.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate official quality constraints: %v", err)
	}
	constraints := definitions.String()
	for _, required := range []string{
		"runtime_crash", "gte_180s", "gte_64k", "unclassified_runtime_failure",
		"not_helpful", "unsafe_or_inappropriate", "octet_length(device_signature) = 64",
	} {
		if !strings.Contains(constraints, required) {
			t.Fatalf("official quality constraints do not pin %q", required)
		}
	}

	var reviewGuard string
	if err := postgres.QueryRow(ctx, `
		SELECT pg_get_functiondef(oid)
		FROM pg_proc
		WHERE proname = 'enforce_official_quality_proposal_review_separation'
	`).Scan(&reviewGuard); err != nil {
		t.Fatalf("read proposal review guard: %v", err)
	}
	for _, required := range []string{"reviewed_revision", "submitted", "reviewer_admin_id"} {
		if !strings.Contains(reviewGuard, required) {
			t.Fatalf("proposal review guard does not enforce %q", required)
		}
	}

	var immutableTriggers int
	if err := postgres.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_trigger
		WHERE NOT tgisinternal
		  AND tgrelid IN (
		      'official_quality_consent_receipts'::regclass,
		      'official_quality_events'::regclass,
		      'official_quality_proposal_aggregates'::regclass,
		      'official_quality_proposal_reviews'::regclass
		  )
		  AND tgname LIKE '%immutable_trigger'
	`).Scan(&immutableTriggers); err != nil {
		t.Fatalf("count official quality immutable triggers: %v", err)
	}
	if immutableTriggers != 4 {
		t.Fatalf("official quality immutable trigger count = %d, want 4", immutableTriggers)
	}
}

func TestOfficialQualityEventRejectsUnknownResultBeforeProvenanceLookup(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	eventID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	_, err = postgres.Exec(ctx, `
		INSERT INTO official_quality_events (
			event_id, protocol_version, consent_version, platform_id,
			definition_id, version_id, release_id, release_revision_id,
			desktop_version, runtime_version, event_day, subject_pseudonym,
			binding_proof_digest, event_kind, result_code, latency_bucket,
			total_token_bucket, device_signature, created_at
		) VALUES (
			$1, 1, 1, $2, $3, $4, $5, $6,
			'1.0.0', '1.0.0', CURRENT_DATE, decode(repeat('11', 32), 'hex'),
			decode(repeat('22', 32), 'hex'), 'metric', 'unknown_result', 'lt_1s',
			'0', decode(repeat('33', 64), 'hex'), now()
		)
	`, eventID, uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New())
	assertPostgresError(t, err, "23514", "official_quality_events_result_check")
}

func TestOfficialQualityEventMutationGuardBlocksDirectUpdateAndDelete(t *testing.T) {
	ctx, postgres := qualitySchema(t)
	conn, err := postgres.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire postgres connection: %v", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `
		CREATE TEMP TABLE official_quality_event_mutation_probe (
			id INTEGER PRIMARY KEY,
			value TEXT NOT NULL
		) ON COMMIT PRESERVE ROWS;
		INSERT INTO official_quality_event_mutation_probe (id, value) VALUES (1, 'original');
		CREATE TRIGGER official_quality_event_mutation_probe_guard
			BEFORE UPDATE OR DELETE ON official_quality_event_mutation_probe
			FOR EACH ROW EXECUTE FUNCTION guard_official_quality_event_mutation();
	`); err != nil {
		t.Fatalf("create event mutation probe: %v", err)
	}

	_, err = conn.Exec(ctx, `UPDATE official_quality_event_mutation_probe SET value = 'changed' WHERE id = 1`)
	assertPostgresError(t, err, "55000", "")

	_, err = conn.Exec(ctx, `DELETE FROM official_quality_event_mutation_probe WHERE id = 1`)
	assertPostgresError(t, err, "55000", "")

	var deleted int64
	if err := conn.QueryRow(ctx, `SELECT delete_official_quality_events_before(CURRENT_DATE)`).Scan(&deleted); err != nil {
		t.Fatalf("retention function error = %v", err)
	}
	if deleted != 0 {
		t.Fatalf("retention function deleted %d rows, want 0", deleted)
	}
}

func assertPostgresError(t *testing.T, err error, code, constraint string) {
	t.Helper()
	if err == nil {
		t.Fatal("database operation unexpectedly succeeded")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("database error = %T %v, want *pgconn.PgError", err, err)
	}
	if pgErr.Code != code {
		t.Fatalf("database error code = %q, want %q: %v", pgErr.Code, code, err)
	}
	if constraint != "" && pgErr.ConstraintName != constraint {
		t.Fatalf("database constraint = %q, want %q: %v", pgErr.ConstraintName, constraint, err)
	}
}
