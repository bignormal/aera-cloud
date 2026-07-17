package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresRecorderPersistsOnlyStructuredRedactedFields(t *testing.T) {
	executor := &fakeExecutor{}
	recorder := &PostgresRecorder{executor: executor}
	actorID := uuid.New()
	deviceID := uuid.New()
	objectID := uuid.New()
	now := time.Date(2026, 7, 17, 16, 30, 0, 0, time.UTC)

	err := recorder.Record(context.Background(), Event{
		ID:          uuid.New(),
		EventType:   "browser_login",
		ActorUserID: &actorID,
		DeviceID:    &deviceID,
		ObjectType:  "user",
		ObjectID:    &objectID,
		Outcome:     OutcomeFailure,
		ReasonCode:  "invalid_credentials",
		RequestID:   "req-opaque",
		IPHMAC:      make([]byte, 32),
		OccurredAt:  now,
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if executor.calls != 1 {
		t.Fatalf("Exec() calls = %d", executor.calls)
	}
	if len(executor.arguments) != 12 {
		t.Fatalf("Exec() arguments = %d", len(executor.arguments))
	}
	if got := executor.arguments[10]; got != "{}" {
		t.Fatalf("metadata argument = %#v, want an empty object", got)
	}
	if got := executor.arguments[11]; got != now {
		t.Fatalf("created_at argument = %#v", got)
	}
}

func TestPostgresRecorderRejectsUnstructuredOrSensitiveShapedValues(t *testing.T) {
	tests := []Event{
		{EventType: "", Outcome: OutcomeSuccess},
		{EventType: "browser.login", Outcome: OutcomeSuccess},
		{EventType: "browser_login", Outcome: "unknown"},
		{EventType: "browser_login", Outcome: OutcomeFailure, ReasonCode: "alice@example.com"},
		{EventType: "browser_login", Outcome: OutcomeFailure, RequestID: "line\nbreak"},
		{EventType: "browser_login", Outcome: OutcomeFailure, IPHMAC: []byte("203.0.113.10")},
	}

	for index, event := range tests {
		recorder := &PostgresRecorder{executor: &fakeExecutor{}}
		if err := recorder.Record(context.Background(), event); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("case %d Record() error = %v", index, err)
		}
	}
}

func TestPostgresRecorderPersistsActorAgainstRealSchema(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE audit_events, users CASCADE`); err != nil {
		t.Fatalf("truncate audit fixture: %v", err)
	}
	actorID := uuid.New()
	now := time.Date(2026, 7, 18, 0, 20, 0, 0, time.UTC)
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)
	`, actorID, now); err != nil {
		t.Fatalf("insert audit actor: %v", err)
	}
	recorder, err := NewPostgresRecorder(postgres)
	if err != nil {
		t.Fatalf("NewPostgresRecorder() error = %v", err)
	}
	if err := recorder.Record(ctx, Event{
		EventType: "browser_login", ActorUserID: &actorID, Outcome: OutcomeSuccess, OccurredAt: now,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	var storedActor uuid.UUID
	var metadata string
	if err := postgres.QueryRow(ctx, `
		SELECT actor_user_id, metadata::text FROM audit_events WHERE event_type = 'browser_login'
	`).Scan(&storedActor, &metadata); err != nil {
		t.Fatalf("read audit event: %v", err)
	}
	if storedActor != actorID || metadata != "{}" {
		t.Fatalf("stored audit actor=%s metadata=%q", storedActor, metadata)
	}
}

type fakeExecutor struct {
	calls     int
	arguments []any
	err       error
}

func (f *fakeExecutor) Exec(_ context.Context, _ string, arguments ...any) (pgconn.CommandTag, error) {
	f.calls++
	f.arguments = append([]any(nil), arguments...)
	return pgconn.CommandTag{}, f.err
}
