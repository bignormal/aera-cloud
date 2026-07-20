package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

func TestPostgresRecorderPersistsBoundedAgentMetadataDeterministically(t *testing.T) {
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	ownerID := uuid.New()
	tenantID := uuid.New()
	versionID := uuid.New()
	metadata := map[string]string{
		"owner_scope":      "USER",
		"agent_version_id": versionID.String(),
		"tenant_id":        tenantID.String(),
		"owner_id":         ownerID.String(),
		"content_digest":   strings.Repeat("a", 64),
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "agent_version_published", Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	encoded, ok := executor.arguments[10].(string)
	if !ok {
		t.Fatalf("metadata argument type = %T", executor.arguments[10])
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatalf("decode metadata argument: %v", err)
	}
	if len(decoded) != len(metadata) || decoded["owner_id"] != ownerID.String() {
		t.Fatalf("stored metadata = %+v", decoded)
	}
	if encoded != `{"agent_version_id":"`+versionID.String()+`","content_digest":"`+strings.Repeat("a", 64)+`","owner_id":"`+ownerID.String()+`","owner_scope":"USER","tenant_id":"`+tenantID.String()+`"}` {
		t.Fatalf("metadata JSON is not deterministic: %s", encoded)
	}

	metadata["owner_id"] = "mutated-after-record"
	if strings.Contains(encoded, "mutated-after-record") {
		t.Fatal("recorded metadata aliases the caller map")
	}
}

func TestPostgresRecorderRejectsUnsafeAgentMetadata(t *testing.T) {
	tooMany := make(map[string]string, 13)
	for index := range 13 {
		tooMany["tenant_id"] = uuid.NewString()
		tooMany["extra_"+string(rune('a'+index))] = "value"
	}
	tests := []map[string]string{
		tooMany,
		{"unexpected": "value"},
		{"Owner_ID": uuid.NewString()},
		{"owner_id": "alice@example.com"},
		{"owner_id": "Bearer opaque-token"},
		{"owner_id": "eyJheader.eyJpayload.signature-value"},
		{"owner_id": "line\nbreak"},
		{"owner_id": "/Users/alice/profile"},
		{"owner_id": strings.Repeat("a", 129)},
	}
	for index, metadata := range tests {
		recorder := &PostgresRecorder{executor: &fakeExecutor{}}
		if err := recorder.Record(context.Background(), Event{
			EventType: "agent_version_published", Outcome: OutcomeDenied, Metadata: metadata,
		}); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("case %d Record() error = %v", index, err)
		}
	}

	recorder := &PostgresRecorder{executor: &fakeExecutor{}}
	if err := recorder.Record(context.Background(), Event{
		EventType: "browser_login", Outcome: OutcomeSuccess, Metadata: map[string]string{"tenant_id": uuid.NewString()},
	}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("non-Agent metadata Record() error = %v", err)
	}
}

func TestPostgresRecorderPersistsBoundedWorkspaceMetadata(t *testing.T) {
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	workspaceID := uuid.New()
	membershipUserID := uuid.New()
	invitationID := uuid.New()
	metadata := map[string]string{
		"workspace_id":       workspaceID.String(),
		"membership_user_id": membershipUserID.String(),
		"invitation_id":      invitationID.String(),
		"role":               "admin",
		"previous_role":      "member",
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "workspace_member_role_changed", Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	encoded, ok := executor.arguments[10].(string)
	if !ok {
		t.Fatalf("metadata argument type = %T", executor.arguments[10])
	}
	want := `{"invitation_id":"` + invitationID.String() + `","membership_user_id":"` + membershipUserID.String() + `","previous_role":"member","role":"admin","workspace_id":"` + workspaceID.String() + `"}`
	if encoded != want {
		t.Fatalf("workspace metadata JSON = %s, want %s", encoded, want)
	}
}

func TestPostgresRecorderRejectsUnsafeWorkspaceMetadata(t *testing.T) {
	workspaceID := uuid.NewString()
	tests := []struct {
		name      string
		eventType string
		metadata  map[string]string
	}{
		{name: "unknown key", eventType: "workspace_created", metadata: map[string]string{"display_name": "Research Team"}},
		{name: "raw token", eventType: "workspace_invitation_created", metadata: map[string]string{"token": "opaque-secret-token"}},
		{name: "invite URL", eventType: "workspace_invitation_created", metadata: map[string]string{"invitation_id": "agentera://workspace-invitation#secret"}},
		{name: "email", eventType: "workspace_member_added", metadata: map[string]string{"membership_user_id": "alice@example.com"}},
		{name: "path", eventType: "workspace_created", metadata: map[string]string{"workspace_id": "/Users/alice/workspace"}},
		{name: "invalid role", eventType: "workspace_member_role_changed", metadata: map[string]string{"workspace_id": workspaceID, "role": "viewer"}},
		{name: "mixed Agent key", eventType: "workspace_created", metadata: map[string]string{"workspace_id": workspaceID, "owner_scope": "USER"}},
		{name: "workspace metadata on Agent event", eventType: "agent_version_published", metadata: map[string]string{"workspace_id": workspaceID}},
		{name: "workspace metadata on browser event", eventType: "browser_login", metadata: map[string]string{"workspace_id": workspaceID}},
		{name: "oversized value", eventType: "workspace_created", metadata: map[string]string{"workspace_id": strings.Repeat("a", 129)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &PostgresRecorder{executor: &fakeExecutor{}}
			if err := recorder.Record(context.Background(), Event{
				EventType: test.eventType, Outcome: OutcomeDenied, Metadata: test.metadata,
			}); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Record() error = %v, want ErrInvalidEvent", err)
			}
		})
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
