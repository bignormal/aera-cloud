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
	if len(executor.arguments) != 13 {
		t.Fatalf("Exec() arguments = %d", len(executor.arguments))
	}
	if got := executor.arguments[10]; got != "{}" {
		t.Fatalf("metadata argument = %#v, want an empty object", got)
	}
	if got := executor.arguments[11]; got != now {
		t.Fatalf("created_at argument = %#v", got)
	}
}

func TestPostgresRecorderPersistsOrganizationScopeAndBoundedMetadataDeterministically(t *testing.T) {
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	organizationID := uuid.MustParse("019f9999-0000-7000-8000-000000000001")
	policyID := uuid.MustParse("019f0000-9999-7000-8000-000000000002")
	metadata := map[string]string{
		"organization_id":    organizationID.String(),
		"policy_snapshot_id": policyID.String(),
		"policy_version":     "2",
		"content_digest":     strings.Repeat("d", 64),
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "organization_policy_published", OrganizationID: &organizationID,
		ObjectType: "organization_policy_snapshot", ObjectID: &policyID,
		Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(executor.arguments) != 13 || executor.arguments[12] != &organizationID {
		t.Fatalf("organization audit arguments = %#v", executor.arguments)
	}
	encoded, ok := executor.arguments[10].(string)
	if !ok {
		t.Fatalf("metadata argument type = %T", executor.arguments[10])
	}
	want := `{"content_digest":"` + strings.Repeat("d", 64) + `","organization_id":"` + organizationID.String() + `","policy_snapshot_id":"` + policyID.String() + `","policy_version":"2"}`
	if encoded != want {
		t.Fatalf("Organization metadata JSON = %s, want %s", encoded, want)
	}
	metadata["policy_version"] = "999"
	var recorded map[string]string
	if err := json.Unmarshal([]byte(encoded), &recorded); err != nil {
		t.Fatalf("decode recorded Organization metadata: %v", err)
	}
	if recorded["policy_version"] != "2" {
		t.Fatalf("recorded Organization metadata aliases the caller map: %+v", recorded)
	}
}

func TestPostgresRecorderRejectsOrganizationSecretsAndPrivateRuntimeMetadata(t *testing.T) {
	organizationID := uuid.New()
	otherOrganizationID := uuid.New()
	tests := []struct {
		name           string
		eventType      string
		organizationID *uuid.UUID
		metadata       map[string]string
	}{
		{name: "missing scope", eventType: "organization_created"},
		{name: "scope on unrelated event", eventType: "browser_login", organizationID: &organizationID},
		{name: "mismatched metadata scope", eventType: "organization_created", organizationID: &organizationID, metadata: map[string]string{"organization_id": otherOrganizationID.String()}},
		{name: "raw invitation", eventType: "organization_invitation_created", organizationID: &organizationID, metadata: map[string]string{"invitation_token": "raw-secret"}},
		{name: "invitation digest", eventType: "organization_invitation_created", organizationID: &organizationID, metadata: map[string]string{"invitation_token_digest": strings.Repeat("a", 64)}},
		{name: "policy document", eventType: "organization_policy_published", organizationID: &organizationID, metadata: map[string]string{"policy_document": `{"schema_version":1}`}},
		{name: "local path", eventType: "organization_created", organizationID: &organizationID, metadata: map[string]string{"profile_path": "/Users/alice/.hermes/profile"}},
		{name: "Memory", eventType: "organization_created", organizationID: &organizationID, metadata: map[string]string{"memory": "private"}},
		{name: "session", eventType: "organization_created", organizationID: &organizationID, metadata: map[string]string{"session_id": uuid.NewString()}},
		{name: "Skill", eventType: "organization_created", organizationID: &organizationID, metadata: map[string]string{"skill": "private"}},
		{name: "nested JSON", eventType: "organization_created", organizationID: &organizationID, metadata: map[string]string{"organization_id": organizationID.String(), "reason": `{"nested":true}`}},
		{name: "invalid role", eventType: "organization_member_role_changed", organizationID: &organizationID, metadata: map[string]string{"role": "superadmin"}},
		{name: "zero policy version", eventType: "organization_policy_published", organizationID: &organizationID, metadata: map[string]string{"policy_version": "0"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &PostgresRecorder{executor: &fakeExecutor{}}
			if err := recorder.Record(context.Background(), Event{
				EventType: test.eventType, OrganizationID: test.organizationID,
				Outcome: OutcomeDenied, Metadata: test.metadata,
			}); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Record() error = %v, want ErrInvalidEvent", err)
			}
		})
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

func TestPostgresRecorderPersistsBoundedWorkspaceAgentMetadataDeterministically(t *testing.T) {
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	workspaceID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	metadata := map[string]string{
		"owner_scope":         "WORKSPACE",
		"workspace_id":        workspaceID.String(),
		"agent_definition_id": definitionID.String(),
		"agent_version_id":    versionID.String(),
		"content_digest":      strings.Repeat("b", 64),
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "agent_definition_published", Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	encoded, ok := executor.arguments[10].(string)
	if !ok {
		t.Fatalf("metadata argument type = %T", executor.arguments[10])
	}
	want := `{"agent_definition_id":"` + definitionID.String() + `","agent_version_id":"` + versionID.String() + `","content_digest":"` + strings.Repeat("b", 64) + `","owner_scope":"WORKSPACE","workspace_id":"` + workspaceID.String() + `"}`
	if encoded != want {
		t.Fatalf("Workspace Agent metadata JSON = %s, want %s", encoded, want)
	}
}

func TestPostgresRecorderAllowsOnlyBoundedExperienceCandidateMetadata(t *testing.T) {
	workspaceID := uuid.New()
	definitionID := uuid.New()
	versionID := uuid.New()
	candidateID := uuid.New()
	metadata := map[string]string{
		"owner_scope":             "WORKSPACE",
		"workspace_id":            workspaceID.String(),
		"agent_definition_id":     definitionID.String(),
		"agent_version_id":        versionID.String(),
		"experience_candidate_id": candidateID.String(),
		"content_digest":          strings.Repeat("c", 64),
		"decision":                "APPROVED",
	}
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "agent_experience_candidate_review_approved", Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	encoded, ok := executor.arguments[10].(string)
	if !ok {
		t.Fatalf("metadata argument type = %T", executor.arguments[10])
	}
	for _, expected := range []string{candidateID.String(), definitionID.String(), versionID.String(), "APPROVED"} {
		if !strings.Contains(encoded, expected) {
			t.Fatalf("metadata JSON %s does not contain %q", encoded, expected)
		}
	}

	for _, unsafe := range []map[string]string{
		{
			"owner_scope": "WORKSPACE", "workspace_id": workspaceID.String(),
			"experience_candidate_id": candidateID.String(), "candidate_content": "secret body",
		},
		{
			"owner_scope": "WORKSPACE", "workspace_id": workspaceID.String(),
			"experience_candidate_id": candidateID.String(), "source_path": "/Users/alice/.hermes/skills/private",
		},
		{
			"owner_scope": "WORKSPACE", "workspace_id": workspaceID.String(),
			"experience_candidate_id": candidateID.String(), "decision": "OVERRIDE",
		},
	} {
		if err := (&PostgresRecorder{executor: &fakeExecutor{}}).Record(context.Background(), Event{
			EventType: "agent_experience_candidate_review_approved", Outcome: OutcomeSuccess, Metadata: unsafe,
		}); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("unsafe candidate metadata Record() error = %v", err)
		}
	}
}

func TestPostgresRecorderPersistsWorkspaceSourcedUserInstallationMetadata(t *testing.T) {
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metadata := map[string]string{
		"tenant_id":             uuid.NewString(),
		"owner_scope":           "USER",
		"owner_id":              uuid.NewString(),
		"agent_definition_id":   uuid.NewString(),
		"agent_version_id":      uuid.NewString(),
		"agent_installation_id": uuid.NewString(),
		"policy_snapshot_id":    uuid.NewString(),
		"source_owner_scope":    "WORKSPACE",
		"source_workspace_id":   uuid.NewString(),
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "agent_installation_created", Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if executor.calls != 1 {
		t.Fatalf("Exec() calls = %d, want 1", executor.calls)
	}
}

func TestPostgresRecorderPersistsOrganizationSourcedUserInstallationMetadata(t *testing.T) {
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metadata := map[string]string{
		"tenant_id":              uuid.NewString(),
		"owner_scope":            "USER",
		"owner_id":               uuid.NewString(),
		"agent_definition_id":    uuid.NewString(),
		"agent_version_id":       uuid.NewString(),
		"agent_installation_id":  uuid.NewString(),
		"policy_snapshot_id":     uuid.NewString(),
		"source_owner_scope":     "ORGANIZATION",
		"source_organization_id": uuid.NewString(),
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "agent_installation_created", Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if executor.calls != 1 {
		t.Fatalf("Exec() calls = %d, want 1", executor.calls)
	}
}

func TestPostgresRecorderPersistsPlatformSourcedUserInstallationMetadata(t *testing.T) {
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metadata := map[string]string{
		"tenant_id":                    uuid.NewString(),
		"owner_scope":                  "USER",
		"owner_id":                     uuid.NewString(),
		"agent_definition_id":          uuid.NewString(),
		"agent_version_id":             uuid.NewString(),
		"agent_installation_id":        uuid.NewString(),
		"policy_snapshot_id":           uuid.NewString(),
		"source_owner_scope":           "PLATFORM",
		"platform_id":                  uuid.NewString(),
		"official_release_id":          uuid.NewString(),
		"official_release_revision_id": uuid.NewString(),
		"product_context_scope":        "USER",
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "agent_installation_created", Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if executor.calls != 1 {
		t.Fatalf("Exec() calls = %d, want 1", executor.calls)
	}
}

func TestPostgresRecorderPersistsManagedPlatformSelectionMetadata(t *testing.T) {
	executor := &fakeExecutor{}
	recorder, err := NewRecorder(executor)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metadata := map[string]string{
		"tenant_id":                    uuid.NewString(),
		"owner_scope":                  "USER",
		"owner_id":                     uuid.NewString(),
		"agent_version_id":             uuid.NewString(),
		"agent_installation_id":        uuid.NewString(),
		"policy_snapshot_id":           uuid.NewString(),
		"source_owner_scope":           "PLATFORM",
		"platform_id":                  uuid.NewString(),
		"official_release_id":          uuid.NewString(),
		"official_release_revision_id": uuid.NewString(),
		"product_context_scope":        "WORKSPACE",
	}
	if err := recorder.Record(context.Background(), Event{
		EventType: "agent_installation_managed_version_selected", Outcome: OutcomeSuccess, Metadata: metadata,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if executor.calls != 1 {
		t.Fatalf("Exec() calls = %d, want 1", executor.calls)
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
	organizationID := uuid.NewString()
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
		{name: "unscoped workspace metadata on Agent event", eventType: "agent_version_published", metadata: map[string]string{"workspace_id": workspaceID}},
		{name: "Workspace Agent metadata without workspace", eventType: "agent_version_published", metadata: map[string]string{"owner_scope": "WORKSPACE"}},
		{name: "mixed Workspace and user Agent ownership", eventType: "agent_version_published", metadata: map[string]string{"owner_scope": "WORKSPACE", "workspace_id": workspaceID, "owner_id": uuid.NewString()}},
		{name: "Workspace-owned Installation", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "WORKSPACE", "workspace_id": workspaceID}},
		{name: "Workspace-owned RuntimeBinding", eventType: "runtime_binding_recorded", metadata: map[string]string{"owner_scope": "WORKSPACE", "workspace_id": workspaceID}},
		{name: "unsupported Workspace Agent event", eventType: "agent_version_revoked", metadata: map[string]string{"owner_scope": "WORKSPACE", "workspace_id": workspaceID}},
		{name: "Workspace source without workspace", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "WORKSPACE"}},
		{name: "USER source with workspace", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "USER", "source_workspace_id": workspaceID}},
		{name: "Organization source without organization", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "ORGANIZATION"}},
		{name: "Organization source with workspace", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "ORGANIZATION", "source_organization_id": organizationID, "source_workspace_id": workspaceID}},
		{name: "Workspace source with organization", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "WORKSPACE", "source_workspace_id": workspaceID, "source_organization_id": organizationID}},
		{name: "Platform source without provenance", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "PLATFORM"}},
		{name: "Platform provenance on user source", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "USER", "platform_id": uuid.NewString(), "official_release_id": uuid.NewString(), "official_release_revision_id": uuid.NewString(), "product_context_scope": "USER"}},
		{name: "Platform source with invalid context scope", eventType: "agent_installation_created", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "PLATFORM", "platform_id": uuid.NewString(), "official_release_id": uuid.NewString(), "official_release_revision_id": uuid.NewString(), "product_context_scope": "PLATFORM"}},
		{name: "source ownership on unrelated Agent event", eventType: "agent_version_published", metadata: map[string]string{"owner_scope": "USER", "source_owner_scope": "WORKSPACE", "source_workspace_id": workspaceID}},
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

func TestOrganizationAuditQueryIndexAvailableAgainstRealSchema(t *testing.T) {
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
	var definition string
	if err := postgres.QueryRow(ctx, `
		SELECT indexdef FROM pg_indexes
		WHERE schemaname = current_schema() AND indexname = 'audit_events_organization_created_idx'
	`).Scan(&definition); err != nil {
		t.Fatalf("read Organization audit index: %v", err)
	}
	for _, fragment := range []string{"organization_id", "created_at DESC", "id DESC"} {
		if !strings.Contains(definition, fragment) {
			t.Fatalf("Organization audit index %q is missing %q", definition, fragment)
		}
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
