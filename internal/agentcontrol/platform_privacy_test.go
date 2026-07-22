package agentcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type officialPrivateStateSnapshot struct {
	files   map[string][sha256.Size]byte
	content [][]byte
	digests []string
}

func newOfficialPrivateStateSnapshot(t *testing.T) officialPrivateStateSnapshot {
	t.Helper()
	directory := t.TempDir()
	fixtures := map[string][]byte{
		"profile":       []byte("HERMES_HOME=/private/" + uuid.NewString()),
		"memory":        []byte("memory-record=" + uuid.NewString()),
		"session":       []byte("session-token=" + uuid.NewString()),
		"private-skill": []byte("private-skill=" + uuid.NewString()),
		"credential":    []byte("API_KEY=" + uuid.NewString()),
		"curator":       []byte("curator-state=" + uuid.NewString()),
	}
	snapshot := officialPrivateStateSnapshot{files: make(map[string][sha256.Size]byte, len(fixtures))}
	for name, content := range fixtures {
		path := filepath.Join(directory, name+".private")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write private fixture %s: %v", name, err)
		}
		digest := sha256.Sum256(content)
		snapshot.files[path] = digest
		snapshot.content = append(snapshot.content, append([]byte(nil), content...))
		snapshot.digests = append(snapshot.digests, hex.EncodeToString(digest[:]))
	}
	return snapshot
}

func (snapshot officialPrivateStateSnapshot) assertUnchangedAndAbsent(t *testing.T, captures ...string) {
	t.Helper()
	for path, before := range snapshot.files {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read private fixture %s: %v", path, err)
		}
		if after := sha256.Sum256(content); after != before {
			t.Fatalf("private fixture changed: %s", path)
		}
	}
	haystack := strings.Join(captures, "\n")
	for index, content := range snapshot.content {
		if strings.Contains(haystack, string(content)) || strings.Contains(haystack, snapshot.digests[index]) {
			t.Fatalf("private fixture %d or its digest entered an official request/row", index)
		}
	}
	for _, forbiddenField := range []string{
		`"profile_path"`, `"hermes_home"`, `"memory"`, `"session_id"`,
		`"credential"`, `"private_skill"`, `"curator"`,
	} {
		if strings.Contains(strings.ToLower(haystack), forbiddenField) {
			t.Fatalf("forbidden private field entered an official request/row: %s", forbiddenField)
		}
	}
}

func TestOfficialCloudOperationsPreserveExternalPrivateStateAndExcludeItFromRows(t *testing.T) {
	privateState := newOfficialPrivateStateSnapshot(t)
	fixture, service, platformService := newOfficialInstallationFixture(t)
	principal := fixture.principal(t, 0xe1)
	_, versionID, release := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0xe2)
	active := fixture.activateOfficialRelease(t, release, versionID, nil, 0xe7)
	contextValue := OfficialEligibilityContext{
		Channel: OfficialChannelStable, DesktopVersion: "v1.0.0",
		Selector: OfficialProductSelector{Scope: OwnerScopeUser, PersonalSpaceID: principal.PersonalSpaceID},
	}
	request := CreateInstallationRequest{
		DefinitionID: release.DefinitionID, OfficialReleaseRevisionID: &active.CurrentRevision.ID,
		OfficialContext: &contextValue, IdempotencyKey: "official-private-boundary", RequestID: "official-private-boundary",
	}
	requestCapture, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal safe official request: %v", err)
	}
	service.officialEligibility = platformService
	created, err := service.CreateInstallation(fixture.ctx, principal, request)
	if err != nil {
		t.Fatalf("create official installation: %v", err)
	}

	profileID := uuid.New()
	activatedAt := active.UpdatedAt.Add(time.Minute)
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE installations
		SET runtime_profile_id = $2, status = 'active', activated_at = $3, updated_at = $3
		WHERE id = $1
	`, created.Installation.ID, profileID, activatedAt); err != nil {
		t.Fatalf("activate official installation fixture: %v", err)
	}
	bindingID := uuid.New()
	if _, err := fixture.repository.InsertRuntimeBinding(fixture.ctx, principal, PersistRuntimeBindingCommand{
		RuntimeBindingRecordCommand: RuntimeBindingRecordCommand{
			BindingID: bindingID, AgentInstallationID: created.Installation.ID,
			AgentVersionID: versionID, RuntimeProfileID: profileID, RuntimeVersion: "v0.18.2-agentera.1",
			PolicySnapshotID: created.Policy.ID, ToolPermissionDigest: [sha256.Size]byte{1},
			OfficialReleaseRevisionID: &active.CurrentRevision.ID,
		},
		Audit: fixture.auditEvidence(0xe8), CreatedAt: activatedAt.Add(time.Minute),
	}); err != nil {
		t.Fatalf("persist official runtime binding: %v", err)
	}

	var persistedRows string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT jsonb_build_object(
			'installation', (SELECT to_jsonb(value) FROM installations value WHERE value.id = $1),
			'policy', (SELECT to_jsonb(value) FROM policy_snapshots value WHERE value.id = $2),
			'binding', (SELECT to_jsonb(value) FROM runtime_binding_records value WHERE value.id = $3),
			'definition', (SELECT to_jsonb(value) FROM agent_definitions value WHERE value.id = $4),
			'version', (SELECT to_jsonb(value) FROM agent_versions value WHERE value.id = $5),
			'release', (SELECT to_jsonb(value) FROM official_releases value WHERE value.id = $6),
			'release_revision', (SELECT to_jsonb(value) FROM official_release_revisions value WHERE value.id = $7),
			'audit', (SELECT COALESCE(jsonb_agg(to_jsonb(value)), '[]'::jsonb) FROM audit_events value)
		)::text
	`, created.Installation.ID, created.Policy.ID, bindingID, release.DefinitionID, versionID,
		release.ID, active.CurrentRevision.ID).Scan(&persistedRows); err != nil {
		t.Fatalf("capture official rows: %v", err)
	}
	privateState.assertUnchangedAndAbsent(t, string(requestCapture), persistedRows)
}
