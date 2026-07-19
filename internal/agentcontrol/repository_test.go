package agentcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRepositoryPublishesSerializedVersionsWithOwnerAndIdempotencyBoundaries(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	principal := fixture.principal(t, 1)
	other := fixture.principal(t, 2)
	unauthorized := principal
	unauthorized.DeviceID = other.DeviceID
	unauthorizedCommand := fixture.initialPublication(principal, "Unauthorized Agent", 20)
	originalBuilder := unauthorizedCommand.BuildVersion
	builderCalled := false
	unauthorizedCommand.BuildVersion = func() (VersionMaterial, error) {
		builderCalled = true
		return originalBuilder()
	}
	if _, err := fixture.repository.PublishInitial(fixture.ctx, unauthorized, unauthorizedCommand); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PublishInitial(unauthorized device) error = %v", err)
	}
	if builderCalled {
		t.Fatal("PublishInitial() built and signed a version before principal authorization")
	}

	initial := fixture.initialPublication(principal, "Research Agent", 1)
	first, err := fixture.repository.PublishInitial(fixture.ctx, principal, initial)
	if err != nil {
		t.Fatalf("PublishInitial() error = %v", err)
	}
	if first.Definition.ID != initial.DefinitionID || first.Version.VersionNumber != 1 || first.Replayed {
		t.Fatalf("PublishInitial() = %+v", first)
	}

	replayed, err := fixture.repository.PublishInitial(fixture.ctx, principal, initial)
	if err != nil {
		t.Fatalf("PublishInitial(replay) error = %v", err)
	}
	if !replayed.Replayed || replayed.Definition.ID != first.Definition.ID || replayed.Version.ID != first.Version.ID {
		t.Fatalf("PublishInitial(replay) = %+v", replayed)
	}

	changed := initial
	changed.Idempotency.RequestHash = sha256.Sum256([]byte("changed canonical request"))
	if _, err := fixture.repository.PublishInitial(fixture.ctx, principal, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("PublishInitial(changed replay) error = %v", err)
	}

	if _, found, err := fixture.repository.FindDefinition(fixture.ctx, other, first.Definition.ID); err != nil || found {
		t.Fatalf("FindDefinition(cross owner) found=%v error=%v", found, err)
	}
	if _, found, err := fixture.repository.FindVersion(fixture.ctx, other, first.Version.ID); err != nil || found {
		t.Fatalf("FindVersion(cross owner) found=%v error=%v", found, err)
	}
	definitions, err := fixture.repository.ListDefinitions(fixture.ctx, principal)
	if err != nil || len(definitions) != 1 || definitions[0].ID != first.Definition.ID {
		t.Fatalf("ListDefinitions() = %+v error=%v", definitions, err)
	}
	otherDefinitions, err := fixture.repository.ListDefinitions(fixture.ctx, other)
	if err != nil || len(otherDefinitions) != 0 {
		t.Fatalf("ListDefinitions(other) = %+v error=%v", otherDefinitions, err)
	}
	if _, err := fixture.repository.ListVersions(fixture.ctx, other, first.Definition.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListVersions(cross owner) error = %v", err)
	}
	if err := fixture.repository.RecordDenied(fixture.ctx, other, DeniedAuditCommand{
		EventID: uuid.New(), ObjectType: "agent_definition", ObjectID: first.Definition.ID,
		ReasonCode: "not_found", RequestID: "cross-owner", OccurredAt: fixture.now,
	}); err != nil {
		t.Fatalf("RecordDenied() error = %v", err)
	}
	var deniedAudits int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM audit_events
		WHERE actor_user_id = $1 AND event_type = 'agent_definition_access_denied'
		  AND outcome = 'denied' AND reason_code = 'not_found'
	`, other.UserID).Scan(&deniedAudits); err != nil || deniedAudits != 1 {
		t.Fatalf("denied audit count = %d error=%v", deniedAudits, err)
	}

	secondCommand := fixture.nextPublication(principal, first.Definition.ID, first.Version.ID, 2)
	second, err := fixture.repository.PublishNext(fixture.ctx, principal, secondCommand)
	if err != nil {
		t.Fatalf("PublishNext() error = %v", err)
	}
	if second.Version.VersionNumber != 2 {
		t.Fatalf("PublishNext() version = %d", second.Version.VersionNumber)
	}

	commands := []NextPublicationCommand{
		fixture.nextPublication(principal, first.Definition.ID, second.Version.ID, 3),
		fixture.nextPublication(principal, first.Definition.ID, second.Version.ID, 4),
	}
	start := make(chan struct{})
	results := make(chan error, len(commands))
	var builders sync.WaitGroup
	builders.Add(len(commands))
	for _, command := range commands {
		command := command
		go func() {
			defer builders.Done()
			<-start
			_, publishErr := fixture.repository.PublishNext(fixture.ctx, principal, command)
			results <- publishErr
		}()
	}
	close(start)
	builders.Wait()
	close(results)
	successes := 0
	conflicts := 0
	for publishErr := range results {
		switch {
		case publishErr == nil:
			successes++
		case errors.Is(publishErr, ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent PublishNext() error = %v", publishErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent publication successes=%d conflicts=%d", successes, conflicts)
	}

	var numbers []int64
	rows, err := fixture.postgres.Query(fixture.ctx, `
		SELECT version_number FROM agent_versions
		WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2 AND definition_id = $3
		ORDER BY version_number
	`, principal.PersonalSpaceID, principal.UserID, first.Definition.ID)
	if err != nil {
		t.Fatalf("query published versions: %v", err)
	}
	for rows.Next() {
		var number int64
		if err := rows.Scan(&number); err != nil {
			rows.Close()
			t.Fatalf("scan published version: %v", err)
		}
		numbers = append(numbers, number)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate published versions: %v", err)
	}
	if fmt.Sprint(numbers) != "[1 2 3]" {
		t.Fatalf("published version numbers = %v", numbers)
	}

	var keyLength, requestLength int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT octet_length(key_hash), octet_length(request_hash)
		FROM agent_control_idempotency_keys
		WHERE tenant_id = $1 AND owner_scope = 'USER' AND owner_id = $2
		ORDER BY created_at LIMIT 1
	`, principal.PersonalSpaceID, principal.UserID).Scan(&keyLength, &requestLength); err != nil {
		t.Fatalf("read idempotency evidence: %v", err)
	}
	if keyLength != sha256.Size || requestLength != sha256.Size {
		t.Fatalf("stored idempotency hash lengths = %d/%d", keyLength, requestLength)
	}
}

func TestRepositoryPersistsInstallationPolicyBindingRevocationAndLifecycle(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	principal := fixture.principal(t, 7)
	publication, err := fixture.repository.PublishInitial(
		fixture.ctx,
		principal,
		fixture.initialPublication(principal, "Operations Agent", 7),
	)
	if err != nil {
		t.Fatalf("PublishInitial() error = %v", err)
	}
	second, err := fixture.repository.PublishNext(
		fixture.ctx,
		principal,
		fixture.nextPublication(principal, publication.Definition.ID, publication.Version.ID, 8),
	)
	if err != nil {
		t.Fatalf("PublishNext() error = %v", err)
	}

	create := fixture.pendingInstallation(principal, publication.Definition.ID, publication.Version.ID, 1, 9)
	created, err := fixture.repository.CreatePendingInstallation(fixture.ctx, principal, create)
	if err != nil {
		t.Fatalf("CreatePendingInstallation() error = %v", err)
	}
	if created.Installation.Status != InstallationStatusPending || created.Installation.RuntimeProfileID != nil ||
		created.Installation.PolicySnapshotID == nil || *created.Installation.PolicySnapshotID != created.Policy.ID {
		t.Fatalf("pending installation = %+v policy=%+v", created.Installation, created.Policy)
	}
	if created.Installation.DeviceInstallationID != fixture.deviceInstallationID(t, principal.DeviceID) {
		t.Fatal("device installation ID was not derived from the authenticated device")
	}
	replayed, err := fixture.repository.CreatePendingInstallation(fixture.ctx, principal, create)
	if err != nil || !replayed.Replayed || replayed.Installation.ID != created.Installation.ID {
		t.Fatalf("CreatePendingInstallation(replay) = %+v error=%v", replayed, err)
	}

	runtimeProfileID := uuid.New()
	activated, err := fixture.repository.ActivateInstallation(fixture.ctx, principal, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: runtimeProfileID,
		Audit: fixture.auditEvidence(10), ActivatedAt: fixture.now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ActivateInstallation() error = %v", err)
	}
	if activated.Status != InstallationStatusActive || activated.RuntimeProfileID == nil || *activated.RuntimeProfileID != runtimeProfileID {
		t.Fatalf("activated installation = %+v", activated)
	}
	if replay, err := fixture.repository.ActivateInstallation(fixture.ctx, principal, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: runtimeProfileID,
		Audit: fixture.auditEvidence(11), ActivatedAt: fixture.now.Add(11 * time.Minute),
	}); err != nil || replay.RuntimeProfileID == nil || *replay.RuntimeProfileID != runtimeProfileID {
		t.Fatalf("ActivateInstallation(replay) = %+v error=%v", replay, err)
	}
	if _, err := fixture.repository.ActivateInstallation(fixture.ctx, principal, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: uuid.New(),
		Audit: fixture.auditEvidence(12), ActivatedAt: fixture.now.Add(12 * time.Minute),
	}); !errors.Is(err, ErrActivationConflict) {
		t.Fatalf("ActivateInstallation(changed profile) error = %v", err)
	}

	failedPolicy := fixture.policy(created.Installation.ID, second.Version.ID, 2, 13)
	failedPolicy.Signature = []byte{1}
	if _, err := fixture.repository.SelectInstallationVersion(fixture.ctx, principal, VersionSelectionCommand{
		InstallationID: created.Installation.ID, VersionID: second.Version.ID, Policy: failedPolicy,
		Audit: fixture.auditEvidence(13), SelectedAt: fixture.now.Add(13 * time.Minute),
	}); err == nil {
		t.Fatal("SelectInstallationVersion(invalid policy) error = nil")
	}
	unchanged, found, err := fixture.repository.FindInstallation(fixture.ctx, principal, created.Installation.ID)
	if err != nil || !found || unchanged.SelectedVersionID != publication.Version.ID || unchanged.PolicySnapshotID == nil || *unchanged.PolicySnapshotID != created.Policy.ID {
		t.Fatalf("installation after rollback = %+v found=%v error=%v", unchanged, found, err)
	}

	selectedPolicy := fixture.policy(created.Installation.ID, second.Version.ID, 2, 14)
	selected, err := fixture.repository.SelectInstallationVersion(fixture.ctx, principal, VersionSelectionCommand{
		InstallationID: created.Installation.ID, VersionID: second.Version.ID, Policy: selectedPolicy,
		Audit: fixture.auditEvidence(14), SelectedAt: fixture.now.Add(14 * time.Minute),
	})
	if err != nil {
		t.Fatalf("SelectInstallationVersion() error = %v", err)
	}
	if selected.SelectedVersionID != second.Version.ID || selected.PolicySnapshotID == nil || *selected.PolicySnapshotID != selectedPolicy.ID {
		t.Fatalf("selected installation = %+v", selected)
	}

	binding := RuntimeBindingRecordCommand{
		BindingID: uuid.New(), AgentInstallationID: created.Installation.ID, AgentVersionID: second.Version.ID,
		RuntimeProfileID: runtimeProfileID, RuntimeVersion: "0.18.2-agentera.1",
		PolicySnapshotID: selectedPolicy.ID, ToolPermissionDigest: sha256.Sum256([]byte("tools")),
		Audit: fixture.auditEvidence(15), CreatedAt: fixture.now.Add(15 * time.Minute),
	}
	storedBinding, err := fixture.repository.InsertRuntimeBinding(fixture.ctx, principal, binding)
	if err != nil {
		t.Fatalf("InsertRuntimeBinding() error = %v", err)
	}
	if storedBinding.ID != binding.BindingID || storedBinding.DeviceID != principal.DeviceID {
		t.Fatalf("stored binding = %+v", storedBinding)
	}

	revocationCommand := VersionRevocationCommand{
		RevocationID: uuid.New(), VersionID: publication.Version.ID, ReasonCode: "owner_revoked",
		PolicySnapshotID: created.Policy.ID, Idempotency: fixture.idempotency(16),
		Audit: fixture.auditEvidence(16), RevokedAt: fixture.now.Add(16 * time.Minute),
	}
	revocation, err := fixture.repository.AppendVersionRevocation(fixture.ctx, principal, revocationCommand)
	if err != nil {
		t.Fatalf("AppendVersionRevocation() error = %v", err)
	}
	if revocation.VersionID != publication.Version.ID || revocation.Replayed {
		t.Fatalf("revocation = %+v", revocation)
	}
	replayCommand := VersionRevocationCommand{
		RevocationID: uuid.New(), VersionID: publication.Version.ID, ReasonCode: "owner_revoked",
		PolicySnapshotID: created.Policy.ID, Idempotency: revocationCommand.Idempotency,
		Audit: fixture.auditEvidence(17), RevokedAt: fixture.now.Add(17 * time.Minute),
	}
	replayedRevocation, err := fixture.repository.AppendVersionRevocation(fixture.ctx, principal, replayCommand)
	if err != nil || !replayedRevocation.Replayed {
		t.Fatalf("AppendVersionRevocation(replay) = %+v error=%v", replayedRevocation, err)
	}
	conflictingReplay := replayCommand
	conflictingReplay.Idempotency.RequestHash = sha256.Sum256([]byte("changed revocation request"))
	if _, err := fixture.repository.AppendVersionRevocation(fixture.ctx, principal, conflictingReplay); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("AppendVersionRevocation(changed replay) error = %v", err)
	}
	if _, err := fixture.repository.AppendVersionRevocation(fixture.ctx, principal, VersionRevocationCommand{
		RevocationID: uuid.New(), VersionID: publication.Version.ID, ReasonCode: "security_issue",
		PolicySnapshotID: created.Policy.ID, Idempotency: fixture.idempotency(18),
		Audit: fixture.auditEvidence(18), RevokedAt: fixture.now.Add(18 * time.Minute),
	}); !errors.Is(err, ErrVersionRevoked) {
		t.Fatalf("AppendVersionRevocation(changed reason) error = %v", err)
	}

	archived, err := fixture.repository.ArchiveInstallation(fixture.ctx, principal, ArchiveInstallationCommand{
		InstallationID: created.Installation.ID, Audit: fixture.auditEvidence(19), ArchivedAt: fixture.now.Add(19 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ArchiveInstallation() error = %v", err)
	}
	if archived.Status != InstallationStatusArchived || archived.ArchivedAt == nil || archived.RuntimeProfileID == nil {
		t.Fatalf("archived installation = %+v", archived)
	}

	for table, want := range map[string]int64{
		"agent_definitions": 1, "agent_versions": 2, "installations": 1, "policy_snapshots": 2,
		"runtime_binding_records": 1, "agent_version_revocations": 1,
	} {
		if got := fixture.count(t, table); got != want {
			t.Fatalf("%s count = %d, want %d", table, got, want)
		}
	}
}

type agentControlRepositoryFixture struct {
	ctx        context.Context
	postgres   *pgxpool.Pool
	repository *PostgresRepository
	now        time.Time
}

func newAgentControlRepositoryFixture(t *testing.T) *agentControlRepositoryFixture {
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
		t.Fatalf("truncate Agent control fixture: %v", err)
	}
	return &agentControlRepositoryFixture{
		ctx: ctx, postgres: postgres, repository: NewPostgresRepository(postgres),
		now: time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC),
	}
}

func (f *agentControlRepositoryFixture) principal(t *testing.T, discriminator byte) Principal {
	t.Helper()
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New()}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)
	`, principal.UserID, f.now); err != nil {
		t.Fatalf("seed principal user: %v", err)
	}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, display_name, status, created_at, updated_at)
		VALUES ($1, $2, 'Personal', 'active', $3, $3)
	`, principal.PersonalSpaceID, principal.UserID, f.now); err != nil {
		t.Fatalf("seed principal space: %v", err)
	}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Test Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, principal.DeviceID, principal.UserID, uuid.New(), bytes.Repeat([]byte{discriminator}, 32), f.now); err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	return principal
}

func (f *agentControlRepositoryFixture) initialPublication(
	principal Principal,
	displayName string,
	discriminator byte,
) InitialPublicationCommand {
	definitionID := uuid.New()
	versionID := uuid.New()
	material := f.versionMaterial(definitionID, versionID, 1, discriminator)
	return InitialPublicationCommand{
		DefinitionID: definitionID, DisplayName: displayName,
		BuildVersion: func() (VersionMaterial, error) { return material, nil },
		Idempotency:  f.idempotency(discriminator), Audit: f.auditEvidence(discriminator), PublishedAt: f.now,
	}
}

func (f *agentControlRepositoryFixture) nextPublication(
	principal Principal,
	definitionID uuid.UUID,
	baseVersionID uuid.UUID,
	discriminator byte,
) NextPublicationCommand {
	versionID := uuid.New()
	return NextPublicationCommand{
		DefinitionID: definitionID, BaseVersionID: baseVersionID,
		BuildVersion: func(versionNumber int64) (VersionMaterial, error) {
			return f.versionMaterial(definitionID, versionID, versionNumber, discriminator), nil
		},
		Idempotency: f.idempotency(discriminator), Audit: f.auditEvidence(discriminator), PublishedAt: f.now.Add(time.Duration(discriminator) * time.Minute),
	}
}

func (f *agentControlRepositoryFixture) versionMaterial(
	definitionID uuid.UUID,
	versionID uuid.UUID,
	versionNumber int64,
	discriminator byte,
) VersionMaterial {
	manifest := []byte(fmt.Sprintf(`{"schema_version":1,"marker":%d}`, discriminator))
	bundle := []byte(fmt.Sprintf(`{"assets":[],"marker":%d}`, discriminator))
	return VersionMaterial{
		ID: versionID, CanonicalManifest: manifest, Bundle: bundle,
		ContentDigest: sha256.Sum256(append(append([]byte(nil), manifest...), bundle...)),
		SigningKeyID:  "agent-control-v1", Signature: bytes.Repeat([]byte{discriminator}, 64),
		RuntimeMinimumVersion: "0.18.2-agentera.1", VersionNumber: versionNumber,
	}
}

func (f *agentControlRepositoryFixture) pendingInstallation(
	principal Principal,
	definitionID uuid.UUID,
	versionID uuid.UUID,
	policyVersion int64,
	discriminator byte,
) CreateInstallationCommand {
	installationID := uuid.New()
	return CreateInstallationCommand{
		InstallationID: installationID, DefinitionID: definitionID, VersionID: versionID,
		Policy:      f.policy(installationID, versionID, policyVersion, discriminator),
		Idempotency: f.idempotency(discriminator), Audit: f.auditEvidence(discriminator), CreatedAt: f.now.Add(time.Duration(discriminator) * time.Minute),
	}
}

func (f *agentControlRepositoryFixture) policy(
	installationID uuid.UUID,
	versionID uuid.UUID,
	policyVersion int64,
	discriminator byte,
) PolicyMaterial {
	document := []byte(fmt.Sprintf(`{"model":"local","marker":%d}`, discriminator))
	return PolicyMaterial{
		ID: uuid.New(), InstallationID: installationID, AgentVersionID: versionID, PolicyVersion: policyVersion,
		Document: document, ContentDigest: sha256.Sum256(document), Issuer: "https://cloud.agentera.local",
		SigningKeyID: "agent-control-v1", Signature: bytes.Repeat([]byte{discriminator}, 64), CreatedAt: f.now.Add(time.Duration(discriminator) * time.Minute),
	}
}

func (f *agentControlRepositoryFixture) idempotency(discriminator byte) IdempotencyEvidence {
	return IdempotencyEvidence{
		ID: uuid.New(), KeyHash: sha256.Sum256([]byte{discriminator, 1}),
		RequestHash: sha256.Sum256([]byte{discriminator, 2}), ExpiresAt: f.now.Add(24 * time.Hour),
	}
}

func (f *agentControlRepositoryFixture) auditEvidence(discriminator byte) AuditEvidence {
	return AuditEvidence{EventID: uuid.New(), RequestID: fmt.Sprintf("request-%d", discriminator)}
}

func (f *agentControlRepositoryFixture) deviceInstallationID(t *testing.T, deviceID uuid.UUID) uuid.UUID {
	t.Helper()
	var installationID uuid.UUID
	if err := f.postgres.QueryRow(f.ctx, `SELECT installation_id FROM devices WHERE id = $1`, deviceID).Scan(&installationID); err != nil {
		t.Fatalf("read device installation: %v", err)
	}
	return installationID
}

func (f *agentControlRepositoryFixture) count(t *testing.T, table string) int64 {
	t.Helper()
	allowed := map[string]struct{}{
		"agent_definitions": {}, "agent_versions": {}, "installations": {}, "policy_snapshots": {},
		"runtime_binding_records": {}, "agent_version_revocations": {},
	}
	if _, exists := allowed[table]; !exists {
		t.Fatalf("unsupported table %q", table)
	}
	var count int64
	if err := f.postgres.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}
