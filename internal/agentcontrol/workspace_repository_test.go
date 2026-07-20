package agentcontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRepositoryWorkspacePublicationRolesDiscoveryAndUserInstallations(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	owner := fixture.principal(t, 41)
	admin := fixture.principal(t, 42)
	member := fixture.principal(t, 43)
	outsider := fixture.principal(t, 44)
	workspaceID := seedAgentWorkspace(t, fixture, owner, admin, member)

	initial := fixture.initialPublication(owner, "Workspace Research Agent", 41)
	publication, err := fixture.repository.PublishWorkspaceInitial(
		fixture.ctx, owner, workspaceID, initial,
	)
	if err != nil {
		t.Fatalf("PublishWorkspaceInitial(Owner) error = %v", err)
	}
	if publication.Definition.ID != initial.DefinitionID || publication.Version.VersionNumber != 1 {
		t.Fatalf("initial Workspace publication = %+v", publication)
	}

	memberAttempt := fixture.initialPublication(member, "Member Agent", 43)
	if _, err := fixture.repository.PublishWorkspaceInitial(
		fixture.ctx, member, workspaceID, memberAttempt,
	); !errors.Is(err, ErrWorkspaceForbidden) {
		t.Fatalf("PublishWorkspaceInitial(Member) error = %v", err)
	}

	next := fixture.nextPublication(admin, publication.Definition.ID, publication.Version.ID, 42)
	second, err := fixture.repository.PublishWorkspaceNext(
		fixture.ctx, admin, workspaceID, next,
	)
	if err != nil {
		t.Fatalf("PublishWorkspaceNext(Admin) error = %v", err)
	}
	if second.Version.VersionNumber != 2 {
		t.Fatalf("Workspace next version = %d, want 2", second.Version.VersionNumber)
	}

	for name, principal := range map[string]Principal{"owner": owner, "admin": admin, "member": member} {
		t.Run("discover as "+name, func(t *testing.T) {
			definitions, listErr := fixture.repository.ListWorkspaceDefinitions(fixture.ctx, principal, workspaceID)
			if listErr != nil || len(definitions) != 1 || definitions[0].ID != publication.Definition.ID {
				t.Fatalf("ListWorkspaceDefinitions() = %+v error=%v", definitions, listErr)
			}
			versions, listErr := fixture.repository.ListWorkspaceVersions(
				fixture.ctx, principal, workspaceID, publication.Definition.ID,
			)
			if listErr != nil || len(versions) != 2 || versions[0].ID != second.Version.ID {
				t.Fatalf("ListWorkspaceVersions() = %+v error=%v", versions, listErr)
			}
		})
	}
	if _, err := fixture.repository.ListWorkspaceDefinitions(fixture.ctx, outsider, workspaceID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListWorkspaceDefinitions(outsider) error = %v", err)
	}

	memberInstallation := fixture.pendingInstallation(
		member, publication.Definition.ID, publication.Version.ID, 1, 45,
	)
	memberInstallation.SourceWorkspaceID = &workspaceID
	created, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx, member, memberInstallation,
	)
	if err != nil {
		t.Fatalf("CreatePendingInstallation(Member) error = %v", err)
	}
	if created.Installation.DeviceID != member.DeviceID {
		t.Fatalf("installation device = %s, want %s", created.Installation.DeviceID, member.DeviceID)
	}
	var tenantID, ownerID uuid.UUID
	var scope string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT tenant_id, owner_scope, owner_id
		FROM installations WHERE id = $1
	`, created.Installation.ID).Scan(&tenantID, &scope, &ownerID); err != nil {
		t.Fatalf("read member installation owner: %v", err)
	}
	if tenantID != member.PersonalSpaceID || scope != "USER" || ownerID != member.UserID {
		t.Fatalf("member installation owner = %s/%s/%s", tenantID, scope, ownerID)
	}
	ownerInstallation := fixture.pendingInstallation(
		owner, publication.Definition.ID, publication.Version.ID, 1, 47,
	)
	ownerInstallation.SourceWorkspaceID = &workspaceID
	ownerCreated, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx, owner, ownerInstallation,
	)
	if err != nil {
		t.Fatalf("CreatePendingInstallation(Owner) error = %v", err)
	}
	if ownerCreated.Installation.ID == created.Installation.ID {
		t.Fatal("two Workspace members shared one Installation")
	}

	runtimeProfileID := uuid.New()
	activated, err := fixture.repository.ActivateInstallation(fixture.ctx, member, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: runtimeProfileID,
		AgentVersionID: publication.Version.ID, PolicySnapshotID: created.Policy.ID,
		VersionDigest: publication.Version.ContentDigest,
		Audit:         fixture.auditEvidence(48), ActivatedAt: fixture.now.Add(48 * time.Minute),
	})
	if err != nil || activated.RuntimeProfileID == nil || *activated.RuntimeProfileID != runtimeProfileID {
		t.Fatalf("ActivateInstallation(Workspace source) = %+v error=%v", activated, err)
	}
	selected, err := fixture.repository.SelectInstallationVersion(fixture.ctx, member, VersionSelectionCommand{
		InstallationID: created.Installation.ID,
		VersionID:      second.Version.ID,
		BuildPolicy: func(policyVersion int64, version Version) (PolicyMaterial, error) {
			return fixture.policy(created.Installation.ID, version.ID, policyVersion, 49), nil
		},
		Audit: fixture.auditEvidence(49), SelectedAt: fixture.now.Add(49 * time.Minute),
	})
	if err != nil || selected.SelectedVersionID != second.Version.ID {
		t.Fatalf("SelectInstallationVersion(Workspace source) = %+v error=%v", selected, err)
	}
	if version, found, err := fixture.repository.FindVersion(
		fixture.ctx, member, second.Version.ID,
	); err != nil || !found || version.ID != second.Version.ID {
		t.Fatalf("FindVersion(Workspace member) = %+v found=%v error=%v", version, found, err)
	}
	if _, found, err := fixture.repository.FindVersion(
		fixture.ctx, outsider, second.Version.ID,
	); err != nil || found {
		t.Fatalf("FindVersion(Workspace outsider) found=%v error=%v", found, err)
	}

	withoutWorkspace := fixture.pendingInstallation(
		member, publication.Definition.ID, publication.Version.ID, 1, 46,
	)
	if _, err := fixture.repository.CreatePendingInstallation(
		fixture.ctx, member, withoutWorkspace,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreatePendingInstallation(without Workspace) error = %v", err)
	}

	var storedWorkspaceID uuid.UUID
	var nullUserColumns bool
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT workspace_id, tenant_id IS NULL AND owner_id IS NULL
		FROM agent_definitions WHERE id = $1
	`, publication.Definition.ID).Scan(&storedWorkspaceID, &nullUserColumns); err != nil {
		t.Fatalf("read Workspace definition ownership: %v", err)
	}
	if storedWorkspaceID != workspaceID || !nullUserColumns {
		t.Fatalf("Workspace definition ownership = %s null-user=%t", storedWorkspaceID, nullUserColumns)
	}
}

func TestRepositoryWorkspaceLifecycleAndMembershipChangesFailClosed(t *testing.T) {
	fixture := newAgentControlRepositoryFixture(t)
	owner := fixture.principal(t, 51)
	member := fixture.principal(t, 52)
	workspaceID := seedAgentWorkspace(t, fixture, owner, Principal{}, member)
	publication, err := fixture.repository.PublishWorkspaceInitial(
		fixture.ctx, owner, workspaceID, fixture.initialPublication(owner, "Lifecycle Agent", 51),
	)
	if err != nil {
		t.Fatalf("PublishWorkspaceInitial() error = %v", err)
	}
	second, err := fixture.repository.PublishWorkspaceNext(
		fixture.ctx,
		owner,
		workspaceID,
		fixture.nextPublication(owner, publication.Definition.ID, publication.Version.ID, 52),
	)
	if err != nil {
		t.Fatalf("PublishWorkspaceNext() error = %v", err)
	}
	install := fixture.pendingInstallation(member, publication.Definition.ID, publication.Version.ID, 1, 53)
	install.SourceWorkspaceID = &workspaceID
	created, err := fixture.repository.CreatePendingInstallation(fixture.ctx, member, install)
	if err != nil {
		t.Fatalf("CreatePendingInstallation(before removal) error = %v", err)
	}
	runtimeProfileID := uuid.New()
	if _, err := fixture.repository.ActivateInstallation(fixture.ctx, member, ActivationCommand{
		InstallationID: created.Installation.ID, RuntimeProfileID: runtimeProfileID,
		AgentVersionID: publication.Version.ID, PolicySnapshotID: created.Policy.ID,
		VersionDigest: publication.Version.ContentDigest,
		Audit:         fixture.auditEvidence(54), ActivatedAt: fixture.now.Add(54 * time.Minute),
	}); err != nil {
		t.Fatalf("ActivateInstallation(before removal) error = %v", err)
	}

	if _, err := fixture.postgres.Exec(fixture.ctx, `
		DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2
	`, workspaceID, member.UserID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	command := fixture.pendingInstallation(member, publication.Definition.ID, publication.Version.ID, 1, 52)
	command.SourceWorkspaceID = &workspaceID
	if _, err := fixture.repository.CreatePendingInstallation(fixture.ctx, member, command); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreatePendingInstallation(removed member) error = %v", err)
	}
	if _, err := fixture.repository.SelectInstallationVersion(fixture.ctx, member, VersionSelectionCommand{
		InstallationID: created.Installation.ID,
		VersionID:      second.Version.ID,
		BuildPolicy: func(policyVersion int64, version Version) (PolicyMaterial, error) {
			return fixture.policy(created.Installation.ID, version.ID, policyVersion, 55), nil
		},
		Audit: fixture.auditEvidence(55), SelectedAt: fixture.now.Add(55 * time.Minute),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SelectInstallationVersion(removed member) error = %v", err)
	}

	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE workspaces SET status = 'archived', archived_at = $2, revision = revision + 1, updated_at = $2
		WHERE id = $1
	`, workspaceID, fixture.now); err != nil {
		t.Fatalf("archive workspace: %v", err)
	}
	if _, err := fixture.repository.PublishWorkspaceNext(
		fixture.ctx,
		owner,
		workspaceID,
		fixture.nextPublication(owner, publication.Definition.ID, publication.Version.ID, 53),
	); !errors.Is(err, ErrWorkspaceArchived) {
		t.Fatalf("PublishWorkspaceNext(archived) error = %v", err)
	}
	if _, err := fixture.repository.ListWorkspaceDefinitions(
		fixture.ctx, owner, workspaceID,
	); !errors.Is(err, ErrWorkspaceArchived) {
		t.Fatalf("ListWorkspaceDefinitions(archived) error = %v", err)
	}
	if _, found, err := fixture.repository.FindVersion(
		fixture.ctx, owner, publication.Version.ID,
	); err != nil || found {
		t.Fatalf("FindVersion(archived Workspace) found=%v error=%v", found, err)
	}

	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE workspaces SET status = 'active', archived_at = NULL, revision = revision + 1, updated_at = $2
		WHERE id = $1
	`, workspaceID, fixture.now); err != nil {
		t.Fatalf("restore Workspace: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE users SET status = 'pending_deletion', deletion_requested_at = $1, updated_at = $1 WHERE id = $2
	`, fixture.now, owner.UserID); err != nil {
		t.Fatalf("make Owner unavailable: %v", err)
	}
	if _, err := fixture.repository.PublishWorkspaceNext(
		fixture.ctx,
		owner,
		workspaceID,
		fixture.nextPublication(owner, publication.Definition.ID, publication.Version.ID, 54),
	); !errors.Is(err, ErrWorkspaceOwnerUnavailable) {
		t.Fatalf("PublishWorkspaceNext(owner unavailable) error = %v", err)
	}
	if _, err := fixture.repository.ListWorkspaceDefinitions(
		fixture.ctx, owner, workspaceID,
	); !errors.Is(err, ErrWorkspaceOwnerUnavailable) {
		t.Fatalf("ListWorkspaceDefinitions(owner unavailable) error = %v", err)
	}
}

func seedAgentWorkspace(
	t *testing.T,
	fixture *agentControlRepositoryFixture,
	owner Principal,
	admin Principal,
	member Principal,
) uuid.UUID {
	t.Helper()
	workspaceID := uuid.New()
	tx, err := fixture.postgres.Begin(fixture.ctx)
	if err != nil {
		t.Fatalf("begin Workspace fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO workspaces (id, owner_user_id, display_name, status, revision, created_at, updated_at)
		VALUES ($1, $2, 'Agent Workspace', 'active', 1, $3, $3)
	`, workspaceID, owner.UserID, fixture.now); err != nil {
		t.Fatalf("insert Workspace: %v", err)
	}
	if _, err := tx.Exec(fixture.ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'owner', 1, $3, $3)
	`, workspaceID, owner.UserID, fixture.now); err != nil {
		t.Fatalf("insert Workspace Owner: %v", err)
	}
	if admin.UserID != uuid.Nil {
		if _, err := tx.Exec(fixture.ctx, `
			INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
			VALUES ($1, $2, 'admin', 1, $3, $3)
		`, workspaceID, admin.UserID, fixture.now); err != nil {
			t.Fatalf("insert Workspace Admin: %v", err)
		}
	}
	if member.UserID != uuid.Nil {
		if _, err := tx.Exec(fixture.ctx, `
			INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
			VALUES ($1, $2, 'member', 1, $3, $3)
		`, workspaceID, member.UserID, fixture.now); err != nil {
			t.Fatalf("insert Workspace Member: %v", err)
		}
	}
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatalf("commit Workspace fixture: %v", err)
	}
	return workspaceID
}
