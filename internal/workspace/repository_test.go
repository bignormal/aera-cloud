package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWorkspaceRepositoryLifecycleCreatesReplaysRenamesArchivesAndRestores(t *testing.T) {
	fixture := newWorkspaceRepositoryFixture(t)
	owner := fixture.actor(t, 1)
	nonMember := fixture.actor(t, 2)
	create := fixture.createCommand("Research Workspace", 1, 10)

	created, replay, err := fixture.repository.Create(fixture.ctx, owner, create)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if replay != IdempotencyFresh || created.ID != create.WorkspaceID || created.ActorRole != RoleOwner ||
		created.Status != WorkspaceStatusActive || created.MutationState != MutationStateWritable ||
		created.Revision != 1 || created.MemberCount != 1 {
		t.Fatalf("Create() = %+v replay=%q", created, replay)
	}

	var ownerRole string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT role FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2
	`, created.ID, owner.UserID).Scan(&ownerRole); err != nil || ownerRole != "owner" {
		t.Fatalf("Owner membership role = %q, error = %v", ownerRole, err)
	}
	var auditMetadata string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT metadata::text FROM audit_events
		WHERE event_type = 'workspace_created' AND object_id = $1
	`, created.ID).Scan(&auditMetadata); err != nil {
		t.Fatalf("read create audit: %v", err)
	}
	if auditMetadata != `{"workspace_id": "`+created.ID.String()+`"}` {
		t.Fatalf("create audit metadata = %s", auditMetadata)
	}

	replayed, replay, err := fixture.repository.Create(fixture.ctx, owner, create)
	if err != nil || replay != IdempotencyReplayed || replayed.ID != created.ID {
		t.Fatalf("Create(replay) = %+v replay=%q error=%v", replayed, replay, err)
	}
	conflict := create
	conflict.Idempotency.RequestDigest = sha256.Sum256([]byte("different request"))
	if _, _, err := fixture.repository.Create(fixture.ctx, owner, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Create(conflicting replay) error = %v", err)
	}

	owned, err := fixture.repository.List(fixture.ctx, owner)
	if err != nil || len(owned) != 1 || owned[0].ID != created.ID {
		t.Fatalf("List(owner) = %+v, %v", owned, err)
	}
	other, err := fixture.repository.List(fixture.ctx, nonMember)
	if err != nil || len(other) != 0 {
		t.Fatalf("List(non-member) = %+v, %v", other, err)
	}

	renamed, err := fixture.repository.Rename(fixture.ctx, owner, RenameCommand{
		WorkspaceID: created.ID, DisplayName: "Renamed Workspace", ExpectedRevision: 1,
		Audit: fixture.auditEvidence(3), UpdatedAt: fixture.now.Add(3 * time.Minute),
	})
	if err != nil || renamed.DisplayName != "Renamed Workspace" || renamed.Revision != 2 {
		t.Fatalf("Rename() = %+v, %v", renamed, err)
	}
	if _, err := fixture.repository.Rename(fixture.ctx, owner, RenameCommand{
		WorkspaceID: created.ID, DisplayName: "Stale Rename", ExpectedRevision: 1,
		Audit: fixture.auditEvidence(4), UpdatedAt: fixture.now.Add(4 * time.Minute),
	}); !errors.Is(err, ErrWorkspaceConflict) {
		t.Fatalf("Rename(stale) error = %v", err)
	}

	invitationID := uuid.New()
	tokenDigest := sha256.Sum256([]byte("pending invitation"))
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO workspace_invitations (
			id, workspace_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
	`, invitationID, created.ID, tokenDigest[:], owner.UserID, fixture.now, fixture.now.Add(7*24*time.Hour)); err != nil {
		t.Fatalf("seed pending invitation: %v", err)
	}
	archived, err := fixture.repository.Archive(fixture.ctx, owner, RevisionCommand{
		WorkspaceID: created.ID, ExpectedRevision: 2, ActiveOwnedLimit: 10,
		Audit: fixture.auditEvidence(5), ChangedAt: fixture.now.Add(5 * time.Minute),
	})
	if err != nil || archived.Status != WorkspaceStatusArchived || archived.MutationState != MutationStateArchived || archived.Revision != 3 {
		t.Fatalf("Archive() = %+v, %v", archived, err)
	}
	var invitationStatus string
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT status FROM workspace_invitations WHERE id = $1
	`, invitationID).Scan(&invitationStatus); err != nil || invitationStatus != "revoked" {
		t.Fatalf("archived invitation status = %q, error = %v", invitationStatus, err)
	}

	secondCreate := fixture.createCommand("Second Workspace", 6, 10)
	second, _, err := fixture.repository.Create(fixture.ctx, owner, secondCreate)
	if err != nil {
		t.Fatalf("Create(second) error = %v", err)
	}
	if _, err := fixture.repository.Restore(fixture.ctx, owner, RevisionCommand{
		WorkspaceID: created.ID, ExpectedRevision: 3, ActiveOwnedLimit: 1,
		Audit: fixture.auditEvidence(7), ChangedAt: fixture.now.Add(7 * time.Minute),
	}); !errors.Is(err, ErrWorkspaceLimitReached) {
		t.Fatalf("Restore(over quota) error = %v", err)
	}
	if _, err := fixture.repository.Archive(fixture.ctx, owner, RevisionCommand{
		WorkspaceID: second.ID, ExpectedRevision: 1, ActiveOwnedLimit: 10,
		Audit: fixture.auditEvidence(8), ChangedAt: fixture.now.Add(8 * time.Minute),
	}); err != nil {
		t.Fatalf("Archive(second) error = %v", err)
	}
	restored, err := fixture.repository.Restore(fixture.ctx, owner, RevisionCommand{
		WorkspaceID: created.ID, ExpectedRevision: 3, ActiveOwnedLimit: 1,
		Audit: fixture.auditEvidence(9), ChangedAt: fixture.now.Add(9 * time.Minute),
	})
	if err != nil || restored.Status != WorkspaceStatusActive || restored.MutationState != MutationStateWritable ||
		restored.ArchivedAt != nil || restored.Revision != 4 {
		t.Fatalf("Restore() = %+v, %v", restored, err)
	}
}

func TestWorkspaceRepositoryLifecycleFreezesOnOwnerDeletionAndIsolatesNonMembers(t *testing.T) {
	fixture := newWorkspaceRepositoryFixture(t)
	owner := fixture.actor(t, 10)
	admin := fixture.actor(t, 11)
	nonMember := fixture.actor(t, 12)
	created, _, err := fixture.repository.Create(fixture.ctx, owner, fixture.createCommand("Frozen Workspace", 10, 10))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, 'admin', 1, $3, $3)
	`, created.ID, admin.UserID, fixture.now); err != nil {
		t.Fatalf("seed Admin membership: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE users SET status = 'pending_deletion', deletion_requested_at = $2, updated_at = $2 WHERE id = $1
	`, owner.UserID, fixture.now.Add(time.Hour)); err != nil {
		t.Fatalf("freeze Owner: %v", err)
	}

	listed, err := fixture.repository.List(fixture.ctx, admin)
	if err != nil || len(listed) != 1 || listed[0].MutationState != MutationStateOwnerUnavailable {
		t.Fatalf("List(Admin during freeze) = %+v, %v", listed, err)
	}
	if _, err := fixture.repository.Rename(fixture.ctx, admin, RenameCommand{
		WorkspaceID: created.ID, DisplayName: "Blocked Rename", ExpectedRevision: 1,
		Audit: fixture.auditEvidence(13), UpdatedAt: fixture.now.Add(2 * time.Hour),
	}); !errors.Is(err, ErrWorkspaceOwnerUnavailable) {
		t.Fatalf("Rename(owner unavailable) error = %v", err)
	}
	if _, err := fixture.repository.Rename(fixture.ctx, nonMember, RenameCommand{
		WorkspaceID: created.ID, DisplayName: "Invisible Rename", ExpectedRevision: 1,
		Audit: fixture.auditEvidence(14), UpdatedAt: fixture.now.Add(2 * time.Hour),
	}); !errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatalf("Rename(non-member) error = %v", err)
	}
}

func TestWorkspaceRepositoryLifecycleRejectsMissingAndMismatchedOwnerRows(t *testing.T) {
	for _, test := range []struct {
		name       string
		mismatched bool
	}{
		{name: "missing Owner"},
		{name: "mismatched Owner", mismatched: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkspaceRepositoryFixture(t)
			owner := fixture.actor(t, 20)
			other := fixture.actor(t, 21)
			created, _, err := fixture.repository.Create(fixture.ctx, owner, fixture.createCommand("Corrupt Workspace", 20, 10))
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if _, err := fixture.postgres.Exec(fixture.ctx, `
				ALTER TABLE workspace_memberships DISABLE TRIGGER workspace_memberships_owner_constraint_trigger
			`); err != nil {
				t.Fatalf("disable Owner invariant trigger: %v", err)
			}
			t.Cleanup(func() {
				_, _ = fixture.postgres.Exec(context.Background(), `
					ALTER TABLE workspace_memberships ENABLE TRIGGER workspace_memberships_owner_constraint_trigger
				`)
			})
			if _, err := fixture.postgres.Exec(fixture.ctx, `
				UPDATE workspace_memberships SET role = 'member' WHERE workspace_id = $1 AND user_id = $2
			`, created.ID, owner.UserID); err != nil {
				t.Fatalf("remove matching Owner role: %v", err)
			}
			if test.mismatched {
				if _, err := fixture.postgres.Exec(fixture.ctx, `
					INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
					VALUES ($1, $2, 'owner', 1, $3, $3)
				`, created.ID, other.UserID, fixture.now); err != nil {
					t.Fatalf("insert mismatched Owner: %v", err)
				}
			}
			if _, err := fixture.postgres.Exec(fixture.ctx, `
				ALTER TABLE workspace_memberships ENABLE TRIGGER workspace_memberships_owner_constraint_trigger
			`); err != nil {
				t.Fatalf("re-enable Owner invariant trigger: %v", err)
			}
			if _, err := fixture.repository.List(fixture.ctx, owner); !errors.Is(err, ErrServiceUnavailable) {
				t.Fatalf("List(corrupt Owner) error = %v, want ErrServiceUnavailable", err)
			}
		})
	}
}

func TestWorkspaceRepositoryLifecycleRollsBackWhenAuditInsertionFails(t *testing.T) {
	fixture := newWorkspaceRepositoryFixture(t)
	owner := fixture.actor(t, 30)
	command := fixture.createCommand("Rollback Workspace", 30, 10)
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO audit_events (id, event_type, outcome, metadata, created_at)
		VALUES ($1, 'browser_login', 'success', '{}'::jsonb, $2)
	`, command.Audit.EventID, fixture.now); err != nil {
		t.Fatalf("seed duplicate audit event: %v", err)
	}

	if _, _, err := fixture.repository.Create(fixture.ctx, owner, command); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("Create(audit failure) error = %v", err)
	}
	checks := []struct {
		name  string
		query string
		args  []any
	}{
		{name: "workspace", query: `SELECT count(*) FROM workspaces WHERE id = $1`, args: []any{command.WorkspaceID}},
		{name: "membership", query: `SELECT count(*) FROM workspace_memberships WHERE workspace_id = $1`, args: []any{command.WorkspaceID}},
		{name: "idempotency", query: `SELECT count(*) FROM workspace_idempotency_records
			WHERE actor_user_id = $1 AND operation = 'workspace_create' AND key_digest = $2`,
			args: []any{owner.UserID, command.Idempotency.KeyDigest[:]}},
	}
	for _, check := range checks {
		var count int
		if err := fixture.postgres.QueryRow(fixture.ctx, check.query, check.args...).Scan(&count); err != nil {
			t.Fatalf("count %s rollback evidence: %v", check.name, err)
		}
		if count != 0 {
			t.Fatalf("%s rows after rollback = %d, want 0", check.name, count)
		}
	}
}

func TestWorkspaceRepositoryMemberRolesRemovalAndLeave(t *testing.T) {
	fixture := newWorkspaceRepositoryFixture(t)
	owner := fixture.actor(t, 40)
	admin := fixture.actor(t, 41)
	member := fixture.actor(t, 42)
	created, _, err := fixture.repository.Create(fixture.ctx, owner, fixture.createCommand("Membership Workspace", 40, 10))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	fixture.addMembership(t, created.ID, admin.UserID, RoleAdmin, 1)
	fixture.addMembership(t, created.ID, member.UserID, RoleMember, 1)

	members, err := fixture.repository.ListMembers(fixture.ctx, owner, created.ID)
	if err != nil || len(members) != 3 {
		t.Fatalf("ListMembers() = %+v, %v", members, err)
	}
	promoted, err := fixture.repository.ChangeMemberRole(fixture.ctx, owner, ChangeRoleCommand{
		WorkspaceID: created.ID, UserID: member.UserID, Role: RoleAdmin, ExpectedRevision: 1,
		Audit: fixture.auditEvidence(43), ChangedAt: fixture.now.Add(43 * time.Minute),
	})
	if err != nil || promoted.Role != RoleAdmin || promoted.Revision != 2 {
		t.Fatalf("ChangeMemberRole(promote) = %+v, %v", promoted, err)
	}
	if _, err := fixture.repository.ChangeMemberRole(fixture.ctx, admin, ChangeRoleCommand{
		WorkspaceID: created.ID, UserID: member.UserID, Role: RoleMember, ExpectedRevision: 2,
		Audit: fixture.auditEvidence(44), ChangedAt: fixture.now.Add(44 * time.Minute),
	}); !errors.Is(err, ErrWorkspaceForbidden) {
		t.Fatalf("ChangeMemberRole(Admin manages Admin) error = %v", err)
	}
	demoted, err := fixture.repository.ChangeMemberRole(fixture.ctx, owner, ChangeRoleCommand{
		WorkspaceID: created.ID, UserID: member.UserID, Role: RoleMember, ExpectedRevision: 2,
		Audit: fixture.auditEvidence(45), ChangedAt: fixture.now.Add(45 * time.Minute),
	})
	if err != nil || demoted.Role != RoleMember || demoted.Revision != 3 {
		t.Fatalf("ChangeMemberRole(demote) = %+v, %v", demoted, err)
	}
	if err := fixture.repository.RemoveMember(fixture.ctx, admin, RemoveMemberCommand{
		WorkspaceID: created.ID, UserID: member.UserID, ExpectedRevision: 3,
		Audit: fixture.auditEvidence(46), RemovedAt: fixture.now.Add(46 * time.Minute),
	}); err != nil {
		t.Fatalf("RemoveMember(Admin removes Member) error = %v", err)
	}
	if _, err := fixture.repository.ListMembers(fixture.ctx, member, created.ID); !errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatalf("removed member ListMembers() error = %v", err)
	}
	if err := fixture.repository.Leave(fixture.ctx, admin, created.ID); err != nil {
		t.Fatalf("Leave(Admin) error = %v", err)
	}
	if err := fixture.repository.Leave(fixture.ctx, owner, created.ID); !errors.Is(err, ErrWorkspaceForbidden) {
		t.Fatalf("Leave(Owner) error = %v", err)
	}
}

func TestWorkspaceRepositoryInvitationQuotaIsAtomicAndSecretOnce(t *testing.T) {
	fixture := newWorkspaceRepositoryFixture(t)
	owner := fixture.actor(t, 50)
	created, _, err := fixture.repository.Create(fixture.ctx, owner, fixture.createCommand("Invitation Quota", 50, 10))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	for index := byte(1); index <= 19; index++ {
		command := fixture.invitationCommand(t, created.ID, index, 20)
		if _, _, err := fixture.repository.CreateInvitation(fixture.ctx, owner, command); err != nil {
			t.Fatalf("CreateInvitation(seed %d) error = %v", index, err)
		}
	}
	commands := []CreateInvitationCommand{
		fixture.invitationCommand(t, created.ID, 20, 20),
		fixture.invitationCommand(t, created.ID, 21, 20),
	}
	start := make(chan struct{})
	results := make(chan struct {
		creation InvitationCreation
		replay   IdempotencyReplay
		err      error
	}, len(commands))
	for _, command := range commands {
		command := command
		go func() {
			<-start
			creation, replay, createErr := fixture.repository.CreateInvitation(fixture.ctx, owner, command)
			results <- struct {
				creation InvitationCreation
				replay   IdempotencyReplay
				err      error
			}{creation: creation, replay: replay, err: createErr}
		}()
	}
	close(start)
	successes := 0
	limits := 0
	var winningCommand CreateInvitationCommand
	for range commands {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			if result.replay != IdempotencyFresh || result.creation.Secret == nil ||
				result.creation.Secret.RawToken == "" {
				t.Fatalf("fresh invitation result = %+v replay=%q", result.creation, result.replay)
			}
			for _, command := range commands {
				if command.InvitationID == result.creation.Invitation.ID {
					winningCommand = command
				}
			}
		case errors.Is(result.err, ErrInvitationLimitReached):
			limits++
		default:
			t.Fatalf("concurrent CreateInvitation() error = %v", result.err)
		}
	}
	if successes != 1 || limits != 1 {
		t.Fatalf("concurrent invitation successes=%d limits=%d", successes, limits)
	}
	var pending int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM workspace_invitations WHERE workspace_id = $1 AND status = 'pending'
	`, created.ID).Scan(&pending); err != nil || pending != 20 {
		t.Fatalf("pending invitations = %d, error = %v", pending, err)
	}
	replayed, replay, err := fixture.repository.CreateInvitation(fixture.ctx, owner, winningCommand)
	if err != nil || replay != IdempotencyReplayed || replayed.Secret != nil || replayed.Invitation.ID != winningCommand.InvitationID {
		t.Fatalf("CreateInvitation(replay) = %+v replay=%q error=%v", replayed, replay, err)
	}
}

func TestWorkspaceRepositoryMemberQuotaIsAtomicAcrossInvitationAcceptance(t *testing.T) {
	fixture := newWorkspaceRepositoryFixture(t)
	owner := fixture.actor(t, 150)
	created, _, err := fixture.repository.Create(fixture.ctx, owner, fixture.createCommand("Member Quota", 150, 10))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	for discriminator := byte(1); discriminator <= 98; discriminator++ {
		member := fixture.actor(t, discriminator)
		fixture.addMembership(t, created.ID, member.UserID, RoleMember, 1)
	}
	candidates := []Actor{fixture.actor(t, 101), fixture.actor(t, 102)}
	commands := make([]AcceptInvitationCommand, 0, 2)
	for index, actor := range candidates {
		invitation := fixture.invitationCommand(t, created.ID, byte(110+index), 20)
		if _, _, err := fixture.repository.CreateInvitation(fixture.ctx, owner, invitation); err != nil {
			t.Fatalf("CreateInvitation(candidate %d) error = %v", index, err)
		}
		commands = append(commands, fixture.acceptCommand(invitation.Secret.Digest, byte(120+index), 100))
		_ = actor
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for index, actor := range candidates {
		index, actor := index, actor
		go func() {
			<-start
			_, acceptErr := fixture.repository.AcceptInvitation(fixture.ctx, actor, commands[index])
			results <- acceptErr
		}()
	}
	close(start)
	successes := 0
	limits := 0
	for range candidates {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrMemberLimitReached):
			limits++
		default:
			t.Fatalf("concurrent AcceptInvitation() error = %v", err)
		}
	}
	if successes != 1 || limits != 1 {
		t.Fatalf("concurrent acceptance successes=%d limits=%d", successes, limits)
	}
	var memberCount int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM workspace_memberships WHERE workspace_id = $1
	`, created.ID).Scan(&memberCount); err != nil || memberCount != 100 {
		t.Fatalf("member count = %d, error = %v", memberCount, err)
	}
}

func TestWorkspaceRepositoryInvitationIsSingleUseGenericAndReplayFirst(t *testing.T) {
	fixture := newWorkspaceRepositoryFixture(t)
	owner := fixture.actor(t, 160)
	member := fixture.actor(t, 161)
	other := fixture.actor(t, 162)
	created, _, err := fixture.repository.Create(fixture.ctx, owner, fixture.createCommand("Invitation Lifecycle", 160, 10))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	invitation := fixture.invitationCommand(t, created.ID, 163, 20)
	creation, _, err := fixture.repository.CreateInvitation(fixture.ctx, owner, invitation)
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	if creation.Invitation.ExpiresAt.Sub(creation.Invitation.CreatedAt) != 7*24*time.Hour {
		t.Fatalf("invitation validity = %v", creation.Invitation.ExpiresAt.Sub(creation.Invitation.CreatedAt))
	}
	accept := fixture.acceptCommand(invitation.Secret.Digest, 164, 100)
	accepted, err := fixture.repository.AcceptInvitation(fixture.ctx, member, accept)
	if err != nil || accepted.Member.UserID != member.UserID || accepted.Member.Role != RoleMember || accepted.Workspace.ID != created.ID {
		t.Fatalf("AcceptInvitation() = %+v, %v", accepted, err)
	}
	replayBeforeToken := accept
	replayBeforeToken.TokenDigest = sha256.Sum256([]byte("unavailable token after replay lookup"))
	replayed, err := fixture.repository.AcceptInvitation(fixture.ctx, member, replayBeforeToken)
	if err != nil || replayed.Member.UserID != member.UserID || replayed.Workspace.ID != created.ID {
		t.Fatalf("AcceptInvitation(replay before token) = %+v, %v", replayed, err)
	}

	unavailable := []AcceptInvitationCommand{
		fixture.acceptCommand(sha256.Sum256([]byte("unknown invitation")), 165, 100),
		fixture.acceptCommand(invitation.Secret.Digest, 166, 100),
	}
	expiredID := uuid.New()
	expiredDigest := sha256.Sum256([]byte("expired invitation"))
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO workspace_invitations (
			id, workspace_id, token_digest, created_by_user_id, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
	`, expiredID, created.ID, expiredDigest[:], owner.UserID, fixture.now.Add(-8*24*time.Hour), fixture.now.Add(-24*time.Hour)); err != nil {
		t.Fatalf("seed expired invitation: %v", err)
	}
	unavailable = append(unavailable, fixture.acceptCommand(expiredDigest, 167, 100))
	revoked := fixture.invitationCommand(t, created.ID, 168, 20)
	if _, _, err := fixture.repository.CreateInvitation(fixture.ctx, owner, revoked); err != nil {
		t.Fatalf("CreateInvitation(revoked) error = %v", err)
	}
	if err := fixture.repository.RevokeInvitation(fixture.ctx, owner, RevokeInvitationCommand{
		WorkspaceID: created.ID, InvitationID: revoked.InvitationID,
		Audit: fixture.auditEvidence(169), RevokedAt: fixture.now.Add(169 * time.Minute),
	}); err != nil {
		t.Fatalf("RevokeInvitation() error = %v", err)
	}
	unavailable = append(unavailable, fixture.acceptCommand(revoked.Secret.Digest, 170, 100))
	for index, command := range unavailable {
		if _, err := fixture.repository.AcceptInvitation(fixture.ctx, other, command); !errors.Is(err, ErrInvitationUnavailable) {
			t.Fatalf("unavailable invitation case %d error = %v", index, err)
		}
	}

	existingMemberInvite := fixture.invitationCommand(t, created.ID, 171, 20)
	if _, _, err := fixture.repository.CreateInvitation(fixture.ctx, owner, existingMemberInvite); err != nil {
		t.Fatalf("CreateInvitation(existing member) error = %v", err)
	}
	existing, err := fixture.repository.AcceptInvitation(
		fixture.ctx, owner, fixture.acceptCommand(existingMemberInvite.Secret.Digest, 172, 100),
	)
	if err != nil || existing.Member.Role != RoleOwner {
		t.Fatalf("AcceptInvitation(existing Owner) = %+v, %v", existing, err)
	}
}

func TestWorkspaceRepositoryInvitationConcurrentAcceptanceHasOneWinner(t *testing.T) {
	fixture := newWorkspaceRepositoryFixture(t)
	owner := fixture.actor(t, 180)
	first := fixture.actor(t, 181)
	second := fixture.actor(t, 182)
	created, _, err := fixture.repository.Create(fixture.ctx, owner, fixture.createCommand("Concurrent Invitation", 180, 10))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	invitation := fixture.invitationCommand(t, created.ID, 183, 20)
	if _, _, err := fixture.repository.CreateInvitation(fixture.ctx, owner, invitation); err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	actors := []Actor{first, second}
	commands := []AcceptInvitationCommand{
		fixture.acceptCommand(invitation.Secret.Digest, 184, 100),
		fixture.acceptCommand(invitation.Secret.Digest, 185, 100),
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for index, actor := range actors {
		index, actor := index, actor
		go func() {
			<-start
			_, acceptErr := fixture.repository.AcceptInvitation(fixture.ctx, actor, commands[index])
			results <- acceptErr
		}()
	}
	close(start)
	successes := 0
	unavailable := 0
	for range actors {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvitationUnavailable):
			unavailable++
		default:
			t.Fatalf("concurrent acceptance error = %v", err)
		}
	}
	if successes != 1 || unavailable != 1 {
		t.Fatalf("concurrent acceptance successes=%d unavailable=%d", successes, unavailable)
	}
}

type workspaceRepositoryFixture struct {
	ctx        context.Context
	postgres   *pgxpool.Pool
	repository *PostgresRepository
	now        time.Time
}

func newWorkspaceRepositoryFixture(t *testing.T) *workspaceRepositoryFixture {
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
		t.Fatalf("truncate Workspace fixture: %v", err)
	}
	return &workspaceRepositoryFixture{
		ctx: ctx, postgres: postgres, repository: NewPostgresRepository(postgres),
		now: time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC),
	}
}

func (f *workspaceRepositoryFixture) actor(t *testing.T, discriminator byte) Actor {
	t.Helper()
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)
	`, actor.UserID, f.now); err != nil {
		t.Fatalf("seed actor user: %v", err)
	}
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Workspace Test Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, actor.DeviceID, actor.UserID, uuid.New(), bytes.Repeat([]byte{discriminator}, 32), f.now); err != nil {
		t.Fatalf("seed actor device: %v", err)
	}
	return actor
}

func (f *workspaceRepositoryFixture) addMembership(
	t *testing.T,
	workspaceID uuid.UUID,
	userID uuid.UUID,
	role Role,
	revision int64,
) {
	t.Helper()
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO workspace_memberships (workspace_id, user_id, role, revision, joined_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)
	`, workspaceID, userID, role, revision, f.now); err != nil {
		t.Fatalf("add %s membership: %v", role, err)
	}
}

func (f *workspaceRepositoryFixture) createCommand(name string, discriminator byte, limit int) CreateCommand {
	createdAt := f.now.Add(time.Duration(discriminator) * time.Minute)
	return CreateCommand{
		WorkspaceID: nameBasedTestUUID(discriminator), DisplayName: name, ActiveOwnedLimit: limit,
		Idempotency: IdempotencyEvidence{
			KeyDigest: sha256.Sum256([]byte{discriminator, 1}), RequestDigest: sha256.Sum256([]byte{discriminator, 2}),
			ExpiresAt: createdAt.Add(24 * time.Hour),
		},
		Audit: fixtureAuditEvidence(discriminator), CreatedAt: createdAt,
	}
}

func (f *workspaceRepositoryFixture) auditEvidence(discriminator byte) AuditEvidence {
	return fixtureAuditEvidence(discriminator)
}

func (f *workspaceRepositoryFixture) invitationCommand(
	t *testing.T,
	workspaceID uuid.UUID,
	discriminator byte,
	limit int,
) CreateInvitationCommand {
	t.Helper()
	secret, err := NewInvitationSecret(bytes.NewReader(bytes.Repeat([]byte{discriminator}, 32)))
	if err != nil {
		t.Fatalf("NewInvitationSecret() error = %v", err)
	}
	createdAt := f.now.Add(time.Duration(discriminator) * time.Minute)
	return CreateInvitationCommand{
		InvitationID: workspaceInvitationTestUUID(discriminator), WorkspaceID: workspaceID, Secret: secret,
		PendingInviteLimit: limit,
		Idempotency: IdempotencyEvidence{
			KeyDigest: sha256.Sum256([]byte{discriminator, 3}), RequestDigest: sha256.Sum256([]byte{discriminator, 4}),
			ExpiresAt: createdAt.Add(24 * time.Hour),
		},
		Audit: fixtureAuditEvidence(discriminator), CreatedAt: createdAt,
	}
}

func (f *workspaceRepositoryFixture) acceptCommand(
	tokenDigest [sha256.Size]byte,
	discriminator byte,
	memberLimit int,
) AcceptInvitationCommand {
	acceptedAt := f.now.Add(time.Duration(discriminator) * time.Minute)
	return AcceptInvitationCommand{
		TokenDigest: tokenDigest, MemberLimit: memberLimit,
		Idempotency: IdempotencyEvidence{
			KeyDigest: sha256.Sum256([]byte{discriminator, 5}), RequestDigest: sha256.Sum256([]byte{discriminator, 6}),
			ExpiresAt: acceptedAt.Add(24 * time.Hour),
		},
		Audit: fixtureAuditEvidence(discriminator), AcceptedAt: acceptedAt,
	}
}

func fixtureAuditEvidence(discriminator byte) AuditEvidence {
	return AuditEvidence{
		EventID: uuid.New(), RequestID: fmt.Sprintf("workspace-request-%d", discriminator),
	}
}

func nameBasedTestUUID(discriminator byte) uuid.UUID {
	digest := sha256.Sum256([]byte("workspace-test-id-" + string([]byte{discriminator})))
	id, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

func workspaceInvitationTestUUID(discriminator byte) uuid.UUID {
	digest := sha256.Sum256([]byte("workspace-invitation-test-id-" + string([]byte{discriminator})))
	id, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}
