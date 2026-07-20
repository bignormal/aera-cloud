package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/google/uuid"
)

func TestWorkspaceServiceCreateAndInvitationCanonicalEvidence(t *testing.T) {
	fixture := newWorkspaceServiceFixture(t)
	var createCommand CreateCommand
	fixture.repository.create = func(_ context.Context, _ Actor, command CreateCommand) (Workspace, IdempotencyReplay, error) {
		createCommand = command
		return fixture.workspace(RoleOwner, MutationStateWritable), IdempotencyFresh, nil
	}
	workspace, replay, err := fixture.service.CreateWorkspace(fixture.ctx, fixture.actor, CreateWorkspaceRequest{
		DisplayName: "  Team Space  ", IdempotencyKey: "  opaque key  ", RequestID: "request-create",
	})
	if err != nil || replay != IdempotencyFresh || workspace.ID == uuid.Nil {
		t.Fatalf("CreateWorkspace() = %+v, %q, %v", workspace, replay, err)
	}
	if createCommand.DisplayName != "Team Space" || createCommand.ActiveOwnedLimit != fixture.quotas.ActiveOwned ||
		createCommand.Idempotency.KeyDigest != sha256.Sum256([]byte("  opaque key  ")) ||
		createCommand.Idempotency.RequestDigest != canonicalWorkspaceCreateDigest("Team Space") ||
		!createCommand.Idempotency.ExpiresAt.Equal(fixture.now.Add(24*time.Hour)) {
		t.Fatalf("CreateWorkspace command = %+v", createCommand)
	}
	fixture.limiter.assertLast(t, LimitWorkspaceCreate, nil)

	fixture.repository.list = func(context.Context, Actor) ([]Workspace, error) {
		return []Workspace{fixture.workspace(RoleAdmin, MutationStateWritable)}, nil
	}
	var invitationCommand CreateInvitationCommand
	fixture.repository.createInvitation = func(_ context.Context, _ Actor, command CreateInvitationCommand) (InvitationCreation, IdempotencyReplay, error) {
		invitationCommand = command
		return InvitationCreation{Invitation: Invitation{
			ID: command.InvitationID, Status: InvitationStatusPending,
			CreatedAt: command.CreatedAt, ExpiresAt: command.CreatedAt.Add(7 * 24 * time.Hour),
		}, Secret: &command.Secret}, IdempotencyFresh, nil
	}
	created, replay, err := fixture.service.CreateInvitation(fixture.ctx, fixture.actor, CreateInvitationRequest{
		WorkspaceID: fixture.workspaceID, IdempotencyKey: "invite-key", RequestID: "request-invite",
	})
	if err != nil || replay != IdempotencyFresh || created.Token == "" ||
		created.InviteURL != "agentera://workspace-invitation#"+created.Token || created.SecretReplayable {
		t.Fatalf("CreateInvitation() = %+v, %q, %v", created, replay, err)
	}
	if len(created.Token) != 43 || invitationCommand.Secret.RawToken != created.Token ||
		invitationCommand.PendingInviteLimit != fixture.quotas.PendingInvitations ||
		invitationCommand.Idempotency.RequestDigest != canonicalInvitationCreateDigest(fixture.workspaceID) {
		t.Fatalf("invitation command/result mismatch: command=%+v result=%+v", invitationCommand, created)
	}
	fixture.limiter.assertLast(t, LimitInvitationCreate, &fixture.workspaceID)

	fixture.repository.createInvitation = func(_ context.Context, _ Actor, command CreateInvitationCommand) (InvitationCreation, IdempotencyReplay, error) {
		return InvitationCreation{Invitation: Invitation{
			ID: command.InvitationID, Status: InvitationStatusPending,
			CreatedAt: command.CreatedAt, ExpiresAt: command.CreatedAt.Add(7 * 24 * time.Hour),
		}}, IdempotencyReplayed, nil
	}
	replayed, replay, err := fixture.service.CreateInvitation(fixture.ctx, fixture.actor, CreateInvitationRequest{
		WorkspaceID: fixture.workspaceID, IdempotencyKey: "invite-key", RequestID: "request-invite-replay",
	})
	if err != nil || replay != IdempotencyReplayed || replayed.Token != "" || replayed.InviteURL != "" || replayed.SecretReplayable {
		t.Fatalf("CreateInvitation(replay) = %+v, %q, %v", replayed, replay, err)
	}
}

func TestWorkspaceServicePermissionMatrixPreventsUnauthorizedMutation(t *testing.T) {
	roles := []Role{RoleOwner, RoleAdmin, RoleMember}
	tests := []struct {
		name      string
		operation Operation
		allowed   map[Role]bool
	}{
		{name: "rename", operation: OperationRename, allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true}},
		{name: "invite", operation: OperationInvite, allowed: map[Role]bool{RoleOwner: true, RoleAdmin: true}},
		{name: "archive", operation: OperationArchiveRestore, allowed: map[Role]bool{RoleOwner: true}},
		{name: "leave", operation: OperationLeave, allowed: map[Role]bool{RoleAdmin: true, RoleMember: true}},
	}
	for _, test := range tests {
		for _, role := range roles {
			t.Run(test.name+"/"+string(role), func(t *testing.T) {
				fixture := newWorkspaceServiceFixture(t)
				fixture.repository.list = func(context.Context, Actor) ([]Workspace, error) {
					return []Workspace{fixture.workspace(role, MutationStateWritable)}, nil
				}
				var err error
				switch test.operation {
				case OperationRename:
					_, err = fixture.service.RenameWorkspace(fixture.ctx, fixture.actor, RenameWorkspaceRequest{
						WorkspaceID: fixture.workspaceID, DisplayName: "Renamed", ExpectedRevision: 1, RequestID: "request-rename",
					})
				case OperationInvite:
					_, _, err = fixture.service.CreateInvitation(fixture.ctx, fixture.actor, CreateInvitationRequest{
						WorkspaceID: fixture.workspaceID, IdempotencyKey: "invite-key", RequestID: "request-invite",
					})
				case OperationArchiveRestore:
					_, err = fixture.service.ArchiveWorkspace(fixture.ctx, fixture.actor, WorkspaceRevisionRequest{
						WorkspaceID: fixture.workspaceID, ExpectedRevision: 1, RequestID: "request-archive",
					})
				case OperationLeave:
					err = fixture.service.LeaveWorkspace(fixture.ctx, fixture.actor, fixture.workspaceID, "request-leave")
				}
				if test.allowed[role] {
					if err != nil {
						t.Fatalf("allowed %s(%s) error = %v", test.name, role, err)
					}
					return
				}
				if !errors.Is(err, ErrWorkspaceForbidden) {
					t.Fatalf("denied %s(%s) error = %v", test.name, role, err)
				}
				if fixture.repository.mutationCalls != 0 {
					t.Fatalf("denied %s(%s) mutation calls = %d", test.name, role, fixture.repository.mutationCalls)
				}
				fixture.auditor.assertLast(t, audit.OutcomeDenied, "workspace_forbidden")
			})
		}
	}
}

func TestWorkspaceServicePermissionTableIsExact(t *testing.T) {
	expected := map[Operation]map[Role]bool{
		OperationRead:           {RoleOwner: true, RoleAdmin: true, RoleMember: true},
		OperationRename:         {RoleOwner: true, RoleAdmin: true},
		OperationInvite:         {RoleOwner: true, RoleAdmin: true},
		OperationRemoveMember:   {RoleOwner: true, RoleAdmin: true},
		OperationManageAdmin:    {RoleOwner: true},
		OperationArchiveRestore: {RoleOwner: true},
		OperationLeave:          {RoleAdmin: true, RoleMember: true},
	}
	if len(permissions) != len(expected) {
		t.Fatalf("permission operation count = %d, want %d", len(permissions), len(expected))
	}
	for operation, expectedRoles := range expected {
		actualRoles, ok := permissions[operation]
		if !ok {
			t.Fatalf("permission operation %q is missing", operation)
		}
		for _, role := range []Role{RoleOwner, RoleAdmin, RoleMember} {
			if actualRoles[role] != expectedRoles[role] {
				t.Fatalf("permission %s/%s = %v, want %v", operation, role, actualRoles[role], expectedRoles[role])
			}
		}
	}
}

func TestWorkspaceServiceTargetSensitiveMemberRules(t *testing.T) {
	tests := []struct {
		name       string
		actorRole  Role
		targetRole Role
		action     string
		want       error
	}{
		{name: "owner promotes member", actorRole: RoleOwner, targetRole: RoleMember, action: "promote"},
		{name: "owner demotes admin", actorRole: RoleOwner, targetRole: RoleAdmin, action: "demote"},
		{name: "owner removes admin", actorRole: RoleOwner, targetRole: RoleAdmin, action: "remove"},
		{name: "admin removes member", actorRole: RoleAdmin, targetRole: RoleMember, action: "remove"},
		{name: "admin cannot remove admin", actorRole: RoleAdmin, targetRole: RoleAdmin, action: "remove", want: ErrWorkspaceForbidden},
		{name: "admin cannot promote member", actorRole: RoleAdmin, targetRole: RoleMember, action: "promote", want: ErrWorkspaceForbidden},
		{name: "member cannot remove member", actorRole: RoleMember, targetRole: RoleMember, action: "remove", want: ErrWorkspaceForbidden},
		{name: "owner cannot change owner", actorRole: RoleOwner, targetRole: RoleOwner, action: "demote", want: ErrMembershipConflict},
		{name: "owner cannot remove owner", actorRole: RoleOwner, targetRole: RoleOwner, action: "remove", want: ErrMembershipConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkspaceServiceFixture(t)
			targetID := uuid.New()
			fixture.repository.list = func(context.Context, Actor) ([]Workspace, error) {
				return []Workspace{fixture.workspace(test.actorRole, MutationStateWritable)}, nil
			}
			fixture.repository.listMembers = func(context.Context, Actor, uuid.UUID) ([]Member, error) {
				return []Member{{UserID: targetID, Role: test.targetRole, Revision: 3, JoinedAt: fixture.now}}, nil
			}
			var err error
			switch test.action {
			case "promote":
				_, err = fixture.service.ChangeMemberRole(fixture.ctx, fixture.actor, ChangeMemberRoleRequest{
					WorkspaceID: fixture.workspaceID, UserID: targetID, Role: RoleAdmin, ExpectedRevision: 3,
					RequestID: "request-role",
				})
			case "demote":
				_, err = fixture.service.ChangeMemberRole(fixture.ctx, fixture.actor, ChangeMemberRoleRequest{
					WorkspaceID: fixture.workspaceID, UserID: targetID, Role: RoleMember, ExpectedRevision: 3,
					RequestID: "request-role",
				})
			case "remove":
				err = fixture.service.RemoveMember(fixture.ctx, fixture.actor, RemoveMemberRequest{
					WorkspaceID: fixture.workspaceID, UserID: targetID, ExpectedRevision: 3, RequestID: "request-remove",
				})
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("member action error = %v, want %v", err, test.want)
			}
			if test.want != nil {
				if fixture.repository.mutationCalls != 0 {
					t.Fatalf("denied member action mutation calls = %d", fixture.repository.mutationCalls)
				}
				fixture.auditor.assertLast(t, audit.OutcomeDenied, workspaceReasonCode(test.want))
			}
		})
	}
}

func TestWorkspaceServiceRejectsStaleAndDuplicateMemberTransitionsBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name             string
		targetRole       Role
		desiredRole      Role
		expectedRevision int64
	}{
		{name: "stale revision", targetRole: RoleMember, desiredRole: RoleAdmin, expectedRevision: 2},
		{name: "duplicate role", targetRole: RoleMember, desiredRole: RoleMember, expectedRevision: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkspaceServiceFixture(t)
			targetID := uuid.New()
			fixture.repository.list = func(context.Context, Actor) ([]Workspace, error) {
				return []Workspace{fixture.workspace(RoleOwner, MutationStateWritable)}, nil
			}
			fixture.repository.listMembers = func(context.Context, Actor, uuid.UUID) ([]Member, error) {
				return []Member{{UserID: targetID, Role: test.targetRole, Revision: 3, JoinedAt: fixture.now}}, nil
			}
			_, err := fixture.service.ChangeMemberRole(fixture.ctx, fixture.actor, ChangeMemberRoleRequest{
				WorkspaceID: fixture.workspaceID, UserID: targetID, Role: test.desiredRole,
				ExpectedRevision: test.expectedRevision, RequestID: "request-conflict",
			})
			if !errors.Is(err, ErrMembershipConflict) || fixture.repository.mutationCalls != 0 {
				t.Fatalf("ChangeMemberRole(%s) error=%v mutationCalls=%d", test.name, err, fixture.repository.mutationCalls)
			}
			fixture.auditor.assertLast(t, audit.OutcomeDenied, "membership_conflict")
		})
	}
}

func TestWorkspaceServiceRejectsArchivedAndOwnerUnavailableBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name  string
		state MutationState
		want  error
	}{
		{name: "archived", state: MutationStateArchived, want: ErrWorkspaceArchived},
		{name: "owner unavailable", state: MutationStateOwnerUnavailable, want: ErrWorkspaceOwnerUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkspaceServiceFixture(t)
			fixture.repository.list = func(context.Context, Actor) ([]Workspace, error) {
				return []Workspace{fixture.workspace(RoleOwner, test.state)}, nil
			}
			_, err := fixture.service.RenameWorkspace(fixture.ctx, fixture.actor, RenameWorkspaceRequest{
				WorkspaceID: fixture.workspaceID, DisplayName: "Blocked", ExpectedRevision: 1, RequestID: "request-blocked",
			})
			if !errors.Is(err, test.want) || fixture.repository.mutationCalls != 0 {
				t.Fatalf("RenameWorkspace(%s) error=%v mutationCalls=%d", test.state, err, fixture.repository.mutationCalls)
			}
			fixture.auditor.assertLast(t, audit.OutcomeDenied, workspaceReasonCode(test.want))
		})
	}
}

func TestWorkspaceServiceAuditsPreflightDependencyFailureAsFailure(t *testing.T) {
	fixture := newWorkspaceServiceFixture(t)
	fixture.repository.list = func(context.Context, Actor) ([]Workspace, error) {
		return nil, ErrServiceUnavailable
	}
	_, err := fixture.service.RenameWorkspace(fixture.ctx, fixture.actor, RenameWorkspaceRequest{
		WorkspaceID: fixture.workspaceID, DisplayName: "Unavailable", ExpectedRevision: 1, RequestID: "request-unavailable",
	})
	if !errors.Is(err, ErrServiceUnavailable) || fixture.repository.mutationCalls != 0 {
		t.Fatalf("RenameWorkspace(preflight failure) error=%v mutationCalls=%d", err, fixture.repository.mutationCalls)
	}
	fixture.auditor.assertLast(t, audit.OutcomeFailure, "service_unavailable")
}

func TestWorkspaceServiceLimiterDenialAndFailureFailClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		limiterErr error
		want       error
		outcome    audit.Outcome
		reason     string
	}{
		{name: "denied", limiterErr: ErrRateLimited, want: ErrRateLimited, outcome: audit.OutcomeDenied, reason: "rate_limited"},
		{name: "unavailable", limiterErr: ErrServiceUnavailable, want: ErrServiceUnavailable, outcome: audit.OutcomeFailure, reason: "service_unavailable"},
	} {
		for _, action := range []LimitAction{LimitWorkspaceCreate, LimitInvitationCreate, LimitInvitationAccept} {
			t.Run(test.name+"/"+string(action), func(t *testing.T) {
				fixture := newWorkspaceServiceFixture(t)
				fixture.limiter.err = test.limiterErr
				fixture.limiter.retryAfter = 37 * time.Second
				fixture.repository.list = func(context.Context, Actor) ([]Workspace, error) {
					return []Workspace{fixture.workspace(RoleAdmin, MutationStateWritable)}, nil
				}
				var err error
				switch action {
				case LimitWorkspaceCreate:
					_, _, err = fixture.service.CreateWorkspace(fixture.ctx, fixture.actor, CreateWorkspaceRequest{
						DisplayName: "Blocked", IdempotencyKey: "create-key", RequestID: "request-limited",
					})
				case LimitInvitationCreate:
					_, _, err = fixture.service.CreateInvitation(fixture.ctx, fixture.actor, CreateInvitationRequest{
						WorkspaceID: fixture.workspaceID, IdempotencyKey: "invite-key", RequestID: "request-limited",
					})
				case LimitInvitationAccept:
					secret, secretErr := NewInvitationSecret(bytes.NewReader(bytes.Repeat([]byte{8}, 32)))
					if secretErr != nil {
						t.Fatalf("NewInvitationSecret() error = %v", secretErr)
					}
					_, err = fixture.service.AcceptInvitation(fixture.ctx, fixture.actor, AcceptInvitationRequest{
						Token: secret.RawToken, IdempotencyKey: "accept-key", RequestID: "request-limited",
					})
				}
				if !errors.Is(err, test.want) || fixture.repository.mutationCalls != 0 {
					t.Fatalf("limited %s error=%v mutationCalls=%d", action, err, fixture.repository.mutationCalls)
				}
				if test.want == ErrRateLimited {
					var limited *RateLimitError
					if !errors.As(err, &limited) || limited.RetryAfter != 37*time.Second {
						t.Fatalf("rate limit error = %#v", err)
					}
				}
				fixture.auditor.assertLast(t, test.outcome, test.reason)
			})
		}
	}
}

func TestWorkspaceServiceAcceptInvitationValidatesTokenAndHashesOpaqueInput(t *testing.T) {
	fixture := newWorkspaceServiceFixture(t)
	secret, err := NewInvitationSecret(bytes.NewReader(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatalf("NewInvitationSecret() error = %v", err)
	}
	var command AcceptInvitationCommand
	fixture.repository.acceptInvitation = func(_ context.Context, _ Actor, captured AcceptInvitationCommand) (Acceptance, error) {
		command = captured
		return Acceptance{Workspace: fixture.workspace(RoleMember, MutationStateWritable), Member: Member{
			UserID: fixture.actor.UserID, Role: RoleMember, Revision: 1, JoinedAt: fixture.now,
		}}, nil
	}
	accepted, err := fixture.service.AcceptInvitation(fixture.ctx, fixture.actor, AcceptInvitationRequest{
		Token: secret.RawToken, IdempotencyKey: "  accept key  ", RequestID: "request-accept",
	})
	if err != nil || accepted.Member.UserID != fixture.actor.UserID {
		t.Fatalf("AcceptInvitation() = %+v, %v", accepted, err)
	}
	if command.TokenDigest != secret.Digest || command.MemberLimit != fixture.quotas.Members ||
		command.Idempotency.KeyDigest != sha256.Sum256([]byte("  accept key  ")) ||
		command.Idempotency.RequestDigest != canonicalInvitationAcceptDigest(secret.RawToken) {
		t.Fatalf("AcceptInvitation command = %+v", command)
	}
	fixture.limiter.assertLast(t, LimitInvitationAccept, nil)

	fixture.repository.mutationCalls = 0
	if _, err := fixture.service.AcceptInvitation(fixture.ctx, fixture.actor, AcceptInvitationRequest{
		Token: "not-a-token", IdempotencyKey: "key", RequestID: "request-invalid",
	}); !errors.Is(err, ErrInvalidRequest) || fixture.repository.mutationCalls != 0 {
		t.Fatalf("AcceptInvitation(invalid) error=%v mutationCalls=%d", err, fixture.repository.mutationCalls)
	}
}

func TestWorkspaceServiceValidatesConfigurationAndOpaqueInputs(t *testing.T) {
	fixture := newWorkspaceServiceFixture(t)
	for _, config := range []ServiceConfig{
		{},
		{Repository: fixture.repository, Limiter: fixture.limiter, Auditor: fixture.auditor, Random: bytes.NewReader(nil)},
	} {
		if _, err := NewService(config); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("NewService(invalid) error = %v", err)
		}
	}
	for _, key := range []string{"", "   ", strings.Repeat("x", 129)} {
		if _, _, err := fixture.service.CreateWorkspace(fixture.ctx, fixture.actor, CreateWorkspaceRequest{
			DisplayName: "Space", IdempotencyKey: key, RequestID: "request-invalid-key",
		}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("CreateWorkspace(key %q) error = %v", key, err)
		}
	}
}

type workspaceServiceFixture struct {
	ctx         context.Context
	actor       Actor
	workspaceID uuid.UUID
	now         time.Time
	quotas      Quotas
	repository  *fakeWorkspaceRepository
	limiter     *fakeWorkspaceLimiter
	auditor     *fakeWorkspaceAuditor
	service     *Service
}

func newWorkspaceServiceFixture(t *testing.T) *workspaceServiceFixture {
	t.Helper()
	fixture := &workspaceServiceFixture{
		ctx: context.Background(), actor: Actor{UserID: uuid.New(), DeviceID: uuid.New()}, workspaceID: uuid.New(),
		now:        time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		quotas:     Quotas{ActiveOwned: 10, Members: 100, PendingInvitations: 20},
		repository: &fakeWorkspaceRepository{}, limiter: &fakeWorkspaceLimiter{}, auditor: &fakeWorkspaceAuditor{},
	}
	service, err := NewService(ServiceConfig{
		Repository: fixture.repository, Limiter: fixture.limiter, Auditor: fixture.auditor,
		Clock: func() time.Time { return fixture.now }, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 4096)),
		Quotas: fixture.quotas,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	fixture.service = service
	return fixture
}

func (f *workspaceServiceFixture) workspace(role Role, state MutationState) Workspace {
	status := WorkspaceStatusActive
	var archivedAt *time.Time
	if state == MutationStateArchived {
		status = WorkspaceStatusArchived
		value := f.now
		archivedAt = &value
	}
	return Workspace{
		ID: f.workspaceID, DisplayName: "Team Space", Status: status, Revision: 1, MutationState: state,
		ActorRole: role, MemberCount: 1, CreatedAt: f.now.Add(-time.Hour), UpdatedAt: f.now, ArchivedAt: archivedAt,
	}
}

type fakeWorkspaceRepository struct {
	mutationCalls    int
	create           func(context.Context, Actor, CreateCommand) (Workspace, IdempotencyReplay, error)
	list             func(context.Context, Actor) ([]Workspace, error)
	listMembers      func(context.Context, Actor, uuid.UUID) ([]Member, error)
	createInvitation func(context.Context, Actor, CreateInvitationCommand) (InvitationCreation, IdempotencyReplay, error)
	acceptInvitation func(context.Context, Actor, AcceptInvitationCommand) (Acceptance, error)
}

func (f *fakeWorkspaceRepository) Create(ctx context.Context, actor Actor, command CreateCommand) (Workspace, IdempotencyReplay, error) {
	f.mutationCalls++
	if f.create != nil {
		return f.create(ctx, actor, command)
	}
	return Workspace{ID: command.WorkspaceID}, IdempotencyFresh, nil
}
func (f *fakeWorkspaceRepository) List(ctx context.Context, actor Actor) ([]Workspace, error) {
	if f.list != nil {
		return f.list(ctx, actor)
	}
	return nil, nil
}
func (f *fakeWorkspaceRepository) Rename(_ context.Context, _ Actor, command RenameCommand) (Workspace, error) {
	f.mutationCalls++
	return Workspace{ID: command.WorkspaceID, DisplayName: command.DisplayName}, nil
}
func (f *fakeWorkspaceRepository) Archive(_ context.Context, _ Actor, command RevisionCommand) (Workspace, error) {
	f.mutationCalls++
	return Workspace{ID: command.WorkspaceID}, nil
}
func (f *fakeWorkspaceRepository) Restore(_ context.Context, _ Actor, command RevisionCommand) (Workspace, error) {
	f.mutationCalls++
	return Workspace{ID: command.WorkspaceID}, nil
}
func (f *fakeWorkspaceRepository) ListMembers(ctx context.Context, actor Actor, workspaceID uuid.UUID) ([]Member, error) {
	if f.listMembers != nil {
		return f.listMembers(ctx, actor, workspaceID)
	}
	return nil, nil
}
func (f *fakeWorkspaceRepository) ChangeMemberRole(_ context.Context, _ Actor, command ChangeRoleCommand) (Member, error) {
	f.mutationCalls++
	return Member{UserID: command.UserID, Role: command.Role, Revision: command.ExpectedRevision + 1}, nil
}
func (f *fakeWorkspaceRepository) RemoveMember(context.Context, Actor, RemoveMemberCommand) error {
	f.mutationCalls++
	return nil
}
func (f *fakeWorkspaceRepository) Leave(context.Context, Actor, uuid.UUID) error {
	f.mutationCalls++
	return nil
}
func (f *fakeWorkspaceRepository) ListInvitations(context.Context, Actor, uuid.UUID) ([]Invitation, error) {
	return nil, nil
}
func (f *fakeWorkspaceRepository) CreateInvitation(ctx context.Context, actor Actor, command CreateInvitationCommand) (InvitationCreation, IdempotencyReplay, error) {
	f.mutationCalls++
	if f.createInvitation != nil {
		return f.createInvitation(ctx, actor, command)
	}
	return InvitationCreation{Invitation: Invitation{ID: command.InvitationID}, Secret: &command.Secret}, IdempotencyFresh, nil
}
func (f *fakeWorkspaceRepository) RevokeInvitation(context.Context, Actor, RevokeInvitationCommand) error {
	f.mutationCalls++
	return nil
}
func (f *fakeWorkspaceRepository) AcceptInvitation(ctx context.Context, actor Actor, command AcceptInvitationCommand) (Acceptance, error) {
	f.mutationCalls++
	if f.acceptInvitation != nil {
		return f.acceptInvitation(ctx, actor, command)
	}
	return Acceptance{}, nil
}

type limiterCall struct {
	action      LimitAction
	workspaceID *uuid.UUID
}
type fakeWorkspaceLimiter struct {
	calls      []limiterCall
	retryAfter time.Duration
	err        error
}

func (f *fakeWorkspaceLimiter) Allow(_ context.Context, action LimitAction, _ Actor, workspaceID *uuid.UUID) (time.Duration, error) {
	var copied *uuid.UUID
	if workspaceID != nil {
		value := *workspaceID
		copied = &value
	}
	f.calls = append(f.calls, limiterCall{action: action, workspaceID: copied})
	return f.retryAfter, f.err
}
func (f *fakeWorkspaceLimiter) assertLast(t *testing.T, action LimitAction, workspaceID *uuid.UUID) {
	t.Helper()
	if len(f.calls) == 0 {
		t.Fatal("limiter was not called")
	}
	call := f.calls[len(f.calls)-1]
	if call.action != action || (workspaceID == nil) != (call.workspaceID == nil) ||
		(workspaceID != nil && *workspaceID != *call.workspaceID) {
		t.Fatalf("limiter call = %+v, want action=%s workspace=%v", call, action, workspaceID)
	}
}

type fakeWorkspaceAuditor struct {
	events []audit.Event
	err    error
}

func (f *fakeWorkspaceAuditor) Record(_ context.Context, event audit.Event) error {
	f.events = append(f.events, event)
	return f.err
}
func (f *fakeWorkspaceAuditor) assertLast(t *testing.T, outcome audit.Outcome, reason string) {
	t.Helper()
	if len(f.events) == 0 {
		t.Fatal("audit recorder was not called")
	}
	event := f.events[len(f.events)-1]
	if event.Outcome != outcome || event.ReasonCode != reason || !strings.HasPrefix(event.EventType, "workspace_") {
		t.Fatalf("audit event = %+v, want outcome=%s reason=%s", event, outcome, reason)
	}
}
