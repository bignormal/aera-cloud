package workspace

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/audit"
	"github.com/google/uuid"
)

const (
	idempotencyLifetime = 24 * time.Hour
	auditAttemptTimeout = 2 * time.Second
	maxIdempotencyBytes = 128
)

var workspaceRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

type Operation string

const (
	OperationRead           Operation = "read"
	OperationRename         Operation = "rename"
	OperationInvite         Operation = "invite"
	OperationRemoveMember   Operation = "remove_member"
	OperationManageAdmin    Operation = "manage_admin"
	OperationArchiveRestore Operation = "archive_restore"
	OperationLeave          Operation = "leave"
)

var permissions = map[Operation]map[Role]bool{
	OperationRead:           {RoleOwner: true, RoleAdmin: true, RoleMember: true},
	OperationRename:         {RoleOwner: true, RoleAdmin: true},
	OperationInvite:         {RoleOwner: true, RoleAdmin: true},
	OperationRemoveMember:   {RoleOwner: true, RoleAdmin: true},
	OperationManageAdmin:    {RoleOwner: true},
	OperationArchiveRestore: {RoleOwner: true},
	OperationLeave:          {RoleAdmin: true, RoleMember: true},
}

type Quotas struct {
	ActiveOwned        int
	Members            int
	PendingInvitations int
}

func (q Quotas) valid() bool {
	return q.ActiveOwned > 0 && q.Members > 0 && q.PendingInvitations > 0
}

type ServiceConfig struct {
	Repository Repository
	Limiter    Limiter
	Auditor    audit.Recorder
	Clock      func() time.Time
	Random     io.Reader
	Quotas     Quotas
}

type Service struct {
	repository Repository
	limiter    Limiter
	auditor    audit.Recorder
	clock      func() time.Time
	random     io.Reader
	randomMu   sync.Mutex
	quotas     Quotas
}

type CreateWorkspaceRequest struct {
	DisplayName    string
	IdempotencyKey string
	RequestID      string
}

type RenameWorkspaceRequest struct {
	WorkspaceID      uuid.UUID
	DisplayName      string
	ExpectedRevision int64
	RequestID        string
}

type WorkspaceRevisionRequest struct {
	WorkspaceID      uuid.UUID
	ExpectedRevision int64
	RequestID        string
}

type ChangeMemberRoleRequest struct {
	WorkspaceID      uuid.UUID
	UserID           uuid.UUID
	Role             Role
	ExpectedRevision int64
	RequestID        string
}

type RemoveMemberRequest struct {
	WorkspaceID      uuid.UUID
	UserID           uuid.UUID
	ExpectedRevision int64
	RequestID        string
}

type CreateInvitationRequest struct {
	WorkspaceID    uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type RevokeInvitationRequest struct {
	WorkspaceID  uuid.UUID
	InvitationID uuid.UUID
	RequestID    string
}

type AcceptInvitationRequest struct {
	Token          string
	IdempotencyKey string
	RequestID      string
}

type InvitationCreationResult struct {
	Invitation       Invitation
	Token            string
	InviteURL        string
	SecretReplayable bool
}

type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return ErrRateLimited.Error()
}

func (e *RateLimitError) Unwrap() error {
	return ErrRateLimited
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.Limiter == nil || config.Auditor == nil || config.Random == nil || !config.Quotas.valid() {
		return nil, fmt.Errorf("%w: workspace service configuration is invalid", ErrInvalidRequest)
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		repository: config.Repository,
		limiter:    config.Limiter,
		auditor:    config.Auditor,
		clock:      clock,
		random:     config.Random,
		quotas:     config.Quotas,
	}, nil
}

func DefaultServiceRandom() io.Reader {
	return rand.Reader
}

func (s *Service) CreateWorkspace(
	ctx context.Context,
	actor Actor,
	request CreateWorkspaceRequest,
) (Workspace, IdempotencyReplay, error) {
	displayName, err := NormalizeDisplayName(request.DisplayName)
	if s == nil || actor.Validate() != nil || err != nil || !validOpaqueIdempotencyKey(request.IdempotencyKey) ||
		!validWorkspaceRequestID(request.RequestID) {
		return Workspace{}, "", ErrInvalidRequest
	}
	workspaceID, err := s.newUUID()
	if err != nil {
		return Workspace{}, "", ErrServiceUnavailable
	}
	auditID, err := s.newUUID()
	if err != nil {
		return Workspace{}, "", ErrServiceUnavailable
	}
	if err := s.applyLimit(ctx, LimitWorkspaceCreate, actor, nil, request.RequestID, &workspaceID); err != nil {
		return Workspace{}, "", err
	}
	now := s.now()
	workspace, replay, err := s.repository.Create(ctx, actor, CreateCommand{
		WorkspaceID: workspaceID, DisplayName: displayName, ActiveOwnedLimit: s.quotas.ActiveOwned,
		Idempotency: IdempotencyEvidence{
			KeyDigest:     sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestDigest: canonicalWorkspaceCreateDigest(displayName), ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, CreatedAt: now,
	})
	if err != nil {
		return Workspace{}, "", s.recordMutationError(ctx, actor, "workspace_create_attempt", request.RequestID, &workspaceID, nil, err)
	}
	return cloneWorkspace(workspace), replay, nil
}

func (s *Service) ListWorkspaces(ctx context.Context, actor Actor) ([]Workspace, error) {
	if s == nil || actor.Validate() != nil {
		return nil, ErrInvalidRequest
	}
	workspaces, err := s.repository.List(ctx, actor)
	if err != nil {
		return nil, err
	}
	return cloneWorkspaces(workspaces), nil
}

func (s *Service) RenameWorkspace(
	ctx context.Context,
	actor Actor,
	request RenameWorkspaceRequest,
) (Workspace, error) {
	displayName, err := NormalizeDisplayName(request.DisplayName)
	if s == nil || actor.Validate() != nil || err != nil || request.WorkspaceID == uuid.Nil ||
		request.ExpectedRevision <= 0 || !validWorkspaceRequestID(request.RequestID) {
		return Workspace{}, ErrInvalidRequest
	}
	if _, err := s.authorizeMutable(ctx, actor, request.WorkspaceID, OperationRename, request.RequestID); err != nil {
		return Workspace{}, err
	}
	auditID, err := s.newUUID()
	if err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	workspace, err := s.repository.Rename(ctx, actor, RenameCommand{
		WorkspaceID: request.WorkspaceID, DisplayName: displayName, ExpectedRevision: request.ExpectedRevision,
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, UpdatedAt: s.now(),
	})
	if err != nil {
		return Workspace{}, s.recordMutationError(ctx, actor, "workspace_rename_attempt", request.RequestID, &request.WorkspaceID, nil, err)
	}
	return cloneWorkspace(workspace), nil
}

func (s *Service) ArchiveWorkspace(
	ctx context.Context,
	actor Actor,
	request WorkspaceRevisionRequest,
) (Workspace, error) {
	if !validWorkspaceRevisionRequest(s, actor, request) {
		return Workspace{}, ErrInvalidRequest
	}
	if _, err := s.authorizeMutable(ctx, actor, request.WorkspaceID, OperationArchiveRestore, request.RequestID); err != nil {
		return Workspace{}, err
	}
	return s.reviseWorkspace(ctx, actor, request, false)
}

func (s *Service) RestoreWorkspace(
	ctx context.Context,
	actor Actor,
	request WorkspaceRevisionRequest,
) (Workspace, error) {
	if !validWorkspaceRevisionRequest(s, actor, request) {
		return Workspace{}, ErrInvalidRequest
	}
	workspace, err := s.authorize(ctx, actor, request.WorkspaceID, OperationArchiveRestore, request.RequestID)
	if err != nil {
		return Workspace{}, err
	}
	if workspace.MutationState == MutationStateOwnerUnavailable {
		return Workspace{}, s.deny(ctx, actor, "workspace_restore_denied", request.RequestID, &request.WorkspaceID, nil, ErrWorkspaceOwnerUnavailable)
	}
	if workspace.Status != WorkspaceStatusArchived {
		return Workspace{}, s.deny(ctx, actor, "workspace_restore_denied", request.RequestID, &request.WorkspaceID, nil, ErrWorkspaceConflict)
	}
	return s.reviseWorkspace(ctx, actor, request, true)
}

func (s *Service) reviseWorkspace(
	ctx context.Context,
	actor Actor,
	request WorkspaceRevisionRequest,
	restore bool,
) (Workspace, error) {
	auditID, err := s.newUUID()
	if err != nil {
		return Workspace{}, ErrServiceUnavailable
	}
	command := RevisionCommand{
		WorkspaceID: request.WorkspaceID, ExpectedRevision: request.ExpectedRevision,
		ActiveOwnedLimit: s.quotas.ActiveOwned, Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID},
		ChangedAt: s.now(),
	}
	var workspace Workspace
	if restore {
		workspace, err = s.repository.Restore(ctx, actor, command)
	} else {
		workspace, err = s.repository.Archive(ctx, actor, command)
	}
	if err != nil {
		eventType := "workspace_archive_attempt"
		if restore {
			eventType = "workspace_restore_attempt"
		}
		return Workspace{}, s.recordMutationError(ctx, actor, eventType, request.RequestID, &request.WorkspaceID, nil, err)
	}
	return cloneWorkspace(workspace), nil
}

func (s *Service) ListMembers(ctx context.Context, actor Actor, workspaceID uuid.UUID) ([]Member, error) {
	if s == nil || actor.Validate() != nil || workspaceID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	if _, err := s.findWorkspace(ctx, actor, workspaceID); err != nil {
		return nil, err
	}
	members, err := s.repository.ListMembers(ctx, actor, workspaceID)
	if err != nil {
		return nil, err
	}
	return append([]Member(nil), members...), nil
}

func (s *Service) ChangeMemberRole(
	ctx context.Context,
	actor Actor,
	request ChangeMemberRoleRequest,
) (Member, error) {
	if s == nil || actor.Validate() != nil || request.WorkspaceID == uuid.Nil || request.UserID == uuid.Nil ||
		(request.Role != RoleAdmin && request.Role != RoleMember) || request.ExpectedRevision <= 0 ||
		!validWorkspaceRequestID(request.RequestID) {
		return Member{}, ErrInvalidRequest
	}
	workspace, err := s.authorizeMutable(ctx, actor, request.WorkspaceID, OperationManageAdmin, request.RequestID)
	if err != nil {
		return Member{}, err
	}
	target, err := s.findTargetMember(ctx, actor, workspace, request.UserID)
	if err != nil {
		return Member{}, s.recordMutationError(ctx, actor, "workspace_member_role_attempt", request.RequestID, &request.WorkspaceID,
			map[string]string{"membership_user_id": request.UserID.String()}, err)
	}
	if target.Role == RoleOwner || target.Role == request.Role || target.Revision != request.ExpectedRevision {
		return Member{}, s.deny(ctx, actor, "workspace_member_role_denied", request.RequestID, &request.WorkspaceID,
			memberAuditMetadata(request.WorkspaceID, target, request.Role), ErrMembershipConflict)
	}
	auditID, err := s.newUUID()
	if err != nil {
		return Member{}, ErrServiceUnavailable
	}
	member, err := s.repository.ChangeMemberRole(ctx, actor, ChangeRoleCommand{
		WorkspaceID: request.WorkspaceID, UserID: request.UserID, Role: request.Role,
		ExpectedRevision: request.ExpectedRevision, Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID},
		ChangedAt: s.now(),
	})
	if err != nil {
		return Member{}, s.recordMutationError(ctx, actor, "workspace_member_role_attempt", request.RequestID,
			&request.WorkspaceID, memberAuditMetadata(request.WorkspaceID, target, request.Role), err)
	}
	return member, nil
}

func (s *Service) RemoveMember(ctx context.Context, actor Actor, request RemoveMemberRequest) error {
	if s == nil || actor.Validate() != nil || request.WorkspaceID == uuid.Nil || request.UserID == uuid.Nil ||
		request.ExpectedRevision <= 0 || !validWorkspaceRequestID(request.RequestID) {
		return ErrInvalidRequest
	}
	workspace, err := s.authorizeMutable(ctx, actor, request.WorkspaceID, OperationRemoveMember, request.RequestID)
	if err != nil {
		return err
	}
	target, err := s.findTargetMember(ctx, actor, workspace, request.UserID)
	if err != nil {
		return s.recordMutationError(ctx, actor, "workspace_member_remove_attempt", request.RequestID, &request.WorkspaceID,
			map[string]string{"membership_user_id": request.UserID.String()}, err)
	}
	if target.Role == RoleOwner {
		return s.deny(ctx, actor, "workspace_member_remove_denied", request.RequestID, &request.WorkspaceID,
			memberAuditMetadata(request.WorkspaceID, target, ""), ErrMembershipConflict)
	}
	if workspace.ActorRole == RoleAdmin && target.Role != RoleMember {
		return s.deny(ctx, actor, "workspace_member_remove_denied", request.RequestID, &request.WorkspaceID,
			memberAuditMetadata(request.WorkspaceID, target, ""), ErrWorkspaceForbidden)
	}
	if target.Revision != request.ExpectedRevision {
		return s.deny(ctx, actor, "workspace_member_remove_denied", request.RequestID, &request.WorkspaceID,
			memberAuditMetadata(request.WorkspaceID, target, ""), ErrMembershipConflict)
	}
	auditID, err := s.newUUID()
	if err != nil {
		return ErrServiceUnavailable
	}
	err = s.repository.RemoveMember(ctx, actor, RemoveMemberCommand{
		WorkspaceID: request.WorkspaceID, UserID: request.UserID, ExpectedRevision: request.ExpectedRevision,
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, RemovedAt: s.now(),
	})
	if err != nil {
		return s.recordMutationError(ctx, actor, "workspace_member_remove_attempt", request.RequestID,
			&request.WorkspaceID, memberAuditMetadata(request.WorkspaceID, target, ""), err)
	}
	return nil
}

func (s *Service) LeaveWorkspace(ctx context.Context, actor Actor, workspaceID uuid.UUID, requestID string) error {
	if s == nil || actor.Validate() != nil || workspaceID == uuid.Nil || !validWorkspaceRequestID(requestID) {
		return ErrInvalidRequest
	}
	if _, err := s.authorizeMutable(ctx, actor, workspaceID, OperationLeave, requestID); err != nil {
		return err
	}
	if err := s.repository.Leave(ctx, actor, workspaceID); err != nil {
		return s.recordMutationError(ctx, actor, "workspace_member_leave_attempt", requestID, &workspaceID, nil, err)
	}
	return nil
}

func (s *Service) ListInvitations(
	ctx context.Context,
	actor Actor,
	workspaceID uuid.UUID,
	requestID string,
) ([]Invitation, error) {
	if s == nil || actor.Validate() != nil || workspaceID == uuid.Nil || !validWorkspaceRequestID(requestID) {
		return nil, ErrInvalidRequest
	}
	if _, err := s.authorize(ctx, actor, workspaceID, OperationInvite, requestID); err != nil {
		return nil, err
	}
	invitations, err := s.repository.ListInvitations(ctx, actor, workspaceID)
	if err != nil {
		return nil, err
	}
	return cloneInvitations(invitations), nil
}

func (s *Service) CreateInvitation(
	ctx context.Context,
	actor Actor,
	request CreateInvitationRequest,
) (InvitationCreationResult, IdempotencyReplay, error) {
	if s == nil || actor.Validate() != nil || request.WorkspaceID == uuid.Nil ||
		!validOpaqueIdempotencyKey(request.IdempotencyKey) || !validWorkspaceRequestID(request.RequestID) {
		return InvitationCreationResult{}, "", ErrInvalidRequest
	}
	if _, err := s.authorizeMutable(ctx, actor, request.WorkspaceID, OperationInvite, request.RequestID); err != nil {
		return InvitationCreationResult{}, "", err
	}
	if err := s.applyLimit(ctx, LimitInvitationCreate, actor, &request.WorkspaceID, request.RequestID, &request.WorkspaceID); err != nil {
		return InvitationCreationResult{}, "", err
	}
	invitationID, err := s.newUUID()
	if err != nil {
		return InvitationCreationResult{}, "", ErrServiceUnavailable
	}
	auditID, err := s.newUUID()
	if err != nil {
		return InvitationCreationResult{}, "", ErrServiceUnavailable
	}
	secret, err := s.newInvitationSecret()
	if err != nil {
		return InvitationCreationResult{}, "", ErrServiceUnavailable
	}
	now := s.now()
	creation, replay, err := s.repository.CreateInvitation(ctx, actor, CreateInvitationCommand{
		InvitationID: invitationID, WorkspaceID: request.WorkspaceID, Secret: secret,
		PendingInviteLimit: s.quotas.PendingInvitations,
		Idempotency: IdempotencyEvidence{
			KeyDigest:     sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestDigest: canonicalInvitationCreateDigest(request.WorkspaceID), ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, CreatedAt: now,
	})
	if err != nil {
		return InvitationCreationResult{}, "", s.recordMutationError(ctx, actor, "workspace_invitation_create_attempt",
			request.RequestID, &request.WorkspaceID, nil, err)
	}
	result := InvitationCreationResult{Invitation: cloneInvitation(creation.Invitation), SecretReplayable: false}
	if replay == IdempotencyFresh {
		if creation.Secret == nil || creation.Secret.RawToken == "" {
			return InvitationCreationResult{}, "", s.recordMutationError(ctx, actor, "workspace_invitation_create_attempt",
				request.RequestID, &request.WorkspaceID, nil, ErrServiceUnavailable)
		}
		result.Token = creation.Secret.RawToken
		result.InviteURL = "agentera://workspace-invitation#" + creation.Secret.RawToken
	}
	return result, replay, nil
}

func (s *Service) RevokeInvitation(ctx context.Context, actor Actor, request RevokeInvitationRequest) error {
	if s == nil || actor.Validate() != nil || request.WorkspaceID == uuid.Nil || request.InvitationID == uuid.Nil ||
		!validWorkspaceRequestID(request.RequestID) {
		return ErrInvalidRequest
	}
	if _, err := s.authorizeMutable(ctx, actor, request.WorkspaceID, OperationInvite, request.RequestID); err != nil {
		return err
	}
	auditID, err := s.newUUID()
	if err != nil {
		return ErrServiceUnavailable
	}
	metadata := map[string]string{
		"workspace_id": request.WorkspaceID.String(), "invitation_id": request.InvitationID.String(),
	}
	err = s.repository.RevokeInvitation(ctx, actor, RevokeInvitationCommand{
		WorkspaceID: request.WorkspaceID, InvitationID: request.InvitationID,
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, RevokedAt: s.now(),
	})
	if err != nil {
		return s.recordMutationError(ctx, actor, "workspace_invitation_revoke_attempt", request.RequestID,
			&request.WorkspaceID, metadata, err)
	}
	return nil
}

func (s *Service) AcceptInvitation(
	ctx context.Context,
	actor Actor,
	request AcceptInvitationRequest,
) (Acceptance, error) {
	if s == nil || actor.Validate() != nil || !validOpaqueIdempotencyKey(request.IdempotencyKey) ||
		!validWorkspaceRequestID(request.RequestID) {
		return Acceptance{}, ErrInvalidRequest
	}
	tokenDigest, err := InvitationDigest(request.Token)
	if err != nil {
		return Acceptance{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitInvitationAccept, actor, nil, request.RequestID, nil); err != nil {
		return Acceptance{}, err
	}
	auditID, err := s.newUUID()
	if err != nil {
		return Acceptance{}, ErrServiceUnavailable
	}
	now := s.now()
	acceptance, err := s.repository.AcceptInvitation(ctx, actor, AcceptInvitationCommand{
		TokenDigest: tokenDigest, MemberLimit: s.quotas.Members,
		Idempotency: IdempotencyEvidence{
			KeyDigest:     sha256.Sum256([]byte(request.IdempotencyKey)),
			RequestDigest: canonicalInvitationAcceptDigest(request.Token), ExpiresAt: now.Add(idempotencyLifetime),
		},
		Audit: AuditEvidence{EventID: auditID, RequestID: request.RequestID}, AcceptedAt: now,
	})
	if err != nil {
		return Acceptance{}, s.recordMutationError(ctx, actor, "workspace_invitation_accept_attempt", request.RequestID, nil, nil, err)
	}
	acceptance.Workspace = cloneWorkspace(acceptance.Workspace)
	return acceptance, nil
}

func (s *Service) authorizeMutable(
	ctx context.Context,
	actor Actor,
	workspaceID uuid.UUID,
	operation Operation,
	requestID string,
) (Workspace, error) {
	workspace, err := s.authorize(ctx, actor, workspaceID, operation, requestID)
	if err != nil {
		return Workspace{}, err
	}
	switch workspace.MutationState {
	case MutationStateOwnerUnavailable:
		return Workspace{}, s.deny(ctx, actor, "workspace_mutation_denied", requestID, &workspaceID, nil, ErrWorkspaceOwnerUnavailable)
	case MutationStateArchived:
		return Workspace{}, s.deny(ctx, actor, "workspace_mutation_denied", requestID, &workspaceID, nil, ErrWorkspaceArchived)
	case MutationStateWritable:
		return workspace, nil
	default:
		return Workspace{}, ErrServiceUnavailable
	}
}

func (s *Service) authorize(
	ctx context.Context,
	actor Actor,
	workspaceID uuid.UUID,
	operation Operation,
	requestID string,
) (Workspace, error) {
	workspace, err := s.findWorkspace(ctx, actor, workspaceID)
	if err != nil {
		return Workspace{}, s.recordMutationError(ctx, actor, "workspace_access_attempt", requestID, &workspaceID, nil, err)
	}
	allowedRoles, exists := permissions[operation]
	if !exists {
		return Workspace{}, ErrInvalidRequest
	}
	if !allowedRoles[workspace.ActorRole] {
		return Workspace{}, s.deny(ctx, actor, "workspace_access_denied", requestID, &workspaceID,
			map[string]string{"workspace_id": workspaceID.String(), "role": string(workspace.ActorRole)}, ErrWorkspaceForbidden)
	}
	return workspace, nil
}

func (s *Service) findWorkspace(ctx context.Context, actor Actor, workspaceID uuid.UUID) (Workspace, error) {
	workspaces, err := s.repository.List(ctx, actor)
	if err != nil {
		return Workspace{}, err
	}
	for _, workspace := range workspaces {
		if workspace.ID == workspaceID {
			return cloneWorkspace(workspace), nil
		}
	}
	return Workspace{}, ErrWorkspaceNotFound
}

func (s *Service) findTargetMember(
	ctx context.Context,
	actor Actor,
	workspace Workspace,
	targetID uuid.UUID,
) (Member, error) {
	members, err := s.repository.ListMembers(ctx, actor, workspace.ID)
	if err != nil {
		return Member{}, err
	}
	for _, member := range members {
		if member.UserID == targetID {
			return member, nil
		}
	}
	return Member{}, ErrWorkspaceNotFound
}

func (s *Service) applyLimit(
	ctx context.Context,
	action LimitAction,
	actor Actor,
	scope *uuid.UUID,
	requestID string,
	objectID *uuid.UUID,
) error {
	retryAfter, err := s.limiter.Allow(ctx, action, actor, scope)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRateLimited) {
		limited := &RateLimitError{RetryAfter: retryAfter}
		if auditErr := s.recordAttempt(ctx, actor, "workspace_rate_limit_denied", audit.OutcomeDenied,
			"rate_limited", requestID, objectID, workspaceMetadata(objectID)); auditErr != nil {
			return ErrServiceUnavailable
		}
		return limited
	}
	if auditErr := s.recordAttempt(ctx, actor, "workspace_rate_limit_failed", audit.OutcomeFailure,
		"service_unavailable", requestID, objectID, workspaceMetadata(objectID)); auditErr != nil {
		return ErrServiceUnavailable
	}
	return ErrServiceUnavailable
}

func (s *Service) deny(
	ctx context.Context,
	actor Actor,
	eventType string,
	requestID string,
	workspaceID *uuid.UUID,
	metadata map[string]string,
	err error,
) error {
	if metadata == nil {
		metadata = workspaceMetadata(workspaceID)
	}
	if auditErr := s.recordAttempt(ctx, actor, eventType, audit.OutcomeDenied, workspaceReasonCode(err),
		requestID, workspaceID, metadata); auditErr != nil {
		return ErrServiceUnavailable
	}
	return err
}

func (s *Service) recordMutationError(
	ctx context.Context,
	actor Actor,
	eventType string,
	requestID string,
	workspaceID *uuid.UUID,
	metadata map[string]string,
	err error,
) error {
	outcome := audit.OutcomeDenied
	if errors.Is(err, ErrServiceUnavailable) {
		outcome = audit.OutcomeFailure
	}
	if metadata == nil {
		metadata = workspaceMetadata(workspaceID)
	}
	if auditErr := s.recordAttempt(ctx, actor, eventType, outcome, workspaceReasonCode(err),
		requestID, workspaceID, metadata); auditErr != nil {
		return ErrServiceUnavailable
	}
	return err
}

func (s *Service) recordAttempt(
	ctx context.Context,
	actor Actor,
	eventType string,
	outcome audit.Outcome,
	reasonCode string,
	requestID string,
	workspaceID *uuid.UUID,
	metadata map[string]string,
) error {
	eventID, err := s.newUUID()
	if err != nil {
		return ErrServiceUnavailable
	}
	actorID := actor.UserID
	deviceID := actor.DeviceID
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditAttemptTimeout)
	defer cancel()
	event := audit.Event{
		ID: eventID, EventType: eventType, ActorUserID: &actorID, DeviceID: &deviceID,
		Outcome: outcome, ReasonCode: reasonCode, RequestID: requestID,
		Metadata: metadata, OccurredAt: s.now(),
	}
	if workspaceID != nil {
		value := *workspaceID
		event.ObjectType = "workspace"
		event.ObjectID = &value
	}
	if err := s.auditor.Record(bounded, event); err != nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (s *Service) now() time.Time {
	return s.clock().UTC()
}

func (s *Service) newUUID() (uuid.UUID, error) {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	value, err := uuid.NewRandomFromReader(s.random)
	if err != nil || value == uuid.Nil {
		return uuid.Nil, ErrServiceUnavailable
	}
	return value, nil
}

func (s *Service) newInvitationSecret() (InvitationSecret, error) {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	return NewInvitationSecret(s.random)
}

func validOpaqueIdempotencyKey(value string) bool {
	return utf8.ValidString(value) && len([]byte(value)) <= maxIdempotencyBytes && strings.TrimSpace(value) != ""
}

func validWorkspaceRequestID(value string) bool {
	return workspaceRequestIDPattern.MatchString(value)
}

func validWorkspaceRevisionRequest(s *Service, actor Actor, request WorkspaceRevisionRequest) bool {
	return s != nil && actor.Validate() == nil && request.WorkspaceID != uuid.Nil && request.ExpectedRevision > 0 &&
		validWorkspaceRequestID(request.RequestID)
}

func canonicalWorkspaceCreateDigest(displayName string) [sha256.Size]byte {
	return canonicalWorkspaceDigest("workspace-create-v1", []byte(displayName))
}

func canonicalInvitationCreateDigest(workspaceID uuid.UUID) [sha256.Size]byte {
	return canonicalWorkspaceDigest("workspace-invitation-create-v1", workspaceID[:])
}

func canonicalInvitationAcceptDigest(rawToken string) [sha256.Size]byte {
	return canonicalWorkspaceDigest("workspace-invitation-accept-v1", []byte(rawToken))
}

func canonicalWorkspaceDigest(domain string, value []byte) [sha256.Size]byte {
	payload := make([]byte, 0, len(domain)+1+len(value))
	payload = append(payload, domain...)
	payload = append(payload, 0)
	payload = append(payload, value...)
	return sha256.Sum256(payload)
}

func workspaceReasonCode(err error) string {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, ErrSessionRevoked):
		return "session_revoked"
	case errors.Is(err, ErrWorkspaceForbidden):
		return "workspace_forbidden"
	case errors.Is(err, ErrWorkspaceNotFound):
		return "workspace_not_found"
	case errors.Is(err, ErrInvitationUnavailable):
		return "invitation_unavailable"
	case errors.Is(err, ErrWorkspaceConflict):
		return "workspace_conflict"
	case errors.Is(err, ErrWorkspaceArchived):
		return "workspace_archived"
	case errors.Is(err, ErrWorkspaceOwnerUnavailable):
		return "workspace_owner_unavailable"
	case errors.Is(err, ErrMembershipConflict):
		return "membership_conflict"
	case errors.Is(err, ErrWorkspaceLimitReached):
		return "workspace_limit_reached"
	case errors.Is(err, ErrMemberLimitReached):
		return "member_limit_reached"
	case errors.Is(err, ErrInvitationLimitReached):
		return "invitation_limit_reached"
	case errors.Is(err, ErrIdempotencyConflict):
		return "idempotency_conflict"
	case errors.Is(err, ErrRateLimited):
		return "rate_limited"
	default:
		return "service_unavailable"
	}
}

func workspaceMetadata(workspaceID *uuid.UUID) map[string]string {
	if workspaceID == nil || *workspaceID == uuid.Nil {
		return nil
	}
	return map[string]string{"workspace_id": workspaceID.String()}
}

func memberAuditMetadata(workspaceID uuid.UUID, target Member, desired Role) map[string]string {
	metadata := map[string]string{
		"workspace_id": workspaceID.String(), "membership_user_id": target.UserID.String(), "previous_role": string(target.Role),
	}
	if desired != "" {
		metadata["role"] = string(desired)
	}
	return metadata
}

func cloneWorkspace(value Workspace) Workspace {
	if value.ArchivedAt != nil {
		archivedAt := *value.ArchivedAt
		value.ArchivedAt = &archivedAt
	}
	return value
}

func cloneWorkspaces(values []Workspace) []Workspace {
	cloned := make([]Workspace, len(values))
	for index, value := range values {
		cloned[index] = cloneWorkspace(value)
	}
	return cloned
}

func cloneInvitation(value Invitation) Invitation {
	if value.CreatedByUserID != nil {
		createdBy := *value.CreatedByUserID
		value.CreatedByUserID = &createdBy
	}
	if value.AcceptedByUserID != nil {
		acceptedBy := *value.AcceptedByUserID
		value.AcceptedByUserID = &acceptedBy
	}
	if value.AcceptedAt != nil {
		acceptedAt := *value.AcceptedAt
		value.AcceptedAt = &acceptedAt
	}
	if value.RevokedAt != nil {
		revokedAt := *value.RevokedAt
		value.RevokedAt = &revokedAt
	}
	return value
}

func cloneInvitations(values []Invitation) []Invitation {
	cloned := make([]Invitation, len(values))
	for index, value := range values {
		cloned[index] = cloneInvitation(value)
	}
	return cloned
}
