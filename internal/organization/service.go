package organization

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

	"github.com/google/uuid"
)

const TransferOrganizationOwnerConfirmation = "transfer-organization-owner"
const DissolveOrganizationConfirmation = "dissolve-organization"

const (
	organizationIdempotencyLifetime = 24 * time.Hour
	organizationInvitationLifetime  = 7 * 24 * time.Hour
)

var organizationRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

type RenameCommand struct {
	OrganizationID   uuid.UUID
	DisplayName      string
	ExpectedRevision int64
	RequestID        string
}

type CreateOrganizationCommand struct {
	DisplayName    string
	IdempotencyKey string
	RequestID      string
}

type OrganizationCreationResult struct {
	Organization OrganizationSummary
	Replayed     bool
}

type PatchMemberCommand struct {
	OrganizationID   uuid.UUID
	UserID           uuid.UUID
	Role             *Role
	ChangeDepartment bool
	DepartmentID     *uuid.UUID
	ClearDepartment  bool
	ExpectedRevision int64
	RequestID        string
}

type RemoveMemberCommand struct {
	OrganizationID   uuid.UUID
	UserID           uuid.UUID
	ExpectedRevision int64
	RequestID        string
}

type LeaveCommand struct {
	OrganizationID uuid.UUID
	RequestID      string
}

type CreateDepartmentCommand struct {
	OrganizationID uuid.UUID
	DisplayName    string
	RequestID      string
}

type RenameDepartmentCommand struct {
	OrganizationID   uuid.UUID
	DepartmentID     uuid.UUID
	DisplayName      string
	ExpectedRevision int64
	RequestID        string
}

type DepartmentLifecycleCommand struct {
	OrganizationID   uuid.UUID
	DepartmentID     uuid.UUID
	ExpectedRevision int64
	RequestID        string
}

type OwnerTransferCommand struct {
	OrganizationID               uuid.UUID
	TargetUserID                 uuid.UUID
	ExpectedOrganizationRevision int64
	ExpectedOwnerRevision        int64
	ExpectedTargetRevision       int64
	Confirmation                 string
	IdempotencyKey               string
	RequestID                    string
}

type CreateInvitationCommand struct {
	OrganizationID uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type RevokeInvitationCommand struct {
	OrganizationID uuid.UUID
	InvitationID   uuid.UUID
	RequestID      string
}

type AcceptInvitationCommand struct {
	Token          string
	IdempotencyKey string
	RequestID      string
}

type ArchiveCommand struct {
	OrganizationID   uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type RestoreCommand struct {
	OrganizationID   uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type DissolveCommand struct {
	OrganizationID   uuid.UUID
	DisplayName      string
	ExpectedRevision int64
	Confirmation     string
	IdempotencyKey   string
	RequestID        string
}

type PublishPolicyCommand struct {
	OrganizationID               uuid.UUID
	Document                     PolicyDocument
	ExpectedOrganizationRevision int64
	ExpectedPolicyVersion        int64
	IdempotencyKey               string
	RequestID                    string
}

type InvitationCreationResult struct {
	Invitation InvitationSummary
	Token      string
	InviteURL  string
}

type InvitationAcceptance struct {
	Organization OrganizationSummary
	Member       MemberSummary
}

type ServiceConfig struct {
	Repository             Repository
	Limiter                Limiter
	OwnedLimit             int
	DepartmentLimit        int
	MemberLimit            int
	PendingInvitationLimit int
	Clock                  func() time.Time
	NewUUID                func() (uuid.UUID, error)
	Random                 io.Reader
}

type Service struct {
	repository             serviceRepository
	limiter                Limiter
	ownedLimit             int
	departmentLimit        int
	memberLimit            int
	pendingInvitationLimit int
	clock                  func() time.Time
	newUUID                func() (uuid.UUID, error)
	random                 io.Reader
	randomMu               sync.Mutex
}

type serviceRepository interface {
	Repository
	rename(context.Context, Actor, renameTransaction) (OrganizationSummary, error)
	patchMember(context.Context, Actor, patchMemberTransaction) (MemberSummary, error)
	removeMember(context.Context, Actor, removeMemberTransaction) error
	leave(context.Context, Actor, leaveTransaction) error
	createDepartment(context.Context, Actor, createDepartmentTransaction) (DepartmentSummary, error)
	renameDepartment(context.Context, Actor, renameDepartmentTransaction) (DepartmentSummary, error)
	archiveDepartment(context.Context, Actor, departmentLifecycleTransaction) (DepartmentSummary, error)
	restoreDepartment(context.Context, Actor, departmentLifecycleTransaction) (DepartmentSummary, error)
	transferOwner(context.Context, Actor, ownerTransferTransaction) (OrganizationSummary, error)
	createInvitation(context.Context, Actor, createInvitationTransaction) (invitationCreation, error)
	revokeInvitation(context.Context, Actor, revokeInvitationTransaction) error
	acceptInvitation(context.Context, Actor, acceptInvitationTransaction) (InvitationAcceptance, error)
	listInvitations(context.Context, uuid.UUID, uuid.UUID, Page) (InvitationPage, error)
	archive(context.Context, Actor, organizationLifecycleTransaction) (OrganizationSummary, error)
	restore(context.Context, Actor, organizationLifecycleTransaction) (OrganizationSummary, error)
	dissolve(context.Context, Actor, dissolveOrganizationTransaction) (OrganizationSummary, error)
	publishPolicy(context.Context, Actor, publishPolicyTransaction) (PolicySnapshot, error)
}

type mutationEvidence struct {
	Audit     AuditEvidence
	ChangedAt time.Time
}

type renameTransaction struct {
	OrganizationID   uuid.UUID
	DisplayName      string
	ExpectedRevision int64
	mutationEvidence
}

type patchMemberTransaction struct {
	OrganizationID   uuid.UUID
	UserID           uuid.UUID
	Role             *Role
	ChangeDepartment bool
	DepartmentID     *uuid.UUID
	ClearDepartment  bool
	ExpectedRevision int64
	mutationEvidence
}

type removeMemberTransaction struct {
	OrganizationID   uuid.UUID
	UserID           uuid.UUID
	ExpectedRevision int64
	mutationEvidence
}

type leaveTransaction struct {
	OrganizationID uuid.UUID
	mutationEvidence
}

type createDepartmentTransaction struct {
	OrganizationID uuid.UUID
	DepartmentID   uuid.UUID
	DisplayName    string
	NameKey        string
	ActiveLimit    int
	mutationEvidence
}

type renameDepartmentTransaction struct {
	OrganizationID   uuid.UUID
	DepartmentID     uuid.UUID
	DisplayName      string
	NameKey          string
	ExpectedRevision int64
	mutationEvidence
}

type departmentLifecycleTransaction struct {
	OrganizationID   uuid.UUID
	DepartmentID     uuid.UUID
	ExpectedRevision int64
	ActiveLimit      int
	mutationEvidence
}

type ownerTransferTransaction struct {
	OrganizationID               uuid.UUID
	TargetUserID                 uuid.UUID
	ExpectedOrganizationRevision int64
	ExpectedOwnerRevision        int64
	ExpectedTargetRevision       int64
	Idempotency                  IdempotencyEvidence
	mutationEvidence
}

type createInvitationTransaction struct {
	OrganizationID uuid.UUID
	InvitationID   uuid.UUID
	Secret         InvitationSecret
	PendingLimit   int
	Idempotency    IdempotencyEvidence
	mutationEvidence
}

type revokeInvitationTransaction struct {
	OrganizationID uuid.UUID
	InvitationID   uuid.UUID
	mutationEvidence
}

type acceptInvitationTransaction struct {
	TokenDigest [sha256.Size]byte
	MemberLimit int
	Idempotency IdempotencyEvidence
	mutationEvidence
}

type organizationLifecycleTransaction struct {
	OrganizationID   uuid.UUID
	ExpectedRevision int64
	OwnedLimit       int
	Idempotency      IdempotencyEvidence
	mutationEvidence
}

type dissolveOrganizationTransaction struct {
	OrganizationID   uuid.UUID
	DisplayName      string
	ExpectedRevision int64
	Idempotency      IdempotencyEvidence
	mutationEvidence
}

type publishPolicyTransaction struct {
	OrganizationID               uuid.UUID
	SnapshotID                   uuid.UUID
	Canonical                    CanonicalPolicy
	ExpectedOrganizationRevision int64
	ExpectedPolicyVersion        int64
	Idempotency                  IdempotencyEvidence
	mutationEvidence
}

type invitationCreation struct {
	Invitation InvitationSummary
	Secret     *InvitationSecret
}

type InvitationPage struct {
	Items []InvitationSummary
	Next  *PageCursor
}

func NewService(config ServiceConfig) (*Service, error) {
	repository, ok := config.Repository.(serviceRepository)
	if config.Repository == nil || !ok || config.Limiter == nil || config.OwnedLimit <= 0 || config.DepartmentLimit <= 0 || config.MemberLimit <= 0 ||
		config.PendingInvitationLimit <= 0 {
		return nil, fmt.Errorf("%w: Organization service configuration is invalid", ErrInvalidRequest)
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	newUUID := config.NewUUID
	if newUUID == nil {
		newUUID = uuid.NewRandom
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	return &Service{
		repository: repository, limiter: config.Limiter, ownedLimit: config.OwnedLimit, departmentLimit: config.DepartmentLimit, memberLimit: config.MemberLimit,
		pendingInvitationLimit: config.PendingInvitationLimit, clock: clock, newUUID: newUUID, random: random,
	}, nil
}

func (s *Service) Create(
	ctx context.Context,
	actor Actor,
	command CreateOrganizationCommand,
) (OrganizationCreationResult, error) {
	displayName, nameErr := NormalizeOrganizationName(command.DisplayName)
	if s == nil || actor.Validate() != nil || nameErr != nil ||
		!validOrganizationIdempotencyKey(command.IdempotencyKey) || !validOrganizationRequestID(command.RequestID) {
		return OrganizationCreationResult{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitOrganizationCreate, actor, nil); err != nil {
		return OrganizationCreationResult{}, err
	}
	organizationID, err := s.newID()
	if err != nil {
		return OrganizationCreationResult{}, err
	}
	policySnapshotID, err := s.newID()
	if err != nil {
		return OrganizationCreationResult{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return OrganizationCreationResult{}, err
	}
	createdAt := evidence.ChangedAt.UTC()
	requestDigest := canonicalCreateRequestDigest(displayName)
	organization, err := s.repository.Create(ctx, CreateTransaction{
		Actor: actor, OrganizationID: organizationID, DisplayName: displayName,
		OwnedLimit: s.ownedLimit, PolicySnapshotID: policySnapshotID,
		Idempotency: IdempotencyEvidence{
			KeyDigest: sha256.Sum256([]byte(command.IdempotencyKey)), RequestDigest: requestDigest,
			ExpiresAt: createdAt.Add(organizationIdempotencyLifetime),
		},
		Audit: evidence.Audit, CreatedAt: createdAt,
	})
	if err != nil {
		return OrganizationCreationResult{}, err
	}
	return OrganizationCreationResult{Organization: organization, Replayed: organization.ID != organizationID}, nil
}

func (s *Service) List(
	ctx context.Context,
	actor Actor,
	page Page,
) (OrganizationPage, error) {
	if s == nil || actor.Validate() != nil || !validPage(page, false) {
		return OrganizationPage{}, ErrInvalidRequest
	}
	return s.repository.ListForActor(ctx, actor.UserID, page)
}

func (s *Service) Get(
	ctx context.Context,
	actor Actor,
	organizationID uuid.UUID,
) (OrganizationSummary, error) {
	if s == nil || actor.Validate() != nil || organizationID == uuid.Nil {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	return s.repository.GetForActor(ctx, actor.UserID, organizationID)
}

func (s *Service) ListMembers(
	ctx context.Context,
	actor Actor,
	organizationID uuid.UUID,
	page Page,
) (MemberPage, error) {
	if s == nil || actor.Validate() != nil || organizationID == uuid.Nil || !validPage(page, false) {
		return MemberPage{}, ErrInvalidRequest
	}
	return s.repository.ListMembers(ctx, actor.UserID, organizationID, page)
}

func (s *Service) ListDepartments(
	ctx context.Context,
	actor Actor,
	organizationID uuid.UUID,
	page Page,
) (DepartmentPage, error) {
	if s == nil || actor.Validate() != nil || organizationID == uuid.Nil || !validPage(page, true) {
		return DepartmentPage{}, ErrInvalidRequest
	}
	return s.repository.ListDepartments(ctx, actor.UserID, organizationID, page)
}

func (s *Service) GetCurrentPolicy(
	ctx context.Context,
	actor Actor,
	organizationID uuid.UUID,
) (PolicySnapshot, error) {
	if s == nil || actor.Validate() != nil || organizationID == uuid.Nil {
		return PolicySnapshot{}, ErrInvalidRequest
	}
	return s.repository.CurrentPolicy(ctx, actor.UserID, organizationID, true)
}

func (s *Service) Rename(ctx context.Context, actor Actor, command RenameCommand) (OrganizationSummary, error) {
	displayName, err := NormalizeOrganizationName(command.DisplayName)
	if s == nil || actor.Validate() != nil || err != nil || command.OrganizationID == uuid.Nil ||
		command.ExpectedRevision <= 0 || !validOrganizationRequestID(command.RequestID) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitMutation, actor, &command.OrganizationID); err != nil {
		return OrganizationSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	return s.repository.rename(ctx, actor, renameTransaction{
		OrganizationID: command.OrganizationID, DisplayName: displayName,
		ExpectedRevision: command.ExpectedRevision, mutationEvidence: evidence,
	})
}

func (s *Service) PatchMember(ctx context.Context, actor Actor, command PatchMemberCommand) (MemberSummary, error) {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil || command.UserID == uuid.Nil ||
		command.ExpectedRevision <= 0 || !validOrganizationRequestID(command.RequestID) || !validPatchMemberCommand(command) {
		return MemberSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitMutation, actor, &command.OrganizationID); err != nil {
		return MemberSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return MemberSummary{}, err
	}
	transaction := patchMemberTransaction{
		OrganizationID: command.OrganizationID, UserID: command.UserID,
		ChangeDepartment: command.ChangeDepartment, ClearDepartment: command.ClearDepartment,
		ExpectedRevision: command.ExpectedRevision, mutationEvidence: evidence,
	}
	if command.Role != nil {
		value := *command.Role
		transaction.Role = &value
	}
	if command.DepartmentID != nil {
		value := *command.DepartmentID
		transaction.DepartmentID = &value
	}
	return s.repository.patchMember(ctx, actor, transaction)
}

func (s *Service) RemoveMember(ctx context.Context, actor Actor, command RemoveMemberCommand) error {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil || command.UserID == uuid.Nil ||
		command.ExpectedRevision <= 0 || !validOrganizationRequestID(command.RequestID) {
		return ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitMutation, actor, &command.OrganizationID); err != nil {
		return err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return err
	}
	return s.repository.removeMember(ctx, actor, removeMemberTransaction{
		OrganizationID: command.OrganizationID, UserID: command.UserID,
		ExpectedRevision: command.ExpectedRevision, mutationEvidence: evidence,
	})
}

func (s *Service) Leave(ctx context.Context, actor Actor, command LeaveCommand) error {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil ||
		!validOrganizationRequestID(command.RequestID) {
		return ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitMutation, actor, &command.OrganizationID); err != nil {
		return err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return err
	}
	return s.repository.leave(ctx, actor, leaveTransaction{
		OrganizationID: command.OrganizationID, mutationEvidence: evidence,
	})
}

func (s *Service) CreateDepartment(
	ctx context.Context,
	actor Actor,
	command CreateDepartmentCommand,
) (DepartmentSummary, error) {
	displayName, nameKey, err := NormalizeDepartmentName(command.DisplayName)
	if s == nil || actor.Validate() != nil || err != nil || command.OrganizationID == uuid.Nil ||
		!validOrganizationRequestID(command.RequestID) {
		return DepartmentSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitMutation, actor, &command.OrganizationID); err != nil {
		return DepartmentSummary{}, err
	}
	departmentID, err := s.newID()
	if err != nil {
		return DepartmentSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return DepartmentSummary{}, err
	}
	return s.repository.createDepartment(ctx, actor, createDepartmentTransaction{
		OrganizationID: command.OrganizationID, DepartmentID: departmentID,
		DisplayName: displayName, NameKey: nameKey, ActiveLimit: s.departmentLimit,
		mutationEvidence: evidence,
	})
}

func (s *Service) RenameDepartment(
	ctx context.Context,
	actor Actor,
	command RenameDepartmentCommand,
) (DepartmentSummary, error) {
	displayName, nameKey, err := NormalizeDepartmentName(command.DisplayName)
	if s == nil || actor.Validate() != nil || err != nil || command.OrganizationID == uuid.Nil ||
		command.DepartmentID == uuid.Nil || command.ExpectedRevision <= 0 ||
		!validOrganizationRequestID(command.RequestID) {
		return DepartmentSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitMutation, actor, &command.OrganizationID); err != nil {
		return DepartmentSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return DepartmentSummary{}, err
	}
	return s.repository.renameDepartment(ctx, actor, renameDepartmentTransaction{
		OrganizationID: command.OrganizationID, DepartmentID: command.DepartmentID,
		DisplayName: displayName, NameKey: nameKey, ExpectedRevision: command.ExpectedRevision,
		mutationEvidence: evidence,
	})
}

func (s *Service) ArchiveDepartment(
	ctx context.Context,
	actor Actor,
	command DepartmentLifecycleCommand,
) (DepartmentSummary, error) {
	return s.changeDepartmentLifecycle(ctx, actor, command, false)
}

func (s *Service) RestoreDepartment(
	ctx context.Context,
	actor Actor,
	command DepartmentLifecycleCommand,
) (DepartmentSummary, error) {
	return s.changeDepartmentLifecycle(ctx, actor, command, true)
}

func (s *Service) changeDepartmentLifecycle(
	ctx context.Context,
	actor Actor,
	command DepartmentLifecycleCommand,
	restore bool,
) (DepartmentSummary, error) {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil || command.DepartmentID == uuid.Nil ||
		command.ExpectedRevision <= 0 || !validOrganizationRequestID(command.RequestID) {
		return DepartmentSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitMutation, actor, &command.OrganizationID); err != nil {
		return DepartmentSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return DepartmentSummary{}, err
	}
	transaction := departmentLifecycleTransaction{
		OrganizationID: command.OrganizationID, DepartmentID: command.DepartmentID,
		ExpectedRevision: command.ExpectedRevision, ActiveLimit: s.departmentLimit,
		mutationEvidence: evidence,
	}
	if restore {
		return s.repository.restoreDepartment(ctx, actor, transaction)
	}
	return s.repository.archiveDepartment(ctx, actor, transaction)
}

func (s *Service) TransferOwner(
	ctx context.Context,
	actor Actor,
	command OwnerTransferCommand,
) (OrganizationSummary, error) {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil || command.TargetUserID == uuid.Nil ||
		command.TargetUserID == actor.UserID || command.ExpectedOrganizationRevision <= 0 ||
		command.ExpectedOwnerRevision <= 0 || command.ExpectedTargetRevision <= 0 ||
		command.Confirmation != TransferOrganizationOwnerConfirmation ||
		!validOrganizationIdempotencyKey(command.IdempotencyKey) || !validOrganizationRequestID(command.RequestID) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitHighRisk, actor, &command.OrganizationID); err != nil {
		return OrganizationSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	return s.repository.transferOwner(ctx, actor, ownerTransferTransaction{
		OrganizationID: command.OrganizationID, TargetUserID: command.TargetUserID,
		ExpectedOrganizationRevision: command.ExpectedOrganizationRevision,
		ExpectedOwnerRevision:        command.ExpectedOwnerRevision, ExpectedTargetRevision: command.ExpectedTargetRevision,
		Idempotency: lifecycleIdempotency(command.IdempotencyKey,
			canonicalOrganizationOwnerTransferRequestDigest(command), evidence.ChangedAt),
		mutationEvidence: evidence,
	})
}

func (s *Service) ListInvitations(
	ctx context.Context,
	actor Actor,
	organizationID uuid.UUID,
	page Page,
) (InvitationPage, error) {
	if s == nil || actor.Validate() != nil || organizationID == uuid.Nil || !validPage(page, true) {
		return InvitationPage{}, ErrInvalidRequest
	}
	return s.repository.listInvitations(ctx, actor.UserID, organizationID, page)
}

func (s *Service) CreateInvitation(
	ctx context.Context,
	actor Actor,
	command CreateInvitationCommand,
) (InvitationCreationResult, error) {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil ||
		!validOrganizationIdempotencyKey(command.IdempotencyKey) || !validOrganizationRequestID(command.RequestID) {
		return InvitationCreationResult{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitInvitationCreate, actor, &command.OrganizationID); err != nil {
		return InvitationCreationResult{}, err
	}
	invitationID, err := s.newID()
	if err != nil {
		return InvitationCreationResult{}, err
	}
	secret, err := s.newInvitationSecret()
	if err != nil {
		return InvitationCreationResult{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return InvitationCreationResult{}, err
	}
	now := evidence.ChangedAt
	creation, err := s.repository.createInvitation(ctx, actor, createInvitationTransaction{
		OrganizationID: command.OrganizationID, InvitationID: invitationID, Secret: secret,
		PendingLimit: s.pendingInvitationLimit,
		Idempotency: IdempotencyEvidence{
			KeyDigest:     sha256.Sum256([]byte(command.IdempotencyKey)),
			RequestDigest: canonicalInvitationCreateRequestDigest(command.OrganizationID),
			ExpiresAt:     now.Add(organizationIdempotencyLifetime),
		},
		mutationEvidence: evidence,
	})
	if err != nil {
		return InvitationCreationResult{}, err
	}
	result := InvitationCreationResult{Invitation: creation.Invitation}
	if creation.Secret != nil {
		result.Token = creation.Secret.RawToken
		result.InviteURL = "agentera://organization-invitation#" + creation.Secret.RawToken
	}
	return result, nil
}

func (s *Service) RevokeInvitation(ctx context.Context, actor Actor, command RevokeInvitationCommand) error {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil || command.InvitationID == uuid.Nil ||
		!validOrganizationRequestID(command.RequestID) {
		return ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitMutation, actor, &command.OrganizationID); err != nil {
		return err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return err
	}
	return s.repository.revokeInvitation(ctx, actor, revokeInvitationTransaction{
		OrganizationID: command.OrganizationID, InvitationID: command.InvitationID,
		mutationEvidence: evidence,
	})
}

func (s *Service) AcceptInvitation(
	ctx context.Context,
	actor Actor,
	command AcceptInvitationCommand,
) (InvitationAcceptance, error) {
	if s == nil || actor.Validate() != nil || !validOrganizationIdempotencyKey(command.IdempotencyKey) ||
		!validOrganizationRequestID(command.RequestID) {
		return InvitationAcceptance{}, ErrInvalidRequest
	}
	tokenDigest, err := InvitationDigest(command.Token)
	if err != nil {
		return InvitationAcceptance{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitInvitationAccept, actor, nil); err != nil {
		return InvitationAcceptance{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return InvitationAcceptance{}, err
	}
	return s.repository.acceptInvitation(ctx, actor, acceptInvitationTransaction{
		TokenDigest: tokenDigest, MemberLimit: s.memberLimit,
		Idempotency: IdempotencyEvidence{
			KeyDigest:     sha256.Sum256([]byte(command.IdempotencyKey)),
			RequestDigest: canonicalInvitationAcceptRequestDigest(tokenDigest),
			ExpiresAt:     evidence.ChangedAt.Add(organizationIdempotencyLifetime),
		},
		mutationEvidence: evidence,
	})
}

func (s *Service) Archive(
	ctx context.Context,
	actor Actor,
	command ArchiveCommand,
) (OrganizationSummary, error) {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil || command.ExpectedRevision <= 0 ||
		!validOrganizationIdempotencyKey(command.IdempotencyKey) || !validOrganizationRequestID(command.RequestID) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitHighRisk, actor, &command.OrganizationID); err != nil {
		return OrganizationSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	return s.repository.archive(ctx, actor, organizationLifecycleTransaction{
		OrganizationID: command.OrganizationID, ExpectedRevision: command.ExpectedRevision,
		Idempotency: lifecycleIdempotency(command.IdempotencyKey,
			canonicalOrganizationLifecycleRequestDigest("archive", command.OrganizationID, command.ExpectedRevision), evidence.ChangedAt),
		mutationEvidence: evidence,
	})
}

func (s *Service) Restore(
	ctx context.Context,
	actor Actor,
	command RestoreCommand,
) (OrganizationSummary, error) {
	if s == nil || actor.Validate() != nil || command.OrganizationID == uuid.Nil || command.ExpectedRevision <= 0 ||
		!validOrganizationIdempotencyKey(command.IdempotencyKey) || !validOrganizationRequestID(command.RequestID) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitHighRisk, actor, &command.OrganizationID); err != nil {
		return OrganizationSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	return s.repository.restore(ctx, actor, organizationLifecycleTransaction{
		OrganizationID: command.OrganizationID, ExpectedRevision: command.ExpectedRevision, OwnedLimit: s.ownedLimit,
		Idempotency: lifecycleIdempotency(command.IdempotencyKey,
			canonicalOrganizationLifecycleRequestDigest("restore", command.OrganizationID, command.ExpectedRevision), evidence.ChangedAt),
		mutationEvidence: evidence,
	})
}

func (s *Service) Dissolve(
	ctx context.Context,
	actor Actor,
	command DissolveCommand,
) (OrganizationSummary, error) {
	displayName, nameErr := NormalizeOrganizationName(command.DisplayName)
	if s == nil || actor.Validate() != nil || nameErr != nil || displayName != command.DisplayName || command.OrganizationID == uuid.Nil ||
		command.ExpectedRevision <= 0 || command.Confirmation != DissolveOrganizationConfirmation ||
		!validOrganizationIdempotencyKey(command.IdempotencyKey) || !validOrganizationRequestID(command.RequestID) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitHighRisk, actor, &command.OrganizationID); err != nil {
		return OrganizationSummary{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	return s.repository.dissolve(ctx, actor, dissolveOrganizationTransaction{
		OrganizationID: command.OrganizationID, DisplayName: displayName, ExpectedRevision: command.ExpectedRevision,
		Idempotency: lifecycleIdempotency(command.IdempotencyKey,
			canonicalOrganizationDissolveRequestDigest(command.OrganizationID, displayName, command.ExpectedRevision), evidence.ChangedAt),
		mutationEvidence: evidence,
	})
}

func (s *Service) PublishPolicy(
	ctx context.Context,
	actor Actor,
	command PublishPolicyCommand,
) (PolicySnapshot, error) {
	canonical, canonicalErr := CanonicalizePolicy(command.Document)
	if s == nil || actor.Validate() != nil || canonicalErr != nil || command.OrganizationID == uuid.Nil ||
		command.ExpectedOrganizationRevision <= 0 || command.ExpectedPolicyVersion <= 1 ||
		!validOrganizationIdempotencyKey(command.IdempotencyKey) || !validOrganizationRequestID(command.RequestID) {
		return PolicySnapshot{}, ErrInvalidRequest
	}
	if err := s.applyLimit(ctx, LimitHighRisk, actor, &command.OrganizationID); err != nil {
		return PolicySnapshot{}, err
	}
	snapshotID, err := s.newID()
	if err != nil {
		return PolicySnapshot{}, err
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return PolicySnapshot{}, err
	}
	return s.repository.publishPolicy(ctx, actor, publishPolicyTransaction{
		OrganizationID: command.OrganizationID, SnapshotID: snapshotID, Canonical: canonical,
		ExpectedOrganizationRevision: command.ExpectedOrganizationRevision,
		ExpectedPolicyVersion:        command.ExpectedPolicyVersion,
		Idempotency: lifecycleIdempotency(command.IdempotencyKey,
			canonicalOrganizationPolicyRequestDigest(command.OrganizationID, canonical.ContentDigest,
				command.ExpectedOrganizationRevision, command.ExpectedPolicyVersion), evidence.ChangedAt),
		mutationEvidence: evidence,
	})
}

func (s *Service) ListPolicySnapshots(
	ctx context.Context,
	actor Actor,
	organizationID uuid.UUID,
	page Page,
) (PolicyPage, error) {
	if s == nil || actor.Validate() != nil || organizationID == uuid.Nil || !validPage(page, true) {
		return PolicyPage{}, ErrInvalidRequest
	}
	return s.repository.ListPolicySnapshots(ctx, actor.UserID, organizationID, page)
}

func (s *Service) GetPolicySnapshot(
	ctx context.Context,
	actor Actor,
	snapshotID uuid.UUID,
) (PolicySnapshot, error) {
	if s == nil || actor.Validate() != nil || snapshotID == uuid.Nil {
		return PolicySnapshot{}, ErrInvalidRequest
	}
	return s.repository.GetPolicySnapshot(ctx, actor.UserID, snapshotID)
}

func (s *Service) ListAudit(
	ctx context.Context,
	actor Actor,
	organizationID uuid.UUID,
	page Page,
) (AuditPage, error) {
	if s == nil || actor.Validate() != nil || organizationID == uuid.Nil || !validPage(page, true) {
		return AuditPage{}, ErrInvalidRequest
	}
	return s.repository.ListAudit(ctx, actor.UserID, organizationID, page)
}

func (s *Service) mutation(requestID string) (mutationEvidence, error) {
	auditID, err := s.newID()
	if err != nil {
		return mutationEvidence{}, err
	}
	return mutationEvidence{
		Audit: AuditEvidence{EventID: auditID, RequestID: requestID}, ChangedAt: s.clock().UTC(),
	}, nil
}

func (s *Service) newID() (uuid.UUID, error) {
	value, err := s.newUUID()
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

func (s *Service) applyLimit(
	ctx context.Context,
	action LimitAction,
	actor Actor,
	organizationID *uuid.UUID,
) error {
	retryAfter, err := s.limiter.Allow(ctx, action, actor, organizationID)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRateLimited) {
		return &RateLimitError{RetryAfter: retryAfter}
	}
	return ErrServiceUnavailable
}

func validPatchMemberCommand(command PatchMemberCommand) bool {
	if command.Role == nil && !command.ChangeDepartment {
		return false
	}
	if command.Role != nil {
		switch *command.Role {
		case RoleAdmin, RoleAuditor, RoleMember:
		default:
			return false
		}
	}
	if !command.ChangeDepartment {
		return command.DepartmentID == nil && !command.ClearDepartment
	}
	return (command.DepartmentID != nil) != command.ClearDepartment &&
		(command.DepartmentID == nil || *command.DepartmentID != uuid.Nil)
}

func validOrganizationRequestID(value string) bool {
	return organizationRequestIDPattern.MatchString(value)
}

func validOrganizationIdempotencyKey(value string) bool {
	return value == strings.TrimSpace(value) && organizationRequestIDPattern.MatchString(value)
}

func canonicalInvitationCreateRequestDigest(organizationID uuid.UUID) [sha256.Size]byte {
	return sha256.Sum256([]byte("agentera.organization-invitation-create.v1\x00" + organizationID.String()))
}

func canonicalInvitationAcceptRequestDigest(tokenDigest [sha256.Size]byte) [sha256.Size]byte {
	payload := make([]byte, 0, 48+sha256.Size)
	payload = append(payload, []byte("agentera.organization-invitation-accept.v1\x00")...)
	payload = append(payload, tokenDigest[:]...)
	return sha256.Sum256(payload)
}

func lifecycleIdempotency(key string, requestDigest [sha256.Size]byte, changedAt time.Time) IdempotencyEvidence {
	return IdempotencyEvidence{
		KeyDigest: sha256.Sum256([]byte(key)), RequestDigest: requestDigest,
		ExpiresAt: changedAt.UTC().Add(organizationIdempotencyLifetime),
	}
}

func canonicalOrganizationLifecycleRequestDigest(
	operation string,
	organizationID uuid.UUID,
	expectedRevision int64,
) [sha256.Size]byte {
	payload := fmt.Sprintf("agentera.organization-%s.v1\x00%s\x00%d", operation, organizationID, expectedRevision)
	return sha256.Sum256([]byte(payload))
}

func canonicalOrganizationDissolveRequestDigest(
	organizationID uuid.UUID,
	displayName string,
	expectedRevision int64,
) [sha256.Size]byte {
	payload := fmt.Sprintf("agentera.organization-dissolve.v1\x00%s\x00%s\x00%d\x00%s",
		organizationID, displayName, expectedRevision, DissolveOrganizationConfirmation)
	return sha256.Sum256([]byte(payload))
}

func canonicalOrganizationPolicyRequestDigest(
	organizationID uuid.UUID,
	contentDigest [sha256.Size]byte,
	expectedOrganizationRevision int64,
	expectedPolicyVersion int64,
) [sha256.Size]byte {
	payload := []byte(fmt.Sprintf("agentera.organization-policy-publish.v1\x00%s\x00%d\x00%d\x00",
		organizationID, expectedOrganizationRevision, expectedPolicyVersion))
	payload = append(payload, contentDigest[:]...)
	return sha256.Sum256(payload)
}

func canonicalOrganizationOwnerTransferRequestDigest(command OwnerTransferCommand) [sha256.Size]byte {
	payload := fmt.Sprintf("agentera.organization-owner-transfer.v1\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s",
		command.OrganizationID, command.TargetUserID, command.ExpectedOrganizationRevision,
		command.ExpectedOwnerRevision, command.ExpectedTargetRevision, TransferOrganizationOwnerConfirmation)
	return sha256.Sum256([]byte(payload))
}
