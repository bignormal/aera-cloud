package organization

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

const TransferOrganizationOwnerConfirmation = "transfer-organization-owner"

var organizationRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

type RenameCommand struct {
	OrganizationID   uuid.UUID
	DisplayName      string
	ExpectedRevision int64
	RequestID        string
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
	RequestID                    string
}

type ServiceConfig struct {
	Repository      Repository
	DepartmentLimit int
	Clock           func() time.Time
	NewUUID         func() (uuid.UUID, error)
}

type Service struct {
	repository      serviceRepository
	departmentLimit int
	clock           func() time.Time
	newUUID         func() (uuid.UUID, error)
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
	mutationEvidence
}

func NewService(config ServiceConfig) (*Service, error) {
	repository, ok := config.Repository.(serviceRepository)
	if config.Repository == nil || !ok || config.DepartmentLimit <= 0 {
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
	return &Service{
		repository: repository, departmentLimit: config.DepartmentLimit,
		clock: clock, newUUID: newUUID,
	}, nil
}

func (s *Service) Rename(ctx context.Context, actor Actor, command RenameCommand) (OrganizationSummary, error) {
	displayName, err := NormalizeOrganizationName(command.DisplayName)
	if s == nil || actor.Validate() != nil || err != nil || command.OrganizationID == uuid.Nil ||
		command.ExpectedRevision <= 0 || !validOrganizationRequestID(command.RequestID) {
		return OrganizationSummary{}, ErrInvalidRequest
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
		command.Confirmation != TransferOrganizationOwnerConfirmation || !validOrganizationRequestID(command.RequestID) {
		return OrganizationSummary{}, ErrInvalidRequest
	}
	evidence, err := s.mutation(command.RequestID)
	if err != nil {
		return OrganizationSummary{}, err
	}
	return s.repository.transferOwner(ctx, actor, ownerTransferTransaction{
		OrganizationID: command.OrganizationID, TargetUserID: command.TargetUserID,
		ExpectedOrganizationRevision: command.ExpectedOrganizationRevision,
		ExpectedOwnerRevision:        command.ExpectedOwnerRevision, ExpectedTargetRevision: command.ExpectedTargetRevision,
		mutationEvidence: evidence,
	})
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
