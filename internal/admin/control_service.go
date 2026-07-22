package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
)

const (
	defaultControlPageLimit = 50
	maximumControlPageLimit = 100
)

type QueryData interface {
	ListUsers(context.Context, UserQuery) (DataPage[User], error)
	LookupUser(context.Context, secure.IdentityKind, string) (User, error)
	GetUser(context.Context, uuid.UUID) (User, error)
	ListUserDevices(context.Context, DeviceQuery) (DataPage[Device], error)
	ListUserSessions(context.Context, SessionQuery) (DataPage[Session], error)
}

type CommandData interface {
	Execute(context.Context, Action, uuid.UUID, Command) (Operation, error)
	GetOperation(context.Context, uuid.UUID) (Operation, error)
}

type OfficialAuditData interface {
	ListOfficialAuditEvents(context.Context, OfficialAuditQuery) (DataPage[OfficialAuditEvent], error)
}

type DataPage[T any] struct {
	Items []T
	Next  *PagePosition
}

type UserQuery struct {
	Status UserStatus
	Limit  int
	After  *PagePosition
}

type DeviceQuery struct {
	UserID uuid.UUID
	Limit  int
	After  *PagePosition
}

type SessionQuery struct {
	UserID uuid.UUID
	Limit  int
	After  *PagePosition
	Now    time.Time
}

type OfficialAuditQuery struct {
	Limit int
	After *PagePosition
}

type ControlServiceConfig struct {
	Queries       QueryData
	Commands      CommandData
	OfficialAudit OfficialAuditData
	Protector     *Protector
	Clock         func() time.Time
}

type ControlService struct {
	queries       QueryData
	commands      CommandData
	officialAudit OfficialAuditData
	protector     *Protector
	clock         func() time.Time
}

func NewControlService(config ControlServiceConfig) (*ControlService, error) {
	if config.Queries == nil || config.Protector == nil || config.Clock == nil {
		return nil, errors.New("admin control service read dependencies are required")
	}
	return &ControlService{
		queries: config.Queries, commands: config.Commands, officialAudit: config.OfficialAudit,
		protector: config.Protector, clock: config.Clock,
	}, nil
}

func (s *ControlService) ListUsers(ctx context.Context, request ListUsersRequest) (Page[User], error) {
	if s == nil || !validUserStatusFilter(request.Status) {
		return Page[User]{}, ErrInvalidCommand
	}
	limit, after, err := s.decodePageRequest("users", request.PageRequest)
	if err != nil {
		return Page[User]{}, err
	}
	data, err := s.queries.ListUsers(ctx, UserQuery{Status: request.Status, Limit: limit, After: after})
	if err != nil {
		return Page[User]{}, mapControlDataError(err)
	}
	return toControlPage(s.protector, "users", data)
}

func (s *ControlService) LookupUser(ctx context.Context, request LookupRequest) (User, error) {
	if s == nil {
		return User{}, ErrInvalidCommand
	}
	normalized, err := secure.NormalizeIdentity(request.Kind, request.Value)
	if err != nil {
		return User{}, ErrInvalidCommand
	}
	user, err := s.queries.LookupUser(ctx, request.Kind, normalized)
	if err != nil {
		return User{}, mapControlDataError(err)
	}
	return user, nil
}

func (s *ControlService) GetUser(ctx context.Context, userID uuid.UUID) (User, error) {
	if s == nil || userID == uuid.Nil {
		return User{}, ErrInvalidCommand
	}
	user, err := s.queries.GetUser(ctx, userID)
	if err != nil {
		return User{}, mapControlDataError(err)
	}
	return user, nil
}

func (s *ControlService) ListUserDevices(
	ctx context.Context,
	userID uuid.UUID,
	request PageRequest,
) (Page[Device], error) {
	if s == nil || userID == uuid.Nil {
		return Page[Device]{}, ErrInvalidCommand
	}
	resource := scopedCursorResource("devices", userID)
	limit, after, err := s.decodePageRequest(resource, request)
	if err != nil {
		return Page[Device]{}, err
	}
	data, err := s.queries.ListUserDevices(ctx, DeviceQuery{UserID: userID, Limit: limit, After: after})
	if err != nil {
		return Page[Device]{}, mapControlDataError(err)
	}
	return toControlPage(s.protector, resource, data)
}

func (s *ControlService) ListUserSessions(
	ctx context.Context,
	userID uuid.UUID,
	request PageRequest,
) (Page[Session], error) {
	if s == nil || userID == uuid.Nil {
		return Page[Session]{}, ErrInvalidCommand
	}
	resource := scopedCursorResource("sessions", userID)
	limit, after, err := s.decodePageRequest(resource, request)
	if err != nil {
		return Page[Session]{}, err
	}
	data, err := s.queries.ListUserSessions(ctx, SessionQuery{
		UserID: userID, Limit: limit, After: after, Now: s.clock().UTC(),
	})
	if err != nil {
		return Page[Session]{}, mapControlDataError(err)
	}
	return toControlPage(s.protector, resource, data)
}

func (s *ControlService) Execute(
	ctx context.Context,
	action Action,
	targetID uuid.UUID,
	command Command,
) (Operation, error) {
	if s == nil || validateControlCommand(action, targetID, command) != nil {
		return Operation{}, ErrInvalidCommand
	}
	if s.commands == nil {
		return Operation{}, ErrUnavailable
	}
	operation, err := s.commands.Execute(ctx, action, targetID, command)
	if err != nil {
		mapped := mapControlDataError(err)
		if errors.Is(mapped, ErrNotFound) || errors.Is(mapped, ErrStateConflict) {
			if validateOperation(operation) != nil {
				return Operation{}, ErrUnavailable
			}
		}
		return operation, mapped
	}
	if err := validateOperation(operation); err != nil {
		return Operation{}, ErrUnavailable
	}
	return operation, nil
}

func (s *ControlService) GetOperation(ctx context.Context, operationID uuid.UUID) (Operation, error) {
	if s == nil || operationID == uuid.Nil {
		return Operation{}, ErrInvalidCommand
	}
	if s.commands == nil {
		return Operation{}, ErrUnavailable
	}
	operation, err := s.commands.GetOperation(ctx, operationID)
	if err != nil {
		return Operation{}, mapControlDataError(err)
	}
	if err := validateOperation(operation); err != nil || operation.ID != operationID {
		return Operation{}, ErrUnavailable
	}
	return operation, nil
}

func (s *ControlService) ListOfficialAuditEvents(
	ctx context.Context,
	request PageRequest,
) (Page[OfficialAuditEvent], error) {
	if s == nil || s.officialAudit == nil {
		return Page[OfficialAuditEvent]{}, ErrUnavailable
	}
	limit, after, err := s.decodePageRequest("official_agent_audit", request)
	if err != nil {
		return Page[OfficialAuditEvent]{}, err
	}
	data, err := s.officialAudit.ListOfficialAuditEvents(ctx, OfficialAuditQuery{Limit: limit, After: after})
	if err != nil {
		return Page[OfficialAuditEvent]{}, mapControlDataError(err)
	}
	return toControlPage(s.protector, "official_agent_audit", data)
}

func (s *ControlService) decodePageRequest(resource string, request PageRequest) (int, *PagePosition, error) {
	limit := request.Limit
	if limit == 0 {
		limit = defaultControlPageLimit
	}
	if limit < 1 || limit > maximumControlPageLimit {
		return 0, nil, ErrInvalidCommand
	}
	if request.Cursor == "" {
		return limit, nil, nil
	}
	after, err := s.protector.DecodeCursor(resource, request.Cursor)
	if err != nil {
		return 0, nil, ErrInvalidCursor
	}
	return limit, after, nil
}

func toControlPage[T any](protector *Protector, resource string, data DataPage[T]) (Page[T], error) {
	items := data.Items
	if items == nil {
		items = make([]T, 0)
	}
	page := Page[T]{Items: items}
	if data.Next == nil {
		return page, nil
	}
	cursor, err := protector.EncodeCursor(resource, *data.Next)
	if err != nil {
		return Page[T]{}, ErrUnavailable
	}
	page.NextCursor = cursor
	return page, nil
}

func validUserStatusFilter(status UserStatus) bool {
	return status == "" || status == UserActive || status == UserPendingDeletion || status == UserDisabled
}

func scopedCursorResource(kind string, userID uuid.UUID) string {
	return fmt.Sprintf("%s/%s", kind, userID.String())
}

func mapControlDataError(err error) error {
	for _, stable := range []error{
		ErrInvalidCommand,
		ErrInvalidCursor,
		ErrNotFound,
		ErrStateConflict,
		ErrIdempotencyKeyReused,
		ErrUnavailable,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	return ErrUnavailable
}
