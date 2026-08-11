package desktopcontrol

import (
	"context"
	"crypto/sha256"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	AcceptHeartbeat(context.Context, DevicePrincipal, Heartbeat) (Instance, error)
	QueueHealthCheck(context.Context, QueueHealthCheckCommand) (Command, error)
	ClaimNextCommand(context.Context, DevicePrincipal) (*Command, error)
	AdvanceCommand(context.Context, DevicePrincipal, uuid.UUID, CommandResult) (Command, error)
	ListInstances(context.Context, InstanceFilter) (InstancePage, error)
	ListUserInstances(context.Context, uuid.UUID, InstanceFilter) (InstancePage, error)
	GetInstance(context.Context, uuid.UUID) (Instance, error)
	GetCommand(context.Context, uuid.UUID) (Command, error)
}

type HeartbeatReceipt struct {
	Instance             Instance
	AcceptedAt           time.Time
	NextHeartbeatSeconds int
	Command              *Command
	ServerTime           time.Time
}

type Service struct {
	repository Repository
	clock      func() time.Time
}

func NewService(repository Repository, clocks ...func() time.Time) *Service {
	clock := time.Now
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &Service{repository: repository, clock: clock}
}

func (s *Service) Heartbeat(ctx context.Context, principal DevicePrincipal, heartbeat Heartbeat) (HeartbeatReceipt, error) {
	if s == nil || s.repository == nil {
		return HeartbeatReceipt{}, ErrUnavailable
	}
	if err := validatePrincipal(principal); err != nil {
		return HeartbeatReceipt{}, err
	}
	if err := validateHeartbeat(heartbeat); err != nil {
		return HeartbeatReceipt{}, err
	}
	now := s.now()
	instance, err := s.repository.AcceptHeartbeat(ctx, principal, heartbeat)
	if err != nil {
		return HeartbeatReceipt{}, serviceError(err)
	}
	if instance.DeviceID != principal.DeviceID || instance.UserID != principal.UserID {
		return HeartbeatReceipt{}, ErrUnavailable
	}
	instance.EffectiveStatusValue = instance.EffectiveStatus(now)
	command, err := s.repository.ClaimNextCommand(ctx, principal)
	if err != nil {
		return HeartbeatReceipt{}, serviceError(err)
	}
	return HeartbeatReceipt{
		Instance: instance, AcceptedAt: now, NextHeartbeatSeconds: 60,
		Command: command, ServerTime: now,
	}, nil
}

func (s *Service) SubmitResult(ctx context.Context, principal DevicePrincipal, commandID uuid.UUID, result CommandResult) (Command, error) {
	if s == nil || s.repository == nil {
		return Command{}, ErrUnavailable
	}
	if err := validatePrincipal(principal); err != nil || commandID == uuid.Nil {
		return Command{}, ErrInvalidInput
	}
	if err := validateResult(result); err != nil {
		return Command{}, err
	}
	command, err := s.repository.AdvanceCommand(ctx, principal, commandID, result)
	if err != nil {
		return Command{}, serviceError(err)
	}
	return command, nil
}

func (s *Service) ListInstances(ctx context.Context, filter InstanceFilter) (InstancePage, error) {
	if s == nil || s.repository == nil {
		return InstancePage{}, ErrUnavailable
	}
	page, err := s.repository.ListInstances(ctx, filter)
	if err != nil {
		return InstancePage{}, serviceError(err)
	}
	return s.decoratePage(page), nil
}

func (s *Service) ListUserInstances(ctx context.Context, userID uuid.UUID, filter InstanceFilter) (InstancePage, error) {
	if s == nil || s.repository == nil || userID == uuid.Nil {
		return InstancePage{}, ErrInvalidInput
	}
	page, err := s.repository.ListUserInstances(ctx, userID, filter)
	if err != nil {
		return InstancePage{}, serviceError(err)
	}
	return s.decoratePage(page), nil
}

func (s *Service) GetInstance(ctx context.Context, deviceID uuid.UUID) (Instance, error) {
	if s == nil || s.repository == nil || deviceID == uuid.Nil {
		return Instance{}, ErrInvalidInput
	}
	instance, err := s.repository.GetInstance(ctx, deviceID)
	if err != nil {
		return Instance{}, serviceError(err)
	}
	instance.EffectiveStatusValue = instance.EffectiveStatus(s.now())
	return instance, nil
}

func (s *Service) QueueHealthCheck(ctx context.Context, actor AdminActor, deviceID uuid.UUID, idempotencyKey string) (Command, error) {
	if s == nil || s.repository == nil || deviceID == uuid.Nil || !idempotencyKeyPattern.MatchString(idempotencyKey) {
		return Command{}, ErrInvalidInput
	}
	hash := sha256.Sum256([]byte(idempotencyKey))
	input := QueueHealthCheckCommand{
		DeviceID: deviceID, IdempotencyKeyHash: hash[:], Actor: actor,
	}
	if err := validateQueue(input); err != nil {
		return Command{}, err
	}
	command, err := s.repository.QueueHealthCheck(ctx, input)
	if err != nil {
		return Command{}, serviceError(err)
	}
	return command, nil
}

func (s *Service) GetCommand(ctx context.Context, commandID uuid.UUID) (Command, error) {
	if s == nil || s.repository == nil || commandID == uuid.Nil {
		return Command{}, ErrInvalidInput
	}
	command, err := s.repository.GetCommand(ctx, commandID)
	if err != nil {
		return Command{}, serviceError(err)
	}
	return command, nil
}

func (s *Service) decoratePage(page InstancePage) InstancePage {
	now := s.now()
	for index := range page.Items {
		page.Items[index].EffectiveStatusValue = page.Items[index].EffectiveStatus(now)
	}
	page.ServerTime = now
	return page
}

func (s *Service) now() time.Time {
	if s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock().UTC()
}

func serviceError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrNotFound), errors.Is(err, ErrConflict),
		errors.Is(err, ErrInvalidTransition), errors.Is(err, ErrUnavailable):
		return err
	default:
		return ErrUnavailable
	}
}

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
