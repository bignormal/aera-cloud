package admin

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrInvalidCommand = errors.New("restricted command is invalid")
	ErrNotFound       = errors.New("restricted command target was not found")
	ErrUnavailable    = errors.New("restricted command storage is unavailable")
)

type Mutation struct {
	Operator     string
	TargetUserID uuid.UUID
	SessionID    uuid.UUID
	AuditEventID uuid.UUID
	OccurredAt   time.Time
}

type AuditQuery struct {
	Operator     string
	TargetUserID uuid.UUID
	Limit        int
	AuditEventID uuid.UUID
	OccurredAt   time.Time
}

// RedactedAuditEvent intentionally omits identity values, IP HMACs, request
// metadata, device IDs, object IDs, and operator metadata.
type RedactedAuditEvent struct {
	ID         uuid.UUID `json:"id"`
	EventType  string    `json:"event_type"`
	Outcome    string    `json:"outcome"`
	ReasonCode string    `json:"reason_code,omitempty"`
	ObjectType string    `json:"object_type,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type Repository interface {
	DisableAccount(context.Context, Mutation) error
	EnableAccount(context.Context, Mutation) error
	RevokeSession(context.Context, Mutation) error
	Audit(context.Context, AuditQuery) ([]RedactedAuditEvent, error)
}

type Commands struct {
	repository Repository
	clock      func() time.Time
}

func NewCommands(repository Repository, clock func() time.Time) (*Commands, error) {
	if repository == nil {
		return nil, errors.New("restricted command repository is required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Commands{repository: repository, clock: clock}, nil
}

func (c *Commands) DisableAccount(ctx context.Context, operator string, userID uuid.UUID) error {
	mutation, err := c.userMutation(operator, userID)
	if err != nil {
		return err
	}
	return mapRepositoryError(c.repository.DisableAccount(ctx, mutation))
}

func (c *Commands) EnableAccount(ctx context.Context, operator string, userID uuid.UUID) error {
	mutation, err := c.userMutation(operator, userID)
	if err != nil {
		return err
	}
	return mapRepositoryError(c.repository.EnableAccount(ctx, mutation))
}

func (c *Commands) RevokeSession(ctx context.Context, operator string, sessionID uuid.UUID) error {
	operator, ok := normalizeOperator(operator)
	if c == nil || !ok || sessionID == uuid.Nil {
		return ErrInvalidCommand
	}
	auditEventID, err := uuid.NewRandom()
	if err != nil {
		return ErrUnavailable
	}
	return mapRepositoryError(c.repository.RevokeSession(ctx, Mutation{
		Operator: operator, SessionID: sessionID, AuditEventID: auditEventID, OccurredAt: c.clock().UTC(),
	}))
}

func (c *Commands) Audit(
	ctx context.Context,
	operator string,
	userID uuid.UUID,
	limit int,
) ([]RedactedAuditEvent, error) {
	operator, ok := normalizeOperator(operator)
	if c == nil || !ok || userID == uuid.Nil || limit < 1 || limit > 200 {
		return nil, ErrInvalidCommand
	}
	auditEventID, err := uuid.NewRandom()
	if err != nil {
		return nil, ErrUnavailable
	}
	events, err := c.repository.Audit(ctx, AuditQuery{
		Operator: operator, TargetUserID: userID, Limit: limit,
		AuditEventID: auditEventID, OccurredAt: c.clock().UTC(),
	})
	if err != nil {
		return nil, mapRepositoryError(err)
	}
	return events, nil
}

func (c *Commands) userMutation(operator string, userID uuid.UUID) (Mutation, error) {
	operator, ok := normalizeOperator(operator)
	if c == nil || !ok || userID == uuid.Nil {
		return Mutation{}, ErrInvalidCommand
	}
	auditEventID, err := uuid.NewRandom()
	if err != nil {
		return Mutation{}, ErrUnavailable
	}
	return Mutation{
		Operator: operator, TargetUserID: userID,
		AuditEventID: auditEventID, OccurredAt: c.clock().UTC(),
	}, nil
}

func normalizeOperator(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 128 {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return value, true
}

func mapRepositoryError(err error) error {
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidCommand) {
		return err
	}
	return ErrUnavailable
}
