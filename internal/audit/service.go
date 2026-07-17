package audit

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

var (
	ErrInvalidEvent = errors.New("audit event is invalid")
	namePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	requestPattern  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

type Event struct {
	ID          uuid.UUID
	EventType   string
	ActorUserID *uuid.UUID
	DeviceID    *uuid.UUID
	ObjectType  string
	ObjectID    *uuid.UUID
	Outcome     Outcome
	ReasonCode  string
	RequestID   string
	IPHMAC      []byte
	OccurredAt  time.Time
}

type Recorder interface {
	Record(context.Context, Event) error
}

type auditExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type PostgresRecorder struct {
	executor auditExecutor
	clock    func() time.Time
}

func NewPostgresRecorder(postgres *pgxpool.Pool) (*PostgresRecorder, error) {
	if postgres == nil {
		return nil, errors.New("audit PostgreSQL pool is required")
	}
	return &PostgresRecorder{executor: postgres, clock: time.Now}, nil
}

func (r *PostgresRecorder) Record(ctx context.Context, event Event) error {
	if r == nil || r.executor == nil || !validEvent(event) {
		return ErrInvalidEvent
	}
	if event.ID == uuid.Nil {
		generated, err := uuid.NewRandom()
		if err != nil {
			return errors.New("audit event identifier could not be generated")
		}
		event.ID = generated
	}
	if event.OccurredAt.IsZero() {
		clock := r.clock
		if clock == nil {
			clock = time.Now
		}
		event.OccurredAt = clock().UTC()
	}

	_, err := r.executor.Exec(ctx, `
		INSERT INTO audit_events (
			id, event_type, actor_user_id, device_id, object_type, object_id,
			outcome, reason_code, request_id, ip_hmac, metadata, created_at
		) VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10, $11::jsonb, $12)
	`,
		event.ID,
		event.EventType,
		event.ActorUserID,
		event.DeviceID,
		event.ObjectType,
		event.ObjectID,
		event.Outcome,
		event.ReasonCode,
		event.RequestID,
		nilIfEmpty(event.IPHMAC),
		"{}",
		event.OccurredAt.UTC(),
	)
	if err != nil {
		return errors.New("audit event could not be recorded")
	}
	return nil
}

func validEvent(event Event) bool {
	if !namePattern.MatchString(event.EventType) ||
		(event.Outcome != OutcomeSuccess && event.Outcome != OutcomeFailure && event.Outcome != OutcomeDenied) ||
		(event.ReasonCode != "" && !namePattern.MatchString(event.ReasonCode)) ||
		(event.ObjectType != "" && !namePattern.MatchString(event.ObjectType)) ||
		(event.RequestID != "" && !requestPattern.MatchString(event.RequestID)) ||
		(len(event.IPHMAC) != 0 && len(event.IPHMAC) != 32) {
		return false
	}
	if event.ActorUserID != nil && *event.ActorUserID == uuid.Nil {
		return false
	}
	if event.DeviceID != nil && *event.DeviceID == uuid.Nil {
		return false
	}
	if event.ObjectID != nil && *event.ObjectID == uuid.Nil {
		return false
	}
	return true
}

func nilIfEmpty(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return value
}
