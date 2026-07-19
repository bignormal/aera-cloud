package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

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
	ErrInvalidEvent   = errors.New("audit event is invalid")
	namePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	jwtPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}$`)
	agentMetadataKeys = map[string]struct{}{
		"tenant_id": {}, "owner_scope": {}, "owner_id": {},
		"agent_definition_id": {}, "agent_version_id": {},
		"agent_installation_id": {}, "policy_snapshot_id": {},
		"content_digest": {},
	}
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
	Metadata    map[string]string
	OccurredAt  time.Time
}

type Recorder interface {
	Record(context.Context, Event) error
}

type Executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type PostgresRecorder struct {
	executor Executor
	clock    func() time.Time
}

func NewPostgresRecorder(postgres *pgxpool.Pool) (*PostgresRecorder, error) {
	if postgres == nil {
		return nil, errors.New("audit PostgreSQL pool is required")
	}
	return NewRecorder(postgres)
}

func NewRecorder(executor Executor) (*PostgresRecorder, error) {
	if executor == nil {
		return nil, errors.New("audit executor is required")
	}
	return &PostgresRecorder{executor: executor, clock: time.Now}, nil
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
	metadata := event.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil {
		return ErrInvalidEvent
	}

	_, err = r.executor.Exec(ctx, `
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
		string(encodedMetadata),
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
	return validMetadata(event.EventType, event.Metadata)
}

func validMetadata(eventType string, metadata map[string]string) bool {
	if len(metadata) == 0 {
		return true
	}
	if len(metadata) > 12 || (!strings.HasPrefix(eventType, "agent_") && !strings.HasPrefix(eventType, "runtime_binding_")) {
		return false
	}
	for key, value := range metadata {
		if !namePattern.MatchString(key) {
			return false
		}
		if _, allowed := agentMetadataKeys[key]; !allowed || !safeMetadataValue(value) {
			return false
		}
		switch key {
		case "owner_scope":
			if value != "USER" {
				return false
			}
		case "content_digest":
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
				return false
			}
		default:
			if _, err := uuid.Parse(value); err != nil {
				return false
			}
		}
	}
	return true
}

func safeMetadataValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	return value == trimmed && utf8.ValidString(value) && len([]byte(value)) <= 128 && value != "" &&
		!strings.ContainsAny(value, "\r\n\x00/@\\{}[]\"") && !strings.HasPrefix(lower, "bearer ") && !jwtPattern.MatchString(value)
}

func nilIfEmpty(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return value
}
