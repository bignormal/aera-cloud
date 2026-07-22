package admin

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
)

var (
	ErrInvalidCursor        = errors.New("admin cursor is invalid")
	ErrStateConflict        = errors.New("admin target state conflicts with the request")
	ErrIdempotencyKeyReused = errors.New("admin idempotency key was reused for a different request")
)

var (
	controlReasonPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	operationErrorPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,99}$`)
	serviceSubjectPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)
)

type serviceSubjectContextKey struct{}

func WithServiceSubject(ctx context.Context, subject string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, serviceSubjectContextKey{}, subject)
}

func serviceSubjectFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	subject, ok := ctx.Value(serviceSubjectContextKey{}).(string)
	return subject, ok && serviceSubjectPattern.MatchString(subject)
}

func ServiceSubject(ctx context.Context) (string, bool) {
	return serviceSubjectFromContext(ctx)
}

type Action string

const (
	RevokeDevice  Action = "revoke_device"
	RevokeSession Action = "revoke_session"
	DisableUser   Action = "disable_user"
	EnableUser    Action = "enable_user"
)

type OperationStatus string

const (
	OperationExecuting OperationStatus = "executing"
	OperationSucceeded OperationStatus = "succeeded"
	OperationFailed    OperationStatus = "failed"
	OperationConflict  OperationStatus = "conflict"
)

type UserStatus string

const (
	UserActive          UserStatus = "active"
	UserPendingDeletion UserStatus = "pending_deletion"
	UserDisabled        UserStatus = "disabled"
)

type PageRequest struct {
	Cursor string
	Limit  int
}

type ListUsersRequest struct {
	PageRequest
	Status UserStatus
}

type LookupRequest struct {
	Kind  secure.IdentityKind `json:"type"`
	Value string              `json:"value"`
}

type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type User struct {
	ID                       uuid.UUID  `json:"user_id"`
	MaskedEmail              string     `json:"masked_email,omitempty"`
	MaskedPhone              string     `json:"masked_phone,omitempty"`
	Status                   UserStatus `json:"status"`
	AdministrativelyDisabled bool       `json:"administratively_disabled"`
	DeletionFinalizedAt      *time.Time `json:"deletion_finalized_at,omitempty"`
	AdministrativeRevision   int64      `json:"administrative_revision"`
	DeviceCount              int        `json:"device_count"`
	ActiveDeviceCount        int        `json:"active_device_count"`
	ActiveSessionCount       int        `json:"active_session_count"`
	CreatedAt                time.Time  `json:"created_at"`
	LastCloudActivityAt      *time.Time `json:"last_cloud_activity_at,omitempty"`
}

type DeviceStatus string

const (
	DeviceActive   DeviceStatus = "active"
	DeviceInactive DeviceStatus = "inactive"
	DeviceRevoked  DeviceStatus = "revoked"
)

type Device struct {
	ID            uuid.UUID    `json:"device_id"`
	UserID        uuid.UUID    `json:"user_id"`
	DisplayName   string       `json:"display_name"`
	Platform      string       `json:"platform"`
	ClientVersion string       `json:"client_version"`
	Status        DeviceStatus `json:"status"`
	LastSeenAt    *time.Time   `json:"last_seen_at,omitempty"`
}

type SessionStatus string

const (
	SessionActive         SessionStatus = "active"
	SessionRotated        SessionStatus = "rotated"
	SessionExpired        SessionStatus = "expired"
	SessionRevoked        SessionStatus = "revoked"
	SessionReplayDetected SessionStatus = "replay_detected"
)

type Session struct {
	ID        uuid.UUID     `json:"session_id"`
	UserID    uuid.UUID     `json:"user_id"`
	DeviceID  uuid.UUID     `json:"device_id"`
	Status    SessionStatus `json:"status"`
	IssuedAt  time.Time     `json:"issued_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	RevokedAt *time.Time    `json:"revoked_at,omitempty"`
}

type Command struct {
	OperationID      uuid.UUID  `json:"operation_id"`
	ActorAdminID     uuid.UUID  `json:"actor_admin_id"`
	ApprovalID       *uuid.UUID `json:"approval_id,omitempty"`
	RequestID        string     `json:"request_id"`
	ReasonCode       string     `json:"reason_code"`
	TicketReference  string     `json:"ticket_reference,omitempty"`
	Note             string     `json:"note,omitempty"`
	ExpectedRevision int64      `json:"expected_revision"`
}

type Operation struct {
	ID                     uuid.UUID       `json:"operation_id"`
	Status                 OperationStatus `json:"status"`
	ErrorCode              string          `json:"error_code,omitempty"`
	AdministrativeRevision int64           `json:"administrative_revision,omitempty"`
	UpdatedAt              time.Time       `json:"updated_at"`
}

type PagePosition struct {
	Time time.Time
	ID   uuid.UUID
}

type Digest struct {
	KeyID string
	Sum   []byte
}

type Service interface {
	ListUsers(context.Context, ListUsersRequest) (Page[User], error)
	LookupUser(context.Context, LookupRequest) (User, error)
	GetUser(context.Context, uuid.UUID) (User, error)
	ListUserDevices(context.Context, uuid.UUID, PageRequest) (Page[Device], error)
	ListUserSessions(context.Context, uuid.UUID, PageRequest) (Page[Session], error)
	Execute(context.Context, Action, uuid.UUID, Command) (Operation, error)
	GetOperation(context.Context, uuid.UUID) (Operation, error)
}

func validateControlCommand(action Action, targetID uuid.UUID, command Command) error {
	if !validControlAction(action) || targetID == uuid.Nil || command.OperationID == uuid.Nil ||
		command.ActorAdminID == uuid.Nil || command.ExpectedRevision < 1 {
		return ErrInvalidCommand
	}
	if command.ApprovalID != nil && *command.ApprovalID == uuid.Nil {
		return ErrInvalidCommand
	}
	if (action == DisableUser || action == EnableUser) && command.ApprovalID == nil {
		return ErrInvalidCommand
	}
	if !validControlText(command.RequestID, 1, 128, false) ||
		!controlReasonPattern.MatchString(command.ReasonCode) ||
		!validControlText(command.TicketReference, 1, 128, true) ||
		!validControlText(command.Note, 1, 500, true) {
		return ErrInvalidCommand
	}
	return nil
}

// ValidateCommand applies the domain-level shape checks required before a
// control command may reach persistent storage.
func ValidateCommand(action Action, targetID uuid.UUID, command Command) error {
	return validateControlCommand(action, targetID, command)
}

func validateOperation(operation Operation) error {
	if operation.ID == uuid.Nil || operation.UpdatedAt.IsZero() {
		return ErrUnavailable
	}
	switch operation.Status {
	case OperationExecuting:
		if operation.ErrorCode != "" || operation.AdministrativeRevision != 0 {
			return ErrUnavailable
		}
	case OperationSucceeded:
		if operation.ErrorCode != "" || operation.AdministrativeRevision < 1 {
			return ErrUnavailable
		}
	case OperationFailed, OperationConflict:
		if !operationErrorPattern.MatchString(operation.ErrorCode) || operation.AdministrativeRevision != 0 {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}

func validControlAction(action Action) bool {
	return action == RevokeDevice || action == RevokeSession || action == DisableUser || action == EnableUser
}

func validControlText(value string, minimum, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
