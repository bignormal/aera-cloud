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
	RevokeDevice                  Action = "revoke_device"
	RevokeSession                 Action = "revoke_session"
	RevokeAllSessions             Action = "revoke_all_sessions"
	DisableUser                   Action = "disable_user"
	EnableUser                    Action = "enable_user"
	ForcePasswordReset            Action = "force_password_reset"
	OfficialDefinitionReserve     Action = "official_definition_reserve"
	OfficialDraftCreate           Action = "official_draft_create"
	OfficialDraftUpdate           Action = "official_draft_update"
	OfficialDraftSubmit           Action = "official_draft_submit"
	OfficialSubmissionWithdraw    Action = "official_submission_withdraw"
	OfficialSubmissionReview      Action = "official_submission_review"
	OfficialReleaseActivate       Action = "official_release_activate"
	OfficialReleaseRollout        Action = "official_release_rollout"
	OfficialReleasePause          Action = "official_release_pause"
	OfficialReleaseResume         Action = "official_release_resume"
	OfficialReleaseRollback       Action = "official_release_rollback"
	OfficialQualityProposalCreate Action = "official_quality_proposal_create"
	OfficialQualityProposalSubmit Action = "official_quality_proposal_submit"
	OfficialQualityProposalReview Action = "official_quality_proposal_review"
	OfficialQualityDraftClone     Action = "official_quality_draft_clone"
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

type OfficialOperationCommand struct {
	OperationID      uuid.UUID
	ActorAdminID     uuid.UUID
	ActorAdminRole   string
	ApprovalID       *uuid.UUID
	RequesterAdminID *uuid.UUID
	RequestID        string
	ReasonCode       string
	TicketReference  string
	ExpectedRevision int64
	PayloadDigest    []byte
}

type Operation struct {
	ID                     uuid.UUID       `json:"operation_id"`
	Status                 OperationStatus `json:"status"`
	ErrorCode              string          `json:"error_code,omitempty"`
	AdministrativeRevision int64           `json:"administrative_revision,omitempty"`
	TargetType             string          `json:"target_type,omitempty"`
	TargetID               string          `json:"target_id,omitempty"`
	UpdatedAt              time.Time       `json:"updated_at"`
}

type OfficialAuditEvent struct {
	ID             uuid.UUID `json:"event_id"`
	EventType      string    `json:"event_type"`
	ObjectType     string    `json:"object_type"`
	ObjectID       uuid.UUID `json:"object_id"`
	Outcome        string    `json:"outcome"`
	ReasonCode     string    `json:"reason_code,omitempty"`
	RequestID      string    `json:"request_id"`
	ActorAdminID   uuid.UUID `json:"actor_admin_id"`
	ActorAdminRole string    `json:"actor_admin_role"`
	CreatedAt      time.Time `json:"created_at"`
}

type OfficialAuditService interface {
	ListOfficialAuditEvents(context.Context, PageRequest) (Page[OfficialAuditEvent], error)
}

type PagePosition struct {
	Time time.Time
	ID   uuid.UUID
}

// PlatformStats aggregates account and device counters for the admin overview
// dashboard. Counts are point-in-time and carry no personal data.
type PlatformStats struct {
	UserTotal           int64 `json:"user_total"`
	UserActive          int64 `json:"user_active"`
	UserDisabled        int64 `json:"user_disabled"`
	UserPendingDeletion int64 `json:"user_pending_deletion"`
	DeviceTotal         int64 `json:"device_total"`
	DeviceActive        int64 `json:"device_active"`
}

// DeviceVersionStat is one bucket of the device version/platform distribution.
type DeviceVersionStat struct {
	Platform   string `json:"platform"`
	AppVersion string `json:"app_version"`
	Total      int64  `json:"total"`
	Active     int64  `json:"active"`
}

// DeviceStats groups the installed base by platform and app version.
type DeviceStats struct {
	Buckets []DeviceVersionStat `json:"buckets"`
}

// Membership is one organization or workspace the user belongs to. The display
// name is a team/org name, not personal data.
type Membership struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	Status      string    `json:"status"`
}

// UserMemberships lists the organizations and workspaces a user belongs to.
type UserMemberships struct {
	Organizations []Membership `json:"organizations"`
	Workspaces    []Membership `json:"workspaces"`
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
	Stats(context.Context) (PlatformStats, error)
	DeviceStats(context.Context) (DeviceStats, error)
	UserMemberships(context.Context, uuid.UUID) (UserMemberships, error)
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

func ValidateOfficialOperationCommand(
	action Action,
	targetID uuid.UUID,
	command OfficialOperationCommand,
) error {
	if !validOfficialAction(action) || targetID == uuid.Nil || command.OperationID == uuid.Nil ||
		command.ActorAdminID == uuid.Nil || command.ExpectedRevision < 1 || len(command.PayloadDigest) != 32 ||
		!validControlText(command.RequestID, 1, 128, false) ||
		!controlReasonPattern.MatchString(command.ReasonCode) ||
		!validControlText(command.TicketReference, 1, 128, true) ||
		!officialRoleAllowed(command.ActorAdminRole, action) {
		return ErrInvalidCommand
	}
	if command.ApprovalID != nil && *command.ApprovalID == uuid.Nil ||
		command.RequesterAdminID != nil && *command.RequesterAdminID == uuid.Nil {
		return ErrInvalidCommand
	}
	if action == OfficialReleaseRollback {
		if command.ApprovalID == nil || command.RequesterAdminID == nil ||
			*command.RequesterAdminID == command.ActorAdminID {
			return ErrInvalidCommand
		}
	} else if command.ApprovalID != nil || command.RequesterAdminID != nil {
		return ErrInvalidCommand
	}
	return nil
}

func validateOperation(operation Operation) error {
	if operation.ID == uuid.Nil || operation.UpdatedAt.IsZero() {
		return ErrUnavailable
	}
	if (operation.TargetType == "") != (operation.TargetID == "") {
		return ErrUnavailable
	}
	if operation.TargetType != "" {
		if _, err := uuid.Parse(operation.TargetID); err != nil || !validOperationTargetType(operation.TargetType) {
			return ErrUnavailable
		}
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

func validOperationTargetType(value string) bool {
	switch value {
	case "device", "session", "user", "platform_definition", "platform_draft",
		"platform_submission", "official_release", "official_quality_proposal":
		return true
	default:
		return false
	}
}

func validControlAction(action Action) bool {
	return action == RevokeDevice || action == RevokeSession || action == RevokeAllSessions ||
		action == DisableUser || action == EnableUser || action == ForcePasswordReset
}

func validOfficialAction(action Action) bool {
	switch action {
	case OfficialDefinitionReserve, OfficialDraftCreate, OfficialDraftUpdate,
		OfficialDraftSubmit, OfficialSubmissionWithdraw, OfficialSubmissionReview,
		OfficialReleaseActivate, OfficialReleaseRollout, OfficialReleasePause,
		OfficialReleaseResume, OfficialReleaseRollback,
		OfficialQualityProposalCreate, OfficialQualityProposalSubmit,
		OfficialQualityProposalReview, OfficialQualityDraftClone:
		return true
	default:
		return false
	}
}

func officialRoleAllowed(role string, action Action) bool {
	switch action {
	case OfficialDefinitionReserve, OfficialDraftCreate, OfficialDraftUpdate,
		OfficialDraftSubmit, OfficialSubmissionWithdraw,
		OfficialQualityProposalCreate, OfficialQualityProposalSubmit,
		OfficialQualityDraftClone:
		return role == "developer"
	case OfficialSubmissionReview, OfficialReleaseRollback, OfficialQualityProposalReview:
		return role == "super_admin"
	case OfficialReleaseActivate, OfficialReleaseRollout, OfficialReleasePause, OfficialReleaseResume:
		return role == "operator"
	default:
		return false
	}
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
