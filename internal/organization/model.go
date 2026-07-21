package organization

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

var (
	ErrInvalidRequest                    = errors.New("organization request is invalid")
	ErrSessionRevoked                    = errors.New("organization session is revoked")
	ErrOrganizationForbidden             = errors.New("organization operation is forbidden")
	ErrOrganizationNotFound              = errors.New("organization was not found")
	ErrOrganizationConflict              = errors.New("organization revision conflict")
	ErrOrganizationArchived              = errors.New("organization is archived")
	ErrOrganizationLimitReached          = errors.New("organization limit reached")
	ErrOrganizationOwnerTransferRequired = errors.New("organization ownership must be transferred")
	ErrOwnerTransferTargetInvalid        = errors.New("organization owner transfer target is invalid")
	ErrMembershipConflict                = errors.New("organization membership conflict")
	ErrMemberLimitReached                = errors.New("organization member limit reached")
	ErrDepartmentNotEmpty                = errors.New("organization department is not empty")
	ErrDepartmentLimitReached            = errors.New("organization department limit reached")
	ErrInvitationUnavailable             = errors.New("organization invitation is unavailable")
	ErrInvitationLimitReached            = errors.New("organization invitation limit reached")
	ErrPolicyVersionConflict             = errors.New("organization policy version conflict")
	ErrIdempotencyConflict               = errors.New("organization idempotency conflict")
	ErrDissolutionBlocked                = errors.New("organization dissolution is blocked")
	ErrRateLimited                       = errors.New("organization rate limit exceeded")
	ErrServiceUnavailable                = errors.New("organization service is unavailable")
	ErrInvalidSignature                  = errors.New("organization policy signature is invalid")
)

type Role string

const (
	RoleOwner   Role = "owner"
	RoleAdmin   Role = "admin"
	RoleAuditor Role = "auditor"
	RoleMember  Role = "member"
)

type OrganizationStatus string

const (
	OrganizationStatusActive    OrganizationStatus = "active"
	OrganizationStatusArchived  OrganizationStatus = "archived"
	OrganizationStatusDissolved OrganizationStatus = "dissolved"
)

type DepartmentStatus string

const (
	DepartmentStatusActive   DepartmentStatus = "active"
	DepartmentStatusArchived DepartmentStatus = "archived"
)

type InvitationStatus string

const (
	InvitationStatusPending  InvitationStatus = "pending"
	InvitationStatusAccepted InvitationStatus = "accepted"
	InvitationStatusRevoked  InvitationStatus = "revoked"
	InvitationStatusExpired  InvitationStatus = "expired"
)

type MutationState string

const (
	MutationStateWritable  MutationState = "writable"
	MutationStateArchived  MutationState = "archived"
	MutationStateDissolved MutationState = "dissolved"
)

type Actor struct {
	UserID   uuid.UUID
	DeviceID uuid.UUID
}

func (a Actor) Validate() error {
	if a.UserID == uuid.Nil || a.DeviceID == uuid.Nil {
		return fmt.Errorf("%w: actor IDs are required", ErrInvalidRequest)
	}
	return nil
}

type Quotas struct {
	Owned              int
	Members            int
	Departments        int
	PendingInvitations int
}

func (q Quotas) Validate() error {
	if q.Owned <= 0 || q.Members <= 0 || q.Departments <= 0 || q.PendingInvitations <= 0 {
		return fmt.Errorf("%w: organization quotas must be positive", ErrInvalidRequest)
	}
	return nil
}

type OrganizationSummary struct {
	ID                   uuid.UUID
	DisplayName          string
	Status               OrganizationStatus
	Revision             int64
	Role                 Role
	MemberCount          int
	DepartmentCount      int
	CurrentPolicyVersion int64
	CurrentPolicyDigest  [32]byte
	MutationState        MutationState
	CreatedAt            time.Time
	UpdatedAt            time.Time
	ArchivedAt           *time.Time
}

type MemberSummary struct {
	UserID       uuid.UUID
	Nickname     *string
	Role         Role
	DepartmentID *uuid.UUID
	Revision     int64
	JoinedAt     time.Time
	UpdatedAt    time.Time
}

type DepartmentSummary struct {
	ID          uuid.UUID
	DisplayName string
	Status      DepartmentStatus
	MemberCount int
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  *time.Time
}

type InvitationSummary struct {
	ID               uuid.UUID
	Status           InvitationStatus
	CreatedByUserID  *uuid.UUID
	AcceptedByUserID *uuid.UUID
	CreatedAt        time.Time
	ExpiresAt        time.Time
	AcceptedAt       *time.Time
	RevokedAt        *time.Time
}

type PolicySummary struct {
	ID            uuid.UUID
	PolicyVersion int64
	SchemaVersion int
	ContentDigest [32]byte
	Issuer        string
	SigningKeyID  string
	CreatedAt     time.Time
}

type PolicySnapshot struct {
	PolicySummary
	Document  PolicyDocument
	Signature []byte
}

type AuditSummary struct {
	ID             uuid.UUID
	EventType      string
	ObjectType     string
	ObjectID       *uuid.UUID
	Outcome        string
	ReasonCode     string
	RequestID      string
	ActorDisplay   *string
	SubjectDisplay *string
	CreatedAt      time.Time
}

func NormalizeOrganizationName(value string) (string, error) {
	return normalizeName(value, 120, "organization")
}

func NormalizeDepartmentName(value string) (string, string, error) {
	displayName, err := normalizeName(value, 80, "department")
	if err != nil {
		return "", "", err
	}
	nameKey := norm.NFC.String(cases.Fold().String(displayName))
	return displayName, nameKey, nil
}

func normalizeName(value string, maximum int, label string) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: %s name is not valid UTF-8", ErrInvalidRequest, label)
	}
	normalized := norm.NFC.String(value)
	for _, character := range normalized {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("%w: %s name contains a control character", ErrInvalidRequest, label)
		}
	}
	normalized = strings.TrimSpace(normalized)
	count := utf8.RuneCountInString(normalized)
	if count < 1 || count > maximum {
		return "", fmt.Errorf("%w: %s name must contain 1 through %d Unicode scalars", ErrInvalidRequest, label, maximum)
	}
	return normalized, nil
}

func ParseRole(value string) (Role, error) {
	role := Role(value)
	switch role {
	case RoleOwner, RoleAdmin, RoleAuditor, RoleMember:
		return role, nil
	default:
		return "", fmt.Errorf("%w: unknown organization role", ErrInvalidRequest)
	}
}

func ParseOrganizationStatus(value string) (OrganizationStatus, error) {
	status := OrganizationStatus(value)
	switch status {
	case OrganizationStatusActive, OrganizationStatusArchived, OrganizationStatusDissolved:
		return status, nil
	default:
		return "", fmt.Errorf("%w: unknown organization status", ErrInvalidRequest)
	}
}

func ParseDepartmentStatus(value string) (DepartmentStatus, error) {
	status := DepartmentStatus(value)
	switch status {
	case DepartmentStatusActive, DepartmentStatusArchived:
		return status, nil
	default:
		return "", fmt.Errorf("%w: unknown organization department status", ErrInvalidRequest)
	}
}

func ParseInvitationStatus(value string) (InvitationStatus, error) {
	status := InvitationStatus(value)
	switch status {
	case InvitationStatusPending, InvitationStatusAccepted, InvitationStatusRevoked, InvitationStatusExpired:
		return status, nil
	default:
		return "", fmt.Errorf("%w: unknown organization invitation status", ErrInvalidRequest)
	}
}

func ParseMutationState(value string) (MutationState, error) {
	state := MutationState(value)
	switch state {
	case MutationStateWritable, MutationStateArchived, MutationStateDissolved:
		return state, nil
	default:
		return "", fmt.Errorf("%w: unknown organization mutation state", ErrInvalidRequest)
	}
}

func ValidateRevision(value int64) error {
	if value <= 0 {
		return fmt.Errorf("%w: revision must be positive", ErrInvalidRequest)
	}
	return nil
}

type LimitAction string

const (
	LimitOrganizationCreate LimitAction = "organization_create"
	LimitInvitationCreate   LimitAction = "invitation_create"
	LimitInvitationAccept   LimitAction = "invitation_accept"
	LimitMutation           LimitAction = "mutation"
	LimitHighRisk           LimitAction = "high_risk"
)

type Limiter interface {
	Allow(context.Context, LimitAction, Actor, *uuid.UUID) (time.Duration, error)
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
