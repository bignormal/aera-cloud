package workspace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrInvalidRequest            = errors.New("workspace request is invalid")
	ErrSessionRevoked            = errors.New("workspace session is revoked")
	ErrWorkspaceForbidden        = errors.New("workspace operation is forbidden")
	ErrWorkspaceNotFound         = errors.New("workspace was not found")
	ErrInvitationUnavailable     = errors.New("workspace invitation is unavailable")
	ErrWorkspaceConflict         = errors.New("workspace revision conflict")
	ErrWorkspaceArchived         = errors.New("workspace is archived")
	ErrWorkspaceOwnerUnavailable = errors.New("workspace owner is unavailable")
	ErrMembershipConflict        = errors.New("workspace membership conflict")
	ErrWorkspaceLimitReached     = errors.New("workspace limit reached")
	ErrMemberLimitReached        = errors.New("workspace member limit reached")
	ErrInvitationLimitReached    = errors.New("workspace invitation limit reached")
	ErrIdempotencyConflict       = errors.New("workspace idempotency conflict")
	ErrRateLimited               = errors.New("workspace rate limit exceeded")
	ErrServiceUnavailable        = errors.New("workspace service is unavailable")
)

type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

type WorkspaceStatus string

const (
	WorkspaceStatusActive   WorkspaceStatus = "active"
	WorkspaceStatusArchived WorkspaceStatus = "archived"
)

type MutationState string

const (
	MutationStateWritable         MutationState = "writable"
	MutationStateArchived         MutationState = "archived"
	MutationStateOwnerUnavailable MutationState = "owner_unavailable"
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

type Workspace struct {
	ID            uuid.UUID
	DisplayName   string
	Status        WorkspaceStatus
	Revision      int64
	MutationState MutationState
	ActorRole     Role
	MemberCount   int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ArchivedAt    *time.Time
}

func NormalizeDisplayName(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: display name is not valid UTF-8", ErrInvalidRequest)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("%w: display name contains a control character", ErrInvalidRequest)
		}
	}
	normalized := strings.TrimSpace(value)
	count := utf8.RuneCountInString(normalized)
	if count < 1 || count > 80 {
		return "", fmt.Errorf("%w: display name must contain 1 through 80 Unicode scalars", ErrInvalidRequest)
	}
	return normalized, nil
}

func ParseRole(value string) (Role, error) {
	role := Role(value)
	switch role {
	case RoleOwner, RoleAdmin, RoleMember:
		return role, nil
	default:
		return "", fmt.Errorf("%w: unknown workspace role", ErrInvalidRequest)
	}
}

func ParseWorkspaceStatus(value string) (WorkspaceStatus, error) {
	status := WorkspaceStatus(value)
	switch status {
	case WorkspaceStatusActive, WorkspaceStatusArchived:
		return status, nil
	default:
		return "", fmt.Errorf("%w: unknown workspace status", ErrInvalidRequest)
	}
}

func ParseMutationState(value string) (MutationState, error) {
	state := MutationState(value)
	switch state {
	case MutationStateWritable, MutationStateArchived, MutationStateOwnerUnavailable:
		return state, nil
	default:
		return "", fmt.Errorf("%w: unknown workspace mutation state", ErrInvalidRequest)
	}
}

func ValidateRevision(value int64) error {
	if value <= 0 {
		return fmt.Errorf("%w: revision must be positive", ErrInvalidRequest)
	}
	return nil
}

func NormalizeWorkspace(value Workspace) (Workspace, error) {
	if value.ID == uuid.Nil {
		return Workspace{}, fmt.Errorf("%w: workspace ID is required", ErrInvalidRequest)
	}
	displayName, err := NormalizeDisplayName(value.DisplayName)
	if err != nil {
		return Workspace{}, err
	}
	if _, err := ParseWorkspaceStatus(string(value.Status)); err != nil {
		return Workspace{}, err
	}
	if err := ValidateRevision(value.Revision); err != nil {
		return Workspace{}, err
	}
	if _, err := ParseMutationState(string(value.MutationState)); err != nil {
		return Workspace{}, err
	}
	if _, err := ParseRole(string(value.ActorRole)); err != nil {
		return Workspace{}, err
	}
	if value.MemberCount <= 0 || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return Workspace{}, fmt.Errorf("%w: workspace metadata is invalid", ErrInvalidRequest)
	}

	switch value.Status {
	case WorkspaceStatusActive:
		if value.ArchivedAt != nil || (value.MutationState != MutationStateWritable && value.MutationState != MutationStateOwnerUnavailable) {
			return Workspace{}, fmt.Errorf("%w: active workspace lifecycle is inconsistent", ErrInvalidRequest)
		}
	case WorkspaceStatusArchived:
		if value.ArchivedAt == nil || value.MutationState != MutationStateArchived {
			return Workspace{}, fmt.Errorf("%w: archived workspace lifecycle is inconsistent", ErrInvalidRequest)
		}
	}

	value.DisplayName = displayName
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	if value.ArchivedAt != nil {
		archivedAt := value.ArchivedAt.UTC()
		value.ArchivedAt = &archivedAt
	}
	return value, nil
}

type LimitAction string

const (
	LimitWorkspaceCreate  LimitAction = "workspace_create"
	LimitInvitationCreate LimitAction = "invitation_create"
	LimitInvitationAccept LimitAction = "invitation_accept"
)

type Limiter interface {
	Allow(context.Context, LimitAction, Actor, *uuid.UUID) (time.Duration, error)
}
