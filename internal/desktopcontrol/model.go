package desktopcontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	CapabilityHealthRead = "diagnostics.health.read"
	CommandHealthCheck   = "health_check"
)

type CommandState string

const (
	CommandQueued    CommandState = "queued"
	CommandClaimed   CommandState = "claimed"
	CommandRunning   CommandState = "running"
	CommandSucceeded CommandState = "succeeded"
	CommandFailed    CommandState = "failed"
	CommandExpired   CommandState = "expired"
)

type HealthStatus string

const (
	HealthUnknown   HealthStatus = "unknown"
	HealthHealthy   HealthStatus = "healthy"
	HealthDegraded  HealthStatus = "degraded"
	HealthUnhealthy HealthStatus = "unhealthy"
)

type HealthCode string

const (
	HealthCodeHealthy            HealthCode = "HEALTHY"
	HealthCodeDesktopUnhealthy   HealthCode = "DESKTOP_UNHEALTHY"
	HealthCodeRuntimeUnavailable HealthCode = "RUNTIME_UNAVAILABLE"
	HealthCodeGatewayUnavailable HealthCode = "GATEWAY_UNAVAILABLE"
	HealthCodeTimeout            HealthCode = "HEALTH_CHECK_TIMEOUT"
	HealthCodeClientInterrupted  HealthCode = "CLIENT_INTERRUPTED"
)

type EffectiveStatus string

const (
	EffectivePending  EffectiveStatus = "pending"
	EffectiveRevoked  EffectiveStatus = "revoked"
	EffectiveDisabled EffectiveStatus = "disabled"
	EffectiveOnline   EffectiveStatus = "online"
	EffectiveOffline  EffectiveStatus = "offline"
)

var (
	ErrInvalidInput      = errors.New("desktop control invalid input")
	ErrNotFound          = errors.New("desktop control not found")
	ErrConflict          = errors.New("desktop control conflict")
	ErrInvalidTransition = errors.New("desktop control invalid transition")
	ErrUnavailable       = errors.New("desktop control unavailable")
)

type DevicePrincipal struct {
	UserID         uuid.UUID
	DeviceID       uuid.UUID
	OrganizationID *uuid.UUID
	WorkspaceID    *uuid.UUID
}

type HealthSummary struct {
	DesktopStatus string     `json:"desktop_status"`
	RuntimeStatus string     `json:"runtime_status"`
	GatewayStatus string     `json:"gateway_status"`
	Code          HealthCode `json:"code"`
	DurationMS    int64      `json:"duration_ms"`
}

type Heartbeat struct {
	DisplayName   string         `json:"display_name"`
	ClientVersion string         `json:"client_version"`
	Platform      string         `json:"platform"`
	Arch          string         `json:"arch"`
	Capabilities  []string       `json:"capabilities"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	Health        *HealthSummary `json:"health,omitempty"`
}

type Instance struct {
	DeviceID             uuid.UUID
	UserID               uuid.UUID
	OrganizationID       *uuid.UUID
	WorkspaceID          *uuid.UUID
	DisplayName          string
	ClientVersion        string
	Platform             string
	Arch                 string
	Capabilities         []string
	LastHeartbeatAt      *time.Time
	HealthStatus         HealthStatus
	HealthSummary        *HealthSummary
	CreatedAt            time.Time
	UpdatedAt            time.Time
	UserStatus           string
	DeviceStatus         string
	EffectiveStatusValue EffectiveStatus `json:"effective_status,omitempty"`
}

func (instance Instance) EffectiveStatus(now time.Time) EffectiveStatus {
	switch instance.UserStatus {
	case "disabled":
		return EffectiveDisabled
	case "pending_deletion":
		return EffectivePending
	}
	switch instance.DeviceStatus {
	case "revoked":
		return EffectiveRevoked
	case "inactive":
		return EffectivePending
	}
	if instance.LastHeartbeatAt == nil || now.Sub(instance.LastHeartbeatAt.UTC()) > 150*time.Second {
		return EffectiveOffline
	}
	return EffectiveOnline
}

type AdminActor struct {
	AdminID        uuid.UUID
	ServiceSubject string
	RequestID      string
}

type QueueHealthCheckCommand struct {
	DeviceID           uuid.UUID
	IdempotencyKeyHash []byte
	Actor              AdminActor
}

type CommandResult struct {
	State   CommandState   `json:"state"`
	Code    HealthCode     `json:"code,omitempty"`
	Summary *HealthSummary `json:"summary,omitempty"`
}

type Command struct {
	ID                 uuid.UUID
	DeviceID           uuid.UUID
	Type               string
	RequiredCapability string
	IdempotencyKeyHash []byte
	State              CommandState
	ExpiresAt          time.Time
	ClaimedAt          *time.Time
	StartedAt          *time.Time
	CompletedAt        *time.Time
	ResultCode         *HealthCode
	ResultSummary      *HealthSummary
	CreatedByAdminID   uuid.UUID
	RequestID          string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	Replayed           bool
}

type InstanceFilter struct {
	DeviceID        *uuid.UUID
	UserID          *uuid.UUID
	OrganizationID  *uuid.UUID
	Platform        string
	ClientVersion   string
	EffectiveStatus *EffectiveStatus
	Limit           int
	Offset          int
}

type InstancePage struct {
	Items      []Instance
	Total      int
	ServerTime time.Time
}

func CanTransition(from, to CommandState) bool {
	switch from {
	case CommandQueued:
		return to == CommandClaimed || to == CommandExpired
	case CommandClaimed:
		return to == CommandRunning || to == CommandExpired
	case CommandRunning:
		return to == CommandSucceeded || to == CommandFailed || to == CommandExpired
	default:
		return false
	}
}

func validatePrincipal(value DevicePrincipal) error {
	if value.UserID == uuid.Nil || value.DeviceID == uuid.Nil {
		return ErrInvalidInput
	}
	return nil
}

func validateHeartbeat(value Heartbeat) error {
	if !boundedText(value.DisplayName, 100) || !boundedText(value.ClientVersion, 64) ||
		value.UptimeSeconds < 0 || value.UptimeSeconds > 7*24*60*60 || len(value.Capabilities) > 8 {
		return ErrInvalidInput
	}
	if value.Platform != "darwin" && value.Platform != "windows" && value.Platform != "linux" {
		return ErrInvalidInput
	}
	if value.Arch != "arm64" && value.Arch != "x64" {
		return ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(value.Capabilities))
	for _, capability := range value.Capabilities {
		if capability != CapabilityHealthRead {
			return ErrInvalidInput
		}
		if _, duplicate := seen[capability]; duplicate {
			return ErrInvalidInput
		}
		seen[capability] = struct{}{}
	}
	if value.Health != nil && !validHealthSummary(*value.Health) {
		return ErrInvalidInput
	}
	return nil
}

func validateQueue(value QueueHealthCheckCommand) error {
	if value.DeviceID == uuid.Nil || value.Actor.AdminID == uuid.Nil || len(value.IdempotencyKeyHash) != 32 ||
		!serviceSubjectPattern.MatchString(value.Actor.ServiceSubject) || !boundedText(value.Actor.RequestID, 128) {
		return ErrInvalidInput
	}
	return nil
}

func validateResult(value CommandResult) error {
	switch value.State {
	case CommandRunning:
		if value.Code != "" || value.Summary != nil {
			return ErrInvalidInput
		}
	case CommandSucceeded, CommandFailed:
		if value.Summary == nil || !validHealthSummary(*value.Summary) || value.Code != value.Summary.Code {
			return ErrInvalidInput
		}
		if value.State == CommandSucceeded && value.Code != HealthCodeHealthy {
			return ErrInvalidInput
		}
		if value.State == CommandFailed && value.Code == HealthCodeHealthy {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func validHealthSummary(value HealthSummary) bool {
	if value.DurationMS < 0 || value.DurationMS > 120000 || !validHealthCode(value.Code) {
		return false
	}
	for _, status := range []string{value.DesktopStatus, value.RuntimeStatus, value.GatewayStatus} {
		if status != "unknown" && status != "healthy" && status != "degraded" && status != "unhealthy" {
			return false
		}
	}
	return true
}

func validHealthCode(value HealthCode) bool {
	switch value {
	case HealthCodeHealthy, HealthCodeDesktopUnhealthy, HealthCodeRuntimeUnavailable,
		HealthCodeGatewayUnavailable, HealthCodeTimeout, HealthCodeClientInterrupted:
		return true
	default:
		return false
	}
}

func healthStatusFor(summary *HealthSummary) HealthStatus {
	if summary == nil {
		return HealthUnknown
	}
	if summary.Code == HealthCodeHealthy {
		return HealthHealthy
	}
	if summary.Code == HealthCodeDesktopUnhealthy {
		return HealthDegraded
	}
	return HealthUnhealthy
}

var serviceSubjectPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)

func boundedText(value string, limit int) bool {
	return value == strings.TrimSpace(value) && value != "" && len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
}

func (value *Heartbeat) UnmarshalJSON(data []byte) error {
	type heartbeatWire Heartbeat
	var decoded heartbeatWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("desktop heartbeat contains multiple JSON values")
		}
		return err
	}
	*value = Heartbeat(decoded)
	return nil
}

func (value *HealthSummary) UnmarshalJSON(data []byte) error {
	type healthSummaryWire HealthSummary
	var decoded healthSummaryWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("health summary contains multiple JSON values")
		}
		return err
	}
	*value = HealthSummary(decoded)
	return nil
}

func (value *CommandResult) UnmarshalJSON(data []byte) error {
	type commandResultWire CommandResult
	var decoded commandResultWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("command result contains multiple JSON values")
		}
		return err
	}
	*value = CommandResult(decoded)
	return nil
}
