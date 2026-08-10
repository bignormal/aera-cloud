package device

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/bignormal/aera-cloud/internal/desktopcontrol"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type DesktopControlHTTPService interface {
	Heartbeat(context.Context, desktopcontrol.DevicePrincipal, desktopcontrol.Heartbeat) (desktopcontrol.HeartbeatReceipt, error)
	SubmitResult(context.Context, desktopcontrol.DevicePrincipal, uuid.UUID, desktopcontrol.CommandResult) (desktopcontrol.Command, error)
}

type DesktopControlRequestLimiter interface {
	Allow(context.Context, desktopcontrol.LimitAction, desktopcontrol.DevicePrincipal) (time.Duration, error)
}

type desktopHeartbeatResponse struct {
	InstanceID           uuid.UUID                      `json:"instance_id"`
	AcceptedAt           time.Time                      `json:"accepted_at"`
	NextHeartbeatSeconds int                            `json:"next_heartbeat_seconds"`
	EffectiveStatus      desktopcontrol.EffectiveStatus `json:"effective_status"`
	ServerTime           time.Time                      `json:"server_time"`
	Command              *desktopCommandResponse        `json:"command,omitempty"`
}

type desktopCommandResponse struct {
	CommandID   uuid.UUID                     `json:"command_id"`
	Type        string                        `json:"type"`
	State       desktopcontrol.CommandState   `json:"state"`
	ExpiresAt   time.Time                     `json:"expires_at"`
	ClaimedAt   *time.Time                    `json:"claimed_at,omitempty"`
	StartedAt   *time.Time                    `json:"started_at,omitempty"`
	CompletedAt *time.Time                    `json:"completed_at,omitempty"`
	Code        *desktopcontrol.HealthCode    `json:"code,omitempty"`
	Summary     *desktopcontrol.HealthSummary `json:"summary,omitempty"`
	Replayed    bool                          `json:"replayed,omitempty"`
}

func (h *httpHandler) desktopHeartbeat(response http.ResponseWriter, request *http.Request) {
	if h.desktopControl == nil {
		writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	principal, ok := h.authorize(response, request, false, true)
	if !ok {
		return
	}
	desktopPrincipal := desktopcontrol.DevicePrincipal{UserID: principal.userID, DeviceID: principal.deviceID}
	if !h.allowDesktopControl(response, request, desktopcontrol.LimitHeartbeat, desktopPrincipal) {
		return
	}
	var heartbeat desktopcontrol.Heartbeat
	if !decodeDeviceJSON(response, request, &heartbeat) {
		writeDeviceError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	receipt, err := h.desktopControl.Heartbeat(request.Context(), desktopPrincipal, heartbeat)
	if err != nil {
		writeDesktopControlError(response, err)
		return
	}
	payload := desktopHeartbeatResponse{
		InstanceID: receipt.Instance.DeviceID, AcceptedAt: receipt.AcceptedAt,
		NextHeartbeatSeconds: receipt.NextHeartbeatSeconds,
		EffectiveStatus:      receipt.Instance.EffectiveStatusValue, ServerTime: receipt.ServerTime,
	}
	if receipt.Command != nil {
		command := publicDesktopCommand(*receipt.Command)
		payload.Command = &command
	}
	writeDeviceJSON(response, http.StatusOK, payload)
}

func (h *httpHandler) desktopCommandResult(response http.ResponseWriter, request *http.Request) {
	if h.desktopControl == nil {
		writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	principal, ok := h.authorize(response, request, false, true)
	if !ok {
		return
	}
	desktopPrincipal := desktopcontrol.DevicePrincipal{UserID: principal.userID, DeviceID: principal.deviceID}
	if !h.allowDesktopControl(response, request, desktopcontrol.LimitCommandResult, desktopPrincipal) {
		return
	}
	commandID, err := uuid.Parse(chi.URLParam(request, "commandID"))
	if err != nil {
		writeDeviceError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	var result desktopcontrol.CommandResult
	if !decodeDeviceJSON(response, request, &result) {
		writeDeviceError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	command, err := h.desktopControl.SubmitResult(request.Context(), desktopPrincipal, commandID, result)
	if err != nil {
		writeDesktopControlError(response, err)
		return
	}
	writeDeviceJSON(response, http.StatusOK, publicDesktopCommand(command))
}

func (h *httpHandler) allowDesktopControl(response http.ResponseWriter, request *http.Request, action desktopcontrol.LimitAction, principal desktopcontrol.DevicePrincipal) bool {
	if h.desktopControlLimiter == nil {
		return true
	}
	retryAfter, err := h.desktopControlLimiter.Allow(request.Context(), action, principal)
	if err == nil {
		return true
	}
	if errors.Is(err, desktopcontrol.ErrRateLimited) {
		seconds := int64((retryAfter + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		response.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeDeviceError(response, http.StatusTooManyRequests, "rate_limited")
		return false
	}
	writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
	return false
}

func publicDesktopCommand(command desktopcontrol.Command) desktopCommandResponse {
	return desktopCommandResponse{
		CommandID: command.ID, Type: command.Type, State: command.State, ExpiresAt: command.ExpiresAt,
		ClaimedAt: command.ClaimedAt, StartedAt: command.StartedAt, CompletedAt: command.CompletedAt,
		Code: command.ResultCode, Summary: command.ResultSummary, Replayed: command.Replayed,
	}
}

func writeDesktopControlError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, desktopcontrol.ErrInvalidInput):
		writeDeviceError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, desktopcontrol.ErrNotFound):
		writeDeviceError(response, http.StatusNotFound, "desktop_command_not_found")
	case errors.Is(err, desktopcontrol.ErrConflict), errors.Is(err, desktopcontrol.ErrInvalidTransition):
		writeDeviceError(response, http.StatusConflict, "desktop_command_conflict")
	default:
		writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
	}
}
