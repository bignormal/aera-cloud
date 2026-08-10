package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/desktopcontrol"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type DesktopControlAdminService interface {
	ListInstances(context.Context, desktopcontrol.InstanceFilter) (desktopcontrol.InstancePage, error)
	ListUserInstances(context.Context, uuid.UUID, desktopcontrol.InstanceFilter) (desktopcontrol.InstancePage, error)
	GetInstance(context.Context, uuid.UUID) (desktopcontrol.Instance, error)
	QueueHealthCheck(context.Context, desktopcontrol.AdminActor, uuid.UUID, string) (desktopcontrol.Command, error)
	GetCommand(context.Context, uuid.UUID) (desktopcontrol.Command, error)
}

type desktopInstanceResponse struct {
	DeviceID        uuid.UUID                      `json:"device_id"`
	UserID          uuid.UUID                      `json:"user_id"`
	OrganizationID  *uuid.UUID                     `json:"organization_id,omitempty"`
	WorkspaceID     *uuid.UUID                     `json:"workspace_id,omitempty"`
	DisplayName     string                         `json:"display_name"`
	ClientVersion   string                         `json:"client_version"`
	Platform        string                         `json:"platform"`
	Arch            string                         `json:"arch"`
	Capabilities    []string                       `json:"capabilities"`
	LastHeartbeatAt *time.Time                     `json:"last_heartbeat_at,omitempty"`
	EffectiveStatus desktopcontrol.EffectiveStatus `json:"effective_status"`
	HealthStatus    desktopcontrol.HealthStatus    `json:"health_status"`
	HealthSummary   *desktopcontrol.HealthSummary  `json:"health_summary,omitempty"`
	CreatedAt       time.Time                      `json:"created_at"`
	UpdatedAt       time.Time                      `json:"updated_at"`
	ServerTime      time.Time                      `json:"server_time,omitempty"`
}

type desktopInstancePageResponse struct {
	Items      []desktopInstanceResponse `json:"items"`
	Total      int                       `json:"total"`
	ServerTime time.Time                 `json:"server_time"`
}

type desktopCommandAdminResponse struct {
	CommandID          uuid.UUID                     `json:"command_id"`
	DeviceID           uuid.UUID                     `json:"device_id"`
	Type               string                        `json:"type"`
	RequiredCapability string                        `json:"required_capability"`
	State              desktopcontrol.CommandState   `json:"state"`
	ExpiresAt          time.Time                     `json:"expires_at"`
	ClaimedAt          *time.Time                    `json:"claimed_at,omitempty"`
	StartedAt          *time.Time                    `json:"started_at,omitempty"`
	CompletedAt        *time.Time                    `json:"completed_at,omitempty"`
	ResultCode         *desktopcontrol.HealthCode    `json:"result_code,omitempty"`
	ResultSummary      *desktopcontrol.HealthSummary `json:"result_summary,omitempty"`
	CreatedByAdminID   uuid.UUID                     `json:"created_by_admin_id"`
	RequestID          string                        `json:"request_id"`
	CreatedAt          time.Time                     `json:"created_at"`
	UpdatedAt          time.Time                     `json:"updated_at"`
	Replayed           bool                          `json:"replayed,omitempty"`
	ServerTime         time.Time                     `json:"server_time"`
}

func registerDesktopControlRoutes(router chi.Router, auth *Authenticator, handler *handler) {
	router.Group(func(read chi.Router) {
		read.Use(auth.RequireScope(ScopeDesktopControlRead))
		read.Get("/desktop-control/instances", handler.listDesktopControlInstances)
		read.Get("/users/{userID}/desktop-control/instances", handler.listUserDesktopControlInstances)
		read.Get("/desktop-control/instances/{deviceID}", handler.getDesktopControlInstance)
		read.Get("/desktop-control/commands/{commandID}", handler.getDesktopControlCommand)
	})
	router.Group(func(command chi.Router) {
		command.Use(auth.RequireScope(ScopeDesktopControlCommand))
		command.Post("/desktop-control/instances/{deviceID}/health-check", handler.createDesktopHealthCheck)
	})
}

func (h *handler) listDesktopControlInstances(response http.ResponseWriter, request *http.Request) {
	filter, ok := parseDesktopInstanceFilter(request.URL, true)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	page, err := h.desktopControl.ListInstances(request.Context(), filter)
	if err != nil {
		writeDesktopControlDomainError(response, request, err, "DESKTOP_INSTANCE_NOT_FOUND")
		return
	}
	writeJSON(response, http.StatusOK, mapDesktopInstancePage(page, h.clock().UTC()))
}

func (h *handler) listUserDesktopControlInstances(response http.ResponseWriter, request *http.Request) {
	userID, ok := parsePathUUID(request, "userID")
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	filter, ok := parseDesktopInstanceFilter(request.URL, false)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	page, err := h.desktopControl.ListUserInstances(request.Context(), userID, filter)
	if err != nil {
		writeDesktopControlDomainError(response, request, err, "DESKTOP_INSTANCE_NOT_FOUND")
		return
	}
	writeJSON(response, http.StatusOK, mapDesktopInstancePage(page, h.clock().UTC()))
}

func (h *handler) getDesktopControlInstance(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	deviceID, ok := parsePathUUID(request, "deviceID")
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	instance, err := h.desktopControl.GetInstance(request.Context(), deviceID)
	if err != nil {
		writeDesktopControlDomainError(response, request, err, "DESKTOP_INSTANCE_NOT_FOUND")
		return
	}
	mapped := mapDesktopInstance(instance)
	mapped.ServerTime = h.clock().UTC()
	writeJSON(response, http.StatusOK, mapped)
}

func (h *handler) createDesktopHealthCheck(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	deviceID, ok := parsePathUUID(request, "deviceID")
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	idempotencyKey, ok := parseDesktopIdempotencyKey(request)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	var empty struct{}
	if err := decodeBoundedJSON(response, request, &empty); err != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	verified, ok := OfficialActorFromContext(request.Context())
	serviceSubject, subjectOK := admin.ServiceSubject(request.Context())
	requestID := requestIDFromContext(request.Context())
	if !ok || !subjectOK || requestID == "" {
		writeErrorResponse(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		return
	}
	command, err := h.desktopControl.QueueHealthCheck(request.Context(), desktopcontrol.AdminActor{
		AdminID: verified.AdminID, ServiceSubject: serviceSubject, RequestID: requestID,
	}, deviceID, idempotencyKey)
	if err != nil {
		writeDesktopControlDomainError(response, request, err, "DESKTOP_INSTANCE_NOT_FOUND")
		return
	}
	writeJSON(response, http.StatusOK, mapDesktopCommand(command, h.clock().UTC()))
}

func (h *handler) getDesktopControlCommand(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	commandID, ok := parsePathUUID(request, "commandID")
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	command, err := h.desktopControl.GetCommand(request.Context(), commandID)
	if err != nil {
		writeDesktopControlDomainError(response, request, err, "DESKTOP_COMMAND_NOT_FOUND")
		return
	}
	writeJSON(response, http.StatusOK, mapDesktopCommand(command, h.clock().UTC()))
}

func parseDesktopInstanceFilter(location *url.URL, allowIdentityFilters bool) (desktopcontrol.InstanceFilter, bool) {
	allowed := map[string]struct{}{"limit": {}, "offset": {}}
	if allowIdentityFilters {
		for _, key := range []string{"device_id", "user_id", "organization_id", "platform", "client_version", "effective_status"} {
			allowed[key] = struct{}{}
		}
	}
	values, ok := parseQuery(location, allowed)
	if !ok {
		return desktopcontrol.InstanceFilter{}, false
	}
	filter := desktopcontrol.InstanceFilter{Limit: 50}
	if raw := singleValue(values, "limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			return desktopcontrol.InstanceFilter{}, false
		}
		filter.Limit = value
	} else if _, present := values["limit"]; present {
		return desktopcontrol.InstanceFilter{}, false
	}
	if raw := singleValue(values, "offset"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 || value > 1_000_000 {
			return desktopcontrol.InstanceFilter{}, false
		}
		filter.Offset = value
	} else if _, present := values["offset"]; present {
		return desktopcontrol.InstanceFilter{}, false
	}
	if !allowIdentityFilters {
		return filter, true
	}
	for key, target := range map[string]**uuid.UUID{
		"device_id": &filter.DeviceID, "user_id": &filter.UserID, "organization_id": &filter.OrganizationID,
	} {
		if raw := singleValue(values, key); raw != "" {
			parsed, err := uuid.Parse(raw)
			if err != nil || parsed == uuid.Nil || parsed.String() != raw {
				return desktopcontrol.InstanceFilter{}, false
			}
			*target = &parsed
		} else if _, present := values[key]; present {
			return desktopcontrol.InstanceFilter{}, false
		}
	}
	filter.Platform = singleValue(values, "platform")
	if filter.Platform != "" && filter.Platform != "darwin" && filter.Platform != "windows" && filter.Platform != "linux" {
		return desktopcontrol.InstanceFilter{}, false
	}
	filter.ClientVersion = singleValue(values, "client_version")
	if strings.TrimSpace(filter.ClientVersion) != filter.ClientVersion || len(filter.ClientVersion) > 64 {
		return desktopcontrol.InstanceFilter{}, false
	}
	if raw := singleValue(values, "effective_status"); raw != "" {
		status := desktopcontrol.EffectiveStatus(raw)
		switch status {
		case desktopcontrol.EffectivePending, desktopcontrol.EffectiveRevoked, desktopcontrol.EffectiveDisabled,
			desktopcontrol.EffectiveOnline, desktopcontrol.EffectiveOffline:
			filter.EffectiveStatus = &status
		default:
			return desktopcontrol.InstanceFilter{}, false
		}
	} else if _, present := values["effective_status"]; present {
		return desktopcontrol.InstanceFilter{}, false
	}
	return filter, true
}

func parseDesktopIdempotencyKey(request *http.Request) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	returnValue := ""
	if len(values) == 1 && safeRequestIDPattern.MatchString(values[0]) {
		returnValue = values[0]
	}
	return returnValue, returnValue != ""
}

func mapDesktopInstancePage(page desktopcontrol.InstancePage, fallback time.Time) desktopInstancePageResponse {
	serverTime := page.ServerTime
	if serverTime.IsZero() {
		serverTime = fallback
	}
	items := make([]desktopInstanceResponse, len(page.Items))
	for index := range page.Items {
		items[index] = mapDesktopInstance(page.Items[index])
	}
	return desktopInstancePageResponse{Items: items, Total: page.Total, ServerTime: serverTime}
}

func mapDesktopInstance(instance desktopcontrol.Instance) desktopInstanceResponse {
	return desktopInstanceResponse{
		DeviceID: instance.DeviceID, UserID: instance.UserID,
		OrganizationID: instance.OrganizationID, WorkspaceID: instance.WorkspaceID,
		DisplayName: instance.DisplayName, ClientVersion: instance.ClientVersion,
		Platform: instance.Platform, Arch: instance.Arch, Capabilities: instance.Capabilities,
		LastHeartbeatAt: instance.LastHeartbeatAt, EffectiveStatus: instance.EffectiveStatusValue,
		HealthStatus: instance.HealthStatus, HealthSummary: instance.HealthSummary,
		CreatedAt: instance.CreatedAt, UpdatedAt: instance.UpdatedAt,
	}
}

func mapDesktopCommand(command desktopcontrol.Command, serverTime time.Time) desktopCommandAdminResponse {
	return desktopCommandAdminResponse{
		CommandID: command.ID, DeviceID: command.DeviceID, Type: command.Type,
		RequiredCapability: command.RequiredCapability, State: command.State, ExpiresAt: command.ExpiresAt,
		ClaimedAt: command.ClaimedAt, StartedAt: command.StartedAt, CompletedAt: command.CompletedAt,
		ResultCode: command.ResultCode, ResultSummary: command.ResultSummary,
		CreatedByAdminID: command.CreatedByAdminID, RequestID: command.RequestID,
		CreatedAt: command.CreatedAt, UpdatedAt: command.UpdatedAt, Replayed: command.Replayed,
		ServerTime: serverTime,
	}
}

func writeDesktopControlDomainError(response http.ResponseWriter, request *http.Request, err error, notFoundCode string) {
	status, code := http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	switch {
	case errors.Is(err, desktopcontrol.ErrInvalidInput):
		status, code = http.StatusBadRequest, "INVALID_REQUEST"
	case errors.Is(err, desktopcontrol.ErrNotFound):
		status, code = http.StatusNotFound, notFoundCode
	case errors.Is(err, desktopcontrol.ErrConflict), errors.Is(err, desktopcontrol.ErrInvalidTransition):
		status, code = http.StatusConflict, "DESKTOP_CONTROL_CONFLICT"
	}
	writeErrorResponse(response, request, status, code)
}
