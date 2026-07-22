package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/agentcontrol"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	maximumAdminRequestBodyBytes = 32 << 10
	internalAdminHealthTimeout   = 2 * time.Second
)

var (
	safeRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	safeErrorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,99}$`)
	requestIDSequence    atomic.Uint64
)

type requestIDContextKey struct{}

type HealthChecker interface {
	Ping(context.Context) error
}

type HandlerConfig struct {
	Service            admin.Service
	OfficialAgents     agentcontrol.PlatformService
	OfficialAudit      admin.OfficialAuditService
	OperationProtector *admin.Protector
	Auth               *Authenticator
	PostgreSQL         HealthChecker
	Redis              HealthChecker
	Clock              func() time.Time
}

type handler struct {
	service            admin.Service
	officialAgents     agentcontrol.PlatformService
	officialAudit      admin.OfficialAuditService
	operationProtector *admin.Protector
	postgresql         HealthChecker
	redis              HealthChecker
}

func NewHandler(config HandlerConfig) (http.Handler, error) {
	if dependencyMissing(config.Service) || config.Auth == nil || dependencyMissing(config.PostgreSQL) ||
		dependencyMissing(config.Redis) || config.Clock == nil {
		return nil, errors.New("internal admin handler dependencies are required")
	}
	hasOfficialAgents := !dependencyMissing(config.OfficialAgents)
	hasOfficialAudit := !dependencyMissing(config.OfficialAudit)
	hasOperationProtector := config.OperationProtector != nil
	if hasOfficialAgents != hasOfficialAudit || hasOfficialAgents != hasOperationProtector {
		return nil, errors.New("official agent admin dependencies must be configured together")
	}

	h := &handler{
		service: config.Service, officialAgents: config.OfficialAgents,
		officialAudit: config.OfficialAudit, operationProtector: config.OperationProtector,
		postgresql: config.PostgreSQL, redis: config.Redis,
	}
	router := chi.NewRouter()
	router.Use(requestIDMiddleware(config.Clock))
	router.Use(jsonResponseMiddleware)
	router.Use(config.Auth.RequireAuthentication)

	router.Route("/internal/admin/v1", func(router chi.Router) {
		router.Group(func(read chi.Router) {
			read.Use(config.Auth.RequireScope(ScopeUsersRead))
			read.Get("/health", h.health)
			read.Get("/users", h.listUsers)
			read.Post("/users/lookup", h.lookupUser)
			read.Get("/users/{userID}", h.getUser)
			read.Get("/users/{userID}/devices", h.listUserDevices)
			read.Get("/users/{userID}/sessions", h.listUserSessions)
		})
		router.Group(func(devices chi.Router) {
			devices.Use(config.Auth.RequireScope(ScopeDevicesWrite))
			devices.Post("/devices/{deviceID}/revoke", h.execute(admin.RevokeDevice, "deviceID"))
		})
		router.Group(func(sessions chi.Router) {
			sessions.Use(config.Auth.RequireScope(ScopeSessionsWrite))
			sessions.Post("/sessions/{sessionID}/revoke", h.execute(admin.RevokeSession, "sessionID"))
		})
		router.Group(func(accounts chi.Router) {
			accounts.Use(config.Auth.RequireScope(ScopeAccountsWrite))
			accounts.Post("/users/{userID}/disable", h.execute(admin.DisableUser, "userID"))
			accounts.Post("/users/{userID}/enable", h.execute(admin.EnableUser, "userID"))
		})
		router.Group(func(operations chi.Router) {
			operations.Use(config.Auth.RequireScope(ScopeOperationsRead))
			operations.Get("/operations/{operationID}", h.getOperation)
		})
		if !dependencyMissing(config.OfficialAgents) {
			registerOfficialAgentRoutes(router, config.Auth, h)
		}
	})
	router.NotFound(func(response http.ResponseWriter, request *http.Request) {
		writeErrorResponse(response, request, http.StatusNotFound, "NOT_FOUND")
	})
	router.MethodNotAllowed(func(response http.ResponseWriter, request *http.Request) {
		writeErrorResponse(response, request, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
	})
	return router, nil
}

func (h *handler) health(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), internalAdminHealthTimeout)
	defer cancel()
	postgresErr := h.postgresql.Ping(ctx)
	redisErr := h.redis.Ping(ctx)
	if postgresErr != nil || redisErr != nil {
		writeErrorResponse(response, request, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE")
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) listUsers(response http.ResponseWriter, request *http.Request) {
	page, status, ok := parseListUsersQuery(request.URL)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	result, err := h.service.ListUsers(request.Context(), admin.ListUsersRequest{PageRequest: page, Status: status})
	if err != nil {
		writeDomainError(response, request, err, "USER_NOT_FOUND", admin.Operation{})
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) lookupUser(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	var lookup admin.LookupRequest
	if err := decodeBoundedJSON(response, request, &lookup); err != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if utf8.RuneCountInString(lookup.Value) < 3 || utf8.RuneCountInString(lookup.Value) > 320 {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if _, err := secure.NormalizeIdentity(lookup.Kind, lookup.Value); err != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	result, err := h.service.LookupUser(request.Context(), lookup)
	if err != nil {
		writeDomainError(response, request, err, "USER_NOT_FOUND", admin.Operation{})
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) getUser(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	userID, ok := parsePathUUID(request, "userID")
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	result, err := h.service.GetUser(request.Context(), userID)
	if err != nil {
		writeDomainError(response, request, err, "USER_NOT_FOUND", admin.Operation{})
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) listUserDevices(response http.ResponseWriter, request *http.Request) {
	h.listUserResource(response, request, func(ctx context.Context, userID uuid.UUID, page admin.PageRequest) (any, error) {
		return h.service.ListUserDevices(ctx, userID, page)
	})
}

func (h *handler) listUserSessions(response http.ResponseWriter, request *http.Request) {
	h.listUserResource(response, request, func(ctx context.Context, userID uuid.UUID, page admin.PageRequest) (any, error) {
		return h.service.ListUserSessions(ctx, userID, page)
	})
}

func (h *handler) listUserResource(
	response http.ResponseWriter,
	request *http.Request,
	load func(context.Context, uuid.UUID, admin.PageRequest) (any, error),
) {
	userID, ok := parsePathUUID(request, "userID")
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	page, ok := parsePageQuery(request.URL)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	result, err := load(request.Context(), userID, page)
	if err != nil {
		writeDomainError(response, request, err, "USER_NOT_FOUND", admin.Operation{})
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) execute(action admin.Action, pathParameter string) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if !hasNoQuery(request.URL) {
			writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		targetID, ok := parsePathUUID(request, pathParameter)
		if !ok {
			writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		operationID, ok := parseIdempotencyKey(request)
		if !ok {
			writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		var command admin.Command
		if err := decodeBoundedJSON(response, request, &command); err != nil ||
			command.OperationID != operationID || admin.ValidateCommand(action, targetID, command) != nil {
			writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		operation, err := h.service.Execute(request.Context(), action, targetID, command)
		if err != nil {
			defaultNotFound := strings.ToUpper(pathParameter[:len(pathParameter)-2]) + "_NOT_FOUND"
			writeDomainError(response, request, err, defaultNotFound, operation)
			return
		}
		writeJSON(response, http.StatusOK, operation)
	}
}

func (h *handler) getOperation(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	operationID, ok := parsePathUUID(request, "operationID")
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	result, err := h.service.GetOperation(request.Context(), operationID)
	if err != nil {
		writeDomainError(response, request, err, "OPERATION_NOT_FOUND", admin.Operation{})
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func parseListUsersQuery(location *url.URL) (admin.PageRequest, admin.UserStatus, bool) {
	values, ok := parseQuery(location, map[string]struct{}{"cursor": {}, "limit": {}, "status": {}})
	if !ok {
		return admin.PageRequest{}, "", false
	}
	page, ok := pageFromValues(values)
	if !ok {
		return admin.PageRequest{}, "", false
	}
	status := admin.UserStatus(singleValue(values, "status"))
	if _, present := values["status"]; present && status == "" {
		return admin.PageRequest{}, "", false
	}
	if status != "" && status != admin.UserActive && status != admin.UserPendingDeletion && status != admin.UserDisabled {
		return admin.PageRequest{}, "", false
	}
	return page, status, true
}

func parsePageQuery(location *url.URL) (admin.PageRequest, bool) {
	values, ok := parseQuery(location, map[string]struct{}{"cursor": {}, "limit": {}})
	if !ok {
		return admin.PageRequest{}, false
	}
	return pageFromValues(values)
}

func parseQuery(location *url.URL, allowed map[string]struct{}) (url.Values, bool) {
	values, err := url.ParseQuery(location.RawQuery)
	if err != nil {
		return nil, false
	}
	for key, entries := range values {
		if _, ok := allowed[key]; !ok || len(entries) != 1 {
			return nil, false
		}
	}
	return values, true
}

func hasNoQuery(location *url.URL) bool {
	values, ok := parseQuery(location, nil)
	return ok && len(values) == 0
}

func pageFromValues(values url.Values) (admin.PageRequest, bool) {
	request := admin.PageRequest{Cursor: singleValue(values, "cursor")}
	if len(request.Cursor) > 512 || !utf8.ValidString(request.Cursor) {
		return admin.PageRequest{}, false
	}
	if raw := singleValue(values, "limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return admin.PageRequest{}, false
		}
		request.Limit = limit
	} else if _, present := values["limit"]; present {
		return admin.PageRequest{}, false
	}
	return request, true
}

func singleValue(values url.Values, key string) string {
	entries := values[key]
	if len(entries) != 1 {
		return ""
	}
	return entries[0]
}

func parsePathUUID(request *http.Request, parameter string) (uuid.UUID, bool) {
	raw := chi.URLParam(request, parameter)
	parsed, err := uuid.Parse(raw)
	return parsed, err == nil && parsed != uuid.Nil && strings.EqualFold(parsed.String(), raw)
}

func parseIdempotencyKey(request *http.Request) (uuid.UUID, bool) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 {
		return uuid.Nil, false
	}
	parsed, err := uuid.Parse(values[0])
	return parsed, err == nil && parsed != uuid.Nil && strings.EqualFold(parsed.String(), values[0])
}

func decodeBoundedJSON(response http.ResponseWriter, request *http.Request, target any) error {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errors.New("one JSON content type is required")
	}
	mediaType, parameters, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return errors.New("JSON content type is required")
	}
	if request.ContentLength > maximumAdminRequestBodyBytes {
		return errors.New("request body is too large")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumAdminRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("request JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("request JSON has trailing data")
	}
	return nil
}

func dependencyMissing(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func requestIDMiddleware(clock func() time.Time) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			requestID := ""
			values := request.Header.Values("X-Request-ID")
			if len(values) == 1 && safeRequestIDPattern.MatchString(values[0]) {
				requestID = values[0]
			}
			if requestID == "" {
				requestID = newRequestID(clock())
			}
			ctx := context.WithValue(request.Context(), requestIDContextKey{}, requestID)
			next.ServeHTTP(response, request.WithContext(ctx))
		})
	}
}

func jsonResponseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(response, request)
	})
}

func newRequestID(now time.Time) string {
	return fmt.Sprintf("req_%x_%x", now.UTC().UnixNano(), requestIDSequence.Add(1))
}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	if !safeRequestIDPattern.MatchString(requestID) {
		return ""
	}
	return requestID
}

func writeDomainError(response http.ResponseWriter, request *http.Request, err error, notFoundCode string, operation admin.Operation) {
	status, code := http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	switch {
	case errors.Is(err, admin.ErrInvalidCursor):
		status, code = http.StatusBadRequest, "INVALID_CURSOR"
	case errors.Is(err, admin.ErrInvalidCommand):
		status, code = http.StatusBadRequest, "INVALID_REQUEST"
	case errors.Is(err, admin.ErrNotFound):
		status, code = http.StatusNotFound, stableOperationCode(operation.ErrorCode, notFoundCode)
	case errors.Is(err, admin.ErrIdempotencyKeyReused):
		status, code = http.StatusConflict, "IDEMPOTENCY_KEY_REUSED"
	case errors.Is(err, admin.ErrStateConflict):
		status, code = http.StatusConflict, stableOperationCode(operation.ErrorCode, "STATE_CONFLICT")
	}
	writeErrorResponse(response, request, status, code)
}

func stableOperationCode(candidate, fallback string) string {
	if safeErrorCodePattern.MatchString(candidate) {
		return candidate
	}
	return fallback
}

func writeErrorResponse(response http.ResponseWriter, request *http.Request, status int, code string) {
	requestID := ""
	if request != nil {
		requestID = requestIDFromContext(request.Context())
	}
	if requestID == "" {
		requestID = newRequestID(time.Now())
	}
	writeJSON(response, status, map[string]any{
		"error": map[string]string{"code": code, "request_id": requestID},
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
