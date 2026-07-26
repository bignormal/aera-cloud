package adminapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
)

var (
	handlerUserID      = uuid.MustParse("019f0000-0000-7000-8000-000000000101")
	handlerDeviceID    = uuid.MustParse("019f0000-0000-7000-8000-000000000102")
	handlerSessionID   = uuid.MustParse("019f0000-0000-7000-8000-000000000103")
	handlerOperationID = uuid.MustParse("019f0000-0000-7000-8000-000000000104")
	handlerAdminID     = uuid.MustParse("019f0000-0000-7000-8000-000000000105")
	handlerApprovalID  = uuid.MustParse("019f0000-0000-7000-8000-000000000106")
)

type handlerHealthStub struct {
	err   error
	calls int
}

func (s *handlerHealthStub) Ping(context.Context) error {
	s.calls++
	return s.err
}

type handlerServiceStub struct {
	user        admin.User
	devices     admin.Page[admin.Device]
	sessions    admin.Page[admin.Session]
	operation   admin.Operation
	stats       admin.PlatformStats
	deviceStats admin.DeviceStats
	memberships admin.UserMemberships

	listUsersErr    error
	lookupUserErr   error
	getUserErr      error
	listDevicesErr  error
	listSessionsErr error
	executeErr      error
	getOperationErr error
	statsErr        error
	deviceStatsErr  error
	membershipsErr  error

	calls       []string
	listRequest admin.ListUsersRequest
	lookup      admin.LookupRequest
	pageRequest admin.PageRequest
	targetID    uuid.UUID
	action      admin.Action
	command     admin.Command
}

func newHandlerServiceStub(now time.Time) *handlerServiceStub {
	lastSeen := now.Add(-time.Minute)
	revokedAt := now.Add(-30 * time.Second)
	return &handlerServiceStub{
		user: admin.User{
			ID: handlerUserID, MaskedEmail: "a***@example.com", Status: admin.UserActive,
			AdministrativeRevision: 1, DeviceCount: 1, ActiveDeviceCount: 1,
			ActiveSessionCount: 1, CreatedAt: now.Add(-24 * time.Hour), LastCloudActivityAt: &lastSeen,
		},
		devices: admin.Page[admin.Device]{
			Items: []admin.Device{{
				ID: handlerDeviceID, UserID: handlerUserID, DisplayName: "MacBook Pro",
				Platform: "darwin", ClientVersion: "1.0.0", Status: admin.DeviceActive, LastSeenAt: &lastSeen,
			}},
			NextCursor: "next-device-cursor",
		},
		sessions: admin.Page[admin.Session]{Items: []admin.Session{{
			ID: handlerSessionID, UserID: handlerUserID, DeviceID: handlerDeviceID,
			Status: admin.SessionRevoked, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
			RevokedAt: &revokedAt,
		}}},
		operation: admin.Operation{
			ID: handlerOperationID, Status: admin.OperationSucceeded,
			AdministrativeRevision: 2, UpdatedAt: now,
		},
	}
}

func (s *handlerServiceStub) ListUsers(_ context.Context, request admin.ListUsersRequest) (admin.Page[admin.User], error) {
	s.calls = append(s.calls, "list_users")
	s.listRequest = request
	return admin.Page[admin.User]{Items: []admin.User{s.user}, NextCursor: "next-user-cursor"}, s.listUsersErr
}

func (s *handlerServiceStub) LookupUser(_ context.Context, request admin.LookupRequest) (admin.User, error) {
	s.calls = append(s.calls, "lookup_user")
	s.lookup = request
	return s.user, s.lookupUserErr
}

func (s *handlerServiceStub) GetUser(_ context.Context, userID uuid.UUID) (admin.User, error) {
	s.calls = append(s.calls, "get_user")
	s.targetID = userID
	return s.user, s.getUserErr
}

func (s *handlerServiceStub) Stats(context.Context) (admin.PlatformStats, error) {
	s.calls = append(s.calls, "stats")
	return s.stats, s.statsErr
}

func (s *handlerServiceStub) DeviceStats(context.Context) (admin.DeviceStats, error) {
	s.calls = append(s.calls, "device_stats")
	return s.deviceStats, s.deviceStatsErr
}

func (s *handlerServiceStub) UserMemberships(_ context.Context, userID uuid.UUID) (admin.UserMemberships, error) {
	s.calls = append(s.calls, "user_memberships")
	s.targetID = userID
	return s.memberships, s.membershipsErr
}

func (s *handlerServiceStub) ListUserDevices(_ context.Context, userID uuid.UUID, request admin.PageRequest) (admin.Page[admin.Device], error) {
	s.calls = append(s.calls, "list_devices")
	s.targetID, s.pageRequest = userID, request
	return s.devices, s.listDevicesErr
}

func (s *handlerServiceStub) ListUserSessions(_ context.Context, userID uuid.UUID, request admin.PageRequest) (admin.Page[admin.Session], error) {
	s.calls = append(s.calls, "list_sessions")
	s.targetID, s.pageRequest = userID, request
	return s.sessions, s.listSessionsErr
}

func (s *handlerServiceStub) Execute(_ context.Context, action admin.Action, targetID uuid.UUID, command admin.Command) (admin.Operation, error) {
	s.calls = append(s.calls, "execute")
	s.action, s.targetID, s.command = action, targetID, command
	return s.operation, s.executeErr
}

func (s *handlerServiceStub) GetOperation(_ context.Context, operationID uuid.UUID) (admin.Operation, error) {
	s.calls = append(s.calls, "get_operation")
	s.targetID = operationID
	return s.operation, s.getOperationErr
}

func TestHandlerServesAllElevenContractRoutes(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	command := validHandlerCommand(true)
	commandBody := mustJSON(t, command)

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		scope      string
		idempotent bool
		wantCall   string
		wantBody   func(*handlerServiceStub) string
		assertCall func(*testing.T, *handlerServiceStub)
	}{
		{
			name: "health", method: http.MethodGet, path: "/internal/admin/v1/health", scope: ScopeUsersRead,
			wantBody: func(*handlerServiceStub) string { return `{"status":"ok"}` + "\n" },
		},
		{
			name: "list users", method: http.MethodGet,
			path: "/internal/admin/v1/users?cursor=user-cursor&limit=25&status=active", scope: ScopeUsersRead,
			wantCall: "list_users",
			wantBody: func(service *handlerServiceStub) string {
				return mustJSON(t, admin.Page[admin.User]{Items: []admin.User{service.user}, NextCursor: "next-user-cursor"}) + "\n"
			},
			assertCall: func(t *testing.T, service *handlerServiceStub) {
				if service.listRequest.Cursor != "user-cursor" || service.listRequest.Limit != 25 || service.listRequest.Status != admin.UserActive {
					t.Fatalf("list request = %+v", service.listRequest)
				}
			},
		},
		{
			name: "lookup user", method: http.MethodPost, path: "/internal/admin/v1/users/lookup",
			body: `{"type":"email","value":"cloud.lookup.canary@example.test"}`, scope: ScopeUsersRead,
			wantCall: "lookup_user", wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.user) + "\n" },
			assertCall: func(t *testing.T, service *handlerServiceStub) {
				if service.lookup.Kind != secure.IdentityEmail || service.lookup.Value != "cloud.lookup.canary@example.test" {
					t.Fatalf("lookup request = %+v", service.lookup)
				}
			},
		},
		{
			name: "get user", method: http.MethodGet, path: "/internal/admin/v1/users/" + handlerUserID.String(), scope: ScopeUsersRead,
			wantCall: "get_user", wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.user) + "\n" },
		},
		{
			name: "list devices", method: http.MethodGet,
			path: "/internal/admin/v1/users/" + handlerUserID.String() + "/devices?cursor=device-cursor&limit=20", scope: ScopeUsersRead,
			wantCall: "list_devices", wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.devices) + "\n" },
			assertCall: func(t *testing.T, service *handlerServiceStub) {
				if service.targetID != handlerUserID || service.pageRequest.Cursor != "device-cursor" || service.pageRequest.Limit != 20 {
					t.Fatalf("device request = %s / %+v", service.targetID, service.pageRequest)
				}
			},
		},
		{
			name: "list sessions", method: http.MethodGet,
			path: "/internal/admin/v1/users/" + handlerUserID.String() + "/sessions", scope: ScopeUsersRead,
			wantCall: "list_sessions", wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.sessions) + "\n" },
		},
		{
			name: "revoke device", method: http.MethodPost,
			path: "/internal/admin/v1/devices/" + handlerDeviceID.String() + "/revoke", body: commandBody,
			scope: ScopeDevicesWrite, idempotent: true, wantCall: "execute",
			wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.operation) + "\n" },
			assertCall: func(t *testing.T, service *handlerServiceStub) {
				if service.action != admin.RevokeDevice || service.targetID != handlerDeviceID {
					t.Fatalf("execute = %s / %s", service.action, service.targetID)
				}
			},
		},
		{
			name: "revoke session", method: http.MethodPost,
			path: "/internal/admin/v1/sessions/" + handlerSessionID.String() + "/revoke", body: commandBody,
			scope: ScopeSessionsWrite, idempotent: true, wantCall: "execute",
			wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.operation) + "\n" },
			assertCall: func(t *testing.T, service *handlerServiceStub) {
				if service.action != admin.RevokeSession || service.targetID != handlerSessionID {
					t.Fatalf("execute = %s / %s", service.action, service.targetID)
				}
			},
		},
		{
			name: "disable user", method: http.MethodPost,
			path: "/internal/admin/v1/users/" + handlerUserID.String() + "/disable", body: commandBody,
			scope: ScopeAccountsWrite, idempotent: true, wantCall: "execute",
			wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.operation) + "\n" },
			assertCall: func(t *testing.T, service *handlerServiceStub) {
				if service.action != admin.DisableUser || service.targetID != handlerUserID {
					t.Fatalf("execute = %s / %s", service.action, service.targetID)
				}
			},
		},
		{
			name: "enable user", method: http.MethodPost,
			path: "/internal/admin/v1/users/" + handlerUserID.String() + "/enable", body: commandBody,
			scope: ScopeAccountsWrite, idempotent: true, wantCall: "execute",
			wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.operation) + "\n" },
			assertCall: func(t *testing.T, service *handlerServiceStub) {
				if service.action != admin.EnableUser || service.targetID != handlerUserID {
					t.Fatalf("execute = %s / %s", service.action, service.targetID)
				}
			},
		},
		{
			name: "get operation", method: http.MethodGet,
			path: "/internal/admin/v1/operations/" + handlerOperationID.String(), scope: ScopeOperationsRead,
			wantCall: "get_operation", wantBody: func(service *handlerServiceStub) string { return mustJSON(t, service.operation) + "\n" },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, service, privateKey := newHandlerFixture(t, now)
			request := authenticatedHandlerRequest(t, privateKey, now, test.method, test.path, test.body, test.scope)
			if test.idempotent {
				request.Header.Set("Idempotency-Key", handlerOperationID.String())
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type = %q", got)
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if got, want := response.Body.String(), test.wantBody(service); got != want {
				t.Fatalf("body = %q, want %q", got, want)
			}
			if test.wantCall == "" {
				if len(service.calls) != 0 {
					t.Fatalf("service calls = %v", service.calls)
				}
			} else if len(service.calls) != 1 || service.calls[0] != test.wantCall {
				t.Fatalf("service calls = %v, want %q", service.calls, test.wantCall)
			}
			if test.assertCall != nil {
				test.assertCall(t, service)
			}
			if strings.Contains(response.Body.String(), "cloud.lookup.canary@example.test") {
				t.Fatal("response leaked exact lookup identity")
			}
		})
	}
}

func TestHandlerRejectsInvalidJSONPathsQueriesAndCommandsBeforeCallingService(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	validCommand := validHandlerCommand(true)
	unsafeNote := validCommand
	unsafeNote.Note = "unsafe\nnote"
	missingApproval := validCommand
	missingApproval.ApprovalID = nil
	mismatchedOperation := validCommand
	mismatchedOperation.OperationID = uuid.MustParse("019f0000-0000-7000-8000-000000000999")

	tests := []struct {
		name        string
		method      string
		path        string
		body        string
		scope       string
		idempotent  string
		contentType string
	}{
		{name: "unknown lookup field", method: http.MethodPost, path: "/internal/admin/v1/users/lookup", body: `{"type":"email","value":"cloud.lookup.canary@example.test","extra":true}`, scope: ScopeUsersRead},
		{name: "trailing lookup JSON", method: http.MethodPost, path: "/internal/admin/v1/users/lookup", body: `{"type":"email","value":"cloud.lookup.canary@example.test"}{}`, scope: ScopeUsersRead},
		{name: "oversized lookup", method: http.MethodPost, path: "/internal/admin/v1/users/lookup", body: `{"type":"email","value":"` + strings.Repeat("x", 33<<10) + `@example.test"}`, scope: ScopeUsersRead},
		{name: "unsupported content type", method: http.MethodPost, path: "/internal/admin/v1/users/lookup", body: `{"type":"email","value":"cloud.lookup.canary@example.test"}`, scope: ScopeUsersRead, contentType: "text/plain"},
		{name: "invalid uuid", method: http.MethodGet, path: "/internal/admin/v1/users/not-a-uuid", scope: ScopeUsersRead},
		{name: "nil uuid", method: http.MethodGet, path: "/internal/admin/v1/users/00000000-0000-0000-0000-000000000000", scope: ScopeUsersRead},
		{name: "limit zero", method: http.MethodGet, path: "/internal/admin/v1/users?limit=0", scope: ScopeUsersRead},
		{name: "limit above maximum", method: http.MethodGet, path: "/internal/admin/v1/users?limit=101", scope: ScopeUsersRead},
		{name: "duplicate limit", method: http.MethodGet, path: "/internal/admin/v1/users?limit=1&limit=2", scope: ScopeUsersRead},
		{name: "unknown query", method: http.MethodGet, path: "/internal/admin/v1/users?email=cloud.lookup.canary@example.test", scope: ScopeUsersRead},
		{name: "invalid status", method: http.MethodGet, path: "/internal/admin/v1/users?status=deleted", scope: ScopeUsersRead},
		{name: "explicit empty status", method: http.MethodGet, path: "/internal/admin/v1/users?status=", scope: ScopeUsersRead},
		{name: "unsafe note", method: http.MethodPost, path: "/internal/admin/v1/users/" + handlerUserID.String() + "/disable", body: mustJSON(t, unsafeNote), scope: ScopeAccountsWrite, idempotent: handlerOperationID.String()},
		{name: "missing account approval", method: http.MethodPost, path: "/internal/admin/v1/users/" + handlerUserID.String() + "/disable", body: mustJSON(t, missingApproval), scope: ScopeAccountsWrite, idempotent: handlerOperationID.String()},
		{name: "operation and idempotency mismatch", method: http.MethodPost, path: "/internal/admin/v1/devices/" + handlerDeviceID.String() + "/revoke", body: mustJSON(t, mismatchedOperation), scope: ScopeDevicesWrite, idempotent: handlerOperationID.String()},
		{name: "missing idempotency header", method: http.MethodPost, path: "/internal/admin/v1/devices/" + handlerDeviceID.String() + "/revoke", body: mustJSON(t, validCommand), scope: ScopeDevicesWrite},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, service, privateKey := newHandlerFixture(t, now)
			request := authenticatedHandlerRequest(t, privateKey, now, test.method, test.path, test.body, test.scope)
			if test.idempotent != "" {
				request.Header.Set("Idempotency-Key", test.idempotent)
			}
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			assertSafeErrorResponse(t, response, "INVALID_REQUEST")
			if len(service.calls) != 0 {
				t.Fatalf("service calls = %v", service.calls)
			}
			if strings.Contains(response.Body.String(), "cloud.lookup.canary@example.test") {
				t.Fatal("error response leaked exact lookup identity")
			}
		})
	}
}

func TestHandlerEnforcesTheMinimumScopeForEveryRouteGroup(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	commandBody := mustJSON(t, validHandlerCommand(true))
	tests := []struct{ path, required string }{
		{"/internal/admin/v1/devices/" + handlerDeviceID.String() + "/revoke", ScopeDevicesWrite},
		{"/internal/admin/v1/sessions/" + handlerSessionID.String() + "/revoke", ScopeSessionsWrite},
		{"/internal/admin/v1/users/" + handlerUserID.String() + "/disable", ScopeAccountsWrite},
		{"/internal/admin/v1/operations/" + handlerOperationID.String(), ScopeOperationsRead},
	}
	for _, test := range tests {
		t.Run(test.required, func(t *testing.T) {
			handler, service, privateKey := newHandlerFixture(t, now)
			method, body := http.MethodPost, commandBody
			if test.required == ScopeOperationsRead {
				method, body = http.MethodGet, ""
			}
			request := authenticatedHandlerRequest(t, privateKey, now, method, test.path, body, ScopeUsersRead)
			if method == http.MethodPost {
				request.Header.Set("Idempotency-Key", handlerOperationID.String())
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			assertSafeErrorResponse(t, response, "PERMISSION_DENIED")
			if len(service.calls) != 0 {
				t.Fatalf("service calls = %v", service.calls)
			}
		})
	}
}

func TestHandlerMapsStableDomainErrorsWithoutLeakingInputs(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		path       string
		configure  func(*handlerServiceStub)
		wantStatus int
		wantCode   string
	}{
		{name: "invalid cursor", path: "/internal/admin/v1/users?cursor=bad", configure: func(s *handlerServiceStub) { s.listUsersErr = admin.ErrInvalidCursor }, wantStatus: 400, wantCode: "INVALID_CURSOR"},
		{name: "user not found", path: "/internal/admin/v1/users/" + handlerUserID.String(), configure: func(s *handlerServiceStub) { s.getUserErr = admin.ErrNotFound }, wantStatus: 404, wantCode: "USER_NOT_FOUND"},
		{name: "unavailable", path: "/internal/admin/v1/users", configure: func(s *handlerServiceStub) { s.listUsersErr = admin.ErrUnavailable }, wantStatus: 503, wantCode: "SERVICE_UNAVAILABLE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, service, privateKey := newHandlerFixture(t, now)
			test.configure(service)
			request := authenticatedHandlerRequest(t, privateKey, now, http.MethodGet, test.path, "", ScopeUsersRead)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			assertSafeErrorResponse(t, response, test.wantCode)
		})
	}
}

func TestHandlerMapsDurableCommandErrorsUsingOnlyStableOperationCodes(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		err        error
		errorCode  string
		wantStatus int
		wantCode   string
	}{
		{name: "target missing", err: admin.ErrNotFound, errorCode: "DEVICE_NOT_FOUND", wantStatus: 404, wantCode: "DEVICE_NOT_FOUND"},
		{name: "state conflict", err: admin.ErrStateConflict, errorCode: "DEVICE_ALREADY_REVOKED", wantStatus: 409, wantCode: "DEVICE_ALREADY_REVOKED"},
		{name: "idempotency conflict", err: admin.ErrIdempotencyKeyReused, wantStatus: 409, wantCode: "IDEMPOTENCY_KEY_REUSED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, service, privateKey := newHandlerFixture(t, now)
			service.executeErr = test.err
			service.operation = admin.Operation{ID: handlerOperationID, Status: admin.OperationConflict, ErrorCode: test.errorCode, UpdatedAt: now}
			request := authenticatedHandlerRequest(t, privateKey, now, http.MethodPost, "/internal/admin/v1/devices/"+handlerDeviceID.String()+"/revoke", mustJSON(t, validHandlerCommand(true)), ScopeDevicesWrite)
			request.Header.Set("Idempotency-Key", handlerOperationID.String())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			assertSafeErrorResponse(t, response, test.wantCode)
		})
	}
}

func TestHandlerHealthFailsClosedAndChecksBothDependencies(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	handler, _, privateKey, postgres, redis := newHandlerFixtureWithHealth(t, now)
	postgres.err = errors.New("postgres raw failure canary")
	request := authenticatedHandlerRequest(t, privateKey, now, http.MethodGet, "/internal/admin/v1/health", "", ScopeUsersRead)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	assertSafeErrorResponse(t, response, "SERVICE_UNAVAILABLE")
	if postgres.calls != 1 || redis.calls != 1 {
		t.Fatalf("health calls = postgres:%d redis:%d", postgres.calls, redis.calls)
	}
	if strings.Contains(response.Body.String(), "raw failure canary") {
		t.Fatal("health response leaked dependency error")
	}
}

func TestHandlerAddsNoStoreAndNeverLogsExactLookupInput(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	handler, service, privateKey := newHandlerFixture(t, now)
	service.lookupUserErr = admin.ErrNotFound
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(original) })

	const canary = "cloud.lookup.canary@example.test"
	request := authenticatedHandlerRequest(t, privateKey, now, http.MethodPost, "/internal/admin/v1/users/lookup", `{"type":"email","value":"`+canary+`"}`, ScopeUsersRead)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	assertSafeErrorResponse(t, response, "USER_NOT_FOUND")
	if strings.Contains(response.Body.String(), canary) || strings.Contains(logs.String(), canary) {
		t.Fatal("exact lookup identity leaked")
	}
}

func TestHandlerReturnsBoundedJSONForAuthenticationMethodAndPathFailures(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	handler, service, privateKey := newHandlerFixture(t, now)
	tests := []struct {
		name       string
		request    *http.Request
		wantStatus int
		wantCode   string
	}{
		{name: "authentication", request: httptest.NewRequest(http.MethodGet, "https://cloud.test/internal/admin/v1/users", nil), wantStatus: 401, wantCode: "AUTHENTICATION_REQUIRED"},
		{name: "method", request: authenticatedHandlerRequest(t, privateKey, now, http.MethodPut, "/internal/admin/v1/users", "", ScopeUsersRead), wantStatus: 405, wantCode: "METHOD_NOT_ALLOWED"},
		{name: "path", request: authenticatedHandlerRequest(t, privateKey, now, http.MethodGet, "/internal/admin/v1/not-present", "", ScopeUsersRead), wantStatus: 404, wantCode: "NOT_FOUND"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.request.Header.Set("X-Request-ID", "request-handler-test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, test.request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			assertSafeErrorResponse(t, response, test.wantCode)
		})
	}
	if len(service.calls) != 0 {
		t.Fatalf("service calls = %v", service.calls)
	}
}

func TestHandlerAuthenticatesBeforeUnknownPathOrMethodDispatch(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	handler, service, _ := newHandlerFixture(t, now)
	for _, target := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPut, path: "/internal/admin/v1/users"},
		{method: http.MethodGet, path: "/internal/admin/v1/not-present"},
	} {
		request := httptest.NewRequest(target.method, "https://cloud.test"+target.path, nil)
		request.Header.Set("X-Request-ID", "request-handler-test")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d; body = %s", target.method, target.path, response.Code, response.Body.String())
		}
		assertSafeErrorResponse(t, response, "AUTHENTICATION_REQUIRED")
	}
	if len(service.calls) != 0 {
		t.Fatalf("service calls = %v", service.calls)
	}
}

func TestHandlerRejectsIncompleteConfiguration(t *testing.T) {
	now := time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)
	auth, _, _ := newTestAuthenticator(t)
	service := newHandlerServiceStub(now)
	health := &handlerHealthStub{}
	valid := HandlerConfig{Service: service, Auth: auth, PostgreSQL: health, Redis: health, Clock: func() time.Time { return now }}
	tests := []HandlerConfig{
		{},
		{Auth: auth, PostgreSQL: health, Redis: health, Clock: valid.Clock},
		{Service: service, PostgreSQL: health, Redis: health, Clock: valid.Clock},
		{Service: service, Auth: auth, Redis: health, Clock: valid.Clock},
		{Service: service, Auth: auth, PostgreSQL: health, Clock: valid.Clock},
		{Service: service, Auth: auth, PostgreSQL: health, Redis: health},
	}
	for index, config := range tests {
		if _, err := NewHandler(config); err == nil {
			t.Fatalf("config %d succeeded", index)
		}
	}
	var typedNilService *handlerServiceStub
	if _, err := NewHandler(HandlerConfig{
		Service: typedNilService, Auth: auth, PostgreSQL: health, Redis: health, Clock: valid.Clock,
	}); err == nil {
		t.Fatal("typed nil service succeeded")
	}
}

func newHandlerFixture(t *testing.T, now time.Time) (http.Handler, *handlerServiceStub, ed25519.PrivateKey) {
	t.Helper()
	handler, service, privateKey, _, _ := newHandlerFixtureWithHealth(t, now)
	return handler, service, privateKey
}

func newHandlerFixtureWithHealth(t *testing.T, now time.Time) (http.Handler, *handlerServiceStub, ed25519.PrivateKey, *handlerHealthStub, *handlerHealthStub) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(AuthenticatorConfig{
		PublicKey: publicKey, Issuer: "aera-admin", Subject: "aera-admin-e2e",
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	service := newHandlerServiceStub(now)
	postgres, redis := &handlerHealthStub{}, &handlerHealthStub{}
	handler, err := NewHandler(HandlerConfig{
		Service: service, Auth: auth, PostgreSQL: postgres, Redis: redis, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, service, privateKey, postgres, redis
}

func authenticatedHandlerRequest(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, method, path, body, scope string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://cloud.test"+path, strings.NewReader(body))
	setVerifiedClientCertificate(request)
	claims := validServiceClaims(now)
	claims["scope"] = []string{scope}
	request.Header.Set("Authorization", "Bearer "+signServiceToken(t, privateKey, validServiceHeader(), claims))
	request.Header.Set("X-Request-ID", "request-handler-test")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func validHandlerCommand(withApproval bool) admin.Command {
	command := admin.Command{
		OperationID: handlerOperationID, ActorAdminID: handlerAdminID, RequestID: "request-handler-command",
		ReasonCode: "security_review", TicketReference: "SUP-100", Note: "Approved account control",
		ExpectedRevision: 1,
	}
	if withApproval {
		command.ApprovalID = &handlerApprovalID
	}
	return command
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertSafeErrorResponse(t *testing.T, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var body struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	decoder := json.NewDecoder(strings.NewReader(response.Body.String()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		t.Fatalf("error body = %q: %v", response.Body.String(), err)
	}
	if body.Error.Code != code || body.Error.RequestID != "request-handler-test" {
		t.Fatalf("error = %+v, want %s / request-handler-test", body.Error, code)
	}
}
