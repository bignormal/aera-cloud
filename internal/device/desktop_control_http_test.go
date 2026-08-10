package device

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/desktopcontrol"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
)

func TestDesktopControlHeartbeatUsesAccessClaimsAndReturnsOneSafeCommand(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	userID, deviceID, commandID := uuid.New(), uuid.New(), uuid.New()
	desktop := &stubDesktopControlHTTPService{receipt: desktopcontrol.HeartbeatReceipt{
		Instance: desktopcontrol.Instance{
			DeviceID: deviceID, UserID: userID, EffectiveStatusValue: desktopcontrol.EffectiveOnline,
		},
		AcceptedAt: now, NextHeartbeatSeconds: 60, ServerTime: now,
		Command: &desktopcontrol.Command{
			ID: commandID, DeviceID: deviceID, Type: desktopcontrol.CommandHealthCheck,
			State: desktopcontrol.CommandClaimed, ExpiresAt: now.Add(10 * time.Minute),
			CreatedByAdminID: uuid.New(), RequestID: "must-not-leak",
		},
	}}
	handler := NewHandler(HTTPConfig{
		Devices: &stubDeviceHTTPService{}, DesktopControl: desktop,
		AccessTokens: &stubAccessAuthenticator{claims: accessClaims(userID, deviceID)},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/current/desktop-control/heartbeat", strings.NewReader(`{
		"display_name":"Aera Mac","client_version":"0.7.4","platform":"darwin","arch":"arm64",
		"capabilities":["diagnostics.health.read"],"uptime_seconds":10
	}`))
	request.Header.Set("Authorization", "Bearer valid-device-session")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat response = %d %q", response.Code, body)
	}
	if desktop.principal.UserID != userID || desktop.principal.DeviceID != deviceID || desktop.heartbeat.DisplayName != "Aera Mac" {
		t.Fatalf("heartbeat principal/payload = %+v/%+v", desktop.principal, desktop.heartbeat)
	}
	for _, expected := range []string{commandID.String(), `"type":"health_check"`, `"effective_status":"online"`, `"next_heartbeat_seconds":60`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("heartbeat response missing %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"created_by_admin", "must-not-leak", "idempotency", "user_id", "device_id"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("heartbeat response leaked %q: %s", forbidden, body)
		}
	}
}

func TestDesktopControlHeartbeatRejectsOwnershipAndOversizedBodies(t *testing.T) {
	userID, deviceID := uuid.New(), uuid.New()
	desktop := &stubDesktopControlHTTPService{}
	handler := NewHandler(HTTPConfig{
		Devices: &stubDeviceHTTPService{}, DesktopControl: desktop,
		AccessTokens: &stubAccessAuthenticator{claims: accessClaims(userID, deviceID)},
	})
	for _, body := range []string{
		`{"display_name":"Aera Mac","client_version":"0.7.4","platform":"darwin","arch":"arm64","capabilities":[],"uptime_seconds":1,"user_id":"` + uuid.NewString() + `"}`,
		`{"display_name":"` + strings.Repeat("a", deviceRequestBodyLimit) + `","client_version":"0.7.4","platform":"darwin","arch":"arm64","capabilities":[],"uptime_seconds":1}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/current/desktop-control/heartbeat", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer valid-device-session")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid heartbeat response = %d %q", response.Code, response.Body.String())
		}
	}
	if desktop.heartbeatCalls != 0 {
		t.Fatalf("invalid heartbeats reached service %d times", desktop.heartbeatCalls)
	}
}

func TestDesktopControlRequiresActiveAccessSession(t *testing.T) {
	handler := NewHandler(HTTPConfig{
		Devices: &stubDeviceHTTPService{}, DesktopControl: &stubDesktopControlHTTPService{},
		AccessTokens: &stubAccessAuthenticator{err: session.ErrSessionRevoked},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/current/desktop-control/heartbeat", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer revoked")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "session_revoked") {
		t.Fatalf("revoked heartbeat response = %d %q", response.Code, response.Body.String())
	}
}

func TestDesktopControlRateLimitReturnsRetryAfter(t *testing.T) {
	userID, deviceID := uuid.New(), uuid.New()
	desktop := &stubDesktopControlHTTPService{}
	handler := NewHandler(HTTPConfig{
		Devices: &stubDeviceHTTPService{}, DesktopControl: desktop,
		DesktopControlLimiter: &stubDesktopControlLimiter{retryAfter: 90 * time.Second, err: desktopcontrol.ErrRateLimited},
		AccessTokens:          &stubAccessAuthenticator{claims: accessClaims(userID, deviceID)},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/current/desktop-control/heartbeat", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer valid-device-session")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "90" || desktop.heartbeatCalls != 0 {
		t.Fatalf("limited heartbeat response=%d retry=%q calls=%d body=%q", response.Code, response.Header().Get("Retry-After"), desktop.heartbeatCalls, response.Body.String())
	}
}

func TestDesktopControlCommandResultUsesCurrentDeviceAndMapsLifecycleErrors(t *testing.T) {
	userID, deviceID, commandID := uuid.New(), uuid.New(), uuid.New()
	desktop := &stubDesktopControlHTTPService{command: desktopcontrol.Command{
		ID: commandID, DeviceID: deviceID, State: desktopcontrol.CommandRunning,
	}}
	handler := NewHandler(HTTPConfig{
		Devices: &stubDeviceHTTPService{}, DesktopControl: desktop,
		AccessTokens: &stubAccessAuthenticator{claims: accessClaims(userID, deviceID)},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/current/desktop-control/commands/"+commandID.String()+"/result", strings.NewReader(`{"state":"running"}`))
	request.Header.Set("Authorization", "Bearer valid-device-session")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || desktop.principal.UserID != userID || desktop.principal.DeviceID != deviceID || desktop.commandID != commandID {
		t.Fatalf("running result response=%d principal=%+v command=%s body=%q", response.Code, desktop.principal, desktop.commandID, response.Body.String())
	}

	desktop.err = desktopcontrol.ErrNotFound
	request = httptest.NewRequest(http.MethodPost, "/api/v1/devices/current/desktop-control/commands/"+commandID.String()+"/result", strings.NewReader(`{"state":"running"}`))
	request.Header.Set("Authorization", "Bearer valid-device-session")
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("foreign command response = %d %q", response.Code, response.Body.String())
	}
}

type stubDesktopControlHTTPService struct {
	receipt        desktopcontrol.HeartbeatReceipt
	command        desktopcontrol.Command
	err            error
	principal      desktopcontrol.DevicePrincipal
	heartbeat      desktopcontrol.Heartbeat
	commandID      uuid.UUID
	result         desktopcontrol.CommandResult
	heartbeatCalls int
}

type stubDesktopControlLimiter struct {
	retryAfter time.Duration
	err        error
}

func (s *stubDesktopControlLimiter) Allow(context.Context, desktopcontrol.LimitAction, desktopcontrol.DevicePrincipal) (time.Duration, error) {
	return s.retryAfter, s.err
}

func (s *stubDesktopControlHTTPService) Heartbeat(_ context.Context, principal desktopcontrol.DevicePrincipal, heartbeat desktopcontrol.Heartbeat) (desktopcontrol.HeartbeatReceipt, error) {
	s.heartbeatCalls++
	s.principal = principal
	s.heartbeat = heartbeat
	return s.receipt, s.err
}

func (s *stubDesktopControlHTTPService) SubmitResult(_ context.Context, principal desktopcontrol.DevicePrincipal, commandID uuid.UUID, result desktopcontrol.CommandResult) (desktopcontrol.Command, error) {
	s.principal = principal
	s.commandID = commandID
	s.result = result
	return s.command, s.err
}

func accessClaims(userID, deviceID uuid.UUID) session.AccessClaims {
	return session.AccessClaims{AccessBinding: session.AccessBinding{
		UserID: userID, DeviceID: deviceID, SessionID: uuid.New(), PersonalSpaceID: uuid.New(),
	}}
}
