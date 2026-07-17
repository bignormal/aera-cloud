package device

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/browser"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
)

func TestHTTPListsRedactedDevicesForAccessToken(t *testing.T) {
	userID := uuid.New()
	deviceID := uuid.New()
	devices := &stubDeviceHTTPService{listed: []PublicDevice{{
		ID: deviceID, DisplayName: "Alice Mac", Platform: "darwin", AppVersion: "0.1.0",
		Status: "active", LastSeenAt: time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC), Current: true,
	}}}
	handler := NewHandler(HTTPConfig{
		Devices: devices,
		AccessTokens: &stubAccessAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
			UserID: userID, DeviceID: deviceID, SessionID: uuid.New(), PersonalSpaceID: uuid.New(),
		}}},
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	request.Header.Set("Authorization", "Bearer signed-access-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	body := response.Body.String()
	if response.Code != http.StatusOK || devices.listUserID != userID || devices.listCurrentID != deviceID {
		t.Fatalf("response=%d %q list=%s/%s", response.Code, body, devices.listUserID, devices.listCurrentID)
	}
	if strings.Contains(body, "installation_id") || strings.Contains(body, "public_key") || !strings.Contains(body, "Alice Mac") {
		t.Fatalf("device response was not redacted: %q", body)
	}
}

func TestHTTPBrowserDeviceRevocationRequiresCSRF(t *testing.T) {
	userID := uuid.New()
	targetID := uuid.New()
	browserSessions := &stubDeviceBrowserSessions{session: browser.Session{Principal: browser.Principal{UserID: userID, PersonalSpaceID: uuid.New()}}}
	devices := &stubDeviceHTTPService{}
	handler := NewHandler(HTTPConfig{Devices: devices, BrowserSessions: browserSessions})
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/"+targetID.String(), nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden || devices.revokedDeviceID != uuid.Nil {
		t.Fatalf("without CSRF response=%d revoked=%s", response.Code, devices.revokedDeviceID)
	}
	browserSessions.csrfOK = true
	request = httptest.NewRequest(http.MethodDelete, "/api/v1/devices/"+targetID.String(), nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || devices.revokedUserID != userID || devices.revokedDeviceID != targetID {
		t.Fatalf("with CSRF response=%d revoked=%s/%s", response.Code, devices.revokedUserID, devices.revokedDeviceID)
	}
}

func TestHTTPSelfRevokeAcceptsOnlyDeviceSignedPayload(t *testing.T) {
	devices := &stubDeviceHTTPService{}
	handler := NewHandler(HTTPConfig{Devices: devices})
	deviceID := uuid.New()
	installationID := uuid.New()
	body := `{"device_id":"` + deviceID.String() + `","installation_id":"` + installationID.String() +
		`","timestamp":1784332800,"nonce":"` + strings.Repeat("A", 43) + `","signature":"` + strings.Repeat("A", 86) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/self-revoke", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || devices.selfRevoke.DeviceID != deviceID || devices.selfRevoke.InstallationID != installationID ||
		len(devices.selfRevoke.Nonce) != 32 || len(devices.selfRevoke.Signature) != 64 {
		t.Fatalf("response=%d command=%+v body=%q", response.Code, devices.selfRevoke, response.Body.String())
	}
}

func TestHTTPCurrentLogoutTargetsOnlyCallingAccessDevice(t *testing.T) {
	userID, deviceID := uuid.New(), uuid.New()
	devices := &stubDeviceHTTPService{}
	handler := NewHandler(HTTPConfig{
		Devices: devices,
		AccessTokens: &stubAccessAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
			UserID: userID, DeviceID: deviceID, SessionID: uuid.New(), PersonalSpaceID: uuid.New(),
		}}},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/current/logout", nil)
	request.Header.Set("Authorization", "Bearer signed-access-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || devices.revokedUserID != userID || devices.revokedDeviceID != deviceID {
		t.Fatalf("logout response=%d revoked=%s/%s", response.Code, devices.revokedUserID, devices.revokedDeviceID)
	}
}

type stubDeviceHTTPService struct {
	listed          []PublicDevice
	listUserID      uuid.UUID
	listCurrentID   uuid.UUID
	revokedUserID   uuid.UUID
	revokedDeviceID uuid.UUID
	selfRevoke      SelfRevokeCommand
}

func (s *stubDeviceHTTPService) List(_ context.Context, userID, currentID uuid.UUID) ([]PublicDevice, error) {
	s.listUserID = userID
	s.listCurrentID = currentID
	return s.listed, nil
}

func (s *stubDeviceHTTPService) Revoke(_ context.Context, userID, deviceID uuid.UUID) error {
	s.revokedUserID = userID
	s.revokedDeviceID = deviceID
	return nil
}

func (s *stubDeviceHTTPService) SelfRevoke(_ context.Context, command SelfRevokeCommand) error {
	s.selfRevoke = command
	return nil
}

type stubAccessAuthenticator struct {
	claims session.AccessClaims
	err    error
}

func (s *stubAccessAuthenticator) Authenticate(context.Context, string) (session.AccessClaims, error) {
	return s.claims, s.err
}

type stubDeviceBrowserSessions struct {
	session browser.Session
	readErr error
	csrfOK  bool
}

func (s *stubDeviceBrowserSessions) Read(context.Context, *http.Request) (browser.Session, error) {
	return s.session, s.readErr
}

func (s *stubDeviceBrowserSessions) RequireCSRF(*http.Request, browser.Session) error {
	if !s.csrfOK {
		return browser.ErrCSRF
	}
	return nil
}
