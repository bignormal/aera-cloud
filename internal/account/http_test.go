package account

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/browser"
	"github.com/bignormal/aera-cloud/internal/legal"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
)

func TestHTTPHandlerRegistersAccountFromStrictJSON(t *testing.T) {
	service := &stubAccountService{registration: Registration{UserID: uuid.New(), PersonalSpaceID: uuid.New()}}
	handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: &stubBrowserSessions{}, Legal: currentLegal(t)})
	request := accountJSONRequest(http.MethodPost, "/api/v1/accounts/register", `{
		"kind":"email",
		"verification_receipt":"opaque-receipt",
		"password":"correct horse battery staple",
		"nickname":"Alice",
		"terms_version":"terms-2026-07",
		"privacy_version":"privacy-2026-07"
	}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if service.registerCalls != 1 || service.lastRegister.Kind != secure.IdentityEmail ||
		service.lastRegister.VerificationReceipt != "opaque-receipt" || service.lastRegister.Nickname != "Alice" {
		t.Fatalf("Register command = %+v", service.lastRegister)
	}
	var payload Registration
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload != service.registration {
		t.Fatalf("response payload = %+v, error:%v", payload, err)
	}
}

func TestHTTPHandlerFailsClosedWhenPublicRegistrationIsDisabled(t *testing.T) {
	service := &stubAccountService{}
	handler := NewHandler(HTTPConfig{
		Accounts:             service,
		BrowserSessions:      &stubBrowserSessions{},
		Legal:                currentLegal(t),
		RegistrationDisabled: true,
	})
	request := accountJSONRequest(http.MethodPost, "/api/v1/accounts/register", `{
		"kind":"email",
		"verification_receipt":"opaque-receipt",
		"password":"correct horse battery staple",
		"nickname":"Alice",
		"terms_version":"terms-2026-07",
		"privacy_version":"privacy-2026-07"
	}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertErrorEnvelope(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if service.registerCalls != 0 {
		t.Fatalf("Register() calls = %d, want 0", service.registerCalls)
	}
}

func TestHTTPHandlerLoginCreatesBrowserSessionWithoutEchoingCredentials(t *testing.T) {
	principal := Principal{UserID: uuid.New(), PersonalSpaceID: uuid.New(), Nickname: "Alice"}
	service := &stubAccountService{principal: principal}
	sessions := &stubBrowserSessions{csrfToken: "opaque-csrf"}
	handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: sessions, Legal: currentLegal(t)})
	request := accountJSONRequest(http.MethodPost, "/api/v1/browser/login", `{
		"identity":"alice@example.com",
		"password":"correct horse battery staple"
	}`)
	request.RemoteAddr = "203.0.113.10:43210"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.loginIP != "203.0.113.10" {
		t.Fatalf("login response = %d %s; IP=%q", response.Code, response.Body.String(), service.loginIP)
	}
	if sessions.started.Principal.UserID != principal.UserID || sessions.started.Principal.PersonalSpaceID != principal.PersonalSpaceID {
		t.Fatalf("started browser session = %+v", sessions.started)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"csrf_token":"opaque-csrf"`) || strings.Contains(body, "correct horse") || strings.Contains(body, "alice@example.com") {
		t.Fatalf("login response = %s", body)
	}
}

func TestHTTPHandlerLogoutRequiresSessionAndCSRF(t *testing.T) {
	sessions := &stubBrowserSessions{
		readSession: browser.Session{Principal: browser.Principal{UserID: uuid.New(), PersonalSpaceID: uuid.New()}},
		csrfErr:     browser.ErrCSRF,
	}
	handler := NewHandler(HTTPConfig{Accounts: &stubAccountService{}, BrowserSessions: sessions, Legal: currentLegal(t)})
	request := accountJSONRequest(http.MethodPost, "/api/v1/browser/logout", `{}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assertErrorEnvelope(t, response, http.StatusForbidden, "invalid_request")
	if sessions.endCalls != 0 {
		t.Fatalf("End() calls = %d", sessions.endCalls)
	}

	sessions.csrfErr = nil
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || sessions.endCalls != 1 {
		t.Fatalf("logout response = %d %s; End calls=%d", response.Code, response.Body.String(), sessions.endCalls)
	}
}

func TestHTTPHandlerResetsPasswordAndReturnsCurrentLegalVersions(t *testing.T) {
	service := &stubAccountService{}
	legalService := currentLegal(t)
	handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: &stubBrowserSessions{}, Legal: legalService})
	reset := accountJSONRequest(http.MethodPost, "/api/v1/accounts/password/reset", `{
		"verification_receipt":"opaque-reset-receipt",
		"new_password":"new correct horse battery"
	}`)
	resetResponse := httptest.NewRecorder()
	handler.ServeHTTP(resetResponse, reset)
	if resetResponse.Code != http.StatusNoContent || service.resetReceipt != "opaque-reset-receipt" {
		t.Fatalf("reset response = %d %s", resetResponse.Code, resetResponse.Body.String())
	}

	legalRequest := httptest.NewRequest(http.MethodGet, "/api/v1/legal/current", nil)
	legalResponse := httptest.NewRecorder()
	handler.ServeHTTP(legalResponse, legalRequest)
	if legalResponse.Code != http.StatusOK || strings.TrimSpace(legalResponse.Body.String()) != `{"terms_version":"terms-2026-07","privacy_version":"privacy-2026-07"}` {
		t.Fatalf("legal response = %d %q", legalResponse.Code, legalResponse.Body.String())
	}
}

func TestHTTPHandlerMapsOnlyStablePublicErrors(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{ErrInvalidRequest, http.StatusBadRequest, "invalid_request"},
		{ErrVerificationRequired, http.StatusBadRequest, "verification_required"},
		{ErrIdentityConflict, http.StatusConflict, "identity_conflict"},
		{ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials"},
		{ErrAccountPendingDeletion, http.StatusForbidden, "account_pending_deletion"},
		{ErrAccountDisabled, http.StatusForbidden, "account_disabled"},
		{errors.New("postgres://user:secret@db/private"), http.StatusServiceUnavailable, "service_unavailable"},
	}
	for _, test := range tests {
		service := &stubAccountService{loginErr: test.err}
		handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: &stubBrowserSessions{}, Legal: currentLegal(t)})
		request := accountJSONRequest(http.MethodPost, "/api/v1/browser/login", `{"identity":"alice@example.com","password":"password-value"}`)
		request.RemoteAddr = "203.0.113.10:1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertErrorEnvelope(t, response, test.status, test.code)
		if strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "private") || strings.Contains(response.Body.String(), "alice@example.com") {
			t.Fatalf("error response leaked internal or identity data: %s", response.Body.String())
		}
	}
}

func TestHTTPHandlerRejectsUnknownFieldsAndWrongMediaType(t *testing.T) {
	service := &stubAccountService{}
	handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: &stubBrowserSessions{}, Legal: currentLegal(t)})
	requests := []*http.Request{
		accountJSONRequest(http.MethodPost, "/api/v1/browser/login", `{"identity":"alice@example.com","password":"password-value","extra":true}`),
		httptest.NewRequest(http.MethodPost, "/api/v1/browser/login", strings.NewReader(`{}`)),
	}
	for _, request := range requests {
		request.RemoteAddr = "203.0.113.10:1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertErrorEnvelope(t, response, http.StatusBadRequest, "invalid_request")
	}
	if service.loginCalls != 0 {
		t.Fatalf("AuthenticatePassword() calls = %d", service.loginCalls)
	}
}

func TestHTTPHandlerServesRedactedProfileForBrowserSession(t *testing.T) {
	userID := uuid.New()
	service := &stubAccountService{profile: Profile{
		UserID: userID, PersonalSpaceID: uuid.New(), Nickname: "Alice", Status: "active",
		IdentityKinds: []secure.IdentityKind{secure.IdentityEmail, secure.IdentityPhone}, OwnedWorkspaceCount: 2,
	}}
	sessions := &stubBrowserSessions{readSession: browser.Session{Principal: browser.Principal{UserID: userID, PersonalSpaceID: uuid.New()}}}
	handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: sessions, Legal: currentLegal(t)})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/accounts/me", nil))

	body := response.Body.String()
	if response.Code != http.StatusOK || service.profileUserID != userID || !strings.Contains(body, `"identity_kinds":["email","phone"]`) ||
		!strings.Contains(body, `"owned_workspace_count":2`) {
		t.Fatalf("profile response = %d %q, user=%s", response.Code, body, service.profileUserID)
	}
	if strings.Contains(body, "alice@example.com") || strings.Contains(body, "+861") ||
		strings.Contains(body, `"workspace_names"`) || strings.Contains(body, `"members"`) {
		t.Fatalf("profile response leaked identity or workspace detail: %s", body)
	}
}

func TestHTTPHandlerIdentityLifecycleRequiresBrowserCSRF(t *testing.T) {
	userID := uuid.New()
	service := &stubAccountService{}
	sessions := &stubBrowserSessions{readSession: browser.Session{Principal: browser.Principal{UserID: userID, PersonalSpaceID: uuid.New()}}, csrfErr: browser.ErrCSRF}
	handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: sessions, Legal: currentLegal(t)})
	request := accountJSONRequest(http.MethodPost, "/api/v1/accounts/identities/bind", `{"current_password":"current","verification_receipt":"receipt"}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertErrorEnvelope(t, response, http.StatusForbidden, "invalid_request")
	if service.bindCalls != 0 {
		t.Fatalf("BindIdentity() calls = %d", service.bindCalls)
	}
	sessions.csrfErr = nil
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || service.bindUserID != userID || service.bindPassword != "current" || service.bindReceipt != "receipt" {
		t.Fatalf("bind response=%d %q command=%s/%q/%q", response.Code, response.Body.String(), service.bindUserID, service.bindPassword, service.bindReceipt)
	}
}

func TestHTTPHandlerChangesPasswordOnlyForCurrentAccessSession(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	service := &stubAccountService{}
	authenticator := &stubAccountAccessAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
		UserID: userID, SessionID: sessionID, DeviceID: uuid.New(), PersonalSpaceID: uuid.New(),
	}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(15 * time.Minute)}}
	handler := NewHandler(HTTPConfig{
		Accounts: service, BrowserSessions: &stubBrowserSessions{}, Legal: currentLegal(t), AccessTokens: authenticator,
	})
	request := accountJSONRequest(http.MethodPost, "/api/v1/accounts/password/change", `{"current_password":"current","new_password":"new correct horse battery"}`)
	request.Header.Set("Authorization", "Bearer signed-access-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || service.changeUserID != userID || service.changeSessionID != sessionID {
		t.Fatalf("change response=%d %q command=%s/%s", response.Code, response.Body.String(), service.changeUserID, service.changeSessionID)
	}
}

func TestHTTPHandlerDeletionEndsBrowserSessionAndRecoveryIsPublic(t *testing.T) {
	userID := uuid.New()
	service := &stubAccountService{}
	sessions := &stubBrowserSessions{readSession: browser.Session{Principal: browser.Principal{UserID: userID, PersonalSpaceID: uuid.New()}}}
	handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: sessions, Legal: currentLegal(t)})
	request := accountJSONRequest(http.MethodPost, "/api/v1/accounts/deletion", `{"current_password":"current","verification_receipt":"delete-receipt"}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || service.deleteUserID != userID || sessions.endCalls != 1 {
		t.Fatalf("deletion response=%d %q user=%s end=%d", response.Code, response.Body.String(), service.deleteUserID, sessions.endCalls)
	}
	recoverRequest := accountJSONRequest(http.MethodPost, "/api/v1/accounts/deletion/recover", `{"identity":"alice@example.com","password":"current","verification_receipt":"recover-receipt"}`)
	recoverResponse := httptest.NewRecorder()
	handler.ServeHTTP(recoverResponse, recoverRequest)
	if recoverResponse.Code != http.StatusNoContent || service.recoverIdentity != "alice@example.com" || service.recoverReceipt != "recover-receipt" {
		t.Fatalf("recovery response=%d %q", recoverResponse.Code, recoverResponse.Body.String())
	}
}

func TestHTTPHandlerDeletionOwnershipConflictReturnsOnlySafeCount(t *testing.T) {
	userID := uuid.New()
	service := &stubAccountService{deleteErr: &OrganizationOwnerTransferRequiredError{OwnedOrganizationCount: 2}}
	sessions := &stubBrowserSessions{readSession: browser.Session{Principal: browser.Principal{UserID: userID, PersonalSpaceID: uuid.New()}}}
	handler := NewHandler(HTTPConfig{Accounts: service, BrowserSessions: sessions, Legal: currentLegal(t)})
	request := accountJSONRequest(http.MethodPost, "/api/v1/accounts/deletion", `{"current_password":"current","verification_receipt":"delete-receipt"}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusConflict || sessions.endCalls != 0 {
		t.Fatalf("deletion response=%d %q end=%d", response.Code, response.Body.String(), sessions.endCalls)
	}
	var payload struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error["code"] != "organization_owner_transfer_required" || payload.Error["owned_organization_count"] != float64(2) {
		t.Fatalf("error payload = %+v", payload.Error)
	}
	for _, forbidden := range []string{"organization_id", "organization_name", "members", "owner_id", "owner@example.com"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("ownership response leaked %q: %s", forbidden, response.Body.String())
		}
	}
}

type stubAccountService struct {
	registration    Registration
	registerErr     error
	registerCalls   int
	lastRegister    RegisterCommand
	principal       Principal
	loginErr        error
	loginCalls      int
	loginIP         string
	resetErr        error
	resetReceipt    string
	profile         Profile
	profileUserID   uuid.UUID
	bindCalls       int
	bindUserID      uuid.UUID
	bindPassword    string
	bindReceipt     string
	removeUserID    uuid.UUID
	removeKind      secure.IdentityKind
	changeUserID    uuid.UUID
	changeSessionID uuid.UUID
	deleteUserID    uuid.UUID
	deleteErr       error
	recoverIdentity string
	recoverReceipt  string
}

func (s *stubAccountService) Register(_ context.Context, command RegisterCommand) (Registration, error) {
	s.registerCalls++
	s.lastRegister = command
	return s.registration, s.registerErr
}

func (s *stubAccountService) AuthenticatePassword(ctx context.Context, _, _ string) (Principal, error) {
	s.loginCalls++
	s.loginIP = loginIPAddress(ctx)
	return s.principal, s.loginErr
}

func (s *stubAccountService) ResetPassword(_ context.Context, receipt, _ string) error {
	s.resetReceipt = receipt
	return s.resetErr
}

func (s *stubAccountService) Profile(_ context.Context, userID uuid.UUID) (Profile, error) {
	s.profileUserID = userID
	return s.profile, nil
}

func (s *stubAccountService) BindIdentity(_ context.Context, userID uuid.UUID, password, receipt string) error {
	s.bindCalls++
	s.bindUserID, s.bindPassword, s.bindReceipt = userID, password, receipt
	return nil
}

func (s *stubAccountService) RemoveIdentity(_ context.Context, userID uuid.UUID, kind secure.IdentityKind, _ string) error {
	s.removeUserID, s.removeKind = userID, kind
	return nil
}

func (s *stubAccountService) ChangePassword(_ context.Context, userID, sessionID uuid.UUID, _, _ string) error {
	s.changeUserID, s.changeSessionID = userID, sessionID
	return nil
}

func (s *stubAccountService) RequestDeletion(_ context.Context, userID uuid.UUID, _, _ string) error {
	s.deleteUserID = userID
	return s.deleteErr
}

func (s *stubAccountService) RecoverDeletion(_ context.Context, identity, _ string, receipt string) error {
	s.recoverIdentity, s.recoverReceipt = identity, receipt
	return nil
}

type stubAccountAccessAuthenticator struct {
	claims session.AccessClaims
	err    error
}

func (s *stubAccountAccessAuthenticator) Authenticate(context.Context, string) (session.AccessClaims, error) {
	return s.claims, s.err
}

type stubBrowserSessions struct {
	csrfToken   string
	startErr    error
	started     browser.Session
	readSession browser.Session
	readErr     error
	csrfErr     error
	endErr      error
	endCalls    int
}

func (s *stubBrowserSessions) Start(_ context.Context, _ http.ResponseWriter, principal browser.Principal) (string, error) {
	s.started = browser.Session{Principal: principal}
	return s.csrfToken, s.startErr
}

func (s *stubBrowserSessions) Read(context.Context, *http.Request) (browser.Session, error) {
	return s.readSession, s.readErr
}

func (s *stubBrowserSessions) RequireCSRF(*http.Request, browser.Session) error {
	return s.csrfErr
}

func (s *stubBrowserSessions) End(context.Context, http.ResponseWriter, *http.Request) error {
	s.endCalls++
	return s.endErr
}

func currentLegal(t *testing.T) *legal.Service {
	t.Helper()
	service, err := legal.NewService("terms-2026-07", "privacy-2026-07")
	if err != nil {
		t.Fatalf("legal.NewService() error = %v", err)
	}
	return service
}

func accountJSONRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func assertErrorEnvelope(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	var payload struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if payload.Error.Code != code || payload.Error.Message != "localized by the client" || payload.Error.RequestID == "" {
		t.Fatalf("error envelope = %+v", payload.Error)
	}
}
