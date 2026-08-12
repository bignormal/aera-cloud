package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/browser"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
)

func TestHTTPAuthorizeStartsRequestThenRemovesProtocolSecretsFromBrowserURL(t *testing.T) {
	requestID := uuid.New()
	service := &stubOAuthService{beginResponse: BeginResponse{RequestID: requestID, ExpiresAt: time.Now().Add(10 * time.Minute)}}
	handler := NewHandler(HTTPConfig{OAuth: service})
	query := url.Values{
		"client_id":             {DesktopClientID},
		"redirect_uri":          {"http://127.0.0.1:43123/agentera/oauth/callback"},
		"code_challenge":        {strings.Repeat("c", 43)},
		"code_challenge_method": {"S256"},
		"state":                 {strings.Repeat("s", 48)},
		"installation_id":       {uuid.NewString()},
		"device_public_key":     {base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		"device_name":           {"Alice Mac"},
		"platform":              {"darwin"},
		"app_version":           {"0.1.0"},
	}
	request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	location := response.Header().Get("Location")
	if location != "/authorize?request_id="+requestID.String() || strings.Contains(location, query.Get("state")) || strings.Contains(location, query.Get("device_public_key")) {
		t.Fatalf("Location = %q", location)
	}
	if service.beginRequest.ClientID != DesktopClientID || service.beginRequest.InstallationID == uuid.Nil {
		t.Fatalf("Begin request = %+v", service.beginRequest)
	}
}

func TestHTTPAuthorizeSelectAccountForcesFreshBrowserLogin(t *testing.T) {
	requestID := uuid.New()
	service := &stubOAuthService{beginResponse: BeginResponse{RequestID: requestID, ExpiresAt: time.Now().Add(10 * time.Minute)}}
	handler := NewHandler(HTTPConfig{OAuth: service})
	query := url.Values{
		"client_id":             {DesktopClientID},
		"redirect_uri":          {"http://127.0.0.1:43123/agentera/oauth/callback"},
		"code_challenge":        {strings.Repeat("c", 43)},
		"code_challenge_method": {"S256"},
		"state":                 {strings.Repeat("s", 48)},
		"installation_id":       {uuid.NewString()},
		"device_public_key":     {base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		"device_name":           {"Alice Mac"},
		"platform":              {"darwin"},
		"app_version":           {"0.1.0"},
		"prompt":                {"select_account"},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil))

	wantNext := "/authorize?request_id=" + requestID.String()
	wantLocation := (&url.URL{Path: "/login", RawQuery: url.Values{"next": {wantNext}}.Encode()}).String()
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != wantLocation {
		t.Fatalf("response = %d Location %q, want %q", response.Code, response.Header().Get("Location"), wantLocation)
	}
	if strings.Contains(response.Header().Get("Location"), query.Get("state")) || strings.Contains(response.Header().Get("Location"), query.Get("device_public_key")) {
		t.Fatalf("Location leaks protocol material: %q", response.Header().Get("Location"))
	}

	query.Set("prompt", "silent")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil))
	assertOAuthError(t, response, http.StatusBadRequest, "invalid_request")

	query["prompt"] = []string{"select_account", "silent"}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil))
	assertOAuthError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestHTTPRejectsNonCanonicalDeviceKeyAndProofEncodings(t *testing.T) {
	service := &stubOAuthService{}
	handler := NewHandler(HTTPConfig{OAuth: service})
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	query := url.Values{
		"client_id":             {DesktopClientID},
		"redirect_uri":          {"http://127.0.0.1:43123/agentera/oauth/callback"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		"code_challenge_method": {"S256"},
		"state":                 {strings.Repeat("s", 48)},
		"installation_id":       {uuid.NewString()},
		"device_public_key":     {testkit.NonCanonicalBase64URLAlias(t, publicKey)},
		"device_name":           {"Alice Mac"},
		"platform":              {"darwin"},
		"app_version":           {"0.1.0"},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil))
	assertOAuthError(t, response, http.StatusBadRequest, "invalid_request")
	if service.beginRequest.InstallationID != uuid.Nil {
		t.Fatal("Begin() received a noncanonical device public key")
	}

	proof := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	body := `{"authorization_code":"opaque-code","code_verifier":"` + strings.Repeat("v", 64) +
		`","installation_id":"` + uuid.NewString() + `","device_proof":"` +
		testkit.NonCanonicalBase64URLAlias(t, proof) + `"}`
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, oauthJSONRequest(http.MethodPost, "/api/v1/oauth/token", body))
	assertOAuthError(t, response, http.StatusBadRequest, "invalid_request")
	if service.exchange.InstallationID != uuid.Nil {
		t.Fatal("Exchange() received a noncanonical device proof")
	}
}

func TestHTTPApproveRequiresBrowserSessionAndCSRF(t *testing.T) {
	userID := uuid.New()
	requestID := uuid.New()
	service := &stubOAuthService{approval: ApprovalResponse{RedirectURI: "http://127.0.0.1:43123/agentera/oauth/callback?code=opaque&state=original"}}
	browserSessions := &stubOAuthBrowserSessions{
		readSession: browser.Session{Principal: browser.Principal{UserID: userID, PersonalSpaceID: uuid.New()}},
	}
	handler := NewHandler(HTTPConfig{OAuth: service, BrowserSessions: browserSessions})
	request := oauthJSONRequest(http.MethodPost, "/api/v1/oauth/authorize/approve", `{"request_id":"`+requestID.String()+`"}`)
	request.Header.Set(browser.CSRFHeader, "opaque-csrf")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.approvedRequestID != requestID || service.approvedUserID != userID {
		t.Fatalf("approve response = %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"redirect_uri"`) || strings.Contains(response.Body.String(), "access_token") {
		t.Fatalf("approve body = %s", response.Body.String())
	}
}

func TestHTTPTokenRefreshRevokeAndSigningKeys(t *testing.T) {
	userID := uuid.New()
	spaceID := uuid.New()
	deviceID := uuid.New()
	tokens := session.TokenSet{
		AccessToken: "access", AccessExpiresAt: time.Date(2026, 7, 18, 6, 15, 0, 0, time.UTC),
		RefreshToken: "refresh", RefreshExpiresAt: time.Date(2026, 8, 17, 6, 0, 0, 0, time.UTC),
		OfflineEntitlement: "offline", OfflineExpiresAt: time.Date(2026, 7, 25, 6, 0, 0, 0, time.UTC),
		UserID: userID, PersonalSpaceID: spaceID, DeviceID: deviceID, SessionID: uuid.New(),
	}
	oauthService := &stubOAuthService{tokens: tokens}
	sessionService := &stubOAuthSessionService{tokens: tokens}
	handler := NewHandler(HTTPConfig{
		OAuth: oauthService, Sessions: sessionService,
		SigningKeys: func() []PublishedKey {
			return []PublishedKey{
				{KeyID: "access-v1", KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig", Purpose: "access", X: "access"},
				{KeyID: "offline-v1", KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig", Purpose: "offline_entitlement", X: "offline"},
				{KeyID: "agent-control-v1", KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig", Purpose: "agent_version", X: "agent"},
				{KeyID: "agent-control-v1", KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig", Purpose: "agent_policy", X: "agent"},
				{KeyID: "agent-control-v1", KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig", Purpose: "organization_policy", X: "agent"},
			}
		},
	})
	installationID := uuid.New()
	tokenRequest := oauthJSONRequest(http.MethodPost, "/api/v1/oauth/token", `{
		"authorization_code":"opaque-code",
		"code_verifier":"`+strings.Repeat("v", 64)+`",
		"installation_id":"`+installationID.String()+`",
		"device_proof":"`+base64.RawURLEncoding.EncodeToString(make([]byte, 64))+`"
	}`)
	tokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK || oauthService.exchange.InstallationID != installationID {
		t.Fatalf("token response = %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokenPayload map[string]any
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokenPayload); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if len(tokenPayload) != 9 || tokenPayload["access_token"] != "access" {
		t.Fatalf("token payload = %+v", tokenPayload)
	}
	if _, present := tokenPayload["session_id"]; present {
		t.Fatal("wire token response exposed internal session ID")
	}

	refreshResponse := httptest.NewRecorder()
	handler.ServeHTTP(refreshResponse, oauthJSONRequest(http.MethodPost, "/api/v1/oauth/refresh", `{"refresh_token":"refresh"}`))
	if refreshResponse.Code != http.StatusOK || sessionService.refreshed != "refresh" {
		t.Fatalf("refresh response = %d %s", refreshResponse.Code, refreshResponse.Body.String())
	}
	revokeResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokeResponse, oauthJSONRequest(http.MethodPost, "/api/v1/oauth/revoke", `{"refresh_token":"refresh"}`))
	if revokeResponse.Code != http.StatusNoContent || sessionService.revoked != "refresh" {
		t.Fatalf("revoke response = %d %s", revokeResponse.Code, revokeResponse.Body.String())
	}
	keysResponse := httptest.NewRecorder()
	handler.ServeHTTP(keysResponse, httptest.NewRequest(http.MethodGet, "/.well-known/agentera-signing-keys.json", nil))
	if keysResponse.Code != http.StatusOK ||
		!strings.Contains(keysResponse.Body.String(), `"purpose":"access"`) ||
		!strings.Contains(keysResponse.Body.String(), `"purpose":"offline_entitlement"`) ||
		!strings.Contains(keysResponse.Body.String(), `"purpose":"agent_version"`) ||
		!strings.Contains(keysResponse.Body.String(), `"purpose":"agent_policy"`) ||
		!strings.Contains(keysResponse.Body.String(), `"purpose":"organization_policy"`) {
		t.Fatalf("keys response = %d %s", keysResponse.Code, keysResponse.Body.String())
	}
}

func TestHTTPMapsOAuthReplayDeviceLimitAndSessionRevocation(t *testing.T) {
	tests := []struct {
		oauthErr   error
		sessionErr error
		path       string
		body       string
		status     int
		code       string
	}{
		{oauthErr: ErrUnavailable, path: "/api/v1/oauth/token", body: validTokenBody(), status: http.StatusServiceUnavailable, code: "service_unavailable"},
		{oauthErr: ErrDeviceConflict, path: "/api/v1/oauth/token", body: validTokenBody(), status: http.StatusConflict, code: "device_conflict"},
		{oauthErr: ErrAuthorizationReplayed, path: "/api/v1/oauth/token", body: validTokenBody(), status: http.StatusConflict, code: "authorization_replayed"},
		{oauthErr: ErrDeviceLimitReached, path: "/api/v1/oauth/token", body: validTokenBody(), status: http.StatusConflict, code: "device_limit_reached"},
		{sessionErr: session.ErrSessionRevoked, path: "/api/v1/oauth/refresh", body: `{"refresh_token":"opaque"}`, status: http.StatusUnauthorized, code: "session_revoked"},
		{sessionErr: session.ErrAccountPendingDeletion, path: "/api/v1/oauth/refresh", body: `{"refresh_token":"opaque"}`, status: http.StatusForbidden, code: "account_pending_deletion"},
		{sessionErr: session.ErrAccountDisabled, path: "/api/v1/oauth/refresh", body: `{"refresh_token":"opaque"}`, status: http.StatusForbidden, code: "account_disabled"},
	}
	for _, test := range tests {
		handler := NewHandler(HTTPConfig{
			OAuth:    &stubOAuthService{exchangeErr: test.oauthErr},
			Sessions: &stubOAuthSessionService{err: test.sessionErr},
		})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, oauthJSONRequest(http.MethodPost, test.path, test.body))
		assertOAuthError(t, response, test.status, test.code)
	}
}

type stubOAuthService struct {
	beginResponse     BeginResponse
	beginRequest      BeginRequest
	approval          ApprovalResponse
	approvedRequestID uuid.UUID
	approvedUserID    uuid.UUID
	tokens            session.TokenSet
	exchange          ExchangeRequest
	exchangeErr       error
}

func (s *stubOAuthService) Begin(_ context.Context, request BeginRequest) (BeginResponse, error) {
	s.beginRequest = request
	return s.beginResponse, nil
}

func (s *stubOAuthService) Approve(_ context.Context, requestID, userID uuid.UUID) (ApprovalResponse, error) {
	s.approvedRequestID = requestID
	s.approvedUserID = userID
	return s.approval, nil
}

func (s *stubOAuthService) Exchange(_ context.Context, request ExchangeRequest) (session.TokenSet, error) {
	s.exchange = request
	return s.tokens, s.exchangeErr
}

type stubOAuthSessionService struct {
	tokens    session.TokenSet
	err       error
	refreshed string
	revoked   string
}

func (s *stubOAuthSessionService) Refresh(_ context.Context, token string) (session.TokenSet, error) {
	s.refreshed = token
	return s.tokens, s.err
}

func (s *stubOAuthSessionService) Revoke(_ context.Context, token string) error {
	s.revoked = token
	return s.err
}

type stubOAuthBrowserSessions struct {
	readSession browser.Session
	readErr     error
	csrfErr     error
}

func (s *stubOAuthBrowserSessions) Read(context.Context, *http.Request) (browser.Session, error) {
	return s.readSession, s.readErr
}

func (s *stubOAuthBrowserSessions) RequireCSRF(*http.Request, browser.Session) error {
	return s.csrfErr
}

func oauthJSONRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func validTokenBody() string {
	return `{"authorization_code":"opaque-code","code_verifier":"` + strings.Repeat("v", 64) + `","installation_id":"` + uuid.NewString() + `","device_proof":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `"}`
}

func assertOAuthError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Error.Code != code {
		t.Fatalf("error payload = %+v, error=%v", payload, err)
	}
}
