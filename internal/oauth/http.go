package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/bignormal/aera-cloud/internal/browser"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const oauthRequestBodyLimit = 64 * 1024

type ServicePort interface {
	Begin(context.Context, BeginRequest) (BeginResponse, error)
	Approve(context.Context, uuid.UUID, uuid.UUID) (ApprovalResponse, error)
	Exchange(context.Context, ExchangeRequest) (session.TokenSet, error)
}

type SessionPort interface {
	Refresh(context.Context, string) (session.TokenSet, error)
	Revoke(context.Context, string) error
}

type BrowserSessionPort interface {
	Read(context.Context, *http.Request) (browser.Session, error)
	RequireCSRF(*http.Request, browser.Session) error
}

type PublishedKey struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	Purpose   string `json:"purpose"`
	X         string `json:"x"`
}

type HTTPConfig struct {
	OAuth           ServicePort
	Sessions        SessionPort
	BrowserSessions BrowserSessionPort
	SigningKeys     func() []PublishedKey
}

type httpHandler struct {
	oauth           ServicePort
	sessions        SessionPort
	browserSessions BrowserSessionPort
	signingKeys     func() []PublishedKey
}

func NewHandler(config HTTPConfig) http.Handler {
	handler := &httpHandler{
		oauth: config.OAuth, sessions: config.Sessions,
		browserSessions: config.BrowserSessions, signingKeys: config.SigningKeys,
	}
	router := chi.NewRouter()
	router.Get("/oauth/authorize", handler.begin)
	router.Post("/api/v1/oauth/authorize/approve", handler.approve)
	router.Post("/api/v1/oauth/token", handler.exchange)
	router.Post("/api/v1/oauth/refresh", handler.refresh)
	router.Post("/api/v1/oauth/revoke", handler.revoke)
	router.Get("/.well-known/agentera-signing-keys.json", handler.keys)
	return router
}

func (h *httpHandler) begin(response http.ResponseWriter, request *http.Request) {
	if h.oauth == nil {
		writeOAuthError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	promptValues := request.URL.Query()["prompt"]
	if len(promptValues) > 1 || (len(promptValues) == 1 && promptValues[0] != "select_account") {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	prompt := ""
	if len(promptValues) == 1 {
		prompt = promptValues[0]
	}
	installationID, err := uuid.Parse(request.URL.Query().Get("installation_id"))
	if err != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	devicePublicKey, ok := secure.DecodeCanonicalBase64URL(request.URL.Query().Get("device_public_key"))
	if !ok || len(devicePublicKey) != 32 {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	started, err := h.oauth.Begin(request.Context(), BeginRequest{
		ClientID: request.URL.Query().Get("client_id"), RedirectURI: request.URL.Query().Get("redirect_uri"),
		CodeChallenge: request.URL.Query().Get("code_challenge"), CodeChallengeMethod: request.URL.Query().Get("code_challenge_method"),
		State: request.URL.Query().Get("state"), InstallationID: installationID, DevicePublicKey: devicePublicKey,
		DeviceDisplayName: request.URL.Query().Get("device_name"), DevicePlatform: request.URL.Query().Get("platform"),
		AppVersion: request.URL.Query().Get("app_version"),
	})
	if err != nil {
		writeMappedOAuthError(response, err)
		return
	}
	location := &url.URL{Path: "/authorize", RawQuery: url.Values{"request_id": {started.RequestID.String()}}.Encode()}
	if prompt == "select_account" {
		location = &url.URL{Path: "/login", RawQuery: url.Values{"next": {location.String()}}.Encode()}
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(response, request, location.String(), http.StatusSeeOther)
}

func (h *httpHandler) approve(response http.ResponseWriter, request *http.Request) {
	if h.oauth == nil || h.browserSessions == nil {
		writeOAuthError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	browserSession, err := h.browserSessions.Read(request.Context(), request)
	if err != nil {
		if errors.Is(err, browser.ErrUnauthenticated) {
			writeOAuthError(response, http.StatusUnauthorized, "session_revoked")
			return
		}
		writeOAuthError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if err := h.browserSessions.RequireCSRF(request, browserSession); err != nil {
		writeOAuthError(response, http.StatusForbidden, "invalid_request")
		return
	}
	var payload struct {
		RequestID uuid.UUID `json:"request_id"`
	}
	if !decodeOAuthJSON(response, request, &payload) || payload.RequestID == uuid.Nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	approved, err := h.oauth.Approve(request.Context(), payload.RequestID, browserSession.Principal.UserID)
	if err != nil {
		writeMappedOAuthError(response, err)
		return
	}
	writeOAuthJSON(response, http.StatusOK, map[string]string{"redirect_uri": approved.RedirectURI})
}

func (h *httpHandler) exchange(response http.ResponseWriter, request *http.Request) {
	if h.oauth == nil {
		writeOAuthError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	var payload struct {
		AuthorizationCode string    `json:"authorization_code"`
		CodeVerifier      string    `json:"code_verifier"`
		InstallationID    uuid.UUID `json:"installation_id"`
		DeviceProof       string    `json:"device_proof"`
	}
	if !decodeOAuthJSON(response, request, &payload) {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	deviceProof, ok := secure.DecodeCanonicalBase64URL(payload.DeviceProof)
	if !ok || len(deviceProof) != 64 {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	tokens, err := h.oauth.Exchange(request.Context(), ExchangeRequest{
		AuthorizationCode: payload.AuthorizationCode, CodeVerifier: payload.CodeVerifier,
		InstallationID: payload.InstallationID, DeviceProof: deviceProof,
	})
	if err != nil {
		writeMappedOAuthError(response, err)
		return
	}
	writeOAuthJSON(response, http.StatusOK, tokens)
}

func (h *httpHandler) refresh(response http.ResponseWriter, request *http.Request) {
	if h.sessions == nil {
		writeOAuthError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	refreshToken, ok := decodeRefreshRequest(response, request)
	if !ok {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	tokens, err := h.sessions.Refresh(request.Context(), refreshToken)
	if err != nil {
		writeMappedOAuthError(response, err)
		return
	}
	writeOAuthJSON(response, http.StatusOK, tokens)
}

func (h *httpHandler) revoke(response http.ResponseWriter, request *http.Request) {
	if h.sessions == nil {
		writeOAuthError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	refreshToken, ok := decodeRefreshRequest(response, request)
	if !ok {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.sessions.Revoke(request.Context(), refreshToken); err != nil {
		writeMappedOAuthError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (h *httpHandler) keys(response http.ResponseWriter, _ *http.Request) {
	if h.signingKeys == nil {
		writeOAuthError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writeOAuthJSON(response, http.StatusOK, struct {
		Keys []PublishedKey `json:"keys"`
	}{Keys: h.signingKeys()})
}

func decodeRefreshRequest(response http.ResponseWriter, request *http.Request) (string, bool) {
	var payload struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeOAuthJSON(response, request, &payload) || strings.TrimSpace(payload.RefreshToken) == "" {
		return "", false
	}
	return payload.RefreshToken, true
}

func decodeOAuthJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, oauthRequestBodyLimit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func writeMappedOAuthError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrInvalidAuthorization):
		writeOAuthError(response, http.StatusBadRequest, "authorization_expired")
	case errors.Is(err, ErrAuthorizationReplayed):
		writeOAuthError(response, http.StatusConflict, "authorization_replayed")
	case errors.Is(err, ErrDeviceLimitReached):
		writeOAuthError(response, http.StatusConflict, "device_limit_reached")
	case errors.Is(err, session.ErrSessionRevoked):
		writeOAuthError(response, http.StatusUnauthorized, "session_revoked")
	default:
		writeOAuthError(response, http.StatusServiceUnavailable, "service_unavailable")
	}
}

func writeOAuthError(response http.ResponseWriter, status int, code string) {
	requestID := "unavailable"
	if generated, err := secure.RandomUUID(); err == nil {
		requestID = generated.String()
	}
	writeOAuthJSON(response, status, struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}{Error: struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}{Code: code, Message: "localized by the client", RequestID: requestID}})
}

func writeOAuthJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(payload)
}
