package device

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/bignormal/aera-cloud/internal/browser"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const deviceRequestBodyLimit = 64 * 1024

type HTTPService interface {
	List(context.Context, uuid.UUID, uuid.UUID) ([]PublicDevice, error)
	Revoke(context.Context, uuid.UUID, uuid.UUID) error
	SelfRevoke(context.Context, SelfRevokeCommand) error
}

type AccessAuthenticator interface {
	Authenticate(context.Context, string) (session.AccessClaims, error)
}

type BrowserSessionPort interface {
	Read(context.Context, *http.Request) (browser.Session, error)
	RequireCSRF(*http.Request, browser.Session) error
}

type HTTPConfig struct {
	Devices         HTTPService
	AccessTokens    AccessAuthenticator
	BrowserSessions BrowserSessionPort
}

type httpHandler struct {
	devices         HTTPService
	accessTokens    AccessAuthenticator
	browserSessions BrowserSessionPort
}

type requestPrincipal struct {
	userID   uuid.UUID
	deviceID uuid.UUID
}

func NewHandler(config HTTPConfig) http.Handler {
	handler := &httpHandler{
		devices: config.Devices, accessTokens: config.AccessTokens, browserSessions: config.BrowserSessions,
	}
	router := chi.NewRouter()
	router.Get("/api/v1/devices", handler.list)
	router.Delete("/api/v1/devices/{deviceID}", handler.revoke)
	router.Post("/api/v1/devices/current/logout", handler.logoutCurrent)
	router.Post("/api/v1/devices/self-revoke", handler.selfRevoke)
	return router
}

func (h *httpHandler) list(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request, false, false)
	if !ok {
		return
	}
	devices, err := h.devices.List(request.Context(), principal.userID, principal.deviceID)
	if err != nil {
		writeDeviceServiceError(response, err)
		return
	}
	writeDeviceJSON(response, http.StatusOK, struct {
		Devices []PublicDevice `json:"devices"`
	}{Devices: devices})
}

func (h *httpHandler) revoke(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request, true, false)
	if !ok {
		return
	}
	deviceID, err := uuid.Parse(chi.URLParam(request, "deviceID"))
	if err != nil {
		writeDeviceError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.devices.Revoke(request.Context(), principal.userID, deviceID); err != nil {
		writeDeviceServiceError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (h *httpHandler) logoutCurrent(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request, false, true)
	if !ok {
		return
	}
	if err := h.devices.Revoke(request.Context(), principal.userID, principal.deviceID); err != nil {
		writeDeviceServiceError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (h *httpHandler) selfRevoke(response http.ResponseWriter, request *http.Request) {
	if h.devices == nil {
		writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	var payload struct {
		DeviceID       uuid.UUID `json:"device_id"`
		InstallationID uuid.UUID `json:"installation_id"`
		Timestamp      int64     `json:"timestamp"`
		Nonce          string    `json:"nonce"`
		Signature      string    `json:"signature"`
	}
	if !decodeDeviceJSON(response, request, &payload) {
		writeDeviceError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	nonce, nonceOK := decodeDeviceBase64(payload.Nonce, 32)
	signature, signatureOK := decodeDeviceBase64(payload.Signature, 64)
	if !nonceOK || !signatureOK {
		writeDeviceError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	err := h.devices.SelfRevoke(request.Context(), SelfRevokeCommand{
		DeviceID: payload.DeviceID, InstallationID: payload.InstallationID,
		Timestamp: payload.Timestamp, Nonce: nonce, Signature: signature,
	})
	if err != nil {
		writeDeviceServiceError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (h *httpHandler) authorize(
	response http.ResponseWriter,
	request *http.Request,
	requireBrowserCSRF bool,
	requireAccessToken bool,
) (requestPrincipal, bool) {
	if h.devices == nil {
		writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
		return requestPrincipal{}, false
	}
	authorizationValues := request.Header.Values("Authorization")
	if len(authorizationValues) > 0 || requireAccessToken {
		if h.accessTokens == nil || len(authorizationValues) != 1 || !strings.HasPrefix(authorizationValues[0], "Bearer ") ||
			strings.TrimSpace(strings.TrimPrefix(authorizationValues[0], "Bearer ")) == "" {
			writeDeviceError(response, http.StatusUnauthorized, "session_revoked")
			return requestPrincipal{}, false
		}
		token := strings.TrimSpace(strings.TrimPrefix(authorizationValues[0], "Bearer "))
		if strings.ContainsAny(token, " \t\r\n") {
			writeDeviceError(response, http.StatusUnauthorized, "session_revoked")
			return requestPrincipal{}, false
		}
		claims, err := h.accessTokens.Authenticate(request.Context(), token)
		if err != nil {
			if errors.Is(err, session.ErrInvalidAccessToken) || errors.Is(err, session.ErrSessionRevoked) {
				writeDeviceError(response, http.StatusUnauthorized, "session_revoked")
			} else {
				writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
			}
			return requestPrincipal{}, false
		}
		return requestPrincipal{userID: claims.UserID, deviceID: claims.DeviceID}, true
	}
	if h.browserSessions == nil {
		writeDeviceError(response, http.StatusUnauthorized, "session_revoked")
		return requestPrincipal{}, false
	}
	browserSession, err := h.browserSessions.Read(request.Context(), request)
	if err != nil {
		if errors.Is(err, browser.ErrUnauthenticated) {
			writeDeviceError(response, http.StatusUnauthorized, "session_revoked")
		} else {
			writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
		}
		return requestPrincipal{}, false
	}
	if requireBrowserCSRF && h.browserSessions.RequireCSRF(request, browserSession) != nil {
		writeDeviceError(response, http.StatusForbidden, "invalid_request")
		return requestPrincipal{}, false
	}
	return requestPrincipal{userID: browserSession.Principal.UserID}, true
}

func decodeDeviceJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, deviceRequestBodyLimit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func decodeDeviceBase64(value string, expectedLength int) ([]byte, bool) {
	decoded, ok := secure.DecodeCanonicalBase64URL(value)
	return decoded, ok && len(decoded) == expectedLength
}

func writeDeviceServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidDevice):
		writeDeviceError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrDeviceNotFound):
		writeDeviceError(response, http.StatusNotFound, "device_not_found")
	case errors.Is(err, ErrAccountUnavailable):
		writeDeviceError(response, http.StatusUnauthorized, "session_revoked")
	case errors.Is(err, ErrSelfRevokeReplay):
		writeDeviceError(response, http.StatusConflict, "self_revoke_replayed")
	default:
		writeDeviceError(response, http.StatusServiceUnavailable, "service_unavailable")
	}
}

func writeDeviceError(response http.ResponseWriter, status int, code string) {
	requestID := "unavailable"
	if generated, err := secure.RandomUUID(); err == nil {
		requestID = generated.String()
	}
	writeDeviceJSON(response, status, struct {
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

func writeDeviceJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(payload)
}
