package account

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/bignormal/aera-cloud/internal/browser"
	"github.com/bignormal/aera-cloud/internal/legal"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const accountRequestBodyLimit = 64 * 1024

type ServicePort interface {
	Register(context.Context, RegisterCommand) (Registration, error)
	AuthenticatePassword(context.Context, string, string) (Principal, error)
	ResetPassword(context.Context, string, string) error
}

type BrowserSessionPort interface {
	Start(context.Context, http.ResponseWriter, browser.Principal) (string, error)
	Read(context.Context, *http.Request) (browser.Session, error)
	RequireCSRF(*http.Request, browser.Session) error
	End(context.Context, http.ResponseWriter, *http.Request) error
}

type LegalPort interface {
	Current() legal.CurrentDocuments
}

type HTTPConfig struct {
	Accounts        ServicePort
	BrowserSessions BrowserSessionPort
	Legal           LegalPort
}

type httpHandler struct {
	accounts        ServicePort
	browserSessions BrowserSessionPort
	legal           LegalPort
}

func NewHandler(config HTTPConfig) http.Handler {
	handler := &httpHandler{
		accounts: config.Accounts, browserSessions: config.BrowserSessions, legal: config.Legal,
	}
	router := chi.NewRouter()
	router.Post("/api/v1/accounts/register", handler.register)
	router.Post("/api/v1/browser/login", handler.login)
	router.Post("/api/v1/browser/logout", handler.logout)
	router.Post("/api/v1/accounts/password/reset", handler.resetPassword)
	router.Get("/api/v1/legal/current", handler.currentLegal)
	return router
}

func (h *httpHandler) register(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		Kind                secure.IdentityKind `json:"kind"`
		VerificationReceipt string              `json:"verification_receipt"`
		Password            string              `json:"password"`
		Nickname            string              `json:"nickname"`
		TermsVersion        string              `json:"terms_version"`
		PrivacyVersion      string              `json:"privacy_version"`
	}
	if h.accounts == nil || !decodeAccountJSON(response, request, &payload) {
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	registration, err := h.accounts.Register(request.Context(), RegisterCommand{
		Kind: payload.Kind, VerificationReceipt: payload.VerificationReceipt, Password: payload.Password,
		Nickname: payload.Nickname, TermsVersion: payload.TermsVersion, PrivacyVersion: payload.PrivacyVersion,
	})
	if err != nil {
		writeMappedAccountError(response, err)
		return
	}
	writeAccountJSON(response, http.StatusCreated, registration)
}

func (h *httpHandler) login(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		Identity string `json:"identity"`
		Password string `json:"password"`
	}
	if h.accounts == nil || h.browserSessions == nil || !decodeAccountJSON(response, request, &payload) {
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx := WithLoginIPAddress(request.Context(), remoteIP(request.RemoteAddr))
	principal, err := h.accounts.AuthenticatePassword(ctx, payload.Identity, payload.Password)
	if err != nil {
		writeMappedAccountError(response, err)
		return
	}
	csrfToken, err := h.browserSessions.Start(request.Context(), response, browser.Principal{
		UserID: principal.UserID, PersonalSpaceID: principal.PersonalSpaceID, Nickname: principal.Nickname,
	})
	if err != nil {
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writeAccountJSON(response, http.StatusOK, struct {
		UserID          uuid.UUID `json:"user_id"`
		PersonalSpaceID uuid.UUID `json:"personal_space_id"`
		Nickname        string    `json:"nickname,omitempty"`
		CSRFToken       string    `json:"csrf_token"`
	}{
		UserID: principal.UserID, PersonalSpaceID: principal.PersonalSpaceID,
		Nickname: principal.Nickname, CSRFToken: csrfToken,
	})
}

func (h *httpHandler) logout(response http.ResponseWriter, request *http.Request) {
	if h.browserSessions == nil {
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	session, err := h.browserSessions.Read(request.Context(), request)
	if err != nil {
		if errors.Is(err, browser.ErrUnauthenticated) {
			writeAccountError(response, http.StatusUnauthorized, "session_revoked")
			return
		}
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if err := h.browserSessions.RequireCSRF(request, session); err != nil {
		writeAccountError(response, http.StatusForbidden, "invalid_request")
		return
	}
	if err := h.browserSessions.End(request.Context(), response, request); err != nil {
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (h *httpHandler) resetPassword(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		VerificationReceipt string `json:"verification_receipt"`
		NewPassword         string `json:"new_password"`
	}
	if h.accounts == nil || !decodeAccountJSON(response, request, &payload) {
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.accounts.ResetPassword(request.Context(), payload.VerificationReceipt, payload.NewPassword); err != nil {
		writeMappedAccountError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (h *httpHandler) currentLegal(response http.ResponseWriter, _ *http.Request) {
	if h.legal == nil {
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writeAccountJSON(response, http.StatusOK, h.legal.Current())
}

func decodeAccountJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, accountRequestBodyLimit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func writeMappedAccountError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrVerificationRequired):
		writeAccountError(response, http.StatusBadRequest, "verification_required")
	case errors.Is(err, ErrIdentityConflict):
		writeAccountError(response, http.StatusConflict, "identity_conflict")
	case errors.Is(err, ErrInvalidCredentials):
		writeAccountError(response, http.StatusUnauthorized, "invalid_credentials")
	case errors.Is(err, ErrAccountPendingDeletion):
		writeAccountError(response, http.StatusForbidden, "account_pending_deletion")
	case errors.Is(err, ErrAccountDisabled):
		writeAccountError(response, http.StatusForbidden, "account_disabled")
	default:
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
	}
}

func writeAccountError(response http.ResponseWriter, status int, code string) {
	writeAccountJSON(response, status, struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}{
		Error: struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		}{Code: code, Message: "localized by the client", RequestID: newRequestID()},
	})
}

func newRequestID() string {
	identifier, err := secure.RandomUUID()
	if err != nil {
		return "unavailable"
	}
	return identifier.String()
}

func writeAccountJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(payload)
}

func remoteIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddress))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddress)
}
