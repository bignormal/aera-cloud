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
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const accountRequestBodyLimit = 64 * 1024

type ServicePort interface {
	Profile(context.Context, uuid.UUID) (Profile, error)
	Register(context.Context, RegisterCommand) (Registration, error)
	AuthenticatePassword(context.Context, string, string) (Principal, error)
	ResetPassword(context.Context, string, string) error
	BindIdentity(context.Context, uuid.UUID, string, string) error
	RemoveIdentity(context.Context, uuid.UUID, secure.IdentityKind, string) error
	ChangePassword(context.Context, uuid.UUID, uuid.UUID, string, string) error
	RequestDeletion(context.Context, uuid.UUID, string, string) error
	RecoverDeletion(context.Context, string, string, string) error
}

type AccessAuthenticator interface {
	Authenticate(context.Context, string) (session.AccessClaims, error)
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
	Accounts             ServicePort
	BrowserSessions      BrowserSessionPort
	Legal                LegalPort
	AccessTokens         AccessAuthenticator
	RegistrationDisabled bool
}

type httpHandler struct {
	accounts             ServicePort
	browserSessions      BrowserSessionPort
	legal                LegalPort
	accessTokens         AccessAuthenticator
	registrationDisabled bool
}

func NewHandler(config HTTPConfig) http.Handler {
	handler := &httpHandler{
		accounts: config.Accounts, browserSessions: config.BrowserSessions, legal: config.Legal,
		accessTokens: config.AccessTokens, registrationDisabled: config.RegistrationDisabled,
	}
	router := chi.NewRouter()
	router.Post("/api/v1/accounts/register", handler.register)
	router.Post("/api/v1/browser/login", handler.login)
	router.Post("/api/v1/browser/logout", handler.logout)
	router.Post("/api/v1/accounts/password/reset", handler.resetPassword)
	router.Get("/api/v1/accounts/me", handler.profile)
	router.Post("/api/v1/accounts/identities/bind", handler.bindIdentity)
	router.Delete("/api/v1/accounts/identities/{kind}", handler.removeIdentity)
	router.Post("/api/v1/accounts/password/change", handler.changePassword)
	router.Post("/api/v1/accounts/deletion", handler.requestDeletion)
	router.Post("/api/v1/accounts/deletion/recover", handler.recoverDeletion)
	router.Get("/api/v1/legal/current", handler.currentLegal)
	return router
}

func (h *httpHandler) profile(response http.ResponseWriter, request *http.Request) {
	browserSession, ok := h.authorizeBrowser(response, request, false)
	if !ok {
		return
	}
	profile, err := h.accounts.Profile(request.Context(), browserSession.Principal.UserID)
	if err != nil {
		writeMappedAccountError(response, err)
		return
	}
	writeAccountJSON(response, http.StatusOK, profile)
}

func (h *httpHandler) bindIdentity(response http.ResponseWriter, request *http.Request) {
	browserSession, ok := h.authorizeBrowser(response, request, true)
	if !ok {
		return
	}
	var payload struct {
		CurrentPassword     string `json:"current_password"`
		VerificationReceipt string `json:"verification_receipt"`
	}
	if !decodeAccountJSON(response, request, &payload) {
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.accounts.BindIdentity(
		request.Context(), browserSession.Principal.UserID, payload.CurrentPassword, payload.VerificationReceipt,
	); err != nil {
		writeMappedAccountError(response, err)
		return
	}
	writeAccountNoContent(response)
}

func (h *httpHandler) removeIdentity(response http.ResponseWriter, request *http.Request) {
	browserSession, ok := h.authorizeBrowser(response, request, true)
	if !ok {
		return
	}
	kind := secure.IdentityKind(chi.URLParam(request, "kind"))
	var payload struct {
		CurrentPassword string `json:"current_password"`
	}
	if !decodeAccountJSON(response, request, &payload) {
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.accounts.RemoveIdentity(request.Context(), browserSession.Principal.UserID, kind, payload.CurrentPassword); err != nil {
		writeMappedAccountError(response, err)
		return
	}
	writeAccountNoContent(response)
}

func (h *httpHandler) changePassword(response http.ResponseWriter, request *http.Request) {
	claims, ok := h.authorizeAccess(response, request)
	if !ok {
		return
	}
	var payload struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeAccountJSON(response, request, &payload) {
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.accounts.ChangePassword(
		request.Context(), claims.UserID, claims.SessionID, payload.CurrentPassword, payload.NewPassword,
	); err != nil {
		writeMappedAccountError(response, err)
		return
	}
	writeAccountNoContent(response)
}

func (h *httpHandler) requestDeletion(response http.ResponseWriter, request *http.Request) {
	browserSession, ok := h.authorizeBrowser(response, request, true)
	if !ok {
		return
	}
	var payload struct {
		CurrentPassword     string `json:"current_password"`
		VerificationReceipt string `json:"verification_receipt"`
	}
	if !decodeAccountJSON(response, request, &payload) {
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.accounts.RequestDeletion(
		request.Context(), browserSession.Principal.UserID, payload.CurrentPassword, payload.VerificationReceipt,
	); err != nil {
		writeMappedAccountError(response, err)
		return
	}
	// The authoritative account state is already pending deletion. End also
	// expires the browser cookie; a Redis delete failure cannot reactivate it.
	_ = h.browserSessions.End(request.Context(), response, request)
	writeAccountNoContent(response)
}

func (h *httpHandler) recoverDeletion(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		Identity            string `json:"identity"`
		Password            string `json:"password"`
		VerificationReceipt string `json:"verification_receipt"`
	}
	if h.accounts == nil || !decodeAccountJSON(response, request, &payload) {
		writeAccountError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.accounts.RecoverDeletion(
		request.Context(), payload.Identity, payload.Password, payload.VerificationReceipt,
	); err != nil {
		writeMappedAccountError(response, err)
		return
	}
	writeAccountNoContent(response)
}

func (h *httpHandler) authorizeBrowser(
	response http.ResponseWriter,
	request *http.Request,
	requireCSRF bool,
) (browser.Session, bool) {
	if h.accounts == nil || h.browserSessions == nil {
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		return browser.Session{}, false
	}
	browserSession, err := h.browserSessions.Read(request.Context(), request)
	if err != nil {
		if errors.Is(err, browser.ErrUnauthenticated) {
			writeAccountError(response, http.StatusUnauthorized, "session_revoked")
		} else {
			writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		}
		return browser.Session{}, false
	}
	if requireCSRF && h.browserSessions.RequireCSRF(request, browserSession) != nil {
		writeAccountError(response, http.StatusForbidden, "invalid_request")
		return browser.Session{}, false
	}
	return browserSession, true
}

func (h *httpHandler) authorizeAccess(response http.ResponseWriter, request *http.Request) (session.AccessClaims, bool) {
	values := request.Header.Values("Authorization")
	if h.accounts == nil || h.accessTokens == nil || len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		writeAccountError(response, http.StatusUnauthorized, "session_revoked")
		return session.AccessClaims{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(values[0], "Bearer "))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		writeAccountError(response, http.StatusUnauthorized, "session_revoked")
		return session.AccessClaims{}, false
	}
	claims, err := h.accessTokens.Authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, session.ErrInvalidAccessToken) || errors.Is(err, session.ErrSessionRevoked) {
			writeAccountError(response, http.StatusUnauthorized, "session_revoked")
		} else {
			writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		}
		return session.AccessClaims{}, false
	}
	return claims, true
}

func (h *httpHandler) register(response http.ResponseWriter, request *http.Request) {
	if h.registrationDisabled {
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
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
	case errors.Is(err, ErrLastIdentity):
		writeAccountError(response, http.StatusConflict, "last_identity")
	case errors.Is(err, ErrDeletionWindowExpired):
		writeAccountError(response, http.StatusGone, "deletion_window_expired")
	case errors.Is(err, ErrOrganizationOwnerTransferRequired):
		var ownership *OrganizationOwnerTransferRequiredError
		if errors.As(err, &ownership) && ownership.OwnedOrganizationCount > 0 {
			writeAccountOrganizationOwnershipError(response, ownership.OwnedOrganizationCount)
			return
		}
		writeAccountError(response, http.StatusConflict, "organization_owner_transfer_required")
	case errors.Is(err, ErrAccountNotFound):
		writeAccountError(response, http.StatusNotFound, "account_not_found")
	default:
		writeAccountError(response, http.StatusServiceUnavailable, "service_unavailable")
	}
}

func writeAccountOrganizationOwnershipError(response http.ResponseWriter, ownedOrganizationCount int) {
	writeAccountJSON(response, http.StatusConflict, struct {
		Error struct {
			Code                   string `json:"code"`
			Message                string `json:"message"`
			RequestID              string `json:"request_id"`
			OwnedOrganizationCount int    `json:"owned_organization_count"`
		} `json:"error"`
	}{
		Error: struct {
			Code                   string `json:"code"`
			Message                string `json:"message"`
			RequestID              string `json:"request_id"`
			OwnedOrganizationCount int    `json:"owned_organization_count"`
		}{
			Code: "organization_owner_transfer_required", Message: "localized by the client",
			RequestID: newRequestID(), OwnedOrganizationCount: ownedOrganizationCount,
		},
	})
}

func writeAccountNoContent(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
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
