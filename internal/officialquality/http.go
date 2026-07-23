package officialquality

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	maximumEventRequestBytes   = 16 * 1024
	maximumConsentRequestBytes = 4 * 1024
)

type Submitter interface {
	Submit(context.Context, Principal, PublicEnvelope) (SubmitResult, error)
}

type ConsentSetter interface {
	Set(context.Context, Principal, ConsentRequest) (ConsentReceipt, error)
}

type AccessAuthenticator interface {
	Authenticate(context.Context, string) (session.AccessClaims, error)
}

type HTTPConfig struct {
	Submitter    Submitter
	Consent      ConsentSetter
	AccessTokens AccessAuthenticator
	Clock        func() time.Time
}

type httpHandler struct {
	submitter    Submitter
	consent      ConsentSetter
	accessTokens AccessAuthenticator
	clock        func() time.Time
}

func NewHandler(config HTTPConfig) http.Handler {
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	handler := &httpHandler{
		submitter: config.Submitter, consent: config.Consent,
		accessTokens: config.AccessTokens, clock: clock,
	}
	router := chi.NewRouter()
	router.Post("/api/v1/official-agent-quality/events", handler.submitEvent)
	router.Post("/api/v1/official-agent-quality/consents/{purpose}/{action}", handler.setConsent)
	return router
}

func (h *httpHandler) submitEvent(response http.ResponseWriter, request *http.Request) {
	if h.submitter == nil || h.accessTokens == nil {
		writeQualityError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	raw, ok := readQualityJSON(response, request, maximumEventRequestBytes)
	if !ok {
		return
	}
	envelope, err := DecodePublicEnvelope(raw, h.clock().UTC())
	if err != nil {
		writeQualityError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.submitter.Submit(request.Context(), principal, envelope)
	if err != nil {
		writeQualityServiceError(response, err)
		return
	}
	status := "accepted"
	if result.Replayed {
		status = "replayed"
	}
	writeQualityJSON(response, http.StatusAccepted, struct {
		EventID uuid.UUID `json:"event_id"`
		Status  string    `json:"status"`
	}{EventID: result.EventID, Status: status})
}

func (h *httpHandler) setConsent(response http.ResponseWriter, request *http.Request) {
	if h.consent == nil || h.accessTokens == nil {
		writeQualityError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	purpose := chi.URLParam(request, "purpose")
	action := chi.URLParam(request, "action")
	if !validPurpose(purpose) || (action != "grant" && action != "revoke") {
		writeQualityError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	raw, ok := readQualityJSON(response, request, maximumConsentRequestBytes)
	if !ok {
		return
	}
	var payload struct {
		ConsentVersion int64 `json:"consent_version"`
	}
	if rejectDuplicateJSONKeys(raw) != nil || decodeStrictJSON(raw, &payload) != nil || payload.ConsentVersion <= 0 {
		writeQualityError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	state := ConsentGranted
	if action == "revoke" {
		state = ConsentRevoked
	}
	receipt, err := h.consent.Set(request.Context(), principal, ConsentRequest{
		Purpose: purpose, ConsentVersion: payload.ConsentVersion, State: state,
	})
	if err != nil {
		writeQualityServiceError(response, err)
		return
	}
	writeQualityJSON(response, http.StatusOK, struct {
		Purpose        string    `json:"purpose"`
		ConsentVersion int64     `json:"consent_version"`
		State          string    `json:"state"`
		Revision       int64     `json:"revision"`
		RecordedAt     time.Time `json:"recorded_at"`
		Replayed       bool      `json:"replayed"`
	}{
		Purpose: receipt.Purpose, ConsentVersion: receipt.ConsentVersion,
		State: receipt.State, Revision: receipt.Revision,
		RecordedAt: receipt.RecordedAt, Replayed: receipt.Replayed,
	})
}

func (h *httpHandler) authorize(response http.ResponseWriter, request *http.Request) (Principal, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		writeQualityError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, " \t\r\n") {
		writeQualityError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	claims, err := h.accessTokens.Authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, session.ErrInvalidAccessToken) || errors.Is(err, session.ErrSessionRevoked) {
			writeQualityError(response, http.StatusUnauthorized, "session_revoked")
		} else {
			writeQualityError(response, http.StatusServiceUnavailable, "service_unavailable")
		}
		return Principal{}, false
	}
	principal := Principal{
		UserID: claims.UserID, DeviceID: claims.DeviceID, PersonalSpaceID: claims.PersonalSpaceID,
	}
	if !principal.valid() {
		writeQualityError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	return principal, true
}

func readQualityJSON(response http.ResponseWriter, request *http.Request, limit int64) ([]byte, bool) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeQualityError(response, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeQualityError(response, http.StatusRequestEntityTooLarge, "invalid_request")
		} else {
			writeQualityError(response, http.StatusBadRequest, "invalid_request")
		}
		return nil, false
	}
	return raw, true
}

func writeQualityServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		writeQualityError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrConsentRequired):
		writeQualityError(response, http.StatusForbidden, "consent_required")
	case errors.Is(err, ErrInvalidSignature), errors.Is(err, ErrIneligible):
		writeQualityError(response, http.StatusForbidden, "not_eligible")
	case errors.Is(err, ErrRateLimited):
		writeQualityError(response, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, ErrDLPRejected):
		writeQualityError(response, http.StatusBadRequest, "privacy_rejected")
	case errors.Is(err, ErrConflict):
		writeQualityError(response, http.StatusConflict, "event_conflict")
	default:
		writeQualityError(response, http.StatusServiceUnavailable, "service_unavailable")
	}
}

func writeQualityError(response http.ResponseWriter, status int, code string) {
	writeQualityJSON(response, status, struct {
		Error string `json:"error"`
	}{Error: code})
}

func writeQualityJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
