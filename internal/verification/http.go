package verification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/go-chi/chi/v5"
)

const verificationRequestBodyLimit = 64 * 1024

type ServicePort interface {
	Send(ctx context.Context, request SendRequest) error
	Verify(ctx context.Context, request VerifyRequest) error
}

type handler struct {
	service ServicePort
}

func NewHandler(service ServicePort) http.Handler {
	router := chi.NewRouter()
	h := &handler{service: service}
	router.Post("/api/v1/verification/challenges", h.send)
	router.Post("/api/v1/verification/challenges/verify", h.verify)
	return router
}

func (h *handler) send(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		Kind         secure.IdentityKind `json:"kind"`
		Destination  string              `json:"destination"`
		Purpose      Purpose             `json:"purpose"`
		CaptchaToken string              `json:"captcha_token"`
	}
	if h.service == nil || !decodeJSON(response, request, &payload) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	err := h.service.Send(request.Context(), SendRequest{
		Kind:           payload.Kind,
		Destination:    payload.Destination,
		Purpose:        payload.Purpose,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
		IPAddress:      remoteIPAddress(request.RemoteAddr),
		DeviceID:       request.Header.Get("X-AgentEra-Installation-ID"),
		CaptchaToken:   payload.CaptchaToken,
	})
	if err != nil {
		status, code := sendErrorResponse(err)
		writeError(response, status, code)
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (h *handler) verify(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		Kind        secure.IdentityKind `json:"kind"`
		Destination string              `json:"destination"`
		Purpose     Purpose             `json:"purpose"`
		Code        string              `json:"code"`
	}
	if h.service == nil || !decodeJSON(response, request, &payload) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	err := h.service.Verify(request.Context(), VerifyRequest{
		Kind:        payload.Kind,
		Destination: payload.Destination,
		Purpose:     payload.Purpose,
		Code:        payload.Code,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidVerification) {
			writeError(response, http.StatusBadRequest, "invalid_or_expired_code")
			return
		}
		writeError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "verified"})
}

func decodeJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, verificationRequestBodyLimit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false
	}
	return true
}

func sendErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ErrResendTooSoon):
		return http.StatusTooManyRequests, "resend_too_soon"
	case errors.Is(err, ErrRateLimited):
		return http.StatusTooManyRequests, "rate_limited"
	case errors.Is(err, ErrCaptchaRequired):
		return http.StatusForbidden, "captcha_required"
	case errors.Is(err, ErrRequestInProgress):
		return http.StatusConflict, "request_in_progress"
	default:
		return http.StatusServiceUnavailable, "temporarily_unavailable"
	}
}

func remoteIPAddress(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}

func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}

func writeJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(payload)
}
