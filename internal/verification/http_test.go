package verification

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
)

func TestHTTPHandlerAcceptsChallengeRequestFromHeadersAndRemoteAddress(t *testing.T) {
	service := &stubVerificationService{}
	handler := NewHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/verification/challenges", strings.NewReader(`{
		"kind":"email",
		"destination":"alice@example.com",
		"purpose":"registration",
		"captcha_token":"proof"
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "request-123")
	request.Header.Set("X-AgentEra-Installation-ID", "device-123")
	request.RemoteAddr = "203.0.113.10:44321"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || strings.TrimSpace(response.Body.String()) != `{"status":"accepted"}` {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	if service.sendCalls != 1 {
		t.Fatalf("Send() calls = %d", service.sendCalls)
	}
	got := service.lastSend
	if got.Kind != secure.IdentityEmail || got.Destination != "alice@example.com" || got.Purpose != PurposeRegistration {
		t.Fatalf("Send request identity = %+v", got)
	}
	if got.IdempotencyKey != "request-123" || got.DeviceID != "device-123" || got.IPAddress != "203.0.113.10" || got.CaptchaToken != "proof" {
		t.Fatalf("Send request metadata = %+v", got)
	}
}

func TestHTTPHandlerVerifiesCodeWithEnumerationSafeFailure(t *testing.T) {
	service := &stubVerificationService{verifyErr: ErrInvalidVerification}
	handler := NewHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/verification/challenges/verify", strings.NewReader(`{
		"kind":"phone",
		"destination":"+8613800138000",
		"purpose":"password_reset",
		"code":"123456"
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || strings.TrimSpace(response.Body.String()) != `{"error":"invalid_or_expired_code"}` {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "+8613800138000") || strings.Contains(response.Body.String(), "password") {
		t.Fatalf("response leaked identity or purpose: %s", response.Body.String())
	}
	if service.lastVerify.Code != "123456" || service.lastVerify.Kind != secure.IdentityPhone {
		t.Fatalf("Verify request = %+v", service.lastVerify)
	}
}

func TestHTTPHandlerReturnsShortLivedReceiptAfterVerification(t *testing.T) {
	expiresAt := time.Date(2026, 7, 17, 16, 10, 0, 0, time.UTC)
	service := &stubVerificationService{verifyResult: VerificationResult{Receipt: "opaque-receipt", ExpiresAt: expiresAt}}
	handler := NewHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/verification/challenges/verify", strings.NewReader(`{
		"kind":"email",
		"destination":"alice@example.com",
		"purpose":"registration",
		"code":"123456"
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	want := `{"status":"verified","receipt":"opaque-receipt","expires_at":"2026-07-17T16:10:00Z"}`
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != want {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestHTTPHandlerMapsSendFailuresToStableCodes(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "invalid", err: ErrInvalidRequest, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "resend", err: ErrResendTooSoon, status: http.StatusTooManyRequests, code: "resend_too_soon"},
		{name: "rate", err: ErrRateLimited, status: http.StatusTooManyRequests, code: "rate_limited"},
		{name: "captcha", err: ErrCaptchaRequired, status: http.StatusForbidden, code: "captcha_required"},
		{name: "in progress", err: ErrRequestInProgress, status: http.StatusConflict, code: "request_in_progress"},
		{name: "provider", err: ErrDeliveryUnavailable, status: http.StatusServiceUnavailable, code: "temporarily_unavailable"},
		{name: "storage", err: ErrTemporarilyUnavailable, status: http.StatusServiceUnavailable, code: "temporarily_unavailable"},
		{name: "unknown", err: errors.New("postgres://user:secret@db/private"), status: http.StatusServiceUnavailable, code: "temporarily_unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &stubVerificationService{sendErr: tt.err}
			handler := NewHandler(service)
			request := validSendHTTPRequest()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != tt.status || strings.TrimSpace(response.Body.String()) != `{"error":"`+tt.code+`"}` {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "private") {
				t.Fatalf("response leaked internal error: %s", response.Body.String())
			}
		})
	}
}

func TestHTTPHandlerRejectsUnknownFieldsWrongMediaTypeAndLargeBodies(t *testing.T) {
	tests := []struct {
		name    string
		request *http.Request
	}{
		{
			name: "unknown field",
			request: func() *http.Request {
				r := validSendHTTPRequest()
				r.Body = ioNopCloser(`{"kind":"email","destination":"alice@example.com","purpose":"registration","unexpected":true}`)
				return r
			}(),
		},
		{
			name: "wrong media type",
			request: func() *http.Request {
				r := validSendHTTPRequest()
				r.Header.Set("Content-Type", "text/plain")
				return r
			}(),
		},
		{
			name: "large body",
			request: func() *http.Request {
				r := validSendHTTPRequest()
				r.Body = ioNopCloser(`{"kind":"email","destination":"` + strings.Repeat("a", 70*1024) + `","purpose":"registration"}`)
				return r
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &stubVerificationService{}
			response := httptest.NewRecorder()
			NewHandler(service).ServeHTTP(response, tt.request)
			if response.Code != http.StatusBadRequest || strings.TrimSpace(response.Body.String()) != `{"error":"invalid_request"}` {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			if service.sendCalls != 0 {
				t.Fatalf("Send() calls = %d, want 0", service.sendCalls)
			}
		})
	}
}

type stubVerificationService struct {
	sendErr      error
	verifyErr    error
	verifyResult VerificationResult
	sendCalls    int
	verifyCalls  int
	lastSend     SendRequest
	lastVerify   VerifyRequest
}

func (s *stubVerificationService) Send(_ context.Context, request SendRequest) error {
	s.sendCalls++
	s.lastSend = request
	return s.sendErr
}

func (s *stubVerificationService) Verify(_ context.Context, request VerifyRequest) (VerificationResult, error) {
	s.verifyCalls++
	s.lastVerify = request
	return s.verifyResult, s.verifyErr
}

func validSendHTTPRequest() *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/verification/challenges", strings.NewReader(`{
		"kind":"email",
		"destination":"alice@example.com",
		"purpose":"registration"
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "request-123")
	request.Header.Set("X-AgentEra-Installation-ID", "device-123")
	request.RemoteAddr = "203.0.113.10:44321"
	return request
}

type stringReadCloser struct {
	*strings.Reader
}

func (stringReadCloser) Close() error { return nil }

func ioNopCloser(value string) stringReadCloser {
	return stringReadCloser{Reader: strings.NewReader(value)}
}
