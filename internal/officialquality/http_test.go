package officialquality

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
)

func TestHTTPEventIngestionAuthenticatesAndForwardsOnlyStrictEnvelope(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	principal := validQualityPrincipal()
	submitter := &stubSubmitter{}
	handler := NewHandler(HTTPConfig{
		Submitter: submitter, Consent: &stubConsentSetter{}, AccessTokens: fixedQualityAuthenticator{
			claims: session.AccessClaims{AccessBinding: session.AccessBinding{
				UserID: principal.UserID, DeviceID: principal.DeviceID, PersonalSpaceID: principal.PersonalSpaceID,
			}},
		},
		Clock: func() time.Time { return now },
	})
	body := validPublicEnvelopeJSON(mustUUIDV7(t), base64Signature(0x51))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/official-agent-quality/events", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("event response = %d %q", response.Code, response.Body.String())
	}
	if submitter.calls != 1 || submitter.principal != principal || submitter.envelope.EventID == uuid.Nil {
		t.Fatalf("event submission = calls=%d principal=%+v envelope=%+v", submitter.calls, submitter.principal, submitter.envelope)
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload["status"] != "accepted" {
		t.Fatalf("event response payload = %v, %v", payload, err)
	}
}

func TestHTTPEventIngestionRejectsUnknownContentAndOversizeBeforeService(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	principal := validQualityPrincipal()
	for name, body := range map[string]string{
		"free text": strings.TrimSuffix(validPublicEnvelopeJSON(mustUUIDV7(t), base64Signature(0x52)), "}") + `,"note":"private-canary"}`,
		"oversize":  `{"padding":"` + strings.Repeat("x", 17*1024) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			submitter := &stubSubmitter{}
			handler := NewHandler(HTTPConfig{
				Submitter: submitter, Consent: &stubConsentSetter{},
				AccessTokens: fixedQualityAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
					UserID: principal.UserID, DeviceID: principal.DeviceID, PersonalSpaceID: principal.PersonalSpaceID,
				}}},
				Clock: func() time.Time { return now },
			})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/official-agent-quality/events", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			want := http.StatusBadRequest
			if name == "oversize" {
				want = http.StatusRequestEntityTooLarge
			}
			if response.Code != want || submitter.calls != 0 {
				t.Fatalf("response = %d %q; submit calls=%d", response.Code, response.Body.String(), submitter.calls)
			}
		})
	}
}

func TestHTTPConsentRoutesPinPurposeStateAndStrictBody(t *testing.T) {
	principal := validQualityPrincipal()
	consent := &stubConsentSetter{}
	handler := NewHandler(HTTPConfig{
		Submitter: &stubSubmitter{}, Consent: consent,
		AccessTokens: fixedQualityAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
			UserID: principal.UserID, DeviceID: principal.DeviceID, PersonalSpaceID: principal.PersonalSpaceID,
		}}},
		Clock: time.Now,
	})

	for _, requestCase := range []struct {
		path  string
		state string
	}{
		{path: "/api/v1/official-agent-quality/consents/official_quality_metrics/grant", state: ConsentGranted},
		{path: "/api/v1/official-agent-quality/consents/official_explicit_feedback/revoke", state: ConsentRevoked},
	} {
		request := httptest.NewRequest(http.MethodPost, requestCase.path, strings.NewReader(`{"consent_version":2}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer access-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("consent response = %d %q", response.Code, response.Body.String())
		}
		last := consent.requests[len(consent.requests)-1]
		if last.State != requestCase.state || last.ConsentVersion != 2 {
			t.Fatalf("consent request = %+v", last)
		}
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/official-agent-quality/consents/official_quality_metrics/grant",
		strings.NewReader(`{"consent_version":2,"note":"private-canary"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(consent.requests) != 2 {
		t.Fatalf("strict consent response = %d %q; calls=%d", response.Code, response.Body.String(), len(consent.requests))
	}
}

func TestHTTPQualityRoutesFailClosedWithoutAuthenticationOrServices(t *testing.T) {
	body := validPublicEnvelopeJSON(mustUUIDV7(t), base64Signature(0x53))
	for name, handler := range map[string]http.Handler{
		"missing auth": NewHandler(HTTPConfig{
			Submitter: &stubSubmitter{}, Consent: &stubConsentSetter{}, AccessTokens: fixedQualityAuthenticator{}, Clock: time.Now,
		}),
		"missing services": NewHandler(HTTPConfig{AccessTokens: fixedQualityAuthenticator{}, Clock: time.Now}),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/official-agent-quality/events", bytes.NewBufferString(body))
			request.Header.Set("Content-Type", "application/json")
			if name == "missing services" {
				request.Header.Set("Authorization", "Bearer access-token")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			want := http.StatusUnauthorized
			if name == "missing services" {
				want = http.StatusServiceUnavailable
			}
			if response.Code != want {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), want)
			}
		})
	}
}

type stubSubmitter struct {
	principal Principal
	envelope  PublicEnvelope
	result    SubmitResult
	err       error
	calls     int
}

func (s *stubSubmitter) Submit(_ context.Context, principal Principal, envelope PublicEnvelope) (SubmitResult, error) {
	s.calls++
	s.principal = principal
	s.envelope = envelope
	if s.result.EventID == uuid.Nil {
		s.result.EventID = envelope.EventID
	}
	return s.result, s.err
}

type stubConsentSetter struct {
	requests []ConsentRequest
	err      error
}

func (s *stubConsentSetter) Set(_ context.Context, _ Principal, request ConsentRequest) (ConsentReceipt, error) {
	s.requests = append(s.requests, request)
	return ConsentReceipt{ID: uuid.New(), Purpose: request.Purpose, ConsentVersion: request.ConsentVersion, State: request.State, Revision: 1}, s.err
}

type fixedQualityAuthenticator struct {
	claims session.AccessClaims
	err    error
}

func (a fixedQualityAuthenticator) Authenticate(context.Context, string) (session.AccessClaims, error) {
	return a.claims, a.err
}
