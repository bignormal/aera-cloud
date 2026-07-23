package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicConfigHandlerReturnsOnlyNonSecretCapabilities(t *testing.T) {
	handler := NewPublicConfigHandler(PublicConfig{
		Environment:                   "internal_beta",
		PublicRegistrationEnabled:     true,
		RegistrationMode:              "direct",
		RegistrationIdentityKinds:     []string{"email"},
		IdentityVerificationAvailable: false,
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/public/config", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	const expected = `{"environment":"internal_beta","public_registration_enabled":true,"registration_mode":"direct","registration_identity_kinds":["email"],"identity_verification_available":false}`
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != expected {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %+v", response.Header())
	}
	for _, forbidden := range []string{"password", "secret", "token", "key", "endpoint"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("public config contains %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestPublicConfigHandlerRejectsNonGETMethods(t *testing.T) {
	handler := NewPublicConfigHandler(PublicConfig{
		Environment: "internal_beta", RegistrationMode: "direct",
		RegistrationIdentityKinds: []string{"email"},
	})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(
			response,
			httptest.NewRequest(method, "/api/v1/public/config", strings.NewReader(`{}`)),
		)
		if response.Code != http.StatusMethodNotAllowed || response.Body.Len() != 0 {
			t.Fatalf("%s response = %d %q", method, response.Code, response.Body.String())
		}
	}
}
