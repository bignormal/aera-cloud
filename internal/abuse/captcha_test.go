package abuse

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPChallengeVerifierSendsFormAndReturnsProviderDecision(t *testing.T) {
	var receivedSecret string
	var receivedToken string
	var receivedIP string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		receivedSecret = request.Form.Get("secret")
		receivedToken = request.Form.Get("response")
		receivedIP = request.Form.Get("remoteip")
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"success":true}`)
	}))
	defer server.Close()

	verifier, err := NewHTTPChallengeVerifier(HTTPChallengeConfig{
		Endpoint:                  server.URL,
		Secret:                    "provider-secret",
		Client:                    server.Client(),
		AllowInsecureLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPChallengeVerifier() error = %v", err)
	}
	valid, err := verifier.Verify(context.Background(), "captcha-token", "203.0.113.10")
	if err != nil || !valid {
		t.Fatalf("Verify() = %v, %v", valid, err)
	}
	if receivedSecret != "provider-secret" || receivedToken != "captcha-token" || receivedIP != "203.0.113.10" {
		t.Fatalf("received secret/token/IP = %q/%q/%q", receivedSecret, receivedToken, receivedIP)
	}
}

func TestHTTPChallengeVerifierReturnsFalseForRejectedProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"success":false,"error-codes":["invalid-input-response"]}`)
	}))
	defer server.Close()
	verifier, err := NewHTTPChallengeVerifier(HTTPChallengeConfig{
		Endpoint:                  server.URL,
		Secret:                    "provider-secret",
		Client:                    server.Client(),
		AllowInsecureLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPChallengeVerifier() error = %v", err)
	}

	valid, err := verifier.Verify(context.Background(), "rejected-token", "203.0.113.10")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if valid {
		t.Fatal("Verify() accepted rejected provider proof")
	}
}

func TestHTTPChallengeVerifierSanitizesProviderFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "provider-secret captcha-token internal-details", http.StatusBadGateway)
	}))
	defer server.Close()
	verifier, err := NewHTTPChallengeVerifier(HTTPChallengeConfig{
		Endpoint:                  server.URL,
		Secret:                    "provider-secret",
		Client:                    &http.Client{Timeout: time.Second},
		AllowInsecureLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPChallengeVerifier() error = %v", err)
	}

	_, err = verifier.Verify(context.Background(), "captcha-token", "203.0.113.10")
	if err == nil {
		t.Fatal("Verify() succeeded on provider failure")
	}
	for _, secret := range []string{"provider-secret", "captcha-token", "internal-details"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error contains secret %q: %v", secret, err)
		}
	}
}

func TestHTTPChallengeVerifierDoesNotFollowProviderRedirects(t *testing.T) {
	redirected := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer redirectTarget.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer provider.Close()
	verifier, err := NewHTTPChallengeVerifier(HTTPChallengeConfig{
		Endpoint: provider.URL, Secret: "provider-secret", Client: provider.Client(), AllowInsecureLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPChallengeVerifier() error = %v", err)
	}

	if _, err := verifier.Verify(context.Background(), "captcha-token", "203.0.113.10"); err == nil {
		t.Fatal("Verify() accepted provider redirect")
	}
	if redirected {
		t.Fatal("CAPTCHA request followed redirect and exposed the request body")
	}
}

func TestHTTPChallengeVerifierRejectsInsecureOrIncompleteConfiguration(t *testing.T) {
	tests := []HTTPChallengeConfig{
		{},
		{Endpoint: "http://captcha.example.com/verify", Secret: "secret"},
		{Endpoint: "https://captcha.example.com/verify"},
	}
	for _, config := range tests {
		if _, err := NewHTTPChallengeVerifier(config); err == nil {
			t.Fatalf("NewHTTPChallengeVerifier(%+v) succeeded", config)
		}
	}
}
