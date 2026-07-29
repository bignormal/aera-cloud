package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bignormal/aera-cloud/internal/verification"
)

func TestRouterSelectsEmailOrSMSWithoutCrossDelivery(t *testing.T) {
	email := &recordingProvider{}
	sms := &recordingProvider{}
	router, err := NewRouter(email, sms)
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	ctx := context.Background()
	if err := router.SendVerification(ctx, "alice@example.com", "123456", verification.PurposeRegistration); err != nil {
		t.Fatalf("email SendVerification() error = %v", err)
	}
	if err := router.SendVerification(ctx, "+8613800138000", "654321", verification.PurposePasswordReset); err != nil {
		t.Fatalf("SMS SendVerification() error = %v", err)
	}
	if len(email.deliveries) != 1 || email.deliveries[0].destination != "alice@example.com" {
		t.Fatalf("email deliveries = %+v", email.deliveries)
	}
	if len(sms.deliveries) != 1 || sms.deliveries[0].destination != "+8613800138000" {
		t.Fatalf("SMS deliveries = %+v", sms.deliveries)
	}
	if err := router.SendVerification(ctx, "unsupported", "123456", verification.PurposeRegistration); err == nil {
		t.Fatal("router accepted unsupported destination")
	}
}

func TestRouterSupportsPhoneOnlyVerification(t *testing.T) {
	sms := &recordingProvider{}
	router, err := NewRouter(nil, sms)
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	if err := router.SendVerification(
		context.Background(),
		"+8613800138000",
		"123456",
		verification.PurposeLogin,
	); err != nil {
		t.Fatalf("phone SendVerification() error = %v", err)
	}
	if len(sms.deliveries) != 1 {
		t.Fatalf("SMS deliveries = %d", len(sms.deliveries))
	}
	if err := router.SendVerification(
		context.Background(),
		"alice@example.com",
		"123456",
		verification.PurposeRegistration,
	); err == nil {
		t.Fatal("phone-only router accepted email delivery")
	}
	if _, err := NewRouter(nil, nil); err == nil {
		t.Fatal("NewRouter() accepted no providers")
	}
}

func TestSMTPEmailBuildsSafeMessageAndKeepsCredentialsOutOfPayload(t *testing.T) {
	transport := &recordingSMTPTransport{}
	provider, err := NewSMTPEmail(SMTPConfig{
		Host: "smtp.example.com", Port: 587, Username: "smtp-user", Password: "smtp-password",
		FromAddress: "accounts@agentera.example", FromName: "Aera",
	}, transport)
	if err != nil {
		t.Fatalf("NewSMTPEmail() error = %v", err)
	}
	if err := provider.SendVerification(context.Background(), "alice@example.com", "123456", verification.PurposeRegistration); err != nil {
		t.Fatalf("SendVerification() error = %v", err)
	}
	if len(transport.envelopes) != 1 {
		t.Fatalf("SMTP envelopes = %d, want 1", len(transport.envelopes))
	}
	envelope := transport.envelopes[0]
	if envelope.Host != "smtp.example.com" || envelope.Port != 587 || envelope.To != "alice@example.com" {
		t.Fatalf("SMTP envelope = %+v", envelope)
	}
	message := string(envelope.Message)
	for _, expected := range []string{"Subject: Aera verification code", "To: alice@example.com", "123456", "5 minutes"} {
		if !strings.Contains(message, expected) {
			t.Errorf("SMTP message missing %q: %s", expected, message)
		}
	}
	for _, secret := range []string{"smtp-password", "smtp-user"} {
		if strings.Contains(message, secret) {
			t.Fatalf("SMTP message contains credential %q", secret)
		}
	}
}

func TestSMTPEmailRejectsHeaderInjectionAndSanitizesTransportFailure(t *testing.T) {
	transport := &recordingSMTPTransport{err: errors.New("smtp-password internal server detail")}
	provider, err := NewSMTPEmail(SMTPConfig{
		Host: "smtp.example.com", Port: 587, Username: "smtp-user", Password: "smtp-password",
		FromAddress: "accounts@agentera.example", FromName: "Aera",
	}, transport)
	if err != nil {
		t.Fatalf("NewSMTPEmail() error = %v", err)
	}
	if err := provider.SendVerification(context.Background(), "alice@example.com\r\nBcc: attacker@example.com", "123456", verification.PurposeRegistration); err == nil {
		t.Fatal("SendVerification() accepted header injection")
	}
	err = provider.SendVerification(context.Background(), "alice@example.com", "123456", verification.PurposeRegistration)
	if err == nil {
		t.Fatal("SendVerification() succeeded on transport failure")
	}
	if strings.Contains(err.Error(), "smtp-password") || strings.Contains(err.Error(), "internal server detail") {
		t.Fatalf("SMTP error leaked transport details: %v", err)
	}
}

func TestHTTPSMSSendsAuthenticatedJSONAndSanitizesFailure(t *testing.T) {
	var authorization string
	var payload map[string]any
	status := http.StatusAccepted
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("Decode() error = %v", err)
		}
		response.WriteHeader(status)
		_, _ = io.WriteString(response, `{"provider":"api-secret","detail":"internal"}`)
	}))
	defer server.Close()
	provider, err := NewHTTPSMS(HTTPSMSConfig{
		Endpoint: server.URL, APIKey: "api-secret", SenderID: "Aera", Client: server.Client(), AllowInsecureLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPSMS() error = %v", err)
	}
	if err := provider.SendVerification(context.Background(), "+8613800138000", "123456", verification.PurposePasswordReset); err != nil {
		t.Fatalf("SendVerification() error = %v", err)
	}
	if authorization != "Bearer api-secret" {
		t.Fatalf("Authorization = %q", authorization)
	}
	if payload["to"] != "+8613800138000" || payload["code"] != "123456" || payload["sender_id"] != "Aera" {
		t.Fatalf("SMS payload = %+v", payload)
	}

	status = http.StatusBadGateway
	err = provider.SendVerification(context.Background(), "+8613800138000", "654321", verification.PurposePasswordReset)
	if err == nil {
		t.Fatal("SendVerification() succeeded on provider failure")
	}
	for _, secret := range []string{"api-secret", "internal", "654321"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("SMS error contains secret %q: %v", secret, err)
		}
	}
}

func TestHTTPSMSDoesNotFollowProviderRedirects(t *testing.T) {
	redirected := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer redirectTarget.Close()
	providerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer providerServer.Close()
	provider, err := NewHTTPSMS(HTTPSMSConfig{
		Endpoint: providerServer.URL, APIKey: "api-secret", SenderID: "Aera", Client: providerServer.Client(), AllowInsecureLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPSMS() error = %v", err)
	}

	if err := provider.SendVerification(context.Background(), "+8613800138000", "123456", verification.PurposeRegistration); err == nil {
		t.Fatal("SendVerification() accepted provider redirect")
	}
	if redirected {
		t.Fatal("SMS request followed redirect and exposed credentials")
	}
}

func TestNotificationProvidersRejectIncompleteOrInsecureConfiguration(t *testing.T) {
	if _, err := NewSMTPEmail(SMTPConfig{}, &recordingSMTPTransport{}); err == nil {
		t.Fatal("NewSMTPEmail() accepted empty configuration")
	}
	if _, err := NewHTTPSMS(HTTPSMSConfig{Endpoint: "http://sms.example.com", APIKey: "key", SenderID: "Aera"}); err == nil {
		t.Fatal("NewHTTPSMS() accepted insecure provider endpoint")
	}
}

func TestNotificationProvidersAcceptEveryPublicVerificationPurpose(t *testing.T) {
	for _, purpose := range []verification.Purpose{
		verification.PurposeRegistration,
		verification.PurposePasswordReset,
		verification.PurposeBindIdentity,
		verification.PurposeAccountDeletion,
		verification.PurposeDeletionRecovery,
	} {
		if !validPurpose(purpose) {
			t.Errorf("validPurpose(%q) = false", purpose)
		}
	}
}

type recordedDelivery struct {
	destination string
	code        string
	purpose     verification.Purpose
}

type recordingProvider struct {
	deliveries []recordedDelivery
}

func (r *recordingProvider) SendVerification(_ context.Context, destination, code string, purpose verification.Purpose) error {
	r.deliveries = append(r.deliveries, recordedDelivery{destination: destination, code: code, purpose: purpose})
	return nil
}

type recordingSMTPTransport struct {
	envelopes []SMTPEnvelope
	err       error
}

func (r *recordingSMTPTransport) Deliver(_ context.Context, envelope SMTPEnvelope) error {
	envelope.Message = bytes.Clone(envelope.Message)
	r.envelopes = append(r.envelopes, envelope)
	return r.err
}
