package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/httpapi"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
)

type smokeVerificationSender struct {
	mu    sync.Mutex
	codes map[string]string
}

func (s *smokeVerificationSender) SendVerification(
	_ context.Context,
	destination string,
	code string,
	_ verification.Purpose,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codes == nil {
		s.codes = make(map[string]string)
	}
	s.codes[destination] = code
	return nil
}

func (s *smokeVerificationSender) code(destination string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.codes[destination]
}

type smokeCaptchaVerifier struct{}

func (smokeCaptchaVerifier) Verify(context.Context, string, string) (bool, error) {
	return true, nil
}

func TestSmokeAuthLifecycle(t *testing.T) {
	runSmokeAuthLifecycle(t)
}

func runSmokeAuthLifecycle(t *testing.T) {
	t.Helper()
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("open isolated PostgreSQL: %v", err)
	}
	defer postgres.Close()
	if _, err := postgres.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset isolated PostgreSQL schema: %v", err)
	}
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("apply isolated migrations: %v", err)
	}

	redisStore, err := store.OpenRedis(ctx, store.RedisOptions{
		Addr: services.RedisAddr, Username: services.RedisUsername,
		Password: services.RedisPassword, DB: services.RedisDB,
	})
	if err != nil {
		t.Fatalf("open isolated Redis: %v", err)
	}
	defer func() { _ = redisStore.Close() }()
	clearSmokeRedis(t, ctx, redisStore)

	cfg, err := configForSmoke(services)
	if err != nil {
		t.Fatalf("load smoke configuration: %v", err)
	}
	identityCodec, receiptCodec, err := buildIdentityCodecs(cfg)
	if err != nil {
		t.Fatalf("build identity codecs: %v", err)
	}
	sender := &smokeVerificationSender{}
	verificationService, err := verification.NewService(verification.ServiceConfig{
		Sender: sender, Repository: verification.NewPostgresRepository(postgres),
		Limiter: verification.NewRedisLimiter(redisStore.Client()), Captcha: smokeCaptchaVerifier{},
		DeliveryGuard: verification.NewRedisDeliveryGuard(redisStore.Client()), TargetIndexer: identityCodec,
		Receipts: receiptCodec, ActiveCodeKeyID: cfg.VerificationCodeKeyRing.ActiveKeyID,
		CodeKeys: cfg.VerificationCodeKeyRing.Keys, RequestHMACKey: cfg.VerificationRequestHMACKey,
	})
	if err != nil {
		t.Fatalf("build smoke verification service: %v", err)
	}
	accountHandler, err := buildAccountHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		t.Fatalf("build smoke account handler: %v", err)
	}
	oauthHandler, err := buildOAuthHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		t.Fatalf("build smoke OAuth handler: %v", err)
	}
	deviceHandler, err := buildDeviceHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		t.Fatalf("build smoke device handler: %v", err)
	}
	server := httptest.NewServer(httpapi.New(httpapi.Dependencies{
		PostgreSQL: postgres, Redis: redisStore, Verification: verification.NewHandler(verificationService),
		Accounts: accountHandler, OAuth: oauthHandler, Devices: deviceHandler,
	}))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create smoke cookie jar: %v", err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Jar: jar}
	smokeRequest(t, client, http.MethodGet, server.URL+"/health/live", nil, nil, http.StatusOK, nil)
	smokeRequest(t, client, http.MethodGet, server.URL+"/health/ready", nil, nil, http.StatusOK, nil)

	var legal struct {
		TermsVersion   string `json:"terms_version"`
		PrivacyVersion string `json:"privacy_version"`
	}
	smokeRequest(t, client, http.MethodGet, server.URL+"/api/v1/legal/current", nil, nil, http.StatusOK, &legal)
	if legal.TermsVersion == "" || legal.PrivacyVersion == "" {
		t.Fatal("smoke legal contract is incomplete")
	}

	destination := "+8613800138000"
	password := "Smoke-only correct battery"
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/verification/challenges", map[string]any{
		"kind": "phone", "destination": destination, "purpose": "registration", "captcha_token": "",
	}, map[string]string{
		"Idempotency-Key": uuid.NewString(), "X-AgentEra-Installation-ID": uuid.NewString(),
	}, http.StatusAccepted, nil)
	code := sender.code(destination)
	if len(code) != 6 {
		t.Fatal("smoke verification provider did not capture a six-digit code")
	}
	var verified struct {
		Receipt string `json:"receipt"`
	}
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/verification/challenges/verify", map[string]any{
		"kind": "phone", "destination": destination, "purpose": "registration", "code": code,
	}, nil, http.StatusOK, &verified)
	if verified.Receipt == "" {
		t.Fatal("smoke verification receipt is missing")
	}
	var registration struct {
		UserID          uuid.UUID `json:"user_id"`
		PersonalSpaceID uuid.UUID `json:"personal_space_id"`
	}
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/accounts/register", map[string]any{
		"kind": "phone", "verification_receipt": verified.Receipt, "password": password,
		"nickname": "Smoke User", "terms_version": legal.TermsVersion, "privacy_version": legal.PrivacyVersion,
	}, nil, http.StatusCreated, &registration)
	if registration.UserID == uuid.Nil || registration.PersonalSpaceID == uuid.Nil {
		t.Fatal("smoke registration did not create an account and personal space")
	}
	var persisted int
	if err := postgres.QueryRow(ctx, `
		SELECT count(*)
		FROM users u
		JOIN identities i ON i.user_id = u.id
		JOIN personal_spaces ps ON ps.owner_user_id = u.id
		WHERE u.id = $1 AND ps.id = $2 AND u.status = 'active'
		  AND i.kind = 'phone' AND i.verified_at IS NOT NULL
	`, registration.UserID, registration.PersonalSpaceID).Scan(&persisted); err != nil {
		t.Fatalf("read persisted phone account: %v", err)
	}
	if persisted != 1 {
		t.Fatalf("persisted phone account rows = %d, want 1", persisted)
	}

	var browserLogin struct {
		CSRFToken string `json:"csrf_token"`
	}
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/verification/challenges", map[string]any{
		"kind": "phone", "destination": destination, "purpose": "login", "captcha_token": "",
	}, map[string]string{
		"Idempotency-Key": uuid.NewString(), "X-AgentEra-Installation-ID": uuid.NewString(),
	}, http.StatusAccepted, nil)
	loginCode := sender.code(destination)
	if len(loginCode) != 6 {
		t.Fatal("smoke login verification provider did not capture a six-digit code")
	}
	var loginVerified struct {
		Receipt string `json:"receipt"`
	}
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/verification/challenges/verify", map[string]any{
		"kind": "phone", "destination": destination, "purpose": "login", "code": loginCode,
	}, nil, http.StatusOK, &loginVerified)
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/browser/login/code", map[string]any{
		"verification_receipt": loginVerified.Receipt,
	}, nil, http.StatusOK, &browserLogin)
	if browserLogin.CSRFToken == "" {
		t.Fatal("smoke code login did not return a CSRF token")
	}
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/browser/login/code", map[string]any{
		"verification_receipt": loginVerified.Receipt,
	}, nil, http.StatusBadRequest, nil)
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/browser/logout", nil, map[string]string{
		"X-CSRF-Token": browserLogin.CSRFToken,
	}, http.StatusNoContent, nil)

	browserLogin.CSRFToken = ""
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/browser/login", map[string]any{
		"identity": destination, "password": password,
	}, nil, http.StatusOK, &browserLogin)
	if browserLogin.CSRFToken == "" {
		t.Fatal("smoke browser session did not return a CSRF token")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate smoke device key: %v", err)
	}
	installationID := uuid.New()
	verifierBytes, err := secure.RandomBytes(32)
	if err != nil {
		t.Fatalf("generate smoke PKCE verifier: %v", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeDigest := sha256.Sum256([]byte(verifier))
	stateBytes, err := secure.RandomBytes(24)
	if err != nil {
		t.Fatalf("generate smoke OAuth state: %v", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	query := url.Values{
		"client_id":             {"agentera-studio"},
		"redirect_uri":          {"http://127.0.0.1:43123/agentera/oauth/callback"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challengeDigest[:])},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"installation_id":       {installationID.String()},
		"device_public_key":     {base64.RawURLEncoding.EncodeToString(publicKey)},
		"device_name":           {"AgentEra Smoke Device"},
		"platform":              {"darwin"},
		"app_version":           {"0.1.0-smoke"},
	}
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	beginResponse, err := noRedirectClient.Get(server.URL + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatalf("begin smoke OAuth: %v", err)
	}
	_ = beginResponse.Body.Close()
	if beginResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("begin smoke OAuth status = %d", beginResponse.StatusCode)
	}
	approvalLocation, err := url.Parse(beginResponse.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse smoke approval location: %v", err)
	}
	requestID := approvalLocation.Query().Get("request_id")
	if _, err := uuid.Parse(requestID); err != nil {
		t.Fatal("smoke OAuth request ID is invalid")
	}
	var approval struct {
		RedirectURI string `json:"redirect_uri"`
	}
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/oauth/authorize/approve", map[string]any{
		"request_id": requestID,
	}, map[string]string{"X-CSRF-Token": browserLogin.CSRFToken}, http.StatusOK, &approval)
	callback, err := url.Parse(approval.RedirectURI)
	if err != nil || callback.Query().Get("state") != state || callback.Query().Get("code") == "" {
		t.Fatal("smoke OAuth approval callback is invalid")
	}
	authorizationCode := callback.Query().Get("code")
	proofDigest := sha256.Sum256([]byte(authorizationCode + "\x00" + verifier + "\x00" + installationID.String()))
	deviceProof := ed25519.Sign(privateKey, proofDigest[:])
	var tokens session.TokenSet
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/oauth/token", map[string]any{
		"authorization_code": authorizationCode, "code_verifier": verifier,
		"installation_id": installationID, "device_proof": base64.RawURLEncoding.EncodeToString(deviceProof),
	}, nil, http.StatusOK, &tokens)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.OfflineEntitlement == "" ||
		tokens.UserID != registration.UserID || tokens.PersonalSpaceID != registration.PersonalSpaceID {
		t.Fatal("smoke OAuth exchange returned an incomplete token set")
	}

	var rotated session.TokenSet
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/oauth/refresh", map[string]string{
		"refresh_token": tokens.RefreshToken,
	}, nil, http.StatusOK, &rotated)
	if rotated.RefreshToken == "" || rotated.RefreshToken == tokens.RefreshToken || rotated.AccessToken == tokens.AccessToken {
		t.Fatal("smoke refresh did not rotate product credentials")
	}
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/oauth/revoke", map[string]string{
		"refresh_token": rotated.RefreshToken,
	}, nil, http.StatusNoContent, nil)
	smokeRequest(t, client, http.MethodPost, server.URL+"/api/v1/oauth/refresh", map[string]string{
		"refresh_token": rotated.RefreshToken,
	}, nil, http.StatusUnauthorized, nil)
	smokeRequest(t, client, http.MethodGet, server.URL+"/api/v1/devices", nil, map[string]string{
		"Authorization": "Bearer " + rotated.AccessToken,
	}, http.StatusUnauthorized, nil)
}

func configForSmoke(services testkit.Services) (config.Config, error) {
	return config.Load(func(key string) (string, bool) {
		switch key {
		case "AGENTERA_CLOUD_DATABASE_URL":
			return services.DatabaseURL, true
		case "AGENTERA_CLOUD_REDIS_ADDR":
			return services.RedisAddr, true
		case "AGENTERA_CLOUD_REDIS_USERNAME":
			return services.RedisUsername, true
		case "AGENTERA_CLOUD_REDIS_PASSWORD":
			return services.RedisPassword, true
		case "AGENTERA_CLOUD_REDIS_DB":
			return strconv.Itoa(services.RedisDB), true
		default:
			return os.LookupEnv(key)
		}
	})
}

func clearSmokeRedis(t *testing.T, ctx context.Context, redisStore *store.RedisStore) {
	t.Helper()
	iterator := redisStore.Client().Scan(ctx, 0, "aera-cloud:*", 100).Iterator()
	for iterator.Next(ctx) {
		if err := redisStore.Client().Del(ctx, iterator.Val()).Err(); err != nil {
			t.Fatalf("clear isolated Redis key: %v", err)
		}
	}
	if err := iterator.Err(); err != nil {
		t.Fatalf("scan isolated Redis keys: %v", err)
	}
}

func smokeRequest(
	t *testing.T,
	client *http.Client,
	method string,
	target string,
	payload any,
	headers map[string]string,
	wantStatus int,
	result any,
) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("encode smoke request for %s: %v", target, err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, target, body)
	if err != nil {
		t.Fatalf("create smoke request for %s: %v", target, err)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("smoke request %s %s failed: %v", method, request.URL.Path, err)
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("read smoke response %s %s: %v", method, request.URL.Path, err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("smoke request %s %s status = %d, want %d", method, request.URL.Path, response.StatusCode, wantStatus)
	}
	if result != nil && (len(responseBody) == 0 || json.Unmarshal(responseBody, result) != nil) {
		t.Fatalf("smoke response %s %s did not match its JSON contract", method, request.URL.Path)
	}
}
