package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/oauth"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/redis/go-redis/v9"
)

func TestServeStopsCleanlyAfterContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, listener, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}))
	}()

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatalf("GET server error = %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		cancel()
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve() did not stop after context cancellation")
	}
}

func TestRunAppliesMigrationsBeforeServing(t *testing.T) {
	services := testkit.IntegrationServices(t)
	databaseCtx, databaseCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer databaseCancel()
	postgres, err := store.OpenPostgres(databaseCtx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if _, err := postgres.Exec(databaseCtx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset test database: %v", err)
	}

	runCtx, stopRun := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() {
		runResult <- run(runCtx, integrationLookup(services))
	}()

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	for {
		var exists bool
		if err := postgres.QueryRow(databaseCtx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
			stopRun()
			t.Fatalf("check schema migrations table: %v", err)
		}
		if exists {
			break
		}
		select {
		case err := <-runResult:
			stopRun()
			t.Fatalf("run() stopped before migrations were applied: %v", err)
		case <-deadline.C:
			stopRun()
			select {
			case <-runResult:
			case <-time.After(time.Second):
			}
			t.Fatal("run() did not apply database migrations")
		case <-poll.C:
		}
	}

	stopRun()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("run() shutdown error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not stop after cancellation")
	}
}

func TestBuildVerificationHandlerWiresVersionedRoute(t *testing.T) {
	services := testkit.Services{
		DatabaseURL:   "postgres://aera_cloud:secret@127.0.0.1:55434/aera_cloud?sslmode=disable",
		RedisAddr:     "127.0.0.1:56381",
		RedisUsername: "aera_cloud",
		RedisPassword: "secret",
		RedisDB:       9,
	}
	cfg, err := config.Load(integrationLookup(services))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	handler, err := buildVerificationHandler(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildVerificationHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/verification/challenges", strings.NewReader(`{
		"kind":"email",
		"destination":"invalid",
		"purpose":"registration"
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "request-123")
	request.Header.Set("X-AgentEra-Installation-ID", "device-123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || strings.TrimSpace(response.Body.String()) != `{"error":"invalid_request"}` {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestBuildAccountHandlerWiresCurrentLegalRoute(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	redisStore, err := store.OpenRedis(ctx, store.RedisOptions{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	if err != nil {
		t.Fatalf("OpenRedis() error = %v", err)
	}
	defer func() { _ = redisStore.Close() }()
	cfg, err := config.Load(integrationLookup(services))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	handler, err := buildAccountHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		t.Fatalf("buildAccountHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/legal/current", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"terms_version":"terms-2026-07","privacy_version":"privacy-2026-07"}` {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestBuildOAuthHandlerWiresProtocolAndPublicSigningKeys(t *testing.T) {
	services := testkit.Services{
		DatabaseURL:   "postgres://aera_cloud:secret@127.0.0.1:55434/aera_cloud?sslmode=disable",
		RedisAddr:     "127.0.0.1:56381",
		RedisUsername: "aera_cloud",
		RedisPassword: "secret",
		RedisDB:       9,
	}
	cfg, err := config.Load(integrationLookup(services))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = redisClient.Close() }()
	handler, err := buildOAuthHandler(cfg, nil, redisClient)
	if err != nil {
		t.Fatalf("buildOAuthHandler() error = %v", err)
	}

	keysRequest := httptest.NewRequest(http.MethodGet, "/.well-known/agentera-signing-keys.json", nil)
	keysResponse := httptest.NewRecorder()
	handler.ServeHTTP(keysResponse, keysRequest)
	var document struct {
		Keys []oauth.PublishedKey `json:"keys"`
	}
	if keysResponse.Code != http.StatusOK || json.Unmarshal(keysResponse.Body.Bytes(), &document) != nil {
		t.Fatalf("signing keys response = %d %q", keysResponse.Code, keysResponse.Body.String())
	}
	if len(document.Keys) != 4 || document.Keys[0].Purpose != "access" || document.Keys[1].Purpose != "offline_entitlement" ||
		document.Keys[2].Purpose != "agent_version" || document.Keys[3].Purpose != "agent_policy" {
		t.Fatalf("published signing keys = %+v", document.Keys)
	}
	for _, key := range document.Keys {
		if key.KeyType != "OKP" || key.Curve != "Ed25519" || key.X == "" {
			t.Fatalf("invalid published key = %+v", key)
		}
	}

	authorizeRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	authorizeResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizeResponse, authorizeRequest)
	if authorizeResponse.Code != http.StatusBadRequest {
		t.Fatalf("authorize status = %d, want protocol validation instead of an unwired route", authorizeResponse.Code)
	}
}

func TestBuildDeviceHandlerWiresPublicSelfRevocationRoute(t *testing.T) {
	services := testkit.Services{
		DatabaseURL:   "postgres://aera_cloud:secret@127.0.0.1:55434/aera_cloud?sslmode=disable",
		RedisAddr:     "127.0.0.1:56381",
		RedisUsername: "aera_cloud",
		RedisPassword: "secret",
		RedisDB:       9,
	}
	cfg, err := config.Load(integrationLookup(services))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = redisClient.Close() }()
	handler, err := buildDeviceHandler(cfg, nil, redisClient)
	if err != nil {
		t.Fatalf("buildDeviceHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/self-revoke", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestBuildAgentControlHandlerWiresAccessTokenOnlyRoute(t *testing.T) {
	services := testkit.Services{
		DatabaseURL:   "postgres://aera_cloud:secret@127.0.0.1:55434/aera_cloud?sslmode=disable",
		RedisAddr:     "127.0.0.1:56381",
		RedisUsername: "aera_cloud",
		RedisPassword: "secret",
		RedisDB:       9,
	}
	cfg, err := config.Load(integrationLookup(services))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = redisClient.Close() }()
	handler, err := buildAgentControlHandler(cfg, nil, redisClient)
	if err != nil {
		t.Fatalf("buildAgentControlHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-definitions", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"session_revoked"`) {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestBuildWorkspaceHandlerWiresConfiguredControlPlaneDependencies(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	redisStore, err := store.OpenRedis(ctx, store.RedisOptions{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	if err != nil {
		t.Fatalf("OpenRedis() error = %v", err)
	}
	defer func() { _ = redisStore.Close() }()
	cfg, err := config.Load(integrationLookup(services))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	handler, err := buildWorkspaceHandler(cfg, postgres, redisStore.Client())
	if err != nil {
		t.Fatalf("buildWorkspaceHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"session_revoked"`) {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}

	if _, err := buildWorkspaceHandler(cfg, nil, redisStore.Client()); err == nil {
		t.Fatal("buildWorkspaceHandler() accepted a nil PostgreSQL dependency")
	}
}

func TestBuildMaintenanceRunnerUsesConfiguredStores(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	redisStore, err := store.OpenRedis(ctx, store.RedisOptions{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	if err != nil {
		t.Fatalf("OpenRedis() error = %v", err)
	}
	defer func() { _ = redisStore.Close() }()
	cfg, err := config.Load(integrationLookup(services))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	runner, err := buildMaintenanceRunner(cfg, postgres, redisStore.Client())

	if err != nil || runner == nil {
		t.Fatalf("buildMaintenanceRunner() = %v, %v", runner, err)
	}
}

func integrationLookup(services testkit.Services) config.LookupEnv {
	agentControlPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, ed25519.SeedSize))
	values := map[string]string{
		"AGENTERA_CLOUD_ENVIRONMENT":                          "development",
		"AGENTERA_CLOUD_LISTEN_ADDR":                          "127.0.0.1:0",
		"AGENTERA_CLOUD_PUBLIC_URL":                           "http://127.0.0.1:8086",
		"AGENTERA_CLOUD_DATABASE_URL":                         services.DatabaseURL,
		"AGENTERA_CLOUD_REDIS_ADDR":                           services.RedisAddr,
		"AGENTERA_CLOUD_REDIS_USERNAME":                       services.RedisUsername,
		"AGENTERA_CLOUD_REDIS_PASSWORD":                       services.RedisPassword,
		"AGENTERA_CLOUD_REDIS_DB":                             strconv.Itoa(services.RedisDB),
		"AGENTERA_CLOUD_IDENTITY_ENCRYPTION_ACTIVE_KEY_ID":    "enc-test-v1",
		"AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS":             `{"enc-test-v1":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`,
		"AGENTERA_CLOUD_IDENTITY_LOOKUP_ACTIVE_KEY_ID":        "lookup-test-v1",
		"AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS":                 `{"lookup-test-v1":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}`,
		"AGENTERA_CLOUD_VERIFICATION_CODE_ACTIVE_KEY_ID":      "code-test-v1",
		"AGENTERA_CLOUD_VERIFICATION_CODE_KEYS":               `{"code-test-v1":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}`,
		"AGENTERA_CLOUD_VERIFICATION_RECEIPT_ACTIVE_KEY_ID":   "receipt-test-v1",
		"AGENTERA_CLOUD_VERIFICATION_RECEIPT_KEYS":            `{"receipt-test-v1":"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="}`,
		"AGENTERA_CLOUD_VERIFICATION_REQUEST_HMAC_KEY":        "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=",
		"AGENTERA_CLOUD_BROWSER_SESSION_HMAC_KEY":             "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=",
		"AGENTERA_CLOUD_LOGIN_RATE_HMAC_KEY":                  "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
		"AGENTERA_CLOUD_OAUTH_STATE_ENCRYPTION_ACTIVE_KEY_ID": "oauth-state-test-v1",
		"AGENTERA_CLOUD_OAUTH_STATE_ENCRYPTION_KEYS":          `{"oauth-state-test-v1":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}`,
		"AGENTERA_CLOUD_OAUTH_STATE_HMAC_KEY":                 "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
		"AGENTERA_CLOUD_REFRESH_TOKEN_HMAC_KEY":               "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=",
		"AGENTERA_CLOUD_ACCESS_SIGNING_ACTIVE_KEY_ID":         "access-test-v1",
		"AGENTERA_CLOUD_ACCESS_SIGNING_KEYS":                  `{"access-test-v1":"CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwtmvn4zLHpFMzK9nQp/fbBV9cXvGgatpm2Ys5+2gQxHOg=="}`,
		"AGENTERA_CLOUD_OFFLINE_SIGNING_ACTIVE_KEY_ID":        "offline-test-v1",
		"AGENTERA_CLOUD_OFFLINE_SIGNING_KEYS":                 `{"offline-test-v1":"DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwLUTrZtJJAFcoJAu0HkETTrF2+wjBvBpSMENqOtuOfLQ=="}`,
		"AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_ACTIVE_KEY_ID":  "agent-control-test-v1",
		"AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_KEYS": fmt.Sprintf(
			`{"agent-control-test-v1":"%s"}`,
			base64.StdEncoding.EncodeToString(agentControlPrivateKey),
		),
		"AGENTERA_CLOUD_OFFLINE_POLICY_VERSION":         "1",
		"AGENTERA_CLOUD_ACTIVE_DEVICE_LIMIT":            "5",
		"AGENTERA_CLOUD_BROWSER_COOKIE_NAME":            "agentera_test_session",
		"AGENTERA_CLOUD_BROWSER_SESSION_TTL_SECONDS":    "900",
		"AGENTERA_CLOUD_LOGIN_IDENTITY_LIMIT":           "5",
		"AGENTERA_CLOUD_LOGIN_IP_LIMIT":                 "20",
		"AGENTERA_CLOUD_LOGIN_WINDOW_SECONDS":           "600",
		"AGENTERA_CLOUD_WORKSPACE_ACTIVE_OWNED_LIMIT":   "10",
		"AGENTERA_CLOUD_WORKSPACE_MEMBER_LIMIT":         "100",
		"AGENTERA_CLOUD_WORKSPACE_PENDING_INVITE_LIMIT": "20",
		"AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_LIMIT":    "10",
		"AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_WINDOW":   "1h",
		"AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_LIMIT":    "20",
		"AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_WINDOW":   "1h",
		"AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_LIMIT":    "30",
		"AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_WINDOW":   "10m",
		"AGENTERA_CLOUD_TERMS_VERSION":                  "terms-2026-07",
		"AGENTERA_CLOUD_PRIVACY_VERSION":                "privacy-2026-07",
		"AGENTERA_CLOUD_SMTP_HOST":                      "smtp.agentera.invalid",
		"AGENTERA_CLOUD_SMTP_PORT":                      "587",
		"AGENTERA_CLOUD_SMTP_USERNAME":                  "smtp-user",
		"AGENTERA_CLOUD_SMTP_PASSWORD":                  "smtp-secret",
		"AGENTERA_CLOUD_SMTP_FROM_ADDRESS":              "accounts@agentera.invalid",
		"AGENTERA_CLOUD_SMTP_FROM_NAME":                 "AgentEra",
		"AGENTERA_CLOUD_SMS_ENDPOINT":                   "https://sms.agentera.invalid/v1/messages",
		"AGENTERA_CLOUD_SMS_API_KEY":                    "sms-secret",
		"AGENTERA_CLOUD_SMS_SENDER_ID":                  "AgentEra",
		"AGENTERA_CLOUD_CAPTCHA_ENDPOINT":               "https://captcha.agentera.invalid/siteverify",
		"AGENTERA_CLOUD_CAPTCHA_SECRET":                 "captcha-secret",
	}
	for key, value := range map[string]string{
		"AGENTERA_CLOUD_ORGANIZATION_OWNED_LIMIT":           "3",
		"AGENTERA_CLOUD_ORGANIZATION_MEMBER_LIMIT":          "500",
		"AGENTERA_CLOUD_ORGANIZATION_DEPARTMENT_LIMIT":      "50",
		"AGENTERA_CLOUD_ORGANIZATION_PENDING_INVITE_LIMIT":  "100",
		"AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_LIMIT":     "6",
		"AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_WINDOW":    "1h",
		"AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_LIMIT":     "30",
		"AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_WINDOW":    "1h",
		"AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_LIMIT":     "30",
		"AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_WINDOW":    "10m",
		"AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_LIMIT":   "120",
		"AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_WINDOW":  "1h",
		"AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_LIMIT":  "20",
		"AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_WINDOW": "1h",
	} {
		values[key] = value
	}
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
