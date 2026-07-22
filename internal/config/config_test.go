package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadAcceptsLoopbackHTTPInDevelopment(t *testing.T) {
	env := validEnvironment("development")

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Environment != "development" {
		t.Fatalf("Environment = %q, want development", cfg.Environment)
	}
	if cfg.ListenAddr != "127.0.0.1:8086" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.PublicURL != "http://127.0.0.1:8086" {
		t.Fatalf("PublicURL = %q", cfg.PublicURL)
	}
	if cfg.RedisDB != 9 {
		t.Fatalf("RedisDB = %d, want 9", cfg.RedisDB)
	}
	if cfg.IdentityEncryptionKeyRing.ActiveKeyID != "enc-dev-v1" {
		t.Fatalf("encryption active key = %q", cfg.IdentityEncryptionKeyRing.ActiveKeyID)
	}
	if !bytes.Equal(cfg.IdentityEncryptionKeyRing.Keys["enc-dev-v1"], bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("encryption key ring was not decoded")
	}
	if cfg.IdentityLookupKeyRing.ActiveKeyID != "lookup-dev-v1" {
		t.Fatalf("lookup active key = %q", cfg.IdentityLookupKeyRing.ActiveKeyID)
	}
	if !bytes.Equal(cfg.IdentityLookupKeyRing.Keys["lookup-dev-v1"], bytes.Repeat([]byte{2}, 32)) {
		t.Fatal("lookup key ring was not decoded")
	}
	if cfg.VerificationCodeKeyRing.ActiveKeyID != "code-dev-v1" ||
		!bytes.Equal(cfg.VerificationCodeKeyRing.Keys["code-dev-v1"], bytes.Repeat([]byte{3}, 32)) {
		t.Fatal("verification code key ring was not decoded")
	}
	if cfg.VerificationReceiptKeyRing.ActiveKeyID != "receipt-dev-v1" ||
		!bytes.Equal(cfg.VerificationReceiptKeyRing.Keys["receipt-dev-v1"], bytes.Repeat([]byte{5}, 32)) {
		t.Fatal("verification receipt key ring was not decoded")
	}
	if !bytes.Equal(cfg.VerificationRequestHMACKey, bytes.Repeat([]byte{4}, 32)) {
		t.Fatal("verification request HMAC key was not decoded")
	}
	if !bytes.Equal(cfg.BrowserSessionHMACKey, bytes.Repeat([]byte{6}, 32)) ||
		!bytes.Equal(cfg.LoginRateHMACKey, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("browser authentication HMAC keys were not decoded")
	}
	if cfg.OAuthStateEncryptionKeyRing.ActiveKeyID != "oauth-state-dev-v1" ||
		!bytes.Equal(cfg.OAuthStateEncryptionKeyRing.Keys["oauth-state-dev-v1"], bytes.Repeat([]byte{8}, 32)) ||
		!bytes.Equal(cfg.OAuthStateHMACKey, bytes.Repeat([]byte{9}, 32)) ||
		!bytes.Equal(cfg.RefreshTokenHMACKey, bytes.Repeat([]byte{10}, 32)) {
		t.Fatal("desktop OAuth key material was not decoded")
	}
	if cfg.AccessSigningKeyRing.ActiveKeyID != "access-dev-v1" ||
		len(cfg.AccessSigningKeyRing.Keys["access-dev-v1"]) != ed25519.PrivateKeySize ||
		cfg.OfflineSigningKeyRing.ActiveKeyID != "offline-dev-v1" ||
		len(cfg.OfflineSigningKeyRing.Keys["offline-dev-v1"]) != ed25519.PrivateKeySize ||
		cfg.AgentControlSigningKeyRing.ActiveKeyID != "agent-control-dev-v1" ||
		len(cfg.AgentControlSigningKeyRing.Keys["agent-control-dev-v1"]) != ed25519.PrivateKeySize {
		t.Fatal("desktop signing key rings were not decoded")
	}
	if cfg.OfflinePolicyVersion != 1 || cfg.ActiveDeviceLimit != 5 {
		t.Fatalf("desktop authorization policy = %d / %d", cfg.OfflinePolicyVersion, cfg.ActiveDeviceLimit)
	}
	if cfg.BrowserCookieName != "agentera_test_session" || cfg.BrowserSessionTTLSeconds != 900 {
		t.Fatalf("browser session configuration = %q / %d", cfg.BrowserCookieName, cfg.BrowserSessionTTLSeconds)
	}
	if cfg.LoginIdentityLimit != 5 || cfg.LoginIPLimit != 20 || cfg.LoginWindowSeconds != 600 {
		t.Fatalf("login limits = %d / %d / %d", cfg.LoginIdentityLimit, cfg.LoginIPLimit, cfg.LoginWindowSeconds)
	}
	assertConfigField(t, cfg, "WorkspaceActiveOwnedLimit", 10)
	assertConfigField(t, cfg, "WorkspaceMemberLimit", 100)
	assertConfigField(t, cfg, "WorkspacePendingInviteLimit", 20)
	assertConfigField(t, cfg, "WorkspaceCreateRateLimit", int64(10))
	assertConfigField(t, cfg, "WorkspaceCreateRateWindow", time.Hour)
	assertConfigField(t, cfg, "WorkspaceInviteRateLimit", int64(20))
	assertConfigField(t, cfg, "WorkspaceInviteRateWindow", time.Hour)
	assertConfigField(t, cfg, "WorkspaceAcceptRateLimit", int64(30))
	assertConfigField(t, cfg, "WorkspaceAcceptRateWindow", 10*time.Minute)
	assertConfigField(t, cfg, "OrganizationOwnedLimit", 3)
	assertConfigField(t, cfg, "OrganizationMemberLimit", 500)
	assertConfigField(t, cfg, "OrganizationDepartmentLimit", 50)
	assertConfigField(t, cfg, "OrganizationPendingInviteLimit", 100)
	assertConfigField(t, cfg, "OrganizationCreateRateLimit", int64(6))
	assertConfigField(t, cfg, "OrganizationCreateRateWindow", time.Hour)
	assertConfigField(t, cfg, "OrganizationInviteRateLimit", int64(30))
	assertConfigField(t, cfg, "OrganizationInviteRateWindow", time.Hour)
	assertConfigField(t, cfg, "OrganizationAcceptRateLimit", int64(30))
	assertConfigField(t, cfg, "OrganizationAcceptRateWindow", 10*time.Minute)
	assertConfigField(t, cfg, "OrganizationMutationRateLimit", int64(120))
	assertConfigField(t, cfg, "OrganizationMutationRateWindow", time.Hour)
	assertConfigField(t, cfg, "OrganizationHighRiskRateLimit", int64(20))
	assertConfigField(t, cfg, "OrganizationHighRiskRateWindow", time.Hour)
	if cfg.TermsVersion != "terms-2026-07" || cfg.PrivacyVersion != "privacy-2026-07" {
		t.Fatalf("legal versions = %q / %q", cfg.TermsVersion, cfg.PrivacyVersion)
	}
	if cfg.SMTPHost != "smtp.example.com" || cfg.SMTPPort != 587 || cfg.SMSAPIKey != "sms-secret" || cfg.CaptchaSecret != "captcha-secret" {
		t.Fatalf("notification configuration was not loaded: %+v", cfg)
	}
}

func TestLoadRejectsHTTPOutsideLoopback(t *testing.T) {
	env := validEnvironment("development")
	env["AGENTERA_CLOUD_PUBLIC_URL"] = "http://192.168.1.20:8086"

	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("Load() error = %v, want loopback validation error", err)
	}
}

func TestLoadRejectsInsecureProductionPublicURL(t *testing.T) {
	env := validEnvironment("production")
	env["AGENTERA_CLOUD_PUBLIC_URL"] = "http://accounts.example.com"

	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("Load() error = %v, want HTTPS validation error", err)
	}
}

func TestLoadRejectsFakeProvidersInProduction(t *testing.T) {
	tests := []struct {
		key   string
		value string
	}{
		{key: "AGENTERA_CLOUD_SMTP_HOST", value: "smtp.agentera.invalid"},
		{key: "AGENTERA_CLOUD_SMTP_FROM_ADDRESS", value: "accounts@agentera.invalid"},
		{key: "AGENTERA_CLOUD_SMS_ENDPOINT", value: "https://sms.agentera.invalid/v1/messages"},
		{key: "AGENTERA_CLOUD_CAPTCHA_ENDPOINT", value: "https://captcha.agentera.invalid/siteverify"},
	}
	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			env := validEnvironment("production")
			env[test.key] = test.value
			if _, err := Load(mapLookup(env)); err == nil || !strings.Contains(err.Error(), "real providers") {
				t.Fatalf("Load() error = %v, want real-provider validation", err)
			}
		})
	}
}

func TestLoadRejectsProductionCredentialsThatAreMissing(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "database URL", key: "AGENTERA_CLOUD_DATABASE_URL"},
		{name: "redis address", key: "AGENTERA_CLOUD_REDIS_ADDR"},
		{name: "redis username", key: "AGENTERA_CLOUD_REDIS_USERNAME"},
		{name: "redis password", key: "AGENTERA_CLOUD_REDIS_PASSWORD"},
		{name: "encryption active key", key: "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_ACTIVE_KEY_ID"},
		{name: "encryption key ring", key: "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS"},
		{name: "lookup active key", key: "AGENTERA_CLOUD_IDENTITY_LOOKUP_ACTIVE_KEY_ID"},
		{name: "lookup key ring", key: "AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS"},
		{name: "verification active key", key: "AGENTERA_CLOUD_VERIFICATION_CODE_ACTIVE_KEY_ID"},
		{name: "verification key ring", key: "AGENTERA_CLOUD_VERIFICATION_CODE_KEYS"},
		{name: "verification receipt active key", key: "AGENTERA_CLOUD_VERIFICATION_RECEIPT_ACTIVE_KEY_ID"},
		{name: "verification receipt key ring", key: "AGENTERA_CLOUD_VERIFICATION_RECEIPT_KEYS"},
		{name: "verification request key", key: "AGENTERA_CLOUD_VERIFICATION_REQUEST_HMAC_KEY"},
		{name: "browser session key", key: "AGENTERA_CLOUD_BROWSER_SESSION_HMAC_KEY"},
		{name: "login rate key", key: "AGENTERA_CLOUD_LOGIN_RATE_HMAC_KEY"},
		{name: "OAuth state encryption active key", key: "AGENTERA_CLOUD_OAUTH_STATE_ENCRYPTION_ACTIVE_KEY_ID"},
		{name: "OAuth state encryption keys", key: "AGENTERA_CLOUD_OAUTH_STATE_ENCRYPTION_KEYS"},
		{name: "OAuth state HMAC key", key: "AGENTERA_CLOUD_OAUTH_STATE_HMAC_KEY"},
		{name: "refresh token HMAC key", key: "AGENTERA_CLOUD_REFRESH_TOKEN_HMAC_KEY"},
		{name: "access signing active key", key: "AGENTERA_CLOUD_ACCESS_SIGNING_ACTIVE_KEY_ID"},
		{name: "access signing keys", key: "AGENTERA_CLOUD_ACCESS_SIGNING_KEYS"},
		{name: "offline signing active key", key: "AGENTERA_CLOUD_OFFLINE_SIGNING_ACTIVE_KEY_ID"},
		{name: "offline signing keys", key: "AGENTERA_CLOUD_OFFLINE_SIGNING_KEYS"},
		{name: "Agent control signing active key", key: "AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_ACTIVE_KEY_ID"},
		{name: "Agent control signing keys", key: "AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_KEYS"},
		{name: "offline policy version", key: "AGENTERA_CLOUD_OFFLINE_POLICY_VERSION"},
		{name: "active device limit", key: "AGENTERA_CLOUD_ACTIVE_DEVICE_LIMIT"},
		{name: "browser cookie", key: "AGENTERA_CLOUD_BROWSER_COOKIE_NAME"},
		{name: "terms version", key: "AGENTERA_CLOUD_TERMS_VERSION"},
		{name: "privacy version", key: "AGENTERA_CLOUD_PRIVACY_VERSION"},
		{name: "SMTP password", key: "AGENTERA_CLOUD_SMTP_PASSWORD"},
		{name: "SMS API key", key: "AGENTERA_CLOUD_SMS_API_KEY"},
		{name: "CAPTCHA secret", key: "AGENTERA_CLOUD_CAPTCHA_SECRET"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnvironment("production")
			delete(env, tt.key)

			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("Load() error = %v, want missing %s", err, tt.key)
			}
		})
	}
}

func TestLoadRejectsReusedDesktopAuthorizationKeys(t *testing.T) {
	env := validEnvironment("production")
	env["AGENTERA_CLOUD_REFRESH_TOKEN_HMAC_KEY"] = env["AGENTERA_CLOUD_OAUTH_STATE_HMAC_KEY"]

	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "independent") {
		t.Fatalf("Load() error = %v, want independent-key validation", err)
	}

	env = validEnvironment("production")
	env["AGENTERA_CLOUD_OFFLINE_SIGNING_KEYS"] = encodedKeyRing(
		"offline-dev-v1",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize)),
	)
	_, err = Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "independent") {
		t.Fatalf("Load() signing error = %v, want independent-key validation", err)
	}

	env = validEnvironment("production")
	env["AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_KEYS"] = encodedKeyRing(
		"agent-control-dev-v1",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize)),
	)
	_, err = Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "independent") {
		t.Fatalf("Load() Agent control signing error = %v, want independent-key validation", err)
	}
}

func TestLoadRejectsChangingTheFiveDeviceProductLimit(t *testing.T) {
	env := validEnvironment("production")
	env["AGENTERA_CLOUD_ACTIVE_DEVICE_LIMIT"] = "6"

	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "AGENTERA_CLOUD_ACTIVE_DEVICE_LIMIT") {
		t.Fatalf("Load() error = %v, want fixed five-device validation", err)
	}
}

func TestLoadRejectsInvalidIdentityKeyRings(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{
			name:  "unknown active encryption key",
			key:   "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_ACTIVE_KEY_ID",
			value: "enc-missing",
			want:  "active key",
		},
		{
			name:  "malformed encryption JSON",
			key:   "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS",
			value: "not-json",
			want:  "JSON object",
		},
		{
			name:  "short encryption key",
			key:   "AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS",
			value: encodedKeyRing("enc-dev-v1", bytes.Repeat([]byte{1}, 31)),
			want:  "32 bytes",
		},
		{
			name:  "short lookup key",
			key:   "AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS",
			value: encodedKeyRing("lookup-dev-v1", bytes.Repeat([]byte{2}, 31)),
			want:  "at least 32 bytes",
		},
		{
			name:  "invalid base64",
			key:   "AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS",
			value: `{"lookup-dev-v1":"%%%"}`,
			want:  "base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnvironment("production")
			env[tt.key] = tt.value

			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadRejectsInvalidVerificationSecrets(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{
			name:  "short code HMAC key",
			key:   "AGENTERA_CLOUD_VERIFICATION_CODE_KEYS",
			value: encodedKeyRing("code-dev-v1", bytes.Repeat([]byte{3}, 31)),
			want:  "at least 32 bytes",
		},
		{
			name:  "short request HMAC key",
			key:   "AGENTERA_CLOUD_VERIFICATION_REQUEST_HMAC_KEY",
			value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 31)),
			want:  "at least 32 bytes",
		},
		{
			name:  "invalid request HMAC base64",
			key:   "AGENTERA_CLOUD_VERIFICATION_REQUEST_HMAC_KEY",
			value: "%%%",
			want:  "base64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnvironment("production")
			env[tt.key] = tt.value
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadRejectsInvalidBrowserAuthenticationConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{name: "short session key", key: "AGENTERA_CLOUD_BROWSER_SESSION_HMAC_KEY", value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 31)), want: "at least 32 bytes"},
		{name: "short login rate key", key: "AGENTERA_CLOUD_LOGIN_RATE_HMAC_KEY", value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 31)), want: "at least 32 bytes"},
		{name: "invalid cookie name", key: "AGENTERA_CLOUD_BROWSER_COOKIE_NAME", value: "shared cookie", want: "invalid"},
		{name: "long browser session", key: "AGENTERA_CLOUD_BROWSER_SESSION_TTL_SECONDS", value: "3600", want: "between 300 and 1800"},
		{name: "IP limit below identity limit", key: "AGENTERA_CLOUD_LOGIN_IP_LIMIT", value: "4", want: "between 5 and 10000"},
		{name: "invalid terms version", key: "AGENTERA_CLOUD_TERMS_VERSION", value: "terms 2026", want: "invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := validEnvironment("production")
			env[test.key] = test.value
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadRequiresWorkspaceConfiguration(t *testing.T) {
	keys := []string{
		"AGENTERA_CLOUD_WORKSPACE_ACTIVE_OWNED_LIMIT",
		"AGENTERA_CLOUD_WORKSPACE_MEMBER_LIMIT",
		"AGENTERA_CLOUD_WORKSPACE_PENDING_INVITE_LIMIT",
		"AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_LIMIT",
		"AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_WINDOW",
		"AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_LIMIT",
		"AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_WINDOW",
		"AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_LIMIT",
		"AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_WINDOW",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			env := validEnvironment("production")
			delete(env, key)
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "required") {
				t.Fatalf("Load() error = %v, want required %s", err, key)
			}
		})
	}
}

func TestLoadRejectsInvalidWorkspaceConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "zero active workspace limit", key: "AGENTERA_CLOUD_WORKSPACE_ACTIVE_OWNED_LIMIT", value: "0"},
		{name: "negative member limit", key: "AGENTERA_CLOUD_WORKSPACE_MEMBER_LIMIT", value: "-1"},
		{name: "zero pending invitation limit", key: "AGENTERA_CLOUD_WORKSPACE_PENDING_INVITE_LIMIT", value: "0"},
		{name: "zero workspace creation rate", key: "AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_LIMIT", value: "0"},
		{name: "zero workspace creation window", key: "AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_WINDOW", value: "0s"},
		{name: "negative invitation creation rate", key: "AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_LIMIT", value: "-1"},
		{name: "invalid invitation creation window", key: "AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_WINDOW", value: "one-hour"},
		{name: "zero invitation acceptance rate", key: "AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_LIMIT", value: "0"},
		{name: "negative invitation acceptance window", key: "AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_WINDOW", value: "-1s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := validEnvironment("production")
			env[test.key] = test.value
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %v, want validation for %s", err, test.key)
			}
		})
	}
}

func TestLoadRequiresOrganizationConfiguration(t *testing.T) {
	keys := []string{
		"AGENTERA_CLOUD_ORGANIZATION_OWNED_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_MEMBER_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_DEPARTMENT_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_PENDING_INVITE_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_WINDOW",
		"AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_WINDOW",
		"AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_WINDOW",
		"AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_WINDOW",
		"AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_LIMIT",
		"AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_WINDOW",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			env := validEnvironment("production")
			delete(env, key)
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "required") {
				t.Fatalf("Load() error = %v, want required %s", err, key)
			}
		})
	}
}

func TestLoadRejectsInvalidOrganizationConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "zero owned limit", key: "AGENTERA_CLOUD_ORGANIZATION_OWNED_LIMIT", value: "0"},
		{name: "negative member limit", key: "AGENTERA_CLOUD_ORGANIZATION_MEMBER_LIMIT", value: "-1"},
		{name: "zero department limit", key: "AGENTERA_CLOUD_ORGANIZATION_DEPARTMENT_LIMIT", value: "0"},
		{name: "negative pending invitation limit", key: "AGENTERA_CLOUD_ORGANIZATION_PENDING_INVITE_LIMIT", value: "-1"},
		{name: "zero creation rate", key: "AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_LIMIT", value: "0"},
		{name: "zero creation window", key: "AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_WINDOW", value: "0s"},
		{name: "negative invite rate", key: "AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_LIMIT", value: "-1"},
		{name: "invalid invite window", key: "AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_WINDOW", value: "one-hour"},
		{name: "zero acceptance rate", key: "AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_LIMIT", value: "0"},
		{name: "negative acceptance window", key: "AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_WINDOW", value: "-1s"},
		{name: "zero mutation rate", key: "AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_LIMIT", value: "0"},
		{name: "invalid mutation window", key: "AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_WINDOW", value: "hour"},
		{name: "negative high-risk rate", key: "AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_LIMIT", value: "-1"},
		{name: "zero high-risk window", key: "AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_WINDOW", value: "0s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := validEnvironment("production")
			env[test.key] = test.value
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %v, want validation for %s", err, test.key)
			}
		})
	}
}

func TestEnvironmentExamplePreservesKeyRingJSONWhenSourced(t *testing.T) {
	environmentFile, err := filepath.Abs(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("resolve .env.example: %v", err)
	}
	command := exec.Command(
		"sh",
		"-c",
		`. "$1"; printf '%s\n%s\n%s\n%s\n%s\n' "$AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS" "$AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS" "$AGENTERA_CLOUD_VERIFICATION_CODE_KEYS" "$AGENTERA_CLOUD_VERIFICATION_RECEIPT_KEYS" "$AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED"`,
		"sh",
		environmentFile,
	)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("source .env.example: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 5 {
		t.Fatalf("sourced configuration lines = %d, want 5", len(lines))
	}
	for index, line := range lines[:4] {
		var keys map[string]string
		if err := json.Unmarshal([]byte(line), &keys); err != nil {
			t.Fatalf("sourced key ring %d is not JSON: %q: %v", index, line, err)
		}
		if len(keys) != 1 {
			t.Fatalf("sourced key ring %d contains %d keys, want 1", index, len(keys))
		}
	}
	if lines[4] != "false" {
		t.Fatalf("sourced official-Agent flag = %q, want false", lines[4])
	}
}

func TestLoadRejectsRechargeDatabase(t *testing.T) {
	env := validEnvironment("production")
	env["AGENTERA_CLOUD_DATABASE_URL"] = "postgres://aera_cloud:secret@postgres:5432/agentera_claw?sslmode=require"

	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "dedicated") {
		t.Fatalf("Load() error = %v, want dedicated database validation error", err)
	}
}

func TestLoadRejectsPublicURLWithCredentialsPathQueryOrFragment(t *testing.T) {
	tests := []string{
		"https://user:password@accounts.example.com",
		"https://accounts.example.com/auth",
		"https://accounts.example.com?tenant=shared",
		"https://accounts.example.com#fragment",
	}

	for _, publicURL := range tests {
		t.Run(publicURL, func(t *testing.T) {
			env := validEnvironment("production")
			env["AGENTERA_CLOUD_PUBLIC_URL"] = publicURL

			if _, err := Load(mapLookup(env)); err == nil {
				t.Fatalf("Load() accepted non-origin public URL %q", publicURL)
			}
		})
	}
}

func validEnvironment(environment string) map[string]string {
	publicURL := "https://accounts.example.com"
	listenAddr := ":8086"
	if environment == "development" {
		publicURL = "http://127.0.0.1:8086"
		listenAddr = "127.0.0.1:8086"
	}

	accessPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	offlinePrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	agentControlPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, ed25519.SeedSize))
	return map[string]string{
		"AGENTERA_CLOUD_ENVIRONMENT":                          environment,
		"AGENTERA_CLOUD_LISTEN_ADDR":                          listenAddr,
		"AGENTERA_CLOUD_PUBLIC_URL":                           publicURL,
		"AGENTERA_CLOUD_DATABASE_URL":                         "postgres://aera_cloud:secret@postgres:5432/aera_cloud?sslmode=require",
		"AGENTERA_CLOUD_REDIS_ADDR":                           "redis:6379",
		"AGENTERA_CLOUD_REDIS_USERNAME":                       "aera_cloud",
		"AGENTERA_CLOUD_REDIS_PASSWORD":                       "secret",
		"AGENTERA_CLOUD_REDIS_DB":                             "9",
		"AGENTERA_CLOUD_IDENTITY_ENCRYPTION_ACTIVE_KEY_ID":    "enc-dev-v1",
		"AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS":             encodedKeyRing("enc-dev-v1", bytes.Repeat([]byte{1}, 32)),
		"AGENTERA_CLOUD_IDENTITY_LOOKUP_ACTIVE_KEY_ID":        "lookup-dev-v1",
		"AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS":                 encodedKeyRing("lookup-dev-v1", bytes.Repeat([]byte{2}, 32)),
		"AGENTERA_CLOUD_VERIFICATION_CODE_ACTIVE_KEY_ID":      "code-dev-v1",
		"AGENTERA_CLOUD_VERIFICATION_CODE_KEYS":               encodedKeyRing("code-dev-v1", bytes.Repeat([]byte{3}, 32)),
		"AGENTERA_CLOUD_VERIFICATION_RECEIPT_ACTIVE_KEY_ID":   "receipt-dev-v1",
		"AGENTERA_CLOUD_VERIFICATION_RECEIPT_KEYS":            encodedKeyRing("receipt-dev-v1", bytes.Repeat([]byte{5}, 32)),
		"AGENTERA_CLOUD_VERIFICATION_REQUEST_HMAC_KEY":        base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		"AGENTERA_CLOUD_BROWSER_SESSION_HMAC_KEY":             base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)),
		"AGENTERA_CLOUD_LOGIN_RATE_HMAC_KEY":                  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		"AGENTERA_CLOUD_OAUTH_STATE_ENCRYPTION_ACTIVE_KEY_ID": "oauth-state-dev-v1",
		"AGENTERA_CLOUD_OAUTH_STATE_ENCRYPTION_KEYS":          encodedKeyRing("oauth-state-dev-v1", bytes.Repeat([]byte{8}, 32)),
		"AGENTERA_CLOUD_OAUTH_STATE_HMAC_KEY":                 base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		"AGENTERA_CLOUD_REFRESH_TOKEN_HMAC_KEY":               base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32)),
		"AGENTERA_CLOUD_ACCESS_SIGNING_ACTIVE_KEY_ID":         "access-dev-v1",
		"AGENTERA_CLOUD_ACCESS_SIGNING_KEYS":                  encodedKeyRing("access-dev-v1", accessPrivateKey),
		"AGENTERA_CLOUD_OFFLINE_SIGNING_ACTIVE_KEY_ID":        "offline-dev-v1",
		"AGENTERA_CLOUD_OFFLINE_SIGNING_KEYS":                 encodedKeyRing("offline-dev-v1", offlinePrivateKey),
		"AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_ACTIVE_KEY_ID":  "agent-control-dev-v1",
		"AGENTERA_CLOUD_AGENT_CONTROL_SIGNING_KEYS":           encodedKeyRing("agent-control-dev-v1", agentControlPrivateKey),
		"AGENTERA_CLOUD_OFFLINE_POLICY_VERSION":               "1",
		"AGENTERA_CLOUD_ACTIVE_DEVICE_LIMIT":                  "5",
		"AGENTERA_CLOUD_BROWSER_COOKIE_NAME":                  "agentera_test_session",
		"AGENTERA_CLOUD_BROWSER_SESSION_TTL_SECONDS":          "900",
		"AGENTERA_CLOUD_LOGIN_IDENTITY_LIMIT":                 "5",
		"AGENTERA_CLOUD_LOGIN_IP_LIMIT":                       "20",
		"AGENTERA_CLOUD_LOGIN_WINDOW_SECONDS":                 "600",
		"AGENTERA_CLOUD_WORKSPACE_ACTIVE_OWNED_LIMIT":         "10",
		"AGENTERA_CLOUD_WORKSPACE_MEMBER_LIMIT":               "100",
		"AGENTERA_CLOUD_WORKSPACE_PENDING_INVITE_LIMIT":       "20",
		"AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_LIMIT":          "10",
		"AGENTERA_CLOUD_WORKSPACE_CREATE_RATE_WINDOW":         "1h",
		"AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_LIMIT":          "20",
		"AGENTERA_CLOUD_WORKSPACE_INVITE_RATE_WINDOW":         "1h",
		"AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_LIMIT":          "30",
		"AGENTERA_CLOUD_WORKSPACE_ACCEPT_RATE_WINDOW":         "10m",
		"AGENTERA_CLOUD_ORGANIZATION_OWNED_LIMIT":             "3",
		"AGENTERA_CLOUD_ORGANIZATION_MEMBER_LIMIT":            "500",
		"AGENTERA_CLOUD_ORGANIZATION_DEPARTMENT_LIMIT":        "50",
		"AGENTERA_CLOUD_ORGANIZATION_PENDING_INVITE_LIMIT":    "100",
		"AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_LIMIT":       "6",
		"AGENTERA_CLOUD_ORGANIZATION_CREATE_RATE_WINDOW":      "1h",
		"AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_LIMIT":       "30",
		"AGENTERA_CLOUD_ORGANIZATION_INVITE_RATE_WINDOW":      "1h",
		"AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_LIMIT":       "30",
		"AGENTERA_CLOUD_ORGANIZATION_ACCEPT_RATE_WINDOW":      "10m",
		"AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_LIMIT":     "120",
		"AGENTERA_CLOUD_ORGANIZATION_MUTATION_RATE_WINDOW":    "1h",
		"AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_LIMIT":    "20",
		"AGENTERA_CLOUD_ORGANIZATION_HIGH_RISK_RATE_WINDOW":   "1h",
		"AGENTERA_CLOUD_TERMS_VERSION":                        "terms-2026-07",
		"AGENTERA_CLOUD_PRIVACY_VERSION":                      "privacy-2026-07",
		"AGENTERA_CLOUD_SMTP_HOST":                            "smtp.example.com",
		"AGENTERA_CLOUD_SMTP_PORT":                            "587",
		"AGENTERA_CLOUD_SMTP_USERNAME":                        "smtp-user",
		"AGENTERA_CLOUD_SMTP_PASSWORD":                        "smtp-secret",
		"AGENTERA_CLOUD_SMTP_FROM_ADDRESS":                    "accounts@example.com",
		"AGENTERA_CLOUD_SMTP_FROM_NAME":                       "AgentEra",
		"AGENTERA_CLOUD_SMS_ENDPOINT":                         "https://sms.example.com/verify",
		"AGENTERA_CLOUD_SMS_API_KEY":                          "sms-secret",
		"AGENTERA_CLOUD_SMS_SENDER_ID":                        "AgentEra",
		"AGENTERA_CLOUD_CAPTCHA_ENDPOINT":                     "https://captcha.example.com/verify",
		"AGENTERA_CLOUD_CAPTCHA_SECRET":                       "captcha-secret",
	}
}

func encodedKeyRing(keyID string, material []byte) string {
	return fmt.Sprintf(`{"%s":"%s"}`, keyID, base64.StdEncoding.EncodeToString(material))
}

func mapLookup(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func assertConfigField(t *testing.T, cfg Config, name string, expected any) {
	t.Helper()
	field := reflect.ValueOf(cfg).FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("Config.%s does not exist", name)
	}
	actual := field.Interface()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Config.%s = %#v, want %#v", name, actual, expected)
	}
}
