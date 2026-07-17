package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

func TestEnvironmentExamplePreservesKeyRingJSONWhenSourced(t *testing.T) {
	environmentFile, err := filepath.Abs(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("resolve .env.example: %v", err)
	}
	command := exec.Command(
		"sh",
		"-c",
		`. "$1"; printf '%s\n%s\n' "$AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS" "$AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS"`,
		"sh",
		environmentFile,
	)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("source .env.example: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		t.Fatalf("sourced key ring lines = %d, want 2", len(lines))
	}
	for index, line := range lines {
		var keys map[string]string
		if err := json.Unmarshal([]byte(line), &keys); err != nil {
			t.Fatalf("sourced key ring %d is not JSON: %q: %v", index, line, err)
		}
		if len(keys) != 1 {
			t.Fatalf("sourced key ring %d contains %d keys, want 1", index, len(keys))
		}
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

	return map[string]string{
		"AGENTERA_CLOUD_ENVIRONMENT":                       environment,
		"AGENTERA_CLOUD_LISTEN_ADDR":                       listenAddr,
		"AGENTERA_CLOUD_PUBLIC_URL":                        publicURL,
		"AGENTERA_CLOUD_DATABASE_URL":                      "postgres://aera_cloud:secret@postgres:5432/aera_cloud?sslmode=require",
		"AGENTERA_CLOUD_REDIS_ADDR":                        "redis:6379",
		"AGENTERA_CLOUD_REDIS_USERNAME":                    "aera_cloud",
		"AGENTERA_CLOUD_REDIS_PASSWORD":                    "secret",
		"AGENTERA_CLOUD_REDIS_DB":                          "9",
		"AGENTERA_CLOUD_IDENTITY_ENCRYPTION_ACTIVE_KEY_ID": "enc-dev-v1",
		"AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS":          encodedKeyRing("enc-dev-v1", bytes.Repeat([]byte{1}, 32)),
		"AGENTERA_CLOUD_IDENTITY_LOOKUP_ACTIVE_KEY_ID":     "lookup-dev-v1",
		"AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS":              encodedKeyRing("lookup-dev-v1", bytes.Repeat([]byte{2}, 32)),
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
