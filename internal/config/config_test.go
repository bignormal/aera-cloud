package config

import (
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
		"AGENTERA_CLOUD_ENVIRONMENT":    environment,
		"AGENTERA_CLOUD_LISTEN_ADDR":    listenAddr,
		"AGENTERA_CLOUD_PUBLIC_URL":     publicURL,
		"AGENTERA_CLOUD_DATABASE_URL":   "postgres://aera_cloud:secret@postgres:5432/aera_cloud?sslmode=require",
		"AGENTERA_CLOUD_REDIS_ADDR":     "redis:6379",
		"AGENTERA_CLOUD_REDIS_USERNAME": "aera_cloud",
		"AGENTERA_CLOUD_REDIS_PASSWORD": "secret",
		"AGENTERA_CLOUD_REDIS_DB":       "9",
	}
}

func mapLookup(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
