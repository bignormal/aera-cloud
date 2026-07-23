package config

import (
	"strings"
	"testing"
)

func TestLoadAcceptsOnlyKnownEnvironmentsIncludingInternalBeta(t *testing.T) {
	for _, environment := range []string{"development", "test", "internal_beta", "production"} {
		t.Run(environment, func(t *testing.T) {
			cfg, err := Load(mapLookup(validEnvironment(environment)))
			if err != nil {
				t.Fatalf("Load(%q) error = %v", environment, err)
			}
			if cfg.Environment != environment {
				t.Fatalf("Environment = %q, want %q", cfg.Environment, environment)
			}
		})
	}

	for _, environment := range []string{"", "staging", "Internal_Beta", "internal-beta"} {
		t.Run("reject_"+environment, func(t *testing.T) {
			env := validEnvironment("development")
			env["AGENTERA_CLOUD_ENVIRONMENT"] = environment
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), "AGENTERA_CLOUD_ENVIRONMENT") {
				t.Fatalf("Load(%q) error = %v, want environment validation", environment, err)
			}
		})
	}
}

func TestInternalBetaRequiresRemoteHTTPSOrigin(t *testing.T) {
	env := validEnvironment("internal_beta")
	env["AGENTERA_CLOUD_PUBLIC_URL"] = "http://192.0.2.10"
	if _, err := Load(mapLookup(env)); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("remote HTTP Load() error = %v, want HTTPS rejection", err)
	}

	for _, raw := range []string{
		"https://user@example.com",
		"https://example.com/path",
		"https://example.com?query=1",
		"https://example.com#fragment",
	} {
		t.Run(raw, func(t *testing.T) {
			env := validEnvironment("internal_beta")
			env["AGENTERA_CLOUD_PUBLIC_URL"] = raw
			if _, err := Load(mapLookup(env)); err == nil {
				t.Fatalf("Load(%q) succeeded, want exact-origin rejection", raw)
			}
		})
	}
}
