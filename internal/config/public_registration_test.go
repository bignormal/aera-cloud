package config

import (
	"strings"
	"testing"
)

func TestPublicRegistrationDefaultsOpenOnlyInLocalEnvironments(t *testing.T) {
	development, err := loadPublicRegistration(func(string) (string, bool) {
		return "", false
	}, "development")
	if err != nil || !development {
		t.Fatalf("development registration = %v, %v", development, err)
	}
	for _, environment := range []string{"internal_beta", "production"} {
		enabled, err := loadPublicRegistration(func(string) (string, bool) {
			return "", false
		}, environment)
		if err != nil || enabled {
			t.Fatalf("%s registration = %v, %v", environment, enabled, err)
		}
	}
}

func TestPublicRegistrationRequiresCanonicalBoolean(t *testing.T) {
	for raw, expected := range map[string]bool{"true": true, "false": false} {
		actual, err := loadPublicRegistration(func(key string) (string, bool) {
			if key != "AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED" {
				t.Fatalf("lookup key = %s", key)
			}
			return raw, true
		}, "production")
		if err != nil || actual != expected {
			t.Fatalf("loadPublicRegistration(%q) = %v, %v", raw, actual, err)
		}
	}
	_, err := loadPublicRegistration(func(string) (string, bool) {
		return "enabled", true
	}, "production")
	if err == nil || !strings.Contains(err.Error(), "AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED") {
		t.Fatalf("invalid registration flag error = %v", err)
	}
}
