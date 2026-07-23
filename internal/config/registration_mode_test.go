package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testRegistrationMode                = "AGENTERA_CLOUD_REGISTRATION_MODE"
	testDirectRegistrationIPLimit       = "AGENTERA_CLOUD_DIRECT_REGISTRATION_IP_LIMIT"
	testDirectRegistrationRequestWindow = "AGENTERA_CLOUD_DIRECT_REGISTRATION_WINDOW"
)

func TestRegistrationModeDefaultsToVerified(t *testing.T) {
	cfg, err := Load(mapLookup(validEnvironment("development")))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertRegistrationField(t, cfg, "RegistrationMode", "verified")
}

func TestInternalBetaDirectRegistrationExplicitlyOmitsDeliveryProviders(t *testing.T) {
	env := validEnvironment("internal_beta")
	env["AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED"] = "true"
	env[testRegistrationMode] = "direct"
	env[testDirectRegistrationIPLimit] = "30"
	env[testDirectRegistrationRequestWindow] = "1h"
	for _, key := range []string{
		"AGENTERA_CLOUD_SMTP_HOST",
		"AGENTERA_CLOUD_SMTP_PORT",
		"AGENTERA_CLOUD_SMTP_USERNAME",
		"AGENTERA_CLOUD_SMTP_PASSWORD",
		"AGENTERA_CLOUD_SMTP_FROM_ADDRESS",
		"AGENTERA_CLOUD_SMTP_FROM_NAME",
		"AGENTERA_CLOUD_SMS_ENDPOINT",
		"AGENTERA_CLOUD_SMS_API_KEY",
		"AGENTERA_CLOUD_SMS_SENDER_ID",
		"AGENTERA_CLOUD_CAPTCHA_ENDPOINT",
		"AGENTERA_CLOUD_CAPTCHA_SECRET",
	} {
		delete(env, key)
	}

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertRegistrationField(t, cfg, "RegistrationMode", "direct")
	assertRegistrationField(t, cfg, "DirectRegistrationIPLimit", int64(30))
	assertRegistrationField(t, cfg, "DirectRegistrationWindow", time.Hour)
	if !cfg.PublicRegistrationEnabled {
		t.Fatal("PublicRegistrationEnabled = false, want explicit true")
	}
}

func TestDirectRegistrationIsInternalBetaOnlyAndExplicit(t *testing.T) {
	for _, environment := range []string{"development", "test", "production"} {
		t.Run(environment, func(t *testing.T) {
			env := validEnvironment(environment)
			env[testRegistrationMode] = "direct"
			env[testDirectRegistrationIPLimit] = "30"
			env[testDirectRegistrationRequestWindow] = "1h"
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), testRegistrationMode) {
				t.Fatalf("Load() error = %v, want direct-mode environment rejection", err)
			}
		})
	}

	env := validEnvironment("internal_beta")
	env["AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED"] = "false"
	env[testRegistrationMode] = "direct"
	env[testDirectRegistrationIPLimit] = "30"
	env[testDirectRegistrationRequestWindow] = "1h"
	if _, err := Load(mapLookup(env)); err == nil || !strings.Contains(err.Error(), "AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED") {
		t.Fatalf("disabled public registration Load() error = %v", err)
	}

	env = validEnvironment("internal_beta")
	env["AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED"] = "true"
	env[testRegistrationMode] = "direct"
	delete(env, testDirectRegistrationIPLimit)
	if _, err := Load(mapLookup(env)); err == nil || !strings.Contains(err.Error(), testDirectRegistrationIPLimit) {
		t.Fatalf("missing limit Load() error = %v", err)
	}
}

func TestDirectRegistrationLimitsAreCanonicalAndBounded(t *testing.T) {
	tests := []struct {
		key   string
		value string
	}{
		{testDirectRegistrationIPLimit, "0"},
		{testDirectRegistrationIPLimit, "10001"},
		{testDirectRegistrationIPLimit, "30.0"},
		{testDirectRegistrationRequestWindow, "0s"},
		{testDirectRegistrationRequestWindow, "25h"},
		{testDirectRegistrationRequestWindow, "3600"},
	}
	for _, test := range tests {
		t.Run(test.key+"_"+test.value, func(t *testing.T) {
			env := validEnvironment("internal_beta")
			env["AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED"] = "true"
			env[testRegistrationMode] = "direct"
			env[testDirectRegistrationIPLimit] = "30"
			env[testDirectRegistrationRequestWindow] = "1h"
			env[test.key] = test.value
			_, err := Load(mapLookup(env))
			if err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %v, want %s validation", err, test.key)
			}
		})
	}
}

func assertRegistrationField(t *testing.T, cfg Config, name string, expected any) {
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
