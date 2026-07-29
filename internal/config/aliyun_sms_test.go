package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestInternalBetaLoadsPhoneOnlyAliyunVerificationWithoutEmailOrCaptcha(t *testing.T) {
	env := phoneOnlyAliyunEnvironment("internal_beta")
	delete(env, envCaptchaEndpoint)
	delete(env, envCaptchaSecret)

	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RegistrationMode != RegistrationModeVerified ||
		!reflect.DeepEqual(cfg.RegistrationIdentityKinds, []string{"phone"}) {
		t.Fatalf(
			"registration config = %q / %#v",
			cfg.RegistrationMode,
			cfg.RegistrationIdentityKinds,
		)
	}
	if cfg.SMSProvider != SMSProviderAliyun ||
		cfg.AliyunSMSAccessKeyID != "test-access-key-id" ||
		cfg.AliyunSMSAccessKeySecret != "test-access-key-secret" ||
		cfg.AliyunSMSRegionID != "cn-hangzhou" ||
		cfg.AliyunSMSSignName != "郑州雾棠" ||
		cfg.AliyunSMSTemplateCode != "SMS_511000030" {
		t.Fatal("Aliyun SMS configuration was not loaded")
	}
	if cfg.SMTPHost != "" || cfg.SMSEndpoint != "" ||
		cfg.CaptchaEndpoint != "" || cfg.CaptchaSecret != "" {
		t.Fatal("phone-only internal beta unexpectedly loaded unused providers")
	}
}

func TestPhoneOnlyAliyunVerificationRequiresEveryCredential(t *testing.T) {
	for _, key := range []string{
		envAliyunSMSAccessKeyID,
		envAliyunSMSAccessKeySecret,
		envAliyunSMSSignName,
		envAliyunSMSTemplateCode,
	} {
		t.Run(key, func(t *testing.T) {
			env := phoneOnlyAliyunEnvironment("internal_beta")
			delete(env, key)
			if _, err := Load(mapLookup(env)); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("Load() error = %v, want missing %s", err, key)
			}
		})
	}
}

func TestProductionAllowsPhoneOnlyAliyunWithRealCaptcha(t *testing.T) {
	cfg, err := Load(mapLookup(phoneOnlyAliyunEnvironment("production")))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SMSProvider != SMSProviderAliyun ||
		!reflect.DeepEqual(cfg.RegistrationIdentityKinds, []string{"phone"}) {
		t.Fatalf("phone-only production config = %+v", cfg.RegistrationIdentityKinds)
	}
}

func TestRegistrationIdentityKindsAreCanonicalAndModeBound(t *testing.T) {
	env := validEnvironment("development")
	env[envRegistrationIdentityKinds] = "phone,email"
	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(cfg.RegistrationIdentityKinds, []string{"email", "phone"}) {
		t.Fatalf("RegistrationIdentityKinds = %#v", cfg.RegistrationIdentityKinds)
	}

	for _, invalid := range []string{"", "phone,phone", "email,other"} {
		env = validEnvironment("development")
		env[envRegistrationIdentityKinds] = invalid
		if invalid == "" {
			continue
		}
		if _, err := Load(mapLookup(env)); err == nil {
			t.Fatalf("Load() accepted identity kinds %q", invalid)
		}
	}

	env = validEnvironment("internal_beta")
	env[envRegistrationMode] = RegistrationModeDirect
	env[envDirectRegistrationIPLimit] = "30"
	env[envDirectRegistrationWindow] = "1h"
	env[envRegistrationIdentityKinds] = "phone"
	if _, err := Load(mapLookup(env)); err == nil ||
		!strings.Contains(err.Error(), envRegistrationIdentityKinds) {
		t.Fatalf("direct-mode Load() error = %v", err)
	}
}

func phoneOnlyAliyunEnvironment(environment string) map[string]string {
	env := validEnvironment(environment)
	env[envRegistrationMode] = RegistrationModeVerified
	env[envRegistrationIdentityKinds] = "phone"
	env[envSMSProvider] = SMSProviderAliyun
	env[envAliyunSMSAccessKeyID] = "test-access-key-id"
	env[envAliyunSMSAccessKeySecret] = "test-access-key-secret"
	env[envAliyunSMSRegionID] = "cn-hangzhou"
	env[envAliyunSMSSignName] = "郑州雾棠"
	env[envAliyunSMSTemplateCode] = "SMS_511000030"
	for _, key := range []string{
		envSMTPHost,
		envSMTPPort,
		envSMTPUsername,
		envSMTPPassword,
		envSMTPFromAddress,
		envSMTPFromName,
		envSMSEndpoint,
		envSMSAPIKey,
		envSMSSenderID,
	} {
		delete(env, key)
	}
	return env
}
