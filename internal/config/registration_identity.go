package config

import (
	"fmt"
	"strings"
)

const envRegistrationIdentityKinds = "AGENTERA_CLOUD_REGISTRATION_IDENTITY_KINDS"

func loadRegistrationIdentityKinds(lookup LookupEnv, mode string) ([]string, error) {
	raw, configured := lookup(envRegistrationIdentityKinds)
	raw = strings.TrimSpace(raw)
	if mode == RegistrationModeDirect {
		if configured && raw != "" && raw != "email" {
			return nil, fmt.Errorf("%s must be email in direct mode", envRegistrationIdentityKinds)
		}
		return []string{"email"}, nil
	}
	if !configured || raw == "" {
		return []string{"email", "phone"}, nil
	}

	enabled := map[string]bool{}
	for _, candidate := range strings.Split(raw, ",") {
		kind := strings.TrimSpace(candidate)
		if kind != "email" && kind != "phone" {
			return nil, fmt.Errorf("%s must contain only email and phone", envRegistrationIdentityKinds)
		}
		if enabled[kind] {
			return nil, fmt.Errorf("%s must not contain duplicate identity kinds", envRegistrationIdentityKinds)
		}
		enabled[kind] = true
	}
	if len(enabled) == 0 {
		return nil, fmt.Errorf("%s must contain at least one identity kind", envRegistrationIdentityKinds)
	}
	kinds := make([]string, 0, len(enabled))
	for _, kind := range []string{"email", "phone"} {
		if enabled[kind] {
			kinds = append(kinds, kind)
		}
	}
	return kinds, nil
}

func registrationIdentityEnabled(kinds []string, expected string) bool {
	for _, kind := range kinds {
		if kind == expected {
			return true
		}
	}
	return false
}
