package config

import "fmt"

const envPublicRegistrationEnabled = "AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED"

func loadPublicRegistration(lookup LookupEnv, environment string) (bool, error) {
	raw, ok := lookup(envPublicRegistrationEnabled)
	if !ok || raw == "" {
		return environment != "production", nil
	}
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", envPublicRegistrationEnabled)
	}
}
