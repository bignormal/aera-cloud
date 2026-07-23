package config

import (
	"fmt"
	"time"
)

const (
	envRegistrationMode             = "AGENTERA_CLOUD_REGISTRATION_MODE"
	envDirectRegistrationIPLimit    = "AGENTERA_CLOUD_DIRECT_REGISTRATION_IP_LIMIT"
	envDirectRegistrationWindow     = "AGENTERA_CLOUD_DIRECT_REGISTRATION_WINDOW"
	RegistrationModeVerified        = "verified"
	RegistrationModeDirect          = "direct"
	maximumDirectRegistrationWindow = 24 * time.Hour
)

func loadRegistrationMode(
	lookup LookupEnv,
	environment string,
) (string, int64, time.Duration, error) {
	mode, ok := lookup(envRegistrationMode)
	if !ok || mode == "" {
		mode = RegistrationModeVerified
	}
	switch mode {
	case RegistrationModeVerified:
		return mode, 0, 0, nil
	case RegistrationModeDirect:
		if !IsInternalBeta(environment) {
			return "", 0, 0, fmt.Errorf("%s=direct is allowed only in internal_beta", envRegistrationMode)
		}
		limit, err := requiredInteger(lookup, envDirectRegistrationIPLimit, 1, 10_000)
		if err != nil {
			return "", 0, 0, err
		}
		window, err := requiredPositiveDuration(lookup, envDirectRegistrationWindow)
		if err != nil {
			return "", 0, 0, err
		}
		if window > maximumDirectRegistrationWindow {
			return "", 0, 0, fmt.Errorf("%s must not exceed 24h", envDirectRegistrationWindow)
		}
		return mode, int64(limit), window, nil
	default:
		return "", 0, 0, fmt.Errorf("%s must be verified or direct", envRegistrationMode)
	}
}
