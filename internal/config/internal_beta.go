package config

func IsInternalBeta(environment string) bool {
	return environment == "internal_beta"
}

func IsDeployedEnvironment(environment string) bool {
	return IsInternalBeta(environment) || environment == "production"
}

func isKnownEnvironment(environment string) bool {
	switch environment {
	case "development", "test", "internal_beta", "production":
		return true
	default:
		return false
	}
}
