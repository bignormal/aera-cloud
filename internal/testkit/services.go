package testkit

import (
	"os"
	"testing"
)

type Services struct {
	DatabaseURL   string
	RedisAddr     string
	RedisUsername string
	RedisPassword string
	RedisDB       int
}

func IntegrationServices(t testing.TB) Services {
	t.Helper()
	if os.Getenv("AERA_INTEGRATION_TESTS") != "1" {
		t.Skip("set AERA_INTEGRATION_TESTS=1 to run service integration tests")
	}
	return Services{
		DatabaseURL:   required(t, "AGENTERA_CLOUD_DATABASE_URL"),
		RedisAddr:     required(t, "AGENTERA_CLOUD_REDIS_ADDR"),
		RedisUsername: required(t, "AGENTERA_CLOUD_REDIS_USERNAME"),
		RedisPassword: required(t, "AGENTERA_CLOUD_REDIS_PASSWORD"),
		RedisDB:       9,
	}
}

func required(t testing.TB, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s is required for integration tests", key)
	}
	return value
}
