package main

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
)

func TestServeStopsCleanlyAfterContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, listener, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}))
	}()

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatalf("GET server error = %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		cancel()
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve() did not stop after context cancellation")
	}
}

func TestRunAppliesMigrationsBeforeServing(t *testing.T) {
	services := testkit.IntegrationServices(t)
	databaseCtx, databaseCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer databaseCancel()
	postgres, err := store.OpenPostgres(databaseCtx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if _, err := postgres.Exec(databaseCtx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset test database: %v", err)
	}

	runCtx, stopRun := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() {
		runResult <- run(runCtx, integrationLookup(services))
	}()

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	for {
		var exists bool
		if err := postgres.QueryRow(databaseCtx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
			stopRun()
			t.Fatalf("check schema migrations table: %v", err)
		}
		if exists {
			break
		}
		select {
		case err := <-runResult:
			stopRun()
			t.Fatalf("run() stopped before migrations were applied: %v", err)
		case <-deadline.C:
			stopRun()
			select {
			case <-runResult:
			case <-time.After(time.Second):
			}
			t.Fatal("run() did not apply database migrations")
		case <-poll.C:
		}
	}

	stopRun()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("run() shutdown error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not stop after cancellation")
	}
}

func integrationLookup(services testkit.Services) config.LookupEnv {
	values := map[string]string{
		"AGENTERA_CLOUD_ENVIRONMENT":                       "development",
		"AGENTERA_CLOUD_LISTEN_ADDR":                       "127.0.0.1:0",
		"AGENTERA_CLOUD_PUBLIC_URL":                        "http://127.0.0.1:8086",
		"AGENTERA_CLOUD_DATABASE_URL":                      services.DatabaseURL,
		"AGENTERA_CLOUD_REDIS_ADDR":                        services.RedisAddr,
		"AGENTERA_CLOUD_REDIS_USERNAME":                    services.RedisUsername,
		"AGENTERA_CLOUD_REDIS_PASSWORD":                    services.RedisPassword,
		"AGENTERA_CLOUD_REDIS_DB":                          strconv.Itoa(services.RedisDB),
		"AGENTERA_CLOUD_IDENTITY_ENCRYPTION_ACTIVE_KEY_ID": "enc-test-v1",
		"AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS":          `{"enc-test-v1":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`,
		"AGENTERA_CLOUD_IDENTITY_LOOKUP_ACTIVE_KEY_ID":     "lookup-test-v1",
		"AGENTERA_CLOUD_IDENTITY_LOOKUP_KEYS":              `{"lookup-test-v1":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}`,
	}
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
