package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubHealthChecker struct {
	err   error
	calls int
}

func (s *stubHealthChecker) Ping(context.Context) error {
	s.calls++
	return s.err
}

func TestLiveDoesNotProbeDependencies(t *testing.T) {
	postgres := &stubHealthChecker{err: errors.New("postgres secret should not leak")}
	redis := &stubHealthChecker{err: errors.New("redis secret should not leak")}
	handler := New(Dependencies{PostgreSQL: postgres, Redis: redis})

	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
	}
	if strings.TrimSpace(response.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("body = %q", response.Body.String())
	}
	if postgres.calls != 0 || redis.calls != 0 {
		t.Fatalf("live endpoint probed dependencies: postgres=%d redis=%d", postgres.calls, redis.calls)
	}
}

func TestReadyReturnsOKWhenDependenciesRespond(t *testing.T) {
	postgres := &stubHealthChecker{}
	redis := &stubHealthChecker{}
	handler := New(Dependencies{PostgreSQL: postgres, Redis: redis})

	request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	if strings.TrimSpace(response.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("body = %q", response.Body.String())
	}
	if postgres.calls != 1 || redis.calls != 1 {
		t.Fatalf("ready probes = postgres:%d redis:%d, want one each", postgres.calls, redis.calls)
	}
}

func TestReadyFailsClosedWithoutLeakingDependencyErrors(t *testing.T) {
	tests := []struct {
		name        string
		postgresErr error
		redisErr    error
	}{
		{name: "postgres unavailable", postgresErr: errors.New("postgres://user:secret@db/private")},
		{name: "redis unavailable", redisErr: errors.New("redis password=secret")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := New(Dependencies{
				PostgreSQL: &stubHealthChecker{err: tt.postgresErr},
				Redis:      &stubHealthChecker{err: tt.redisErr},
			})

			request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
			}
			body := strings.TrimSpace(response.Body.String())
			if body != `{"status":"unavailable"}` {
				t.Fatalf("body = %q", body)
			}
			if strings.Contains(body, "secret") || strings.Contains(body, "private") {
				t.Fatalf("body leaked dependency error: %q", body)
			}
		})
	}
}

func TestReadyFailsClosedWhenDependencyIsMissing(t *testing.T) {
	handler := New(Dependencies{})
	request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestVerificationRoutesAreMountedWithoutChangingHealthContract(t *testing.T) {
	verificationHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/verification/challenges" {
			t.Errorf("verification path = %q", request.URL.Path)
		}
		response.WriteHeader(http.StatusAccepted)
	})
	handler := New(Dependencies{
		PostgreSQL:   &stubHealthChecker{},
		Redis:        &stubHealthChecker{},
		Verification: verificationHandler,
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/verification/challenges", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
}

func TestAccountRoutesAreMountedWithoutChangingHealthContract(t *testing.T) {
	accountHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/legal/current" {
			t.Errorf("account path = %q", request.URL.Path)
		}
		response.WriteHeader(http.StatusOK)
	})
	handler := New(Dependencies{
		PostgreSQL: &stubHealthChecker{},
		Redis:      &stubHealthChecker{},
		Accounts:   accountHandler,
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/legal/current", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestDesktopOAuthRoutesAreMountedWithoutChangingHealthContract(t *testing.T) {
	paths := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/oauth/authorize"},
		{method: http.MethodPost, path: "/api/v1/oauth/token"},
		{method: http.MethodGet, path: "/.well-known/agentera-signing-keys.json"},
	}
	for _, route := range paths {
		t.Run(route.path, func(t *testing.T) {
			oauthHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != route.path {
					t.Errorf("OAuth path = %q", request.URL.Path)
				}
				response.WriteHeader(http.StatusTeapot)
			})
			handler := New(Dependencies{
				PostgreSQL: &stubHealthChecker{}, Redis: &stubHealthChecker{}, OAuth: oauthHandler,
			})
			request := httptest.NewRequest(route.method, route.path, nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusTeapot {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusTeapot)
			}
		})
	}
}
