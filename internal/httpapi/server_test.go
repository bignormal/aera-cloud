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

func TestDeviceRoutesAreMountedWithoutChangingHealthContract(t *testing.T) {
	deviceHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/devices/current/logout" {
			t.Errorf("device path = %q", request.URL.Path)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	handler := New(Dependencies{
		PostgreSQL: &stubHealthChecker{}, Redis: &stubHealthChecker{}, Devices: deviceHandler,
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/devices/current/logout", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestAgentControlRoutesAreMountedWithoutCapturingOtherAPIRoutes(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/agent-definitions"},
		{method: http.MethodGet, path: "/api/v1/agent-definitions/definition-id"},
		{method: http.MethodGet, path: "/api/v1/agent-versions/version-id"},
		{method: http.MethodPost, path: "/api/v1/agent-installations"},
		{method: http.MethodPost, path: "/api/v1/agent-installations/installation-id/activate"},
		{method: http.MethodGet, path: "/api/v1/policy-snapshots/policy-id"},
		{method: http.MethodPost, path: "/api/v1/runtime-binding-records"},
	}
	agentHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusTeapot)
	})
	handler := New(Dependencies{
		PostgreSQL: &stubHealthChecker{}, Redis: &stubHealthChecker{}, AgentControl: agentHandler,
	})
	for _, route := range routes {
		t.Run(route.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
			if response.Code != http.StatusTeapot {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusTeapot)
			}
		})
	}

	unrelated := httptest.NewRecorder()
	handler.ServeHTTP(unrelated, httptest.NewRequest(http.MethodGet, "/api/v1/accounts/me", nil))
	if unrelated.Code != http.StatusNotFound {
		t.Fatalf("unrelated API status = %d, want %d", unrelated.Code, http.StatusNotFound)
	}
}

func TestWorkspaceRoutesAreMountedWithoutCapturingOtherAPIRoutes(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/workspaces"},
		{method: http.MethodPost, path: "/api/v1/workspaces"},
		{method: http.MethodPatch, path: "/api/v1/workspaces/workspace-id"},
		{method: http.MethodGet, path: "/api/v1/workspaces/workspace-id/members"},
		{method: http.MethodPost, path: "/api/v1/workspaces/workspace-id/invitations"},
		{method: http.MethodPost, path: "/api/v1/workspace-invitations/accept"},
	}
	workspaceHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusTeapot)
	})
	handler := New(Dependencies{
		PostgreSQL: &stubHealthChecker{}, Redis: &stubHealthChecker{}, Workspace: workspaceHandler,
	})
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
			if response.Code != http.StatusTeapot {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusTeapot)
			}
		})
	}

	for _, unrelated := range []string{"/api/v1/accounts/me", "/api/v1/agent-definitions", "/api/v1/workspace-missing"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, unrelated, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("unrelated path %s status = %d, want %d", unrelated, response.Code, http.StatusNotFound)
		}
	}
}

func TestOrganizationRoutesAreMountedWithoutCapturingWorkspaceOrAgentRoutes(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/organizations"},
		{method: http.MethodPost, path: "/api/v1/organizations"},
		{method: http.MethodGet, path: "/api/v1/organizations/organization-id"},
		{method: http.MethodGet, path: "/api/v1/organizations/organization-id/members"},
		{method: http.MethodPost, path: "/api/v1/organizations/organization-id/invitations"},
		{method: http.MethodPost, path: "/api/v1/organization-invitations/accept"},
		{method: http.MethodGet, path: "/api/v1/organization-policy-snapshots/snapshot-id"},
	}
	organizationHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusTeapot)
	})
	handler := New(Dependencies{
		PostgreSQL: &stubHealthChecker{}, Redis: &stubHealthChecker{}, Organization: organizationHandler,
	})
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
			if response.Code != http.StatusTeapot {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusTeapot)
			}
		})
	}

	for _, unrelated := range []string{
		"/api/v1/workspaces/workspace-id",
		"/api/v1/agent-definitions/definition-id",
		"/api/v1/organization-missing",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, unrelated, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("unrelated path %s status = %d, want %d", unrelated, response.Code, http.StatusNotFound)
		}
	}
}

func TestWorkspaceAgentRoutesReachAgentControlBeforeWorkspaceWildcard(t *testing.T) {
	agentCalls := 0
	workspaceCalls := 0
	agentHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		agentCalls++
		response.WriteHeader(http.StatusAccepted)
	})
	workspaceHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		workspaceCalls++
		response.WriteHeader(http.StatusTeapot)
	})
	handler := New(Dependencies{
		PostgreSQL: &stubHealthChecker{}, Redis: &stubHealthChecker{},
		AgentControl: agentHandler, Workspace: workspaceHandler,
	})

	for _, path := range []string{
		"/api/v1/workspaces/workspace-id/agent-definitions",
		"/api/v1/workspaces/workspace-id/agent-definitions/definition-id",
		"/api/v1/workspaces/workspace-id/agent-definitions/definition-id/versions",
		"/api/v1/workspaces/workspace-id/agent-definitions/definition-id/experience-candidates",
		"/api/v1/workspaces/workspace-id/experience-candidates",
		"/api/v1/workspaces/workspace-id/experience-candidates/mine",
		"/api/v1/workspaces/workspace-id/experience-candidates/candidate-id",
		"/api/v1/workspaces/workspace-id/experience-candidates/candidate-id/review",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusAccepted {
			t.Fatalf("nested Agent path %s status = %d", path, response.Code)
		}
	}
	workspaceResponse := httptest.NewRecorder()
	handler.ServeHTTP(workspaceResponse, httptest.NewRequest(
		http.MethodGet, "/api/v1/workspaces/workspace-id/members", nil,
	))
	if workspaceResponse.Code != http.StatusTeapot || agentCalls != 8 || workspaceCalls != 1 {
		t.Fatalf("routing calls Agent=%d Workspace=%d status=%d", agentCalls, workspaceCalls, workspaceResponse.Code)
	}
}

func TestOrganizationAgentRoutesReachAgentControlBeforeOrganizationWildcard(t *testing.T) {
	agentCalls := 0
	organizationCalls := 0
	agentHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		agentCalls++
		response.WriteHeader(http.StatusAccepted)
	})
	organizationHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		organizationCalls++
		response.WriteHeader(http.StatusTeapot)
	})
	handler := New(Dependencies{
		PostgreSQL: &stubHealthChecker{}, Redis: &stubHealthChecker{},
		AgentControl: agentHandler, Organization: organizationHandler,
	})

	for _, path := range []string{
		"/api/v1/organizations/organization-id/agent-definitions",
		"/api/v1/organizations/organization-id/agent-definitions/definition-id",
		"/api/v1/organizations/organization-id/agent-definitions/definition-id/versions",
		"/api/v1/organizations/organization-id/agent-publication-submissions",
		"/api/v1/organizations/organization-id/agent-publication-submissions/submission-id",
		"/api/v1/organizations/organization-id/agent-publication-submissions/submission-id/withdraw",
		"/api/v1/organizations/organization-id/agent-publication-submissions/submission-id/reviews",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusAccepted {
			t.Fatalf("nested Organization Agent path %s status = %d", path, response.Code)
		}
	}
	organizationResponse := httptest.NewRecorder()
	handler.ServeHTTP(organizationResponse, httptest.NewRequest(
		http.MethodGet, "/api/v1/organizations/organization-id/members", nil,
	))
	if organizationResponse.Code != http.StatusTeapot || agentCalls != 7 || organizationCalls != 1 {
		t.Fatalf("routing calls Agent=%d Organization=%d status=%d", agentCalls, organizationCalls, organizationResponse.Code)
	}
}

func TestWebAccountCenterHandlesOnlyUnmatchedNonServiceRoutes(t *testing.T) {
	web := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("AgentEra account center: " + request.URL.Path))
	})
	handler := New(Dependencies{
		PostgreSQL: &stubHealthChecker{}, Redis: &stubHealthChecker{}, Web: web,
	})

	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/login", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "/login") {
		t.Fatalf("web page = %d %q", page.Code, page.Body.String())
	}

	for _, path := range []string{"/api/v1/missing", "/health/missing", "/oauth/missing", "/.well-known/missing", "/internal/admin/v1/health"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "account center") {
			t.Fatalf("reserved path %s = %d %q", path, response.Code, response.Body.String())
		}
	}
}
