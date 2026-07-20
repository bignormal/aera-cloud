package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const readinessTimeout = 2 * time.Second

type HealthChecker interface {
	Ping(context.Context) error
}

type Dependencies struct {
	PostgreSQL   HealthChecker
	Redis        HealthChecker
	Verification http.Handler
	Accounts     http.Handler
	OAuth        http.Handler
	Devices      http.Handler
	AgentControl http.Handler
	Workspace    http.Handler
	Web          http.Handler
}

func New(dependencies Dependencies) http.Handler {
	router := chi.NewRouter()
	router.Get("/health/live", func(response http.ResponseWriter, _ *http.Request) {
		writeStatus(response, http.StatusOK, "ok")
	})
	router.Get("/health/ready", func(response http.ResponseWriter, request *http.Request) {
		if dependencies.PostgreSQL == nil || dependencies.Redis == nil {
			writeStatus(response, http.StatusServiceUnavailable, "unavailable")
			return
		}

		ctx, cancel := context.WithTimeout(request.Context(), readinessTimeout)
		defer cancel()
		if dependencies.PostgreSQL.Ping(ctx) != nil || dependencies.Redis.Ping(ctx) != nil {
			writeStatus(response, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeStatus(response, http.StatusOK, "ok")
	})
	if dependencies.Verification != nil {
		router.Handle("/api/v1/verification/*", dependencies.Verification)
	}
	if dependencies.Accounts != nil {
		router.Handle("/api/v1/accounts/*", dependencies.Accounts)
		router.Handle("/api/v1/browser/*", dependencies.Accounts)
		router.Handle("/api/v1/legal/*", dependencies.Accounts)
	}
	if dependencies.OAuth != nil {
		router.Handle("/oauth/*", dependencies.OAuth)
		router.Handle("/api/v1/oauth/*", dependencies.OAuth)
		router.Handle("/.well-known/agentera-signing-keys.json", dependencies.OAuth)
	}
	if dependencies.Devices != nil {
		router.Handle("/api/v1/devices", dependencies.Devices)
		router.Handle("/api/v1/devices/*", dependencies.Devices)
	}
	if dependencies.AgentControl != nil {
		router.Handle("/api/v1/agent-definitions", dependencies.AgentControl)
		router.Handle("/api/v1/agent-definitions/*", dependencies.AgentControl)
		router.Handle("/api/v1/agent-versions/*", dependencies.AgentControl)
		router.Handle("/api/v1/agent-installations", dependencies.AgentControl)
		router.Handle("/api/v1/agent-installations/*", dependencies.AgentControl)
		router.Handle("/api/v1/policy-snapshots/*", dependencies.AgentControl)
		router.Handle("/api/v1/runtime-binding-records", dependencies.AgentControl)
		router.Handle("/api/v1/workspaces/{workspaceID}/agent-definitions", dependencies.AgentControl)
		router.Handle("/api/v1/workspaces/{workspaceID}/agent-definitions/*", dependencies.AgentControl)
		router.Handle("/api/v1/workspaces/{workspaceID}/experience-candidates", dependencies.AgentControl)
		router.Handle("/api/v1/workspaces/{workspaceID}/experience-candidates/*", dependencies.AgentControl)
	}
	if dependencies.Workspace != nil {
		router.Handle("/api/v1/workspaces", dependencies.Workspace)
		router.Handle("/api/v1/workspaces/*", dependencies.Workspace)
		router.Handle("/api/v1/workspace-invitations/*", dependencies.Workspace)
	}
	router.NotFound(func(response http.ResponseWriter, request *http.Request) {
		if dependencies.Web == nil || servicePath(request.URL.Path) {
			http.NotFound(response, request)
			return
		}
		dependencies.Web.ServeHTTP(response, request)
	})
	return router
}

func servicePath(raw string) bool {
	trimmed := strings.TrimPrefix(raw, "/")
	first, _, _ := strings.Cut(trimmed, "/")
	return first == "api" || first == "health" || first == "oauth" || first == ".well-known"
}

func writeStatus(response http.ResponseWriter, statusCode int, status string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(statusCode)
	_ = json.NewEncoder(response).Encode(map[string]string{"status": status})
}
