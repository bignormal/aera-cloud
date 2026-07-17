package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
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
	return router
}

func writeStatus(response http.ResponseWriter, statusCode int, status string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(statusCode)
	_ = json.NewEncoder(response).Encode(map[string]string{"status": status})
}
