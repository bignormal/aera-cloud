package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHandlerServesAssetsAndFallsBackToIndexForAccountRoutes(t *testing.T) {
	handler, err := NewFromFS(fstest.MapFS{
		"index.html":        {Data: []byte("<title>Aera Account</title>")},
		"assets/app.js":     {Data: []byte("export const app = true")},
		"aera-icon.png":     {Data: []byte("png")},
	})
	if err != nil {
		t.Fatalf("NewFromFS() error = %v", err)
	}

	for _, path := range []string{"/login", "/authorize?request_id=opaque", "/devices", "/delete-account"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Aera Account") {
			t.Fatalf("GET %s = %d %q", path, response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Security-Policy") == "" ||
			response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("GET %s security headers = %+v", path, response.Header())
		}
	}

	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "app = true") ||
		!strings.Contains(asset.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("asset response = %d %q headers=%+v", asset.Code, asset.Body.String(), asset.Header())
	}
}

func TestHandlerNeverFallsBackForReservedServicePaths(t *testing.T) {
	handler, err := NewFromFS(fstest.MapFS{"index.html": {Data: []byte("Aera")}})
	if err != nil {
		t.Fatalf("NewFromFS() error = %v", err)
	}
	for _, path := range []string{
		"/api/v1/missing", "/health/missing", "/oauth/missing", "/.well-known/missing",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "Aera") {
			t.Fatalf("reserved GET %s = %d %q", path, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/login", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /login = %d", response.Code)
	}
}

func TestEmbeddedAccountCenterContainsProductionEntryPoint(t *testing.T) {
	handler := New()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "/assets/app.js") {
		t.Fatalf("embedded login = %d %q", response.Code, response.Body.String())
	}
	if _, err := fs.Stat(embeddedAssets, "static/aera-icon.png"); err != nil {
		t.Fatalf("embedded Aera icon: %v", err)
	}
}
