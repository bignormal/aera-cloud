package api

import (
	"os"
	"strings"
	"testing"
)

func TestInternalAdminOpenAPIRequiresDualAuthenticationAndElevenRoutes(t *testing.T) {
	raw, err := os.ReadFile("openapi/internal-admin.yaml")
	if err != nil {
		t.Fatalf("read Internal Admin OpenAPI: %v", err)
	}
	document := string(raw)
	if !strings.Contains(document, "version: 1.0.0") ||
		!strings.Contains(document, "mutualTLS: { type: mutualTLS }") ||
		!strings.Contains(document, "serviceJWT: { type: http, scheme: bearer, bearerFormat: JWT }") {
		t.Fatal("Internal Admin OpenAPI does not require the approved dual authentication")
	}
	if got := strings.Count(document, "  /internal/admin/v1/"); got != 11 {
		t.Fatalf("Internal Admin route count = %d, want 11", got)
	}
	for _, forbidden := range []string{"password_hash", "refresh_token_hash", "public_key", "family_id"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("Internal Admin contract exposes %q", forbidden)
		}
	}
}
