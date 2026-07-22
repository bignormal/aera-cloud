package api

import (
	"os"
	"strings"
	"testing"
)

func TestInternalAdminOpenAPIRequiresDualAuthenticationAndOfficialAgentRoutes(t *testing.T) {
	raw, err := os.ReadFile("openapi/internal-admin.yaml")
	if err != nil {
		t.Fatalf("read Internal Admin OpenAPI: %v", err)
	}
	document := string(raw)
	if !strings.Contains(document, "version: 1.1.0") ||
		!strings.Contains(document, "mutualTLS: { type: mutualTLS }") ||
		!strings.Contains(document, "serviceJWT: { type: http, scheme: bearer, bearerFormat: JWT }") {
		t.Fatal("Internal Admin OpenAPI does not require the approved dual authentication")
	}
	if got := strings.Count(document, "  /internal/admin/v1/"); got != 31 {
		t.Fatalf("Internal Admin route count = %d, want 31", got)
	}
	if got := strings.Count(document, "'200': { $ref: '#/components/responses/Operation' }"); got != 16 {
		t.Fatalf("operation response count = %d, want 16 including all official mutations", got)
	}
	for _, path := range []string{
		"/official-agent-definitions:", "/official-agent-drafts:",
		"/official-agent-submissions:", "/official-agent-versions:",
		"/official-agent-releases:", "/official-agent-audit-events:",
		"/official-agent-releases/{releaseID}/rollback:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("Internal Admin contract is missing %q", path)
		}
	}
	for _, required := range []string{"admin_id", "admin_role", "operation_id", "requester_admin_id", "approval_id", "Idempotency-Key"} {
		if !strings.Contains(document, required) {
			t.Fatalf("Internal Admin contract is missing actor binding %q", required)
		}
	}
	for _, required := range []string{
		"AgentIdentityV1:", "AgentManifestAssetV1:", "AgentBundleAssetV1:",
		"OfficialDraftCreateMutation:", "OfficialDraftUpdateMutation:",
		"OfficialDeveloperEmptyMutation:", "OfficialOperatorEmptyMutation:",
		"OfficialReview:", "ErrorEnvelope:", "PUBLICATION_DLP_BLOCKED", "STATE_CONFLICT",
	} {
		if !strings.Contains(document, required) {
			t.Fatalf("Internal Admin contract is missing strict schema or error %q", required)
		}
	}
	for _, placeholder := range []string{
		"Strict canonical Agent Manifest V1", "Canonical draft content plus digests",
		"Immutable submitted content and terminal review evidence",
		"Immutable published content; excludes", "Current append-only release head",
	} {
		if strings.Contains(document, placeholder) {
			t.Fatalf("Internal Admin contract still has loose placeholder schema %q", placeholder)
		}
	}
	for _, privatePath := range []string{"\n  /api/v1/", "\n  /oauth/", "\n  /.well-known/"} {
		if strings.Contains(document, privatePath) {
			t.Fatalf("Internal Admin contract exposes public route prefix %q", privatePath)
		}
	}
	for _, schema := range []string{"OfficialDraft", "OfficialSubmission", "OfficialVersion", "OfficialRelease"} {
		block := internalAdminSchemaBlock(t, document, schema)
		if !strings.Contains(block, "additionalProperties: false") {
			t.Fatalf("%s schema is not closed", schema)
		}
	}
	versionBlock := internalAdminSchemaBlock(t, document, "OfficialVersion")
	for _, forbidden := range []string{"signing_key_id", "signature"} {
		if strings.Contains(versionBlock, forbidden) {
			t.Fatalf("OfficialVersion exposes %q", forbidden)
		}
	}
	releaseBlock := internalAdminSchemaBlock(t, document, "OfficialRelease")
	if strings.Contains(releaseBlock, "allowlisted_user_ids") || !strings.Contains(releaseBlock, "audience_count") {
		t.Fatal("OfficialRelease must expose audience_count without raw allowlist IDs")
	}
	for _, forbidden := range []string{"password_hash", "refresh_token_hash", "public_key", "family_id"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("Internal Admin contract exposes %q", forbidden)
		}
	}
	publicRaw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read public OpenAPI: %v", err)
	}
	if strings.Contains(string(publicRaw), "/internal/admin/") {
		t.Fatal("public OpenAPI exposes an Internal Admin path")
	}
}

func internalAdminSchemaBlock(t *testing.T, document, name string) string {
	t.Helper()
	schemas := strings.Index(document, "\n  schemas:\n")
	if schemas < 0 {
		t.Fatal("components.schemas is missing")
	}
	document = document[schemas:]
	marker := "\n    " + name + ":\n"
	start := strings.Index(document, marker)
	if start < 0 {
		t.Fatalf("schema %s is missing", name)
	}
	remainder := document[start+len(marker):]
	for offset := 0; offset < len(remainder); {
		next := strings.Index(remainder[offset:], "\n    ")
		if next < 0 {
			return remainder
		}
		end := offset + next
		afterIndent := end + len("\n    ")
		if afterIndent < len(remainder) && remainder[afterIndent] != ' ' {
			return remainder[:end]
		}
		offset = afterIndent
	}
	return remainder
}
