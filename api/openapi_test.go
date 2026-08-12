package api

import (
	"os"
	"strings"
	"testing"
)

func TestOpenAPIUsesAeraVisibleBrandAndRetainsCompatibilityIdentifiers(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, required := range []string{
		"title: Aera Cloud API",
		"contracts for Aera.",
		"enum: [agentera-studio]",
		"X-AgentEra-Desktop-Version",
	} {
		if !strings.Contains(document, required) {
			t.Fatalf("OpenAPI is missing required brand or compatibility fragment %q", required)
		}
	}
	for _, forbidden := range []string{
		"AgentEra App Cloud API",
		"AgentEra Studio",
		"Hermes runtime state",
		"local Hermes state",
		"Hermes profile",
	} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("OpenAPI exposes obsolete user-visible brand fragment %q", forbidden)
		}
	}
}

func TestOpenAPIContainsTaskFourAccountContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/api/v1/accounts/register:",
		"/api/v1/browser/login:",
		"/api/v1/browser/logout:",
		"/api/v1/accounts/password/reset:",
		"/api/v1/legal/current:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, code := range []string{
		"invalid_request", "verification_required", "identity_conflict", "invalid_credentials",
		"device_limit_reached", "device_conflict", "authorization_expired", "authorization_replayed", "session_revoked",
		"account_pending_deletion", "account_disabled", "service_unavailable",
	} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing public error code %q", code)
		}
	}
	if strings.Contains(document, "username") {
		t.Fatal("OpenAPI introduced a username field")
	}
}

func TestOpenAPIContainsDesktopOAuthAndTokenContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/oauth/authorize:",
		"/api/v1/oauth/authorize/approve:",
		"/api/v1/oauth/token:",
		"/api/v1/oauth/refresh:",
		"/api/v1/oauth/revoke:",
		"/.well-known/agentera-signing-keys.json:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, field := range []string{
		"access_token", "access_expires_at", "refresh_token", "refresh_expires_at",
		"offline_entitlement", "offline_expires_at", "user_id", "personal_space_id", "device_id",
	} {
		if !strings.Contains(document, field+":") {
			t.Fatalf("OpenAPI is missing token field %q", field)
		}
	}
	for _, protocolConstraint := range []string{
		"enum: [agentera-studio]", "enum: [S256]", "device_proof", "authorization_code",
		"offline_entitlement", "purpose", "Ed25519",
	} {
		if !strings.Contains(document, protocolConstraint) {
			t.Fatalf("OpenAPI is missing OAuth constraint %q", protocolConstraint)
		}
	}
}

func TestOpenAPIContainsAccountLifecycleAndDeviceContractWithoutAdminHTTP(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/api/v1/accounts/me:",
		"/api/v1/accounts/identities/bind:",
		"/api/v1/accounts/identities/{kind}:",
		"/api/v1/accounts/password/change:",
		"/api/v1/accounts/deletion:",
		"/api/v1/accounts/deletion/recover:",
		"/api/v1/devices:",
		"/api/v1/devices/{device_id}:",
		"/api/v1/devices/current/logout:",
		"/api/v1/devices/self-revoke:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, field := range []string{
		"identity_kinds:", "current_password:", "new_password:", "verification_receipt:",
		"display_name:", "last_seen_at:", "installation_id:", "signature:", "nonce:",
	} {
		if !strings.Contains(document, field) {
			t.Fatalf("OpenAPI is missing lifecycle field %q", field)
		}
	}
	for _, code := range []string{"last_identity", "deletion_window_expired", "device_not_found", "self_revoke_replayed"} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing lifecycle error code %q", code)
		}
	}
	for _, forbidden := range []string{"/api/v1/admin", "/admin/disable", "/admin/audit"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("OpenAPI exposed restricted administration route %q", forbidden)
		}
	}
}

func TestOpenAPIContainsStrictDesktopControlPublicContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, contract := range []string{
		"/api/v1/devices/current/desktop-control/heartbeat:",
		"operationId: submitCurrentDesktopHeartbeat",
		"/api/v1/devices/current/desktop-control/commands/{commandID}/result:",
		"operationId: submitCurrentDesktopCommandResult",
		"DesktopHeartbeatRequest:",
		"DesktopHeartbeatReceipt:",
		"DesktopCommandResultRequest:",
		"DesktopControlCommand:",
	} {
		if !strings.Contains(document, contract) {
			t.Fatalf("OpenAPI is missing Desktop control contract %q", contract)
		}
	}
	for _, schema := range []string{"DesktopHeartbeatRequest", "DesktopCommandResultRequest"} {
		block := openAPISchemaBlock(t, document, schema)
		if !strings.Contains(block, "additionalProperties: false") {
			t.Fatalf("%s is not closed", schema)
		}
		for _, forbidden := range []string{
			"user_id", "device_id", "prompt", "conversation", "memory", "file", "path",
			"log", "secret", "token", "credential",
		} {
			if strings.Contains(strings.ToLower(block), forbidden) {
				t.Fatalf("%s exposes forbidden field %q:\n%s", schema, forbidden, block)
			}
		}
	}
	heartbeat := openAPISchemaBlock(t, document, "DesktopHeartbeatRequest")
	for _, fixed := range []string{
		"required: [display_name, client_version, platform, arch, capabilities, uptime_seconds]",
		"enum: [diagnostics.health.read]",
		"enum: [darwin, windows, linux]",
		"enum: [arm64, x64]",
	} {
		if !strings.Contains(heartbeat, fixed) {
			t.Fatalf("DesktopHeartbeatRequest is missing %q:\n%s", fixed, heartbeat)
		}
	}
	result := openAPISchemaBlock(t, document, "DesktopCommandResultRequest")
	if !strings.Contains(result, "enum: [running, succeeded, failed]") {
		t.Fatalf("DesktopCommandResultRequest is missing the accepted result states:\n%s", result)
	}
	command := openAPISchemaBlock(t, document, "DesktopControlCommand")
	for _, fixed := range []string{
		"enum: [health_check]",
		"enum: [queued, claimed, running, succeeded, failed, expired]",
		"HEALTHY", "DESKTOP_UNHEALTHY", "RUNTIME_UNAVAILABLE", "GATEWAY_UNAVAILABLE",
		"HEALTH_CHECK_TIMEOUT", "CLIENT_INTERRUPTED",
	} {
		if !strings.Contains(command, fixed) {
			t.Fatalf("DesktopControlCommand is missing %q:\n%s", fixed, command)
		}
	}
	if strings.Contains(document, "/internal/admin/") {
		t.Fatal("public OpenAPI exposes an Internal Admin path")
	}
}

func TestOpenAPIContainsStrictUserAgentControlPlaneContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	if !strings.Contains(document, "version: 0.9.0") {
		t.Fatal("OpenAPI version does not include the Official Managed Agent baseline and Official Quality V1")
	}
	for _, path := range []string{
		"/api/v1/agent-definitions:",
		"/api/v1/agent-definitions/{definition_id}:",
		"/api/v1/agent-definitions/{definition_id}/versions:",
		"/api/v1/agent-versions/{version_id}:",
		"/api/v1/agent-versions/{version_id}/revocations:",
		"/api/v1/policy-snapshots/{policy_snapshot_id}:",
		"/api/v1/agent-installations:",
		"/api/v1/agent-installations/{installation_id}/activate:",
		"/api/v1/agent-installations/{installation_id}/select-version:",
		"/api/v1/agent-installations/{installation_id}/archive:",
		"/api/v1/runtime-binding-records:",
		"/api/v1/workspaces/{workspace_id}/agent-definitions:",
		"/api/v1/workspaces/{workspace_id}/agent-definitions/{definition_id}:",
		"/api/v1/workspaces/{workspace_id}/agent-definitions/{definition_id}/versions:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, schema := range []string{
		"AgentDefinition:", "AgentVersion:", "AgentPolicySnapshot:", "AgentInstallation:",
		"RuntimeBindingRecord:", "PublishInitialAgentRequest:", "PublishNextAgentVersionRequest:",
	} {
		if !strings.Contains(document, schema) {
			t.Fatalf("OpenAPI is missing schema %q", schema)
		}
	}
	for _, contract := range []string{
		"Idempotency-Key", "maximum agent publication request body is 2621440 bytes",
		"maximum Agent metadata request body is 65536 bytes", "agent_version", "agent_policy",
		"nullable: true",
	} {
		if !strings.Contains(document, contract) {
			t.Fatalf("OpenAPI is missing Agent contract %q", contract)
		}
	}
	for _, code := range []string{
		"invalid_agent_content", "runtime_incompatible", "invalid_device_proof", "not_found",
		"version_conflict", "idempotency_conflict", "definition_archived", "version_revoked",
		"activation_conflict", "installation_archived",
	} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing Agent error code %q", code)
		}
	}
	for _, forbidden := range []string{
		"AgentDraft", "agent_draft", "memory_scope", "profile_path", "adaptive_state", "api_key", "curator_state",
	} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("OpenAPI exposed local-only Agent state %q", forbidden)
		}
	}
	start := strings.Index(document, "    CreateAgentInstallationRequest:\n")
	end := strings.Index(document, "    ActivateAgentInstallationRequest:\n")
	if start < 0 || end <= start {
		t.Fatal("OpenAPI is missing the bounded installation request schema")
	}
	installationSchema := document[start:end]
	if !strings.Contains(installationSchema, "        workspace_id:\n") ||
		!strings.Contains(installationSchema, "Exact source Workspace") {
		t.Fatalf("installation schema is missing exact Workspace source binding:\n%s", installationSchema)
	}
	for _, forbidden := range []string{"owner_scope:", "tenant_id:", "owner_id:", "actor_user_id:", "actor_role:"} {
		if strings.Contains(installationSchema, forbidden) {
			t.Fatalf("installation schema exposed ownership input %q", forbidden)
		}
	}
}

func TestOpenAPINextAgentVersionRequiresMutableDisplayName(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	start := strings.Index(document, "    PublishNextAgentVersionRequest:\n")
	end := strings.Index(document, "    AgentPublication:\n")
	if start < 0 || end <= start {
		t.Fatal("OpenAPI is missing the bounded next Agent version schema")
	}
	schema := document[start:end]
	if !strings.Contains(schema, "required: [base_version_id, display_name, manifest, bundle]") ||
		!strings.Contains(schema, "        display_name:\n") {
		t.Fatalf("next Agent version schema does not carry mutable display_name:\n%s", schema)
	}
}

func TestOpenAPIExposesStrictAgentManifestV2ModelPolicy(t *testing.T) {
	for _, path := range []string{"openapi.yaml", "openapi/internal-admin.yaml"} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		document := string(contents)
		for _, fragment := range []string{
			"oneOf:\n        - $ref: '#/components/schemas/AgentManifestV1'\n        - $ref: '#/components/schemas/AgentManifestV2'",
			"required: [schema_version, identity, assets, model_policy, tools, dependencies, runtime_compatibility]",
			"required: [mode, allowed_providers, allowed_models]",
			"enum: [user_select, allowlist, fixed]",
		} {
			if !strings.Contains(document, fragment) {
				t.Fatalf("%s is missing Agent Manifest V2 contract %q", path, fragment)
			}
		}
		v2Start := strings.Index(document, "    AgentManifestV2:\n")
		v2End := strings.Index(document[v2Start+1:], "    AgentModelConstraintsV1:\n")
		if v2Start < 0 || v2End < 0 {
			t.Fatalf("%s has no deterministic AgentManifestV2 boundary", path)
		}
		v2 := document[v2Start : v2Start+1+v2End]
		if strings.Contains(v2, "model_constraints:") || !strings.Contains(v2, "model_policy:") {
			t.Fatalf("%s mixes V1 and V2 model fields", path)
		}
	}
}

func TestOpenAPIExposesStrictAgentManifestV3MCPRequirements(t *testing.T) {
	for _, path := range []string{"openapi.yaml", "openapi/internal-admin.yaml"} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		document := string(contents)
		manifestUnion := openAPISchemaBlock(t, document, "AgentManifest")
		for _, reference := range []string{"AgentManifestV1", "AgentManifestV2", "AgentManifestV3"} {
			if !strings.Contains(manifestUnion, "#/components/schemas/"+reference) {
				t.Fatalf("%s AgentManifest union is missing %s", path, reference)
			}
		}

		v3 := openAPISchemaBlock(t, document, "AgentManifestV3")
		for _, fragment := range []string{
			"additionalProperties: false",
			"required: [schema_version, identity, assets, model_policy, mcp_requirements, tools, dependencies, runtime_compatibility]",
			"enum: [3]",
			"maxItems: 32",
			"$ref: '#/components/schemas/AgentMCPRequirementV3'",
		} {
			if !strings.Contains(v3, fragment) {
				t.Fatalf("%s AgentManifestV3 is missing %q:\n%s", path, fragment, v3)
			}
		}
		if strings.Contains(v3, "model_constraints:") {
			t.Fatalf("%s AgentManifestV3 mixes V1 model constraints:\n%s", path, v3)
		}

		requirement := openAPISchemaBlock(t, document, "AgentMCPRequirementV3")
		for _, fragment := range []string{
			"additionalProperties: false", "required: [logical_name, tools, required, permission_reason]",
			"maxItems: 128", "maxLength: 300",
		} {
			if !strings.Contains(requirement, fragment) {
				t.Fatalf("%s AgentMCPRequirementV3 is missing %q:\n%s", path, fragment, requirement)
			}
		}
		for _, forbidden := range []string{
			"url:", "command:", "args:", "env:", "headers:", "token:", "auth:",
			"credential_ref:", "profile_path:", "local_path:",
		} {
			if strings.Contains(requirement, forbidden) {
				t.Fatalf("%s AgentMCPRequirementV3 exposes forbidden field %q:\n%s", path, forbidden, requirement)
			}
		}
	}
}

func TestOpenAPIAgentRuntimeCompatibilityAllowsNullMaximum(t *testing.T) {
	expectations := map[string]string{
		"openapi.yaml":                "maximum_version_exclusive:\n          type: string\n          nullable: true",
		"openapi/internal-admin.yaml": "maximum_version_exclusive: { type: string, nullable: true, minLength: 1, maxLength: 64 }",
	}
	for path, fragment := range expectations {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(contents), fragment) {
			t.Fatalf("%s does not allow a null Agent runtime maximum", path)
		}
	}
}

func TestOpenAPIContainsOrganizationAgentApprovalContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/api/v1/organizations/{organization_id}/agent-definitions:",
		"/api/v1/organizations/{organization_id}/agent-definitions/{definition_id}:",
		"/api/v1/organizations/{organization_id}/agent-definitions/{definition_id}/versions:",
		"/api/v1/organizations/{organization_id}/agent-publication-submissions:",
		"/api/v1/organizations/{organization_id}/agent-publication-submissions/{submission_id}:",
		"/api/v1/organizations/{organization_id}/agent-publication-submissions/{submission_id}/withdraw:",
		"/api/v1/organizations/{organization_id}/agent-publication-submissions/{submission_id}/reviews:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, schema := range []string{
		"OrganizationAgentSubmission:", "OrganizationAgentSubmissionDetail:", "OrganizationAgentReview:",
		"SubmitInitialOrganizationAgentRequest:", "SubmitNextOrganizationAgentRequest:",
		"ReviewOrganizationAgentRequest:", "WithdrawOrganizationAgentRequest:",
	} {
		if !strings.Contains(document, schema) {
			t.Fatalf("OpenAPI is missing schema %q", schema)
		}
	}
	submissionStart := strings.Index(document, "    OrganizationAgentSubmission:\n")
	submissionEnd := strings.Index(document, "    OrganizationAgentSubmissionDetail:\n")
	if submissionStart < 0 || submissionEnd <= submissionStart {
		t.Fatal("OpenAPI is missing the bounded OrganizationAgentSubmission schema")
	}
	submission := document[submissionStart:submissionEnd]
	if !strings.Contains(submission, "        - published_version_id\n") ||
		!strings.Contains(submission, "        published_version_id:\n          type: string\n          format: uuid\n          nullable: true") {
		t.Fatalf("OrganizationAgentSubmission does not require a nullable published_version_id:\n%s", submission)
	}
	installationStart := strings.Index(document, "    CreateAgentInstallationRequest:\n")
	installationEnd := strings.Index(document, "    ActivateAgentInstallationRequest:\n")
	if installationStart < 0 || installationEnd <= installationStart {
		t.Fatal("OpenAPI is missing CreateAgentInstallationRequest")
	}
	installation := document[installationStart:installationEnd]
	normalStart := strings.Index(document, "    NormalAgentInstallationSource:\n")
	normalEnd := strings.Index(document, "    OfficialAgentInstallationSource:\n")
	if normalStart < 0 || normalEnd <= normalStart {
		t.Fatal("OpenAPI is missing normal installation source schema")
	}
	normalInstallation := document[normalStart:normalEnd]
	for _, fragment := range []string{"organization_id:", "oneOf:", "not:"} {
		candidate := installation
		if fragment == "organization_id:" || fragment == "not:" {
			candidate = normalInstallation
		}
		if !strings.Contains(candidate, fragment) {
			t.Fatalf("installation source union is missing %q:\n%s", fragment, candidate)
		}
	}
	for _, code := range []string{
		"organization_agent_not_found", "organization_agent_forbidden", "organization_archived",
		"organization_submission_conflict",
		"organization_submission_superseded", "organization_publication_policy_blocked",
		"organization_publication_dlp_blocked",
	} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing Organization Agent error code %q", code)
		}
	}
	if strings.Contains(document, "organization_submission_self_review") ||
		strings.Contains(document, "self-review is forbidden") {
		t.Fatal("OpenAPI still exposes the removed Organization Agent self-review restriction")
	}
	if strings.Contains(document, "/api/v1/organizations/{organization_id}/agent-definitions:\n    post:") {
		t.Fatal("OpenAPI exposed direct Organization Agent publication")
	}
}

func TestOpenAPIContainsStrictOfficialManagedAgentPublicContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/api/v1/official-agents:",
		"/api/v1/official-agents/{definition_id}:",
		"/api/v1/official-agents/{definition_id}/release:",
		"/api/v1/agent-installations/{installation_id}/managed-update:",
		"/api/v1/agent-installations/{installation_id}/apply-managed-update:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, parameter := range []string{
		"X-AgentEra-Official-Channel", "X-AgentEra-Desktop-Version",
		"X-AgentEra-Product-Context", "X-AgentEra-Product-Context-ID",
	} {
		if !strings.Contains(document, parameter) {
			t.Fatalf("OpenAPI is missing trusted official header %q", parameter)
		}
	}
	for _, schema := range []string{
		"OfficialAgentSummary:", "OfficialAgentDetail:", "OfficialAgentListResponse:",
		"OfficialManagedUpdateResponse:", "ApplyManagedOfficialUpdateRequest:",
		"NormalAgentInstallationSource:", "OfficialAgentInstallationSource:",
	} {
		if !strings.Contains(document, schema) {
			t.Fatalf("OpenAPI is missing schema %q", schema)
		}
	}
	createPathStart := strings.Index(document, "  /api/v1/agent-installations:\n")
	createPathEnd := strings.Index(document, "  /api/v1/agent-installations/{installation_id}/managed-update:\n")
	if createPathStart < 0 || createPathEnd <= createPathStart {
		t.Fatal("OpenAPI is missing the bounded Installation create operation")
	}
	if createOperation := document[createPathStart:createPathEnd]; !strings.Contains(createOperation, "#/components/responses/AgentInstallationError") ||
		strings.Contains(createOperation, "#/components/responses/OfficialAgentError") {
		t.Fatalf("Installation create did not preserve a source-neutral error contract:\n%s", createOperation)
	}
	installationStart := strings.Index(document, "    CreateAgentInstallationRequest:\n")
	installationEnd := strings.Index(document, "    NormalAgentInstallationSource:\n")
	if installationStart < 0 || installationEnd <= installationStart {
		t.Fatal("OpenAPI is missing strict installation source union")
	}
	installation := document[installationStart:installationEnd]
	for _, fragment := range []string{
		"oneOf:", "$ref: '#/components/schemas/NormalAgentInstallationSource'",
		"$ref: '#/components/schemas/OfficialAgentInstallationSource'",
	} {
		if !strings.Contains(installation, fragment) {
			t.Fatalf("installation union is missing %q:\n%s", fragment, installation)
		}
	}
	officialStart := strings.Index(document, "    OfficialAgentInstallationSource:\n")
	officialEnd := strings.Index(document, "    ActivateAgentInstallationRequest:\n")
	if officialStart < 0 || officialEnd <= officialStart {
		t.Fatal("OpenAPI is missing official installation source")
	}
	official := document[officialStart:officialEnd]
	if !strings.Contains(official, "official_release_revision_id:") {
		t.Fatalf("official source lacks release revision:\n%s", official)
	}
	for _, forbidden := range []string{
		"version_id:", "workspace_id:", "organization_id:", "owner_scope:", "platform_id:",
		"user_id:", "device_id:", "policy_snapshot_id:",
	} {
		if strings.Contains(official, forbidden) {
			t.Fatalf("official source exposed forbidden field %q:\n%s", forbidden, official)
		}
	}
	for _, code := range []string{
		"official_agent_not_eligible", "official_release_paused", "official_release_revision_conflict",
		"official_client_version_unsupported", "official_installation_policy_blocked",
		"official_managed_update_conflict", "cloud_unavailable",
	} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing official error code %q", code)
		}
	}
	if strings.Contains(document, "/internal/") || strings.Contains(document, "official_agent_draft") ||
		strings.Contains(document, "official_agent_review") {
		t.Fatal("public OpenAPI exposed Internal Admin official-agent surfaces")
	}
}

func TestOpenAPIContainsStrictOfficialQualityPublicContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	if !strings.Contains(document, "version: 0.9.0") {
		t.Fatal("OpenAPI version was not advanced for Official Quality V1")
	}
	for _, path := range []string{
		"/api/v1/official-agent-quality/events:",
		"/api/v1/official-agent-quality/consents/{purpose}/{action}:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, schema := range []string{
		"OfficialQualityEventRequest", "OfficialQualityEventReceipt",
		"OfficialQualityConsentRequest", "OfficialQualityConsentReceipt",
		"OfficialQualityErrorEnvelope",
	} {
		block := openAPISchemaBlock(t, document, schema)
		if !strings.Contains(block, "additionalProperties: false") {
			t.Fatalf("%s schema is not closed:\n%s", schema, block)
		}
	}
	event := openAPISchemaBlock(t, document, "OfficialQualityEventRequest")
	for _, required := range []string{
		"protocol_version", "consent_version", "event_id", "platform_id", "definition_id",
		"version_id", "release_id", "release_revision_id", "desktop_version", "runtime_version",
		"event_day", "kind", "result", "latency_bucket", "total_token_bucket", "crash_code",
		"feedback_rating", "feedback_reason_codes", "binding_proof", "device_signature",
	} {
		if !strings.Contains(event, required+":") {
			t.Fatalf("official quality event is missing %q:\n%s", required, event)
		}
	}
	for _, fixed := range []string{
		"enum: [metric, explicit_feedback]",
		"enum: [success, user_cancelled, model_error, tool_error, runtime_crash, timeout]",
		"enum: [lt_1s, 1s_5s, 5s_15s, 15s_60s, 60s_180s, gte_180s]",
		"enum: ['0', 1_1k, 1k_4k, 4k_16k, 16k_64k, gte_64k]",
		"enum: [helpful, not_helpful]",
		"uniqueItems: true",
	} {
		if !strings.Contains(event, fixed) {
			t.Fatalf("official quality event is missing fixed contract %q:\n%s", fixed, event)
		}
	}
	for _, forbidden := range []string{
		"free_text", "feedback_text", "conversation", "message", "prompt", "user_id",
		"device_id", "session_id", "memory", "profile", "skill", "attachment", "api_key",
	} {
		if strings.Contains(strings.ToLower(event), forbidden) {
			t.Fatalf("official quality event exposes forbidden property %q:\n%s", forbidden, event)
		}
	}
	consent := openAPISchemaBlock(t, document, "OfficialQualityConsentRequest")
	if !strings.Contains(consent, "required: [consent_version]") ||
		!strings.Contains(consent, "minimum: 1") {
		t.Fatalf("official quality consent request is not revision-bound:\n%s", consent)
	}
}

func openAPISchemaBlock(t *testing.T, document, name string) string {
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

func TestOpenAPIContainsStrictExperienceCandidateContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/api/v1/workspaces/{workspace_id}/agent-definitions/{definition_id}/experience-candidates:",
		"/api/v1/workspaces/{workspace_id}/experience-candidates/mine:",
		"/api/v1/workspaces/{workspace_id}/experience-candidates:",
		"/api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}:",
		"/api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}/review:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, schema := range []string{
		"ExperienceCandidateAsset:", "ExperienceCandidateBundle:", "ExperienceCandidateSummary:",
		"ExperienceCandidateDetail:", "ExperienceCandidateListResponse:", "ReviewExperienceCandidateRequest:",
		"ExperienceCandidateFinding:", "ExperienceCandidateErrorEnvelope:",
	} {
		if !strings.Contains(document, schema) {
			t.Fatalf("OpenAPI is missing candidate schema %q", schema)
		}
	}
	for _, contract := range []string{
		"maximum ExperienceCandidate request body is 1310720 bytes", "experience-candidate-dlp-v1",
		"enum: [APPROVED, REJECTED]", "enum: [text/markdown, text/plain]", "maxItems: 32",
	} {
		if !strings.Contains(document, contract) {
			t.Fatalf("OpenAPI is missing candidate contract %q", contract)
		}
	}
	for _, code := range []string{"invalid_experience_candidate", "candidate_dlp_blocked", "candidate_already_reviewed"} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing candidate error code %q", code)
		}
	}
	reviewStart := strings.Index(document, "  /api/v1/workspaces/{workspace_id}/experience-candidates/{candidate_id}/review:\n")
	if reviewStart < 0 {
		t.Fatal("OpenAPI is missing bounded candidate review operation")
	}
	reviewEnd := strings.Index(document[reviewStart:], "  /api/v1/agent-definitions:\n")
	if reviewEnd < 0 {
		t.Fatal("OpenAPI candidate review operation has no deterministic boundary")
	}
	reviewOperation := document[reviewStart : reviewStart+reviewEnd]
	if !strings.Contains(reviewOperation, "        '413':\n") {
		t.Fatal("candidate review operation does not document its 65536-byte body limit")
	}
	start := strings.Index(document, "    SubmitExperienceCandidateRequest:\n")
	end := strings.Index(document, "    ReviewExperienceCandidateRequest:\n")
	if start < 0 || end <= start {
		t.Fatal("OpenAPI is missing bounded candidate submission/review schemas")
	}
	submissionSchema := document[start:end]
	for _, required := range []string{"source_version_id:", "bundle:", "content_digest:"} {
		if !strings.Contains(submissionSchema, required) {
			t.Fatalf("candidate submission schema is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"definition_id:", "workspace_id:", "owner_scope:", "owner_id:", "profile_path:",
		"source_path:", "installation_id:", "dlp_override:", "reviewed_by_user_id:",
	} {
		if strings.Contains(submissionSchema, forbidden) {
			t.Fatalf("candidate submission schema exposed forbidden input %q", forbidden)
		}
	}
}

func TestOpenAPIContainsStrictOrganizationExperienceCandidateContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/api/v1/organizations/{organization_id}/agent-definitions/{definition_id}/experience-candidates:",
		"/api/v1/organizations/{organization_id}/experience-candidates/mine:",
		"/api/v1/organizations/{organization_id}/experience-candidates:",
		"/api/v1/organizations/{organization_id}/experience-candidates/{candidate_id}:",
		"/api/v1/organizations/{organization_id}/experience-candidates/{candidate_id}/review:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, schema := range []string{
		"SubmitOrganizationExperienceCandidateRequest:",
		"OrganizationExperienceCandidateSummary:",
		"OrganizationExperienceCandidateDetail:",
		"OrganizationExperienceCandidateListResponse:",
	} {
		if !strings.Contains(document, schema) {
			t.Fatalf("OpenAPI is missing Organization candidate schema %q", schema)
		}
	}
	submissionSchema := openAPISchemaBlock(t, document, "SubmitOrganizationExperienceCandidateRequest")
	for _, required := range []string{
		"source_version_id:", "skill_name:", "schema_version:", "dlp_contract_version:", "bundle:",
	} {
		if !strings.Contains(submissionSchema, required) {
			t.Fatalf("Organization candidate submission schema is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"organization_id:", "definition_id:", "actor_user_id:", "role:", "device_id:",
		"origin:", "token:", "profile_path:", "source_path:", "content_digest:",
		"dlp_bypass:", "replacement_content:",
	} {
		if strings.Contains(submissionSchema, forbidden) {
			t.Fatalf("Organization candidate submission schema exposed forbidden input %q", forbidden)
		}
	}
}

func TestOpenAPIContainsStrictWorkspaceControlPlaneContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/api/v1/workspaces:",
		"/api/v1/workspaces/{workspace_id}:",
		"/api/v1/workspaces/{workspace_id}/archive:",
		"/api/v1/workspaces/{workspace_id}/restore:",
		"/api/v1/workspaces/{workspace_id}/members:",
		"/api/v1/workspaces/{workspace_id}/members/{user_id}:",
		"/api/v1/workspaces/{workspace_id}/leave:",
		"/api/v1/workspaces/{workspace_id}/invitations:",
		"/api/v1/workspaces/{workspace_id}/invitations/{invitation_id}:",
		"/api/v1/workspace-invitations/accept:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, schema := range []string{
		"WorkspaceSummary", "WorkspaceMember", "WorkspaceInvitation", "WorkspaceInvitationCreation",
		"WorkspaceInvitationAcceptance", "WorkspaceListResponse", "WorkspaceMemberListResponse",
		"WorkspaceInvitationListResponse", "CreateWorkspaceRequest", "RenameWorkspaceRequest",
		"WorkspaceRevisionRequest", "ChangeWorkspaceMemberRoleRequest", "AcceptWorkspaceInvitationRequest",
	} {
		strictObject := "    " + schema + ":\n      type: object\n      additionalProperties: false"
		if !strings.Contains(document, strictObject) {
			t.Fatalf("OpenAPI is missing strict Workspace schema %q", schema)
		}
	}
	for _, contract := range []string{
		"WorkspaceIdempotencyKey:", "name: Idempotency-Key", "maxLength: 128",
		"owned_workspace_count:", "enum: [owner, admin, member]", "enum: [active, archived]",
		"enum: [writable, archived, owner_unavailable]", "enum: [pending, accepted, revoked, expired]",
		"pattern: '^[A-Za-z0-9_-]{43}$'",
		"pattern: '^agentera://workspace-invitation#[A-Za-z0-9_-]{43}$'",
	} {
		if !strings.Contains(document, contract) {
			t.Fatalf("OpenAPI is missing Workspace contract %q", contract)
		}
	}
	for _, code := range []string{
		"workspace_forbidden", "workspace_not_found", "invitation_unavailable", "workspace_conflict",
		"workspace_archived", "workspace_owner_unavailable", "membership_conflict",
		"workspace_limit_reached", "member_limit_reached", "invitation_limit_reached", "rate_limited",
	} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing Workspace error code %q", code)
		}
	}
	start := strings.Index(document, "    WorkspaceRole:\n")
	end := strings.Index(document, "    OrganizationRole:\n")
	if start < 0 || end <= start {
		t.Fatal("OpenAPI Workspace schema section has no deterministic boundary")
	}
	workspaceSchemas := document[start:end]
	for _, forbidden := range []string{
		"owner_scope:", "MEMORY", "USER:", "profile_path:", "session:", "credential:", "api_key:", "raw_token:",
	} {
		if strings.Contains(workspaceSchemas, forbidden) {
			t.Fatalf("OpenAPI exposed forbidden Workspace persistence field %q", forbidden)
		}
	}
}

func TestOpenAPIContainsStrictOrganizationFoundationContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	if !strings.HasPrefix(document, "openapi: 3.0.3\n") || !strings.Contains(document, "version: 0.9.0") {
		t.Fatal("OpenAPI did not preserve Organization Foundation in the Official Quality 0.9.0 contract")
	}
	for _, path := range []string{
		"/api/v1/organizations:",
		"/api/v1/organizations/{organization_id}:",
		"/api/v1/organizations/{organization_id}/archive:",
		"/api/v1/organizations/{organization_id}/restore:",
		"/api/v1/organizations/{organization_id}/owner-transfer:",
		"/api/v1/organizations/{organization_id}/dissolve:",
		"/api/v1/organizations/{organization_id}/members:",
		"/api/v1/organizations/{organization_id}/members/{user_id}:",
		"/api/v1/organizations/{organization_id}/leave:",
		"/api/v1/organizations/{organization_id}/departments:",
		"/api/v1/organizations/{organization_id}/departments/{department_id}:",
		"/api/v1/organizations/{organization_id}/departments/{department_id}/archive:",
		"/api/v1/organizations/{organization_id}/departments/{department_id}/restore:",
		"/api/v1/organizations/{organization_id}/invitations:",
		"/api/v1/organizations/{organization_id}/invitations/{invitation_id}:",
		"/api/v1/organization-invitations/accept:",
		"/api/v1/organizations/{organization_id}/policy:",
		"/api/v1/organizations/{organization_id}/policy-snapshots:",
		"/api/v1/organization-policy-snapshots/{policy_snapshot_id}:",
		"/api/v1/organizations/{organization_id}/audit-events:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, schema := range []string{
		"OrganizationSummary", "OrganizationMember", "OrganizationDepartment", "OrganizationInvitation",
		"OrganizationInvitationCreation", "OrganizationInvitationAcceptance", "OrganizationPolicySummary",
		"OrganizationPolicySnapshot", "OrganizationAuditEvent", "OrganizationListResponse",
		"OrganizationMemberListResponse", "OrganizationDepartmentListResponse", "OrganizationInvitationListResponse",
		"OrganizationPolicyListResponse", "OrganizationAuditListResponse", "CreateOrganizationRequest",
		"RenameOrganizationRequest", "OrganizationRevisionRequest", "TransferOrganizationOwnerRequest",
		"DissolveOrganizationRequest", "PatchOrganizationMemberRequest", "CreateOrganizationDepartmentRequest",
		"RenameOrganizationDepartmentRequest", "OrganizationDepartmentRevisionRequest",
		"AcceptOrganizationInvitationRequest", "PublishOrganizationPolicyRequest", "OrganizationPolicyDocument",
		"OrganizationErrorEnvelope", "AccountDeletionOwnershipErrorEnvelope",
	} {
		strictObject := "    " + schema + ":\n      type: object\n      additionalProperties: false"
		if !strings.Contains(document, strictObject) {
			t.Fatalf("OpenAPI is missing strict Organization schema %q", schema)
		}
	}
	for _, contract := range []string{
		"OrganizationIdempotencyKey:", "OrganizationPageLimit:", "maximum: 100", "default: 50",
		"OrganizationCursor:", "maxLength: 684", "enum: [owner, admin, auditor, member]",
		"enum: [active, archived, dissolved]", "enum: [writable, archived, dissolved]",
		"pattern: '^agentera://organization-invitation#[A-Za-z0-9_-]{43}$'",
		"pattern: '^[0-9a-f]{64}$'", "pattern: '^[A-Za-z0-9_-]{86}$'",
		"organization_policy", "owned_organization_count:",
	} {
		if !strings.Contains(document, contract) {
			t.Fatalf("OpenAPI is missing Organization contract %q", contract)
		}
	}
	for _, code := range []string{
		"authentication_required", "organization_forbidden", "organization_not_found", "invitation_unavailable",
		"invitation_expired", "invitation_revoked", "invitation_used", "organization_conflict",
		"organization_archived", "organization_limit_reached", "organization_owner_transfer_required",
		"owner_transfer_target_invalid", "membership_conflict", "member_limit_reached", "department_not_empty",
		"department_limit_reached", "invitation_limit_reached", "policy_version_conflict", "dissolution_blocked",
	} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing Organization error code %q", code)
		}
	}
	start := strings.Index(document, "    OrganizationRole:\n")
	end := strings.Index(document, "    EncryptedBackupDeviceRegistrationRequest:\n")
	if start < 0 || end <= start {
		t.Fatal("OpenAPI Organization schema section has no deterministic boundary")
	}
	organizationSchemas := strings.ToLower(document[start:end])
	for _, forbidden := range []string{
		"owner_scope", "runtimebinding", "runtime_binding", "profile", "memory", "session", "credential",
		"api_key", "private_skill", "curator", "token_digest", "email", "phone",
	} {
		if strings.Contains(organizationSchemas, forbidden) {
			t.Fatalf("OpenAPI exposed private/runtime Organization field %q", forbidden)
		}
	}
}

func TestOpenAPIContainsCiphertextOnlyEncryptedProfileBackupContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	for _, path := range []string{
		"/api/v1/encrypted-profile-backups:",
		"/api/v1/encrypted-profile-backups/devices/current:",
		"/api/v1/encrypted-profile-backups/devices:",
		"/api/v1/encrypted-profile-backups/devices/{device_id}:",
		"/api/v1/encrypted-profile-backups/{backup_id}:",
		"/api/v1/encrypted-profile-backups/{backup_id}/chunks/{chunk_index}:",
		"/api/v1/encrypted-profile-backups/{backup_id}/manifest:",
		"/api/v1/encrypted-profile-backups/{backup_id}/seal:",
		"/api/v1/encrypted-profile-backups/{backup_id}/objects/{object_id}:",
		"/api/v1/encrypted-profile-backups/{backup_id}/device-envelopes:",
	} {
		if !strings.Contains(document, path) {
			t.Fatalf("OpenAPI is missing %s", path)
		}
	}
	for _, contract := range []string{
		"EncryptedBackupDeviceRegistrationRequest:",
		"EncryptedBackupInitiateRequest:",
		"EncryptedBackupPublicEnvelope:",
		"EncryptedBackupObjectSpec:",
		"EncryptedBackupDetail:",
		"EncryptedBackupErrorEnvelope:",
		"EncryptedBackupCiphertextSize:",
		"EncryptedBackupCiphertextDigest:",
		"application/octet-stream:",
		"format: binary",
		"pattern: '^[0-9a-f]{64}$'",
		"pattern: '^[A-Za-z0-9_-]+$'",
		"maximum: 1073741824",
		"enum: [initiated, uploading, sealed, deleting, deleted, expired]",
	} {
		if !strings.Contains(document, contract) {
			t.Fatalf("OpenAPI is missing encrypted backup contract %q", contract)
		}
	}
	start := strings.Index(document, "    EncryptedBackupDeviceRegistrationRequest:\n")
	end := strings.Index(document, "    SigningKeySet:\n")
	if start < 0 || end <= start {
		t.Fatal("OpenAPI encrypted backup schema section has no deterministic boundary")
	}
	backupSchemas := strings.ToLower(document[start:end])
	for _, forbidden := range []string{
		"recovery_phrase", "plaintext", "file_path", "profile_path", "filename",
		"conversation", "memory_content", "private_key", "data_encryption_key",
		"manifest_json", "content_json",
	} {
		if strings.Contains(backupSchemas, forbidden) {
			t.Fatalf("OpenAPI exposed encrypted backup plaintext/private field %q", forbidden)
		}
	}
	for _, schema := range []string{
		"EncryptedBackupDeviceRegistrationRequest",
		"EncryptedBackupInitiateRequest",
		"EncryptedBackupPublicEnvelope",
		"EncryptedBackupObjectSpec",
		"EncryptedBackupChunkSpec",
		"EncryptedBackupRecoveryParameters",
		"EncryptedBackupAddDeviceEnvelopeRequest",
		"EncryptedBackupDetail",
		"EncryptedBackupErrorEnvelope",
	} {
		strictObject := "    " + schema + ":\n      type: object\n      additionalProperties: false"
		if !strings.Contains(document, strictObject) {
			t.Fatalf("OpenAPI is missing strict encrypted backup schema %q", schema)
		}
	}
}
