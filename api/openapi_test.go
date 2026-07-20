package api

import (
	"os"
	"strings"
	"testing"
)

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
		"device_limit_reached", "authorization_expired", "authorization_replayed", "session_revoked",
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
		"enum: [agentera-studio]", "const: S256", "device_proof", "authorization_code",
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

func TestOpenAPIContainsStrictUserAgentControlPlaneContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	if !strings.Contains(document, "version: 0.4.0") {
		t.Fatal("OpenAPI version was not advanced for Workspace Agent V1")
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
		"type: [string, 'null']",
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
	for _, forbidden := range []string{
		"owner_scope:", "MEMORY", "USER:", "profile_path:", "session:", "credential:", "api_key:", "raw_token:",
	} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("OpenAPI exposed forbidden Workspace persistence field %q", forbidden)
		}
	}
}
