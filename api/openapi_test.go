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

func TestOpenAPIContainsStrictUserAgentControlPlaneContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	if !strings.Contains(document, "version: 0.8.0") {
		t.Fatal("OpenAPI version was not advanced for Official Managed Agent V1")
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
		"organization_submission_self_review", "organization_submission_conflict",
		"organization_submission_superseded", "organization_publication_policy_blocked",
		"organization_publication_dlp_blocked",
	} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing Organization Agent error code %q", code)
		}
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

func TestOpenAPIContainsStrictOrganizationFoundationContract(t *testing.T) {
	contents, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	document := string(contents)
	if !strings.HasPrefix(document, "openapi: 3.0.3\n") || !strings.Contains(document, "version: 0.8.0") {
		t.Fatal("OpenAPI did not preserve Organization Foundation in the Official Managed Agent 0.8.0 contract")
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
		"authentication_required", "organization_forbidden", "organization_not_found", "organization_conflict",
		"organization_archived", "organization_limit_reached", "organization_owner_transfer_required",
		"owner_transfer_target_invalid", "membership_conflict", "member_limit_reached", "department_not_empty",
		"department_limit_reached", "invitation_limit_reached", "policy_version_conflict", "dissolution_blocked",
	} {
		if !strings.Contains(document, "- "+code) {
			t.Fatalf("OpenAPI is missing Organization error code %q", code)
		}
	}
	start := strings.Index(document, "    OrganizationRole:\n")
	end := strings.Index(document, "    SigningKeySet:\n")
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
