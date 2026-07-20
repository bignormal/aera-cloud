package agentcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
)

func TestHTTPAgentControlRoutesUseOnlyAccessClaimsAndStrictContracts(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	routes := []struct {
		name       string
		method     string
		path       string
		body       string
		status     int
		idempotent bool
		workspace  bool
	}{
		{name: "list definitions", method: http.MethodGet, path: "/api/v1/agent-definitions", status: http.StatusOK},
		{name: "publish initial", method: http.MethodPost, path: "/api/v1/agent-definitions", body: initialPublicationJSON(), status: http.StatusCreated, idempotent: true},
		{name: "get definition", method: http.MethodGet, path: "/api/v1/agent-definitions/" + fixture.definitionID.String(), status: http.StatusOK},
		{name: "list versions", method: http.MethodGet, path: "/api/v1/agent-definitions/" + fixture.definitionID.String() + "/versions", status: http.StatusOK},
		{name: "publish next", method: http.MethodPost, path: "/api/v1/agent-definitions/" + fixture.definitionID.String() + "/versions", body: nextPublicationJSON(fixture.versionID), status: http.StatusCreated, idempotent: true},
		{name: "get version", method: http.MethodGet, path: "/api/v1/agent-versions/" + fixture.versionID.String(), status: http.StatusOK},
		{name: "get policy snapshot", method: http.MethodGet, path: "/api/v1/policy-snapshots/" + fixture.policyID.String(), status: http.StatusOK},
		{name: "revoke version", method: http.MethodPost, path: "/api/v1/agent-versions/" + fixture.versionID.String() + "/revocations", body: `{"reason_code":"owner_revoked","policy_snapshot_id":"` + fixture.policyID.String() + `"}`, status: http.StatusCreated, idempotent: true},
		{name: "create installation", method: http.MethodPost, path: "/api/v1/agent-installations", body: `{"definition_id":"` + fixture.definitionID.String() + `","version_id":"` + fixture.versionID.String() + `"}`, status: http.StatusCreated, idempotent: true},
		{name: "activate installation", method: http.MethodPost, path: "/api/v1/agent-installations/" + fixture.installationID.String() + "/activate", body: activationJSON(fixture), status: http.StatusOK, idempotent: true},
		{name: "select version", method: http.MethodPost, path: "/api/v1/agent-installations/" + fixture.installationID.String() + "/select-version", body: `{"version_id":"` + fixture.versionID.String() + `"}`, status: http.StatusOK, idempotent: true},
		{name: "archive installation", method: http.MethodPost, path: "/api/v1/agent-installations/" + fixture.installationID.String() + "/archive", body: `{}`, status: http.StatusOK, idempotent: true},
		{name: "record binding", method: http.MethodPost, path: "/api/v1/runtime-binding-records", body: bindingJSON(fixture), status: http.StatusCreated, idempotent: true},
		{name: "list workspace definitions", method: http.MethodGet, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/agent-definitions", status: http.StatusOK, workspace: true},
		{name: "publish workspace initial", method: http.MethodPost, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/agent-definitions", body: initialPublicationJSON(), status: http.StatusCreated, idempotent: true, workspace: true},
		{name: "get workspace definition", method: http.MethodGet, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/agent-definitions/" + fixture.definitionID.String(), status: http.StatusOK, workspace: true},
		{name: "list workspace versions", method: http.MethodGet, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/agent-definitions/" + fixture.definitionID.String() + "/versions", status: http.StatusOK, workspace: true},
		{name: "publish workspace next", method: http.MethodPost, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/agent-definitions/" + fixture.definitionID.String() + "/versions", body: nextPublicationJSON(fixture.versionID), status: http.StatusCreated, idempotent: true, workspace: true},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
			request.Header.Set("Authorization", "Bearer valid-access-token")
			if route.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if route.idempotent {
				request.Header.Set("Idempotency-Key", "idempotency-"+strings.ReplaceAll(route.name, " ", "-"))
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)

			if response.Code != route.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), route.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("response headers = %+v", response.Header())
			}
			body := strings.ToLower(response.Body.String())
			for _, forbidden := range []string{"owner_id", "tenant_id", "profile_path", "memory", "credential", "request_body"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("response leaked %q: %s", forbidden, body)
				}
			}
			if fixture.service.lastPrincipal != fixture.principal {
				t.Fatalf("service principal = %+v, want claims %+v", fixture.service.lastPrincipal, fixture.principal)
			}
			if route.workspace && fixture.service.lastWorkspaceID != fixture.workspaceID {
				t.Fatalf("service Workspace = %s, want %s", fixture.service.lastWorkspaceID, fixture.workspaceID)
			}
		})
	}
}

func TestHTTPAgentControlBindsInstallationToExactWorkspaceWithoutOwnershipFields(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations", strings.NewReader(
		`{"definition_id":"`+fixture.definitionID.String()+`","version_id":"`+fixture.versionID.String()+`","workspace_id":"`+fixture.workspaceID.String()+`"}`,
	))
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "workspace-install")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("Workspace installation response = %d %q", response.Code, response.Body.String())
	}
	if fixture.service.lastInstallationRequest.SourceWorkspaceID == nil ||
		*fixture.service.lastInstallationRequest.SourceWorkspaceID != fixture.workspaceID {
		t.Fatalf("Workspace installation request = %+v", fixture.service.lastInstallationRequest)
	}

	for _, field := range []string{"owner_scope", "tenant_id", "owner_id", "actor_user_id", "actor_role"} {
		body := `{"definition_id":"` + fixture.definitionID.String() + `","version_id":"` + fixture.versionID.String() + `","` + field + `":"forbidden"}`
		forbidden := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations", strings.NewReader(body))
		forbidden.Header.Set("Authorization", "Bearer valid-access-token")
		forbidden.Header.Set("Content-Type", "application/json")
		forbidden.Header.Set("Idempotency-Key", "forbidden-"+field)
		forbiddenResponse := httptest.NewRecorder()
		fixture.handler.ServeHTTP(forbiddenResponse, forbidden)
		if forbiddenResponse.Code != http.StatusBadRequest {
			t.Fatalf("%s response = %d %q", field, forbiddenResponse.Code, forbiddenResponse.Body.String())
		}
	}
}

func TestHTTPAgentControlRejectsAmbiguousBodiesLimitsAndMissingIdempotency(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	tests := []struct {
		name        string
		path        string
		body        string
		contentType string
		idempotency string
		status      int
	}{
		{name: "unknown property", path: "/api/v1/agent-definitions", body: strings.Replace(initialPublicationJSON(), `"display_name":`, `"unexpected":true,"display_name":`, 1), contentType: "application/json", idempotency: "key", status: http.StatusBadRequest},
		{name: "duplicate property", path: "/api/v1/agent-definitions", body: strings.Replace(initialPublicationJSON(), `"display_name":`, `"display_name":"duplicate","display_name":`, 1), contentType: "application/json", idempotency: "key", status: http.StatusBadRequest},
		{name: "second value", path: "/api/v1/agent-definitions", body: initialPublicationJSON() + `{}`, contentType: "application/json", idempotency: "key", status: http.StatusBadRequest},
		{name: "wrong content type", path: "/api/v1/agent-definitions", body: initialPublicationJSON(), contentType: "text/plain", idempotency: "key", status: http.StatusBadRequest},
		{name: "missing idempotency", path: "/api/v1/agent-definitions", body: initialPublicationJSON(), contentType: "application/json", status: http.StatusBadRequest},
		{name: "oversized metadata", path: "/api/v1/agent-installations", body: `{"definition_id":"` + fixture.definitionID.String() + `","version_id":"` + fixture.versionID.String() + `","padding":"` + strings.Repeat("a", metadataRequestBodyLimit) + `"}`, contentType: "application/json", idempotency: "key", status: http.StatusRequestEntityTooLarge},
		{name: "oversized publication", path: "/api/v1/agent-definitions", body: strings.Repeat(" ", publicationRequestBodyLimit+1), contentType: "application/json", idempotency: "key", status: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer valid-access-token")
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			if test.idempotency != "" {
				request.Header.Set("Idempotency-Key", test.idempotency)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
		})
	}
}

func TestHTTPAgentControlRejectsMalformedRevokedAndBrowserOnlyAuthorization(t *testing.T) {
	tests := []struct {
		name          string
		authorization []string
		cookie        bool
		authErr       error
	}{
		{name: "missing bearer"},
		{name: "browser cookie", cookie: true},
		{name: "empty bearer", authorization: []string{"Bearer "}},
		{name: "bearer whitespace", authorization: []string{"Bearer token with space"}},
		{name: "duplicate authorization", authorization: []string{"Bearer one", "Bearer two"}},
		{name: "revoked session", authorization: []string{"Bearer revoked"}, authErr: session.ErrSessionRevoked},
		{name: "invalid token", authorization: []string{"Bearer invalid"}, authErr: session.ErrInvalidAccessToken},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentControlHTTPFixture(t)
			fixture.authenticator.err = test.authErr
			request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-definitions", nil)
			for _, value := range test.authorization {
				request.Header.Add("Authorization", value)
			}
			if test.cookie {
				request.AddCookie(&http.Cookie{Name: "agentera_browser_session", Value: "browser-session"})
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"session_revoked"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			if (len(test.authorization) != 1 || !strings.HasPrefix(test.authorization[0], "Bearer ") || strings.Contains(test.authorization[0][7:], " ")) && fixture.authenticator.calls != 0 {
				t.Fatalf("authenticator calls = %d", fixture.authenticator.calls)
			}
		})
	}
}

func TestHTTPAgentControlMapsStableServiceErrorsWithoutDisclosingObjectExistence(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{ErrNotFound, http.StatusNotFound, "not_found"},
		{ErrVersionConflict, http.StatusConflict, "version_conflict"},
		{ErrIdempotencyConflict, http.StatusConflict, "idempotency_conflict"},
		{ErrDefinitionArchived, http.StatusConflict, "definition_archived"},
		{ErrVersionRevoked, http.StatusConflict, "version_revoked"},
		{ErrActivationConflict, http.StatusConflict, "activation_conflict"},
		{ErrInstallationArchived, http.StatusConflict, "installation_archived"},
		{ErrWorkspaceForbidden, http.StatusForbidden, "workspace_forbidden"},
		{ErrWorkspaceArchived, http.StatusConflict, "workspace_archived"},
		{ErrWorkspaceOwnerUnavailable, http.StatusConflict, "workspace_owner_unavailable"},
		{ErrInvalidRequest, http.StatusBadRequest, "invalid_request"},
		{ErrInvalidRepositoryCommand, http.StatusBadRequest, "invalid_request"},
		{ErrInvalidAgentContent, http.StatusBadRequest, "invalid_agent_content"},
		{ErrInvalidExperienceCandidate, http.StatusBadRequest, "invalid_experience_candidate"},
		{ErrExperienceCandidateAlreadyReviewed, http.StatusConflict, "candidate_already_reviewed"},
		{ErrRuntimeIncompatible, http.StatusBadRequest, "runtime_incompatible"},
		{ErrInvalidDeviceProof, http.StatusBadRequest, "invalid_device_proof"},
		{ErrServiceUnavailable, http.StatusServiceUnavailable, "service_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			fixture := newAgentControlHTTPFixture(t)
			fixture.service.err = test.err
			request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-definitions/"+fixture.definitionID.String(), nil)
			request.Header.Set("Authorization", "Bearer valid-access-token")
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) ||
				strings.Contains(response.Body.String(), fixture.definitionID.String()) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
		})
	}
}

func TestHTTPAgentControlRejectsWrongMethodAndMalformedActivationProof(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	wrongMethod := httptest.NewRequest(http.MethodDelete, "/api/v1/agent-definitions", nil)
	wrongMethod.Header.Set("Authorization", "Bearer valid-access-token")
	wrongResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(wrongResponse, wrongMethod)
	if wrongResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method response = %d %q", wrongResponse.Code, wrongResponse.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations/"+fixture.installationID.String()+"/activate", strings.NewReader(
		`{"runtime_profile_id":"`+fixture.profileID.String()+`","version_digest":"not-hex","timestamp":1784448000,"device_proof":"not-base64"}`,
	))
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "activate")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("malformed activation response = %d %q", response.Code, response.Body.String())
	}
}

func TestHTTPAgentControlRejectsMalformedWorkspacePath(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/workspaces/not-a-uuid/agent-definitions",
		nil,
	)
	request.Header.Set("Authorization", "Bearer valid-access-token")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("malformed Workspace response = %d %q", response.Code, response.Body.String())
	}
}

type agentControlHTTPFixture struct {
	handler        http.Handler
	service        *stubAgentControlHTTPService
	authenticator  *stubAgentControlAuthenticator
	principal      Principal
	workspaceID    uuid.UUID
	definitionID   uuid.UUID
	versionID      uuid.UUID
	installationID uuid.UUID
	candidateID    uuid.UUID
	policyID       uuid.UUID
	profileID      uuid.UUID
	digest         [sha256.Size]byte
}

func newAgentControlHTTPFixture(t *testing.T) *agentControlHTTPFixture {
	t.Helper()
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New()}
	workspaceID := uuid.New()
	definitionID, versionID := uuid.New(), uuid.New()
	installationID, policyID, profileID := uuid.New(), uuid.New(), uuid.New()
	candidateID := uuid.New()
	digest := sha256.Sum256([]byte("version"))
	latest := versionID
	now := time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC)
	definition := Definition{ID: definitionID, DisplayName: "Research Agent", Status: definitionStatusActive, LatestVersionID: &latest, CreatedAt: now, UpdatedAt: now}
	version := Version{
		ID: versionID, DefinitionID: definitionID, VersionNumber: 1,
		CanonicalManifest: []byte(`{"schema_version":1}`), Bundle: []byte(`{"assets":[]}`), ContentDigest: digest,
		SigningKeyID: "agent-control-v1", Signature: make([]byte, 64), RuntimeMinimumVersion: "v0.18.2-agentera.1", PublishedAt: now,
	}
	policy := PolicySnapshot{
		ID: policyID, InstallationID: installationID, AgentVersionID: versionID, PolicyVersion: 1,
		Document: []byte(`{"schema_version":1}`), ContentDigest: sha256.Sum256([]byte(`{"schema_version":1}`)),
		Issuer: "https://accounts.example.com", SigningKeyID: "agent-control-v1", Signature: make([]byte, 64), CreatedAt: now,
	}
	installation := Installation{
		ID: installationID, DeviceID: principal.DeviceID, DeviceInstallationID: uuid.New(),
		DefinitionID: definitionID, SelectedVersionID: versionID, RuntimeProfileID: &profileID,
		PolicySnapshotID: &policyID, UpdatePolicy: installationUpdatePolicy, Status: InstallationStatusActive,
		CreatedAt: now, UpdatedAt: now, ActivatedAt: &now,
	}
	candidateBundle := validExperienceCandidateBundle()
	candidateCanonical, err := CanonicalizeExperienceCandidate(candidateBundle)
	if err != nil {
		t.Fatalf("CanonicalizeExperienceCandidate() error = %v", err)
	}
	candidate := ExperienceCandidate{
		ID: candidateID, WorkspaceID: workspaceID, AgentDefinitionID: definitionID,
		SourceAgentVersionID: versionID, SubmittedByUserID: &principal.UserID,
		SubmittedFromDeviceID: &principal.DeviceID, SkillName: candidateBundle.SkillName,
		DLPContractVersion: ExperienceCandidateDLPVersion, ContentDigest: candidateCanonical.ContentDigest,
		Bundle: candidateCanonical.Bundle, CreatedAt: now,
	}
	service := &stubAgentControlHTTPService{
		definitions: []Definition{definition}, definition: definition, versions: []Version{version}, version: version,
		publication: Publication{Definition: definition, Version: version},
		creation:    InstallationCreation{Installation: installation, Policy: policy}, policy: policy, installation: installation,
		revocation: VersionRevocation{ID: uuid.New(), VersionID: versionID, ReasonCode: "owner_revoked", PolicySnapshotID: policyID, CreatedAt: now},
		binding: RuntimeBindingRecord{
			ID: uuid.New(), DeviceID: principal.DeviceID, AgentInstallationID: installationID, AgentVersionID: versionID,
			RuntimeProfileID: profileID, RuntimeVersion: "0.18.2-agentera.1", PolicySnapshotID: policyID,
			ToolPermissionDigest: sha256.Sum256([]byte("tools")), CreatedAt: now,
		},
		candidates: []ExperienceCandidate{candidate}, candidate: candidate,
	}
	authenticator := &stubAgentControlAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
		UserID: principal.UserID, DeviceID: principal.DeviceID, PersonalSpaceID: principal.PersonalSpaceID, SessionID: uuid.New(),
	}}}
	return &agentControlHTTPFixture{
		handler: NewHandler(HTTPConfig{Service: service, AccessTokens: authenticator}),
		service: service, authenticator: authenticator, principal: principal,
		workspaceID: workspaceID, definitionID: definitionID, versionID: versionID, installationID: installationID,
		policyID: policyID, profileID: profileID, candidateID: candidateID, digest: digest,
	}
}

type stubAgentControlHTTPService struct {
	lastPrincipal            Principal
	lastWorkspaceID          uuid.UUID
	lastInstallationRequest  CreateInstallationRequest
	err                      error
	definitions              []Definition
	definition               Definition
	versions                 []Version
	version                  Version
	publication              Publication
	creation                 InstallationCreation
	policy                   PolicySnapshot
	installation             Installation
	revocation               VersionRevocation
	binding                  RuntimeBindingRecord
	candidates               []ExperienceCandidate
	candidate                ExperienceCandidate
	lastCandidateSubmit      SubmitExperienceCandidateRequest
	lastCandidateReview      ReviewExperienceCandidateRequest
	lastCandidateID          uuid.UUID
	lastCandidateRequestID   string
	candidateSubmitCalls     int
	candidateReviewCalls     int
	candidateOwnListCalls    int
	candidateReviewListCalls int
}

func (s *stubAgentControlHTTPService) ListDefinitions(_ context.Context, principal Principal) ([]Definition, error) {
	s.lastPrincipal = principal
	return s.definitions, s.err
}

func (s *stubAgentControlHTTPService) PublishInitial(_ context.Context, principal Principal, _ PublishInitialRequest) (Publication, error) {
	s.lastPrincipal = principal
	return s.publication, s.err
}

func (s *stubAgentControlHTTPService) GetDefinition(_ context.Context, principal Principal, _ uuid.UUID, _ string) (Definition, error) {
	s.lastPrincipal = principal
	return s.definition, s.err
}

func (s *stubAgentControlHTTPService) ListVersions(_ context.Context, principal Principal, _ uuid.UUID, _ string) ([]Version, error) {
	s.lastPrincipal = principal
	return s.versions, s.err
}

func (s *stubAgentControlHTTPService) PublishNext(_ context.Context, principal Principal, _ PublishNextRequest) (Publication, error) {
	s.lastPrincipal = principal
	return s.publication, s.err
}

func (s *stubAgentControlHTTPService) GetVersion(_ context.Context, principal Principal, _ uuid.UUID, _ string) (Version, error) {
	s.lastPrincipal = principal
	return s.version, s.err
}

func (s *stubAgentControlHTTPService) GetPolicySnapshot(_ context.Context, principal Principal, _ uuid.UUID, _ string) (PolicySnapshot, error) {
	s.lastPrincipal = principal
	return s.policy, s.err
}

func (s *stubAgentControlHTTPService) RevokeVersion(_ context.Context, principal Principal, _ RevokeVersionRequest) (VersionRevocation, error) {
	s.lastPrincipal = principal
	return s.revocation, s.err
}

func (s *stubAgentControlHTTPService) CreateInstallation(_ context.Context, principal Principal, request CreateInstallationRequest) (InstallationCreation, error) {
	s.lastPrincipal = principal
	s.lastInstallationRequest = request
	return s.creation, s.err
}

func (s *stubAgentControlHTTPService) ListWorkspaceDefinitions(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]Definition, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	return s.definitions, s.err
}

func (s *stubAgentControlHTTPService) PublishWorkspaceInitial(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	_ PublishInitialRequest,
) (Publication, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	return s.publication, s.err
}

func (s *stubAgentControlHTTPService) GetWorkspaceDefinition(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	_ uuid.UUID,
	_ string,
) (Definition, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	return s.definition, s.err
}

func (s *stubAgentControlHTTPService) ListWorkspaceVersions(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	_ uuid.UUID,
	_ string,
) ([]Version, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	return s.versions, s.err
}

func (s *stubAgentControlHTTPService) PublishWorkspaceNext(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	_ PublishNextRequest,
) (Publication, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	return s.publication, s.err
}

func (s *stubAgentControlHTTPService) ActivateInstallation(_ context.Context, principal Principal, _ ActivateInstallationRequest) (Installation, error) {
	s.lastPrincipal = principal
	return s.installation, s.err
}

func (s *stubAgentControlHTTPService) SelectInstallationVersion(_ context.Context, principal Principal, _ SelectInstallationVersionRequest) (Installation, error) {
	s.lastPrincipal = principal
	return s.installation, s.err
}

func (s *stubAgentControlHTTPService) ArchiveInstallation(_ context.Context, principal Principal, _ ArchiveInstallationRequest) (Installation, error) {
	s.lastPrincipal = principal
	return s.installation, s.err
}

func (s *stubAgentControlHTTPService) RecordRuntimeBinding(_ context.Context, principal Principal, _ RuntimeBindingRecordCommand, _ string) (RuntimeBindingRecord, error) {
	s.lastPrincipal = principal
	return s.binding, s.err
}

func (s *stubAgentControlHTTPService) SubmitExperienceCandidate(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	request SubmitExperienceCandidateRequest,
) (ExperienceCandidate, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	s.lastCandidateSubmit = request
	s.candidateSubmitCalls++
	return s.candidate, s.err
}

func (s *stubAgentControlHTTPService) ListOwnExperienceCandidates(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]ExperienceCandidate, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	s.candidateOwnListCalls++
	return s.candidates, s.err
}

func (s *stubAgentControlHTTPService) ListWorkspaceExperienceCandidates(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
) ([]ExperienceCandidate, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	s.candidateReviewListCalls++
	return s.candidates, s.err
}

func (s *stubAgentControlHTTPService) GetExperienceCandidate(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	candidateID uuid.UUID,
	requestID string,
) (ExperienceCandidate, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	s.lastCandidateID = candidateID
	s.lastCandidateRequestID = requestID
	return s.candidate, s.err
}

func (s *stubAgentControlHTTPService) ReviewExperienceCandidate(
	_ context.Context,
	principal Principal,
	workspaceID uuid.UUID,
	request ReviewExperienceCandidateRequest,
) (ExperienceCandidate, error) {
	s.lastPrincipal = principal
	s.lastWorkspaceID = workspaceID
	s.lastCandidateID = request.CandidateID
	s.lastCandidateReview = request
	s.candidateReviewCalls++
	return s.candidate, s.err
}

type stubAgentControlAuthenticator struct {
	claims session.AccessClaims
	err    error
	calls  int
}

func (s *stubAgentControlAuthenticator) Authenticate(context.Context, string) (session.AccessClaims, error) {
	s.calls++
	return s.claims, s.err
}

func initialPublicationJSON() string {
	return `{"display_name":"Research Agent","manifest":` + validHTTPManifestJSON() + `,"bundle":{"assets":[]}}`
}

func nextPublicationJSON(baseVersionID uuid.UUID) string {
	return `{"base_version_id":"` + baseVersionID.String() + `","manifest":` + validHTTPManifestJSON() + `,"bundle":{"assets":[]}}`
}

func validHTTPManifestJSON() string {
	return `{"schema_version":1,"identity":{"system_prompt":"Research safely"},"assets":[],"model_constraints":{"allowed_providers":["openai"],"allowed_models":["gpt-5.6"]},"tools":{"allowed":["files.read"],"denied":[]},"dependencies":[],"runtime_compatibility":{"minimum_version":"0.18.2-agentera.1"}}`
}

func activationJSON(fixture *agentControlHTTPFixture) string {
	return `{"runtime_profile_id":"` + fixture.profileID.String() + `","version_digest":"` + hex.EncodeToString(fixture.digest[:]) +
		`","timestamp":1784448000,"device_proof":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `"}`
}

func bindingJSON(fixture *agentControlHTTPFixture) string {
	return `{"binding_id":"` + fixture.service.binding.ID.String() + `","agent_installation_id":"` + fixture.installationID.String() +
		`","agent_version_id":"` + fixture.versionID.String() + `","runtime_profile_id":"` + fixture.profileID.String() +
		`","runtime_version":"0.18.2-agentera.1","policy_snapshot_id":"` + fixture.policyID.String() +
		`","tool_permission_digest":"` + hex.EncodeToString(fixture.service.binding.ToolPermissionDigest[:]) + `"}`
}
