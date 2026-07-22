package agentcontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
)

func TestHTTPOfficialCatalogUsesDerivedContextAndSafeResponses(t *testing.T) {
	fixture, official := newOfficialHTTPFixture(t)
	routes := []struct {
		path       string
		wantDetail bool
	}{
		{path: "/api/v1/official-agents"},
		{path: "/api/v1/official-agents/" + fixture.definitionID.String(), wantDetail: true},
		{path: "/api/v1/official-agents/" + fixture.definitionID.String() + "/release"},
	}
	for _, route := range routes {
		request := httptest.NewRequest(http.MethodGet, route.path, nil)
		setOfficialHeaders(request, "USER", "")
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s response = %d %q", route.path, response.Code, response.Body.String())
		}
		body := response.Body.String()
		for _, required := range []string{
			fixture.definitionID.String(), official.entry.Target.ReleaseID.String(),
			official.entry.Target.ReleaseRevisionID.String(), `"official":true`,
		} {
			if !strings.Contains(body, required) {
				t.Fatalf("%s missing %q: %s", route.path, required, body)
			}
		}
		for _, forbidden := range []string{
			"platform_id", "user_id", "device_id", "personal_space_id", "rollout", "allowlist",
			"profile", "memory", "session", "credential", "private_skill", "curator",
		} {
			if strings.Contains(strings.ToLower(body), forbidden) {
				t.Fatalf("%s leaked %q: %s", route.path, forbidden, body)
			}
		}
		if route.wantDetail && (!strings.Contains(body, `"manifest"`) || !strings.Contains(body, `"bundle"`)) {
			t.Fatalf("official detail lacks signed Version material: %s", body)
		}
		if official.lastContext.Selector.Scope != OwnerScopeUser ||
			official.lastContext.Selector.PersonalSpaceID != fixture.principal.PersonalSpaceID ||
			official.lastContext.Selector.WorkspaceID != uuid.Nil || official.lastContext.Selector.OrganizationID != uuid.Nil {
			t.Fatalf("derived official context = %+v", official.lastContext)
		}
	}
}

func TestHTTPOfficialCatalogRejectsUntrustedOrAmbiguousContext(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*http.Request)
	}{
		{name: "missing channel", prepare: func(request *http.Request) {
			setOfficialHeaders(request, "USER", "")
			request.Header.Del("X-AgentEra-Official-Channel")
		}},
		{name: "duplicate channel", prepare: func(request *http.Request) {
			setOfficialHeaders(request, "USER", "")
			request.Header.Add("X-AgentEra-Official-Channel", "stable")
		}},
		{name: "invalid desktop version", prepare: func(request *http.Request) {
			setOfficialHeaders(request, "USER", "")
			request.Header.Set("X-AgentEra-Desktop-Version", "latest")
		}},
		{name: "personal context carries id", prepare: func(request *http.Request) {
			setOfficialHeaders(request, "USER", uuid.NewString())
		}},
		{name: "workspace context missing id", prepare: func(request *http.Request) {
			setOfficialHeaders(request, "WORKSPACE", "")
		}},
		{name: "organization context malformed id", prepare: func(request *http.Request) {
			setOfficialHeaders(request, "ORGANIZATION", "not-a-uuid")
		}},
		{name: "platform product context", prepare: func(request *http.Request) {
			setOfficialHeaders(request, "PLATFORM", uuid.NewString())
		}},
		{name: "unknown query", prepare: func(request *http.Request) {
			setOfficialHeaders(request, "USER", "")
			request.URL.RawQuery = "include=reviews"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, official := newOfficialHTTPFixture(t)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/official-agents", nil)
			test.prepare(request)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			if official.calls != 0 {
				t.Fatalf("official service calls = %d", official.calls)
			}
		})
	}
}

func TestHTTPOfficialInstallationUsesStrictSourceUnion(t *testing.T) {
	fixture, official := newOfficialHTTPFixture(t)
	revisionID := official.entry.Target.ReleaseRevisionID
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations", strings.NewReader(
		`{"definition_id":"`+fixture.definitionID.String()+`","official_release_revision_id":"`+revisionID.String()+`"}`,
	))
	setOfficialHeaders(request, "USER", "")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "official-install")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("official install response = %d %q", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), official.entry.Target.ReleaseID.String()) ||
		!strings.Contains(response.Body.String(), revisionID.String()) || strings.Contains(response.Body.String(), "platform_id") {
		t.Fatalf("official install provenance response = %s", response.Body.String())
	}
	got := fixture.service.lastInstallationRequest
	if got.VersionID != uuid.Nil || got.OfficialReleaseRevisionID == nil || *got.OfficialReleaseRevisionID != revisionID ||
		got.OfficialContext == nil || got.OfficialContext.Selector.PersonalSpaceID != fixture.principal.PersonalSpaceID {
		t.Fatalf("official installation request = %+v", got)
	}

	invalidBodies := []string{
		`{"definition_id":"` + fixture.definitionID.String() + `","version_id":"` + fixture.versionID.String() + `","official_release_revision_id":"` + revisionID.String() + `"}`,
		`{"definition_id":"` + fixture.definitionID.String() + `","official_release_revision_id":"` + revisionID.String() + `","workspace_id":"` + fixture.workspaceID.String() + `"}`,
		`{"definition_id":"` + fixture.definitionID.String() + `","official_release_revision_id":"` + revisionID.String() + `","platform_id":"` + uuid.NewString() + `"}`,
		`{"definition_id":"` + fixture.definitionID.String() + `","official_release_revision_id":"` + revisionID.String() + `","owner_scope":"PLATFORM"}`,
		`{"definition_id":"` + fixture.definitionID.String() + `","official_release_revision_id":"` + revisionID.String() + `","user_id":"` + uuid.NewString() + `"}`,
		`{"definition_id":"` + fixture.definitionID.String() + `","official_release_revision_id":"` + revisionID.String() + `","device_id":"` + uuid.NewString() + `"}`,
		`{"definition_id":"` + fixture.definitionID.String() + `","official_release_revision_id":"` + revisionID.String() + `","policy_snapshot_id":"` + uuid.NewString() + `"}`,
		`{"definition_id":"` + fixture.definitionID.String() + `","definition_id":"` + fixture.definitionID.String() + `","official_release_revision_id":"` + revisionID.String() + `"}`,
	}
	for index, body := range invalidBodies {
		invalid := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations", strings.NewReader(body))
		setOfficialHeaders(invalid, "USER", "")
		invalid.Header.Set("Content-Type", "application/json")
		invalid.Header.Set("Idempotency-Key", "invalid-official-install")
		invalidResponse := httptest.NewRecorder()
		fixture.handler.ServeHTTP(invalidResponse, invalid)
		if invalidResponse.Code != http.StatusBadRequest {
			t.Fatalf("invalid body %d response = %d %q", index, invalidResponse.Code, invalidResponse.Body.String())
		}
	}
}

func TestHTTPOfficialRejectsNonCanonicalPathAndOversizedInstallation(t *testing.T) {
	fixture, _ := newOfficialHTTPFixture(t)
	nonCanonical := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/official-agents/AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
		nil,
	)
	setOfficialHeaders(nonCanonical, "USER", "")
	nonCanonicalResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(nonCanonicalResponse, nonCanonical)
	if nonCanonicalResponse.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical path response = %d %q", nonCanonicalResponse.Code, nonCanonicalResponse.Body.String())
	}

	oversized := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/agent-installations",
		strings.NewReader(`{"padding":"`+strings.Repeat("x", int(metadataRequestBodyLimit))+`"}`),
	)
	setOfficialHeaders(oversized, "USER", "")
	oversized.Header.Set("Content-Type", "application/json")
	oversized.Header.Set("Idempotency-Key", "oversized-official-install")
	oversizedResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized installation response = %d %q", oversizedResponse.Code, oversizedResponse.Body.String())
	}
}

func TestHTTPOfficialRuntimeBindingCarriesOnlyReleaseRevisionProvenance(t *testing.T) {
	fixture, official := newOfficialHTTPFixture(t)
	revisionID := official.entry.Target.ReleaseRevisionID
	fixture.service.binding.OfficialReleaseRevisionID = &revisionID
	body := strings.TrimSuffix(bindingJSON(fixture), "}") + `,"official_release_revision_id":"` + revisionID.String() + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-binding-records", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "official-runtime-binding")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), revisionID.String()) ||
		strings.Contains(response.Body.String(), "platform_id") {
		t.Fatalf("official RuntimeBinding response = %d %q", response.Code, response.Body.String())
	}
	if fixture.service.lastBindingCommand.OfficialReleaseRevisionID == nil ||
		*fixture.service.lastBindingCommand.OfficialReleaseRevisionID != revisionID {
		t.Fatalf("official RuntimeBinding command = %+v", fixture.service.lastBindingCommand)
	}
}

func TestHTTPManagedOfficialUpdateUsesOnlyExactRevisionPair(t *testing.T) {
	fixture, official := newOfficialHTTPFixture(t)
	expectedRevisionID := uuid.New()
	targetRevisionID := official.entry.Target.ReleaseRevisionID
	fixture.service.managedUpdate = OfficialManagedUpdate{
		UpdateAvailable: true, InstallationID: fixture.installationID,
		ExpectedSelectedReleaseRevisionID: expectedRevisionID,
		Target:                            official.entry.Target, Version: official.entry.Version,
	}
	read := httptest.NewRequest(http.MethodGet,
		"/api/v1/agent-installations/"+fixture.installationID.String()+"/managed-update", nil)
	setOfficialHeaders(read, "WORKSPACE", fixture.workspaceID.String())
	readResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(readResponse, read)
	if readResponse.Code != http.StatusOK || !strings.Contains(readResponse.Body.String(), targetRevisionID.String()) ||
		strings.Contains(readResponse.Body.String(), "platform_id") {
		t.Fatalf("managed update response = %d %q", readResponse.Code, readResponse.Body.String())
	}
	if fixture.service.lastManagedUpdateRequest.OfficialContext.Selector.WorkspaceID != fixture.workspaceID {
		t.Fatalf("managed read context = %+v", fixture.service.lastManagedUpdateRequest)
	}

	apply := httptest.NewRequest(http.MethodPost,
		"/api/v1/agent-installations/"+fixture.installationID.String()+"/apply-managed-update",
		strings.NewReader(`{"expected_selected_release_revision_id":"`+expectedRevisionID.String()+`","target_release_revision_id":"`+targetRevisionID.String()+`"}`),
	)
	setOfficialHeaders(apply, "WORKSPACE", fixture.workspaceID.String())
	apply.Header.Set("Content-Type", "application/json")
	apply.Header.Set("Idempotency-Key", "apply-managed-update")
	applyResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(applyResponse, apply)
	if applyResponse.Code != http.StatusOK {
		t.Fatalf("managed apply response = %d %q", applyResponse.Code, applyResponse.Body.String())
	}
	if fixture.service.lastManagedApplyRequest.ExpectedSelectedRevisionID != expectedRevisionID ||
		fixture.service.lastManagedApplyRequest.TargetReleaseRevisionID != targetRevisionID ||
		fixture.service.lastManagedApplyRequest.OfficialContext.Selector.WorkspaceID != fixture.workspaceID {
		t.Fatalf("managed apply request = %+v", fixture.service.lastManagedApplyRequest)
	}

	for _, forbidden := range []string{"version_id", "platform_id", "owner_scope", "policy_snapshot_id"} {
		body := `{"expected_selected_release_revision_id":"` + expectedRevisionID.String() + `","target_release_revision_id":"` + targetRevisionID.String() + `","` + forbidden + `":"forbidden"}`
		request := httptest.NewRequest(http.MethodPost,
			"/api/v1/agent-installations/"+fixture.installationID.String()+"/apply-managed-update", strings.NewReader(body))
		setOfficialHeaders(request, "WORKSPACE", fixture.workspaceID.String())
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "forbidden-managed-update")
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s response = %d %q", forbidden, response.Code, response.Body.String())
		}
	}
}

func TestHTTPManagedOfficialUpdateWithoutTargetReturnsExactFalseShape(t *testing.T) {
	fixture, _ := newOfficialHTTPFixture(t)
	fixture.service.managedUpdate = OfficialManagedUpdate{UpdateAvailable: false}
	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/agent-installations/"+fixture.installationID.String()+"/managed-update", nil)
	setOfficialHeaders(request, "USER", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(decoded) != 1 || decoded["update_available"] != false {
		t.Fatalf("managed no-update response = %#v", decoded)
	}
}

func TestHTTPOfficialCatalogAndInstallationUseRealRepositoryBoundaries(t *testing.T) {
	fixture, service, platformService := newOfficialInstallationFixture(t)
	principal := fixture.principal(t, 0xe1)
	_, versionID, release := fixture.publishInitialOfficialRelease(t, OfficialChannelStable, 0xe2)
	active := fixture.activateOfficialRelease(t, release, versionID, nil, 0xe7)
	authenticator := &stubAgentControlAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
		UserID: principal.UserID, DeviceID: principal.DeviceID, PersonalSpaceID: principal.PersonalSpaceID,
		SessionID: uuid.New(),
	}}}
	handler := NewHandler(HTTPConfig{Service: service, Official: platformService, AccessTokens: authenticator})
	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/official-agents", nil)
	setOfficialHeaders(listRequest, "USER", "")
	listRequest.Header.Set("X-AgentEra-Official-Channel", "stable")
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), release.DefinitionID.String()) ||
		strings.Contains(strings.ToLower(listResponse.Body.String()), "allowlist") {
		t.Fatalf("real official catalog = %d %q", listResponse.Code, listResponse.Body.String())
	}
	installRequest := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations", strings.NewReader(
		`{"definition_id":"`+release.DefinitionID.String()+`","official_release_revision_id":"`+active.CurrentRevision.ID.String()+`"}`,
	))
	setOfficialHeaders(installRequest, "USER", "")
	installRequest.Header.Set("X-AgentEra-Official-Channel", "stable")
	installRequest.Header.Set("Content-Type", "application/json")
	installRequest.Header.Set("Idempotency-Key", "real-official-http-install")
	installResponse := httptest.NewRecorder()
	handler.ServeHTTP(installResponse, installRequest)
	if installResponse.Code != http.StatusCreated || !strings.Contains(installResponse.Body.String(), active.CurrentRevision.ID.String()) {
		t.Fatalf("real official installation = %d %q", installResponse.Code, installResponse.Body.String())
	}
	for _, forbidden := range []string{"profile_path", "memory", "session", "credential", "private_skill", "curator"} {
		if strings.Contains(strings.ToLower(installResponse.Body.String()), forbidden) {
			t.Fatalf("real official installation leaked %q: %s", forbidden, installResponse.Body.String())
		}
	}
}

type stubOfficialCatalogHTTPService struct {
	entry       OfficialAgentCatalogEntry
	lastContext OfficialEligibilityContext
	calls       int
	err         error
}

func (s *stubOfficialCatalogHTTPService) ListOfficialAgents(
	_ context.Context,
	_ Principal,
	contextValue OfficialEligibilityContext,
) ([]OfficialAgentCatalogEntry, error) {
	s.calls++
	s.lastContext = contextValue
	return []OfficialAgentCatalogEntry{s.entry}, s.err
}

func (s *stubOfficialCatalogHTTPService) GetOfficialAgent(
	_ context.Context,
	_ Principal,
	_ uuid.UUID,
	contextValue OfficialEligibilityContext,
) (OfficialAgentCatalogEntry, error) {
	s.calls++
	s.lastContext = contextValue
	return s.entry, s.err
}

func (s *stubOfficialCatalogHTTPService) ResolveOfficialReleaseRevision(
	_ context.Context,
	_ Principal,
	_ uuid.UUID,
	_ uuid.UUID,
	contextValue OfficialEligibilityContext,
) (OfficialManagedTarget, error) {
	s.calls++
	s.lastContext = contextValue
	return s.entry.Target, s.err
}

func (s *stubOfficialCatalogHTTPService) EvaluateOfficialEligibilityRecord(
	_ Principal,
	contextValue OfficialEligibilityContext,
	_ OfficialEligibilityRecord,
	_ bool,
) (OfficialManagedTarget, error) {
	s.calls++
	s.lastContext = contextValue
	return s.entry.Target, s.err
}

func newOfficialHTTPFixture(t *testing.T) (*agentControlHTTPFixture, *stubOfficialCatalogHTTPService) {
	t.Helper()
	fixture := newAgentControlHTTPFixture(t)
	releaseID, releaseRevisionID := uuid.New(), uuid.New()
	official := &stubOfficialCatalogHTTPService{entry: OfficialAgentCatalogEntry{
		DefinitionID: fixture.definitionID, DisplayName: "Official Research",
		IconMediaType: "image/png", IconData: []byte{1, 2, 3}, Version: fixture.service.version,
		Target: OfficialManagedTarget{
			PlatformID: uuid.New(), ReleaseID: releaseID, ReleaseRevisionID: releaseRevisionID,
			DefinitionID: fixture.definitionID, VersionID: fixture.versionID, Channel: OfficialChannelInternal,
		},
		InstallationState: OfficialInstallationNotInstalled, UpdateState: OfficialUpdateCurrent,
	}}
	fixture.service.installation.OfficialReleaseID = &releaseID
	fixture.service.installation.SelectedReleaseRevisionID = &releaseRevisionID
	fixture.service.installation.UpdatePolicy = installationUpdatePolicyManaged
	fixture.service.creation.Installation = fixture.service.installation
	fixture.handler = NewHandler(HTTPConfig{
		Service: fixture.service, Official: official, AccessTokens: fixture.authenticator,
	})
	return fixture, official
}

func setOfficialHeaders(request *http.Request, productContext string, productContextID string) {
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("X-AgentEra-Official-Channel", "internal")
	request.Header.Set("X-AgentEra-Desktop-Version", "v1.0.0")
	request.Header.Set("X-AgentEra-Product-Context", productContext)
	if productContextID != "" {
		request.Header.Set("X-AgentEra-Product-Context-ID", productContextID)
	}
}
