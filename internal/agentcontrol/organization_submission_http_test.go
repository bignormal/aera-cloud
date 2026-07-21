package agentcontrol

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestHTTPOrganizationAgentRoutesUseClaimsAndNeverDirectPublish(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	organizationID := uuid.New()
	submissionID := uuid.New()
	routes := []struct {
		name       string
		method     string
		path       string
		body       string
		status     int
		idempotent bool
	}{
		{name: "list definitions", method: http.MethodGet, path: "/api/v1/organizations/" + organizationID.String() + "/agent-definitions", status: http.StatusOK},
		{name: "get definition", method: http.MethodGet, path: "/api/v1/organizations/" + organizationID.String() + "/agent-definitions/" + fixture.definitionID.String(), status: http.StatusOK},
		{name: "list versions", method: http.MethodGet, path: "/api/v1/organizations/" + organizationID.String() + "/agent-definitions/" + fixture.definitionID.String() + "/versions", status: http.StatusOK},
		{name: "submit", method: http.MethodPost, path: "/api/v1/organizations/" + organizationID.String() + "/agent-publication-submissions", body: initialOrganizationSubmissionJSON(), status: http.StatusCreated, idempotent: true},
		{name: "list submissions", method: http.MethodGet, path: "/api/v1/organizations/" + organizationID.String() + "/agent-publication-submissions", status: http.StatusOK},
		{name: "get submission", method: http.MethodGet, path: "/api/v1/organizations/" + organizationID.String() + "/agent-publication-submissions/" + submissionID.String(), status: http.StatusOK},
		{name: "withdraw", method: http.MethodPost, path: "/api/v1/organizations/" + organizationID.String() + "/agent-publication-submissions/" + submissionID.String() + "/withdraw", body: `{"expected_revision":1}`, status: http.StatusOK, idempotent: true},
		{name: "review", method: http.MethodPost, path: "/api/v1/organizations/" + organizationID.String() + "/agent-publication-submissions/" + submissionID.String() + "/reviews", body: `{"expected_revision":1,"decision":"approve"}`, status: http.StatusOK, idempotent: true},
		{name: "no direct publish", method: http.MethodPost, path: "/api/v1/organizations/" + organizationID.String() + "/agent-definitions", body: initialPublicationJSON(), status: http.StatusMethodNotAllowed, idempotent: true},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
			request.Header.Set("Authorization", "Bearer valid-access-token")
			if route.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if route.idempotent {
				request.Header.Set("Idempotency-Key", "organization-"+strings.ReplaceAll(route.name, " ", "-"))
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != route.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), route.status)
			}
		})
	}
}

func TestHTTPOrganizationSubmissionRejectsOwnershipAmbiguousUnionAndNonCanonicalPath(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	organizationID := uuid.New()
	path := "/api/v1/organizations/" + organizationID.String() + "/agent-publication-submissions"
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "path ownership field",
			path: path,
			body: strings.Replace(initialOrganizationSubmissionJSON(), `"display_name":`, `"organization_id":"`+organizationID.String()+`","display_name":`, 1),
		},
		{
			name: "initial with next field",
			path: path,
			body: strings.Replace(initialOrganizationSubmissionJSON(), `"display_name":`, `"base_version_id":"`+uuid.NewString()+`","display_name":`, 1),
		},
		{
			name: "initial with null next field",
			path: path,
			body: strings.Replace(initialOrganizationSubmissionJSON(), `"display_name":`, `"base_version_id":null,"display_name":`, 1),
		},
		{
			name: "next with initial field",
			path: path,
			body: `{"kind":"next","definition_id":"` + fixture.definitionID.String() + `","base_version_id":"` + fixture.versionID.String() + `","display_name":"forbidden","manifest":` + validHTTPManifestJSON() + `,"bundle":{"assets":[]}}`,
		},
		{
			name: "next with non canonical definition",
			path: path,
			body: `{"kind":"next","definition_id":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA","base_version_id":"` + fixture.versionID.String() + `","manifest":` + validHTTPManifestJSON() + `,"bundle":{"assets":[]}}`,
		},
		{
			name: "non canonical path",
			path: "/api/v1/organizations/" + strings.ToUpper(organizationID.String()) + "/agent-publication-submissions",
			body: initialOrganizationSubmissionJSON(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer valid-access-token")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "strict-organization-submission")
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
		})
	}
}

func TestHTTPAgentInstallationBindsExactOrganizationAndRejectsAmbiguousSource(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	organizationID := uuid.New()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations", strings.NewReader(
		`{"definition_id":"`+fixture.definitionID.String()+`","version_id":"`+fixture.versionID.String()+`","organization_id":"`+organizationID.String()+`"}`,
	))
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "organization-install")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("Organization installation response = %d %q", response.Code, response.Body.String())
	}
	if fixture.service.lastInstallationRequest.OrganizationID == nil ||
		*fixture.service.lastInstallationRequest.OrganizationID != organizationID {
		t.Fatalf("Organization installation request = %+v", fixture.service.lastInstallationRequest)
	}

	ambiguous := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations", strings.NewReader(
		`{"definition_id":"`+fixture.definitionID.String()+`","version_id":"`+fixture.versionID.String()+`","workspace_id":"`+fixture.workspaceID.String()+`","organization_id":"`+organizationID.String()+`"}`,
	))
	ambiguous.Header.Set("Authorization", "Bearer valid-access-token")
	ambiguous.Header.Set("Content-Type", "application/json")
	ambiguous.Header.Set("Idempotency-Key", "ambiguous-install")
	ambiguousResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(ambiguousResponse, ambiguous)
	if ambiguousResponse.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous response = %d %q", ambiguousResponse.Code, ambiguousResponse.Body.String())
	}

	nonCanonical := httptest.NewRequest(http.MethodPost, "/api/v1/agent-installations", strings.NewReader(
		`{"definition_id":"`+fixture.definitionID.String()+`","version_id":"`+fixture.versionID.String()+`","organization_id":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}`,
	))
	nonCanonical.Header.Set("Authorization", "Bearer valid-access-token")
	nonCanonical.Header.Set("Content-Type", "application/json")
	nonCanonical.Header.Set("Idempotency-Key", "non-canonical-install")
	nonCanonicalResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(nonCanonicalResponse, nonCanonical)
	if nonCanonicalResponse.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical response = %d %q", nonCanonicalResponse.Code, nonCanonicalResponse.Body.String())
	}
}

func TestHTTPOrganizationAgentMapsStableErrorsAndSafeDLP(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{ErrOrganizationAgentNotFound, http.StatusNotFound, "organization_agent_not_found"},
		{ErrOrganizationAgentForbidden, http.StatusForbidden, "organization_agent_forbidden"},
		{ErrOrganizationArchived, http.StatusConflict, "organization_archived"},
		{ErrOrganizationSubmissionSelfReview, http.StatusForbidden, "organization_submission_self_review"},
		{ErrOrganizationSubmissionConflict, http.StatusConflict, "organization_submission_conflict"},
		{ErrOrganizationPublicationPolicyBlocked, http.StatusUnprocessableEntity, "organization_publication_policy_blocked"},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeAgentServiceErrorWithRequestID(response, test.err, "organization-request")
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
		})
	}

	fixture := newAgentControlHTTPFixture(t)
	organizationID := uuid.New()
	fixture.service.err = &OrganizationPublicationDLPError{Findings: []ExperienceCandidateFinding{{
		Code: "credential_api_key", Path: "knowledge/safe.md", Line: 2,
	}}}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+organizationID.String()+"/agent-publication-submissions", strings.NewReader(initialOrganizationSubmissionJSON()))
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "dlp-submission")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(response.Body.String(), `"code":"organization_publication_dlp_blocked"`) ||
		!strings.Contains(response.Body.String(), `"path":"knowledge/safe.md"`) ||
		strings.Contains(response.Body.String(), "secret-value") {
		t.Fatalf("DLP response = %d %q", response.Code, response.Body.String())
	}
}

func TestHTTPOrganizationSupersededReturnsCommittedTerminalSummary(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	organizationID := uuid.New()
	submissionID := uuid.New()
	fixture.service.err = &OrganizationSubmissionSupersededError{Submission: OrganizationAgentSubmission{
		ID: submissionID, OrganizationID: organizationID, Kind: OrganizationSubmissionNext,
		DefinitionID: fixture.definitionID, BaseVersionID: fixture.versionID,
		ContentDigest: fixture.digest, Status: OrganizationSubmissionSuperseded, Revision: 2,
	}}
	request := httptest.NewRequest(http.MethodPost,
		"/api/v1/organizations/"+organizationID.String()+"/agent-publication-submissions/"+submissionID.String()+"/reviews",
		strings.NewReader(`{"expected_revision":1,"decision":"approve"}`),
	)
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "superseded-review")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), `"code":"organization_submission_superseded"`) ||
		!strings.Contains(response.Body.String(), `"status":"superseded"`) ||
		!strings.Contains(response.Body.String(), submissionID.String()) {
		t.Fatalf("superseded response = %d %q", response.Code, response.Body.String())
	}
}

func TestOrganizationHTTPErrorSentinelsRemainDistinct(t *testing.T) {
	if errors.Is(ErrOrganizationAgentNotFound, ErrNotFound) ||
		errors.Is(ErrOrganizationAgentForbidden, ErrWorkspaceForbidden) {
		t.Fatal("Organization public errors alias an existing scope")
	}
}

func initialOrganizationSubmissionJSON() string {
	return `{"kind":"initial","display_name":"Organization Research Agent","manifest":` +
		validHTTPManifestJSON() + `,"bundle":{"assets":[]}}`
}
