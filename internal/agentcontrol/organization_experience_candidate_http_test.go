package agentcontrol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPOrganizationExperienceCandidateRoutesUseClaimsAndOrganizationScope(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	base := "/api/v1/organizations/" + fixture.organizationID.String() + "/experience-candidates"
	submitPath := "/api/v1/organizations/" + fixture.organizationID.String() +
		"/agent-definitions/" + fixture.definitionID.String() + "/experience-candidates"
	routes := []struct {
		name       string
		method     string
		path       string
		body       string
		status     int
		idempotent bool
		wantBundle bool
	}{
		{name: "submit", method: http.MethodPost, path: submitPath, body: organizationCandidateSubmitJSON(t, fixture), status: http.StatusCreated, idempotent: true, wantBundle: true},
		{name: "mine", method: http.MethodGet, path: base + "/mine", status: http.StatusOK},
		{name: "review queue", method: http.MethodGet, path: base, status: http.StatusOK},
		{name: "detail", method: http.MethodGet, path: base + "/" + fixture.candidateID.String(), status: http.StatusOK, wantBundle: true},
		{name: "review", method: http.MethodPost, path: base + "/" + fixture.candidateID.String() + "/review", body: `{"decision":"APPROVED"}`, status: http.StatusOK, idempotent: true, wantBundle: true},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
			request.Header.Set("Authorization", "Bearer valid-access-token")
			if route.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if route.idempotent {
				request.Header.Set("Idempotency-Key", "organization-candidate-"+strings.ReplaceAll(route.name, " ", "-"))
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != route.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), route.status)
			}
			if fixture.service.lastPrincipal != fixture.principal || fixture.service.lastOrganizationID != fixture.organizationID {
				t.Fatalf("service target principal=%+v Organization=%s", fixture.service.lastPrincipal, fixture.service.lastOrganizationID)
			}
			body := response.Body.String()
			if strings.Contains(body, "owner_scope") || strings.Contains(body, "profile_path") ||
				strings.Contains(body, "source_path") || strings.Contains(body, "submitted_from_device_id") {
				t.Fatalf("Organization candidate response exposed ownership or path fields: %s", body)
			}
			if strings.Contains(body, `"bundle"`) != route.wantBundle {
				t.Fatalf("Organization candidate bundle visibility = %t, want %t: %s", strings.Contains(body, `"bundle"`), route.wantBundle, body)
			}
		})
	}
	if fixture.service.organizationCandidateSubmitCalls != 1 ||
		fixture.service.organizationCandidateOwnListCalls != 1 ||
		fixture.service.organizationCandidateReviewListCalls != 1 ||
		fixture.service.organizationCandidateReviewCalls != 1 {
		t.Fatalf("Organization candidate dispatch counts submit/mine/review-list/review = %d/%d/%d/%d",
			fixture.service.organizationCandidateSubmitCalls, fixture.service.organizationCandidateOwnListCalls,
			fixture.service.organizationCandidateReviewListCalls, fixture.service.organizationCandidateReviewCalls)
	}
	if fixture.service.lastOrganizationCandidateSubmit.DefinitionID != fixture.definitionID ||
		fixture.service.lastOrganizationCandidateSubmit.SourceVersionID != fixture.versionID ||
		fixture.service.lastOrganizationCandidateID != fixture.candidateID ||
		fixture.service.lastOrganizationCandidateReview.CandidateID != fixture.candidateID {
		t.Fatalf("Organization candidate path-derived targets submit=%+v review=%+v candidate=%s",
			fixture.service.lastOrganizationCandidateSubmit,
			fixture.service.lastOrganizationCandidateReview,
			fixture.service.lastOrganizationCandidateID)
	}
}

func TestHTTPOrganizationExperienceCandidateRejectsUntrustedAndReplacementInputs(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	submitPath := "/api/v1/organizations/" + fixture.organizationID.String() +
		"/agent-definitions/" + fixture.definitionID.String() + "/experience-candidates"
	reviewPath := "/api/v1/organizations/" + fixture.organizationID.String() + "/experience-candidates/" +
		fixture.candidateID.String() + "/review"
	validSubmit := organizationCandidateSubmitJSON(t, fixture)
	tests := []struct {
		name        string
		path        string
		body        string
		idempotency bool
	}{
		{name: "missing submit idempotency", path: submitPath, body: validSubmit},
		{name: "missing review idempotency", path: reviewPath, body: `{"decision":"APPROVED"}`},
		{name: "actor input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"actor_user_id":"`+fixture.principal.UserID.String()+`","source_version_id":`, 1), idempotency: true},
		{name: "role input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"role":"owner","source_version_id":`, 1), idempotency: true},
		{name: "device input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"device_id":"`+fixture.principal.DeviceID.String()+`","source_version_id":`, 1), idempotency: true},
		{name: "origin input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"origin":"local-profile","source_version_id":`, 1), idempotency: true},
		{name: "token input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"token":"opaque","source_version_id":`, 1), idempotency: true},
		{name: "path input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"profile_path":"/Users/private","source_version_id":`, 1), idempotency: true},
		{name: "DLP bypass", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"dlp_bypass":true,"source_version_id":`, 1), idempotency: true},
		{name: "replacement digest", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"content_digest":"`+strings.Repeat("0", 64)+`","source_version_id":`, 1), idempotency: true},
		{name: "path Organization input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"organization_id":"`+fixture.organizationID.String()+`","source_version_id":`, 1), idempotency: true},
		{name: "path definition input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"definition_id":"`+fixture.definitionID.String()+`","source_version_id":`, 1), idempotency: true},
		{name: "review actor input", path: reviewPath, body: `{"decision":"APPROVED","actor_user_id":"` + fixture.principal.UserID.String() + `"}`, idempotency: true},
		{name: "review replacement content", path: reviewPath, body: `{"decision":"APPROVED","bundle":{"schema_version":1}}`, idempotency: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer valid-access-token")
			request.Header.Set("Content-Type", "application/json")
			if test.idempotency {
				request.Header.Set("Idempotency-Key", "organization-candidate-strict-key")
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
		})
	}
	if fixture.service.organizationCandidateSubmitCalls != 0 || fixture.service.organizationCandidateReviewCalls != 0 {
		t.Fatalf("Organization candidate service called for rejected request: submit=%d review=%d",
			fixture.service.organizationCandidateSubmitCalls, fixture.service.organizationCandidateReviewCalls)
	}
}

func TestHTTPOrganizationExperienceCandidateMapsSafeDLPAndTerminalErrors(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	submitPath := "/api/v1/organizations/" + fixture.organizationID.String() +
		"/agent-definitions/" + fixture.definitionID.String() + "/experience-candidates"
	fixture.service.err = &ExperienceCandidateDLPError{Findings: []ExperienceCandidateFinding{{
		Code: "credential_private_key", Path: "skills/weekly-summary/SKILL.md", Line: 4,
	}}}
	request := httptest.NewRequest(http.MethodPost, submitPath, strings.NewReader(organizationCandidateSubmitJSON(t, fixture)))
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "organization-candidate-dlp-key")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("DLP response = %d %q", response.Code, response.Body.String())
	}
	var payload struct {
		Error struct {
			Code      string                       `json:"code"`
			Message   string                       `json:"message"`
			RequestID string                       `json:"request_id"`
			Findings  []ExperienceCandidateFinding `json:"findings"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode DLP response: %v", err)
	}
	if payload.Error.Code != "candidate_dlp_blocked" || payload.Error.Message != "localized by the client" ||
		payload.Error.RequestID == "" || len(payload.Error.Findings) != 1 ||
		payload.Error.Findings[0].Code != "credential_private_key" {
		t.Fatalf("DLP response payload = %+v", payload)
	}
	for _, forbidden := range []string{"BEGIN PRIVATE KEY", "request_body", "/Users/", "Bearer "} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("DLP response leaked %q: %s", forbidden, response.Body.String())
		}
	}

	fixture.service.err = ErrExperienceCandidateAlreadyReviewed
	reviewPath := "/api/v1/organizations/" + fixture.organizationID.String() + "/experience-candidates/" +
		fixture.candidateID.String() + "/review"
	review := httptest.NewRequest(http.MethodPost, reviewPath, strings.NewReader(`{"decision":"APPROVED"}`))
	review.Header.Set("Authorization", "Bearer valid-access-token")
	review.Header.Set("Content-Type", "application/json")
	review.Header.Set("Idempotency-Key", "organization-candidate-terminal-key")
	reviewResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(reviewResponse, review)
	if reviewResponse.Code != http.StatusConflict ||
		!strings.Contains(reviewResponse.Body.String(), `"code":"candidate_already_reviewed"`) {
		t.Fatalf("terminal response = %d %q", reviewResponse.Code, reviewResponse.Body.String())
	}
}

func organizationCandidateSubmitJSON(t *testing.T, fixture *agentControlHTTPFixture) string {
	t.Helper()
	payload := struct {
		SourceVersionID    string                      `json:"source_version_id"`
		SkillName          string                      `json:"skill_name"`
		SchemaVersion      int                         `json:"schema_version"`
		DLPContractVersion string                      `json:"dlp_contract_version"`
		Bundle             ExperienceCandidateBundleV1 `json:"bundle"`
	}{
		SourceVersionID: fixture.versionID.String(), SkillName: fixture.service.organizationCandidate.SkillName,
		SchemaVersion: ExperienceCandidateSchemaVersion, DLPContractVersion: ExperienceCandidateDLPVersion,
		Bundle: fixture.service.organizationCandidate.Bundle,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal Organization candidate submission: %v", err)
	}
	return string(encoded)
}
