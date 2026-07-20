package agentcontrol

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPExperienceCandidateRoutesUseClaimsAndSeparateMineFromReviewQueue(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	base := "/api/v1/workspaces/" + fixture.workspaceID.String() + "/experience-candidates"
	submitPath := "/api/v1/workspaces/" + fixture.workspaceID.String() +
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
		{name: "submit", method: http.MethodPost, path: submitPath, body: candidateSubmitJSON(t, fixture), status: http.StatusCreated, idempotent: true, wantBundle: true},
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
				request.Header.Set("Idempotency-Key", "candidate-"+strings.ReplaceAll(route.name, " ", "-"))
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != route.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), route.status)
			}
			if fixture.service.lastPrincipal != fixture.principal || fixture.service.lastWorkspaceID != fixture.workspaceID {
				t.Fatalf("service target principal=%+v Workspace=%s", fixture.service.lastPrincipal, fixture.service.lastWorkspaceID)
			}
			body := response.Body.String()
			if strings.Contains(body, "owner_scope") || strings.Contains(body, "profile_path") ||
				strings.Contains(body, "source_path") || strings.Contains(body, "submitted_from_device_id") {
				t.Fatalf("candidate response exposed ownership or path fields: %s", body)
			}
			if strings.Contains(body, `"bundle"`) != route.wantBundle {
				t.Fatalf("candidate response bundle visibility = %t, want %t: %s", strings.Contains(body, `"bundle"`), route.wantBundle, body)
			}
		})
	}
	if fixture.service.candidateSubmitCalls != 1 || fixture.service.candidateOwnListCalls != 1 ||
		fixture.service.candidateReviewListCalls != 1 || fixture.service.candidateReviewCalls != 1 {
		t.Fatalf("candidate route dispatch counts submit/mine/review-list/review = %d/%d/%d/%d",
			fixture.service.candidateSubmitCalls, fixture.service.candidateOwnListCalls,
			fixture.service.candidateReviewListCalls, fixture.service.candidateReviewCalls)
	}
	if fixture.service.lastCandidateSubmit.DefinitionID != fixture.definitionID ||
		fixture.service.lastCandidateSubmit.SourceVersionID != fixture.versionID ||
		fixture.service.lastCandidateID != fixture.candidateID ||
		fixture.service.lastCandidateReview.CandidateID != fixture.candidateID {
		t.Fatalf("candidate path-derived targets submit=%+v review=%+v candidate=%s",
			fixture.service.lastCandidateSubmit, fixture.service.lastCandidateReview, fixture.service.lastCandidateID)
	}
}

func TestHTTPExperienceCandidateRejectsAmbiguousOversizedAndOwnershipInputs(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	submitPath := "/api/v1/workspaces/" + fixture.workspaceID.String() +
		"/agent-definitions/" + fixture.definitionID.String() + "/experience-candidates"
	reviewPath := "/api/v1/workspaces/" + fixture.workspaceID.String() + "/experience-candidates/" +
		fixture.candidateID.String() + "/review"
	validSubmit := candidateSubmitJSON(t, fixture)
	const expectedCandidateBodyLimit = 5 * 1024 * 1024 / 4
	tests := []struct {
		name        string
		path        string
		body        string
		idempotency bool
		status      int
	}{
		{name: "missing submit idempotency", path: submitPath, body: validSubmit, status: http.StatusBadRequest},
		{name: "missing review idempotency", path: reviewPath, body: `{"decision":"APPROVED"}`, status: http.StatusBadRequest},
		{name: "duplicate submit key", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"source_version_id":"`+fixture.versionID.String()+`","source_version_id":`, 1), idempotency: true, status: http.StatusBadRequest},
		{name: "forbidden definition input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"definition_id":"`+fixture.definitionID.String()+`","source_version_id":`, 1), idempotency: true, status: http.StatusBadRequest},
		{name: "forbidden ownership input", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"owner_scope":"WORKSPACE","source_version_id":`, 1), idempotency: true, status: http.StatusBadRequest},
		{name: "forbidden source path", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"source_path":"/Users/private","source_version_id":`, 1), idempotency: true, status: http.StatusBadRequest},
		{name: "forbidden DLP override", path: submitPath, body: strings.Replace(validSubmit, `"source_version_id":`, `"dlp_override":true,"source_version_id":`, 1), idempotency: true, status: http.StatusBadRequest},
		{name: "forbidden review Workspace", path: reviewPath, body: `{"decision":"APPROVED","workspace_id":"` + fixture.workspaceID.String() + `"}`, idempotency: true, status: http.StatusBadRequest},
		{name: "oversized candidate", path: submitPath, body: strings.Repeat(" ", expectedCandidateBodyLimit+1), idempotency: true, status: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer valid-access-token")
			request.Header.Set("Content-Type", "application/json")
			if test.idempotency {
				request.Header.Set("Idempotency-Key", "candidate-strict-key")
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
		})
	}
	if fixture.service.candidateSubmitCalls != 0 || fixture.service.candidateReviewCalls != 0 {
		t.Fatalf("candidate service called for rejected request: submit=%d review=%d",
			fixture.service.candidateSubmitCalls, fixture.service.candidateReviewCalls)
	}
}

func TestHTTPExperienceCandidateMapsDLPAndTerminalErrorsWithoutContentLeakage(t *testing.T) {
	fixture := newAgentControlHTTPFixture(t)
	submitPath := "/api/v1/workspaces/" + fixture.workspaceID.String() +
		"/agent-definitions/" + fixture.definitionID.String() + "/experience-candidates"
	fixture.service.err = &ExperienceCandidateDLPError{Findings: []ExperienceCandidateFinding{{
		Code: "credential_private_key", Path: "skills/weekly-summary/SKILL.md", Line: 4,
	}}}
	request := httptest.NewRequest(http.MethodPost, submitPath, strings.NewReader(candidateSubmitJSON(t, fixture)))
	request.Header.Set("Authorization", "Bearer valid-access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "candidate-dlp-key")
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
		payload.Error.RequestID == "" || payload.Error.RequestID != fixture.service.lastCandidateSubmit.RequestID ||
		len(payload.Error.Findings) != 1 || payload.Error.Findings[0].Code != "credential_private_key" {
		t.Fatalf("DLP response payload = %+v", payload)
	}
	for _, forbidden := range []string{"BEGIN PRIVATE KEY", "request_body", "/Users/", "Bearer "} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("DLP response leaked %q: %s", forbidden, response.Body.String())
		}
	}

	fixture.service.err = ErrExperienceCandidateAlreadyReviewed
	reviewPath := "/api/v1/workspaces/" + fixture.workspaceID.String() + "/experience-candidates/" +
		fixture.candidateID.String() + "/review"
	review := httptest.NewRequest(http.MethodPost, reviewPath, strings.NewReader(`{"decision":"APPROVED"}`))
	review.Header.Set("Authorization", "Bearer valid-access-token")
	review.Header.Set("Content-Type", "application/json")
	review.Header.Set("Idempotency-Key", "candidate-terminal-key")
	reviewResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(reviewResponse, review)
	if reviewResponse.Code != http.StatusConflict ||
		!strings.Contains(reviewResponse.Body.String(), `"code":"candidate_already_reviewed"`) {
		t.Fatalf("terminal response = %d %q", reviewResponse.Code, reviewResponse.Body.String())
	}

	fixture.service.err = ErrInvalidExperienceCandidate
	invalid := httptest.NewRequest(http.MethodPost, submitPath, strings.NewReader(candidateSubmitJSON(t, fixture)))
	invalid.Header.Set("Authorization", "Bearer valid-access-token")
	invalid.Header.Set("Content-Type", "application/json")
	invalid.Header.Set("Idempotency-Key", "candidate-invalid-key")
	invalidResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest ||
		!strings.Contains(invalidResponse.Body.String(), `"code":"invalid_experience_candidate"`) {
		t.Fatalf("invalid candidate response = %d %q", invalidResponse.Code, invalidResponse.Body.String())
	}
}

func candidateSubmitJSON(t *testing.T, fixture *agentControlHTTPFixture) string {
	t.Helper()
	payload := struct {
		SourceVersionID string                      `json:"source_version_id"`
		Bundle          ExperienceCandidateBundleV1 `json:"bundle"`
		ContentDigest   string                      `json:"content_digest"`
	}{
		SourceVersionID: fixture.versionID.String(), Bundle: fixture.service.candidate.Bundle,
		ContentDigest: hex.EncodeToString(fixture.service.candidate.ContentDigest[:]),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal candidate submission: %v", err)
	}
	return string(encoded)
}
