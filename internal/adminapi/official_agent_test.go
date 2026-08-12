package adminapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/agentcontrol"
	"github.com/google/uuid"
)

var errOfficialRouteCanary = agentcontrol.ErrCloudUnavailable

func TestParseCanonicalUUIDListRejectsDuplicateAudienceMembers(t *testing.T) {
	memberID := uuid.NewString()
	if _, ok := parseCanonicalUUIDList([]string{memberID, memberID}); ok {
		t.Fatal("duplicate audience member was accepted")
	}
}

type officialAgentServiceStub struct {
	agentcontrol.PlatformService
	calls                 []string
	actor                 agentcontrol.PlatformAdminActor
	reserve               agentcontrol.ReservePlatformDefinitionCommand
	definitions           agentcontrol.PlatformDefinitionPage
	deliveryVerifications agentcontrol.OfficialDeliveryVerificationSummary
	deliveryTarget        agentcontrol.OfficialDeliveryTarget
}

type officialAuditServiceStub struct{}

func (officialAuditServiceStub) ListOfficialAuditEvents(
	context.Context,
	admin.PageRequest,
) (admin.Page[admin.OfficialAuditEvent], error) {
	return admin.Page[admin.OfficialAuditEvent]{Items: []admin.OfficialAuditEvent{}}, nil
}

func (s *officialAgentServiceStub) ListDefinitions(
	_ context.Context,
	actor agentcontrol.PlatformAdminActor,
	_ agentcontrol.PageRequest,
) (agentcontrol.PlatformDefinitionPage, error) {
	s.calls = append(s.calls, "list_definitions")
	s.actor = actor
	return s.definitions, nil
}

func (s *officialAgentServiceStub) ReserveDefinition(
	_ context.Context,
	actor agentcontrol.PlatformAdminActor,
	command agentcontrol.ReservePlatformDefinitionCommand,
) (agentcontrol.PlatformDefinitionReservation, error) {
	s.calls = append(s.calls, "reserve_definition")
	s.actor, s.reserve = actor, command
	return agentcontrol.PlatformDefinitionReservation{
		ID:          uuid.MustParse("019f0000-0000-7000-8000-000000000221"),
		DisplayName: command.DisplayName, CreatedAt: time.Date(2026, 7, 22, 18, 0, 0, 0, time.UTC),
	}, nil
}

func (s *officialAgentServiceStub) GetDefinition(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.PlatformDefinitionDetail, error) {
	return agentcontrol.PlatformDefinitionDetail{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) ListDrafts(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.PageRequest) (agentcontrol.PlatformDraftPage, error) {
	return agentcontrol.PlatformDraftPage{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) GetDraft(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.PlatformAgentDraft, error) {
	return agentcontrol.PlatformAgentDraft{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) CreateDraft(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.CreatePlatformDraftCommand) (agentcontrol.PlatformAgentDraft, error) {
	return agentcontrol.PlatformAgentDraft{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) UpdateDraft(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.UpdatePlatformDraftCommand) (agentcontrol.PlatformAgentDraft, error) {
	return agentcontrol.PlatformAgentDraft{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) ValidateDraft(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.PlatformDraftValidation, error) {
	return agentcontrol.PlatformDraftValidation{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) SubmitDraft(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.SubmitPlatformDraftCommand) (agentcontrol.PlatformAgentSubmission, error) {
	return agentcontrol.PlatformAgentSubmission{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) ListSubmissions(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.PlatformSubmissionFilter) (agentcontrol.PlatformSubmissionPage, error) {
	return agentcontrol.PlatformSubmissionPage{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) GetSubmission(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.PlatformAgentSubmission, error) {
	return agentcontrol.PlatformAgentSubmission{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) WithdrawSubmission(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.TerminalPlatformSubmissionCommand) (agentcontrol.PlatformAgentSubmission, error) {
	return agentcontrol.PlatformAgentSubmission{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) ReviewSubmission(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.ReviewPlatformSubmissionCommand) (agentcontrol.PlatformAgentSubmission, error) {
	return agentcontrol.PlatformAgentSubmission{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) ListVersions(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.PageRequest) (agentcontrol.PlatformVersionPage, error) {
	return agentcontrol.PlatformVersionPage{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) GetVersion(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.Version, error) {
	return agentcontrol.Version{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) ListReleases(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.PageRequest) (agentcontrol.OfficialReleasePage, error) {
	return agentcontrol.OfficialReleasePage{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) GetRelease(context.Context, agentcontrol.PlatformAdminActor, uuid.UUID) (agentcontrol.OfficialRelease, error) {
	return agentcontrol.OfficialRelease{}, errOfficialRouteCanary
}

func (s *officialAgentServiceStub) GetDeliveryVerificationSummary(
	_ context.Context,
	actor agentcontrol.PlatformAdminActor,
	_ uuid.UUID,
) (agentcontrol.OfficialDeliveryVerificationSummary, error) {
	s.calls = append(s.calls, "delivery_verifications")
	s.actor = actor
	return s.deliveryVerifications, nil
}
func (s *officialAgentServiceStub) GetDeliveryTarget(
	_ context.Context,
	actor agentcontrol.PlatformAdminActor,
	_ uuid.UUID,
) (agentcontrol.OfficialDeliveryTarget, error) {
	s.calls = append(s.calls, "delivery_target")
	s.actor = actor
	return s.deliveryTarget, nil
}
func (s *officialAgentServiceStub) ActivateOfficialRelease(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.ActivateOfficialReleaseCommand) (agentcontrol.OfficialRelease, error) {
	return agentcontrol.OfficialRelease{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) UpdateOfficialRollout(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.UpdateOfficialRolloutCommand) (agentcontrol.OfficialRelease, error) {
	return agentcontrol.OfficialRelease{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) PauseOfficialRelease(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.ChangeOfficialReleaseStateCommand) (agentcontrol.OfficialRelease, error) {
	return agentcontrol.OfficialRelease{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) ResumeOfficialRelease(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.ChangeOfficialReleaseStateCommand) (agentcontrol.OfficialRelease, error) {
	return agentcontrol.OfficialRelease{}, errOfficialRouteCanary
}
func (s *officialAgentServiceStub) RollbackOfficialRelease(context.Context, agentcontrol.PlatformAdminActor, agentcontrol.RollbackOfficialReleaseCommand) (agentcontrol.OfficialRelease, error) {
	return agentcontrol.OfficialRelease{}, errOfficialRouteCanary
}

func TestOfficialAgentRoutesRequireActorAndBindMutationEvidence(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	service := &officialAgentServiceStub{definitions: agentcontrol.PlatformDefinitionPage{Items: []agentcontrol.PlatformDefinitionDetail{}}}
	handler, privateKey := newOfficialHandlerFixture(t, now, service)

	t.Run("read", func(t *testing.T) {
		claims := validOfficialServiceClaims(now, ScopeOfficialAgentsRead, false, false)
		request := officialHandlerRequest(t, privateKey, now, http.MethodGet,
			"/internal/admin/v1/official-agent-definitions", "", claims)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || len(service.calls) != 1 || service.calls[0] != "list_definitions" {
			t.Fatalf("read = %d %v %s", response.Code, service.calls, response.Body.String())
		}
		if service.actor.AdminID != authAdminID || service.actor.Role != "developer" || service.actor.Operation != nil {
			t.Fatalf("read actor = %+v", service.actor)
		}
	})

	t.Run("mutation", func(t *testing.T) {
		service.calls = nil
		body := mustJSON(t, map[string]any{
			"operation_id": authOperationID, "actor_admin_id": authAdminID,
			"actor_admin_role": "developer", "expected_revision": 1,
			"reason_code": "definition_create",
			"payload":     map[string]any{"display_name": "Official Research"},
		})
		claims := validOfficialServiceClaims(now, ScopeOfficialDraftsWrite, true, false)
		request := officialHandlerRequest(t, privateKey, now, http.MethodPost,
			"/internal/admin/v1/official-agent-definitions", body, claims)
		request.Header.Set("Idempotency-Key", authOperationID.String())
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || len(service.calls) != 1 || service.calls[0] != "reserve_definition" {
			t.Fatalf("mutation = %d %v %s", response.Code, service.calls, response.Body.String())
		}
		if !bytes.Contains(response.Body.Bytes(), []byte(`"operation_id":"`+authOperationID.String()+`"`)) ||
			!bytes.Contains(response.Body.Bytes(), []byte(`"status":"succeeded"`)) {
			t.Fatalf("mutation operation response = %s", response.Body.String())
		}
		proof := service.actor.Operation
		if proof == nil || proof.OperationID != authOperationID || proof.Action != string(admin.OfficialDefinitionReserve) ||
			proof.TargetType != "platform_definition" || proof.ServiceSubject != "aera-admin-e2e" ||
			proof.ExpectedRevision != 1 || len(proof.IdempotencyKeyHMAC) != 32 || len(proof.RequestFingerprint) != 32 {
			t.Fatalf("operation proof = %+v", proof)
		}
		if service.reserve.DisplayName != "Official Research" || service.reserve.IdempotencyKey != authOperationID.String() {
			t.Fatalf("reserve = %+v", service.reserve)
		}
	})
}

func TestOfficialAgentMutationRejectsBodyActorMismatchBeforeService(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		actorID uuid.UUID
		role    string
	}{
		{name: "actor id", actorID: uuid.New(), role: "developer"},
		{name: "actor role", actorID: authAdminID, role: "operator"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &officialAgentServiceStub{}
			handler, privateKey := newOfficialHandlerFixture(t, now, service)
			body := mustJSON(t, map[string]any{
				"operation_id": authOperationID, "actor_admin_id": test.actorID,
				"actor_admin_role": test.role, "expected_revision": 1,
				"reason_code": "definition_create",
				"payload":     map[string]any{"display_name": "Official Research"},
			})
			request := officialHandlerRequest(t, privateKey, now, http.MethodPost,
				"/internal/admin/v1/official-agent-definitions", body,
				validOfficialServiceClaims(now, ScopeOfficialDraftsWrite, true, false))
			request.Header.Set("Idempotency-Key", authOperationID.String())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || len(service.calls) != 0 {
				t.Fatalf("mismatch = %d %v %s", response.Code, service.calls, response.Body.String())
			}
		})
	}
}

func TestOfficialMutationOperationCanBeReconciledAfterAmbiguousRead(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	targetID := uuid.New()
	service := newHandlerServiceStub(now)
	service.operation = admin.Operation{
		ID: authOperationID, Status: admin.OperationSucceeded,
		AdministrativeRevision: 1, TargetType: "platform_definition", TargetID: targetID.String(),
		UpdatedAt: now,
	}
	service.getOperationErr = admin.ErrUnavailable
	handler := &handler{service: service}
	request := httptest.NewRequest(http.MethodPost, "https://cloud.test/internal/admin/v1/official-agent-definitions", nil)

	ambiguous := httptest.NewRecorder()
	handler.writeOfficialOperationResult(ambiguous, request, authOperationID.String())
	if ambiguous.Code != http.StatusServiceUnavailable || service.targetID != authOperationID {
		t.Fatalf("ambiguous result = %d target=%s body=%s", ambiguous.Code, service.targetID, ambiguous.Body.String())
	}

	service.getOperationErr = nil
	reconciled := httptest.NewRecorder()
	handler.writeOfficialOperationResult(reconciled, request, authOperationID.String())
	if reconciled.Code != http.StatusOK ||
		!bytes.Contains(reconciled.Body.Bytes(), []byte(`"operation_id":"`+authOperationID.String()+`"`)) ||
		!bytes.Contains(reconciled.Body.Bytes(), []byte(`"target_type":"platform_definition"`)) ||
		!bytes.Contains(reconciled.Body.Bytes(), []byte(`"target_id":"`+targetID.String()+`"`)) {
		t.Fatalf("reconciled result = %d body=%s", reconciled.Code, reconciled.Body.String())
	}
}

func TestOfficialDefinitionMutationRejectsNonInitialRevisionAndDuplicateKeys(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		body func(*testing.T) string
	}{
		{
			name: "non initial revision",
			body: func(t *testing.T) string {
				return mustJSON(t, map[string]any{
					"operation_id": authOperationID, "actor_admin_id": authAdminID,
					"actor_admin_role": "developer", "expected_revision": 2,
					"reason_code": "definition_create",
					"payload":     map[string]any{"display_name": "Official Research"},
				})
			},
		},
		{
			name: "nested duplicate key",
			body: func(*testing.T) string {
				return `{"operation_id":"` + authOperationID.String() +
					`","actor_admin_id":"` + authAdminID.String() +
					`","actor_admin_role":"developer","expected_revision":1,` +
					`"reason_code":"definition_create","payload":{` +
					`"display_name":"Official Research","display_name":"Shadow"}}`
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &officialAgentServiceStub{}
			handler, privateKey := newOfficialHandlerFixture(t, now, service)
			request := officialHandlerRequest(t, privateKey, now, http.MethodPost,
				"/internal/admin/v1/official-agent-definitions", test.body(t),
				validOfficialServiceClaims(now, ScopeOfficialDraftsWrite, true, false))
			request.Header.Set("Idempotency-Key", authOperationID.String())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || len(service.calls) != 0 {
				t.Fatalf("status/calls = %d/%v, want 400/no calls; body=%s", response.Code, service.calls, response.Body.String())
			}
		})
	}
}

func TestOfficialDraftUpdateRequiresExplicitDraftKind(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	handler, privateKey := newOfficialHandlerFixture(t, now, &officialAgentServiceStub{})
	body := mustJSON(t, map[string]any{
		"operation_id": authOperationID, "actor_admin_id": authAdminID,
		"actor_admin_role": "developer", "expected_revision": 1,
		"reason_code": "draft_update",
		"payload": map[string]any{
			"display_name": "Official Research", "manifest": map[string]any{},
			"bundle": map[string]any{"assets": []any{}},
		},
	})
	request := officialHandlerRequest(t, privateKey, now, http.MethodPatch,
		"/internal/admin/v1/official-agent-drafts/"+uuid.NewString(), body,
		validOfficialServiceClaims(now, ScopeOfficialDraftsWrite, true, false))
	request.Header.Set("Idempotency-Key", authOperationID.String())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestOfficialAuditRejectsRolesWithoutHistoryPermission(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	handler, privateKey := newOfficialHandlerFixture(t, now, &officialAgentServiceStub{})
	claims := validOfficialServiceClaims(now, ScopeOfficialAuditRead, false, false)
	claims["admin_role"] = "developer"
	request := officialHandlerRequest(t, privateKey, now, http.MethodGet,
		"/internal/admin/v1/official-agent-audit-events", "", claims)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", response.Code, response.Body.String())
	}
}

func TestOfficialSubmissionResponseKeepsFrozenSafeReviewMaterial(t *testing.T) {
	manifestDigest := [32]byte{0x11}
	bundleDigest := [32]byte{0x22}
	contentDigest := [32]byte{0x33}
	response := officialSubmissionFromDomain(agentcontrol.PlatformAgentSubmission{
		ID: uuid.New(), PlatformID: uuid.New(), DraftID: uuid.New(), DraftRevision: 3,
		DefinitionID: uuid.New(), Kind: agentcontrol.PlatformDraftInitial,
		DisplayName: "Official Research", IconMediaType: "image/png", IconData: []byte("safe-icon"),
		Manifest: agentcontrol.AgentManifestV1{SchemaVersion: 1}, Bundle: agentcontrol.VersionBundleV1{Assets: []agentcontrol.BundleAssetV1{}},
		ManifestDigest: manifestDigest, BundleDigest: bundleDigest, ContentDigest: contentDigest,
		SubmittedByAdminID: uuid.New(), SubmittedByRole: "developer",
		Status: agentcontrol.PlatformSubmissionPending, Revision: 1,
		SubmittedAt: time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC),
	})
	if response.IconMediaType != "image/png" || string(response.IconData) != "safe-icon" ||
		response.ManifestDigest != digestString(manifestDigest) ||
		response.BundleDigest != digestString(bundleDigest) {
		t.Fatalf("frozen response = %+v", response)
	}
}

func TestOfficialHandlerRejectsPartialDependencyConfiguration(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	auth, _, _ := newTestAuthenticator(t)
	health := &handlerHealthStub{}
	if _, err := NewHandler(HandlerConfig{
		Service: newHandlerServiceStub(now), OfficialAudit: officialAuditServiceStub{},
		Auth: auth, PostgreSQL: health, Redis: health, Clock: func() time.Time { return now },
	}); err == nil {
		t.Fatal("NewHandler accepted OfficialAudit without the PlatformService and operation protector")
	}
}

func TestOfficialAgentContractRoutesAreMountedWithActionSpecificClaims(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	handler, privateKey := newOfficialHandlerFixture(t, now, &officialAgentServiceStub{})
	definitionID, draftID, submissionID, versionID, releaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	draftPayload := map[string]any{
		"kind": "initial", "display_name": "Official Research",
		"manifest": map[string]any{
			"schema_version": 1,
			"identity":       map[string]any{"system_prompt": "Research safely."},
			"assets":         []any{},
			"model_constraints": map[string]any{
				"allowed_providers": []any{"openai"},
				"allowed_models":    []any{"gpt-5.6"},
			},
			"tools":                 map[string]any{"allowed": []any{}, "denied": []any{}},
			"dependencies":          []any{},
			"runtime_compatibility": map[string]any{"minimum_version": "v0.18.2-agentera.1"},
		},
		"bundle": map[string]any{"assets": []any{}},
	}
	emptyPayload := map[string]any{}
	tests := []struct {
		name, method, path, scope, role string
		payload                         any
		mutation, rollback              bool
	}{
		{"definitions", "GET", "/internal/admin/v1/official-agent-definitions", ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"definition", "GET", "/internal/admin/v1/official-agent-definitions/" + definitionID.String(), ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"drafts", "GET", "/internal/admin/v1/official-agent-drafts", ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"create draft", "POST", "/internal/admin/v1/official-agent-drafts", ScopeOfficialDraftsWrite, "developer", withField(draftPayload, "definition_id", definitionID.String()), true, false},
		{"draft", "GET", "/internal/admin/v1/official-agent-drafts/" + draftID.String(), ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"update draft", "PATCH", "/internal/admin/v1/official-agent-drafts/" + draftID.String(), ScopeOfficialDraftsWrite, "developer", draftPayload, true, false},
		{"validate draft", "POST", "/internal/admin/v1/official-agent-drafts/" + draftID.String() + "/validate", ScopeOfficialDraftsWrite, "developer", nil, false, false},
		{"submit draft", "POST", "/internal/admin/v1/official-agent-drafts/" + draftID.String() + "/submissions", ScopeOfficialDraftsWrite, "developer", emptyPayload, true, false},
		{"submissions", "GET", "/internal/admin/v1/official-agent-submissions", ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"submission", "GET", "/internal/admin/v1/official-agent-submissions/" + submissionID.String(), ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"withdraw", "POST", "/internal/admin/v1/official-agent-submissions/" + submissionID.String() + "/withdraw", ScopeOfficialDraftsWrite, "developer", emptyPayload, true, false},
		{"review", "POST", "/internal/admin/v1/official-agent-submissions/" + submissionID.String() + "/reviews", ScopeOfficialReviewsWrite, "super_admin", map[string]any{"decision": "reject", "review_reason_code": "policy_mismatch"}, true, false},
		{"versions", "GET", "/internal/admin/v1/official-agent-versions", ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"version", "GET", "/internal/admin/v1/official-agent-versions/" + versionID.String(), ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"releases", "GET", "/internal/admin/v1/official-agent-releases", ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"release", "GET", "/internal/admin/v1/official-agent-releases/" + releaseID.String(), ScopeOfficialAgentsRead, "developer", nil, false, false},
		{"activate", "POST", "/internal/admin/v1/official-agent-releases/" + releaseID.String() + "/activate", ScopeOfficialReleaseWrite, "operator", map[string]any{"version_id": versionID.String(), "rollout_basis_points": 100, "minimum_desktop_version": "1.0.0"}, true, false},
		{"rollout", "POST", "/internal/admin/v1/official-agent-releases/" + releaseID.String() + "/rollout", ScopeOfficialReleaseWrite, "operator", map[string]any{"rollout_basis_points": 500, "minimum_desktop_version": "1.0.0"}, true, false},
		{"pause", "POST", "/internal/admin/v1/official-agent-releases/" + releaseID.String() + "/pause", ScopeOfficialReleaseWrite, "operator", emptyPayload, true, false},
		{"resume", "POST", "/internal/admin/v1/official-agent-releases/" + releaseID.String() + "/resume", ScopeOfficialReleaseWrite, "operator", emptyPayload, true, false},
		{"rollback", "POST", "/internal/admin/v1/official-agent-releases/" + releaseID.String() + "/rollback", ScopeOfficialReleaseWrite, "super_admin", map[string]any{"target_version_id": versionID.String(), "target_release_revision_id": uuid.NewString()}, true, true},
		{"audit", "GET", "/internal/admin/v1/official-agent-audit-events", ScopeOfficialAuditRead, "auditor", nil, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validOfficialServiceClaims(now, test.scope, test.mutation, test.rollback)
			claims["admin_role"] = test.role
			body := ""
			if test.mutation {
				envelope := map[string]any{
					"operation_id": authOperationID.String(), "actor_admin_id": authAdminID.String(),
					"actor_admin_role": test.role, "expected_revision": 1,
					"reason_code": "official_change", "payload": test.payload,
				}
				if test.rollback {
					envelope["approval_id"] = authApprovalID.String()
					envelope["requester_admin_id"] = authRequesterID.String()
				}
				body = mustJSON(t, envelope)
			}
			request := officialHandlerRequest(t, privateKey, now, test.method, test.path, body, claims)
			if test.mutation {
				request.Header.Set("Idempotency-Key", authOperationID.String())
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			switch response.Code {
			case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
				http.StatusNotFound, http.StatusMethodNotAllowed:
				t.Fatalf("route rejected before service: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestOfficialDeliveryVerificationSummaryReturnsOnlyAggregatedMetadata(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	releaseID, revisionID, definitionID, versionID, requestID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	service := &officialAgentServiceStub{deliveryVerifications: agentcontrol.OfficialDeliveryVerificationSummary{
		ReleaseID: releaseID,
		Stages: []agentcontrol.OfficialDeliveryVerificationStage{{
			Status: agentcontrol.OfficialDeliveryActivated, ReleaseRevisionID: revisionID,
			DefinitionID: definitionID, VersionID: versionID, ContentDigest: [32]byte{0xab},
			DeviceCount: 2, RuntimeVersion: "v0.18.2-agentera.1", DesktopVersion: "v0.24.0",
			OccurredAt: now.Add(-time.Minute), ReceivedAt: now, RequestID: requestID,
		}},
	}}
	handler, privateKey := newOfficialHandlerFixture(t, now, service)
	request := officialHandlerRequest(t, privateKey, now, http.MethodGet,
		"/internal/admin/v1/official-agent-releases/"+releaseID.String()+"/delivery-verifications", "",
		validOfficialServiceClaims(now, ScopeOfficialAgentsRead, false, false))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("delivery verification status = %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, required := range []string{
		`"release_id":"` + releaseID.String() + `"`,
		`"verification_status":"activated"`, `"device_count":2`,
		`"content_digest":"ab000000`, `"request_id":"` + requestID.String() + `"`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("delivery verification body missing %q: %s", required, body)
		}
	}
	if strings.Contains(body, "user_id") || strings.Contains(body, "device_id") {
		t.Fatalf("delivery verification leaked identity fields: %s", body)
	}
}

func TestOfficialDeliveryTargetReturnsOnlyImmutablePublicationMetadata(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	submissionID, definitionID, versionID := uuid.New(), uuid.New(), uuid.New()
	releaseID, revisionID := uuid.New(), uuid.New()
	service := &officialAgentServiceStub{deliveryTarget: agentcontrol.OfficialDeliveryTarget{
		SubmissionID: submissionID, DefinitionID: definitionID, VersionID: versionID,
		ContentDigest: [32]byte{0xab},
		Releases: []agentcontrol.OfficialDeliveryTargetRelease{{
			ID: releaseID, CurrentRevisionID: revisionID, VersionID: versionID,
			Channel: agentcontrol.OfficialChannelInternal, State: agentcontrol.OfficialReleaseStateActive,
		}},
	}}
	handler, privateKey := newOfficialHandlerFixture(t, now, service)
	request := officialHandlerRequest(t, privateKey, now, http.MethodGet,
		"/internal/admin/v1/official-agent-submissions/"+submissionID.String()+"/delivery-target", "",
		validOfficialServiceClaims(now, ScopeOfficialAgentsRead, false, false))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("delivery target status = %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, required := range []string{
		`"submission_id":"` + submissionID.String() + `"`,
		`"definition_id":"` + definitionID.String() + `"`,
		`"version_id":"` + versionID.String() + `"`,
		`"release_id":"` + releaseID.String() + `"`,
		`"current_revision_id":"` + revisionID.String() + `"`,
		`"content_digest":"ab000000`, `"channel":"internal"`, `"state":"active"`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("delivery target body missing %q: %s", required, body)
		}
	}
	for _, forbidden := range []string{"user_id", "device_id", "installation_id", "prompt", "bundle", "path"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("delivery target leaked %q: %s", forbidden, body)
		}
	}
}

func withField(source map[string]any, key string, value any) map[string]any {
	result := make(map[string]any, len(source)+1)
	for sourceKey, sourceValue := range source {
		result[sourceKey] = sourceValue
	}
	result[key] = value
	return result
}

func newOfficialHandlerFixture(
	t *testing.T,
	now time.Time,
	official agentcontrol.PlatformService,
) (http.Handler, []byte) {
	t.Helper()
	auth, privateKey, _ := newTestAuthenticator(t)
	protector, err := admin.NewProtector("v1", map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	health := &handlerHealthStub{}
	control := newHandlerServiceStub(now)
	control.operation = admin.Operation{
		ID: authOperationID, Status: admin.OperationSucceeded,
		AdministrativeRevision: 1, UpdatedAt: now,
	}
	handler, err := NewHandler(HandlerConfig{
		Service: control, OfficialAgents: official, OfficialAudit: officialAuditServiceStub{},
		OperationProtector: protector,
		Auth:               auth, PostgreSQL: health, Redis: health, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, privateKey
}

func officialHandlerRequest(
	t *testing.T,
	privateKey []byte,
	now time.Time,
	method, path, body string,
	claims map[string]any,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://cloud.test"+path, bytes.NewBufferString(body))
	setVerifiedClientCertificate(request)
	request.Header.Set("Authorization", "Bearer "+signServiceToken(t, privateKey, validServiceHeader(), claims))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}
