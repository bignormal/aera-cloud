package adminapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/agentcontrol"
	"github.com/bignormal/aera-cloud/internal/officialquality"
	"github.com/google/uuid"
)

func TestOfficialQualityRoutesRequireExactScopesAndActionRoles(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	platformID := uuid.New()
	proposalID := uuid.New()
	service := &officialQualityServiceStub{platformID: platformID, proposalID: proposalID}
	handler, privateKey := newOfficialQualityHandlerFixture(t, now, service)
	day := "2026-07-22"

	tests := []struct {
		name, method, path, scope, role string
		payload                         any
		mutation                        bool
	}{
		{
			name: "aggregates", method: http.MethodGet,
			path:  "/internal/admin/v1/official-quality/aggregates?platform_id=" + platformID.String() + "&from_day=" + day + "&to_day=" + day + "&limit=25",
			scope: ScopeOfficialQualityRead, role: "auditor",
		},
		{
			name: "proposals", method: http.MethodGet,
			path:  "/internal/admin/v1/official-quality/proposals?platform_id=" + platformID.String() + "&limit=25",
			scope: ScopeOfficialQualityRead, role: "developer",
		},
		{
			name: "proposal", method: http.MethodGet,
			path:  "/internal/admin/v1/official-quality/proposals/" + proposalID.String(),
			scope: ScopeOfficialQualityRead, role: "super_admin",
		},
		{
			name: "create", method: http.MethodPost,
			path:  "/internal/admin/v1/official-quality/proposals",
			scope: ScopeOfficialQualityPropose, role: "developer", mutation: true,
			payload: map[string]any{
				"aggregate_ids":         []string{uuid.NewString()},
				"problem_categories":    []string{"latency"},
				"improvement_objective": "Reduce bounded official Agent latency without private runtime data.",
			},
		},
		{
			name: "submit", method: http.MethodPost,
			path:  "/internal/admin/v1/official-quality/proposals/" + proposalID.String() + "/submit",
			scope: ScopeOfficialQualityPropose, role: "developer", mutation: true,
			payload: map[string]any{},
		},
		{
			name: "review", method: http.MethodPost,
			path:  "/internal/admin/v1/official-quality/proposals/" + proposalID.String() + "/reviews",
			scope: ScopeOfficialQualityReview, role: "super_admin", mutation: true,
			payload: map[string]any{"decision": "approve"},
		},
		{
			name: "clone", method: http.MethodPost,
			path:  "/internal/admin/v1/official-quality/proposals/" + proposalID.String() + "/clone",
			scope: ScopeOfficialQualityClone, role: "developer", mutation: true,
			payload: map[string]any{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validOfficialServiceClaims(now, test.scope, test.mutation, false)
			claims["admin_role"] = test.role
			body := ""
			if test.mutation {
				body = mustJSON(t, map[string]any{
					"operation_id": authOperationID.String(), "actor_admin_id": authAdminID.String(),
					"actor_admin_role": test.role, "expected_revision": 1,
					"reason_code": "quality_review", "ticket_reference": "QF-123",
					"payload": test.payload,
				})
			}
			request := officialHandlerRequest(t, privateKey, now, test.method, test.path, body, claims)
			if test.mutation {
				request.Header.Set("Idempotency-Key", authOperationID.String())
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}

	wrongScopeClaims := validOfficialServiceClaims(now, ScopeOfficialAgentsRead, false, false)
	request := officialHandlerRequest(t, privateKey, now, http.MethodGet,
		"/internal/admin/v1/official-quality/aggregates?platform_id="+platformID.String()+"&from_day="+day+"&to_day="+day+"&limit=25", "", wrongScopeClaims)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong scope response = %d %s", response.Code, response.Body.String())
	}
}

func TestOfficialQualityHandlerRejectsUnknownFieldsBeforeService(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	service := &officialQualityServiceStub{platformID: uuid.New(), proposalID: uuid.New()}
	handler, privateKey := newOfficialQualityHandlerFixture(t, now, service)
	claims := validOfficialServiceClaims(now, ScopeOfficialQualityPropose, true, false)
	body := mustJSON(t, map[string]any{
		"operation_id": authOperationID.String(), "actor_admin_id": authAdminID.String(),
		"actor_admin_role": "developer", "expected_revision": 1,
		"reason_code": "quality_review", "payload": map[string]any{
			"aggregate_ids": []string{uuid.NewString()}, "problem_categories": []string{"latency"},
			"improvement_objective": "Keep the proposal objective bounded and human authored.",
			"conversation_text":     "forbidden",
		},
	})
	request := officialHandlerRequest(t, privateKey, now, http.MethodPost,
		"/internal/admin/v1/official-quality/proposals", body, claims)
	request.Header.Set("Idempotency-Key", authOperationID.String())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || service.createCalls != 0 {
		t.Fatalf("unknown field response=%d calls=%d body=%s", response.Code, service.createCalls, response.Body.String())
	}
}

type officialQualityServiceStub struct {
	platformID  uuid.UUID
	proposalID  uuid.UUID
	createCalls int
}

func (stub *officialQualityServiceStub) ListAggregates(
	context.Context, officialquality.QualityAdminActor, officialquality.AggregateFilter, officialquality.AggregatePageRequest,
) (officialquality.AggregatePage, error) {
	return officialquality.AggregatePage{Items: []officialquality.Aggregate{}}, nil
}

func (stub *officialQualityServiceStub) Create(
	_ context.Context, actor officialquality.QualityAdminActor, _ officialquality.CreateProposalCommand,
) (officialquality.Proposal, error) {
	stub.createCalls++
	if actor.Role != officialquality.QualityRoleDeveloper {
		return officialquality.Proposal{}, officialquality.ErrAdminForbidden
	}
	return stub.proposal(officialquality.ProposalStatusOpen), nil
}

func (stub *officialQualityServiceStub) Submit(
	_ context.Context, actor officialquality.QualityAdminActor, _ officialquality.SubmitProposalCommand,
) (officialquality.Proposal, error) {
	if actor.Role != officialquality.QualityRoleDeveloper {
		return officialquality.Proposal{}, officialquality.ErrAdminForbidden
	}
	return stub.proposal(officialquality.ProposalStatusSubmitted), nil
}

func (stub *officialQualityServiceStub) Review(
	_ context.Context, actor officialquality.QualityAdminActor, _ officialquality.ReviewProposalCommand,
) (officialquality.Proposal, error) {
	if actor.Role != officialquality.QualityRoleSuperAdmin {
		return officialquality.Proposal{}, officialquality.ErrAdminForbidden
	}
	return stub.proposal(officialquality.ProposalStatusApproved), nil
}

func (stub *officialQualityServiceStub) CloneToDraft(
	_ context.Context, actor officialquality.QualityAdminActor, _ officialquality.CloneProposalCommand,
) (officialquality.Proposal, error) {
	if actor.Role != officialquality.QualityRoleDeveloper {
		return officialquality.Proposal{}, officialquality.ErrAdminForbidden
	}
	value := stub.proposal(officialquality.ProposalStatusDraftLinked)
	value.LinkedDraftID = uuid.New()
	return value, nil
}

func (stub *officialQualityServiceStub) GetProposal(context.Context, officialquality.QualityAdminActor, uuid.UUID) (officialquality.Proposal, error) {
	return stub.proposal(officialquality.ProposalStatusOpen), nil
}

func (stub *officialQualityServiceStub) ListProposals(
	context.Context, officialquality.QualityAdminActor, officialquality.ProposalFilter, officialquality.ProposalPageRequest,
) (officialquality.ProposalPage, error) {
	return officialquality.ProposalPage{Items: []officialquality.Proposal{}}, nil
}

func (stub *officialQualityServiceStub) proposal(status officialquality.ProposalStatus) officialquality.Proposal {
	return officialquality.Proposal{
		ID: stub.proposalID, PlatformID: stub.platformID, DefinitionID: uuid.New(),
		VersionID: uuid.New(), ReleaseID: uuid.New(), ReleaseRevisionID: uuid.New(),
		AggregateIDs: []uuid.UUID{}, ProblemCategories: []string{"latency"},
		ImprovementObjective: "Reduce bounded latency without user content.",
		CreatedByAdminID:     authAdminID, CreatedByRole: "developer",
		Status: status, Revision: 1, ReasonCode: "quality_review",
		CreatedAt: time.Date(2026, 7, 23, 9, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 7, 23, 9, 0, 0, 0, time.UTC),
	}
}

func newOfficialQualityHandlerFixture(
	t *testing.T,
	now time.Time,
	quality officialquality.AdminService,
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
		Service: control, OfficialAgents: &officialAgentServiceStub{}, OfficialAudit: officialAuditServiceStub{},
		OfficialQuality: quality, OperationProtector: protector,
		Auth: auth, PostgreSQL: health, Redis: health, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, privateKey
}

var _ agentcontrol.PlatformService = (*officialAgentServiceStub)(nil)
