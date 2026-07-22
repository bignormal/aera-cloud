package adminapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/officialquality"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type createQualityProposalPayload struct {
	AggregateIDs         []string `json:"aggregate_ids"`
	ProblemCategories    []string `json:"problem_categories"`
	ImprovementObjective string   `json:"improvement_objective"`
}

type reviewQualityProposalPayload struct {
	Decision string `json:"decision"`
}

type qualityProposalResponse struct {
	ProposalID           uuid.UUID                       `json:"proposal_id"`
	PlatformID           uuid.UUID                       `json:"platform_id"`
	DefinitionID         uuid.UUID                       `json:"definition_id"`
	VersionID            uuid.UUID                       `json:"version_id"`
	ReleaseID            uuid.UUID                       `json:"release_id"`
	ReleaseRevisionID    uuid.UUID                       `json:"release_revision_id"`
	AggregateIDs         []uuid.UUID                     `json:"aggregate_ids"`
	ProblemCategories    []string                        `json:"problem_categories"`
	ImprovementObjective string                          `json:"improvement_objective"`
	CreatedByAdminID     uuid.UUID                       `json:"created_by_admin_id"`
	CreatedByRole        string                          `json:"created_by_role"`
	Status               officialquality.ProposalStatus  `json:"status"`
	Revision             int64                           `json:"revision"`
	ReasonCode           string                          `json:"reason_code"`
	TicketReference      string                          `json:"ticket_reference,omitempty"`
	LinkedDraftID        *uuid.UUID                      `json:"linked_draft_id,omitempty"`
	Review               *officialquality.ProposalReview `json:"review,omitempty"`
	CreatedAt            time.Time                       `json:"created_at"`
	UpdatedAt            time.Time                       `json:"updated_at"`
	TerminalAt           *time.Time                      `json:"terminal_at,omitempty"`
	Replayed             bool                            `json:"replayed,omitempty"`
}

type qualityProposalPageResponse struct {
	Items      []qualityProposalResponse `json:"items"`
	NextCursor string                    `json:"next_cursor,omitempty"`
}

func registerOfficialQualityRoutes(router chi.Router, auth *Authenticator, h *handler) {
	router.Group(func(read chi.Router) {
		read.Use(auth.RequireOfficialScope(ScopeOfficialQualityRead, OfficialActorRead))
		read.Get("/official-quality/aggregates", h.listOfficialQualityAggregates)
		read.Get("/official-quality/proposals", h.listOfficialQualityProposals)
		read.Get("/official-quality/proposals/{proposalID}", h.getOfficialQualityProposal)
	})
	router.Group(func(propose chi.Router) {
		propose.Use(auth.RequireOfficialScope(ScopeOfficialQualityPropose, OfficialActorMutation))
		propose.Post("/official-quality/proposals", h.createOfficialQualityProposal)
		propose.Post("/official-quality/proposals/{proposalID}/submit", h.submitOfficialQualityProposal)
	})
	router.Group(func(review chi.Router) {
		review.Use(auth.RequireOfficialScope(ScopeOfficialQualityReview, OfficialActorMutation))
		review.Post("/official-quality/proposals/{proposalID}/reviews", h.reviewOfficialQualityProposal)
	})
	router.Group(func(clone chi.Router) {
		clone.Use(auth.RequireOfficialScope(ScopeOfficialQualityClone, OfficialActorMutation))
		clone.Post("/official-quality/proposals/{proposalID}/clone", h.cloneOfficialQualityProposal)
	})
}

func (h *handler) listOfficialQualityAggregates(response http.ResponseWriter, request *http.Request) {
	filter, page, ok := parseQualityAggregateQuery(request.URL)
	actor, actorOK := qualityReadActor(request)
	if !ok || !actorOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialQuality.ListAggregates(request.Context(), actor, filter, page)
	if err != nil {
		writeOfficialQualityError(response, request, err)
		return
	}
	if value.Items == nil {
		value.Items = []officialquality.Aggregate{}
	}
	writeJSON(response, http.StatusOK, value)
}

func (h *handler) listOfficialQualityProposals(response http.ResponseWriter, request *http.Request) {
	filter, page, ok := parseQualityProposalQuery(request.URL)
	actor, actorOK := qualityReadActor(request)
	if !ok || !actorOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialQuality.ListProposals(request.Context(), actor, filter, page)
	if err != nil {
		writeOfficialQualityError(response, request, err)
		return
	}
	items := make([]qualityProposalResponse, len(value.Items))
	for index := range value.Items {
		items[index] = qualityProposalFromDomain(value.Items[index])
	}
	result := qualityProposalPageResponse{Items: items}
	if value.Next != uuid.Nil {
		result.NextCursor = value.Next.String()
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) getOfficialQualityProposal(response http.ResponseWriter, request *http.Request) {
	proposalID, ok := qualityPathUUID(request, "proposalID")
	actor, actorOK := qualityReadActor(request)
	if !ok || !actorOK || !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialQuality.GetProposal(request.Context(), actor, proposalID)
	if err != nil {
		writeOfficialQualityError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, qualityProposalFromDomain(value))
}

func (h *handler) createOfficialQualityProposal(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	var envelope officialMutationEnvelope[createQualityProposalPayload]
	if decodeOfficialAdminJSON(response, request, &envelope) != nil || envelope.ExpectedRevision != 1 {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	operationID, operationOK := parseCanonicalUUID(envelope.OperationID)
	aggregateIDs, aggregatesOK := parseCanonicalUUIDList(envelope.Payload.AggregateIDs)
	if !operationOK || !aggregatesOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.qualityMutationActor(
		request, admin.OfficialQualityProposalCreate, operationID, envelope.evidence(), envelope.Payload,
	)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialQuality.Create(request.Context(), actor, officialquality.CreateProposalCommand{
		AggregateIDs: aggregateIDs, ProblemCategories: append([]string(nil), envelope.Payload.ProblemCategories...),
		ImprovementObjective: envelope.Payload.ImprovementObjective,
	})
	if err != nil {
		writeOfficialQualityError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) submitOfficialQualityProposal(response http.ResponseWriter, request *http.Request) {
	h.mutateOfficialQualityProposal(response, request, admin.OfficialQualityProposalSubmit,
		func(ctxRequest *http.Request, actor officialquality.QualityAdminActor, proposalID uuid.UUID, revision int64) error {
			_, err := h.officialQuality.Submit(ctxRequest.Context(), actor, officialquality.SubmitProposalCommand{
				ProposalID: proposalID, ExpectedRevision: revision,
			})
			return err
		})
}

func (h *handler) reviewOfficialQualityProposal(response http.ResponseWriter, request *http.Request) {
	proposalID, pathOK := qualityPathUUID(request, "proposalID")
	var envelope officialMutationEnvelope[reviewQualityProposalPayload]
	if !pathOK || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.qualityMutationActor(
		request, admin.OfficialQualityProposalReview, proposalID, envelope.evidence(), envelope.Payload,
	)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialQuality.Review(request.Context(), actor, officialquality.ReviewProposalCommand{
		ProposalID: proposalID, ExpectedRevision: envelope.ExpectedRevision,
		Decision: envelope.Payload.Decision,
	})
	if err != nil {
		writeOfficialQualityError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) cloneOfficialQualityProposal(response http.ResponseWriter, request *http.Request) {
	h.mutateOfficialQualityProposal(response, request, admin.OfficialQualityDraftClone,
		func(ctxRequest *http.Request, actor officialquality.QualityAdminActor, proposalID uuid.UUID, revision int64) error {
			_, err := h.officialQuality.CloneToDraft(ctxRequest.Context(), actor, officialquality.CloneProposalCommand{
				ProposalID: proposalID, ExpectedRevision: revision,
			})
			return err
		})
}

func (h *handler) mutateOfficialQualityProposal(
	response http.ResponseWriter,
	request *http.Request,
	action admin.Action,
	mutate func(*http.Request, officialquality.QualityAdminActor, uuid.UUID, int64) error,
) {
	proposalID, pathOK := qualityPathUUID(request, "proposalID")
	var envelope officialMutationEnvelope[emptyOfficialPayload]
	if !pathOK || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.qualityMutationActor(request, action, proposalID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := mutate(request, actor, proposalID, envelope.ExpectedRevision); err != nil {
		writeOfficialQualityError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) qualityMutationActor(
	request *http.Request,
	action admin.Action,
	targetID uuid.UUID,
	evidence officialMutationEvidence,
	payload any,
) (officialquality.QualityAdminActor, bool) {
	verified, ok := OfficialActorFromContext(request.Context())
	if !ok || h.operationProtector == nil || targetID == uuid.Nil {
		return officialquality.QualityAdminActor{}, false
	}
	operationID, operationOK := parseCanonicalUUID(evidence.OperationID)
	actorID, actorOK := parseCanonicalUUID(evidence.ActorAdminID)
	if !operationOK || !actorOK || operationID != verified.OperationID || actorID != verified.AdminID ||
		evidence.ActorAdminRole != verified.Role || evidence.ApprovalID != nil || evidence.RequesterAdminID != nil {
		return officialquality.QualityAdminActor{}, false
	}
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || values[0] != evidence.OperationID {
		return officialquality.QualityAdminActor{}, false
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return officialquality.QualityAdminActor{}, false
	}
	payloadDigest := sha256.Sum256(payloadJSON)
	command := admin.OfficialOperationCommand{
		OperationID: operationID, ActorAdminID: actorID, ActorAdminRole: verified.Role,
		RequestID: requestIDFromContext(request.Context()), ReasonCode: evidence.ReasonCode,
		TicketReference: evidence.TicketReference, ExpectedRevision: evidence.ExpectedRevision,
		PayloadDigest: payloadDigest[:],
	}
	digest, fingerprint, err := h.operationProtector.ProtectOfficialOperation(action, targetID, command)
	if err != nil {
		return officialquality.QualityAdminActor{}, false
	}
	serviceSubject, ok := admin.ServiceSubject(request.Context())
	if !ok {
		return officialquality.QualityAdminActor{}, false
	}
	return officialquality.QualityAdminActor{
		AdminID: actorID, Role: verified.Role, RequestID: command.RequestID,
		Operation: &officialquality.QualityAdminOperationProof{
			OperationID: operationID, Action: string(action), TargetType: "official_quality_proposal",
			TargetID: targetID, ExpectedRevision: evidence.ExpectedRevision,
			ServiceSubject: serviceSubject, IdempotencyKeyID: digest.KeyID,
			IdempotencyKeyHMAC: append([]byte(nil), digest.Sum...),
			RequestFingerprint: append([]byte(nil), fingerprint...),
			ReasonCode:         evidence.ReasonCode, TicketReference: evidence.TicketReference,
		},
	}, true
}

func qualityReadActor(request *http.Request) (officialquality.QualityAdminActor, bool) {
	verified, ok := OfficialActorFromContext(request.Context())
	requestID := requestIDFromContext(request.Context())
	if !ok || requestID == "" {
		return officialquality.QualityAdminActor{}, false
	}
	return officialquality.QualityAdminActor{
		AdminID: verified.AdminID, Role: verified.Role, RequestID: requestID,
	}, true
}

func parseQualityAggregateQuery(value *url.URL) (officialquality.AggregateFilter, officialquality.AggregatePageRequest, bool) {
	if value == nil {
		return officialquality.AggregateFilter{}, officialquality.AggregatePageRequest{}, false
	}
	query := value.Query()
	allowed := map[string]struct{}{
		"platform_id": {}, "definition_id": {}, "from_day": {}, "to_day": {}, "cursor": {}, "limit": {},
	}
	for key, values := range query {
		if _, ok := allowed[key]; !ok || len(values) != 1 || values[0] == "" {
			return officialquality.AggregateFilter{}, officialquality.AggregatePageRequest{}, false
		}
	}
	platformID, platformOK := parseCanonicalUUID(query.Get("platform_id"))
	definitionID := uuid.Nil
	definitionOK := true
	if raw := query.Get("definition_id"); raw != "" {
		definitionID, definitionOK = parseCanonicalUUID(raw)
	}
	fromDay, fromOK := parseQualityDay(query.Get("from_day"))
	toDay, toOK := parseQualityDay(query.Get("to_day"))
	limit, limitOK := parseQualityLimit(query.Get("limit"))
	if !platformOK || !definitionOK || !fromOK || !toOK || !limitOK {
		return officialquality.AggregateFilter{}, officialquality.AggregatePageRequest{}, false
	}
	return officialquality.AggregateFilter{
		PlatformID: platformID, DefinitionID: definitionID, FromDay: fromDay, ToDay: toDay,
	}, officialquality.AggregatePageRequest{Limit: limit, Cursor: query.Get("cursor")}, true
}

func parseQualityProposalQuery(value *url.URL) (officialquality.ProposalFilter, officialquality.ProposalPageRequest, bool) {
	if value == nil {
		return officialquality.ProposalFilter{}, officialquality.ProposalPageRequest{}, false
	}
	query := value.Query()
	for key, values := range query {
		if (key != "platform_id" && key != "status" && key != "cursor" && key != "limit") ||
			len(values) != 1 || values[0] == "" {
			return officialquality.ProposalFilter{}, officialquality.ProposalPageRequest{}, false
		}
	}
	platformID, ok := parseCanonicalUUID(query.Get("platform_id"))
	limit, limitOK := parseQualityLimit(query.Get("limit"))
	after := uuid.Nil
	if raw := query.Get("cursor"); raw != "" {
		after, ok = parseCanonicalUUID(raw)
	}
	status := officialquality.ProposalStatus(query.Get("status"))
	switch status {
	case "", officialquality.ProposalStatusOpen, officialquality.ProposalStatusSubmitted,
		officialquality.ProposalStatusApproved, officialquality.ProposalStatusRejected,
		officialquality.ProposalStatusDraftLinked, officialquality.ProposalStatusClosed:
	default:
		ok = false
	}
	if !ok || !limitOK {
		return officialquality.ProposalFilter{}, officialquality.ProposalPageRequest{}, false
	}
	return officialquality.ProposalFilter{PlatformID: platformID, Status: status},
		officialquality.ProposalPageRequest{After: after, Limit: limit}, true
}

func parseQualityLimit(raw string) (int, bool) {
	if raw == "" {
		return 50, true
	}
	value, err := strconv.Atoi(raw)
	return value, err == nil && value >= 1 && value <= 100 && strconv.Itoa(value) == raw
}

func parseQualityDay(raw string) (time.Time, bool) {
	value, err := time.Parse("2006-01-02", raw)
	return value, err == nil && value.Format("2006-01-02") == raw
}

func qualityPathUUID(request *http.Request, key string) (uuid.UUID, bool) {
	if request == nil {
		return uuid.Nil, false
	}
	return parseCanonicalUUID(chi.URLParam(request, key))
}

func qualityProposalFromDomain(value officialquality.Proposal) qualityProposalResponse {
	result := qualityProposalResponse{
		ProposalID: value.ID, PlatformID: value.PlatformID, DefinitionID: value.DefinitionID,
		VersionID: value.VersionID, ReleaseID: value.ReleaseID,
		ReleaseRevisionID:    value.ReleaseRevisionID,
		AggregateIDs:         append([]uuid.UUID(nil), value.AggregateIDs...),
		ProblemCategories:    append([]string(nil), value.ProblemCategories...),
		ImprovementObjective: value.ImprovementObjective,
		CreatedByAdminID:     value.CreatedByAdminID, CreatedByRole: value.CreatedByRole,
		Status: value.Status, Revision: value.Revision, ReasonCode: value.ReasonCode,
		TicketReference: value.TicketReference, Review: value.Review,
		CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(), Replayed: value.Replayed,
	}
	if result.AggregateIDs == nil {
		result.AggregateIDs = []uuid.UUID{}
	}
	if result.ProblemCategories == nil {
		result.ProblemCategories = []string{}
	}
	if value.LinkedDraftID != uuid.Nil {
		linked := value.LinkedDraftID
		result.LinkedDraftID = &linked
	}
	if value.TerminalAt != nil {
		terminal := value.TerminalAt.UTC()
		result.TerminalAt = &terminal
	}
	if value.Review != nil {
		review := *value.Review
		review.ReviewedAt = review.ReviewedAt.UTC()
		result.Review = &review
	}
	return result
}

func writeOfficialQualityError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, officialquality.ErrInvalidRequest):
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
	case errors.Is(err, officialquality.ErrAdminForbidden):
		writeErrorResponse(response, request, http.StatusForbidden, "PERMISSION_DENIED")
	case errors.Is(err, officialquality.ErrProposalNotFound):
		writeErrorResponse(response, request, http.StatusNotFound, "QUALITY_PROPOSAL_NOT_FOUND")
	case errors.Is(err, officialquality.ErrConflict), errors.Is(err, officialquality.ErrProposalStateConflict):
		writeErrorResponse(response, request, http.StatusConflict, "STATE_CONFLICT")
	case errors.Is(err, officialquality.ErrDLPRejected):
		writeErrorResponse(response, request, http.StatusUnprocessableEntity, "PRIVACY_REJECTED")
	default:
		writeErrorResponse(response, request, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE")
	}
}
