package agentcontrol

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type organizationExperienceCandidateSummaryResponse struct {
	ID                   uuid.UUID                          `json:"id"`
	OrganizationID       uuid.UUID                          `json:"organization_id"`
	AgentDefinitionID    uuid.UUID                          `json:"agent_definition_id"`
	SourceAgentVersionID uuid.UUID                          `json:"source_agent_version_id"`
	SubmittedByUserID    *uuid.UUID                         `json:"submitted_by_user_id"`
	SkillName            string                             `json:"skill_name"`
	DLPContractVersion   string                             `json:"dlp_contract_version"`
	ContentDigest        string                             `json:"content_digest"`
	CreatedAt            time.Time                          `json:"created_at"`
	Review               *experienceCandidateReviewResponse `json:"review,omitempty"`
}

type organizationExperienceCandidateDetailResponse struct {
	organizationExperienceCandidateSummaryResponse
	Bundle ExperienceCandidateBundleV1 `json:"bundle"`
}

func (h *httpHandler) submitOrganizationExperienceCandidate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	organizationID, ok := pathUUID(response, request, "organizationID")
	if !ok {
		return
	}
	definitionID, ok := pathUUID(response, request, "definitionID")
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	var payload struct {
		SourceVersionID    uuid.UUID                   `json:"source_version_id"`
		SkillName          string                      `json:"skill_name"`
		SchemaVersion      int                         `json:"schema_version"`
		DLPContractVersion string                      `json:"dlp_contract_version"`
		Bundle             ExperienceCandidateBundleV1 `json:"bundle"`
	}
	if !decodeAgentJSON(response, request, candidateRequestBodyLimit, &payload) {
		return
	}
	requestID := newAgentRequestID()
	candidate, err := h.service.SubmitOrganizationExperienceCandidate(
		request.Context(), principal, organizationID,
		SubmitOrganizationExperienceCandidateRequest{
			DefinitionID: definitionID, SourceVersionID: payload.SourceVersionID,
			SkillName: payload.SkillName, SchemaVersion: payload.SchemaVersion,
			DLPContractVersion: payload.DLPContractVersion, Bundle: payload.Bundle,
			IdempotencyKey: idempotencyKey, RequestID: requestID,
		},
	)
	if err != nil {
		writeExperienceCandidateServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicOrganizationExperienceCandidateDetail(candidate))
}

func (h *httpHandler) listOwnOrganizationExperienceCandidates(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	organizationID, ok := pathUUID(response, request, "organizationID")
	if !ok {
		return
	}
	candidates, err := h.service.ListOwnOrganizationExperienceCandidates(
		request.Context(), principal, organizationID,
	)
	if err != nil {
		writeExperienceCandidateServiceError(response, err, newAgentRequestID())
		return
	}
	writeOrganizationExperienceCandidateList(response, candidates)
}

func (h *httpHandler) listOrganizationExperienceCandidates(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	organizationID, ok := pathUUID(response, request, "organizationID")
	if !ok {
		return
	}
	candidates, err := h.service.ListOrganizationExperienceCandidates(
		request.Context(), principal, organizationID,
	)
	if err != nil {
		writeExperienceCandidateServiceError(response, err, newAgentRequestID())
		return
	}
	writeOrganizationExperienceCandidateList(response, candidates)
}

func (h *httpHandler) getOrganizationExperienceCandidate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	organizationID, ok := pathUUID(response, request, "organizationID")
	if !ok {
		return
	}
	candidateID, ok := pathUUID(response, request, "candidateID")
	if !ok {
		return
	}
	requestID := newAgentRequestID()
	candidate, err := h.service.GetOrganizationExperienceCandidate(
		request.Context(), principal, organizationID, candidateID, requestID,
	)
	if err != nil {
		writeExperienceCandidateServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicOrganizationExperienceCandidateDetail(candidate))
}

func (h *httpHandler) reviewOrganizationExperienceCandidate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	organizationID, ok := pathUUID(response, request, "organizationID")
	if !ok {
		return
	}
	candidateID, ok := pathUUID(response, request, "candidateID")
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	var payload struct {
		Decision   ExperienceCandidateDecision `json:"decision"`
		ReasonCode string                      `json:"reason_code,omitempty"`
		SafeNote   string                      `json:"safe_note,omitempty"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	requestID := newAgentRequestID()
	candidate, err := h.service.ReviewOrganizationExperienceCandidate(
		request.Context(), principal, organizationID,
		ReviewOrganizationExperienceCandidateRequest{
			CandidateID: candidateID, Decision: payload.Decision,
			ReasonCode: payload.ReasonCode, SafeNote: payload.SafeNote,
			IdempotencyKey: idempotencyKey, RequestID: requestID,
		},
	)
	if err != nil {
		writeExperienceCandidateServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicOrganizationExperienceCandidateDetail(candidate))
}

func writeOrganizationExperienceCandidateList(
	response http.ResponseWriter,
	candidates []OrganizationExperienceCandidate,
) {
	items := make([]organizationExperienceCandidateSummaryResponse, len(candidates))
	for index, candidate := range candidates {
		items[index] = publicOrganizationExperienceCandidateSummary(candidate)
	}
	writeAgentJSON(response, http.StatusOK, struct {
		Candidates []organizationExperienceCandidateSummaryResponse `json:"candidates"`
	}{Candidates: items})
}

func publicOrganizationExperienceCandidateSummary(
	value OrganizationExperienceCandidate,
) organizationExperienceCandidateSummaryResponse {
	response := organizationExperienceCandidateSummaryResponse{
		ID: value.ID, OrganizationID: value.OrganizationID,
		AgentDefinitionID: value.AgentDefinitionID, SourceAgentVersionID: value.SourceAgentVersionID,
		SubmittedByUserID: cloneUUIDPointer(value.SubmittedByUserID), SkillName: value.SkillName,
		DLPContractVersion: value.DLPContractVersion,
		ContentDigest:      hex.EncodeToString(value.ContentDigest[:]), CreatedAt: value.CreatedAt,
	}
	if value.Review != nil {
		response.Review = &experienceCandidateReviewResponse{
			ID: value.Review.ID, ReviewedByUserID: cloneUUIDPointer(value.Review.ReviewedByUserID),
			Decision: value.Review.Decision, ReasonCode: value.Review.ReasonCode,
			SafeNote: value.Review.SafeNote, ReviewedAt: value.Review.ReviewedAt,
		}
	}
	return response
}

func publicOrganizationExperienceCandidateDetail(
	value OrganizationExperienceCandidate,
) organizationExperienceCandidateDetailResponse {
	return organizationExperienceCandidateDetailResponse{
		organizationExperienceCandidateSummaryResponse: publicOrganizationExperienceCandidateSummary(value),
		Bundle: cloneOrganizationExperienceCandidate(value).Bundle,
	}
}
