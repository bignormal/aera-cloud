package agentcontrol

import (
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type experienceCandidateReviewResponse struct {
	ID               uuid.UUID                   `json:"id"`
	ReviewedByUserID *uuid.UUID                  `json:"reviewed_by_user_id"`
	Decision         ExperienceCandidateDecision `json:"decision"`
	ReasonCode       string                      `json:"reason_code,omitempty"`
	SafeNote         string                      `json:"safe_note,omitempty"`
	ReviewedAt       time.Time                   `json:"reviewed_at"`
}

type experienceCandidateSummaryResponse struct {
	ID                   uuid.UUID                          `json:"id"`
	WorkspaceID          uuid.UUID                          `json:"workspace_id"`
	AgentDefinitionID    uuid.UUID                          `json:"agent_definition_id"`
	SourceAgentVersionID uuid.UUID                          `json:"source_agent_version_id"`
	SubmittedByUserID    *uuid.UUID                         `json:"submitted_by_user_id"`
	SkillName            string                             `json:"skill_name"`
	DLPContractVersion   string                             `json:"dlp_contract_version"`
	ContentDigest        string                             `json:"content_digest"`
	CreatedAt            time.Time                          `json:"created_at"`
	Review               *experienceCandidateReviewResponse `json:"review,omitempty"`
}

type experienceCandidateDetailResponse struct {
	experienceCandidateSummaryResponse
	Bundle ExperienceCandidateBundleV1 `json:"bundle"`
}

func (h *httpHandler) submitExperienceCandidate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	workspaceID, ok := pathUUID(response, request, "workspaceID")
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
		SourceVersionID uuid.UUID                   `json:"source_version_id"`
		Bundle          ExperienceCandidateBundleV1 `json:"bundle"`
		ContentDigest   string                      `json:"content_digest"`
	}
	if !decodeAgentJSON(response, request, candidateRequestBodyLimit, &payload) {
		return
	}
	requestID := newAgentRequestID()
	candidate, err := h.service.SubmitExperienceCandidate(request.Context(), principal, workspaceID, SubmitExperienceCandidateRequest{
		DefinitionID: definitionID, SourceVersionID: payload.SourceVersionID,
		Bundle: payload.Bundle, ContentDigest: payload.ContentDigest,
		IdempotencyKey: idempotencyKey, RequestID: requestID,
	})
	if err != nil {
		writeExperienceCandidateServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicExperienceCandidateDetail(candidate))
}

func (h *httpHandler) listOwnExperienceCandidates(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	workspaceID, ok := pathUUID(response, request, "workspaceID")
	if !ok {
		return
	}
	candidates, err := h.service.ListOwnExperienceCandidates(request.Context(), principal, workspaceID)
	if err != nil {
		writeExperienceCandidateServiceError(response, err, newAgentRequestID())
		return
	}
	writeExperienceCandidateList(response, candidates)
}

func (h *httpHandler) listWorkspaceExperienceCandidates(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	workspaceID, ok := pathUUID(response, request, "workspaceID")
	if !ok {
		return
	}
	candidates, err := h.service.ListWorkspaceExperienceCandidates(request.Context(), principal, workspaceID)
	if err != nil {
		writeExperienceCandidateServiceError(response, err, newAgentRequestID())
		return
	}
	writeExperienceCandidateList(response, candidates)
}

func (h *httpHandler) getExperienceCandidate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	workspaceID, ok := pathUUID(response, request, "workspaceID")
	if !ok {
		return
	}
	candidateID, ok := pathUUID(response, request, "candidateID")
	if !ok {
		return
	}
	requestID := newAgentRequestID()
	candidate, err := h.service.GetExperienceCandidate(
		request.Context(), principal, workspaceID, candidateID, requestID,
	)
	if err != nil {
		writeExperienceCandidateServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicExperienceCandidateDetail(candidate))
}

func (h *httpHandler) reviewExperienceCandidate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	workspaceID, ok := pathUUID(response, request, "workspaceID")
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
	candidate, err := h.service.ReviewExperienceCandidate(request.Context(), principal, workspaceID, ReviewExperienceCandidateRequest{
		CandidateID: candidateID, Decision: payload.Decision, ReasonCode: payload.ReasonCode,
		SafeNote: payload.SafeNote, IdempotencyKey: idempotencyKey, RequestID: requestID,
	})
	if err != nil {
		writeExperienceCandidateServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicExperienceCandidateDetail(candidate))
}

func writeExperienceCandidateList(response http.ResponseWriter, candidates []ExperienceCandidate) {
	items := make([]experienceCandidateSummaryResponse, len(candidates))
	for index, candidate := range candidates {
		items[index] = publicExperienceCandidateSummary(candidate)
	}
	writeAgentJSON(response, http.StatusOK, struct {
		Candidates []experienceCandidateSummaryResponse `json:"candidates"`
	}{Candidates: items})
}

func publicExperienceCandidateSummary(value ExperienceCandidate) experienceCandidateSummaryResponse {
	response := experienceCandidateSummaryResponse{
		ID: value.ID, WorkspaceID: value.WorkspaceID, AgentDefinitionID: value.AgentDefinitionID,
		SourceAgentVersionID: value.SourceAgentVersionID,
		SubmittedByUserID:    cloneUUIDPointer(value.SubmittedByUserID), SkillName: value.SkillName,
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

func publicExperienceCandidateDetail(value ExperienceCandidate) experienceCandidateDetailResponse {
	return experienceCandidateDetailResponse{
		experienceCandidateSummaryResponse: publicExperienceCandidateSummary(value),
		Bundle:                             cloneExperienceCandidate(value).Bundle,
	}
}

func writeExperienceCandidateServiceError(response http.ResponseWriter, err error, requestID string) {
	var dlpError *ExperienceCandidateDLPError
	if errors.As(err, &dlpError) {
		writeAgentJSON(response, http.StatusBadRequest, struct {
			Error struct {
				Code      string                       `json:"code"`
				Message   string                       `json:"message"`
				RequestID string                       `json:"request_id"`
				Findings  []ExperienceCandidateFinding `json:"findings"`
			} `json:"error"`
		}{Error: struct {
			Code      string                       `json:"code"`
			Message   string                       `json:"message"`
			RequestID string                       `json:"request_id"`
			Findings  []ExperienceCandidateFinding `json:"findings"`
		}{
			Code: "candidate_dlp_blocked", Message: "localized by the client", RequestID: requestID,
			Findings: cloneExperienceCandidateFindings(dlpError.Findings),
		}})
		return
	}
	writeAgentServiceErrorWithRequestID(response, err, requestID)
}
