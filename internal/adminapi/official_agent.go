package adminapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/agentcontrol"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const maximumOfficialAdminRequestBodyBytes = 3 << 20

type officialMutationEnvelope[T any] struct {
	OperationID      string  `json:"operation_id"`
	ActorAdminID     string  `json:"actor_admin_id"`
	ActorAdminRole   string  `json:"actor_admin_role"`
	ApprovalID       *string `json:"approval_id,omitempty"`
	RequesterAdminID *string `json:"requester_admin_id,omitempty"`
	ExpectedRevision int64   `json:"expected_revision"`
	ReasonCode       string  `json:"reason_code"`
	TicketReference  string  `json:"ticket_reference,omitempty"`
	Payload          T       `json:"payload"`
}

type officialMutationEvidence struct {
	OperationID      string
	ActorAdminID     string
	ActorAdminRole   string
	ApprovalID       *string
	RequesterAdminID *string
	ExpectedRevision int64
	ReasonCode       string
	TicketReference  string
}

func (value officialMutationEnvelope[T]) evidence() officialMutationEvidence {
	return officialMutationEvidence{
		OperationID: value.OperationID, ActorAdminID: value.ActorAdminID,
		ActorAdminRole: value.ActorAdminRole, ApprovalID: value.ApprovalID,
		RequesterAdminID: value.RequesterAdminID, ExpectedRevision: value.ExpectedRevision,
		ReasonCode: value.ReasonCode, TicketReference: value.TicketReference,
	}
}

type reserveOfficialDefinitionPayload struct {
	DisplayName   string `json:"display_name"`
	IconMediaType string `json:"icon_media_type,omitempty"`
	IconData      []byte `json:"icon_data,omitempty"`
}

type officialDraftPayload struct {
	DefinitionID  string                         `json:"definition_id,omitempty"`
	BaseVersionID *string                        `json:"base_version_id,omitempty"`
	Kind          agentcontrol.PlatformDraftKind `json:"kind"`
	DisplayName   string                         `json:"display_name"`
	IconMediaType string                         `json:"icon_media_type,omitempty"`
	IconData      []byte                         `json:"icon_data,omitempty"`
	Manifest      agentcontrol.AgentManifestV1   `json:"manifest"`
	Bundle        agentcontrol.VersionBundleV1   `json:"bundle"`
}

type emptyOfficialPayload struct{}

type reviewOfficialSubmissionPayload struct {
	Decision         agentcontrol.PlatformReviewDecision `json:"decision"`
	ReviewReasonCode string                              `json:"review_reason_code,omitempty"`
	SafeNote         string                              `json:"safe_note,omitempty"`
	InitialChannels  []agentcontrol.OfficialChannel      `json:"initial_channels,omitempty"`
}

type activateOfficialReleasePayload struct {
	VersionID             string   `json:"version_id"`
	RolloutBasisPoints    int      `json:"rollout_basis_points"`
	MinimumDesktopVersion string   `json:"minimum_desktop_version"`
	AllowlistedUserIDs    []string `json:"allowlisted_user_ids,omitempty"`
}

type rolloutOfficialReleasePayload struct {
	RolloutBasisPoints    int      `json:"rollout_basis_points"`
	MinimumDesktopVersion string   `json:"minimum_desktop_version"`
	AllowlistedUserIDs    []string `json:"allowlisted_user_ids,omitempty"`
}

type rollbackOfficialReleasePayload struct {
	TargetVersionID         string `json:"target_version_id"`
	TargetReleaseRevisionID string `json:"target_release_revision_id"`
}

type officialDefinitionResponse struct {
	DefinitionID     uuid.UUID  `json:"definition_id"`
	PlatformID       uuid.UUID  `json:"platform_id"`
	DisplayName      string     `json:"display_name"`
	IconMediaType    string     `json:"icon_media_type,omitempty"`
	IconData         []byte     `json:"icon_data,omitempty"`
	Status           string     `json:"status"`
	LatestVersionID  *uuid.UUID `json:"latest_version_id,omitempty"`
	CreatedByAdminID uuid.UUID  `json:"created_by_admin_id"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Replayed         bool       `json:"replayed,omitempty"`
}

type officialDefinitionPageResponse struct {
	Items      []officialDefinitionResponse `json:"items"`
	NextCursor string                       `json:"next_cursor,omitempty"`
}

type officialDraftResponse struct {
	DraftID           uuid.UUID                        `json:"draft_id"`
	PlatformID        uuid.UUID                        `json:"platform_id"`
	DefinitionID      uuid.UUID                        `json:"definition_id"`
	BaseVersionID     *uuid.UUID                       `json:"base_version_id,omitempty"`
	Kind              agentcontrol.PlatformDraftKind   `json:"kind"`
	DisplayName       string                           `json:"display_name"`
	IconMediaType     string                           `json:"icon_media_type,omitempty"`
	IconData          []byte                           `json:"icon_data,omitempty"`
	Manifest          agentcontrol.AgentManifestV1     `json:"manifest"`
	Bundle            agentcontrol.VersionBundleV1     `json:"bundle"`
	ManifestDigest    string                           `json:"manifest_digest"`
	BundleDigest      string                           `json:"bundle_digest"`
	ContentDigest     string                           `json:"content_digest"`
	Revision          int64                            `json:"revision"`
	Status            agentcontrol.PlatformDraftStatus `json:"status"`
	LastEditorAdminID uuid.UUID                        `json:"last_editor_admin_id"`
	LastEditorRole    string                           `json:"last_editor_role"`
	CreatedAt         time.Time                        `json:"created_at"`
	UpdatedAt         time.Time                        `json:"updated_at"`
	Replayed          bool                             `json:"replayed,omitempty"`
}

type officialReviewResponse struct {
	ReviewID                 uuid.UUID                           `json:"review_id"`
	ReviewerAdminID          uuid.UUID                           `json:"reviewer_admin_id"`
	ReviewerRole             string                              `json:"reviewer_role"`
	Decision                 agentcontrol.PlatformReviewDecision `json:"decision"`
	ReasonCode               string                              `json:"reason_code,omitempty"`
	SafeNote                 string                              `json:"safe_note,omitempty"`
	PlatformPolicySnapshotID uuid.UUID                           `json:"platform_policy_snapshot_id"`
	PlatformPolicyVersion    int64                               `json:"platform_policy_version"`
	ReviewedContentDigest    string                              `json:"reviewed_content_digest"`
	ReviewedAt               time.Time                           `json:"reviewed_at"`
}

type officialSubmissionResponse struct {
	SubmissionID       uuid.UUID                             `json:"submission_id"`
	PlatformID         uuid.UUID                             `json:"platform_id"`
	DraftID            uuid.UUID                             `json:"draft_id"`
	DraftRevision      int64                                 `json:"draft_revision"`
	DefinitionID       uuid.UUID                             `json:"definition_id"`
	BaseVersionID      *uuid.UUID                            `json:"base_version_id,omitempty"`
	Kind               agentcontrol.PlatformDraftKind        `json:"kind"`
	DisplayName        string                                `json:"display_name"`
	IconMediaType      string                                `json:"icon_media_type,omitempty"`
	IconData           []byte                                `json:"icon_data,omitempty"`
	Manifest           agentcontrol.AgentManifestV1          `json:"manifest"`
	Bundle             agentcontrol.VersionBundleV1          `json:"bundle"`
	ManifestDigest     string                                `json:"manifest_digest"`
	BundleDigest       string                                `json:"bundle_digest"`
	ContentDigest      string                                `json:"content_digest"`
	SubmittedByAdminID uuid.UUID                             `json:"submitted_by_admin_id"`
	SubmittedByRole    string                                `json:"submitted_by_role"`
	Status             agentcontrol.PlatformSubmissionStatus `json:"status"`
	Revision           int64                                 `json:"revision"`
	SubmittedAt        time.Time                             `json:"submitted_at"`
	TerminalAt         *time.Time                            `json:"terminal_at,omitempty"`
	UpdatedAt          time.Time                             `json:"updated_at"`
	Review             *officialReviewResponse               `json:"review,omitempty"`
	Replayed           bool                                  `json:"replayed,omitempty"`
}

type officialVersionResponse struct {
	VersionID                      uuid.UUID                    `json:"version_id"`
	DefinitionID                   uuid.UUID                    `json:"definition_id"`
	VersionNumber                  int64                        `json:"version_number"`
	Manifest                       agentcontrol.AgentManifestV1 `json:"manifest"`
	Bundle                         agentcontrol.VersionBundleV1 `json:"bundle"`
	ContentDigest                  string                       `json:"content_digest"`
	RuntimeMinimumVersion          string                       `json:"runtime_minimum_version"`
	RuntimeMaximumVersionExclusive string                       `json:"runtime_maximum_version_exclusive,omitempty"`
	PublishedAt                    time.Time                    `json:"published_at"`
}

type officialReleaseResponse struct {
	ReleaseID             uuid.UUID                          `json:"release_id"`
	PlatformID            uuid.UUID                          `json:"platform_id"`
	DefinitionID          uuid.UUID                          `json:"definition_id"`
	Channel               agentcontrol.OfficialChannel       `json:"channel"`
	CurrentRevisionID     uuid.UUID                          `json:"current_revision_id"`
	HeadRevision          int64                              `json:"head_revision"`
	AgentVersionID        uuid.UUID                          `json:"agent_version_id"`
	State                 agentcontrol.OfficialReleaseState  `json:"state"`
	RolloutBasisPoints    int                                `json:"rollout_basis_points"`
	MinimumDesktopVersion string                             `json:"minimum_desktop_version"`
	Action                agentcontrol.OfficialReleaseAction `json:"action"`
	PreviousRevisionID    *uuid.UUID                         `json:"previous_revision_id,omitempty"`
	RollbackRevisionID    *uuid.UUID                         `json:"rollback_target_revision_id,omitempty"`
	ActorAdminID          uuid.UUID                          `json:"actor_admin_id"`
	ActorAdminRole        string                             `json:"actor_admin_role"`
	ReasonCode            string                             `json:"reason_code"`
	TicketReference       string                             `json:"ticket_reference,omitempty"`
	AudienceCount         int                                `json:"audience_count"`
	CreatedAt             time.Time                          `json:"created_at"`
	UpdatedAt             time.Time                          `json:"updated_at"`
	Replayed              bool                               `json:"replayed,omitempty"`
}

type officialDeliveryVerificationStageResponse struct {
	VerificationStatus agentcontrol.OfficialAgentDeliveryVerificationStatus `json:"verification_status"`
	ErrorCode          string                                               `json:"error_code,omitempty"`
	ReleaseRevisionID  uuid.UUID                                            `json:"release_revision_id"`
	DefinitionID       uuid.UUID                                            `json:"definition_id"`
	VersionID          uuid.UUID                                            `json:"version_id"`
	ContentDigest      string                                               `json:"content_digest"`
	DeviceCount        int                                                  `json:"device_count"`
	RuntimeVersion     string                                               `json:"runtime_version"`
	DesktopVersion     string                                               `json:"desktop_version"`
	OccurredAt         time.Time                                            `json:"occurred_at"`
	ReceivedAt         time.Time                                            `json:"received_at"`
	RequestID          uuid.UUID                                            `json:"request_id"`
}

type officialDeliveryVerificationSummaryResponse struct {
	ReleaseID uuid.UUID                                   `json:"release_id"`
	Stages    []officialDeliveryVerificationStageResponse `json:"stages"`
}

type officialDeliveryTargetReleaseResponse struct {
	ReleaseID         uuid.UUID                         `json:"release_id"`
	CurrentRevisionID uuid.UUID                         `json:"current_revision_id"`
	VersionID         uuid.UUID                         `json:"version_id"`
	Channel           agentcontrol.OfficialChannel      `json:"channel"`
	State             agentcontrol.OfficialReleaseState `json:"state"`
}

type officialDeliveryTargetResponse struct {
	SubmissionID  uuid.UUID                               `json:"submission_id"`
	DefinitionID  uuid.UUID                               `json:"definition_id"`
	VersionID     uuid.UUID                               `json:"version_id"`
	ContentDigest string                                  `json:"content_digest"`
	Releases      []officialDeliveryTargetReleaseResponse `json:"releases"`
}

type officialPageResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func registerOfficialAgentRoutes(router chi.Router, auth *Authenticator, h *handler) {
	router.Group(func(read chi.Router) {
		read.Use(auth.RequireOfficialScope(ScopeOfficialAgentsRead, OfficialActorRead))
		read.Get("/official-agent-definitions", h.listOfficialDefinitions)
		read.Get("/official-agent-definitions/{definitionID}", h.getOfficialDefinition)
		read.Get("/official-agent-drafts", h.listOfficialDrafts)
		read.Get("/official-agent-drafts/{draftID}", h.getOfficialDraft)
		read.Get("/official-agent-submissions", h.listOfficialSubmissions)
		read.Get("/official-agent-submissions/{submissionID}", h.getOfficialSubmission)
		read.Get("/official-agent-submissions/{submissionID}/delivery-target", h.getOfficialDeliveryTarget)
		read.Get("/official-agent-versions", h.listOfficialVersions)
		read.Get("/official-agent-versions/{versionID}", h.getOfficialVersion)
		read.Get("/official-agent-releases", h.listOfficialReleases)
		read.Get("/official-agent-releases/{releaseID}", h.getOfficialRelease)
		read.Get("/official-agent-releases/{releaseID}/delivery-verifications", h.getOfficialDeliveryVerificationSummary)
	})
	router.Group(func(validate chi.Router) {
		validate.Use(auth.RequireOfficialScope(ScopeOfficialDraftsWrite, OfficialActorRead))
		validate.Post("/official-agent-drafts/{draftID}/validate", h.validateOfficialDraft)
	})
	router.Group(func(drafts chi.Router) {
		drafts.Use(auth.RequireOfficialScope(ScopeOfficialDraftsWrite, OfficialActorMutation))
		drafts.Post("/official-agent-definitions", h.reserveOfficialDefinition)
		drafts.Post("/official-agent-drafts", h.createOfficialDraft)
		drafts.Patch("/official-agent-drafts/{draftID}", h.updateOfficialDraft)
		drafts.Post("/official-agent-drafts/{draftID}/submissions", h.submitOfficialDraft)
		drafts.Post("/official-agent-submissions/{submissionID}/withdraw", h.withdrawOfficialSubmission)
	})
	router.Group(func(reviews chi.Router) {
		reviews.Use(auth.RequireOfficialScope(ScopeOfficialReviewsWrite, OfficialActorMutation))
		reviews.Post("/official-agent-submissions/{submissionID}/reviews", h.reviewOfficialSubmission)
	})
	router.Group(func(releases chi.Router) {
		releases.Use(auth.RequireOfficialScope(ScopeOfficialReleaseWrite, OfficialActorMutation))
		releases.Post("/official-agent-releases/{releaseID}/activate", h.activateOfficialRelease)
		releases.Post("/official-agent-releases/{releaseID}/rollout", h.updateOfficialReleaseRollout)
		releases.Post("/official-agent-releases/{releaseID}/pause", h.pauseOfficialRelease)
		releases.Post("/official-agent-releases/{releaseID}/resume", h.resumeOfficialRelease)
	})
	router.Group(func(rollback chi.Router) {
		rollback.Use(auth.RequireOfficialScope(ScopeOfficialReleaseWrite, OfficialActorRollback))
		rollback.Post("/official-agent-releases/{releaseID}/rollback", h.rollbackOfficialRelease)
	})
	router.Group(func(audits chi.Router) {
		audits.Use(auth.RequireOfficialScope(ScopeOfficialAuditRead, OfficialActorRead))
		audits.Get("/official-agent-audit-events", h.listOfficialAgentAuditEvents)
	})
}

func (h *handler) listOfficialDefinitions(response http.ResponseWriter, request *http.Request) {
	page, ok := parseOfficialPage(request.URL)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := officialPlatformActor(request)
	if !ok {
		writeErrorResponse(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		return
	}
	result, err := h.officialAgents.ListDefinitions(request.Context(), actor, page)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	items := make([]officialDefinitionResponse, len(result.Items))
	for index := range result.Items {
		items[index] = officialDefinitionFromDetail(result.Items[index])
	}
	pageResponse := officialDefinitionPageResponse{Items: items}
	if result.Next != uuid.Nil {
		pageResponse.NextCursor = result.Next.String()
	}
	writeJSON(response, http.StatusOK, pageResponse)
}

func (h *handler) reserveOfficialDefinition(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	var envelope officialMutationEnvelope[reserveOfficialDefinitionPayload]
	if decodeOfficialAdminJSON(response, request, &envelope) != nil || envelope.ExpectedRevision != 1 {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	operationID, ok := parseCanonicalUUID(envelope.OperationID)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(
		request, admin.OfficialDefinitionReserve, "platform_definition", operationID,
		envelope.evidence(), envelope.Payload,
	)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.ReserveDefinition(request.Context(), actor, agentcontrol.ReservePlatformDefinitionCommand{
		DisplayName: envelope.Payload.DisplayName, IconMediaType: envelope.Payload.IconMediaType,
		IconData: append([]byte(nil), envelope.Payload.IconData...), IdempotencyKey: envelope.OperationID,
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) getOfficialDefinition(response http.ResponseWriter, request *http.Request) {
	id, ok := officialPathUUID(request, "definitionID")
	if !ok || !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := officialPlatformActor(request)
	if !ok {
		writeErrorResponse(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		return
	}
	value, err := h.officialAgents.GetDefinition(request.Context(), actor, id)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, officialDefinitionFromDetail(value))
}

func (h *handler) listOfficialDrafts(response http.ResponseWriter, request *http.Request) {
	page, ok := parseOfficialPage(request.URL)
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.ListDrafts(request.Context(), actor, page)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	items := make([]officialDraftResponse, len(value.Items))
	for index := range value.Items {
		items[index] = officialDraftFromDomain(value.Items[index])
	}
	writeJSON(response, http.StatusOK, officialPage(value.Next, items))
}

func (h *handler) getOfficialDraft(response http.ResponseWriter, request *http.Request) {
	id, ok := officialPathUUID(request, "draftID")
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK || !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.GetDraft(request.Context(), actor, id)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, officialDraftFromDomain(value))
}

func (h *handler) createOfficialDraft(response http.ResponseWriter, request *http.Request) {
	if !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	var envelope officialMutationEnvelope[officialDraftPayload]
	if decodeOfficialAdminJSON(response, request, &envelope) != nil || envelope.ExpectedRevision != 1 {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	operationID, opOK := parseCanonicalUUID(envelope.OperationID)
	definitionID, definitionOK := parseCanonicalUUID(envelope.Payload.DefinitionID)
	baseVersionID, baseOK := parseOptionalCanonicalUUID(envelope.Payload.BaseVersionID)
	if !opOK || !definitionOK || !baseOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, admin.OfficialDraftCreate, "platform_draft", operationID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.CreateDraft(request.Context(), actor, agentcontrol.CreatePlatformDraftCommand{
		DefinitionID: definitionID, BaseVersionID: baseVersionID, Kind: envelope.Payload.Kind,
		DisplayName: envelope.Payload.DisplayName, IconMediaType: envelope.Payload.IconMediaType,
		IconData: append([]byte(nil), envelope.Payload.IconData...), Manifest: envelope.Payload.Manifest,
		Bundle: envelope.Payload.Bundle, IdempotencyKey: envelope.OperationID,
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) updateOfficialDraft(response http.ResponseWriter, request *http.Request) {
	draftID, pathOK := officialPathUUID(request, "draftID")
	var envelope officialMutationEnvelope[officialDraftPayload]
	if !pathOK || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil ||
		envelope.Payload.DefinitionID != "" || envelope.Payload.Kind == "" {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	baseVersionID, baseOK := parseOptionalCanonicalUUID(envelope.Payload.BaseVersionID)
	if !baseOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, admin.OfficialDraftUpdate, "platform_draft", draftID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.UpdateDraft(request.Context(), actor, agentcontrol.UpdatePlatformDraftCommand{
		DraftID: draftID, ExpectedRevision: envelope.ExpectedRevision, Kind: envelope.Payload.Kind,
		BaseVersionID: baseVersionID, DisplayName: envelope.Payload.DisplayName,
		IconMediaType: envelope.Payload.IconMediaType, IconData: append([]byte(nil), envelope.Payload.IconData...),
		Manifest: envelope.Payload.Manifest, Bundle: envelope.Payload.Bundle, IdempotencyKey: envelope.OperationID,
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) validateOfficialDraft(response http.ResponseWriter, request *http.Request) {
	draftID, ok := officialPathUUID(request, "draftID")
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK || !hasNoQuery(request.URL) || request.ContentLength > 0 {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.ValidateDraft(request.Context(), actor, draftID)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	findings := value.Findings
	if findings == nil {
		findings = make([]agentcontrol.ExperienceCandidateFinding, 0)
	}
	writeJSON(response, http.StatusOK, struct {
		DraftID       uuid.UUID                                 `json:"draft_id"`
		DraftRevision int64                                     `json:"draft_revision"`
		ContentDigest string                                    `json:"content_digest"`
		DLPVersion    string                                    `json:"dlp_version"`
		Valid         bool                                      `json:"valid"`
		Findings      []agentcontrol.ExperienceCandidateFinding `json:"findings"`
	}{value.DraftID, value.DraftRevision, digestString(value.ContentDigest), value.DLPVersion, value.Valid, findings})
}

func (h *handler) submitOfficialDraft(response http.ResponseWriter, request *http.Request) {
	draftID, ok := officialPathUUID(request, "draftID")
	var envelope officialMutationEnvelope[emptyOfficialPayload]
	if !ok || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	operationID, opOK := parseCanonicalUUID(envelope.OperationID)
	if !opOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, admin.OfficialDraftSubmit, "platform_submission", operationID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.SubmitDraft(request.Context(), actor, agentcontrol.SubmitPlatformDraftCommand{
		DraftID: draftID, ExpectedRevision: envelope.ExpectedRevision, IdempotencyKey: envelope.OperationID,
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) listOfficialSubmissions(response http.ResponseWriter, request *http.Request) {
	filter, ok := parseOfficialSubmissionFilter(request.URL)
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.ListSubmissions(request.Context(), actor, filter)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	items := make([]officialSubmissionResponse, len(value.Items))
	for index := range value.Items {
		items[index] = officialSubmissionFromDomain(value.Items[index])
	}
	writeJSON(response, http.StatusOK, officialPage(value.Next, items))
}

func (h *handler) getOfficialSubmission(response http.ResponseWriter, request *http.Request) {
	id, ok := officialPathUUID(request, "submissionID")
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK || !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.GetSubmission(request.Context(), actor, id)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, officialSubmissionFromDomain(value))
}

func (h *handler) withdrawOfficialSubmission(response http.ResponseWriter, request *http.Request) {
	submissionID, ok := officialPathUUID(request, "submissionID")
	var envelope officialMutationEnvelope[emptyOfficialPayload]
	if !ok || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, admin.OfficialSubmissionWithdraw, "platform_submission", submissionID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.WithdrawSubmission(request.Context(), actor, agentcontrol.TerminalPlatformSubmissionCommand{
		SubmissionID: submissionID, ExpectedRevision: envelope.ExpectedRevision, IdempotencyKey: envelope.OperationID,
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) reviewOfficialSubmission(response http.ResponseWriter, request *http.Request) {
	submissionID, ok := officialPathUUID(request, "submissionID")
	var envelope officialMutationEnvelope[reviewOfficialSubmissionPayload]
	if !ok || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, admin.OfficialSubmissionReview, "platform_submission", submissionID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.ReviewSubmission(request.Context(), actor, agentcontrol.ReviewPlatformSubmissionCommand{
		SubmissionID: submissionID, ExpectedRevision: envelope.ExpectedRevision,
		Decision: envelope.Payload.Decision, ReasonCode: envelope.Payload.ReviewReasonCode,
		SafeNote: envelope.Payload.SafeNote, InitialChannels: append([]agentcontrol.OfficialChannel(nil), envelope.Payload.InitialChannels...),
		IdempotencyKey: envelope.OperationID,
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) listOfficialVersions(response http.ResponseWriter, request *http.Request) {
	page, ok := parseOfficialPage(request.URL)
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.ListVersions(request.Context(), actor, page)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	items := make([]officialVersionResponse, len(value.Items))
	for index := range value.Items {
		converted, ok := officialVersionFromDomain(value.Items[index])
		if !ok {
			writeErrorResponse(response, request, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE")
			return
		}
		items[index] = converted
	}
	writeJSON(response, http.StatusOK, officialPage(value.Next, items))
}

func (h *handler) getOfficialVersion(response http.ResponseWriter, request *http.Request) {
	id, ok := officialPathUUID(request, "versionID")
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK || !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.GetVersion(request.Context(), actor, id)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	converted, ok := officialVersionFromDomain(value)
	if !ok {
		writeErrorResponse(response, request, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE")
		return
	}
	writeJSON(response, http.StatusOK, converted)
}

func (h *handler) listOfficialReleases(response http.ResponseWriter, request *http.Request) {
	page, ok := parseOfficialPage(request.URL)
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.ListReleases(request.Context(), actor, page)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	items := make([]officialReleaseResponse, len(value.Items))
	for index := range value.Items {
		items[index] = officialReleaseFromDomain(value.Items[index])
	}
	writeJSON(response, http.StatusOK, officialPage(value.Next, items))
}

func (h *handler) getOfficialRelease(response http.ResponseWriter, request *http.Request) {
	id, ok := officialPathUUID(request, "releaseID")
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK || !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.GetRelease(request.Context(), actor, id)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, officialReleaseFromDomain(value))
}

func (h *handler) getOfficialDeliveryVerificationSummary(response http.ResponseWriter, request *http.Request) {
	id, ok := officialPathUUID(request, "releaseID")
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK || !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.GetDeliveryVerificationSummary(request.Context(), actor, id)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, officialDeliveryVerificationSummaryFromDomain(value))
}

func (h *handler) getOfficialDeliveryTarget(response http.ResponseWriter, request *http.Request) {
	id, ok := officialPathUUID(request, "submissionID")
	actor, actorOK := officialPlatformActor(request)
	if !ok || !actorOK || !hasNoQuery(request.URL) {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAgents.GetDeliveryTarget(request.Context(), actor, id)
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, officialDeliveryTargetFromDomain(value))
}

func (h *handler) activateOfficialRelease(response http.ResponseWriter, request *http.Request) {
	releaseID, ok := officialPathUUID(request, "releaseID")
	var envelope officialMutationEnvelope[activateOfficialReleasePayload]
	if !ok || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	versionID, versionOK := parseCanonicalUUID(envelope.Payload.VersionID)
	audience, audienceOK := parseCanonicalUUIDList(envelope.Payload.AllowlistedUserIDs)
	if !versionOK || !audienceOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, admin.OfficialReleaseActivate, "official_release", releaseID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.ActivateOfficialRelease(request.Context(), actor, agentcontrol.ActivateOfficialReleaseCommand{
		ReleaseID: releaseID, VersionID: versionID, ExpectedHeadRevision: envelope.ExpectedRevision,
		RolloutBasisPoints:    envelope.Payload.RolloutBasisPoints,
		MinimumDesktopVersion: envelope.Payload.MinimumDesktopVersion, AllowlistedUserIDs: audience,
		Evidence: platformOperationEvidence(envelope),
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) updateOfficialReleaseRollout(response http.ResponseWriter, request *http.Request) {
	releaseID, ok := officialPathUUID(request, "releaseID")
	var envelope officialMutationEnvelope[rolloutOfficialReleasePayload]
	if !ok || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	audience, audienceOK := parseCanonicalUUIDList(envelope.Payload.AllowlistedUserIDs)
	if !audienceOK {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, admin.OfficialReleaseRollout, "official_release", releaseID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.UpdateOfficialRollout(request.Context(), actor, agentcontrol.UpdateOfficialRolloutCommand{
		ReleaseID: releaseID, ExpectedHeadRevision: envelope.ExpectedRevision,
		RolloutBasisPoints:    envelope.Payload.RolloutBasisPoints,
		MinimumDesktopVersion: envelope.Payload.MinimumDesktopVersion, AllowlistedUserIDs: audience,
		Evidence: platformOperationEvidence(envelope),
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) pauseOfficialRelease(response http.ResponseWriter, request *http.Request) {
	h.changeOfficialReleaseState(response, request, admin.OfficialReleasePause, true)
}

func (h *handler) resumeOfficialRelease(response http.ResponseWriter, request *http.Request) {
	h.changeOfficialReleaseState(response, request, admin.OfficialReleaseResume, false)
}

func (h *handler) changeOfficialReleaseState(
	response http.ResponseWriter,
	request *http.Request,
	action admin.Action,
	pause bool,
) {
	releaseID, ok := officialPathUUID(request, "releaseID")
	var envelope officialMutationEnvelope[emptyOfficialPayload]
	if !ok || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, action, "official_release", releaseID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	command := agentcontrol.ChangeOfficialReleaseStateCommand{
		ReleaseID: releaseID, ExpectedHeadRevision: envelope.ExpectedRevision,
		Evidence: platformOperationEvidence(envelope),
	}
	var err error
	if pause {
		_, err = h.officialAgents.PauseOfficialRelease(request.Context(), actor, command)
	} else {
		_, err = h.officialAgents.ResumeOfficialRelease(request.Context(), actor, command)
	}
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) rollbackOfficialRelease(response http.ResponseWriter, request *http.Request) {
	releaseID, ok := officialPathUUID(request, "releaseID")
	var envelope officialMutationEnvelope[rollbackOfficialReleasePayload]
	if !ok || !hasNoQuery(request.URL) || decodeOfficialAdminJSON(response, request, &envelope) != nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	versionID, versionOK := parseCanonicalUUID(envelope.Payload.TargetVersionID)
	revisionID, revisionOK := parseCanonicalUUID(envelope.Payload.TargetReleaseRevisionID)
	approvalID, approvalOK := parseOptionalCanonicalUUID(envelope.ApprovalID)
	if !versionOK || !revisionOK || !approvalOK || approvalID == uuid.Nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := h.officialMutationActor(request, admin.OfficialReleaseRollback, "official_release", releaseID, envelope.evidence(), envelope.Payload)
	if !ok {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	_, err := h.officialAgents.RollbackOfficialRelease(request.Context(), actor, agentcontrol.RollbackOfficialReleaseCommand{
		ReleaseID: releaseID, TargetVersionID: versionID, TargetReleaseRevisionID: revisionID,
		ExpectedHeadRevision: envelope.ExpectedRevision, ApprovalID: approvalID,
		Evidence: platformOperationEvidence(envelope),
	})
	if err != nil {
		writeOfficialAgentError(response, request, err)
		return
	}
	h.writeOfficialOperationResult(response, request, envelope.OperationID)
}

func (h *handler) listOfficialAgentAuditEvents(response http.ResponseWriter, request *http.Request) {
	actor, actorOK := OfficialActorFromContext(request.Context())
	if !actorOK {
		writeErrorResponse(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		return
	}
	if actor.Role != "super_admin" && actor.Role != "auditor" {
		writeErrorResponse(response, request, http.StatusForbidden, "PERMISSION_DENIED")
		return
	}
	page, ok := parsePageQuery(request.URL)
	if !ok || h.officialAudit == nil {
		writeErrorResponse(response, request, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	value, err := h.officialAudit.ListOfficialAuditEvents(request.Context(), page)
	if err != nil {
		writeDomainError(response, request, err, "AUDIT_EVENT_NOT_FOUND", admin.Operation{})
		return
	}
	writeJSON(response, http.StatusOK, value)
}

func (h *handler) writeOfficialOperationResult(
	response http.ResponseWriter,
	request *http.Request,
	operationIDValue string,
) {
	operationID, ok := parseCanonicalUUID(operationIDValue)
	if !ok {
		writeErrorResponse(response, request, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE")
		return
	}
	operation, err := h.service.GetOperation(request.Context(), operationID)
	if err != nil {
		writeDomainError(response, request, err, "OPERATION_NOT_FOUND", admin.Operation{})
		return
	}
	if operation.ID != operationID || operation.Status != admin.OperationSucceeded {
		writeErrorResponse(response, request, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE")
		return
	}
	writeJSON(response, http.StatusOK, operation)
}

func (h *handler) officialMutationActor(
	request *http.Request,
	action admin.Action,
	targetType string,
	targetID uuid.UUID,
	evidence officialMutationEvidence,
	payload any,
) (agentcontrol.PlatformAdminActor, bool) {
	verified, ok := OfficialActorFromContext(request.Context())
	if !ok || h.operationProtector == nil || targetID == uuid.Nil {
		return agentcontrol.PlatformAdminActor{}, false
	}
	operationID, operationOK := parseCanonicalUUID(evidence.OperationID)
	actorID, actorOK := parseCanonicalUUID(evidence.ActorAdminID)
	if !operationOK || !actorOK || operationID != verified.OperationID || actorID != verified.AdminID ||
		evidence.ActorAdminRole != verified.Role {
		return agentcontrol.PlatformAdminActor{}, false
	}
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || values[0] != evidence.OperationID {
		return agentcontrol.PlatformAdminActor{}, false
	}
	approvalID, approvalOK := parseOptionalCanonicalUUID(evidence.ApprovalID)
	requesterID, requesterOK := parseOptionalCanonicalUUID(evidence.RequesterAdminID)
	if !approvalOK || !requesterOK || approvalID != verified.ApprovalID || requesterID != verified.RequesterAdminID {
		return agentcontrol.PlatformAdminActor{}, false
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return agentcontrol.PlatformAdminActor{}, false
	}
	payloadDigest := sha256.Sum256(payloadJSON)
	var approvalPointer, requesterPointer *uuid.UUID
	if approvalID != uuid.Nil {
		approvalPointer, requesterPointer = &approvalID, &requesterID
	}
	command := admin.OfficialOperationCommand{
		OperationID: operationID, ActorAdminID: actorID, ActorAdminRole: verified.Role,
		ApprovalID: approvalPointer, RequesterAdminID: requesterPointer,
		RequestID: requestIDFromContext(request.Context()), ReasonCode: evidence.ReasonCode,
		TicketReference: evidence.TicketReference, ExpectedRevision: evidence.ExpectedRevision,
		PayloadDigest: payloadDigest[:],
	}
	digest, fingerprint, err := h.operationProtector.ProtectOfficialOperation(action, targetID, command)
	if err != nil {
		return agentcontrol.PlatformAdminActor{}, false
	}
	serviceSubject, ok := admin.ServiceSubject(request.Context())
	if !ok {
		return agentcontrol.PlatformAdminActor{}, false
	}
	return agentcontrol.PlatformAdminActor{
		AdminID: actorID, Role: verified.Role, RequestID: command.RequestID,
		Operation: &agentcontrol.PlatformAdminOperationProof{
			OperationID: operationID, Action: string(action), TargetType: targetType, TargetID: targetID,
			ExpectedRevision: evidence.ExpectedRevision, ApprovalID: approvalID,
			RequesterAdminID: requesterID, ServiceSubject: serviceSubject,
			IdempotencyKeyID: digest.KeyID, IdempotencyKeyHMAC: append([]byte(nil), digest.Sum...),
			RequestFingerprint: append([]byte(nil), fingerprint...), ReasonCode: evidence.ReasonCode,
			TicketReference: evidence.TicketReference,
		},
	}, true
}

func officialPlatformActor(request *http.Request) (agentcontrol.PlatformAdminActor, bool) {
	verified, ok := OfficialActorFromContext(request.Context())
	requestID := requestIDFromContext(request.Context())
	if !ok || requestID == "" {
		return agentcontrol.PlatformAdminActor{}, false
	}
	return agentcontrol.PlatformAdminActor{
		AdminID: verified.AdminID, Role: verified.Role, RequestID: requestID,
	}, true
}

func officialDefinitionFromDetail(value agentcontrol.PlatformDefinitionDetail) officialDefinitionResponse {
	return officialDefinitionResponse{
		DefinitionID: value.Definition.ID, PlatformID: value.PlatformID,
		DisplayName: value.Definition.DisplayName, IconMediaType: value.Definition.IconMediaType,
		IconData: append([]byte(nil), value.Definition.IconData...), Status: value.Definition.Status,
		LatestVersionID: value.Definition.LatestVersionID, CreatedByAdminID: value.CreatedByAdminID,
		CreatedAt: value.Definition.CreatedAt.UTC(), UpdatedAt: value.Definition.UpdatedAt.UTC(),
	}
}

func officialDraftFromDomain(value agentcontrol.PlatformAgentDraft) officialDraftResponse {
	return officialDraftResponse{
		DraftID: value.ID, PlatformID: value.PlatformID, DefinitionID: value.DefinitionID,
		BaseVersionID: optionalUUID(value.BaseVersionID), Kind: value.Kind, DisplayName: value.DisplayName,
		IconMediaType: value.IconMediaType, IconData: append([]byte(nil), value.IconData...),
		Manifest: value.Manifest, Bundle: value.Bundle, ManifestDigest: digestString(value.ManifestDigest),
		BundleDigest: digestString(value.BundleDigest), ContentDigest: digestString(value.ContentDigest),
		Revision: value.Revision, Status: value.Status, LastEditorAdminID: value.LastEditorAdminID,
		LastEditorRole: value.LastEditorRole, CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(),
		Replayed: value.Replayed,
	}
}

func officialSubmissionFromDomain(value agentcontrol.PlatformAgentSubmission) officialSubmissionResponse {
	result := officialSubmissionResponse{
		SubmissionID: value.ID, PlatformID: value.PlatformID, DraftID: value.DraftID,
		DraftRevision: value.DraftRevision, DefinitionID: value.DefinitionID,
		BaseVersionID: optionalUUID(value.BaseVersionID), Kind: value.Kind, DisplayName: value.DisplayName,
		IconMediaType: value.IconMediaType, IconData: append([]byte(nil), value.IconData...),
		Manifest: value.Manifest, Bundle: value.Bundle, ManifestDigest: digestString(value.ManifestDigest),
		BundleDigest: digestString(value.BundleDigest), ContentDigest: digestString(value.ContentDigest),
		SubmittedByAdminID: value.SubmittedByAdminID, SubmittedByRole: value.SubmittedByRole,
		Status: value.Status, Revision: value.Revision, SubmittedAt: value.SubmittedAt.UTC(),
		UpdatedAt: value.UpdatedAt.UTC(), Replayed: value.Replayed,
	}
	if value.TerminalAt != nil {
		terminal := value.TerminalAt.UTC()
		result.TerminalAt = &terminal
	}
	if value.Review != nil {
		result.Review = &officialReviewResponse{
			ReviewID: value.Review.ID, ReviewerAdminID: value.Review.ReviewerAdminID,
			ReviewerRole: value.Review.ReviewerRole, Decision: value.Review.Decision,
			ReasonCode: value.Review.ReasonCode, SafeNote: value.Review.SafeNote,
			PlatformPolicySnapshotID: value.Review.PlatformPolicySnapshotID,
			PlatformPolicyVersion:    value.Review.PlatformPolicyVersion,
			ReviewedContentDigest:    digestString(value.Review.ReviewedContentDigest),
			ReviewedAt:               value.Review.ReviewedAt.UTC(),
		}
	}
	return result
}

func officialVersionFromDomain(value agentcontrol.Version) (officialVersionResponse, bool) {
	var manifest agentcontrol.AgentManifestV1
	var bundle agentcontrol.VersionBundleV1
	if json.Unmarshal(value.CanonicalManifest, &manifest) != nil || json.Unmarshal(value.Bundle, &bundle) != nil {
		return officialVersionResponse{}, false
	}
	return officialVersionResponse{
		VersionID: value.ID, DefinitionID: value.DefinitionID, VersionNumber: value.VersionNumber,
		Manifest: manifest, Bundle: bundle, ContentDigest: digestString(value.ContentDigest),
		RuntimeMinimumVersion:          value.RuntimeMinimumVersion,
		RuntimeMaximumVersionExclusive: value.RuntimeMaximumVersionExclusive,
		PublishedAt:                    value.PublishedAt.UTC(),
	}, true
}

func officialReleaseFromDomain(value agentcontrol.OfficialRelease) officialReleaseResponse {
	revision := value.CurrentRevision
	return officialReleaseResponse{
		ReleaseID: value.ID, PlatformID: value.PlatformID, DefinitionID: value.DefinitionID,
		Channel: value.Channel, CurrentRevisionID: value.CurrentRevisionID, HeadRevision: value.HeadRevision,
		AgentVersionID: revision.AgentVersionID, State: revision.State,
		RolloutBasisPoints: revision.RolloutBasisPoints, MinimumDesktopVersion: revision.MinimumDesktopVersion,
		Action: revision.Action, PreviousRevisionID: optionalUUID(revision.PreviousRevisionID),
		RollbackRevisionID: optionalUUID(revision.RollbackTargetRevisionID),
		ActorAdminID:       revision.ActorAdminID, ActorAdminRole: revision.ActorAdminRole,
		ReasonCode: revision.ReasonCode, TicketReference: revision.TicketReference,
		AudienceCount: len(revision.AllowlistedUserIDs), CreatedAt: value.CreatedAt.UTC(),
		UpdatedAt: value.UpdatedAt.UTC(), Replayed: value.Replayed,
	}
}

func officialDeliveryVerificationSummaryFromDomain(
	value agentcontrol.OfficialDeliveryVerificationSummary,
) officialDeliveryVerificationSummaryResponse {
	stages := make([]officialDeliveryVerificationStageResponse, len(value.Stages))
	for index := range value.Stages {
		stage := value.Stages[index]
		stages[index] = officialDeliveryVerificationStageResponse{
			VerificationStatus: stage.Status, ErrorCode: stage.ErrorCode,
			ReleaseRevisionID: stage.ReleaseRevisionID, DefinitionID: stage.DefinitionID,
			VersionID: stage.VersionID, ContentDigest: digestString(stage.ContentDigest),
			DeviceCount: stage.DeviceCount, RuntimeVersion: stage.RuntimeVersion,
			DesktopVersion: stage.DesktopVersion, OccurredAt: stage.OccurredAt.UTC(),
			ReceivedAt: stage.ReceivedAt.UTC(), RequestID: stage.RequestID,
		}
	}
	return officialDeliveryVerificationSummaryResponse{ReleaseID: value.ReleaseID, Stages: stages}
}

func officialDeliveryTargetFromDomain(value agentcontrol.OfficialDeliveryTarget) officialDeliveryTargetResponse {
	releases := make([]officialDeliveryTargetReleaseResponse, len(value.Releases))
	for index := range value.Releases {
		release := value.Releases[index]
		releases[index] = officialDeliveryTargetReleaseResponse{
			ReleaseID: release.ID, CurrentRevisionID: release.CurrentRevisionID, VersionID: release.VersionID,
			Channel: release.Channel, State: release.State,
		}
	}
	return officialDeliveryTargetResponse{
		SubmissionID: value.SubmissionID, DefinitionID: value.DefinitionID, VersionID: value.VersionID,
		ContentDigest: digestString(value.ContentDigest), Releases: releases,
	}
}

func officialPage[T any](next uuid.UUID, items []T) officialPageResponse[T] {
	if items == nil {
		items = make([]T, 0)
	}
	result := officialPageResponse[T]{Items: items}
	if next != uuid.Nil {
		result.NextCursor = next.String()
	}
	return result
}

func optionalUUID(value uuid.UUID) *uuid.UUID {
	if value == uuid.Nil {
		return nil
	}
	copy := value
	return &copy
}

func digestString(value [sha256.Size]byte) string {
	return hex.EncodeToString(value[:])
}

func officialPathUUID(request *http.Request, key string) (uuid.UUID, bool) {
	if request == nil {
		return uuid.Nil, false
	}
	return parseCanonicalUUID(chi.URLParam(request, key))
}

func parseCanonicalUUIDList(values []string) ([]uuid.UUID, bool) {
	if len(values) > 10000 {
		return nil, false
	}
	result := make([]uuid.UUID, len(values))
	seen := make(map[uuid.UUID]struct{}, len(values))
	for index, value := range values {
		parsed, ok := parseCanonicalUUID(value)
		if !ok {
			return nil, false
		}
		if _, duplicate := seen[parsed]; duplicate {
			return nil, false
		}
		seen[parsed] = struct{}{}
		result[index] = parsed
	}
	return result, true
}

func platformOperationEvidence[T any](envelope officialMutationEnvelope[T]) agentcontrol.PlatformOperationEvidence {
	return agentcontrol.PlatformOperationEvidence{
		ReasonCode: envelope.ReasonCode, TicketReference: envelope.TicketReference,
		IdempotencyKey: envelope.OperationID,
	}
}

func parseOfficialPage(value *url.URL) (agentcontrol.PageRequest, bool) {
	if value == nil {
		return agentcontrol.PageRequest{}, false
	}
	query := value.Query()
	for key, values := range query {
		if (key != "cursor" && key != "limit") || len(values) != 1 || values[0] == "" {
			return agentcontrol.PageRequest{}, false
		}
	}
	page := agentcontrol.PageRequest{}
	if cursor := query.Get("cursor"); cursor != "" {
		parsed, ok := parseCanonicalUUID(cursor)
		if !ok {
			return agentcontrol.PageRequest{}, false
		}
		page.After = parsed
	}
	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != raw {
			return agentcontrol.PageRequest{}, false
		}
		page.Limit = limit
	}
	return page, true
}

func parseOfficialSubmissionFilter(value *url.URL) (agentcontrol.PlatformSubmissionFilter, bool) {
	if value == nil {
		return agentcontrol.PlatformSubmissionFilter{}, false
	}
	query := value.Query()
	for key, values := range query {
		if (key != "cursor" && key != "limit" && key != "status") || len(values) != 1 || values[0] == "" {
			return agentcontrol.PlatformSubmissionFilter{}, false
		}
	}
	pageURL := *value
	pageQuery := pageURL.Query()
	pageQuery.Del("status")
	pageURL.RawQuery = pageQuery.Encode()
	page, ok := parseOfficialPage(&pageURL)
	if !ok {
		return agentcontrol.PlatformSubmissionFilter{}, false
	}
	status := agentcontrol.PlatformSubmissionStatus(query.Get("status"))
	switch status {
	case "", agentcontrol.PlatformSubmissionPending, agentcontrol.PlatformSubmissionApproved,
		agentcontrol.PlatformSubmissionRejected, agentcontrol.PlatformSubmissionWithdrawn,
		agentcontrol.PlatformSubmissionSuperseded:
	default:
		return agentcontrol.PlatformSubmissionFilter{}, false
	}
	return agentcontrol.PlatformSubmissionFilter{Status: status, Page: page}, true
}

func parseOptionalCanonicalUUID(value *string) (uuid.UUID, bool) {
	if value == nil {
		return uuid.Nil, true
	}
	return parseCanonicalUUID(*value)
}

func decodeOfficialAdminJSON(response http.ResponseWriter, request *http.Request, target any) error {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errors.New("one JSON content type is required")
	}
	mediaType, parameters, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" || len(parameters) != 0 ||
		request.ContentLength > maximumOfficialAdminRequestBodyBytes {
		return errors.New("valid JSON content type is required")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumOfficialAdminRequestBodyBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || rejectDuplicateObjectKeys(raw) != nil {
		return errors.New("request JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("request JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("request JSON has trailing data")
	}
	return nil
}

func rejectDuplicateObjectKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON has trailing data")
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, duplicate := keys[key]; duplicate {
				return errors.New("duplicate JSON key")
			}
			keys[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("JSON delimiter is invalid")
	}
	return nil
}

func writeOfficialAgentError(response http.ResponseWriter, request *http.Request, err error) {
	status, code := http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	switch {
	case errors.Is(err, agentcontrol.ErrInvalidRequest), errors.Is(err, agentcontrol.ErrInvalidAgentContent),
		errors.Is(err, agentcontrol.ErrOfficialRolloutInvalid):
		status, code = http.StatusBadRequest, "INVALID_REQUEST"
	case errors.Is(err, agentcontrol.ErrPlatformForbidden):
		status, code = http.StatusForbidden, "PERMISSION_DENIED"
	case errors.Is(err, agentcontrol.ErrNotFound):
		status, code = http.StatusNotFound, "OFFICIAL_AGENT_NOT_FOUND"
	case errors.Is(err, agentcontrol.ErrOfficialSubmissionConflict),
		errors.Is(err, agentcontrol.ErrOfficialReleaseRevisionConflict),
		errors.Is(err, agentcontrol.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "STATE_CONFLICT"
	case errors.Is(err, agentcontrol.ErrPlatformPublicationDLPBlocked):
		status, code = http.StatusUnprocessableEntity, "PUBLICATION_DLP_BLOCKED"
	}
	writeErrorResponse(response, request, status, code)
}
