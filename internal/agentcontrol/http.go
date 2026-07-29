package agentcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	metadataRequestBodyLimit    = 64 * 1024
	publicationRequestBodyLimit = 5 * 1024 * 1024 / 2
	candidateRequestBodyLimit   = 5 * 1024 * 1024 / 4
)

type HTTPService interface {
	ListDefinitions(context.Context, Principal) ([]Definition, error)
	PublishInitial(context.Context, Principal, PublishInitialRequest) (Publication, error)
	GetDefinition(context.Context, Principal, uuid.UUID, string) (Definition, error)
	ListVersions(context.Context, Principal, uuid.UUID, string) ([]Version, error)
	PublishNext(context.Context, Principal, PublishNextRequest) (Publication, error)
	ListWorkspaceDefinitions(context.Context, Principal, uuid.UUID) ([]Definition, error)
	PublishWorkspaceInitial(context.Context, Principal, uuid.UUID, PublishInitialRequest) (Publication, error)
	GetWorkspaceDefinition(context.Context, Principal, uuid.UUID, uuid.UUID, string) (Definition, error)
	ListWorkspaceVersions(context.Context, Principal, uuid.UUID, uuid.UUID, string) ([]Version, error)
	PublishWorkspaceNext(context.Context, Principal, uuid.UUID, PublishNextRequest) (Publication, error)
	ListOrganizationDefinitions(context.Context, Principal, uuid.UUID) ([]Definition, error)
	GetOrganizationDefinition(context.Context, Principal, uuid.UUID, uuid.UUID, string) (Definition, error)
	ListOrganizationVersions(context.Context, Principal, uuid.UUID, uuid.UUID, string) ([]Version, error)
	SubmitOrganizationAgent(context.Context, Principal, uuid.UUID, SubmitOrganizationAgentRequest) (OrganizationAgentSubmission, error)
	ListOrganizationAgentSubmissions(context.Context, Principal, uuid.UUID) ([]OrganizationAgentSubmission, error)
	GetOrganizationAgentSubmission(context.Context, Principal, uuid.UUID, uuid.UUID) (OrganizationAgentSubmission, error)
	WithdrawOrganizationAgentSubmission(context.Context, Principal, uuid.UUID, WithdrawOrganizationAgentRequest) (OrganizationAgentSubmission, error)
	ReviewOrganizationAgentSubmission(context.Context, Principal, uuid.UUID, ReviewOrganizationAgentRequest) (OrganizationAgentSubmission, error)
	GetVersion(context.Context, Principal, uuid.UUID, string) (Version, error)
	GetPolicySnapshot(context.Context, Principal, uuid.UUID, string) (PolicySnapshot, error)
	RevokeVersion(context.Context, Principal, RevokeVersionRequest) (VersionRevocation, error)
	CreateInstallation(context.Context, Principal, CreateInstallationRequest) (InstallationCreation, error)
	ActivateInstallation(context.Context, Principal, ActivateInstallationRequest) (Installation, error)
	SelectInstallationVersion(context.Context, Principal, SelectInstallationVersionRequest) (Installation, error)
	GetManagedOfficialUpdate(context.Context, Principal, GetManagedOfficialUpdateRequest) (OfficialManagedUpdate, error)
	ApplyManagedOfficialUpdate(context.Context, Principal, ManagedUpdateRequest) (Installation, error)
	ArchiveInstallation(context.Context, Principal, ArchiveInstallationRequest) (Installation, error)
	RecordRuntimeBinding(context.Context, Principal, RuntimeBindingRecordCommand, string) (RuntimeBindingRecord, error)
	SubmitExperienceCandidate(context.Context, Principal, uuid.UUID, SubmitExperienceCandidateRequest) (ExperienceCandidate, error)
	ListOwnExperienceCandidates(context.Context, Principal, uuid.UUID) ([]ExperienceCandidate, error)
	ListWorkspaceExperienceCandidates(context.Context, Principal, uuid.UUID) ([]ExperienceCandidate, error)
	GetExperienceCandidate(context.Context, Principal, uuid.UUID, uuid.UUID, string) (ExperienceCandidate, error)
	ReviewExperienceCandidate(context.Context, Principal, uuid.UUID, ReviewExperienceCandidateRequest) (ExperienceCandidate, error)
}

type OfficialCatalogHTTPService interface {
	ListOfficialAgents(context.Context, Principal, OfficialEligibilityContext) ([]OfficialAgentCatalogEntry, error)
	GetOfficialAgent(context.Context, Principal, uuid.UUID, OfficialEligibilityContext) (OfficialAgentCatalogEntry, error)
}

type AccessAuthenticator interface {
	Authenticate(context.Context, string) (session.AccessClaims, error)
}

type HTTPConfig struct {
	Service      HTTPService
	Official     OfficialCatalogHTTPService
	AccessTokens AccessAuthenticator
}

type httpHandler struct {
	service      HTTPService
	official     OfficialCatalogHTTPService
	accessTokens AccessAuthenticator
}

func NewHandler(config HTTPConfig) http.Handler {
	handler := &httpHandler{service: config.Service, official: config.Official, accessTokens: config.AccessTokens}
	router := chi.NewRouter()
	router.Get("/api/v1/official-agents", handler.listOfficialAgents)
	router.Get("/api/v1/official-agents/{definitionID}", handler.getOfficialAgent)
	router.Get("/api/v1/official-agents/{definitionID}/release", handler.getOfficialRelease)
	router.Get("/api/v1/agent-definitions", handler.listDefinitions)
	router.Post("/api/v1/agent-definitions", handler.publishInitial)
	router.Get("/api/v1/agent-definitions/{definitionID}", handler.getDefinition)
	router.Get("/api/v1/agent-definitions/{definitionID}/versions", handler.listVersions)
	router.Post("/api/v1/agent-definitions/{definitionID}/versions", handler.publishNext)
	router.Get("/api/v1/workspaces/{workspaceID}/agent-definitions", handler.listWorkspaceDefinitions)
	router.Post("/api/v1/workspaces/{workspaceID}/agent-definitions", handler.publishWorkspaceInitial)
	router.Get("/api/v1/workspaces/{workspaceID}/agent-definitions/{definitionID}", handler.getWorkspaceDefinition)
	router.Get("/api/v1/workspaces/{workspaceID}/agent-definitions/{definitionID}/versions", handler.listWorkspaceVersions)
	router.Post("/api/v1/workspaces/{workspaceID}/agent-definitions/{definitionID}/versions", handler.publishWorkspaceNext)
	router.Get("/api/v1/organizations/{organizationID}/agent-definitions", handler.listOrganizationDefinitions)
	router.Get("/api/v1/organizations/{organizationID}/agent-definitions/{definitionID}", handler.getOrganizationDefinition)
	router.Get("/api/v1/organizations/{organizationID}/agent-definitions/{definitionID}/versions", handler.listOrganizationVersions)
	router.Post("/api/v1/organizations/{organizationID}/agent-publication-submissions", handler.submitOrganizationAgent)
	router.Get("/api/v1/organizations/{organizationID}/agent-publication-submissions", handler.listOrganizationAgentSubmissions)
	router.Get("/api/v1/organizations/{organizationID}/agent-publication-submissions/{submissionID}", handler.getOrganizationAgentSubmission)
	router.Post("/api/v1/organizations/{organizationID}/agent-publication-submissions/{submissionID}/withdraw", handler.withdrawOrganizationAgentSubmission)
	router.Post("/api/v1/organizations/{organizationID}/agent-publication-submissions/{submissionID}/reviews", handler.reviewOrganizationAgentSubmission)
	router.Post("/api/v1/workspaces/{workspaceID}/agent-definitions/{definitionID}/experience-candidates", handler.submitExperienceCandidate)
	router.Get("/api/v1/workspaces/{workspaceID}/experience-candidates/mine", handler.listOwnExperienceCandidates)
	router.Get("/api/v1/workspaces/{workspaceID}/experience-candidates", handler.listWorkspaceExperienceCandidates)
	router.Get("/api/v1/workspaces/{workspaceID}/experience-candidates/{candidateID}", handler.getExperienceCandidate)
	router.Post("/api/v1/workspaces/{workspaceID}/experience-candidates/{candidateID}/review", handler.reviewExperienceCandidate)
	router.Get("/api/v1/agent-versions/{versionID}", handler.getVersion)
	router.Get("/api/v1/policy-snapshots/{policySnapshotID}", handler.getPolicySnapshot)
	router.Post("/api/v1/agent-versions/{versionID}/revocations", handler.revokeVersion)
	router.Post("/api/v1/agent-installations", handler.createInstallation)
	router.Post("/api/v1/agent-installations/{installationID}/activate", handler.activateInstallation)
	router.Post("/api/v1/agent-installations/{installationID}/select-version", handler.selectInstallationVersion)
	router.Get("/api/v1/agent-installations/{installationID}/managed-update", handler.getManagedOfficialUpdate)
	router.Post("/api/v1/agent-installations/{installationID}/apply-managed-update", handler.applyManagedOfficialUpdate)
	router.Post("/api/v1/agent-installations/{installationID}/archive", handler.archiveInstallation)
	router.Post("/api/v1/runtime-binding-records", handler.recordRuntimeBinding)
	return router
}

func (h *httpHandler) listDefinitions(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	definitions, err := h.service.ListDefinitions(request.Context(), principal)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	items := make([]definitionResponse, len(definitions))
	for index, definition := range definitions {
		items[index] = publicDefinition(definition)
	}
	writeAgentJSON(response, http.StatusOK, struct {
		Definitions []definitionResponse `json:"definitions"`
	}{Definitions: items})
}

func (h *httpHandler) publishInitial(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	var payload struct {
		DisplayName   string          `json:"display_name"`
		IconMediaType string          `json:"icon_media_type,omitempty"`
		IconData      string          `json:"icon_data,omitempty"`
		Manifest      AgentManifestV1 `json:"manifest"`
		Bundle        VersionBundleV1 `json:"bundle"`
	}
	if !decodeAgentJSON(response, request, publicationRequestBodyLimit, &payload) {
		return
	}
	iconData, ok := decodeOptionalBase64URL(payload.IconData)
	if !ok {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	publication, err := h.service.PublishInitial(request.Context(), principal, PublishInitialRequest{
		DisplayName: payload.DisplayName, IconMediaType: payload.IconMediaType, IconData: iconData,
		Manifest: payload.Manifest, Bundle: payload.Bundle, IdempotencyKey: idempotencyKey,
		RequestID: newAgentRequestID(),
	})
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicPublication(publication))
}

func (h *httpHandler) getDefinition(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	definitionID, ok := pathUUID(response, request, "definitionID")
	if !ok {
		return
	}
	definition, err := h.service.GetDefinition(request.Context(), principal, definitionID, newAgentRequestID())
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicDefinition(definition))
}

func (h *httpHandler) listVersions(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	definitionID, ok := pathUUID(response, request, "definitionID")
	if !ok {
		return
	}
	versions, err := h.service.ListVersions(request.Context(), principal, definitionID, newAgentRequestID())
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	items := make([]versionResponse, len(versions))
	for index, version := range versions {
		items[index] = publicVersion(version)
	}
	writeAgentJSON(response, http.StatusOK, struct {
		Versions []versionResponse `json:"versions"`
	}{Versions: items})
}

func (h *httpHandler) publishNext(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
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
		BaseVersionID uuid.UUID       `json:"base_version_id"`
		Manifest      AgentManifestV1 `json:"manifest"`
		Bundle        VersionBundleV1 `json:"bundle"`
	}
	if !decodeAgentJSON(response, request, publicationRequestBodyLimit, &payload) {
		return
	}
	publication, err := h.service.PublishNext(request.Context(), principal, PublishNextRequest{
		DefinitionID: definitionID, BaseVersionID: payload.BaseVersionID,
		Manifest: payload.Manifest, Bundle: payload.Bundle, IdempotencyKey: idempotencyKey,
		RequestID: newAgentRequestID(),
	})
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicPublication(publication))
}

func (h *httpHandler) listWorkspaceDefinitions(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	workspaceID, ok := pathUUID(response, request, "workspaceID")
	if !ok {
		return
	}
	definitions, err := h.service.ListWorkspaceDefinitions(request.Context(), principal, workspaceID)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	items := make([]definitionResponse, len(definitions))
	for index, definition := range definitions {
		items[index] = publicDefinition(definition)
	}
	writeAgentJSON(response, http.StatusOK, struct {
		Definitions []definitionResponse `json:"definitions"`
	}{Definitions: items})
}

func (h *httpHandler) publishWorkspaceInitial(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	workspaceID, ok := pathUUID(response, request, "workspaceID")
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	var payload struct {
		DisplayName   string          `json:"display_name"`
		IconMediaType string          `json:"icon_media_type,omitempty"`
		IconData      string          `json:"icon_data,omitempty"`
		Manifest      AgentManifestV1 `json:"manifest"`
		Bundle        VersionBundleV1 `json:"bundle"`
	}
	if !decodeAgentJSON(response, request, publicationRequestBodyLimit, &payload) {
		return
	}
	iconData, ok := decodeOptionalBase64URL(payload.IconData)
	if !ok {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	publication, err := h.service.PublishWorkspaceInitial(
		request.Context(), principal, workspaceID, PublishInitialRequest{
			DisplayName: payload.DisplayName, IconMediaType: payload.IconMediaType, IconData: iconData,
			Manifest: payload.Manifest, Bundle: payload.Bundle, IdempotencyKey: idempotencyKey,
			RequestID: newAgentRequestID(),
		},
	)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicPublication(publication))
}

func (h *httpHandler) getWorkspaceDefinition(response http.ResponseWriter, request *http.Request) {
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
	definition, err := h.service.GetWorkspaceDefinition(
		request.Context(), principal, workspaceID, definitionID, newAgentRequestID(),
	)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicDefinition(definition))
}

func (h *httpHandler) listWorkspaceVersions(response http.ResponseWriter, request *http.Request) {
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
	versions, err := h.service.ListWorkspaceVersions(
		request.Context(), principal, workspaceID, definitionID, newAgentRequestID(),
	)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	items := make([]versionResponse, len(versions))
	for index, version := range versions {
		items[index] = publicVersion(version)
	}
	writeAgentJSON(response, http.StatusOK, struct {
		Versions []versionResponse `json:"versions"`
	}{Versions: items})
}

func (h *httpHandler) publishWorkspaceNext(response http.ResponseWriter, request *http.Request) {
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
		BaseVersionID uuid.UUID       `json:"base_version_id"`
		Manifest      AgentManifestV1 `json:"manifest"`
		Bundle        VersionBundleV1 `json:"bundle"`
	}
	if !decodeAgentJSON(response, request, publicationRequestBodyLimit, &payload) {
		return
	}
	publication, err := h.service.PublishWorkspaceNext(
		request.Context(), principal, workspaceID, PublishNextRequest{
			DefinitionID: definitionID, BaseVersionID: payload.BaseVersionID,
			Manifest: payload.Manifest, Bundle: payload.Bundle, IdempotencyKey: idempotencyKey,
			RequestID: newAgentRequestID(),
		},
	)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicPublication(publication))
}

func (h *httpHandler) getVersion(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	versionID, ok := pathUUID(response, request, "versionID")
	if !ok {
		return
	}
	version, err := h.service.GetVersion(request.Context(), principal, versionID, newAgentRequestID())
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicVersion(version))
}

func (h *httpHandler) getPolicySnapshot(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	policySnapshotID, ok := pathUUID(response, request, "policySnapshotID")
	if !ok {
		return
	}
	policy, err := h.service.GetPolicySnapshot(request.Context(), principal, policySnapshotID, newAgentRequestID())
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicPolicy(policy))
}

func (h *httpHandler) revokeVersion(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	versionID, ok := pathUUID(response, request, "versionID")
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	var payload struct {
		ReasonCode           string     `json:"reason_code"`
		PolicySnapshotID     uuid.UUID  `json:"policy_snapshot_id"`
		SupersedingVersionID *uuid.UUID `json:"superseding_version_id,omitempty"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	revocation, err := h.service.RevokeVersion(request.Context(), principal, RevokeVersionRequest{
		VersionID: versionID, ReasonCode: payload.ReasonCode, PolicySnapshotID: payload.PolicySnapshotID,
		SupersedingVersionID: payload.SupersedingVersionID, IdempotencyKey: idempotencyKey,
		RequestID: newAgentRequestID(),
	})
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicRevocation(revocation))
}

func (h *httpHandler) createInstallation(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	var payload struct {
		DefinitionID              string  `json:"definition_id"`
		VersionID                 *string `json:"version_id,omitempty"`
		WorkspaceID               *string `json:"workspace_id,omitempty"`
		OrganizationID            *string `json:"organization_id,omitempty"`
		OfficialReleaseRevisionID *string `json:"official_release_revision_id,omitempty"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	official := payload.OfficialReleaseRevisionID != nil
	if payload.WorkspaceID != nil && payload.OrganizationID != nil ||
		(official && (payload.VersionID != nil || payload.WorkspaceID != nil || payload.OrganizationID != nil)) ||
		(!official && payload.VersionID == nil) {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	definitionID, definitionOK := canonicalUUID(payload.DefinitionID)
	var versionID uuid.UUID
	versionOK := true
	if payload.VersionID != nil {
		versionID, versionOK = canonicalUUID(*payload.VersionID)
	}
	workspaceID, workspaceOK := optionalCanonicalUUID(payload.WorkspaceID)
	organizationID, organizationOK := optionalCanonicalUUID(payload.OrganizationID)
	if !definitionOK || !versionOK || !workspaceOK || !organizationOK {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	serviceRequest := CreateInstallationRequest{
		DefinitionID: definitionID, VersionID: versionID, SourceWorkspaceID: workspaceID,
		OrganizationID: organizationID,
		IdempotencyKey: idempotencyKey, RequestID: newAgentRequestID(),
	}
	if official {
		revisionID, ok := canonicalUUID(*payload.OfficialReleaseRevisionID)
		if !ok {
			writeAgentError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		contextValue, ok := h.requireOfficialContext(response, request, principal)
		if !ok {
			return
		}
		serviceRequest.OfficialReleaseRevisionID = &revisionID
		serviceRequest.OfficialContext = &contextValue
	}
	creation, err := h.service.CreateInstallation(request.Context(), principal, serviceRequest)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicInstallationCreation(creation))
}

func (h *httpHandler) activateInstallation(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	installationID, ok := pathUUID(response, request, "installationID")
	if !ok {
		return
	}
	if _, ok := requireIdempotencyKey(response, request); !ok {
		return
	}
	var payload struct {
		RuntimeProfileID uuid.UUID `json:"runtime_profile_id"`
		VersionDigest    string    `json:"version_digest"`
		Timestamp        int64     `json:"timestamp"`
		DeviceProof      string    `json:"device_proof"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	digest, digestOK := decodeSHA256(payload.VersionDigest)
	proof, proofOK := decodeFixedBase64URL(payload.DeviceProof, 64)
	if !digestOK || !proofOK {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	installation, err := h.service.ActivateInstallation(request.Context(), principal, ActivateInstallationRequest{
		InstallationID: installationID, RuntimeProfileID: payload.RuntimeProfileID,
		VersionDigest: digest, Timestamp: payload.Timestamp, DeviceProof: proof, RequestID: newAgentRequestID(),
	})
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicInstallation(installation))
}

func (h *httpHandler) selectInstallationVersion(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	installationID, ok := pathUUID(response, request, "installationID")
	if !ok {
		return
	}
	if _, ok := requireIdempotencyKey(response, request); !ok {
		return
	}
	var payload struct {
		VersionID uuid.UUID `json:"version_id"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	installation, err := h.service.SelectInstallationVersion(request.Context(), principal, SelectInstallationVersionRequest{
		InstallationID: installationID, VersionID: payload.VersionID, RequestID: newAgentRequestID(),
	})
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicInstallation(installation))
}

func (h *httpHandler) archiveInstallation(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	installationID, ok := pathUUID(response, request, "installationID")
	if !ok {
		return
	}
	if _, ok := requireIdempotencyKey(response, request); !ok {
		return
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &struct{}{}) {
		return
	}
	installation, err := h.service.ArchiveInstallation(request.Context(), principal, ArchiveInstallationRequest{
		InstallationID: installationID, RequestID: newAgentRequestID(),
	})
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicInstallation(installation))
}

func (h *httpHandler) recordRuntimeBinding(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	if _, ok := requireIdempotencyKey(response, request); !ok {
		return
	}
	var payload struct {
		BindingID                 uuid.UUID `json:"binding_id"`
		AgentInstallationID       uuid.UUID `json:"agent_installation_id"`
		AgentVersionID            uuid.UUID `json:"agent_version_id"`
		RuntimeProfileID          uuid.UUID `json:"runtime_profile_id"`
		RuntimeVersion            string    `json:"runtime_version"`
		PolicySnapshotID          uuid.UUID `json:"policy_snapshot_id"`
		OfficialReleaseRevisionID *string   `json:"official_release_revision_id,omitempty"`
		ToolPermissionDigest      string    `json:"tool_permission_digest"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	digest, ok := decodeSHA256(payload.ToolPermissionDigest)
	officialReleaseRevisionID, officialOK := optionalCanonicalUUID(payload.OfficialReleaseRevisionID)
	if !ok || !officialOK {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	record, err := h.service.RecordRuntimeBinding(request.Context(), principal, RuntimeBindingRecordCommand{
		BindingID: payload.BindingID, AgentInstallationID: payload.AgentInstallationID,
		AgentVersionID: payload.AgentVersionID, RuntimeProfileID: payload.RuntimeProfileID,
		RuntimeVersion: payload.RuntimeVersion, PolicySnapshotID: payload.PolicySnapshotID,
		OfficialReleaseRevisionID: officialReleaseRevisionID,
		ToolPermissionDigest:      digest,
	}, newAgentRequestID())
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicRuntimeBinding(record))
}

func (h *httpHandler) authorize(response http.ResponseWriter, request *http.Request) (Principal, bool) {
	if h.service == nil || h.accessTokens == nil {
		writeAgentError(response, http.StatusServiceUnavailable, "service_unavailable")
		return Principal{}, false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		writeAgentError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, " \t\r\n") {
		writeAgentError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	claims, err := h.accessTokens.Authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, session.ErrInvalidAccessToken) || errors.Is(err, session.ErrSessionRevoked) {
			writeAgentError(response, http.StatusUnauthorized, "session_revoked")
		} else {
			writeAgentError(response, http.StatusServiceUnavailable, "service_unavailable")
		}
		return Principal{}, false
	}
	if claims.UserID == uuid.Nil || claims.DeviceID == uuid.Nil || claims.PersonalSpaceID == uuid.Nil {
		writeAgentError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	return Principal{UserID: claims.UserID, DeviceID: claims.DeviceID, PersonalSpaceID: claims.PersonalSpaceID}, true
}

func decodeAgentJSON(response http.ResponseWriter, request *http.Request, limit int64, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeAgentError(response, http.StatusRequestEntityTooLarge, "invalid_request")
		} else {
			writeAgentError(response, http.StatusBadRequest, "invalid_request")
		}
		return false
	}
	if rejectDuplicateJSONKeys(raw) != nil || decodeStrictJSON(raw, target) != nil {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func requireIdempotencyKey(response http.ResponseWriter, request *http.Request) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !validIdempotencyKey(values[0]) {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return "", false
	}
	return values[0], true
}

func pathUUID(response http.ResponseWriter, request *http.Request, name string) (uuid.UUID, bool) {
	raw := chi.URLParam(request, name)
	identifier, err := uuid.Parse(raw)
	if err != nil || identifier == uuid.Nil || identifier.String() != raw {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return uuid.Nil, false
	}
	return identifier, true
}

func decodeOptionalBase64URL(value string) ([]byte, bool) {
	if value == "" {
		return nil, true
	}
	decoded, ok := secure.DecodeCanonicalBase64URL(value)
	return decoded, ok
}

func decodeFixedBase64URL(value string, size int) ([]byte, bool) {
	decoded, ok := secure.DecodeCanonicalBase64URL(value)
	return decoded, ok && len(decoded) == size
}

func decodeSHA256(value string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return digest, false
	}
	copy(digest[:], decoded)
	return digest, true
}

type definitionResponse struct {
	ID              uuid.UUID  `json:"id"`
	DisplayName     string     `json:"display_name"`
	IconMediaType   string     `json:"icon_media_type,omitempty"`
	IconData        string     `json:"icon_data,omitempty"`
	Status          string     `json:"status"`
	LatestVersionID *uuid.UUID `json:"latest_version_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type versionResponse struct {
	ID                             uuid.UUID       `json:"id"`
	DefinitionID                   uuid.UUID       `json:"definition_id"`
	VersionNumber                  int64           `json:"version_number"`
	Manifest                       json.RawMessage `json:"manifest"`
	Bundle                         json.RawMessage `json:"bundle"`
	ContentDigest                  string          `json:"content_digest"`
	SigningKeyID                   string          `json:"signing_key_id"`
	Signature                      string          `json:"signature"`
	RuntimeMinimumVersion          string          `json:"runtime_minimum_version"`
	RuntimeMaximumVersionExclusive string          `json:"runtime_maximum_version_exclusive,omitempty"`
	PublishedAt                    time.Time       `json:"published_at"`
}

type policyResponse struct {
	ID             uuid.UUID       `json:"id"`
	InstallationID uuid.UUID       `json:"installation_id"`
	AgentVersionID uuid.UUID       `json:"agent_version_id"`
	PolicyVersion  int64           `json:"policy_version"`
	Document       json.RawMessage `json:"document"`
	ContentDigest  string          `json:"content_digest"`
	Issuer         string          `json:"issuer"`
	SigningKeyID   string          `json:"signing_key_id"`
	Signature      string          `json:"signature"`
	CreatedAt      time.Time       `json:"created_at"`
}

type installationResponse struct {
	ID                        uuid.UUID  `json:"id"`
	DefinitionID              uuid.UUID  `json:"definition_id"`
	SelectedVersionID         uuid.UUID  `json:"selected_version_id"`
	RuntimeProfileID          *uuid.UUID `json:"runtime_profile_id,omitempty"`
	PolicySnapshotID          *uuid.UUID `json:"policy_snapshot_id,omitempty"`
	OfficialReleaseID         *uuid.UUID `json:"official_release_id,omitempty"`
	SelectedReleaseRevisionID *uuid.UUID `json:"selected_release_revision_id,omitempty"`
	UpdatePolicy              string     `json:"update_policy"`
	Status                    string     `json:"status"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
	ActivatedAt               *time.Time `json:"activated_at,omitempty"`
	ArchivedAt                *time.Time `json:"archived_at,omitempty"`
}

type publicationResponse struct {
	Definition definitionResponse `json:"definition"`
	Version    versionResponse    `json:"version"`
	Replayed   bool               `json:"replayed"`
}

type installationCreationResponse struct {
	Installation   installationResponse `json:"installation"`
	PolicySnapshot policyResponse       `json:"policy_snapshot"`
	Replayed       bool                 `json:"replayed"`
}

type revocationResponse struct {
	ID                   uuid.UUID  `json:"id"`
	VersionID            uuid.UUID  `json:"version_id"`
	ReasonCode           string     `json:"reason_code"`
	PolicySnapshotID     uuid.UUID  `json:"policy_snapshot_id"`
	SupersedingVersionID *uuid.UUID `json:"superseding_version_id,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	Replayed             bool       `json:"replayed"`
}

type runtimeBindingResponse struct {
	ID                        uuid.UUID  `json:"id"`
	AgentInstallationID       uuid.UUID  `json:"agent_installation_id"`
	AgentVersionID            uuid.UUID  `json:"agent_version_id"`
	RuntimeProfileID          uuid.UUID  `json:"runtime_profile_id"`
	RuntimeVersion            string     `json:"runtime_version"`
	PolicySnapshotID          uuid.UUID  `json:"policy_snapshot_id"`
	OfficialReleaseRevisionID *uuid.UUID `json:"official_release_revision_id,omitempty"`
	ToolPermissionDigest      string     `json:"tool_permission_digest"`
	CreatedAt                 time.Time  `json:"created_at"`
}

func publicDefinition(value Definition) definitionResponse {
	return definitionResponse{
		ID: value.ID, DisplayName: value.DisplayName, IconMediaType: value.IconMediaType,
		IconData: base64.RawURLEncoding.EncodeToString(value.IconData), Status: value.Status,
		LatestVersionID: cloneUUIDPointer(value.LatestVersionID), CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func publicVersion(value Version) versionResponse {
	return versionResponse{
		ID: value.ID, DefinitionID: value.DefinitionID, VersionNumber: value.VersionNumber,
		Manifest: append(json.RawMessage(nil), value.CanonicalManifest...), Bundle: append(json.RawMessage(nil), value.Bundle...),
		ContentDigest: hex.EncodeToString(value.ContentDigest[:]), SigningKeyID: value.SigningKeyID,
		Signature: base64.RawURLEncoding.EncodeToString(value.Signature), RuntimeMinimumVersion: value.RuntimeMinimumVersion,
		RuntimeMaximumVersionExclusive: value.RuntimeMaximumVersionExclusive, PublishedAt: value.PublishedAt.UTC(),
	}
}

func publicPolicy(value PolicySnapshot) policyResponse {
	return policyResponse{
		ID: value.ID, InstallationID: value.InstallationID, AgentVersionID: value.AgentVersionID,
		PolicyVersion: value.PolicyVersion, Document: append(json.RawMessage(nil), value.Document...),
		ContentDigest: hex.EncodeToString(value.ContentDigest[:]), Issuer: value.Issuer,
		SigningKeyID: value.SigningKeyID, Signature: base64.RawURLEncoding.EncodeToString(value.Signature), CreatedAt: value.CreatedAt,
	}
}

func publicInstallation(value Installation) installationResponse {
	return installationResponse{
		ID: value.ID, DefinitionID: value.DefinitionID, SelectedVersionID: value.SelectedVersionID,
		RuntimeProfileID: cloneUUIDPointer(value.RuntimeProfileID), PolicySnapshotID: cloneUUIDPointer(value.PolicySnapshotID),
		OfficialReleaseID:         cloneUUIDPointer(value.OfficialReleaseID),
		SelectedReleaseRevisionID: cloneUUIDPointer(value.SelectedReleaseRevisionID),
		UpdatePolicy:              value.UpdatePolicy, Status: value.Status, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		ActivatedAt: cloneTimePointer(value.ActivatedAt), ArchivedAt: cloneTimePointer(value.ArchivedAt),
	}
}

func publicPublication(value Publication) publicationResponse {
	return publicationResponse{Definition: publicDefinition(value.Definition), Version: publicVersion(value.Version), Replayed: value.Replayed}
}

func publicInstallationCreation(value InstallationCreation) installationCreationResponse {
	return installationCreationResponse{
		Installation: publicInstallation(value.Installation), PolicySnapshot: publicPolicy(value.Policy), Replayed: value.Replayed,
	}
}

func publicRevocation(value VersionRevocation) revocationResponse {
	return revocationResponse{
		ID: value.ID, VersionID: value.VersionID, ReasonCode: value.ReasonCode,
		PolicySnapshotID: value.PolicySnapshotID, SupersedingVersionID: cloneUUIDPointer(value.SupersedingVersionID),
		CreatedAt: value.CreatedAt, Replayed: value.Replayed,
	}
}

func publicRuntimeBinding(value RuntimeBindingRecord) runtimeBindingResponse {
	return runtimeBindingResponse{
		ID: value.ID, AgentInstallationID: value.AgentInstallationID, AgentVersionID: value.AgentVersionID,
		RuntimeProfileID: value.RuntimeProfileID, RuntimeVersion: value.RuntimeVersion,
		PolicySnapshotID:          value.PolicySnapshotID,
		OfficialReleaseRevisionID: cloneUUIDPointer(value.OfficialReleaseRevisionID),
		ToolPermissionDigest:      hex.EncodeToString(value.ToolPermissionDigest[:]),
		CreatedAt:                 value.CreatedAt,
	}
}

func writeAgentServiceError(response http.ResponseWriter, err error) {
	writeAgentServiceErrorWithRequestID(response, err, newAgentRequestID())
}

func writeAgentServiceErrorWithRequestID(response http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidRepositoryCommand):
		writeAgentErrorWithRequestID(response, http.StatusBadRequest, "invalid_request", requestID)
	case errors.Is(err, ErrInvalidAgentContent):
		writeAgentErrorWithRequestID(response, http.StatusBadRequest, "invalid_agent_content", requestID)
	case errors.Is(err, ErrInvalidExperienceCandidate):
		writeAgentErrorWithRequestID(response, http.StatusBadRequest, "invalid_experience_candidate", requestID)
	case errors.Is(err, ErrRuntimeIncompatible):
		writeAgentErrorWithRequestID(response, http.StatusBadRequest, "runtime_incompatible", requestID)
	case errors.Is(err, ErrInvalidDeviceProof):
		writeAgentErrorWithRequestID(response, http.StatusBadRequest, "invalid_device_proof", requestID)
	case errors.Is(err, ErrNotFound):
		writeAgentErrorWithRequestID(response, http.StatusNotFound, "not_found", requestID)
	case errors.Is(err, ErrVersionConflict):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "version_conflict", requestID)
	case errors.Is(err, ErrIdempotencyConflict):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "idempotency_conflict", requestID)
	case errors.Is(err, ErrExperienceCandidateAlreadyReviewed):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "candidate_already_reviewed", requestID)
	case errors.Is(err, ErrDefinitionArchived):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "definition_archived", requestID)
	case errors.Is(err, ErrVersionRevoked):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "version_revoked", requestID)
	case errors.Is(err, ErrActivationConflict):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "activation_conflict", requestID)
	case errors.Is(err, ErrInstallationArchived):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "installation_archived", requestID)
	case errors.Is(err, ErrWorkspaceForbidden):
		writeAgentErrorWithRequestID(response, http.StatusForbidden, "workspace_forbidden", requestID)
	case errors.Is(err, ErrWorkspaceArchived):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "workspace_archived", requestID)
	case errors.Is(err, ErrWorkspaceOwnerUnavailable):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "workspace_owner_unavailable", requestID)
	case errors.Is(err, ErrOrganizationAgentNotFound):
		writeAgentErrorWithRequestID(response, http.StatusNotFound, "organization_agent_not_found", requestID)
	case errors.Is(err, ErrOrganizationAgentForbidden):
		writeAgentErrorWithRequestID(response, http.StatusForbidden, "organization_agent_forbidden", requestID)
	case errors.Is(err, ErrOrganizationArchived):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "organization_archived", requestID)
	case errors.Is(err, ErrOrganizationSubmissionConflict):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "organization_submission_conflict", requestID)
	case errors.Is(err, ErrOrganizationPublicationPolicyBlocked):
		writeAgentErrorWithRequestID(response, http.StatusUnprocessableEntity, "organization_publication_policy_blocked", requestID)
	case errors.Is(err, ErrOrganizationPublicationDLPBlocked):
		writeAgentErrorWithRequestID(response, http.StatusUnprocessableEntity, "organization_publication_dlp_blocked", requestID)
	case errors.Is(err, ErrOfficialAgentNotEligible):
		writeAgentErrorWithRequestID(response, http.StatusForbidden, "official_agent_not_eligible", requestID)
	case errors.Is(err, ErrOfficialReleasePaused):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "official_release_paused", requestID)
	case errors.Is(err, ErrOfficialReleaseRevisionConflict):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "official_release_revision_conflict", requestID)
	case errors.Is(err, ErrOfficialClientVersionUnsupported):
		writeAgentErrorWithRequestID(response, http.StatusUnprocessableEntity, "official_client_version_unsupported", requestID)
	case errors.Is(err, ErrOfficialInstallationPolicyBlocked):
		writeAgentErrorWithRequestID(response, http.StatusForbidden, "official_installation_policy_blocked", requestID)
	case errors.Is(err, ErrOfficialManagedUpdateConflict):
		writeAgentErrorWithRequestID(response, http.StatusConflict, "official_managed_update_conflict", requestID)
	case errors.Is(err, ErrCloudUnavailable):
		writeAgentErrorWithRequestID(response, http.StatusServiceUnavailable, "cloud_unavailable", requestID)
	default:
		writeAgentErrorWithRequestID(response, http.StatusServiceUnavailable, "service_unavailable", requestID)
	}
}

func writeAgentError(response http.ResponseWriter, status int, code string) {
	writeAgentErrorWithRequestID(response, status, code, newAgentRequestID())
}

func writeAgentErrorWithRequestID(response http.ResponseWriter, status int, code string, requestID string) {
	writeAgentJSON(response, status, struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}{Error: struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}{Code: code, Message: "localized by the client", RequestID: requestID}})
}

func newAgentRequestID() string {
	identifier, err := secure.RandomUUID()
	if err != nil {
		return "unavailable"
	}
	return identifier.String()
}

func writeAgentJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(payload)
}
