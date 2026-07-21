package agentcontrol

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type organizationSubmissionRequestEnvelope struct {
	Kind          OrganizationSubmissionKind `json:"kind"`
	DefinitionID  json.RawMessage            `json:"definition_id,omitempty"`
	BaseVersionID json.RawMessage            `json:"base_version_id,omitempty"`
	DisplayName   json.RawMessage            `json:"display_name,omitempty"`
	IconMediaType json.RawMessage            `json:"icon_media_type,omitempty"`
	IconData      json.RawMessage            `json:"icon_data,omitempty"`
	Manifest      AgentManifestV1            `json:"manifest"`
	Bundle        VersionBundleV1            `json:"bundle"`
}

type organizationAgentReviewResponse struct {
	ID                           uuid.UUID                  `json:"id"`
	ReviewerUserID               uuid.UUID                  `json:"reviewer_user_id"`
	Decision                     OrganizationReviewDecision `json:"decision"`
	ReasonCode                   *string                    `json:"reason_code"`
	SafeNote                     *string                    `json:"safe_note"`
	OrganizationPolicySnapshotID uuid.UUID                  `json:"organization_policy_snapshot_id"`
	OrganizationPolicyVersion    int64                      `json:"organization_policy_version"`
	ReviewedContentDigest        string                     `json:"reviewed_content_digest"`
	ReviewedAt                   time.Time                  `json:"reviewed_at"`
}

type organizationAgentSubmissionResponse struct {
	ID                uuid.UUID                        `json:"id"`
	OrganizationID    uuid.UUID                        `json:"organization_id"`
	Kind              OrganizationSubmissionKind       `json:"kind"`
	DefinitionID      uuid.UUID                        `json:"definition_id"`
	BaseVersionID     *uuid.UUID                       `json:"base_version_id"`
	SubmittedByUserID uuid.UUID                        `json:"submitted_by_user_id"`
	ContentDigest     string                           `json:"content_digest"`
	Status            OrganizationSubmissionStatus     `json:"status"`
	Revision          int64                            `json:"revision"`
	SubmittedAt       time.Time                        `json:"submitted_at"`
	TerminalAt        *time.Time                       `json:"terminal_at"`
	UpdatedAt         time.Time                        `json:"updated_at"`
	Review            *organizationAgentReviewResponse `json:"review"`
}

type organizationAgentSubmissionDetailResponse struct {
	organizationAgentSubmissionResponse
	DisplayName    string          `json:"display_name,omitempty"`
	IconMediaType  string          `json:"icon_media_type,omitempty"`
	IconData       string          `json:"icon_data,omitempty"`
	Manifest       AgentManifestV1 `json:"manifest"`
	Bundle         VersionBundleV1 `json:"bundle"`
	ManifestDigest string          `json:"manifest_digest"`
	BundleDigest   string          `json:"bundle_digest"`
}

func (h *httpHandler) listOrganizationDefinitions(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	organizationID, ok := pathUUID(response, request, "organizationID")
	if !ok {
		return
	}
	definitions, err := h.service.ListOrganizationDefinitions(request.Context(), principal, organizationID)
	if err != nil {
		writeOrganizationAgentServiceError(response, err, newAgentRequestID())
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

func (h *httpHandler) getOrganizationDefinition(response http.ResponseWriter, request *http.Request) {
	principal, organizationID, ok := h.authorizeOrganizationPath(response, request)
	if !ok {
		return
	}
	definitionID, ok := pathUUID(response, request, "definitionID")
	if !ok {
		return
	}
	requestID := newAgentRequestID()
	definition, err := h.service.GetOrganizationDefinition(
		request.Context(), principal, organizationID, definitionID, requestID,
	)
	if err != nil {
		writeOrganizationAgentServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicDefinition(definition))
}

func (h *httpHandler) listOrganizationVersions(response http.ResponseWriter, request *http.Request) {
	principal, organizationID, ok := h.authorizeOrganizationPath(response, request)
	if !ok {
		return
	}
	definitionID, ok := pathUUID(response, request, "definitionID")
	if !ok {
		return
	}
	requestID := newAgentRequestID()
	versions, err := h.service.ListOrganizationVersions(
		request.Context(), principal, organizationID, definitionID, requestID,
	)
	if err != nil {
		writeOrganizationAgentServiceError(response, err, requestID)
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

func (h *httpHandler) submitOrganizationAgent(response http.ResponseWriter, request *http.Request) {
	principal, organizationID, ok := h.authorizeOrganizationPath(response, request)
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	var payload organizationSubmissionRequestEnvelope
	if !decodeAgentJSON(response, request, publicationRequestBodyLimit, &payload) {
		return
	}
	packageValue, ok := decodeOrganizationSubmissionPackage(payload)
	if !ok {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	requestID := newAgentRequestID()
	value, err := h.service.SubmitOrganizationAgent(
		request.Context(), principal, organizationID, SubmitOrganizationAgentRequest{
			Package: packageValue, IdempotencyKey: idempotencyKey, RequestID: requestID,
		},
	)
	if err != nil {
		writeOrganizationAgentServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusCreated, publicOrganizationAgentSubmissionDetail(value))
}

func (h *httpHandler) listOrganizationAgentSubmissions(response http.ResponseWriter, request *http.Request) {
	principal, organizationID, ok := h.authorizeOrganizationPath(response, request)
	if !ok {
		return
	}
	values, err := h.service.ListOrganizationAgentSubmissions(request.Context(), principal, organizationID)
	if err != nil {
		writeOrganizationAgentServiceError(response, err, newAgentRequestID())
		return
	}
	items := make([]organizationAgentSubmissionResponse, len(values))
	for index, value := range values {
		items[index] = publicOrganizationAgentSubmission(value)
	}
	writeAgentJSON(response, http.StatusOK, struct {
		Submissions []organizationAgentSubmissionResponse `json:"submissions"`
	}{Submissions: items})
}

func (h *httpHandler) getOrganizationAgentSubmission(response http.ResponseWriter, request *http.Request) {
	principal, organizationID, ok := h.authorizeOrganizationPath(response, request)
	if !ok {
		return
	}
	submissionID, ok := pathUUID(response, request, "submissionID")
	if !ok {
		return
	}
	value, err := h.service.GetOrganizationAgentSubmission(
		request.Context(), principal, organizationID, submissionID,
	)
	if err != nil {
		writeOrganizationAgentServiceError(response, err, newAgentRequestID())
		return
	}
	writeAgentJSON(response, http.StatusOK, publicOrganizationAgentSubmissionDetail(value))
}

func (h *httpHandler) withdrawOrganizationAgentSubmission(response http.ResponseWriter, request *http.Request) {
	principal, organizationID, ok := h.authorizeOrganizationPath(response, request)
	if !ok {
		return
	}
	submissionID, ok := pathUUID(response, request, "submissionID")
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	var payload struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	requestID := newAgentRequestID()
	value, err := h.service.WithdrawOrganizationAgentSubmission(
		request.Context(), principal, organizationID, WithdrawOrganizationAgentRequest{
			SubmissionID: submissionID, ExpectedRevision: payload.ExpectedRevision,
			IdempotencyKey: idempotencyKey, RequestID: requestID,
		},
	)
	if err != nil {
		writeOrganizationAgentServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicOrganizationAgentSubmissionDetail(value))
}

func (h *httpHandler) reviewOrganizationAgentSubmission(response http.ResponseWriter, request *http.Request) {
	principal, organizationID, ok := h.authorizeOrganizationPath(response, request)
	if !ok {
		return
	}
	submissionID, ok := pathUUID(response, request, "submissionID")
	if !ok {
		return
	}
	idempotencyKey, ok := requireIdempotencyKey(response, request)
	if !ok {
		return
	}
	var payload struct {
		ExpectedRevision int64                      `json:"expected_revision"`
		Decision         OrganizationReviewDecision `json:"decision"`
		ReasonCode       string                     `json:"reason_code,omitempty"`
		SafeNote         string                     `json:"safe_note,omitempty"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	requestID := newAgentRequestID()
	value, err := h.service.ReviewOrganizationAgentSubmission(
		request.Context(), principal, organizationID, ReviewOrganizationAgentRequest{
			SubmissionID: submissionID, ExpectedRevision: payload.ExpectedRevision,
			Decision: payload.Decision, ReasonCode: payload.ReasonCode, SafeNote: payload.SafeNote,
			IdempotencyKey: idempotencyKey, RequestID: requestID,
		},
	)
	if err != nil {
		writeOrganizationAgentServiceError(response, err, requestID)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicOrganizationAgentSubmissionDetail(value))
}

func (h *httpHandler) authorizeOrganizationPath(
	response http.ResponseWriter,
	request *http.Request,
) (Principal, uuid.UUID, bool) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return Principal{}, uuid.Nil, false
	}
	organizationID, ok := pathUUID(response, request, "organizationID")
	if !ok {
		return Principal{}, uuid.Nil, false
	}
	return principal, organizationID, true
}

func decodeOrganizationSubmissionPackage(
	payload organizationSubmissionRequestEnvelope,
) (OrganizationSubmissionPackage, bool) {
	result := OrganizationSubmissionPackage{
		Kind: payload.Kind, Manifest: payload.Manifest, Bundle: payload.Bundle,
	}
	switch payload.Kind {
	case OrganizationSubmissionInitial:
		if len(payload.DefinitionID) != 0 || len(payload.BaseVersionID) != 0 || len(payload.DisplayName) == 0 {
			return OrganizationSubmissionPackage{}, false
		}
		displayName, ok := strictJSONString(payload.DisplayName)
		if !ok {
			return OrganizationSubmissionPackage{}, false
		}
		result.DisplayName = displayName
		if len(payload.IconMediaType) != 0 {
			iconMediaType, ok := strictJSONString(payload.IconMediaType)
			if !ok {
				return OrganizationSubmissionPackage{}, false
			}
			result.IconMediaType = iconMediaType
		}
		if len(payload.IconData) != 0 {
			iconData, ok := strictJSONString(payload.IconData)
			if !ok {
				return OrganizationSubmissionPackage{}, false
			}
			decoded, ok := decodeOptionalBase64URL(iconData)
			if !ok {
				return OrganizationSubmissionPackage{}, false
			}
			result.IconData = decoded
		}
	case OrganizationSubmissionNext:
		if len(payload.DefinitionID) == 0 || len(payload.BaseVersionID) == 0 || len(payload.DisplayName) != 0 ||
			len(payload.IconMediaType) != 0 || len(payload.IconData) != 0 {
			return OrganizationSubmissionPackage{}, false
		}
		definitionValue, ok := strictJSONString(payload.DefinitionID)
		if !ok {
			return OrganizationSubmissionPackage{}, false
		}
		baseVersionValue, ok := strictJSONString(payload.BaseVersionID)
		if !ok {
			return OrganizationSubmissionPackage{}, false
		}
		definitionID, ok := canonicalUUID(definitionValue)
		if !ok {
			return OrganizationSubmissionPackage{}, false
		}
		baseVersionID, ok := canonicalUUID(baseVersionValue)
		if !ok {
			return OrganizationSubmissionPackage{}, false
		}
		result.DefinitionID = definitionID
		result.BaseVersionID = baseVersionID
	default:
		return OrganizationSubmissionPackage{}, false
	}
	return result, true
}

func strictJSONString(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 || decodeStrictJSON(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func canonicalUUID(raw string) (uuid.UUID, bool) {
	identifier, err := uuid.Parse(raw)
	return identifier, err == nil && identifier != uuid.Nil && identifier.String() == raw
}

func optionalCanonicalUUID(raw *string) (*uuid.UUID, bool) {
	if raw == nil {
		return nil, true
	}
	identifier, ok := canonicalUUID(*raw)
	if !ok {
		return nil, false
	}
	return &identifier, true
}

func publicOrganizationAgentSubmission(
	value OrganizationAgentSubmission,
) organizationAgentSubmissionResponse {
	response := organizationAgentSubmissionResponse{
		ID: value.ID, OrganizationID: value.OrganizationID, Kind: value.Kind,
		DefinitionID: value.DefinitionID, BaseVersionID: optionalUUID(value.BaseVersionID),
		SubmittedByUserID: value.SubmittedByUserID, ContentDigest: hex.EncodeToString(value.ContentDigest[:]),
		Status: value.Status, Revision: value.Revision, SubmittedAt: value.SubmittedAt,
		TerminalAt: cloneTimePointer(value.TerminalAt), UpdatedAt: value.UpdatedAt,
	}
	if value.Review != nil {
		response.Review = &organizationAgentReviewResponse{
			ID: value.Review.ID, ReviewerUserID: value.Review.ReviewerUserID,
			Decision: value.Review.Decision, ReasonCode: optionalString(value.Review.ReasonCode),
			SafeNote:                     optionalString(value.Review.SafeNote),
			OrganizationPolicySnapshotID: value.Review.OrganizationPolicySnapshotID,
			OrganizationPolicyVersion:    value.Review.OrganizationPolicyVersion,
			ReviewedContentDigest:        hex.EncodeToString(value.Review.ReviewedContentDigest[:]),
			ReviewedAt:                   value.Review.ReviewedAt,
		}
	}
	return response
}

func publicOrganizationAgentSubmissionDetail(
	value OrganizationAgentSubmission,
) organizationAgentSubmissionDetailResponse {
	return organizationAgentSubmissionDetailResponse{
		organizationAgentSubmissionResponse: publicOrganizationAgentSubmission(value),
		DisplayName:                         value.DisplayName, IconMediaType: value.IconMediaType,
		IconData: base64.RawURLEncoding.EncodeToString(value.IconData),
		Manifest: cloneAgentManifest(value.Manifest), Bundle: cloneVersionBundle(value.Bundle),
		ManifestDigest: hex.EncodeToString(value.ManifestDigest[:]),
		BundleDigest:   hex.EncodeToString(value.BundleDigest[:]),
	}
}

func optionalUUID(value uuid.UUID) *uuid.UUID {
	if value == uuid.Nil {
		return nil
	}
	copyValue := value
	return &copyValue
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	copyValue := value
	return &copyValue
}

func writeOrganizationAgentServiceError(response http.ResponseWriter, err error, requestID string) {
	var superseded *OrganizationSubmissionSupersededError
	if errors.As(err, &superseded) {
		writeAgentJSON(response, http.StatusConflict, struct {
			Error struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
			Submission organizationAgentSubmissionResponse `json:"submission"`
		}{
			Error: struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			}{
				Code: "organization_submission_superseded", Message: "localized by the client", RequestID: requestID,
			},
			Submission: publicOrganizationAgentSubmission(superseded.Submission),
		})
		return
	}
	var dlpError *OrganizationPublicationDLPError
	if errors.As(err, &dlpError) {
		writeAgentJSON(response, http.StatusUnprocessableEntity, struct {
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
			Code: "organization_publication_dlp_blocked", Message: "localized by the client",
			RequestID: requestID, Findings: cloneExperienceCandidateFindings(dlpError.Findings),
		}})
		return
	}
	writeAgentServiceErrorWithRequestID(response, err, requestID)
}
