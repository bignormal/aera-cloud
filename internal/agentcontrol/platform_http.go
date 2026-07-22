package agentcontrol

import (
	"encoding/base64"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	officialChannelHeader       = "X-AgentEra-Official-Channel"
	desktopVersionHeader        = "X-AgentEra-Desktop-Version"
	productContextHeader        = "X-AgentEra-Product-Context"
	productContextIDHeader      = "X-AgentEra-Product-Context-ID"
	maximumDesktopVersionLength = 128
)

type officialAgentSummaryResponse struct {
	DefinitionID                   string `json:"definition_id"`
	DisplayName                    string `json:"display_name"`
	IconMediaType                  string `json:"icon_media_type,omitempty"`
	IconData                       string `json:"icon_data,omitempty"`
	Official                       bool   `json:"official"`
	VersionID                      string `json:"version_id"`
	VersionNumber                  int64  `json:"version_number"`
	ReleaseID                      string `json:"release_id"`
	ReleaseRevisionID              string `json:"release_revision_id"`
	Channel                        string `json:"channel"`
	RuntimeMinimumVersion          string `json:"runtime_minimum_version"`
	RuntimeMaximumVersionExclusive string `json:"runtime_maximum_version_exclusive,omitempty"`
	InstallationState              string `json:"installation_state"`
	UpdateState                    string `json:"update_state"`
}

type officialAgentDetailResponse struct {
	Agent   officialAgentSummaryResponse `json:"agent"`
	Version versionResponse              `json:"version"`
}

type officialManagedUpdateResponse struct {
	UpdateAvailable                   bool   `json:"update_available"`
	InstallationID                    string `json:"installation_id"`
	ExpectedSelectedReleaseRevisionID string `json:"expected_selected_release_revision_id"`
	TargetReleaseRevisionID           string `json:"target_release_revision_id"`
	TargetVersionID                   string `json:"target_version_id"`
	RuntimeMinimumVersion             string `json:"runtime_minimum_version"`
	RuntimeMaximumVersionExclusive    string `json:"runtime_maximum_version_exclusive,omitempty"`
}

func (h *httpHandler) listOfficialAgents(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorizeOfficial(response, request)
	if !ok {
		return
	}
	contextValue, ok := h.requireOfficialContext(response, request, principal)
	if !ok {
		return
	}
	values, err := h.official.ListOfficialAgents(request.Context(), principal, contextValue)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	items := make([]officialAgentSummaryResponse, len(values))
	for index, value := range values {
		item, valid := publicOfficialAgent(value)
		if !valid {
			writeAgentServiceError(response, ErrCloudUnavailable)
			return
		}
		items[index] = item
	}
	writeAgentJSON(response, http.StatusOK, struct {
		OfficialAgents []officialAgentSummaryResponse `json:"official_agents"`
	}{OfficialAgents: items})
}

func (h *httpHandler) getOfficialAgent(response http.ResponseWriter, request *http.Request) {
	principal, definitionID, contextValue, ok := h.officialAgentRequest(response, request)
	if !ok {
		return
	}
	value, err := h.official.GetOfficialAgent(request.Context(), principal, definitionID, contextValue)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	item, valid := publicOfficialAgent(value)
	if !valid {
		writeAgentServiceError(response, ErrCloudUnavailable)
		return
	}
	writeAgentJSON(response, http.StatusOK, officialAgentDetailResponse{Agent: item, Version: publicVersion(value.Version)})
}

func (h *httpHandler) getOfficialRelease(response http.ResponseWriter, request *http.Request) {
	principal, definitionID, contextValue, ok := h.officialAgentRequest(response, request)
	if !ok {
		return
	}
	value, err := h.official.GetOfficialAgent(request.Context(), principal, definitionID, contextValue)
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	item, valid := publicOfficialAgent(value)
	if !valid {
		writeAgentServiceError(response, ErrCloudUnavailable)
		return
	}
	writeAgentJSON(response, http.StatusOK, item)
}

func (h *httpHandler) getManagedOfficialUpdate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	installationID, ok := pathUUID(response, request, "installationID")
	if !ok {
		return
	}
	contextValue, ok := h.requireOfficialContext(response, request, principal)
	if !ok {
		return
	}
	value, err := h.service.GetManagedOfficialUpdate(request.Context(), principal, GetManagedOfficialUpdateRequest{
		InstallationID: installationID, OfficialContext: contextValue, RequestID: newAgentRequestID(),
	})
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	if !value.UpdateAvailable {
		writeAgentJSON(response, http.StatusOK, struct {
			UpdateAvailable bool `json:"update_available"`
		}{UpdateAvailable: false})
		return
	}
	if !validOfficialManagedUpdate(value, installationID) {
		writeAgentServiceError(response, ErrCloudUnavailable)
		return
	}
	writeAgentJSON(response, http.StatusOK, officialManagedUpdateResponse{
		UpdateAvailable: true, InstallationID: value.InstallationID.String(),
		ExpectedSelectedReleaseRevisionID: value.ExpectedSelectedReleaseRevisionID.String(),
		TargetReleaseRevisionID:           value.Target.ReleaseRevisionID.String(), TargetVersionID: value.Target.VersionID.String(),
		RuntimeMinimumVersion:          value.Version.RuntimeMinimumVersion,
		RuntimeMaximumVersionExclusive: value.Version.RuntimeMaximumVersionExclusive,
	})
}

func (h *httpHandler) applyManagedOfficialUpdate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	installationID, ok := pathUUID(response, request, "installationID")
	if !ok {
		return
	}
	if _, ok := requireIdempotencyKey(response, request); !ok {
		return
	}
	contextValue, ok := h.requireOfficialContext(response, request, principal)
	if !ok {
		return
	}
	var payload struct {
		ExpectedSelectedReleaseRevisionID string `json:"expected_selected_release_revision_id"`
		TargetReleaseRevisionID           string `json:"target_release_revision_id"`
	}
	if !decodeAgentJSON(response, request, metadataRequestBodyLimit, &payload) {
		return
	}
	expectedRevisionID, expectedOK := canonicalUUID(payload.ExpectedSelectedReleaseRevisionID)
	targetRevisionID, targetOK := canonicalUUID(payload.TargetReleaseRevisionID)
	if !expectedOK || !targetOK {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	installation, err := h.service.ApplyManagedOfficialUpdate(request.Context(), principal, ManagedUpdateRequest{
		InstallationID: installationID, ExpectedSelectedRevisionID: expectedRevisionID,
		TargetReleaseRevisionID: targetRevisionID, OfficialContext: contextValue, RequestID: newAgentRequestID(),
	})
	if err != nil {
		writeAgentServiceError(response, err)
		return
	}
	writeAgentJSON(response, http.StatusOK, publicInstallation(installation))
}

func (h *httpHandler) officialAgentRequest(
	response http.ResponseWriter,
	request *http.Request,
) (Principal, uuid.UUID, OfficialEligibilityContext, bool) {
	principal, ok := h.authorizeOfficial(response, request)
	if !ok {
		return Principal{}, uuid.Nil, OfficialEligibilityContext{}, false
	}
	definitionID, ok := pathUUID(response, request, "definitionID")
	if !ok {
		return Principal{}, uuid.Nil, OfficialEligibilityContext{}, false
	}
	contextValue, ok := h.requireOfficialContext(response, request, principal)
	return principal, definitionID, contextValue, ok
}

func (h *httpHandler) authorizeOfficial(response http.ResponseWriter, request *http.Request) (Principal, bool) {
	principal, ok := h.authorize(response, request)
	if !ok {
		return Principal{}, false
	}
	if h.official == nil {
		writeAgentError(response, http.StatusServiceUnavailable, "service_unavailable")
		return Principal{}, false
	}
	if request.URL.RawQuery != "" {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return Principal{}, false
	}
	return principal, true
}

func (h *httpHandler) requireOfficialContext(
	response http.ResponseWriter,
	request *http.Request,
	principal Principal,
) (OfficialEligibilityContext, bool) {
	channel, channelOK := singleOfficialHeader(request, officialChannelHeader)
	desktopVersion, versionOK := singleOfficialHeader(request, desktopVersionHeader)
	productContext, contextOK := singleOfficialHeader(request, productContextHeader)
	contextIDs := request.Header.Values(productContextIDHeader)
	if !channelOK || !versionOK || !contextOK || len(desktopVersion) > maximumDesktopVersionLength || !utf8.ValidString(desktopVersion) {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return OfficialEligibilityContext{}, false
	}
	value := OfficialEligibilityContext{Channel: OfficialChannel(channel), DesktopVersion: desktopVersion}
	switch OwnerScope(productContext) {
	case OwnerScopeUser:
		if len(contextIDs) != 0 {
			writeAgentError(response, http.StatusBadRequest, "invalid_request")
			return OfficialEligibilityContext{}, false
		}
		value.Selector = OfficialProductSelector{Scope: OwnerScopeUser, PersonalSpaceID: principal.PersonalSpaceID}
	case OwnerScopeWorkspace:
		identifier, ok := singleCanonicalHeaderUUID(contextIDs)
		if !ok {
			writeAgentError(response, http.StatusBadRequest, "invalid_request")
			return OfficialEligibilityContext{}, false
		}
		value.Selector = OfficialProductSelector{Scope: OwnerScopeWorkspace, WorkspaceID: identifier}
	case OwnerScopeOrganization:
		identifier, ok := singleCanonicalHeaderUUID(contextIDs)
		if !ok {
			writeAgentError(response, http.StatusBadRequest, "invalid_request")
			return OfficialEligibilityContext{}, false
		}
		value.Selector = OfficialProductSelector{Scope: OwnerScopeOrganization, OrganizationID: identifier}
	default:
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return OfficialEligibilityContext{}, false
	}
	if !validOfficialEligibilityContext(principal, value) {
		writeAgentError(response, http.StatusBadRequest, "invalid_request")
		return OfficialEligibilityContext{}, false
	}
	return value, true
}

func singleOfficialHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	if len(values) != 1 || values[0] == "" || values[0] != strings.TrimSpace(values[0]) || strings.ContainsAny(values[0], "\r\n") {
		return "", false
	}
	return values[0], true
}

func singleCanonicalHeaderUUID(values []string) (uuid.UUID, bool) {
	if len(values) != 1 {
		return uuid.Nil, false
	}
	return canonicalUUID(values[0])
}

func publicOfficialAgent(value OfficialAgentCatalogEntry) (officialAgentSummaryResponse, bool) {
	if value.DefinitionID == uuid.Nil || value.Target.PlatformID == uuid.Nil || value.Target.ReleaseID == uuid.Nil ||
		value.Target.ReleaseRevisionID == uuid.Nil || value.Target.DefinitionID != value.DefinitionID ||
		value.Target.VersionID == uuid.Nil || value.Version.ID != value.Target.VersionID ||
		value.Version.DefinitionID != value.DefinitionID || value.Version.VersionNumber <= 0 ||
		(value.Target.Channel != OfficialChannelInternal && value.Target.Channel != OfficialChannelStable) ||
		(value.InstallationState != OfficialInstallationNotInstalled && value.InstallationState != OfficialInstallationInstalled) ||
		(value.UpdateState != OfficialUpdateCurrent && value.UpdateState != OfficialUpdateAvailable) {
		return officialAgentSummaryResponse{}, false
	}
	return officialAgentSummaryResponse{
		DefinitionID: value.DefinitionID.String(), DisplayName: value.DisplayName,
		IconMediaType: value.IconMediaType, IconData: base64.RawURLEncoding.EncodeToString(value.IconData), Official: true,
		VersionID: value.Version.ID.String(), VersionNumber: value.Version.VersionNumber,
		ReleaseID: value.Target.ReleaseID.String(), ReleaseRevisionID: value.Target.ReleaseRevisionID.String(),
		Channel: string(value.Target.Channel), RuntimeMinimumVersion: value.Version.RuntimeMinimumVersion,
		RuntimeMaximumVersionExclusive: value.Version.RuntimeMaximumVersionExclusive,
		InstallationState:              string(value.InstallationState), UpdateState: string(value.UpdateState),
	}, true
}

func validOfficialManagedUpdate(value OfficialManagedUpdate, installationID uuid.UUID) bool {
	return value.UpdateAvailable && value.InstallationID == installationID &&
		value.ExpectedSelectedReleaseRevisionID != uuid.Nil && value.Target.PlatformID != uuid.Nil &&
		value.Target.ReleaseID != uuid.Nil && value.Target.ReleaseRevisionID != uuid.Nil &&
		value.Target.DefinitionID != uuid.Nil && value.Target.VersionID != uuid.Nil &&
		value.Version.ID == value.Target.VersionID && value.Version.DefinitionID == value.Target.DefinitionID
}
