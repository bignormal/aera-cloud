package organization

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	maxOrganizationBodyBytes = 80 * 1024
	defaultOrganizationPage  = 50
)

type HTTPService interface {
	Create(context.Context, Actor, CreateOrganizationCommand) (OrganizationCreationResult, error)
	List(context.Context, Actor, Page) (OrganizationPage, error)
	Get(context.Context, Actor, uuid.UUID) (OrganizationSummary, error)
	Rename(context.Context, Actor, RenameCommand) (OrganizationSummary, error)
	Archive(context.Context, Actor, ArchiveCommand) (OrganizationSummary, error)
	Restore(context.Context, Actor, RestoreCommand) (OrganizationSummary, error)
	TransferOwner(context.Context, Actor, OwnerTransferCommand) (OrganizationSummary, error)
	Dissolve(context.Context, Actor, DissolveCommand) (OrganizationSummary, error)
	ListMembers(context.Context, Actor, uuid.UUID, Page) (MemberPage, error)
	PatchMember(context.Context, Actor, PatchMemberCommand) (MemberSummary, error)
	RemoveMember(context.Context, Actor, RemoveMemberCommand) error
	Leave(context.Context, Actor, LeaveCommand) error
	ListDepartments(context.Context, Actor, uuid.UUID, Page) (DepartmentPage, error)
	CreateDepartment(context.Context, Actor, CreateDepartmentCommand) (DepartmentSummary, error)
	RenameDepartment(context.Context, Actor, RenameDepartmentCommand) (DepartmentSummary, error)
	ArchiveDepartment(context.Context, Actor, DepartmentLifecycleCommand) (DepartmentSummary, error)
	RestoreDepartment(context.Context, Actor, DepartmentLifecycleCommand) (DepartmentSummary, error)
	ListInvitations(context.Context, Actor, uuid.UUID, Page) (InvitationPage, error)
	CreateInvitation(context.Context, Actor, CreateInvitationCommand) (InvitationCreationResult, error)
	RevokeInvitation(context.Context, Actor, RevokeInvitationCommand) error
	AcceptInvitation(context.Context, Actor, AcceptInvitationCommand) (InvitationAcceptance, error)
	GetCurrentPolicy(context.Context, Actor, uuid.UUID) (PolicySnapshot, error)
	ListPolicySnapshots(context.Context, Actor, uuid.UUID, Page) (PolicyPage, error)
	PublishPolicy(context.Context, Actor, PublishPolicyCommand) (PolicySnapshot, error)
	GetPolicySnapshot(context.Context, Actor, uuid.UUID) (PolicySnapshot, error)
	ListAudit(context.Context, Actor, uuid.UUID, Page) (AuditPage, error)
}

type AccessAuthenticator interface {
	Authenticate(context.Context, string) (session.AccessClaims, error)
}

type HTTPConfig struct {
	Service      HTTPService
	AccessTokens AccessAuthenticator
}

type httpHandler struct {
	service      HTTPService
	accessTokens AccessAuthenticator
}

func NewHandler(config HTTPConfig) http.Handler {
	handler := &httpHandler{service: config.Service, accessTokens: config.AccessTokens}
	router := chi.NewRouter()
	router.Get("/api/v1/organizations", handler.listOrganizations)
	router.Post("/api/v1/organizations", handler.createOrganization)
	router.Get("/api/v1/organizations/{organizationID}", handler.getOrganization)
	router.Patch("/api/v1/organizations/{organizationID}", handler.renameOrganization)
	router.Post("/api/v1/organizations/{organizationID}/archive", handler.archiveOrganization)
	router.Post("/api/v1/organizations/{organizationID}/restore", handler.restoreOrganization)
	router.Post("/api/v1/organizations/{organizationID}/owner-transfer", handler.transferOwner)
	router.Post("/api/v1/organizations/{organizationID}/dissolve", handler.dissolveOrganization)
	router.Get("/api/v1/organizations/{organizationID}/members", handler.listMembers)
	router.Patch("/api/v1/organizations/{organizationID}/members/{userID}", handler.patchMember)
	router.Delete("/api/v1/organizations/{organizationID}/members/{userID}", handler.removeMember)
	router.Post("/api/v1/organizations/{organizationID}/leave", handler.leaveOrganization)
	router.Get("/api/v1/organizations/{organizationID}/departments", handler.listDepartments)
	router.Post("/api/v1/organizations/{organizationID}/departments", handler.createDepartment)
	router.Patch("/api/v1/organizations/{organizationID}/departments/{departmentID}", handler.renameDepartment)
	router.Post("/api/v1/organizations/{organizationID}/departments/{departmentID}/archive", handler.archiveDepartment)
	router.Post("/api/v1/organizations/{organizationID}/departments/{departmentID}/restore", handler.restoreDepartment)
	router.Get("/api/v1/organizations/{organizationID}/invitations", handler.listInvitations)
	router.Post("/api/v1/organizations/{organizationID}/invitations", handler.createInvitation)
	router.Delete("/api/v1/organizations/{organizationID}/invitations/{invitationID}", handler.revokeInvitation)
	router.Post("/api/v1/organization-invitations/accept", handler.acceptInvitation)
	router.Get("/api/v1/organizations/{organizationID}/policy", handler.getCurrentPolicy)
	router.Get("/api/v1/organizations/{organizationID}/policy-snapshots", handler.listPolicySnapshots)
	router.Post("/api/v1/organizations/{organizationID}/policy-snapshots", handler.publishPolicy)
	router.Get("/api/v1/organization-policy-snapshots/{snapshotID}", handler.getPolicySnapshot)
	router.Get("/api/v1/organizations/{organizationID}/audit-events", handler.listAudit)
	return router
}

func (h *httpHandler) listOrganizations(response http.ResponseWriter, request *http.Request) {
	requestID, actor, ok := h.authorize(response, request)
	if !ok {
		return
	}
	page, ok := organizationHTTPPage(response, request, requestID, "organizations")
	if !ok {
		return
	}
	result, err := h.service.List(request.Context(), actor, page)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	items := make([]organizationResponse, len(result.Items))
	for index, item := range result.Items {
		items[index] = publicOrganization(item)
	}
	writeOrganizationJSON(response, 200, collectionResponse[organizationResponse]{Items: items, NextCursor: encodeOrganizationCursor("organizations", result.Next)})
}

func (h *httpHandler) createOrganization(response http.ResponseWriter, request *http.Request) {
	requestID, actor, ok := h.authorize(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	key, ok := requireOrganizationIdempotency(response, request, requestID)
	if !ok {
		return
	}
	var payload struct {
		DisplayName string `json:"display_name"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	displayName, err := NormalizeOrganizationName(payload.DisplayName)
	if err != nil {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.Create(request.Context(), actor, CreateOrganizationCommand{DisplayName: displayName, IdempotencyKey: key, RequestID: requestID})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	writeOrganizationJSON(response, status, publicOrganization(result.Organization))
}

func (h *httpHandler) getOrganization(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	result, err := h.service.Get(request.Context(), actor, organizationID)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicOrganization(result))
}

func (h *httpHandler) renameOrganization(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	var payload struct {
		DisplayName      string `json:"display_name"`
		ExpectedRevision int64  `json:"expected_revision"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	displayName, err := NormalizeOrganizationName(payload.DisplayName)
	if err != nil || payload.ExpectedRevision <= 0 {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.Rename(request.Context(), actor, RenameCommand{OrganizationID: organizationID, DisplayName: displayName, ExpectedRevision: payload.ExpectedRevision, RequestID: requestID})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicOrganization(result))
}

func (h *httpHandler) archiveOrganization(response http.ResponseWriter, request *http.Request) {
	h.reviseOrganization(response, request, false)
}
func (h *httpHandler) restoreOrganization(response http.ResponseWriter, request *http.Request) {
	h.reviseOrganization(response, request, true)
}

func (h *httpHandler) reviseOrganization(response http.ResponseWriter, request *http.Request, restore bool) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	key, ok := requireOrganizationIdempotency(response, request, requestID)
	if !ok {
		return
	}
	var payload struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	if payload.ExpectedRevision <= 0 {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	var result OrganizationSummary
	var err error
	if restore {
		result, err = h.service.Restore(request.Context(), actor, RestoreCommand{OrganizationID: organizationID, ExpectedRevision: payload.ExpectedRevision, IdempotencyKey: key, RequestID: requestID})
	} else {
		result, err = h.service.Archive(request.Context(), actor, ArchiveCommand{OrganizationID: organizationID, ExpectedRevision: payload.ExpectedRevision, IdempotencyKey: key, RequestID: requestID})
	}
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicOrganization(result))
}

func (h *httpHandler) transferOwner(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	key, ok := requireOrganizationIdempotency(response, request, requestID)
	if !ok {
		return
	}
	var payload struct {
		TargetUserID                 string `json:"target_user_id"`
		ExpectedOrganizationRevision int64  `json:"expected_organization_revision"`
		ExpectedOwnerRevision        int64  `json:"expected_owner_revision"`
		ExpectedTargetRevision       int64  `json:"expected_target_revision"`
		Confirmation                 string `json:"confirmation"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	targetID, valid := canonicalOrganizationUUID(payload.TargetUserID)
	if !valid || payload.ExpectedOrganizationRevision <= 0 || payload.ExpectedOwnerRevision <= 0 || payload.ExpectedTargetRevision <= 0 || payload.Confirmation != TransferOrganizationOwnerConfirmation {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.TransferOwner(request.Context(), actor, OwnerTransferCommand{
		OrganizationID: organizationID, TargetUserID: targetID, ExpectedOrganizationRevision: payload.ExpectedOrganizationRevision,
		ExpectedOwnerRevision: payload.ExpectedOwnerRevision, ExpectedTargetRevision: payload.ExpectedTargetRevision,
		Confirmation: payload.Confirmation, IdempotencyKey: key, RequestID: requestID,
	})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicOrganization(result))
}

func (h *httpHandler) dissolveOrganization(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	key, ok := requireOrganizationIdempotency(response, request, requestID)
	if !ok {
		return
	}
	var payload struct {
		DisplayName      string `json:"display_name"`
		ExpectedRevision int64  `json:"expected_revision"`
		Confirmation     string `json:"confirmation"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	displayName, nameErr := NormalizeOrganizationName(payload.DisplayName)
	if nameErr != nil || displayName != payload.DisplayName || payload.ExpectedRevision <= 0 || payload.Confirmation != DissolveOrganizationConfirmation {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.Dissolve(request.Context(), actor, DissolveCommand{OrganizationID: organizationID, DisplayName: displayName, ExpectedRevision: payload.ExpectedRevision, Confirmation: payload.Confirmation, IdempotencyKey: key, RequestID: requestID})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicOrganization(result))
}

func (h *httpHandler) listMembers(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok {
		return
	}
	page, ok := organizationHTTPPage(response, request, requestID, "members")
	if !ok {
		return
	}
	result, err := h.service.ListMembers(request.Context(), actor, organizationID, page)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	items := make([]memberResponse, len(result.Items))
	for index, item := range result.Items {
		items[index] = publicMember(item)
	}
	writeOrganizationJSON(response, 200, collectionResponse[memberResponse]{Items: items, NextCursor: encodeOrganizationCursor("members", result.Next)})
}

func (h *httpHandler) patchMember(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	userID, ok := organizationPathUUID(response, request, "userID", requestID)
	if !ok {
		return
	}
	var payload struct {
		Role             *Role           `json:"role"`
		DepartmentID     json.RawMessage `json:"department_id"`
		ExpectedRevision int64           `json:"expected_revision"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	command := PatchMemberCommand{OrganizationID: organizationID, UserID: userID, Role: payload.Role, ExpectedRevision: payload.ExpectedRevision, RequestID: requestID}
	if payload.Role != nil && *payload.Role != RoleAdmin && *payload.Role != RoleAuditor && *payload.Role != RoleMember {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	if payload.DepartmentID != nil {
		command.ChangeDepartment = true
		if bytes.Equal(bytes.TrimSpace(payload.DepartmentID), []byte("null")) {
			command.ClearDepartment = true
		} else {
			var raw string
			if json.Unmarshal(payload.DepartmentID, &raw) != nil {
				writeOrganizationError(response, 400, "invalid_request", requestID)
				return
			}
			departmentID, valid := canonicalOrganizationUUID(raw)
			if !valid {
				writeOrganizationError(response, 400, "invalid_request", requestID)
				return
			}
			command.DepartmentID = &departmentID
		}
	}
	if payload.ExpectedRevision <= 0 || (payload.Role == nil && !command.ChangeDepartment) {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.PatchMember(request.Context(), actor, command)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicMember(result))
}

func (h *httpHandler) removeMember(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok {
		return
	}
	userID, ok := organizationPathUUID(response, request, "userID", requestID)
	if !ok {
		return
	}
	revision, ok := organizationExpectedRevision(response, request, requestID)
	if !ok {
		return
	}
	if err := h.service.RemoveMember(request.Context(), actor, RemoveMemberCommand{OrganizationID: organizationID, UserID: userID, ExpectedRevision: revision, RequestID: requestID}); err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationNoContent(response)
}

func (h *httpHandler) leaveOrganization(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	if !decodeOrganizationJSON(response, request, requestID, &struct{}{}) {
		return
	}
	if err := h.service.Leave(request.Context(), actor, LeaveCommand{OrganizationID: organizationID, RequestID: requestID}); err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationNoContent(response)
}

func (h *httpHandler) listDepartments(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok {
		return
	}
	page, ok := organizationHTTPPage(response, request, requestID, "departments")
	if !ok {
		return
	}
	result, err := h.service.ListDepartments(request.Context(), actor, organizationID, page)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	items := make([]departmentResponse, len(result.Items))
	for index, item := range result.Items {
		items[index] = publicDepartment(item)
	}
	writeOrganizationJSON(response, 200, collectionResponse[departmentResponse]{Items: items, NextCursor: encodeOrganizationCursor("departments", result.Next)})
}

func (h *httpHandler) createDepartment(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	var payload struct {
		DisplayName string `json:"display_name"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	displayName, _, err := NormalizeDepartmentName(payload.DisplayName)
	if err != nil {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.CreateDepartment(request.Context(), actor, CreateDepartmentCommand{OrganizationID: organizationID, DisplayName: displayName, RequestID: requestID})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 201, publicDepartment(result))
}

func (h *httpHandler) renameDepartment(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	departmentID, ok := organizationPathUUID(response, request, "departmentID", requestID)
	if !ok {
		return
	}
	var payload struct {
		DisplayName      string `json:"display_name"`
		ExpectedRevision int64  `json:"expected_revision"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	displayName, _, err := NormalizeDepartmentName(payload.DisplayName)
	if err != nil || payload.ExpectedRevision <= 0 {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.RenameDepartment(request.Context(), actor, RenameDepartmentCommand{OrganizationID: organizationID, DepartmentID: departmentID, DisplayName: displayName, ExpectedRevision: payload.ExpectedRevision, RequestID: requestID})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicDepartment(result))
}

func (h *httpHandler) archiveDepartment(response http.ResponseWriter, request *http.Request) {
	h.reviseDepartment(response, request, false)
}
func (h *httpHandler) restoreDepartment(response http.ResponseWriter, request *http.Request) {
	h.reviseDepartment(response, request, true)
}

func (h *httpHandler) reviseDepartment(response http.ResponseWriter, request *http.Request, restore bool) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	departmentID, ok := organizationPathUUID(response, request, "departmentID", requestID)
	if !ok {
		return
	}
	var payload struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	if payload.ExpectedRevision <= 0 {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	command := DepartmentLifecycleCommand{OrganizationID: organizationID, DepartmentID: departmentID, ExpectedRevision: payload.ExpectedRevision, RequestID: requestID}
	var result DepartmentSummary
	var err error
	if restore {
		result, err = h.service.RestoreDepartment(request.Context(), actor, command)
	} else {
		result, err = h.service.ArchiveDepartment(request.Context(), actor, command)
	}
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicDepartment(result))
}

func (h *httpHandler) listInvitations(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok {
		return
	}
	page, ok := organizationHTTPPage(response, request, requestID, "invitations")
	if !ok {
		return
	}
	result, err := h.service.ListInvitations(request.Context(), actor, organizationID, page)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	items := make([]invitationResponse, len(result.Items))
	for index, item := range result.Items {
		items[index] = publicInvitation(item)
	}
	writeOrganizationJSON(response, 200, collectionResponse[invitationResponse]{Items: items, NextCursor: encodeOrganizationCursor("invitations", result.Next)})
}

func (h *httpHandler) createInvitation(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	key, ok := requireOrganizationIdempotency(response, request, requestID)
	if !ok {
		return
	}
	if !decodeOrganizationJSON(response, request, requestID, &struct{}{}) {
		return
	}
	result, err := h.service.CreateInvitation(request.Context(), actor, CreateInvitationCommand{OrganizationID: organizationID, IdempotencyKey: key, RequestID: requestID})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	public, fresh, valid := publicInvitationCreation(result)
	if !valid {
		writeOrganizationError(response, 503, "service_unavailable", requestID)
		return
	}
	status := http.StatusOK
	if fresh {
		status = http.StatusCreated
	}
	writeOrganizationJSON(response, status, public)
}

func (h *httpHandler) revokeInvitation(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok {
		return
	}
	if !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	invitationID, ok := organizationPathUUID(response, request, "invitationID", requestID)
	if !ok {
		return
	}
	if err := h.service.RevokeInvitation(request.Context(), actor, RevokeInvitationCommand{OrganizationID: organizationID, InvitationID: invitationID, RequestID: requestID}); err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationNoContent(response)
}

func (h *httpHandler) acceptInvitation(response http.ResponseWriter, request *http.Request) {
	requestID, actor, ok := h.authorize(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	key, ok := requireOrganizationIdempotency(response, request, requestID)
	if !ok {
		return
	}
	var payload struct {
		Token string `json:"token"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	if _, err := InvitationDigest(payload.Token); err != nil {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.AcceptInvitation(request.Context(), actor, AcceptInvitationCommand{Token: payload.Token, IdempotencyKey: key, RequestID: requestID})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, invitationAcceptanceResponse{Organization: publicOrganization(result.Organization), Member: publicMember(result.Member)})
}

func (h *httpHandler) getCurrentPolicy(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	result, err := h.service.GetCurrentPolicy(request.Context(), actor, organizationID)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicPolicySnapshot(result))
}

func (h *httpHandler) listPolicySnapshots(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok {
		return
	}
	page, ok := organizationHTTPPage(response, request, requestID, "policy_snapshots")
	if !ok {
		return
	}
	result, err := h.service.ListPolicySnapshots(request.Context(), actor, organizationID, page)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	items := make([]policySummaryResponse, len(result.Items))
	for index, item := range result.Items {
		items[index] = publicPolicySummary(item)
	}
	writeOrganizationJSON(response, 200, collectionResponse[policySummaryResponse]{Items: items, NextCursor: encodeOrganizationCursor("policy_snapshots", result.Next)})
}

func (h *httpHandler) publishPolicy(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	key, ok := requireOrganizationIdempotency(response, request, requestID)
	if !ok {
		return
	}
	var payload struct {
		PolicyDocument               PolicyDocument `json:"policy_document"`
		ExpectedOrganizationRevision int64          `json:"expected_organization_revision"`
		ExpectedPolicyVersion        int64          `json:"expected_policy_version"`
	}
	if !decodeOrganizationJSON(response, request, requestID, &payload) {
		return
	}
	canonical, err := CanonicalizePolicy(payload.PolicyDocument)
	if err != nil || payload.ExpectedOrganizationRevision <= 0 || payload.ExpectedPolicyVersion <= 1 {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return
	}
	result, err := h.service.PublishPolicy(request.Context(), actor, PublishPolicyCommand{OrganizationID: organizationID, Document: canonical.Document, ExpectedOrganizationRevision: payload.ExpectedOrganizationRevision, ExpectedPolicyVersion: payload.ExpectedPolicyVersion, IdempotencyKey: key, RequestID: requestID})
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, http.StatusCreated, publicPolicySnapshot(result))
}

func (h *httpHandler) getPolicySnapshot(response http.ResponseWriter, request *http.Request) {
	requestID, actor, ok := h.authorize(response, request)
	if !ok || !requireNoOrganizationQuery(response, request, requestID) {
		return
	}
	snapshotID, ok := organizationPathUUID(response, request, "snapshotID", requestID)
	if !ok {
		return
	}
	result, err := h.service.GetPolicySnapshot(request.Context(), actor, snapshotID)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	writeOrganizationJSON(response, 200, publicPolicySnapshot(result))
}

func (h *httpHandler) listAudit(response http.ResponseWriter, request *http.Request) {
	requestID, actor, organizationID, ok := h.authorizeOrganization(response, request)
	if !ok {
		return
	}
	page, ok := organizationHTTPPage(response, request, requestID, "audit_events")
	if !ok {
		return
	}
	result, err := h.service.ListAudit(request.Context(), actor, organizationID, page)
	if err != nil {
		writeOrganizationServiceError(response, err, requestID)
		return
	}
	items := make([]auditResponse, len(result.Items))
	for index, item := range result.Items {
		items[index] = publicAudit(item)
	}
	writeOrganizationJSON(response, 200, collectionResponse[auditResponse]{Items: items, NextCursor: encodeOrganizationCursor("audit_events", result.Next)})
}

func (h *httpHandler) authorize(response http.ResponseWriter, request *http.Request) (string, Actor, bool) {
	requestID := newOrganizationRequestID()
	if h.service == nil || h.accessTokens == nil {
		writeOrganizationError(response, 503, "service_unavailable", requestID)
		return requestID, Actor{}, false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		writeOrganizationError(response, 401, "authentication_required", requestID)
		return requestID, Actor{}, false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, " \t\r\n") {
		writeOrganizationError(response, 401, "authentication_required", requestID)
		return requestID, Actor{}, false
	}
	claims, err := h.accessTokens.Authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, session.ErrInvalidAccessToken) || errors.Is(err, session.ErrSessionRevoked) {
			writeOrganizationError(response, 401, "authentication_required", requestID)
		} else {
			writeOrganizationError(response, 503, "service_unavailable", requestID)
		}
		return requestID, Actor{}, false
	}
	if claims.UserID == uuid.Nil || claims.DeviceID == uuid.Nil || claims.PersonalSpaceID == uuid.Nil {
		writeOrganizationError(response, 401, "authentication_required", requestID)
		return requestID, Actor{}, false
	}
	return requestID, Actor{UserID: claims.UserID, DeviceID: claims.DeviceID}, true
}

func (h *httpHandler) authorizeOrganization(
	response http.ResponseWriter,
	request *http.Request,
) (string, Actor, uuid.UUID, bool) {
	requestID, actor, ok := h.authorize(response, request)
	if !ok {
		return requestID, Actor{}, uuid.Nil, false
	}
	organizationID, ok := organizationPathUUID(response, request, "organizationID", requestID)
	return requestID, actor, organizationID, ok
}

func decodeOrganizationJSON(response http.ResponseWriter, request *http.Request, requestID string, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxOrganizationBodyBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeOrganizationError(response, 413, "invalid_request", requestID)
		} else {
			writeOrganizationError(response, 400, "invalid_request", requestID)
		}
		return false
	}
	if rejectPolicyDuplicateJSONKeys(raw) != nil || decodeStrictOrganizationJSON(raw, target) != nil {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return false
	}
	return true
}

func decodeStrictOrganizationJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func requireOrganizationIdempotency(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !validOrganizationIdempotencyKey(values[0]) || strings.ContainsAny(values[0], "\r\n\x00") {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return "", false
	}
	return values[0], true
}

func organizationPathUUID(
	response http.ResponseWriter,
	request *http.Request,
	name string,
	requestID string,
) (uuid.UUID, bool) {
	identifier, ok := canonicalOrganizationUUID(chi.URLParam(request, name))
	if !ok {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return uuid.Nil, false
	}
	return identifier, true
}

func canonicalOrganizationUUID(raw string) (uuid.UUID, bool) {
	identifier, err := uuid.Parse(raw)
	return identifier, err == nil && identifier != uuid.Nil && identifier.String() == raw
}

func organizationExpectedRevision(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (int64, bool) {
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(values) != 1 || len(values["expected_revision"]) != 1 {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return 0, false
	}
	raw := values["expected_revision"][0]
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != raw {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return 0, false
	}
	return revision, true
}

type organizationCursorEnvelope struct {
	Kind    string    `json:"kind"`
	SortKey string    `json:"sort_key,omitempty"`
	ID      uuid.UUID `json:"id"`
}

func organizationHTTPPage(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	kind string,
) (Page, bool) {
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return Page{}, false
	}
	for key, entries := range values {
		if (key != "limit" && key != "cursor") || len(entries) != 1 {
			writeOrganizationError(response, 400, "invalid_request", requestID)
			return Page{}, false
		}
	}
	page := Page{Limit: defaultOrganizationPage}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != raw {
			writeOrganizationError(response, 400, "invalid_request", requestID)
			return Page{}, false
		}
		page.Limit = limit
	}
	if raw := values.Get("cursor"); raw != "" {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
		if err != nil || len(decoded) > 512 {
			writeOrganizationError(response, 400, "invalid_request", requestID)
			return Page{}, false
		}
		var cursor organizationCursorEnvelope
		if rejectPolicyDuplicateJSONKeys(decoded) != nil || decodeStrictOrganizationJSON(decoded, &cursor) != nil ||
			cursor.Kind != kind || cursor.ID == uuid.Nil {
			writeOrganizationError(response, 400, "invalid_request", requestID)
			return Page{}, false
		}
		page.After = &PageCursor{SortKey: cursor.SortKey, ID: cursor.ID}
	}
	return page, true
}

func encodeOrganizationCursor(kind string, cursor *PageCursor) string {
	if cursor == nil || cursor.ID == uuid.Nil {
		return ""
	}
	raw, err := json.Marshal(organizationCursorEnvelope{Kind: kind, SortKey: cursor.SortKey, ID: cursor.ID})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func requireNoOrganizationQuery(response http.ResponseWriter, request *http.Request, requestID string) bool {
	if request.URL.RawQuery != "" {
		writeOrganizationError(response, 400, "invalid_request", requestID)
		return false
	}
	return true
}

type collectionResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type organizationResponse struct {
	ID                   uuid.UUID          `json:"id"`
	DisplayName          string             `json:"display_name"`
	Status               OrganizationStatus `json:"status"`
	Revision             int64              `json:"revision"`
	Role                 Role               `json:"role"`
	MemberCount          int                `json:"member_count"`
	DepartmentCount      int                `json:"department_count"`
	CurrentPolicyVersion int64              `json:"current_policy_version"`
	CurrentPolicyDigest  string             `json:"current_policy_digest"`
	MutationState        MutationState      `json:"mutation_state"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
	ArchivedAt           *time.Time         `json:"archived_at,omitempty"`
}

type memberResponse struct {
	UserID       uuid.UUID  `json:"user_id"`
	Nickname     *string    `json:"nickname,omitempty"`
	Role         Role       `json:"role"`
	DepartmentID *uuid.UUID `json:"department_id,omitempty"`
	Revision     int64      `json:"revision"`
	JoinedAt     time.Time  `json:"joined_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type departmentResponse struct {
	ID          uuid.UUID        `json:"id"`
	DisplayName string           `json:"display_name"`
	Status      DepartmentStatus `json:"status"`
	MemberCount int              `json:"member_count"`
	Revision    int64            `json:"revision"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	ArchivedAt  *time.Time       `json:"archived_at,omitempty"`
}

type invitationResponse struct {
	ID               uuid.UUID        `json:"id"`
	Status           InvitationStatus `json:"status"`
	CreatedByUserID  *uuid.UUID       `json:"created_by_user_id,omitempty"`
	AcceptedByUserID *uuid.UUID       `json:"accepted_by_user_id,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	ExpiresAt        time.Time        `json:"expires_at"`
	AcceptedAt       *time.Time       `json:"accepted_at,omitempty"`
	RevokedAt        *time.Time       `json:"revoked_at,omitempty"`
}

type invitationCreationResponse struct {
	Invitation       invitationResponse `json:"invitation"`
	Token            string             `json:"token,omitempty"`
	InviteURL        string             `json:"invite_url,omitempty"`
	SecretReplayable bool               `json:"secret_replayable"`
}

type invitationAcceptanceResponse struct {
	Organization organizationResponse `json:"organization"`
	Member       memberResponse       `json:"member"`
}

type policySummaryResponse struct {
	ID            uuid.UUID `json:"id"`
	PolicyVersion int64     `json:"policy_version"`
	SchemaVersion int       `json:"schema_version"`
	ContentDigest string    `json:"content_digest"`
	Issuer        string    `json:"issuer"`
	SigningKeyID  string    `json:"signing_key_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type policySnapshotResponse struct {
	policySummaryResponse
	Document  *PolicyDocument `json:"policy_document,omitempty"`
	Signature string          `json:"signature,omitempty"`
}

type auditResponse struct {
	ID             uuid.UUID  `json:"id"`
	EventType      string     `json:"event_type"`
	ObjectType     string     `json:"object_type,omitempty"`
	ObjectID       *uuid.UUID `json:"object_id,omitempty"`
	Outcome        string     `json:"outcome"`
	ReasonCode     string     `json:"reason_code,omitempty"`
	RequestID      string     `json:"request_id,omitempty"`
	ActorDisplay   *string    `json:"actor_display,omitempty"`
	SubjectDisplay *string    `json:"subject_display,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

func publicOrganization(value OrganizationSummary) organizationResponse {
	return organizationResponse{
		ID: value.ID, DisplayName: value.DisplayName, Status: value.Status, Revision: value.Revision, Role: value.Role,
		MemberCount: value.MemberCount, DepartmentCount: value.DepartmentCount,
		CurrentPolicyVersion: value.CurrentPolicyVersion, CurrentPolicyDigest: hex.EncodeToString(value.CurrentPolicyDigest[:]),
		MutationState: value.MutationState, CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(),
		ArchivedAt: cloneOrganizationHTTPTime(value.ArchivedAt),
	}
}

func publicMember(value MemberSummary) memberResponse {
	return memberResponse{UserID: value.UserID, Nickname: cloneOrganizationHTTPString(value.Nickname), Role: value.Role,
		DepartmentID: cloneOrganizationHTTPUUID(value.DepartmentID), Revision: value.Revision,
		JoinedAt: value.JoinedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC()}
}

func publicDepartment(value DepartmentSummary) departmentResponse {
	return departmentResponse{ID: value.ID, DisplayName: value.DisplayName, Status: value.Status, MemberCount: value.MemberCount,
		Revision: value.Revision, CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(), ArchivedAt: cloneOrganizationHTTPTime(value.ArchivedAt)}
}

func publicInvitation(value InvitationSummary) invitationResponse {
	return invitationResponse{ID: value.ID, Status: value.Status, CreatedByUserID: cloneOrganizationHTTPUUID(value.CreatedByUserID),
		AcceptedByUserID: cloneOrganizationHTTPUUID(value.AcceptedByUserID), CreatedAt: value.CreatedAt.UTC(), ExpiresAt: value.ExpiresAt.UTC(),
		AcceptedAt: cloneOrganizationHTTPTime(value.AcceptedAt), RevokedAt: cloneOrganizationHTTPTime(value.RevokedAt)}
}

func publicInvitationCreation(value InvitationCreationResult) (invitationCreationResponse, bool, bool) {
	result := invitationCreationResponse{Invitation: publicInvitation(value.Invitation), SecretReplayable: false}
	if value.Token == "" && value.InviteURL == "" {
		return result, false, true
	}
	digest, err := InvitationDigest(value.Token)
	if err != nil || digest == ([32]byte{}) || value.InviteURL != "agentera://organization-invitation#"+value.Token {
		return invitationCreationResponse{}, false, false
	}
	result.Token = value.Token
	result.InviteURL = value.InviteURL
	return result, true, true
}

func publicPolicySummary(value PolicySummary) policySummaryResponse {
	return policySummaryResponse{ID: value.ID, PolicyVersion: value.PolicyVersion, SchemaVersion: value.SchemaVersion,
		ContentDigest: hex.EncodeToString(value.ContentDigest[:]), Issuer: value.Issuer, SigningKeyID: value.SigningKeyID,
		CreatedAt: value.CreatedAt.UTC()}
}

func publicPolicySnapshot(value PolicySnapshot) policySnapshotResponse {
	result := policySnapshotResponse{policySummaryResponse: publicPolicySummary(value.PolicySummary)}
	if len(value.Signature) > 0 {
		document := value.Document
		result.Document = &document
		result.Signature = base64.RawURLEncoding.EncodeToString(value.Signature)
	}
	return result
}

func publicAudit(value AuditSummary) auditResponse {
	return auditResponse{ID: value.ID, EventType: value.EventType, ObjectType: value.ObjectType,
		ObjectID: cloneOrganizationHTTPUUID(value.ObjectID), Outcome: value.Outcome, ReasonCode: value.ReasonCode,
		RequestID: value.RequestID, ActorDisplay: cloneOrganizationHTTPString(value.ActorDisplay),
		SubjectDisplay: cloneOrganizationHTTPString(value.SubjectDisplay), CreatedAt: value.CreatedAt.UTC()}
}

func cloneOrganizationHTTPUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
func cloneOrganizationHTTPTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}
func cloneOrganizationHTTPString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func writeOrganizationServiceError(response http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		writeOrganizationError(response, 400, "invalid_request", requestID)
	case errors.Is(err, ErrSessionRevoked):
		writeOrganizationError(response, 401, "authentication_required", requestID)
	case errors.Is(err, ErrOrganizationForbidden):
		writeOrganizationError(response, 403, "organization_forbidden", requestID)
	case errors.Is(err, ErrOrganizationNotFound):
		writeOrganizationError(response, 404, "organization_not_found", requestID)
	case errors.Is(err, ErrInvitationUnavailable):
		writeOrganizationError(response, 404, "invitation_unavailable", requestID)
	case errors.Is(err, ErrInvitationExpired):
		writeOrganizationError(response, 410, "invitation_expired", requestID)
	case errors.Is(err, ErrInvitationRevoked):
		writeOrganizationError(response, 410, "invitation_revoked", requestID)
	case errors.Is(err, ErrInvitationUsed):
		writeOrganizationError(response, 409, "invitation_used", requestID)
	case errors.Is(err, ErrOrganizationConflict):
		writeOrganizationError(response, 409, "organization_conflict", requestID)
	case errors.Is(err, ErrOrganizationArchived):
		writeOrganizationError(response, 409, "organization_archived", requestID)
	case errors.Is(err, ErrOrganizationLimitReached):
		writeOrganizationError(response, 409, "organization_limit_reached", requestID)
	case errors.Is(err, ErrOrganizationOwnerTransferRequired):
		writeOrganizationError(response, 409, "organization_owner_transfer_required", requestID)
	case errors.Is(err, ErrOwnerTransferTargetInvalid):
		writeOrganizationError(response, 409, "owner_transfer_target_invalid", requestID)
	case errors.Is(err, ErrMembershipConflict):
		writeOrganizationError(response, 409, "membership_conflict", requestID)
	case errors.Is(err, ErrMemberLimitReached):
		writeOrganizationError(response, 409, "member_limit_reached", requestID)
	case errors.Is(err, ErrDepartmentNotEmpty):
		writeOrganizationError(response, 409, "department_not_empty", requestID)
	case errors.Is(err, ErrDepartmentLimitReached):
		writeOrganizationError(response, 409, "department_limit_reached", requestID)
	case errors.Is(err, ErrInvitationLimitReached):
		writeOrganizationError(response, 409, "invitation_limit_reached", requestID)
	case errors.Is(err, ErrPolicyVersionConflict):
		writeOrganizationError(response, 409, "policy_version_conflict", requestID)
	case errors.Is(err, ErrIdempotencyConflict):
		writeOrganizationError(response, 409, "idempotency_conflict", requestID)
	case errors.Is(err, ErrDissolutionBlocked):
		writeOrganizationError(response, 409, "dissolution_blocked", requestID)
	case errors.Is(err, ErrRateLimited):
		retryAfter := time.Second
		var limited *RateLimitError
		if errors.As(err, &limited) && limited.RetryAfter > 0 {
			retryAfter = limited.RetryAfter
		}
		seconds := int64(math.Ceil(retryAfter.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		response.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeOrganizationError(response, 429, "rate_limited", requestID)
	default:
		writeOrganizationError(response, 503, "service_unavailable", requestID)
	}
}

func writeOrganizationError(response http.ResponseWriter, status int, code, requestID string) {
	writeOrganizationJSON(response, status, struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}{
		Error: struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		}{Code: code, RequestID: requestID},
	})
}

func writeOrganizationJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(payload)
}

func writeOrganizationNoContent(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func newOrganizationRequestID() string {
	identifier, err := secure.RandomUUID()
	if err != nil {
		return "unavailable"
	}
	return identifier.String()
}

var _ HTTPService = (*Service)(nil)
