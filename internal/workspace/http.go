package workspace

import (
	"bytes"
	"context"
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
	maxWorkspaceBodyBytes  = 16 * 1024
	maxIdempotencyKeyBytes = 128
)

type HTTPService interface {
	ListWorkspaces(context.Context, Actor) ([]Workspace, error)
	CreateWorkspace(context.Context, Actor, CreateWorkspaceRequest) (Workspace, IdempotencyReplay, error)
	RenameWorkspace(context.Context, Actor, RenameWorkspaceRequest) (Workspace, error)
	ArchiveWorkspace(context.Context, Actor, WorkspaceRevisionRequest) (Workspace, error)
	RestoreWorkspace(context.Context, Actor, WorkspaceRevisionRequest) (Workspace, error)
	ListMembers(context.Context, Actor, uuid.UUID) ([]Member, error)
	ChangeMemberRole(context.Context, Actor, ChangeMemberRoleRequest) (Member, error)
	RemoveMember(context.Context, Actor, RemoveMemberRequest) error
	LeaveWorkspace(context.Context, Actor, uuid.UUID, string) error
	ListInvitations(context.Context, Actor, uuid.UUID, string) ([]Invitation, error)
	CreateInvitation(context.Context, Actor, CreateInvitationRequest) (InvitationCreationResult, IdempotencyReplay, error)
	RevokeInvitation(context.Context, Actor, RevokeInvitationRequest) error
	AcceptInvitation(context.Context, Actor, AcceptInvitationRequest) (Acceptance, error)
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
	router.Get("/api/v1/workspaces", handler.listWorkspaces)
	router.Post("/api/v1/workspaces", handler.createWorkspace)
	router.Patch("/api/v1/workspaces/{workspaceID}", handler.renameWorkspace)
	router.Post("/api/v1/workspaces/{workspaceID}/archive", handler.archiveWorkspace)
	router.Post("/api/v1/workspaces/{workspaceID}/restore", handler.restoreWorkspace)
	router.Get("/api/v1/workspaces/{workspaceID}/members", handler.listMembers)
	router.Patch("/api/v1/workspaces/{workspaceID}/members/{userID}", handler.changeMemberRole)
	router.Delete("/api/v1/workspaces/{workspaceID}/members/{userID}", handler.removeMember)
	router.Post("/api/v1/workspaces/{workspaceID}/leave", handler.leaveWorkspace)
	router.Get("/api/v1/workspaces/{workspaceID}/invitations", handler.listInvitations)
	router.Post("/api/v1/workspaces/{workspaceID}/invitations", handler.createInvitation)
	router.Delete("/api/v1/workspaces/{workspaceID}/invitations/{invitationID}", handler.revokeInvitation)
	router.Post("/api/v1/workspace-invitations/accept", handler.acceptInvitation)
	return router
}

func (h *httpHandler) listWorkspaces(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaces, err := h.service.ListWorkspaces(request.Context(), actor)
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	items := make([]workspaceResponse, len(workspaces))
	for index, workspace := range workspaces {
		items[index] = publicWorkspace(workspace)
	}
	writeWorkspaceJSON(response, http.StatusOK, struct {
		Workspaces []workspaceResponse `json:"workspaces"`
	}{Workspaces: items})
}

func (h *httpHandler) createWorkspace(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	idempotencyKey, ok := requireWorkspaceIdempotencyKey(response, request, requestID)
	if !ok {
		return
	}
	var payload struct {
		DisplayName string `json:"display_name"`
	}
	if !decodeWorkspaceJSON(response, request, requestID, &payload) {
		return
	}
	workspace, replay, err := h.service.CreateWorkspace(request.Context(), actor, CreateWorkspaceRequest{
		DisplayName: payload.DisplayName, IdempotencyKey: idempotencyKey, RequestID: requestID,
	})
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	status, ok := creationStatus(replay)
	if !ok {
		writeWorkspaceError(response, http.StatusServiceUnavailable, "service_unavailable", requestID)
		return
	}
	writeWorkspaceJSON(response, status, publicWorkspace(workspace))
}

func (h *httpHandler) renameWorkspace(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	var payload struct {
		DisplayName      string `json:"display_name"`
		ExpectedRevision int64  `json:"expected_revision"`
	}
	if !decodeWorkspaceJSON(response, request, requestID, &payload) {
		return
	}
	workspace, err := h.service.RenameWorkspace(request.Context(), actor, RenameWorkspaceRequest{
		WorkspaceID: workspaceID, DisplayName: payload.DisplayName,
		ExpectedRevision: payload.ExpectedRevision, RequestID: requestID,
	})
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	writeWorkspaceJSON(response, http.StatusOK, publicWorkspace(workspace))
}

func (h *httpHandler) archiveWorkspace(response http.ResponseWriter, request *http.Request) {
	h.reviseWorkspace(response, request, false)
}

func (h *httpHandler) restoreWorkspace(response http.ResponseWriter, request *http.Request) {
	h.reviseWorkspace(response, request, true)
}

func (h *httpHandler) reviseWorkspace(response http.ResponseWriter, request *http.Request, restore bool) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	var payload struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if !decodeWorkspaceJSON(response, request, requestID, &payload) {
		return
	}
	command := WorkspaceRevisionRequest{
		WorkspaceID: workspaceID, ExpectedRevision: payload.ExpectedRevision, RequestID: requestID,
	}
	var workspace Workspace
	var err error
	if restore {
		workspace, err = h.service.RestoreWorkspace(request.Context(), actor, command)
	} else {
		workspace, err = h.service.ArchiveWorkspace(request.Context(), actor, command)
	}
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	writeWorkspaceJSON(response, http.StatusOK, publicWorkspace(workspace))
}

func (h *httpHandler) listMembers(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	members, err := h.service.ListMembers(request.Context(), actor, workspaceID)
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	items := make([]memberResponse, len(members))
	for index, member := range members {
		items[index] = publicMember(member)
	}
	writeWorkspaceJSON(response, http.StatusOK, struct {
		Members []memberResponse `json:"members"`
	}{Members: items})
}

func (h *httpHandler) changeMemberRole(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	userID, ok := workspacePathUUID(response, request, "userID", requestID)
	if !ok {
		return
	}
	var payload struct {
		Role             Role  `json:"role"`
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if !decodeWorkspaceJSON(response, request, requestID, &payload) {
		return
	}
	member, err := h.service.ChangeMemberRole(request.Context(), actor, ChangeMemberRoleRequest{
		WorkspaceID: workspaceID, UserID: userID, Role: payload.Role,
		ExpectedRevision: payload.ExpectedRevision, RequestID: requestID,
	})
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	writeWorkspaceJSON(response, http.StatusOK, publicMember(member))
}

func (h *httpHandler) removeMember(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	userID, ok := workspacePathUUID(response, request, "userID", requestID)
	if !ok {
		return
	}
	expectedRevision, ok := workspaceExpectedRevision(response, request, requestID)
	if !ok {
		return
	}
	if err := h.service.RemoveMember(request.Context(), actor, RemoveMemberRequest{
		WorkspaceID: workspaceID, UserID: userID, ExpectedRevision: expectedRevision, RequestID: requestID,
	}); err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	writeWorkspaceNoContent(response)
}

func (h *httpHandler) leaveWorkspace(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	if !decodeWorkspaceJSON(response, request, requestID, &struct{}{}) {
		return
	}
	if err := h.service.LeaveWorkspace(request.Context(), actor, workspaceID, requestID); err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	writeWorkspaceNoContent(response)
}

func (h *httpHandler) listInvitations(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	invitations, err := h.service.ListInvitations(request.Context(), actor, workspaceID, requestID)
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	items := make([]invitationResponse, len(invitations))
	for index, invitation := range invitations {
		items[index] = publicInvitation(invitation)
	}
	writeWorkspaceJSON(response, http.StatusOK, struct {
		Invitations []invitationResponse `json:"invitations"`
	}{Invitations: items})
}

func (h *httpHandler) createInvitation(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	idempotencyKey, ok := requireWorkspaceIdempotencyKey(response, request, requestID)
	if !ok {
		return
	}
	if !decodeWorkspaceJSON(response, request, requestID, &struct{}{}) {
		return
	}
	creation, replay, err := h.service.CreateInvitation(request.Context(), actor, CreateInvitationRequest{
		WorkspaceID: workspaceID, IdempotencyKey: idempotencyKey, RequestID: requestID,
	})
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	status, ok := creationStatus(replay)
	if !ok {
		writeWorkspaceError(response, http.StatusServiceUnavailable, "service_unavailable", requestID)
		return
	}
	public, ok := publicInvitationCreation(creation, replay)
	if !ok {
		writeWorkspaceError(response, http.StatusServiceUnavailable, "service_unavailable", requestID)
		return
	}
	writeWorkspaceJSON(response, status, public)
}

func (h *httpHandler) revokeInvitation(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	workspaceID, ok := workspacePathUUID(response, request, "workspaceID", requestID)
	if !ok {
		return
	}
	invitationID, ok := workspacePathUUID(response, request, "invitationID", requestID)
	if !ok {
		return
	}
	if err := h.service.RevokeInvitation(request.Context(), actor, RevokeInvitationRequest{
		WorkspaceID: workspaceID, InvitationID: invitationID, RequestID: requestID,
	}); err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	writeWorkspaceNoContent(response)
}

func (h *httpHandler) acceptInvitation(response http.ResponseWriter, request *http.Request) {
	requestID := newWorkspaceRequestID()
	actor, ok := h.authorize(response, request, requestID)
	if !ok {
		return
	}
	idempotencyKey, ok := requireWorkspaceIdempotencyKey(response, request, requestID)
	if !ok {
		return
	}
	var payload struct {
		Token string `json:"token"`
	}
	if !decodeWorkspaceJSON(response, request, requestID, &payload) {
		return
	}
	acceptance, err := h.service.AcceptInvitation(request.Context(), actor, AcceptInvitationRequest{
		Token: payload.Token, IdempotencyKey: idempotencyKey, RequestID: requestID,
	})
	if err != nil {
		writeWorkspaceServiceError(response, err, requestID)
		return
	}
	writeWorkspaceJSON(response, http.StatusOK, invitationAcceptanceResponse{
		Workspace: publicWorkspace(acceptance.Workspace), Member: publicMember(acceptance.Member),
	})
}

func (h *httpHandler) authorize(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (Actor, bool) {
	if h.service == nil || h.accessTokens == nil {
		writeWorkspaceError(response, http.StatusServiceUnavailable, "service_unavailable", requestID)
		return Actor{}, false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		writeWorkspaceError(response, http.StatusUnauthorized, "session_revoked", requestID)
		return Actor{}, false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, " \t\r\n") {
		writeWorkspaceError(response, http.StatusUnauthorized, "session_revoked", requestID)
		return Actor{}, false
	}
	claims, err := h.accessTokens.Authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, session.ErrInvalidAccessToken) || errors.Is(err, session.ErrSessionRevoked) {
			writeWorkspaceError(response, http.StatusUnauthorized, "session_revoked", requestID)
		} else {
			writeWorkspaceError(response, http.StatusServiceUnavailable, "service_unavailable", requestID)
		}
		return Actor{}, false
	}
	if claims.UserID == uuid.Nil || claims.DeviceID == uuid.Nil || claims.PersonalSpaceID == uuid.Nil {
		writeWorkspaceError(response, http.StatusUnauthorized, "session_revoked", requestID)
		return Actor{}, false
	}
	return Actor{UserID: claims.UserID, DeviceID: claims.DeviceID}, true
}

func decodeWorkspaceJSON(response http.ResponseWriter, request *http.Request, requestID string, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeWorkspaceError(response, http.StatusBadRequest, "invalid_request", requestID)
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxWorkspaceBodyBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeWorkspaceError(response, http.StatusRequestEntityTooLarge, "invalid_request", requestID)
		} else {
			writeWorkspaceError(response, http.StatusBadRequest, "invalid_request", requestID)
		}
		return false
	}
	if rejectWorkspaceDuplicateJSONKeys(raw) != nil || decodeStrictWorkspaceJSON(raw, target) != nil {
		writeWorkspaceError(response, http.StatusBadRequest, "invalid_request", requestID)
		return false
	}
	return true
}

func requireWorkspaceIdempotencyKey(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !validWorkspaceHTTPIdempotencyKey(values[0]) {
		writeWorkspaceError(response, http.StatusBadRequest, "invalid_request", requestID)
		return "", false
	}
	return values[0], true
}

func validWorkspaceHTTPIdempotencyKey(value string) bool {
	return len([]byte(value)) <= maxIdempotencyKeyBytes && validOpaqueIdempotencyKey(value) &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func workspacePathUUID(
	response http.ResponseWriter,
	request *http.Request,
	name string,
	requestID string,
) (uuid.UUID, bool) {
	raw := chi.URLParam(request, name)
	identifier, err := uuid.Parse(raw)
	if err != nil || identifier == uuid.Nil || identifier.String() != raw {
		writeWorkspaceError(response, http.StatusBadRequest, "invalid_request", requestID)
		return uuid.Nil, false
	}
	return identifier, true
}

func workspaceExpectedRevision(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (int64, bool) {
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(values) != 1 || len(values["expected_revision"]) != 1 {
		writeWorkspaceError(response, http.StatusBadRequest, "invalid_request", requestID)
		return 0, false
	}
	raw := values["expected_revision"][0]
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != raw {
		writeWorkspaceError(response, http.StatusBadRequest, "invalid_request", requestID)
		return 0, false
	}
	return revision, true
}

type workspaceResponse struct {
	ID            uuid.UUID       `json:"id"`
	DisplayName   string          `json:"display_name"`
	Status        WorkspaceStatus `json:"status"`
	Revision      int64           `json:"revision"`
	MutationState MutationState   `json:"mutation_state"`
	Role          Role            `json:"role"`
	MemberCount   int             `json:"member_count"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	ArchivedAt    *time.Time      `json:"archived_at,omitempty"`
}

type memberResponse struct {
	UserID   uuid.UUID `json:"user_id"`
	Nickname string    `json:"nickname,omitempty"`
	Role     Role      `json:"role"`
	Revision int64     `json:"revision"`
	JoinedAt time.Time `json:"joined_at"`
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
	invitationResponse
	Token            string `json:"token,omitempty"`
	InviteURL        string `json:"invite_url,omitempty"`
	SecretReplayable bool   `json:"secret_replayable"`
}

type invitationAcceptanceResponse struct {
	Workspace workspaceResponse `json:"workspace"`
	Member    memberResponse    `json:"member"`
}

func publicWorkspace(value Workspace) workspaceResponse {
	return workspaceResponse{
		ID: value.ID, DisplayName: value.DisplayName, Status: value.Status, Revision: value.Revision,
		MutationState: value.MutationState, Role: value.ActorRole, MemberCount: value.MemberCount,
		CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(), ArchivedAt: cloneHTTPTime(value.ArchivedAt),
	}
}

func publicMember(value Member) memberResponse {
	return memberResponse{
		UserID: value.UserID, Nickname: value.Nickname, Role: value.Role, Revision: value.Revision, JoinedAt: value.JoinedAt.UTC(),
	}
}

func publicInvitation(value Invitation) invitationResponse {
	return invitationResponse{
		ID: value.ID, Status: value.Status, CreatedByUserID: cloneHTTPUUID(value.CreatedByUserID),
		AcceptedByUserID: cloneHTTPUUID(value.AcceptedByUserID), CreatedAt: value.CreatedAt.UTC(), ExpiresAt: value.ExpiresAt.UTC(),
		AcceptedAt: cloneHTTPTime(value.AcceptedAt), RevokedAt: cloneHTTPTime(value.RevokedAt),
	}
}

func publicInvitationCreation(value InvitationCreationResult, replay IdempotencyReplay) (invitationCreationResponse, bool) {
	response := invitationCreationResponse{
		invitationResponse: publicInvitation(value.Invitation), SecretReplayable: false,
	}
	if replay == IdempotencyReplayed {
		return response, true
	}
	if replay != IdempotencyFresh {
		return invitationCreationResponse{}, false
	}
	digest, err := InvitationDigest(value.Token)
	if err != nil || digest == ([32]byte{}) || value.InviteURL != "agentera://workspace-invitation#"+value.Token {
		return invitationCreationResponse{}, false
	}
	response.Token = value.Token
	response.InviteURL = value.InviteURL
	return response, true
}

func creationStatus(replay IdempotencyReplay) (int, bool) {
	switch replay {
	case IdempotencyFresh:
		return http.StatusCreated, true
	case IdempotencyReplayed:
		return http.StatusOK, true
	default:
		return 0, false
	}
}

func cloneHTTPUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneHTTPTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func writeWorkspaceServiceError(response http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		writeWorkspaceError(response, http.StatusBadRequest, "invalid_request", requestID)
	case errors.Is(err, ErrSessionRevoked):
		writeWorkspaceError(response, http.StatusUnauthorized, "session_revoked", requestID)
	case errors.Is(err, ErrWorkspaceForbidden):
		writeWorkspaceError(response, http.StatusForbidden, "workspace_forbidden", requestID)
	case errors.Is(err, ErrWorkspaceNotFound):
		writeWorkspaceError(response, http.StatusNotFound, "workspace_not_found", requestID)
	case errors.Is(err, ErrInvitationUnavailable):
		writeWorkspaceError(response, http.StatusNotFound, "invitation_unavailable", requestID)
	case errors.Is(err, ErrWorkspaceConflict):
		writeWorkspaceError(response, http.StatusConflict, "workspace_conflict", requestID)
	case errors.Is(err, ErrWorkspaceArchived):
		writeWorkspaceError(response, http.StatusConflict, "workspace_archived", requestID)
	case errors.Is(err, ErrWorkspaceOwnerUnavailable):
		writeWorkspaceError(response, http.StatusConflict, "workspace_owner_unavailable", requestID)
	case errors.Is(err, ErrMembershipConflict):
		writeWorkspaceError(response, http.StatusConflict, "membership_conflict", requestID)
	case errors.Is(err, ErrWorkspaceLimitReached):
		writeWorkspaceError(response, http.StatusConflict, "workspace_limit_reached", requestID)
	case errors.Is(err, ErrMemberLimitReached):
		writeWorkspaceError(response, http.StatusConflict, "member_limit_reached", requestID)
	case errors.Is(err, ErrInvitationLimitReached):
		writeWorkspaceError(response, http.StatusConflict, "invitation_limit_reached", requestID)
	case errors.Is(err, ErrIdempotencyConflict):
		writeWorkspaceError(response, http.StatusConflict, "idempotency_conflict", requestID)
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
		writeWorkspaceError(response, http.StatusTooManyRequests, "rate_limited", requestID)
	default:
		writeWorkspaceError(response, http.StatusServiceUnavailable, "service_unavailable", requestID)
	}
}

func writeWorkspaceError(response http.ResponseWriter, status int, code string, requestID string) {
	writeWorkspaceJSON(response, status, struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}{Error: struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}{Code: code, RequestID: requestID}})
}

func writeWorkspaceJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(payload)
}

func writeWorkspaceNoContent(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func newWorkspaceRequestID() string {
	identifier, err := secure.RandomUUID()
	if err != nil {
		return "unavailable"
	}
	return identifier.String()
}

func decodeStrictWorkspaceJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func rejectWorkspaceDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanWorkspaceJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func scanWorkspaceJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("JSON object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := scanWorkspaceJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanWorkspaceJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil || closing != matchingWorkspaceDelimiter(delimiter) {
		return errors.New("JSON container is not closed")
	}
	return nil
}

func matchingWorkspaceDelimiter(open json.Delim) json.Delim {
	if open == '{' {
		return '}'
	}
	return ']'
}

var _ HTTPService = (*Service)(nil)
