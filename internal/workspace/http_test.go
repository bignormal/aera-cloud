package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
)

func TestWorkspaceHTTPRoutesUseBearerActorAndSafeExactShapes(t *testing.T) {
	fixture := newWorkspaceHTTPFixture(t)
	routes := []struct {
		name       string
		method     string
		path       string
		body       string
		status     int
		idempotent bool
	}{
		{name: "list workspaces", method: http.MethodGet, path: "/api/v1/workspaces", status: http.StatusOK},
		{name: "create workspace", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"Team Space"}`, status: http.StatusCreated, idempotent: true},
		{name: "rename workspace", method: http.MethodPatch, path: "/api/v1/workspaces/" + fixture.workspaceID.String(), body: `{"display_name":"Renamed","expected_revision":1}`, status: http.StatusOK},
		{name: "archive workspace", method: http.MethodPost, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/archive", body: `{"expected_revision":1}`, status: http.StatusOK},
		{name: "restore workspace", method: http.MethodPost, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/restore", body: `{"expected_revision":1}`, status: http.StatusOK},
		{name: "list members", method: http.MethodGet, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/members", status: http.StatusOK},
		{name: "change member role", method: http.MethodPatch, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/members/" + fixture.memberID.String(), body: `{"role":"admin","expected_revision":1}`, status: http.StatusOK},
		{name: "remove member", method: http.MethodDelete, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/members/" + fixture.memberID.String() + "?expected_revision=1", status: http.StatusNoContent},
		{name: "leave workspace", method: http.MethodPost, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/leave", body: `{}`, status: http.StatusNoContent},
		{name: "list invitations", method: http.MethodGet, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/invitations", status: http.StatusOK},
		{name: "create invitation", method: http.MethodPost, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/invitations", body: `{}`, status: http.StatusCreated, idempotent: true},
		{name: "revoke invitation", method: http.MethodDelete, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/invitations/" + fixture.invitationID.String(), status: http.StatusNoContent},
		{name: "accept invitation", method: http.MethodPost, path: "/api/v1/workspace-invitations/accept", body: `{"token":"` + fixture.rawToken + `"}`, status: http.StatusOK, idempotent: true},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
			request.Header.Set("Authorization", "Bearer workspace-access-token")
			if route.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if route.idempotent {
				request.Header.Set("Idempotency-Key", "  opaque-"+strings.ReplaceAll(route.name, " ", "-")+"  ")
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != route.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), route.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
			if route.status == http.StatusNoContent {
				if response.Body.Len() != 0 {
					t.Fatalf("204 body = %q", response.Body.String())
				}
			} else if response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
			}
			if fixture.service.lastActor != fixture.actor {
				t.Fatalf("service actor = %+v, want bearer actor %+v", fixture.service.lastActor, fixture.actor)
			}
			body := strings.ToLower(response.Body.String())
			for _, forbidden := range []string{"owner_scope", "profile_path", "memory.md", "user.md", "credential", "api_key", "session"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("response leaked %q: %s", forbidden, body)
				}
			}
			if route.name != "create invitation" && strings.Contains(body, fixture.rawToken) {
				t.Fatalf("response leaked invitation token: %s", body)
			}
		})
	}
	if fixture.authenticator.lastToken != "workspace-access-token" {
		t.Fatalf("authenticated token = %q", fixture.authenticator.lastToken)
	}
}

func TestWorkspaceHTTPCreationReplayReturns200WithoutInvitationSecret(t *testing.T) {
	fixture := newWorkspaceHTTPFixture(t)
	fixture.service.replay = IdempotencyReplayed

	workspaceResponse := fixture.request(t, http.MethodPost, "/api/v1/workspaces", `{"display_name":"Team Space"}`, true)
	if workspaceResponse.Code != http.StatusOK {
		t.Fatalf("workspace replay = %d %q", workspaceResponse.Code, workspaceResponse.Body.String())
	}
	invitationResponse := fixture.request(t, http.MethodPost, "/api/v1/workspaces/"+fixture.workspaceID.String()+"/invitations", `{}`, true)
	if invitationResponse.Code != http.StatusOK || strings.Contains(invitationResponse.Body.String(), fixture.rawToken) ||
		strings.Contains(invitationResponse.Body.String(), "invite_url") ||
		!strings.Contains(invitationResponse.Body.String(), `"secret_replayable":false`) {
		t.Fatalf("invitation replay = %d %q", invitationResponse.Code, invitationResponse.Body.String())
	}
}

func TestWorkspaceHTTPPreservesOpaqueIdempotencyAndSharesRequestIDWithErrors(t *testing.T) {
	fixture := newWorkspaceHTTPFixture(t)
	create := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", strings.NewReader(`{"display_name":"Team Space"}`))
	create.Header.Set("Authorization", "Bearer workspace-access-token")
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "  exact opaque key  ")
	createResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(createResponse, create)
	if createResponse.Code != http.StatusCreated || fixture.service.lastCreateRequest.IdempotencyKey != "  exact opaque key  " {
		t.Fatalf("create response=%d request=%+v", createResponse.Code, fixture.service.lastCreateRequest)
	}

	fixture.service.err = ErrWorkspaceConflict
	rename := httptest.NewRequest(
		http.MethodPatch,
		"/api/v1/workspaces/"+fixture.workspaceID.String(),
		strings.NewReader(`{"display_name":"Renamed","expected_revision":1}`),
	)
	rename.Header.Set("Authorization", "Bearer workspace-access-token")
	rename.Header.Set("Content-Type", "application/json")
	renameResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(renameResponse, rename)
	var payload struct {
		Error struct {
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(renameResponse.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode rename error: %v", err)
	}
	if renameResponse.Code != http.StatusConflict || payload.Error.RequestID == "" ||
		payload.Error.RequestID != fixture.service.lastRequestID {
		t.Fatalf("rename response=%d body=%q service request=%q", renameResponse.Code, renameResponse.Body.String(), fixture.service.lastRequestID)
	}
}

func TestWorkspaceHTTPRejectsAmbiguousBodiesIdentifiersAndIdempotency(t *testing.T) {
	fixture := newWorkspaceHTTPFixture(t)
	tests := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
		idempotency []string
		status      int
	}{
		{name: "unknown field", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"Space","unknown":true}`, contentType: "application/json", idempotency: []string{"key"}, status: http.StatusBadRequest},
		{name: "duplicate field", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"One","display_name":"Two"}`, contentType: "application/json", idempotency: []string{"key"}, status: http.StatusBadRequest},
		{name: "second value", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"Space"}{}`, contentType: "application/json", idempotency: []string{"key"}, status: http.StatusBadRequest},
		{name: "wrong content type", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"Space"}`, contentType: "text/plain", idempotency: []string{"key"}, status: http.StatusBadRequest},
		{name: "oversized body", method: http.MethodPost, path: "/api/v1/workspaces", body: strings.Repeat(" ", maxWorkspaceBodyBytes+1), contentType: "application/json", idempotency: []string{"key"}, status: http.StatusRequestEntityTooLarge},
		{name: "missing idempotency", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"Space"}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "blank idempotency", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"Space"}`, contentType: "application/json", idempotency: []string{"   "}, status: http.StatusBadRequest},
		{name: "oversized idempotency", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"Space"}`, contentType: "application/json", idempotency: []string{strings.Repeat("k", maxIdempotencyKeyBytes+1)}, status: http.StatusBadRequest},
		{name: "duplicate idempotency", method: http.MethodPost, path: "/api/v1/workspaces", body: `{"display_name":"Space"}`, contentType: "application/json", idempotency: []string{"one", "two"}, status: http.StatusBadRequest},
		{name: "malformed workspace UUID", method: http.MethodPatch, path: "/api/v1/workspaces/not-a-uuid", body: `{"display_name":"Space","expected_revision":1}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "noncanonical workspace UUID", method: http.MethodPatch, path: "/api/v1/workspaces/" + strings.ToUpper(fixture.workspaceID.String()), body: `{"display_name":"Space","expected_revision":1}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "duplicate revision query", method: http.MethodDelete, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/members/" + fixture.memberID.String() + "?expected_revision=1&expected_revision=1", status: http.StatusBadRequest},
		{name: "extra revision query", method: http.MethodDelete, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/members/" + fixture.memberID.String() + "?expected_revision=1&extra=1", status: http.StatusBadRequest},
		{name: "nonpositive revision query", method: http.MethodDelete, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/members/" + fixture.memberID.String() + "?expected_revision=0", status: http.StatusBadRequest},
		{name: "missing empty object", method: http.MethodPost, path: "/api/v1/workspaces/" + fixture.workspaceID.String() + "/invitations", contentType: "application/json", idempotency: []string{"key"}, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer workspace-access-token")
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			for _, value := range test.idempotency {
				request.Header.Add("Idempotency-Key", value)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), test.status)
			}
			assertWorkspaceErrorEnvelope(t, response, "invalid_request")
		})
	}
}

func TestWorkspaceHTTPRejectsMalformedOrRevokedBearerAuthorization(t *testing.T) {
	for _, test := range []struct {
		name          string
		authorization []string
		authErr       error
		status        int
		code          string
	}{
		{name: "missing", status: http.StatusUnauthorized, code: "session_revoked"},
		{name: "empty", authorization: []string{"Bearer "}, status: http.StatusUnauthorized, code: "session_revoked"},
		{name: "whitespace", authorization: []string{"Bearer token with spaces"}, status: http.StatusUnauthorized, code: "session_revoked"},
		{name: "duplicate", authorization: []string{"Bearer one", "Bearer two"}, status: http.StatusUnauthorized, code: "session_revoked"},
		{name: "revoked", authorization: []string{"Bearer revoked"}, authErr: session.ErrSessionRevoked, status: http.StatusUnauthorized, code: "session_revoked"},
		{name: "invalid", authorization: []string{"Bearer invalid"}, authErr: session.ErrInvalidAccessToken, status: http.StatusUnauthorized, code: "session_revoked"},
		{name: "dependency", authorization: []string{"Bearer unavailable"}, authErr: errors.New("secret storage failure"), status: http.StatusServiceUnavailable, code: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkspaceHTTPFixture(t)
			fixture.authenticator.err = test.authErr
			request := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
			for _, value := range test.authorization {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			assertWorkspaceErrorEnvelope(t, response, test.code)
			if fixture.service.calls != 0 {
				t.Fatalf("service calls after rejected auth = %d", fixture.service.calls)
			}
		})
	}
}

func TestWorkspaceHTTPMapsStableDomainErrorsAndRetryAfter(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
		retry  string
	}{
		{err: ErrInvalidRequest, status: 400, code: "invalid_request"},
		{err: ErrSessionRevoked, status: 401, code: "session_revoked"},
		{err: ErrWorkspaceForbidden, status: 403, code: "workspace_forbidden"},
		{err: ErrWorkspaceNotFound, status: 404, code: "workspace_not_found"},
		{err: ErrInvitationUnavailable, status: 404, code: "invitation_unavailable"},
		{err: ErrWorkspaceConflict, status: 409, code: "workspace_conflict"},
		{err: ErrWorkspaceArchived, status: 409, code: "workspace_archived"},
		{err: ErrWorkspaceOwnerUnavailable, status: 409, code: "workspace_owner_unavailable"},
		{err: ErrMembershipConflict, status: 409, code: "membership_conflict"},
		{err: ErrWorkspaceLimitReached, status: 409, code: "workspace_limit_reached"},
		{err: ErrMemberLimitReached, status: 409, code: "member_limit_reached"},
		{err: ErrInvitationLimitReached, status: 409, code: "invitation_limit_reached"},
		{err: ErrIdempotencyConflict, status: 409, code: "idempotency_conflict"},
		{err: &RateLimitError{RetryAfter: 1500 * time.Millisecond}, status: 429, code: "rate_limited", retry: "2"},
		{err: ErrServiceUnavailable, status: 503, code: "service_unavailable"},
		{err: errors.New("postgres://user:secret@private"), status: 503, code: "service_unavailable"},
	} {
		t.Run(test.code, func(t *testing.T) {
			fixture := newWorkspaceHTTPFixture(t)
			fixture.service.err = test.err
			response := fixture.request(t, http.MethodGet, "/api/v1/workspaces", "", false)
			if response.Code != test.status || response.Header().Get("Retry-After") != test.retry {
				t.Fatalf("response = %d retry=%q body=%q", response.Code, response.Header().Get("Retry-After"), response.Body.String())
			}
			assertWorkspaceErrorEnvelope(t, response, test.code)
			if strings.Contains(response.Body.String(), "postgres") || strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("error leaked internal details: %s", response.Body.String())
			}
		})
	}
}

func assertWorkspaceErrorEnvelope(t *testing.T, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	var payload struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error envelope: %v; body=%q", err, response.Body.String())
	}
	if len(payload.Error) != 2 || payload.Error["code"] != code {
		t.Fatalf("error envelope = %+v", payload.Error)
	}
	requestID, ok := payload.Error["request_id"].(string)
	if !ok || requestID == "" {
		t.Fatalf("request_id = %#v", payload.Error["request_id"])
	}
}

type workspaceHTTPFixture struct {
	handler       http.Handler
	service       *stubWorkspaceHTTPService
	authenticator *stubWorkspaceAuthenticator
	actor         Actor
	workspaceID   uuid.UUID
	memberID      uuid.UUID
	invitationID  uuid.UUID
	rawToken      string
}

func newWorkspaceHTTPFixture(t *testing.T) *workspaceHTTPFixture {
	t.Helper()
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	workspaceID, memberID, invitationID := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 7, 20, 15, 0, 0, 0, time.UTC)
	secret, err := NewInvitationSecret(strings.NewReader(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatalf("NewInvitationSecret() error = %v", err)
	}
	workspace := Workspace{
		ID: workspaceID, DisplayName: "Team Space", Status: WorkspaceStatusActive, Revision: 1,
		MutationState: MutationStateWritable, ActorRole: RoleOwner, MemberCount: 2,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	member := Member{UserID: memberID, Nickname: "Teammate", Role: RoleMember, Revision: 1, JoinedAt: now}
	invitation := Invitation{
		ID: invitationID, Status: InvitationStatusPending, CreatedByUserID: &actor.UserID,
		CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour),
	}
	service := &stubWorkspaceHTTPService{
		workspace: workspace, workspaces: []Workspace{workspace}, member: member, members: []Member{member},
		invitation: invitation, invitations: []Invitation{invitation}, rawToken: secret.RawToken,
	}
	authenticator := &stubWorkspaceAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
		UserID: actor.UserID, DeviceID: actor.DeviceID, PersonalSpaceID: uuid.New(), SessionID: uuid.New(),
	}}}
	return &workspaceHTTPFixture{
		handler: NewHandler(HTTPConfig{Service: service, AccessTokens: authenticator}),
		service: service, authenticator: authenticator, actor: actor,
		workspaceID: workspaceID, memberID: memberID, invitationID: invitationID, rawToken: secret.RawToken,
	}
}

func (f *workspaceHTTPFixture) request(t *testing.T, method string, path string, body string, idempotent bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer workspace-access-token")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotent {
		request.Header.Set("Idempotency-Key", "workspace-key")
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

type stubWorkspaceHTTPService struct {
	lastActor         Actor
	lastRequestID     string
	lastCreateRequest CreateWorkspaceRequest
	calls             int
	err               error
	replay            IdempotencyReplay
	workspace         Workspace
	workspaces        []Workspace
	member            Member
	members           []Member
	invitation        Invitation
	invitations       []Invitation
	rawToken          string
}

func (s *stubWorkspaceHTTPService) called(actor Actor) {
	s.calls++
	s.lastActor = actor
}
func (s *stubWorkspaceHTTPService) ListWorkspaces(_ context.Context, actor Actor) ([]Workspace, error) {
	s.called(actor)
	return s.workspaces, s.err
}
func (s *stubWorkspaceHTTPService) CreateWorkspace(_ context.Context, actor Actor, request CreateWorkspaceRequest) (Workspace, IdempotencyReplay, error) {
	s.called(actor)
	s.lastRequestID = request.RequestID
	s.lastCreateRequest = request
	return s.workspace, s.replayOrFresh(), s.err
}
func (s *stubWorkspaceHTTPService) RenameWorkspace(_ context.Context, actor Actor, request RenameWorkspaceRequest) (Workspace, error) {
	s.called(actor)
	s.lastRequestID = request.RequestID
	return s.workspace, s.err
}
func (s *stubWorkspaceHTTPService) ArchiveWorkspace(_ context.Context, actor Actor, request WorkspaceRevisionRequest) (Workspace, error) {
	s.called(actor)
	s.lastRequestID = request.RequestID
	return s.workspace, s.err
}
func (s *stubWorkspaceHTTPService) RestoreWorkspace(_ context.Context, actor Actor, request WorkspaceRevisionRequest) (Workspace, error) {
	s.called(actor)
	s.lastRequestID = request.RequestID
	return s.workspace, s.err
}
func (s *stubWorkspaceHTTPService) ListMembers(_ context.Context, actor Actor, _ uuid.UUID) ([]Member, error) {
	s.called(actor)
	return s.members, s.err
}
func (s *stubWorkspaceHTTPService) ChangeMemberRole(_ context.Context, actor Actor, request ChangeMemberRoleRequest) (Member, error) {
	s.called(actor)
	s.lastRequestID = request.RequestID
	return s.member, s.err
}
func (s *stubWorkspaceHTTPService) RemoveMember(_ context.Context, actor Actor, request RemoveMemberRequest) error {
	s.called(actor)
	s.lastRequestID = request.RequestID
	return s.err
}
func (s *stubWorkspaceHTTPService) LeaveWorkspace(_ context.Context, actor Actor, _ uuid.UUID, requestID string) error {
	s.called(actor)
	s.lastRequestID = requestID
	return s.err
}
func (s *stubWorkspaceHTTPService) ListInvitations(_ context.Context, actor Actor, _ uuid.UUID, requestID string) ([]Invitation, error) {
	s.called(actor)
	s.lastRequestID = requestID
	return s.invitations, s.err
}
func (s *stubWorkspaceHTTPService) CreateInvitation(_ context.Context, actor Actor, request CreateInvitationRequest) (InvitationCreationResult, IdempotencyReplay, error) {
	s.called(actor)
	s.lastRequestID = request.RequestID
	result := InvitationCreationResult{Invitation: s.invitation, SecretReplayable: false}
	if s.replay != IdempotencyReplayed {
		result.Token = s.rawToken
		result.InviteURL = "agentera://workspace-invitation#" + s.rawToken
	}
	return result, s.replayOrFresh(), s.err
}
func (s *stubWorkspaceHTTPService) RevokeInvitation(_ context.Context, actor Actor, request RevokeInvitationRequest) error {
	s.called(actor)
	s.lastRequestID = request.RequestID
	return s.err
}
func (s *stubWorkspaceHTTPService) AcceptInvitation(_ context.Context, actor Actor, request AcceptInvitationRequest) (Acceptance, error) {
	s.called(actor)
	s.lastRequestID = request.RequestID
	return Acceptance{Workspace: s.workspace, Member: s.member}, s.err
}
func (s *stubWorkspaceHTTPService) replayOrFresh() IdempotencyReplay {
	if s.replay == "" {
		return IdempotencyFresh
	}
	return s.replay
}

type stubWorkspaceAuthenticator struct {
	claims    session.AccessClaims
	err       error
	lastToken string
}

func (s *stubWorkspaceAuthenticator) Authenticate(_ context.Context, token string) (session.AccessClaims, error) {
	s.lastToken = token
	return s.claims, s.err
}
