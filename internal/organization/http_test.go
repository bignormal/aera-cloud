package organization

import (
	"bytes"
	"context"
	"encoding/base64"
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

func TestOrganizationHTTPRoutesUseBearerActorAndExactSafeShapes(t *testing.T) {
	fixture := newOrganizationHTTPFixture(t)
	routes := []struct {
		name       string
		method     string
		path       string
		body       string
		status     int
		idempotent bool
	}{
		{name: "list organizations", method: http.MethodGet, path: "/api/v1/organizations", status: 200},
		{name: "create organization", method: http.MethodPost, path: "/api/v1/organizations", body: `{"display_name":"Acme"}`, status: 201, idempotent: true},
		{name: "get organization", method: http.MethodGet, path: "/api/v1/organizations/" + fixture.organizationID.String(), status: 200},
		{name: "rename organization", method: http.MethodPatch, path: "/api/v1/organizations/" + fixture.organizationID.String(), body: `{"display_name":"Renamed","expected_revision":1}`, status: 200},
		{name: "archive organization", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/archive", body: `{"expected_revision":1}`, status: 200, idempotent: true},
		{name: "restore organization", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/restore", body: `{"expected_revision":2}`, status: 200, idempotent: true},
		{name: "transfer owner", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/owner-transfer", body: `{"target_user_id":"` + fixture.memberID.String() + `","expected_organization_revision":1,"expected_owner_revision":1,"expected_target_revision":1,"confirmation":"transfer-organization-owner"}`, status: 200, idempotent: true},
		{name: "dissolve organization", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/dissolve", body: `{"display_name":"Acme","expected_revision":2,"confirmation":"dissolve-organization"}`, status: 200, idempotent: true},
		{name: "list members", method: http.MethodGet, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/members", status: 200},
		{name: "patch member", method: http.MethodPatch, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/members/" + fixture.memberID.String(), body: `{"role":"auditor","department_id":null,"expected_revision":1}`, status: 200},
		{name: "remove member", method: http.MethodDelete, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/members/" + fixture.memberID.String() + "?expected_revision=1", status: 204},
		{name: "leave organization", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/leave", body: `{}`, status: 204},
		{name: "list departments", method: http.MethodGet, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/departments", status: 200},
		{name: "create department", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/departments", body: `{"display_name":"Research"}`, status: 201},
		{name: "rename department", method: http.MethodPatch, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/departments/" + fixture.departmentID.String(), body: `{"display_name":"Labs","expected_revision":1}`, status: 200},
		{name: "archive department", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/departments/" + fixture.departmentID.String() + "/archive", body: `{"expected_revision":1}`, status: 200},
		{name: "restore department", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/departments/" + fixture.departmentID.String() + "/restore", body: `{"expected_revision":2}`, status: 200},
		{name: "list invitations", method: http.MethodGet, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/invitations", status: 200},
		{name: "create invitation", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/invitations", body: `{}`, status: 201, idempotent: true},
		{name: "revoke invitation", method: http.MethodDelete, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/invitations/" + fixture.invitationID.String(), status: 204},
		{name: "accept invitation", method: http.MethodPost, path: "/api/v1/organization-invitations/accept", body: `{"token":"` + fixture.rawToken + `"}`, status: 200, idempotent: true},
		{name: "current policy", method: http.MethodGet, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/policy", status: 200},
		{name: "policy history", method: http.MethodGet, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/policy-snapshots", status: 200},
		{name: "publish policy", method: http.MethodPost, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/policy-snapshots", body: validOrganizationPolicyPublicationBody(), status: 201, idempotent: true},
		{name: "policy detail", method: http.MethodGet, path: "/api/v1/organization-policy-snapshots/" + fixture.policyID.String(), status: 200},
		{name: "audit events", method: http.MethodGet, path: "/api/v1/organizations/" + fixture.organizationID.String() + "/audit-events", status: 200},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			response := fixture.request(t, route.method, route.path, route.body, route.idempotent)
			if response.Code != route.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), route.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
			if fixture.service.lastActor != fixture.actor {
				t.Fatalf("service actor = %+v", fixture.service.lastActor)
			}
			body := strings.ToLower(response.Body.String())
			for _, forbidden := range []string{"owner_scope", "runtime_binding", "profile_path", "memory.md", "user.md", "credential", "api_key", "session_id", "private_skill"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("response leaked %q: %s", forbidden, body)
				}
			}
			if route.name != "create invitation" && strings.Contains(body, fixture.rawToken) {
				t.Fatalf("response leaked invitation token: %s", body)
			}
		})
	}
	if fixture.authenticator.lastToken != "organization-access-token" {
		t.Fatalf("authenticated token = %q", fixture.authenticator.lastToken)
	}
}

func TestOrganizationHTTPRejectsAmbiguousInputBeforeService(t *testing.T) {
	fixture := newOrganizationHTTPFixture(t)
	tests := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
		keys        []string
		status      int
	}{
		{name: "unknown field", method: "POST", path: "/api/v1/organizations", body: `{"display_name":"A","unknown":true}`, contentType: "application/json", keys: []string{"key"}, status: 400},
		{name: "duplicate field", method: "POST", path: "/api/v1/organizations", body: `{"display_name":"A","display_name":"B"}`, contentType: "application/json", keys: []string{"key"}, status: 400},
		{name: "second value", method: "POST", path: "/api/v1/organizations", body: `{"display_name":"A"}{}`, contentType: "application/json", keys: []string{"key"}, status: 400},
		{name: "wrong content type", method: "POST", path: "/api/v1/organizations", body: `{"display_name":"A"}`, contentType: "text/plain", keys: []string{"key"}, status: 400},
		{name: "oversized body", method: "POST", path: "/api/v1/organizations", body: strings.Repeat(" ", maxOrganizationBodyBytes+1), contentType: "application/json", keys: []string{"key"}, status: 413},
		{name: "missing idempotency", method: "POST", path: "/api/v1/organizations", body: `{"display_name":"A"}`, contentType: "application/json", status: 400},
		{name: "duplicate idempotency", method: "POST", path: "/api/v1/organizations", body: `{"display_name":"A"}`, contentType: "application/json", keys: []string{"one", "two"}, status: 400},
		{name: "noncanonical UUID", method: "GET", path: "/api/v1/organizations/" + strings.ToUpper(fixture.organizationID.String()), status: 400},
		{name: "bad page limit", method: "GET", path: "/api/v1/organizations?limit=0", status: 400},
		{name: "extra query", method: "GET", path: "/api/v1/organizations?extra=1", status: 400},
		{name: "extra mutation query", method: "POST", path: "/api/v1/organizations?extra=1", body: `{"display_name":"A"}`, contentType: "application/json", keys: []string{"key"}, status: 400},
		{name: "bad cursor", method: "GET", path: "/api/v1/organizations?cursor=not-base64", status: 400},
		{name: "wrong owner confirmation", method: "POST", path: "/api/v1/organizations/" + fixture.organizationID.String() + "/owner-transfer", body: `{"target_user_id":"` + fixture.memberID.String() + `","expected_organization_revision":1,"expected_owner_revision":1,"expected_target_revision":1,"confirmation":"transfer"}`, contentType: "application/json", keys: []string{"key"}, status: 400},
		{name: "wrong dissolve confirmation", method: "POST", path: "/api/v1/organizations/" + fixture.organizationID.String() + "/dissolve", body: `{"display_name":"Acme","expected_revision":1,"confirmation":"delete"}`, contentType: "application/json", keys: []string{"key"}, status: 400},
		{name: "unknown policy key", method: "POST", path: "/api/v1/organizations/" + fixture.organizationID.String() + "/policy-snapshots", body: strings.Replace(validOrganizationPolicyPublicationBody(), `"tools":{"allowlist":null}`, `"tools":{"allowlist":null,"profile_path":"/private"}`, 1), contentType: "application/json", keys: []string{"key"}, status: 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture.service.calls = 0
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer organization-access-token")
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			for _, key := range test.keys {
				request.Header.Add("Idempotency-Key", key)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), test.status)
			}
			assertOrganizationError(t, response, "invalid_request")
			if fixture.service.calls != 0 {
				t.Fatalf("service calls after invalid input = %d", fixture.service.calls)
			}
		})
	}
}

func TestOrganizationHTTPRejectsInvalidBearerAndMapsStableErrors(t *testing.T) {
	fixture := newOrganizationHTTPFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/organizations", nil)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatalf("missing bearer response = %d %q", response.Code, response.Body.String())
	}
	assertOrganizationError(t, response, "authentication_required")

	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{ErrInvalidRequest, 400, "invalid_request"},
		{ErrSessionRevoked, 401, "authentication_required"},
		{ErrOrganizationForbidden, 403, "organization_forbidden"},
		{ErrOrganizationNotFound, 404, "organization_not_found"},
		{ErrInvitationUnavailable, 404, "invitation_unavailable"},
		{ErrOrganizationConflict, 409, "organization_conflict"},
		{ErrOrganizationArchived, 409, "organization_archived"},
		{ErrOrganizationLimitReached, 409, "organization_limit_reached"},
		{ErrOwnerTransferTargetInvalid, 409, "owner_transfer_target_invalid"},
		{ErrMembershipConflict, 409, "membership_conflict"},
		{ErrDepartmentNotEmpty, 409, "department_not_empty"},
		{ErrPolicyVersionConflict, 409, "policy_version_conflict"},
		{ErrIdempotencyConflict, 409, "idempotency_conflict"},
		{ErrDissolutionBlocked, 409, "dissolution_blocked"},
		{&RateLimitError{RetryAfter: 1500 * time.Millisecond}, 429, "rate_limited"},
		{errors.New("postgres://user:secret@private"), 503, "service_unavailable"},
	} {
		fixture.service.err = test.err
		response := fixture.request(t, http.MethodGet, "/api/v1/organizations", "", false)
		if response.Code != test.status {
			t.Fatalf("%s response = %d %q", test.code, response.Code, response.Body.String())
		}
		assertOrganizationError(t, response, test.code)
		if strings.Contains(response.Body.String(), "postgres") || strings.Contains(response.Body.String(), "secret") {
			t.Fatalf("internal error leaked: %s", response.Body.String())
		}
	}
}

func TestOrganizationHTTPAuthenticationFailsClosed(t *testing.T) {
	fixture := newOrganizationHTTPFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/organizations", nil)
	request.Header.Add("Authorization", "Bearer first")
	request.Header.Add("Authorization", "Bearer second")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate bearer response = %d %q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/organizations", nil)
	request.Header.Set("Authorization", "Bearer token with spaces")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("malformed bearer response = %d %q", response.Code, response.Body.String())
	}

	fixture.authenticator.err = session.ErrInvalidAccessToken
	response = fixture.request(t, http.MethodGet, "/api/v1/organizations", "", false)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid access response = %d %q", response.Code, response.Body.String())
	}

	fixture.authenticator.err = errors.New("authentication store unavailable")
	response = fixture.request(t, http.MethodGet, "/api/v1/organizations", "", false)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("dependency response = %d %q", response.Code, response.Body.String())
	}

	fixture.authenticator.err = nil
	fixture.authenticator.claims.PersonalSpaceID = uuid.Nil
	response = fixture.request(t, http.MethodGet, "/api/v1/organizations", "", false)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("incomplete claims response = %d %q", response.Code, response.Body.String())
	}
}

func TestOrganizationHTTPUsesOpaqueTypedKeysetCursor(t *testing.T) {
	fixture := newOrganizationHTTPFixture(t)
	fixture.service.organizationPage.Next = &PageCursor{ID: uuid.New()}
	first := fixture.request(t, http.MethodGet, "/api/v1/organizations?limit=1", "", false)
	var payload struct {
		NextCursor string `json:"next_cursor"`
	}
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &payload) != nil || payload.NextCursor == "" || strings.Contains(payload.NextCursor, "{") {
		t.Fatalf("first page = %d %q", first.Code, first.Body.String())
	}
	second := fixture.request(t, http.MethodGet, "/api/v1/organizations?limit=1&cursor="+payload.NextCursor, "", false)
	if second.Code != 200 || fixture.service.lastPage.After == nil || fixture.service.lastPage.After.ID != fixture.service.organizationPage.Next.ID {
		t.Fatalf("second page = %d %q page=%+v", second.Code, second.Body.String(), fixture.service.lastPage)
	}
}

func TestOrganizationHTTPInvitationSecretIsReturnedOnlyForAValidFreshCreation(t *testing.T) {
	fixture := newOrganizationHTTPFixture(t)
	path := "/api/v1/organizations/" + fixture.organizationID.String() + "/invitations"

	fixture.service.creation.Token = ""
	fixture.service.creation.InviteURL = ""
	replay := fixture.request(t, http.MethodPost, path, `{}`, true)
	if replay.Code != http.StatusOK || strings.Contains(replay.Body.String(), fixture.rawToken) {
		t.Fatalf("replay response = %d %q", replay.Code, replay.Body.String())
	}

	fixture.service.creation.Token = fixture.rawToken
	fixture.service.creation.InviteURL = "agentera://organization-invitation#different"
	invalid := fixture.request(t, http.MethodPost, path, `{}`, true)
	if invalid.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid secret response = %d %q", invalid.Code, invalid.Body.String())
	}
	assertOrganizationError(t, invalid, "service_unavailable")
}

func TestOrganizationHTTPPolicyProjectionUsesRawURLSignatureAndMemberSummary(t *testing.T) {
	fixture := newOrganizationHTTPFixture(t)
	path := "/api/v1/organizations/" + fixture.organizationID.String() + "/policy"
	full := fixture.request(t, http.MethodGet, path, "", false)
	if full.Code != http.StatusOK || !strings.Contains(full.Body.String(), `"signature":"`+base64.RawURLEncoding.EncodeToString(fixture.service.policy.Signature)+`"`) ||
		!strings.Contains(full.Body.String(), `"policy_document"`) {
		t.Fatalf("full policy response = %d %q", full.Code, full.Body.String())
	}

	fixture.service.policy.Signature = nil
	fixture.service.policy.Document = PolicyDocument{}
	summary := fixture.request(t, http.MethodGet, path, "", false)
	if summary.Code != http.StatusOK || strings.Contains(summary.Body.String(), `"signature"`) || strings.Contains(summary.Body.String(), `"policy_document"`) {
		t.Fatalf("member policy response = %d %q", summary.Code, summary.Body.String())
	}
}

func TestOrganizationHTTPMalformedLifecycleJSONWritesOneError(t *testing.T) {
	fixture := newOrganizationHTTPFixture(t)
	path := "/api/v1/organizations/" + fixture.organizationID.String() + "/archive"
	response := fixture.request(t, http.MethodPost, path, `{`, true)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
	if err := decoder.Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		t.Fatalf("response contains multiple JSON values: %q", response.Body.String())
	}
}

func validOrganizationPolicyPublicationBody() string {
	return `{"policy_document":{"schema_version":1,"models":{"allowlist":null},"tools":{"allowlist":null},"experience_candidates":{"mode":"manual_review"},"official_agents":{"installation":"allowed"}},"expected_organization_revision":1,"expected_policy_version":2}`
}

type organizationHTTPFixture struct {
	handler        http.Handler
	service        *fakeOrganizationHTTPService
	authenticator  *fakeOrganizationAccessAuthenticator
	actor          Actor
	organizationID uuid.UUID
	memberID       uuid.UUID
	departmentID   uuid.UUID
	invitationID   uuid.UUID
	policyID       uuid.UUID
	rawToken       string
}

func newOrganizationHTTPFixture(t *testing.T) *organizationHTTPFixture {
	t.Helper()
	actor := Actor{UserID: uuid.New(), DeviceID: uuid.New()}
	secret, err := NewInvitationSecret(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatalf("NewInvitationSecret() error = %v", err)
	}
	service := newFakeOrganizationHTTPService(secret)
	authenticator := &fakeOrganizationAccessAuthenticator{claims: session.AccessClaims{AccessBinding: session.AccessBinding{
		UserID: actor.UserID, DeviceID: actor.DeviceID, PersonalSpaceID: uuid.New(),
	}}}
	return &organizationHTTPFixture{
		handler: NewHandler(HTTPConfig{Service: service, AccessTokens: authenticator}),
		service: service, authenticator: authenticator, actor: actor,
		organizationID: service.organization.ID, memberID: service.member.UserID,
		departmentID: service.department.ID, invitationID: service.invitation.ID,
		policyID: service.policy.ID, rawToken: secret.RawToken,
	}
}

func (f *organizationHTTPFixture) request(t *testing.T, method, path, body string, idempotent bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer organization-access-token")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotent {
		request.Header.Set("Idempotency-Key", "organization-idempotency-key")
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

type fakeOrganizationAccessAuthenticator struct {
	claims    session.AccessClaims
	err       error
	lastToken string
}

func (f *fakeOrganizationAccessAuthenticator) Authenticate(_ context.Context, token string) (session.AccessClaims, error) {
	f.lastToken = token
	return f.claims, f.err
}

type fakeOrganizationHTTPService struct {
	err              error
	calls            int
	lastActor        Actor
	lastPage         Page
	organization     OrganizationSummary
	member           MemberSummary
	department       DepartmentSummary
	invitation       InvitationSummary
	policy           PolicySnapshot
	audit            AuditSummary
	creation         InvitationCreationResult
	organizationPage OrganizationPage
}

func newFakeOrganizationHTTPService(secret InvitationSecret) *fakeOrganizationHTTPService {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	digest := [32]byte{1}
	organization := OrganizationSummary{
		ID: uuid.New(), DisplayName: "Acme", Status: OrganizationStatusActive, Revision: 1, Role: RoleOwner,
		MemberCount: 2, DepartmentCount: 1, CurrentPolicyVersion: 1, CurrentPolicyDigest: digest,
		MutationState: MutationStateWritable, CreatedAt: now, UpdatedAt: now,
	}
	member := MemberSummary{UserID: uuid.New(), Role: RoleMember, Revision: 1, JoinedAt: now, UpdatedAt: now}
	department := DepartmentSummary{ID: uuid.New(), DisplayName: "Research", Status: DepartmentStatusActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	invitation := InvitationSummary{ID: uuid.New(), Status: InvitationStatusPending, CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour)}
	policy := PolicySnapshot{PolicySummary: PolicySummary{
		ID: uuid.New(), PolicyVersion: 1, SchemaVersion: 1, ContentDigest: digest,
		Issuer: "https://accounts.example", SigningKeyID: "organization-v1", CreatedAt: now,
	}, Document: DefaultPolicyDocument(), Signature: bytes.Repeat([]byte{1}, 64)}
	service := &fakeOrganizationHTTPService{
		organization: organization, member: member, department: department, invitation: invitation, policy: policy,
		audit: AuditSummary{ID: uuid.New(), EventType: "organization_created", ObjectType: "organization", Outcome: "success", RequestID: "request", CreatedAt: now},
	}
	service.creation = InvitationCreationResult{
		Invitation: invitation, Token: secret.RawToken, InviteURL: "agentera://organization-invitation#" + secret.RawToken,
	}
	service.organizationPage = OrganizationPage{Items: []OrganizationSummary{organization}}
	return service
}

func (f *fakeOrganizationHTTPService) called(actor Actor) error {
	f.calls++
	f.lastActor = actor
	return f.err
}
func (f *fakeOrganizationHTTPService) Create(_ context.Context, actor Actor, _ CreateOrganizationCommand) (OrganizationCreationResult, error) {
	return OrganizationCreationResult{Organization: f.organization}, f.called(actor)
}
func (f *fakeOrganizationHTTPService) List(_ context.Context, actor Actor, page Page) (OrganizationPage, error) {
	f.lastPage = page
	return f.organizationPage, f.called(actor)
}
func (f *fakeOrganizationHTTPService) Get(_ context.Context, actor Actor, _ uuid.UUID) (OrganizationSummary, error) {
	return f.organization, f.called(actor)
}
func (f *fakeOrganizationHTTPService) Rename(_ context.Context, actor Actor, _ RenameCommand) (OrganizationSummary, error) {
	return f.organization, f.called(actor)
}
func (f *fakeOrganizationHTTPService) Archive(_ context.Context, actor Actor, _ ArchiveCommand) (OrganizationSummary, error) {
	return f.organization, f.called(actor)
}
func (f *fakeOrganizationHTTPService) Restore(_ context.Context, actor Actor, _ RestoreCommand) (OrganizationSummary, error) {
	return f.organization, f.called(actor)
}
func (f *fakeOrganizationHTTPService) TransferOwner(_ context.Context, actor Actor, _ OwnerTransferCommand) (OrganizationSummary, error) {
	return f.organization, f.called(actor)
}
func (f *fakeOrganizationHTTPService) Dissolve(_ context.Context, actor Actor, _ DissolveCommand) (OrganizationSummary, error) {
	return f.organization, f.called(actor)
}
func (f *fakeOrganizationHTTPService) ListMembers(_ context.Context, actor Actor, _ uuid.UUID, page Page) (MemberPage, error) {
	f.lastPage = page
	return MemberPage{Items: []MemberSummary{f.member}}, f.called(actor)
}
func (f *fakeOrganizationHTTPService) PatchMember(_ context.Context, actor Actor, _ PatchMemberCommand) (MemberSummary, error) {
	return f.member, f.called(actor)
}
func (f *fakeOrganizationHTTPService) RemoveMember(_ context.Context, actor Actor, _ RemoveMemberCommand) error {
	return f.called(actor)
}
func (f *fakeOrganizationHTTPService) Leave(_ context.Context, actor Actor, _ LeaveCommand) error {
	return f.called(actor)
}
func (f *fakeOrganizationHTTPService) ListDepartments(_ context.Context, actor Actor, _ uuid.UUID, page Page) (DepartmentPage, error) {
	f.lastPage = page
	return DepartmentPage{Items: []DepartmentSummary{f.department}}, f.called(actor)
}
func (f *fakeOrganizationHTTPService) CreateDepartment(_ context.Context, actor Actor, _ CreateDepartmentCommand) (DepartmentSummary, error) {
	return f.department, f.called(actor)
}
func (f *fakeOrganizationHTTPService) RenameDepartment(_ context.Context, actor Actor, _ RenameDepartmentCommand) (DepartmentSummary, error) {
	return f.department, f.called(actor)
}
func (f *fakeOrganizationHTTPService) ArchiveDepartment(_ context.Context, actor Actor, _ DepartmentLifecycleCommand) (DepartmentSummary, error) {
	return f.department, f.called(actor)
}
func (f *fakeOrganizationHTTPService) RestoreDepartment(_ context.Context, actor Actor, _ DepartmentLifecycleCommand) (DepartmentSummary, error) {
	return f.department, f.called(actor)
}
func (f *fakeOrganizationHTTPService) ListInvitations(_ context.Context, actor Actor, _ uuid.UUID, page Page) (InvitationPage, error) {
	f.lastPage = page
	return InvitationPage{Items: []InvitationSummary{f.invitation}}, f.called(actor)
}
func (f *fakeOrganizationHTTPService) CreateInvitation(_ context.Context, actor Actor, _ CreateInvitationCommand) (InvitationCreationResult, error) {
	return f.creation, f.called(actor)
}
func (f *fakeOrganizationHTTPService) RevokeInvitation(_ context.Context, actor Actor, _ RevokeInvitationCommand) error {
	return f.called(actor)
}
func (f *fakeOrganizationHTTPService) AcceptInvitation(_ context.Context, actor Actor, _ AcceptInvitationCommand) (InvitationAcceptance, error) {
	return InvitationAcceptance{Organization: f.organization, Member: f.member}, f.called(actor)
}
func (f *fakeOrganizationHTTPService) GetCurrentPolicy(_ context.Context, actor Actor, _ uuid.UUID) (PolicySnapshot, error) {
	return f.policy, f.called(actor)
}
func (f *fakeOrganizationHTTPService) ListPolicySnapshots(_ context.Context, actor Actor, _ uuid.UUID, page Page) (PolicyPage, error) {
	f.lastPage = page
	return PolicyPage{Items: []PolicySummary{f.policy.PolicySummary}}, f.called(actor)
}
func (f *fakeOrganizationHTTPService) PublishPolicy(_ context.Context, actor Actor, _ PublishPolicyCommand) (PolicySnapshot, error) {
	return f.policy, f.called(actor)
}
func (f *fakeOrganizationHTTPService) GetPolicySnapshot(_ context.Context, actor Actor, _ uuid.UUID) (PolicySnapshot, error) {
	return f.policy, f.called(actor)
}
func (f *fakeOrganizationHTTPService) ListAudit(_ context.Context, actor Actor, _ uuid.UUID, page Page) (AuditPage, error) {
	f.lastPage = page
	return AuditPage{Items: []AuditSummary{f.audit}}, f.called(actor)
}

func assertOrganizationError(t *testing.T, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	var payload struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if json.Unmarshal(response.Body.Bytes(), &payload) != nil || payload.Error.Code != code || payload.Error.RequestID == "" {
		t.Fatalf("error response = %d %q", response.Code, response.Body.String())
	}
}
