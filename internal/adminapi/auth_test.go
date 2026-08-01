package adminapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/google/uuid"
)

var (
	authAdminID     = uuid.MustParse("019f0000-0000-7000-8000-000000000201")
	authOperationID = uuid.MustParse("019f0000-0000-7000-8000-000000000202")
	authApprovalID  = uuid.MustParse("019f0000-0000-7000-8000-000000000203")
	authRequesterID = uuid.MustParse("019f0000-0000-7000-8000-000000000204")
)

func TestRequireScopeJWTFailureMatrix(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(AuthenticatorConfig{
		PublicKey: publicKey, Issuer: "aera-admin", Subject: "aera-admin-e2e",
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || len(otherPublic) == 0 {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		token func() string
		want  int
	}{
		{name: "valid", token: func() string { return signServiceToken(t, privateKey, validServiceHeader(), validServiceClaims(now)) }, want: http.StatusNoContent},
		{name: "missing bearer", token: func() string { return "" }, want: http.StatusUnauthorized},
		{name: "malformed segments", token: func() string { return "abc.def" }, want: http.StatusUnauthorized},
		{name: "malformed base64", token: func() string { return "abc+.def.ghi" }, want: http.StatusUnauthorized},
		{name: "wrong alg", token: func() string {
			header := validServiceHeader()
			header["alg"] = "HS256"
			return signServiceToken(t, privateKey, header, validServiceClaims(now))
		}, want: http.StatusUnauthorized},
		{name: "wrong type", token: func() string {
			header := validServiceHeader()
			header["typ"] = "at+jwt"
			return signServiceToken(t, privateKey, header, validServiceClaims(now))
		}, want: http.StatusUnauthorized},
		{name: "unknown header", token: func() string {
			header := validServiceHeader()
			header["kid"] = "unexpected"
			return signServiceToken(t, privateKey, header, validServiceClaims(now))
		}, want: http.StatusUnauthorized},
		{name: "wrong signature", token: func() string { return signServiceToken(t, otherPrivate, validServiceHeader(), validServiceClaims(now)) }, want: http.StatusUnauthorized},
		{name: "unknown claim", token: func() string {
			claims := validServiceClaims(now)
			claims["email"] = "raw.identity.canary@example.test"
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "wrong issuer", token: func() string {
			claims := validServiceClaims(now)
			claims["iss"] = "other-admin"
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "wrong subject", token: func() string {
			claims := validServiceClaims(now)
			claims["sub"] = "other-bff"
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "wrong audience", token: func() string {
			claims := validServiceClaims(now)
			claims["aud"] = "other-service"
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "future issued at", token: func() string {
			claims := validServiceClaims(now)
			claims["iat"] = now.Add(31 * time.Second).Unix()
			claims["nbf"] = now.Unix()
			claims["exp"] = now.Add(5 * time.Minute).Unix()
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "future not before", token: func() string {
			claims := validServiceClaims(now)
			claims["nbf"] = now.Add(31 * time.Second).Unix()
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "expired", token: func() string {
			claims := validServiceClaims(now)
			claims["iat"] = now.Add(-5 * time.Minute).Unix()
			claims["nbf"] = now.Add(-5 * time.Minute).Unix()
			claims["exp"] = now.Add(-31 * time.Second).Unix()
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "lifetime over five minutes", token: func() string {
			claims := validServiceClaims(now)
			claims["exp"] = now.Add(5*time.Minute + time.Second).Unix()
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "missing scope", token: func() string {
			claims := validServiceClaims(now)
			delete(claims, "scope")
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "empty scope", token: func() string {
			claims := validServiceClaims(now)
			claims["scope"] = []string{}
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "duplicate scope", token: func() string {
			claims := validServiceClaims(now)
			claims["scope"] = []string{ScopeUsersRead, ScopeUsersRead}
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "unknown scope", token: func() string {
			claims := validServiceClaims(now)
			claims["scope"] = []string{ScopeUsersRead, "root:all"}
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "empty jwt id", token: func() string {
			claims := validServiceClaims(now)
			claims["jti"] = ""
			return signServiceToken(t, privateKey, validServiceHeader(), claims)
		}, want: http.StatusUnauthorized},
		{name: "oversized token", token: func() string { return strings.Repeat("A", 8193) }, want: http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := auth.RequireScope(ScopeUsersRead)(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				called = true
				subject, ok := admin.ServiceSubject(request.Context())
				if !ok || subject != "aera-admin-e2e" {
					t.Fatalf("service subject = %q / %t", subject, ok)
				}
				response.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(http.MethodGet, "https://cloud.test/internal/admin/v1/users", nil)
			setVerifiedClientCertificate(request)
			if token := test.token(); token != "" {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.want, response.Body.String())
			}
			if called != (test.want == http.StatusNoContent) {
				t.Fatalf("handler called = %t", called)
			}
			if strings.Contains(response.Body.String(), "raw.identity.canary@example.test") {
				t.Fatal("authentication response leaked a claim")
			}
		})
	}
}

func TestRequireScopeAlsoRequiresVerifiedClientCertificate(t *testing.T) {
	auth, privateKey, now := newTestAuthenticator(t)
	handler := auth.RequireScope(ScopeUsersRead)(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "https://cloud.test/internal/admin/v1/health", nil)
	request.Header.Set("Authorization", "Bearer "+signServiceToken(t, privateKey, validServiceHeader(), validServiceClaims(now)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestRequireScopeRejectsMissingPermissionAndAmbiguousAuthorization(t *testing.T) {
	auth, privateKey, now := newTestAuthenticator(t)
	token := signServiceToken(t, privateKey, validServiceHeader(), validServiceClaims(now))

	t.Run("missing permission", func(t *testing.T) {
		handler := auth.RequireScope(ScopeAccountsWrite)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler called")
		}))
		request := httptest.NewRequest(http.MethodPost, "https://cloud.test/internal/admin/v1/users/id/disable", nil)
		setVerifiedClientCertificate(request)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
		}
	})

	t.Run("multiple authorization headers", func(t *testing.T) {
		handler := auth.RequireScope(ScopeUsersRead)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler called")
		}))
		request := httptest.NewRequest(http.MethodGet, "https://cloud.test/internal/admin/v1/users", nil)
		setVerifiedClientCertificate(request)
		request.Header.Add("Authorization", "Bearer "+token)
		request.Header.Add("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
		}
	})
}

func TestRequireOfficialScopeBindsSignedActorAndOperationClaims(t *testing.T) {
	auth, privateKey, now := newTestAuthenticator(t)
	tests := []struct {
		name      string
		claims    func() map[string]any
		mode      OfficialActorRequirement
		want      int
		wantActor bool
		wantRole  string
	}{
		{
			name: "read actor", mode: OfficialActorRead, want: http.StatusNoContent, wantActor: true,
			claims: func() map[string]any { return validOfficialServiceClaims(now, ScopeOfficialAgentsRead, false, false) },
		},
		{
			name: "mutation actor", mode: OfficialActorMutation, want: http.StatusNoContent, wantActor: true,
			claims: func() map[string]any { return validOfficialServiceClaims(now, ScopeOfficialDraftsWrite, true, false) },
		},
		{
			name: "rollback actor", mode: OfficialActorRollback, want: http.StatusNoContent, wantActor: true, wantRole: "super_admin",
			claims: func() map[string]any {
				claims := validOfficialServiceClaims(now, ScopeOfficialReleaseWrite, true, true)
				claims["admin_role"] = "super_admin"
				return claims
			},
		},
		{
			name: "service only token", mode: OfficialActorRead, want: http.StatusUnauthorized,
			claims: func() map[string]any {
				claims := validServiceClaims(now)
				claims["scope"] = []string{ScopeOfficialAgentsRead}
				return claims
			},
		},
		{
			name: "missing mutation operation", mode: OfficialActorMutation, want: http.StatusUnauthorized,
			claims: func() map[string]any { return validOfficialServiceClaims(now, ScopeOfficialDraftsWrite, false, false) },
		},
		{
			name: "wrong official scope", mode: OfficialActorMutation, want: http.StatusForbidden,
			claims: func() map[string]any { return validOfficialServiceClaims(now, ScopeOfficialAgentsRead, true, false) },
		},
		{
			name: "missing rollback approval", mode: OfficialActorRollback, want: http.StatusUnauthorized,
			claims: func() map[string]any { return validOfficialServiceClaims(now, ScopeOfficialReleaseWrite, true, false) },
		},
		{
			name: "invalid role", mode: OfficialActorRead, want: http.StatusUnauthorized,
			claims: func() map[string]any {
				claims := validOfficialServiceClaims(now, ScopeOfficialAgentsRead, false, false)
				claims["admin_role"] = "root"
				return claims
			},
		},
		{
			name: "noncanonical admin uuid", mode: OfficialActorRead, want: http.StatusUnauthorized,
			claims: func() map[string]any {
				claims := validOfficialServiceClaims(now, ScopeOfficialAgentsRead, false, false)
				claims["admin_id"] = strings.ToUpper(authAdminID.String())
				return claims
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wantRole := test.wantRole
			if wantRole == "" {
				wantRole = "developer"
			}
			called := false
			scope := ScopeOfficialAgentsRead
			if test.mode == OfficialActorMutation {
				scope = ScopeOfficialDraftsWrite
			}
			if test.mode == OfficialActorRollback {
				scope = ScopeOfficialReleaseWrite
			}
			handler := auth.RequireOfficialScope(scope, test.mode)(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				called = true
				actor, ok := OfficialActorFromContext(request.Context())
				if !ok || actor.AdminID != authAdminID || actor.Role != wantRole {
					t.Fatalf("actor = %+v / %t", actor, ok)
				}
				if test.mode != OfficialActorRead && actor.OperationID != authOperationID {
					t.Fatalf("operation = %s", actor.OperationID)
				}
				if test.mode == OfficialActorRollback && (actor.ApprovalID != authApprovalID || actor.RequesterAdminID != authRequesterID) {
					t.Fatalf("rollback evidence = %+v", actor)
				}
				response.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(http.MethodGet, "https://cloud.test/internal/admin/v1/official-agent-definitions", nil)
			setVerifiedClientCertificate(request)
			request.Header.Set("Authorization", "Bearer "+signServiceToken(t, privateKey, validServiceHeader(), test.claims()))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || called != test.wantActor {
				t.Fatalf("status/called = %d/%t, want %d/%t; body=%s", response.Code, called, test.want, test.wantActor, response.Body.String())
			}
		})
	}
}

func TestRequireOfficialScopeBindsCloudScopesToRealActorDuties(t *testing.T) {
	auth, privateKey, now := newTestAuthenticator(t)
	tests := []struct {
		name        string
		role        string
		scope       string
		requirement OfficialActorRequirement
		want        int
	}{
		{name: "developer draft", role: "developer", scope: ScopeOfficialDraftsWrite, requirement: OfficialActorMutation, want: http.StatusNoContent},
		{name: "super admin review", role: "super_admin", scope: ScopeOfficialReviewsWrite, requirement: OfficialActorMutation, want: http.StatusNoContent},
		{name: "operator release", role: "operator", scope: ScopeOfficialReleaseWrite, requirement: OfficialActorMutation, want: http.StatusNoContent},
		{name: "super admin rollback", role: "super_admin", scope: ScopeOfficialReleaseWrite, requirement: OfficialActorRollback, want: http.StatusNoContent},
		{name: "auditor official read", role: "auditor", scope: ScopeOfficialAgentsRead, requirement: OfficialActorRead, want: http.StatusNoContent},
		{name: "auditor audit read", role: "auditor", scope: ScopeOfficialAuditRead, requirement: OfficialActorRead, want: http.StatusNoContent},
		{name: "developer cannot review", role: "developer", scope: ScopeOfficialReviewsWrite, requirement: OfficialActorMutation, want: http.StatusForbidden},
		{name: "operator cannot draft", role: "operator", scope: ScopeOfficialDraftsWrite, requirement: OfficialActorMutation, want: http.StatusForbidden},
		{name: "super admin cannot publish", role: "super_admin", scope: ScopeOfficialReleaseWrite, requirement: OfficialActorMutation, want: http.StatusForbidden},
		{name: "operator cannot rollback", role: "operator", scope: ScopeOfficialReleaseWrite, requirement: OfficialActorRollback, want: http.StatusForbidden},
		{name: "developer cannot attach rollback evidence to draft", role: "developer", scope: ScopeOfficialDraftsWrite, requirement: OfficialActorRollback, want: http.StatusForbidden},
		{name: "auditor cannot mutate", role: "auditor", scope: ScopeOfficialDraftsWrite, requirement: OfficialActorMutation, want: http.StatusForbidden},
		{name: "developer cannot read audit", role: "developer", scope: ScopeOfficialAuditRead, requirement: OfficialActorRead, want: http.StatusForbidden},
		{name: "finance cannot read official agents", role: "finance", scope: ScopeOfficialAgentsRead, requirement: OfficialActorRead, want: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := auth.RequireOfficialScope(test.scope, test.requirement)(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				called = true
				actor, ok := OfficialActorFromContext(request.Context())
				if !ok || actor.Role != test.role {
					t.Fatalf("actor = %+v / %t", actor, ok)
				}
				response.WriteHeader(http.StatusNoContent)
			}))
			claims := validOfficialServiceClaims(now, test.scope, test.requirement != OfficialActorRead, test.requirement == OfficialActorRollback)
			claims["admin_role"] = test.role
			request := httptest.NewRequest(http.MethodPost, "https://cloud.test/internal/admin/v1/official-agent-duty-check", nil)
			setVerifiedClientCertificate(request)
			request.Header.Set("Authorization", "Bearer "+signServiceToken(t, privateKey, validServiceHeader(), claims))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || called != (test.want == http.StatusNoContent) {
				t.Fatalf("status/called = %d/%t, want %d/%t; body=%s", response.Code, called, test.want, test.want == http.StatusNoContent, response.Body.String())
			}
		})
	}
}

func TestOfficialActorFromContextRejectsMissingOrPartialValues(t *testing.T) {
	if _, ok := OfficialActorFromContext(context.Background()); ok {
		t.Fatal("empty context returned an actor")
	}
}

func TestNewAuthenticatorRejectsInvalidConfiguration(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []AuthenticatorConfig{
		{Issuer: "aera-admin", Subject: "aera-admin-e2e", Clock: time.Now},
		{PublicKey: publicKey, Issuer: "bad issuer", Subject: "aera-admin-e2e", Clock: time.Now},
		{PublicKey: publicKey, Issuer: "aera-admin", Subject: "bad subject", Clock: time.Now},
		{PublicKey: publicKey, Issuer: "aera-admin", Subject: "aera-admin-e2e"},
	}
	for index, config := range tests {
		if _, err := NewAuthenticator(config); err == nil {
			t.Fatalf("config %d was accepted", index)
		}
	}
}

func newTestAuthenticator(t *testing.T) (*Authenticator, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(AuthenticatorConfig{
		PublicKey: publicKey, Issuer: "aera-admin", Subject: "aera-admin-e2e",
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth, privateKey, now
}

func validServiceHeader() map[string]any {
	return map[string]any{"alg": "EdDSA", "typ": "JWT"}
}

func validServiceClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "aera-admin", "sub": "aera-admin-e2e", "aud": "aera-cloud-admin",
		"scope": []string{ScopeUsersRead}, "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "jti": "019f0000000070008000000000000001",
	}
}

func validOfficialServiceClaims(now time.Time, scope string, mutation, rollback bool) map[string]any {
	claims := validServiceClaims(now)
	claims["scope"] = []string{scope}
	claims["admin_id"] = authAdminID.String()
	claims["admin_role"] = "developer"
	if mutation {
		claims["operation_id"] = authOperationID.String()
	}
	if rollback {
		claims["approval_id"] = authApprovalID.String()
		claims["requester_admin_id"] = authRequesterID.String()
	}
	return claims
}

func signServiceToken(t *testing.T, privateKey ed25519.PrivateKey, header, claims any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := ed25519.Sign(privateKey, []byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func setVerifiedClientCertificate(request *http.Request) {
	certificate := &x509.Certificate{Raw: []byte{1, 2, 3}}
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
}
