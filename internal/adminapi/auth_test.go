package adminapi

import (
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
