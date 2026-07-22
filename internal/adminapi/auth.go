package adminapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
)

const (
	ScopeUsersRead      = "users:read"
	ScopeDevicesWrite   = "devices:write"
	ScopeSessionsWrite  = "sessions:write"
	ScopeAccountsWrite  = "accounts:write"
	ScopeOperationsRead = "operations:read"

	serviceJWTAudience       = "aera-cloud-admin"
	maximumServiceTokenBytes = 8192
	maximumServiceTokenLife  = 5 * time.Minute
	maximumServiceClockSkew  = 30 * time.Second
)

var (
	serviceIdentityPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)
	serviceJWTIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	allowedServiceScopes   = map[string]struct{}{
		ScopeUsersRead:      {},
		ScopeDevicesWrite:   {},
		ScopeSessionsWrite:  {},
		ScopeAccountsWrite:  {},
		ScopeOperationsRead: {},
	}
	errInvalidServiceAuthentication = errors.New("internal service authentication failed")
)

type AuthenticatorConfig struct {
	PublicKey ed25519.PublicKey
	Issuer    string
	Subject   string
	Clock     func() time.Time
}

type Authenticator struct {
	publicKey ed25519.PublicKey
	issuer    string
	subject   string
	clock     func() time.Time
}

type serviceJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type serviceJWTClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	Scopes    []string `json:"scope"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	JWTID     string   `json:"jti"`
}

func NewAuthenticator(config AuthenticatorConfig) (*Authenticator, error) {
	if len(config.PublicKey) != ed25519.PublicKeySize ||
		!serviceIdentityPattern.MatchString(config.Issuer) ||
		!serviceIdentityPattern.MatchString(config.Subject) || config.Clock == nil {
		return nil, errors.New("internal service authenticator configuration is invalid")
	}
	return &Authenticator{
		publicKey: append(ed25519.PublicKey(nil), config.PublicKey...),
		issuer:    config.Issuer, subject: config.Subject, clock: config.Clock,
	}, nil
}

func (a *Authenticator) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if a == nil || next == nil || !verifiedClientCertificate(request) {
				writeAuthenticationError(response, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
				return
			}
			claims, err := a.authenticate(request)
			if err != nil {
				writeAuthenticationError(response, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
				return
			}
			if _, allowed := allowedServiceScopes[scope]; !allowed || !containsScope(claims.Scopes, scope) {
				writeAuthenticationError(response, http.StatusForbidden, "PERMISSION_DENIED")
				return
			}
			ctx := admin.WithServiceSubject(request.Context(), claims.Subject)
			next.ServeHTTP(response, request.WithContext(ctx))
		})
	}
}

func (a *Authenticator) authenticate(request *http.Request) (serviceJWTClaims, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || len(token) > maximumServiceTokenBytes || strings.ContainsAny(token, " \t\r\n") {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	return a.verifyToken(token)
}

func (a *Authenticator) verifyToken(token string) (serviceJWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	headerJSON, ok := decodeCanonicalJWTPart(parts[0], 1024)
	if !ok {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	claimsJSON, ok := decodeCanonicalJWTPart(parts[1], 4096)
	if !ok {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	signature, ok := decodeCanonicalJWTPart(parts[2], ed25519.SignatureSize)
	if !ok || len(signature) != ed25519.SignatureSize {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	var header serviceJWTHeader
	if !decodeStrictJWTJSON(headerJSON, &header) || header.Algorithm != "EdDSA" || header.Type != "JWT" {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	if !ed25519.Verify(a.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	var claims serviceJWTClaims
	if !decodeStrictJWTJSON(claimsJSON, &claims) || !a.validClaims(claims) {
		return serviceJWTClaims{}, errInvalidServiceAuthentication
	}
	return claims, nil
}

func (a *Authenticator) validClaims(claims serviceJWTClaims) bool {
	if claims.Issuer != a.issuer || claims.Subject != a.subject || claims.Audience != serviceJWTAudience ||
		!serviceJWTIDPattern.MatchString(claims.JWTID) || len(claims.Scopes) == 0 ||
		len(claims.Scopes) > len(allowedServiceScopes) {
		return false
	}
	seen := make(map[string]struct{}, len(claims.Scopes))
	for _, scope := range claims.Scopes {
		if _, allowed := allowedServiceScopes[scope]; !allowed {
			return false
		}
		if _, duplicate := seen[scope]; duplicate {
			return false
		}
		seen[scope] = struct{}{}
	}

	maximumLifetimeSeconds := int64(maximumServiceTokenLife / time.Second)
	maximumSkewSeconds := int64(maximumServiceClockSkew / time.Second)
	if claims.IssuedAt <= 0 || claims.NotBefore <= 0 || claims.ExpiresAt <= 0 ||
		claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > maximumLifetimeSeconds ||
		claims.NotBefore < claims.IssuedAt-maximumSkewSeconds ||
		claims.NotBefore > claims.IssuedAt+maximumSkewSeconds {
		return false
	}
	now := a.clock().UTC().Unix()
	if now < claims.IssuedAt-maximumSkewSeconds || now < claims.NotBefore-maximumSkewSeconds ||
		now > claims.ExpiresAt+maximumSkewSeconds {
		return false
	}
	return true
}

func verifiedClientCertificate(request *http.Request) bool {
	if request == nil || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 ||
		len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	peer := request.TLS.PeerCertificates[0]
	verified := request.TLS.VerifiedChains[0][0]
	return peer != nil && verified != nil && peer.Equal(verified)
}

func decodeCanonicalJWTPart(encoded string, maximumBytes int) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > maximumBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, false
	}
	return decoded, true
}

func decodeStrictJWTJSON(raw []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func containsScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

func writeAuthenticationError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write([]byte(`{"error":{"code":"` + code + `"}}`))
}
