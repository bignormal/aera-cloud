package adminapi

import (
	"bytes"
	"context"
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
	"github.com/google/uuid"
)

const (
	ScopeUsersRead              = "users:read"
	ScopeDevicesWrite           = "devices:write"
	ScopeSessionsWrite          = "sessions:write"
	ScopeAccountsWrite          = "accounts:write"
	ScopeOperationsRead         = "operations:read"
	ScopeOfficialAgentsRead     = "official_agents:read"
	ScopeOfficialDraftsWrite    = "official_agent_drafts:write"
	ScopeOfficialReviewsWrite   = "official_agent_reviews:write"
	ScopeOfficialReleaseWrite   = "official_agent_releases:write"
	ScopeOfficialAuditRead      = "official_agent_audit:read"
	ScopeOfficialQualityRead    = "official_quality:read"
	ScopeOfficialQualityPropose = "official_quality:propose"
	ScopeOfficialQualityReview  = "official_quality:review"
	ScopeOfficialQualityClone   = "official_quality:clone"

	serviceJWTAudience       = "aera-cloud-admin"
	maximumServiceTokenBytes = 8192
	maximumServiceTokenLife  = 5 * time.Minute
	maximumServiceClockSkew  = 30 * time.Second
)

var (
	serviceIdentityPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)
	serviceJWTIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	allowedServiceScopes   = map[string]struct{}{
		ScopeUsersRead:              {},
		ScopeDevicesWrite:           {},
		ScopeSessionsWrite:          {},
		ScopeAccountsWrite:          {},
		ScopeOperationsRead:         {},
		ScopeOfficialAgentsRead:     {},
		ScopeOfficialDraftsWrite:    {},
		ScopeOfficialReviewsWrite:   {},
		ScopeOfficialReleaseWrite:   {},
		ScopeOfficialAuditRead:      {},
		ScopeOfficialQualityRead:    {},
		ScopeOfficialQualityPropose: {},
		ScopeOfficialQualityReview:  {},
		ScopeOfficialQualityClone:   {},
	}
	allowedOfficialRoles = map[string]struct{}{
		"super_admin": {}, "developer": {}, "operator": {},
		"support": {}, "finance": {}, "auditor": {},
	}
	errInvalidServiceAuthentication = errors.New("internal service authentication failed")
)

type officialActorContextKey struct{}

type OfficialActorRequirement uint8

const (
	OfficialActorRead OfficialActorRequirement = iota + 1
	OfficialActorMutation
	OfficialActorRollback
)

type VerifiedOfficialActor struct {
	AdminID          uuid.UUID
	Role             string
	OperationID      uuid.UUID
	ApprovalID       uuid.UUID
	RequesterAdminID uuid.UUID
}

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
	ServiceActorClaims
}

type ServiceActorClaims struct {
	AdminID          string `json:"admin_id,omitempty"`
	Role             string `json:"admin_role,omitempty"`
	OperationID      string `json:"operation_id,omitempty"`
	ApprovalID       string `json:"approval_id,omitempty"`
	RequesterAdminID string `json:"requester_admin_id,omitempty"`
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
		return a.require(next, scope, 0)
	}
}

func (a *Authenticator) RequireOfficialScope(
	scope string,
	requirement OfficialActorRequirement,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return a.require(next, scope, requirement)
	}
}

func (a *Authenticator) RequireAuthentication(next http.Handler) http.Handler {
	return a.require(next, "", 0)
}

func (a *Authenticator) require(next http.Handler, scope string, requirement OfficialActorRequirement) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if a == nil || next == nil || !verifiedClientCertificate(request) {
			writeAuthenticationError(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
			return
		}
		claims, err := a.authenticate(request)
		if err != nil {
			writeAuthenticationError(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
			return
		}
		if scope != "" {
			if _, allowed := allowedServiceScopes[scope]; !allowed || !containsScope(claims.Scopes, scope) {
				writeAuthenticationError(response, request, http.StatusForbidden, "PERMISSION_DENIED")
				return
			}
		}
		actor, hasActor := officialActorFromClaims(claims)
		if requirement != 0 && (!hasActor || !actorSatisfies(actor, requirement)) {
			writeAuthenticationError(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
			return
		}
		if requirement != 0 && !officialActorHasDuty(actor.Role, scope, requirement) {
			writeAuthenticationError(response, request, http.StatusForbidden, "PERMISSION_DENIED")
			return
		}
		ctx := admin.WithServiceSubject(request.Context(), claims.Subject)
		if hasActor {
			ctx = contextWithOfficialActor(ctx, actor)
		}
		next.ServeHTTP(response, request.WithContext(ctx))
	})
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
	if !validOptionalOfficialActorClaims(claims) {
		return false
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

func validOptionalOfficialActorClaims(claims serviceJWTClaims) bool {
	hasAny := claims.AdminID != "" || claims.Role != "" || claims.OperationID != "" ||
		claims.ApprovalID != "" || claims.RequesterAdminID != ""
	if !hasAny {
		return true
	}
	actor, ok := officialActorFromClaims(claims)
	if !ok {
		return false
	}
	if actor.OperationID == uuid.Nil {
		return actor.ApprovalID == uuid.Nil && actor.RequesterAdminID == uuid.Nil
	}
	return (actor.ApprovalID == uuid.Nil) == (actor.RequesterAdminID == uuid.Nil)
}

func officialActorFromClaims(claims serviceJWTClaims) (VerifiedOfficialActor, bool) {
	adminID, ok := parseCanonicalUUID(claims.AdminID)
	if !ok {
		return VerifiedOfficialActor{}, false
	}
	if _, ok := allowedOfficialRoles[claims.Role]; !ok {
		return VerifiedOfficialActor{}, false
	}
	actor := VerifiedOfficialActor{AdminID: adminID, Role: claims.Role}
	values := []struct {
		value  string
		target *uuid.UUID
	}{
		{claims.OperationID, &actor.OperationID},
		{claims.ApprovalID, &actor.ApprovalID},
		{claims.RequesterAdminID, &actor.RequesterAdminID},
	}
	for _, candidate := range values {
		if candidate.value == "" {
			continue
		}
		parsed, valid := parseCanonicalUUID(candidate.value)
		if !valid {
			return VerifiedOfficialActor{}, false
		}
		*candidate.target = parsed
	}
	return actor, true
}

func actorSatisfies(actor VerifiedOfficialActor, requirement OfficialActorRequirement) bool {
	switch requirement {
	case OfficialActorRead:
		return actor.OperationID == uuid.Nil && actor.ApprovalID == uuid.Nil && actor.RequesterAdminID == uuid.Nil
	case OfficialActorMutation:
		return actor.OperationID != uuid.Nil && actor.ApprovalID == uuid.Nil && actor.RequesterAdminID == uuid.Nil
	case OfficialActorRollback:
		return actor.OperationID != uuid.Nil && actor.ApprovalID != uuid.Nil && actor.RequesterAdminID != uuid.Nil &&
			actor.AdminID != actor.RequesterAdminID
	default:
		return false
	}
}

func officialActorHasDuty(role, scope string, requirement OfficialActorRequirement) bool {
	switch scope {
	case ScopeOfficialAgentsRead:
		return requirement == OfficialActorRead &&
			(role == "developer" || role == "operator" || role == "super_admin" || role == "auditor")
	case ScopeOfficialDraftsWrite:
		return role == "developer" &&
			(requirement == OfficialActorRead || requirement == OfficialActorMutation)
	case ScopeOfficialReviewsWrite:
		return requirement == OfficialActorMutation && role == "super_admin"
	case ScopeOfficialReleaseWrite:
		if requirement == OfficialActorRollback {
			return role == "super_admin"
		}
		return requirement == OfficialActorMutation && role == "operator"
	case ScopeOfficialAuditRead:
		return requirement == OfficialActorRead && (role == "super_admin" || role == "auditor")
	default:
		// Official quality has its own domain-level role checks. Keep those scopes
		// unchanged while this guard binds only the official Agent contract.
		return true
	}
}

func parseCanonicalUUID(value string) (uuid.UUID, bool) {
	parsed, err := uuid.Parse(value)
	return parsed, err == nil && parsed != uuid.Nil && parsed.String() == value
}

func contextWithOfficialActor(ctx context.Context, actor VerifiedOfficialActor) context.Context {
	return context.WithValue(ctx, officialActorContextKey{}, actor)
}

func OfficialActorFromContext(ctx context.Context) (VerifiedOfficialActor, bool) {
	if ctx == nil {
		return VerifiedOfficialActor{}, false
	}
	actor, ok := ctx.Value(officialActorContextKey{}).(VerifiedOfficialActor)
	return actor, ok && actor.AdminID != uuid.Nil
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

func writeAuthenticationError(response http.ResponseWriter, request *http.Request, status int, code string) {
	writeErrorResponse(response, request, status, code)
}
