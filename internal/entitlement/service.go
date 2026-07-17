package entitlement

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	entitlementLifetime = 7 * 24 * time.Hour
	maximumTokenLength  = 8192
)

var (
	ErrInvalidEntitlement = errors.New("offline entitlement is invalid or expired")
	ErrUnavailable        = errors.New("offline entitlement service is unavailable")
)

type Binding struct {
	UserID          uuid.UUID
	DeviceID        uuid.UUID
	InstallationID  uuid.UUID
	PersonalSpaceID uuid.UUID
}

type Claims struct {
	JTI uuid.UUID
	Binding
	PolicyVersion int
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

type Issuance struct {
	JTI           uuid.UUID
	Binding       Binding
	SigningKeyID  string
	PolicyVersion int
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

type Issued struct {
	Serialized string
	ExpiresAt  time.Time
}

type PublicSigningKey struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	X         string `json:"x"`
}

type Repository interface {
	Record(context.Context, Issuance) error
	RecordInTx(context.Context, pgx.Tx, Issuance) error
}

type ServiceConfig struct {
	Repository       Repository
	Issuer           string
	Audience         string
	ActiveKeyID      string
	SigningKeys      map[string]ed25519.PrivateKey
	VerificationKeys map[string]ed25519.PublicKey
	PolicyVersion    int
	Clock            func() time.Time
}

type Service struct {
	repository    Repository
	issuer        string
	audience      string
	activeKeyID   string
	signingKey    ed25519.PrivateKey
	verification  map[string]ed25519.PublicKey
	policyVersion int
	clock         func() time.Time
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type tokenPayload struct {
	Issuer          string    `json:"iss"`
	Audience        string    `json:"aud"`
	JTI             uuid.UUID `json:"jti"`
	UserID          uuid.UUID `json:"sub"`
	DeviceID        uuid.UUID `json:"device_id"`
	InstallationID  uuid.UUID `json:"installation_id"`
	PersonalSpaceID uuid.UUID `json:"personal_space_id"`
	PolicyVersion   int       `json:"policy_version"`
	IssuedAtUnix    int64     `json:"iat"`
	ExpiresAtUnix   int64     `json:"exp"`
}

func NewService(config ServiceConfig) (*Service, error) {
	parsedIssuer, err := url.Parse(config.Issuer)
	if err != nil || parsedIssuer.Host == "" || (parsedIssuer.Scheme != "https" && parsedIssuer.Scheme != "http") ||
		strings.TrimSpace(config.Audience) == "" || strings.TrimSpace(config.ActiveKeyID) == "" ||
		config.Repository == nil || config.PolicyVersion <= 0 {
		return nil, errors.New("offline entitlement configuration is invalid")
	}
	verification := make(map[string]ed25519.PublicKey, len(config.SigningKeys)+len(config.VerificationKeys))
	var active ed25519.PrivateKey
	for keyID, privateKey := range config.SigningKeys {
		if strings.TrimSpace(keyID) == "" || len(privateKey) != ed25519.PrivateKeySize {
			return nil, errors.New("offline entitlement signing key is invalid")
		}
		copied := append(ed25519.PrivateKey(nil), privateKey...)
		verification[keyID] = append(ed25519.PublicKey(nil), copied.Public().(ed25519.PublicKey)...)
		if keyID == config.ActiveKeyID {
			active = copied
		}
	}
	for keyID, publicKey := range config.VerificationKeys {
		if strings.TrimSpace(keyID) == "" || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("offline entitlement verification key is invalid")
		}
		verification[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	if len(active) != ed25519.PrivateKeySize || len(verification) == 0 {
		return nil, errors.New("active offline entitlement signing key is unavailable")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		repository: config.Repository, issuer: config.Issuer, audience: config.Audience,
		activeKeyID: config.ActiveKeyID, signingKey: active, verification: verification,
		policyVersion: config.PolicyVersion, clock: clock,
	}, nil
}

func (s *Service) Issue(ctx context.Context, binding Binding) (Issued, error) {
	if s == nil {
		return Issued{}, ErrInvalidEntitlement
	}
	return s.issue(ctx, binding, s.repository.Record)
}

func (s *Service) IssueInTx(ctx context.Context, tx pgx.Tx, binding Binding) (Issued, error) {
	if s == nil || tx == nil {
		return Issued{}, ErrUnavailable
	}
	return s.issue(ctx, binding, func(ctx context.Context, issuance Issuance) error {
		return s.repository.RecordInTx(ctx, tx, issuance)
	})
}

func (s *Service) issue(
	ctx context.Context,
	binding Binding,
	record func(context.Context, Issuance) error,
) (Issued, error) {
	if s == nil || !validBinding(binding) {
		return Issued{}, ErrInvalidEntitlement
	}
	jti, err := secure.RandomUUID()
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	issuedAt := s.clock().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(entitlementLifetime)
	header, err := json.Marshal(tokenHeader{Algorithm: "EdDSA", KeyID: s.activeKeyID, Type: "agentera-offline-entitlement+jwt"})
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	payload, err := json.Marshal(tokenPayload{
		Issuer: s.issuer, Audience: s.audience, JTI: jti, UserID: binding.UserID,
		DeviceID: binding.DeviceID, InstallationID: binding.InstallationID, PersonalSpaceID: binding.PersonalSpaceID,
		PolicyVersion: s.policyVersion, IssuedAtUnix: issuedAt.Unix(), ExpiresAtUnix: expiresAt.Unix(),
	})
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	signature := ed25519.Sign(s.signingKey, []byte(signingInput))
	serialized := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	issuance := Issuance{
		JTI: jti, Binding: binding, SigningKeyID: s.activeKeyID, PolicyVersion: s.policyVersion,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
	if err := record(ctx, issuance); err != nil {
		return Issued{}, ErrUnavailable
	}
	return Issued{Serialized: serialized, ExpiresAt: expiresAt}, nil
}

func (s *Service) Verify(serialized string) (Claims, error) {
	if s == nil || len(serialized) == 0 || len(serialized) > maximumTokenLength || strings.Count(serialized, ".") != 2 {
		return Claims{}, ErrInvalidEntitlement
	}
	parts := strings.Split(serialized, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidEntitlement
	}
	var header tokenHeader
	if !decodeStrict(headerJSON, &header) || header.Algorithm != "EdDSA" || header.Type != "agentera-offline-entitlement+jwt" {
		return Claims{}, ErrInvalidEntitlement
	}
	publicKey, ok := s.verification[header.KeyID]
	if !ok {
		return Claims{}, ErrInvalidEntitlement
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, ErrInvalidEntitlement
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidEntitlement
	}
	var payload tokenPayload
	if !decodeStrict(payloadJSON, &payload) {
		return Claims{}, ErrInvalidEntitlement
	}
	issuedAt := time.Unix(payload.IssuedAtUnix, 0).UTC()
	expiresAt := time.Unix(payload.ExpiresAtUnix, 0).UTC()
	binding := Binding{
		UserID: payload.UserID, DeviceID: payload.DeviceID,
		InstallationID: payload.InstallationID, PersonalSpaceID: payload.PersonalSpaceID,
	}
	now := s.clock().UTC()
	if payload.Issuer != s.issuer || payload.Audience != s.audience || payload.JTI == uuid.Nil || !validBinding(binding) ||
		payload.PolicyVersion <= 0 || expiresAt.Sub(issuedAt) != entitlementLifetime ||
		now.Before(issuedAt.Add(-time.Minute)) || !now.Before(expiresAt) {
		return Claims{}, ErrInvalidEntitlement
	}
	return Claims{
		JTI: payload.JTI, Binding: binding, PolicyVersion: payload.PolicyVersion,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) PublicKeys() []PublicSigningKey {
	if s == nil {
		return nil
	}
	keyIDs := make([]string, 0, len(s.verification))
	for keyID := range s.verification {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	keys := make([]PublicSigningKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		keys = append(keys, PublicSigningKey{
			KeyID: keyID, KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig",
			X: base64.RawURLEncoding.EncodeToString(s.verification[keyID]),
		})
	}
	return keys
}

func validBinding(binding Binding) bool {
	return binding.UserID != uuid.Nil && binding.DeviceID != uuid.Nil &&
		binding.InstallationID != uuid.Nil && binding.PersonalSpaceID != uuid.Nil
}

func decodeStrict(encoded []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}
