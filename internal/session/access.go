package session

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	accessTokenLifetime      = 15 * time.Minute
	maximumAccessTokenLength = 8192
)

var ErrInvalidAccessToken = errors.New("access token is invalid or expired")

type AccessBinding struct {
	UserID          uuid.UUID
	SessionID       uuid.UUID
	DeviceID        uuid.UUID
	PersonalSpaceID uuid.UUID
}

type AccessClaims struct {
	AccessBinding
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type IssuedAccessToken struct {
	Serialized string
	ExpiresAt  time.Time
}

type AccessSignerConfig struct {
	Issuer           string
	Audience         string
	ActiveKeyID      string
	SigningKeys      map[string]ed25519.PrivateKey
	VerificationKeys map[string]ed25519.PublicKey
	Clock            func() time.Time
}

type AccessSigner struct {
	issuer       string
	audience     string
	activeKeyID  string
	signingKey   ed25519.PrivateKey
	verification map[string]ed25519.PublicKey
	clock        func() time.Time
}

type PublicSigningKey struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	X         string `json:"x"`
}

type accessHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type accessPayload struct {
	Issuer          string    `json:"iss"`
	Audience        string    `json:"aud"`
	UserID          uuid.UUID `json:"sub"`
	SessionID       uuid.UUID `json:"session_id"`
	DeviceID        uuid.UUID `json:"device_id"`
	PersonalSpaceID uuid.UUID `json:"personal_space_id"`
	IssuedAtUnix    int64     `json:"iat"`
	ExpiresAtUnix   int64     `json:"exp"`
}

func NewAccessSigner(config AccessSignerConfig) (*AccessSigner, error) {
	parsedIssuer, err := url.Parse(config.Issuer)
	if err != nil || parsedIssuer.Host == "" || (parsedIssuer.Scheme != "https" && parsedIssuer.Scheme != "http") ||
		strings.TrimSpace(config.Audience) == "" || strings.TrimSpace(config.ActiveKeyID) == "" {
		return nil, errors.New("access token configuration is invalid")
	}
	verification := make(map[string]ed25519.PublicKey, len(config.SigningKeys)+len(config.VerificationKeys))
	var active ed25519.PrivateKey
	for keyID, privateKey := range config.SigningKeys {
		if strings.TrimSpace(keyID) == "" || len(privateKey) != ed25519.PrivateKeySize {
			return nil, errors.New("access token signing key is invalid")
		}
		copied := append(ed25519.PrivateKey(nil), privateKey...)
		verification[keyID] = append(ed25519.PublicKey(nil), copied.Public().(ed25519.PublicKey)...)
		if keyID == config.ActiveKeyID {
			active = copied
		}
	}
	for keyID, publicKey := range config.VerificationKeys {
		if strings.TrimSpace(keyID) == "" || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("access token verification key is invalid")
		}
		verification[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	if len(active) != ed25519.PrivateKeySize || len(verification) == 0 {
		return nil, errors.New("active access token signing key is unavailable")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &AccessSigner{
		issuer: config.Issuer, audience: config.Audience, activeKeyID: config.ActiveKeyID,
		signingKey: active, verification: verification, clock: clock,
	}, nil
}

func (s *AccessSigner) Issue(binding AccessBinding) (IssuedAccessToken, error) {
	if s == nil || !validAccessBinding(binding) {
		return IssuedAccessToken{}, ErrInvalidAccessToken
	}
	issuedAt := s.clock().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(accessTokenLifetime)
	header, err := json.Marshal(accessHeader{Algorithm: "EdDSA", KeyID: s.activeKeyID, Type: "at+jwt"})
	if err != nil {
		return IssuedAccessToken{}, errors.New("access token could not be encoded")
	}
	payload, err := json.Marshal(accessPayload{
		Issuer: s.issuer, Audience: s.audience, UserID: binding.UserID, SessionID: binding.SessionID,
		DeviceID: binding.DeviceID, PersonalSpaceID: binding.PersonalSpaceID,
		IssuedAtUnix: issuedAt.Unix(), ExpiresAtUnix: expiresAt.Unix(),
	})
	if err != nil {
		return IssuedAccessToken{}, errors.New("access token could not be encoded")
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	signature := ed25519.Sign(s.signingKey, []byte(signingInput))
	return IssuedAccessToken{
		Serialized: signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), ExpiresAt: expiresAt,
	}, nil
}

func (s *AccessSigner) Verify(serialized string) (AccessClaims, error) {
	if s == nil || len(serialized) == 0 || len(serialized) > maximumAccessTokenLength || strings.Count(serialized, ".") != 2 {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	parts := strings.Split(serialized, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	var header accessHeader
	if !decodeAccessJSON(headerJSON, &header) || header.Algorithm != "EdDSA" || header.Type != "at+jwt" {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	publicKey, ok := s.verification[header.KeyID]
	if !ok {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	var payload accessPayload
	if !decodeAccessJSON(payloadJSON, &payload) {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	binding := AccessBinding{
		UserID: payload.UserID, SessionID: payload.SessionID,
		DeviceID: payload.DeviceID, PersonalSpaceID: payload.PersonalSpaceID,
	}
	issuedAt := time.Unix(payload.IssuedAtUnix, 0).UTC()
	expiresAt := time.Unix(payload.ExpiresAtUnix, 0).UTC()
	now := s.clock().UTC()
	if payload.Issuer != s.issuer || payload.Audience != s.audience || !validAccessBinding(binding) ||
		expiresAt.Sub(issuedAt) != accessTokenLifetime || now.Before(issuedAt.Add(-time.Minute)) || !now.Before(expiresAt) {
		return AccessClaims{}, ErrInvalidAccessToken
	}
	return AccessClaims{AccessBinding: binding, IssuedAt: issuedAt, ExpiresAt: expiresAt}, nil
}

func (s *AccessSigner) PublicKeys() []PublicSigningKey {
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

func validAccessBinding(binding AccessBinding) bool {
	return binding.UserID != uuid.Nil && binding.SessionID != uuid.Nil &&
		binding.DeviceID != uuid.Nil && binding.PersonalSpaceID != uuid.Nil
}

func decodeAccessJSON(encoded []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}
