package verification

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
)

const (
	receiptLifetime           = 10 * time.Minute
	maximumReceiptTokenLength = 8192
)

var ErrInvalidReceipt = errors.New("verification receipt is invalid or expired")

type ReceiptCodecConfig struct {
	IdentityCodec      *secure.IdentityCodec
	ActiveSigningKeyID string
	SigningKeys        map[string][]byte
	Clock              func() time.Time
}

type ReceiptClaims struct {
	ChallengeID        uuid.UUID
	Kind               secure.IdentityKind
	NormalizedIdentity string
	Purpose            Purpose
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

type ReceiptCodec struct {
	identityCodec      *secure.IdentityCodec
	activeSigningKeyID string
	signingKeys        map[string][]byte
	clock              func() time.Time
}

type receiptPayload struct {
	Version         int                 `json:"v"`
	SigningKeyID    string              `json:"kid"`
	ChallengeID     uuid.UUID           `json:"challenge_id"`
	Kind            secure.IdentityKind `json:"kind"`
	Purpose         Purpose             `json:"purpose"`
	EncryptionKeyID string              `json:"enc_kid"`
	Nonce           []byte              `json:"nonce"`
	Ciphertext      []byte              `json:"ciphertext"`
	IssuedAtUnix    int64               `json:"iat"`
	ExpiresAtUnix   int64               `json:"exp"`
}

func NewReceiptCodec(config ReceiptCodecConfig) (*ReceiptCodec, error) {
	if config.IdentityCodec == nil {
		return nil, errors.New("verification receipt identity codec is required")
	}
	keys, err := copyKeyRing(config.SigningKeys, 32)
	if err != nil {
		return nil, err
	}
	if _, ok := keys[config.ActiveSigningKeyID]; !ok || strings.TrimSpace(config.ActiveSigningKeyID) == "" {
		return nil, errors.New("active verification receipt key is unavailable")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &ReceiptCodec{
		identityCodec:      config.IdentityCodec,
		activeSigningKeyID: config.ActiveSigningKeyID,
		signingKeys:        keys,
		clock:              clock,
	}, nil
}

func (c *ReceiptCodec) Issue(challenge Challenge, normalizedIdentity string) (string, time.Time, error) {
	if challenge.ID == uuid.Nil || !validPurpose(challenge.Purpose) {
		return "", time.Time{}, ErrInvalidReceipt
	}
	normalized, err := secure.NormalizeIdentity(challenge.IdentityKind, normalizedIdentity)
	if err != nil || normalized != normalizedIdentity {
		return "", time.Time{}, ErrInvalidReceipt
	}
	sealed, err := c.identityCodec.Seal(challenge.IdentityKind, normalizedIdentity)
	if err != nil {
		return "", time.Time{}, errors.New("verification receipt could not be encrypted")
	}
	issuedAt := c.clock().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(receiptLifetime)
	payload := receiptPayload{
		Version:         1,
		SigningKeyID:    c.activeSigningKeyID,
		ChallengeID:     challenge.ID,
		Kind:            challenge.IdentityKind,
		Purpose:         challenge.Purpose,
		EncryptionKeyID: sealed.EncryptionKeyID,
		Nonce:           sealed.Nonce,
		Ciphertext:      sealed.Ciphertext,
		IssuedAtUnix:    issuedAt.Unix(),
		ExpiresAtUnix:   expiresAt.Unix(),
	}
	encodedJSON, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, errors.New("verification receipt could not be encoded")
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(encodedJSON)
	signature := receiptSignature(c.signingKeys[c.activeSigningKeyID], encodedPayload)
	return encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature), expiresAt, nil
}

func (c *ReceiptCodec) Parse(token string, expectedPurpose Purpose) (ReceiptClaims, error) {
	if c == nil || len(token) == 0 || len(token) > maximumReceiptTokenLength || strings.Count(token, ".") != 1 || !validPurpose(expectedPurpose) {
		return ReceiptClaims{}, ErrInvalidReceipt
	}
	encodedPayload, encodedSignature, _ := strings.Cut(token, ".")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil || len(payloadJSON) == 0 || len(payloadJSON) > maximumReceiptTokenLength {
		return ReceiptClaims{}, ErrInvalidReceipt
	}
	var payload receiptPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return ReceiptClaims{}, ErrInvalidReceipt
	}
	key, ok := c.signingKeys[payload.SigningKeyID]
	if !ok {
		return ReceiptClaims{}, ErrInvalidReceipt
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(signature) != sha256.Size || !hmac.Equal(signature, receiptSignature(key, encodedPayload)) {
		return ReceiptClaims{}, ErrInvalidReceipt
	}
	issuedAt := time.Unix(payload.IssuedAtUnix, 0).UTC()
	expiresAt := time.Unix(payload.ExpiresAtUnix, 0).UTC()
	now := c.clock().UTC()
	if payload.Version != 1 || payload.ChallengeID == uuid.Nil || payload.Purpose != expectedPurpose ||
		!validPurpose(payload.Purpose) || expiresAt.Sub(issuedAt) != receiptLifetime || now.Before(issuedAt.Add(-time.Minute)) || !now.Before(expiresAt) {
		return ReceiptClaims{}, ErrInvalidReceipt
	}
	normalized, err := c.identityCodec.Open(payload.Kind, secure.SealedIdentity{
		EncryptionKeyID: payload.EncryptionKeyID,
		Nonce:           payload.Nonce,
		Ciphertext:      payload.Ciphertext,
	})
	if err != nil {
		return ReceiptClaims{}, ErrInvalidReceipt
	}
	validated, err := secure.NormalizeIdentity(payload.Kind, normalized)
	if err != nil || validated != normalized {
		return ReceiptClaims{}, ErrInvalidReceipt
	}
	return ReceiptClaims{
		ChallengeID:        payload.ChallengeID,
		Kind:               payload.Kind,
		NormalizedIdentity: normalized,
		Purpose:            payload.Purpose,
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt,
	}, nil
}

func receiptSignature(key []byte, encodedPayload string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("agentera.verification-receipt.v1\x00"))
	_, _ = mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}
