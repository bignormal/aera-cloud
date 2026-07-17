package verification

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
)

func TestReceiptCodecEncryptsIdentityAndRoundTripsClaims(t *testing.T) {
	now := time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC)
	codec := newTestReceiptCodec(t, "receipt-v2", now)
	challenge := repositoryTestChallenge(t, now, 7)

	token, expiresAt, err := codec.Issue(challenge, "alice@example.com")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if strings.Contains(token, "alice@example.com") {
		t.Fatal("receipt token contains plaintext identity")
	}
	if expiresAt != now.Add(10*time.Minute) {
		t.Fatalf("expiresAt = %s", expiresAt)
	}
	claims, err := codec.Parse(token, PurposeRegistration)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.ChallengeID != challenge.ID || claims.Kind != secure.IdentityEmail || claims.NormalizedIdentity != "alice@example.com" {
		t.Fatalf("claims = %+v", claims)
	}
	if claims.Purpose != PurposeRegistration || claims.IssuedAt != now || claims.ExpiresAt != expiresAt {
		t.Fatalf("claim times/purpose = %+v", claims)
	}
}

func TestReceiptCodecRejectsTamperingWrongPurposeAndExpiry(t *testing.T) {
	now := time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC)
	codec := newTestReceiptCodec(t, "receipt-v2", now)
	challenge := repositoryTestChallenge(t, now, 8)
	token, _, err := codec.Issue(challenge, "alice@example.com")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	replacement := "A"
	if strings.HasSuffix(token, replacement) {
		replacement = "B"
	}
	tampered := token[:len(token)-1] + replacement
	if _, err := codec.Parse(tampered, PurposeRegistration); err == nil {
		t.Fatal("Parse() accepted tampered receipt")
	}
	if _, err := codec.Parse(token, PurposePasswordReset); err == nil {
		t.Fatal("Parse() accepted receipt for a different purpose")
	}
	codec.clock = func() time.Time { return now.Add(10*time.Minute + time.Second) }
	if _, err := codec.Parse(token, PurposeRegistration); err == nil {
		t.Fatal("Parse() accepted expired receipt")
	}
}

func TestReceiptCodecParsesOldSigningKeyAfterRotation(t *testing.T) {
	now := time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC)
	oldCodec := newTestReceiptCodec(t, "receipt-v1", now)
	challenge := repositoryTestChallenge(t, now, 9)
	challenge.IdentityKind = secure.IdentityPhone
	token, _, err := oldCodec.Issue(challenge, "+8613800138000")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	rotated := newTestReceiptCodec(t, "receipt-v2", now)
	claims, err := rotated.Parse(token, PurposeRegistration)
	if err != nil {
		t.Fatalf("rotated Parse() error = %v", err)
	}
	if claims.NormalizedIdentity != "+8613800138000" {
		t.Fatalf("identity = %q", claims.NormalizedIdentity)
	}
}

func newTestReceiptCodec(t *testing.T, activeKeyID string, now time.Time) *ReceiptCodec {
	t.Helper()
	identityCodec, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: "enc-v1",
		EncryptionKeys:        map[string][]byte{"enc-v1": bytes.Repeat([]byte{1}, 32)},
		ActiveLookupKeyID:     "lookup-v1",
		LookupKeys:            map[string][]byte{"lookup-v1": bytes.Repeat([]byte{2}, 32)},
	})
	if err != nil {
		t.Fatalf("NewIdentityCodec() error = %v", err)
	}
	codec, err := NewReceiptCodec(ReceiptCodecConfig{
		IdentityCodec:      identityCodec,
		ActiveSigningKeyID: activeKeyID,
		SigningKeys: map[string][]byte{
			"receipt-v1": bytes.Repeat([]byte{3}, 32),
			"receipt-v2": bytes.Repeat([]byte{4}, 32),
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewReceiptCodec() error = %v", err)
	}
	return codec
}
