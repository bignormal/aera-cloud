package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAccessTokensUseEdDSAForExactFifteenMinuteMinimalClaims(t *testing.T) {
	fixture := newAccessFixture(t)
	binding := AccessBinding{
		UserID: uuid.New(), SessionID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New(),
	}

	issued, err := fixture.signer.Issue(binding)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if issued.ExpiresAt != fixture.now.Add(15*time.Minute) {
		t.Fatalf("ExpiresAt = %s", issued.ExpiresAt)
	}
	claims, err := fixture.signer.Verify(issued.Serialized)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.AccessBinding != binding || claims.IssuedAt != fixture.now || claims.ExpiresAt != issued.ExpiresAt {
		t.Fatalf("claims = %+v", claims)
	}

	parts := strings.Split(issued.Serialized, ".")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("decode payload JSON: %v", err)
	}
	wantKeys := map[string]bool{
		"iss": true, "aud": true, "sub": true, "session_id": true,
		"device_id": true, "personal_space_id": true, "iat": true, "exp": true,
	}
	if len(payload) != len(wantKeys) {
		t.Fatalf("access claim count = %d, claims=%+v", len(payload), payload)
	}
	for key := range payload {
		if !wantKeys[key] {
			t.Fatalf("unexpected access claim %q", key)
		}
	}
}

func TestAccessTokensRejectTamperingUnknownKeysAndExpiry(t *testing.T) {
	fixture := newAccessFixture(t)
	issued, err := fixture.signer.Issue(AccessBinding{
		UserID: uuid.New(), SessionID: uuid.New(), DeviceID: uuid.New(), PersonalSpaceID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	parts := strings.Split(issued.Serialized, ".")
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	if _, err := fixture.signer.Verify(strings.Join(parts, ".")); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("Verify(tampered) error = %v", err)
	}

	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	other, err := NewAccessSigner(AccessSignerConfig{
		Issuer: "https://accounts.agentera.example", Audience: "agentera-studio",
		ActiveKeyID: "access-other", SigningKeys: map[string]ed25519.PrivateKey{"access-other": otherPrivate},
		Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("NewAccessSigner(other) error = %v", err)
	}
	if _, err := other.Verify(issued.Serialized); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("Verify(unknown key) error = %v", err)
	}

	fixture.now = fixture.now.Add(15 * time.Minute)
	if _, err := fixture.signer.Verify(issued.Serialized); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("Verify(expired) error = %v", err)
	}
}

type accessFixture struct {
	now    time.Time
	signer *AccessSigner
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	fixture := &accessFixture{now: time.Date(2026, 7, 18, 1, 30, 0, 0, time.UTC)}
	signer, err := NewAccessSigner(AccessSignerConfig{
		Issuer: "https://accounts.agentera.example", Audience: "agentera-studio",
		ActiveKeyID: "access-v1", SigningKeys: map[string]ed25519.PrivateKey{"access-v1": privateKey},
		Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("NewAccessSigner() error = %v", err)
	}
	fixture.signer = signer
	return fixture
}
