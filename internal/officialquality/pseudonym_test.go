package officialquality

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPseudonymizerIsDailyPurposeSeparatedAndSupportsKeyRotation(t *testing.T) {
	activeKey := bytes.Repeat([]byte{0x41}, 32)
	previousKey := bytes.Repeat([]byte{0x42}, 32)
	pseudonyms, err := NewPseudonymizer("active", map[string][]byte{
		"active": activeKey, "previous": previousKey,
	})
	if err != nil {
		t.Fatalf("NewPseudonymizer() error = %v", err)
	}
	userID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	day := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)

	first := pseudonyms.Active(userID, PurposeMetrics, day)
	second := pseudonyms.Active(userID, PurposeMetrics, day.Add(12*time.Hour))
	if !bytes.Equal(first, second) {
		t.Fatal("active pseudonym changed inside one UTC day")
	}
	if bytes.Equal(first, pseudonyms.Active(userID, PurposeMetrics, day.Add(24*time.Hour))) {
		t.Fatal("active pseudonym did not rotate across UTC days")
	}
	if bytes.Equal(first, pseudonyms.Active(userID, PurposeExplicitFeedback, day)) {
		t.Fatal("active pseudonym is not purpose separated")
	}

	want := hmac.New(sha256.New, activeKey)
	_, _ = want.Write([]byte("official-quality-v1\x00official_quality_metrics\x00" + userID.String() + "\x002026-07-23"))
	if !bytes.Equal(first, want.Sum(nil)) {
		t.Fatalf("active pseudonym = %x, want %x", first, want.Sum(nil))
	}

	candidates := pseudonyms.Candidates(userID, PurposeMetrics, day)
	if len(candidates) != 2 || !bytes.Equal(candidates[0], first) {
		t.Fatalf("rotation candidates = %x, want active first and previous second", candidates)
	}
	previous := hmac.New(sha256.New, previousKey)
	_, _ = previous.Write([]byte("official-quality-v1\x00official_quality_metrics\x00" + userID.String() + "\x002026-07-23"))
	if !bytes.Equal(candidates[1], previous.Sum(nil)) {
		t.Fatalf("previous pseudonym = %x, want %x", candidates[1], previous.Sum(nil))
	}
}

func TestPseudonymizerRejectsInvalidKeyRings(t *testing.T) {
	tests := map[string]struct {
		active string
		keys   map[string][]byte
	}{
		"empty":          {},
		"missing active": {active: "missing", keys: map[string][]byte{"old": bytes.Repeat([]byte{1}, 32)}},
		"short key":      {active: "active", keys: map[string][]byte{"active": bytes.Repeat([]byte{1}, 31)}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPseudonymizer(test.active, test.keys); err == nil {
				t.Fatal("NewPseudonymizer() accepted invalid key ring")
			}
		})
	}
}
