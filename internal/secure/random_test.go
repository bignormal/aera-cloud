package secure

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func TestRandomBytesReturnsRequestedIndependentValues(t *testing.T) {
	first, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes() error = %v", err)
	}
	second, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes() second error = %v", err)
	}
	if len(first) != 32 || len(second) != 32 {
		t.Fatalf("lengths = %d and %d, want 32", len(first), len(second))
	}
	if bytes.Equal(first, second) {
		t.Fatal("two random values unexpectedly match")
	}
}

func TestRandomTokenUsesUnpaddedURLSafeEncoding(t *testing.T) {
	token, err := RandomToken(32)
	if err != nil {
		t.Fatalf("RandomToken() error = %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not raw URL-safe base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded length = %d, want 32", len(decoded))
	}
}

func TestRandomUUIDReturnsIndependentRFC4122Version4Values(t *testing.T) {
	first, err := RandomUUID()
	if err != nil {
		t.Fatalf("RandomUUID() error = %v", err)
	}
	second, err := RandomUUID()
	if err != nil {
		t.Fatalf("RandomUUID() second error = %v", err)
	}
	if first == second {
		t.Fatal("two random UUID values unexpectedly match")
	}
	if first.Version() != 4 || second.Version() != 4 {
		t.Fatalf("UUID versions = %d and %d, want 4", first.Version(), second.Version())
	}
	if first.Variant() != uuid.RFC4122 || second.Variant() != uuid.RFC4122 {
		t.Fatalf("UUID variants = %v and %v, want RFC4122", first.Variant(), second.Variant())
	}
}

func TestRandomValuesRejectNonPositiveSize(t *testing.T) {
	if _, err := RandomBytes(0); err == nil {
		t.Fatal("RandomBytes(0) succeeded")
	}
	if _, err := RandomToken(-1); err == nil {
		t.Fatal("RandomToken(-1) succeeded")
	}
}
