package secure

import (
	"bytes"
	"testing"
)

func TestNormalizeIdentity(t *testing.T) {
	tests := []struct {
		name string
		kind IdentityKind
		raw  string
		want string
	}{
		{name: "email", kind: IdentityEmail, raw: "  Alice@Example.COM  ", want: "alice@example.com"},
		{name: "mainland mobile", kind: IdentityPhone, raw: "138 0013 8000", want: "+8613800138000"},
		{name: "country prefix", kind: IdentityPhone, raw: "+86-138-0013-8000", want: "+8613800138000"},
		{name: "international prefix", kind: IdentityPhone, raw: "0086 (138) 0013 8000", want: "+8613800138000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeIdentity(tt.kind, tt.raw)
			if err != nil {
				t.Fatalf("NormalizeIdentity() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeIdentity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeIdentityRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		kind IdentityKind
		raw  string
	}{
		{kind: IdentityEmail, raw: "missing-at.example.com"},
		{kind: IdentityEmail, raw: "@example.com"},
		{kind: IdentityPhone, raw: "+8612800138000"},
		{kind: IdentityPhone, raw: "+14155552671"},
		{kind: IdentityKind("username"), raw: "alice"},
	}

	for _, tt := range tests {
		if _, err := NormalizeIdentity(tt.kind, tt.raw); err == nil {
			t.Errorf("NormalizeIdentity(%q, %q) succeeded", tt.kind, tt.raw)
		}
	}
}

func TestIdentityCodecEncryptsWithRandomNonceAndRoundTrips(t *testing.T) {
	codec := newTestIdentityCodec(t, "enc-v2", "lookup-v2")

	first, err := codec.Seal(IdentityEmail, "alice@example.com")
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	second, err := codec.Seal(IdentityEmail, "alice@example.com")
	if err != nil {
		t.Fatalf("Seal() second error = %v", err)
	}

	if first.EncryptionKeyID != "enc-v2" || first.LookupKeyID != "lookup-v2" {
		t.Fatalf("unexpected key IDs: encryption=%q lookup=%q", first.EncryptionKeyID, first.LookupKeyID)
	}
	if len(first.Nonce) != 12 {
		t.Fatalf("nonce length = %d, want 12", len(first.Nonce))
	}
	if bytes.Equal(first.Nonce, second.Nonce) || bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("sealing the same identity reused encryption output")
	}
	if bytes.Contains(first.Ciphertext, []byte("alice@example.com")) {
		t.Fatal("ciphertext contains plaintext identity")
	}
	if !bytes.Equal(first.LookupHMAC, second.LookupHMAC) {
		t.Fatal("lookup HMAC is not stable")
	}

	plaintext, err := codec.Open(IdentityEmail, first)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if plaintext != "alice@example.com" {
		t.Fatalf("Open() = %q", plaintext)
	}
	if _, err := codec.Open(IdentityPhone, first); err == nil {
		t.Fatal("Open() accepted ciphertext under a different identity kind")
	}
}

func TestIdentityCodecOpensOldEncryptionKeyAfterRotation(t *testing.T) {
	oldCodec := newTestIdentityCodec(t, "enc-v1", "lookup-v1")
	sealed, err := oldCodec.Seal(IdentityEmail, "alice@example.com")
	if err != nil {
		t.Fatalf("old Seal() error = %v", err)
	}

	rotated := newTestIdentityCodec(t, "enc-v2", "lookup-v2")
	plaintext, err := rotated.Open(IdentityEmail, sealed)
	if err != nil {
		t.Fatalf("rotated Open() error = %v", err)
	}
	if plaintext != "alice@example.com" {
		t.Fatalf("Open() = %q", plaintext)
	}
}

func TestIdentityCodecReturnsLookupCandidatesForControlledReindex(t *testing.T) {
	oldCodec := newTestIdentityCodec(t, "enc-v1", "lookup-v1")
	oldCandidates := oldCodec.LookupCandidates(IdentityEmail, "alice@example.com")
	rotated := newTestIdentityCodec(t, "enc-v2", "lookup-v2")
	candidates := rotated.LookupCandidates(IdentityEmail, "alice@example.com")

	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2", len(candidates))
	}
	if candidates[0].KeyID != "lookup-v2" {
		t.Fatalf("first candidate key = %q, want active key", candidates[0].KeyID)
	}
	if candidates[1].KeyID != "lookup-v1" {
		t.Fatalf("second candidate key = %q, want previous key", candidates[1].KeyID)
	}
	if !bytes.Equal(candidates[1].HMAC, oldCandidates[0].HMAC) {
		t.Fatal("old lookup digest changed during rotation")
	}
	if bytes.Equal(candidates[0].HMAC, candidates[1].HMAC) {
		t.Fatal("different lookup keys produced the same digest")
	}
	phone := rotated.LookupCandidates(IdentityPhone, "alice@example.com")
	if bytes.Equal(candidates[0].HMAC, phone[0].HMAC) {
		t.Fatal("lookup digest is not bound to identity kind")
	}
}

func TestIdentityCodecRejectsUnknownOrInvalidKeys(t *testing.T) {
	if _, err := NewIdentityCodec(IdentityCodecConfig{
		ActiveEncryptionKeyID: "missing",
		EncryptionKeys:        map[string][]byte{"enc-v1": bytes.Repeat([]byte{1}, 32)},
		ActiveLookupKeyID:     "lookup-v1",
		LookupKeys:            map[string][]byte{"lookup-v1": bytes.Repeat([]byte{2}, 32)},
	}); err == nil {
		t.Fatal("NewIdentityCodec() accepted missing active key")
	}
	if _, err := NewIdentityCodec(IdentityCodecConfig{
		ActiveEncryptionKeyID: "enc-v1",
		EncryptionKeys:        map[string][]byte{"enc-v1": []byte("short")},
		ActiveLookupKeyID:     "lookup-v1",
		LookupKeys:            map[string][]byte{"lookup-v1": bytes.Repeat([]byte{2}, 32)},
	}); err == nil {
		t.Fatal("NewIdentityCodec() accepted a short encryption key")
	}

	codec := newTestIdentityCodec(t, "enc-v2", "lookup-v2")
	sealed, err := codec.Seal(IdentityEmail, "alice@example.com")
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	sealed.EncryptionKeyID = "unknown"
	if _, err := codec.Open(IdentityEmail, sealed); err == nil {
		t.Fatal("Open() accepted unknown encryption key")
	}
}

func newTestIdentityCodec(t *testing.T, activeEncryptionKey, activeLookupKey string) *IdentityCodec {
	t.Helper()
	codec, err := NewIdentityCodec(IdentityCodecConfig{
		ActiveEncryptionKeyID: activeEncryptionKey,
		EncryptionKeys: map[string][]byte{
			"enc-v1": bytes.Repeat([]byte{1}, 32),
			"enc-v2": bytes.Repeat([]byte{2}, 32),
		},
		ActiveLookupKeyID: activeLookupKey,
		LookupKeys: map[string][]byte{
			"lookup-v1": bytes.Repeat([]byte{3}, 32),
			"lookup-v2": bytes.Repeat([]byte{4}, 32),
		},
	})
	if err != nil {
		t.Fatalf("NewIdentityCodec() error = %v", err)
	}
	return codec
}
