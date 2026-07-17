package secure

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/bignormal/aera-cloud/internal/testkit"
)

func TestDecodeCanonicalBase64URLRejectsEquivalentNonCanonicalEncoding(t *testing.T) {
	want := bytes.Repeat([]byte{0}, 32)
	canonical := base64.RawURLEncoding.EncodeToString(want)

	decoded, ok := DecodeCanonicalBase64URL(canonical)
	if !ok || !bytes.Equal(decoded, want) {
		t.Fatalf("DecodeCanonicalBase64URL(canonical) = %x, %v", decoded, ok)
	}

	alias := testkit.NonCanonicalBase64URLAlias(t, canonical)
	permissive, err := base64.RawURLEncoding.DecodeString(alias)
	if err != nil || !bytes.Equal(permissive, want) {
		t.Fatalf("test alias does not reproduce permissive decoding: %x, %v", permissive, err)
	}
	if decoded, ok := DecodeCanonicalBase64URL(alias); ok || decoded != nil {
		t.Fatalf("DecodeCanonicalBase64URL(alias) = %x, %v", decoded, ok)
	}
	if decoded, ok := DecodeCanonicalBase64URL("not+base64url"); ok || decoded != nil {
		t.Fatalf("DecodeCanonicalBase64URL(invalid) = %x, %v", decoded, ok)
	}
}
