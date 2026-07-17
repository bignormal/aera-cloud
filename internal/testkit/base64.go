package testkit

import (
	"strings"
	"testing"
)

const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// NonCanonicalBase64URLAlias returns a different raw-base64url spelling that
// Go's permissive decoder maps to the same bytes by changing only unused tail
// bits. It is intended for security-boundary regression tests.
func NonCanonicalBase64URLAlias(t testing.TB, encoded string) string {
	t.Helper()
	if encoded == "" {
		t.Fatal("cannot alias an empty base64url value")
	}
	index := strings.IndexByte(base64URLAlphabet, encoded[len(encoded)-1])
	if index < 0 {
		t.Fatalf("invalid base64url tail in %q", encoded)
	}
	switch len(encoded) % 4 {
	case 2:
		if index%16 != 0 || index+1 >= len(base64URLAlphabet) {
			t.Fatalf("base64url value has no canonical four-bit tail: %q", encoded)
		}
	case 3:
		if index%4 != 0 || index+1 >= len(base64URLAlphabet) {
			t.Fatalf("base64url value has no canonical two-bit tail: %q", encoded)
		}
	default:
		t.Fatalf("base64url value has no unused tail bits: %q", encoded)
	}
	return encoded[:len(encoded)-1] + string(base64URLAlphabet[index+1])
}
