package admin

import (
	"testing"

	"github.com/bignormal/aera-cloud/internal/secure"
)

func TestMaskIdentityUsesApprovedFormats(t *testing.T) {
	tests := []struct {
		kind        secure.IdentityKind
		value, want string
	}{
		{secure.IdentityEmail, "alice@example.com", "a***@example.com"},
		{secure.IdentityEmail, "x@example.test", "x***@example.test"},
		{secure.IdentityPhone, "+8613800138000", "138****8000"},
	}
	for _, test := range tests {
		got, err := MaskIdentity(test.kind, test.value)
		if err != nil || got != test.want {
			t.Fatalf("MaskIdentity(%q, %q) = %q, %v; want %q", test.kind, test.value, got, err, test.want)
		}
	}
}

func TestMaskIdentityRejectsUnsupportedOrNonNormalizedValues(t *testing.T) {
	tests := []struct {
		kind  secure.IdentityKind
		value string
	}{
		{secure.IdentityKind("username"), "alice"},
		{secure.IdentityEmail, " Alice@Example.COM "},
		{secure.IdentityEmail, "missing-at.example.com"},
		{secure.IdentityPhone, "13800138000"},
	}
	for _, test := range tests {
		if masked, err := MaskIdentity(test.kind, test.value); err == nil || masked != "" {
			t.Fatalf("MaskIdentity(%q, %q) = %q, %v; want rejection", test.kind, test.value, masked, err)
		}
	}
}
