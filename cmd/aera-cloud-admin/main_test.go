package main

import (
	"testing"

	"github.com/google/uuid"
)

func TestParseInvocationRequiresOperatorAndTarget(t *testing.T) {
	userID := uuid.New()
	if _, err := parseInvocation([]string{"disable-account", "--user-id", userID.String()}, "postgres://configured"); err == nil {
		t.Fatal("parseInvocation() accepted a mutation without an operator")
	}
	if _, err := parseInvocation([]string{"--operator", "operator-01", "disable-account"}, "postgres://configured"); err == nil {
		t.Fatal("parseInvocation() accepted a mutation without a user ID")
	}
}

func TestParseInvocationSupportsRestrictedCommandsOnly(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	tests := []struct {
		args    []string
		command string
		target  uuid.UUID
		limit   int
	}{
		{[]string{"--operator", "operator-01", "disable-account", "--user-id", userID.String()}, "disable-account", userID, 0},
		{[]string{"--operator", "operator-01", "enable-account", "--user-id", userID.String()}, "enable-account", userID, 0},
		{[]string{"--operator", "operator-01", "revoke-session", "--session-id", sessionID.String()}, "revoke-session", sessionID, 0},
		{[]string{"--operator", "operator-01", "audit", "--user-id", userID.String(), "--limit", "25"}, "audit", userID, 25},
		{[]string{"--operator", "operator-01", "verify-identities"}, "verify-identities", uuid.Nil, 0},
	}
	for _, test := range tests {
		invocation, err := parseInvocation(test.args, "postgres://configured")
		if err != nil {
			t.Fatalf("parseInvocation(%s) error = %v", test.command, err)
		}
		if invocation.Command != test.command || invocation.TargetID != test.target || invocation.Limit != test.limit ||
			invocation.Operator != "operator-01" || invocation.DatabaseURL != "postgres://configured" {
			t.Fatalf("parseInvocation(%s) = %+v", test.command, invocation)
		}
	}
	if _, err := parseInvocation([]string{"--operator", "operator-01", "serve-http"}, "postgres://configured"); err == nil {
		t.Fatal("parseInvocation() accepted a public server command")
	}
}

func TestParseRecoveryEncryptionKeysRejectsMissingAndAcceptsRotationSet(t *testing.T) {
	keys, err := parseRecoveryEncryptionKeys(`{
		"enc-v1":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		"enc-v2":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	}`)
	if err != nil {
		t.Fatalf("parseRecoveryEncryptionKeys() error = %v", err)
	}
	if len(keys) != 2 || len(keys["enc-v1"]) != 32 || len(keys["enc-v2"]) != 32 {
		t.Fatalf("recovery keys = %+v", keys)
	}
	if _, err := parseRecoveryEncryptionKeys(`{"enc-v1":"c2hvcnQ="}`); err == nil {
		t.Fatal("parseRecoveryEncryptionKeys() accepted a short key")
	}
	if _, err := parseRecoveryEncryptionKeys(""); err == nil {
		t.Fatal("parseRecoveryEncryptionKeys() accepted a missing recovery set")
	}
}
