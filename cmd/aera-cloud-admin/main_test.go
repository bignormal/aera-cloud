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
