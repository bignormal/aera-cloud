package organization

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNewInvitationSecretReadsExactlyThirtyTwoBytes(t *testing.T) {
	entropy := make([]byte, 32)
	for index := range entropy {
		entropy[index] = byte(index)
	}
	reader := bytes.NewReader(append(append([]byte(nil), entropy...), 0xff))

	secret, err := NewInvitationSecret(reader)
	if err != nil {
		t.Fatalf("NewInvitationSecret() error = %v", err)
	}
	wantRaw := base64.RawURLEncoding.EncodeToString(entropy)
	wantDigest := sha256.Sum256([]byte(wantRaw))
	if secret.RawToken != wantRaw || len(secret.RawToken) != 43 || secret.Digest != wantDigest {
		t.Fatalf("NewInvitationSecret() = %#v, want raw %q and digest %x", secret, wantRaw, wantDigest)
	}
	if reader.Len() != 1 {
		t.Fatalf("entropy bytes remaining = %d, want 1", reader.Len())
	}
	digest, err := InvitationDigest(secret.RawToken)
	if err != nil || digest != wantDigest {
		t.Fatalf("InvitationDigest() = %x, %v; want %x", digest, err, wantDigest)
	}
}

func TestInvitationSecretFailsClosedAndRedactsEveryFormatter(t *testing.T) {
	if _, err := NewInvitationSecret(bytes.NewReader(make([]byte, 31))); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("short entropy error = %v", err)
	}
	if _, err := NewInvitationSecret(nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("nil entropy error = %v", err)
	}
	secret, err := NewInvitationSecret(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatalf("NewInvitationSecret() error = %v", err)
	}
	formatted := strings.Join([]string{fmt.Sprint(secret), fmt.Sprintf("%+v", secret), fmt.Sprintf("%#v", secret)}, "\n")
	if strings.Contains(formatted, secret.RawToken) || !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("formatted secret was not redacted: %q", formatted)
	}
	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), secret.RawToken) {
		t.Fatalf("JSON exposed raw invitation token: %s", encoded)
	}
}

func TestInvitationDigestRejectsNonCanonicalOrWrongLengthTokens(t *testing.T) {
	valid := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	for _, value := range []string{
		"",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 31)),
		valid + "=",
		strings.Repeat("+", 43),
		valid[:42] + "*",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 33)),
	} {
		if _, err := InvitationDigest(value); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("InvitationDigest(%q) error = %v, want ErrInvalidRequest", value, err)
		}
	}
}
