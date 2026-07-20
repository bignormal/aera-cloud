package workspace

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/bignormal/aera-cloud/internal/secure"
)

const invitationEntropyBytes = 32

type InvitationSecret struct {
	RawToken string   `json:"-"`
	Digest   [32]byte `json:"-"`
}

func GenerateInvitationSecret() (InvitationSecret, error) {
	return NewInvitationSecret(rand.Reader)
}

func NewInvitationSecret(entropy io.Reader) (InvitationSecret, error) {
	if entropy == nil {
		return InvitationSecret{}, ErrServiceUnavailable
	}
	value := make([]byte, invitationEntropyBytes)
	if _, err := io.ReadFull(entropy, value); err != nil {
		return InvitationSecret{}, ErrServiceUnavailable
	}
	rawToken := base64.RawURLEncoding.EncodeToString(value)
	return InvitationSecret{
		RawToken: rawToken,
		Digest:   sha256.Sum256([]byte(rawToken)),
	}, nil
}

func InvitationDigest(rawToken string) ([sha256.Size]byte, error) {
	decoded, ok := secure.DecodeCanonicalBase64URL(rawToken)
	if !ok || len(decoded) != invitationEntropyBytes {
		return [sha256.Size]byte{}, fmt.Errorf("%w: invitation token is invalid", ErrInvalidRequest)
	}
	return sha256.Sum256([]byte(rawToken)), nil
}

func (InvitationSecret) String() string {
	return "InvitationSecret{RawToken:REDACTED}"
}

func (InvitationSecret) GoString() string {
	return "workspace.InvitationSecret{RawToken:REDACTED}"
}

func (InvitationSecret) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "workspace.InvitationSecret{RawToken:REDACTED}")
}

func (InvitationSecret) LogValue() slog.Value {
	return slog.StringValue("workspace.InvitationSecret{RawToken:REDACTED}")
}

func (InvitationSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Redacted bool `json:"redacted"`
	}{Redacted: true})
}
