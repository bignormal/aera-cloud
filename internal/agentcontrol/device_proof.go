package agentcontrol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const (
	activationProofDomain = "agentera-agent-installation-activate-v1"
	activationProofWindow = 5 * time.Minute
)

var ErrInvalidDeviceProof = errors.New("Agent installation device proof is invalid")

type ActivationProofInput struct {
	AgentInstallationID uuid.UUID
	RuntimeProfileID    uuid.UUID
	VersionDigest       [sha256.Size]byte
	Timestamp           int64
}

func ActivationProofBytes(input ActivationProofInput) ([]byte, error) {
	if input.AgentInstallationID == uuid.Nil || input.RuntimeProfileID == uuid.Nil ||
		zeroDigest(input.VersionDigest) || input.Timestamp <= 0 {
		return nil, ErrInvalidDeviceProof
	}
	payload := activationProofDomain + "\x00" + input.AgentInstallationID.String() + "\x00" +
		input.RuntimeProfileID.String() + "\x00" + hex.EncodeToString(input.VersionDigest[:]) + "\x00" +
		strconv.FormatInt(input.Timestamp, 10)
	return []byte(payload), nil
}

func VerifyActivationProof(
	publicKey ed25519.PublicKey,
	input ActivationProofInput,
	proof []byte,
	now time.Time,
) error {
	if len(publicKey) != ed25519.PublicKeySize || len(proof) != ed25519.SignatureSize || now.IsZero() {
		return ErrInvalidDeviceProof
	}
	proofTime := time.Unix(input.Timestamp, 0).UTC()
	current := now.UTC()
	if proofTime.Before(current.Add(-activationProofWindow)) || proofTime.After(current.Add(activationProofWindow)) {
		return ErrInvalidDeviceProof
	}
	payload, err := ActivationProofBytes(input)
	if err != nil || !ed25519.Verify(publicKey, payload, proof) {
		return ErrInvalidDeviceProof
	}
	return nil
}
