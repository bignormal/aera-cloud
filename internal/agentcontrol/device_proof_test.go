package agentcontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeviceProofActivationPayloadIsExactAndVerifiable(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	input := ActivationProofInput{
		AgentInstallationID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		RuntimeProfileID:    uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		VersionDigest:       sha256.Sum256([]byte("version")),
		Timestamp:           1_786_000_000,
	}
	payload, err := ActivationProofBytes(input)
	if err != nil {
		t.Fatalf("ActivationProofBytes() error = %v", err)
	}
	want := "agentera-agent-installation-activate-v1\x00" + input.AgentInstallationID.String() + "\x00" +
		input.RuntimeProfileID.String() + "\x00" + hex.EncodeToString(input.VersionDigest[:]) + "\x001786000000"
	if string(payload) != want {
		t.Fatalf("ActivationProofBytes() = %q, want %q", payload, want)
	}
	proof := ed25519.Sign(private, payload)
	if err := VerifyActivationProof(private.Public().(ed25519.PublicKey), input, proof, time.Unix(input.Timestamp, 0)); err != nil {
		t.Fatalf("VerifyActivationProof() error = %v", err)
	}
}

func TestDeviceProofActivationRejectsWrongKeyBoundValueAndExpiredTimestamp(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	input := ActivationProofInput{
		AgentInstallationID: uuid.New(), RuntimeProfileID: uuid.New(),
		VersionDigest: sha256.Sum256([]byte("version")), Timestamp: now.Unix(),
	}
	payload, err := ActivationProofBytes(input)
	if err != nil {
		t.Fatalf("ActivationProofBytes() error = %v", err)
	}
	proof := ed25519.Sign(private, payload)

	tests := map[string]struct {
		public ed25519.PublicKey
		input  ActivationProofInput
		proof  []byte
		now    time.Time
	}{
		"wrong key":        {public: other.Public().(ed25519.PublicKey), input: input, proof: proof, now: now},
		"wrong profile":    {public: private.Public().(ed25519.PublicKey), input: withActivationProfile(input, uuid.New()), proof: proof, now: now},
		"wrong digest":     {public: private.Public().(ed25519.PublicKey), input: withActivationDigest(input, sha256.Sum256([]byte("other"))), proof: proof, now: now},
		"altered proof":    {public: private.Public().(ed25519.PublicKey), input: input, proof: append([]byte(nil), proof...), now: now},
		"expired past":     {public: private.Public().(ed25519.PublicKey), input: input, proof: proof, now: now.Add(5*time.Minute + time.Second)},
		"future timestamp": {public: private.Public().(ed25519.PublicKey), input: input, proof: proof, now: now.Add(-5*time.Minute - time.Second)},
	}
	tests["altered proof"].proof[0] ^= 0xff
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := VerifyActivationProof(test.public, test.input, test.proof, test.now); !errorsIsInvalidDeviceProof(err) {
				t.Fatalf("VerifyActivationProof() error = %v", err)
			}
		})
	}
}

func withActivationProfile(input ActivationProofInput, profileID uuid.UUID) ActivationProofInput {
	input.RuntimeProfileID = profileID
	return input
}

func withActivationDigest(input ActivationProofInput, digest [sha256.Size]byte) ActivationProofInput {
	input.VersionDigest = digest
	return input
}

func errorsIsInvalidDeviceProof(err error) bool {
	return err == ErrInvalidDeviceProof
}
