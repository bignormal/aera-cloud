package organization

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestOrganizationPolicySignerProducesDomainSeparatedVerifiableAttestation(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	signer, err := NewSigner(SigningConfig{
		Issuer: "https://accounts.example.com", ActiveKeyID: "organization-v1",
		SigningKeys: map[string]ed25519.PrivateKey{"organization-v1": privateKey},
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	input := PolicySignatureInput{
		OrganizationID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		SnapshotID:     uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		PolicyVersion:  7,
		ContentDigest:  [32]byte{1, 2, 3, 4},
	}
	attestation, err := signer.SignPolicy(input)
	if err != nil {
		t.Fatalf("SignPolicy() error = %v", err)
	}
	if attestation.Issuer != "https://accounts.example.com" || attestation.KeyID != "organization-v1" ||
		attestation.OrganizationID != input.OrganizationID || attestation.SnapshotID != input.SnapshotID ||
		attestation.PolicyVersion != input.PolicyVersion || attestation.ContentDigest != input.ContentDigest ||
		len(attestation.Signature) != ed25519.SignatureSize {
		t.Fatalf("attestation = %+v", attestation)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verifier, err := NewVerifier(VerifierConfig{
		Issuer: "https://accounts.example.com",
		Keys: map[string]VerificationKey{
			"organization-v1": {Purpose: PurposeOrganizationPolicy, PublicKey: publicKey},
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if err := verifier.VerifyPolicy(attestation); err != nil {
		t.Fatalf("VerifyPolicy() error = %v", err)
	}
	wrongDomainPayload := []byte("agentera-agent-policy-v1\x00" + input.SnapshotID.String())
	if ed25519.Verify(publicKey, wrongDomainPayload, attestation.Signature) {
		t.Fatal("Organization policy signature verified under the Agent policy domain")
	}

	keys := signer.PublicKeys()
	if len(keys) != 1 || keys[0].KeyID != "organization-v1" || keys[0].Purpose != PurposeOrganizationPolicy ||
		keys[0].X != base64.RawURLEncoding.EncodeToString(publicKey) {
		t.Fatalf("PublicKeys() = %+v", keys)
	}
}

func TestOrganizationPolicyVerifierRejectsEveryBoundFieldMutation(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, ed25519.SeedSize))
	signer, err := NewSigner(SigningConfig{
		Issuer: "https://accounts.example.com", ActiveKeyID: "key-v1",
		SigningKeys: map[string]ed25519.PrivateKey{"key-v1": privateKey},
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	input := PolicySignatureInput{
		OrganizationID: uuid.New(), SnapshotID: uuid.New(), PolicyVersion: 1, ContentDigest: [32]byte{9},
	}
	valid, err := signer.SignPolicy(input)
	if err != nil {
		t.Fatalf("SignPolicy() error = %v", err)
	}
	verifier, err := NewVerifier(VerifierConfig{
		Issuer: "https://accounts.example.com",
		Keys: map[string]VerificationKey{
			"key-v1": {Purpose: PurposeOrganizationPolicy, PublicKey: privateKey.Public().(ed25519.PublicKey)},
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	mutations := []func(*PolicyAttestation){
		func(value *PolicyAttestation) { value.Issuer = "https://evil.example" },
		func(value *PolicyAttestation) { value.KeyID = "missing" },
		func(value *PolicyAttestation) { value.OrganizationID = uuid.New() },
		func(value *PolicyAttestation) { value.SnapshotID = uuid.New() },
		func(value *PolicyAttestation) { value.PolicyVersion++ },
		func(value *PolicyAttestation) { value.ContentDigest[0] ^= 1 },
		func(value *PolicyAttestation) { value.Signature[0] ^= 1 },
	}
	for index, mutate := range mutations {
		candidate := valid
		candidate.Signature = append([]byte(nil), valid.Signature...)
		mutate(&candidate)
		if err := verifier.VerifyPolicy(candidate); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("mutation %d VerifyPolicy() error = %v", index, err)
		}
	}
	wrongPurpose, err := NewVerifier(VerifierConfig{
		Issuer: "https://accounts.example.com",
		Keys: map[string]VerificationKey{
			"key-v1": {Purpose: "agent_policy", PublicKey: privateKey.Public().(ed25519.PublicKey)},
		},
	})
	if err == nil || wrongPurpose != nil {
		t.Fatal("NewVerifier() accepted a non-Organization signing purpose")
	}
}

func TestOrganizationPolicySignerValidatesAndCopiesKeyMaterial(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{33}, ed25519.SeedSize))
	config := SigningConfig{
		Issuer: "https://accounts.example.com", ActiveKeyID: "key-v1",
		SigningKeys: map[string]ed25519.PrivateKey{"key-v1": privateKey},
	}
	signer, err := NewSigner(config)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	input := PolicySignatureInput{
		OrganizationID: uuid.New(), SnapshotID: uuid.New(), PolicyVersion: 1, ContentDigest: [32]byte{7},
	}
	first, err := signer.SignPolicy(input)
	if err != nil {
		t.Fatalf("SignPolicy() error = %v", err)
	}
	for index := range privateKey {
		privateKey[index] = 0
	}
	second, err := signer.SignPolicy(input)
	if err != nil || !bytes.Equal(first.Signature, second.Signature) {
		t.Fatal("Signer retained aliased private key material")
	}

	for name, invalid := range map[string]SigningConfig{
		"empty issuer":     {ActiveKeyID: "key-v1", SigningKeys: map[string]ed25519.PrivateKey{"key-v1": secondKey(1)}},
		"trimmed issuer":   {Issuer: " https://accounts.example.com", ActiveKeyID: "key-v1", SigningKeys: map[string]ed25519.PrivateKey{"key-v1": secondKey(2)}},
		"missing active":   {Issuer: "https://accounts.example.com", ActiveKeyID: "missing", SigningKeys: map[string]ed25519.PrivateKey{"key-v1": secondKey(3)}},
		"short key":        {Issuer: "https://accounts.example.com", ActiveKeyID: "key-v1", SigningKeys: map[string]ed25519.PrivateKey{"key-v1": make([]byte, 63)}},
		"noncanonical key": {Issuer: "https://accounts.example.com", ActiveKeyID: "key-v1", SigningKeys: map[string]ed25519.PrivateKey{"key-v1": bytes.Repeat([]byte{1}, 64)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSigner(invalid); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("NewSigner() error = %v", err)
			}
		})
	}
	if _, err := signer.SignPolicy(PolicySignatureInput{}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("SignPolicy(empty) error = %v", err)
	}
}

func secondKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}
