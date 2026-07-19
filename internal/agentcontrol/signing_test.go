package agentcontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

func TestVersionAttestationBindsEveryIdentityAndDigestField(t *testing.T) {
	signer, verifier := signingFixture(t)
	input := VersionSignatureInput{
		DefinitionID:   uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		VersionID:      uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		VersionNumber:  7,
		ManifestDigest: sha256.Sum256([]byte("manifest")),
		BundleDigest:   sha256.Sum256([]byte("bundle")),
	}
	attestation, err := signer.SignVersion(input)
	if err != nil {
		t.Fatalf("SignVersion() error = %v", err)
	}
	if err := verifier.VerifyVersion(attestation); err != nil {
		t.Fatalf("VerifyVersion() error = %v", err)
	}

	tests := map[string]func(VersionAttestation) VersionAttestation{
		"issuer": func(value VersionAttestation) VersionAttestation {
			value.Issuer = "https://other.example.com"
			return value
		},
		"definition ID": func(value VersionAttestation) VersionAttestation {
			value.DefinitionID = uuid.New()
			return value
		},
		"version ID": func(value VersionAttestation) VersionAttestation {
			value.VersionID = uuid.New()
			return value
		},
		"version number": func(value VersionAttestation) VersionAttestation {
			value.VersionNumber++
			return value
		},
		"manifest digest": func(value VersionAttestation) VersionAttestation {
			value.ManifestDigest = sha256.Sum256([]byte("altered manifest"))
			return value
		},
		"bundle digest": func(value VersionAttestation) VersionAttestation {
			value.BundleDigest = sha256.Sum256([]byte("altered bundle"))
			return value
		},
		"key ID": func(value VersionAttestation) VersionAttestation {
			value.KeyID = "unknown"
			return value
		},
		"signature": func(value VersionAttestation) VersionAttestation {
			value.Signature = append([]byte(nil), value.Signature...)
			value.Signature[0] ^= 0xff
			return value
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := verifier.VerifyVersion(mutate(attestation)); err == nil {
				t.Fatalf("VerifyVersion() accepted altered %s", name)
			}
		})
	}
}

func TestVersionAttestationRejectsWrongKeyPurposeEvenWithSamePublicBytes(t *testing.T) {
	signer, _ := signingFixture(t)
	attestation, err := signer.SignVersion(VersionSignatureInput{
		DefinitionID: uuid.New(), VersionID: uuid.New(), VersionNumber: 1,
		ManifestDigest: sha256.Sum256([]byte("manifest")), BundleDigest: sha256.Sum256([]byte("bundle")),
	})
	if err != nil {
		t.Fatalf("SignVersion() error = %v", err)
	}
	public := signer.PublicKeys()[0].PublicKey
	wrongPurpose, err := NewVerifier(VerifierConfig{
		Issuer: "https://accounts.example.com",
		Keys: map[string]VerificationKey{
			"agent-control-v1": {Purpose: PurposeAgentPolicy, PublicKey: public},
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if err := wrongPurpose.VerifyVersion(attestation); err == nil {
		t.Fatal("VerifyVersion() accepted a policy-purpose key")
	}
}

func TestPolicyAttestationUsesSeparateDomainAndBindsPolicyIdentity(t *testing.T) {
	signer, verifier := signingFixture(t)
	input := PolicySignatureInput{
		PolicyID:       uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		PolicyVersion:  3,
		DocumentDigest: sha256.Sum256([]byte("policy")),
	}
	attestation, err := signer.SignPolicy(input)
	if err != nil {
		t.Fatalf("SignPolicy() error = %v", err)
	}
	if err := verifier.VerifyPolicy(attestation); err != nil {
		t.Fatalf("VerifyPolicy() error = %v", err)
	}

	alteredID := attestation
	alteredID.PolicyID = uuid.New()
	alteredVersion := attestation
	alteredVersion.PolicyVersion++
	alteredDigest := attestation
	alteredDigest.DocumentDigest = sha256.Sum256([]byte("altered"))
	for name, altered := range map[string]PolicyAttestation{
		"policy ID": alteredID, "policy version": alteredVersion, "document": alteredDigest,
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifier.VerifyPolicy(altered); err == nil {
				t.Fatalf("VerifyPolicy() accepted altered %s", name)
			}
		})
	}

	versionShaped := VersionAttestation{
		Issuer: attestation.Issuer, KeyID: attestation.KeyID,
		DefinitionID: uuid.New(), VersionID: uuid.New(), VersionNumber: 1,
		ManifestDigest: attestation.DocumentDigest, BundleDigest: attestation.DocumentDigest,
		Signature: append([]byte(nil), attestation.Signature...),
	}
	if err := verifier.VerifyVersion(versionShaped); err == nil {
		t.Fatal("VerifyVersion() accepted a policy-domain signature")
	}
}

func TestSignerRejectsInvalidConfigurationAndInputs(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	for name, config := range map[string]SigningConfig{
		"missing issuer":      {ActiveKeyID: "key", SigningKeys: map[string]ed25519.PrivateKey{"key": private}},
		"missing active key":  {Issuer: "https://accounts.example.com", ActiveKeyID: "missing", SigningKeys: map[string]ed25519.PrivateKey{"key": private}},
		"invalid private key": {Issuer: "https://accounts.example.com", ActiveKeyID: "key", SigningKeys: map[string]ed25519.PrivateKey{"key": {1, 2, 3}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSigner(config); err == nil {
				t.Fatalf("NewSigner() accepted %s", name)
			}
		})
	}

	signer, _ := signingFixture(t)
	if _, err := signer.SignVersion(VersionSignatureInput{}); err == nil {
		t.Fatal("SignVersion() accepted empty identity")
	}
	if _, err := signer.SignPolicy(PolicySignatureInput{}); err == nil {
		t.Fatal("SignPolicy() accepted empty identity")
	}
}

func signingFixture(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	signer, err := NewSigner(SigningConfig{
		Issuer: "https://accounts.example.com", ActiveKeyID: "agent-control-v1",
		SigningKeys: map[string]ed25519.PrivateKey{"agent-control-v1": private},
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	verifier, err := NewVerifier(VerifierConfig{
		Issuer: "https://accounts.example.com",
		Keys: map[string]VerificationKey{
			"agent-control-v1": {Purpose: PurposeAgentVersion, PublicKey: private.Public().(ed25519.PublicKey)},
		},
		PolicyKeys: map[string]VerificationKey{
			"agent-control-v1": {Purpose: PurposeAgentPolicy, PublicKey: private.Public().(ed25519.PublicKey)},
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return signer, verifier
}
