package agentcontrol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	versionSignatureDomain = "agentera-agent-version-v1"
	policySignatureDomain  = "agentera-agent-policy-v1"
)

type SigningPurpose string

const (
	PurposeAgentVersion SigningPurpose = "agent_version"
	PurposeAgentPolicy  SigningPurpose = "agent_policy"
)

type SigningConfig struct {
	Issuer      string
	ActiveKeyID string
	SigningKeys map[string]ed25519.PrivateKey
}

type Signer struct {
	issuer      string
	activeKeyID string
	privateKeys map[string]ed25519.PrivateKey
}

type PublishedSigningKey struct {
	KeyID     string
	KeyType   string
	Curve     string
	Algorithm string
	Use       string
	X         string
	PublicKey ed25519.PublicKey
}

type VersionSignatureInput struct {
	DefinitionID   uuid.UUID
	VersionID      uuid.UUID
	VersionNumber  int64
	ManifestDigest [32]byte
	BundleDigest   [32]byte
}

type VersionAttestation struct {
	Issuer         string
	KeyID          string
	DefinitionID   uuid.UUID
	VersionID      uuid.UUID
	VersionNumber  int64
	ManifestDigest [32]byte
	BundleDigest   [32]byte
	Signature      []byte
}

type PolicySignatureInput struct {
	PolicyID       uuid.UUID
	PolicyVersion  int64
	DocumentDigest [32]byte
}

type PolicyAttestation struct {
	Issuer         string
	KeyID          string
	PolicyID       uuid.UUID
	PolicyVersion  int64
	DocumentDigest [32]byte
	Signature      []byte
}

type VerificationKey struct {
	Purpose   SigningPurpose
	PublicKey ed25519.PublicKey
}

type VerifierConfig struct {
	Issuer     string
	Keys       map[string]VerificationKey
	PolicyKeys map[string]VerificationKey
}

type Verifier struct {
	issuer      string
	versionKeys map[string]VerificationKey
	policyKeys  map[string]VerificationKey
}

func NewSigner(config SigningConfig) (*Signer, error) {
	if strings.TrimSpace(config.Issuer) == "" || config.Issuer != strings.TrimSpace(config.Issuer) ||
		strings.TrimSpace(config.ActiveKeyID) == "" {
		return nil, ErrInvalidSignature
	}
	privateKeys := make(map[string]ed25519.PrivateKey, len(config.SigningKeys))
	for keyID, privateKey := range config.SigningKeys {
		if strings.TrimSpace(keyID) == "" || keyID != strings.TrimSpace(keyID) || len(privateKey) != ed25519.PrivateKeySize {
			return nil, ErrInvalidSignature
		}
		canonical := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
		if !bytes.Equal(privateKey, canonical) {
			return nil, ErrInvalidSignature
		}
		privateKeys[keyID] = append(ed25519.PrivateKey(nil), privateKey...)
	}
	if _, exists := privateKeys[config.ActiveKeyID]; !exists {
		return nil, ErrInvalidSignature
	}
	return &Signer{issuer: config.Issuer, activeKeyID: config.ActiveKeyID, privateKeys: privateKeys}, nil
}

func (s *Signer) SignVersion(input VersionSignatureInput) (VersionAttestation, error) {
	if s == nil || input.DefinitionID == uuid.Nil || input.VersionID == uuid.Nil || input.VersionNumber <= 0 ||
		zeroDigest(input.ManifestDigest) || zeroDigest(input.BundleDigest) {
		return VersionAttestation{}, ErrInvalidSignature
	}
	signature := ed25519.Sign(s.privateKeys[s.activeKeyID], versionSignaturePayload(input))
	return VersionAttestation{
		Issuer: s.issuer, KeyID: s.activeKeyID,
		DefinitionID: input.DefinitionID, VersionID: input.VersionID, VersionNumber: input.VersionNumber,
		ManifestDigest: input.ManifestDigest, BundleDigest: input.BundleDigest, Signature: signature,
	}, nil
}

func (s *Signer) SignPolicy(input PolicySignatureInput) (PolicyAttestation, error) {
	if s == nil || input.PolicyID == uuid.Nil || input.PolicyVersion <= 0 || zeroDigest(input.DocumentDigest) {
		return PolicyAttestation{}, ErrInvalidSignature
	}
	signature := ed25519.Sign(s.privateKeys[s.activeKeyID], policySignaturePayload(input))
	return PolicyAttestation{
		Issuer: s.issuer, KeyID: s.activeKeyID, PolicyID: input.PolicyID,
		PolicyVersion: input.PolicyVersion, DocumentDigest: input.DocumentDigest, Signature: signature,
	}, nil
}

func (s *Signer) PublicKeys() []PublishedSigningKey {
	if s == nil {
		return nil
	}
	keyIDs := make([]string, 0, len(s.privateKeys))
	for keyID := range s.privateKeys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	published := make([]PublishedSigningKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		publicKey := s.privateKeys[keyID].Public().(ed25519.PublicKey)
		published = append(published, PublishedSigningKey{
			KeyID: keyID, KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig",
			X: base64.RawURLEncoding.EncodeToString(publicKey), PublicKey: append(ed25519.PublicKey(nil), publicKey...),
		})
	}
	return published
}

func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if strings.TrimSpace(config.Issuer) == "" || config.Issuer != strings.TrimSpace(config.Issuer) {
		return nil, ErrInvalidSignature
	}
	versionKeys, err := copyVerificationKeys(config.Keys)
	if err != nil {
		return nil, err
	}
	policyKeys, err := copyVerificationKeys(config.PolicyKeys)
	if err != nil {
		return nil, err
	}
	if len(versionKeys) == 0 && len(policyKeys) == 0 {
		return nil, ErrInvalidSignature
	}
	return &Verifier{issuer: config.Issuer, versionKeys: versionKeys, policyKeys: policyKeys}, nil
}

func (v *Verifier) VerifyVersion(attestation VersionAttestation) error {
	if v == nil || attestation.Issuer != v.issuer || attestation.DefinitionID == uuid.Nil ||
		attestation.VersionID == uuid.Nil || attestation.VersionNumber <= 0 ||
		zeroDigest(attestation.ManifestDigest) || zeroDigest(attestation.BundleDigest) ||
		len(attestation.Signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	key, exists := v.versionKeys[attestation.KeyID]
	if !exists || key.Purpose != PurposeAgentVersion || !ed25519.Verify(key.PublicKey, versionSignaturePayload(VersionSignatureInput{
		DefinitionID: attestation.DefinitionID, VersionID: attestation.VersionID,
		VersionNumber: attestation.VersionNumber, ManifestDigest: attestation.ManifestDigest, BundleDigest: attestation.BundleDigest,
	}), attestation.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (v *Verifier) VerifyPolicy(attestation PolicyAttestation) error {
	if v == nil || attestation.Issuer != v.issuer || attestation.PolicyID == uuid.Nil || attestation.PolicyVersion <= 0 ||
		zeroDigest(attestation.DocumentDigest) || len(attestation.Signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	key, exists := v.policyKeys[attestation.KeyID]
	if !exists || key.Purpose != PurposeAgentPolicy || !ed25519.Verify(key.PublicKey, policySignaturePayload(PolicySignatureInput{
		PolicyID: attestation.PolicyID, PolicyVersion: attestation.PolicyVersion, DocumentDigest: attestation.DocumentDigest,
	}), attestation.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func versionSignaturePayload(input VersionSignatureInput) []byte {
	return []byte(versionSignatureDomain + "\x00" + input.DefinitionID.String() + "\x00" + input.VersionID.String() + "\x00" +
		strconv.FormatInt(input.VersionNumber, 10) + "\x00" + hex.EncodeToString(input.ManifestDigest[:]) + "\x00" +
		hex.EncodeToString(input.BundleDigest[:]))
}

func policySignaturePayload(input PolicySignatureInput) []byte {
	return []byte(policySignatureDomain + "\x00" + input.PolicyID.String() + "\x00" + strconv.FormatInt(input.PolicyVersion, 10) +
		"\x00" + hex.EncodeToString(input.DocumentDigest[:]))
}

func copyVerificationKeys(input map[string]VerificationKey) (map[string]VerificationKey, error) {
	output := make(map[string]VerificationKey, len(input))
	for keyID, key := range input {
		if strings.TrimSpace(keyID) == "" || keyID != strings.TrimSpace(keyID) ||
			(key.Purpose != PurposeAgentVersion && key.Purpose != PurposeAgentPolicy) ||
			len(key.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrInvalidSignature
		}
		output[keyID] = VerificationKey{
			Purpose: key.Purpose, PublicKey: append(ed25519.PublicKey(nil), key.PublicKey...),
		}
	}
	return output, nil
}

func zeroDigest(value [32]byte) bool {
	var zero [32]byte
	return value == zero
}
