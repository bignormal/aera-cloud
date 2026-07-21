package organization

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

const organizationPolicySignatureDomain = "agentera-organization-policy-v1"

type SigningPurpose string

const PurposeOrganizationPolicy SigningPurpose = "organization_policy"

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
	Purpose   SigningPurpose
	X         string
	PublicKey ed25519.PublicKey
}

type PolicySignatureInput struct {
	OrganizationID uuid.UUID
	SnapshotID     uuid.UUID
	PolicyVersion  int64
	ContentDigest  [32]byte
}

type PolicyAttestation struct {
	Issuer         string
	KeyID          string
	OrganizationID uuid.UUID
	SnapshotID     uuid.UUID
	PolicyVersion  int64
	ContentDigest  [32]byte
	Signature      []byte
}

type VerificationKey struct {
	Purpose   SigningPurpose
	PublicKey ed25519.PublicKey
}

type VerifierConfig struct {
	Issuer string
	Keys   map[string]VerificationKey
}

type Verifier struct {
	issuer string
	keys   map[string]VerificationKey
}

func NewSigner(config SigningConfig) (*Signer, error) {
	if strings.TrimSpace(config.Issuer) == "" || config.Issuer != strings.TrimSpace(config.Issuer) ||
		strings.TrimSpace(config.ActiveKeyID) == "" || config.ActiveKeyID != strings.TrimSpace(config.ActiveKeyID) {
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

func (s *Signer) SignPolicy(input PolicySignatureInput) (PolicyAttestation, error) {
	if s == nil || input.OrganizationID == uuid.Nil || input.SnapshotID == uuid.Nil || input.PolicyVersion <= 0 ||
		zeroPolicyDigest(input.ContentDigest) {
		return PolicyAttestation{}, ErrInvalidSignature
	}
	signature := ed25519.Sign(s.privateKeys[s.activeKeyID], organizationPolicySignaturePayload(input))
	return PolicyAttestation{
		Issuer: s.issuer, KeyID: s.activeKeyID, OrganizationID: input.OrganizationID, SnapshotID: input.SnapshotID,
		PolicyVersion: input.PolicyVersion, ContentDigest: input.ContentDigest, Signature: signature,
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
	result := make([]PublishedSigningKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		publicKey := s.privateKeys[keyID].Public().(ed25519.PublicKey)
		result = append(result, PublishedSigningKey{
			KeyID: keyID, KeyType: "OKP", Curve: "Ed25519", Algorithm: "EdDSA", Use: "sig",
			Purpose: PurposeOrganizationPolicy, X: base64.RawURLEncoding.EncodeToString(publicKey),
			PublicKey: append(ed25519.PublicKey(nil), publicKey...),
		})
	}
	return result
}

func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if strings.TrimSpace(config.Issuer) == "" || config.Issuer != strings.TrimSpace(config.Issuer) {
		return nil, ErrInvalidSignature
	}
	keys := make(map[string]VerificationKey, len(config.Keys))
	for keyID, key := range config.Keys {
		if strings.TrimSpace(keyID) == "" || keyID != strings.TrimSpace(keyID) ||
			key.Purpose != PurposeOrganizationPolicy || len(key.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrInvalidSignature
		}
		keys[keyID] = VerificationKey{Purpose: key.Purpose, PublicKey: append(ed25519.PublicKey(nil), key.PublicKey...)}
	}
	if len(keys) == 0 {
		return nil, ErrInvalidSignature
	}
	return &Verifier{issuer: config.Issuer, keys: keys}, nil
}

func (v *Verifier) VerifyPolicy(attestation PolicyAttestation) error {
	if v == nil || attestation.Issuer != v.issuer || attestation.OrganizationID == uuid.Nil ||
		attestation.SnapshotID == uuid.Nil || attestation.PolicyVersion <= 0 || zeroPolicyDigest(attestation.ContentDigest) ||
		len(attestation.Signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	key, exists := v.keys[attestation.KeyID]
	if !exists || key.Purpose != PurposeOrganizationPolicy || !ed25519.Verify(
		key.PublicKey,
		organizationPolicySignaturePayload(PolicySignatureInput{
			OrganizationID: attestation.OrganizationID, SnapshotID: attestation.SnapshotID,
			PolicyVersion: attestation.PolicyVersion, ContentDigest: attestation.ContentDigest,
		}),
		attestation.Signature,
	) {
		return ErrInvalidSignature
	}
	return nil
}

func organizationPolicySignaturePayload(input PolicySignatureInput) []byte {
	return []byte(organizationPolicySignatureDomain + "\x00" + input.OrganizationID.String() + "\x00" + input.SnapshotID.String() +
		"\x00" + strconv.FormatInt(input.PolicyVersion, 10) + "\x00" + hex.EncodeToString(input.ContentDigest[:]))
}

func zeroPolicyDigest(value [32]byte) bool {
	var zero [32]byte
	return value == zero
}
