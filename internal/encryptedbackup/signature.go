package encryptedbackup

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
)

const (
	publicEnvelopeSignatureDomain  = "agentera-encrypted-profile-backup-public-envelope.v1\x00"
	backupDeviceRegistrationDomain = "agentera-encrypted-profile-backup-device-registration.v1\x00"
)

type canonicalObjectSpec struct {
	ObjectID         string `json:"object_id"`
	CiphertextDigest string `json:"ciphertext_digest"`
	CiphertextSize   int64  `json:"ciphertext_size"`
}

type canonicalChunkSpec struct {
	Index int `json:"index"`
	canonicalObjectSpec
}

type canonicalPublicEnvelope struct {
	FormatVersion              int16                `json:"format_version"`
	CipherSuite                string               `json:"cipher_suite"`
	BackupID                   string               `json:"backup_id"`
	ProfileLineageID           string               `json:"profile_lineage_id"`
	ParentBackupID             *string              `json:"parent_backup_id"`
	SourceDeviceID             string               `json:"source_device_id"`
	SourceInstallationID       string               `json:"source_installation_id"`
	SourceDefinitionID         string               `json:"source_definition_id"`
	SourceVersionID            string               `json:"source_version_id"`
	BaseOwnerScope             string               `json:"base_owner_scope"`
	KeyEpoch                   int64                `json:"key_epoch"`
	CreatedAt                  string               `json:"created_at"`
	Manifest                   canonicalObjectSpec  `json:"manifest"`
	Chunks                     []canonicalChunkSpec `json:"chunks"`
	TotalCiphertextSize        int64                `json:"total_ciphertext_size"`
	RecoveryEnvelopeDigest     string               `json:"recovery_envelope_digest"`
	WrappedDataKeyDigest       string               `json:"wrapped_data_key_digest"`
	SourceDeviceEnvelopeDigest string               `json:"source_device_envelope_digest"`
}

type canonicalBackupDeviceRegistration struct {
	UserID    string `json:"user_id"`
	DeviceID  string `json:"device_id"`
	KeyEpoch  int64  `json:"key_epoch"`
	Revision  int64  `json:"revision"`
	PublicKey string `json:"public_key"`
}

func PublicEnvelopeSigningDigest(envelope PublicEnvelope) []byte {
	parentID := (*string)(nil)
	if envelope.ParentBackupID != nil {
		value := envelope.ParentBackupID.String()
		parentID = &value
	}
	chunks := make([]canonicalChunkSpec, len(envelope.Chunks))
	for index, chunk := range envelope.Chunks {
		chunks[index] = canonicalChunkSpec{
			Index:               index,
			canonicalObjectSpec: canonicalizeObjectSpec(chunk.ObjectSpec),
		}
	}
	canonical := canonicalPublicEnvelope{
		FormatVersion: envelope.FormatVersion, CipherSuite: envelope.CipherSuite,
		BackupID: envelope.BackupID.String(), ProfileLineageID: envelope.ProfileLineageID.String(),
		ParentBackupID: parentID, SourceDeviceID: envelope.SourceDeviceID.String(),
		SourceInstallationID: envelope.SourceInstallationID.String(),
		SourceDefinitionID:   envelope.SourceDefinitionID.String(), SourceVersionID: envelope.SourceVersionID.String(),
		BaseOwnerScope: envelope.BaseOwnerScope, KeyEpoch: envelope.KeyEpoch,
		CreatedAt: envelope.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		Manifest:  canonicalizeObjectSpec(envelope.Manifest), Chunks: chunks,
		TotalCiphertextSize:        envelope.TotalCiphertextSize,
		RecoveryEnvelopeDigest:     base64.RawURLEncoding.EncodeToString(envelope.RecoveryEnvelopeDigest[:]),
		WrappedDataKeyDigest:       base64.RawURLEncoding.EncodeToString(envelope.WrappedDataKeyDigest[:]),
		SourceDeviceEnvelopeDigest: base64.RawURLEncoding.EncodeToString(envelope.SourceDeviceEnvelopeDigest[:]),
	}
	serialized, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(append([]byte(publicEnvelopeSignatureDomain), serialized...))
	return digest[:]
}

func VerifyPublicEnvelopeSignature(
	publicKey ed25519.PublicKey,
	envelope PublicEnvelope,
	signature []byte,
) error {
	if len(publicKey) != ed25519.PublicKeySize ||
		len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, PublicEnvelopeSigningDigest(envelope), signature) {
		return ErrInvalidSignature
	}
	return nil
}

func BackupDeviceRegistrationSigningDigest(registration BackupDeviceRegistration) []byte {
	canonical := canonicalBackupDeviceRegistration{
		UserID: registration.UserID.String(), DeviceID: registration.DeviceID.String(),
		KeyEpoch: registration.KeyEpoch, Revision: registration.Revision,
		PublicKey: base64.RawURLEncoding.EncodeToString(registration.PublicKey),
	}
	serialized, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(append([]byte(backupDeviceRegistrationDomain), serialized...))
	return digest[:]
}

func VerifyBackupDeviceRegistrationSignature(
	publicKey ed25519.PublicKey,
	registration BackupDeviceRegistration,
	signature []byte,
) error {
	if len(publicKey) != ed25519.PublicKeySize ||
		len(registration.PublicKey) != 32 ||
		len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, BackupDeviceRegistrationSigningDigest(registration), signature) {
		return ErrInvalidSignature
	}
	return nil
}

func digestMatches(value []byte, expected [sha256.Size]byte) bool {
	actual := sha256.Sum256(value)
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

func canonicalizeObjectSpec(spec ObjectSpec) canonicalObjectSpec {
	return canonicalObjectSpec{
		ObjectID:         spec.ObjectID,
		CiphertextDigest: base64.RawURLEncoding.EncodeToString(spec.CiphertextDigest[:]),
		CiphertextSize:   spec.CiphertextSize,
	}
}
