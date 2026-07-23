package encryptedbackup

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	BackupFormatVersion int16 = 1
	BackupCipherSuite         = "HPKE-X25519-HKDF-SHA256-AES256GCM+ARGON2ID+AES256GCM"

	RecoveryMemoryKiB   = 65536
	RecoveryIterations  = 3
	RecoveryParallelism = 1

	maximumChunkCount          = 131072
	maximumChunkCiphertextSize = 9_437_200
	maximumManifestBytes       = 16 << 20
	minimumCiphertextBytes     = 17
	maximumEnvelopeBytes       = 4096
	minimumEnvelopeBytes       = 48
)

var (
	ErrInvalidRequest       = errors.New("encrypted backup request is invalid")
	ErrInvalidSignature     = errors.New("encrypted backup signature is invalid")
	ErrUnauthorized         = errors.New("encrypted backup access is unauthorized")
	ErrDeviceRevoked        = errors.New("encrypted backup device is revoked")
	ErrBackupNotFound       = errors.New("encrypted backup was not found")
	ErrBackupConflict       = errors.New("encrypted backup conflicts with existing state")
	ErrBackupExpired        = errors.New("encrypted backup upload expired")
	ErrBackupIncomplete     = errors.New("encrypted backup upload is incomplete")
	ErrQuotaExceeded        = errors.New("encrypted backup quota exceeded")
	ErrEncryptedUnavailable = errors.New("encrypted backup service is unavailable")
)

type BackupState string

const (
	BackupStateInitiated BackupState = "initiated"
	BackupStateUploading BackupState = "uploading"
	BackupStateSealed    BackupState = "sealed"
	BackupStateDeleting  BackupState = "deleting"
	BackupStateDeleted   BackupState = "deleted"
	BackupStateExpired   BackupState = "expired"
)

type Principal struct {
	UserID   uuid.UUID
	DeviceID uuid.UUID
}

func (principal Principal) valid() bool {
	return principal.UserID != uuid.Nil && principal.DeviceID != uuid.Nil
}

type ObjectSpec struct {
	ObjectID         string
	CiphertextDigest [sha256.Size]byte
	CiphertextSize   int64
}

type ChunkSpec struct {
	Index int
	ObjectSpec
}

type PublicEnvelope struct {
	FormatVersion              int16
	CipherSuite                string
	BackupID                   uuid.UUID
	ProfileLineageID           uuid.UUID
	ParentBackupID             *uuid.UUID
	SourceDeviceID             uuid.UUID
	SourceInstallationID       uuid.UUID
	SourceDefinitionID         uuid.UUID
	SourceVersionID            uuid.UUID
	BaseOwnerScope             string
	KeyEpoch                   int64
	CreatedAt                  time.Time
	Manifest                   ObjectSpec
	Chunks                     []ChunkSpec
	TotalCiphertextSize        int64
	RecoveryEnvelopeDigest     [sha256.Size]byte
	WrappedDataKeyDigest       [sha256.Size]byte
	SourceDeviceEnvelopeDigest [sha256.Size]byte
}

func (envelope PublicEnvelope) valid(maxBackupBytes int64) bool {
	if envelope.FormatVersion != BackupFormatVersion ||
		envelope.CipherSuite != BackupCipherSuite ||
		envelope.BackupID == uuid.Nil ||
		envelope.ProfileLineageID == uuid.Nil ||
		envelope.SourceDeviceID == uuid.Nil ||
		envelope.SourceInstallationID == uuid.Nil ||
		envelope.SourceDefinitionID == uuid.Nil ||
		envelope.SourceVersionID == uuid.Nil ||
		envelope.BaseOwnerScope != "USER" ||
		envelope.KeyEpoch <= 0 ||
		envelope.CreatedAt.IsZero() ||
		envelope.CreatedAt.Location() != time.UTC ||
		envelope.TotalCiphertextSize < minimumCiphertextBytes ||
		envelope.TotalCiphertextSize > maxBackupBytes ||
		len(envelope.Chunks) < 1 ||
		len(envelope.Chunks) > maximumChunkCount ||
		!validObjectSpec(envelope.Manifest, maximumManifestBytes) {
		return false
	}
	if envelope.ParentBackupID != nil &&
		(*envelope.ParentBackupID == uuid.Nil || *envelope.ParentBackupID == envelope.BackupID) {
		return false
	}
	var total int64
	for index, chunk := range envelope.Chunks {
		if chunk.Index != index || !validObjectSpec(chunk.ObjectSpec, maximumChunkCiphertextSize) {
			return false
		}
		total += chunk.CiphertextSize
		if total < 0 || total > maxBackupBytes {
			return false
		}
	}
	return total == envelope.TotalCiphertextSize
}

func validObjectSpec(spec ObjectSpec, maximum int64) bool {
	return ciphertextObjectIDPattern.MatchString(spec.ObjectID) &&
		spec.CiphertextSize >= minimumCiphertextBytes &&
		spec.CiphertextSize <= maximum
}

type BackupDeviceRegistration struct {
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	KeyEpoch  int64
	Revision  int64
	PublicKey []byte
}

type RegisterDeviceCommand struct {
	KeyEpoch  int64
	Revision  int64
	PublicKey []byte
	Signature []byte
}

type RegistrationRecord struct {
	BackupDeviceRegistration
	Signature  []byte
	RecordedAt time.Time
}

type BackupDevice struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	KeyEpoch  int64
	PublicKey []byte
	Revision  int64
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
	RevokedAt *time.Time
}

type AuthenticationDevice struct {
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	PublicKey []byte
	Status    string
}

type RecoveryParameters struct {
	Salt        []byte
	MemoryKiB   int
	Iterations  int
	Parallelism int
}

type InitiateCommand struct {
	Principal                   Principal
	Envelope                    PublicEnvelope
	Signature                   []byte
	Recovery                    RecoveryParameters
	RecoveryRootKeyEnvelope     []byte
	WrappedDataKey              []byte
	SourceDeviceRootKeyEnvelope []byte
}

type InitiateResult struct {
	BackupID        uuid.UUID
	State           BackupState
	UploadExpiresAt time.Time
	Replayed        bool
}

type Backup struct {
	ID                      uuid.UUID
	UserID                  uuid.UUID
	SourceDeviceID          uuid.UUID
	SourceInstallationID    uuid.UUID
	SourceDefinitionID      uuid.UUID
	SourceVersionID         uuid.UUID
	ProfileLineageID        uuid.UUID
	ParentBackupID          *uuid.UUID
	FormatVersion           int16
	CipherSuite             string
	State                   BackupState
	KeyEpoch                int64
	ChunkCount              int
	TotalCiphertextSize     int64
	Manifest                ObjectSpec
	PublicEnvelopeDigest    [sha256.Size]byte
	PublicSignature         []byte
	Recovery                RecoveryParameters
	RecoveryRootKeyEnvelope []byte
	WrappedDataKey          []byte
	CreatedAt               time.Time
	UpdatedAt               time.Time
	UploadExpiresAt         time.Time
	SealedAt                *time.Time
	DeletionStartedAt       *time.Time
	DeletedAt               *time.Time
}

type KeyEnvelope struct {
	ID                    uuid.UUID
	BackupID              uuid.UUID
	BackupDeviceID        uuid.UUID
	DeviceID              uuid.UUID
	KeyEpoch              int64
	RootKeyEnvelope       []byte
	RootKeyEnvelopeDigest [sha256.Size]byte
	CreatedAt             time.Time
}

type BackupDetail struct {
	Backup
	Chunks                     []ChunkSpec
	SourceDevicePublicKey      []byte
	SourceDeviceEnvelopeDigest [sha256.Size]byte
	CurrentDeviceKey           *KeyEnvelope
}

type UploadTarget struct {
	BackupID        uuid.UUID
	UserID          uuid.UUID
	SourceDeviceID  uuid.UUID
	State           BackupState
	UploadExpiresAt time.Time
	Object          ObjectSpec
}

type EnvelopeRecord struct {
	ID                    uuid.UUID
	BackupID              uuid.UUID
	BackupDeviceID        uuid.UUID
	KeyEpoch              int64
	RootKeyEnvelope       []byte
	RootKeyEnvelopeDigest [sha256.Size]byte
	CreatedAt             time.Time
}

type InitiateRecord struct {
	Backup
	Chunks               []ChunkSpec
	SourceDeviceEnvelope EnvelopeRecord
	PublicEnvelopeDigest [sha256.Size]byte
}

type SealResult struct {
	BackupID uuid.UUID
	State    BackupState
	SealedAt *time.Time
	Replayed bool
}

type DeletionRecord struct {
	BackupID  uuid.UUID
	UserID    uuid.UUID
	State     BackupState
	ObjectIDs []string
}
