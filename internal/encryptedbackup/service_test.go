package encryptedbackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceRegistersBackupDeviceWithSignedMonotonicRevision(t *testing.T) {
	service, repository, _, identityPrivate, principal, now := newServiceFixture(t)
	publicKey := testBytes(32, 0x61)
	command := RegisterDeviceCommand{KeyEpoch: 1, Revision: 1, PublicKey: publicKey}
	command.Signature = ed25519.Sign(identityPrivate, BackupDeviceRegistrationSigningDigest(BackupDeviceRegistration{
		UserID: principal.UserID, DeviceID: principal.DeviceID,
		KeyEpoch: command.KeyEpoch, Revision: command.Revision, PublicKey: command.PublicKey,
	}))

	registered, replayed, err := service.RegisterDevice(context.Background(), principal, command)
	if err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if replayed || registered.Revision != 1 || registered.Status != "active" {
		t.Fatalf("RegisterDevice() = %#v, replayed=%v", registered, replayed)
	}

	replacement := command
	replacement.Revision = 2
	replacement.PublicKey = testBytes(32, 0x62)
	if _, _, err := service.RegisterDevice(context.Background(), principal, replacement); err != ErrInvalidSignature {
		t.Fatalf("unsigned replacement error = %v, want %v", err, ErrInvalidSignature)
	}
	replacement.Signature = ed25519.Sign(identityPrivate, BackupDeviceRegistrationSigningDigest(BackupDeviceRegistration{
		UserID: principal.UserID, DeviceID: principal.DeviceID,
		KeyEpoch: replacement.KeyEpoch, Revision: replacement.Revision, PublicKey: replacement.PublicKey,
	}))
	registered, replayed, err = service.RegisterDevice(context.Background(), principal, replacement)
	if err != nil {
		t.Fatalf("replacement RegisterDevice() error = %v", err)
	}
	if replayed || registered.Revision != 2 || !bytes.Equal(registered.PublicKey, replacement.PublicKey) {
		t.Fatalf("replacement RegisterDevice() = %#v, replayed=%v", registered, replayed)
	}

	stale := command
	stale.Signature = ed25519.Sign(identityPrivate, BackupDeviceRegistrationSigningDigest(BackupDeviceRegistration{
		UserID: principal.UserID, DeviceID: principal.DeviceID,
		KeyEpoch: stale.KeyEpoch, Revision: stale.Revision, PublicKey: stale.PublicKey,
	}))
	if _, _, err := service.RegisterDevice(context.Background(), principal, stale); err != ErrBackupConflict {
		t.Fatalf("stale registration error = %v, want %v", err, ErrBackupConflict)
	}
	if repository.registrationCount != 2 || !repository.lastRegistration.RecordedAt.Equal(now) {
		t.Fatalf("registration calls/time = %d/%v", repository.registrationCount, repository.lastRegistration.RecordedAt)
	}
}

func TestServiceRunsSignedUploadLifecycleAndSealsOnlyCompleteCiphertext(t *testing.T) {
	service, repository, objects, identityPrivate, principal, now := newServiceFixture(t)
	envelope := testPublicEnvelope()
	envelope.SourceDeviceID = principal.DeviceID
	envelope.CreatedAt = now
	signature := ed25519.Sign(identityPrivate, PublicEnvelopeSigningDigest(envelope))
	recoveryEnvelope := []byte("recovery-envelope-ciphertext-that-is-at-least-forty-eight-bytes")
	wrappedDataKey := []byte("wrapped-data-key-ciphertext-that-is-at-least-forty-eight-bytes")
	sourceEnvelope := []byte("source-device-envelope-ciphertext-that-is-at-least-forty-eight")
	envelope.RecoveryEnvelopeDigest = sha256.Sum256(recoveryEnvelope)
	envelope.WrappedDataKeyDigest = sha256.Sum256(wrappedDataKey)
	envelope.SourceDeviceEnvelopeDigest = sha256.Sum256(sourceEnvelope)
	signature = ed25519.Sign(identityPrivate, PublicEnvelopeSigningDigest(envelope))
	command := InitiateCommand{
		Principal: principal, Envelope: envelope, Signature: signature,
		Recovery: RecoveryParameters{
			Salt: testBytes(16, 0x71), MemoryKiB: RecoveryMemoryKiB,
			Iterations: RecoveryIterations, Parallelism: RecoveryParallelism,
		},
		RecoveryRootKeyEnvelope: recoveryEnvelope, WrappedDataKey: wrappedDataKey,
		SourceDeviceRootKeyEnvelope: sourceEnvelope,
	}

	initiated, err := service.Initiate(context.Background(), command)
	if err != nil {
		t.Fatalf("Initiate() error = %v", err)
	}
	if initiated.State != BackupStateInitiated || initiated.Replayed ||
		!initiated.UploadExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("Initiate() = %#v", initiated)
	}
	replayed, err := service.Initiate(context.Background(), command)
	if err != nil || !replayed.Replayed {
		t.Fatalf("replayed Initiate() = %#v, %v", replayed, err)
	}

	chunkBody := []byte("chunk ciphertext")
	envelope.Chunks[0].CiphertextDigest = sha256.Sum256(chunkBody)
	envelope.Chunks[0].CiphertextSize = int64(len(chunkBody))
	// The fixture minimum is intentionally enforced before object storage.
	if err := service.UploadChunk(context.Background(), principal, envelope.BackupID, 0, bytes.NewReader(chunkBody),
		int64(len(chunkBody)), sha256.Sum256(chunkBody)); err != ErrInvalidRequest {
		t.Fatalf("undersized chunk error = %v, want %v", err, ErrInvalidRequest)
	}

	chunkBody = testBytes(64, 0x72)
	repository.chunkTarget.Object.CiphertextDigest = sha256.Sum256(chunkBody)
	repository.chunkTarget.Object.CiphertextSize = int64(len(chunkBody))
	repository.detail.Chunks[0].ObjectSpec = repository.chunkTarget.Object
	if err := service.UploadChunk(context.Background(), principal, envelope.BackupID, 0, bytes.NewReader(chunkBody),
		int64(len(chunkBody)), sha256.Sum256([]byte("wrong"))); err != ErrCiphertextMismatch {
		t.Fatalf("chunk digest mismatch error = %v, want %v", err, ErrCiphertextMismatch)
	}
	if err := service.UploadChunk(context.Background(), principal, envelope.BackupID, 0, bytes.NewReader(chunkBody),
		int64(len(chunkBody)), sha256.Sum256(chunkBody)); err != nil {
		t.Fatalf("UploadChunk() error = %v", err)
	}
	if _, err := service.Seal(context.Background(), principal, envelope.BackupID); err != ErrBackupIncomplete {
		t.Fatalf("Seal() missing manifest error = %v, want %v", err, ErrBackupIncomplete)
	}

	manifestBody := testBytes(48, 0x73)
	repository.manifestTarget.Object.CiphertextDigest = sha256.Sum256(manifestBody)
	repository.manifestTarget.Object.CiphertextSize = int64(len(manifestBody))
	repository.detail.Manifest = repository.manifestTarget.Object
	if err := service.UploadManifest(context.Background(), principal, envelope.BackupID, bytes.NewReader(manifestBody),
		int64(len(manifestBody)), sha256.Sum256(manifestBody)); err != nil {
		t.Fatalf("UploadManifest() error = %v", err)
	}
	sealed, err := service.Seal(context.Background(), principal, envelope.BackupID)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if sealed.State != BackupStateSealed || sealed.Replayed || repository.sealCount != 1 {
		t.Fatalf("Seal() = %#v, calls=%d", sealed, repository.sealCount)
	}
	replayedSeal, err := service.Seal(context.Background(), principal, envelope.BackupID)
	if err != nil || !replayedSeal.Replayed {
		t.Fatalf("replayed Seal() = %#v, %v", replayedSeal, err)
	}
	if len(objects.putOrder) != 2 {
		t.Fatalf("object writes = %v, want chunk and manifest", objects.putOrder)
	}
}

func TestServiceRejectsInvalidSignatureRevokedDeviceExpiryAndQuota(t *testing.T) {
	service, repository, _, identityPrivate, principal, now := newServiceFixture(t)
	command := validInitiateCommand(identityPrivate, principal, now)
	command.Signature[0] ^= 0xff
	if _, err := service.Initiate(context.Background(), command); err != ErrInvalidSignature {
		t.Fatalf("invalid signature error = %v, want %v", err, ErrInvalidSignature)
	}

	command = validInitiateCommand(identityPrivate, principal, now)
	repository.authentication.Status = "revoked"
	if _, err := service.Initiate(context.Background(), command); err != ErrDeviceRevoked {
		t.Fatalf("revoked device error = %v, want %v", err, ErrDeviceRevoked)
	}

	repository.authentication.Status = "active"
	repository.initiateError = ErrQuotaExceeded
	if _, err := service.Initiate(context.Background(), command); err != ErrQuotaExceeded {
		t.Fatalf("quota error = %v, want %v", err, ErrQuotaExceeded)
	}
	repository.initiateError = nil
	repository.chunkTarget.UploadExpiresAt = now.Add(-time.Second)
	repository.chunkTarget.BackupID = command.Envelope.BackupID
	repository.chunkTarget.UserID = principal.UserID
	repository.chunkTarget.SourceDeviceID = principal.DeviceID
	repository.chunkTarget.State = BackupStateInitiated
	body := testBytes(64, 0x74)
	repository.chunkTarget.Object.CiphertextDigest = sha256.Sum256(body)
	repository.chunkTarget.Object.CiphertextSize = int64(len(body))
	if err := service.UploadChunk(context.Background(), principal, command.Envelope.BackupID, 0,
		bytes.NewReader(body), int64(len(body)), sha256.Sum256(body)); err != ErrBackupExpired {
		t.Fatalf("expired upload error = %v, want %v", err, ErrBackupExpired)
	}

	repository.backupDevice.Status = "revoked"
	repository.detail.State = BackupStateUploading
	repository.detail.KeyEpoch = 1
	repository.detail.SourceDeviceID = principal.DeviceID
	repository.detail.UploadExpiresAt = now.Add(time.Hour)
	if _, err := service.Seal(context.Background(), principal, repository.detail.ID); err != ErrDeviceRevoked {
		t.Fatalf("revoked backup source Seal() error = %v, want %v", err, ErrDeviceRevoked)
	}
}

func TestServiceScopesRestoreAndNeverReceivesRecoveryPhrase(t *testing.T) {
	service, repository, objects, _, principal, _ := newServiceFixture(t)
	repository.listResult = []Backup{{ID: uuid.New(), UserID: principal.UserID, State: BackupStateSealed}}
	found, err := service.List(context.Background(), principal)
	if err != nil || len(found) != 1 {
		t.Fatalf("List() = %#v, %v", found, err)
	}
	other := principal
	other.UserID = uuid.New()
	if _, err := service.Get(context.Background(), other, repository.detail.Backup.ID); err != ErrUnauthorized {
		t.Fatalf("cross-account Get() error = %v, want %v", err, ErrUnauthorized)
	}

	targetDeviceID := uuid.New()
	repository.targetBackupDevice = BackupDevice{
		ID: uuid.New(), UserID: principal.UserID, DeviceID: targetDeviceID,
		KeyEpoch: 1, Status: "revoked",
	}
	envelope := testBytes(80, 0x75)
	if _, err := service.AddDeviceEnvelope(context.Background(), principal, repository.detail.Backup.ID,
		targetDeviceID, 1, envelope, sha256.Sum256(envelope)); err != ErrDeviceRevoked {
		t.Fatalf("revoked envelope target error = %v, want %v", err, ErrDeviceRevoked)
	}

	repository.targetBackupDevice.Status = "active"
	repository.detail.State = BackupStateSealed
	download, err := service.Download(context.Background(), principal, repository.detail.Backup.ID,
		repository.detail.Manifest.ObjectID)
	if err != nil {
		t.Fatalf("phrase-path Download() error = %v", err)
	}
	_ = download.Body.Close()
	if repository.lastDownloadUserID != principal.UserID || objects.lastGetRef.ObjectID() != repository.detail.Manifest.ObjectID {
		t.Fatalf("download authorization/ref = %v/%s", repository.lastDownloadUserID, objects.lastGetRef.ObjectID())
	}
}

func TestServiceDestroysEnvelopesBeforeObjectCleanupAndLeavesDeletingOnFailure(t *testing.T) {
	service, repository, objects, _, principal, _ := newServiceFixture(t)
	objects.deleteError = ErrObjectStoreUnavailable
	err := service.Delete(context.Background(), principal, repository.deletion.BackupID)
	if !errors.Is(err, ErrObjectStoreUnavailable) {
		t.Fatalf("Delete() error = %v, want object-store failure", err)
	}
	if len(repository.events) == 0 || repository.events[0] != "begin_deletion" ||
		len(objects.deleteOrder) == 0 || repository.completeDeletionCount != 0 {
		t.Fatalf("deletion ordering/events = %v / %v / completed=%d",
			repository.events, objects.deleteOrder, repository.completeDeletionCount)
	}
	if repository.deletion.State != BackupStateDeleting {
		t.Fatalf("partial deletion state = %s, want deleting", repository.deletion.State)
	}

	objects.deleteError = nil
	if err := service.Delete(context.Background(), principal, repository.deletion.BackupID); err != nil {
		t.Fatalf("retry Delete() error = %v", err)
	}
	if repository.completeDeletionCount != 1 {
		t.Fatalf("completed deletion calls = %d, want 1", repository.completeDeletionCount)
	}
}

type memoryBackupRepository struct {
	authentication        AuthenticationDevice
	backupDevice          BackupDevice
	targetBackupDevice    BackupDevice
	lastRegistration      RegistrationRecord
	registrationCount     int
	initiateError         error
	initiated             bool
	initiateDigest        [sha256.Size]byte
	chunkTarget           UploadTarget
	manifestTarget        UploadTarget
	detail                BackupDetail
	listResult            []Backup
	lastDownloadUserID    uuid.UUID
	sealCount             int
	deletion              DeletionRecord
	events                []string
	completeDeletionCount int
}

func (repository *memoryBackupRepository) AuthenticationDevice(
	_ context.Context,
	userID, deviceID uuid.UUID,
) (AuthenticationDevice, error) {
	if repository.authentication.UserID != userID || repository.authentication.DeviceID != deviceID {
		return AuthenticationDevice{}, ErrUnauthorized
	}
	return repository.authentication, nil
}

func (repository *memoryBackupRepository) RegisterBackupDevice(
	_ context.Context,
	record RegistrationRecord,
) (BackupDevice, bool, error) {
	if repository.registrationCount > 0 {
		if record.Revision == repository.backupDevice.Revision &&
			bytes.Equal(record.PublicKey, repository.backupDevice.PublicKey) {
			return repository.backupDevice, true, nil
		}
		if record.Revision != repository.backupDevice.Revision+1 {
			return BackupDevice{}, false, ErrBackupConflict
		}
	}
	repository.registrationCount++
	repository.lastRegistration = record
	if repository.backupDevice.ID == uuid.Nil {
		repository.backupDevice.ID = uuid.New()
		repository.backupDevice.CreatedAt = record.RecordedAt
	}
	repository.backupDevice.UserID = record.UserID
	repository.backupDevice.DeviceID = record.DeviceID
	repository.backupDevice.KeyEpoch = record.KeyEpoch
	repository.backupDevice.PublicKey = append([]byte(nil), record.PublicKey...)
	repository.backupDevice.Revision = record.Revision
	repository.backupDevice.Status = "active"
	repository.backupDevice.UpdatedAt = record.RecordedAt
	return repository.backupDevice, false, nil
}

func (repository *memoryBackupRepository) RevokeBackupDevice(
	context.Context, uuid.UUID, uuid.UUID, time.Time,
) error {
	return nil
}

func (repository *memoryBackupRepository) BackupDevice(
	_ context.Context,
	userID, deviceID uuid.UUID,
	keyEpoch int64,
) (BackupDevice, error) {
	found := repository.backupDevice
	if repository.targetBackupDevice.DeviceID == deviceID {
		found = repository.targetBackupDevice
	}
	if found.UserID != userID || found.DeviceID != deviceID || found.KeyEpoch != keyEpoch {
		return BackupDevice{}, ErrUnauthorized
	}
	return found, nil
}

func (repository *memoryBackupRepository) LatestBackupDeviceStatus(
	_ context.Context,
	userID, deviceID uuid.UUID,
) (string, error) {
	if repository.backupDevice.UserID != userID ||
		repository.backupDevice.DeviceID != deviceID {
		return "", nil
	}
	return repository.backupDevice.Status, nil
}

func (repository *memoryBackupRepository) Initiate(
	_ context.Context,
	record InitiateRecord,
) (Backup, bool, error) {
	if repository.initiateError != nil {
		return Backup{}, false, repository.initiateError
	}
	if repository.initiated {
		if record.PublicEnvelopeDigest == repository.initiateDigest {
			return repository.detail.Backup, true, nil
		}
		return Backup{}, false, ErrBackupConflict
	}
	repository.initiated = true
	repository.initiateDigest = record.PublicEnvelopeDigest
	repository.detail.Backup = record.Backup
	repository.detail.Chunks = append([]ChunkSpec(nil), record.Chunks...)
	repository.chunkTarget = UploadTarget{
		BackupID: record.Backup.ID, UserID: record.Backup.UserID,
		SourceDeviceID: record.Backup.SourceDeviceID, State: BackupStateInitiated,
		UploadExpiresAt: record.Backup.UploadExpiresAt, Object: record.Chunks[0].ObjectSpec,
	}
	repository.manifestTarget = repository.chunkTarget
	repository.manifestTarget.Object = record.Backup.Manifest
	repository.deletion = DeletionRecord{
		BackupID: record.Backup.ID, UserID: record.Backup.UserID, State: BackupStateSealed,
		ObjectIDs: []string{record.Backup.Manifest.ObjectID, record.Chunks[0].ObjectID},
	}
	return record.Backup, false, nil
}

func (repository *memoryBackupRepository) ChunkUploadTarget(
	context.Context, uuid.UUID, uuid.UUID, int,
) (UploadTarget, error) {
	return repository.chunkTarget, nil
}

func (repository *memoryBackupRepository) ManifestUploadTarget(
	context.Context, uuid.UUID, uuid.UUID,
) (UploadTarget, error) {
	return repository.manifestTarget, nil
}

func (repository *memoryBackupRepository) MarkUploading(context.Context, uuid.UUID, uuid.UUID, time.Time) error {
	repository.detail.State = BackupStateUploading
	return nil
}

func (repository *memoryBackupRepository) BackupForSeal(
	_ context.Context, userID, backupID uuid.UUID,
) (BackupDetail, error) {
	if repository.detail.UserID != userID || repository.detail.ID != backupID {
		return BackupDetail{}, ErrBackupNotFound
	}
	return repository.detail, nil
}

func (repository *memoryBackupRepository) Seal(
	context.Context, uuid.UUID, uuid.UUID, time.Time,
) (Backup, bool, error) {
	if repository.detail.State == BackupStateSealed {
		return repository.detail.Backup, true, nil
	}
	repository.detail.State = BackupStateSealed
	repository.sealCount++
	return repository.detail.Backup, false, nil
}

func (repository *memoryBackupRepository) ListSealed(
	_ context.Context, userID uuid.UUID,
) ([]Backup, error) {
	for _, backup := range repository.listResult {
		if backup.UserID != userID {
			return nil, ErrBackupNotFound
		}
	}
	return repository.listResult, nil
}

func (repository *memoryBackupRepository) GetSealed(
	_ context.Context, userID, backupID, deviceID uuid.UUID,
) (BackupDetail, error) {
	repository.lastDownloadUserID = userID
	if repository.detail.UserID != userID || repository.detail.ID != backupID {
		return BackupDetail{}, ErrBackupNotFound
	}
	return repository.detail, nil
}

func (repository *memoryBackupRepository) AddDeviceEnvelope(
	context.Context, uuid.UUID, uuid.UUID, EnvelopeRecord,
) (bool, error) {
	return false, nil
}

func (repository *memoryBackupRepository) BeginDeletion(
	_ context.Context, userID, backupID uuid.UUID, _ time.Time,
) (DeletionRecord, error) {
	repository.events = append(repository.events, "begin_deletion")
	if repository.deletion.UserID != userID || repository.deletion.BackupID != backupID {
		return DeletionRecord{}, ErrBackupNotFound
	}
	repository.deletion.State = BackupStateDeleting
	return repository.deletion, nil
}

func (repository *memoryBackupRepository) CompleteDeletion(
	context.Context, uuid.UUID, uuid.UUID, time.Time,
) error {
	repository.completeDeletionCount++
	repository.deletion.State = BackupStateDeleted
	return nil
}

type memoryObjectStore struct {
	objects     map[string][]byte
	putOrder    []string
	deleteOrder []string
	deleteError error
	lastGetRef  CiphertextObjectRef
}

func (store *memoryObjectStore) PutCiphertext(
	_ context.Context,
	ref CiphertextObjectRef,
	body io.Reader,
	size int64,
	digest [sha256.Size]byte,
) (CiphertextMetadata, error) {
	value, err := io.ReadAll(body)
	if err != nil {
		return CiphertextMetadata{}, err
	}
	actual := sha256.Sum256(value)
	if int64(len(value)) != size || actual != digest {
		return CiphertextMetadata{}, ErrCiphertextMismatch
	}
	if _, exists := store.objects[ref.ObjectID()]; exists {
		return CiphertextMetadata{}, ErrCiphertextAlreadyExists
	}
	store.objects[ref.ObjectID()] = value
	store.putOrder = append(store.putOrder, ref.ObjectID())
	return CiphertextMetadata{Key: ref.ObjectID(), Size: size, SHA256: digest}, nil
}

func (store *memoryObjectStore) GetCiphertext(
	_ context.Context,
	ref CiphertextObjectRef,
) (CiphertextDownload, error) {
	store.lastGetRef = ref
	value, exists := store.objects[ref.ObjectID()]
	if !exists {
		// The restore authorization test is about the absence of a recovery
		// phrase in the service contract, not object-store seeding.
		value = []byte("ciphertext")
	}
	digest := sha256.Sum256(value)
	return CiphertextDownload{
		Body: io.NopCloser(bytes.NewReader(value)),
		Metadata: CiphertextMetadata{
			Key: ref.ObjectID(), Size: int64(len(value)), SHA256: digest,
		},
	}, nil
}

func (store *memoryObjectStore) HeadCiphertext(
	_ context.Context,
	ref CiphertextObjectRef,
) (CiphertextMetadata, error) {
	value, exists := store.objects[ref.ObjectID()]
	if !exists {
		return CiphertextMetadata{}, ErrCiphertextNotFound
	}
	return CiphertextMetadata{
		Key: ref.ObjectID(), Size: int64(len(value)), SHA256: sha256.Sum256(value),
	}, nil
}

func (store *memoryObjectStore) DeleteCiphertexts(_ context.Context, refs []CiphertextObjectRef) error {
	for _, ref := range refs {
		store.deleteOrder = append(store.deleteOrder, ref.ObjectID())
	}
	if store.deleteError != nil {
		return store.deleteError
	}
	for _, ref := range refs {
		delete(store.objects, ref.ObjectID())
	}
	return nil
}

func newServiceFixture(
	t *testing.T,
) (*Service, *memoryBackupRepository, *memoryObjectStore, ed25519.PrivateKey, Principal, time.Time) {
	t.Helper()
	identityPublic, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Date(2026, 7, 23, 3, 0, 0, 0, time.UTC)
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New()}
	repository := &memoryBackupRepository{
		authentication: AuthenticationDevice{
			UserID: principal.UserID, DeviceID: principal.DeviceID,
			PublicKey: identityPublic, Status: "active",
		},
		backupDevice: BackupDevice{
			ID: uuid.New(), UserID: principal.UserID, DeviceID: principal.DeviceID,
			KeyEpoch: 1, PublicKey: testBytes(32, 0x61), Revision: 1, Status: "active",
		},
	}
	detail := testPublicEnvelope()
	detail.SourceDeviceID = principal.DeviceID
	repository.detail = BackupDetail{Backup: Backup{
		ID: detail.BackupID, UserID: principal.UserID, SourceDeviceID: principal.DeviceID,
		State: BackupStateUploading, KeyEpoch: 1, UploadExpiresAt: now.Add(24 * time.Hour),
		Manifest: detail.Manifest,
	}, Chunks: append([]ChunkSpec(nil), detail.Chunks...)}
	repository.deletion = DeletionRecord{
		BackupID: repository.detail.ID, UserID: principal.UserID, State: BackupStateSealed,
		ObjectIDs: []string{detail.Manifest.ObjectID, detail.Chunks[0].ObjectID},
	}
	objects := &memoryObjectStore{objects: make(map[string][]byte)}
	service, err := NewService(ServiceConfig{
		Repository: repository, Objects: objects, Clock: func() time.Time { return now },
		MaxBackupBytes: 1 << 30, UploadTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service, repository, objects, identityPrivate, principal, now
}

func validInitiateCommand(
	identityPrivate ed25519.PrivateKey,
	principal Principal,
	now time.Time,
) InitiateCommand {
	envelope := testPublicEnvelope()
	envelope.SourceDeviceID = principal.DeviceID
	envelope.CreatedAt = now
	recoveryEnvelope := testBytes(64, 0x81)
	wrappedDataKey := testBytes(64, 0x82)
	sourceDeviceEnvelope := testBytes(64, 0x83)
	envelope.RecoveryEnvelopeDigest = sha256.Sum256(recoveryEnvelope)
	envelope.WrappedDataKeyDigest = sha256.Sum256(wrappedDataKey)
	envelope.SourceDeviceEnvelopeDigest = sha256.Sum256(sourceDeviceEnvelope)
	return InitiateCommand{
		Principal: principal, Envelope: envelope,
		Signature: ed25519.Sign(identityPrivate, PublicEnvelopeSigningDigest(envelope)),
		Recovery: RecoveryParameters{
			Salt: testBytes(16, 0x84), MemoryKiB: RecoveryMemoryKiB,
			Iterations: RecoveryIterations, Parallelism: RecoveryParallelism,
		},
		RecoveryRootKeyEnvelope: recoveryEnvelope, WrappedDataKey: wrappedDataKey,
		SourceDeviceRootKeyEnvelope: sourceDeviceEnvelope,
	}
}
