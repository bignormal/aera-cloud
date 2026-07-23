package encryptedbackup

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/google/uuid"
)

const maximumEnvelopeClockSkew = 5 * time.Minute

type Repository interface {
	AuthenticationDevice(context.Context, uuid.UUID, uuid.UUID) (AuthenticationDevice, error)
	RegisterBackupDevice(context.Context, RegistrationRecord) (BackupDevice, bool, error)
	RevokeBackupDevice(context.Context, uuid.UUID, uuid.UUID, time.Time) error
	BackupDevice(context.Context, uuid.UUID, uuid.UUID, int64) (BackupDevice, error)
	LatestBackupDeviceStatus(context.Context, uuid.UUID, uuid.UUID) (string, error)
	ListBackupDevices(context.Context, uuid.UUID) ([]BackupDevice, error)
	Initiate(context.Context, InitiateRecord) (Backup, bool, error)
	ChunkUploadTarget(context.Context, uuid.UUID, uuid.UUID, int) (UploadTarget, error)
	ManifestUploadTarget(context.Context, uuid.UUID, uuid.UUID) (UploadTarget, error)
	MarkUploading(context.Context, uuid.UUID, uuid.UUID, time.Time) error
	BackupForSeal(context.Context, uuid.UUID, uuid.UUID) (BackupDetail, error)
	Seal(context.Context, uuid.UUID, uuid.UUID, time.Time) (Backup, bool, error)
	ListSealed(context.Context, uuid.UUID) ([]Backup, error)
	GetSealed(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (BackupDetail, error)
	AddDeviceEnvelope(context.Context, uuid.UUID, uuid.UUID, EnvelopeRecord) (bool, error)
	BeginDeletion(context.Context, uuid.UUID, uuid.UUID, time.Time) (DeletionRecord, error)
	CompleteDeletion(context.Context, uuid.UUID, uuid.UUID, time.Time) error
}

type ServiceConfig struct {
	Repository     Repository
	Objects        ObjectStore
	Clock          func() time.Time
	MaxBackupBytes int64
	UploadTTL      time.Duration
}

type Service struct {
	repository     Repository
	objects        ObjectStore
	clock          func() time.Time
	maxBackupBytes int64
	uploadTTL      time.Duration
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil ||
		config.Objects == nil ||
		config.MaxBackupBytes < minimumCiphertextBytes ||
		config.MaxBackupBytes > maxCiphertextObjectBytes ||
		config.UploadTTL <= 0 ||
		config.UploadTTL > 24*time.Hour {
		return nil, errors.New("encrypted backup service configuration is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		repository:     config.Repository,
		objects:        config.Objects,
		clock:          clock,
		maxBackupBytes: config.MaxBackupBytes,
		uploadTTL:      config.UploadTTL,
	}, nil
}

func (service *Service) RegisterDevice(
	ctx context.Context,
	principal Principal,
	command RegisterDeviceCommand,
) (BackupDevice, bool, error) {
	if service == nil || !principal.valid() ||
		command.KeyEpoch <= 0 ||
		command.Revision <= 0 ||
		len(command.PublicKey) != 32 ||
		len(command.Signature) != ed25519.SignatureSize {
		return BackupDevice{}, false, ErrInvalidRequest
	}
	identity, err := service.activeAuthenticationDevice(ctx, principal)
	if err != nil {
		return BackupDevice{}, false, err
	}
	registration := BackupDeviceRegistration{
		UserID:    principal.UserID,
		DeviceID:  principal.DeviceID,
		KeyEpoch:  command.KeyEpoch,
		Revision:  command.Revision,
		PublicKey: append([]byte(nil), command.PublicKey...),
	}
	if err := VerifyBackupDeviceRegistrationSignature(
		ed25519.PublicKey(identity.PublicKey),
		registration,
		command.Signature,
	); err != nil {
		return BackupDevice{}, false, err
	}
	return service.repository.RegisterBackupDevice(ctx, RegistrationRecord{
		BackupDeviceRegistration: registration,
		Signature:                append([]byte(nil), command.Signature...),
		RecordedAt:               service.clock().UTC(),
	})
}

func (service *Service) RevokeDevice(
	ctx context.Context,
	principal Principal,
	targetDeviceID uuid.UUID,
) error {
	if service == nil || !principal.valid() || targetDeviceID == uuid.Nil {
		return ErrInvalidRequest
	}
	if _, err := service.activeAuthenticationDevice(ctx, principal); err != nil {
		return err
	}
	return service.repository.RevokeBackupDevice(
		ctx,
		principal.UserID,
		targetDeviceID,
		service.clock().UTC(),
	)
}

func (service *Service) ListDevices(
	ctx context.Context,
	principal Principal,
) ([]BackupDevice, error) {
	if service == nil || !principal.valid() {
		return nil, ErrInvalidRequest
	}
	if _, err := service.activeAuthenticationDevice(ctx, principal); err != nil {
		return nil, err
	}
	if err := service.ensureBackupDeviceNotRevoked(ctx, principal); err != nil {
		return nil, err
	}
	devices, err := service.repository.ListBackupDevices(ctx, principal.UserID)
	if err != nil {
		return nil, err
	}
	for index := range devices {
		if devices[index].UserID != principal.UserID ||
			devices[index].DeviceID == uuid.Nil ||
			devices[index].KeyEpoch <= 0 ||
			devices[index].Revision <= 0 ||
			len(devices[index].PublicKey) != 32 ||
			(devices[index].Status != "active" && devices[index].Status != "revoked") {
			return nil, ErrEncryptedUnavailable
		}
		devices[index].PublicKey = append([]byte(nil), devices[index].PublicKey...)
	}
	return devices, nil
}

func (service *Service) Initiate(
	ctx context.Context,
	command InitiateCommand,
) (InitiateResult, error) {
	if service == nil ||
		!command.Principal.valid() ||
		command.Envelope.SourceDeviceID != command.Principal.DeviceID ||
		!command.Envelope.valid(service.maxBackupBytes) ||
		len(command.Signature) != ed25519.SignatureSize ||
		!validRecovery(command.Recovery) ||
		!validEnvelope(command.RecoveryRootKeyEnvelope) ||
		!validEnvelope(command.WrappedDataKey) ||
		!validEnvelope(command.SourceDeviceRootKeyEnvelope) ||
		!digestMatches(command.RecoveryRootKeyEnvelope, command.Envelope.RecoveryEnvelopeDigest) ||
		!digestMatches(command.WrappedDataKey, command.Envelope.WrappedDataKeyDigest) ||
		!digestMatches(command.SourceDeviceRootKeyEnvelope, command.Envelope.SourceDeviceEnvelopeDigest) {
		return InitiateResult{}, ErrInvalidRequest
	}
	now := service.clock().UTC()
	delta := now.Sub(command.Envelope.CreatedAt)
	if delta < -maximumEnvelopeClockSkew || delta > maximumEnvelopeClockSkew {
		return InitiateResult{}, ErrInvalidRequest
	}
	identity, err := service.activeAuthenticationDevice(ctx, command.Principal)
	if err != nil {
		return InitiateResult{}, err
	}
	if err := VerifyPublicEnvelopeSignature(
		ed25519.PublicKey(identity.PublicKey),
		command.Envelope,
		command.Signature,
	); err != nil {
		return InitiateResult{}, err
	}
	recordedAt := now
	if command.Envelope.CreatedAt.After(recordedAt) {
		recordedAt = command.Envelope.CreatedAt
	}
	backupDevice, err := service.repository.BackupDevice(
		ctx,
		command.Principal.UserID,
		command.Principal.DeviceID,
		command.Envelope.KeyEpoch,
	)
	if err != nil {
		return InitiateResult{}, err
	}
	if backupDevice.Status != "active" {
		return InitiateResult{}, ErrDeviceRevoked
	}
	envelopeDigest := PublicEnvelopeSigningDigest(command.Envelope)
	var storedDigest [sha256.Size]byte
	copy(storedDigest[:], envelopeDigest)
	sourceEnvelopeID, err := secure.RandomUUID()
	if err != nil {
		return InitiateResult{}, ErrEncryptedUnavailable
	}
	record := InitiateRecord{
		Backup: Backup{
			ID:                      command.Envelope.BackupID,
			UserID:                  command.Principal.UserID,
			SourceDeviceID:          command.Envelope.SourceDeviceID,
			SourceInstallationID:    command.Envelope.SourceInstallationID,
			SourceDefinitionID:      command.Envelope.SourceDefinitionID,
			SourceVersionID:         command.Envelope.SourceVersionID,
			ProfileLineageID:        command.Envelope.ProfileLineageID,
			ParentBackupID:          cloneUUIDPointer(command.Envelope.ParentBackupID),
			FormatVersion:           command.Envelope.FormatVersion,
			CipherSuite:             command.Envelope.CipherSuite,
			State:                   BackupStateInitiated,
			KeyEpoch:                command.Envelope.KeyEpoch,
			ChunkCount:              len(command.Envelope.Chunks),
			TotalCiphertextSize:     command.Envelope.TotalCiphertextSize,
			Manifest:                command.Envelope.Manifest,
			PublicEnvelopeDigest:    storedDigest,
			PublicSignature:         append([]byte(nil), command.Signature...),
			Recovery:                cloneRecovery(command.Recovery),
			RecoveryRootKeyEnvelope: append([]byte(nil), command.RecoveryRootKeyEnvelope...),
			WrappedDataKey:          append([]byte(nil), command.WrappedDataKey...),
			CreatedAt:               command.Envelope.CreatedAt,
			UpdatedAt:               recordedAt,
			UploadExpiresAt:         command.Envelope.CreatedAt.Add(service.uploadTTL),
		},
		Chunks: append([]ChunkSpec(nil), command.Envelope.Chunks...),
		SourceDeviceEnvelope: EnvelopeRecord{
			ID:                    sourceEnvelopeID,
			BackupID:              command.Envelope.BackupID,
			BackupDeviceID:        backupDevice.ID,
			KeyEpoch:              backupDevice.KeyEpoch,
			RootKeyEnvelope:       append([]byte(nil), command.SourceDeviceRootKeyEnvelope...),
			RootKeyEnvelopeDigest: command.Envelope.SourceDeviceEnvelopeDigest,
			CreatedAt:             recordedAt,
		},
		PublicEnvelopeDigest: storedDigest,
	}
	created, replayed, err := service.repository.Initiate(ctx, record)
	if err != nil {
		return InitiateResult{}, err
	}
	return InitiateResult{
		BackupID:        created.ID,
		State:           created.State,
		UploadExpiresAt: created.UploadExpiresAt,
		Replayed:        replayed,
	}, nil
}

func (service *Service) UploadChunk(
	ctx context.Context,
	principal Principal,
	backupID uuid.UUID,
	index int,
	body io.Reader,
	size int64,
	digest [sha256.Size]byte,
) error {
	if service == nil || !principal.valid() || backupID == uuid.Nil ||
		index < 0 || index >= maximumChunkCount {
		return ErrInvalidRequest
	}
	target, err := service.repository.ChunkUploadTarget(
		ctx,
		principal.UserID,
		backupID,
		index,
	)
	if err != nil {
		return err
	}
	return service.upload(ctx, principal, target, body, size, digest)
}

func (service *Service) UploadManifest(
	ctx context.Context,
	principal Principal,
	backupID uuid.UUID,
	body io.Reader,
	size int64,
	digest [sha256.Size]byte,
) error {
	if service == nil || !principal.valid() || backupID == uuid.Nil {
		return ErrInvalidRequest
	}
	target, err := service.repository.ManifestUploadTarget(
		ctx,
		principal.UserID,
		backupID,
	)
	if err != nil {
		return err
	}
	return service.upload(ctx, principal, target, body, size, digest)
}

func (service *Service) upload(
	ctx context.Context,
	principal Principal,
	target UploadTarget,
	body io.Reader,
	size int64,
	digest [sha256.Size]byte,
) error {
	if target.BackupID == uuid.Nil ||
		target.UserID != principal.UserID ||
		target.SourceDeviceID != principal.DeviceID {
		return ErrUnauthorized
	}
	if body == nil || size < minimumCiphertextBytes {
		return ErrInvalidRequest
	}
	if size != target.Object.CiphertextSize ||
		subtle.ConstantTimeCompare(digest[:], target.Object.CiphertextDigest[:]) != 1 {
		return ErrCiphertextMismatch
	}
	if target.State != BackupStateInitiated && target.State != BackupStateUploading {
		if target.State == BackupStateSealed {
			return ErrBackupConflict
		}
		return ErrBackupNotFound
	}
	now := service.clock().UTC()
	if !now.Before(target.UploadExpiresAt) {
		return ErrBackupExpired
	}
	if _, err := service.activeAuthenticationDevice(ctx, principal); err != nil {
		return err
	}
	ref, err := NewCiphertextObjectRef(
		target.UserID,
		target.BackupID,
		target.Object.ObjectID,
	)
	if err != nil {
		return ErrInvalidRequest
	}
	_, err = service.objects.PutCiphertext(ctx, ref, body, size, digest)
	if errors.Is(err, ErrCiphertextAlreadyExists) {
		metadata, headErr := service.objects.HeadCiphertext(ctx, ref)
		if headErr == nil &&
			metadata.Size == size &&
			subtle.ConstantTimeCompare(metadata.SHA256[:], digest[:]) == 1 {
			err = nil
		}
	}
	if err != nil {
		return err
	}
	return service.repository.MarkUploading(
		ctx,
		target.UserID,
		target.BackupID,
		now,
	)
}

func (service *Service) Seal(
	ctx context.Context,
	principal Principal,
	backupID uuid.UUID,
) (SealResult, error) {
	if service == nil || !principal.valid() || backupID == uuid.Nil {
		return SealResult{}, ErrInvalidRequest
	}
	if _, err := service.activeAuthenticationDevice(ctx, principal); err != nil {
		return SealResult{}, err
	}
	detail, err := service.repository.BackupForSeal(
		ctx,
		principal.UserID,
		backupID,
	)
	if err != nil {
		return SealResult{}, err
	}
	if detail.SourceDeviceID != principal.DeviceID {
		return SealResult{}, ErrUnauthorized
	}
	if detail.State == BackupStateSealed {
		return SealResult{
			BackupID: detail.ID,
			State:    detail.State,
			SealedAt: detail.SealedAt,
			Replayed: true,
		}, nil
	}
	if detail.State != BackupStateInitiated && detail.State != BackupStateUploading {
		return SealResult{}, ErrBackupConflict
	}
	sourceDevice, err := service.repository.BackupDevice(
		ctx,
		principal.UserID,
		principal.DeviceID,
		detail.KeyEpoch,
	)
	if err != nil {
		return SealResult{}, err
	}
	if sourceDevice.Status != "active" {
		return SealResult{}, ErrDeviceRevoked
	}
	if !service.clock().UTC().Before(detail.UploadExpiresAt) {
		return SealResult{}, ErrBackupExpired
	}
	if len(detail.Chunks) != detail.ChunkCount {
		return SealResult{}, ErrBackupIncomplete
	}
	if err := service.verifyObject(ctx, detail.UserID, detail.ID, detail.Manifest); err != nil {
		return SealResult{}, err
	}
	for _, chunk := range detail.Chunks {
		if err := service.verifyObject(
			ctx,
			detail.UserID,
			detail.ID,
			chunk.ObjectSpec,
		); err != nil {
			return SealResult{}, err
		}
	}
	sealed, replayed, err := service.repository.Seal(
		ctx,
		principal.UserID,
		backupID,
		service.clock().UTC(),
	)
	if err != nil {
		return SealResult{}, err
	}
	return SealResult{
		BackupID: sealed.ID,
		State:    sealed.State,
		SealedAt: sealed.SealedAt,
		Replayed: replayed,
	}, nil
}

func (service *Service) List(
	ctx context.Context,
	principal Principal,
) ([]Backup, error) {
	if service == nil || !principal.valid() {
		return nil, ErrInvalidRequest
	}
	if _, err := service.activeAuthenticationDevice(ctx, principal); err != nil {
		return nil, err
	}
	if err := service.ensureBackupDeviceNotRevoked(ctx, principal); err != nil {
		return nil, err
	}
	return service.repository.ListSealed(ctx, principal.UserID)
}

func (service *Service) Get(
	ctx context.Context,
	principal Principal,
	backupID uuid.UUID,
) (BackupDetail, error) {
	if service == nil || !principal.valid() || backupID == uuid.Nil {
		return BackupDetail{}, ErrInvalidRequest
	}
	if _, err := service.activeAuthenticationDevice(ctx, principal); err != nil {
		return BackupDetail{}, err
	}
	if err := service.ensureBackupDeviceNotRevoked(ctx, principal); err != nil {
		return BackupDetail{}, err
	}
	return service.repository.GetSealed(
		ctx,
		principal.UserID,
		backupID,
		principal.DeviceID,
	)
}

func (service *Service) Download(
	ctx context.Context,
	principal Principal,
	backupID uuid.UUID,
	objectID string,
) (CiphertextDownload, error) {
	detail, err := service.Get(ctx, principal, backupID)
	if err != nil {
		return CiphertextDownload{}, err
	}
	if detail.State != BackupStateSealed {
		return CiphertextDownload{}, ErrBackupNotFound
	}
	allowed := objectID == detail.Manifest.ObjectID
	for _, chunk := range detail.Chunks {
		allowed = allowed || objectID == chunk.ObjectID
	}
	if !allowed {
		return CiphertextDownload{}, ErrBackupNotFound
	}
	ref, err := NewCiphertextObjectRef(
		principal.UserID,
		backupID,
		objectID,
	)
	if err != nil {
		return CiphertextDownload{}, ErrInvalidRequest
	}
	return service.objects.GetCiphertext(ctx, ref)
}

func (service *Service) AddDeviceEnvelope(
	ctx context.Context,
	principal Principal,
	backupID uuid.UUID,
	targetDeviceID uuid.UUID,
	keyEpoch int64,
	envelope []byte,
	digest [sha256.Size]byte,
) (bool, error) {
	if service == nil || !principal.valid() ||
		backupID == uuid.Nil ||
		targetDeviceID == uuid.Nil ||
		keyEpoch <= 0 ||
		!validEnvelope(envelope) ||
		!digestMatches(envelope, digest) {
		return false, ErrInvalidRequest
	}
	if _, err := service.activeAuthenticationDevice(ctx, principal); err != nil {
		return false, err
	}
	detail, err := service.repository.GetSealed(
		ctx,
		principal.UserID,
		backupID,
		principal.DeviceID,
	)
	if err != nil {
		return false, err
	}
	if detail.KeyEpoch != 0 && detail.KeyEpoch != keyEpoch {
		return false, ErrBackupConflict
	}
	target, err := service.repository.BackupDevice(
		ctx,
		principal.UserID,
		targetDeviceID,
		keyEpoch,
	)
	if err != nil {
		return false, err
	}
	if target.Status != "active" {
		return false, ErrDeviceRevoked
	}
	if targetDeviceID != principal.DeviceID {
		caller, err := service.repository.BackupDevice(
			ctx,
			principal.UserID,
			principal.DeviceID,
			keyEpoch,
		)
		if err != nil {
			return false, err
		}
		if caller.Status != "active" {
			return false, ErrDeviceRevoked
		}
	}
	envelopeID, err := secure.RandomUUID()
	if err != nil {
		return false, ErrEncryptedUnavailable
	}
	return service.repository.AddDeviceEnvelope(
		ctx,
		principal.UserID,
		backupID,
		EnvelopeRecord{
			ID:                    envelopeID,
			BackupID:              backupID,
			BackupDeviceID:        target.ID,
			KeyEpoch:              keyEpoch,
			RootKeyEnvelope:       append([]byte(nil), envelope...),
			RootKeyEnvelopeDigest: digest,
			CreatedAt:             service.clock().UTC(),
		},
	)
}

func (service *Service) Delete(
	ctx context.Context,
	principal Principal,
	backupID uuid.UUID,
) error {
	if service == nil || !principal.valid() || backupID == uuid.Nil {
		return ErrInvalidRequest
	}
	if _, err := service.activeAuthenticationDevice(ctx, principal); err != nil {
		return err
	}
	if err := service.ensureBackupDeviceNotRevoked(ctx, principal); err != nil {
		return err
	}
	deletion, err := service.repository.BeginDeletion(
		ctx,
		principal.UserID,
		backupID,
		service.clock().UTC(),
	)
	if err != nil {
		return err
	}
	refs := make([]CiphertextObjectRef, 0, len(deletion.ObjectIDs))
	for _, objectID := range deletion.ObjectIDs {
		ref, err := NewCiphertextObjectRef(
			principal.UserID,
			backupID,
			objectID,
		)
		if err != nil {
			return ErrEncryptedUnavailable
		}
		refs = append(refs, ref)
	}
	if err := service.objects.DeleteCiphertexts(ctx, refs); err != nil {
		return err
	}
	return service.repository.CompleteDeletion(
		ctx,
		principal.UserID,
		backupID,
		service.clock().UTC(),
	)
}

func (service *Service) activeAuthenticationDevice(
	ctx context.Context,
	principal Principal,
) (AuthenticationDevice, error) {
	if !principal.valid() {
		return AuthenticationDevice{}, ErrInvalidRequest
	}
	found, err := service.repository.AuthenticationDevice(
		ctx,
		principal.UserID,
		principal.DeviceID,
	)
	if err != nil {
		return AuthenticationDevice{}, err
	}
	if found.UserID != principal.UserID || found.DeviceID != principal.DeviceID {
		return AuthenticationDevice{}, ErrUnauthorized
	}
	if found.Status != "active" {
		return AuthenticationDevice{}, ErrDeviceRevoked
	}
	if len(found.PublicKey) != ed25519.PublicKeySize {
		return AuthenticationDevice{}, ErrEncryptedUnavailable
	}
	return found, nil
}

func (service *Service) ensureBackupDeviceNotRevoked(
	ctx context.Context,
	principal Principal,
) error {
	status, err := service.repository.LatestBackupDeviceStatus(
		ctx,
		principal.UserID,
		principal.DeviceID,
	)
	if err != nil {
		return err
	}
	switch status {
	case "", "active":
		return nil
	case "revoked":
		return ErrDeviceRevoked
	default:
		return ErrEncryptedUnavailable
	}
}

func (service *Service) verifyObject(
	ctx context.Context,
	userID uuid.UUID,
	backupID uuid.UUID,
	spec ObjectSpec,
) error {
	ref, err := NewCiphertextObjectRef(userID, backupID, spec.ObjectID)
	if err != nil {
		return ErrEncryptedUnavailable
	}
	metadata, err := service.objects.HeadCiphertext(ctx, ref)
	if errors.Is(err, ErrCiphertextNotFound) {
		return ErrBackupIncomplete
	}
	if err != nil {
		return err
	}
	if metadata.Size != spec.CiphertextSize ||
		subtle.ConstantTimeCompare(
			metadata.SHA256[:],
			spec.CiphertextDigest[:],
		) != 1 {
		return ErrCiphertextMismatch
	}
	return nil
}

func validRecovery(recovery RecoveryParameters) bool {
	return len(recovery.Salt) >= 16 &&
		len(recovery.Salt) <= 32 &&
		recovery.MemoryKiB == RecoveryMemoryKiB &&
		recovery.Iterations == RecoveryIterations &&
		recovery.Parallelism == RecoveryParallelism
}

func validEnvelope(value []byte) bool {
	return len(value) >= minimumEnvelopeBytes &&
		len(value) <= maximumEnvelopeBytes
}

func cloneRecovery(value RecoveryParameters) RecoveryParameters {
	value.Salt = append([]byte(nil), value.Salt...)
	return value
}

func cloneUUIDPointer(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
