package encryptedbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	maximumInitiateRequestBytes = 8 << 20
	maximumEnvelopeRequestBytes = 16 << 10
	maximumBinaryRequestBytes   = maximumManifestBytes + 1

	ciphertextSizeHeader   = "X-AgentEra-Ciphertext-Size"
	ciphertextDigestHeader = "X-AgentEra-Ciphertext-SHA256"
)

type BackupHTTPService interface {
	RegisterDevice(context.Context, Principal, RegisterDeviceCommand) (BackupDevice, bool, error)
	RevokeDevice(context.Context, Principal, uuid.UUID) error
	Initiate(context.Context, InitiateCommand) (InitiateResult, error)
	UploadChunk(context.Context, Principal, uuid.UUID, int, io.Reader, int64, [sha256.Size]byte) error
	UploadManifest(context.Context, Principal, uuid.UUID, io.Reader, int64, [sha256.Size]byte) error
	Seal(context.Context, Principal, uuid.UUID) (SealResult, error)
	List(context.Context, Principal) ([]Backup, error)
	Get(context.Context, Principal, uuid.UUID) (BackupDetail, error)
	Download(context.Context, Principal, uuid.UUID, string) (CiphertextDownload, error)
	AddDeviceEnvelope(context.Context, Principal, uuid.UUID, uuid.UUID, int64, []byte, [sha256.Size]byte) (bool, error)
	Delete(context.Context, Principal, uuid.UUID) error
}

type AccessAuthenticator interface {
	Authenticate(context.Context, string) (session.AccessClaims, error)
}

type HTTPConfig struct {
	Service      BackupHTTPService
	AccessTokens AccessAuthenticator
}

type backupHTTPHandler struct {
	service      BackupHTTPService
	accessTokens AccessAuthenticator
}

type objectHTTPSpec struct {
	ObjectID         string `json:"object_id"`
	CiphertextDigest string `json:"ciphertext_digest"`
	CiphertextSize   int64  `json:"ciphertext_size"`
}

type chunkHTTPSpec struct {
	Index int `json:"index"`
	objectHTTPSpec
}

type publicEnvelopeHTTPRequest struct {
	FormatVersion              int16           `json:"format_version"`
	CipherSuite                string          `json:"cipher_suite"`
	BackupID                   string          `json:"backup_id"`
	ProfileLineageID           string          `json:"profile_lineage_id"`
	ParentBackupID             *string         `json:"parent_backup_id"`
	SourceDeviceID             string          `json:"source_device_id"`
	SourceInstallationID       string          `json:"source_installation_id"`
	SourceDefinitionID         string          `json:"source_definition_id"`
	SourceVersionID            string          `json:"source_version_id"`
	BaseOwnerScope             string          `json:"base_owner_scope"`
	KeyEpoch                   int64           `json:"key_epoch"`
	CreatedAt                  time.Time       `json:"created_at"`
	Manifest                   objectHTTPSpec  `json:"manifest"`
	Chunks                     []chunkHTTPSpec `json:"chunks"`
	TotalCiphertextSize        int64           `json:"total_ciphertext_size"`
	RecoveryEnvelopeDigest     string          `json:"recovery_envelope_digest"`
	WrappedDataKeyDigest       string          `json:"wrapped_data_key_digest"`
	SourceDeviceEnvelopeDigest string          `json:"source_device_envelope_digest"`
}

type recoveryHTTPParameters struct {
	Salt        string `json:"salt"`
	MemoryKiB   int    `json:"memory_kib"`
	Iterations  int    `json:"iterations"`
	Parallelism int    `json:"parallelism"`
}

type initiateHTTPRequest struct {
	Envelope                    publicEnvelopeHTTPRequest `json:"envelope"`
	Signature                   string                    `json:"signature"`
	Recovery                    recoveryHTTPParameters    `json:"recovery"`
	RecoveryRootKeyEnvelope     string                    `json:"recovery_root_key_envelope"`
	WrappedDataKey              string                    `json:"wrapped_data_key"`
	SourceDeviceRootKeyEnvelope string                    `json:"source_device_root_key_envelope"`
}

type backupSummaryHTTPResponse struct {
	BackupID             uuid.UUID   `json:"backup_id"`
	ProfileLineageID     uuid.UUID   `json:"profile_lineage_id"`
	ParentBackupID       *uuid.UUID  `json:"parent_backup_id"`
	SourceDeviceID       uuid.UUID   `json:"source_device_id"`
	SourceInstallationID uuid.UUID   `json:"source_installation_id"`
	SourceDefinitionID   uuid.UUID   `json:"source_definition_id"`
	SourceVersionID      uuid.UUID   `json:"source_version_id"`
	FormatVersion        int16       `json:"format_version"`
	CipherSuite          string      `json:"cipher_suite"`
	State                BackupState `json:"state"`
	KeyEpoch             int64       `json:"key_epoch"`
	ChunkCount           int         `json:"chunk_count"`
	TotalCiphertextSize  int64       `json:"total_ciphertext_size"`
	CreatedAt            time.Time   `json:"created_at"`
	SealedAt             *time.Time  `json:"sealed_at"`
}

type keyEnvelopeHTTPResponse struct {
	DeviceID              uuid.UUID `json:"device_id"`
	KeyEpoch              int64     `json:"key_epoch"`
	RootKeyEnvelope       string    `json:"root_key_envelope"`
	RootKeyEnvelopeDigest string    `json:"root_key_envelope_digest"`
}

type backupDetailHTTPResponse struct {
	backupSummaryHTTPResponse
	Manifest                objectHTTPSpec           `json:"manifest"`
	Chunks                  []chunkHTTPSpec          `json:"chunks"`
	PublicEnvelopeDigest    string                   `json:"public_envelope_digest"`
	PublicSignature         string                   `json:"public_signature"`
	Recovery                recoveryHTTPParameters   `json:"recovery"`
	RecoveryRootKeyEnvelope string                   `json:"recovery_root_key_envelope"`
	WrappedDataKey          string                   `json:"wrapped_data_key"`
	CurrentDeviceEnvelope   *keyEnvelopeHTTPResponse `json:"current_device_envelope"`
}

func NewHandler(config HTTPConfig) http.Handler {
	handler := &backupHTTPHandler{
		service:      config.Service,
		accessTokens: config.AccessTokens,
	}
	router := chi.NewRouter()
	router.Put("/api/v1/encrypted-profile-backups/devices/current", handler.registerCurrentDevice)
	router.Delete("/api/v1/encrypted-profile-backups/devices/{deviceID}", handler.revokeDevice)
	router.Post("/api/v1/encrypted-profile-backups", handler.initiate)
	router.Get("/api/v1/encrypted-profile-backups", handler.list)
	router.Put("/api/v1/encrypted-profile-backups/{backupID}/chunks/{chunkIndex}", handler.uploadChunk)
	router.Put("/api/v1/encrypted-profile-backups/{backupID}/manifest", handler.uploadManifest)
	router.Post("/api/v1/encrypted-profile-backups/{backupID}/seal", handler.seal)
	router.Get("/api/v1/encrypted-profile-backups/{backupID}", handler.get)
	router.Get("/api/v1/encrypted-profile-backups/{backupID}/objects/{objectID}", handler.download)
	router.Post("/api/v1/encrypted-profile-backups/{backupID}/device-envelopes", handler.addDeviceEnvelope)
	router.Delete("/api/v1/encrypted-profile-backups/{backupID}", handler.delete)
	return router
}

func (handler *backupHTTPHandler) registerCurrentDevice(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, ok := handler.authorize(response, request)
	if !ok {
		return
	}
	var payload struct {
		KeyEpoch  int64  `json:"key_epoch"`
		Revision  int64  `json:"revision"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	}
	if !readBackupJSON(response, request, maximumEnvelopeRequestBytes, &payload) {
		return
	}
	publicKey, publicKeyOK := decodeBackupBase64(payload.PublicKey, 32, 32)
	signature, signatureOK := decodeBackupBase64(payload.Signature, 64, 64)
	if !publicKeyOK || !signatureOK {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	registered, replayed, err := handler.service.RegisterDevice(
		request.Context(),
		principal,
		RegisterDeviceCommand{
			KeyEpoch:  payload.KeyEpoch,
			Revision:  payload.Revision,
			PublicKey: publicKey,
			Signature: signature,
		},
	)
	if err != nil {
		writeBackupServiceError(response, err)
		return
	}
	writeBackupJSON(response, http.StatusOK, struct {
		DeviceID uuid.UUID `json:"device_id"`
		KeyEpoch int64     `json:"key_epoch"`
		Revision int64     `json:"revision"`
		Status   string    `json:"status"`
		Replayed bool      `json:"replayed"`
	}{
		DeviceID: registered.DeviceID,
		KeyEpoch: registered.KeyEpoch,
		Revision: registered.Revision,
		Status:   registered.Status,
		Replayed: replayed,
	})
}

func (handler *backupHTTPHandler) revokeDevice(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, ok := handler.authorize(response, request)
	if !ok {
		return
	}
	deviceID, ok := parseCanonicalUUID(chi.URLParam(request, "deviceID"))
	if !ok {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := handler.service.RevokeDevice(request.Context(), principal, deviceID); err != nil {
		writeBackupServiceError(response, err)
		return
	}
	writeBackupNoContent(response)
}

func (handler *backupHTTPHandler) initiate(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, ok := handler.authorize(response, request)
	if !ok {
		return
	}
	var payload initiateHTTPRequest
	if !readBackupJSON(response, request, maximumInitiateRequestBytes, &payload) {
		return
	}
	command, ok := payload.command(principal)
	if !ok {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := handler.service.Initiate(request.Context(), command)
	if err != nil {
		writeBackupServiceError(response, err)
		return
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	writeBackupJSON(response, status, struct {
		BackupID        uuid.UUID   `json:"backup_id"`
		State           BackupState `json:"state"`
		UploadExpiresAt time.Time   `json:"upload_expires_at"`
		Replayed        bool        `json:"replayed"`
	}{
		BackupID:        result.BackupID,
		State:           result.State,
		UploadExpiresAt: result.UploadExpiresAt,
		Replayed:        result.Replayed,
	})
}

func (handler *backupHTTPHandler) uploadChunk(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, backupID, ok := handler.authorizeBackup(response, request)
	if !ok {
		return
	}
	index, err := strconv.Atoi(chi.URLParam(request, "chunkIndex"))
	if err != nil || index < 0 || index >= maximumChunkCount {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	size, digest, ok := readCiphertextHeaders(response, request)
	if !ok {
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumBinaryRequestBytes)
	if err := handler.service.UploadChunk(
		request.Context(),
		principal,
		backupID,
		index,
		request.Body,
		size,
		digest,
	); err != nil {
		writeBackupServiceError(response, err)
		return
	}
	writeBackupNoContent(response)
}

func (handler *backupHTTPHandler) uploadManifest(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, backupID, ok := handler.authorizeBackup(response, request)
	if !ok {
		return
	}
	size, digest, ok := readCiphertextHeaders(response, request)
	if !ok {
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumBinaryRequestBytes)
	if err := handler.service.UploadManifest(
		request.Context(),
		principal,
		backupID,
		request.Body,
		size,
		digest,
	); err != nil {
		writeBackupServiceError(response, err)
		return
	}
	writeBackupNoContent(response)
}

func (handler *backupHTTPHandler) seal(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, backupID, ok := handler.authorizeBackup(response, request)
	if !ok {
		return
	}
	if request.ContentLength > 0 {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := handler.service.Seal(request.Context(), principal, backupID)
	if err != nil {
		writeBackupServiceError(response, err)
		return
	}
	writeBackupJSON(response, http.StatusOK, struct {
		BackupID uuid.UUID   `json:"backup_id"`
		State    BackupState `json:"state"`
		SealedAt *time.Time  `json:"sealed_at"`
		Replayed bool        `json:"replayed"`
	}{
		BackupID: result.BackupID,
		State:    result.State,
		SealedAt: result.SealedAt,
		Replayed: result.Replayed,
	})
}

func (handler *backupHTTPHandler) list(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, ok := handler.authorize(response, request)
	if !ok {
		return
	}
	backups, err := handler.service.List(request.Context(), principal)
	if err != nil {
		writeBackupServiceError(response, err)
		return
	}
	items := make([]backupSummaryHTTPResponse, 0, len(backups))
	for _, backup := range backups {
		items = append(items, encodeBackupSummary(backup))
	}
	writeBackupJSON(response, http.StatusOK, struct {
		Backups []backupSummaryHTTPResponse `json:"backups"`
	}{Backups: items})
}

func (handler *backupHTTPHandler) get(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, backupID, ok := handler.authorizeBackup(response, request)
	if !ok {
		return
	}
	detail, err := handler.service.Get(request.Context(), principal, backupID)
	if err != nil {
		writeBackupServiceError(response, err)
		return
	}
	writeBackupJSON(response, http.StatusOK, encodeBackupDetail(detail))
}

func (handler *backupHTTPHandler) download(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, backupID, ok := handler.authorizeBackup(response, request)
	if !ok {
		return
	}
	objectID := chi.URLParam(request, "objectID")
	if !ciphertextObjectIDPattern.MatchString(objectID) {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	download, err := handler.service.Download(
		request.Context(),
		principal,
		backupID,
		objectID,
	)
	if err != nil {
		writeBackupServiceError(response, err)
		return
	}
	defer func() { _ = download.Body.Close() }()
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Length", strconv.FormatInt(download.Metadata.Size, 10))
	response.Header().Set(
		ciphertextDigestHeader,
		base64.RawURLEncoding.EncodeToString(download.Metadata.SHA256[:]),
	)
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(response, download.Body, download.Metadata.Size)
}

func (handler *backupHTTPHandler) addDeviceEnvelope(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, backupID, ok := handler.authorizeBackup(response, request)
	if !ok {
		return
	}
	var payload struct {
		DeviceID              string `json:"device_id"`
		KeyEpoch              int64  `json:"key_epoch"`
		RootKeyEnvelope       string `json:"root_key_envelope"`
		RootKeyEnvelopeDigest string `json:"root_key_envelope_digest"`
	}
	if !readBackupJSON(response, request, maximumEnvelopeRequestBytes, &payload) {
		return
	}
	deviceID, deviceOK := parseCanonicalUUID(payload.DeviceID)
	envelope, envelopeOK := decodeBackupBase64(
		payload.RootKeyEnvelope,
		minimumEnvelopeBytes,
		maximumEnvelopeBytes,
	)
	digestBytes, digestOK := decodeBackupBase64(
		payload.RootKeyEnvelopeDigest,
		sha256.Size,
		sha256.Size,
	)
	if !deviceOK || !envelopeOK || !digestOK {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	replayed, err := handler.service.AddDeviceEnvelope(
		request.Context(),
		principal,
		backupID,
		deviceID,
		payload.KeyEpoch,
		envelope,
		digest,
	)
	if err != nil {
		writeBackupServiceError(response, err)
		return
	}
	writeBackupJSON(response, http.StatusOK, struct {
		BackupID uuid.UUID `json:"backup_id"`
		DeviceID uuid.UUID `json:"device_id"`
		KeyEpoch int64     `json:"key_epoch"`
		Replayed bool      `json:"replayed"`
	}{
		BackupID: backupID,
		DeviceID: deviceID,
		KeyEpoch: payload.KeyEpoch,
		Replayed: replayed,
	})
}

func (handler *backupHTTPHandler) delete(
	response http.ResponseWriter,
	request *http.Request,
) {
	principal, backupID, ok := handler.authorizeBackup(response, request)
	if !ok {
		return
	}
	if err := handler.service.Delete(request.Context(), principal, backupID); err != nil {
		writeBackupServiceError(response, err)
		return
	}
	writeBackupNoContent(response)
}

func (handler *backupHTTPHandler) authorizeBackup(
	response http.ResponseWriter,
	request *http.Request,
) (Principal, uuid.UUID, bool) {
	principal, ok := handler.authorize(response, request)
	if !ok {
		return Principal{}, uuid.Nil, false
	}
	backupID, ok := parseCanonicalUUID(chi.URLParam(request, "backupID"))
	if !ok {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return Principal{}, uuid.Nil, false
	}
	return principal, backupID, true
}

func (handler *backupHTTPHandler) authorize(
	response http.ResponseWriter,
	request *http.Request,
) (Principal, bool) {
	if handler == nil || handler.service == nil || handler.accessTokens == nil {
		writeBackupError(response, http.StatusServiceUnavailable, "feature_unavailable")
		return Principal{}, false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		writeBackupError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" ||
		token != strings.TrimSpace(token) ||
		strings.ContainsAny(token, " \t\r\n") {
		writeBackupError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	claims, err := handler.accessTokens.Authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, session.ErrInvalidAccessToken) ||
			errors.Is(err, session.ErrSessionRevoked) {
			writeBackupError(response, http.StatusUnauthorized, "session_revoked")
		} else {
			writeBackupError(response, http.StatusServiceUnavailable, "service_unavailable")
		}
		return Principal{}, false
	}
	principal := Principal{
		UserID:   claims.UserID,
		DeviceID: claims.DeviceID,
	}
	if !principal.valid() {
		writeBackupError(response, http.StatusUnauthorized, "session_revoked")
		return Principal{}, false
	}
	return principal, true
}

func (payload initiateHTTPRequest) command(principal Principal) (InitiateCommand, bool) {
	envelope, ok := payload.Envelope.decode()
	if !ok {
		return InitiateCommand{}, false
	}
	signature, signatureOK := decodeBackupBase64(payload.Signature, 64, 64)
	salt, saltOK := decodeBackupBase64(payload.Recovery.Salt, 16, 32)
	recoveryEnvelope, recoveryOK := decodeBackupBase64(
		payload.RecoveryRootKeyEnvelope,
		minimumEnvelopeBytes,
		maximumEnvelopeBytes,
	)
	wrappedDataKey, wrappedOK := decodeBackupBase64(
		payload.WrappedDataKey,
		minimumEnvelopeBytes,
		maximumEnvelopeBytes,
	)
	sourceDeviceEnvelope, sourceOK := decodeBackupBase64(
		payload.SourceDeviceRootKeyEnvelope,
		minimumEnvelopeBytes,
		maximumEnvelopeBytes,
	)
	if !signatureOK || !saltOK || !recoveryOK || !wrappedOK || !sourceOK {
		return InitiateCommand{}, false
	}
	return InitiateCommand{
		Principal: principal,
		Envelope:  envelope,
		Signature: signature,
		Recovery: RecoveryParameters{
			Salt:        salt,
			MemoryKiB:   payload.Recovery.MemoryKiB,
			Iterations:  payload.Recovery.Iterations,
			Parallelism: payload.Recovery.Parallelism,
		},
		RecoveryRootKeyEnvelope:     recoveryEnvelope,
		WrappedDataKey:              wrappedDataKey,
		SourceDeviceRootKeyEnvelope: sourceDeviceEnvelope,
	}, true
}

func (payload publicEnvelopeHTTPRequest) decode() (PublicEnvelope, bool) {
	backupID, backupOK := parseCanonicalUUID(payload.BackupID)
	lineageID, lineageOK := parseCanonicalUUID(payload.ProfileLineageID)
	sourceDeviceID, sourceDeviceOK := parseCanonicalUUID(payload.SourceDeviceID)
	installationID, installationOK := parseCanonicalUUID(payload.SourceInstallationID)
	definitionID, definitionOK := parseCanonicalUUID(payload.SourceDefinitionID)
	versionID, versionOK := parseCanonicalUUID(payload.SourceVersionID)
	var parentID *uuid.UUID
	parentOK := true
	if payload.ParentBackupID != nil {
		value, ok := parseCanonicalUUID(*payload.ParentBackupID)
		parentOK = ok
		parentID = &value
	}
	manifest, manifestOK := payload.Manifest.decode()
	chunks := make([]ChunkSpec, len(payload.Chunks))
	chunksOK := true
	for index, chunk := range payload.Chunks {
		object, ok := chunk.objectHTTPSpec.decode()
		if !ok || chunk.Index != index {
			chunksOK = false
			break
		}
		chunks[index] = ChunkSpec{Index: chunk.Index, ObjectSpec: object}
	}
	recoveryDigest, recoveryOK := decodeHTTPDigest(payload.RecoveryEnvelopeDigest)
	wrappedDigest, wrappedOK := decodeHTTPDigest(payload.WrappedDataKeyDigest)
	deviceDigest, deviceOK := decodeHTTPDigest(payload.SourceDeviceEnvelopeDigest)
	if !backupOK || !lineageOK || !parentOK || !sourceDeviceOK ||
		!installationOK || !definitionOK || !versionOK ||
		!manifestOK || !chunksOK || !recoveryOK || !wrappedOK || !deviceOK {
		return PublicEnvelope{}, false
	}
	return PublicEnvelope{
		FormatVersion:              payload.FormatVersion,
		CipherSuite:                payload.CipherSuite,
		BackupID:                   backupID,
		ProfileLineageID:           lineageID,
		ParentBackupID:             parentID,
		SourceDeviceID:             sourceDeviceID,
		SourceInstallationID:       installationID,
		SourceDefinitionID:         definitionID,
		SourceVersionID:            versionID,
		BaseOwnerScope:             payload.BaseOwnerScope,
		KeyEpoch:                   payload.KeyEpoch,
		CreatedAt:                  payload.CreatedAt,
		Manifest:                   manifest,
		Chunks:                     chunks,
		TotalCiphertextSize:        payload.TotalCiphertextSize,
		RecoveryEnvelopeDigest:     recoveryDigest,
		WrappedDataKeyDigest:       wrappedDigest,
		SourceDeviceEnvelopeDigest: deviceDigest,
	}, true
}

func (payload objectHTTPSpec) decode() (ObjectSpec, bool) {
	digest, ok := decodeHTTPDigest(payload.CiphertextDigest)
	return ObjectSpec{
		ObjectID:         payload.ObjectID,
		CiphertextDigest: digest,
		CiphertextSize:   payload.CiphertextSize,
	}, ok && ciphertextObjectIDPattern.MatchString(payload.ObjectID)
}

func readCiphertextHeaders(
	response http.ResponseWriter,
	request *http.Request,
) (int64, [sha256.Size]byte, bool) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" ||
		len(request.Header.Values(ciphertextSizeHeader)) != 1 ||
		len(request.Header.Values(ciphertextDigestHeader)) != 1 {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return 0, [sha256.Size]byte{}, false
	}
	sizeText := request.Header.Get(ciphertextSizeHeader)
	size, err := strconv.ParseInt(sizeText, 10, 64)
	if err != nil ||
		strconv.FormatInt(size, 10) != sizeText ||
		size < minimumCiphertextBytes ||
		size > maximumManifestBytes ||
		request.ContentLength != size {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return 0, [sha256.Size]byte{}, false
	}
	digest, ok := decodeHTTPDigest(request.Header.Get(ciphertextDigestHeader))
	if !ok {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return 0, [sha256.Size]byte{}, false
	}
	return size, digest, true
}

func readBackupJSON(
	response http.ResponseWriter,
	request *http.Request,
	limit int64,
	target any,
) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeBackupError(response, http.StatusRequestEntityTooLarge, "invalid_request")
		} else {
			writeBackupError(response, http.StatusBadRequest, "invalid_request")
		}
		return false
	}
	if rejectBackupDuplicateJSONKeys(raw) != nil ||
		decodeBackupStrictJSON(raw, target) != nil {
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func decodeBackupStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func rejectBackupDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanBackupJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains more than one value")
	}
	return nil
}

func scanBackupJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("JSON object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := scanBackupJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanBackupJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil || closing != matchingBackupDelimiter(delimiter) {
		return errors.New("JSON container is not closed")
	}
	return nil
}

func matchingBackupDelimiter(opening json.Delim) json.Delim {
	if opening == '{' {
		return '}'
	}
	return ']'
}

func parseCanonicalUUID(raw string) (uuid.UUID, bool) {
	value, err := uuid.Parse(raw)
	return value, err == nil && value != uuid.Nil && value.String() == raw
}

func decodeBackupBase64(raw string, minimum int, maximum int) ([]byte, bool) {
	value, ok := secure.DecodeCanonicalBase64URL(raw)
	return value, ok && len(value) >= minimum && len(value) <= maximum
}

func decodeHTTPDigest(raw string) ([sha256.Size]byte, bool) {
	value, ok := decodeBackupBase64(raw, sha256.Size, sha256.Size)
	var digest [sha256.Size]byte
	if ok {
		copy(digest[:], value)
	}
	return digest, ok
}

func encodeBackupBase64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func encodeHTTPPublicEnvelope(envelope PublicEnvelope) publicEnvelopeHTTPRequest {
	var parentID *string
	if envelope.ParentBackupID != nil {
		value := envelope.ParentBackupID.String()
		parentID = &value
	}
	chunks := make([]chunkHTTPSpec, len(envelope.Chunks))
	for index, chunk := range envelope.Chunks {
		chunks[index] = chunkHTTPSpec{
			Index:          chunk.Index,
			objectHTTPSpec: encodeHTTPObject(chunk.ObjectSpec),
		}
	}
	return publicEnvelopeHTTPRequest{
		FormatVersion:              envelope.FormatVersion,
		CipherSuite:                envelope.CipherSuite,
		BackupID:                   envelope.BackupID.String(),
		ProfileLineageID:           envelope.ProfileLineageID.String(),
		ParentBackupID:             parentID,
		SourceDeviceID:             envelope.SourceDeviceID.String(),
		SourceInstallationID:       envelope.SourceInstallationID.String(),
		SourceDefinitionID:         envelope.SourceDefinitionID.String(),
		SourceVersionID:            envelope.SourceVersionID.String(),
		BaseOwnerScope:             envelope.BaseOwnerScope,
		KeyEpoch:                   envelope.KeyEpoch,
		CreatedAt:                  envelope.CreatedAt,
		Manifest:                   encodeHTTPObject(envelope.Manifest),
		Chunks:                     chunks,
		TotalCiphertextSize:        envelope.TotalCiphertextSize,
		RecoveryEnvelopeDigest:     encodeBackupBase64(envelope.RecoveryEnvelopeDigest[:]),
		WrappedDataKeyDigest:       encodeBackupBase64(envelope.WrappedDataKeyDigest[:]),
		SourceDeviceEnvelopeDigest: encodeBackupBase64(envelope.SourceDeviceEnvelopeDigest[:]),
	}
}

func encodeHTTPObject(object ObjectSpec) objectHTTPSpec {
	return objectHTTPSpec{
		ObjectID:         object.ObjectID,
		CiphertextDigest: encodeBackupBase64(object.CiphertextDigest[:]),
		CiphertextSize:   object.CiphertextSize,
	}
}

func encodeBackupSummary(backup Backup) backupSummaryHTTPResponse {
	return backupSummaryHTTPResponse{
		BackupID:             backup.ID,
		ProfileLineageID:     backup.ProfileLineageID,
		ParentBackupID:       cloneUUIDPointer(backup.ParentBackupID),
		SourceDeviceID:       backup.SourceDeviceID,
		SourceInstallationID: backup.SourceInstallationID,
		SourceDefinitionID:   backup.SourceDefinitionID,
		SourceVersionID:      backup.SourceVersionID,
		FormatVersion:        backup.FormatVersion,
		CipherSuite:          backup.CipherSuite,
		State:                backup.State,
		KeyEpoch:             backup.KeyEpoch,
		ChunkCount:           backup.ChunkCount,
		TotalCiphertextSize:  backup.TotalCiphertextSize,
		CreatedAt:            backup.CreatedAt,
		SealedAt:             backup.SealedAt,
	}
}

func encodeBackupDetail(detail BackupDetail) backupDetailHTTPResponse {
	chunks := make([]chunkHTTPSpec, len(detail.Chunks))
	for index, chunk := range detail.Chunks {
		chunks[index] = chunkHTTPSpec{
			Index:          chunk.Index,
			objectHTTPSpec: encodeHTTPObject(chunk.ObjectSpec),
		}
	}
	var current *keyEnvelopeHTTPResponse
	if detail.CurrentDeviceKey != nil {
		current = &keyEnvelopeHTTPResponse{
			DeviceID:              detail.CurrentDeviceKey.DeviceID,
			KeyEpoch:              detail.CurrentDeviceKey.KeyEpoch,
			RootKeyEnvelope:       encodeBackupBase64(detail.CurrentDeviceKey.RootKeyEnvelope),
			RootKeyEnvelopeDigest: encodeBackupBase64(detail.CurrentDeviceKey.RootKeyEnvelopeDigest[:]),
		}
	}
	return backupDetailHTTPResponse{
		backupSummaryHTTPResponse: encodeBackupSummary(detail.Backup),
		Manifest:                  encodeHTTPObject(detail.Manifest),
		Chunks:                    chunks,
		PublicEnvelopeDigest:      encodeBackupBase64(detail.PublicEnvelopeDigest[:]),
		PublicSignature:           encodeBackupBase64(detail.PublicSignature),
		Recovery: recoveryHTTPParameters{
			Salt:        encodeBackupBase64(detail.Recovery.Salt),
			MemoryKiB:   detail.Recovery.MemoryKiB,
			Iterations:  detail.Recovery.Iterations,
			Parallelism: detail.Recovery.Parallelism,
		},
		RecoveryRootKeyEnvelope: encodeBackupBase64(detail.RecoveryRootKeyEnvelope),
		WrappedDataKey:          encodeBackupBase64(detail.WrappedDataKey),
		CurrentDeviceEnvelope:   current,
	}
}

func writeBackupServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrCiphertextMismatch):
		writeBackupError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrInvalidSignature):
		writeBackupError(response, http.StatusForbidden, "invalid_signature")
	case errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrDeviceRevoked):
		writeBackupError(response, http.StatusForbidden, "not_authorized")
	case errors.Is(err, ErrBackupNotFound),
		errors.Is(err, ErrCiphertextNotFound):
		writeBackupError(response, http.StatusNotFound, "backup_not_found")
	case errors.Is(err, ErrBackupExpired):
		writeBackupError(response, http.StatusGone, "upload_expired")
	case errors.Is(err, ErrBackupConflict),
		errors.Is(err, ErrBackupIncomplete),
		errors.Is(err, ErrCiphertextAlreadyExists):
		writeBackupError(response, http.StatusConflict, "backup_conflict")
	case errors.Is(err, ErrQuotaExceeded):
		writeBackupError(response, http.StatusRequestEntityTooLarge, "quota_exceeded")
	default:
		writeBackupError(response, http.StatusServiceUnavailable, "service_unavailable")
	}
}

func writeBackupError(response http.ResponseWriter, status int, code string) {
	writeBackupJSON(response, status, struct {
		Error string `json:"error"`
	}{Error: code})
}

func writeBackupJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeBackupNoContent(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}
