package encryptedbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/google/uuid"
)

func TestHTTPRequiresOneValidAccessToken(t *testing.T) {
	handler := NewHandler(HTTPConfig{
		Service: &stubBackupHTTPService{},
		AccessTokens: fixedBackupAuthenticator{
			err: session.ErrSessionRevoked,
		},
	})
	for _, authorization := range []string{"", "Bearer ", "Bearer bad token", "Basic token"} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/encrypted-profile-backups", nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("authorization %q status = %d, body=%s", authorization, response.Code, response.Body.String())
		}
	}
}

func TestHTTPRegistersCurrentBackupDeviceWithStrictOpaqueFields(t *testing.T) {
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New()}
	service := &stubBackupHTTPService{
		registered: BackupDevice{
			ID: uuid.New(), UserID: principal.UserID, DeviceID: principal.DeviceID,
			KeyEpoch: 2, Revision: 3, Status: "active",
		},
	}
	handler := testBackupHandler(service, principal)
	body := `{
		"key_epoch":2,
		"revision":3,
		"public_key":"` + base64.RawURLEncoding.EncodeToString(testBytes(32, 0x41)) + `",
		"signature":"` + base64.RawURLEncoding.EncodeToString(testBytes(64, 0x42)) + `"
	}`
	request := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/encrypted-profile-backups/devices/current",
		strings.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer valid")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("register status = %d, body=%s", response.Code, response.Body.String())
	}
	if service.registerPrincipal != principal ||
		service.registerCommand.KeyEpoch != 2 ||
		len(service.registerCommand.PublicKey) != 32 ||
		len(service.registerCommand.Signature) != 64 {
		t.Fatalf("register service input = %#v/%#v", service.registerPrincipal, service.registerCommand)
	}
	if strings.Contains(response.Body.String(), "public_key") ||
		strings.Contains(response.Body.String(), "signature") {
		t.Fatalf("registration response exposed key material: %s", response.Body.String())
	}

	duplicate := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/encrypted-profile-backups/devices/current",
		strings.NewReader(`{"key_epoch":2,"key_epoch":3,"revision":3,"public_key":"x","signature":"y"}`),
	)
	duplicate.Header.Set("Authorization", "Bearer valid")
	duplicate.Header.Set("Content-Type", "application/json")
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusBadRequest {
		t.Fatalf("duplicate-key status = %d", duplicateResponse.Code)
	}
}

func TestHTTPInitiatesSignedCiphertextInventory(t *testing.T) {
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New()}
	service := &stubBackupHTTPService{}
	handler := testBackupHandler(service, principal)
	envelope := testPublicEnvelope()
	envelope.SourceDeviceID = principal.DeviceID
	recovery := testBytes(64, 0x51)
	wrapped := testBytes(64, 0x52)
	deviceEnvelope := testBytes(64, 0x53)
	envelope.RecoveryEnvelopeDigest = sha256.Sum256(recovery)
	envelope.WrappedDataKeyDigest = sha256.Sum256(wrapped)
	envelope.SourceDeviceEnvelopeDigest = sha256.Sum256(deviceEnvelope)
	requestBody := initiateHTTPRequest{
		Envelope:  encodeHTTPPublicEnvelope(envelope),
		Signature: encodeBackupBase64(testBytes(64, 0x54)),
		Recovery: recoveryHTTPParameters{
			Salt:        encodeBackupBase64(testBytes(16, 0x55)),
			MemoryKiB:   RecoveryMemoryKiB,
			Iterations:  RecoveryIterations,
			Parallelism: RecoveryParallelism,
		},
		RecoveryRootKeyEnvelope:     encodeBackupBase64(recovery),
		WrappedDataKey:              encodeBackupBase64(wrapped),
		SourceDeviceRootKeyEnvelope: encodeBackupBase64(deviceEnvelope),
	}
	raw, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/encrypted-profile-backups", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer valid")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("initiate status = %d, body=%s", response.Code, response.Body.String())
	}
	if service.initiateCommand.Principal != principal ||
		service.initiateCommand.Envelope.BackupID != envelope.BackupID ||
		!bytes.Equal(service.initiateCommand.RecoveryRootKeyEnvelope, recovery) {
		t.Fatalf("initiate service input = %#v", service.initiateCommand)
	}
}

func TestHTTPUploadsExactBinaryCiphertextAndDownloadsWithoutPhrase(t *testing.T) {
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New()}
	backupID := uuid.New()
	objectID := testObjectID(0x61)
	payload := testBytes(64, 0x62)
	digest := sha256.Sum256(payload)
	service := &stubBackupHTTPService{
		download: CiphertextDownload{
			Body: io.NopCloser(bytes.NewReader(payload)),
			Metadata: CiphertextMetadata{
				Key: objectID, Size: int64(len(payload)), SHA256: digest,
			},
		},
	}
	handler := testBackupHandler(service, principal)
	upload := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/encrypted-profile-backups/"+backupID.String()+"/chunks/0",
		bytes.NewReader(payload),
	)
	upload.Header.Set("Authorization", "Bearer valid")
	upload.Header.Set("Content-Type", "application/octet-stream")
	upload.Header.Set(ciphertextSizeHeader, strconv.Itoa(len(payload)))
	upload.Header.Set(ciphertextDigestHeader, base64.RawURLEncoding.EncodeToString(digest[:]))
	uploadResponse := httptest.NewRecorder()
	handler.ServeHTTP(uploadResponse, upload)
	if uploadResponse.Code != http.StatusNoContent {
		t.Fatalf("upload status = %d, body=%s", uploadResponse.Code, uploadResponse.Body.String())
	}
	if service.uploadChunkPrincipal != principal ||
		service.uploadChunkBackupID != backupID ||
		service.uploadChunkIndex != 0 ||
		!bytes.Equal(service.uploadChunkBody, payload) {
		t.Fatalf("upload service input = %v/%v/%d/%x",
			service.uploadChunkPrincipal, service.uploadChunkBackupID,
			service.uploadChunkIndex, service.uploadChunkBody)
	}

	download := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/encrypted-profile-backups/"+backupID.String()+"/objects/"+objectID,
		nil,
	)
	download.Header.Set("Authorization", "Bearer valid")
	downloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(downloadResponse, download)
	if downloadResponse.Code != http.StatusOK ||
		!bytes.Equal(downloadResponse.Body.Bytes(), payload) ||
		downloadResponse.Header().Get(ciphertextDigestHeader) != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("download = %d/%q/%q", downloadResponse.Code, downloadResponse.Body.Bytes(),
			downloadResponse.Header().Get(ciphertextDigestHeader))
	}
	if strings.Contains(strings.ToLower(download.RequestURI), "phrase") ||
		service.downloadPrincipal != principal {
		t.Fatalf("download unexpectedly used recovery phrase: %s/%#v", download.RequestURI, service.downloadPrincipal)
	}
}

func TestHTTPGetReturnsOnlyCiphertextMetadataAndOpaqueEnvelopes(t *testing.T) {
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New()}
	envelope := testPublicEnvelope()
	now := time.Date(2026, 7, 23, 4, 0, 0, 0, time.UTC)
	sealedAt := now.Add(time.Minute)
	service := &stubBackupHTTPService{
		detail: BackupDetail{
			Backup: Backup{
				ID: envelope.BackupID, UserID: principal.UserID,
				SourceDeviceID:       principal.DeviceID,
				SourceInstallationID: envelope.SourceInstallationID,
				SourceDefinitionID:   envelope.SourceDefinitionID,
				SourceVersionID:      envelope.SourceVersionID,
				ProfileLineageID:     envelope.ProfileLineageID,
				FormatVersion:        BackupFormatVersion, CipherSuite: BackupCipherSuite,
				State: BackupStateSealed, KeyEpoch: 1, ChunkCount: 1,
				TotalCiphertextSize:  envelope.TotalCiphertextSize,
				Manifest:             envelope.Manifest,
				PublicEnvelopeDigest: sha256.Sum256([]byte("public")),
				PublicSignature:      testBytes(64, 0x71),
				Recovery: RecoveryParameters{
					Salt: testBytes(16, 0x72), MemoryKiB: RecoveryMemoryKiB,
					Iterations: RecoveryIterations, Parallelism: RecoveryParallelism,
				},
				RecoveryRootKeyEnvelope: testBytes(64, 0x73),
				WrappedDataKey:          testBytes(64, 0x74),
				CreatedAt:               now, UpdatedAt: sealedAt, UploadExpiresAt: now.Add(24 * time.Hour),
				SealedAt: &sealedAt,
			},
			Chunks: envelope.Chunks,
			CurrentDeviceKey: &KeyEnvelope{
				DeviceID: principal.DeviceID, KeyEpoch: 1,
				RootKeyEnvelope:       testBytes(64, 0x75),
				RootKeyEnvelopeDigest: sha256.Sum256(testBytes(64, 0x75)),
			},
		},
	}
	handler := testBackupHandler(service, principal)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/encrypted-profile-backups/"+envelope.BackupID.String(),
		nil,
	)
	request.Header.Set("Authorization", "Bearer valid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", response.Code, response.Body.String())
	}
	lower := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{
		"recovery_phrase", "plaintext", "file_path", "filename",
		"conversation", "memory_content", "private_key",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("get response contains forbidden field %q: %s", forbidden, response.Body.String())
		}
	}
	if !strings.Contains(lower, "recovery_root_key_envelope") ||
		!strings.Contains(lower, "current_device_envelope") {
		t.Fatalf("get response omitted opaque restore envelopes: %s", response.Body.String())
	}
}

func TestHTTPMapsLifecycleErrorsAndUnavailableFeature(t *testing.T) {
	principal := Principal{UserID: uuid.New(), DeviceID: uuid.New()}
	for serviceError, expectedStatus := range map[error]int{
		ErrInvalidRequest:       http.StatusBadRequest,
		ErrInvalidSignature:     http.StatusForbidden,
		ErrUnauthorized:         http.StatusForbidden,
		ErrDeviceRevoked:        http.StatusForbidden,
		ErrBackupNotFound:       http.StatusNotFound,
		ErrBackupConflict:       http.StatusConflict,
		ErrBackupExpired:        http.StatusGone,
		ErrBackupIncomplete:     http.StatusConflict,
		ErrQuotaExceeded:        http.StatusRequestEntityTooLarge,
		ErrEncryptedUnavailable: http.StatusServiceUnavailable,
	} {
		service := &stubBackupHTTPService{listError: serviceError}
		request := httptest.NewRequest(http.MethodGet, "/api/v1/encrypted-profile-backups", nil)
		request.Header.Set("Authorization", "Bearer valid")
		response := httptest.NewRecorder()
		testBackupHandler(service, principal).ServeHTTP(response, request)
		if response.Code != expectedStatus {
			t.Fatalf("error %v status = %d, want %d", serviceError, response.Code, expectedStatus)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/encrypted-profile-backups", nil)
	response := httptest.NewRecorder()
	NewHandler(HTTPConfig{}).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled feature status = %d, body=%s", response.Code, response.Body.String())
	}
}

type stubBackupHTTPService struct {
	registered           BackupDevice
	registerPrincipal    Principal
	registerCommand      RegisterDeviceCommand
	initiateCommand      InitiateCommand
	uploadChunkPrincipal Principal
	uploadChunkBackupID  uuid.UUID
	uploadChunkIndex     int
	uploadChunkBody      []byte
	listResult           []Backup
	listError            error
	detail               BackupDetail
	download             CiphertextDownload
	downloadPrincipal    Principal
}

func (service *stubBackupHTTPService) RegisterDevice(
	_ context.Context,
	principal Principal,
	command RegisterDeviceCommand,
) (BackupDevice, bool, error) {
	service.registerPrincipal = principal
	service.registerCommand = command
	return service.registered, false, nil
}

func (service *stubBackupHTTPService) RevokeDevice(context.Context, Principal, uuid.UUID) error {
	return nil
}

func (service *stubBackupHTTPService) Initiate(
	_ context.Context,
	command InitiateCommand,
) (InitiateResult, error) {
	service.initiateCommand = command
	return InitiateResult{
		BackupID:        command.Envelope.BackupID,
		State:           BackupStateInitiated,
		UploadExpiresAt: time.Now().UTC().Add(time.Hour),
	}, nil
}

func (service *stubBackupHTTPService) UploadChunk(
	_ context.Context,
	principal Principal,
	backupID uuid.UUID,
	index int,
	body io.Reader,
	_ int64,
	_ [sha256.Size]byte,
) error {
	service.uploadChunkPrincipal = principal
	service.uploadChunkBackupID = backupID
	service.uploadChunkIndex = index
	service.uploadChunkBody, _ = io.ReadAll(body)
	return nil
}

func (service *stubBackupHTTPService) UploadManifest(
	context.Context,
	Principal,
	uuid.UUID,
	io.Reader,
	int64,
	[sha256.Size]byte,
) error {
	return nil
}

func (service *stubBackupHTTPService) Seal(
	context.Context,
	Principal,
	uuid.UUID,
) (SealResult, error) {
	return SealResult{}, nil
}

func (service *stubBackupHTTPService) List(
	context.Context,
	Principal,
) ([]Backup, error) {
	return service.listResult, service.listError
}

func (service *stubBackupHTTPService) Get(
	context.Context,
	Principal,
	uuid.UUID,
) (BackupDetail, error) {
	return service.detail, nil
}

func (service *stubBackupHTTPService) Download(
	_ context.Context,
	principal Principal,
	_ uuid.UUID,
	_ string,
) (CiphertextDownload, error) {
	service.downloadPrincipal = principal
	return service.download, nil
}

func (service *stubBackupHTTPService) AddDeviceEnvelope(
	context.Context,
	Principal,
	uuid.UUID,
	uuid.UUID,
	int64,
	[]byte,
	[sha256.Size]byte,
) (bool, error) {
	return false, nil
}

func (service *stubBackupHTTPService) Delete(context.Context, Principal, uuid.UUID) error {
	return nil
}

type fixedBackupAuthenticator struct {
	claims session.AccessClaims
	err    error
}

func (authenticator fixedBackupAuthenticator) Authenticate(
	context.Context,
	string,
) (session.AccessClaims, error) {
	return authenticator.claims, authenticator.err
}

func testBackupHandler(service BackupHTTPService, principal Principal) http.Handler {
	return NewHandler(HTTPConfig{
		Service: service,
		AccessTokens: fixedBackupAuthenticator{
			claims: session.AccessClaims{
				AccessBinding: session.AccessBinding{
					UserID: principal.UserID, DeviceID: principal.DeviceID,
					SessionID: uuid.New(), PersonalSpaceID: uuid.New(),
				},
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	})
}
