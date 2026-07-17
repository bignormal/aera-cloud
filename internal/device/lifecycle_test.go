package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestListDevicesReturnsOnlyRedactedActiveViewAndMarksCurrentDevice(t *testing.T) {
	currentID := uuid.New()
	repository := &fakeLifecycleDeviceRepository{devices: []Device{
		{ID: currentID, DisplayName: "Current Mac", Platform: "darwin", AppVersion: "0.1.0", Status: "active"},
		{ID: uuid.New(), DisplayName: "Office PC", Platform: "windows", AppVersion: "0.1.0", Status: "revoked"},
	}}
	service, err := NewService(ServiceConfig{Repository: repository, ActiveLimit: 5})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	devices, err := service.List(context.Background(), uuid.New(), currentID)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(devices) != 1 || !devices[0].Current || devices[0].DisplayName != "Current Mac" {
		t.Fatalf("public devices = %+v", devices)
	}
}

func TestSelfRevokeRequiresFreshDeviceSignatureAndRejectsNonceReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Date(2026, 7, 18, 7, 0, 0, 0, time.UTC)
	deviceID := uuid.New()
	installationID := uuid.New()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	repository := &fakeLifecycleDeviceRepository{found: Device{
		ID: deviceID, UserID: uuid.New(), InstallationID: installationID,
		PublicKey: publicKey, Status: "active",
	}}
	service, err := NewService(ServiceConfig{
		Repository: repository, ActiveLimit: 5, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	command := SelfRevokeCommand{
		DeviceID: deviceID, InstallationID: installationID, Timestamp: now.Unix(), Nonce: nonce,
	}
	command.Signature = ed25519.Sign(privateKey, testSelfRevokeDigest(command))

	stale := command
	stale.Timestamp = now.Add(-3 * time.Minute).Unix()
	stale.Signature = ed25519.Sign(privateKey, testSelfRevokeDigest(stale))
	if err := service.SelfRevoke(context.Background(), stale); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("SelfRevoke(stale) error = %v", err)
	}
	tampered := command
	tampered.InstallationID = uuid.New()
	if err := service.SelfRevoke(context.Background(), tampered); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("SelfRevoke(tampered) error = %v", err)
	}
	if err := service.SelfRevoke(context.Background(), command); err != nil {
		t.Fatalf("SelfRevoke() error = %v", err)
	}
	if repository.selfRevocation.DeviceID != deviceID || len(repository.selfRevocation.NonceHash) != sha256.Size {
		t.Fatalf("self revocation record = %+v", repository.selfRevocation)
	}
	repository.selfErr = ErrSelfRevokeReplay
	if err := service.SelfRevoke(context.Background(), command); !errors.Is(err, ErrSelfRevokeReplay) {
		t.Fatalf("SelfRevoke(replay) error = %v", err)
	}
}

func TestPostgresSelfRevokeAtomicallyRevokesDeviceSessionsAndNonce(t *testing.T) {
	fixture := newDeviceFixture(t)
	userID := fixture.user(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	installationID := uuid.New()
	created, err := fixture.service.Authorize(fixture.ctx, AuthorizeCommand{
		UserID: userID, InstallationID: installationID, PublicKey: publicKey,
		DisplayName: "Signed Mac", Platform: "darwin", AppVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	sessionID := uuid.New()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO sessions (
			id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, sessionID, userID, created.ID, uuid.New(), bytes.Repeat([]byte{91}, 32), fixture.now, fixture.now.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert device session: %v", err)
	}
	nonce := bytes.Repeat([]byte{17}, 32)
	command := SelfRevokeCommand{
		DeviceID: created.ID, InstallationID: installationID, Timestamp: fixture.now.Unix(), Nonce: nonce,
	}
	command.Signature = ed25519.Sign(privateKey, testSelfRevokeDigest(command))
	if err := fixture.service.SelfRevoke(fixture.ctx, command); err != nil {
		t.Fatalf("SelfRevoke() error = %v", err)
	}
	if err := fixture.service.SelfRevoke(fixture.ctx, command); !errors.Is(err, ErrSelfRevokeReplay) {
		t.Fatalf("SelfRevoke(replay) error = %v", err)
	}
	var deviceStatus string
	var sessionRevoked pgtype.Timestamptz
	var nonces, audits int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT status FROM devices WHERE id = $1`, created.ID).Scan(&deviceStatus); err != nil {
		t.Fatalf("read device status: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, sessionID).Scan(&sessionRevoked); err != nil {
		t.Fatalf("read session revocation: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM device_self_revocation_nonces WHERE device_id = $1`, created.ID).Scan(&nonces); err != nil {
		t.Fatalf("count self-revocation nonces: %v", err)
	}
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'device_self_revoked' AND device_id = $1`, created.ID).Scan(&audits); err != nil {
		t.Fatalf("count self-revocation audit: %v", err)
	}
	if deviceStatus != "revoked" || !sessionRevoked.Valid || nonces != 1 || audits != 1 {
		t.Fatalf("self-revocation state device=%s session=%v nonces=%d audits=%d", deviceStatus, sessionRevoked.Valid, nonces, audits)
	}
}

func TestPostgresDeviceManagementRejectsStaleBrowserAccountAfterDeletionRequest(t *testing.T) {
	fixture := newDeviceFixture(t)
	userID := fixture.user(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	created, err := fixture.service.Authorize(fixture.ctx, AuthorizeCommand{
		UserID: userID, InstallationID: uuid.New(), PublicKey: publicKey,
		DisplayName: "Stale Browser Mac", Platform: "darwin", AppVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		UPDATE users SET status = 'pending_deletion', deletion_requested_at = $2 WHERE id = $1
	`, userID, fixture.now); err != nil {
		t.Fatalf("mark account pending deletion: %v", err)
	}

	if _, err := fixture.service.List(fixture.ctx, userID, uuid.Nil); !errors.Is(err, ErrAccountUnavailable) {
		t.Fatalf("List(pending deletion) error = %v", err)
	}
	if err := fixture.service.Revoke(fixture.ctx, userID, created.ID); !errors.Is(err, ErrAccountUnavailable) {
		t.Fatalf("Revoke(pending deletion) error = %v", err)
	}
}

func testSelfRevokeDigest(command SelfRevokeCommand) []byte {
	digest := sha256.Sum256([]byte(
		"agentera-self-revoke\x00" + command.DeviceID.String() + "\x00" + command.InstallationID.String() + "\x00" +
			strconv.FormatInt(command.Timestamp, 10) + "\x00" + string(command.Nonce),
	))
	return digest[:]
}

type fakeLifecycleDeviceRepository struct {
	devices        []Device
	found          Device
	selfRevocation SelfRevocationRecord
	selfErr        error
}

func (f *fakeLifecycleDeviceRepository) Authorize(context.Context, AuthorizationRecord, int) (Device, error) {
	return Device{}, nil
}

func (f *fakeLifecycleDeviceRepository) AuthorizeInTx(context.Context, pgx.Tx, AuthorizationRecord, int) (Device, error) {
	return Device{}, nil
}

func (f *fakeLifecycleDeviceRepository) Revoke(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, time.Time) error {
	return nil
}

func (f *fakeLifecycleDeviceRepository) List(context.Context, uuid.UUID) ([]Device, error) {
	return f.devices, nil
}

func (f *fakeLifecycleDeviceRepository) FindForSelfRevoke(context.Context, uuid.UUID) (Device, error) {
	return f.found, nil
}

func (f *fakeLifecycleDeviceRepository) SelfRevoke(_ context.Context, record SelfRevocationRecord) error {
	f.selfRevocation = record
	return f.selfErr
}
