package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestConcurrentSixthDeviceIsRejectedUntilExistingDeviceIsRevoked(t *testing.T) {
	fixture := newDeviceFixture(t)
	userID := fixture.user(t)
	active := make([]Device, 0, 5)
	for index := 1; index <= 5; index++ {
		created, err := fixture.service.Authorize(fixture.ctx, deviceCommand(userID, index))
		if err != nil {
			t.Fatalf("Authorize(device %d) error = %v", index, err)
		}
		active = append(active, created)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, index := range []int{6, 7} {
		index := index
		go func() {
			<-start
			_, err := fixture.service.Authorize(fixture.ctx, deviceCommand(userID, index))
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; !errors.Is(err, ErrDeviceLimitReached) {
			t.Fatalf("sixth-device Authorize() error = %v", err)
		}
	}
	if got := fixture.activeCount(t, userID); got != 5 {
		t.Fatalf("active devices = %d, want 5", got)
	}

	if err := fixture.service.Revoke(fixture.ctx, userID, active[0].ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	created, err := fixture.service.Authorize(fixture.ctx, deviceCommand(userID, 6))
	if err != nil || created.ID == uuid.Nil {
		t.Fatalf("Authorize(after revoke) = %+v, %v", created, err)
	}
	if got := fixture.activeCount(t, userID); got != 5 {
		t.Fatalf("active devices after replacement = %d, want 5", got)
	}
}

func TestAuthorizeReusesSameInstallationForSameUserButRejectsOtherOwner(t *testing.T) {
	fixture := newDeviceFixture(t)
	firstUser := fixture.user(t)
	secondUser := fixture.user(t)
	command := deviceCommand(firstUser, 20)
	first, err := fixture.service.Authorize(fixture.ctx, command)
	if err != nil {
		t.Fatalf("Authorize(first) error = %v", err)
	}
	command.DisplayName = "Renamed Mac"
	reused, err := fixture.service.Authorize(fixture.ctx, command)
	if err != nil || reused.ID != first.ID || reused.DisplayName != "Renamed Mac" {
		t.Fatalf("Authorize(reuse) = %+v, %v", reused, err)
	}
	command.UserID = secondUser
	if _, err := fixture.service.Authorize(fixture.ctx, command); !errors.Is(err, ErrDeviceConflict) {
		t.Fatalf("Authorize(other owner) error = %v", err)
	}
}

func TestAuthorizeTransfersOnlyARevokedInstallationToAnotherOwnerWithTheSameKey(t *testing.T) {
	fixture := newDeviceFixture(t)
	firstUser := fixture.user(t)
	secondUser := fixture.user(t)
	command := deviceCommand(firstUser, 21)
	first, err := fixture.service.Authorize(fixture.ctx, command)
	if err != nil {
		t.Fatalf("Authorize(first) error = %v", err)
	}
	if err := fixture.service.Revoke(fixture.ctx, firstUser, first.ID); err != nil {
		t.Fatalf("Revoke(first) error = %v", err)
	}

	command.UserID = secondUser
	transferred, err := fixture.service.Authorize(fixture.ctx, command)
	if err != nil || transferred.ID != first.ID || transferred.UserID != secondUser || transferred.Status != "active" {
		t.Fatalf("Authorize(transferred) = %+v, %v", transferred, err)
	}

	if err := fixture.service.Revoke(fixture.ctx, secondUser, transferred.ID); err != nil {
		t.Fatalf("Revoke(transferred) error = %v", err)
	}
	command.UserID = firstUser
	command.PublicKey = bytes.Repeat([]byte{99}, 32)
	if _, err := fixture.service.Authorize(fixture.ctx, command); !errors.Is(err, ErrDeviceConflict) {
		t.Fatalf("Authorize(changed key) error = %v", err)
	}
}

func TestAuthorizeTransfersRevokedInstallationWithoutInheritingDesktopControlState(t *testing.T) {
	fixture := newDeviceFixture(t)
	firstUser := fixture.user(t)
	secondUser := fixture.user(t)
	command := deviceCommand(firstUser, 22)
	created, err := fixture.service.Authorize(fixture.ctx, command)
	if err != nil {
		t.Fatalf("Authorize(first) error = %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO desktop_control_instances (
			device_id, user_id, display_name, instance_type, client_version, platform, arch,
			capabilities, last_heartbeat_at, health_status, created_at, updated_at
		) VALUES ($1, $2, 'Old owner PC', 'desktop', '0.7.4', 'windows', 'x64',
			'["diagnostics.health.read"]'::jsonb, $3, 'unknown', $3, $3)
	`, created.ID, firstUser, fixture.now); err != nil {
		t.Fatalf("seed old Desktop control instance: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO desktop_control_commands (
			id, device_id, type, required_capability, idempotency_key_hash, state,
			expires_at, created_by_admin_id, request_id, created_at, updated_at
		) VALUES ($1, $2, 'health_check', 'diagnostics.health.read', $3, 'queued',
			$4::timestamptz + INTERVAL '10 minutes', $5, 'old-owner-health-check', $4, $4)
	`, uuid.New(), created.ID, bytes.Repeat([]byte{22}, 32), fixture.now, uuid.New()); err != nil {
		t.Fatalf("seed old Desktop control command: %v", err)
	}
	if err := fixture.service.Revoke(fixture.ctx, firstUser, created.ID); err != nil {
		t.Fatalf("Revoke(first) error = %v", err)
	}

	command.UserID = secondUser
	transferred, err := fixture.service.Authorize(fixture.ctx, command)
	if err != nil {
		t.Fatalf("Authorize(transferred) error = %v", err)
	}
	if transferred.ID != created.ID || transferred.UserID != secondUser || transferred.Status != "active" {
		t.Fatalf("Authorize(transferred) = %+v", transferred)
	}

	var instances, commands int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT
			(SELECT count(*) FROM desktop_control_instances WHERE device_id = $1),
			(SELECT count(*) FROM desktop_control_commands WHERE device_id = $1)
	`, created.ID).Scan(&instances, &commands); err != nil {
		t.Fatalf("count old Desktop control state: %v", err)
	}
	if instances != 0 || commands != 0 {
		t.Fatalf("old Desktop control state instances=%d commands=%d, want 0/0", instances, commands)
	}
}

func TestAuthorizePreservesDesktopControlStateForSameOwner(t *testing.T) {
	fixture := newDeviceFixture(t)
	userID := fixture.user(t)
	command := deviceCommand(userID, 23)
	created, err := fixture.service.Authorize(fixture.ctx, command)
	if err != nil {
		t.Fatalf("Authorize(first) error = %v", err)
	}
	seedDesktopControlState(t, fixture, created.ID, userID, 23)

	command.DisplayName = "Renamed same-owner PC"
	if _, err := fixture.service.Authorize(fixture.ctx, command); err != nil {
		t.Fatalf("Authorize(same owner) error = %v", err)
	}
	instances, commands := desktopControlStateCounts(t, fixture, created.ID)
	if instances != 1 || commands != 1 {
		t.Fatalf("same-owner Desktop control state instances=%d commands=%d, want 1/1", instances, commands)
	}
}

func TestAuthorizeRejectsCrossOwnerTransferWithOwnerBoundBackupState(t *testing.T) {
	fixture := newDeviceFixture(t)
	firstUser := fixture.user(t)
	secondUser := fixture.user(t)
	command := deviceCommand(firstUser, 24)
	created, err := fixture.service.Authorize(fixture.ctx, command)
	if err != nil {
		t.Fatalf("Authorize(first) error = %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO backup_devices (
			id, user_id, device_id, key_epoch, public_key, registration_signature,
			revision, status, created_at, updated_at
		) VALUES ($1, $2, $3, 1, $4, $5, 1, 'active', $6, $6)
	`, uuid.New(), firstUser, created.ID, bytes.Repeat([]byte{124}, 32), bytes.Repeat([]byte{24}, 64), fixture.now); err != nil {
		t.Fatalf("seed owner-bound backup state: %v", err)
	}
	if err := fixture.service.Revoke(fixture.ctx, firstUser, created.ID); err != nil {
		t.Fatalf("Revoke(first) error = %v", err)
	}

	command.UserID = secondUser
	if _, err := fixture.service.Authorize(fixture.ctx, command); !errors.Is(err, ErrDeviceConflict) {
		t.Fatalf("Authorize(backup-bound transfer) error = %v", err)
	}
	var storedUserID uuid.UUID
	if err := fixture.postgres.QueryRow(fixture.ctx, `SELECT user_id FROM devices WHERE id = $1`, created.ID).Scan(&storedUserID); err != nil {
		t.Fatalf("read backup-bound device owner: %v", err)
	}
	if storedUserID != firstUser {
		t.Fatalf("backup-bound device owner = %s, want %s", storedUserID, firstUser)
	}
}

func seedDesktopControlState(t *testing.T, fixture *deviceFixture, deviceID, userID uuid.UUID, marker byte) {
	t.Helper()
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO desktop_control_instances (
			device_id, user_id, display_name, instance_type, client_version, platform, arch,
			capabilities, last_heartbeat_at, health_status, created_at, updated_at
		) VALUES ($1, $2, 'Stored PC', 'desktop', '0.7.4', 'windows', 'x64',
			'["diagnostics.health.read"]'::jsonb, $3, 'unknown', $3, $3)
	`, deviceID, userID, fixture.now); err != nil {
		t.Fatalf("seed Desktop control instance: %v", err)
	}
	if _, err := fixture.postgres.Exec(fixture.ctx, `
		INSERT INTO desktop_control_commands (
			id, device_id, type, required_capability, idempotency_key_hash, state,
			expires_at, created_by_admin_id, request_id, created_at, updated_at
		) VALUES ($1, $2, 'health_check', 'diagnostics.health.read', $3, 'queued',
			$4::timestamptz + INTERVAL '10 minutes', $5, 'stored-health-check', $4, $4)
	`, uuid.New(), deviceID, bytes.Repeat([]byte{marker}, 32), fixture.now, uuid.New()); err != nil {
		t.Fatalf("seed Desktop control command: %v", err)
	}
}

func desktopControlStateCounts(t *testing.T, fixture *deviceFixture, deviceID uuid.UUID) (int64, int64) {
	t.Helper()
	var instances, commands int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT
			(SELECT count(*) FROM desktop_control_instances WHERE device_id = $1),
			(SELECT count(*) FROM desktop_control_commands WHERE device_id = $1)
	`, deviceID).Scan(&instances, &commands); err != nil {
		t.Fatalf("count Desktop control state: %v", err)
	}
	return instances, commands
}

type deviceFixture struct {
	ctx      context.Context
	postgres *pgxpool.Pool
	service  *Service
	now      time.Time
}

func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	t.Cleanup(postgres.Close)
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE sessions, devices, users CASCADE`); err != nil {
		t.Fatalf("truncate device tables: %v", err)
	}
	fixture := &deviceFixture{ctx: ctx, postgres: postgres, now: time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)}
	service, err := NewService(ServiceConfig{
		Repository: NewPostgresRepository(postgres), Clock: func() time.Time { return fixture.now }, ActiveLimit: 5,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	fixture.service = service
	return fixture
}

func (f *deviceFixture) user(t *testing.T) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)
	`, userID, f.now); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return userID
}

func (f *deviceFixture) activeCount(t *testing.T, userID uuid.UUID) int64 {
	t.Helper()
	var count int64
	if err := f.postgres.QueryRow(f.ctx, `
		SELECT count(*) FROM devices WHERE user_id = $1 AND status = 'active'
	`, userID).Scan(&count); err != nil {
		t.Fatalf("count active devices: %v", err)
	}
	return count
}

func deviceCommand(userID uuid.UUID, index int) AuthorizeCommand {
	return AuthorizeCommand{
		UserID: userID, InstallationID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("installation-%d", index))),
		PublicKey: bytes.Repeat([]byte{byte(index)}, 32), DisplayName: fmt.Sprintf("Device %d", index),
		Platform: "darwin", AppVersion: "0.1.0",
	}
}
