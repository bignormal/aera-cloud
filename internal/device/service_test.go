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
