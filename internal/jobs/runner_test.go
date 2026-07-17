package jobs

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRunOncePausesAllMaintenanceWhenLeaseStoreFails(t *testing.T) {
	maintenance := &fakeMaintenance{}
	runner, err := NewRunner(RunnerConfig{
		Lease: &fakeLease{acquireErr: errors.New("redis unavailable")}, Maintenance: maintenance,
		Owner: "instance-a", LeaseTTL: time.Minute, Interval: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}

	err = runner.RunOnce(context.Background())

	if !errors.Is(err, ErrLeaseUnavailable) {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if maintenance.calls.Load() != 0 {
		t.Fatalf("maintenance calls = %d", maintenance.calls.Load())
	}
}

func TestConcurrentRunnersExecuteDestructiveMaintenanceOnlyOnce(t *testing.T) {
	lease := &fakeLease{}
	maintenance := &fakeMaintenance{started: make(chan struct{}), unblock: make(chan struct{})}
	first := mustRunner(t, lease, maintenance, "instance-a")
	second := mustRunner(t, lease, maintenance, "instance-b")
	firstResult := make(chan error, 1)
	go func() { firstResult <- first.RunOnce(context.Background()) }()
	select {
	case <-maintenance.started:
	case <-time.After(time.Second):
		t.Fatal("first runner did not start maintenance")
	}

	if err := second.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce() error = %v", err)
	}
	if maintenance.calls.Load() != 1 {
		t.Fatalf("maintenance calls while leased = %d", maintenance.calls.Load())
	}
	close(maintenance.unblock)
	if err := <-firstResult; err != nil {
		t.Fatalf("first RunOnce() error = %v", err)
	}
	if lease.releases.Load() != 1 {
		t.Fatalf("lease releases = %d", lease.releases.Load())
	}
}

func TestRunStopsPromptlyWithItsContext(t *testing.T) {
	runner := mustRunner(t, &fakeLease{}, &fakeMaintenance{}, "instance-a")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runner.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop")
	}
}

func TestRedisLeaseUsesOwnerCheckedRelease(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr: services.RedisAddr, Username: services.RedisUsername, Password: services.RedisPassword, DB: services.RedisDB,
	})
	defer func() { _ = client.Close() }()
	lease := NewRedisLease(client)
	key := "jobs-test-" + uuid.NewString()

	acquired, err := lease.Acquire(ctx, key, "owner-a", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("Acquire(owner-a) = %v, %v", acquired, err)
	}
	acquired, err = lease.Acquire(ctx, key, "owner-b", time.Minute)
	if err != nil || acquired {
		t.Fatalf("Acquire(owner-b) = %v, %v", acquired, err)
	}
	if err := lease.Release(ctx, key, "owner-b"); err != nil {
		t.Fatalf("Release(wrong owner) error = %v", err)
	}
	acquired, err = lease.Acquire(ctx, key, "owner-b", time.Minute)
	if err != nil || acquired {
		t.Fatalf("Acquire(after wrong release) = %v, %v", acquired, err)
	}
	if err := lease.Release(ctx, key, "owner-a"); err != nil {
		t.Fatalf("Release(owner-a) error = %v", err)
	}
	acquired, err = lease.Acquire(ctx, key, "owner-b", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("Acquire(after owner release) = %v, %v", acquired, err)
	}
	_ = lease.Release(ctx, key, "owner-b")
}

func TestPostgresMaintenanceCleansExpiredRowsAndFindsDueDeletion(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		TRUNCATE audit_events, device_self_revocation_nonces, authorization_codes, oauth_requests,
		verification_challenges, sessions, devices, personal_spaces, users CASCADE
	`); err != nil {
		t.Fatalf("truncate maintenance tables: %v", err)
	}
	now := time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC)
	userID, spaceID, deviceID := uuid.New(), uuid.New(), uuid.New()
	createdAt := now.Add(-48 * time.Hour)
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, nickname, status, created_at, updated_at) VALUES ($1, 'Active', 'active', $2, $2)
	`, userID, createdAt); err != nil {
		t.Fatalf("seed maintenance user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at) VALUES ($1, $2, 'active', $3, $3)
	`, spaceID, userID, createdAt); err != nil {
		t.Fatalf("seed maintenance personal space: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO devices (id, user_id, installation_id, public_key, display_name, platform, app_version, status, last_seen_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'Maintenance Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, deviceID, userID, uuid.New(), bytes.Repeat([]byte{1}, 32), createdAt); err != nil {
		t.Fatalf("seed maintenance device: %v", err)
	}
	for index, expiry := range []time.Time{now.Add(-time.Minute), now.Add(time.Hour)} {
		if _, err := postgres.Exec(ctx, `
			INSERT INTO sessions (id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, uuid.New(), userID, deviceID, uuid.New(), bytes.Repeat([]byte{byte(10 + index)}, 32), now.Add(-time.Hour), expiry); err != nil {
			t.Fatalf("seed session %d: %v", index, err)
		}
		if _, err := postgres.Exec(ctx, `
			INSERT INTO verification_challenges (
				id, purpose, identity_kind, target_lookup_key_id, target_lookup_hmac, code_key_id, code_hmac,
				idempotency_key_hash, expires_at, resend_after, created_at
			) VALUES ($1, 'registration', 'email', 'lookup-v1', $2, 'code-v1', $3, $4, $5, $6, $7)
		`, uuid.New(), bytes.Repeat([]byte{byte(20 + index)}, 32), bytes.Repeat([]byte{byte(30 + index)}, 32),
			bytes.Repeat([]byte{byte(40 + index)}, 32), expiry, now.Add(-30*time.Minute), now.Add(-time.Hour)); err != nil {
			t.Fatalf("seed challenge %d: %v", index, err)
		}
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO verification_challenges (
			id, purpose, identity_kind, target_lookup_key_id, target_lookup_hmac, code_key_id, code_hmac,
			idempotency_key_hash, expires_at, resend_after, consumed_at, created_at
		) VALUES ($1, 'account_deletion', 'email', 'lookup-v1', $2, 'code-v1', $3, $4, $5, $6, $7, $8)
	`, uuid.New(), bytes.Repeat([]byte{61}, 32), bytes.Repeat([]byte{62}, 32), bytes.Repeat([]byte{63}, 32),
		now.Add(-time.Minute), now.Add(-30*time.Minute), now.Add(-30*time.Second), now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("seed still-valid verification receipt backing row: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO device_self_revocation_nonces (device_id, nonce_hash, used_at)
		VALUES ($1, $2, $4), ($1, $3, $5)
	`, deviceID, bytes.Repeat([]byte{50}, 32), bytes.Repeat([]byte{51}, 32), now.Add(-25*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed self-revoke nonces: %v", err)
	}
	dueUserID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, status, deletion_requested_at, created_at, updated_at)
		VALUES ($1, 'pending_deletion', $2, $2, $2)
	`, dueUserID, now.Add(-8*24*time.Hour)); err != nil {
		t.Fatalf("seed due deletion: %v", err)
	}
	finalizer := &fakeDeletionFinalizer{}
	maintenance, err := NewPostgresMaintenance(postgres, finalizer)
	if err != nil {
		t.Fatalf("NewPostgresMaintenance() error = %v", err)
	}

	if err := maintenance.Run(ctx, now); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for table, want := range map[string]int64{
		"sessions": 1, "verification_challenges": 2, "device_self_revocation_nonces": 1,
	} {
		var count int64
		if err := postgres.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != want {
			t.Fatalf("%s rows = %d, want %d", table, count, want)
		}
	}
	if len(finalizer.userIDs) != 1 || finalizer.userIDs[0] != dueUserID {
		t.Fatalf("finalized users = %v", finalizer.userIDs)
	}
}

func mustRunner(t *testing.T, lease Lease, maintenance Maintenance, owner string) *Runner {
	t.Helper()
	runner, err := NewRunner(RunnerConfig{
		Lease: lease, Maintenance: maintenance, Owner: owner,
		LeaseTTL: time.Minute, Interval: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	return runner
}

type fakeLease struct {
	mu         sync.Mutex
	held       bool
	acquireErr error
	releases   atomic.Int64
}

func (f *fakeLease) Acquire(context.Context, string, string, time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquireErr != nil {
		return false, f.acquireErr
	}
	if f.held {
		return false, nil
	}
	f.held = true
	return true, nil
}

func (f *fakeLease) Release(context.Context, string, string) error {
	f.mu.Lock()
	f.held = false
	f.mu.Unlock()
	f.releases.Add(1)
	return nil
}

type fakeMaintenance struct {
	calls   atomic.Int64
	started chan struct{}
	unblock chan struct{}
	err     error
}

func (f *fakeMaintenance) Run(context.Context, time.Time) error {
	f.calls.Add(1)
	if f.started != nil {
		close(f.started)
	}
	if f.unblock != nil {
		<-f.unblock
	}
	return f.err
}

type fakeDeletionFinalizer struct {
	userIDs []uuid.UUID
	err     error
}

func (f *fakeDeletionFinalizer) FinalizeDeletion(_ context.Context, userID, _ uuid.UUID, _ time.Time) error {
	f.userIDs = append(f.userIDs, userID)
	return f.err
}
