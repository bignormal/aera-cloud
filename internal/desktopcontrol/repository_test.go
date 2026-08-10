package desktopcontrol

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCommandTransitionsMatchDesktopHealthLifecycle(t *testing.T) {
	tests := []struct {
		from CommandState
		to   CommandState
		want bool
	}{
		{CommandQueued, CommandClaimed, true},
		{CommandQueued, CommandExpired, true},
		{CommandClaimed, CommandRunning, true},
		{CommandClaimed, CommandFailed, false},
		{CommandClaimed, CommandExpired, true},
		{CommandRunning, CommandSucceeded, true},
		{CommandRunning, CommandFailed, true},
		{CommandRunning, CommandExpired, true},
		{CommandSucceeded, CommandRunning, false},
		{CommandFailed, CommandRunning, false},
		{CommandExpired, CommandQueued, false},
	}
	for _, test := range tests {
		if got := CanTransition(test.from, test.to); got != test.want {
			t.Errorf("CanTransition(%q, %q) = %v, want %v", test.from, test.to, got, test.want)
		}
	}
}

func TestInstanceEffectiveStatusPrioritizesLifecycleOverHeartbeat(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	heartbeat := now.Add(-60 * time.Second)
	tests := []struct {
		name         string
		userStatus   string
		deviceStatus string
		heartbeat    *time.Time
		want         EffectiveStatus
	}{
		{"online", "active", "active", &heartbeat, EffectiveOnline},
		{"offline without heartbeat", "active", "active", nil, EffectiveOffline},
		{"offline after threshold", "active", "active", timePointer(now.Add(-151 * time.Second)), EffectiveOffline},
		{"online at threshold", "active", "active", timePointer(now.Add(-150 * time.Second)), EffectiveOnline},
		{"revoked wins", "active", "revoked", &heartbeat, EffectiveRevoked},
		{"disabled wins", "disabled", "active", &heartbeat, EffectiveDisabled},
		{"pending wins", "pending_deletion", "active", &heartbeat, EffectivePending},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance := Instance{
				UserStatus: test.userStatus, DeviceStatus: test.deviceStatus,
				LastHeartbeatAt: test.heartbeat,
			}
			if got := instance.EffectiveStatus(now); got != test.want {
				t.Fatalf("EffectiveStatus() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPostgresRepositoryUpsertsOneInstancePerDevice(t *testing.T) {
	fixture := newRepositoryFixture(t)
	ctx := context.Background()
	first, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, Heartbeat{
		DisplayName: "Aera Mac", ClientVersion: "0.7.4", Platform: "darwin", Arch: "arm64",
		Capabilities: []string{CapabilityHealthRead},
	})
	if err != nil {
		t.Fatalf("AcceptHeartbeat(first) error = %v", err)
	}
	fixture.now = fixture.now.Add(time.Minute)
	health := HealthSummary{
		DesktopStatus: "healthy", RuntimeStatus: "healthy", GatewayStatus: "healthy",
		Code: HealthCodeHealthy, DurationMS: 12,
	}
	second, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, Heartbeat{
		DisplayName: "Aera Mac", ClientVersion: "0.7.5", Platform: "darwin", Arch: "arm64",
		Capabilities: []string{CapabilityHealthRead}, Health: &health,
	})
	if err != nil {
		t.Fatalf("AcceptHeartbeat(second) error = %v", err)
	}
	if first.DeviceID != second.DeviceID || second.ClientVersion != "0.7.5" || second.HealthStatus != HealthHealthy {
		t.Fatalf("upserted instances = first:%+v second:%+v", first, second)
	}
	var instances, heartbeatAudits int
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM desktop_control_instances WHERE device_id = $1`, fixture.deviceID).Scan(&instances); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE device_id = $1 AND event_type LIKE 'desktop_%'`, fixture.deviceID).Scan(&heartbeatAudits); err != nil {
		t.Fatal(err)
	}
	if instances != 1 || heartbeatAudits != 0 {
		t.Fatalf("instance/audit counts = %d/%d, want 1/0", instances, heartbeatAudits)
	}
}

func TestPostgresRepositoryReadsLifecycleAwareInstances(t *testing.T) {
	fixture := newRepositoryFixture(t)
	ctx := context.Background()
	if _, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, fixture.heartbeat()); err != nil {
		t.Fatal(err)
	}

	online := EffectiveOnline
	page, err := fixture.repository.ListInstances(ctx, InstanceFilter{
		DeviceID: &fixture.deviceID, EffectiveStatus: &online, Limit: 10,
	})
	if err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("ListInstances(online) = %+v error=%v", page, err)
	}
	userPage, err := fixture.repository.ListUserInstances(ctx, fixture.userID, InstanceFilter{Limit: 10})
	if err != nil || userPage.Total != 1 || len(userPage.Items) != 1 {
		t.Fatalf("ListUserInstances() = %+v error=%v", userPage, err)
	}
	instance, err := fixture.repository.GetInstance(ctx, fixture.deviceID)
	if err != nil || instance.EffectiveStatus(fixture.now) != EffectiveOnline {
		t.Fatalf("GetInstance(online) = %+v error=%v", instance, err)
	}

	if _, err := fixture.postgres.Exec(ctx, `
		UPDATE devices SET status = 'revoked', revoked_at = $2, updated_at = $2 WHERE id = $1
	`, fixture.deviceID, fixture.now); err != nil {
		t.Fatal(err)
	}
	instance, err = fixture.repository.GetInstance(ctx, fixture.deviceID)
	if err != nil || instance.EffectiveStatus(fixture.now) != EffectiveRevoked {
		t.Fatalf("GetInstance(revoked) = %+v error=%v", instance, err)
	}
	revoked := EffectiveRevoked
	page, err = fixture.repository.ListInstances(ctx, InstanceFilter{EffectiveStatus: &revoked, Limit: 10})
	if err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("ListInstances(revoked) = %+v error=%v", page, err)
	}

	if _, err := fixture.postgres.Exec(ctx, `UPDATE users SET status = 'disabled', updated_at = $2 WHERE id = $1`, fixture.userID, fixture.now); err != nil {
		t.Fatal(err)
	}
	instance, err = fixture.repository.GetInstance(ctx, fixture.deviceID)
	if err != nil || instance.EffectiveStatus(fixture.now) != EffectiveDisabled {
		t.Fatalf("GetInstance(disabled) = %+v error=%v", instance, err)
	}
}

func TestPostgresRepositoryQueuesClaimsRunsAndCompletesOnce(t *testing.T) {
	fixture := newRepositoryFixture(t)
	ctx := context.Background()
	if _, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, fixture.heartbeat()); err != nil {
		t.Fatal(err)
	}
	commandInput := QueueHealthCheckCommand{
		DeviceID: fixture.deviceID, IdempotencyKeyHash: bytes.Repeat([]byte{41}, 32),
		Actor: AdminActor{AdminID: uuid.New(), ServiceSubject: "aera-admin-test", RequestID: "req-health-1"},
	}
	queued, err := fixture.repository.QueueHealthCheck(ctx, commandInput)
	if err != nil {
		t.Fatalf("QueueHealthCheck() error = %v", err)
	}
	replayed, err := fixture.repository.QueueHealthCheck(ctx, commandInput)
	if err != nil || replayed.ID != queued.ID || !replayed.Replayed {
		t.Fatalf("QueueHealthCheck(replay) = %+v error=%v", replayed, err)
	}
	claimed, err := fixture.repository.ClaimNextCommand(ctx, fixture.principal)
	if err != nil || claimed == nil || claimed.ID != queued.ID || claimed.State != CommandClaimed {
		t.Fatalf("ClaimNextCommand() = %+v error=%v", claimed, err)
	}
	if _, err := fixture.repository.AdvanceCommand(ctx, fixture.principal, queued.ID, CommandResult{State: CommandFailed, Code: HealthCodeRuntimeUnavailable}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("claimed -> failed error = %v, want ErrInvalidTransition", err)
	}
	if _, err := fixture.repository.AdvanceCommand(ctx, fixture.principal, queued.ID, CommandResult{State: CommandRunning}); err != nil {
		t.Fatalf("AdvanceCommand(running) error = %v", err)
	}
	summary := HealthSummary{DesktopStatus: "healthy", RuntimeStatus: "healthy", GatewayStatus: "healthy", Code: HealthCodeHealthy, DurationMS: 9}
	completed, err := fixture.repository.AdvanceCommand(ctx, fixture.principal, queued.ID, CommandResult{State: CommandSucceeded, Code: HealthCodeHealthy, Summary: &summary})
	if err != nil || completed.State != CommandSucceeded {
		t.Fatalf("AdvanceCommand(succeeded) = %+v error=%v", completed, err)
	}
	replayedTerminal, err := fixture.repository.AdvanceCommand(ctx, fixture.principal, queued.ID, CommandResult{State: CommandSucceeded, Code: HealthCodeHealthy, Summary: &summary})
	if err != nil || !replayedTerminal.Replayed {
		t.Fatalf("AdvanceCommand(replay) = %+v error=%v", replayedTerminal, err)
	}
	var commands, audits int
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM desktop_control_commands WHERE device_id = $1`, fixture.deviceID).Scan(&commands); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE object_id = $1 AND event_type LIKE 'desktop_health_check_%'`, queued.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if commands != 1 || audits != 2 {
		t.Fatalf("command/audit counts = %d/%d, want 1/2", commands, audits)
	}
	var requestedState, completedState, completedCode string
	if err := fixture.postgres.QueryRow(ctx, `
		SELECT metadata->>'state'
		FROM audit_events
		WHERE object_id = $1 AND event_type = 'desktop_health_check_requested'
	`, queued.ID).Scan(&requestedState); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `
		SELECT metadata->>'state', metadata->>'result_code'
		FROM audit_events
		WHERE object_id = $1 AND event_type = 'desktop_health_check_completed'
	`, queued.ID).Scan(&completedState, &completedCode); err != nil {
		t.Fatal(err)
	}
	if requestedState != string(CommandQueued) || completedState != string(CommandSucceeded) || completedCode != string(HealthCodeHealthy) {
		t.Fatalf("audit states/code = %q/%q/%q", requestedState, completedState, completedCode)
	}
}

func TestPostgresRepositoryClaimsCommandOnceConcurrently(t *testing.T) {
	fixture := newRepositoryFixture(t)
	ctx := context.Background()
	if _, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, fixture.heartbeat()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.QueueHealthCheck(ctx, QueueHealthCheckCommand{
		DeviceID: fixture.deviceID, IdempotencyKeyHash: bytes.Repeat([]byte{42}, 32),
		Actor: AdminActor{AdminID: uuid.New(), ServiceSubject: "aera-admin-test", RequestID: "req-health-race"},
	}); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan *Command, 2)
	errorsByClaim := make(chan error, 2)
	for range 2 {
		go func() {
			defer wait.Done()
			command, err := fixture.repository.ClaimNextCommand(ctx, fixture.principal)
			results <- command
			errorsByClaim <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsByClaim)
	claimed := 0
	for err := range errorsByClaim {
		if err != nil {
			t.Fatalf("concurrent claim error = %v", err)
		}
	}
	for command := range results {
		if command != nil {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("concurrent claimed commands = %d, want 1", claimed)
	}
}

func TestPostgresRepositoryQueuesSameIdempotencyKeyOnceConcurrently(t *testing.T) {
	fixture := newRepositoryFixture(t)
	ctx := context.Background()
	if _, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, fixture.heartbeat()); err != nil {
		t.Fatal(err)
	}
	input := QueueHealthCheckCommand{
		DeviceID: fixture.deviceID, IdempotencyKeyHash: bytes.Repeat([]byte{44}, 32),
		Actor: AdminActor{AdminID: uuid.New(), ServiceSubject: "aera-admin-test", RequestID: "req-health-idempotent-race"},
	}
	if _, err := fixture.postgres.Exec(ctx, `
		CREATE OR REPLACE FUNCTION desktop_control_test_delay_command_insert()
		RETURNS TRIGGER LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(0.1);
			RETURN NEW;
		END;
		$$
	`); err != nil {
		t.Fatalf("install command insert race function: %v", err)
	}
	if _, err := fixture.postgres.Exec(ctx, `
		CREATE TRIGGER desktop_control_test_delay_command_insert_trigger
		BEFORE INSERT ON desktop_control_commands
		FOR EACH ROW EXECUTE FUNCTION desktop_control_test_delay_command_insert()
	`); err != nil {
		t.Fatalf("install command insert race trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = fixture.postgres.Exec(context.Background(), `DROP TRIGGER IF EXISTS desktop_control_test_delay_command_insert_trigger ON desktop_control_commands`)
		_, _ = fixture.postgres.Exec(context.Background(), `DROP FUNCTION IF EXISTS desktop_control_test_delay_command_insert()`)
	})
	var wait sync.WaitGroup
	wait.Add(2)
	commands := make(chan Command, 2)
	errorsByQueue := make(chan error, 2)
	for range 2 {
		go func() {
			defer wait.Done()
			command, err := fixture.repository.QueueHealthCheck(ctx, input)
			commands <- command
			errorsByQueue <- err
		}()
	}
	wait.Wait()
	close(commands)
	close(errorsByQueue)
	for err := range errorsByQueue {
		if err != nil {
			t.Fatalf("concurrent queue error = %v", err)
		}
	}
	var commandID uuid.UUID
	replays := 0
	for command := range commands {
		if commandID == uuid.Nil {
			commandID = command.ID
		} else if command.ID != commandID {
			t.Fatalf("concurrent command IDs = %s and %s", commandID, command.ID)
		}
		if command.Replayed {
			replays++
		}
	}
	if replays != 1 {
		t.Fatalf("concurrent replay count = %d, want 1", replays)
	}
	var audits int
	if err := fixture.postgres.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		WHERE object_id = $1 AND event_type = 'desktop_health_check_requested'
	`, commandID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("concurrent requested audits = %d, want 1", audits)
	}
}

func TestPostgresRepositoryDoesNotClaimWhenCapabilityWasWithdrawn(t *testing.T) {
	fixture := newRepositoryFixture(t)
	ctx := context.Background()
	if _, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, fixture.heartbeat()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.QueueHealthCheck(ctx, QueueHealthCheckCommand{
		DeviceID: fixture.deviceID, IdempotencyKeyHash: bytes.Repeat([]byte{45}, 32),
		Actor: AdminActor{AdminID: uuid.New(), ServiceSubject: "aera-admin-test", RequestID: "req-health-capability"},
	}); err != nil {
		t.Fatal(err)
	}
	withoutCapability := fixture.heartbeat()
	withoutCapability.Capabilities = nil
	if _, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, withoutCapability); err != nil {
		t.Fatal(err)
	}
	claimed, err := fixture.repository.ClaimNextCommand(ctx, fixture.principal)
	if err != nil {
		t.Fatal(err)
	}
	if claimed != nil {
		t.Fatalf("ClaimNextCommand(withdrawn capability) = %+v, want nil", claimed)
	}
}

func TestPostgresRepositoryExpiresOverdueCommand(t *testing.T) {
	fixture := newRepositoryFixture(t)
	ctx := context.Background()
	if _, err := fixture.repository.AcceptHeartbeat(ctx, fixture.principal, fixture.heartbeat()); err != nil {
		t.Fatal(err)
	}
	queued, err := fixture.repository.QueueHealthCheck(ctx, QueueHealthCheckCommand{
		DeviceID: fixture.deviceID, IdempotencyKeyHash: bytes.Repeat([]byte{43}, 32),
		Actor: AdminActor{AdminID: uuid.New(), ServiceSubject: "aera-admin-test", RequestID: "req-health-expire"},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(10*time.Minute + time.Second)
	claimed, err := fixture.repository.ClaimNextCommand(ctx, fixture.principal)
	if err != nil || claimed != nil {
		t.Fatalf("ClaimNextCommand(expired) = %+v error=%v", claimed, err)
	}
	expired, err := fixture.repository.GetCommand(ctx, queued.ID)
	if err != nil || expired.State != CommandExpired {
		t.Fatalf("GetCommand(expired) = %+v error=%v", expired, err)
	}
}

type repositoryFixture struct {
	postgres   *pgxpool.Pool
	repository *PostgresRepository
	now        time.Time
	userID     uuid.UUID
	deviceID   uuid.UUID
	principal  DevicePrincipal
}

func newRepositoryFixture(t *testing.T) *repositoryFixture {
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
	if _, err := postgres.Exec(ctx, `TRUNCATE desktop_control_commands, desktop_control_instances, audit_events, users CASCADE`); err != nil {
		t.Fatalf("truncate desktop control fixtures: %v", err)
	}
	fixture := &repositoryFixture{
		postgres: postgres, now: time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC),
		userID: uuid.New(), deviceID: uuid.New(),
	}
	fixture.principal = DevicePrincipal{UserID: fixture.userID, DeviceID: fixture.deviceID}
	fixture.repository = NewPostgresRepository(postgres, func() time.Time { return fixture.now })
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, nickname, status, created_at, updated_at)
		VALUES ($1, 'Desktop Fleet User', 'active', $2, $2)
	`, fixture.userID, fixture.now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed Desktop user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Aera Mac', 'darwin', '0.7.4', 'active', $5, $5, $5)
	`, fixture.deviceID, fixture.userID, uuid.New(), bytes.Repeat([]byte{71}, 32), fixture.now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed Desktop device: %v", err)
	}
	return fixture
}

func (f *repositoryFixture) heartbeat() Heartbeat {
	return Heartbeat{
		DisplayName: "Aera Mac", ClientVersion: "0.7.4", Platform: "darwin", Arch: "arm64",
		Capabilities: []string{CapabilityHealthRead},
	}
}

func timePointer(value time.Time) *time.Time { return &value }
