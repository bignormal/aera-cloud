package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestControlRepositoryQueriesRealMaskedAccountState(t *testing.T) {
	fixture := newControlQueryFixture(t)
	ctx := context.Background()

	page, err := fixture.service.ListUsers(ctx, ListUsersRequest{PageRequest: PageRequest{Limit: 1}})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page = %+v, %v", page, err)
	}
	second, err := fixture.service.ListUsers(ctx, ListUsersRequest{PageRequest: PageRequest{Limit: 1, Cursor: page.NextCursor}})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID == page.Items[0].ID || second.NextCursor != "" {
		t.Fatalf("second page = %+v, %v", second, err)
	}
	if strings.Contains(fmt.Sprintf("%+v %+v", page, second), "alice@example.com") ||
		strings.Contains(fmt.Sprintf("%+v %+v", page, second), "+8613800138000") {
		t.Fatal("user page contains raw identity")
	}

	alice, err := fixture.service.LookupUser(ctx, LookupRequest{Kind: secure.IdentityEmail, Value: " Alice@Example.COM "})
	if err != nil {
		t.Fatalf("LookupUser(email) error = %v", err)
	}
	if alice.ID != fixture.aliceID || alice.MaskedEmail != "a***@example.com" || alice.MaskedPhone != "138****8000" {
		t.Fatalf("masked Alice = %+v", alice)
	}
	if alice.DeviceCount != 3 || alice.ActiveDeviceCount != 1 || alice.ActiveSessionCount != 1 ||
		alice.AdministrativeRevision != 1 || alice.LastCloudActivityAt == nil {
		t.Fatalf("Alice aggregates = %+v", alice)
	}
	byPhone, err := fixture.service.LookupUser(ctx, LookupRequest{Kind: secure.IdentityPhone, Value: "138 0013 8000"})
	if err != nil || byPhone.ID != fixture.aliceID {
		t.Fatalf("LookupUser(phone) = %+v, %v", byPhone, err)
	}
	byID, err := fixture.service.GetUser(ctx, fixture.aliceID)
	if err != nil || !reflect.DeepEqual(byID, alice) {
		t.Fatalf("GetUser() = %+v, %v; want %+v", byID, err, alice)
	}
	if _, err := fixture.service.LookupUser(ctx, LookupRequest{Kind: secure.IdentityEmail, Value: "nobody@example.com"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing lookup error = %v", err)
	}

	disabled, err := fixture.service.ListUsers(ctx, ListUsersRequest{Status: UserDisabled})
	if err != nil || len(disabled.Items) != 1 || disabled.Items[0].ID != fixture.bobID || !disabled.Items[0].AdministrativelyDisabled {
		t.Fatalf("disabled page = %+v, %v", disabled, err)
	}

	devices, err := fixture.service.ListUserDevices(ctx, fixture.aliceID, PageRequest{Limit: 2})
	if err != nil || len(devices.Items) != 2 || devices.NextCursor == "" {
		t.Fatalf("device first page = %+v, %v", devices, err)
	}
	deviceTail, err := fixture.service.ListUserDevices(ctx, fixture.aliceID, PageRequest{Limit: 2, Cursor: devices.NextCursor})
	if err != nil || len(deviceTail.Items) != 1 || deviceTail.NextCursor != "" {
		t.Fatalf("device second page = %+v, %v", deviceTail, err)
	}
	deviceJSON, err := json.Marshal(append(devices.Items, deviceTail.Items...))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(deviceJSON, []byte("installation")) || bytes.Contains(deviceJSON, []byte("public_key")) {
		t.Fatalf("device response leaked protected fields: %s", deviceJSON)
	}

	sessions, err := fixture.service.ListUserSessions(ctx, fixture.aliceID, PageRequest{Limit: 100})
	if err != nil || len(sessions.Items) != 5 || sessions.NextCursor != "" {
		t.Fatalf("sessions = %+v, %v", sessions, err)
	}
	statuses := make(map[uuid.UUID]SessionStatus, len(sessions.Items))
	for _, session := range sessions.Items {
		statuses[session.ID] = session.Status
	}
	for id, want := range map[uuid.UUID]SessionStatus{
		fixture.replaySessionID:  SessionReplayDetected,
		fixture.revokedSessionID: SessionRevoked,
		fixture.rotatedSessionID: SessionRotated,
		fixture.expiredSessionID: SessionExpired,
		fixture.activeSessionID:  SessionActive,
	} {
		if statuses[id] != want {
			t.Errorf("session %s status = %q, want %q", id, statuses[id], want)
		}
	}
	sessionJSON, err := json.Marshal(sessions)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sessionJSON, []byte("refresh")) || bytes.Contains(sessionJSON, []byte("family")) {
		t.Fatalf("session response leaked protected fields: %s", sessionJSON)
	}
}

func TestControlRepositoryQueriesReturnNonNullEmptyPages(t *testing.T) {
	fixture := newControlQueryFixture(t)
	ctx := context.Background()
	unknownUserID := uuid.New()

	if _, err := fixture.service.ListUserDevices(ctx, unknownUserID, PageRequest{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user devices error = %v", err)
	}
	if _, err := fixture.service.ListUserSessions(ctx, unknownUserID, PageRequest{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user sessions error = %v", err)
	}

	emailOnlyID := fixture.bobID
	devices, err := fixture.service.ListUserDevices(ctx, emailOnlyID, PageRequest{})
	if err != nil || devices.Items == nil || len(devices.Items) != 0 {
		t.Fatalf("empty devices = %+v, %v", devices, err)
	}
	sessions, err := fixture.service.ListUserSessions(ctx, emailOnlyID, PageRequest{})
	if err != nil || sessions.Items == nil || len(sessions.Items) != 0 {
		t.Fatalf("empty sessions = %+v, %v", sessions, err)
	}
}

func TestControlRepositoryCommandRevokesSessionFamilyIdempotently(t *testing.T) {
	fixture := newControlCommandFixture(t)
	ctx := WithServiceSubject(context.Background(), "aera-admin-e2e")
	command := fixture.command(1, false)

	first, err := fixture.service.Execute(ctx, RevokeSession, fixture.sessionID, command)
	if err != nil || first.Status != OperationSucceeded || first.AdministrativeRevision != 2 {
		t.Fatalf("first = %+v, %v", first, err)
	}
	replay, err := fixture.service.Execute(ctx, RevokeSession, fixture.sessionID, command)
	if err != nil || replay != first {
		t.Fatalf("replay = %+v, %v; want %+v", replay, err, first)
	}
	changed := command
	changed.Note = "different safe note"
	if _, err := fixture.service.Execute(ctx, RevokeSession, fixture.sessionID, changed); !errors.Is(err, ErrIdempotencyKeyReused) {
		t.Fatalf("semantic replay error = %v", err)
	}

	var revokedFamily, operationCount, auditCount int
	if err := fixture.postgres.QueryRow(ctx, `
		SELECT count(*) FROM sessions WHERE family_id = $1 AND revoked_at IS NOT NULL
	`, fixture.familyID).Scan(&revokedFamily); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `
		SELECT count(*) FROM admin_operations WHERE operation_id = $1 AND status = 'succeeded'
	`, command.OperationID).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		WHERE event_type = 'session_admin_revoked'
		  AND operator_identity = 'aera-admin-e2e'
		  AND subject_user_id = $1
		  AND metadata->>'operation_id' = $2
		  AND NOT (metadata ? 'note')
		  AND metadata::text NOT LIKE '%safe support note%'
	`, fixture.userID, command.OperationID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if revokedFamily != 2 || operationCount != 1 || auditCount != 1 {
		t.Fatalf("durable session command = family:%d operation:%d audit:%d", revokedFamily, operationCount, auditCount)
	}
}

func TestControlRepositoryCommandRevokesDeviceSessionsAndEntitlements(t *testing.T) {
	fixture := newControlCommandFixture(t)
	ctx := WithServiceSubject(context.Background(), "aera-admin-e2e")
	command := fixture.command(1, false)

	operation, err := fixture.service.Execute(ctx, RevokeDevice, fixture.deviceID, command)
	if err != nil || operation.Status != OperationSucceeded || operation.AdministrativeRevision != 2 {
		t.Fatalf("operation = %+v, %v", operation, err)
	}
	var deviceStatus string
	var revokedSessions, revokedEntitlements int
	if err := fixture.postgres.QueryRow(ctx, `SELECT status FROM devices WHERE id = $1`, fixture.deviceID).Scan(&deviceStatus); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE device_id = $1 AND revoked_at IS NOT NULL`, fixture.deviceID).Scan(&revokedSessions); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM offline_entitlement_issuances WHERE device_id = $1 AND revoked_at IS NOT NULL`, fixture.deviceID).Scan(&revokedEntitlements); err != nil {
		t.Fatal(err)
	}
	if deviceStatus != "revoked" || revokedSessions != 2 || revokedEntitlements != 1 {
		t.Fatalf("revoked device state = %s / sessions:%d / entitlements:%d", deviceStatus, revokedSessions, revokedEntitlements)
	}
}

func TestControlRepositoryCommandDisableThenEnableDoesNotRestoreCredentials(t *testing.T) {
	fixture := newControlCommandFixture(t)
	ctx := WithServiceSubject(context.Background(), "aera-admin-e2e")
	disable := fixture.command(1, true)

	disabled, err := fixture.service.Execute(ctx, DisableUser, fixture.userID, disable)
	if err != nil || disabled.Status != OperationSucceeded || disabled.AdministrativeRevision != 2 {
		t.Fatalf("disable = %+v, %v", disabled, err)
	}
	enable := fixture.command(2, true)
	enabled, err := fixture.service.Execute(ctx, EnableUser, fixture.userID, enable)
	if err != nil || enabled.Status != OperationSucceeded || enabled.AdministrativeRevision != 3 {
		t.Fatalf("enable = %+v, %v", enabled, err)
	}

	var userStatus, spaceStatus, deviceStatus string
	var administrativelyDisabled bool
	var revision int64
	var activeSessions, activeEntitlements int
	if err := fixture.postgres.QueryRow(ctx, `
		SELECT status, administratively_disabled, administrative_revision FROM users WHERE id = $1
	`, fixture.userID).Scan(&userStatus, &administrativelyDisabled, &revision); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT status FROM personal_spaces WHERE id = $1`, fixture.spaceID).Scan(&spaceStatus); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT status FROM devices WHERE id = $1`, fixture.deviceID).Scan(&deviceStatus); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, fixture.userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM offline_entitlement_issuances WHERE user_id = $1 AND revoked_at IS NULL`, fixture.userID).Scan(&activeEntitlements); err != nil {
		t.Fatal(err)
	}
	if userStatus != "active" || administrativelyDisabled || revision != 3 || spaceStatus != "active" ||
		deviceStatus != "revoked" || activeSessions != 0 || activeEntitlements != 0 {
		t.Fatalf(
			"enabled state = user:%s/%t/%d space:%s device:%s sessions:%d entitlements:%d",
			userStatus, administrativelyDisabled, revision, spaceStatus, deviceStatus, activeSessions, activeEntitlements,
		)
	}
}

func TestControlRepositoryCommandPersistsNotFoundAndStateConflict(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		fixture := newControlCommandFixture(t)
		ctx := WithServiceSubject(context.Background(), "aera-admin-e2e")
		command := fixture.command(1, false)
		operation, err := fixture.service.Execute(ctx, RevokeDevice, uuid.New(), command)
		if !errors.Is(err, ErrNotFound) || operation.Status != OperationFailed || operation.ErrorCode != "DEVICE_NOT_FOUND" {
			t.Fatalf("operation = %+v, %v", operation, err)
		}
		stored, err := fixture.service.GetOperation(ctx, command.OperationID)
		if err != nil || stored != operation {
			t.Fatalf("stored operation = %+v, %v; want %+v", stored, err, operation)
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		fixture := newControlCommandFixture(t)
		ctx := WithServiceSubject(context.Background(), "aera-admin-e2e")
		if _, err := fixture.postgres.Exec(ctx, `
			UPDATE devices SET status = 'revoked', revoked_at = $2 WHERE id = $1
		`, fixture.deviceID, fixture.now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		command := fixture.command(1, false)
		operation, err := fixture.service.Execute(ctx, RevokeDevice, fixture.deviceID, command)
		if !errors.Is(err, ErrStateConflict) || operation.Status != OperationConflict || operation.ErrorCode != "DEVICE_ALREADY_REVOKED" {
			t.Fatalf("operation = %+v, %v", operation, err)
		}
		var revision int64
		if err := fixture.postgres.QueryRow(ctx, `SELECT administrative_revision FROM users WHERE id = $1`, fixture.userID).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		if revision != 1 {
			t.Fatalf("revision = %d, want 1", revision)
		}
	})
}

func TestControlRepositoryCommandSerializesSameRevisionRace(t *testing.T) {
	fixture := newControlCommandFixture(t)
	ctx := WithServiceSubject(context.Background(), "aera-admin-e2e")
	commands := []Command{fixture.command(1, false), fixture.command(1, false)}
	type result struct {
		operation Operation
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, command := range commands {
		command := command
		go func() {
			<-start
			operation, err := fixture.service.Execute(ctx, RevokeSession, fixture.sessionID, command)
			results <- result{operation: operation, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results

	var successes, conflicts int
	for _, current := range []result{first, second} {
		switch {
		case current.err == nil && current.operation.Status == OperationSucceeded:
			successes++
		case errors.Is(current.err, ErrStateConflict) && current.operation.Status == OperationConflict && current.operation.ErrorCode == "USER_STATE_CONFLICT":
			conflicts++
		default:
			t.Fatalf("race result = %+v, %v", current.operation, current.err)
		}
	}
	var operationCount, auditCount int
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM admin_operations WHERE operation_id = ANY($1::uuid[])`, []uuid.UUID{commands[0].OperationID, commands[1].OperationID}).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		WHERE metadata->>'operation_id' = ANY($1::text[])
	`, []string{commands[0].OperationID.String(), commands[1].OperationID.String()}).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if successes != 1 || conflicts != 1 || operationCount != 2 || auditCount != 2 {
		t.Fatalf("race = success:%d conflict:%d operations:%d audits:%d", successes, conflicts, operationCount, auditCount)
	}
}

func TestControlRepositoryCommandCoalescesConcurrentExactReplay(t *testing.T) {
	fixture := newControlCommandFixture(t)
	ctx := WithServiceSubject(context.Background(), "aera-admin-e2e")
	command := fixture.command(1, false)
	type result struct {
		operation Operation
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			operation, err := fixture.service.Execute(ctx, RevokeSession, fixture.sessionID, command)
			results <- result{operation: operation, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.operation != second.operation ||
		first.operation.Status != OperationSucceeded || first.operation.AdministrativeRevision != 2 {
		t.Fatalf("concurrent replay = %+v/%v and %+v/%v", first.operation, first.err, second.operation, second.err)
	}
	var revision int64
	var operationCount, auditCount int
	if err := fixture.postgres.QueryRow(ctx, `SELECT administrative_revision FROM users WHERE id = $1`, fixture.userID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM admin_operations WHERE operation_id = $1`, command.OperationID).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.postgres.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE metadata->>'operation_id' = $1`, command.OperationID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if revision != 2 || operationCount != 1 || auditCount != 1 {
		t.Fatalf("coalesced replay = revision:%d operations:%d audits:%d", revision, operationCount, auditCount)
	}
}

type controlCommandFixture struct {
	postgres  *pgxpool.Pool
	service   *ControlService
	now       time.Time
	userID    uuid.UUID
	spaceID   uuid.UUID
	deviceID  uuid.UUID
	sessionID uuid.UUID
	familyID  uuid.UUID
}

func newControlCommandFixture(t *testing.T) *controlCommandFixture {
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
	if _, err := postgres.Exec(ctx, `TRUNCATE admin_operations, users CASCADE`); err != nil {
		t.Fatalf("truncate command tables: %v", err)
	}
	identity, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: "command-enc-v1",
		EncryptionKeys:        map[string][]byte{"command-enc-v1": bytes.Repeat([]byte{71}, 32)},
		ActiveLookupKeyID:     "command-lookup-v1",
		LookupKeys:            map[string][]byte{"command-lookup-v1": bytes.Repeat([]byte{72}, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	protector := testProtector(t)
	now := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	repository, err := NewControlRepository(postgres, identity, protector, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewControlService(ControlServiceConfig{
		Queries: repository, Commands: repository, Protector: protector, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &controlCommandFixture{
		postgres: postgres, service: service, now: now,
		userID: uuid.New(), spaceID: uuid.New(), deviceID: uuid.New(), sessionID: uuid.New(), familyID: uuid.New(),
	}
	fixture.seed(t, ctx)
	return fixture
}

func (f *controlCommandFixture) seed(t *testing.T, ctx context.Context) {
	t.Helper()
	if _, err := f.postgres.Exec(ctx, `
		INSERT INTO users (id, nickname, status, created_at, updated_at)
		VALUES ($1, 'Command User', 'active', $2, $2)
	`, f.userID, f.now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed command user: %v", err)
	}
	if _, err := f.postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, f.spaceID, f.userID, f.now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed command space: %v", err)
	}
	if _, err := f.postgres.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Command Mac', 'darwin', '1.0.0', 'active', $5, $5, $5)
	`, f.deviceID, f.userID, uuid.New(), bytes.Repeat([]byte{73}, 32), f.now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed command device: %v", err)
	}
	for index, sessionID := range []uuid.UUID{f.sessionID, uuid.New()} {
		if _, err := f.postgres.Exec(ctx, `
			INSERT INTO sessions (id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, sessionID, f.userID, f.deviceID, f.familyID, bytes.Repeat([]byte{byte(74 + index)}, 32),
			f.now.Add(-30*time.Minute), f.now.Add(24*time.Hour)); err != nil {
			t.Fatalf("seed command session: %v", err)
		}
	}
	if _, err := f.postgres.Exec(ctx, `
		INSERT INTO offline_entitlement_issuances (
			jti, user_id, device_id, personal_space_id, installation_id,
			signing_key_id, policy_version, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 'offline-v1', 1, $6, $7)
	`, uuid.New(), f.userID, f.deviceID, f.spaceID, uuid.New(), f.now.Add(-time.Hour), f.now.Add(24*time.Hour)); err != nil {
		t.Fatalf("seed command entitlement: %v", err)
	}
}

func (f *controlCommandFixture) command(expectedRevision int64, approval bool) Command {
	command := Command{
		OperationID: uuid.New(), ActorAdminID: uuid.New(), RequestID: "req-command-1",
		ReasonCode: "support_action", TicketReference: "OPS-123", Note: "safe support note",
		ExpectedRevision: expectedRevision,
	}
	if approval {
		approvalID := uuid.New()
		command.ApprovalID = &approvalID
	}
	return command
}

type controlQueryFixture struct {
	postgres         *pgxpool.Pool
	service          *ControlService
	identity         *secure.IdentityCodec
	now              time.Time
	aliceID          uuid.UUID
	bobID            uuid.UUID
	activeSessionID  uuid.UUID
	expiredSessionID uuid.UUID
	rotatedSessionID uuid.UUID
	revokedSessionID uuid.UUID
	replaySessionID  uuid.UUID
}

func newControlQueryFixture(t *testing.T) *controlQueryFixture {
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
	if _, err := postgres.Exec(ctx, `TRUNCATE admin_operations, users CASCADE`); err != nil {
		t.Fatalf("truncate control query tables: %v", err)
	}

	identity, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: "query-enc-v1",
		EncryptionKeys:        map[string][]byte{"query-enc-v1": bytes.Repeat([]byte{31}, 32)},
		ActiveLookupKeyID:     "query-lookup-v1",
		LookupKeys:            map[string][]byte{"query-lookup-v1": bytes.Repeat([]byte{32}, 32)},
	})
	if err != nil {
		t.Fatalf("NewIdentityCodec() error = %v", err)
	}
	protector := testProtector(t)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	repository, err := NewControlRepository(postgres, identity, protector, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewControlRepository() error = %v", err)
	}
	service, err := NewControlService(ControlServiceConfig{
		Queries: repository, Protector: protector, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewControlService() error = %v", err)
	}
	fixture := &controlQueryFixture{
		postgres: postgres, service: service, identity: identity, now: now,
		aliceID: uuid.New(), bobID: uuid.New(),
		activeSessionID: uuid.New(), expiredSessionID: uuid.New(), rotatedSessionID: uuid.New(),
		revokedSessionID: uuid.New(), replaySessionID: uuid.New(),
	}
	fixture.seed(t, ctx)
	return fixture
}

func (f *controlQueryFixture) seed(t *testing.T, ctx context.Context) {
	t.Helper()
	if _, err := f.postgres.Exec(ctx, `
		INSERT INTO users (id, nickname, status, administratively_disabled, created_at, updated_at)
		VALUES ($1, 'Alice', 'active', FALSE, $3, $3),
		       ($2, 'Bob', 'disabled', TRUE, $4, $4)
	`, f.aliceID, f.bobID, f.now.Add(-2*time.Hour), f.now.Add(-3*time.Hour)); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	f.seedIdentity(t, ctx, f.aliceID, secure.IdentityEmail, "alice@example.com", f.now.Add(-2*time.Hour))
	f.seedIdentity(t, ctx, f.aliceID, secure.IdentityPhone, "+8613800138000", f.now.Add(-90*time.Minute))
	f.seedIdentity(t, ctx, f.bobID, secure.IdentityEmail, "bob@example.com", f.now.Add(-3*time.Hour))

	activeDeviceID := uuid.New()
	f.seedDevice(t, ctx, activeDeviceID, f.aliceID, "Active Mac", "darwin", "1.0.0", "active", f.now.Add(-time.Minute), nil, 41)
	f.seedDevice(t, ctx, uuid.New(), f.aliceID, "Inactive PC", "windows", "1.0.0", "inactive", f.now.Add(-2*time.Minute), nil, 42)
	revokedAt := f.now.Add(-3 * time.Minute)
	f.seedDevice(t, ctx, uuid.New(), f.aliceID, "Revoked Mac", "darwin", "0.9.0", "revoked", f.now.Add(-3*time.Minute), &revokedAt, 43)

	f.seedSession(t, ctx, f.activeSessionID, activeDeviceID, f.now.Add(-5*time.Minute), f.now.Add(time.Hour), nil, nil, nil, 51)
	f.seedSession(t, ctx, f.expiredSessionID, activeDeviceID, f.now.Add(-6*time.Minute), f.now.Add(-time.Minute), nil, nil, nil, 52)
	replacedAt := f.now.Add(-4 * time.Minute)
	f.seedSession(t, ctx, f.rotatedSessionID, activeDeviceID, f.now.Add(-7*time.Minute), f.now.Add(-time.Minute), &replacedAt, nil, nil, 53)
	revokedAt = f.now.Add(-4 * time.Minute)
	f.seedSession(t, ctx, f.revokedSessionID, activeDeviceID, f.now.Add(-8*time.Minute), f.now.Add(-time.Minute), &replacedAt, &revokedAt, nil, 54)
	replayAt := f.now.Add(-3 * time.Minute)
	f.seedSession(t, ctx, f.replaySessionID, activeDeviceID, f.now.Add(-9*time.Minute), f.now.Add(-time.Minute), &replacedAt, &revokedAt, &replayAt, 55)
}

func (f *controlQueryFixture) seedIdentity(
	t *testing.T,
	ctx context.Context,
	userID uuid.UUID,
	kind secure.IdentityKind,
	normalized string,
	createdAt time.Time,
) {
	t.Helper()
	sealed, err := f.identity.Seal(kind, normalized)
	if err != nil {
		t.Fatalf("seal %s identity: %v", kind, err)
	}
	if _, err := f.postgres.Exec(ctx, `
		INSERT INTO identities (
			id, user_id, kind, encryption_key_id, nonce, ciphertext,
			lookup_key_id, lookup_hmac, verified_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
	`, uuid.New(), userID, kind, sealed.EncryptionKeyID, sealed.Nonce, sealed.Ciphertext,
		sealed.LookupKeyID, sealed.LookupHMAC, createdAt); err != nil {
		t.Fatalf("seed %s identity: %v", kind, err)
	}
}

func (f *controlQueryFixture) seedDevice(
	t *testing.T,
	ctx context.Context,
	id, userID uuid.UUID,
	displayName, platform, version, status string,
	lastSeen time.Time,
	revokedAt *time.Time,
	keyByte byte,
) {
	t.Helper()
	if _, err := f.postgres.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, revoked_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $9, $9)
	`, id, userID, uuid.New(), bytes.Repeat([]byte{keyByte}, 32), displayName, platform,
		version, status, lastSeen, revokedAt); err != nil {
		t.Fatalf("seed device %s: %v", status, err)
	}
}

func (f *controlQueryFixture) seedSession(
	t *testing.T,
	ctx context.Context,
	id, deviceID uuid.UUID,
	issuedAt, expiresAt time.Time,
	replacedAt, revokedAt, replayAt *time.Time,
	hashByte byte,
) {
	t.Helper()
	if _, err := f.postgres.Exec(ctx, `
		INSERT INTO sessions (
			id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at,
			replaced_at, revoked_at, replay_detected_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, id, f.aliceID, deviceID, uuid.New(), bytes.Repeat([]byte{hashByte}, 32), issuedAt,
		expiresAt, replacedAt, revokedAt, replayAt); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}
