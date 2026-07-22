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
