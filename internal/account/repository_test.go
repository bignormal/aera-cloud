package account

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/bignormal/aera-cloud/internal/verification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresRepositoryRegistersAllAccountStateAtomically(t *testing.T) {
	fixture := newRepositoryFixture(t)
	claims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 1)
	record := fixture.registrationRecord(t, claims, "Alice")

	registration, err := fixture.repository.Register(fixture.ctx, record)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if registration.UserID != record.UserID || registration.PersonalSpaceID != record.PersonalSpaceID {
		t.Fatalf("Register() = %+v", registration)
	}
	for table, want := range map[string]int64{
		"users": 1, "identities": 1, "password_credentials": 1, "personal_spaces": 1,
		"legal_acceptances": 2, "audit_events": 1,
	} {
		if got := fixture.count(t, table); got != want {
			t.Fatalf("%s count = %d, want %d", table, got, want)
		}
	}
	fixture.requireReceiptConsumed(t, claims.ChallengeID)

	candidates := fixture.identity.LookupCandidates(secure.IdentityEmail, claims.NormalizedIdentity)
	credential, found, err := fixture.repository.FindCredential(fixture.ctx, secure.IdentityEmail, candidates)
	if err != nil || !found || credential.UserID != record.UserID || credential.PersonalSpaceID != record.PersonalSpaceID {
		t.Fatalf("FindCredential() = %+v, found:%v, error:%v", credential, found, err)
	}
}

func TestPostgresRepositoryRollsBackEveryRegistrationWriteOnFailure(t *testing.T) {
	fixture := newRepositoryFixture(t)
	claims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 2)
	record := fixture.registrationRecord(t, claims, "Alice")
	record.SealedIdentity.Nonce = []byte{1}

	if _, err := fixture.repository.Register(fixture.ctx, record); err == nil {
		t.Fatal("Register() error = nil")
	}
	for _, table := range []string{"users", "identities", "password_credentials", "personal_spaces", "legal_acceptances", "audit_events"} {
		if got := fixture.count(t, table); got != 0 {
			t.Fatalf("%s count after rollback = %d", table, got)
		}
	}
	fixture.requireReceiptAvailable(t, claims.ChallengeID)
}

func TestPostgresRepositoryAllowsOnlyOneConcurrentUserForNormalizedIdentity(t *testing.T) {
	fixture := newRepositoryFixture(t)
	firstClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 3)
	secondClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 4)
	first := fixture.registrationRecord(t, firstClaims, "Alice One")
	second := fixture.registrationRecord(t, secondClaims, "Alice Two")

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, record := range []RegistrationRecord{first, second} {
		record := record
		go func() {
			<-start
			_, err := fixture.repository.Register(fixture.ctx, record)
			results <- err
		}()
	}
	close(start)

	successes := 0
	conflicts := 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrIdentityConflict):
			conflicts++
		default:
			t.Fatalf("concurrent Register() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 || fixture.count(t, "users") != 1 {
		t.Fatalf("successes=%d conflicts=%d users=%d", successes, conflicts, fixture.count(t, "users"))
	}
}

func TestPostgresRepositoryRejectsExistingIdentityAcrossLookupKeyRotation(t *testing.T) {
	fixture := newRepositoryFixture(t)
	oldClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 9)
	if _, err := fixture.repository.Register(fixture.ctx, fixture.registrationRecord(t, oldClaims, "Alice")); err != nil {
		t.Fatalf("Register(old lookup key) error = %v", err)
	}

	rotatedIdentity, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: "enc-v1", EncryptionKeys: map[string][]byte{"enc-v1": bytes.Repeat([]byte{1}, 32)},
		ActiveLookupKeyID: "lookup-v2", LookupKeys: map[string][]byte{
			"lookup-v1": bytes.Repeat([]byte{2}, 32),
			"lookup-v2": bytes.Repeat([]byte{3}, 32),
		},
	})
	if err != nil {
		t.Fatalf("NewIdentityCodec(rotated) error = %v", err)
	}
	fixture.identity = rotatedIdentity
	fixture.repository = NewPostgresRepository(fixture.postgres, rotatedIdentity)
	newClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 10)
	_, err = fixture.repository.Register(fixture.ctx, fixture.registrationRecord(t, newClaims, "Alice Again"))
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("Register(rotated lookup key) error = %v", err)
	}
	if got := fixture.count(t, "users"); got != 1 {
		t.Fatalf("users after lookup rotation = %d, want 1", got)
	}
	fixture.requireReceiptAvailable(t, newClaims.ChallengeID)
}

func TestPostgresRepositorySerializesConcurrentRegistrationAcrossActiveLookupKeys(t *testing.T) {
	fixture := newRepositoryFixture(t)
	codecFor := func(active string) *secure.IdentityCodec {
		codec, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
			ActiveEncryptionKeyID: "enc-v1", EncryptionKeys: map[string][]byte{"enc-v1": bytes.Repeat([]byte{1}, 32)},
			ActiveLookupKeyID: active, LookupKeys: map[string][]byte{
				"lookup-v1": bytes.Repeat([]byte{2}, 32),
				"lookup-v2": bytes.Repeat([]byte{3}, 32),
			},
		})
		if err != nil {
			t.Fatalf("NewIdentityCodec(%s) error = %v", active, err)
		}
		return codec
	}
	oldActive := codecFor("lookup-v1")
	newActive := codecFor("lookup-v2")
	fixture.identity = oldActive
	oldClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 11)
	oldRecord := fixture.registrationRecord(t, oldClaims, "Alice Old Active")
	oldRepository := NewPostgresRepository(fixture.postgres, oldActive)
	fixture.identity = newActive
	newClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 12)
	newRecord := fixture.registrationRecord(t, newClaims, "Alice New Active")
	newRepository := NewPostgresRepository(fixture.postgres, newActive)

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, err := oldRepository.Register(fixture.ctx, oldRecord)
		results <- err
	}()
	go func() {
		<-start
		_, err := newRepository.Register(fixture.ctx, newRecord)
		results <- err
	}()
	close(start)

	successes := 0
	conflicts := 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrIdentityConflict):
			conflicts++
		default:
			t.Fatalf("cross-key concurrent Register() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 || fixture.count(t, "users") != 1 {
		t.Fatalf("successes=%d conflicts=%d users=%d", successes, conflicts, fixture.count(t, "users"))
	}
}

func TestPostgresRepositoryFindsSameAccountByBoundEmailOrPhone(t *testing.T) {
	fixture := newRepositoryFixture(t)
	emailClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 5)
	registrationRecord := fixture.registrationRecord(t, emailClaims, "Alice")
	if _, err := fixture.repository.Register(fixture.ctx, registrationRecord); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	phoneClaims := fixture.verifiedReceipt(t, secure.IdentityPhone, "+8613800138000", verification.PurposeBindIdentity, 6)
	sealedPhone, err := fixture.identity.Seal(phoneClaims.Kind, phoneClaims.NormalizedIdentity)
	if err != nil {
		t.Fatalf("Seal(phone) error = %v", err)
	}
	if err := fixture.repository.BindIdentity(fixture.ctx, IdentityBindingRecord{
		ReceiptClaims: phoneClaims, UserID: registrationRecord.UserID, IdentityID: uuid.New(), AuditEventID: uuid.New(),
		SealedIdentity: sealedPhone, CreatedAt: fixture.now,
	}); err != nil {
		t.Fatalf("BindIdentity() error = %v", err)
	}

	for _, lookup := range []struct {
		kind       secure.IdentityKind
		normalized string
	}{{secure.IdentityEmail, "alice@example.com"}, {secure.IdentityPhone, "+8613800138000"}} {
		credential, found, err := fixture.repository.FindCredential(
			fixture.ctx, lookup.kind, fixture.identity.LookupCandidates(lookup.kind, lookup.normalized),
		)
		if err != nil || !found || credential.UserID != registrationRecord.UserID {
			t.Fatalf("FindCredential(%s) = %+v, found:%v, error:%v", lookup.kind, credential, found, err)
		}
	}
}

func TestPostgresRepositoryPasswordResetConsumesReceiptAndRevokesAllSessionFamilies(t *testing.T) {
	fixture := newRepositoryFixture(t)
	registrationClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposeRegistration, 7)
	registrationRecord := fixture.registrationRecord(t, registrationClaims, "Alice")
	if _, err := fixture.repository.Register(fixture.ctx, registrationRecord); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	fixture.seedSessions(t, registrationRecord.UserID)

	resetClaims := fixture.verifiedReceipt(t, secure.IdentityEmail, "alice@example.com", verification.PurposePasswordReset, 8)
	resetRecord := PasswordResetRecord{
		ReceiptClaims: resetClaims, PasswordHash: "replacement-hash", PasswordParamsVersion: 2,
		AuditEventID: uuid.New(), ChangedAt: fixture.now.Add(time.Minute),
	}
	if err := fixture.repository.ResetPassword(fixture.ctx, resetRecord); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	if err := fixture.repository.ResetPassword(fixture.ctx, resetRecord); !errors.Is(err, ErrReceiptUnavailable) {
		t.Fatalf("ResetPassword(replay) error = %v", err)
	}
	fixture.requireReceiptConsumed(t, resetClaims.ChallengeID)

	var passwordHash string
	var paramsVersion int
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT password_hash, params_version FROM password_credentials WHERE user_id = $1
	`, registrationRecord.UserID).Scan(&passwordHash, &paramsVersion); err != nil {
		t.Fatalf("read password credential: %v", err)
	}
	if passwordHash != "replacement-hash" || paramsVersion != 2 {
		t.Fatalf("password credential = %q v%d", passwordHash, paramsVersion)
	}
	var revoked int64
	if err := fixture.postgres.QueryRow(fixture.ctx, `
		SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NOT NULL AND revoked_reason = 'password_reset'
	`, registrationRecord.UserID).Scan(&revoked); err != nil {
		t.Fatalf("count revoked sessions: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("revoked sessions = %d, want 2", revoked)
	}
}

type repositoryFixture struct {
	ctx        context.Context
	postgres   *pgxpool.Pool
	identity   *secure.IdentityCodec
	repository *PostgresRepository
	now        time.Time
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
	if _, err := postgres.Exec(ctx, `
		TRUNCATE audit_events, legal_acceptances, sessions, devices, password_credentials,
		identities, personal_spaces, users, verification_challenges CASCADE
	`); err != nil {
		t.Fatalf("truncate account tables: %v", err)
	}
	identity, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: "enc-v1", EncryptionKeys: map[string][]byte{"enc-v1": bytes.Repeat([]byte{1}, 32)},
		ActiveLookupKeyID: "lookup-v1", LookupKeys: map[string][]byte{"lookup-v1": bytes.Repeat([]byte{2}, 32)},
	})
	if err != nil {
		t.Fatalf("NewIdentityCodec() error = %v", err)
	}
	return &repositoryFixture{
		ctx: ctx, postgres: postgres, identity: identity, repository: NewPostgresRepository(postgres, identity),
		now: time.Date(2026, 7, 17, 17, 0, 0, 0, time.UTC),
	}
}

func (f *repositoryFixture) verifiedReceipt(
	t *testing.T,
	kind secure.IdentityKind,
	normalized string,
	purpose verification.Purpose,
	discriminator byte,
) verification.ReceiptClaims {
	t.Helper()
	challengeID := uuid.New()
	lookup := f.identity.LookupCandidates(kind, normalized)[0]
	createdAt := f.now.Add(-2 * time.Minute)
	consumedAt := f.now.Add(-time.Minute)
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO verification_challenges (
			id, purpose, identity_kind, target_lookup_key_id, target_lookup_hmac,
			code_key_id, code_hmac, idempotency_key_hash, expires_at, resend_after,
			failed_attempts, consumed_at, created_at
		) VALUES ($1, $2, $3, $4, $5, 'code-v1', $6, $7, $8, $9, 0, $10, $11)
	`, challengeID, purpose, kind, lookup.KeyID, lookup.HMAC, bytes.Repeat([]byte{discriminator + 20}, 32),
		bytes.Repeat([]byte{discriminator + 40}, 32), createdAt.Add(5*time.Minute), createdAt.Add(time.Minute), consumedAt, createdAt); err != nil {
		t.Fatalf("insert verified challenge: %v", err)
	}
	return verification.ReceiptClaims{
		ChallengeID: challengeID, Kind: kind, NormalizedIdentity: normalized, Purpose: purpose,
		IssuedAt: consumedAt, ExpiresAt: f.now.Add(9 * time.Minute),
	}
}

func (f *repositoryFixture) registrationRecord(t *testing.T, claims verification.ReceiptClaims, nickname string) RegistrationRecord {
	t.Helper()
	sealed, err := f.identity.Seal(claims.Kind, claims.NormalizedIdentity)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	return RegistrationRecord{
		ReceiptClaims: claims, UserID: uuid.New(), IdentityID: uuid.New(), PersonalSpaceID: uuid.New(),
		TermsAcceptanceID: uuid.New(), PrivacyAcceptanceID: uuid.New(), AuditEventID: uuid.New(),
		Nickname: nickname, SealedIdentity: sealed, PasswordHash: "password-hash", PasswordParamsVersion: 1,
		TermsVersion: "terms-2026-07", PrivacyVersion: "privacy-2026-07", CreatedAt: f.now,
	}
}

func (f *repositoryFixture) seedSessions(t *testing.T, userID uuid.UUID) {
	t.Helper()
	deviceID := uuid.New()
	if _, err := f.postgres.Exec(f.ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Test Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, deviceID, userID, uuid.New(), bytes.Repeat([]byte{9}, 32), f.now); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	for index := byte(1); index <= 2; index++ {
		if _, err := f.postgres.Exec(f.ctx, `
			INSERT INTO sessions (
				id, user_id, device_id, family_id, refresh_token_hash, issued_at, expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, uuid.New(), userID, deviceID, uuid.New(), bytes.Repeat([]byte{index}, 32), f.now, f.now.Add(24*time.Hour)); err != nil {
			t.Fatalf("insert session %d: %v", index, err)
		}
	}
}

func (f *repositoryFixture) count(t *testing.T, table string) int64 {
	t.Helper()
	allowed := map[string]bool{
		"users": true, "identities": true, "password_credentials": true, "personal_spaces": true,
		"legal_acceptances": true, "audit_events": true,
	}
	if !allowed[table] {
		t.Fatalf("unsupported table %q", table)
	}
	var count int64
	if err := f.postgres.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

func (f *repositoryFixture) requireReceiptConsumed(t *testing.T, challengeID uuid.UUID) {
	t.Helper()
	var consumedAt pgtype.Timestamptz
	if err := f.postgres.QueryRow(f.ctx, `
		SELECT receipt_consumed_at FROM verification_challenges WHERE id = $1
	`, challengeID).Scan(&consumedAt); err != nil {
		t.Fatalf("read receipt consumption: %v", err)
	}
	if !consumedAt.Valid {
		t.Fatal("verification receipt remains available")
	}
}

func (f *repositoryFixture) requireReceiptAvailable(t *testing.T, challengeID uuid.UUID) {
	t.Helper()
	var consumedAt pgtype.Timestamptz
	if err := f.postgres.QueryRow(f.ctx, `
		SELECT receipt_consumed_at FROM verification_challenges WHERE id = $1
	`, challengeID).Scan(&consumedAt); err != nil {
		t.Fatalf("read receipt consumption: %v", err)
	}
	if consumedAt.Valid {
		t.Fatal("verification receipt was consumed by rolled back transaction")
	}
}
