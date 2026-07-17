package entitlement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestServiceIssuesSevenDayDeviceBoundEntitlementAndAuditsIssuance(t *testing.T) {
	fixture := newEntitlementFixture(t)
	binding := Binding{
		UserID: uuid.New(), DeviceID: uuid.New(), InstallationID: uuid.New(), PersonalSpaceID: uuid.New(),
	}

	issued, err := fixture.service.Issue(context.Background(), binding)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if issued.Serialized == "" || issued.ExpiresAt != fixture.now.Add(7*24*time.Hour) {
		t.Fatalf("Issue() = %+v", issued)
	}
	claims, err := fixture.service.Verify(issued.Serialized)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.UserID != binding.UserID || claims.DeviceID != binding.DeviceID ||
		claims.InstallationID != binding.InstallationID || claims.PersonalSpaceID != binding.PersonalSpaceID ||
		claims.PolicyVersion != 3 || claims.IssuedAt != fixture.now || claims.ExpiresAt != issued.ExpiresAt || claims.JTI == uuid.Nil {
		t.Fatalf("claims = %+v", claims)
	}
	if len(fixture.repository.issuances) != 1 {
		t.Fatalf("issuance audit count = %d", len(fixture.repository.issuances))
	}
	audit := fixture.repository.issuances[0]
	if audit.JTI != claims.JTI || audit.SigningKeyID != "offline-v1" || audit.Binding != binding || audit.PolicyVersion != 3 {
		t.Fatalf("issuance audit = %+v", audit)
	}

	parts := strings.Split(issued.Serialized, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("decode header JSON: %v", err)
	}
	if header["alg"] != "EdDSA" || header["kid"] != "offline-v1" || header["typ"] != "agentera-offline-entitlement+jwt" {
		t.Fatalf("header = %+v", header)
	}
}

func TestServiceRejectsTamperingWrongKeyAndExpiry(t *testing.T) {
	fixture := newEntitlementFixture(t)
	issued, err := fixture.service.Issue(context.Background(), Binding{
		UserID: uuid.New(), DeviceID: uuid.New(), InstallationID: uuid.New(), PersonalSpaceID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	parts := strings.Split(issued.Serialized, ".")
	if parts[1][0] == 'A' {
		parts[1] = "B" + parts[1][1:]
	} else {
		parts[1] = "A" + parts[1][1:]
	}
	if _, err := fixture.service.Verify(strings.Join(parts, ".")); !errors.Is(err, ErrInvalidEntitlement) {
		t.Fatalf("Verify(tampered) error = %v", err)
	}
	parts = strings.Split(issued.Serialized, ".")
	parts[2] = testkit.NonCanonicalBase64URLAlias(t, parts[2])
	if _, err := fixture.service.Verify(strings.Join(parts, ".")); !errors.Is(err, ErrInvalidEntitlement) {
		t.Fatalf("Verify(noncanonical signature) error = %v", err)
	}

	_, unrelatedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	unrelated, err := NewService(ServiceConfig{
		Repository: &fakeRepository{}, Issuer: "https://accounts.agentera.example", Audience: "agentera-studio",
		ActiveKeyID: "offline-other", SigningKeys: map[string]ed25519.PrivateKey{"offline-other": unrelatedPrivate},
		PolicyVersion: 3, Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("NewService(unrelated) error = %v", err)
	}
	if _, err := unrelated.Verify(issued.Serialized); !errors.Is(err, ErrInvalidEntitlement) {
		t.Fatalf("Verify(wrong key) error = %v", err)
	}

	fixture.now = fixture.now.Add(7 * 24 * time.Hour)
	if _, err := fixture.service.Verify(issued.Serialized); !errors.Is(err, ErrInvalidEntitlement) {
		t.Fatalf("Verify(expired) error = %v", err)
	}
}

func TestServiceFailsClosedWhenIssuanceAuditCannotBePersisted(t *testing.T) {
	fixture := newEntitlementFixture(t)
	fixture.repository.err = errors.New("postgres://secret")
	issued, err := fixture.service.Issue(context.Background(), Binding{
		UserID: uuid.New(), DeviceID: uuid.New(), InstallationID: uuid.New(), PersonalSpaceID: uuid.New(),
	})
	if !errors.Is(err, ErrUnavailable) || issued.Serialized != "" {
		t.Fatalf("Issue() = %+v, %v", issued, err)
	}
}

func TestPostgresRepositoryPersistsIssuanceAudit(t *testing.T) {
	services := testkit.IntegrationServices(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	postgres, err := store.OpenPostgres(ctx, services.DatabaseURL)
	if err != nil {
		t.Fatalf("OpenPostgres() error = %v", err)
	}
	defer postgres.Close()
	if err := store.ApplyMigrations(ctx, postgres); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `TRUNCATE offline_entitlement_issuances, devices, personal_spaces, users CASCADE`); err != nil {
		t.Fatalf("truncate entitlement tables: %v", err)
	}
	now := time.Date(2026, 7, 18, 1, 15, 0, 0, time.UTC)
	binding := Binding{UserID: uuid.New(), DeviceID: uuid.New(), InstallationID: uuid.New(), PersonalSpaceID: uuid.New()}
	if _, err := postgres.Exec(ctx, `INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)`, binding.UserID, now); err != nil {
		t.Fatalf("insert entitlement user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, binding.PersonalSpaceID, binding.UserID, now); err != nil {
		t.Fatalf("insert entitlement space: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, installation_id, public_key, display_name, platform, app_version,
			status, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'Test Mac', 'darwin', '0.1.0', 'active', $5, $5, $5)
	`, binding.DeviceID, binding.UserID, binding.InstallationID, make([]byte, 32), now); err != nil {
		t.Fatalf("insert entitlement device: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	service, err := NewService(ServiceConfig{
		Repository: NewPostgresRepository(postgres), Issuer: "https://accounts.agentera.example", Audience: "agentera-studio",
		ActiveKeyID: "offline-v1", SigningKeys: map[string]ed25519.PrivateKey{"offline-v1": privateKey},
		PolicyVersion: 3, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	issued, err := service.Issue(ctx, binding)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	claims, err := service.Verify(issued.Serialized)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	var storedKeyID string
	var storedPolicy int
	if err := postgres.QueryRow(ctx, `
		SELECT signing_key_id, policy_version FROM offline_entitlement_issuances WHERE jti = $1
	`, claims.JTI).Scan(&storedKeyID, &storedPolicy); err != nil {
		t.Fatalf("read issuance audit: %v", err)
	}
	if storedKeyID != "offline-v1" || storedPolicy != 3 {
		t.Fatalf("issuance audit key=%q policy=%d", storedKeyID, storedPolicy)
	}
}

type entitlementFixture struct {
	now        time.Time
	repository *fakeRepository
	service    *Service
}

func newEntitlementFixture(t *testing.T) *entitlementFixture {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	fixture := &entitlementFixture{
		now: time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC), repository: &fakeRepository{},
	}
	service, err := NewService(ServiceConfig{
		Repository: fixture.repository, Issuer: "https://accounts.agentera.example", Audience: "agentera-studio",
		ActiveKeyID: "offline-v1", SigningKeys: map[string]ed25519.PrivateKey{"offline-v1": privateKey},
		PolicyVersion: 3, Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	fixture.service = service
	return fixture
}

type fakeRepository struct {
	issuances []Issuance
	err       error
}

func (f *fakeRepository) Record(_ context.Context, issuance Issuance) error {
	f.issuances = append(f.issuances, issuance)
	return f.err
}

func (f *fakeRepository) RecordInTx(_ context.Context, _ pgx.Tx, issuance Issuance) error {
	return f.Record(context.Background(), issuance)
}
