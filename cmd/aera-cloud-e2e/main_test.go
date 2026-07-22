//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/admin"
	"github.com/bignormal/aera-cloud/internal/config"
	"github.com/bignormal/aera-cloud/internal/secure"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSeedRefusesNonTestOrNonLoopbackDatabase(t *testing.T) {
	for _, candidate := range []seedConfig{
		{Environment: "production", DatabaseURL: "postgres://u:p@127.0.0.1/aera_cloud"},
		{Environment: "test", DatabaseURL: "postgres://u:p@db.internal/aera_cloud"},
		{Environment: "test", DatabaseURL: "postgres://u:p@10.0.0.8/aera_cloud"},
		{Environment: "test", DatabaseURL: "postgres://u:p@127.0.0.1/aera_cloud?host=db.internal"},
		{Environment: "test", DatabaseURL: "postgres://u:p@localhost/aera_cloud"},
		{Environment: "test", DatabaseURL: "postgres://u:p@127.0.0.1/"},
	} {
		if err := candidate.validate(); err == nil {
			t.Fatalf("validate(%+v) succeeded", candidate)
		}
	}
	for _, databaseURL := range []string{
		"postgres://u:p@127.0.0.1/aera_cloud_test",
		"postgres://u:p@[::1]/aera_cloud_test",
	} {
		if err := (seedConfig{Environment: "test", DatabaseURL: databaseURL}).validate(); err != nil {
			t.Fatalf("validate(%q) error = %v", databaseURL, err)
		}
	}
}

func TestSeedAndVerifyRealCloudAdminFacts(t *testing.T) {
	seedConfig := integrationSeedConfig(t)
	output := filepath.Join(t.TempDir(), "cloud-fixture.json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seeded, err := seed(ctx, seedConfig, output)
	if err != nil {
		t.Fatalf("seed() error = %v", err)
	}
	if seeded.UserID == uuid.Nil || seeded.DeviceID == uuid.Nil || seeded.SessionID == uuid.Nil ||
		seeded.MaskedEmail == "" || seeded.RawIdentity == "" || seeded.InitialRevision != 1 {
		t.Fatalf("fixture = %+v", seeded)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("fixture mode/error = %v / %v", info.Mode().Perm(), err)
	}
	rawFixture, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var fixtureObject map[string]json.RawMessage
	if err := json.Unmarshal(rawFixture, &fixtureObject); err != nil || len(fixtureObject) != 6 {
		t.Fatalf("fixture JSON keys/error = %v / %v", fixtureObject, err)
	}
	for _, key := range []string{"user_id", "device_id", "session_id", "masked_email", "raw_lookup_identity", "initial_revision"} {
		if _, ok := fixtureObject[key]; !ok {
			t.Fatalf("fixture JSON is missing %q", key)
		}
	}

	postgres := openE2ETestPostgres(t, ctx, seedConfig.DatabaseURL)
	defer postgres.Close()
	defer cleanupE2EFixture(t, postgres, seeded)
	assertSeededCloudFacts(t, ctx, postgres, seedConfig, seeded)
	if err := verify(ctx, seedConfig, output); err == nil {
		t.Fatal("verify() succeeded before management operations")
	}

	identityCodec, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: seedConfig.IdentityEncryptionKeys.ActiveKeyID,
		EncryptionKeys:        seedConfig.IdentityEncryptionKeys.Keys,
		ActiveLookupKeyID:     seedConfig.IdentityLookupKeys.ActiveKeyID,
		LookupKeys:            seedConfig.IdentityLookupKeys.Keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	protector, err := admin.NewProtector("e2e-admin-v1", map[string][]byte{
		"e2e-admin-v1": bytes.Repeat([]byte{93}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := admin.NewControlRepository(postgres, identityCodec, protector, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := admin.NewControlService(admin.ControlServiceConfig{
		Queries: repository, Commands: repository, Protector: protector, Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorized := admin.WithServiceSubject(ctx, "aera-admin-e2e")
	actorID := uuid.New()
	sessionOperationID := uuid.New()
	sessionOperation, err := service.Execute(authorized, admin.RevokeSession, seeded.SessionID, admin.Command{
		OperationID: sessionOperationID, ActorAdminID: actorID, RequestID: "e2e-session-revoke",
		ReasonCode: "support_action", TicketReference: "E2E-SESSION", Note: "E2E session revocation",
		ExpectedRevision: 1,
	})
	if err != nil || sessionOperation.Status != admin.OperationSucceeded || sessionOperation.AdministrativeRevision != 2 {
		t.Fatalf("session operation = %+v / %v", sessionOperation, err)
	}
	approvalID := uuid.New()
	disableOperationID := uuid.New()
	disableOperation, err := service.Execute(authorized, admin.DisableUser, seeded.UserID, admin.Command{
		OperationID: disableOperationID, ActorAdminID: actorID, ApprovalID: &approvalID,
		RequestID: "e2e-account-disable", ReasonCode: "security_review",
		TicketReference: "E2E-ACCOUNT", Note: "E2E account disable", ExpectedRevision: 2,
	})
	if err != nil || disableOperation.Status != admin.OperationSucceeded || disableOperation.AdministrativeRevision != 3 {
		t.Fatalf("disable operation = %+v / %v", disableOperation, err)
	}

	if err := verify(ctx, seedConfig, output); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		UPDATE admin_operations SET ticket_reference = $2 WHERE operation_id = $1
	`, sessionOperationID, seeded.RawIdentity); err != nil {
		t.Fatal(err)
	}
	if err := verify(ctx, seedConfig, output); err == nil {
		t.Fatal("verify() ignored a raw identity leak in admin_operations")
	}
	if _, err := postgres.Exec(ctx, `
		UPDATE admin_operations SET ticket_reference = 'E2E-SESSION' WHERE operation_id = $1
	`, sessionOperationID); err != nil {
		t.Fatal(err)
	}
	if err := verify(ctx, seedConfig, output); err != nil {
		t.Fatalf("verify() after leak cleanup error = %v", err)
	}
}

func integrationSeedConfig(t *testing.T) seedConfig {
	t.Helper()
	services := testkit.IntegrationServices(t)
	return seedConfig{
		Environment: "test", DatabaseURL: services.DatabaseURL,
		IdentityEncryptionKeys: config.KeyRing{
			ActiveKeyID: "e2e-identity-enc-v1",
			Keys:        map[string][]byte{"e2e-identity-enc-v1": bytes.Repeat([]byte{91}, 32)},
		},
		IdentityLookupKeys: config.KeyRing{
			ActiveKeyID: "e2e-identity-lookup-v1",
			Keys:        map[string][]byte{"e2e-identity-lookup-v1": bytes.Repeat([]byte{92}, 32)},
		},
	}
}

func openE2ETestPostgres(t *testing.T, ctx context.Context, databaseURL string) *pgxpool.Pool {
	t.Helper()
	postgres, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	return postgres
}

func assertSeededCloudFacts(t *testing.T, ctx context.Context, postgres *pgxpool.Pool, cfg seedConfig, seeded fixture) {
	t.Helper()
	var revision int64
	var userStatus, deviceStatus string
	var sessionIsActive bool
	if err := postgres.QueryRow(ctx, `
		SELECT u.administrative_revision, u.status, d.status,
		       s.revoked_at IS NULL AND s.replaced_at IS NULL AND s.expires_at > now()
		FROM users u
		JOIN devices d ON d.user_id = u.id AND d.id = $2
		JOIN sessions s ON s.user_id = u.id AND s.device_id = d.id AND s.id = $3
		WHERE u.id = $1
	`, seeded.UserID, seeded.DeviceID, seeded.SessionID).Scan(&revision, &userStatus, &deviceStatus, &sessionIsActive); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || userStatus != "active" || deviceStatus != "active" || !sessionIsActive {
		t.Fatalf("seed state = revision:%d user:%s device:%s session_active:%t", revision, userStatus, deviceStatus, sessionIsActive)
	}
	var kind secure.IdentityKind
	var encryptionKeyID, lookupKeyID string
	var nonce, ciphertext, lookupHMAC []byte
	if err := postgres.QueryRow(ctx, `
		SELECT kind, encryption_key_id, nonce, ciphertext, lookup_key_id, lookup_hmac
		FROM identities WHERE user_id = $1
	`, seeded.UserID).Scan(&kind, &encryptionKeyID, &nonce, &ciphertext, &lookupKeyID, &lookupHMAC); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(seeded.RawIdentity)) {
		t.Fatal("identity ciphertext contains the exact lookup identity")
	}
	codec, err := secure.NewIdentityCodec(secure.IdentityCodecConfig{
		ActiveEncryptionKeyID: cfg.IdentityEncryptionKeys.ActiveKeyID,
		EncryptionKeys:        cfg.IdentityEncryptionKeys.Keys,
		ActiveLookupKeyID:     cfg.IdentityLookupKeys.ActiveKeyID,
		LookupKeys:            cfg.IdentityLookupKeys.Keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := codec.Open(kind, secure.SealedIdentity{
		EncryptionKeyID: encryptionKeyID, Nonce: nonce, Ciphertext: ciphertext,
		LookupKeyID: lookupKeyID, LookupHMAC: lookupHMAC,
	})
	if err != nil || opened != seeded.RawIdentity {
		t.Fatalf("opened identity = %q / %v", opened, err)
	}
	masked, err := admin.MaskIdentity(kind, opened)
	if err != nil || masked != seeded.MaskedEmail {
		t.Fatalf("masked identity = %q / %v", masked, err)
	}
}

func cleanupE2EFixture(t *testing.T, postgres *pgxpool.Pool, seeded fixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := postgres.Exec(ctx, `DELETE FROM audit_events WHERE subject_user_id = $1`, seeded.UserID); err != nil {
		t.Errorf("cleanup audit events: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		DELETE FROM admin_operations
		WHERE (target_type = 'user' AND target_id = $1)
		   OR (target_type = 'device' AND target_id = $2)
		   OR (target_type = 'session' AND target_id = $3)
	`, seeded.UserID, seeded.DeviceID, seeded.SessionID); err != nil {
		t.Errorf("cleanup admin operations: %v", err)
	}
	if _, err := postgres.Exec(ctx, `DELETE FROM users WHERE id = $1`, seeded.UserID); err != nil {
		t.Errorf("cleanup fixture user: %v", err)
	}
}
