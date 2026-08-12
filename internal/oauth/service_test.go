package oauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bignormal/aera-cloud/internal/device"
	"github.com/bignormal/aera-cloud/internal/entitlement"
	"github.com/bignormal/aera-cloud/internal/session"
	"github.com/bignormal/aera-cloud/internal/store"
	"github.com/bignormal/aera-cloud/internal/testkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestBeginAuthorizationRequiresFixedClientS256AndExactLoopbackRedirect(t *testing.T) {
	fixture := newOAuthFixture(t)
	valid := fixture.beginRequest()
	started, err := fixture.service.Begin(context.Background(), valid)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if started.RequestID == uuid.Nil || started.ExpiresAt != fixture.now.Add(10*time.Minute) {
		t.Fatalf("Begin() = %+v", started)
	}
	stored := fixture.repository.request
	if stored.ClientID != DesktopClientID || stored.CodeChallengeMethod != "S256" || stored.RedirectURI != valid.RedirectURI {
		t.Fatalf("stored request = %+v", stored)
	}
	if bytes.Contains(stored.StateCiphertext, []byte(valid.State)) || len(stored.StateHash) != sha256.Size ||
		len(stored.StateNonce) != 12 || stored.StateEncryptionKeyID != "oauth-state-v1" {
		t.Fatal("authorization state was not encrypted and HMAC-indexed")
	}
	if len(stored.DeviceKeyDigest) != sha256.Size || bytes.Contains(stored.DeviceKeyDigest, valid.DevicePublicKey) {
		t.Fatal("device key digest was not stored safely")
	}

	invalid := []BeginRequest{
		withBegin(valid, func(request *BeginRequest) { request.ClientID = "another-client" }),
		withBegin(valid, func(request *BeginRequest) { request.CodeChallengeMethod = "plain" }),
		withBegin(valid, func(request *BeginRequest) { request.RedirectURI = "http://localhost:43123/agentera/oauth/callback" }),
		withBegin(valid, func(request *BeginRequest) { request.RedirectURI = "http://127.0.0.1:43123/wrong" }),
		withBegin(valid, func(request *BeginRequest) { request.RedirectURI = "https://127.0.0.1:43123/agentera/oauth/callback" }),
		withBegin(valid, func(request *BeginRequest) { request.RedirectURI += "?leak=true" }),
	}
	for index, request := range invalid {
		if _, err := fixture.service.Begin(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid case %d Begin() error = %v", index, err)
		}
	}
}

func TestApproveStoresOnlyAuthorizationCodeHashAndEchoesOriginalState(t *testing.T) {
	fixture := newOAuthFixture(t)
	request := fixture.beginRequest()
	started, err := fixture.service.Begin(context.Background(), request)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	userID := uuid.New()
	personalSpaceID := uuid.New()
	fixture.repository.userID = userID
	fixture.repository.personalSpaceID = personalSpaceID
	approved, err := fixture.service.Approve(context.Background(), started.RequestID, userID)
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	parsed, err := url.Parse(approved.RedirectURI)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if parsed.Query().Get("state") != request.State || code == "" {
		t.Fatalf("approval redirect = %q", approved.RedirectURI)
	}
	if fixture.repository.approval.CodeExpiresAt != fixture.now.Add(2*time.Minute) ||
		len(fixture.repository.approval.CodeHash) != sha256.Size || bytes.Contains(fixture.repository.approval.CodeHash, []byte(code)) {
		t.Fatalf("approval record = %+v", fixture.repository.approval)
	}
	if strings.Contains(approved.RedirectURI, "access_token") || strings.Contains(approved.RedirectURI, "refresh_token") {
		t.Fatalf("approval redirect leaked tokens: %q", approved.RedirectURI)
	}
}

func TestExchangeRequiresPKCEAndDeviceProofAndConsumesCodeOnce(t *testing.T) {
	fixture := newOAuthFixture(t)
	request := fixture.beginRequest()
	started, err := fixture.service.Begin(context.Background(), request)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	fixture.repository.userID = uuid.New()
	fixture.repository.personalSpaceID = uuid.New()
	approved, err := fixture.service.Approve(context.Background(), started.RequestID, fixture.repository.userID)
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	parsed, _ := url.Parse(approved.RedirectURI)
	code := parsed.Query().Get("code")

	wrongVerifier := fixture.exchangeRequest(code)
	wrongVerifier.CodeVerifier = strings.Repeat("z", 64)
	wrongVerifier.DeviceProof = signDeviceProof(t, fixture.devicePrivateKey, code, wrongVerifier.CodeVerifier, request.InstallationID)
	if _, err := fixture.service.Exchange(context.Background(), wrongVerifier); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("Exchange(wrong verifier) error = %v", err)
	}
	if fixture.repository.consumed {
		t.Fatal("wrong PKCE verifier consumed the authorization code")
	}

	wrongProof := fixture.exchangeRequest(code)
	wrongProof.DeviceProof = bytes.Repeat([]byte{1}, ed25519.SignatureSize)
	if _, err := fixture.service.Exchange(context.Background(), wrongProof); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("Exchange(wrong proof) error = %v", err)
	}
	if fixture.repository.consumed {
		t.Fatal("wrong device proof consumed the authorization code")
	}

	valid := fixture.exchangeRequest(code)
	tokens, err := fixture.service.Exchange(context.Background(), valid)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if !fixture.repository.consumed || tokens.UserID != fixture.repository.userID || tokens.DeviceID == uuid.Nil ||
		tokens.PersonalSpaceID != fixture.repository.personalSpaceID {
		t.Fatalf("token response = %+v", tokens)
	}
	if fixture.devices.last.InstallationID != request.InstallationID || !bytes.Equal(fixture.devices.last.PublicKey, request.DevicePublicKey) {
		t.Fatalf("authorized device = %+v", fixture.devices.last)
	}
	if _, err := fixture.service.Exchange(context.Background(), valid); !errors.Is(err, ErrAuthorizationReplayed) {
		t.Fatalf("Exchange(replay) error = %v", err)
	}
}

func TestExchangePreservesDeviceServiceUnavailable(t *testing.T) {
	fixture := newOAuthFixture(t)
	request := fixture.beginRequest()
	started, err := fixture.service.Begin(context.Background(), request)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	fixture.repository.userID = uuid.New()
	fixture.repository.personalSpaceID = uuid.New()
	approved, err := fixture.service.Approve(context.Background(), started.RequestID, fixture.repository.userID)
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	parsed, _ := url.Parse(approved.RedirectURI)
	fixture.devices.err = device.ErrUnavailable

	if _, err := fixture.service.Exchange(context.Background(), fixture.exchangeRequest(parsed.Query().Get("code"))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Exchange(device unavailable) error = %v", err)
	}
	if fixture.repository.consumed {
		t.Fatal("device storage failure consumed the authorization code")
	}
}

func TestExchangePreservesDeviceConflict(t *testing.T) {
	fixture := newOAuthFixture(t)
	request := fixture.beginRequest()
	started, err := fixture.service.Begin(context.Background(), request)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	fixture.repository.userID = uuid.New()
	fixture.repository.personalSpaceID = uuid.New()
	approved, err := fixture.service.Approve(context.Background(), started.RequestID, fixture.repository.userID)
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	parsed, _ := url.Parse(approved.RedirectURI)
	fixture.devices.err = device.ErrDeviceConflict

	if _, err := fixture.service.Exchange(context.Background(), fixture.exchangeRequest(parsed.Query().Get("code"))); !errors.Is(err, ErrDeviceConflict) {
		t.Fatalf("Exchange(device conflict) error = %v", err)
	}
	if fixture.repository.consumed {
		t.Fatal("device ownership conflict consumed the authorization code")
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
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
	if _, err := postgres.Exec(ctx, `TRUNCATE authorization_codes, oauth_requests, personal_spaces, users CASCADE`); err != nil {
		t.Fatalf("truncate OAuth tables: %v", err)
	}
	now := time.Date(2026, 7, 18, 4, 30, 0, 0, time.UTC)
	userID := uuid.New()
	personalSpaceID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)
	`, userID, now); err != nil {
		t.Fatalf("insert OAuth user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, personalSpaceID, userID, now); err != nil {
		t.Fatalf("insert OAuth personal space: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	verifier := strings.Repeat("p", 64)
	challenge := sha256.Sum256([]byte(verifier))
	oauthService, err := NewService(ServiceConfig{
		Repository: NewPostgresRepository(postgres), Devices: &fakeDeviceAuthorizer{}, Sessions: &fakeSessionStarter{},
		ActiveStateKeyID: "oauth-state-v1", StateEncryptionKeys: map[string][]byte{"oauth-state-v1": bytes.Repeat([]byte{5}, 32)},
		StateHMACKey: bytes.Repeat([]byte{6}, 32), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	begin := BeginRequest{
		ClientID: DesktopClientID, RedirectURI: "http://127.0.0.1:43123/agentera/oauth/callback",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), CodeChallengeMethod: "S256",
		State: strings.Repeat("r", 48), InstallationID: uuid.New(), DevicePublicKey: publicKey,
		DeviceDisplayName: "Test Mac", DevicePlatform: "darwin", AppVersion: "0.1.0",
	}
	started, err := oauthService.Begin(ctx, begin)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	approved, err := oauthService.Approve(ctx, started.RequestID, userID)
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	redirect, _ := url.Parse(approved.RedirectURI)
	code := redirect.Query().Get("code")
	exchange := ExchangeRequest{
		AuthorizationCode: code, CodeVerifier: verifier, InstallationID: begin.InstallationID,
		DeviceProof: signDeviceProof(t, privateKey, code, verifier, begin.InstallationID),
	}
	if _, err := oauthService.Exchange(ctx, exchange); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if _, err := oauthService.Exchange(ctx, exchange); !errors.Is(err, ErrAuthorizationReplayed) {
		t.Fatalf("Exchange(replay) error = %v", err)
	}
	var storedCodeHash []byte
	var codeConsumed pgtype.Timestamptz
	var requestConsumed pgtype.Timestamptz
	var stateCiphertext []byte
	if err := postgres.QueryRow(ctx, `
		SELECT ac.code_hash, ac.consumed_at, r.consumed_at, r.state_ciphertext
		FROM authorization_codes ac JOIN oauth_requests r ON r.id = ac.oauth_request_id
	`).Scan(&storedCodeHash, &codeConsumed, &requestConsumed, &stateCiphertext); err != nil {
		t.Fatalf("read OAuth storage: %v", err)
	}
	if len(storedCodeHash) != sha256.Size || bytes.Contains(storedCodeHash, []byte(code)) ||
		!codeConsumed.Valid || !requestConsumed.Valid || bytes.Contains(stateCiphertext, []byte(begin.State)) {
		t.Fatalf("OAuth storage hash=%d codeConsumed=%v requestConsumed=%v", len(storedCodeHash), codeConsumed.Valid, requestConsumed.Valid)
	}
}

func TestConcurrentSixthDeviceExchangesRemainRetryableUntilCapacityExists(t *testing.T) {
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
		TRUNCATE authorization_codes, oauth_requests, audit_events, sessions, devices, personal_spaces, users CASCADE
	`); err != nil {
		t.Fatalf("truncate OAuth device tables: %v", err)
	}
	now := time.Date(2026, 7, 18, 5, 0, 0, 0, time.UTC)
	userID := uuid.New()
	personalSpaceID := uuid.New()
	if _, err := postgres.Exec(ctx, `INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)`, userID, now); err != nil {
		t.Fatalf("insert OAuth device user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, personalSpaceID, userID, now); err != nil {
		t.Fatalf("insert OAuth device personal space: %v", err)
	}
	deviceService, err := device.NewService(device.ServiceConfig{
		Repository: device.NewPostgresRepository(postgres), ActiveLimit: 5, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("device.NewService() error = %v", err)
	}
	active := make([]device.Device, 0, 5)
	for index := byte(1); index <= 5; index++ {
		created, err := deviceService.Authorize(ctx, device.AuthorizeCommand{
			UserID: userID, InstallationID: uuid.New(), PublicKey: bytes.Repeat([]byte{index}, 32),
			DisplayName: "Existing Device", Platform: "darwin", AppVersion: "0.1.0",
		})
		if err != nil {
			t.Fatalf("seed device %d: %v", index, err)
		}
		active = append(active, created)
	}
	oauthService, err := NewService(ServiceConfig{
		Repository: NewPostgresRepository(postgres), Devices: deviceService, Sessions: &fakeSessionStarter{},
		ActiveStateKeyID: "oauth-state-v1", StateEncryptionKeys: map[string][]byte{"oauth-state-v1": bytes.Repeat([]byte{5}, 32)},
		StateHMACKey: bytes.Repeat([]byte{6}, 32), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	first := prepareApprovedExchange(t, ctx, oauthService, userID, 6)
	second := prepareApprovedExchange(t, ctx, oauthService, userID, 7)

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, exchange := range []ExchangeRequest{first, second} {
		exchange := exchange
		go func() {
			<-start
			_, err := oauthService.Exchange(ctx, exchange)
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; !errors.Is(err, ErrDeviceLimitReached) {
			t.Fatalf("sixth-device Exchange() error = %v", err)
		}
	}
	var consumed int64
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM authorization_codes WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil {
		t.Fatalf("count consumed codes: %v", err)
	}
	if consumed != 0 {
		t.Fatalf("device-limit failures consumed %d authorization codes", consumed)
	}
	if err := deviceService.Revoke(ctx, userID, active[0].ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, err := oauthService.Exchange(ctx, first); err != nil {
		t.Fatalf("Exchange(after revoke) error = %v", err)
	}
	if _, err := oauthService.Exchange(ctx, second); !errors.Is(err, ErrDeviceLimitReached) {
		t.Fatalf("second waiting Exchange() error = %v", err)
	}
}

func TestFailedExchangeRollsBackDeviceAndLeavesAuthorizationRetryable(t *testing.T) {
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
		TRUNCATE authorization_codes, oauth_requests, audit_events, sessions, devices, personal_spaces, users CASCADE
	`); err != nil {
		t.Fatalf("truncate OAuth transaction tables: %v", err)
	}
	now := time.Date(2026, 7, 18, 5, 30, 0, 0, time.UTC)
	userID := uuid.New()
	personalSpaceID := uuid.New()
	if _, err := postgres.Exec(ctx, `INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)`, userID, now); err != nil {
		t.Fatalf("insert OAuth transaction user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, personalSpaceID, userID, now); err != nil {
		t.Fatalf("insert OAuth transaction personal space: %v", err)
	}
	deviceService, err := device.NewService(device.ServiceConfig{
		Repository: device.NewPostgresRepository(postgres), ActiveLimit: 5, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("device.NewService() error = %v", err)
	}
	oauthService, err := NewService(ServiceConfig{
		Repository: NewPostgresRepository(postgres), Devices: deviceService, Sessions: failingSessionStarter{},
		ActiveStateKeyID: "oauth-state-v1", StateEncryptionKeys: map[string][]byte{"oauth-state-v1": bytes.Repeat([]byte{5}, 32)},
		StateHMACKey: bytes.Repeat([]byte{6}, 32), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	exchange := prepareApprovedExchange(t, ctx, oauthService, userID, 8)
	if _, err := oauthService.Exchange(ctx, exchange); !errors.Is(err, session.ErrUnavailable) {
		t.Fatalf("Exchange() error = %v", err)
	}
	var devices int64
	var consumed int64
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&devices); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM authorization_codes WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil {
		t.Fatalf("count consumed authorization codes: %v", err)
	}
	if devices != 0 || consumed != 0 {
		t.Fatalf("failed exchange left devices=%d consumed_codes=%d", devices, consumed)
	}
}

func TestFailedExchangeRollsBackCrossOwnerDeviceTransferAndLeavesAuthorizationRetryable(t *testing.T) {
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
		TRUNCATE authorization_codes, oauth_requests, audit_events, sessions, devices, personal_spaces, users CASCADE
	`); err != nil {
		t.Fatalf("truncate OAuth transfer tables: %v", err)
	}
	now := time.Date(2026, 8, 13, 2, 0, 0, 0, time.UTC)
	oldUserID := uuid.New()
	newUserID := uuid.New()
	newPersonalSpaceID := uuid.New()
	if _, err := postgres.Exec(ctx, `
		INSERT INTO users (id, status, created_at, updated_at)
		VALUES ($1, 'active', $3, $3), ($2, 'active', $3, $3)
	`, oldUserID, newUserID, now); err != nil {
		t.Fatalf("insert OAuth transfer users: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, newPersonalSpaceID, newUserID, now); err != nil {
		t.Fatalf("insert OAuth transfer personal space: %v", err)
	}
	deviceService, err := device.NewService(device.ServiceConfig{
		Repository: device.NewPostgresRepository(postgres), ActiveLimit: 5, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("device.NewService() error = %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	installationID := uuid.New()
	storedDevice, err := deviceService.Authorize(ctx, device.AuthorizeCommand{
		UserID: oldUserID, InstallationID: installationID, PublicKey: publicKey,
		DisplayName: "Old owner PC", Platform: "windows", AppVersion: "0.7.4",
	})
	if err != nil {
		t.Fatalf("Authorize(old owner) error = %v", err)
	}
	if err := deviceService.Revoke(ctx, oldUserID, storedDevice.ID); err != nil {
		t.Fatalf("Revoke(old owner) error = %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO desktop_control_instances (
			device_id, user_id, display_name, instance_type, client_version, platform, arch,
			capabilities, last_heartbeat_at, health_status, created_at, updated_at
		) VALUES ($1, $2, 'Old owner PC', 'desktop', '0.7.4', 'windows', 'x64',
			'["diagnostics.health.read"]'::jsonb, $3, 'unknown', $3, $3)
	`, storedDevice.ID, oldUserID, now); err != nil {
		t.Fatalf("seed old-owner Desktop control instance: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO desktop_control_commands (
			id, device_id, type, required_capability, idempotency_key_hash, state,
			expires_at, created_by_admin_id, request_id, created_at, updated_at
		) VALUES ($1, $2, 'health_check', 'diagnostics.health.read', $3, 'queued',
			$4::timestamptz + INTERVAL '10 minutes', $5, 'rollback-health-check', $4, $4)
	`, uuid.New(), storedDevice.ID, bytes.Repeat([]byte{0x31}, 32), now, uuid.New()); err != nil {
		t.Fatalf("seed old-owner Desktop control command: %v", err)
	}
	oauthService, err := NewService(ServiceConfig{
		Repository: NewPostgresRepository(postgres), Devices: deviceService, Sessions: failingSessionStarter{},
		ActiveStateKeyID: "oauth-state-v1", StateEncryptionKeys: map[string][]byte{"oauth-state-v1": bytes.Repeat([]byte{5}, 32)},
		StateHMACKey: bytes.Repeat([]byte{6}, 32), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	verifier := strings.Repeat("x", 64)
	challenge := sha256.Sum256([]byte(verifier))
	started, err := oauthService.Begin(ctx, BeginRequest{
		ClientID: DesktopClientID, RedirectURI: "http://127.0.0.1:43123/agentera/oauth/callback",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), CodeChallengeMethod: "S256",
		State: strings.Repeat("r", 48), InstallationID: installationID, DevicePublicKey: publicKey,
		DeviceDisplayName: "New owner PC", DevicePlatform: "windows", AppVersion: "0.7.4",
	})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	approved, err := oauthService.Approve(ctx, started.RequestID, newUserID)
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	redirect, _ := url.Parse(approved.RedirectURI)
	code := redirect.Query().Get("code")
	exchange := ExchangeRequest{
		AuthorizationCode: code, CodeVerifier: verifier, InstallationID: installationID,
		DeviceProof: signDeviceProof(t, privateKey, code, verifier, installationID),
	}
	if _, err := oauthService.Exchange(ctx, exchange); !errors.Is(err, session.ErrUnavailable) {
		t.Fatalf("Exchange() error = %v", err)
	}

	var storedUserID uuid.UUID
	var status string
	var instances, commands, consumedCodes int64
	if err := postgres.QueryRow(ctx, `
		SELECT
			(SELECT user_id FROM devices WHERE id = $1),
			(SELECT status FROM devices WHERE id = $1),
			(SELECT count(*) FROM desktop_control_instances WHERE device_id = $1),
			(SELECT count(*) FROM desktop_control_commands WHERE device_id = $1),
			(SELECT count(*) FROM authorization_codes WHERE consumed_at IS NOT NULL)
	`, storedDevice.ID).Scan(&storedUserID, &status, &instances, &commands, &consumedCodes); err != nil {
		t.Fatalf("read rolled-back OAuth transfer state: %v", err)
	}
	if storedUserID != oldUserID || status != "revoked" || instances != 1 || commands != 1 || consumedCodes != 0 {
		t.Fatalf(
			"rolled-back transfer owner=%s status=%s instances=%d commands=%d consumed_codes=%d, want %s/revoked/1/1/0",
			storedUserID, status, instances, commands, consumedCodes, oldUserID,
		)
	}
}

func TestAuthorizationExchangeCommitsDeviceSessionEntitlementAndCodeTogether(t *testing.T) {
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
		TRUNCATE authorization_codes, oauth_requests, offline_entitlement_issuances,
			audit_events, sessions, devices, personal_spaces, users CASCADE
	`); err != nil {
		t.Fatalf("truncate OAuth commit tables: %v", err)
	}
	now := time.Date(2026, 7, 18, 5, 45, 0, 0, time.UTC)
	userID := uuid.New()
	personalSpaceID := uuid.New()
	if _, err := postgres.Exec(ctx, `INSERT INTO users (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)`, userID, now); err != nil {
		t.Fatalf("insert OAuth commit user: %v", err)
	}
	if _, err := postgres.Exec(ctx, `
		INSERT INTO personal_spaces (id, owner_user_id, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, personalSpaceID, userID, now); err != nil {
		t.Fatalf("insert OAuth commit personal space: %v", err)
	}
	_, accessPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate access signing key: %v", err)
	}
	accessSigner, err := session.NewAccessSigner(session.AccessSignerConfig{
		Issuer: "https://accounts.agentera.example", Audience: DesktopClientID,
		ActiveKeyID: "access-v1", SigningKeys: map[string]ed25519.PrivateKey{"access-v1": accessPrivateKey},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("session.NewAccessSigner() error = %v", err)
	}
	_, offlinePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate offline signing key: %v", err)
	}
	offlineService, err := entitlement.NewService(entitlement.ServiceConfig{
		Repository: entitlement.NewPostgresRepository(postgres),
		Issuer:     "https://accounts.agentera.example", Audience: DesktopClientID,
		ActiveKeyID: "offline-v1", SigningKeys: map[string]ed25519.PrivateKey{"offline-v1": offlinePrivateKey},
		PolicyVersion: 1, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("entitlement.NewService() error = %v", err)
	}
	sessionService, err := session.NewService(session.ServiceConfig{
		Repository: session.NewPostgresRepository(postgres), AccessTokens: accessSigner,
		OfflineEntitlements: offlineService, RefreshHMACKey: bytes.Repeat([]byte{9}, 32),
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("session.NewService() error = %v", err)
	}
	deviceService, err := device.NewService(device.ServiceConfig{
		Repository: device.NewPostgresRepository(postgres), ActiveLimit: 5, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("device.NewService() error = %v", err)
	}
	oauthService, err := NewService(ServiceConfig{
		Repository: NewPostgresRepository(postgres), Devices: deviceService, Sessions: sessionService,
		ActiveStateKeyID: "oauth-state-v1", StateEncryptionKeys: map[string][]byte{"oauth-state-v1": bytes.Repeat([]byte{5}, 32)},
		StateHMACKey: bytes.Repeat([]byte{6}, 32), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	exchange := prepareApprovedExchange(t, ctx, oauthService, userID, 9)
	tokens, err := oauthService.Exchange(ctx, exchange)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	accessClaims, err := accessSigner.Verify(tokens.AccessToken)
	if err != nil || accessClaims.UserID != userID || accessClaims.DeviceID != tokens.DeviceID {
		t.Fatalf("access claims = %+v, %v", accessClaims, err)
	}
	offlineClaims, err := offlineService.Verify(tokens.OfflineEntitlement)
	if err != nil || offlineClaims.UserID != userID || offlineClaims.DeviceID != tokens.DeviceID ||
		offlineClaims.InstallationID != exchange.InstallationID {
		t.Fatalf("offline claims = %+v, %v", offlineClaims, err)
	}
	var deviceCount, sessionCount, entitlementCount, consumedCodeCount int64
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&deviceCount); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&sessionCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM offline_entitlement_issuances`).Scan(&entitlementCount); err != nil {
		t.Fatalf("count entitlements: %v", err)
	}
	if err := postgres.QueryRow(ctx, `SELECT count(*) FROM authorization_codes WHERE consumed_at IS NOT NULL`).Scan(&consumedCodeCount); err != nil {
		t.Fatalf("count consumed authorization codes: %v", err)
	}
	if deviceCount != 1 || sessionCount != 1 || entitlementCount != 1 || consumedCodeCount != 1 {
		t.Fatalf("committed rows devices=%d sessions=%d entitlements=%d codes=%d", deviceCount, sessionCount, entitlementCount, consumedCodeCount)
	}
}

func prepareApprovedExchange(
	t *testing.T,
	ctx context.Context,
	service *Service,
	userID uuid.UUID,
	discriminator int,
) ExchangeRequest {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	verifier := strings.Repeat(string(rune('a'+discriminator)), 64)
	challenge := sha256.Sum256([]byte(verifier))
	installationID := uuid.New()
	started, err := service.Begin(ctx, BeginRequest{
		ClientID: DesktopClientID, RedirectURI: "http://127.0.0.1:43123/agentera/oauth/callback",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), CodeChallengeMethod: "S256",
		State: strings.Repeat(string(rune('k'+discriminator)), 48), InstallationID: installationID,
		DevicePublicKey: publicKey, DeviceDisplayName: "New Device", DevicePlatform: "darwin", AppVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	approved, err := service.Approve(ctx, started.RequestID, userID)
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	redirect, _ := url.Parse(approved.RedirectURI)
	code := redirect.Query().Get("code")
	return ExchangeRequest{
		AuthorizationCode: code, CodeVerifier: verifier, InstallationID: installationID,
		DeviceProof: signDeviceProof(t, privateKey, code, verifier, installationID),
	}
}

type oauthFixture struct {
	now              time.Time
	codeVerifier     string
	devicePublicKey  ed25519.PublicKey
	devicePrivateKey ed25519.PrivateKey
	repository       *fakeOAuthRepository
	devices          *fakeDeviceAuthorizer
	sessions         *fakeSessionStarter
	service          *Service
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	fixture := &oauthFixture{
		now: time.Date(2026, 7, 18, 4, 0, 0, 0, time.UTC), codeVerifier: strings.Repeat("v", 64),
		devicePublicKey: publicKey, devicePrivateKey: privateKey,
		repository: &fakeOAuthRepository{}, devices: &fakeDeviceAuthorizer{}, sessions: &fakeSessionStarter{},
	}
	service, err := NewService(ServiceConfig{
		Repository: fixture.repository, Devices: fixture.devices, Sessions: fixture.sessions,
		ActiveStateKeyID: "oauth-state-v1", StateEncryptionKeys: map[string][]byte{"oauth-state-v1": bytes.Repeat([]byte{5}, 32)},
		StateHMACKey: bytes.Repeat([]byte{6}, 32), Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	fixture.service = service
	return fixture
}

func (f *oauthFixture) beginRequest() BeginRequest {
	digest := sha256.Sum256([]byte(f.codeVerifier))
	return BeginRequest{
		ClientID: DesktopClientID, RedirectURI: "http://127.0.0.1:43123/agentera/oauth/callback",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]), CodeChallengeMethod: "S256",
		State: strings.Repeat("s", 48), InstallationID: uuid.New(), DevicePublicKey: append([]byte(nil), f.devicePublicKey...),
		DeviceDisplayName: "Alice Mac", DevicePlatform: "darwin", AppVersion: "0.1.0",
	}
}

func (f *oauthFixture) exchangeRequest(code string) ExchangeRequest {
	return ExchangeRequest{
		AuthorizationCode: code, CodeVerifier: f.codeVerifier, InstallationID: f.repository.request.InstallationID,
		DeviceProof: signDeviceProof(nil, f.devicePrivateKey, code, f.codeVerifier, f.repository.request.InstallationID),
	}
}

func withBegin(request BeginRequest, mutate func(*BeginRequest)) BeginRequest {
	copy := request
	mutate(&copy)
	return copy
}

func signDeviceProof(t *testing.T, privateKey ed25519.PrivateKey, code, verifier string, installationID uuid.UUID) []byte {
	if t != nil {
		t.Helper()
	}
	digest := sha256.Sum256([]byte(code + "\x00" + verifier + "\x00" + installationID.String()))
	return ed25519.Sign(privateKey, digest[:])
}

type fakeOAuthRepository struct {
	request         AuthorizationRecord
	approval        ApprovalRecord
	userID          uuid.UUID
	personalSpaceID uuid.UUID
	consumed        bool
}

func (f *fakeOAuthRepository) Save(_ context.Context, record AuthorizationRecord) error {
	f.request = record
	return nil
}

func (f *fakeOAuthRepository) Approve(_ context.Context, record ApprovalRecord) (ApprovedRequest, error) {
	f.approval = record
	if record.RequestID != f.request.ID || f.request.ExpiresAt.Before(record.ApprovedAt) || f.userID != record.UserID {
		return ApprovedRequest{}, ErrInvalidAuthorization
	}
	return ApprovedRequest{AuthorizationRecord: f.request}, nil
}

func (f *fakeOAuthRepository) Exchange(
	ctx context.Context,
	codeHash []byte,
	_ time.Time,
	finalize func(context.Context, pgx.Tx, Grant) (session.TokenSet, error),
) (session.TokenSet, error) {
	if f.consumed {
		return session.TokenSet{}, ErrAuthorizationReplayed
	}
	if !bytes.Equal(codeHash, f.approval.CodeHash) {
		return session.TokenSet{}, ErrInvalidAuthorization
	}
	tokens, err := finalize(ctx, nil, Grant{
		AuthorizationRecord: f.request, UserID: f.userID, PersonalSpaceID: f.personalSpaceID,
	})
	if err != nil {
		return session.TokenSet{}, err
	}
	f.consumed = true
	return tokens, nil
}

type fakeDeviceAuthorizer struct {
	last device.AuthorizeCommand
	err  error
}

func (f *fakeDeviceAuthorizer) AuthorizeInTx(_ context.Context, _ pgx.Tx, command device.AuthorizeCommand) (device.Device, error) {
	f.last = command
	if f.err != nil {
		return device.Device{}, f.err
	}
	return device.Device{ID: uuid.New(), UserID: command.UserID, InstallationID: command.InstallationID}, nil
}

type fakeSessionStarter struct{}

func (*fakeSessionStarter) StartInTx(_ context.Context, _ pgx.Tx, binding session.Binding) (session.TokenSet, error) {
	return session.TokenSet{
		AccessToken: "access-token", RefreshToken: "refresh-token", OfflineEntitlement: "offline-entitlement",
		UserID: binding.UserID, PersonalSpaceID: binding.PersonalSpaceID, DeviceID: binding.DeviceID,
	}, nil
}

type failingSessionStarter struct{}

func (failingSessionStarter) StartInTx(context.Context, pgx.Tx, session.Binding) (session.TokenSet, error) {
	return session.TokenSet{}, session.ErrUnavailable
}
