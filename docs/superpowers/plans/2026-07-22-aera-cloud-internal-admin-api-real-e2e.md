# Aera Cloud Internal Admin API and Real Cross-Repository E2E Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the real Aera Cloud Internal Admin API and replace the Aera Admin Cloud Stub with a reproducible, isolated, real-Cloud cross-repository E2E.

**Architecture:** Keep one `aera-cloud` process with separate public and TLS 1.3 Internal Admin listeners. Reuse the Cloud `internal/admin` domain, add a focused `internal/adminapi` transport/authentication layer, execute each management command synchronously in one PostgreSQL transaction, and let the existing Admin Outbox provide at-least-once delivery and reconciliation.

**Tech Stack:** Go 1.26.5, chi v5, pgx v5, PostgreSQL 17, Redis 7.4, Ed25519 JWT, TLS 1.3 mutual authentication, OpenAPI 3.1, TypeScript, Playwright, POSIX shell, Docker Compose.

## Global Constraints

- Work only in `/Users/zizimutou/Desktop/aera/aera-cloud/.worktrees/internal-admin-api` and `/Users/zizimutou/Desktop/aera/aera-admin/.worktrees/real-cloud-e2e`.
- Do not use subagents; execute this plan inline with `superpowers:executing-plans` and TDD checkpoints.
- Do not modify the desktop, runtime, API recharge, or website repositories.
- Internal Admin routes must never be mounted on the public Cloud Router.
- Every Internal Admin request requires both a verified mTLS client certificate and a valid short-lived Ed25519 service JWT.
- Route scopes are exactly `users:read`, `devices:write`, `sessions:write`, `accounts:write`, and `operations:read`; unknown or duplicate scopes are rejected.
- Exact email/phone input may exist only in the POST body and current request memory; never log, audit, cache, persist, place in a URL, or return it.
- All user identities returned by Cloud must be masked as `a***@example.com` or `138****1234`.
- Account disable/enable requires `approval_id`; device and session revocation does not.
- Revoking one session revokes its complete refresh-token family while keeping the family ID out of API and audit responses.
- A successful mutation, Cloud audit event, user revision increment, and final `admin_operations` state must commit atomically.
- PostgreSQL remains authoritative for access revocation; Redis may accelerate terminal status but may not override PostgreSQL.
- Push, deployment, and production release are separate states and must be reported separately.

## File and Responsibility Map

### Aera Cloud

- `api/openapi/internal-admin.yaml`: provider copy of the shared Internal Admin contract.
- `api/internal_admin_openapi_test.go`: provider contract and public/private boundary checks.
- `internal/config/internal_admin.go`: optional-but-fail-closed Internal Admin configuration loader.
- `internal/config/config.go`: embeds `InternalAdminConfig` in the root configuration.
- `migrations/000015_internal_admin_api.sql`: `administrative_revision` and `admin_operations` schema.
- `internal/admin/control_model.go`: shared query, command, page, operation, and stable error types.
- `internal/admin/protector.go`: purpose-separated HMAC digests, request fingerprints, and signed cursors.
- `internal/admin/identity_mask.go`: deterministic email/phone masking.
- `internal/admin/control_service.go`: input validation, cursor handling, and domain orchestration.
- `internal/admin/control_repository.go`: real PostgreSQL reads and atomic command transactions.
- `internal/adminapi/auth.go`: strict Ed25519 JWT and scope verification plus defense-in-depth client-certificate check.
- `internal/adminapi/tls.go`: server certificate and client CA loading with TLS 1.3-only policy.
- `internal/adminapi/handler.go`: the eleven Internal Admin routes and bounded JSON/error responses.
- `cmd/aera-cloud/internal_admin.go`: production wiring for the internal service and listener.
- `cmd/aera-cloud/main.go`: coordinated public/internal listener lifecycle.
- `cmd/aera-cloud-e2e/main.go`: e2e-tagged seed and verify command.
- `.env.example`, `README.md`, `docs/runbooks/private-staging.md`: configuration and non-deployment truth.

### Aera Admin

- `api/openapi/cloud-admin-client.yaml`: consumer copy of the shared contract.
- `api/openapi_test.go`: consumer/provider drift guard when a Cloud path is supplied.
- `scripts/run-e2e.sh`: real Cloud build, isolated Compose, PKI, service startup, and cleanup.
- `scripts/tests/run-e2e-contract.test.sh`: safe runner structure and Stub-removal assertions.
- `e2e/global-setup.ts`: consumes the real Cloud fixture JSON.
- `e2e/global-teardown.ts`: verifies real Cloud persistence and scans both service logs.
- `e2e/support.ts`: typed real Cloud fixture loading.
- `Makefile`: removes Stub formatting/build references and runs the runner contract test.
- `README.md`: replaces the Stub limitation with the precise real-Cloud/local-only boundary.
- `e2e/cloud-stub/main.go`: deleted after the real Cloud runner passes.

---

### Task 1: Establish the Shared Provider/Consumer OpenAPI Contract

**Files:**
- Create: `aera-cloud/api/openapi/internal-admin.yaml`
- Create: `aera-cloud/api/internal_admin_openapi_test.go`
- Modify: `aera-admin/api/openapi/cloud-admin-client.yaml`
- Modify: `aera-admin/api/openapi_test.go`

**Interfaces:**
- Consumes: the existing `aera-admin/api/openapi/cloud-admin-client.yaml` schemas and paths.
- Produces: byte-identical provider and consumer OpenAPI files at version `1.0.0`, with eleven `/internal/admin/v1` routes and combined `mutualTLS` plus `serviceJWT` security.

- [ ] **Step 1: Write the failing Cloud provider contract test**

```go
func TestInternalAdminOpenAPIRequiresDualAuthenticationAndElevenRoutes(t *testing.T) {
	raw, err := os.ReadFile("openapi/internal-admin.yaml")
	if err != nil {
		t.Fatalf("read Internal Admin OpenAPI: %v", err)
	}
	document := string(raw)
	if !strings.Contains(document, "version: 1.0.0") ||
		!strings.Contains(document, "mutualTLS: { type: mutualTLS }") ||
		!strings.Contains(document, "serviceJWT: { type: http, scheme: bearer, bearerFormat: JWT }") {
		t.Fatal("Internal Admin OpenAPI does not require the approved dual authentication")
	}
	if got := strings.Count(document, "  /internal/admin/v1/"); got != 11 {
		t.Fatalf("Internal Admin route count = %d, want 11", got)
	}
	for _, forbidden := range []string{"password_hash", "refresh_token_hash", "public_key", "family_id"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("Internal Admin contract exposes %q", forbidden)
		}
	}
}
```

- [ ] **Step 2: Run the provider test and verify the missing contract failure**

Run: `go test ./api -run '^TestInternalAdminOpenAPI' -count=1 -v`
Expected: FAIL because `api/openapi/internal-admin.yaml` does not exist.

- [ ] **Step 3: Add the shared contract and consumer drift test**

Use the existing Admin consumer contract as the complete schema source, change `info.version` to `1.0.0`, and replace the old “consumer only / not implemented” description with:

```yaml
description: |
  Shared provider/consumer contract for the Aera Cloud Internal Admin API.
  Exact identity lookup accepts a full email or phone only in the request body;
  every identity field in every response remains masked.
```

Add this Admin test without making the ordinary single-repository test depend on a sibling checkout:

```go
func TestCloudAdminContractMatchesProviderWhenConfigured(t *testing.T) {
	cloudRepo := os.Getenv("AERA_ADMIN_TEST_CLOUD_REPO")
	if cloudRepo == "" {
		t.Skip("AERA_ADMIN_TEST_CLOUD_REPO is not configured")
	}
	consumer, err := os.ReadFile("openapi/cloud-admin-client.yaml")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := os.ReadFile(filepath.Join(cloudRepo, "api", "openapi", "internal-admin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(consumer, provider) {
		t.Fatal("Cloud Internal Admin provider and consumer contracts differ")
	}
}
```

- [ ] **Step 4: Run both contract tests**

Run in Cloud: `go test ./api -run '^TestInternalAdminOpenAPI' -count=1 -v`
Expected: PASS.

Run in Admin: `AERA_ADMIN_TEST_CLOUD_REPO=/Users/zizimutou/Desktop/aera/aera-cloud/.worktrees/internal-admin-api go test ./api -run '^TestCloudAdminContract' -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Commit each repository independently**

```bash
# Cloud
git add api/openapi/internal-admin.yaml api/internal_admin_openapi_test.go
git commit -m "docs: publish internal admin API contract"

# Admin
git add api/openapi/cloud-admin-client.yaml api/openapi_test.go
git commit -m "test: pin Cloud admin provider contract"
```

### Task 2: Add Optional Fail-Closed Internal Admin Configuration

**Files:**
- Create: `aera-cloud/internal/config/internal_admin.go`
- Create: `aera-cloud/internal/config/internal_admin_test.go`
- Modify: `aera-cloud/internal/config/config.go`
- Modify: `aera-cloud/.env.example`

**Interfaces:**
- Consumes: `config.LookupEnv`, `config.KeyRing`, and the existing exact-length key-ring loader.
- Produces: `config.InternalAdminConfig` and `Config.InternalAdmin`.

- [ ] **Step 1: Write failing configuration tests**

```go
func TestLoadLeavesInternalAdminDisabledWithoutSecretFiles(t *testing.T) {
	env := validEnvironment("test")
	delete(env, "AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED")
	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.InternalAdmin.Enabled {
		t.Fatal("Internal Admin unexpectedly enabled")
	}
}

func TestLoadRequiresEveryInternalAdminSettingWhenEnabled(t *testing.T) {
	env := validEnvironment("test")
	env["AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED"] = "true"
	_, err := Load(mapLookup(env))
	if err == nil || !strings.Contains(err.Error(), "INTERNAL_ADMIN_LISTEN_ADDR") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadAcceptsCompleteInternalAdminConfiguration(t *testing.T) {
	env := validEnvironment("test")
	addValidInternalAdminEnvironment(env)
	cfg, err := Load(mapLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.InternalAdmin.Enabled || cfg.InternalAdmin.ListenAddr != "127.0.0.1:18443" ||
		cfg.InternalAdmin.JWTIssuer != "aera-admin" || cfg.InternalAdmin.JWTSubject != "aera-admin-e2e" ||
		len(cfg.InternalAdmin.HMACKeys.Keys["e2e-v1"]) != 32 {
		t.Fatalf("Internal Admin config = %+v", cfg.InternalAdmin)
	}
}
```

`addValidInternalAdminEnvironment` must set all ten variables from the design and an exact 32-byte base64 HMAC key.

- [ ] **Step 2: Run the tests and confirm the missing type/field failure**

Run: `go test ./internal/config -run '^TestLoad.*InternalAdmin' -count=1 -v`
Expected: FAIL because `Config.InternalAdmin` and its loader do not exist.

- [ ] **Step 3: Implement the configuration type and loader**

```go
type InternalAdminConfig struct {
	Enabled          bool
	ListenAddr       string
	ServerCertFile   string
	ServerKeyFile    string
	ClientCAFile     string
	JWTPublicKeyFile string
	JWTIssuer        string
	JWTSubject       string
	HMACKeys         KeyRing
}

func loadInternalAdmin(lookup LookupEnv, publicListenAddr string) (InternalAdminConfig, error) {
	raw, ok := lookup("AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED")
	if !ok || strings.TrimSpace(raw) == "" || strings.EqualFold(strings.TrimSpace(raw), "false") {
		return InternalAdminConfig{}, nil
	}
	if !strings.EqualFold(strings.TrimSpace(raw), "true") {
		return InternalAdminConfig{}, errors.New("AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED must be true or false")
	}
	listenAddr, err := required(lookup, "AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR")
	if err != nil {
		return InternalAdminConfig{}, err
	}
	if listenAddr == publicListenAddr {
		return InternalAdminConfig{}, errors.New("Internal Admin and public listeners must differ")
	}
	serverCertFile, err := required(lookup, "AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_CERT_FILE")
	if err != nil { return InternalAdminConfig{}, err }
	serverKeyFile, err := required(lookup, "AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_KEY_FILE")
	if err != nil { return InternalAdminConfig{}, err }
	clientCAFile, err := required(lookup, "AGENTERA_CLOUD_INTERNAL_ADMIN_CLIENT_CA_FILE")
	if err != nil { return InternalAdminConfig{}, err }
	jwtPublicKeyFile, err := required(lookup, "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_PUBLIC_KEY_FILE")
	if err != nil { return InternalAdminConfig{}, err }
	issuer, err := required(lookup, "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_ISSUER")
	if err != nil { return InternalAdminConfig{}, err }
	subject, err := required(lookup, "AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_SUBJECT")
	if err != nil { return InternalAdminConfig{}, err }
	identityPattern := regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)
	if !identityPattern.MatchString(issuer) || !identityPattern.MatchString(subject) {
		return InternalAdminConfig{}, errors.New("Internal Admin service identity is invalid")
	}
	hmacKeys, err := loadKeyRing(
		lookup,
		"AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_ACTIVE_KEY_ID",
		"AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_KEYS",
		32,
		true,
	)
	if err != nil { return InternalAdminConfig{}, err }
	return InternalAdminConfig{
		Enabled: true, ListenAddr: listenAddr,
		ServerCertFile: serverCertFile, ServerKeyFile: serverKeyFile,
		ClientCAFile: clientCAFile, JWTPublicKeyFile: jwtPublicKeyFile,
		JWTIssuer: issuer, JWTSubject: subject, HMACKeys: hmacKeys,
	}, nil
}
```

Add `InternalAdmin InternalAdminConfig` to `Config`, call `loadInternalAdmin` after the public listener is loaded, and return it from `Load`.

In `.env.example`, add only the safe default:

```dotenv
# Internal Admin is disabled until every TLS, service identity, and HMAC setting is injected.
AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED=false
```

- [ ] **Step 4: Run config tests and the full config package**

Run: `go test ./internal/config -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/internal_admin.go internal/config/internal_admin_test.go .env.example
git commit -m "feat: configure internal admin listener"
```

### Task 3: Add Administrative Revision and Durable Operations Migration

**Files:**
- Create: `aera-cloud/migrations/000015_internal_admin_api.sql`
- Modify: `aera-cloud/internal/store/migrate_test.go`

**Interfaces:**
- Produces: `users.administrative_revision` and `admin_operations` with the exact fields required by `internal/admin.ControlRepository`.

- [ ] **Step 1: Extend the migration integration test first**

Add assertions after `ApplyMigrations`:

```go
assertColumns(t, ctx, postgres, "users", []string{"administrative_revision"})
assertColumns(t, ctx, postgres, "admin_operations", []string{
	"operation_id", "idempotency_key_id", "idempotency_key_hmac", "request_fingerprint",
	"service_subject", "actor_admin_id", "approval_id", "request_id", "action", "target_type",
	"target_id", "expected_revision", "result_revision", "status", "error_code", "reason_code",
	"ticket_reference", "created_at", "updated_at", "completed_at",
})
for _, status := range []string{"executing", "succeeded", "failed", "conflict"} {
	assertCheckConstraintContains(t, ctx, postgres, "admin_operations", "admin_operations_status_check", status)
}
```

Also query `information_schema.columns` and assert there is no `note`, raw idempotency key, email, phone, token, or certificate column.

- [ ] **Step 2: Run the migration test and verify it fails**

Run:

```bash
docker compose up -d --wait postgres redis
set -a; . ./.env.example; set +a
AERA_INTEGRATION_TESTS=1 go test ./internal/store -run '^TestApplyMigrations' -count=1 -v
```

Expected: FAIL because migration 15 and its columns do not exist.

- [ ] **Step 3: Add the forward-only SQL migration**

```sql
ALTER TABLE users
    ADD COLUMN administrative_revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT users_administrative_revision_check CHECK (administrative_revision > 0);

CREATE TABLE admin_operations (
    operation_id UUID PRIMARY KEY,
    idempotency_key_id TEXT NOT NULL,
    idempotency_key_hmac BYTEA NOT NULL,
    request_fingerprint BYTEA NOT NULL,
    service_subject TEXT NOT NULL,
    actor_admin_id UUID NOT NULL,
    approval_id UUID,
    request_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id UUID NOT NULL,
    expected_revision BIGINT NOT NULL,
    result_revision BIGINT,
    status TEXT NOT NULL,
    error_code TEXT,
    reason_code TEXT NOT NULL,
    ticket_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CONSTRAINT admin_operations_idempotency_hmac_length_check CHECK (octet_length(idempotency_key_hmac) = 32),
    CONSTRAINT admin_operations_request_fingerprint_length_check CHECK (octet_length(request_fingerprint) = 32),
    CONSTRAINT admin_operations_action_check CHECK (action IN ('revoke_device', 'revoke_session', 'disable_user', 'enable_user')),
    CONSTRAINT admin_operations_target_type_check CHECK (target_type IN ('device', 'session', 'user')),
    CONSTRAINT admin_operations_expected_revision_check CHECK (expected_revision > 0),
    CONSTRAINT admin_operations_result_revision_check CHECK (result_revision IS NULL OR result_revision > 0),
    CONSTRAINT admin_operations_status_check CHECK (status IN ('executing', 'succeeded', 'failed', 'conflict')),
    CONSTRAINT admin_operations_key_id_length_check CHECK (char_length(idempotency_key_id) BETWEEN 1 AND 64),
    CONSTRAINT admin_operations_service_subject_check CHECK (service_subject ~ '^[a-z][a-z0-9._-]{2,63}$'),
    CONSTRAINT admin_operations_request_id_length_check CHECK (char_length(request_id) BETWEEN 1 AND 128),
    CONSTRAINT admin_operations_reason_code_check CHECK (reason_code ~ '^[a-z][a-z0-9_]{2,63}$'),
    CONSTRAINT admin_operations_ticket_reference_check CHECK (ticket_reference IS NULL OR char_length(ticket_reference) BETWEEN 1 AND 128),
    CONSTRAINT admin_operations_error_code_check CHECK (error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{2,99}$'),
    CONSTRAINT admin_operations_action_target_check CHECK (
        (action = 'revoke_device' AND target_type = 'device') OR
        (action = 'revoke_session' AND target_type = 'session') OR
        (action IN ('disable_user', 'enable_user') AND target_type = 'user')
    ),
    CONSTRAINT admin_operations_approval_check CHECK (
        (action IN ('disable_user', 'enable_user') AND approval_id IS NOT NULL) OR
        (action IN ('revoke_device', 'revoke_session'))
    ),
    CONSTRAINT admin_operations_terminal_state_check CHECK (
        (status = 'executing' AND completed_at IS NULL AND result_revision IS NULL AND error_code IS NULL) OR
        (status = 'succeeded' AND completed_at IS NOT NULL AND result_revision IS NOT NULL AND error_code IS NULL) OR
        (status IN ('failed', 'conflict') AND completed_at IS NOT NULL AND error_code IS NOT NULL)
    ),
    CONSTRAINT admin_operations_idempotency_key_unique UNIQUE (idempotency_key_id, idempotency_key_hmac)
);

CREATE INDEX admin_operations_target_time_idx ON admin_operations(target_type, target_id, created_at DESC);
CREATE INDEX admin_operations_updated_idx ON admin_operations(updated_at DESC);
```

- [ ] **Step 4: Run migration and checksum tests**

Run: `set -a; . ./.env.example; set +a; AERA_INTEGRATION_TESTS=1 go test ./internal/store -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add migrations/000015_internal_admin_api.sql internal/store/migrate_test.go
git commit -m "feat: persist Cloud admin operations"
```

### Task 4: Implement Masking, HMAC Protection, Cursors, and Domain Types

**Files:**
- Create: `aera-cloud/internal/admin/control_model.go`
- Create: `aera-cloud/internal/admin/control_model_test.go`
- Create: `aera-cloud/internal/admin/identity_mask.go`
- Create: `aera-cloud/internal/admin/identity_mask_test.go`
- Create: `aera-cloud/internal/admin/protector.go`
- Create: `aera-cloud/internal/admin/protector_test.go`

**Interfaces:**
- Produces: `User`, `Device`, `Session`, `Page[T]`, `Command`, `Operation`, `Action`, `OperationStatus`, `PagePosition`, `Protector`, `MaskIdentity`, and stable domain errors.

- [ ] **Step 1: Write pure unit tests**

```go
func TestMaskIdentityUsesApprovedFormats(t *testing.T) {
	tests := []struct{ kind secure.IdentityKind; value, want string }{
		{secure.IdentityEmail, "alice@example.com", "a***@example.com"},
		{secure.IdentityEmail, "x@example.test", "x***@example.test"},
		{secure.IdentityPhone, "+8613800138000", "138****8000"},
	}
	for _, test := range tests {
		got, err := MaskIdentity(test.kind, test.value)
		if err != nil || got != test.want {
			t.Fatalf("MaskIdentity() = %q, %v; want %q", got, err, test.want)
		}
	}
}

func TestProtectorSeparatesDomainsAndRejectsCursorCrossUse(t *testing.T) {
	protector, err := NewProtector("v1", map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)})
	if err != nil { t.Fatal(err) }
	id := uuid.MustParse("019f0000-0000-7000-8000-000000000071")
	digests := protector.IdempotencyCandidates(id)
	fingerprint := protector.RequestFingerprint("v1", RevokeSession, id, validCommand(id))
	if bytes.Equal(digests[0].Sum, fingerprint) { t.Fatal("HMAC domains overlap") }
	cursor, err := protector.EncodeCursor("users", PagePosition{Time: time.Unix(10, 0).UTC(), ID: id})
	if err != nil { t.Fatal(err) }
	if _, err := protector.DecodeCursor("sessions", cursor); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-resource cursor error = %v", err)
	}
}

func validCommand(operationID uuid.UUID) Command {
	return Command{
		OperationID: operationID,
		ActorAdminID: uuid.MustParse("019f0000-0000-7000-8000-000000000081"),
		RequestID: "req-protector-1",
		ReasonCode: "session_cleanup",
		ExpectedRevision: 1,
	}
}
```

Add the exact command validation table:

```go
func TestValidateControlCommand(t *testing.T) {
	targetID, operationID, actorID, approvalID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	valid := Command{
		OperationID: operationID, ActorAdminID: actorID, RequestID: "req-control-1",
		ReasonCode: "session_cleanup", TicketReference: "OPS-123", Note: "manual support action",
		ExpectedRevision: 1,
	}
	tests := []struct {
		name string
		action Action
		command Command
		wantErr bool
	}{
		{name: "session revoke", action: RevokeSession, command: valid},
		{name: "device revoke", action: RevokeDevice, command: valid},
		{name: "disable needs approval", action: DisableUser, command: valid, wantErr: true},
		{name: "enable needs approval", action: EnableUser, command: valid, wantErr: true},
		{name: "disable approved", action: DisableUser, command: func() Command { c := valid; c.ApprovalID = &approvalID; return c }()},
		{name: "bad reason", action: RevokeSession, command: func() Command { c := valid; c.ReasonCode = "Bad Reason"; return c }(), wantErr: true},
		{name: "zero revision", action: RevokeSession, command: func() Command { c := valid; c.ExpectedRevision = 0; return c }(), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateControlCommand(test.action, targetID, test.command)
			if (err != nil) != test.wantErr { t.Fatalf("error = %v", err) }
		})
	}
}
```

Add the operation invariant test:

```go
func TestOperationValidation(t *testing.T) {
	now, id := time.Now().UTC(), uuid.New()
	tests := []struct { name string; value Operation; wantErr bool }{
		{name: "executing", value: Operation{ID: id, Status: OperationExecuting, UpdatedAt: now}},
		{name: "succeeded", value: Operation{ID: id, Status: OperationSucceeded, AdministrativeRevision: 2, UpdatedAt: now}},
		{name: "failed", value: Operation{ID: id, Status: OperationFailed, ErrorCode: "USER_NOT_FOUND", UpdatedAt: now}},
		{name: "conflict", value: Operation{ID: id, Status: OperationConflict, ErrorCode: "USER_STATE_CONFLICT", UpdatedAt: now}},
		{name: "success without revision", value: Operation{ID: id, Status: OperationSucceeded, UpdatedAt: now}, wantErr: true},
		{name: "failure without code", value: Operation{ID: id, Status: OperationFailed, UpdatedAt: now}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateOperation(test.value)
			if (err != nil) != test.wantErr { t.Fatalf("error = %v", err) }
		})
	}
}
```

The `Page[T]` constructors used by `ControlService` must allocate `Items: make([]T, 0)` when the repository returns no rows.

- [ ] **Step 2: Run the new tests and confirm undefined-symbol failures**

Run: `go test ./internal/admin -run '^(TestMaskIdentity|TestProtector|TestValidateControl)' -count=1 -v`
Expected: FAIL because the new domain types and functions do not exist.

- [ ] **Step 3: Implement the types and protectors**

Define the contract types exactly once in `control_model.go`:

```go
type Action string
const (
	RevokeDevice  Action = "revoke_device"
	RevokeSession Action = "revoke_session"
	DisableUser   Action = "disable_user"
	EnableUser    Action = "enable_user"
)

type OperationStatus string
const (
	OperationExecuting OperationStatus = "executing"
	OperationSucceeded OperationStatus = "succeeded"
	OperationFailed    OperationStatus = "failed"
	OperationConflict  OperationStatus = "conflict"
)

type UserStatus string
const (
	UserActive UserStatus = "active"
	UserPendingDeletion UserStatus = "pending_deletion"
	UserDisabled UserStatus = "disabled"
)

type PageRequest struct { Cursor string; Limit int }
type ListUsersRequest struct { PageRequest; Status UserStatus }
type LookupRequest struct { Kind secure.IdentityKind `json:"type"`; Value string `json:"value"` }
type Page[T any] struct { Items []T `json:"items"`; NextCursor string `json:"next_cursor,omitempty"` }

type User struct {
	ID uuid.UUID `json:"user_id"`
	MaskedEmail string `json:"masked_email,omitempty"`
	MaskedPhone string `json:"masked_phone,omitempty"`
	Status UserStatus `json:"status"`
	AdministrativelyDisabled bool `json:"administratively_disabled"`
	DeletionFinalizedAt *time.Time `json:"deletion_finalized_at,omitempty"`
	AdministrativeRevision int64 `json:"administrative_revision"`
	DeviceCount int `json:"device_count"`
	ActiveDeviceCount int `json:"active_device_count"`
	ActiveSessionCount int `json:"active_session_count"`
	CreatedAt time.Time `json:"created_at"`
	LastCloudActivityAt *time.Time `json:"last_cloud_activity_at,omitempty"`
}

type DeviceStatus string
const (
	DeviceActive DeviceStatus = "active"
	DeviceInactive DeviceStatus = "inactive"
	DeviceRevoked DeviceStatus = "revoked"
)
type Device struct {
	ID uuid.UUID `json:"device_id"`
	UserID uuid.UUID `json:"user_id"`
	DisplayName string `json:"display_name"`
	Platform string `json:"platform"`
	ClientVersion string `json:"client_version"`
	Status DeviceStatus `json:"status"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

type SessionStatus string
const (
	SessionActive SessionStatus = "active"
	SessionRotated SessionStatus = "rotated"
	SessionExpired SessionStatus = "expired"
	SessionRevoked SessionStatus = "revoked"
	SessionReplayDetected SessionStatus = "replay_detected"
)
type Session struct {
	ID uuid.UUID `json:"session_id"`
	UserID uuid.UUID `json:"user_id"`
	DeviceID uuid.UUID `json:"device_id"`
	Status SessionStatus `json:"status"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type Command struct {
	OperationID uuid.UUID `json:"operation_id"`
	ActorAdminID uuid.UUID `json:"actor_admin_id"`
	ApprovalID *uuid.UUID `json:"approval_id,omitempty"`
	RequestID string `json:"request_id"`
	ReasonCode string `json:"reason_code"`
	TicketReference string `json:"ticket_reference,omitempty"`
	Note string `json:"note,omitempty"`
	ExpectedRevision int64 `json:"expected_revision"`
}

type Operation struct {
	ID uuid.UUID `json:"operation_id"`
	Status OperationStatus `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
	AdministrativeRevision int64 `json:"administrative_revision,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PagePosition struct { Time time.Time; ID uuid.UUID }
type Digest struct { KeyID string; Sum []byte }
```

Add `ErrInvalidCursor`, `ErrStateConflict`, and `ErrIdempotencyKeyReused` alongside the existing `ErrInvalidCommand`, `ErrNotFound`, and `ErrUnavailable`. Use these exact public signatures:

```go
func MaskIdentity(kind secure.IdentityKind, normalized string) (string, error)

type Protector struct { /* copied keys, deterministic active-first order */ }
func NewProtector(activeKeyID string, keys map[string][]byte) (*Protector, error)
func (p *Protector) IdempotencyCandidates(operationID uuid.UUID) []Digest
func (p *Protector) RequestFingerprint(keyID string, action Action, targetID uuid.UUID, command Command) []byte
func (p *Protector) EncodeCursor(resource string, position PagePosition) (string, error)
func (p *Protector) DecodeCursor(resource, cursor string) (*PagePosition, error)

type Service interface {
	ListUsers(context.Context, ListUsersRequest) (Page[User], error)
	LookupUser(context.Context, LookupRequest) (User, error)
	GetUser(context.Context, uuid.UUID) (User, error)
	ListUserDevices(context.Context, uuid.UUID, PageRequest) (Page[Device], error)
	ListUserSessions(context.Context, uuid.UUID, PageRequest) (Page[Session], error)
	Execute(context.Context, Action, uuid.UUID, Command) (Operation, error)
	GetOperation(context.Context, uuid.UUID) (Operation, error)
}
```

Serialize fingerprints as length-prefixed canonical fields rather than JSON maps. Use HMAC-SHA256 messages prefixed with `aera-cloud.admin.idempotency.v1`, `aera-cloud.admin.request.v1`, and `aera-cloud.admin.cursor.v1` respectively. Cursor output must match `^[A-Za-z0-9_-]{1,512}$`.

- [ ] **Step 4: Run pure tests**

Run: `go test ./internal/admin -count=1`
Expected: PASS, including the existing restricted CLI tests.

- [ ] **Step 5: Commit**

```bash
git add internal/admin/control_model.go internal/admin/control_model_test.go internal/admin/identity_mask.go internal/admin/identity_mask_test.go internal/admin/protector.go internal/admin/protector_test.go
git commit -m "feat: define Cloud admin control contracts"
```

### Task 5: Implement Real Masked User, Device, and Session Queries

**Files:**
- Create: `aera-cloud/internal/admin/control_service.go`
- Create: `aera-cloud/internal/admin/control_service_test.go`
- Create: `aera-cloud/internal/admin/control_repository.go`
- Create: `aera-cloud/internal/admin/control_repository_test.go`

**Interfaces:**
- Consumes: `secure.IdentityCodec`, `Protector`, and Task 4 models.
- Produces: `ControlService`, `ControlRepository`, `NewControlService`, and `NewControlRepository` with all read methods implemented.

- [ ] **Step 1: Write service and PostgreSQL query tests first**

Service test:

```go
func TestControlServiceNormalizesLookupAndNeverReturnsRawIdentity(t *testing.T) {
	repository := &controlRepositoryStub{lookupUser: User{
		ID: uuid.New(), MaskedEmail: "a***@example.com", Status: UserActive,
		AdministrativeRevision: 1, CreatedAt: time.Now().UTC(),
	}}
	service, err := NewControlService(ControlServiceConfig{Queries: repository, Protector: testProtector(t), Clock: time.Now})
	if err != nil { t.Fatal(err) }
	user, err := service.LookupUser(context.Background(), LookupRequest{Kind: secure.IdentityEmail, Value: " Alice@Example.COM "})
	if err != nil { t.Fatal(err) }
	if repository.normalizedLookup != "alice@example.com" || user.MaskedEmail != "a***@example.com" {
		t.Fatalf("lookup = %q / %+v", repository.normalizedLookup, user)
	}
}

type controlRepositoryStub struct {
	normalizedLookup string
	lookupUser User
}

func (s *controlRepositoryStub) LookupUser(_ context.Context, _ secure.IdentityKind, normalized string) (User, error) {
	s.normalizedLookup = normalized
	return s.lookupUser, nil
}
func (s *controlRepositoryStub) ListUsers(context.Context, UserQuery) (DataPage[User], error) {
	return DataPage[User]{Items: make([]User, 0)}, nil
}
func (s *controlRepositoryStub) GetUser(context.Context, uuid.UUID) (User, error) { return s.lookupUser, nil }
func (s *controlRepositoryStub) ListUserDevices(context.Context, DeviceQuery) (DataPage[Device], error) {
	return DataPage[Device]{Items: make([]Device, 0)}, nil
}
func (s *controlRepositoryStub) ListUserSessions(context.Context, SessionQuery) (DataPage[Session], error) {
	return DataPage[Session]{Items: make([]Session, 0)}, nil
}

func testProtector(t *testing.T) *Protector {
	t.Helper()
	protector, err := NewProtector("test-v1", map[string][]byte{"test-v1": bytes.Repeat([]byte{9}, 32)})
	if err != nil { t.Fatal(err) }
	return protector
}
```

Integration test fixture must insert two users, email and phone identities through `IdentityCodec.Seal`, active/inactive/revoked devices, active/rotated/revoked/expired sessions, and then assert:

```go
page, err := service.ListUsers(ctx, ListUsersRequest{PageRequest: PageRequest{Limit: 1}})
if err != nil || len(page.Items) != 1 || page.NextCursor == "" { t.Fatalf("first page = %+v, %v", page, err) }
second, err := service.ListUsers(ctx, ListUsersRequest{PageRequest: PageRequest{Limit: 1, Cursor: page.NextCursor}})
if err != nil || len(second.Items) != 1 || second.Items[0].ID == page.Items[0].ID { t.Fatalf("second page = %+v, %v", second, err) }
if strings.Contains(fmt.Sprintf("%+v", page), "alice@example.com") { t.Fatal("page contains raw identity") }
```

Also assert device responses omit installation/public key and session responses derive replay, revoked, rotated, expired, and active in that priority.

- [ ] **Step 2: Run tests and verify missing service/repository failures**

Run:

```bash
go test ./internal/admin -run '^TestControlService' -count=1 -v
set -a; . ./.env.example; set +a
AERA_INTEGRATION_TESTS=1 go test ./internal/admin -run '^TestControlRepository.*Query' -count=1 -v
```

Expected: FAIL because `ControlService` and `ControlRepository` are not implemented.

- [ ] **Step 3: Implement read orchestration and keyset SQL**

Use these exact constructors:

```go
type ControlServiceConfig struct {
	Queries    QueryData
	Commands   CommandData
	Protector  *Protector
	Clock      func() time.Time
}

func NewControlService(config ControlServiceConfig) (*ControlService, error)
func NewControlRepository(postgres *pgxpool.Pool, identities *secure.IdentityCodec, protector *Protector, clock func() time.Time) (*ControlRepository, error)
```

Use these exact storage interfaces:

```go
type QueryData interface {
	ListUsers(context.Context, UserQuery) (DataPage[User], error)
	LookupUser(context.Context, secure.IdentityKind, string) (User, error)
	GetUser(context.Context, uuid.UUID) (User, error)
	ListUserDevices(context.Context, DeviceQuery) (DataPage[Device], error)
	ListUserSessions(context.Context, SessionQuery) (DataPage[Session], error)
}

type CommandData interface {
	Execute(context.Context, Action, uuid.UUID, Command) (Operation, error)
	GetOperation(context.Context, uuid.UUID) (Operation, error)
}

type DataPage[T any] struct {
	Items []T
	Next  *PagePosition
}

type UserQuery struct { Status UserStatus; Limit int; After *PagePosition }
type DeviceQuery struct { UserID uuid.UUID; Limit int; After *PagePosition }
type SessionQuery struct { UserID uuid.UUID; Limit int; After *PagePosition; Now time.Time }
```

`NewControlService` requires `Queries`, `Protector`, and `Clock`; `Commands` may be nil until Task 6 and causes only command methods to return `ErrUnavailable`. `ControlRepository` may decrypt an identity only long enough to call `MaskIdentity` before constructing `User`; raw plaintext never leaves the repository method.

Use `(created_at, id)` descending keyset pagination for users, `(last_seen_at, id)` descending for devices, and `(issued_at, id)` descending for sessions. Fetch `limit + 1`, return a non-nil `items` slice, and sign the final retained position only when another row exists.

- [ ] **Step 4: Run unit and integration query tests**

Run:

```bash
go test ./internal/admin -count=1
set -a; . ./.env.example; set +a
AERA_INTEGRATION_TESTS=1 go test ./internal/admin -run '^TestControlRepository.*Query' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/admin/control_service.go internal/admin/control_service_test.go internal/admin/control_repository.go internal/admin/control_repository_test.go
git commit -m "feat: query masked Cloud account state"
```

### Task 6: Implement Atomic Idempotent Cloud Management Commands

**Files:**
- Modify: `aera-cloud/internal/admin/control_service.go`
- Modify: `aera-cloud/internal/admin/control_service_test.go`
- Modify: `aera-cloud/internal/admin/control_repository.go`
- Modify: `aera-cloud/internal/admin/control_repository_test.go`
- Modify: `aera-cloud/internal/admin/repository.go`
- Modify: `aera-cloud/internal/admin/commands_test.go`

**Interfaces:**
- Consumes: Task 3 schema and Task 4 fingerprints.
- Produces: `ControlService.Execute`, `ControlService.GetOperation`, and atomic implementations for all four actions.

- [ ] **Step 1: Write failing command integration tests**

Create table-driven fixtures for `RevokeDevice`, `RevokeSession`, `DisableUser`, and `EnableUser`. The session test must create two rows in one family and assert both revoke. The account enable test must assert old device/session/offline entitlement rows remain revoked.

Add exact replay and semantic conflict:

```go
first, err := service.Execute(ctx, RevokeSession, sessionID, command)
if err != nil || first.Status != OperationSucceeded || first.AdministrativeRevision != 2 { t.Fatalf("first = %+v, %v", first, err) }
replay, err := service.Execute(ctx, RevokeSession, sessionID, command)
if err != nil || replay != first { t.Fatalf("replay = %+v, %v", replay, err) }
changed := command
changed.Note = "different safe note"
if _, err := service.Execute(ctx, RevokeSession, sessionID, changed); !errors.Is(err, ErrIdempotencyKeyReused) {
	t.Fatalf("semantic replay error = %v", err)
}
```

Add two goroutines with different operation IDs and the same expected revision; assert exactly one succeeds and the other returns `ErrStateConflict`. Query `admin_operations` and `audit_events` to prove each terminal operation is durable and the successful mutation has one matching Cloud audit.

- [ ] **Step 2: Run command tests and verify failures**

Run: `set -a; . ./.env.example; set +a; AERA_INTEGRATION_TESTS=1 go test ./internal/admin -run '^TestControlRepository.*Command' -count=1 -v`
Expected: FAIL because command repository methods are missing.

- [ ] **Step 3: Implement the transaction algorithm**

For every action:

```go
func (r *ControlRepository) Execute(ctx context.Context, action Action, targetID uuid.UUID, command Command) (Operation, error) {
	if r == nil || validateControlCommand(action, targetID, command) != nil {
		return Operation{}, ErrInvalidCommand
	}
	digests := r.protector.IdempotencyCandidates(command.OperationID)
	tx, err := r.postgres.BeginTx(ctx, pgx.TxOptions{})
	if err != nil { return Operation{}, ErrUnavailable }
	defer func() { _ = tx.Rollback(context.Background()) }()

	existing, found, err := r.findOperation(ctx, tx, command.OperationID, digests)
	if err != nil { return Operation{}, err }
	if found {
		fingerprint := r.protector.RequestFingerprint(existing.KeyID, action, targetID, command)
		if subtle.ConstantTimeCompare(existing.Fingerprint, fingerprint) != 1 {
			return Operation{}, ErrIdempotencyKeyReused
		}
		return operationReplayResult(existing.Operation)
	}

	active := digests[0]
	fingerprint := r.protector.RequestFingerprint(active.KeyID, action, targetID, command)
	inserted, err := r.insertExecuting(ctx, tx, action, targetID, command, active, fingerprint)
	if err != nil { return Operation{}, err }
	if !inserted {
		existing, found, err = r.findOperation(ctx, tx, command.OperationID, digests)
		if err != nil || !found { return Operation{}, ErrUnavailable }
		if subtle.ConstantTimeCompare(existing.Fingerprint, fingerprint) != 1 {
			return Operation{}, ErrIdempotencyKeyReused
		}
		return operationReplayResult(existing.Operation)
	}

	mutation, domainErr := r.applyAction(ctx, tx, action, targetID, command)
	if domainErr != nil {
		if !durableDomainFailure(domainErr) { return Operation{}, ErrUnavailable }
		operation, finishErr := r.finishRejected(ctx, tx, action, targetID, command, mutation, domainErr)
		if finishErr != nil { return Operation{}, finishErr }
		if err := tx.Commit(ctx); err != nil { return Operation{}, ErrUnavailable }
		return operation, domainErr
	}
	operation, err := r.finishSucceeded(ctx, tx, action, targetID, command, mutation)
	if err != nil { return Operation{}, err }
	if err := tx.Commit(ctx); err != nil { return Operation{}, ErrUnavailable }
	return operation, nil
}
```

Define the helpers with these signatures:

```go
type storedOperation struct { KeyID string; Fingerprint []byte; Operation Operation }
type mutationResult struct { UserID uuid.UUID; BeforeRevision, AfterRevision int64; ErrorCode string }

func (r *ControlRepository) findOperation(context.Context, pgx.Tx, uuid.UUID, []Digest) (storedOperation, bool, error)
func (r *ControlRepository) insertExecuting(context.Context, pgx.Tx, Action, uuid.UUID, Command, Digest, []byte) (bool, error)
func (r *ControlRepository) applyAction(context.Context, pgx.Tx, Action, uuid.UUID, Command) (mutationResult, error)
func (r *ControlRepository) finishRejected(context.Context, pgx.Tx, Action, uuid.UUID, Command, mutationResult, error) (Operation, error)
func (r *ControlRepository) finishSucceeded(context.Context, pgx.Tx, Action, uuid.UUID, Command, mutationResult) (Operation, error)
func operationReplayResult(Operation) (Operation, error)
func durableDomainFailure(error) bool
```

`insertExecuting` uses `INSERT ... ON CONFLICT DO NOTHING` so either the operation primary key or HMAC uniqueness race does not abort the transaction. `applyAction` owns target resolution, `lockTargetUser`, `SELECT users ... FOR UPDATE`, revision comparison, mutation SQL, and one revision increment. `durableDomainFailure` returns true only for not-found, already-revoked, disallowed-state, and revision-conflict errors; dependency or SQL failures roll back without a terminal operation. `finishRejected` maps not-found to failed and state conflicts to conflict, writes a denied Cloud audit, and stores the terminal operation. `finishSucceeded` writes a success audit and terminal operation. Use `json.Marshal` only for metadata containing operation/admin/approval UUIDs, expected/result revision, and ticket reference; never include note or identity.

Refactor the legacy restricted CLI SQL helpers to use the same lifecycle mutation functions so CLI actions also increment `administrative_revision`; preserve its public command signatures and existing audit behavior.

- [ ] **Step 4: Run integration, concurrency, and legacy CLI tests**

Run:

```bash
set -a; . ./.env.example; set +a
AERA_INTEGRATION_TESTS=1 go test ./internal/admin -count=1
AERA_INTEGRATION_TESTS=1 go test -race ./internal/admin -run '^(TestControlRepository.*Command|TestPostgresRepository)' -count=1
```

Expected: PASS with one success in the same-revision race and no restored credentials after enable.

- [ ] **Step 5: Commit**

```bash
git add internal/admin/control_service.go internal/admin/control_service_test.go internal/admin/control_repository.go internal/admin/control_repository_test.go internal/admin/repository.go internal/admin/commands_test.go
git commit -m "feat: execute idempotent Cloud admin controls"
```

### Task 7: Implement Strict mTLS and Service JWT Authentication

**Files:**
- Create: `aera-cloud/internal/adminapi/auth.go`
- Create: `aera-cloud/internal/adminapi/auth_test.go`
- Create: `aera-cloud/internal/adminapi/tls.go`
- Create: `aera-cloud/internal/adminapi/tls_test.go`

**Interfaces:**
- Produces: `Authenticator`, `NewAuthenticator`, `Authenticator.RequireScope`, `LoadEd25519PublicKey`, `LoadTLSConfig`, and the fixed scope constants.

- [ ] **Step 1: Write JWT and TLS failure-matrix tests**

JWT table must include valid, missing bearer, malformed segments, wrong alg, wrong signature, unknown claim, wrong issuer, wrong subject, wrong audience, future iat, future nbf, expired, lifetime over five minutes, missing/duplicate/unknown scope, empty jti, and oversized token.

```go
func TestRequireScopeAlsoRequiresVerifiedClientCertificate(t *testing.T) {
	auth := testAuthenticator(t)
	handler := auth.RequireScope(ScopeUsersRead)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodGet, "https://cloud.test/internal/admin/v1/health", nil)
	request.Header.Set("Authorization", "Bearer "+testServiceToken(t, validClaims()))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized { t.Fatalf("status = %d", response.Code) }
}
```

TLS integration test must build a one-day test CA/server/client identity and verify no client certificate fails the handshake while the trusted client succeeds with TLS 1.3. Public-key tests must accept one PKIX Ed25519 `PUBLIC KEY` PEM and reject private keys, RSA keys, multiple PEM blocks, trailing content, and malformed input without returning file contents in the error.

- [ ] **Step 2: Run tests and confirm missing package failures**

Run: `go test ./internal/adminapi -run '^(TestRequireScope|TestLoadTLS)' -count=1 -v`
Expected: FAIL because `internal/adminapi` does not exist.

- [ ] **Step 3: Implement strict auth and TLS loaders**

```go
type AuthenticatorConfig struct {
	PublicKey ed25519.PublicKey
	Issuer    string
	Subject   string
	Clock     func() time.Time
}

func NewAuthenticator(config AuthenticatorConfig) (*Authenticator, error)
func (a *Authenticator) RequireScope(scope string) func(http.Handler) http.Handler
func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error)
func LoadTLSConfig(serverCertFile, serverKeyFile, clientCAFile string) (*tls.Config, error)
```

Define the scope constants exactly:

```go
const (
	ScopeUsersRead      = "users:read"
	ScopeDevicesWrite   = "devices:write"
	ScopeSessionsWrite  = "sessions:write"
	ScopeAccountsWrite  = "accounts:write"
	ScopeOperationsRead = "operations:read"
)
```

Use `json.Decoder.DisallowUnknownFields` for JWT header and claims, Ed25519 verification through `ed25519.Verify`, exact `aud=aera-cloud-admin`, maximum 5-minute lifetime, 30-second maximum clock skew, and the fixed five-scope allowlist. `LoadEd25519PublicKey` reads one PEM block, requires `block.Type == "PUBLIC KEY"`, parses PKIX, requires `ed25519.PublicKeySize`, and rejects non-whitespace trailing bytes. `LoadTLSConfig` must return `MinVersion: TLS1.3`, `MaxVersion: TLS1.3`, `ClientAuth: tls.RequireAndVerifyClientCert`, and a pool containing only the configured client CA.

- [ ] **Step 4: Run the package and race tests**

Run:

```bash
go test ./internal/adminapi -count=1
go test -race ./internal/adminapi -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/adminapi/auth.go internal/adminapi/auth_test.go internal/adminapi/tls.go internal/adminapi/tls_test.go
git commit -m "feat: authenticate internal Cloud admin calls"
```

### Task 8: Implement the Eleven Internal Admin HTTP Routes

**Files:**
- Create: `aera-cloud/internal/adminapi/handler.go`
- Create: `aera-cloud/internal/adminapi/handler_test.go`

**Interfaces:**
- Consumes: `admin.Service`, `Authenticator`, PostgreSQL/Redis `Ping`, and the shared OpenAPI contract.
- Produces: `adminapi.NewHandler(HandlerConfig) (http.Handler, error)`.

- [ ] **Step 1: Write route, scope, JSON, and privacy tests**

Use a fake `admin.Service` and a real test authenticator. Cover every route and assert the method/path calls the correct service method and returns exact contract JSON. Add direct tests for unknown JSON field, trailing JSON, body over 32 KiB, invalid UUID, limit 0/101, unsafe note, missing approval on account action, and exact lookup canary absence from response and captured logs.

```go
func TestHandlerAddsNoStoreAndRejectsUnknownLookupFields(t *testing.T) {
	handler := newAuthenticatedTestHandler(t)
	request := authenticatedRequest(t, http.MethodPost, "/internal/admin/v1/users/lookup", `{"type":"email","value":"cloud.lookup.canary@example.test","extra":true}`, ScopeUsersRead)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d / %q", response.Code, response.Header().Get("Cache-Control"))
	}
	if strings.Contains(response.Body.String(), "cloud.lookup.canary@example.test") {
		t.Fatal("error response echoed exact lookup identity")
	}
}
```

- [ ] **Step 2: Run handler tests and verify missing constructor failure**

Run: `go test ./internal/adminapi -run '^TestHandler' -count=1 -v`
Expected: FAIL because the handler does not exist.

- [ ] **Step 3: Implement the bounded chi Router**

```go
type HealthChecker interface { Ping(context.Context) error }

type HandlerConfig struct {
	Service    admin.Service
	Auth       *Authenticator
	PostgreSQL HealthChecker
	Redis      HealthChecker
	Clock      func() time.Time
}

func NewHandler(config HandlerConfig) (http.Handler, error)
```

Create route groups with the exact five scopes. Decode commands into `admin.Command`, verify `Idempotency-Key` equals `operation_id`, and map sentinels to stable statuses: invalid request/cursor `400`, authentication `401`, scope `403`, target/operation missing `404`, state/idempotency conflict `409`, dependency unavailable `503`. Return only `{"error":{"code":"...","request_id":"..."}}` for errors.

- [ ] **Step 4: Run handler, contract, and full package tests**

Run:

```bash
go test ./internal/adminapi -count=1
go test ./api ./internal/admin ./internal/adminapi -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/adminapi/handler.go internal/adminapi/handler_test.go
git commit -m "feat: serve Cloud internal admin routes"
```

### Task 9: Wire a Separate Internal Listener Into the Cloud Process

**Files:**
- Create: `aera-cloud/cmd/aera-cloud/internal_admin.go`
- Create: `aera-cloud/cmd/aera-cloud/internal_admin_test.go`
- Modify: `aera-cloud/cmd/aera-cloud/main.go`
- Modify: `aera-cloud/cmd/aera-cloud/main_test.go`
- Modify: `aera-cloud/internal/httpapi/server.go`
- Modify: `aera-cloud/internal/httpapi/server_test.go`

**Interfaces:**
- Consumes: Tasks 2, 5, 7, and 8.
- Produces: coordinated listener startup and a public Router that always returns 404 for `/internal/*`.

- [ ] **Step 1: Write failing public-boundary and lifecycle tests**

```go
func TestPublicRouterNeverServesInternalPathsFromWebFallback(t *testing.T) {
	handler := New(Dependencies{Web: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })})
	request := httptest.NewRequest(http.MethodGet, "/internal/admin/v1/health", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound { t.Fatalf("status = %d", response.Code) }
}
```

Add `run` tests proving disabled Internal Admin opens only the public listener, enabled configuration opens both, an internal bind/TLS/build failure closes the public listener, and cancellation shuts both servers down.

- [ ] **Step 2: Run focused tests and verify failures**

Run: `go test ./internal/httpapi ./cmd/aera-cloud -run '^(TestPublicRouterNever|TestRun.*InternalAdmin)' -count=1 -v`
Expected: FAIL because `internal` is not a protected service path and dual-listener wiring is absent.

- [ ] **Step 3: Implement production wiring**

`buildInternalAdmin` must:

```go
func buildInternalAdmin(cfg config.Config, postgres *pgxpool.Pool, redisStore *store.RedisStore) (http.Handler, *tls.Config, error)
```

It builds the identity codec, `admin.Protector`, `admin.ControlRepository`, `admin.ControlService`, Ed25519 authenticator, handler, and TLS config. It returns an error without opening a listener when any dependency is invalid.

Update `servicePath` to treat first segment `internal` as a service path. Coordinate public and optional internal `net.Listener` instances under a child context; the first non-shutdown error cancels both, and `run` waits for both `serve` calls before returning.

- [ ] **Step 4: Run main, public Router, and full Cloud unit tests**

Run:

```bash
go test ./internal/httpapi ./cmd/aera-cloud -count=1
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/aera-cloud/internal_admin.go cmd/aera-cloud/internal_admin_test.go cmd/aera-cloud/main.go cmd/aera-cloud/main_test.go internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat: run isolated Cloud admin listener"
```

### Task 10: Add a Build-Tagged Real Cloud E2E Seed and Verifier

**Files:**
- Create: `aera-cloud/cmd/aera-cloud-e2e/main.go`
- Create: `aera-cloud/cmd/aera-cloud-e2e/main_test.go`

**Interfaces:**
- Produces: `aera-cloud-e2e seed --output <path>` and `aera-cloud-e2e verify --fixture <path>` available only with `-tags e2e`.

- [ ] **Step 1: Write failing guard, seed, and verify integration tests**

```go
func TestSeedRefusesNonTestOrNonLoopbackDatabase(t *testing.T) {
	for _, fixture := range []seedConfig{
		{Environment: "production", DatabaseURL: "postgres://u:p@127.0.0.1/aera_cloud"},
		{Environment: "test", DatabaseURL: "postgres://u:p@db.internal/aera_cloud"},
	} {
		if err := fixture.validate(); err == nil { t.Fatalf("validate(%+v) succeeded", fixture) }
	}
}
```

Integration test must seed an encrypted email identity, assert the plaintext is absent from `identities.ciphertext`, start with revision 1, and have one active device/session. The verifier test must fail before management operations and pass after inserting the same terminal facts expected from Playwright.

- [ ] **Step 2: Run tagged tests and verify missing command failure**

Run: `set -a; . ./.env.example; set +a; AERA_INTEGRATION_TESTS=1 go test -tags e2e ./cmd/aera-cloud-e2e -count=1 -v`
Expected: FAIL because the build-tagged command does not exist.

- [ ] **Step 3: Implement `seed` and `verify` modes**

Fixture JSON must have this exact shape:

```go
type fixture struct {
	UserID        uuid.UUID `json:"user_id"`
	DeviceID      uuid.UUID `json:"device_id"`
	SessionID     uuid.UUID `json:"session_id"`
	MaskedEmail   string    `json:"masked_email"`
	RawIdentity   string    `json:"raw_lookup_identity"`
	InitialRevision int64   `json:"initial_revision"`
}
```

`seed` applies migrations and uses `secure.IdentityCodec.Seal`; it writes the fixture with mode `0600`. `verify` asserts at least one succeeded session revoke, one succeeded account disable, matching Cloud audit events, final user disabled state, revision at least 3, revoked device/session, and absence of the raw identity in `admin_operations::text` and matching admin audit rows.

- [ ] **Step 4: Run tagged integration tests and release exclusion check**

Run:

```bash
set -a; . ./.env.example; set +a
AERA_INTEGRATION_TESTS=1 go test -tags e2e ./cmd/aera-cloud-e2e -count=1
if go list ./... | grep -q 'cmd/aera-cloud-e2e'; then
  echo 'release package list contains e2e fixture command' >&2
  exit 1
fi
CGO_ENABLED=0 go build -trimpath -o /tmp/aera-cloud ./cmd/aera-cloud
```

Expected: tagged tests PASS, ordinary package list excludes the fixture command, release build PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/aera-cloud-e2e/main.go cmd/aera-cloud-e2e/main_test.go
git commit -m "test: seed and verify real Cloud admin E2E"
```

### Task 11: Replace the Admin Cloud Stub With the Real Cloud Runner

**Files:**
- Delete: `aera-admin/e2e/cloud-stub/main.go`
- Modify: `aera-admin/scripts/run-e2e.sh`
- Create: `aera-admin/scripts/tests/run-e2e-contract.test.sh`
- Modify: `aera-admin/e2e/support.ts`
- Modify: `aera-admin/e2e/global-setup.ts`
- Modify: `aera-admin/e2e/global-teardown.ts`
- Modify: `aera-admin/Makefile`

**Interfaces:**
- Consumes: the real Cloud worktree, shared OpenAPI, `aera-cloud`, and `aera-cloud-e2e`.
- Produces: `AERA_ADMIN_E2E_CLOUD_REPO=<absolute path> make e2e` with no Stub code path.

- [ ] **Step 1: Write the failing runner contract test**

```sh
#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
test ! -e "$root/e2e/cloud-stub/main.go"
grep -q 'AERA_ADMIN_E2E_CLOUD_REPO' "$root/scripts/run-e2e.sh"
grep -q 'github.com/bignormal/aera-cloud' "$root/scripts/run-e2e.sh"
grep -q 'cmd/aera-cloud-e2e' "$root/scripts/run-e2e.sh"
if grep -q 'cloud-stub' "$root/scripts/run-e2e.sh" "$root/Makefile"; then
  echo 'real Cloud E2E still references the Stub' >&2
  exit 1
fi
```

- [ ] **Step 2: Run the runner contract test and verify failure**

Run: `sh scripts/tests/run-e2e-contract.test.sh`
Expected: FAIL because the Stub exists and the runner builds it.

- [ ] **Step 3: Implement safe repository discovery and isolated dependencies**

At the start of `run-e2e.sh`:

```sh
cloud_repo=${AERA_ADMIN_E2E_CLOUD_REPO:-}
if [ -z "$cloud_repo" ]; then
  common_dir=$(git rev-parse --git-common-dir)
  case "$common_dir" in /*) ;; *) common_dir="$repository_root/$common_dir" ;; esac
  canonical_admin=$(CDPATH= cd -- "$(dirname -- "$common_dir")" && pwd -P)
  cloud_repo=$(CDPATH= cd -- "$canonical_admin/../aera-cloud" && pwd -P)
else
  cloud_repo=$(CDPATH= cd -- "$cloud_repo" && pwd -P)
fi
test "$(sed -n 's/^module //p' "$cloud_repo/go.mod")" = 'github.com/bignormal/aera-cloud'
cmp "$repository_root/api/openapi/cloud-admin-client.yaml" "$cloud_repo/api/openapi/internal-admin.yaml"
```

Use unique Compose project names and `AERA_ADMIN_POSTGRES_BIND=127.0.0.1:` / `AERA_CLOUD_POSTGRES_BIND=127.0.0.1:` plus the Redis equivalents. Resolve dynamic ports with `docker compose -p "$project" port`. Cleanup must validate the generated project prefixes before calling `docker compose down -v --remove-orphans` in each repository.

- [ ] **Step 4: Build, seed, and start real services**

Replace the Stub build with:

```sh
(cd "$cloud_repo" && go build -trimpath -o "$cloud_binary" ./cmd/aera-cloud)
(cd "$cloud_repo" && go build -tags e2e -trimpath -o "$cloud_e2e_binary" ./cmd/aera-cloud-e2e)
"$cloud_e2e_binary" seed --output "$cloud_fixture_file"
"$cloud_binary" >"$cloud_log" 2>&1 &
cloud_pid=$!
```

Source Cloud `.env.example` only after capturing Admin environment, then override environment to `test`, dynamic database/Redis addresses, both listen addresses, all one-time PKI paths, expected JWT issuer/subject, and the generated HMAC key ring. Keep the existing Admin PKI client and service private key settings aligned with Cloud.

- [ ] **Step 5: Load the real fixture in TypeScript and verify it at teardown**

Add:

```ts
export interface CloudFixture {
  user_id: string;
  device_id: string;
  session_id: string;
  masked_email: string;
  raw_lookup_identity: string;
  initial_revision: number;
}

export function readCloudFixture(path: string): CloudFixture {
  return JSON.parse(readFileSync(path, 'utf8')) as CloudFixture;
}
```

`global-setup.ts` must populate `fixtures.cloud` from `AERA_ADMIN_E2E_CLOUD_FIXTURE_FILE`, not hard-coded UUIDs. `global-teardown.ts` must retain the two log canary scans and run:

```ts
const cloudFixture = readCloudFixture(requiredEnvironment('AERA_ADMIN_E2E_CLOUD_FIXTURE_FILE'));
sensitiveCanaries.push({ kind: 'cloud_raw_lookup_identity', value: cloudFixture.raw_lookup_identity });

const fixtures: E2EFixtures = {
  baseURL,
  browserCandidate: {
    activationURL: candidateInvitation.body.activation_url,
    adminId: candidate.adminId,
    email: candidateEmail,
    maskedIdentity: maskedEmail(candidateEmail),
    password: candidatePassword,
    totpSecret: candidate.secret,
  },
  cloud: {
    maskedEmail: cloudFixture.masked_email,
    rawLookupIdentity: cloudFixture.raw_lookup_identity,
    sessionID: cloudFixture.session_id,
    deviceID: cloudFixture.device_id,
    userID: cloudFixture.user_id,
  },
  roles: roleFixtures,
  sensitiveCanaries,
};
```

`global-teardown.ts` retains the two existing `assertNoCanaries` calls and then runs:

```ts
execFileSync(requiredEnvironment('AERA_ADMIN_E2E_CLOUD_VERIFY_BINARY'), [
  'verify', '--fixture', requiredEnvironment('AERA_ADMIN_E2E_CLOUD_FIXTURE_FILE'),
], { env: process.env, stdio: 'inherit' });
```

- [ ] **Step 6: Remove the Stub and update Makefile checks**

Delete `e2e/cloud-stub/main.go`. Change `format-check` to scan existing Go roots without the deleted path, and add `sh scripts/tests/run-e2e-contract.test.sh` to `check` before builds.

- [ ] **Step 7: Run static, type, and real cross-repository E2E checks**

Run:

```bash
sh scripts/tests/run-e2e-contract.test.sh
pnpm exec tsc -p tsconfig.e2e.json
AERA_ADMIN_E2E_CLOUD_REPO=/Users/zizimutou/Desktop/aera/aera-cloud/.worktrees/internal-admin-api make e2e
```

Expected: runner contract PASS, E2E typecheck PASS, Playwright `10 passed`, Cloud verifier PASS, and no canary leakage in either log.

- [ ] **Step 8: Commit Admin changes**

```bash
git add Makefile scripts/run-e2e.sh scripts/tests/run-e2e-contract.test.sh e2e/support.ts e2e/global-setup.ts e2e/global-teardown.ts e2e/cloud-stub/main.go
git commit -m "test: run admin E2E against real Cloud"
```

### Task 12: Document the Real Boundary and Run Complete Verification

**Files:**
- Modify: `aera-cloud/README.md`
- Modify: `aera-cloud/docs/runbooks/private-staging.md`
- Modify: `aera-admin/README.md`
- Modify: `aera-cloud/.github/workflows/ci.yml`

**Interfaces:**
- Produces: accurate operation/runbook documentation and final evidence without claiming deployment.

- [ ] **Step 1: Write documentation contract checks first**

Extend existing shell contract tests to require Cloud README/runbook text for the independent listener, mTLS plus service JWT, and disabled-by-default configuration. Require Admin README to contain `真实 aera-cloud` and forbid `真实 Internal Admin API 尚未.*实现`.

- [ ] **Step 2: Run documentation checks and verify old-boundary failure**

Run in Cloud: `bash scripts/tests/delivery-contract.test.sh`
Run in Admin: `sh scripts/tests/run-e2e-contract.test.sh`
Expected: at least one FAIL because README still describes the Stub/unimplemented boundary.

- [ ] **Step 3: Update docs and CI within available repository permissions**

Document:

- every Internal Admin environment variable without sample secrets;
- private-network and certificate requirements;
- exact local real-Cloud E2E command;
- PostgreSQL authority and non-restoration behavior;
- migration-first deployment and listener-first rollback;
- local verification versus push versus deployment.

Add Cloud CI steps for `go test ./internal/admin ./internal/adminapi`, race tests for both packages, provider OpenAPI, tagged E2E fixture tests under service integration, and release build exclusion. Keep Admin cross-repository E2E as the documented local/authorized workflow; do not modify Admin CI or add a PAT/secret assumption in this increment.

- [ ] **Step 4: Run complete Cloud verification**

Run:

```bash
gofmt -w api cmd internal
test -z "$(gofmt -l api cmd internal)"
go vet ./...
go test ./... -count=1
set -a; . ./.env.example; set +a
AERA_INTEGRATION_TESTS=1 go test -p 1 ./... -count=1
AERA_INTEGRATION_TESTS=1 go test -race ./internal/admin ./internal/adminapi -count=1
CGO_ENABLED=0 go build -trimpath -o /tmp/aera-cloud ./cmd/aera-cloud
CGO_ENABLED=0 go build -trimpath -o /tmp/aera-cloud-admin ./cmd/aera-cloud-admin
bash scripts/check-secrets.sh
bash scripts/tests/check-secrets.test.sh
bash scripts/tests/delivery-contract.test.sh
```

Expected: all commands PASS.

- [ ] **Step 5: Run complete Admin verification and real E2E again**

Run:

```bash
make verify
AERA_ADMIN_E2E_CLOUD_REPO=/Users/zizimutou/Desktop/aera/aera-cloud/.worktrees/internal-admin-api make e2e
make image
```

Expected: Admin unit/integration/race/frontend/OpenAPI/build PASS, Playwright `10 passed` against real Cloud, Cloud verifier PASS, Docker image build PASS.

- [ ] **Step 6: Inspect diffs, security boundaries, and worktree state**

Run in both worktrees:

```bash
git diff --check
git status --short --branch
git log --oneline --decorate -15
```

Manually confirm no raw identity, private key, generated certificate, database URL, token, fixture file, or test artifact is tracked. Confirm `/internal/admin` appears only in the provider Router/package and in public-Router rejection tests, never in `internal/httpapi.New` route registration.

- [ ] **Step 7: Commit documentation and CI changes separately in each repository**

```bash
# Cloud
git add README.md docs/runbooks/private-staging.md .github/workflows/ci.yml
git commit -m "docs: operate the internal admin API safely"

# Admin
git add README.md
git commit -m "docs: record real Cloud admin validation"
```

- [ ] **Step 8: Use the finishing-development-branch workflow before push**

Invoke `superpowers:verification-before-completion`, then `superpowers:requesting-code-review`, then `superpowers:finishing-a-development-branch`. Preserve the two feature branches until the user-selected integration path is complete. Push each branch only after final verification, and report branch/commit/push status separately from deployment.
