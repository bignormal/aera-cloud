# Cloud Ownership Integrity Guardrails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Cloud ownership and OAuth changes follow repository-level safety rules and enforce the Beta.27 regression contracts in the existing serial PostgreSQL CI gate.

**Architecture:** A root `AGENTS.md` supplies mandatory repository-scoped instructions to compatible AI contributors. Existing device and OAuth tests remain the executable enforcement layer: device integration tests exercise real migrations and inbound foreign keys, while OAuth service/HTTP tests preserve transactional rollback and public error semantics.

**Tech Stack:** Markdown, Go 1.26, PostgreSQL 17, `pgx/v5`, `net/http`, GitHub Actions.

---

## File Structure

- Create `AGENTS.md`: repository-scoped AI and contributor rules for ownership, relational integrity, transactions, OAuth error mapping, and serial integration tests.
- Modify `internal/device/service_test.go`: real PostgreSQL regression fixtures for protected backup relationships and rejected-transfer state preservation.
- Modify `internal/oauth/model.go`: introduce the explicit OAuth device-conflict domain error.
- Modify `internal/oauth/service.go`: preserve device conflicts instead of converting them to expired authorization.
- Modify `internal/oauth/service_test.go`: service error propagation plus rollback of an interrupted cross-owner device transfer.
- Modify `internal/oauth/http.go`: map explicit device conflicts to HTTP 409 `device_conflict`.
- Modify `internal/oauth/http_test.go`: freeze unavailable and conflict HTTP mappings.
- Modify `api/openapi.yaml`: publish `device_conflict` in the public error vocabulary.
- Modify `api/openapi_test.go`: freeze the new public error-code contract.

### Task 1: Add Repository-Scoped Mandatory Rules

**Files:**
- Create: `AGENTS.md`

- [ ] **Step 1: Add the root instruction file**

Write concise mandatory rules that require:

```markdown
# Cloud Development Rules

## Required relational-integrity analysis

- Before changing identity, ownership, authorization, revocation, reassignment, or a composite key, enumerate every inbound PostgreSQL foreign key and application-owned reference to the affected entity.
- Define and test same-owner reauthorization, cross-owner transfer, and owner-bound protected-data behavior separately.
- Preserve same-owner operational state. During an allowed cross-owner transfer, remove only disposable old-owner state. Never silently delete or reassign encrypted backups, backup authority, audit evidence, or other protected user data.
- Execute the complete ownership transition in one PostgreSQL transaction and prove rollback after a failure that occurs after intermediate mutations.

## Required error semantics

- Invalid or expired authorization material may map to `authorization_expired`.
- Database, foreign-key, dependency, and availability failures must remain retryable availability failures unless deliberately classified as a stable domain conflict.
- Preserve domain errors through repository, service, and HTTP layers and add a mapping test at every changed boundary.

## Required verification

- Use real migrations and PostgreSQL for relational-state regression tests; schema mocks do not prove foreign-key behavior.
- Run packages sharing the integration database serially with `AERA_INTEGRATION_TESTS=1 go test -count=1 -p 1 ...`.
- Validate only affected Cloud boundaries unless another repository or platform changed.
```

- [ ] **Step 2: Verify the file contains every mandatory category**

Run:

```bash
rg -n "inbound PostgreSQL foreign key|same-owner|cross-owner|protected user data|one PostgreSQL transaction|authorization_expired|domain errors|real migrations|-p 1|affected Cloud boundaries" AGENTS.md
```

Expected: every pattern appears at least once.

- [ ] **Step 3: Commit the instruction layer**

```bash
git add AGENTS.md
git diff --cached --check
git commit -m "docs: require Cloud ownership integrity checks"
```

### Task 2: Lock Protected Relational State in Device Integration Tests

**Files:**
- Modify: `internal/device/service_test.go`

- [ ] **Step 1: Strengthen the existing backup-device rejection test**

Before attempting the transfer, seed one Desktop Control instance and command. After `ErrDeviceConflict`, query the device owner plus counts for `backup_devices`, `desktop_control_instances`, and `desktop_control_commands`; require the original owner and `1/1/1` related rows. This proves validation occurs before destructive cleanup.

- [ ] **Step 2: Add the encrypted-profile-backup rejection test**

Create valid rows for the old user's personal space, Agent definition, Agent version, Installation, and an `encrypted_profile_backups` record referencing the revoked device. Attempt same-key authorization as a second user and assert:

```go
if _, err := fixture.service.Authorize(fixture.ctx, command); !errors.Is(err, ErrDeviceConflict) {
    t.Fatalf("Authorize(encrypted-backup-bound transfer) error = %v", err)
}
```

Then query `devices.user_id` and the backup count, requiring the original owner and one preserved backup.

- [ ] **Step 3: Run the real relational regression tests**

Run:

```bash
AERA_INTEGRATION_TESTS=1 go test -count=1 -p 1 ./internal/device -run 'TestAuthorize(PreservesDesktopControlStateForSameOwner|TransfersRevokedInstallationWithoutInheritingDesktopControlState|RejectsCrossOwnerTransferWithOwnerBoundBackupState|RejectsCrossOwnerTransferWithEncryptedProfileBackup)$'
```

Expected: PASS. These are regression tests for already-deployed behavior; no production change is expected.

- [ ] **Step 4: Commit protected-state regressions**

```bash
git add internal/device/service_test.go
git diff --cached --check
git commit -m "test(device): lock owner-bound transfer safety"
```

### Task 3: Preserve Explicit Device Conflicts Through OAuth

**Files:**
- Modify: `internal/oauth/model.go`
- Modify: `internal/oauth/service.go`
- Modify: `internal/oauth/service_test.go`
- Modify: `internal/oauth/http.go`
- Modify: `internal/oauth/http_test.go`
- Modify: `api/openapi.yaml`
- Modify: `api/openapi_test.go`

- [ ] **Step 1: Write failing service and HTTP mapping tests**

Add `TestExchangePreservesDeviceConflict` beside `TestExchangePreservesDeviceServiceUnavailable`. Configure the fake device authorizer with `device.ErrDeviceConflict` and require `ErrDeviceConflict` without consuming the code.

Extend the HTTP error table with:

```go
{oauthErr: ErrUnavailable, path: "/api/v1/oauth/token", body: validTokenBody(), status: http.StatusServiceUnavailable, code: "service_unavailable"},
{oauthErr: ErrDeviceConflict, path: "/api/v1/oauth/token", body: validTokenBody(), status: http.StatusConflict, code: "device_conflict"},
```

Extend the OpenAPI error-code assertion to require `device_conflict`.

- [ ] **Step 2: Run tests and verify the new contract fails first**

Run:

```bash
go test ./internal/oauth ./api -run 'Test(ExchangePreservesDeviceConflict|HTTPMapsOAuthReplayDeviceLimitAndSessionRevocation|OpenAPIContainsTaskFourAccountContract)$' -count=1
```

Expected: FAIL because OAuth has no `ErrDeviceConflict` and no public `device_conflict` mapping yet.

- [ ] **Step 3: Implement the minimal error propagation**

Add `ErrDeviceConflict` to `internal/oauth/model.go`. In `Service.Exchange`, translate `device.ErrDeviceConflict` to it before the generic invalid-authorization fallback. In `writeMappedOAuthError`, map it to HTTP 409 `device_conflict`. Add `device_conflict` to `ErrorCode` in `api/openapi.yaml`.

- [ ] **Step 4: Run the mapping tests and verify they pass**

Run the Step 2 command again.

Expected: PASS.

- [ ] **Step 5: Commit explicit conflict semantics**

```bash
git add internal/oauth/model.go internal/oauth/service.go internal/oauth/service_test.go internal/oauth/http.go internal/oauth/http_test.go api/openapi.yaml api/openapi_test.go
git diff --cached --check
git commit -m "fix(oauth): preserve device ownership conflicts"
```

### Task 4: Prove Cross-Owner Cleanup Rolls Back With OAuth Failure

**Files:**
- Modify: `internal/oauth/service_test.go`

- [ ] **Step 1: Add an interrupted-transfer integration regression**

Create old and new users plus the new user's personal space. Authorize and revoke the old user's device, seed its Desktop Control instance and command, and prepare an OAuth exchange for the new user with the same installation ID and device key. Use `failingSessionStarter` so failure occurs after device cleanup and owner update but before transaction commit.

After the exchange returns `session.ErrUnavailable`, assert in PostgreSQL:

```text
devices.user_id = old user
devices.status = revoked
desktop_control_instances count = 1
desktop_control_commands count = 1
authorization_codes consumed count = 0
```

- [ ] **Step 2: Run the interrupted-transfer test**

Run:

```bash
AERA_INTEGRATION_TESTS=1 go test -count=1 -p 1 ./internal/oauth -run '^TestFailedExchangeRollsBackCrossOwnerDeviceTransferAndLeavesAuthorizationRetryable$'
```

Expected: PASS against the existing transaction boundary.

- [ ] **Step 3: Commit the transaction regression**

```bash
git add internal/oauth/service_test.go
git diff --cached --check
git commit -m "test(oauth): prove device transfer rollback"
```

### Task 5: Run the Changed Cloud Boundary Gate

**Files:**
- Verify only; no planned source changes.

- [ ] **Step 1: Format modified Go files**

```bash
gofmt -w internal/device/service_test.go internal/oauth/model.go internal/oauth/service.go internal/oauth/service_test.go internal/oauth/http.go internal/oauth/http_test.go api/openapi_test.go
```

- [ ] **Step 2: Run unit tests for changed packages**

```bash
go test -count=1 ./api ./internal/device ./internal/oauth
```

Expected: PASS.

- [ ] **Step 3: Run serial PostgreSQL integration tests for changed packages**

```bash
AERA_INTEGRATION_TESTS=1 go test -count=1 -p 1 ./internal/device ./internal/oauth
```

Expected: PASS.

- [ ] **Step 4: Run static and whitespace checks**

```bash
go vet ./internal/device ./internal/oauth
git diff --check
git status --short
```

Expected: no vet or whitespace errors; status contains only intentional committed work.

- [ ] **Step 5: Review the branch against its remote-main base**

```bash
git log --oneline origin/main..HEAD
git diff --stat origin/main...HEAD
git status --short --branch
```

Expected: the design, implementation plan, repository rules, and targeted regression commits are present; the worktree is clean.
