# Cloud Ownership Integrity Guardrails

## Purpose

Prevent authentication and device-ownership changes from shipping with incomplete relational-state handling or misleading OAuth errors.

The Beta.27 login incident exposed a cross-domain failure: a revoked device could be reassigned to another account, but owner-bound Desktop Control rows still referenced the old `(device_id, user_id)`. PostgreSQL correctly rejected the owner update, while OAuth converted the dependency failure into `authorization_expired`. The browser had already completed authorization, so the Desktop could not establish a Product Session even though the user saw a success page.

This design turns the incident lesson into repository-level instructions for future AI and human contributors plus executable CI regression coverage. It is limited to `aera-cloud`; it does not introduce Desktop, Runtime, Admin, or multi-platform validation work.

## Repository Instruction Boundary

Add a root `AGENTS.md`, because `aera-cloud` currently has no repository-scoped AI instruction file. Compatible coding agents entering any path in this repository must read this root file before making changes.

The instruction file will require contributors modifying identity, ownership, authorization, revocation, reassignment, or schema relationships to:

1. inspect every inbound foreign key and application-owned reference to the entity before changing an owner or composite key;
2. define behavior separately for same-owner reauthorization, cross-owner transfer, and owner-bound protected data;
3. preserve same-owner operational state unless the feature contract explicitly requires replacement;
4. remove only disposable old-owner state during a permitted cross-owner transfer;
5. reject transfer of encrypted backup or other protected user data instead of silently deleting or reassigning it;
6. perform the complete ownership transition in one PostgreSQL transaction and prove rollback behavior;
7. preserve dependency and availability failures through the service and HTTP layers rather than mapping them to expired or invalid credentials;
8. add real PostgreSQL integration tests for every affected relational state; and
9. run shared-database integration packages serially with `-p 1`.

`AGENTS.md` is the mandatory guidance layer for compatible AI tooling. It cannot technically prove that every possible third-party AI client read the file, so executable CI remains the enforcement layer.

## Executable Regression Gate

The existing GitHub Actions integration job already starts isolated PostgreSQL and runs `AERA_INTEGRATION_TESTS=1 go test -count=1 -p 1 ./...`. The new and strengthened tests therefore become merge-blocking without adding another platform matrix or duplicated workflow.

The gate will cover these contracts:

| Scenario | Required result |
| --- | --- |
| Same installation and same owner | Reauthorization succeeds and Desktop Control instance/command rows remain intact. |
| Revoked installation transferred to another owner | Transfer succeeds only with the same device key; old Desktop Control commands and instance are removed before the owner update. |
| Active or inactive installation owned by another account | Transfer fails with `device_conflict` and no data changes. |
| Revoked installation with `backup_devices` state | Transfer fails with `device_conflict`; owner, backup state, and unrelated control state remain unchanged. |
| Revoked installation with `encrypted_profile_backups` state | Transfer fails with `device_conflict`; owner and backup lineage remain unchanged. |
| Failure after old-owner cleanup but before OAuth exchange commit | The transaction restores the device owner and all pre-existing control state, and the authorization code remains retryable. |
| Device repository unavailable during OAuth exchange | Service returns OAuth unavailable; HTTP returns `503 service_unavailable`, never `authorization_expired`. |

Tests should use current fixtures and migrations rather than schema mocks so a newly introduced foreign key participates in the regression gate. No Desktop or other platform build is added because this change affects only Cloud relational and OAuth behavior.

## Error and Data-Safety Contract

`authorization_expired` is reserved for invalid, expired, or cryptographically rejected authorization material. SQL failures, foreign-key conflicts not translated into an explicit domain conflict, and unavailable dependencies must remain retryable availability failures and reach HTTP as `503 service_unavailable`.

An intentional ownership conflict must remain a stable conflict response. Protected user data, especially encrypted backup lineage and device backup authority, must never be deleted or reassigned merely to make a device transfer succeed. A rejected transfer must leave the original owner and all related rows unchanged.

## Change Scope

Implementation will add the root instruction file and fill only the missing regression assertions around the already-deployed fix. Production behavior will not be changed unless a test exposes a remaining contract violation. The existing Cloud CI workflow remains the execution mechanism.

The implementation will not:

- alter Desktop binaries or publish a new Desktop version;
- disable Desktop Control heartbeats;
- change backup ownership semantics;
- add a new database migration without evidence that the current schema cannot satisfy the contract; or
- run unchanged Desktop, Runtime, Admin, macOS, Linux, or Windows test matrices.

## Acceptance Criteria

The change is complete when:

- the root `AGENTS.md` contains the ownership-integrity, transaction, error-mapping, and serial-integration-test rules;
- the missing backup, rollback, and HTTP mapping cases are covered by real tests at their affected boundaries;
- `AERA_INTEGRATION_TESTS=1 go test -count=1 -p 1 ./internal/device ./internal/oauth` passes against isolated PostgreSQL;
- `go vet ./internal/device ./internal/oauth` and `git diff --check` pass; and
- the PR CI succeeds on the exact submitted commit.
