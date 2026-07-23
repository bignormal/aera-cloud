# User-encrypted backup operations

AgentEra encrypted Profile backup is a client-encrypted disaster-recovery feature. Cloud stores opaque ciphertext, device public keys, encrypted envelopes, hashes, sizes, quotas, and random object references. Cloud operators cannot recover filenames, Profile content, conversations, Memory, USER state, private Skills, the 24-word phrase, the Backup Root Key, or per-backup Data Encryption Keys.

The feature is disabled by default. Enabling it proves only that the Cloud API and ciphertext object store are available; it does not authorize a public rollout.

## Configuration and isolation

Inject every value from the deployment secret manager. Never commit production object-store credentials or copy the development values from `.env.example`.

- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED`: explicit feature gate; keep `false` until schema, storage, monitoring, restore, and rollback gates pass.
- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENDPOINT`: dedicated S3-compatible endpoint as `host:port`, without a scheme or path.
- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_BUCKET`: dedicated ciphertext-only bucket.
- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_REGION`: exact bucket region.
- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_ACCESS_KEY`: least-privilege service identity restricted to the dedicated bucket.
- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_SECRET_KEY`: matching secret, supplied only at runtime.
- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_USE_TLS`: must be `true` for a non-loopback production endpoint.

The bucket must not host logs, database backups, static assets, or another product's objects. Deny public access, enable encryption at rest and transport TLS, restrict the service identity to required object lifecycle operations, and audit policy changes. Object-store server-side encryption is defense in depth; the application payload remains client ciphertext.

Startup fails when encrypted backup is enabled with incomplete or unsafe production configuration. When the feature is disabled or the object store is unavailable, normal local Profiles, chat, sessions, and learning continue without a server-side fallback or plaintext upload.

## Readiness and monitoring

Before enabling a private environment:

1. Apply the additive encrypted-backup migrations and verify Cloud readiness with the feature still disabled.
2. Create the dedicated bucket and least-privilege credentials.
3. Enable the feature on one private Cloud instance and verify its readiness endpoint.
4. Run the complete Desktop backup, authorized-device restore, phrase-only restore, revoke, tamper, deletion, and cleanup-retry acceptance flow.
5. Inspect PostgreSQL and object metadata for only opaque identifiers, ciphertext, hashes, sizes, state, and timestamps.
6. Disable the feature again until the rollout change is separately approved.

Monitor bounded counts and states: initiated/sealed/deleting/deleted backups, incomplete-upload age, pending object deletions, object-count reconciliation, quota rejection codes, and fixed failure classes. Logs, traces, metrics, alerts, and support tickets must never contain the recovery phrase, root or data-encryption keys, private keys, decrypted bytes, filenames, local paths, plaintext canaries, authorization tokens, or raw request bodies.

Use opaque account, device, backup, and object identifiers only when an incident requires correlation. Do not dump `bytea` values or object bodies into terminals, chat, tickets, dashboards, or audit exports.

## Lifecycle and failure behavior

An incomplete upload is not restorable. Missing chunks may be resumed while its upload lease is valid; an expired attempt must restart with new backup material. Cleanup of expired or failed uploads is idempotent and may be retried after an object-store outage.

Device authorization creates a client-produced encrypted root-key envelope for that device. Revocation removes the device's recovery authority and envelopes; it does not erase a key the device may already hold locally. Treat a lost or suspected-compromised device as a user security event and advise recovery-key rotation through a new backup lineage when available.

Deletion is deliberately ordered:

1. make the backup unavailable for restore;
2. destroy recovery material, wrapped backup keys, and device envelopes in PostgreSQL;
3. delete ciphertext objects asynchronously and idempotently;
4. retain only privacy-safe deletion state needed to retry and reconcile.

An object-store outage must not restore database recovery material. Retry object deletion until reconciliation reports zero objects for the deleted backup.

## Incident playbooks

### Object store unavailable

Keep the feature enabled only if normal Cloud readiness semantics and the approved error budget allow it. Backup upload, download, and object cleanup return unavailable or pending states; they never report success from a mock path. Verify local chat and existing Profiles are unaffected. Restore storage service, resume eligible uploads, and drain deletion retries before reopening rollout.

### Ciphertext, digest, or signature mismatch

Treat the affected backup as untrusted. Do not bypass verification, rewrite signed public metadata, or copy decrypted partial output into a destination Profile. Preserve only privacy-safe identifiers and fixed error codes for investigation. Quarantine the opaque objects if retention policy allows, revoke suspect devices when appropriate, and have the user create a new verified backup.

### Database or object-count divergence

Query only backup state, opaque object keys, sizes, digests, and counts. A sealed database record with missing objects is unavailable, not successful. Objects without live recovery material are unrecoverable ciphertext and should enter the reviewed orphan-cleanup path. Never recreate an envelope, wrapped key, or recovery row from operator-held material.

### Suspected key or credential exposure

Rotate the object-store service credential and review bucket access logs. Object-store credentials do not decrypt client ciphertext. A disclosed user recovery phrase or authorized-device private key is a user-side compromise: revoke affected device authority, stop relying on existing backups, and create a new recovery lineage when the product supports rotation.

## Safe reconciliation

Operational queries may aggregate:

- backups by lifecycle state and age;
- incomplete uploads beyond their lease;
- pending deletions and retry age;
- declared versus observed opaque object count and total ciphertext bytes;
- device registrations and revocation timestamps by opaque ID.

Queries must not select ciphertext/envelope columns unless a narrowly approved integrity tool streams them directly into digest verification without displaying or persisting the bytes. Never decode, stringify, export, or sample encrypted blobs as an observability technique.

## Restore rehearsal

At least once per release candidate, use disposable test accounts and isolated device homes to:

1. create known private Profile state and an immutable Agent base;
2. seal a backup and verify plaintext canaries are absent from PostgreSQL and object storage;
3. restore through an authorized second device into a fresh Installation/Profile;
4. restore through the 24-word phrase on a third device;
5. reject a wrong phrase, revoked device, and tampered object without changing any existing Profile;
6. delete the backup during a simulated storage outage and verify key/envelope destruction precedes eventual zero-object cleanup.

Destroy the disposable accounts, device homes, local phrases, and test bucket objects after retaining only privacy-safe pass/fail evidence.

## Rollback and account deletion

Application rollback begins by setting `AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=false`. Preserve additive schema, lifecycle records, encrypted objects, and privacy-safe audit facts. Do not drop tables, delete unknown objects, restore destroyed envelopes, or roll back key destruction. Deploy an older binary only when it tolerates the applied schema.

Account deletion must first make every backup unavailable and destroy its recovery material and device envelopes transactionally, then enqueue idempotent ciphertext-object deletion. A storage outage leaves only unrecoverable ciphertext pending cleanup and must not block destruction of database recovery material. Reconcile to zero objects before closing the deletion operation.

Record local commit, local verification, local main merge, remote push, remote CI, staging deployment, production deployment, feature enablement, and public release as separate states.
