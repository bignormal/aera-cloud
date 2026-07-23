# Production runbook

## Hard launch gates

Do not enable public registration until every item is true:

- the final domain has completed the required filing and resolves to the server;
- Caddy or an equivalent reverse proxy serves a trusted HTTPS certificate;
- real SMTP, SMS, and CAPTCHA providers are configured and delivery is tested;
- the published Privacy Policy and Terms of Service versions match the configured versions;
- PostgreSQL backups are encrypted to an offline `age` recipient;
- a disposable restore has passed integrity and identity-decryption verification;
- the desktop release contains the current offline-entitlement public key IDs;
- `go test`, frontend tests, the isolated auth smoke test, and `check-secrets.sh` pass.

The server IP is acceptable for private staging only. Do not establish a public production issuer on a temporary IP: changing `AGENTERA_CLOUD_PUBLIC_URL` later changes `iss` and forces every product session and offline entitlement to be renewed.

## Secrets and isolation

1. Create `/srv/agentera-cloud/secrets/agentera-cloud.env` with mode `0600`; never place it in the repository.
2. Start from the variable names in `.env.example`, not its development values. Generate independent random material for every encryption, lookup, HMAC, verification, OAuth, access-signing, and offline-signing key. Signing key rings contain canonical raw Ed25519 private keys encoded with standard base64.
3. Set a unique cookie such as `agentera_app_session`; never reuse the recharge website cookie or secret.
4. Set `AGENTERA_CLOUD_PUBLIC_URL=https://YOUR_FILED_DOMAIN`, real provider endpoints, and the reviewed legal document versions.
5. Generate URL-safe infrastructure passwords, store them in the deployment password manager, and export them only for Compose:

   ```bash
   export AERA_CLOUD_POSTGRES_PASSWORD='REDACTED_URL_SAFE_RANDOM_VALUE'
   export AERA_CLOUD_REDIS_PASSWORD='REDACTED_URL_SAFE_RANDOM_VALUE'
   export AGENTERA_CLOUD_ENV_FILE=/srv/agentera-cloud/secrets/agentera-cloud.env
   ```

The production Compose project owns only the `aera_cloud` database/role, Redis ACL user with the `aera-cloud:*` namespace in database 9, and AgentEra account-service volumes. It does not join the recharge application network.

## Deploy

Production does not build from the server checkout and does not accept a mutable tag. The protected `promote-production.yml` workflow downloads an already successful Cloud candidate by run ID and source SHA, verifies its keyless Cosign signature/provenance, and supplies the exact `ghcr.io/...@sha256:...` reference as `AGENTERA_CLOUD_IMAGE_DIGEST`.

Before the application changes, the workflow runs the approved encrypted PostgreSQL backup and disposable restore commands. `scripts/release/deploy-by-digest.sh deploy` records the previous candidate, pulls the exact digest, and starts the new image with these enforced settings:

```text
AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false
AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=false
AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=false
AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=false
```

The generated feature file is mode `0600` outside Git and is loaded after the base secret environment file. Health, auth, official-quality, and encrypted-backup read-only/fail-closed smoke must pass before the disabled deployment is recorded.

The production Compose file also requires the Internal Admin server certificate/key, dedicated Admin client CA, and Admin service-JWT public key as read-only host mounts. It joins the Cloud app—not PostgreSQL, Redis, or object storage—to the external `AERA_CLOUD_ADMIN_PRIVATE_NETWORK`, where it is available only as `aera-cloud-internal-admin:8443`. The listener has no host port. The paired Admin deployment must verify the server CA through its own trust bundle and prove mTLS plus the audience-bound service JWT before enabling any Admin mutation.

Feature enablement is a separate protected job and requires the `enable_rollout` input plus explicit booleans for each cohort. It re-verifies the same manifest and refuses a different digest; it never rebuilds the image. Public registration remains false until its independent domain, provider, legal, backup, and production-approval gates pass.

Install `deploy/Caddyfile.example` with `AGENTERA_ACCOUNT_HOST` set to the filed domain. Keep port 18086 loopback-only. The example deliberately disables access logs so OAuth state and device metadata in query strings are not retained.

## Backup and restore gate

```bash
export AGENTERA_CLOUD_DATABASE_URL='REDACTED_PRODUCTION_DATABASE_URL'
export AGENTERA_BACKUP_AGE_RECIPIENT='age1...'
export AGENTERA_BACKUP_DIR=/var/backups/agentera-cloud
./deploy/backup.sh
```

Copy the encrypted archive and checksum to separate storage. At least monthly, run `restore-verify.sh` against a disposable PostgreSQL instance with the complete recovery encryption-key set. Never use the live production database as the restore target.

## Upgrade and rollback

1. Create and verify an encrypted backup.
2. Verify the signed candidate manifest, exact image digest, CI source SHA, SBOM, provenance, and schema compatibility.
3. Run migrations by starting one application instance; migrations are transactional and lock-protected.
4. Verify health and the account-center routes before allowing traffic.
5. Roll back application code only if the previous signed manifest supports the already-applied schema. Never roll back key rings by deleting a still-referenced key.

`rollback-production.yml` requires a previous candidate run ID/SHA, reason, ticket, and production approval. It disables every new feature, verifies the previous signature and schema maximum against the current highest migration, repeats backup/restore verification, switches to the exact previous digest, re-runs health/smoke, and records `rollback-evidence.json`. It never invokes a down migration or deletes new schema/data.

The same workflow supports a protected `staging` rehearsal only when the exact current candidate run/SHA is also supplied and `restore_current_after_rehearsal=true`. Before switching images, it restarts the current digest with all new features disabled and re-runs health/smoke. It then records current B → previous A, verifies A, and re-verifies/deploys exact B disabled. Separate rollback and restoration artifacts must exist; a staging rehearsal that cannot restore B is failed.

Production rollback keeps `restore_current_after_rehearsal=false` and never auto-restores the suspected image. The `production` environment approval, production runner, and production state directory remain distinct from staging.

## Evidence-backed delivery status

Report local code/tests, local commits, local merge, remote push, remote CI, signed candidate, staging deployment/acceptance, rollback rehearsal, production disabled deployment, feature rollout, and public release separately.

The production workflow uploads disabled and enabled state artifacts. Desktop publication must verify their exact source SHA, manifest hash, image digest, `environment=production`, and actual feature values. A successful job conclusion without those state files is insufficient.

The local deployment harness proves digest/signature/schema checks, encrypted backup/disposable restore hooks, disable-before-rollback behavior, B → A → B rehearsal restoration, and fail-closed rollout recovery. It does not prove a remote candidate, staging or production deployment, production provider, legal/domain approval, monitoring window, or public release.

No push, deployment, DNS change, public exposure, or registration enablement is implied by this runbook; each is a separate authorized operation.
