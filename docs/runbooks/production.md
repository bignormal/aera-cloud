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

```bash
docker compose -f deploy/compose.production.yaml build --pull
docker compose -f deploy/compose.production.yaml up -d
docker compose -f deploy/compose.production.yaml ps
curl --fail http://127.0.0.1:18086/health/ready
```

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
2. Build an immutable image tag from the reviewed commit.
3. Run migrations by starting one application instance; migrations are transactional and lock-protected.
4. Verify health and the account-center routes before allowing traffic.
5. Roll back application code only if the previous binary supports the already-applied schema. Never roll back key rings by deleting a still-referenced key.

No push, deployment, DNS change, public exposure, or registration enablement is implied by this runbook; each is a separate authorized operation.
