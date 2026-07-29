# Cloud Internal Beta Runbook

This stack is for the temporary company-internal Beta only. It exposes the
Cloud account listener through trusted HTTPS on the reviewed IP origin. Cloud
PostgreSQL, Redis, encrypted-backup MinIO, and the mTLS Internal Admin listener
have no host-public ports.

The default rollout still omits SMTP and SMS. In that mode the enabled phase
uses isolated `internal_beta` direct registration: an email-shaped identifier
is stored as unverified and mailbox ownership is not claimed. A separately
approved rollout may enable verified phone-only registration and login with a
real Alibaba Cloud SMS provider. That rollout never treats SMS delivery alone
as account creation: the verification receipt, account, encrypted phone
identity, personal space, legal acceptance, audit event, and one-time login
receipt must all persist successfully.

## Immutable inputs

Deploy only a downloaded `candidate.yml` artifact for an exact, successful
`main` run. Keep these files together:

- `manifest.json`
- `manifest.sigstore.json`
- `provenance.json`
- `sbom.spdx.json`

The deployment command verifies the image signature, provenance attestation,
manifest bundle, source SHA, workflow identity, SBOM digest, and immutable GHCR
image reference before Docker may pull or start the application.

Do not clone a writable repository onto the host. Copy the reviewed Compose,
Caddy, operator scripts, and candidate evidence into
`/opt/aera/internal-beta`, owned by the dedicated deployment account.

## Host-only inputs

The host ceremony creates an owner-only Cloud environment file. It must contain
independent values for Cloud PostgreSQL and Redis, encrypted-backup MinIO,
identity encryption and lookup, verification, browser/login limits, OAuth
state, refresh tokens, access/offline/agent-control signing, Official Agent
rollout, quality pseudonyms, and Internal Admin HMAC settings.

For an approved verified phone rollout, the same owner-only file also contains:

- `AGENTERA_CLOUD_SMS_PROVIDER=aliyun`
- `AGENTERA_CLOUD_ALIYUN_SMS_ACCESS_KEY_ID`
- `AGENTERA_CLOUD_ALIYUN_SMS_ACCESS_KEY_SECRET`
- `AGENTERA_CLOUD_ALIYUN_SMS_REGION_ID`
- `AGENTERA_CLOUD_ALIYUN_SMS_SIGN_NAME`
- `AGENTERA_CLOUD_ALIYUN_SMS_TEMPLATE_CODE`

Use a dedicated least-privilege RAM identity. Never print, source into an
interactive transcript, commit, or copy these credentials into Desktop.

Registration and login share one Redis-backed 60-second cooldown per normalized
phone number, with the persisted delivered challenge as a second cross-purpose
guard. A denied request returns HTTP 429 with `Retry-After: 60`. Operational
logs retain only the validated Aliyun error code and masked request ID; never
copy the provider message, destination, code, or credential material into logs.

The Compose interpolation contract also requires:

- `AERA_CLOUD_POSTGRES_PASSWORD`
- `AERA_CLOUD_REDIS_PASSWORD`
- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_ACCESS_KEY`
- `AGENTERA_CLOUD_ENCRYPTED_BACKUP_SECRET_KEY`
- `AERA_CLOUD_INTERNAL_ADMIN_SERVER_CERT_FILE_HOST`
- `AERA_CLOUD_INTERNAL_ADMIN_SERVER_KEY_FILE_HOST`
- `AERA_CLOUD_INTERNAL_ADMIN_CLIENT_CA_FILE_HOST`
- `AERA_CLOUD_INTERNAL_ADMIN_JWT_PUBLIC_KEY_FILE_HOST`

The four Internal Admin trust files are mounted read-only. The application
listens on `127.0.0.1:18086` at the host boundary; its port 8443 listener is
reachable only as `aera-cloud-internal-admin` on the existing external
`aera-cloud-admin-private` container network.

Keep the environment file, private keys, certificates, deployment state, and
candidate evidence under owner-only directories. Do not print, source, upload,
or commit the environment file.

## HTTPS IP ingress

Install the reviewed Caddy configuration at `/etc/caddy/Caddyfile`. Supply
`AERA_INTERNAL_BETA_IP` and `AERA_INTERNAL_BETA_CERTIFICATE_NAME` through the
Caddy service environment.

Port 80 serves only `/.well-known/acme-challenge/` from
`/var/lib/aera-certbot`; all other requests redirect to HTTPS. Port 443 uses
the Certbot-managed IP certificate, rejects `/admin` and every `/admin/*`
request with 404, and proxies all remaining traffic only to
`127.0.0.1:18086`. The Admin UI is available exclusively through its separate
SSH loopback tunnel. Request access logging is deliberately omitted because
OAuth start URLs contain short-lived state and public device metadata.

Certificate issuance and renewal belong to the host ceremony. A certificate
that is expired or has less than the required validity window is not healthy.
Moving from the IP to a filed domain is a new issuer ceremony and requires a
new Desktop trust map plus tester reauthentication.

## First deployment

Create the private Admin network once:

```sh
docker network inspect aera-cloud-admin-private >/dev/null 2>&1 ||
  docker network create --internal aera-cloud-admin-private
```

Export only non-secret operator paths and exact reviewed identity:

```sh
export AERA_INTERNAL_BETA_PUBLIC_ORIGIN=https://IP_ADDRESS
export AERA_INTERNAL_BETA_STATE_DIR=/var/lib/aera/internal-beta/cloud
export AERA_INTERNAL_BETA_COMPOSE_FILE=/opt/aera/internal-beta/cloud/compose.internal-beta.yaml
export AERA_CLOUD_ENV_FILE=/etc/aera/internal-beta/cloud.env
export AERA_INTERNAL_BETA_EXPECTED_SHA=EXACT_40_CHARACTER_SOURCE_SHA
```

The candidate workflow identity and OIDC issuer default to the exact
`bignormal/aera-cloud` `candidate.yml` workflow on `main` and GitHub Actions.
Do not broaden the certificate identity regular expression.

Deploy with every user-facing feature disabled. The generated configuration
keeps the selected mode as `direct` so no SMTP/SMS provider is constructed,
while `AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false` keeps the registration
endpoint closed:

```sh
/opt/aera/internal-beta/cloud/deploy/internal-beta/deploy.sh \
  deploy /opt/aera/internal-beta/candidates/cloud/manifest.json
```

This starts PostgreSQL, Redis, MinIO, creates the ciphertext bucket, runs
forward-only Cloud startup/migrations, checks public HTTPS health, checks the
public capability document, verifies the offline-entitlement public key when
its expected ID/key are supplied, and rejects unintended public listeners.
Only after those checks succeed is the exact candidate recorded as current.

Inspect the redacted state; it contains only source/image identities,
timestamps, generated feature status, and a relative evidence path:

```sh
jq . /var/lib/aera/internal-beta/cloud/deployment-state.json
```

## Enable the approved internal features

After Cloud health, schema, HTTPS, and trust-root probes pass, enable direct
registration, Official Agent, quality, and encrypted backup for the exact same
manifest:

```sh
/opt/aera/internal-beta/cloud/deploy/internal-beta/deploy.sh \
  enable /opt/aera/internal-beta/candidates/cloud/manifest.json
```

To enable the separately approved phone-only verification mode, set the
operator choice only for the `enable` command:

```sh
AERA_INTERNAL_BETA_REGISTRATION_MODE=verified \
  /opt/aera/internal-beta/cloud/deploy/internal-beta/deploy.sh \
  enable /opt/aera/internal-beta/candidates/cloud/manifest.json
```

The generated public capability must then report
`registration_mode=verified`, `registration_identity_kinds=["phone"]`, and
`identity_verification_available=true`. The deploy and rollback disabled phases
remain in backward-compatible direct mode so the previously signed candidate
can still be restored without requiring the new provider configuration.

The generated feature file is replaced atomically and remains owner-only. An
enabled smoke failure immediately recreates the same digest with all four
features disabled. It never records a successful enablement after a failed
smoke.

## Update and rollback

An update repeats `deploy MANIFEST_JSON` with a new reviewed SHA. The currently
recorded candidate is reverified first. The update is accepted only when that
recorded image can run the candidate's forward schema. A failed update is
automatically returned to the recorded current digest with all features
disabled; a failed first deployment is stopped and is never recorded.

After a successful update, manual rollback takes no image, tag, digest, or
manifest argument:

```sh
/opt/aera/internal-beta/cloud/deploy/internal-beta/deploy.sh rollback
```

It can use only the signed previous candidate already stored in deployment
state. It rechecks signature and schema compatibility, preserves the forward
schema, performs no down migration, disables every feature, and writes
redacted rollback evidence.

## Required checks

Run after each host change and after reboot:

```sh
AERA_INTERNAL_BETA_EXPECT_FEATURES=enabled \
  AERA_INTERNAL_BETA_EXPECT_REGISTRATION_MODE=verified \
  /opt/aera/internal-beta/cloud/deploy/internal-beta/health-smoke.sh
/opt/aera/internal-beta/cloud/deploy/internal-beta/exposure-check.sh
```

Expected public host listeners are SSH, HTTP, and HTTPS only. A public Docker
mapping or a published PostgreSQL, Redis, MinIO, Internal Admin, or Docker API
port is a release stop. The application mapping must remain loopback-only.

Database, Redis, and MinIO volumes are persistent and separate. Never delete
them as an application rollback step. Backup and restore verification are
separate operational gates before destructive host maintenance.
