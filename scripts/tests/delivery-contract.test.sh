#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

fail() {
  printf 'delivery contract test failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing $1"
}

require_text() {
  local file=$1
  local pattern=$2
  grep -Eq "$pattern" "$file" || fail "$file does not match $pattern"
}

forbid_text() {
  local file=$1
  local pattern=$2
  if grep -Eq "$pattern" "$file"; then
    fail "$file unexpectedly matches $pattern"
  fi
}

for file in \
  Dockerfile \
  deploy/compose.production.yaml \
  deploy/compose.internal-beta.yaml \
  deploy/Caddyfile.example \
  deploy/internal-beta/Caddyfile \
  deploy/internal-beta/deploy.sh \
  deploy/internal-beta/health-smoke.sh \
  deploy/internal-beta/exposure-check.sh \
  deploy/backup.sh \
  deploy/restore-verify.sh \
  docs/runbooks/internal-beta.md \
  docs/runbooks/private-staging.md \
  docs/runbooks/production.md \
  docs/runbooks/key-rotation.md \
  docs/runbooks/account-recovery.md \
  scripts/smoke-auth.sh \
  scripts/check-secrets.sh \
  scripts/release/build-provenance.sh \
  scripts/release/build-manifest.sh \
  scripts/release/verify-manifest.sh \
  scripts/release/deploy-by-digest.sh \
  scripts/release/rollback-by-digest.sh \
  .github/workflows/candidate.yml \
  .github/workflows/deploy-staging.yml \
  .github/workflows/promote-production.yml \
  .github/workflows/rollback-production.yml \
  .github/workflows/ci.yml; do
  require_file "$file"
done

require_text Dockerfile 'npm ci'
require_text Dockerfile 'npm run build'
require_text Dockerfile 'CGO_ENABLED=0'
require_text Dockerfile 'USER [0-9]+'

require_text deploy/compose.production.yaml 'POSTGRES_DB: aera_cloud'
require_text deploy/compose.production.yaml 'POSTGRES_USER: aera_cloud'
require_text deploy/compose.production.yaml 'AGENTERA_CLOUD_REDIS_USERNAME: aera_cloud'
require_text deploy/compose.production.yaml 'AGENTERA_CLOUD_REDIS_DB: "9"'
require_text deploy/compose.production.yaml 'cpus: "0\.[5-9][0-9]*"'
require_text deploy/compose.production.yaml 'mem_limit: (256|320|384|448|512)m'
require_text deploy/compose.production.yaml '127\.0\.0\.1:'
require_text deploy/compose.production.yaml 'AGENTERA_CLOUD_IMAGE_DIGEST'
require_text deploy/compose.production.yaml 'AGENTERA_CLOUD_FEATURE_ENV_FILE'
if grep -Eq '^[[:space:]]+build:' deploy/compose.production.yaml; then
  fail 'production Compose must not rebuild the application image'
fi

require_text deploy/compose.internal-beta.yaml 'AGENTERA_CLOUD_ENVIRONMENT: internal_beta'
require_text deploy/compose.internal-beta.yaml 'AGENTERA_CLOUD_IMAGE_DIGEST'
require_text deploy/compose.internal-beta.yaml '127\.0\.0\.1:'
require_text deploy/compose.internal-beta.yaml 'encrypted-backup-minio'
require_text deploy/compose.internal-beta.yaml 'aera-cloud-admin-private'
require_text deploy/compose.internal-beta.yaml 'read_only: true'
require_text deploy/internal-beta/Caddyfile '/\.well-known/acme-challenge/'
require_text deploy/internal-beta/Caddyfile '@private_admin path /admin /admin/\*'
require_text deploy/internal-beta/Caddyfile 'respond @private_admin 404'
require_text deploy/internal-beta/Caddyfile '@desktop_update_metadata path /desktop-updates/internal-beta/manifest\.json /desktop-updates/internal-beta/manifest\.sig'
require_text deploy/internal-beta/Caddyfile 'root \* /var/lib/aera/desktop-updates/internal-beta/current'
require_text deploy/internal-beta/Caddyfile '@desktop_update_release path /desktop-updates/internal-beta/releases/\*'
require_text deploy/internal-beta/Caddyfile 'Cache-Control "public, max-age=31536000, immutable"'
require_text deploy/internal-beta/Caddyfile 'reverse_proxy 127\.0\.0\.1:18086'
require_text deploy/internal-beta/deploy.sh 'verify-manifest\.sh'
require_text deploy/internal-beta/deploy.sh 'candidate digest is already current'
require_text deploy/internal-beta/deploy.sh 'recorded previous'
require_text deploy/internal-beta/health-smoke.sh 'AERA_INTERNAL_BETA_EXPECT_REGISTRATION_MODE'
require_text deploy/internal-beta/deploy.sh 'AGENTERA_CLOUD_REGISTRATION_IDENTITY_KINDS=phone'
require_text deploy/internal-beta/exposure-check.sh 'unexpected public host listener'
require_text docs/runbooks/internal-beta.md 'default rollout still omits SMTP and SMS'
require_text docs/runbooks/internal-beta.md 'AGENTERA_CLOUD_SMS_PROVIDER=aliyun'
require_text docs/runbooks/internal-beta.md 'takes no image, tag, digest, or'

require_text deploy/backup.sh 'pg_dump'
require_text deploy/backup.sh 'age'
require_text deploy/backup.sh 'umask 077'
require_text deploy/restore-verify.sh 'pg_restore'
require_text deploy/restore-verify.sh 'trap .*drop'
require_text deploy/restore-verify.sh 'verify-identities'

require_text docs/runbooks/private-staging.md '(VPN|SSH tunnel|allowlist)'
require_text README.md 'separate TLS 1\.3 Internal Admin listener'
require_text README.md 'mTLS and a short-lived Ed25519 service JWT'
require_text README.md 'disabled by default'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_ENABLED'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_CERT_FILE'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_SERVER_KEY_FILE'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_CLIENT_CA_FILE'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_PUBLIC_KEY_FILE'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_ISSUER'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_JWT_SUBJECT'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_ACTIVE_KEY_ID'
require_text docs/runbooks/private-staging.md 'AGENTERA_CLOUD_INTERNAL_ADMIN_HMAC_KEYS'
require_text docs/runbooks/private-staging.md 'PostgreSQL remains authoritative'
require_text docs/runbooks/private-staging.md 'does not restore access'
require_text docs/runbooks/private-staging.md 'Apply migration .*000015_internal_admin_api\.sql.*before enabling'
require_text docs/runbooks/private-staging.md 'stop the Internal Admin listener before rolling back'
require_text docs/runbooks/production.md 'public registration'
require_text docs/runbooks/production.md '(privacy policy|Privacy Policy)'
require_text docs/runbooks/key-rotation.md 'desktop.*public.*kid'
require_text docs/runbooks/key-rotation.md 'seven-day|7-day|7 day'
require_text docs/runbooks/key-rotation.md 'cloud-only'
require_text docs/runbooks/account-recovery.md 'local Hermes'

require_text scripts/smoke-auth.sh 'TestSmokeAuthLifecycle'
require_text .github/workflows/ci.yml 'check-secrets\.sh'
require_text .github/workflows/ci.yml 'smoke-auth\.sh'
require_text .github/workflows/ci.yml 'docker build'
require_text .github/workflows/candidate.yml 'inputs\.source_sha'
require_text .github/workflows/candidate.yml 'inputs\.ci_run_id'
require_text .github/workflows/candidate.yml 'docker buildx build'
require_text .github/workflows/candidate.yml 'steps\.image\.outputs\.digest'
require_text .github/workflows/candidate.yml 'syft'
require_text .github/workflows/candidate.yml 'cosign/v3/cmd/cosign@v3\.0\.6'
require_text .github/workflows/candidate.yml 'syft/cmd/syft@v1\.44\.0'
require_text .github/workflows/candidate.yml 'cosign sign --yes'
require_text .github/workflows/candidate.yml 'cosign attest --yes'
require_text .github/workflows/candidate.yml 'cosign sign-blob --yes'
require_text .github/workflows/candidate.yml 'cosign sign --yes --use-signing-config=false --bundle'
require_text .github/workflows/candidate.yml 'cosign attest --yes --use-signing-config=false --type slsaprovenance1'
require_text .github/workflows/candidate.yml 'manifest\.sigstore\.json'
forbid_text .github/workflows/candidate.yml 'actions/attest-build-provenance'
forbid_text .github/workflows/candidate.yml 'attestations:[[:space:]]*write'
require_text .github/workflows/candidate.yml 'build-manifest\.sh'
require_text .github/workflows/candidate.yml 'verify-manifest\.sh'
require_text .github/workflows/candidate.yml 'encrypted-backup-minio'
require_text .github/workflows/candidate.yml 'AERA_RELEASE_SCHEMA_MAX: "20"'
require_text .github/workflows/candidate.yml 'AERA_RELEASE_HIGHEST_MIGRATION: "20"'
require_text scripts/release/verify-manifest.sh 'cosign verify'
require_text scripts/release/verify-manifest.sh 'verify-attestation'
require_text scripts/release/verify-manifest.sh 'verify-blob'
require_text scripts/release/verify-manifest.sh 'slsaprovenance1'
require_text scripts/release/build-manifest.sh 'git status --porcelain'
require_text scripts/release/deploy-by-digest.sh 'verify-manifest\.sh'
require_text scripts/release/deploy-by-digest.sh 'AERA_RELEASE_BACKUP_COMMAND'
require_text scripts/release/deploy-by-digest.sh 'AERA_RELEASE_RESTORE_VERIFY_COMMAND'
require_text scripts/release/deploy-by-digest.sh 'PUBLIC_REGISTRATION_ENABLED'
require_text scripts/release/rollback-by-digest.sh 'previous image is incompatible'
require_text scripts/release/rollback-by-digest.sh 'forwardSchemaPreserved'
require_text .github/workflows/deploy-staging.yml 'environment: staging'
require_text .github/workflows/promote-production.yml 'environment: production'
require_text .github/workflows/promote-production.yml 'deploy-by-digest\.sh deploy'
require_text .github/workflows/promote-production.yml 'deploy-by-digest\.sh enable-approved'
require_text .github/workflows/promote-production.yml 'cloud-production-enabled-'
require_text .github/workflows/promote-production.yml 'deployment-state\.json'
require_text .github/workflows/promote-production.yml 'current-manifest\.json'
require_text .github/workflows/rollback-production.yml 'rollback-by-digest\.sh'
require_text .github/workflows/rollback-production.yml 'target_environment'
require_text .github/workflows/rollback-production.yml 'restore_current_after_rehearsal'
require_text .github/workflows/rollback-production.yml 'AERA_RELEASE_REHEARSAL_RESTORE_CURRENT'
require_text .github/workflows/rollback-production.yml 'rehearsal-restore-evidence\.json'
require_text scripts/release/rollback-by-digest.sh 'healthBefore'
require_text scripts/release/rollback-by-digest.sh 'downMigrationExecuted'

printf 'delivery contract tests passed\n'
