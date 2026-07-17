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

for file in \
  Dockerfile \
  deploy/compose.production.yaml \
  deploy/Caddyfile.example \
  deploy/backup.sh \
  deploy/restore-verify.sh \
  docs/runbooks/private-staging.md \
  docs/runbooks/production.md \
  docs/runbooks/key-rotation.md \
  docs/runbooks/account-recovery.md \
  scripts/smoke-auth.sh \
  scripts/check-secrets.sh \
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

require_text deploy/backup.sh 'pg_dump'
require_text deploy/backup.sh 'age'
require_text deploy/backup.sh 'umask 077'
require_text deploy/restore-verify.sh 'pg_restore'
require_text deploy/restore-verify.sh 'trap .*drop'
require_text deploy/restore-verify.sh 'verify-identities'

require_text docs/runbooks/private-staging.md '(VPN|SSH tunnel|allowlist)'
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

printf 'delivery contract tests passed\n'
