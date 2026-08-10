#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
compose_file="$repo_root/deploy/compose.internal-beta.yaml"
caddy_file="$repo_root/deploy/internal-beta/Caddyfile"
deploy_script="$repo_root/deploy/internal-beta/deploy.sh"
health_script="$repo_root/deploy/internal-beta/health-smoke.sh"
exposure_script="$repo_root/deploy/internal-beta/exposure-check.sh"

fail() {
  printf 'internal beta deploy test failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  [[ -f $1 ]] || fail "missing ${1#"$repo_root/"}"
}

require_text() {
  local file=$1
  local pattern=$2
  grep -Eq "$pattern" "$file" ||
    fail "${file#"$repo_root/"} does not match $pattern"
}

forbid_text() {
  local file=$1
  local pattern=$2
  if grep -Eq "$pattern" "$file"; then
    fail "${file#"$repo_root/"} unexpectedly matches $pattern"
  fi
}

for file in \
  "$compose_file" \
  "$caddy_file" \
  "$deploy_script" \
  "$health_script" \
  "$exposure_script"; do
  require_file "$file"
done

# Static topology and hardening contract.
require_text "$compose_file" 'image: \$\{AGENTERA_CLOUD_IMAGE_DIGEST:\?'
require_text "$compose_file" 'AGENTERA_CLOUD_ENVIRONMENT: internal_beta'
require_text "$compose_file" '127\.0\.0\.1:\$\{AERA_CLOUD_HTTP_PORT:-18086\}:8086'
require_text "$compose_file" 'AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR: 0\.0\.0\.0:8443'
require_text "$compose_file" 'AGENTERA_CLOUD_FEATURE_ENV_FILE'
require_text "$compose_file" 'read_only: true'
require_text "$compose_file" 'cap_drop: \[ALL\]'
require_text "$compose_file" 'cpus: "[0-9]'
require_text "$compose_file" 'mem_limit: [0-9]'
require_text "$compose_file" 'encrypted-backup-minio:'
require_text "$compose_file" 'MC_CONFIG_DIR: /tmp/\.mc'
require_text "$compose_file" 'aera-cloud-minio-internal-beta:/data'
require_text "$compose_file" 'aera-cloud-admin-private:'
require_text "$compose_file" 'external: true'
require_text "$compose_file" 'aera-cloud-ingress:'
require_text "$compose_file" 'name: aera-cloud-ingress-internal-beta'
require_text "$compose_file" 'internal: false'
[[ $(grep -Ec '^[[:space:]]+aera-cloud-ingress:$' "$compose_file") -eq 2 ]] ||
  fail 'loopback ingress network must be attached only to the Cloud app'
require_text "$compose_file" 'condition: service_healthy'
require_text "$compose_file" '/health/ready'
[[ $(grep -Ec 'internal-admin-(server|client|jwt).+:ro$' "$compose_file") -ge 4 ]] ||
  fail 'Internal Admin trust files are not all mounted read-only'
forbid_text "$compose_file" '^[[:space:]]+build:'
for port in 5432 6379 9000 9001 8443; do
  forbid_text "$compose_file" "^[[:space:]]+- [\"']?[^#]*:${port}(:|[\"']?$)"
done

# The IP certificate challenge is served on port 80; all other HTTP traffic is
# redirected, and only loopback Cloud ingress is proxied without access logs.
require_text "$caddy_file" 'http://\{\$AERA_INTERNAL_BETA_IP\}'
# Bare-IP clients cannot send SNI, so the IP certificate must be the default.
require_text "$caddy_file" 'default_sni \{\$AERA_INTERNAL_BETA_IP\}'
require_text "$caddy_file" '/\.well-known/acme-challenge/\*'
require_text "$caddy_file" 'root \* /var/lib/aera-certbot'
require_text "$caddy_file" 'redir https://\{\$AERA_INTERNAL_BETA_IP\}\{uri\}'
# Caddy sorts a top-level `redir` ahead of `handle`, regardless of source order.
# Keep the redirect in a fallback handle so the ACME handler remains reachable.
require_text "$caddy_file" $'^\thandle \\{$'
require_text "$caddy_file" $'^\t\tredir https://\\{\\$AERA_INTERNAL_BETA_IP\\}\\{uri\\} permanent$'
forbid_text "$caddy_file" $'^\tredir https://\\{\\$AERA_INTERNAL_BETA_IP\\}\\{uri\\} permanent$'
require_text "$caddy_file" 'tls /etc/letsencrypt/live/\{\$AERA_INTERNAL_BETA_CERTIFICATE_NAME\}/fullchain\.pem /etc/letsencrypt/live/\{\$AERA_INTERNAL_BETA_CERTIFICATE_NAME\}/privkey\.pem'
require_text "$caddy_file" 'X-Frame-Options "DENY"'
require_text "$caddy_file" "Content-Security-Policy \"frame-ancestors 'none'\""
require_text "$caddy_file" '@private_admin path /admin /admin/\*'
require_text "$caddy_file" 'respond @private_admin 404'
require_text "$caddy_file" '@desktop_update_metadata path /desktop-updates/internal-beta/manifest\.json /desktop-updates/internal-beta/manifest\.sig'
require_text "$caddy_file" 'Cache-Control "no-store"'
require_text "$caddy_file" 'root \* /var/lib/aera/desktop-updates/internal-beta/current'
require_text "$caddy_file" '@desktop_update_release path /desktop-updates/internal-beta/releases/\*'
require_text "$caddy_file" 'Cache-Control "public, max-age=31536000, immutable"'
require_text "$caddy_file" '@runtime_update_metadata path /runtime-updates/stable/agentera-runtime-stable\.index\.json /runtime-updates/stable/agentera-runtime-stable\.index\.sig'
require_text "$caddy_file" 'root \* /var/lib/aera/runtime-updates/stable/current'
require_text "$caddy_file" '@runtime_update_release path /runtime-updates/stable/releases/\*'
require_text "$caddy_file" 'root \* /var/lib/aera/runtime-updates/stable'
require_text "$caddy_file" 'reverse_proxy 127\.0\.0\.1:18086'
forbid_text "$caddy_file" '^[[:space:]]*log[[:space:]]*\{'

# Caddy can retain a failed active-health result while the app is starting.
# The public smoke must tolerate that bounded propagation window instead of
# rejecting an otherwise healthy first deployment.
require_text "$health_script" '\-\-retry 15'
require_text "$health_script" '\-\-retry-delay 2'
require_text "$health_script" '\-\-retry-max-time 45'
require_text "$health_script" '\-\-retry-all-errors'
require_text "$health_script" '\-\-retry-connrefused'

tmp=$(mktemp -d "${TMPDIR:-/tmp}/aera-cloud-internal-beta.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/state" "$tmp/evidence"
command_log="$tmp/commands.log"
export AERA_INTERNAL_BETA_TEST_LOG="$command_log"

digest() {
  local character=$1
  printf 'sha256:'
  for _ in {1..64}; do
    printf '%s' "$character"
  done
}

manifest() {
  local directory=$1
  local sha=$2
  local image_digest=$3
  local highest=$4
  mkdir -p "$directory"
  jq -cnS \
    --arg sha "$sha" \
    --arg digest "$image_digest" \
    --arg reference "ghcr.io/bignormal/aera-cloud@$image_digest" \
    --argjson highest "$highest" \
    '{
      schemaVersion: 1,
      repository: "bignormal/aera-cloud",
      commitSha: $sha,
      image: {reference: $reference, digest: $digest},
      schema: {minimum: 17, maximum: 20, highestMigration: $highest}
    }' >"$directory/manifest.json"
  printf '\n' >>"$directory/manifest.json"
}

cat >"$tmp/bin/cosign" <<'SH'
#!/bin/sh
set -eu
printf 'cosign %s\n' "$*" >>"$AERA_INTERNAL_BETA_TEST_LOG"
SH

cat >"$tmp/bin/verify" <<'SH'
#!/bin/sh
set -eu
manifest=$1
printf 'verify %s\n' "$(jq -r '.image.digest' "$manifest")" >>"$AERA_INTERNAL_BETA_TEST_LOG"
cosign verify "$(jq -r '.image.reference' "$manifest")"
test "$(jq -r '.commitSha' "$manifest")" = "$AERA_RELEASE_EXPECTED_SHA"
printf 'candidate verified\n'
SH

cat >"$tmp/bin/docker" <<'SH'
#!/bin/sh
set -eu
printf 'docker image=%s %s\n' "${AGENTERA_CLOUD_IMAGE_DIGEST:-none}" "$*" \
  >>"$AERA_INTERNAL_BETA_TEST_LOG"
if test "${1:-}" = compose; then
  case " $* " in
    *" up "*)
      printf '%s\n' "$AGENTERA_CLOUD_IMAGE_DIGEST" >"$AERA_INTERNAL_BETA_STATE_DIR/test-running-image"
      ;;
  esac
fi
SH

cat >"$tmp/bin/curl" <<'SH'
#!/bin/sh
set -eu
printf 'curl %s\n' "$*" >>"$AERA_INTERNAL_BETA_TEST_LOG"
if test "${AERA_INTERNAL_BETA_FAIL_ENABLED_SMOKE:-0}" = 1 &&
  grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=true$' \
    "$AERA_INTERNAL_BETA_STATE_DIR/feature-flags.env"; then
  exit 22
fi
if test -n "${AERA_INTERNAL_BETA_FAIL_IMAGE:-}" &&
  test -f "$AERA_INTERNAL_BETA_STATE_DIR/test-running-image" &&
  test "$(cat "$AERA_INTERNAL_BETA_STATE_DIR/test-running-image")" = "$AERA_INTERNAL_BETA_FAIL_IMAGE"; then
  exit 22
fi
printf '{"status":"ok"}\n'
SH

cat >"$tmp/bin/health" <<'SH'
#!/bin/sh
set -eu
curl --fail --silent "$AERA_INTERNAL_BETA_PUBLIC_ORIGIN/health/ready" >/dev/null
SH

cat >"$tmp/bin/exposure" <<'SH'
#!/bin/sh
set -eu
printf 'exposure\n' >>"$AERA_INTERNAL_BETA_TEST_LOG"
SH

chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH"

sha_a=$(printf 'a%.0s' {1..40})
sha_b=$(printf 'b%.0s' {1..40})
digest_a=$(digest a)
digest_b=$(digest b)
reference_a="ghcr.io/bignormal/aera-cloud@$digest_a"
reference_b="ghcr.io/bignormal/aera-cloud@$digest_b"
manifest "$tmp/evidence/a" "$sha_a" "$digest_a" 18
manifest "$tmp/evidence/b" "$sha_b" "$digest_b" 19
printf 'services: {}\n' >"$tmp/compose.yaml"
printf 'fixture only\n' >"$tmp/cloud.env"

export AERA_INTERNAL_BETA_STATE_DIR="$tmp/state"
export AERA_INTERNAL_BETA_COMPOSE_FILE="$tmp/compose.yaml"
export AERA_INTERNAL_BETA_COMPOSE_PROJECT=aera-internal-beta-test
export AERA_INTERNAL_BETA_VERIFY_COMMAND="$tmp/bin/verify"
export AERA_INTERNAL_BETA_HEALTH_COMMAND="$tmp/bin/health"
export AERA_INTERNAL_BETA_EXPOSURE_COMMAND="$tmp/bin/exposure"
export AERA_INTERNAL_BETA_PUBLIC_ORIGIN=https://192.0.2.10
export AERA_CLOUD_ENV_FILE="$tmp/cloud.env"

# First deployment must verify before Docker receives either pull or up, remain
# feature-disabled, and record only redacted immutable identity.
export AERA_INTERNAL_BETA_EXPECTED_SHA="$sha_a"
"$deploy_script" deploy "$tmp/evidence/a/manifest.json"
feature_file="$tmp/state/feature-flags.env"
state_file="$tmp/state/deployment-state.json"
grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false$' "$feature_file"
grep -q '^AGENTERA_CLOUD_REGISTRATION_MODE=direct$' "$feature_file"
grep -q '^AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=false$' "$feature_file"
grep -q '^AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=false$' "$feature_file"
grep -q '^AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=false$' "$feature_file"
jq -e --arg digest "$digest_a" --arg sha "$sha_a" '
  .environment == "internal_beta" and
  .current.imageDigest == $digest and
  .current.commitSha == $sha and
  .previous == null and
  .features.publicRegistration == false
' "$state_file" >/dev/null
verify_line=$(grep -n "^verify $digest_a$" "$command_log" | head -1 | cut -d: -f1 || true)
pull_line=$(grep -n "docker image=$reference_a .* pull app$" "$command_log" | head -1 | cut -d: -f1 || true)
[[ -n $verify_line && -n $pull_line && $verify_line -lt $pull_line ]] ||
  fail "candidate verification did not occur before image pull: $(tr '\n' ';' <"$command_log")"

# A failed enabled smoke must atomically return the same image to disabled
# operation and must not claim the features were enabled.
export AERA_INTERNAL_BETA_FAIL_ENABLED_SMOKE=1
if "$deploy_script" enable "$tmp/evidence/a/manifest.json" \
  >"$tmp/enable.out" 2>"$tmp/enable.err"; then
  fail 'failed enabled smoke unexpectedly succeeded'
fi
unset AERA_INTERNAL_BETA_FAIL_ENABLED_SMOKE
grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false$' "$feature_file"
grep -q '^AGENTERA_CLOUD_REGISTRATION_MODE=direct$' "$feature_file"
jq -e '.features.publicRegistration == false and .features.encryptedBackup == false' \
  "$state_file" >/dev/null

"$deploy_script" enable "$tmp/evidence/a/manifest.json"
grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=true$' "$feature_file"
grep -q '^AGENTERA_CLOUD_REGISTRATION_MODE=direct$' "$feature_file"
grep -q '^AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=true$' "$feature_file"
grep -q '^AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=true$' "$feature_file"
grep -q '^AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=true$' "$feature_file"
jq -e '.features.publicRegistration == true and .features.encryptedBackup == true' \
  "$state_file" >/dev/null

# An explicitly approved phone-verification rollout keeps the disabled phase
# backward-compatible, then enables only verified phone registration.
export AERA_INTERNAL_BETA_REGISTRATION_MODE=verified
"$deploy_script" enable "$tmp/evidence/a/manifest.json"
grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=true$' "$feature_file"
grep -q '^AGENTERA_CLOUD_REGISTRATION_MODE=verified$' "$feature_file"
grep -q '^AGENTERA_CLOUD_REGISTRATION_IDENTITY_KINDS=phone$' "$feature_file"
if grep -q '^AGENTERA_CLOUD_DIRECT_REGISTRATION_' "$feature_file"; then
  fail 'verified rollout retained direct-registration limits'
fi
jq -e '.features.publicRegistration == true and .features.registrationMode == "verified"' \
  "$state_file" >/dev/null
unset AERA_INTERNAL_BETA_REGISTRATION_MODE

# A failed update may roll back only to the manifest already recorded as
# current. State remains on A and every feature is disabled after the failure.
export AERA_INTERNAL_BETA_EXPECTED_SHA="$sha_b"
export AERA_INTERNAL_BETA_FAIL_IMAGE="$reference_b"
if "$deploy_script" deploy "$tmp/evidence/b/manifest.json" \
  >"$tmp/update.out" 2>"$tmp/update.err"; then
  fail 'failed candidate update unexpectedly succeeded'
fi
unset AERA_INTERNAL_BETA_FAIL_IMAGE
jq -e --arg digest "$digest_a" '.current.imageDigest == $digest' "$state_file" >/dev/null
grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false$' "$feature_file"
[[ $(tail -n 1 "$tmp/state/test-running-image") == "$reference_a" ]] ||
  fail 'failed update did not return to the recorded current digest'

# A later successful update records A as the sole rollback target. The manual
# rollback command accepts no caller-supplied image or manifest.
"$deploy_script" deploy "$tmp/evidence/b/manifest.json"
jq -e --arg current "$digest_b" --arg previous "$digest_a" '
  .current.imageDigest == $current and .previous.imageDigest == $previous
' "$state_file" >/dev/null
"$deploy_script" rollback
jq -e --arg current "$digest_a" --arg previous "$digest_b" '
  .current.imageDigest == $current and .previous.imageDigest == $previous
' "$state_file" >/dev/null

# The real HTTPS smoke accepts the SMTP-free disabled rollout only when the
# server reports direct mode with registration closed, then requires the exact
# enabled capability after rollout.
cat >"$tmp/bin/curl" <<'SH'
#!/bin/sh
set -eu
for argument in "$@"; do
  url=$argument
done
case "$url" in
  */health/live | */health/ready)
    printf '{"status":"ok"}\n'
    ;;
  */api/v1/public/config)
    if test "$AERA_INTERNAL_BETA_HEALTH_FIXTURE" = verified; then
      printf '%s\n' '{"environment":"internal_beta","public_registration_enabled":true,"registration_mode":"verified","registration_identity_kinds":["phone"],"identity_verification_available":true}'
    elif test "$AERA_INTERNAL_BETA_HEALTH_FIXTURE" = enabled; then
      printf '%s\n' '{"environment":"internal_beta","public_registration_enabled":true,"registration_mode":"direct","registration_identity_kinds":["email"],"identity_verification_available":false}'
    else
      printf '%s\n' '{"environment":"internal_beta","public_registration_enabled":false,"registration_mode":"direct","registration_identity_kinds":["email"],"identity_verification_available":false}'
    fi
    ;;
  *)
    exit 22
    ;;
esac
SH
chmod +x "$tmp/bin/curl"
export AERA_INTERNAL_BETA_HEALTH_FIXTURE=disabled
AERA_INTERNAL_BETA_EXPECT_FEATURES=disabled "$health_script"
export AERA_INTERNAL_BETA_HEALTH_FIXTURE=enabled
AERA_INTERNAL_BETA_EXPECT_FEATURES=enabled "$health_script"
export AERA_INTERNAL_BETA_HEALTH_FIXTURE=verified
AERA_INTERNAL_BETA_EXPECT_FEATURES=enabled \
  AERA_INTERNAL_BETA_EXPECT_REGISTRATION_MODE=verified \
  "$health_script"

# Exposure audit: only SSH/HTTP/HTTPS may bind publicly, while application
# ingress may remain on loopback. Both host and Docker data-port leaks fail.
cat >"$tmp/bin/ss" <<'SH'
#!/bin/sh
cat "$AERA_INTERNAL_BETA_SS_FIXTURE"
SH
cat >"$tmp/bin/docker" <<'SH'
#!/bin/sh
cat "$AERA_INTERNAL_BETA_DOCKER_FIXTURE"
SH
chmod +x "$tmp/bin/ss" "$tmp/bin/docker"

cat >"$tmp/ss-good" <<'EOF'
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*
LISTEN 0 4096 [::]:443 [::]:*
LISTEN 0 4096 127.0.0.1:18086 0.0.0.0:*
EOF
printf 'aera-cloud-app\t8443/tcp, 127.0.0.1:18086->8086/tcp\n' >"$tmp/docker-good"
export AERA_INTERNAL_BETA_SS_FIXTURE="$tmp/ss-good"
export AERA_INTERNAL_BETA_DOCKER_FIXTURE="$tmp/docker-good"
"$exposure_script"

cat >"$tmp/ss-bad" <<'EOF'
LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:*
EOF
export AERA_INTERNAL_BETA_SS_FIXTURE="$tmp/ss-bad"
if "$exposure_script" >"$tmp/ss-bad.out" 2>"$tmp/ss-bad.err"; then
  fail 'public PostgreSQL listener unexpectedly passed exposure audit'
fi

printf 'postgres\t127.0.0.1:16379->6379/tcp\n' >"$tmp/docker-bad"
export AERA_INTERNAL_BETA_SS_FIXTURE="$tmp/ss-good"
export AERA_INTERNAL_BETA_DOCKER_FIXTURE="$tmp/docker-bad"
if "$exposure_script" >"$tmp/docker-bad.out" 2>"$tmp/docker-bad.err"; then
  fail 'public Redis container port unexpectedly passed exposure audit'
fi

printf 'internal beta deploy tests passed\n'
