#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
deploy="$root/scripts/release/deploy-by-digest.sh"
rollback="$root/scripts/release/rollback-by-digest.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/aera-cloud-deploy.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/bin" "$tmp/state"
log="$tmp/commands.log"
export AERA_RELEASE_TEST_LOG="$log"

cat > "$tmp/bin/cosign" <<'SH'
#!/bin/sh
set -eu
printf 'cosign %s\n' "$*" >> "$AERA_RELEASE_TEST_LOG"
test "${COSIGN_TEST_FAIL:-0}" = 0
SH
cat > "$tmp/bin/docker" <<'SH'
#!/bin/sh
set -eu
printf 'docker %s\n' "$*" >> "$AERA_RELEASE_TEST_LOG"
SH
for name in backup restore health smoke; do
  cat > "$tmp/bin/$name" <<SH
#!/bin/sh
set -eu
printf '$name\\n' >> "\$AERA_RELEASE_TEST_LOG"
SH
done
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH"

digest() {
  character="$1"
  printf 'sha256:'
  for _ in $(seq 64); do printf '%s' "$character"; done
}

manifest() {
  path="$1"
  sha="$2"
  image_digest="$3"
  minimum="$4"
  maximum="$5"
  highest="$6"
  jq -cnS \
    --arg sha "$sha" \
    --arg digest "$image_digest" \
    --arg image "ghcr.io/bignormal/aera-cloud@$image_digest" \
    --arg sbom "$(digest b)" \
    --arg provenance "$(digest c)" \
    --argjson minimum "$minimum" \
    --argjson maximum "$maximum" \
    --argjson highest "$highest" \
    '{
      schemaVersion:1,
      repository:"bignormal/aera-cloud",
      commitSha:$sha,
      image:{reference:$image,digest:$digest},
      build:{workflow:"Cloud candidate",runUrl:"https://github.com/bignormal/aera-cloud/actions/runs/1234"},
      schema:{minimum:$minimum,maximum:$maximum,highestMigration:$highest},
      supplyChain:{sbomDigest:$sbom,provenanceDigest:$provenance},
      features:{officialQualityEnabledByDefault:false,encryptedBackupEnabledByDefault:false},
      createdAt:"2026-07-23T09:00:00Z"
    }' > "$path"
  printf '\n' >> "$path"
}

current_sha=$(printf 'a%.0s' $(seq 40))
previous_sha=$(printf 'd%.0s' $(seq 40))
manifest "$tmp/current.json" "$current_sha" "$(digest a)" 17 18 18
manifest "$tmp/previous.json" "$previous_sha" "$(digest d)" 17 18 17
printf 'services: {}\n' > "$tmp/compose.yaml"
printf 'production secrets fixture\n' > "$tmp/base.env"

export AERA_RELEASE_MANIFEST="$tmp/current.json"
export AERA_RELEASE_EXPECTED_SHA="$current_sha"
export AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP='^https://github.com/bignormal/aera-cloud/'
export AERA_RELEASE_CERTIFICATE_OIDC_ISSUER=https://token.actions.githubusercontent.com
export AERA_RELEASE_STATE_DIR="$tmp/state"
export AERA_RELEASE_COMPOSE_FILE="$tmp/compose.yaml"
export AGENTERA_CLOUD_ENV_FILE="$tmp/base.env"
export AERA_RELEASE_BACKUP_COMMAND="$tmp/bin/backup"
export AERA_RELEASE_RESTORE_VERIFY_COMMAND="$tmp/bin/restore"
export AERA_RELEASE_HEALTH_COMMAND="$tmp/bin/health"
export AERA_RELEASE_SMOKE_COMMAND="$tmp/bin/smoke"
export AERA_RELEASE_ENVIRONMENT=staging
export AERA_RELEASE_APPROVED_PUBLIC_REGISTRATION=false
export AERA_RELEASE_APPROVED_OFFICIAL_AGENTS=true
export AERA_RELEASE_APPROVED_OFFICIAL_QUALITY=true
export AERA_RELEASE_APPROVED_ENCRYPTED_BACKUP=true
export AERA_RELEASE_ROLLOUT_APPROVED=true

"$deploy" deploy
feature_env="$tmp/state/feature-flags.env"
grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false$' "$feature_env"
grep -q '^AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=false$' "$feature_env"
grep -q '^AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=false$' "$feature_env"
grep -q 'docker compose.* pull app' "$log"
grep -q 'docker compose.* up -d --wait app' "$log"
grep -q '^backup$' "$log"
grep -q '^restore$' "$log"
grep -q '^health$' "$log"
grep -q '^smoke$' "$log"
jq -e '.current.imageDigest == $digest and .environment == "staging"' \
  --arg digest "$(digest a)" "$tmp/state/deployment-state.json" >/dev/null

"$deploy" enable-approved
grep -q '^AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=true$' "$feature_env"
grep -q '^AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=true$' "$feature_env"
grep -q '^AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=true$' "$feature_env"
grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false$' "$feature_env"

jq -cnS \
  --arg digest "$(digest a)" \
  '{current:{imageDigest:$digest}}' > "$tmp/state/deployment-state.json"
cp "$tmp/current.json" "$tmp/state/current-manifest.json"
export AERA_RELEASE_PREVIOUS_MANIFEST="$tmp/previous.json"
export AERA_RELEASE_EXPECTED_SHA="$previous_sha"
export AERA_RELEASE_ROLLBACK_REASON="candidate regression"
export AERA_RELEASE_ROLLBACK_TICKET="OPS-1234"
"$rollback"
grep -q '^AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=false$' "$feature_env"
grep -q '^AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=false$' "$feature_env"
grep -q '^AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=false$' "$feature_env"
jq -e '.rollback.fromDigest == $from and .rollback.toDigest == $to and .rollback.ticket == "OPS-1234"' \
  --arg from "$(digest a)" --arg to "$(digest d)" \
  "$tmp/state/rollback-evidence.json" >/dev/null

jq '.image.reference = "ghcr.io/bignormal/aera-cloud:latest"' \
  "$tmp/current.json" > "$tmp/mutable.json"
export AERA_RELEASE_MANIFEST="$tmp/mutable.json"
export AERA_RELEASE_EXPECTED_SHA="$current_sha"
if "$deploy" deploy >"$tmp/mutable.out" 2>"$tmp/mutable.err"; then
  echo "tag-only deployment unexpectedly passed" >&2
  exit 1
fi

manifest "$tmp/incompatible.json" "$previous_sha" "$(digest e)" 16 17 17
cp "$tmp/current.json" "$tmp/state/current-manifest.json"
export AERA_RELEASE_PREVIOUS_MANIFEST="$tmp/incompatible.json"
export AERA_RELEASE_EXPECTED_SHA="$previous_sha"
if "$rollback" >"$tmp/incompatible.out" 2>"$tmp/incompatible.err"; then
  echo "schema-incompatible rollback unexpectedly passed" >&2
  exit 1
fi

COSIGN_TEST_FAIL=1 "$rollback" >"$tmp/unsigned.out" 2>"$tmp/unsigned.err" &&
  {
    echo "unsigned rollback unexpectedly passed" >&2
    exit 1
  }

printf 'deploy-by-digest tests passed\n'
