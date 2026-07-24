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
case "$1" in
  verify-attestation)
    for argument in "$@"; do image_reference=$argument; done
    predicate=
    for candidate in "$COSIGN_TEST_ROOT"/*; do
      test -f "$candidate/manifest.json" || continue
      if jq -e --arg image "$image_reference" '.image.reference == $image' \
        "$candidate/manifest.json" >/dev/null; then
        predicate="$candidate/provenance.json"
        break
      fi
    done
    test -f "$predicate"
    digest=${image_reference##*@sha256:}
    image=${image_reference%@*}
    statement=$(jq -cn \
      --arg image "$image" \
      --arg digest "$digest" \
      --slurpfile predicate "$predicate" \
      '{
        _type:"https://in-toto.io/Statement/v0.1",
        subject:[{name:$image,digest:{sha256:$digest}}],
        predicateType:"https://slsa.dev/provenance/v1",
        predicate:$predicate[0]
      }')
    payload=$(printf '%s' "$statement" | base64 | tr -d '\n')
    jq -cn --arg payload "$payload" '{payload:$payload}'
    ;;
  verify-blob)
    bundle=
    previous=
    for argument in "$@"; do
      if test "$previous" = "--bundle"; then bundle=$argument; fi
      previous=$argument
    done
    jq -e '.valid == true' "$bundle" >/dev/null
    ;;
esac
SH
cat > "$tmp/bin/docker" <<'SH'
#!/bin/sh
set -eu
printf 'docker %s\n' "$*" >> "$AERA_RELEASE_TEST_LOG"
SH
for name in backup restore health smoke; do
  failure_check=:
  if test "$name" = smoke; then
    failure_check='if test "${SMOKE_TEST_FAIL:-0}" = 1 &&
  grep -q "^AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=true$" \
    "$AERA_RELEASE_STATE_DIR/feature-flags.env"; then
  exit 1
fi'
  fi
  cat > "$tmp/bin/$name" <<SH
#!/bin/sh
set -eu
printf '$name\\n' >> "\$AERA_RELEASE_TEST_LOG"
$failure_check
SH
done
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH"
export COSIGN_TEST_ROOT="$tmp"

digest() {
  character="$1"
  printf 'sha256:'
  for _ in $(seq 64); do printf '%s' "$character"; done
}

manifest() {
  directory="$1"
  sha="$2"
  image_digest="$3"
  minimum="$4"
  maximum="$5"
  highest="$6"
  mkdir -p "$directory"
  path="$directory/manifest.json"
  printf '{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3"}\n' \
    > "$directory/sbom.spdx.json"
  AERA_PROVENANCE_REPOSITORY=bignormal/aera-cloud \
  AERA_PROVENANCE_SOURCE_SHA="$sha" \
  AERA_PROVENANCE_WORKFLOW_PATH=.github/workflows/candidate.yml \
  AERA_PROVENANCE_WORKFLOW_REF=refs/heads/main \
  AERA_PROVENANCE_RUN_URL=https://github.com/bignormal/aera-cloud/actions/runs/1234 \
  AERA_PROVENANCE_BUILDER_ID=https://github.com/bignormal/aera-cloud/.github/workflows/candidate.yml@refs/heads/main \
  AERA_PROVENANCE_IMAGE_DIGEST="$image_digest" \
  AERA_PROVENANCE_IMAGE_REFERENCE="ghcr.io/bignormal/aera-cloud@$image_digest" \
    "$root/scripts/release/build-provenance.sh" "$directory/provenance.json"
  sbom_digest="sha256:$(sha256sum "$directory/sbom.spdx.json" | cut -d' ' -f1)"
  provenance_digest="sha256:$(sha256sum "$directory/provenance.json" | cut -d' ' -f1)"
  jq -cnS \
    --arg sha "$sha" \
    --arg digest "$image_digest" \
    --arg image "ghcr.io/bignormal/aera-cloud@$image_digest" \
    --arg sbom "$sbom_digest" \
    --arg provenance "$provenance_digest" \
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
  printf '{"valid":true}\n' > "$directory/manifest.sigstore.json"
}

current_sha=$(printf 'a%.0s' $(seq 40))
previous_sha=$(printf 'd%.0s' $(seq 40))
manifest "$tmp/current" "$current_sha" "$(digest a)" 17 19 19
manifest "$tmp/previous" "$previous_sha" "$(digest d)" 17 19 18
printf 'services: {}\n' > "$tmp/compose.yaml"
printf 'production secrets fixture\n' > "$tmp/base.env"

export AERA_RELEASE_MANIFEST="$tmp/current/manifest.json"
export AERA_RELEASE_EXPECTED_SHA="$current_sha"
export AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP='^https://github\.com/bignormal/aera-cloud/\.github/workflows/candidate\.yml@refs/heads/main$'
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

export SMOKE_TEST_FAIL=1
if "$deploy" enable-approved >"$tmp/enable-failure.out" 2>"$tmp/enable-failure.err"; then
  echo "failed Cloud rollout unexpectedly remained enabled" >&2
  exit 1
fi
grep -q '^AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=false$' "$feature_env"
grep -q '^AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=false$' "$feature_env"
grep -q '^AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=false$' "$feature_env"
jq -e '
  .features.publicRegistration == false and
  .features.officialAgents == false and
  .features.officialQuality == false and
  .features.encryptedBackup == false
' "$tmp/state/deployment-state.json" >/dev/null
unset SMOKE_TEST_FAIL

"$deploy" enable-approved
grep -q '^AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=true$' "$feature_env"
grep -q '^AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=true$' "$feature_env"
grep -q '^AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=true$' "$feature_env"
grep -q '^AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false$' "$feature_env"

jq -cnS \
  --arg digest "$(digest a)" \
  '{current:{imageDigest:$digest}}' > "$tmp/state/deployment-state.json"
cp "$tmp/current/manifest.json" "$tmp/state/current-manifest.json"
export AERA_RELEASE_PREVIOUS_MANIFEST="$tmp/previous/manifest.json"
export AERA_RELEASE_EXPECTED_SHA="$previous_sha"
export AERA_RELEASE_ROLLBACK_REASON="candidate regression"
export AERA_RELEASE_ROLLBACK_TICKET="OPS-1234"
export AERA_RELEASE_REHEARSAL_RESTORE_CURRENT=true
export AERA_RELEASE_CURRENT_MANIFEST="$tmp/current/manifest.json"
export AERA_RELEASE_EXPECTED_CURRENT_SHA="$current_sha"
"$rollback"
grep -q '^AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=false$' "$feature_env"
grep -q '^AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=false$' "$feature_env"
grep -q '^AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=false$' "$feature_env"
jq -e '
  .rollback.fromDigest == $from and
  .rollback.toDigest == $to and
  .rollback.ticket == "OPS-1234" and
  .rollback.featuresDisabledBeforeRollback == true
' \
  --arg from "$(digest a)" --arg to "$(digest d)" \
  "$tmp/state/rollback-evidence.json" >/dev/null
jq -e '
  .environment == "staging" and
  .restoredFromDigest == $from and
  .restoredToDigest == $to and
  .healthAfterRestore == "passed"
' --arg from "$(digest d)" --arg to "$(digest a)" \
  "$tmp/state/rehearsal-restore-evidence.json" >/dev/null
jq -e '
  .environment == "staging" and
  .current.imageDigest == $digest and
  .features.officialAgents == false and
  .features.officialQuality == false and
  .features.encryptedBackup == false
' --arg digest "$(digest a)" "$tmp/state/deployment-state.json" >/dev/null
unset AERA_RELEASE_REHEARSAL_RESTORE_CURRENT
unset AERA_RELEASE_CURRENT_MANIFEST
unset AERA_RELEASE_EXPECTED_CURRENT_SHA

jq '.image.reference = "ghcr.io/bignormal/aera-cloud:latest"' \
  "$tmp/current/manifest.json" > "$tmp/mutable.json"
export AERA_RELEASE_MANIFEST="$tmp/mutable.json"
export AERA_RELEASE_EXPECTED_SHA="$current_sha"
if "$deploy" deploy >"$tmp/mutable.out" 2>"$tmp/mutable.err"; then
  echo "tag-only deployment unexpectedly passed" >&2
  exit 1
fi

manifest "$tmp/incompatible" "$previous_sha" "$(digest e)" 16 17 17
cp "$tmp/current/manifest.json" "$tmp/state/current-manifest.json"
export AERA_RELEASE_PREVIOUS_MANIFEST="$tmp/incompatible/manifest.json"
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

compose_file="$root/deploy/compose.production.yaml"
grep -q 'AGENTERA_CLOUD_INTERNAL_ADMIN_LISTEN_ADDR: 0.0.0.0:8443' "$compose_file"
grep -q 'aera-cloud-internal-admin' "$compose_file"
grep -q 'aera-cloud-admin-private' "$compose_file"
test "$(grep -c ':ro$' "$compose_file")" -ge 4
if grep -Eq '8443:8443|:8443"' "$compose_file"; then
  echo "Internal Admin listener unexpectedly has a host port" >&2
  exit 1
fi

printf 'deploy-by-digest tests passed\n'
