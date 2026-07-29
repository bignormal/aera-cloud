#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

fail() {
  printf 'internal beta Cloud deployment failed: %s\n' "$1" >&2
  exit 1
}

require_value() {
  local name=$1
  [[ -n ${!name:-} ]] || fail "$name is required"
}

require_file() {
  [[ -f $1 ]] || fail "required file is missing"
}

for command_name in docker jq; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "$command_name is required"
done

mode=${1:-}
case "$mode" in
  deploy | enable)
    [[ $# -eq 2 ]] || fail "usage: ${0##*/} $mode MANIFEST_JSON"
    supplied_manifest=$2
    ;;
  rollback)
    [[ $# -eq 1 ]] || fail "rollback uses only the recorded previous candidate"
    supplied_manifest=
    ;;
  *)
    fail "usage: ${0##*/} deploy MANIFEST_JSON | enable MANIFEST_JSON | rollback"
    ;;
esac

state_dir=${AERA_INTERNAL_BETA_STATE_DIR:-/var/lib/aera/internal-beta/cloud}
compose_file=${AERA_INTERNAL_BETA_COMPOSE_FILE:-"$repo_root/deploy/compose.internal-beta.yaml"}
compose_project=${AERA_INTERNAL_BETA_COMPOSE_PROJECT:-aera-cloud-internal-beta}
verify_command=${AERA_INTERNAL_BETA_VERIFY_COMMAND:-"$repo_root/scripts/release/verify-manifest.sh"}
health_command=${AERA_INTERNAL_BETA_HEALTH_COMMAND:-"$repo_root/deploy/internal-beta/health-smoke.sh"}
exposure_command=${AERA_INTERNAL_BETA_EXPOSURE_COMMAND:-"$repo_root/deploy/internal-beta/exposure-check.sh"}
enabled_registration_mode=${AERA_INTERNAL_BETA_REGISTRATION_MODE:-direct}
case "$enabled_registration_mode" in
  direct | verified) ;;
  *) fail 'AERA_INTERNAL_BETA_REGISTRATION_MODE must be direct or verified' ;;
esac

require_value AERA_INTERNAL_BETA_PUBLIC_ORIGIN
require_value AERA_CLOUD_ENV_FILE
[[ $AERA_INTERNAL_BETA_PUBLIC_ORIGIN =~ ^https://([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] ||
  fail 'AERA_INTERNAL_BETA_PUBLIC_ORIGIN must be an exact HTTPS IPv4 origin'
require_file "$AERA_CLOUD_ENV_FILE"
require_file "$compose_file"
[[ -x $verify_command ]] || fail 'candidate verifier is not executable'
[[ -x $health_command ]] || fail 'health smoke command is not executable'
[[ -x $exposure_command ]] || fail 'exposure command is not executable'

export AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP="${AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP:-^https://github\\.com/bignormal/aera-cloud/\\.github/workflows/candidate\\.yml@refs/heads/main$}"
export AERA_RELEASE_CERTIFICATE_OIDC_ISSUER="${AERA_RELEASE_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
[[ $AERA_RELEASE_CERTIFICATE_OIDC_ISSUER == https://token.actions.githubusercontent.com ]] ||
  fail 'candidate OIDC issuer must be GitHub Actions'

umask 077
mkdir -p "$state_dir/candidates"
chmod 700 "$state_dir" "$state_dir/candidates"
state_file="$state_dir/deployment-state.json"
feature_file="$state_dir/feature-flags.env"
current_manifest_file="$state_dir/current-manifest.json"
previous_manifest_file="$state_dir/previous-manifest.json"

manifest_value() {
  local manifest=$1
  local expression=$2
  jq -er "$expression" "$manifest" 2>/dev/null ||
    fail 'candidate manifest is missing a required identity field'
}

validate_manifest_identity() {
  local manifest=$1
  require_file "$manifest"
  local sha image digest
  sha=$(manifest_value "$manifest" '.commitSha')
  image=$(manifest_value "$manifest" '.image.reference')
  digest=$(manifest_value "$manifest" '.image.digest')
  [[ $sha =~ ^[0-9a-f]{40}$ ]] || fail 'candidate source SHA is invalid'
  [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'candidate digest is not immutable'
  [[ $image == "ghcr.io/bignormal/aera-cloud@$digest" ]] ||
    fail 'candidate image is not the exact Aera Cloud GHCR digest'
}

verify_candidate() {
  local manifest=$1
  local expected_sha=$2
  validate_manifest_identity "$manifest"
  AERA_RELEASE_EXPECTED_SHA="$expected_sha" "$verify_command" "$manifest" >/dev/null
}

candidate_relative_path() {
  local digest=$1
  printf 'candidates/sha256-%s/manifest.json' "${digest#sha256:}"
}

candidate_absolute_path() {
  local relative=$1
  [[ $relative =~ ^candidates/sha256-[0-9a-f]{64}/manifest\.json$ ]] ||
    fail 'recorded candidate path is invalid'
  printf '%s/%s' "$state_dir" "$relative"
}

persist_candidate() {
  local manifest=$1
  local digest=$2
  local relative target source_base source_dir
  relative=$(candidate_relative_path "$digest")
  target=$(candidate_absolute_path "$relative")
  mkdir -p "$(dirname "$target")"
  chmod 700 "$(dirname "$target")"
  install -m 600 "$manifest" "$target.tmp"
  mv "$target.tmp" "$target"

  source_base=${manifest%.json}
  source_dir=$(dirname "$manifest")
  if [[ -f $source_base.sigstore.json ]]; then
    install -m 600 "$source_base.sigstore.json" \
      "$(dirname "$target")/manifest.sigstore.json.tmp"
    mv "$(dirname "$target")/manifest.sigstore.json.tmp" \
      "$(dirname "$target")/manifest.sigstore.json"
  fi
  for evidence in provenance.json sbom.spdx.json; do
    if [[ -f $source_dir/$evidence ]]; then
      install -m 600 "$source_dir/$evidence" "$(dirname "$target")/$evidence.tmp"
      mv "$(dirname "$target")/$evidence.tmp" "$(dirname "$target")/$evidence"
    fi
  done
  printf '%s' "$relative"
}

write_features() {
  local status=$1
  local registration mode official quality backup
  case "$status" in
    disabled)
      registration=false
      mode=direct
      official=false
      quality=false
      backup=false
      ;;
    enabled)
      registration=true
      mode=$enabled_registration_mode
      official=true
      quality=true
      backup=true
      ;;
    *) fail 'internal feature status is invalid' ;;
  esac
  {
    printf 'AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=%s\n' "$registration"
    printf 'AGENTERA_CLOUD_REGISTRATION_MODE=%s\n' "$mode"
    if [[ $mode == verified ]]; then
      printf 'AGENTERA_CLOUD_REGISTRATION_IDENTITY_KINDS=phone\n'
    else
      printf 'AGENTERA_CLOUD_REGISTRATION_IDENTITY_KINDS=email\n'
      printf 'AGENTERA_CLOUD_DIRECT_REGISTRATION_IP_LIMIT=30\n'
      printf 'AGENTERA_CLOUD_DIRECT_REGISTRATION_WINDOW=1h\n'
    fi
    printf 'AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=%s\n' "$official"
    printf 'AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=%s\n' "$quality"
    printf 'AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=%s\n' "$backup"
  } >"$feature_file.tmp"
  chmod 600 "$feature_file.tmp"
  mv "$feature_file.tmp" "$feature_file"
}

feature_json() {
  local status=$1
  if [[ $status == enabled ]]; then
    printf '{"encryptedBackup":true,"officialAgents":true,"officialQuality":true,"publicRegistration":true,"registrationMode":"%s"}' \
      "$enabled_registration_mode"
  else
    printf '%s' '{"encryptedBackup":false,"officialAgents":false,"officialQuality":false,"publicRegistration":false,"registrationMode":"direct"}'
  fi
}

update_recorded_features() {
  local status=$1
  [[ -f $state_file ]] || return 0
  local now features
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  features=$(feature_json "$status")
  jq -cS \
    --arg updatedAt "$now" \
    --argjson features "$features" \
    '.features = $features | .updatedAt = $updatedAt' \
    "$state_file" >"$state_file.tmp"
  chmod 600 "$state_file.tmp"
  mv "$state_file.tmp" "$state_file"
}

compose_image() {
  local image=$1
  shift
  AGENTERA_CLOUD_IMAGE_DIGEST="$image" \
    AGENTERA_CLOUD_FEATURE_ENV_FILE="$feature_file" \
    AERA_CLOUD_ENV_FILE="$AERA_CLOUD_ENV_FILE" \
    AERA_INTERNAL_BETA_PUBLIC_ORIGIN="$AERA_INTERNAL_BETA_PUBLIC_ORIGIN" \
    docker compose \
      --env-file "$AERA_CLOUD_ENV_FILE" \
      --project-name "$compose_project" \
      -f "$compose_file" "$@"
}

start_image() {
  local image=$1
  compose_image "$image" pull app &&
    compose_image "$image" up -d postgres redis encrypted-backup-minio &&
    compose_image "$image" run --rm encrypted-backup-minio-init &&
    compose_image "$image" up -d --force-recreate --wait app
}

check_image() {
  local feature_status=$1
  local expected_registration_mode=direct
  if [[ $feature_status == enabled ]]; then
    expected_registration_mode=$enabled_registration_mode
  fi
  AERA_INTERNAL_BETA_EXPECT_FEATURES="$feature_status" \
    AERA_INTERNAL_BETA_EXPECT_REGISTRATION_MODE="$expected_registration_mode" \
    "$health_command" &&
    "$exposure_command"
}

stop_app() {
  local image=$1
  compose_image "$image" stop app >/dev/null 2>&1 || true
}

state_candidate() {
  local slot=$1
  local relative
  relative=$(jq -er ".$slot.candidateManifest" "$state_file" 2>/dev/null) ||
    fail "recorded $slot candidate is missing"
  candidate_absolute_path "$relative"
}

verify_recorded_slot() {
  local slot=$1
  local manifest sha state_digest manifest_digest
  manifest=$(state_candidate "$slot")
  sha=$(jq -er ".$slot.commitSha" "$state_file")
  state_digest=$(jq -er ".$slot.imageDigest" "$state_file")
  verify_candidate "$manifest" "$sha"
  manifest_digest=$(manifest_value "$manifest" '.image.digest')
  [[ $manifest_digest == "$state_digest" ]] ||
    fail "recorded $slot digest differs from its verified manifest"
  printf '%s' "$manifest"
}

record_deployment() {
  local manifest=$1
  local sha image digest candidate_relative now previous
  sha=$(manifest_value "$manifest" '.commitSha')
  image=$(manifest_value "$manifest" '.image.reference')
  digest=$(manifest_value "$manifest" '.image.digest')
  candidate_relative=$(persist_candidate "$manifest" "$digest")
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if [[ -f $state_file ]]; then
    previous=$(jq -c '.current' "$state_file")
    cp "$current_manifest_file" "$previous_manifest_file.tmp"
    chmod 600 "$previous_manifest_file.tmp"
    mv "$previous_manifest_file.tmp" "$previous_manifest_file"
  else
    previous=null
  fi
  jq -cnS \
    --arg sha "$sha" \
    --arg image "$image" \
    --arg digest "$digest" \
    --arg candidateManifest "$candidate_relative" \
    --arg deployedAt "$now" \
    --argjson previous "$previous" \
    --argjson features "$(feature_json disabled)" '
      {
        schemaVersion: 1,
        environment: "internal_beta",
        current: {
          commitSha: $sha,
          imageReference: $image,
          imageDigest: $digest,
          candidateManifest: $candidateManifest,
          deployedAt: $deployedAt
        },
        previous: $previous,
        features: $features,
        updatedAt: $deployedAt
      }
    ' >"$state_file.tmp"
  chmod 600 "$state_file.tmp"
  mv "$state_file.tmp" "$state_file"
  install -m 600 "$manifest" "$current_manifest_file"
}

deploy_candidate() {
  local manifest=$1
  require_value AERA_INTERNAL_BETA_EXPECTED_SHA
  verify_candidate "$manifest" "$AERA_INTERNAL_BETA_EXPECTED_SHA"
  local image digest previous_manifest previous_image previous_max new_highest
  image=$(manifest_value "$manifest" '.image.reference')
  digest=$(manifest_value "$manifest" '.image.digest')
  previous_manifest=
  previous_image=

  if [[ -f $state_file ]]; then
    previous_manifest=$(verify_recorded_slot current)
    previous_image=$(manifest_value "$previous_manifest" '.image.reference')
    [[ $(manifest_value "$previous_manifest" '.image.digest') != "$digest" ]] ||
      fail 'candidate digest is already current; use enable if appropriate'
    previous_max=$(manifest_value "$previous_manifest" '.schema.maximum')
    new_highest=$(manifest_value "$manifest" '.schema.highestMigration')
    [[ $previous_max =~ ^[0-9]+$ && $new_highest =~ ^[0-9]+$ &&
      $previous_max -ge $new_highest ]] ||
      fail 'recorded image cannot safely run the candidate forward schema'
  fi

  write_features disabled
  update_recorded_features disabled
  if ! start_image "$image" || ! check_image disabled; then
    if [[ -n $previous_image ]]; then
      write_features disabled
      if ! start_image "$previous_image" || ! check_image disabled; then
        stop_app "$previous_image"
        fail 'candidate failed and the recorded digest could not be restored'
      fi
      fail 'candidate failed and was returned to the recorded digest'
    fi
    stop_app "$image"
    fail 'first candidate failed; no deployment was recorded'
  fi

  record_deployment "$manifest"
  printf 'internal beta Cloud deployed disabled: %s\n' "$digest"
}

enable_candidate() {
  local manifest=$1
  require_value AERA_INTERNAL_BETA_EXPECTED_SHA
  [[ -f $state_file ]] || fail 'no disabled deployment is available to enable'
  verify_candidate "$manifest" "$AERA_INTERNAL_BETA_EXPECTED_SHA"
  local supplied_digest current_digest current_image
  supplied_digest=$(manifest_value "$manifest" '.image.digest')
  current_digest=$(jq -er '.current.imageDigest' "$state_file")
  current_image=$(jq -er '.current.imageReference' "$state_file")
  [[ $supplied_digest == "$current_digest" ]] ||
    fail 'enable manifest differs from the recorded current digest'
  verify_recorded_slot current >/dev/null

  write_features enabled
  if ! start_image "$current_image" || ! check_image enabled; then
    write_features disabled
    update_recorded_features disabled
    if ! start_image "$current_image" || ! check_image disabled; then
      stop_app "$current_image"
      fail 'enabled smoke failed and disabled restoration also failed'
    fi
    fail 'enabled smoke failed and the same digest was returned to disabled'
  fi
  update_recorded_features enabled
  printf 'internal beta Cloud features enabled: %s\n' "$current_digest"
}

rollback_recorded() {
  [[ -f $state_file ]] || fail 'deployment state is missing'
  jq -e '.previous != null' "$state_file" >/dev/null ||
    fail 'no recorded previous candidate is available'
  local current_manifest target_manifest current_image current_digest
  local target_image target_digest target_sha target_relative current_highest target_max
  current_manifest=$(verify_recorded_slot current)
  target_manifest=$(verify_recorded_slot previous)
  current_image=$(manifest_value "$current_manifest" '.image.reference')
  current_digest=$(manifest_value "$current_manifest" '.image.digest')
  target_image=$(manifest_value "$target_manifest" '.image.reference')
  target_digest=$(manifest_value "$target_manifest" '.image.digest')
  target_sha=$(manifest_value "$target_manifest" '.commitSha')
  target_relative=$(candidate_relative_path "$target_digest")
  current_highest=$(manifest_value "$current_manifest" '.schema.highestMigration')
  target_max=$(manifest_value "$target_manifest" '.schema.maximum')
  [[ $target_max =~ ^[0-9]+$ && $current_highest =~ ^[0-9]+$ &&
    $target_max -ge $current_highest ]] ||
    fail 'recorded previous image is incompatible with the forward schema'

  write_features disabled
  update_recorded_features disabled
  if ! start_image "$target_image" || ! check_image disabled; then
    write_features disabled
    if ! start_image "$current_image" || ! check_image disabled; then
      stop_app "$current_image"
      fail 'recorded rollback failed and current digest restoration also failed'
    fi
    fail 'recorded rollback failed; current digest was restored disabled'
  fi

  local now old_current
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  old_current=$(jq -c '.current' "$state_file")
  jq -cS \
    --arg sha "$target_sha" \
    --arg image "$target_image" \
    --arg digest "$target_digest" \
    --arg candidateManifest "$target_relative" \
    --arg now "$now" \
    --argjson previous "$old_current" \
    --argjson features "$(feature_json disabled)" '
      .current = {
        commitSha: $sha,
        imageReference: $image,
        imageDigest: $digest,
        candidateManifest: $candidateManifest,
        deployedAt: $now
      } |
      .previous = $previous |
      .features = $features |
      .updatedAt = $now
    ' "$state_file" >"$state_file.tmp"
  chmod 600 "$state_file.tmp"
  mv "$state_file.tmp" "$state_file"
  install -m 600 "$current_manifest" "$previous_manifest_file"
  install -m 600 "$target_manifest" "$current_manifest_file"
  jq -cnS \
    --arg fromDigest "$current_digest" \
    --arg toDigest "$target_digest" \
    --arg rolledBackAt "$now" '
      {
        schemaVersion: 1,
        environment: "internal_beta",
        fromDigest: $fromDigest,
        toDigest: $toDigest,
        rolledBackAt: $rolledBackAt,
        targetSource: "recorded_previous",
        featuresDisabled: true,
        forwardSchemaPreserved: true,
        downMigrationExecuted: false
      }
    ' >"$state_dir/rollback-evidence.json.tmp"
  chmod 600 "$state_dir/rollback-evidence.json.tmp"
  mv "$state_dir/rollback-evidence.json.tmp" "$state_dir/rollback-evidence.json"
  printf 'internal beta Cloud rolled back to recorded digest: %s\n' "$target_digest"
}

case "$mode" in
  deploy) deploy_candidate "$supplied_manifest" ;;
  enable) enable_candidate "$supplied_manifest" ;;
  rollback) rollback_recorded ;;
esac
