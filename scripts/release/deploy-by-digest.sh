#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)

fail() {
  printf 'cloud digest deployment failed: %s\n' "$*" >&2
  exit 1
}

require() {
  name="$1"
  eval "value=\${$name:-}"
  test -n "$value" || fail "$name is required"
}

boolean() {
  case "$2" in
    true|false) printf '%s' "$2" ;;
    *) fail "$1 must be true or false" ;;
  esac
}

write_flags() {
  registration=$(boolean AERA_RELEASE_APPROVED_PUBLIC_REGISTRATION "$1")
  official_agents=$(boolean AERA_RELEASE_APPROVED_OFFICIAL_AGENTS "$2")
  official_quality=$(boolean AERA_RELEASE_APPROVED_OFFICIAL_QUALITY "$3")
  encrypted_backup=$(boolean AERA_RELEASE_APPROVED_ENCRYPTED_BACKUP "$4")
  umask 077
  flags_tmp="$feature_env.tmp.$$"
  {
    printf 'AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=%s\n' "$registration"
    printf 'AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=%s\n' "$official_agents"
    printf 'AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=%s\n' "$official_quality"
    printf 'AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=%s\n' "$encrypted_backup"
  } > "$flags_tmp"
  mv "$flags_tmp" "$feature_env"
}

compose() {
  AGENTERA_CLOUD_IMAGE_DIGEST="$image_reference" \
    AGENTERA_CLOUD_FEATURE_ENV_FILE="$feature_env" \
    docker compose \
      --project-name "${AERA_RELEASE_COMPOSE_PROJECT:-agentera-cloud}" \
      -f "$AERA_RELEASE_COMPOSE_FILE" "$@"
}

test "$#" -eq 1 || fail "usage: deploy-by-digest.sh deploy|enable-approved"
mode="$1"
case "$mode" in deploy|enable-approved) ;; *) fail "unknown mode $mode" ;; esac

for name in \
  AERA_RELEASE_MANIFEST \
  AERA_RELEASE_EXPECTED_SHA \
  AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP \
  AERA_RELEASE_CERTIFICATE_OIDC_ISSUER \
  AERA_RELEASE_STATE_DIR \
  AERA_RELEASE_COMPOSE_FILE \
  AERA_RELEASE_ENVIRONMENT \
  AGENTERA_CLOUD_ENV_FILE \
  AERA_RELEASE_HEALTH_COMMAND \
  AERA_RELEASE_SMOKE_COMMAND
do
  require "$name"
done
case "$AERA_RELEASE_ENVIRONMENT" in staging|production) ;; *)
  fail "AERA_RELEASE_ENVIRONMENT must be staging or production"
esac
test -f "$AERA_RELEASE_COMPOSE_FILE" || fail "Compose file is missing"
test -f "$AGENTERA_CLOUD_ENV_FILE" || fail "base secret environment file is missing"

"$root/scripts/release/verify-manifest.sh" "$AERA_RELEASE_MANIFEST"
image_reference=$(jq -r '.image.reference' "$AERA_RELEASE_MANIFEST")
image_digest=$(jq -r '.image.digest' "$AERA_RELEASE_MANIFEST")
commit_sha=$(jq -r '.commitSha' "$AERA_RELEASE_MANIFEST")

state_dir="$AERA_RELEASE_STATE_DIR"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
feature_env="$state_dir/feature-flags.env"
state_file="$state_dir/deployment-state.json"
current_manifest="$state_dir/current-manifest.json"
previous_manifest="$state_dir/previous-manifest.json"

if test "$mode" = "enable-approved"; then
  test "${AERA_RELEASE_ROLLOUT_APPROVED:-false}" = "true" ||
    fail "explicit rollout approval is required"
  test -f "$state_file" && test -f "$current_manifest" ||
    fail "no disabled deployment is available for rollout"
  state_digest=$(jq -r '.current.imageDigest' "$state_file")
  test "$state_digest" = "$image_digest" ||
    fail "rollout manifest differs from the disabled deployment"
  write_flags \
    "${AERA_RELEASE_APPROVED_PUBLIC_REGISTRATION:-false}" \
    "${AERA_RELEASE_APPROVED_OFFICIAL_AGENTS:-false}" \
    "${AERA_RELEASE_APPROVED_OFFICIAL_QUALITY:-false}" \
    "${AERA_RELEASE_APPROVED_ENCRYPTED_BACKUP:-false}"
  if ! (
    compose up -d --wait app &&
    "$AERA_RELEASE_HEALTH_COMMAND" &&
    "$AERA_RELEASE_SMOKE_COMMAND"
  ); then
    write_flags false false false false
    if ! (
      compose up -d --wait app &&
      "$AERA_RELEASE_HEALTH_COMMAND" &&
      "$AERA_RELEASE_SMOKE_COMMAND"
    ); then
      compose stop app >/dev/null 2>&1 || true
      fail "approved rollout failed, disable rollback failed, and the service was stopped"
    fi
    jq -cS \
      '.features = {
        publicRegistration: false,
        officialAgents: false,
        officialQuality: false,
        encryptedBackup: false
      }' "$state_file" > "$state_file.tmp"
    mv "$state_file.tmp" "$state_file"
    chmod 600 "$state_file" "$feature_env"
    fail "approved rollout failed and was returned to disabled"
  fi
  jq -cS \
    --argjson registration "${AERA_RELEASE_APPROVED_PUBLIC_REGISTRATION:-false}" \
    --argjson officialAgents "${AERA_RELEASE_APPROVED_OFFICIAL_AGENTS:-false}" \
    --argjson officialQuality "${AERA_RELEASE_APPROVED_OFFICIAL_QUALITY:-false}" \
    --argjson encryptedBackup "${AERA_RELEASE_APPROVED_ENCRYPTED_BACKUP:-false}" \
    '.features = {
      publicRegistration: $registration,
      officialAgents: $officialAgents,
      officialQuality: $officialQuality,
      encryptedBackup: $encryptedBackup
    }' "$state_file" > "$state_file.tmp"
  mv "$state_file.tmp" "$state_file"
  printf 'cloud rollout flags applied to %s\n' "$image_digest"
  exit 0
fi

for name in AERA_RELEASE_BACKUP_COMMAND AERA_RELEASE_RESTORE_VERIFY_COMMAND; do
  require "$name"
done
if test -f "$current_manifest"; then
  cp "$current_manifest" "$previous_manifest"
fi
write_flags false false false false
"$AERA_RELEASE_BACKUP_COMMAND"
"$AERA_RELEASE_RESTORE_VERIFY_COMMAND"
compose pull app
compose up -d --wait app
"$AERA_RELEASE_HEALTH_COMMAND"
"$AERA_RELEASE_SMOKE_COMMAND"

previous_digest=null
if test -f "$previous_manifest"; then
  previous_digest=$(jq -r '.image.digest' "$previous_manifest")
fi
deployed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cnS \
  --arg environment "$AERA_RELEASE_ENVIRONMENT" \
  --arg commitSha "$commit_sha" \
  --arg imageReference "$image_reference" \
  --arg imageDigest "$image_digest" \
  --arg previousDigest "$previous_digest" \
  --arg deployedAt "$deployed_at" \
  '{
    environment: $environment,
    current: {
      commitSha: $commitSha,
      imageReference: $imageReference,
      imageDigest: $imageDigest,
      deployedAt: $deployedAt
    },
    previousImageDigest: (
      if $previousDigest == "null" then null else $previousDigest end
    ),
    features: {
      publicRegistration: false,
      officialAgents: false,
      officialQuality: false,
      encryptedBackup: false
    }
  }' > "$state_file.tmp"
mv "$state_file.tmp" "$state_file"
cp "$AERA_RELEASE_MANIFEST" "$current_manifest"
chmod 600 "$state_file" "$current_manifest" "$feature_env"
printf 'cloud image deployed disabled: %s\n' "$image_digest"
