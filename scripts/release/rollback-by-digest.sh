#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)

fail() {
  printf 'cloud digest rollback failed: %s\n' "$*" >&2
  exit 1
}

require() {
  name="$1"
  eval "value=\${$name:-}"
  test -n "$value" || fail "$name is required"
}

for name in \
  AERA_RELEASE_PREVIOUS_MANIFEST \
  AERA_RELEASE_EXPECTED_SHA \
  AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP \
  AERA_RELEASE_CERTIFICATE_OIDC_ISSUER \
  AERA_RELEASE_STATE_DIR \
  AERA_RELEASE_COMPOSE_FILE \
  AERA_RELEASE_ENVIRONMENT \
  AGENTERA_CLOUD_ENV_FILE \
  AERA_RELEASE_BACKUP_COMMAND \
  AERA_RELEASE_RESTORE_VERIFY_COMMAND \
  AERA_RELEASE_HEALTH_COMMAND \
  AERA_RELEASE_SMOKE_COMMAND \
  AERA_RELEASE_ROLLBACK_REASON \
  AERA_RELEASE_ROLLBACK_TICKET
do
  require "$name"
done
case "$AERA_RELEASE_ENVIRONMENT" in staging|production) ;; *)
  fail "AERA_RELEASE_ENVIRONMENT must be staging or production"
esac

restore_current="${AERA_RELEASE_REHEARSAL_RESTORE_CURRENT:-false}"
case "$restore_current" in true|false) ;; *)
  fail "AERA_RELEASE_REHEARSAL_RESTORE_CURRENT must be true or false"
esac
if test "$restore_current" = "true"; then
  test "$AERA_RELEASE_ENVIRONMENT" = "staging" ||
    fail "current-digest restoration is allowed only for a staging rehearsal"
  require AERA_RELEASE_CURRENT_MANIFEST
  require AERA_RELEASE_EXPECTED_CURRENT_SHA
fi

state_dir="$AERA_RELEASE_STATE_DIR"
state_file="$state_dir/deployment-state.json"
current_manifest="$state_dir/current-manifest.json"
feature_env="$state_dir/feature-flags.env"
test -f "$state_file" && test -f "$current_manifest" ||
  fail "current deployment evidence is missing"
test -f "$AERA_RELEASE_PREVIOUS_MANIFEST" ||
  fail "previous candidate manifest is missing"

"$root/scripts/release/verify-manifest.sh" "$AERA_RELEASE_PREVIOUS_MANIFEST"
current_highest=$(jq -r '.schema.highestMigration' "$current_manifest")
previous_maximum=$(jq -r '.schema.maximum' "$AERA_RELEASE_PREVIOUS_MANIFEST")
test "$previous_maximum" -ge "$current_highest" ||
  fail "previous image is incompatible with the current forward schema"

from_digest=$(jq -r '.image.digest' "$current_manifest")
from_reference=$(jq -r '.image.reference' "$current_manifest")
to_digest=$(jq -r '.image.digest' "$AERA_RELEASE_PREVIOUS_MANIFEST")
to_reference=$(jq -r '.image.reference' "$AERA_RELEASE_PREVIOUS_MANIFEST")
to_commit=$(jq -r '.commitSha' "$AERA_RELEASE_PREVIOUS_MANIFEST")
test "$from_digest" != "$to_digest" || fail "rollback target equals current image"
if test "$restore_current" = "true"; then
  AERA_RELEASE_EXPECTED_SHA="$AERA_RELEASE_EXPECTED_CURRENT_SHA" \
    "$root/scripts/release/verify-manifest.sh" "$AERA_RELEASE_CURRENT_MANIFEST"
  rehearsal_current_digest=$(jq -r '.image.digest' "$AERA_RELEASE_CURRENT_MANIFEST")
  test "$rehearsal_current_digest" = "$from_digest" ||
    fail "rehearsal current manifest differs from the deployed image"
fi

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$AERA_RELEASE_HEALTH_COMMAND"
umask 077
cat > "$feature_env.tmp" <<'FLAGS'
AGENTERA_CLOUD_PUBLIC_REGISTRATION_ENABLED=false
AGENTERA_CLOUD_OFFICIAL_AGENTS_ENABLED=false
AGENTERA_CLOUD_OFFICIAL_QUALITY_ENABLED=false
AGENTERA_CLOUD_ENCRYPTED_BACKUP_ENABLED=false
FLAGS
mv "$feature_env.tmp" "$feature_env"

AGENTERA_CLOUD_IMAGE_DIGEST="$from_reference" \
  AGENTERA_CLOUD_FEATURE_ENV_FILE="$feature_env" \
  docker compose \
    --project-name "${AERA_RELEASE_COMPOSE_PROJECT:-agentera-cloud}" \
    -f "$AERA_RELEASE_COMPOSE_FILE" up -d --wait app
"$AERA_RELEASE_HEALTH_COMMAND"
"$AERA_RELEASE_SMOKE_COMMAND"
"$AERA_RELEASE_BACKUP_COMMAND"
"$AERA_RELEASE_RESTORE_VERIFY_COMMAND"
AGENTERA_CLOUD_IMAGE_DIGEST="$to_reference" \
  AGENTERA_CLOUD_FEATURE_ENV_FILE="$feature_env" \
  docker compose \
    --project-name "${AERA_RELEASE_COMPOSE_PROJECT:-agentera-cloud}" \
    -f "$AERA_RELEASE_COMPOSE_FILE" pull app
AGENTERA_CLOUD_IMAGE_DIGEST="$to_reference" \
  AGENTERA_CLOUD_FEATURE_ENV_FILE="$feature_env" \
  docker compose \
    --project-name "${AERA_RELEASE_COMPOSE_PROJECT:-agentera-cloud}" \
    -f "$AERA_RELEASE_COMPOSE_FILE" up -d --wait app
"$AERA_RELEASE_HEALTH_COMMAND"
"$AERA_RELEASE_SMOKE_COMMAND"

rolled_back_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
evidence="$state_dir/rollback-evidence.json"
jq -cnS \
  --arg environment "$AERA_RELEASE_ENVIRONMENT" \
  --arg fromDigest "$from_digest" \
  --arg toDigest "$to_digest" \
  --arg toCommit "$to_commit" \
  --arg reason "$AERA_RELEASE_ROLLBACK_REASON" \
  --arg ticket "$AERA_RELEASE_ROLLBACK_TICKET" \
  --arg startedAt "$started_at" \
  --arg rolledBackAt "$rolled_back_at" \
  '{
    schemaVersion: 1,
    environment: $environment,
    rollback: {
      fromDigest: $fromDigest,
      toDigest: $toDigest,
      toCommit: $toCommit,
      reason: $reason,
      ticket: $ticket,
      startedAt: $startedAt,
      rolledBackAt: $rolledBackAt,
      previousSignatureVerified: true,
      previousSchemaCompatible: true,
      encryptedBackupVerified: true,
      disposableRestoreVerified: true,
      healthBefore: "passed",
      healthAfter: "passed",
      featuresDisabledBeforeRollback: true,
      forwardSchemaPreserved: true,
      downMigrationExecuted: false
    }
  }' > "$evidence"
cp "$AERA_RELEASE_PREVIOUS_MANIFEST" "$current_manifest"
jq -cnS \
  --arg environment "$AERA_RELEASE_ENVIRONMENT" \
  --arg digest "$to_digest" \
  --arg reference "$to_reference" \
  --arg commit "$to_commit" \
  --arg previousDigest "$from_digest" \
  --arg rolledBackAt "$rolled_back_at" \
  '{
    environment: $environment,
    current: {
      imageDigest: $digest,
      imageReference: $reference,
      commitSha: $commit,
      deployedAt: $rolledBackAt
    },
    previousImageDigest: $previousDigest,
    features: {
      publicRegistration: false,
      officialAgents: false,
      officialQuality: false,
      encryptedBackup: false
    }
  }' > "$state_file"
chmod 600 "$feature_env" "$evidence" "$current_manifest" "$state_file"

if test "$restore_current" = "true"; then
  AERA_RELEASE_MANIFEST="$AERA_RELEASE_CURRENT_MANIFEST" \
    AERA_RELEASE_EXPECTED_SHA="$AERA_RELEASE_EXPECTED_CURRENT_SHA" \
    "$root/scripts/release/deploy-by-digest.sh" deploy
  restored_digest=$(jq -r '.current.imageDigest' "$state_file")
  test "$restored_digest" = "$from_digest" ||
    fail "staging rehearsal did not restore the current image digest"
  restored_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  restore_evidence="$state_dir/rehearsal-restore-evidence.json"
  jq -cnS \
    --arg environment "$AERA_RELEASE_ENVIRONMENT" \
    --arg restoredFromDigest "$to_digest" \
    --arg restoredToDigest "$from_digest" \
    --arg restoredAt "$restored_at" \
    '{
      schemaVersion: 1,
      environment: $environment,
      restoredFromDigest: $restoredFromDigest,
      restoredToDigest: $restoredToDigest,
      restoredAt: $restoredAt,
      healthAfterRestore: "passed",
      featuresDisabled: true
    }' > "$restore_evidence"
  chmod 600 "$restore_evidence"
  printf 'cloud rollback rehearsal restored current digest: %s\n' "$from_digest"
else
  printf 'cloud image rolled back without down migration: %s\n' "$to_digest"
fi
