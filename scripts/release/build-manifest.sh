#!/bin/sh
set -eu

fail() {
  printf 'cloud candidate manifest build failed: %s\n' "$*" >&2
  exit 1
}

require() {
  name="$1"
  eval "value=\${$name:-}"
  test -n "$value" || fail "$name is required"
}

test "$#" -eq 1 || fail "usage: build-manifest.sh OUTPUT_JSON"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"

for name in \
  AERA_RELEASE_REPOSITORY \
  AERA_RELEASE_COMMIT_SHA \
  AERA_RELEASE_IMAGE \
  AERA_RELEASE_IMAGE_DIGEST \
  AERA_RELEASE_WORKFLOW \
  AERA_RELEASE_RUN_URL \
  AERA_RELEASE_SCHEMA_MIN \
  AERA_RELEASE_SCHEMA_MAX \
  AERA_RELEASE_HIGHEST_MIGRATION \
  AERA_RELEASE_SBOM_DIGEST \
  AERA_RELEASE_PROVENANCE_DIGEST \
  AERA_RELEASE_CREATED_AT
do
  require "$name"
done

git rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
  fail "source must be a Git worktree"
test -z "$(git status --porcelain=v1)" || fail "source tree is dirty"
head_sha=$(git rev-parse HEAD)
test "$head_sha" = "$AERA_RELEASE_COMMIT_SHA" ||
  fail "AERA_RELEASE_COMMIT_SHA does not match HEAD"

case "$AERA_RELEASE_COMMIT_SHA" in
  *[!0-9a-f]*|"") fail "commit SHA must be 40 lowercase hexadecimal characters" ;;
esac
test "${#AERA_RELEASE_COMMIT_SHA}" -eq 40 ||
  fail "commit SHA must be 40 lowercase hexadecimal characters"

digest_pattern='^sha256:[0-9a-f]{64}$'
printf '%s\n' "$AERA_RELEASE_IMAGE_DIGEST" | grep -Eq "$digest_pattern" ||
  fail "image digest must be immutable sha256"
printf '%s\n' "$AERA_RELEASE_SBOM_DIGEST" | grep -Eq "$digest_pattern" ||
  fail "SBOM digest must be sha256"
printf '%s\n' "$AERA_RELEASE_PROVENANCE_DIGEST" | grep -Eq "$digest_pattern" ||
  fail "provenance digest must be sha256"
printf '%s\n' "$AERA_RELEASE_IMAGE" |
  grep -Eq '^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+$' ||
  fail "image must be an untagged GHCR repository"
printf '%s\n' "$AERA_RELEASE_RUN_URL" |
  grep -Eq '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[1-9][0-9]*$' ||
  fail "run URL must be an exact GitHub Actions run"

for value in \
  "$AERA_RELEASE_SCHEMA_MIN" \
  "$AERA_RELEASE_SCHEMA_MAX" \
  "$AERA_RELEASE_HIGHEST_MIGRATION"
do
  case "$value" in
    *[!0-9]*|"") fail "schema versions must be positive integers" ;;
  esac
done
test "$AERA_RELEASE_SCHEMA_MIN" -le "$AERA_RELEASE_HIGHEST_MIGRATION" ||
  fail "highest migration is below the schema minimum"
test "$AERA_RELEASE_HIGHEST_MIGRATION" -le "$AERA_RELEASE_SCHEMA_MAX" ||
  fail "highest migration exceeds the schema maximum"

output="$1"
image_reference="${AERA_RELEASE_IMAGE}@${AERA_RELEASE_IMAGE_DIGEST}"
jq -cnS \
  --arg repository "$AERA_RELEASE_REPOSITORY" \
  --arg commitSha "$AERA_RELEASE_COMMIT_SHA" \
  --arg imageReference "$image_reference" \
  --arg imageDigest "$AERA_RELEASE_IMAGE_DIGEST" \
  --arg workflow "$AERA_RELEASE_WORKFLOW" \
  --arg runUrl "$AERA_RELEASE_RUN_URL" \
  --argjson schemaMinimum "$AERA_RELEASE_SCHEMA_MIN" \
  --argjson schemaMaximum "$AERA_RELEASE_SCHEMA_MAX" \
  --argjson highestMigration "$AERA_RELEASE_HIGHEST_MIGRATION" \
  --arg sbomDigest "$AERA_RELEASE_SBOM_DIGEST" \
  --arg provenanceDigest "$AERA_RELEASE_PROVENANCE_DIGEST" \
  --arg createdAt "$AERA_RELEASE_CREATED_AT" \
  '{
    schemaVersion: 1,
    repository: $repository,
    commitSha: $commitSha,
    image: {
      reference: $imageReference,
      digest: $imageDigest
    },
    build: {
      workflow: $workflow,
      runUrl: $runUrl
    },
    schema: {
      minimum: $schemaMinimum,
      maximum: $schemaMaximum,
      highestMigration: $highestMigration
    },
    supplyChain: {
      sbomDigest: $sbomDigest,
      provenanceDigest: $provenanceDigest
    },
    features: {
      officialQualityEnabledByDefault: false,
      encryptedBackupEnabledByDefault: false
    },
    createdAt: $createdAt
  }' > "$output"
printf '\n' >> "$output"
