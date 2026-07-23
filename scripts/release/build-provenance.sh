#!/bin/sh
set -eu

fail() {
  printf 'cloud candidate provenance build failed: %s\n' "$*" >&2
  exit 1
}

require() {
  name=$1
  eval "value=\${$name:-}"
  test -n "$value" || fail "$name is required"
}

test "$#" -eq 1 || fail "usage: build-provenance.sh OUTPUT_JSON"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"

for name in \
  AERA_PROVENANCE_REPOSITORY \
  AERA_PROVENANCE_SOURCE_SHA \
  AERA_PROVENANCE_WORKFLOW_PATH \
  AERA_PROVENANCE_WORKFLOW_REF \
  AERA_PROVENANCE_RUN_URL \
  AERA_PROVENANCE_BUILDER_ID \
  AERA_PROVENANCE_IMAGE_REFERENCE \
  AERA_PROVENANCE_IMAGE_DIGEST
do
  require "$name"
done

printf '%s\n' "$AERA_PROVENANCE_REPOSITORY" |
  grep -Eq '^[a-z0-9_.-]+/[a-z0-9_.-]+$' ||
  fail "repository must be a canonical owner/name"
printf '%s\n' "$AERA_PROVENANCE_SOURCE_SHA" |
  grep -Eq '^[0-9a-f]{40}$' ||
  fail "source SHA must be 40 lowercase hexadecimal characters"
printf '%s\n' "$AERA_PROVENANCE_WORKFLOW_PATH" |
  grep -Eq '^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$' ||
  fail "workflow path must name one repository workflow"
case "$AERA_PROVENANCE_WORKFLOW_REF" in
  refs/heads/*) ;;
  *) fail "workflow ref must be an exact branch ref" ;;
esac
git check-ref-format "$AERA_PROVENANCE_WORKFLOW_REF" >/dev/null 2>&1 ||
  fail "workflow ref is invalid"

expected_run_prefix="https://github.com/$AERA_PROVENANCE_REPOSITORY/actions/runs/"
case "$AERA_PROVENANCE_RUN_URL" in
  "$expected_run_prefix"[1-9]*)
    run_id=${AERA_PROVENANCE_RUN_URL#"$expected_run_prefix"}
    case "$run_id" in *[!0-9]*) fail "run URL must end in a numeric run ID" ;; esac
    ;;
  *) fail "run URL must belong to the exact repository" ;;
esac

expected_builder="https://github.com/$AERA_PROVENANCE_REPOSITORY/$AERA_PROVENANCE_WORKFLOW_PATH@$AERA_PROVENANCE_WORKFLOW_REF"
test "$AERA_PROVENANCE_BUILDER_ID" = "$expected_builder" ||
  fail "builder identity does not match the workflow path and ref"
printf '%s\n' "$AERA_PROVENANCE_IMAGE_DIGEST" |
  grep -Eq '^sha256:[0-9a-f]{64}$' ||
  fail "image digest must be immutable sha256"
expected_image="ghcr.io/$AERA_PROVENANCE_REPOSITORY@$AERA_PROVENANCE_IMAGE_DIGEST"
test "$AERA_PROVENANCE_IMAGE_REFERENCE" = "$expected_image" ||
  fail "image reference must bind the repository to the exact digest"

digest_hex=${AERA_PROVENANCE_IMAGE_DIGEST#sha256:}
repository_uri="https://github.com/$AERA_PROVENANCE_REPOSITORY"
dependency_uri="git+$repository_uri@$AERA_PROVENANCE_WORKFLOW_REF"

jq -cnS \
  --arg repository "$repository_uri" \
  --arg sourceSha "$AERA_PROVENANCE_SOURCE_SHA" \
  --arg workflowPath "$AERA_PROVENANCE_WORKFLOW_PATH" \
  --arg workflowRef "$AERA_PROVENANCE_WORKFLOW_REF" \
  --arg runUrl "$AERA_PROVENANCE_RUN_URL" \
  --arg builderID "$AERA_PROVENANCE_BUILDER_ID" \
  --arg image "$AERA_PROVENANCE_IMAGE_REFERENCE" \
  --arg dependencyURI "$dependency_uri" \
  --arg digest "$digest_hex" \
  '{
    buildDefinition: {
      buildType: "https://slsa.dev/provenance/v1",
      externalParameters: {
        repository: $repository,
        sourceSha: $sourceSha,
        workflowPath: $workflowPath,
        workflowRef: $workflowRef,
        runUrl: $runUrl,
        image: $image
      },
      internalParameters: {},
      resolvedDependencies: [{
        uri: $dependencyURI,
        digest: {gitCommit: $sourceSha}
      }]
    },
    runDetails: {
      builder: {id: $builderID},
      metadata: {invocationId: $runUrl},
      byproducts: [{
        name: $image,
        digest: {sha256: $digest}
      }]
    }
  }' > "$1"
printf '\n' >> "$1"
