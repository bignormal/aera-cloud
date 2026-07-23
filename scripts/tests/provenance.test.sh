#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
build="$root/scripts/release/build-provenance.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/aera-cloud-provenance.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

export AERA_PROVENANCE_REPOSITORY=bignormal/aera-cloud
export AERA_PROVENANCE_SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export AERA_PROVENANCE_WORKFLOW_PATH=.github/workflows/candidate.yml
export AERA_PROVENANCE_WORKFLOW_REF=refs/heads/aera/internal-beta-delivery
export AERA_PROVENANCE_RUN_URL=https://github.com/bignormal/aera-cloud/actions/runs/1234
export AERA_PROVENANCE_BUILDER_ID=https://github.com/bignormal/aera-cloud/.github/workflows/candidate.yml@refs/heads/aera/internal-beta-delivery
export AERA_PROVENANCE_IMAGE_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export AERA_PROVENANCE_IMAGE_REFERENCE=ghcr.io/bignormal/aera-cloud@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

output="$tmp/provenance.json"
"$build" "$output"

jq -e '
  keys == ["buildDefinition", "runDetails"] and
  .buildDefinition.buildType == "https://slsa.dev/provenance/v1" and
  .buildDefinition.externalParameters == {
    repository: "https://github.com/bignormal/aera-cloud",
    sourceSha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    workflowPath: ".github/workflows/candidate.yml",
    workflowRef: "refs/heads/aera/internal-beta-delivery",
    runUrl: "https://github.com/bignormal/aera-cloud/actions/runs/1234",
    image: "ghcr.io/bignormal/aera-cloud@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  } and
  .buildDefinition.internalParameters == {} and
  .buildDefinition.resolvedDependencies == [{
    uri: "git+https://github.com/bignormal/aera-cloud@refs/heads/aera/internal-beta-delivery",
    digest: {gitCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  }] and
  .runDetails.builder == {
    id: "https://github.com/bignormal/aera-cloud/.github/workflows/candidate.yml@refs/heads/aera/internal-beta-delivery"
  } and
  .runDetails.metadata == {
    invocationId: "https://github.com/bignormal/aera-cloud/actions/runs/1234"
  } and
  .runDetails.byproducts == [{
    name: "ghcr.io/bignormal/aera-cloud@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    digest: {sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  }]
' "$output" >/dev/null

canonical=$(jq -cS . "$output")
actual=$(tr -d '\n' < "$output")
test "$actual" = "$canonical" || {
  echo "provenance is not canonical JSON" >&2
  exit 1
}

expect_failure() {
  label=$1
  variable=$2
  value=$3
  if (
    export "$variable=$value"
    "$build" "$tmp/$label.json"
  ) >"$tmp/$label.out" 2>"$tmp/$label.err"; then
    echo "$label unexpectedly passed" >&2
    exit 1
  fi
}

expect_failure bad-repository AERA_PROVENANCE_REPOSITORY bignormal
expect_failure bad-sha AERA_PROVENANCE_SOURCE_SHA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
expect_failure bad-workflow-path AERA_PROVENANCE_WORKFLOW_PATH candidate.yml
expect_failure mutable-workflow-ref AERA_PROVENANCE_WORKFLOW_REF main
expect_failure wrong-run AERA_PROVENANCE_RUN_URL https://github.com/other/repo/actions/runs/1234
expect_failure wrong-builder AERA_PROVENANCE_BUILDER_ID https://github.com/other/repo/.github/workflows/candidate.yml@refs/heads/main
expect_failure mutable-image AERA_PROVENANCE_IMAGE_REFERENCE ghcr.io/bignormal/aera-cloud:latest
expect_failure wrong-digest AERA_PROVENANCE_IMAGE_DIGEST sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

printf 'provenance tests passed\n'
