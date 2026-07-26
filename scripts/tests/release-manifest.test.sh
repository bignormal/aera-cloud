#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
build="$root/scripts/release/build-manifest.sh"
build_provenance="$root/scripts/release/build-provenance.sh"
verify="$root/scripts/release/verify-manifest.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/aera-cloud-release-manifest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

repo="$tmp/repo"
mkdir -p "$repo" "$tmp/bin"
git -C "$repo" init -q
git -C "$repo" config user.email release-test@invalid.example
git -C "$repo" config user.name release-test
printf 'fixture\n' > "$repo/source.txt"
git -C "$repo" add source.txt
git -C "$repo" commit -qm fixture
sha=$(git -C "$repo" rev-parse HEAD)

cat > "$tmp/bin/cosign" <<'SH'
#!/bin/sh
set -eu

has_pair() {
  wanted_name=$1
  wanted_value=$2
  shift 2
  while test "$#" -gt 1; do
    if test "$1" = "$wanted_name" && test "$2" = "$wanted_value"; then
      return 0
    fi
    shift
  done
  return 1
}

test "${COSIGN_TEST_FAIL_IMAGE:-0}" = 0 || exit 1
case "$1" in
  verify)
    has_pair --certificate-identity-regexp "$COSIGN_TEST_EXPECTED_IDENTITY" "$@"
    has_pair --certificate-oidc-issuer "$COSIGN_TEST_EXPECTED_ISSUER" "$@"
    ;;
  verify-attestation)
    test "${COSIGN_TEST_NO_ATTESTATION:-0}" = 0 || exit 1
    has_pair --type slsaprovenance1 "$@"
    has_pair --certificate-identity-regexp "$COSIGN_TEST_EXPECTED_IDENTITY" "$@"
    has_pair --certificate-oidc-issuer "$COSIGN_TEST_EXPECTED_ISSUER" "$@"
    predicate="$COSIGN_TEST_PREDICATE"
    if test "${COSIGN_TEST_WRONG_PREDICATE:-0}" = 1; then
      predicate="$COSIGN_TEST_WRONG_PREDICATE_FILE"
    fi
    digest=${COSIGN_TEST_IMAGE##*@sha256:}
    image=${COSIGN_TEST_IMAGE%@*}
    statement_type=https://in-toto.io/Statement/v0.1
    if test "${COSIGN_TEST_WRONG_STATEMENT_TYPE:-0}" = 1; then
      statement_type=https://in-toto.io/Statement/v1
    fi
    statement=$(jq -cn \
      --arg image "$image" \
      --arg digest "$digest" \
      --arg statementType "$statement_type" \
      --slurpfile predicate "$predicate" \
      '{
        _type: $statementType,
        subject: [{name: $image, digest: {sha256: $digest}}],
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: $predicate[0]
      }')
    payload=$(printf '%s' "$statement" | base64 | tr -d '\n')
    jq -cn --arg payload "$payload" '{payload:$payload}'
    if test "${COSIGN_TEST_APPEND_UNRELATED_ATTESTATION:-0}" = 1; then
      printf '%s\n' '{"payload":"bm90LWpzb24="}'
    fi
    ;;
  verify-blob)
    has_pair --certificate-identity-regexp "$COSIGN_TEST_EXPECTED_IDENTITY" "$@"
    has_pair --certificate-oidc-issuer "$COSIGN_TEST_EXPECTED_ISSUER" "$@"
    blob=$2
    bundle=
    previous=
    for argument in "$@"; do
      if test "$previous" = "--bundle"; then
        bundle=$argument
      fi
      previous=$argument
    done
    test -f "$bundle"
    jq -e '.valid == true' "$bundle" >/dev/null
    test "$(sha256sum "$blob" | cut -d' ' -f1)" = "$COSIGN_TEST_MANIFEST_SHA"
    ;;
  *) exit 1 ;;
esac
SH
chmod +x "$tmp/bin/cosign"

export PATH="$tmp/bin:$PATH"
export AERA_RELEASE_REPOSITORY=bignormal/aera-cloud
export AERA_RELEASE_COMMIT_SHA="$sha"
export AERA_RELEASE_IMAGE=ghcr.io/bignormal/aera-cloud
export AERA_RELEASE_IMAGE_DIGEST="sha256:$(printf 'a%.0s' $(jot 64 1 64 2>/dev/null || seq 64))"
export AERA_RELEASE_WORKFLOW="Cloud candidate"
export AERA_RELEASE_RUN_URL=https://github.com/bignormal/aera-cloud/actions/runs/1234
export AERA_RELEASE_SCHEMA_MIN=17
export AERA_RELEASE_SCHEMA_MAX=20
export AERA_RELEASE_HIGHEST_MIGRATION=20
export AERA_RELEASE_CREATED_AT=2026-07-23T09:00:00Z
export AERA_RELEASE_EXPECTED_SHA="$sha"
export AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP='^https://github.com/bignormal/aera-cloud/'
export AERA_RELEASE_CERTIFICATE_OIDC_ISSUER=https://token.actions.githubusercontent.com

manifest="$tmp/manifest.json"
printf '{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3"}\n' > "$tmp/sbom.spdx.json"
export AERA_PROVENANCE_REPOSITORY=bignormal/aera-cloud
export AERA_PROVENANCE_SOURCE_SHA="$sha"
export AERA_PROVENANCE_WORKFLOW_PATH=.github/workflows/candidate.yml
export AERA_PROVENANCE_WORKFLOW_REF=refs/heads/aera/internal-beta-delivery
export AERA_PROVENANCE_RUN_URL="$AERA_RELEASE_RUN_URL"
export AERA_PROVENANCE_BUILDER_ID=https://github.com/bignormal/aera-cloud/.github/workflows/candidate.yml@refs/heads/aera/internal-beta-delivery
export AERA_PROVENANCE_IMAGE_DIGEST="$AERA_RELEASE_IMAGE_DIGEST"
export AERA_PROVENANCE_IMAGE_REFERENCE="$AERA_RELEASE_IMAGE@$AERA_RELEASE_IMAGE_DIGEST"
"$build_provenance" "$tmp/provenance.json"
export AERA_RELEASE_SBOM_DIGEST="sha256:$(sha256sum "$tmp/sbom.spdx.json" | cut -d' ' -f1)"
export AERA_RELEASE_PROVENANCE_DIGEST="sha256:$(sha256sum "$tmp/provenance.json" | cut -d' ' -f1)"
(
  cd "$repo"
  "$build" "$manifest"
)
printf '{"valid":true}\n' > "$tmp/manifest.sigstore.json"
printf '{}\n' > "$tmp/wrong-provenance.json"
export COSIGN_TEST_EXPECTED_IDENTITY="$AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP"
export COSIGN_TEST_EXPECTED_ISSUER="$AERA_RELEASE_CERTIFICATE_OIDC_ISSUER"
export COSIGN_TEST_IMAGE="$AERA_PROVENANCE_IMAGE_REFERENCE"
export COSIGN_TEST_PREDICATE="$tmp/provenance.json"
export COSIGN_TEST_WRONG_PREDICATE_FILE="$tmp/wrong-provenance.json"
export COSIGN_TEST_MANIFEST_SHA
COSIGN_TEST_MANIFEST_SHA=$(sha256sum "$manifest" | cut -d' ' -f1)
"$verify" "$manifest"
COSIGN_TEST_APPEND_UNRELATED_ATTESTATION=1 "$verify" "$manifest"
jq -e '
  .repository == "bignormal/aera-cloud" and
  .commitSha == $sha and
  .image.reference == ("ghcr.io/bignormal/aera-cloud@" + .image.digest) and
  .features.officialQualityEnabledByDefault == false and
  .features.encryptedBackupEnabledByDefault == false
' --arg sha "$sha" "$manifest" >/dev/null

expect_failure() {
  label="$1"
  candidate="$2"
  if "$verify" "$candidate" >"$tmp/$label.out" 2>"$tmp/$label.err"; then
    echo "$label unexpectedly passed" >&2
    exit 1
  fi
}

jq '.image.reference = "ghcr.io/bignormal/aera-cloud:latest"' \
  "$manifest" > "$tmp/mutable-tag.json"
expect_failure mutable-tag "$tmp/mutable-tag.json"

jq '.commitSha = "dddddddddddddddddddddddddddddddddddddddd"' \
  "$manifest" > "$tmp/wrong-sha.json"
expect_failure wrong-sha "$tmp/wrong-sha.json"

jq 'del(.schema.minimum)' "$manifest" > "$tmp/missing-schema.json"
expect_failure missing-schema "$tmp/missing-schema.json"

jq 'del(.supplyChain.sbomDigest)' "$manifest" > "$tmp/missing-sbom.json"
expect_failure missing-sbom "$tmp/missing-sbom.json"

COSIGN_TEST_FAIL_IMAGE=1 expect_failure unsigned-image "$manifest"

mv "$tmp/manifest.sigstore.json" "$tmp/manifest.sigstore.missing"
expect_failure missing-manifest-bundle "$manifest"
mv "$tmp/manifest.sigstore.missing" "$tmp/manifest.sigstore.json"

printf '{"valid":false}\n' > "$tmp/manifest.sigstore.json"
expect_failure tampered-manifest-bundle "$manifest"
printf '{"valid":true}\n' > "$tmp/manifest.sigstore.json"

COSIGN_TEST_NO_ATTESTATION=1 expect_failure missing-attestation "$manifest"
COSIGN_TEST_WRONG_PREDICATE=1 expect_failure wrong-attestation-predicate "$manifest"
COSIGN_TEST_WRONG_STATEMENT_TYPE=1 expect_failure wrong-attestation-statement-type "$manifest"

saved_identity=$AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP
AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP='^https://github.com/other/repository/'
export AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP
expect_failure wrong-certificate-identity "$manifest"
AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP=$saved_identity
export AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP

saved_issuer=$AERA_RELEASE_CERTIFICATE_OIDC_ISSUER
AERA_RELEASE_CERTIFICATE_OIDC_ISSUER=https://issuer.invalid.example
export AERA_RELEASE_CERTIFICATE_OIDC_ISSUER
expect_failure wrong-oidc-issuer "$manifest"
AERA_RELEASE_CERTIFICATE_OIDC_ISSUER=$saved_issuer
export AERA_RELEASE_CERTIFICATE_OIDC_ISSUER

cp "$tmp/provenance.json" "$tmp/provenance.saved"
jq '.runDetails.metadata.invocationId = "https://github.com/bignormal/aera-cloud/actions/runs/9999"' \
  "$tmp/provenance.saved" > "$tmp/provenance.json"
expect_failure tampered-provenance "$manifest"
mv "$tmp/provenance.saved" "$tmp/provenance.json"

jq -cS '.createdAt = "2026-07-23T09:00:01Z"' "$manifest" > "$tmp/tampered-valid-manifest.json"
cp "$tmp/manifest.sigstore.json" "$tmp/tampered-valid-manifest.sigstore.json"
expect_failure manifest-bundle-does-not-match "$tmp/tampered-valid-manifest.json"

printf 'dirty\n' > "$repo/untracked.txt"
if (
  cd "$repo"
  "$build" "$tmp/dirty.json"
) >"$tmp/dirty.out" 2>"$tmp/dirty.err"; then
  echo "dirty source tree unexpectedly produced a manifest" >&2
  exit 1
fi

printf 'release manifest tests passed\n'
