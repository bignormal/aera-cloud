#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
build="$root/scripts/release/build-manifest.sh"
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
test "${COSIGN_TEST_FAIL:-0}" = 0
case "$1" in
  verify) test "$2" = "--certificate-identity-regexp" ;;
  verify-attestation) test "$2" = "--type" ;;
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
export AERA_RELEASE_SCHEMA_MAX=18
export AERA_RELEASE_HIGHEST_MIGRATION=18
export AERA_RELEASE_SBOM_DIGEST="sha256:$(printf 'b%.0s' $(jot 64 1 64 2>/dev/null || seq 64))"
export AERA_RELEASE_PROVENANCE_DIGEST="sha256:$(printf 'c%.0s' $(jot 64 1 64 2>/dev/null || seq 64))"
export AERA_RELEASE_CREATED_AT=2026-07-23T09:00:00Z
export AERA_RELEASE_EXPECTED_SHA="$sha"
export AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP='^https://github.com/bignormal/aera-cloud/'
export AERA_RELEASE_CERTIFICATE_OIDC_ISSUER=https://token.actions.githubusercontent.com

manifest="$tmp/manifest.json"
(
  cd "$repo"
  "$build" "$manifest"
)
"$verify" "$manifest"
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

COSIGN_TEST_FAIL=1 expect_failure unsigned-image "$manifest"

printf 'dirty\n' > "$repo/untracked.txt"
if (
  cd "$repo"
  "$build" "$tmp/dirty.json"
) >"$tmp/dirty.out" 2>"$tmp/dirty.err"; then
  echo "dirty source tree unexpectedly produced a manifest" >&2
  exit 1
fi

printf 'release manifest tests passed\n'
