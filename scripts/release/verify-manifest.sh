#!/bin/sh
set -eu

fail() {
  printf 'cloud candidate manifest verification failed: %s\n' "$*" >&2
  exit 1
}

test "$#" -eq 1 || fail "usage: verify-manifest.sh MANIFEST_JSON"
manifest="$1"
test -f "$manifest" || fail "manifest is missing"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v cosign >/dev/null 2>&1 || fail "cosign is required"

expected_sha=${AERA_RELEASE_EXPECTED_SHA:-}
identity=${AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP:-}
issuer=${AERA_RELEASE_CERTIFICATE_OIDC_ISSUER:-}
test -n "$expected_sha" || fail "AERA_RELEASE_EXPECTED_SHA is required"
test -n "$identity" || fail "AERA_RELEASE_CERTIFICATE_IDENTITY_REGEXP is required"
test -n "$issuer" || fail "AERA_RELEASE_CERTIFICATE_OIDC_ISSUER is required"

jq -e '
  type == "object" and
  .schemaVersion == 1 and
  (.repository | type == "string" and length > 0) and
  (.commitSha | test("^[0-9a-f]{40}$")) and
  (.image | type == "object") and
  (.image.digest | test("^sha256:[0-9a-f]{64}$")) and
  (.image.reference | type == "string") and
  (.build.workflow | type == "string" and length > 0) and
  (.build.runUrl | test("^https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[1-9][0-9]*$")) and
  (.schema.minimum | type == "number" and floor == . and . > 0) and
  (.schema.maximum | type == "number" and floor == . and . > 0) and
  (.schema.highestMigration | type == "number" and floor == . and . > 0) and
  (.schema.minimum <= .schema.highestMigration) and
  (.schema.highestMigration <= .schema.maximum) and
  (.supplyChain.sbomDigest | test("^sha256:[0-9a-f]{64}$")) and
  (.supplyChain.provenanceDigest | test("^sha256:[0-9a-f]{64}$")) and
  .features.officialQualityEnabledByDefault == false and
  .features.encryptedBackupEnabledByDefault == false and
  (.createdAt | fromdateiso8601 | type == "number")
' "$manifest" >/dev/null || fail "manifest schema or required evidence is invalid"

canonical=$(jq -cS . "$manifest")
actual=$(tr -d '\n' < "$manifest")
test "$actual" = "$canonical" || fail "manifest is not canonical JSON"

commit_sha=$(jq -r '.commitSha' "$manifest")
test "$commit_sha" = "$expected_sha" || fail "manifest source SHA does not match"
image=$(jq -r '.image.reference' "$manifest")
digest=$(jq -r '.image.digest' "$manifest")
base_image=${image%@*}
test "$image" = "${base_image}@${digest}" ||
  fail "image reference is mutable or does not match its digest"
printf '%s\n' "$base_image" |
  grep -Eq '^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+$' ||
  fail "image reference is not an immutable GHCR reference"

cosign verify \
  --certificate-identity-regexp "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$image" >/dev/null ||
  fail "image signature verification failed"
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$image" >/dev/null ||
  fail "image provenance attestation verification failed"

printf 'cloud candidate manifest verified: %s at %s\n' "$commit_sha" "$digest"
