#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'internal beta Cloud health smoke failed: %s\n' "$1" >&2
  exit 1
}

origin=${AERA_INTERNAL_BETA_PUBLIC_ORIGIN:-}
expected_features=${AERA_INTERNAL_BETA_EXPECT_FEATURES:-}
expected_registration_mode=${AERA_INTERNAL_BETA_EXPECT_REGISTRATION_MODE:-direct}
[[ $origin =~ ^https://([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] ||
  fail 'AERA_INTERNAL_BETA_PUBLIC_ORIGIN must be an exact HTTPS IPv4 origin'
case "$expected_features" in
  disabled | enabled) ;;
  *) fail 'AERA_INTERNAL_BETA_EXPECT_FEATURES must be disabled or enabled' ;;
esac
case "$expected_registration_mode" in
  direct | verified) ;;
  *) fail 'AERA_INTERNAL_BETA_EXPECT_REGISTRATION_MODE must be direct or verified' ;;
esac
command -v curl >/dev/null 2>&1 || fail 'curl is required'
command -v jq >/dev/null 2>&1 || fail 'jq is required'

tmp=$(mktemp -d "${TMPDIR:-/tmp}/aera-cloud-health.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
curl_args=(
  --fail
  --silent
  --show-error
  --proto '=https'
  --tlsv1.2
  --connect-timeout 10
  --max-time 30
  --retry 15
  --retry-delay 2
  --retry-max-time 45
  --retry-all-errors
  --retry-connrefused
)

curl "${curl_args[@]}" "$origin/health/live" >"$tmp/live.json"
curl "${curl_args[@]}" "$origin/health/ready" >"$tmp/ready.json"
jq -e '.status == "ok"' "$tmp/live.json" >/dev/null ||
  fail 'liveness response is not ok'
jq -e '.status == "ok"' "$tmp/ready.json" >/dev/null ||
  fail 'readiness response is not ok'

curl "${curl_args[@]}" "$origin/api/v1/public/config" >"$tmp/public-config.json"
expected_registration=false
if [[ $expected_features == enabled ]]; then
  expected_registration=true
fi
if [[ $expected_registration_mode == verified ]]; then
  expected_identity_kinds='["phone"]'
  expected_verification=true
else
  expected_identity_kinds='["email"]'
  expected_verification=false
fi
jq -e \
  --arg mode "$expected_registration_mode" \
  --argjson registration "$expected_registration" \
  --argjson kinds "$expected_identity_kinds" \
  --argjson verification "$expected_verification" '
  keys == [
    "environment",
    "identity_verification_available",
    "public_registration_enabled",
    "registration_identity_kinds",
    "registration_mode"
  ] and
  .environment == "internal_beta" and
  .public_registration_enabled == $registration and
  .registration_mode == $mode and
  .registration_identity_kinds == $kinds and
  .identity_verification_available == $verification
' "$tmp/public-config.json" >/dev/null ||
  fail 'public capability document is incorrect'

if [[ -n ${AERA_INTERNAL_BETA_EXPECTED_OFFLINE_KEY_ID:-} ||
  -n ${AERA_INTERNAL_BETA_EXPECTED_OFFLINE_PUBLIC_KEY:-} ]]; then
  [[ -n ${AERA_INTERNAL_BETA_EXPECTED_OFFLINE_KEY_ID:-} &&
    -n ${AERA_INTERNAL_BETA_EXPECTED_OFFLINE_PUBLIC_KEY:-} ]] ||
    fail 'offline key ID and public key must be checked together'
  curl "${curl_args[@]}" \
    "$origin/.well-known/agentera-signing-keys.json" >"$tmp/signing-keys.json"
  jq -e \
    --arg kid "$AERA_INTERNAL_BETA_EXPECTED_OFFLINE_KEY_ID" \
    --arg publicKey "$AERA_INTERNAL_BETA_EXPECTED_OFFLINE_PUBLIC_KEY" '
      [
        .keys[] |
        select(
          .kid == $kid and
          .kty == "OKP" and
          .crv == "Ed25519" and
          .alg == "EdDSA" and
          .use == "sig" and
          .purpose == "offline_entitlement" and
          .x == $publicKey
        )
      ] | length == 1
    ' "$tmp/signing-keys.json" >/dev/null ||
    fail 'published offline-entitlement trust root does not match'
fi

printf 'internal beta Cloud health smoke passed (%s)\n' "$expected_features"
