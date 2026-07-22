#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker="$repo_root/scripts/check-secrets.sh"

fail() {
  printf 'check-secrets test failed: %s\n' "$1" >&2
  exit 1
}

[[ -x "$checker" ]] || fail "scripts/check-secrets.sh is not executable"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

new_repo() {
  local name=$1
  local path="$scratch/$name"
  mkdir -p "$path"
  git -C "$path" init -q
  git -C "$path" config user.email test@agentera.invalid
  git -C "$path" config user.name AgentEra-Test
  printf '%s\n' "$path"
}

track() {
  git -C "$1" add .
}

expect_pass() {
  local path=$1
  "$checker" --repo "$path" >/dev/null || fail "safe repository was rejected"
}

expect_fail() {
  local path=$1
  if "$checker" --repo "$path" >/dev/null 2>&1; then
    fail "unsafe repository was accepted: $path"
  fi
}

safe=$(new_repo safe)
mkdir -p "$safe/api" "$safe/docs/runbooks" "$safe/internal" "$safe/migrations"
printf 'AGENTERA_CLOUD_ENVIRONMENT=development\n' > "$safe/.env.example"
printf 'package internal\nvar testCode = "123456"\n' > "$safe/internal/provider_test.go"
printf 'var fakeProviderFixture = map[string]string{"AGENTERA_CLOUD_SMTP_HOST": "smtp.agentera.invalid"}\n' >> "$safe/internal/provider_test.go"
printf 'CHECK (octet_length(icon_data) <= 524288);\n' > "$safe/migrations/000001_size_limit.sql"
printf 'maxLength: 262144\n' > "$safe/api/openapi.yaml"
printf 'Apply migration 000015_internal_admin_api.sql before enabling.\n' > "$safe/docs/runbooks/private-staging.md"
printf '%s%s\ntoken=eyJfixture.fixture.fixture\n' '-----BEGIN ' 'PRIVATE KEY-----' > "$safe/api/experience-candidate-v1-vectors.json"
track "$safe"
expect_pass "$safe"

committed_env=$(new_repo committed-env)
printf 'SECRET=value\n' > "$committed_env/.env"
track "$committed_env"
expect_fail "$committed_env"

pem=$(new_repo pem)
printf '%s%s\n%s\n%s%s\n' '-----BEGIN ' 'PRIVATE KEY-----' 'not-real-key-material' '-----END ' 'PRIVATE KEY-----' > "$pem/key.txt"
track "$pem"
expect_fail "$pem"

token=$(new_repo token)
printf 'token: ghp_%s%s\n' 'abcdefghijklmnopqr' 'stuvwxyz1234567890' > "$token/config.yaml"
track "$token"
expect_fail "$token"

verification_code=$(new_repo verification-code)
mkdir -p "$verification_code/deploy"
printf 'verification_code: "%s%s"\n' '654' '321' > "$verification_code/deploy/config.yaml"
track "$verification_code"
expect_fail "$verification_code"

sql_verification_code=$(new_repo sql-verification-code)
mkdir -p "$sql_verification_code/migrations"
printf "INSERT INTO verification_fixtures (code) VALUES ('654321');\n" > "$sql_verification_code/migrations/000001_fixture.sql"
track "$sql_verification_code"
expect_fail "$sql_verification_code"

fake_production_provider=$(new_repo production-provider)
mkdir -p "$fake_production_provider/deploy"
printf 'AGENTERA_CLOUD_ENVIRONMENT: production\nAGENTERA_CLOUD_SMTP_HOST: smtp.agentera.%s\n' 'invalid' > "$fake_production_provider/deploy/compose.production.yaml"
track "$fake_production_provider"
expect_fail "$fake_production_provider"

printf 'check-secrets tests passed\n'
