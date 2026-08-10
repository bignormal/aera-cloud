#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
migration_source_sha=aba165d256cd447abcd43ce4c397041c2bf802d1
migration_sha256=f02358bdacd540f92f5977a24a7ef5568de3354803e436ce966699a5433e6fd7
migration_name=000022_organization_experience_candidates.sql
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/aera-schema22-compat.XXXXXX")
project="aera-schema22-compat-$$"
compose=(docker compose -p "$project")

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp_root"
}
trap cleanup EXIT

for command_name in docker go shasum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'schema 22 compatibility test: %s is required\n' "$command_name" >&2
    exit 1
  }
done

migration_file="$tmp_root/$migration_name"
if [[ -n ${AERA_SCHEMA22_MIGRATION_FILE:-} ]]; then
  cp "$AERA_SCHEMA22_MIGRATION_FILE" "$migration_file"
else
  command -v gh >/dev/null 2>&1 || {
    printf 'schema 22 compatibility test: gh is required to fetch the pinned private migration\n' >&2
    exit 1
  }
  gh api \
    -H 'Accept: application/vnd.github.raw+json' \
    "repos/bignormal/aera-cloud/contents/migrations/$migration_name?ref=$migration_source_sha" \
    >"$migration_file"
fi
[[ $(shasum -a 256 "$migration_file" | awk '{print $1}') == "$migration_sha256" ]]

AERA_CLOUD_POSTGRES_BIND='127.0.0.1:' \
AERA_CLOUD_REDIS_BIND='127.0.0.1:' \
  "${compose[@]}" up -d --wait postgres redis
postgres_address=$("${compose[@]}" port postgres 5432)
redis_address=$("${compose[@]}" port redis 6379)
set -a
source "$repo_root/.env.example"
set +a
export AGENTERA_CLOUD_DATABASE_URL="postgres://aera_cloud:aera-cloud-dev-only@$postgres_address/aera_cloud?sslmode=disable"
export AGENTERA_CLOUD_REDIS_ADDR="$redis_address"
export AERA_INTEGRATION_TESTS=1

go test -count=1 ./internal/store -run '^TestApplyMigrationsCreatesAuthSchemaAndIsIdempotent$'
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U aera_cloud -d aera_cloud -1 <"$migration_file"
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U aera_cloud -d aera_cloud <<SQL
INSERT INTO schema_migrations (version, name, checksum)
VALUES (22, '$migration_name', decode('$migration_sha256', 'hex'));
SQL
[[ $("${compose[@]}" exec -T postgres psql -At -U aera_cloud -d aera_cloud -c 'SELECT max(version) FROM schema_migrations') == 22 ]]

go test -count=1 -p 1 ./internal/account ./internal/organization ./internal/agentcontrol
go test -count=1 ./cmd/aera-cloud -run '^TestSmokeAuthLifecycle$'
CGO_ENABLED=0 go build -trimpath -o "$tmp_root/aera-cloud" ./cmd/aera-cloud
printf 'schema 22 compatibility passed: bridge=%s migration-source=%s highest=22\n' \
  "$(git rev-parse HEAD)" "$migration_source_sha"
