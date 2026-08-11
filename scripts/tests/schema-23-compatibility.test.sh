#!/usr/bin/env bash
set -euo pipefail

bridge_sha=0bf56678c772c918e08423f0ad1c3aeb868cdc7e
migration_sha256=489bd9cea1aa40358892227cff3e35bc947a55df613fc8a3bfffb50a95dc7eb5
migration_name=000023_desktop_control_v1.sql
bridge_root=${AERA_SCHEMA23_BRIDGE_ROOT:?set AERA_SCHEMA23_BRIDGE_ROOT to the verified bridge checkout}
migration_file=${AERA_SCHEMA23_MIGRATION_FILE:?set AERA_SCHEMA23_MIGRATION_FILE to migration 23}
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/aera-schema23-compat.XXXXXX")
project="aera-schema23-compat-$$"
compose=(docker compose --project-directory "$bridge_root" -f "$bridge_root/compose.yaml" -p "$project")
app_pid=

cleanup() {
  if [[ -n $app_pid ]]; then
    kill "$app_pid" >/dev/null 2>&1 || true
    wait "$app_pid" >/dev/null 2>&1 || true
  fi
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp_root"
}
trap cleanup EXIT

fail() {
  printf 'schema 23 compatibility test failed: %s\n' "$1" >&2
  exit 1
}

for command_name in curl docker git go python3 shasum; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

[[ $(git -C "$bridge_root" rev-parse HEAD) == "$bridge_sha" ]] ||
  fail 'bridge checkout is not the allowlisted source'
[[ -z $(git -C "$bridge_root" status --porcelain=v1) ]] ||
  fail 'bridge checkout is dirty'
[[ -f $migration_file && $(basename "$migration_file") == "$migration_name" ]] ||
  fail 'migration 23 file is missing or misnamed'
[[ $(shasum -a 256 "$migration_file" | awk '{print $1}') == "$migration_sha256" ]] ||
  fail 'migration 23 checksum differs from the reviewed source'

AERA_CLOUD_POSTGRES_BIND='127.0.0.1:' \
AERA_CLOUD_REDIS_BIND='127.0.0.1:' \
  "${compose[@]}" up -d --wait postgres redis
postgres_address=$("${compose[@]}" port postgres 5432)
redis_address=$("${compose[@]}" port redis 6379)

set -a
source "$bridge_root/.env.example"
set +a
export AGENTERA_CLOUD_DATABASE_URL="postgres://aera_cloud:aera-cloud-dev-only@$postgres_address/aera_cloud?sslmode=disable"
export AGENTERA_CLOUD_REDIS_ADDR="$redis_address"
export AERA_INTEGRATION_TESTS=1

(
  cd "$bridge_root"
  go test -count=1 ./internal/store -run '^TestApplyMigrationsCreatesAuthSchemaAndIsIdempotent$'
)
"${compose[@]}" exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U aera_cloud -d aera_cloud -1 <"$migration_file"
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U aera_cloud -d aera_cloud <<SQL
INSERT INTO schema_migrations (version, name, checksum)
VALUES (23, '$migration_name', decode('$migration_sha256', 'hex'));
SQL
[[ $("${compose[@]}" exec -T postgres psql -At -U aera_cloud -d aera_cloud \
  -c 'SELECT max(version) FROM schema_migrations') == 23 ]] ||
  fail 'database did not reach schema 23'

(
  cd "$bridge_root"
  go test -count=1 -p 1 \
    ./internal/account \
    ./internal/agentcontrol \
    ./internal/device \
    ./internal/httpapi \
    ./internal/organization
  go test -count=1 ./cmd/aera-cloud -run '^TestSmokeAuthLifecycle$'
  CGO_ENABLED=0 go build -trimpath -o "$tmp_root/aera-cloud" ./cmd/aera-cloud
)

listen_address=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(f"127.0.0.1:{sock.getsockname()[1]}")
PY
)
export AGENTERA_CLOUD_LISTEN_ADDR="$listen_address"
export AGENTERA_CLOUD_PUBLIC_URL="http://$listen_address"
"$tmp_root/aera-cloud" >"$tmp_root/aera-cloud.log" 2>&1 &
app_pid=$!

ready=0
for _ in {1..30}; do
  if curl --fail --silent --show-error "http://$listen_address/health/ready" >/dev/null 2>&1; then
    ready=1
    break
  fi
  kill -0 "$app_pid" >/dev/null 2>&1 || break
  sleep 1
done
if [[ $ready != 1 ]]; then
  process_state=running
  kill -0 "$app_pid" >/dev/null 2>&1 || process_state=exited
  diagnostic=$(python3 - "$tmp_root/aera-cloud.log" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(errors="replace").lower()
categories = (
    ("database-migration", ("migration", "schema_migrations")),
    ("postgres", ("postgres", "database")),
    ("redis", ("redis",)),
    ("configuration", ("configuration", "config", "environment")),
    ("listener", ("listen", "bind", "address already in use")),
    ("registration", ("registration", "verification")),
    ("official-agent", ("official", "platform")),
)
print(next((name for name, needles in categories if any(needle in text for needle in needles)), "unclassified"))
PY
  )
  fail "verified bridge binary did not become ready on schema 23 (process=$process_state category=$diagnostic)"
fi
curl --fail --silent --show-error "http://$listen_address/health/live" >/dev/null

kill "$app_pid" >/dev/null 2>&1 || true
wait "$app_pid" >/dev/null 2>&1 || true
app_pid=
printf 'schema 23 compatibility passed: bridge=%s highest=23\n' "$bridge_sha"
