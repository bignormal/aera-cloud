#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

project=
cleanup() {
  if [[ -n $project ]]; then
    docker compose -p "$project" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ ${AERA_SMOKE_USE_EXISTING_STACK:-0} == 1 ]]; then
  [[ ${AERA_SMOKE_ALLOW_DATABASE_RESET:-0} == 1 ]] || {
    printf 'smoke-auth: existing-stack mode requires AERA_SMOKE_ALLOW_DATABASE_RESET=1\n' >&2
    exit 2
  }
  : "${AGENTERA_CLOUD_DATABASE_URL:?source a non-production smoke environment first}"
  : "${AGENTERA_CLOUD_REDIS_ADDR:?source a non-production smoke environment first}"
else
  command -v docker >/dev/null 2>&1 || {
    printf 'smoke-auth: Docker is required for the isolated stack\n' >&2
    exit 2
  }
  project="agentera-cloud-smoke-$$"
  AERA_CLOUD_POSTGRES_BIND='127.0.0.1:'
  AERA_CLOUD_REDIS_BIND='127.0.0.1:'
  export AERA_CLOUD_POSTGRES_BIND AERA_CLOUD_REDIS_BIND
  docker compose -p "$project" up -d --wait postgres redis
  postgres_address=$(docker compose -p "$project" port postgres 5432)
  redis_address=$(docker compose -p "$project" port redis 6379)
  set -a
  source .env.example
  set +a
  AGENTERA_CLOUD_DATABASE_URL="postgres://aera_cloud:aera-cloud-dev-only@${postgres_address}/aera_cloud?sslmode=disable"
  AGENTERA_CLOUD_REDIS_ADDR="$redis_address"
  export AGENTERA_CLOUD_DATABASE_URL AGENTERA_CLOUD_REDIS_ADDR
fi

case ${AGENTERA_CLOUD_ENVIRONMENT:-} in
  development|test) ;;
  *)
    printf 'smoke-auth: refusing to reset a production or unknown environment\n' >&2
    exit 2
    ;;
esac

case $AGENTERA_CLOUD_DATABASE_URL in
  *127.0.0.1*|*localhost*) ;;
  *)
    printf 'smoke-auth: database must be loopback-only\n' >&2
    exit 2
    ;;
esac

export AERA_INTEGRATION_TESTS=1
go test -count=1 ./cmd/aera-cloud -run '^TestSmokeAuthLifecycle$'
go run ./cmd/aera-cloud-admin --operator restore-verify verify-identities >/dev/null
printf 'smoke-auth: health, registration, browser session, PKCE, rotation, revoke, and recovery-key checks passed\n'
