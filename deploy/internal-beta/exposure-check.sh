#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'internal beta exposure check failed: %s\n' "$1" >&2
  exit 1
}

command -v ss >/dev/null 2>&1 || fail 'ss is required'
command -v docker >/dev/null 2>&1 || fail 'docker is required'

ssh_port=${AERA_INTERNAL_BETA_SSH_PORT:-22}
[[ $ssh_port =~ ^[1-9][0-9]{0,4}$ && $ssh_port -le 65535 ]] ||
  fail 'AERA_INTERNAL_BETA_SSH_PORT is invalid'

while IFS= read -r listener; do
  [[ -n $listener ]] || continue
  local_address=$(awk '{print $4}' <<<"$listener")
  case "$local_address" in
    0.0.0.0:* | "[::]":* | "*":*)
      port=${local_address##*:}
      case "$port" in
        "$ssh_port" | 80 | 443) ;;
        *) fail "unexpected public host listener on port $port" ;;
      esac
      ;;
  esac
done < <(ss -H -lnt)

while IFS=$'\t' read -r container ports; do
  [[ -n ${container:-} ]] || continue
  if [[ $ports == *"0.0.0.0:"* || $ports == *":::"* || $ports == *"[::]:"* ]]; then
    fail "container $container publishes a port on every interface"
  fi
  if [[ $ports =~ (5432|6379|9000|9001|8443|2375|2376)/tcp ]] &&
    [[ $ports == *"->"* ]]; then
    fail "container $container publishes a protected data or control port"
  fi
done < <(docker ps --format '{{.Names}}\t{{.Ports}}')

printf 'internal beta exposure check passed\n'
