#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
policy="$repo_root/scripts/release/resolve-schema-maximum.sh"
bridge_sha=0bf56678c772c918e08423f0ad1c3aeb868cdc7e
current_sha=87631f0b40d6551c2cafd3f3d11b222f1e02d271
ordinary_sha=1111111111111111111111111111111111111111

fail() {
  printf 'schema maximum policy test failed: %s\n' "$1" >&2
  exit 1
}

[[ -x "$policy" ]] || fail 'policy resolver is missing or not executable'
[[ $("$policy" "$bridge_sha" 22) == 23 ]] ||
  fail 'verified schema 22 bridge must declare compatibility through schema 23'
[[ $("$policy" "$current_sha" 23) == 23 ]] ||
  fail 'current schema 23 source must retain schema maximum 23'
[[ $("$policy" "$ordinary_sha" 22) == 22 ]] ||
  fail 'unverified schema 22 source must not gain forward-schema compatibility'

if "$policy" "$bridge_sha" 23 >/dev/null 2>&1; then
  fail 'bridge mapping accepted an unexpected embedded migration'
fi
if "$policy" not-a-sha 22 >/dev/null 2>&1; then
  fail 'policy accepted a non-canonical source SHA'
fi
if "$policy" "$ordinary_sha" 0 >/dev/null 2>&1; then
  fail 'policy accepted an invalid migration version'
fi
if "$policy" "$ordinary_sha" 22 unexpected >/dev/null 2>&1; then
  fail 'policy accepted an arbitrary schema maximum argument'
fi

printf 'schema maximum policy tests passed\n'
