#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'cloud schema compatibility policy failed: %s\n' "$1" >&2
  exit 1
}

[[ $# == 2 ]] || fail 'usage: resolve-schema-maximum.sh SOURCE_SHA HIGHEST_MIGRATION'

source_sha=$1
highest_migration=$2
[[ $source_sha =~ ^[0-9a-f]{40}$ ]] || fail 'source SHA must be 40 lowercase hexadecimal characters'
[[ $highest_migration =~ ^[1-9][0-9]*$ ]] || fail 'highest migration must be a positive integer'

case "$source_sha:$highest_migration" in
  0bf56678c772c918e08423f0ad1c3aeb868cdc7e:22)
    printf '23\n'
    ;;
  0bf56678c772c918e08423f0ad1c3aeb868cdc7e:*)
    fail 'verified schema 23 bridge source has an unexpected embedded migration'
    ;;
  *)
    printf '%s\n' "$highest_migration"
    ;;
esac
