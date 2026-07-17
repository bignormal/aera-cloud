#!/usr/bin/env bash
set -euo pipefail
umask 077

required() {
  local name=$1
  [[ -n ${!name:-} ]] || {
    printf 'backup: %s is required\n' "$name" >&2
    exit 2
  }
}

for command in pg_dump age; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'backup: %s is required\n' "$command" >&2
    exit 2
  }
done

required AGENTERA_CLOUD_DATABASE_URL
required AGENTERA_BACKUP_AGE_RECIPIENT

backup_dir=${AGENTERA_BACKUP_DIR:-/var/backups/agentera-cloud}
mkdir -p "$backup_dir"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
output="$backup_dir/agentera-cloud-$timestamp.dump.age"
partial="$output.partial"
trap 'rm -f "$partial"' EXIT

pg_dump --dbname="$AGENTERA_CLOUD_DATABASE_URL" \
  --format=custom --compress=9 --no-owner --no-privileges | \
  age --encrypt --recipient "$AGENTERA_BACKUP_AGE_RECIPIENT" --output "$partial"

mv "$partial" "$output"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$backup_dir" && sha256sum "${output##*/}") > "$output.sha256"
else
  (cd "$backup_dir" && shasum -a 256 "${output##*/}") > "$output.sha256"
fi

printf 'backup: encrypted archive created at %s\n' "$output"
