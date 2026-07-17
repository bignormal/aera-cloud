#!/usr/bin/env bash
set -euo pipefail
umask 077

required() {
  local name=$1
  [[ -n ${!name:-} ]] || {
    printf 'restore-verify: %s is required\n' "$name" >&2
    exit 2
  }
}

for command in age createdb dropdb pg_restore psql; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'restore-verify: %s is required\n' "$command" >&2
    exit 2
  }
done

required AGENTERA_RESTORE_BACKUP
required AGENTERA_RESTORE_AGE_IDENTITY
required AGENTERA_RESTORE_ADMIN_URL
required AGENTERA_CLOUD_IDENTITY_ENCRYPTION_KEYS

[[ -r $AGENTERA_RESTORE_BACKUP ]] || {
  printf 'restore-verify: encrypted backup is unreadable\n' >&2
  exit 2
}
[[ -r $AGENTERA_RESTORE_AGE_IDENTITY ]] || {
  printf 'restore-verify: age identity is unreadable\n' >&2
  exit 2
}

if [[ -r $AGENTERA_RESTORE_BACKUP.sha256 ]]; then
  backup_dir=${AGENTERA_RESTORE_BACKUP%/*}
  backup_name=${AGENTERA_RESTORE_BACKUP##*/}
  [[ $backup_dir != "$AGENTERA_RESTORE_BACKUP" ]] || backup_dir=.
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$backup_dir" && sha256sum -c "$backup_name.sha256" >/dev/null)
  else
    (cd "$backup_dir" && shasum -a 256 -c "$backup_name.sha256" >/dev/null)
  fi
fi

database_url_for() {
  local source=$1
  local database=$2
  local base=$source
  local query=
  if [[ $source == *\?* ]]; then
    base=${source%%\?*}
    query="?${source#*\?}"
  fi
  printf '%s/%s%s\n' "${base%/*}" "$database" "$query"
}

disposable_database="aera_restore_verify_$(date -u +%Y%m%d%H%M%S)_$$"
restored_url=$(database_url_for "$AGENTERA_RESTORE_ADMIN_URL" "$disposable_database")
created=0

drop_disposable_database() {
  if [[ $created == 1 ]]; then
    dropdb --if-exists --force --maintenance-db="$AGENTERA_RESTORE_ADMIN_URL" "$disposable_database" >/dev/null
  fi
}
trap drop_disposable_database EXIT

createdb --maintenance-db="$AGENTERA_RESTORE_ADMIN_URL" "$disposable_database"
created=1
age --decrypt --identity "$AGENTERA_RESTORE_AGE_IDENTITY" "$AGENTERA_RESTORE_BACKUP" | \
  pg_restore --exit-on-error --no-owner --no-privileges --dbname="$restored_url"

integrity_failures=$(psql "$restored_url" --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 --command="
  SELECT
    (SELECT count(*) FROM users u LEFT JOIN password_credentials p ON p.user_id = u.id WHERE p.user_id IS NULL) +
    (SELECT count(*) FROM users u LEFT JOIN personal_spaces s ON s.owner_user_id = u.id WHERE s.id IS NULL) +
    (SELECT count(*) FROM identities i LEFT JOIN users u ON u.id = i.user_id WHERE u.id IS NULL) +
    (SELECT count(*) FROM identities WHERE octet_length(nonce) <> 12 OR octet_length(ciphertext) <= 16);
")
[[ $integrity_failures == 0 ]] || {
  printf 'restore-verify: relational integrity checks failed\n' >&2
  exit 1
}

migration_count=$(psql "$restored_url" --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 \
  --command='SELECT count(*) FROM schema_migrations;')
[[ $migration_count -gt 0 ]] || {
  printf 'restore-verify: migration ledger is empty\n' >&2
  exit 1
}

if [[ -n ${AGENTERA_CLOUD_ADMIN_BIN:-} ]]; then
  admin_command=("$AGENTERA_CLOUD_ADMIN_BIN")
elif command -v aera-cloud-admin >/dev/null 2>&1; then
  admin_command=(aera-cloud-admin)
elif command -v go >/dev/null 2>&1 && [[ -f cmd/aera-cloud-admin/main.go ]]; then
  admin_command=(go run ./cmd/aera-cloud-admin)
else
  printf 'restore-verify: aera-cloud-admin or a Go source checkout is required\n' >&2
  exit 2
fi

AGENTERA_CLOUD_DATABASE_URL="$restored_url" \
  "${admin_command[@]}" --operator restore-verify verify-identities >/dev/null

printf 'restore-verify: disposable restore, integrity checks, and identity decryption passed\n'
