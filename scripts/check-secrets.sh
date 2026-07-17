#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s [--repo PATH]\n' "${0##*/}" >&2
  exit 2
}

repo_root=
if [[ $# -eq 0 ]]; then
  repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
    printf 'check-secrets: current directory is not a Git repository\n' >&2
    exit 2
  }
elif [[ $# -eq 2 && $1 == "--repo" ]]; then
  repo_root=$(git -C "$2" rev-parse --show-toplevel 2>/dev/null) || {
    printf 'check-secrets: --repo must point to a Git repository\n' >&2
    exit 2
  }
else
  usage
fi

findings=$(mktemp)
trap 'rm -f "$findings"' EXIT

report() {
  printf '%s: %s\n' "$1" "$2" >> "$findings"
}

is_allowed_example_env() {
  [[ $1 == ".env.example" || $1 == */.env.example ]]
}

is_test_fixture() {
  case "$1" in
    *_test.go|*.test.ts|*.test.tsx|web/tests/*|scripts/tests/*)
      return 0
      ;;
  esac
  return 1
}

while IFS= read -r -d '' relative; do
  case "$relative" in
    .env|.env.*|*/.env|*/.env.*)
      if ! is_allowed_example_env "$relative"; then
        report "$relative" "committed environment file"
      fi
      ;;
  esac

  absolute="$repo_root/$relative"
  [[ -f "$absolute" ]] || continue
  grep -Iq . "$absolute" || continue

  if grep -Eq -- '-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----' "$absolute"; then
    report "$relative" "PEM private key marker"
  fi

  if ! is_test_fixture "$relative"; then
    if grep -Eq -- '(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})' "$absolute"; then
      report "$relative" "token-shaped value"
    fi
    if [[ $relative != go.sum && $relative != */package-lock.json && $relative != internal/webui/static/* ]] &&
      grep -Eq -- '(^|[^0-9])[0-9]{6}([^0-9]|$)' "$absolute"; then
      report "$relative" "plaintext six-digit verification-code shape"
    fi
  fi

  if ! is_test_fixture "$relative" &&
    [[ $relative != .env.example && $relative != */.env.example ]] &&
    grep -Eq -- 'AGENTERA_CLOUD_(SMTP_HOST|SMS_ENDPOINT|CAPTCHA_ENDPOINT).*\.invalid([^A-Za-z0-9.-]|$)' "$absolute"; then
    report "$relative" "fake provider configured outside the development example"
  fi
done < <(git -C "$repo_root" ls-files -z)

if [[ -s "$findings" ]]; then
  printf 'check-secrets: rejected tracked secret or production-fixture patterns:\n' >&2
  sort -u "$findings" >&2
  exit 1
fi

printf 'check-secrets: tracked files passed secret-boundary checks\n'
