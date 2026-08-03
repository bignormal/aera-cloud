#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
publisher="$repo_root/deploy/internal-beta/publish-runtime-update.sh"

fail() {
  printf 'Runtime update mirror test failed: %s\n' "$1" >&2
  exit 1
}

[[ -x $publisher ]] || fail 'publisher is missing or not executable'

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_mode() {
  if [[ $(uname -s) == Darwin ]]; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

write_signature() {
  local path=$1
  local key_id=$2
  local signature
  signature=$(printf '%*s' 86 '' | tr ' ' A)
  jq -cnS \
    --arg key_id "$key_id" \
    --arg signature_base64 "${signature}==" \
    '{algorithm:"Ed25519",key_id:$key_id,schema_version:1,signature_base64:$signature_base64}' \
    >"$path"
}

write_manifest() {
  local path=$1
  local key_id=$2
  local version=$3
  local source_commit=$4
  local platform=$5
  local arch=$6
  local archive_name=$7
  local archive_path=$8
  local archive_sha archive_size
  archive_sha=$(sha256_file "$archive_path")
  archive_size=$(wc -c <"$archive_path" | tr -d ' ')
  jq -cnS \
    --arg key_id "$key_id" \
    --arg version "$version" \
    --arg source_commit "$source_commit" \
    --arg platform "$platform" \
    --arg arch "$arch" \
    --arg archive_name "$archive_name" \
    --arg archive_sha "$archive_sha" \
    --argjson archive_size "$archive_size" \
    '{arch:$arch,archive_name:$archive_name,archive_sha256:$archive_sha,archive_size:$archive_size,channel:"stable",key_id:$key_id,platform:$platform,runtime_version:$version,schema_version:1,source_commit:$source_commit,source_repository:"bignormal/aera-runtime"}' \
    >"$path"
}

write_bundle() {
  local directory=$1
  local darwin_payload=$2
  local windows_payload=$3
  local version=0.18.2-agentera.3
  local release_tag=runtime-v0.18.2-agentera.3
  local source_commit=d8536e72a919eaa31245ea40dbc1faecf9e82d3d
  local key_id=agentera-runtime-2026-01
  local darwin_base="agentera-runtime-${version}-darwin-arm64"
  local windows_base="agentera-runtime-${version}-windows-x64"
  local darwin_archive="${darwin_base}.tar.zst"
  local windows_archive="${windows_base}.zip"
  mkdir -p "$directory"
  printf '%s' "$darwin_payload" >"$directory/$darwin_archive"
  printf '%s' "$windows_payload" >"$directory/$windows_archive"
  write_manifest \
    "$directory/${darwin_base}.manifest.json" "$key_id" "$version" \
    "$source_commit" darwin arm64 "$darwin_archive" \
    "$directory/$darwin_archive"
  write_manifest \
    "$directory/${windows_base}.manifest.json" "$key_id" "$version" \
    "$source_commit" windows x64 "$windows_archive" \
    "$directory/$windows_archive"
  write_signature "$directory/${darwin_base}.manifest.sig" "$key_id"
  write_signature "$directory/${windows_base}.manifest.sig" "$key_id"
  jq -cnS \
    --arg key_id "$key_id" \
    --arg version "$version" \
    --arg release_tag "$release_tag" \
    --arg source_commit "$source_commit" \
    --arg darwin_archive "$darwin_archive" \
    --arg darwin_sha "$(sha256_file "$directory/$darwin_archive")" \
    --arg windows_archive "$windows_archive" \
    --arg windows_sha "$(sha256_file "$directory/$windows_archive")" \
    '{channel:"stable",created_at:"2026-08-03T00:00:00Z",key_id:$key_id,release_tag:$release_tag,runtime_version:$version,schema_version:1,source_commit:$source_commit,source_repository:"bignormal/aera-runtime",targets:[{arch:"arm64",archive_name:$darwin_archive,archive_sha256:$darwin_sha,manifest_name:($darwin_archive|sub("\\.tar\\.zst$";".manifest.json")),platform:"darwin",signature_name:($darwin_archive|sub("\\.tar\\.zst$";".manifest.sig"))},{arch:"x64",archive_name:$windows_archive,archive_sha256:$windows_sha,manifest_name:($windows_archive|sub("\\.zip$";".manifest.json")),platform:"windows",signature_name:($windows_archive|sub("\\.zip$";".manifest.sig"))}]}' \
    >"$directory/agentera-runtime-stable.index.json"
  write_signature "$directory/agentera-runtime-stable.index.sig" "$key_id"
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/aera-runtime-mirror.XXXXXX")
cleanup() {
  chmod -R u+w "$tmp" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

bundle="$tmp/bundle"
root="$tmp/root"
write_bundle "$bundle" darwin-v1 windows-v1
AERA_RUNTIME_UPDATE_ROOT="$root" "$publisher" "$bundle"

release_tag=runtime-v0.18.2-agentera.3
[[ -L $root/current ]] || fail 'current pointer is not an atomic symlink'
[[ $(readlink "$root/current") == "releases/$release_tag" ]] ||
  fail 'current pointer does not select the published release'
cmp -s \
  "$bundle/agentera-runtime-stable.index.json" \
  "$root/current/agentera-runtime-stable.index.json" ||
  fail 'current index bytes differ from the supplied bundle'
[[ $(file_mode "$root/releases/$release_tag") == 555 ]] ||
  fail 'release directory is not read-only'
[[ $(file_mode "$root/current/agentera-runtime-stable.index.json") == 444 ]] ||
  fail 'published metadata is not read-only'

# Exact re-publication is idempotent and does not replace immutable bytes.
AERA_RUNTIME_UPDATE_ROOT="$root" "$publisher" "$bundle"

conflict="$tmp/conflict"
write_bundle "$conflict" darwin-v2 windows-v2
if AERA_RUNTIME_UPDATE_ROOT="$root" "$publisher" "$conflict"; then
  fail 'same-tag different bytes were accepted'
fi
cmp -s \
  "$bundle/agentera-runtime-stable.index.json" \
  "$root/current/agentera-runtime-stable.index.json" ||
  fail 'failed conflict changed current metadata'

tampered="$tmp/tampered"
cp -R "$bundle" "$tampered"
printf 'tamper' >>"$tampered/agentera-runtime-0.18.2-agentera.3-windows-x64.zip"
if AERA_RUNTIME_UPDATE_ROOT="$tmp/tampered-root" "$publisher" "$tampered"; then
  fail 'archive digest mismatch was accepted'
fi
[[ ! -e $tmp/tampered-root/current ]] ||
  fail 'invalid bundle created a current pointer'

printf 'Runtime update mirror tests passed\n'
