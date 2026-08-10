#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'Runtime update mirror publication failed: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 1 ]] || fail "usage: ${0##*/} VERIFIED_BUNDLE_DIRECTORY"
for command_name in jq install find cmp; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "$command_name is required"
done

bundle=$1
[[ -d $bundle && ! -L $bundle ]] || fail 'bundle directory is missing or unsafe'
bundle=$(cd "$bundle" && pwd -P)
root=${AERA_RUNTIME_UPDATE_ROOT:-/var/lib/aera/runtime-updates/stable}
[[ $root == /* && $root != / && $root != /var && $root != /var/lib ]] ||
  fail 'AERA_RUNTIME_UPDATE_ROOT must be a bounded absolute path'
[[ ! -L $root ]] || fail 'Runtime update root cannot be a symlink'

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail 'sha256sum or shasum is required'
  fi
}

file_size() {
  wc -c <"$1" | tr -d ' '
}

require_regular_file() {
  local path=$1
  [[ -f $path && ! -L $path ]] ||
    fail "required regular file is missing: ${path##*/}"
}

validate_signature_envelope() {
  local path=$1
  local key_id=$2
  require_regular_file "$path"
  jq -e \
    --arg key_id "$key_id" \
    'type == "object" and
     (keys | sort) == ["algorithm","key_id","schema_version","signature_base64"] and
     .schema_version == 1 and
     .key_id == $key_id and
     .algorithm == "Ed25519" and
     (.signature_base64 | type == "string" and test("^[A-Za-z0-9+/]{86}==$"))' \
    "$path" >/dev/null || fail "signature envelope is invalid: ${path##*/}"
}

index_path="$bundle/agentera-runtime-stable.index.json"
index_signature_path="$bundle/agentera-runtime-stable.index.sig"
require_regular_file "$index_path"
require_regular_file "$index_signature_path"

jq -e '
  type == "object" and
  (keys | sort) == ["channel","created_at","key_id","release_tag","runtime_version","schema_version","source_commit","source_repository","targets"] and
  .schema_version == 1 and
  .channel == "stable" and
  .source_repository == "bignormal/aera-runtime" and
  (.key_id | type == "string" and test("^[a-z0-9][a-z0-9._-]{2,63}$")) and
  (.runtime_version | type == "string" and test("^[0-9]+(\\.[0-9]+)+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$")) and
  .release_tag == ("runtime-v" + .runtime_version) and
  (.source_commit | type == "string" and test("^[0-9a-f]{40}$")) and
  (.created_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$")) and
  (.targets | type == "array" and length == 2) and
  .targets[0].platform == "darwin" and .targets[0].arch == "arm64" and
  .targets[1].platform == "windows" and .targets[1].arch == "x64" and
  (all(.targets[];
    type == "object" and
    (keys | sort) == ["arch","archive_name","archive_sha256","manifest_name","platform","signature_name"] and
    (.archive_sha256 | type == "string" and test("^[0-9a-f]{64}$"))))
' "$index_path" >/dev/null || fail 'stable index contract is invalid'

version=$(jq -er '.runtime_version' "$index_path")
release_tag=$(jq -er '.release_tag' "$index_path")
source_commit=$(jq -er '.source_commit' "$index_path")
key_id=$(jq -er '.key_id' "$index_path")
validate_signature_envelope "$index_signature_path" "$key_id"

expected_names=(
  agentera-runtime-stable.index.json
  agentera-runtime-stable.index.sig
)

validate_target() {
  local target_index=$1
  local platform=$2
  local arch=$3
  local extension=$4
  local base="agentera-runtime-${version}-${platform}-${arch}"
  local archive_name="${base}${extension}"
  local manifest_name="${base}.manifest.json"
  local signature_name="${base}.manifest.sig"
  local archive_path="$bundle/$archive_name"
  local manifest_path="$bundle/$manifest_name"
  local signature_path="$bundle/$signature_name"
  local expected_sha actual_sha expected_size actual_size

  [[ $(jq -er ".targets[$target_index].archive_name" "$index_path") == "$archive_name" ]] ||
    fail "stable index archive name is invalid for $platform-$arch"
  [[ $(jq -er ".targets[$target_index].manifest_name" "$index_path") == "$manifest_name" ]] ||
    fail "stable index manifest name is invalid for $platform-$arch"
  [[ $(jq -er ".targets[$target_index].signature_name" "$index_path") == "$signature_name" ]] ||
    fail "stable index signature name is invalid for $platform-$arch"

  require_regular_file "$archive_path"
  require_regular_file "$manifest_path"
  validate_signature_envelope "$signature_path" "$key_id"
  expected_sha=$(jq -er ".targets[$target_index].archive_sha256" "$index_path")
  actual_sha=$(sha256_file "$archive_path")
  [[ $actual_sha == "$expected_sha" ]] ||
    fail "archive SHA-256 differs from the stable index for $platform-$arch"

  jq -e \
    --arg key_id "$key_id" \
    --arg version "$version" \
    --arg source_commit "$source_commit" \
    --arg platform "$platform" \
    --arg arch "$arch" \
    --arg archive_name "$archive_name" \
    --arg archive_sha "$actual_sha" \
    '.schema_version == 1 and
     .key_id == $key_id and
     .runtime_version == $version and
     .source_repository == "bignormal/aera-runtime" and
     .source_commit == $source_commit and
     .channel == "stable" and
     .platform == $platform and
     .arch == $arch and
     .archive_name == $archive_name and
     .archive_sha256 == $archive_sha and
     (.archive_size | type == "number" and . >= 0 and floor == .)' \
    "$manifest_path" >/dev/null ||
    fail "manifest differs from the stable index for $platform-$arch"
  expected_size=$(jq -er '.archive_size' "$manifest_path")
  actual_size=$(file_size "$archive_path")
  [[ $actual_size == "$expected_size" ]] ||
    fail "archive size differs from the manifest for $platform-$arch"

  expected_names+=("$archive_name" "$manifest_name" "$signature_name")
}

validate_target 0 darwin arm64 .tar.zst
validate_target 1 windows x64 .zip

shopt -s dotglob nullglob
bundle_entries=("$bundle"/*)
[[ ${#bundle_entries[@]} -eq ${#expected_names[@]} ]] ||
  fail 'bundle contains missing or extra entries'
for entry in "${bundle_entries[@]}"; do
  require_regular_file "$entry"
  name=${entry##*/}
  matched=false
  for expected_name in "${expected_names[@]}"; do
    if [[ $name == "$expected_name" ]]; then
      matched=true
      break
    fi
  done
  [[ $matched == true ]] || fail "bundle contains an unexpected file: $name"
done

install -d -m 0755 "$root" "$root/releases" "$root/staging"
lock_path="$root/.publish.lock"
mkdir "$lock_path" 2>/dev/null || fail 'another Runtime publication is active'
stage_path=
next_pointer=
cleanup() {
  if [[ -n $stage_path && -d $stage_path ]]; then
    chmod 0700 "$stage_path" 2>/dev/null || true
    find "$stage_path" -type f -exec chmod 0600 {} + 2>/dev/null || true
    rm -rf "$stage_path"
  fi
  if [[ -n $next_pointer && -L $next_pointer ]]; then
    rm "$next_pointer"
  fi
  rmdir "$lock_path" 2>/dev/null || true
}
trap cleanup EXIT

release_directory="$root/releases/$release_tag"
if [[ -e $release_directory || -L $release_directory ]]; then
  [[ -d $release_directory && ! -L $release_directory ]] ||
    fail 'immutable release path is not a regular directory'
  for expected_name in "${expected_names[@]}"; do
    require_regular_file "$release_directory/$expected_name"
    cmp -s "$bundle/$expected_name" "$release_directory/$expected_name" ||
      fail "immutable release already exists with different bytes: $expected_name"
    chmod 0444 "$release_directory/$expected_name"
  done
  chmod 0555 "$release_directory"
else
  stage_path="$root/staging/.${release_tag}.$$"
  mkdir -m 0700 "$stage_path"
  for expected_name in "${expected_names[@]}"; do
    install -m 0444 "$bundle/$expected_name" "$stage_path/$expected_name"
  done
  mv "$stage_path" "$release_directory"
  stage_path=
  chmod 0555 "$release_directory"
fi

pointer_target="releases/$release_tag"
if [[ -L $root/current && $(readlink "$root/current") == "$pointer_target" ]]; then
  printf 'Runtime update mirror already publishes %s\n' "$release_tag"
  exit 0
fi
if [[ -e $root/current || -L $root/current ]]; then
  [[ -L $root/current ]] || fail 'current Runtime pointer is not a symlink'
fi
next_pointer="$root/.current.$$"
ln -s "$pointer_target" "$next_pointer"
if [[ $(uname -s) == Darwin ]]; then
  mv -fh "$next_pointer" "$root/current"
else
  mv -Tf "$next_pointer" "$root/current"
fi
next_pointer=

printf 'Runtime update mirror now publishes %s\n' "$release_tag"
