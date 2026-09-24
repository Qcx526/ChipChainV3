#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
metadata_dir="$repo_root/tools/ghidra"
install_dir="$metadata_dir/install"
archive=""
verify_only=false
offline=false

usage() {
  cat <<'EOF'
Usage: ./scripts/setup_ghidra.sh [--verify-only] [--offline] [--archive PATH]
                                [--install-dir PATH]

Verify the pinned project-managed Ghidra installation, or install it from a
local archive. When no installation, archive or cache exists, download the
pinned ChipChain Release asset unless --offline is set. Relative paths are
resolved from the current directory for --archive and from the repository
root for --install-dir.
EOF
}

fail() {
  printf '[ChipChain] Ghidra setup FAIL: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --verify-only) verify_only=true; shift ;;
    --offline) offline=true; shift ;;
    --archive|--install-dir)
      option=$1
      (($# >= 2)) || fail "$option requires a path."
      [[ -n $2 ]] || fail "$option requires a nonempty path."
      if [[ $option == --archive ]]; then
        archive=$2
      elif [[ $2 == /* ]]; then
        install_dir=$2
      else
        install_dir="$repo_root/$2"
      fi
      shift 2 ;;
    *) fail "Unknown option: $1. Run --help for usage." ;;
  esac
done

if $verify_only && [[ -n $archive ]]; then
  fail '--verify-only and --archive cannot be combined.'
fi

version_file="$metadata_dir/VERSION"
source_file="$metadata_dir/SOURCE"
manifest="$metadata_dir/SHA256SUMS"
for required in "$version_file" "$source_file" "$manifest"; do
  [[ -f $required ]] || fail "Missing pinned metadata: $required"
done

pinned_version=""
pinned_release=""
pinned_revision=""
minimum_java=""
first_line=true
while IFS= read -r line || [[ -n $line ]]; do
  if $first_line; then
    if [[ $line =~ ^Ghidra[[:space:]]+([^[:space:]]+)[[:space:]]+(.+)$ ]]; then
      pinned_version=${BASH_REMATCH[1]}
      pinned_release=${BASH_REMATCH[2]}
    fi
    first_line=false
  fi
  case "$line" in
    upstream_revision=*) pinned_revision=${line#*=} ;;
    minimum_java=*) minimum_java=${line#*=} ;;
  esac
done < "$version_file"
[[ -n $pinned_version && -n $pinned_release && $pinned_revision =~ ^[0-9a-f]{40}$ && $minimum_java =~ ^[0-9]+$ ]] ||
  fail "Malformed pinned version metadata: $version_file"

bundle_sha=""
release_url=""
while IFS= read -r line || [[ -n $line ]]; do
  case "$line" in
    'Local bundle SHA256: '*) bundle_sha=${line#'Local bundle SHA256: '} ;;
    chipchain_release_asset_url=*) release_url=${line#*=} ;;
  esac
done < "$source_file"
[[ $bundle_sha =~ ^[0-9a-f]{64}$ ]] || fail "Missing local bundle SHA256 in $source_file"
[[ $release_url =~ ^https://[^[:space:]]+$ && ${release_url##*/} == ghidra_12.3_DEV-local.tar.gz ]] ||
  fail "Missing or invalid HTTPS ChipChain release asset URL in $source_file"

printf '[ChipChain] Repository: %s\n' "$repo_root"
printf '[ChipChain] Required Java: >=%s\n' "$minimum_java"
if ! command -v java >/dev/null 2>&1; then
  fail "Java: unavailable. Install Java $minimum_java or newer and retry; no Ghidra files were changed."
fi
if ! java_output=$(java -XshowSettings:properties -version 2>&1); then
  fail "Java: unavailable (java could not run). Install Java $minimum_java or newer and retry; no Ghidra files were changed."
fi
java_spec=""
java_version=""
while IFS= read -r line; do
  if [[ $line =~ ^[[:space:]]*java\.specification\.version[[:space:]]*=[[:space:]]*([^[:space:]]+) ]]; then
    java_spec=${BASH_REMATCH[1]}
  elif [[ $line =~ ^[[:space:]]*java\.version[[:space:]]*=[[:space:]]*([^[:space:]]+) ]]; then
    java_version=${BASH_REMATCH[1]}
  fi
done <<< "$java_output"
if [[ $java_spec =~ ^1\.([0-9]+)$ ]]; then
  java_major=${BASH_REMATCH[1]}
elif [[ $java_spec =~ ^([0-9]+)(\.[0-9]+)*$ ]]; then
  java_major=${BASH_REMATCH[1]}
else
  fail "Java: unrecognized specification version '${java_spec:-unknown}'; required >=$minimum_java."
fi
printf '[ChipChain] Java: %s (specification %s)\n' "${java_version:-$java_spec}" "$java_spec"
((10#$java_major >= 10#$minimum_java)) ||
  fail "Java $java_major is too old; required >=$minimum_java. No Ghidra files were changed."

manifest_entries=$(wc -l < "$manifest")
((manifest_entries > 0)) || fail "Empty checksum manifest: $manifest"

property_value() {
  local wanted=$1 property_file=$2 line
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "$wanted="* ]]; then
      printf '%s' "${line#*=}"
      return 0
    fi
  done < "$property_file"
  return 1
}

verify_install() {
  local root=$1 properties version release revision
  [[ -f "$root/support/analyzeHeadless" && -f "$root/Ghidra/application.properties" ]] || {
    printf '[ChipChain] Missing support/analyzeHeadless or Ghidra/application.properties in %s\n' "$root" >&2
    return 1
  }
  properties="$root/Ghidra/application.properties"
  version=$(property_value application.version "$properties") || version=""
  release=$(property_value application.release.name "$properties") || release=""
  revision=$(property_value application.revision.ghidra "$properties") || revision=""
  if [[ $version != "$pinned_version" || $release != "$pinned_release" || $revision != "$pinned_revision" ]]; then
    printf '[ChipChain] Ghidra version/revision mismatch in %s: got %s %s / %s; required %s %s / %s\n' \
      "$root" "${version:-missing}" "${release:-missing}" "${revision:-missing}" \
      "$pinned_version" "$pinned_release" "$pinned_revision" >&2
    return 1
  fi
  printf '[ChipChain] Ghidra: %s %s\n' "$version" "$release"
  printf '[ChipChain] Revision: %s\n' "$revision"
  printf '[ChipChain] Verifying %s files...\n' "$manifest_entries"
  if ! (cd -- "$root" && sha256sum --check --quiet --strict "$manifest"); then
    printf '[ChipChain] Installed-file checksum verification failed in %s\n' "$root" >&2
    return 1
  fi
}

if [[ -e $install_dir || -L $install_dir ]]; then
  verify_install "$install_dir" || fail "Existing installation is invalid; it was left untouched. See $metadata_dir/README.md."
  printf '[ChipChain] Pinned Ghidra is already installed.\n'
  printf '[ChipChain] Ghidra setup PASS\n[ChipChain] Install: %s\n' "$install_dir"
  exit 0
fi

if $verify_only; then
  fail "Ghidra is not installed at $install_dir. Provide the pinned local distribution with: ./scripts/setup_ghidra.sh --archive /path/to/archive.tar.gz (see tools/ghidra/README.md)."
fi

download_stage=""
stage=""
cleanup() {
  [[ -z $stage ]] || rm -rf -- "$stage"
  [[ -z $download_stage ]] || rm -f -- "$download_stage"
}
trap cleanup EXIT

verify_bundle_sha() {
  local checked_archive=$1 actual_sha
  printf '[ChipChain] Verifying archive SHA256...\n'
  actual_sha=$(sha256sum -- "$checked_archive")
  actual_sha=${actual_sha%% *}
  [[ $actual_sha == "$bundle_sha" ]] || fail "Archive SHA256 mismatch for $checked_archive: got $actual_sha; required $bundle_sha. No extraction or cache promotion occurred."
  printf '[ChipChain] Archive SHA256 PASS.\n'
}

archive_verified=false
if [[ -z $archive ]]; then
  archive="$metadata_dir/ghidra_12.3_DEV-local.tar.gz"
  if [[ ! -f $archive ]]; then
    if $offline; then
      fail "Ghidra is not installed and no cached bundle exists. Offline mode forbids download; provide the pinned distribution with: ./scripts/setup_ghidra.sh --offline --archive /path/to/archive.tar.gz"
    fi
    if command -v curl >/dev/null 2>&1; then
      downloader=curl
    elif command -v wget >/dev/null 2>&1; then
      downloader=wget
    else
      fail "Neither curl nor wget is available. Install one downloader or provide the archive explicitly: ./scripts/setup_ghidra.sh --archive /path/to/archive.tar.gz"
    fi
    printf '[ChipChain] Ghidra is not installed.\n'
    printf '[ChipChain] Downloading pinned Ghidra %s %s...\n' "$pinned_version" "$pinned_release"
    printf '[ChipChain] Source:\n  %s\n' "$release_url"
    download_stage=$(mktemp "$metadata_dir/.chipchain-download.XXXXXXXX")
    if [[ $downloader == curl ]]; then
      curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
        --output "$download_stage" "$release_url" || fail "Download failed. Retry or provide a local archive with --archive."
    else
      wget --https-only --output-document="$download_stage" "$release_url" ||
        fail "Download failed. Retry or provide a local archive with --archive."
    fi
    printf '[ChipChain] Download complete.\n'
    verify_bundle_sha "$download_stage"
    archive_verified=true
    [[ ! -e $archive && ! -L $archive ]] || fail "Cached archive appeared during download; it was not overwritten: $archive"
    mv -T -- "$download_stage" "$archive"
    download_stage=""
  fi
fi
[[ -f $archive ]] || fail "Ghidra is not installed and local archive is missing: $archive. Provide the pinned distribution with: ./scripts/setup_ghidra.sh --archive /path/to/archive.tar.gz (see tools/ghidra/README.md)."

if [[ ${archive##*/} == ghidra_12.3_DEV-local.tar.gz ]]; then
  $archive_verified || verify_bundle_sha "$archive"
else
  printf '[ChipChain] External archive: installed files will be checked against the pinned manifest; no original-archive hash is claimed.\n'
fi

command -v python3 >/dev/null 2>&1 || fail 'Python 3 is required to safely inspect and extract the local archive.'
install_parent=$(dirname -- "$install_dir")
mkdir -p -- "$install_parent"
stage=$(mktemp -d "$install_parent/.chipchain-ghidra-stage.XXXXXXXX")

python3 - "$archive" "$stage" <<'PY'
import pathlib
import sys
import tarfile

archive, stage = sys.argv[1:]
try:
    with tarfile.open(archive, "r:*") as bundle:
        members = bundle.getmembers()
        if not members:
            raise ValueError("archive is empty")
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or not (member.isfile() or member.isdir())):
                raise ValueError(f"unsafe archive entry: {member.name}")
        bundle.extractall(stage, members=members)
except (OSError, tarfile.TarError, ValueError) as error:
    sys.exit(f"[ChipChain] Ghidra setup FAIL: Archive rejected: {error}")
PY

mapfile -d '' properties_files < <(find "$stage" -type f -path '*/Ghidra/application.properties' -print0)
candidates=()
for properties in "${properties_files[@]}"; do
  candidate=$(dirname -- "$(dirname -- "$properties")")
  if [[ -f $candidate/support/analyzeHeadless ]]; then
    candidates+=("$candidate")
  fi
done
((${#candidates[@]} == 1)) || fail "Archive must contain exactly one Ghidra root with support/analyzeHeadless and Ghidra/application.properties; found ${#candidates[@]}."

verify_install "${candidates[0]}" || fail 'Staged Ghidra failed pinned validation; existing installation was not changed.'
[[ ! -e $install_dir && ! -L $install_dir ]] || fail 'Install directory appeared during staging; it was not overwritten.'
mv -T -- "${candidates[0]}" "$install_dir"
printf '[ChipChain] Ghidra setup PASS\n[ChipChain] Install: %s\n' "$install_dir"
