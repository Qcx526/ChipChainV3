#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
metadata_dir="$repo_root/tools/qemu"
install_dir="$metadata_dir/install"
archive=""
verify_only=false
offline=false
bundle_name=qemu_11.1.1-chipchain-linux-x86_64.tar.xz
target_list=arm-softmmu,aarch64-softmmu,riscv32-softmmu,riscv64-softmmu,ppc-softmmu,ppc64-softmmu
executables=(qemu-system-arm qemu-system-aarch64 qemu-system-riscv32 qemu-system-riscv64 qemu-system-ppc qemu-system-ppc64)
representatives=(qemu-system-aarch64 qemu-system-riscv64 qemu-system-ppc64)
plugin_relative=lib/qemu/plugins/libexeclog.so

usage() {
  cat <<'EOF'
Usage: ./scripts/setup_qemu.sh [--verify-only] [--offline] [--archive PATH]
                              [--install-dir PATH]

Verify or install the pinned QEMU 11.1.1 Linux x86_64 runtime. Relative archive
paths are resolved from the current directory; relative install paths are
resolved from the repository root. Without an archive, use the cached bundle
or download its pinned ChipChain Release asset (unless --offline is set).
EOF
}

fail() {
  printf '[ChipChain] QEMU setup FAIL: %s\n' "$*" >&2
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
  [[ -f $required && ! -L $required ]] || fail "Missing or unsafe pinned metadata: $required"
done

declare -A version_meta=() source_meta=()
read_metadata() {
  local file=$1 array_name=$2 line key value
  local -n values=$array_name
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^([a-z_][a-z_0-9]*)=(.+)$ ]] || fail "Malformed pinned metadata line in $file"
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    [[ ! -v values[$key] ]] || fail "Duplicate pinned metadata key '$key' in $file"
    values[$key]=$value
  done < "$file"
}

IFS= read -r version_line < "$version_file" || fail "Malformed pinned version metadata: $version_file"
[[ $version_line == 'QEMU 11.1.1' ]] || fail "Malformed pinned version metadata: $version_file"
version_properties=$(mktemp)
trap 'rm -f -- "$version_properties"' EXIT
tail -n +2 -- "$version_file" > "$version_properties"
read_metadata "$version_properties" version_meta
read_metadata "$source_file" source_meta
rm -f -- "$version_properties"
trap - EXIT

[[ ${version_meta[supported_guest_families]:-} == arm,riscv,powerpc &&
   ${version_meta[supported_system_targets]:-} == "$target_list" &&
   ${version_meta[supported_host]:-} == linux-x86_64 &&
   ${version_meta[minimum_glibc]:-} == 2.35 ]] ||
  fail "Malformed pinned version metadata: $version_file"
[[ ${source_meta[official_source_url]:-} == https://download.qemu.org/qemu-11.1.1.tar.xz &&
   ${source_meta[official_version]:-} == 11.1.1 &&
   ${source_meta[official_source_sha256]:-} =~ ^[0-9a-f]{64}$ &&
   ${source_meta[chipchain_bundle_filename]:-} == "$bundle_name" &&
   ${source_meta[chipchain_bundle_sha256]:-} =~ ^[0-9a-f]{64}$ &&
   ${source_meta[chipchain_release_asset_url]:-} == "https://github.com/Qcx526/ChipChainV3/releases/download/v3-qemu-runtime-foundation-stable/$bundle_name" &&
   -n ${source_meta[build_host]:-} && -n ${source_meta[build_configuration]:-} &&
   -n ${source_meta[plugin_configuration]:-} && -n ${source_meta[capstone_status]:-} &&
   ${source_meta[build_glibc]:-} == 2.35 ]] ||
  fail "Malformed pinned source metadata: $source_file"

host_os=$(uname -s)
host_arch=$(uname -m)
[[ $host_os == Linux && $host_arch == x86_64 ]] ||
  fail "Unsupported host $host_os/$host_arch; this bundle supports Linux/x86_64 only."
command -v getconf >/dev/null 2>&1 || fail 'Cannot determine host glibc version (getconf is unavailable).'
host_libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || fail 'Host glibc is unavailable; this bundle requires glibc >=2.35.'
[[ $host_libc =~ ^glibc[[:space:]]+([0-9]+)\.([0-9]+)$ ]] ||
  fail "Unrecognized host libc '$host_libc'; this bundle requires glibc >=2.35."
host_glibc_major=${BASH_REMATCH[1]}
host_glibc_minor=${BASH_REMATCH[2]}
((10#$host_glibc_major > 2 ||
  (10#$host_glibc_major == 2 && 10#$host_glibc_minor >= 35))) ||
  fail "Host glibc $host_glibc_major.$host_glibc_minor is too old; required >=2.35."
command -v python3 >/dev/null 2>&1 || fail 'Python 3 is required for safe archive and manifest validation.'
command -v timeout >/dev/null 2>&1 || fail 'GNU timeout is required for bounded QEMU verification.'

validate_manifest() {
  python3 - "$manifest" <<'PY'
import pathlib
import re
import sys

manifest = pathlib.Path(sys.argv[1])
required = {
    'bin/qemu-system-arm', 'bin/qemu-system-aarch64',
    'bin/qemu-system-riscv32', 'bin/qemu-system-riscv64',
    'bin/qemu-system-ppc', 'bin/qemu-system-ppc64',
    'lib/qemu/plugins/libexeclog.so',
}
paths = set()
try:
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('malformed SHA256SUMS line')
        name = match.group(2)
        path = pathlib.PurePosixPath(name)
        if (path.is_absolute() or '..' in path.parts or '\\' in name
                or name.startswith('./') or str(path) != name or name in paths):
            raise ValueError(f'unsafe or duplicate SHA256SUMS path: {name}')
        paths.add(name)
    if not required <= paths:
        raise ValueError('SHA256SUMS omits a required emulator or plugin')
except (OSError, UnicodeError, ValueError) as error:
    sys.exit(f'[ChipChain] QEMU setup FAIL: Invalid installed-file manifest: {error}')
PY
}
validate_manifest

verify_files() {
  local root=$1
  python3 - "$root" "$manifest" <<'PY'
import hashlib
import os
import pathlib
import re
import stat
import sys

root, manifest = map(pathlib.Path, sys.argv[1:])
try:
    if root.is_symlink() or not root.is_dir():
        raise ValueError('install root is missing or a symlink')
    expected = {}
    for line in manifest.read_text().splitlines():
        digest, relative = line.split('  ', 1)
        expected[relative] = digest
    actual = set()
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            path = pathlib.Path(current) / name
            if not stat.S_ISDIR(path.lstat().st_mode):
                raise ValueError(f'unsafe directory entry: {path}')
        for name in files:
            path = pathlib.Path(current) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f'unsafe file entry: {path}')
            relative = path.relative_to(root).as_posix()
            actual.add(relative)
            if relative not in expected:
                raise ValueError(f'untracked installed file: {relative}')
            digest = hashlib.sha256()
            with path.open('rb') as installed:
                for chunk in iter(lambda: installed.read(1024 * 1024), b''):
                    digest.update(chunk)
            if digest.hexdigest() != expected[relative]:
                raise ValueError(f'installed-file checksum mismatch: {relative}')
    if actual != set(expected):
        raise ValueError(f'missing installed file: {sorted(set(expected) - actual)[0]}')
except (OSError, UnicodeError, ValueError) as error:
    sys.exit(f'[ChipChain] Installed-file verification failed: {error}')
PY
}

has_machine() {
  awk '/^Supported machines are:/{listed=1; next} listed && NF >= 2 && $1 != "none" {found=1} END {exit !found}'
}

verify_install() {
  local root=$1 executable binary output machines plugin status log missing_plugin
  verify_files "$root" || return 1
  for executable in "${executables[@]}"; do
    binary="$root/bin/$executable"
    [[ -f $binary && -x $binary && ! -L $binary ]] || {
      printf '[ChipChain] Missing executable: %s\n' "$binary" >&2
      return 1
    }
    if ! output=$(timeout --signal=TERM --kill-after=1s 10s "$binary" --version 2>&1); then
      printf '[ChipChain] Version probe failed: %s\n%s\n' "$binary" "$output" >&2
      return 1
    fi
    [[ $output =~ ^QEMU[[:space:]]emulator[[:space:]]version[[:space:]]11\.1\.1([[:space:]]|$) ]] || {
      printf '[ChipChain] QEMU version mismatch: %s: %s\n' "$binary" "$output" >&2
      return 1
    }
    if ! machines=$(timeout --signal=TERM --kill-after=1s 10s "$binary" -machine help 2>&1); then
      printf '[ChipChain] Machine probe failed: %s\n%s\n' "$binary" "$machines" >&2
      return 1
    fi
    if ! has_machine <<< "$machines"; then
      printf '[ChipChain] No supported machine listed: %s\n' "$binary" >&2
      return 1
    fi
    printf '[ChipChain] Verified %s: QEMU 11.1.1 and machine availability.\n' "$executable"
  done
  plugin="$root/$plugin_relative"
  [[ -f $plugin && ! -L $plugin ]] || {
    printf '[ChipChain] Missing execution-log plugin: %s\n' "$plugin" >&2
    return 1
  }
  for executable in "${representatives[@]}"; do
    missing_plugin="$root/.chipchain-intentionally-missing-plugin.so"
    status=0
    timeout --signal=TERM --kill-after=1s 3s "$root/bin/$executable" \
      -machine none -accel tcg -nographic -nodefaults -monitor none -serial none \
      -S -plugin "$missing_plugin" >/dev/null 2>&1 || status=$?
    if [[ $status == 0 || $status == 124 ]]; then
      printf '[ChipChain] Plugin rejection control failed for %s (exit %s).\n' "$executable" "$status" >&2
      return 1
    fi
    log=$(mktemp)
    status=0
    timeout --signal=TERM --kill-after=1s 3s "$root/bin/$executable" \
      -machine none -accel tcg -nographic -nodefaults -monitor none -serial none \
      -S -plugin "$plugin" >"$log" 2>&1 || status=$?
    if [[ $status != 124 ]]; then
      printf '[ChipChain] Plugin smoke failed for %s (exit %s):\n' "$executable" "$status" >&2
      cat -- "$log" >&2
      rm -f -- "$log"
      return 1
    fi
    rm -f -- "$log"
    printf '[ChipChain] Plugin load smoke passed: %s.\n' "$executable"
  done
}

if [[ -e $install_dir || -L $install_dir ]]; then
  verify_install "$install_dir" || fail "Existing installation is invalid; it was left untouched."
  printf '[ChipChain] Pinned QEMU is already installed.\n'
  printf '[ChipChain] QEMU setup PASS\n[ChipChain] Install: %s\n' "$install_dir"
  exit 0
fi

if $verify_only; then
  fail "QEMU is not installed at $install_dir. Provide the pinned bundle with --archive /path/to/$bundle_name."
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
  actual_sha=$(sha256sum -- "$checked_archive")
  actual_sha=${actual_sha%% *}
  [[ $actual_sha == "${source_meta[chipchain_bundle_sha256]}" ]] ||
    fail "Archive SHA256 mismatch for $checked_archive: got $actual_sha; required ${source_meta[chipchain_bundle_sha256]}."
  printf '[ChipChain] Archive SHA256 PASS.\n'
}

if [[ -z $archive ]]; then
  archive="$metadata_dir/$bundle_name"
  if [[ ! -f $archive ]]; then
    $offline && fail "QEMU is not installed and no cached bundle exists. Offline mode forbids download; provide --archive /path/to/$bundle_name."
    if command -v curl >/dev/null 2>&1; then
      downloader=curl
    elif command -v wget >/dev/null 2>&1; then
      downloader=wget
    else
      fail "Neither curl nor wget is available; provide the pinned bundle with --archive."
    fi
    download_stage=$(mktemp "$metadata_dir/.chipchain-qemu-download.XXXXXXXX")
    printf '[ChipChain] Downloading pinned QEMU bundle from %s\n' "${source_meta[chipchain_release_asset_url]}"
    if [[ $downloader == curl ]]; then
      curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 300 --output "$download_stage" \
        "${source_meta[chipchain_release_asset_url]}" || fail 'Download failed.'
    else
      wget --https-only --timeout=30 --tries=1 --output-document="$download_stage" \
        "${source_meta[chipchain_release_asset_url]}" || fail 'Download failed.'
    fi
    verify_bundle_sha "$download_stage"
    [[ ! -e $archive && ! -L $archive ]] || fail "Cached archive appeared during download; it was left untouched: $archive"
    mv -T -- "$download_stage" "$archive"
    download_stage=""
  fi
fi
[[ -f $archive ]] || fail "Local QEMU bundle is missing: $archive"
verify_bundle_sha "$archive"

install_parent=$(dirname -- "$install_dir")
mkdir -p -- "$install_parent"
stage=$(mktemp -d "$install_parent/.chipchain-qemu-stage.XXXXXXXX")

python3 - "$archive" "$stage" "${source_meta[chipchain_bundle_sha256]}" <<'PY'
import hashlib
import os
import pathlib
import shutil
import sys
import tarfile

archive, stage, expected_sha = sys.argv[1:]
try:
    with open(archive, 'rb') as source:
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
        actual_sha = digest.hexdigest()
        if actual_sha != expected_sha:
            raise ValueError('archive changed after SHA256 verification')
        source.seek(0)
        with tarfile.open(fileobj=source, mode='r:*') as bundle:
            members = bundle.getmembers()
            if not members:
                raise ValueError('archive is empty')
            paths = set()
            for member in members:
                name = member.name
                path = pathlib.PurePosixPath(name)
                if (path.is_absolute() or '..' in path.parts or '\\' in name
                        or not (member.isfile() or member.isdir())):
                    raise ValueError(f'unsafe archive entry: {name}')
                normalized = str(path)
                if normalized != '.' and normalized in paths:
                    raise ValueError(f'duplicate archive entry: {name}')
                paths.add(normalized)
            for member in members:
                target = pathlib.Path(stage) / member.name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        raise ValueError(f'cannot read archive entry: {member.name}')
                    with extracted, target.open('xb') as destination:
                        shutil.copyfileobj(extracted, destination)
                    os.chmod(target, member.mode & 0o755)
except (OSError, tarfile.TarError, ValueError) as error:
    sys.exit(f'[ChipChain] QEMU setup FAIL: Archive rejected: {error}')
PY

verify_install "$stage" || fail 'Staged QEMU failed pinned validation; no installation was promoted.'
[[ ! -e $install_dir && ! -L $install_dir ]] || fail 'Install directory appeared during staging; it was left untouched.'
chmod 755 -- "$stage"
mv -T -- "$stage" "$install_dir"
stage=""
printf '[ChipChain] QEMU setup PASS\n[ChipChain] Install: %s\n' "$install_dir"
