#!/usr/bin/env bash
set -euo pipefail

# Maintainer-only builder. Customer machines use setup_qemu.sh and the pinned
# ChipChain bundle, never a host QEMU installation.
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
metadata_dir="$repo_root/tools/qemu"
work_dir="$repo_root/output/qemu-build"
source_input=""
capstone_input=""
jobs=2
manifest_tmp=""
bundle_tmp=""
version_tmp=""
source_tmp=""

cleanup_metadata_temps() {
  local path
  for path in "$manifest_tmp" "$bundle_tmp" "$version_tmp" "$source_tmp"; do
    [[ -z $path ]] || rm -f -- "$path"
  done
}
trap cleanup_metadata_temps EXIT

qemu_version=11.1.1
qemu_archive=qemu-11.1.1.tar.xz
qemu_url=https://download.qemu.org/qemu-11.1.1.tar.xz
qemu_sha=079ffbff8a7111bbc89022107cbabf3bbfd614d5fc9d7cc675991196aca12482
qemu_key_fingerprint=CEACC9E15534EBABB82D3FA03353C9CEF108B584
capstone_version=5.0.9
capstone_archive=capstone-5.0.9.tar.gz
capstone_url=https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.9.tar.gz
capstone_sha=0619da31af08152600af95c481527ef6d756c0a8404fca7544a4fdf6dfc2c0f9
bundle_name=qemu_11.1.1-chipchain-linux-x86_64.tar.xz
targets=arm-softmmu,aarch64-softmmu,riscv32-softmmu,riscv64-softmmu,ppc-softmmu,ppc64-softmmu
executables=(qemu-system-arm qemu-system-aarch64 qemu-system-riscv32 qemu-system-riscv64 qemu-system-ppc qemu-system-ppc64)

usage() {
  cat <<'EOF'
Usage: ./scripts/build_qemu_bundle.sh [--source-archive PATH]
                                      [--capstone-archive PATH]
                                      [--work-dir PATH] [--jobs N]

Build the pinned QEMU 11.1.1 Linux x86_64 bundle for maintainers. Source
archives are downloaded when absent; supplied archives must match pinned
SHA256 values. Build dependencies: C/C++ compiler, make, ninja, pkg-config,
Python 3 with venv and pip, curl, gpg/gpgv, tar, xz, glib and pixman headers.
Meson 1.10.2 and tomli 2.2.1 are installed in the ignored build workspace.
The result is cached at tools/qemu/<bundle-name>; no Release is uploaded.
EOF
}

fail() {
  printf '[ChipChain] QEMU bundle build FAIL: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --source-archive|--capstone-archive|--work-dir|--jobs)
      (($# >= 2)) || fail "$1 requires a value"
      [[ -n $2 ]] || fail "$1 requires a nonempty value"
      case "$1" in
        --source-archive) source_input=$2 ;;
        --capstone-archive) capstone_input=$2 ;;
        --work-dir) work_dir=$2 ;;
        --jobs) jobs=$2 ;;
      esac
      shift 2 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

[[ $jobs =~ ^[1-9][0-9]*$ ]] || fail '--jobs must be a positive integer'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] ||
  fail "Unsupported build host: $(uname -s)/$(uname -m); this V1 bundle is Linux/x86_64 only"
glibc_line=$(getconf GNU_LIBC_VERSION 2>/dev/null) || fail 'GNU glibc is required'
[[ $glibc_line =~ ^glibc[[:space:]]+([0-9]+)\.([0-9]+)$ ]] || fail "Unknown glibc version: $glibc_line"
glibc_version=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}
[[ $glibc_version == 2.35 ]] ||
  fail "This pinned V1 bundle must be built on the validated glibc 2.35 host; got $glibc_version"

for command_name in curl gpg gpgv tar xz bzip2 sha256sum python3 make ninja \
                    pkg-config gcc g++ readelf timeout rg awk realpath; do
  command -v "$command_name" >/dev/null 2>&1 || fail "Missing build tool: $command_name"
done
pkg-config --exists 'glib-2.0 >= 2.56' pixman-1 ||
  fail 'Missing glib-2.0 or pixman-1 development headers (pkg-config)'
[[ $work_dir == /* ]] || work_dir="$repo_root/$work_dir"
mkdir -p -- "$work_dir" "$metadata_dir"
work_dir=$(cd -- "$work_dir" && pwd -P)

download() {
  local url=$1 dest=$2
  local tmp
  tmp=$(mktemp "$work_dir/.download.XXXXXXXX")
  if ! curl --fail --location --retry 3 --silent --show-error \
      --proto '=https' --proto-redir '=https' --output "$tmp" "$url"; then
    rm -f -- "$tmp"
    fail "Download failed: $url"
  fi
  mv -f -- "$tmp" "$dest"
}

verify_sha() {
  local file=$1 expected=$2 label=$3 actual
  actual=$(sha256sum -- "$file")
  actual=${actual%% *}
  [[ $actual == "$expected" ]] || fail "$label SHA256 mismatch: got $actual; required $expected"
  printf '[ChipChain] Verified %s SHA256: %s\n' "$label" "$actual"
}

prepare_archive() {
  local input=$1 cached=$2 url=$3 expected=$4 label=$5
  if [[ -n $input ]]; then
    [[ -f $input && ! -L $input ]] || fail "$label archive missing or symlink: $input"
    verify_sha "$input" "$expected" "$label"
    if [[ $(realpath -- "$input") != $(realpath -m -- "$cached") ]]; then
      cp -- "$input" "$cached"
    fi
  elif [[ ! -f $cached ]]; then
    printf '[ChipChain] Downloading %s from %s\n' "$label" "$url"
    download "$url" "$cached"
  fi
  [[ -f $cached && ! -L $cached ]] || fail "Unsafe cached $label archive: $cached"
  verify_sha "$cached" "$expected" "$label"
}

qemu_cached="$work_dir/$qemu_archive"
capstone_cached="$work_dir/$capstone_archive"
prepare_archive "$source_input" "$qemu_cached" "$qemu_url" "$qemu_sha" 'official QEMU source'
prepare_archive "$capstone_input" "$capstone_cached" "$capstone_url" "$capstone_sha" 'Capstone source'

# The official archive SHA is mandatory for both online and local input. The
# default download requires the detached signature. A supplied archive may be
# built offline, with its signature status reported accurately below.
signature_status=pinned_sha256_only_signature_not_checked
signature="$work_dir/$qemu_archive.sig"
key_asc="$work_dir/qemu-release-key.asc"
if [[ -z $source_input ]]; then
  [[ -f $signature ]] || download "$qemu_url.sig" "$signature"
  [[ -f $key_asc ]] || download \
    "https://keys.openpgp.org/vks/v1/by-fingerprint/$qemu_key_fingerprint" "$key_asc"
fi
if [[ -f $signature && -f $key_asc ]]; then
  actual_fingerprint=$(gpg --batch --show-keys --with-colons "$key_asc" 2>/dev/null |
    awk -F: '$1 == "fpr" {print $10; exit}')
  [[ $actual_fingerprint == "$qemu_key_fingerprint" ]] ||
    fail "QEMU release key fingerprint mismatch: $actual_fingerprint"
  keyring="$work_dir/qemu-release-key.gpg"
  gpg --batch --yes --dearmor --output "$keyring" "$key_asc" >/dev/null 2>&1 ||
    fail 'Could not prepare QEMU release keyring'
  gpgv --keyring "$keyring" "$signature" "$qemu_cached" ||
    fail 'Official QEMU source signature verification failed'
  signature_status=verified_good_signature_with_pinned_release_key
fi

source_tree="$work_dir/qemu-$qemu_version"
capstone_tree="$work_dir/capstone-$capstone_version"
if [[ ! -d $source_tree ]]; then
  tar -xJf "$qemu_cached" -C "$work_dir"
fi
if [[ ! -d $capstone_tree ]]; then
  tar -xzf "$capstone_cached" -C "$work_dir"
fi
[[ -f $source_tree/VERSION && $(cat "$source_tree/VERSION") == "$qemu_version" ]] ||
  fail 'QEMU source tree has the wrong version'
[[ -f $capstone_tree/pkgconfig.mk ]] || fail 'Capstone source tree is incomplete'

# An ignored work directory can persist across builds. Check every archived
# source file against the extracted tree before compiling cached sources.
python3 - "$qemu_cached" "$capstone_cached" "$work_dir" <<'PY' ||
  fail 'Extracted source tree differs from a pinned archive'
import pathlib
import os
import stat
import sys
import tarfile

root = pathlib.Path(sys.argv[3])
for archive_path in sys.argv[1:3]:
    with tarfile.open(archive_path) as archive:
        for member in archive:
            name = pathlib.PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or '\\' in member.name:
                raise SystemExit(f'unsafe source archive path: {member.name}')
            installed = root.joinpath(*name.parts)
            mode = installed.lstat().st_mode
            if member.isfile():
                if not stat.S_ISREG(mode):
                    raise SystemExit(f'changed source file type: {member.name}')
                source = archive.extractfile(member)
                assert source is not None
                with source, installed.open('rb') as extracted:
                    while chunk := source.read(1024 * 1024):
                        if chunk != extracted.read(len(chunk)):
                            raise SystemExit(f'changed source file: {member.name}')
                    if extracted.read(1):
                        raise SystemExit(f'changed source file size: {member.name}')
            elif member.issym():
                if not stat.S_ISLNK(mode) or os.readlink(installed) != member.linkname:
                    raise SystemExit(f'changed source symlink: {member.name}')
            elif member.isdir():
                if not stat.S_ISDIR(mode):
                    raise SystemExit(f'changed source directory: {member.name}')
            else:
                raise SystemExit(f'unsupported source archive entry: {member.name}')
print('[ChipChain] Extracted source trees match pinned archives.')
PY

meson_venv="$work_dir/meson-venv"
if [[ ! -x $meson_venv/bin/python ]]; then
  python3 -m venv "$meson_venv"
fi
if [[ ! -x $meson_venv/bin/meson || $("$meson_venv/bin/meson" --version) != 1.10.2 ]] ||
   ! "$meson_venv/bin/python" -c 'import tomli' >/dev/null 2>&1; then
  "$meson_venv/bin/python" -m pip install --disable-pip-version-check \
    'meson==1.10.2' 'tomli==2.2.1'
fi

capstone_prefix="$work_dir/capstone-prefix"
printf '[ChipChain] Building static Capstone %s for ARM, AArch64, RISC-V, PowerPC...\n' "$capstone_version"
make -C "$capstone_tree" -j "$jobs" \
  CAPSTONE_ARCHS='arm aarch64 powerpc riscv' CAPSTONE_SHARED=no \
  CAPSTONE_STATIC=yes CAPSTONE_BUILD_CORE_ONLY=yes PREFIX="$capstone_prefix" \
  > "$work_dir/capstone-build.log" 2>&1 || {
    tail -80 "$work_dir/capstone-build.log" >&2
    fail 'Capstone build failed'
  }
make -C "$capstone_tree" \
  CAPSTONE_ARCHS='arm aarch64 powerpc riscv' CAPSTONE_SHARED=no \
  CAPSTONE_STATIC=yes CAPSTONE_BUILD_CORE_ONLY=yes PREFIX="$capstone_prefix" \
  install >> "$work_dir/capstone-build.log" 2>&1 || fail 'Capstone install failed'
[[ -f $capstone_prefix/lib/libcapstone.a ]] || fail 'Missing static Capstone library'
[[ $(PKG_CONFIG_PATH="$capstone_prefix/lib/pkgconfig" pkg-config --modversion capstone) == "$capstone_version" ]] ||
  fail 'Capstone pkg-config version mismatch'

build_dir="$work_dir/build"
mkdir -p -- "$build_dir"
configure_flags=(
  --prefix=/opt/chipchain/qemu
  "--target-list=$targets"
  --enable-system --enable-tcg --enable-plugins --enable-capstone
  --enable-fdt=internal --enable-pixman --enable-relocatable
  --disable-rust --disable-docs --disable-gtk --disable-sdl
  --disable-curses --disable-vnc --disable-kvm --disable-tools
  --disable-slirp --disable-guest-agent --disable-virtfs
  --disable-modules --disable-debug-info --enable-strip
)
printf '[ChipChain] Configuring QEMU %s for %s...\n' "$qemu_version" "$targets"
if ! (cd "$build_dir" &&
      PATH="$meson_venv/bin:$PATH" \
      PKG_CONFIG_PATH="$capstone_prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
      "$source_tree/configure" "${configure_flags[@]}" \
      > "$work_dir/configure.log" 2>&1); then
  tail -100 "$work_dir/configure.log" >&2
  fail 'QEMU configure failed'
fi
for required_line in 'TCG support *: YES' 'TCG plugins *: YES' 'capstone *: YES 5.0.9' 'fdt support *: internal'; do
  rg -q "$required_line" "$work_dir/configure.log" || fail "QEMU configure omitted $required_line"
done
[[ $(sed -n 's/^TARGET_DIRS=//p' "$build_dir/config-host.mak") == \
   'arm-softmmu aarch64-softmmu riscv32-softmmu riscv64-softmmu ppc-softmmu ppc64-softmmu' ]] ||
  fail 'QEMU configure target list differs from pinned six targets'

printf '[ChipChain] Building six system emulators and libexeclog.so (-j%s)...\n' "$jobs"
if ! (cd "$build_dir" && ninja -j "$jobs" "${executables[@]}" \
      contrib/plugins/libexeclog.so > "$work_dir/build.log" 2>&1); then
  tail -100 "$work_dir/build.log" >&2
  fail 'QEMU build failed'
fi

stage=$(mktemp -d "$work_dir/stage.XXXXXXXX")
mkdir -p "$stage/bin" "$stage/lib/qemu/plugins" "$stage/share/qemu/dtb"
for binary in "${executables[@]}"; do
  install -m 0755 "$build_dir/$binary" "$stage/bin/$binary"
done
install -m 0644 "$build_dir/contrib/plugins/libexeclog.so" \
  "$stage/lib/qemu/plugins/libexeclog.so"
if readelf -d "$stage/bin/qemu-system-riscv64" | rg -q 'NEEDED.*libcapstone'; then
  fail 'Capstone was dynamically linked; expected static linkage'
fi

# Architecture-relevant firmware assets from the signed QEMU source. Unpack
# EDK2 images as QEMU's install target does; avoid unrelated x86 BIOS blobs.
for edk2 in edk2-aarch64-code.fd edk2-arm-code.fd edk2-arm-vars.fd \
            edk2-riscv-code.fd edk2-riscv-vars.fd; do
  bzip2 -dc "$source_tree/pc-bios/$edk2.bz2" > "$stage/share/qemu/$edk2"
done
for blob in openbios-ppc opensbi-riscv32-generic-fw_dynamic.bin \
            opensbi-riscv64-generic-fw_dynamic.bin slof.bin skiboot.lid \
            pnv-pnor.bin u-boot.e500 u-boot-sam460.bin vof.bin vof-nvram.bin \
            qemu_vga.ndrv; do
  install -m 0644 "$source_tree/pc-bios/$blob" "$stage/share/qemu/$blob"
done
for dtb in bamboo.dtb canyonlands.dtb pegasos1.dtb pegasos2.dtb; do
  install -m 0644 "$source_tree/pc-bios/dtb/$dtb" "$stage/share/qemu/dtb/$dtb"
done

# These probes execute the staged paths and never consult system QEMU.
for binary in "${executables[@]}"; do
  version_output=$(timeout 10s "$stage/bin/$binary" --version) || fail "$binary --version failed"
  [[ $version_output =~ ^QEMU[[:space:]]emulator[[:space:]]version[[:space:]]11\.1\.1([[:space:]]|$) ]] ||
    fail "$binary has the wrong version: $version_output"
  timeout 10s "$stage/bin/$binary" -machine help | awk '
    /^Supported machines are:/{listed=1; next}
    listed && NF >= 2 && $1 != "none" {found=1}
    END {exit !found}' || fail "$binary has no usable machine"
done
for binary in qemu-system-aarch64 qemu-system-riscv64 qemu-system-ppc64; do
  status=0
  timeout --signal=TERM --kill-after=1s 3s "$stage/bin/$binary" \
    -machine none -accel tcg -nographic -nodefaults -monitor none -serial none \
    -S -plugin "$stage/lib/qemu/plugins/libexeclog.so" \
    > "$work_dir/$binary-plugin-smoke.log" 2>&1 || status=$?
  [[ $status == 124 ]] || {
    cat "$work_dir/$binary-plugin-smoke.log" >&2
    fail "$binary did not load libexeclog.so (exit $status)"
  }
done

manifest_tmp=$(mktemp "$metadata_dir/.SHA256SUMS.XXXXXXXX")
(cd "$stage" && find bin lib share -type f -print0 | LC_ALL=C sort -z |
  xargs -0 sha256sum) > "$manifest_tmp"
[[ -s $manifest_tmp ]] || fail 'Empty installed-file manifest'
if find "$stage" -type l -print -quit | rg -q .; then
  fail 'Staged bundle contains a symlink'
fi

bundle_tmp=$(mktemp "$metadata_dir/.qemu-bundle.XXXXXXXX.tar.xz")
tar -C "$stage" --sort=name --mtime='@0' --owner=0 --group=0 \
  --numeric-owner --format=gnu -cf - bin lib share | xz -T "$jobs" -6 > "$bundle_tmp"
bundle_sha=$(sha256sum "$bundle_tmp")
bundle_sha=${bundle_sha%% *}

version_tmp=$(mktemp "$metadata_dir/.VERSION.XXXXXXXX")
source_tmp=$(mktemp "$metadata_dir/.SOURCE.XXXXXXXX")
cat > "$version_tmp" <<EOF
QEMU $qemu_version
supported_guest_families=arm,riscv,powerpc
supported_system_targets=$targets
supported_host=linux-x86_64
minimum_glibc=$glibc_version
EOF
cat > "$source_tmp" <<EOF
official_source_url=$qemu_url
official_version=$qemu_version
official_tag=v11.1.1
official_tag_commit=c3d48b7d1e89604920e5b81b91140c2ad39a1943
official_source_archive=$qemu_archive
official_source_sha256=$qemu_sha
official_signature_url=$qemu_url.sig
official_signing_fingerprint=$qemu_key_fingerprint
official_signature_status=$signature_status
capstone_source_url=$capstone_url
capstone_version=$capstone_version
capstone_tag_commit=841cee33c3c630cf7d321a64f47aefe7b0b8da99
capstone_source_sha256=$capstone_sha
chipchain_bundle_filename=$bundle_name
chipchain_bundle_sha256=$bundle_sha
chipchain_release_asset_url=https://github.com/Qcx526/ChipChainV3/releases/download/v3-qemu-runtime-foundation-stable/$bundle_name
build_host=Linux_x86_64_glibc_$glibc_version
build_glibc=$glibc_version
build_configuration=${configure_flags[*]}
plugin_configuration=TCG_plugins_enabled;QEMU_contrib_plugins/libexeclog.so
capstone_status=enabled_$capstone_version-static_arm_aarch64_powerpc_riscv
EOF

chmod 0644 "$version_tmp" "$source_tmp" "$manifest_tmp" "$bundle_tmp"

mv -f -- "$version_tmp" "$metadata_dir/VERSION"
mv -f -- "$source_tmp" "$metadata_dir/SOURCE"
mv -f -- "$manifest_tmp" "$metadata_dir/SHA256SUMS"
mv -f -- "$bundle_tmp" "$metadata_dir/$bundle_name"

printf '[ChipChain] Bundle: %s\n' "$metadata_dir/$bundle_name"
printf '[ChipChain] Bundle SHA256: %s\n' "$bundle_sha"
printf '[ChipChain] Staged files: %s\n' "$(wc -l < "$metadata_dir/SHA256SUMS")"
printf '[ChipChain] Stage: %s\n' "$stage"
printf '[ChipChain] Build logs: %s/{configure,build,capstone-build}.log\n' "$work_dir"
