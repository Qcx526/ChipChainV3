# Project-managed QEMU 11.1.1

ChipChain pins one QEMU system-emulation bundle for Linux x86_64. It contains
`qemu-system-arm`, `qemu-system-aarch64`, `qemu-system-riscv32`,
`qemu-system-riscv64`, `qemu-system-ppc`, `qemu-system-ppc64`, and QEMU's
`libexeclog.so` TCG plugin. The binaries use TCG and Capstone 5.0.9; Capstone
is statically linked. `share/qemu/` contains firmware and device-tree assets
relevant to the three supported guest families. It is not a universal board
image or a source of compatible firmware profiles.

The bundle was built and validated on Ubuntu 22.04.5 LTS, Linux x86_64,
glibc 2.35. The setup script rejects other OS/CPU combinations and glibc
older than 2.35. Other Linux x86_64 distributions with glibc 2.35 or newer
have not been validated. The six executables directly require host
`libc.so.6`, `libm.so.6`, `libglib-2.0.so.0`, `libgobject-2.0.so.0`,
`libgio-2.0.so.0`, `libgmodule-2.0.so.0`, `libpixman-1.so.0`, and
`libz.so.1`; their transitive libraries are supplied by the tested host.
This is a pinned QEMU build, not a fully static Linux distribution. Neither
macOS nor Windows is supported by this V1 bundle.

From the repository root:

```bash
./scripts/setup_env.sh
./scripts/setup_ghidra.sh
./scripts/setup_qemu.sh
./scripts/setup_qemu.sh --verify-only
```

For a supplied copy of the pinned bundle, including offline use or an
alternate project-local install directory:

```bash
./scripts/setup_qemu.sh --offline --archive /path/to/qemu_11.1.1-chipchain-linux-x86_64.tar.xz
./scripts/setup_qemu.sh --offline --archive /path/to/qemu_11.1.1-chipchain-linux-x86_64.tar.xz --install-dir output/qemu-alternate-install
./scripts/setup_qemu.sh --verify-only --install-dir output/qemu-alternate-install
```

`--archive` checks the tracked bundle SHA256 even when a different pathname
is supplied. A valid installation is reused; an invalid existing directory
is left untouched. `--verify-only` does not install or download. `--offline`
forbids a download. Without an installation, explicit archive, or cached
bundle, setup attempts the exact `chipchain_release_asset_url` in `SOURCE`.
That URL is a planned ChipChain Release asset and may not exist until the
reviewed bundle is published. The cached bundle and `install/` are ignored by
Git. They are not part of a source checkout.

The maintainer build command is:

```bash
./scripts/build_qemu_bundle.sh
```

It downloads the official [QEMU 11.1.1 release archive](https://download.qemu.org/qemu-11.1.1.tar.xz),
checks its pinned SHA256, and verifies its detached signature against the
release-key fingerprint listed by [QEMU](https://www.qemu.org/download/).
An already downloaded archive may be supplied with `--source-archive PATH`;
its SHA256 must still match. The builder also pins the
[Capstone 5.0.9 source tag](https://github.com/capstone-engine/capstone/releases/tag/5.0.9)
and checks that archive's SHA256. `--capstone-archive PATH` accepts an exact
local copy. Build tools and temporary files stay under ignored
`output/qemu-build/`; `--work-dir PATH` changes that location and `--jobs N`
controls parallelism (default 2). The builder requires a C/C++ compiler,
make, ninja, pkg-config, Python 3 with venv and pip, curl, GnuPG, GNU tar,
xz, GLib and Pixman development headers. It installs Meson 1.10.2 and tomli
2.2.1 into a build-local Python venv. No root access or system QEMU package
is used. The builder does not publish a Release or commit the bundle.

`VERSION` names the supported guests and host floor. `SOURCE` records the
official archive, tag, source SHA256, signature key, Capstone source, build
configuration, bundle name and SHA256, and future release URL. `SHA256SUMS`
pins every regular installed file relative to the installation root. Setup
checks that manifest, all six binary versions and machine lists, and bounded
plugin-load probes on AArch64, RISC-V 64, and PowerPC 64. It always invokes
the exact project-local binary path.

This bundle provides a shared QEMU execution mechanism across ARM, RISC-V,
and PowerPC. A firmware run still needs an explicit, compatible architecture,
machine, CPU, and load profile. Machine availability does not establish
equivalence to a target board. QEMU diagnostic observations are distinct
from ProcessorFuzz RTL execution and from physical silicon evidence; they
cannot establish a hardware vulnerability trigger by themselves. The
execution-log plugin output is diagnostic until a separate, source-bound
runtime evidence model is defined.
