# Project-managed Ghidra

`install/` contains the working Ghidra 12.3 DEV distribution used by the firmware frontend. It is intentionally Git-ignored because the distribution is about 879 MB; it remains inside the repository workspace. `VERSION`, `SOURCE`, and `SHA256SUMS` are tracked pinned metadata. `SOURCE` records the upstream revision and SHA256 of a locally created bundle; the original upstream archive is unavailable, so its hash is not claimed.

With internet access, the repository-root setup script downloads the exact pinned [ChipChain Release asset](https://github.com/Qcx526/ChipChainV3/releases/tag/v3-ghidra-setup-stable) if no installation or cached bundle exists:

```bash
./scripts/setup_ghidra.sh
./scripts/setup_ghidra.sh --verify-only
```

For an offline setup, provide the archive yourself:

```bash
./scripts/setup_ghidra.sh --offline --archive /media/usb/ghidra_12.3_DEV-local.tar.gz
```

`--archive PATH` never downloads, and `--offline` prohibits network access even when the local cache is absent. If `ghidra_12.3_DEV-local.tar.gz` is already present here, the script uses it without downloading. The Release URL and local-bundle SHA256 come from tracked `SOURCE`; downloads land in a temporary file here and enter the Git-ignored cache only after SHA256 validation. The script does not install Java. Java must meet `minimum_java` in `VERSION` (currently 25). An explicitly supplied archive named `ghidra_12.3_DEV-local.tar.gz` must match the same bundle SHA256; an external archive with another name has no claimed original-archive hash. In every case the extracted installation must match the version, release, revision and every file listed in `SHA256SUMS` (currently 5459 entries) before promotion to `install/`. Release hosting does not change the provenance or evidence checks.

`--verify-only` checks an existing installation without changing it. `--install-dir PATH` selects an alternate installation; a relative install path is resolved from the repository root. The script preserves an existing installation and refuses to replace an invalid directory. The frontend discovers `tools/ghidra/install/` by default and accepts `--ghidra-home` as an explicit override. A fresh clone needs this pinned distribution before raw-ELF Ghidra analysis; portable canonical artifacts and tests can be read without it.
