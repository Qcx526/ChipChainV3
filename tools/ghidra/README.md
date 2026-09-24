# Project-managed Ghidra

`install/` contains the working Ghidra 12.3 DEV distribution used by the firmware frontend. It is intentionally Git-ignored because the distribution is about 879 MB; it remains inside the repository workspace. `VERSION`, `SOURCE`, and `SHA256SUMS` are tracked pinned metadata. `SOURCE` records the upstream revision and SHA256 of a locally created bundle; the original upstream archive is unavailable, so its hash is not claimed.

Use the repository-root setup script with a **locally supplied** distribution:

```bash
./scripts/setup_ghidra.sh --archive /path/to/pinned-ghidra.tar.gz
./scripts/setup_ghidra.sh --verify-only
```

If `ghidra_12.3_DEV-local.tar.gz` is already present here, `./scripts/setup_ghidra.sh` may use it without `--archive`. The script does not download Ghidra or install Java. Java must meet `minimum_java` in `VERSION` (currently 25). An archive named `ghidra_12.3_DEV-local.tar.gz` must match the local-bundle SHA256 in `SOURCE`; other supplied archive names have no claimed original-archive hash. In every case the extracted installation must match the version, release, revision and every file listed in `SHA256SUMS` (currently 5459 entries) before promotion to `install/`.

`--verify-only` checks an existing installation without changing it. `--install-dir PATH` selects an alternate installation; a relative install path is resolved from the repository root. The script preserves an existing installation and refuses to replace an invalid directory. The frontend discovers `tools/ghidra/install/` by default and accepts `--ghidra-home` as an explicit override. A fresh clone needs this pinned distribution before raw-ELF Ghidra analysis; portable canonical artifacts and tests can be read without it.
