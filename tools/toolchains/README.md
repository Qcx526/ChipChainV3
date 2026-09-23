# Local sample-build toolchains

The three sample build tools are installed inside `tools/toolchains/install/`, which is ignored by Git. The ARM and PowerPC assembler/linker packages were downloaded into `downloads/` and extracted locally; the RISC-V assembler/linker come from a locally copied lowRISC distribution. Pinned versions and executable hashes are recorded in `MANIFEST.json`.

`scripts/build_firmware_samples.py` uses only these project-local executables. Its RISC-V link runs from `output/firmware-build/` with a basename object argument, so the ELF symbol table contains `riscv.o` instead of a host-specific path. The three tracked sample manifests record the exact relative commands, link working directory, source hashes and resulting ELF hashes. Assembly sources and ELFs are tracked; no external script or tool path is required to rebuild them after installing the pinned tools.
