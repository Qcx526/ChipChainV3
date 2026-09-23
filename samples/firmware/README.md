# Firmware input workspace

This directory contains three **tracked synthetic** instruction-coverage samples under `arm/`, `riscv/` and `powerpc/`. Each has source, reproducibly built ELF, manifest and Ghidra-backed expected analysis. Other local research binaries and analyzer outputs remain Git-ignored by default. `chipchain firmware analyze` accepts an explicit ELF path and uses project-managed Ghidra; dropping a file into this directory does not trigger automatic analysis.

The controlled Type-II `chipchain analyze` command instead replays an explicit manifest naming existing ELF, canonical MMIO catalog, execution bridge and firmware capabilities against supplied bytes.

The checked-in `examples/` are small synthetic fixtures. Real local materials and external read-only artifacts should not be copied into Git merely to create a paired case.
