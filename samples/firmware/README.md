# Firmware input workspace

Use this Git-ignored directory for local firmware binaries, disassembly and future deterministic analyzer results. The current controlled Type-II CLI does not infer capabilities from arbitrary files placed here. Its manifest references an existing ELF, canonical MMIO catalog, execution bridge and firmware capabilities, then replays them against the supplied bytes.

The checked-in `examples/` are small synthetic fixtures. Real local materials and external read-only artifacts should not be copied into Git merely to create a paired case.
