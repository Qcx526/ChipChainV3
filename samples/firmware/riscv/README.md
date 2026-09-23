# RV32 synthetic firmware

`source.S` covers three functions, direct calls, a conditional branch, LW/SW, a CSR read and FENCE. `sample.elf` is rebuilt with the pinned project-local lowRISC GCC. `expected/` contains the actual Ghidra Headless export and its ELF-byte-checked canonical analysis, summary and report. Its `0x40000000` access is a memory fact until a catalog binds it; this sample alone proves no Type-II trigger.
