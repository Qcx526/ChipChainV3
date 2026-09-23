# PowerPC32 big-endian synthetic firmware

`source.S` covers three functions, calls/branches, LWZ/STW, MFSPR and SYNC. `sample.elf` is built using the pinned project-local PowerPC binutils. `expected/` contains the actual Ghidra Headless export and its ELF-byte-checked canonical analysis, summary and report. Its `0x40000000` access remains an ordinary memory fact without a hardware resource catalog.
