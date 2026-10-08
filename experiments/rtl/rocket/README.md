# Rocket RTL feasibility research smoke

These tools produce diagnostic research artifacts. They do not invoke or extend
the frozen Type-II verifier, and do not manufacture a HardwareRuntimeEvidence
object. Shared ChipChain scientific contracts remain unchanged.

Keep user archives read-only under ignored `samples/rtl-input/`. All extraction,
third-party sources, environments, builds and run outputs belong under ignored
`output/rtl-rocket-feasibility/`. Never commit RTL archives or generated models.

## Inspect the explicit archive

```bash
.venv/bin/python scripts/rtl/inspect_rocket_benchmark.py \
  --zip samples/rtl-input/Benchmarks.zip \
  --expected-zip-sha256 987d8f81bd36567418afa9473864c54dba34532e979fcae35d99428c7bc97287 \
  --rtl-member Benchmarks/Verilog/RocketTile_latest.v \
  --expected-rtl-sha256 508717f1a3af02f235633f20d274048e19bbb89d702d5d736cc7c1dc181ea188 \
  --top RocketTile --output output/rtl-rocket-feasibility/inspection-fresh
```

Selection is by exact ZIP member and expected byte hash. Module/port/CSR clues
are text inspection, not elaboration, processor-configuration proof or execution.

## Reproduce with the genuine upstream driver

The inspected ProcessorFuzz commit is
`2d08d0d8b4563212175212f9db0e69f6e68c9619` from
<https://github.com/bu-icsg/ProcessorFuzz>. Keep the checkout in ignored output.
The wrapper reuses its complete `RTLSim.host` and TileLink adapter. It bypasses
the outer fuzz loop's mutation, coverage-guidance gating and file deletion.

`run_rocket_reproduction.py --help` lists explicit paths, hashes, driver commit,
top, compile arguments, seed, cycle bounds and watchdog limits. The inspected
profile uses RV64 little-endian ELF, native 64-bit-word HEX, matching physical
and virtual load addresses, the upstream BootROM at `0x10000`, six ELF-backed
random-data ranges, zeroed tohost/signature and disabled test interrupts.
HEX must match every file-backed ELF PT_LOAD byte range. ELF symbols determine
the actual loader and signature spans. The helper does not rebuild an ELF from
SI or claim an unknown SI-to-ELF build chain.

The original case001 trigger-test ELF is SHA256
`649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86`.
It is hardware-supplied test firmware, not customer firmware or synthetic FW-POS.

```bash
.venv/bin/python scripts/rtl/run_rocket_reproduction.py \
  --rtl output/rtl-rocket-feasibility/input/Benchmarks/Verilog/RocketTile_latest.v \
  --rtl-sha256 508717f1a3af02f235633f20d274048e19bbb89d702d5d736cc7c1dc181ea188 \
  --top RocketTile \
  --elf output/rtl-rocket-feasibility/program/input.elf \
  --elf-sha256 649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86 \
  --hex output/rtl-rocket-feasibility/program/input.hex \
  --upstream output/rtl-rocket-feasibility/upstream/ProcessorFuzz \
  --upstream-commit 2d08d0d8b4563212175212f9db0e69f6e68c9619 \
  --verilator output/rtl-rocket-feasibility/environment/verilator/install/bin/verilator \
  --python output/rtl-rocket-feasibility/environment/venv/bin/python \
  --compile-arg=-DPRINTF_COND=0 --compile-arg=-DSTOP_COND=0 \
  --compile-arg=-Wno-PINMISSING --compile-arg=-Wno-fatal \
  --max-cycles 6000 --seed 0 --jobs 2 \
  --build-timeout 900 --run-timeout 120 \
  --output output/rtl-rocket-feasibility/replay-fresh
```

Use a new/empty output child directory. `-Wno-fatal` retains warnings in raw
stderr; it does not change processor logic. Generated Makefile arguments remain
inspectable. `raw/` includes complete stdout/stderr, source-wrapper snapshots,
driver status and actual trace/signature when produced. The manifest records
source/tool/binary hashes, versions, exact commands, initialization policy,
wall duration and process status. Wall duration is diagnostic, not hardware time.

## Interpret outcomes

- BUILD_PASSED: the generated RTL simulator binary actually built.
- SIMULATION_EXECUTED: the driver returned evidence of clocked testbench work.
- SOURCE_BOUND_EXECUTION: this diagnostic run's inputs remained intact and a
  normal source-defined monitor row matches the selected ELF's entry bytes.
  This binds the new run only; it does not identify the historical case revision,
  authenticate every state column or establish architectural-reference equivalence.
- Completion is separate. A valid observed prefix may coexist with timeout or
  assertion failure; the smoke returns nonzero unless source binding and normal
  completion are established.

The supplied latest RTL has an expanded trace payload but an unchanged short
header. Its apparent `COV` column is actually `mstatus`; state/exception/delayed
rows require source-specific interpretation. Do not use row position as a cycle
number or call posedge state fields post-update retirement snapshots.

Raw signature comparison does not independently prove a hardware deviation.
The pinned ProcessorFuzz all-CSR Spike is a modified reference; its new run does
not authenticate the original package's unknown Spike/RTL revisions.

Ordinary pytest is offline and never starts these expensive tools. Run research
smokes explicitly. ARM/PowerPC RTL backends and FPGA/silicon claims are outside
this experiment. See [research acceptance](../../../docs/research/rocket-rtl-feasibility-v1.md)
for actual outcomes and remaining evidence gaps.
