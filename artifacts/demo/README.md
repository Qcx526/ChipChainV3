# Reviewable demo artifacts

`firmware/{arm,riscv,powerpc}/` contains the shared static IR, summary, twelve-section human report, normalized Ghidra export, and conservative synthetic CAP0 projection for each real ELF sample. The matching files in `samples/firmware/*/expected/` are the portable reference outputs. All are generated deterministically from tracked bytes; no local output path or timestamp enters scientific IDs.

`type2/hardware-resource-catalog.json` declares the controlled synthetic ENABLE, COMMAND and STATUS registers. Each `type2/{positive,trigger-negative,unknown}/` directory contains generic firmware analysis, static CAP0 projection, resource bindings and static→runtime capability continuity. The cross-layer candidate is made from the general static projection; the frozen verifier's `verification.json` and readable report remain the authority for runtime order, pre-state, objective observation and Reference/Variant differential. Positive includes N2 Reference-control in its summary and verification object.

`processorfuzz/real_case_001/` contains the first authentic hardware-team delivery ZIP ingestion result. Its ELF is hardware-supplied trigger-test firmware, not customer or production firmware. The report names accepted SI/ELF/traces/signatures, shows the disassembly/ELF conflict and unbound note, and preserves the missing Type-II verification requirements. The package helps examine the hardware trigger reference and evidence binding; it does not prove that customer firmware contains the trigger. Its signature difference is not a verified vulnerability.

Regenerate offline from tracked Ghidra exports with:

```bash
PYTHONPATH=src .venv/bin/python scripts/build_demo_artifacts.py
```

Add `--refresh-ghidra` to actually rerun the pinned Ghidra Headless exporter on every ELF. These fixtures are controlled synthetic evidence, not physical-chip vulnerability claims.
