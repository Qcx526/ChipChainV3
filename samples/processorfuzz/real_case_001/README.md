# ProcessorFuzz real case 001

The only supplied ZIP currently present is `raw/testis.zip` (SHA256
`c0fe4e328be70238cfd7383fe3cc9b58267eeafc0795d1dbb8b4b074ad69df34`).
The requested name `raw/processorfuzz-case.zip` was not present when this
acceptance run began. The ZIP is kept byte-for-byte unchanged. The adapter
reads it in memory; Ghidra's private ELF snapshot is created under `output/`.

This is an authentic hardware-team **trigger-validation package**. The ELF
inside is **hardware-supplied trigger-test firmware**, not customer firmware,
production firmware or a real target image. It can ground the hardware
trigger reference and test evidence binding. It cannot show that customer
firmware contains the trigger behavior. The manifest records this explicit
intake classification; it is not inferred from ZIP contents. General
firmware-analysis validation remains based on independently authored project
firmware samples. Future customer firmware must enter separately and pass
through the same generic firmware frontend.

`expected/` holds deterministic regression artifacts generated from that ZIP.
The human-readable copy is in
`artifacts/demo/processorfuzz/real_case_001/`. The case manifest lists every
ZIP member and its hash. `note.log` remains a human note; the package's
`disassembly.asm` is rejected as an ELF provenance conflict.

Reproduce with:

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/python scripts/build_processorfuzz_artifacts.py \
  --package samples/processorfuzz/real_case_001/raw/testis.zip
```
