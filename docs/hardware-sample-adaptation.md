# Hardware Sample Adaptation Guide

This is a **developer workflow**, not a ChipChain runtime stage. A dedicated sample-adaptation Codex may use it to inspect one new hardware delivery and propose the smallest evidence-honest adapter change. The primary engineering Codex maintains the interfaces and reviews integration. Neither Codex session is an evidence source, verifier, or part of scientific identity.

## Preserve the input

Keep the original hardware-team delivery under `samples/<tool>/real_case_NNN/raw/` without editing its bytes. Use `manifest/` for intake notes and `expected/` for reviewed deterministic regression output when needed; do not require every delivery to match `real_case_001` internally. Record the raw package hash separately before adaptation. The ELF in the existing ProcessorFuzz hardware-team delivery is a trigger-validation test program, not customer firmware. For a new delivery, establish its ELF role independently. Customer firmware enters through the generic `chipchain firmware analyze --elf ...` frontend as a separate evidence source.

The existing `samples/processorfuzz/real_case_001/raw/testis.zip` is an example, not a universal ProcessorFuzz layout. Its [sample README](../samples/processorfuzz/real_case_001/README.md) states its explicit hardware-team role. Do not rename, repair, or repack that raw ZIP to make a future case fit.

## Inspect before adapting

From the repository root, invoke the script with explicit input and output paths. From another working directory, use absolute paths for the script, input and output:

```bash
.venv/bin/python scripts/inspect_hardware_sample.py \
  --input samples/processorfuzz/real_case_001/raw/testis.zip \
  --output output/hardware-sample-inspection/real_case_001
```

The tool accepts a directory, ZIP, or TAR (including compressed TAR). It writes `inventory.json` and `adaptation-brief.md` only to a new or empty output directory, never inside an input directory. `--help` lists the CLI. The inventory is a deterministic **development diagnostic**: relative paths, entry type, size, SHA256, container type, extension, byte-established broad content kind, UTF-8/binary status, bounded text structure, and ELF header fields. Filename-based adaptation hints are separate from objective facts. The brief summarizes ELF headers, same-directory/stem groupings, trace/signature/source-shaped files, build noise, current-adapter filename shapes, and the actual project files to inspect. A matching filename is not a trusted role or producer binding.

The inspector hashes in chunks, reads at most 64 KiB per file for header/preview classification, and never executes package contents. It checks complete UTF-8 validity and LF counts while streaming. Bounds are 20,000 members, 2 GiB per file, 4 GiB total member bytes and 4 GiB compressed archive bytes. Unsafe archive paths, links and devices are rejected. Generated-build entries remain individually visible in `inventory.json` but are summarized in the short brief. These limits are operational safety limits, not scientific eligibility rules. A package rejected by an inspection limit needs a reviewed handling plan; do not silently discard members.

The outputs do **not** assert SI↔ELF, trace↔ELF, signature↔run or source-revision binding. They do not produce ChipChain evidence IDs, HardwareBehaviorContracts, Type-II results, vulnerability claims or confidence scores. Do not feed inspection paths, times or hints into scientific objects.

## Adapt one case

1. Preserve and hash the raw delivery. Read its inspection inventory and brief alongside the raw files.
2. Compare it with existing supported cases and the current parser requirements. In particular, inspect `src/chipchain/workflow/processorfuzz.py`, `src/chipchain/runtime/processorfuzz.py`, `src/chipchain/firmware/processorfuzz_si.py`, `src/chipchain/firmware/elf.py`, `tests/unit/test_processorfuzz_ingestion.py`, `tests/integration/test_processorfuzz_real_case.py`, and the reviewed `real_case_001` sample and demo artifacts.
3. Reuse deterministic parser logic first. Extend only the concrete new file/record form needed; do not introduce a universal recognition framework, dynamic registry or LLM intake stage.
4. Establish each provenance binding independently. Co-location, basename similarity and byte resemblance do not prove one build or execution. Distinguish static facts, runtime facts, simulation results and silicon applicability.
5. Accept negative or incomplete packages. Missing traces or unreliable bindings may remain `UNKNOWN` / `NOT_ESTABLISHED`; never fabricate a Type-II chain or force the new delivery into `real_case_001` conventions.
6. Generate reviewed deterministic expected artifacts under the new case's `expected/`, add focused regression tests, then run the full project validation (`pytest -q`, `python -m pip check`, `python -m compileall -q src tests scripts`, `git diff --check`).
7. Stop and report the new support, evidence boundaries, tests and remaining unknowns for primary-engineering review before any commit or tag.

This guide intentionally stops at adaptation. Static Fact != Runtime Fact; CFG reachability != execution; trigger support != deviation; pattern/candidate != vulnerability; simulation evidence != physical silicon evidence. A later dedicated adaptation session handles one raw sample at a time; this guide does not add or adapt `real_case_002`.

## Codex 快速适配入口

请适配以下新硬件样本：

CASE_ID=real_case_NNN
DECLARED_TOOL_FAMILY=processorfuzz
RAW_SOURCE=/path/to/sample.zip
SAMPLE_ROOT=samples/processorfuzz/real_case_NNN

严格按照 docs/hardware-sample-adaptation.md 执行。
完成后停止在 commit 前并报告。
