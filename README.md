# ChipChain

ChipChain is an **evidence-driven Type-II firmware–hardware cross-layer analysis framework**. It asks whether normal firmware execution satisfies a hardware trigger, whether the hardware then deviates from a stated specification, and whether a controlled Reference/Variant comparison objectively supports that conclusion.

The current runnable backend is a **controlled synthetic Ibex MMIO experiment**. It replays existing ELF, trace, source, contract, and capability artifacts without invoking an LLM, building RTL, or running a simulator. External SI/log adapters and other processors are future work. This repository does not claim an end-to-end vulnerability in a physical chip.

## What is verified

```mermaid
flowchart LR
    A[Normal firmware behavior] --> B[Hardware trigger]
    B --> C[Hardware deviation]
    C --> D[Objective observation]
    D --> E[Controlled Type-II verification]
```

Each arrow is an evidence boundary. A candidate is not a vulnerability. A static instruction fact is not runtime execution. Execution does not establish trigger satisfaction. A satisfied trigger does not establish deviation. An observed value is not, by itself, a verified deviation. A controlled synthetic result does not establish a silicon vulnerability or external attacker control.

The verifier returns `supported`, `contradicted`, or `unknown` for the component conditions. Invalid bytes or broken identities fail closed as errors; missing evidence stays `unknown` rather than becoming a positive result. See [architecture](docs/architecture.md) and [methodology](docs/methodology.md) for the evidence gates.

## Install and quick start

Python 3.11+ is required. The public examples need only the package and its deterministic dependencies; no API key or external simulator is needed.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m chipchain.cli analyze \
  --manifest examples/type2_positive/manifest.json \
  --output output/type2-positive
```

After installation, `chipchain analyze` is equivalent to `python -m chipchain.cli analyze`. Try the other two packaged examples:

```bash
chipchain analyze --manifest examples/type2_trigger_negative/manifest.json --output output/type2-negative
chipchain analyze --manifest examples/type2_unknown/manifest.json --output output/type2-unknown
```

`--verbose-artifacts` additionally writes selected validated contract, static, and bridge objects. Normal output contains only three files. The analysis API is read-only; CLI output is written only when the command explicitly calls the writer.
An existing nonempty output directory is rejected to protect earlier results.

## Inputs

`--manifest` names a JSON **artifact index**. It points to an existing `HardwareBehaviorContract`, optional state/source proof, and target and Reference run indexes. Each run index points to the canonical static catalog, runtime observations, execution bridge, platform proof, firmware capabilities, input identity, ELF bytes, raw bus/processor traces, stdout/stderr, and an optional explicit observation binding. Paths are relative to their containing index; external read-only files may also be referenced. The index is an I/O envelope, not a scientific schema or new ID recipe.

The examples include small synthetic artifacts under `examples/type2_positive/fixtures/`; the negative and unknown manifests reuse these files. Their frozen scientific identities are replayed from the included bytes. `samples/` is a local, Git-ignored workspace for real research inputs; `output/` is a local, Git-ignored result workspace. The packaged examples are synthetic and are not real processor findings. See [examples](examples/README.md) and [samples](samples/README.md).
The portable fixtures contain pinned source manifests and changed peripheral bytes, not the full RTL source tree or a simulator executable. They replay the frozen evidence chain; independent regeneration of source/platform attestations requires the separately retained local research workspace.

The current CLI accepts **existing canonical artifacts**. It does not accept raw `.si`, arbitrary hardware logs, or an arbitrary `--firmware firmware.elf --hardware-spec hardware.json --hardware-log hardware.log` pipeline. Such adapters require separate validated ingestion before this workflow can consume their outputs.

## Outputs and how to read them

| File | Meaning |
| --- | --- |
| `summary.json` | Compact final outcome, stage statuses, contract/result IDs, and Reference control. |
| `verification.json` | Complete canonical `Type2VerificationResult`, including per-condition evidence IDs, reason codes, and missing requirements. |
| `report.md` | Short, human-readable Chinese explanation and scope warning. |

For the positive example, `report.md` begins:

> **结论：受控合成 Type-II 链条已验证。** 触发、偏差、客观观测和 Reference/Variant 对照均为 `supported`。Reference 的触发和预期行为成立，未观测到偏差。

`unknown` is a scientific outcome, not an execution failure. A malformed or mismatched artifact exits with code 2 and does not produce an accepted verification result. The CLI returns code 0 for a valid positive, negative, or unknown result.

## Controlled golden outcomes

| Case | Expected outcome | What it demonstrates |
| --- | --- | --- |
| P1 (`type2_positive`) | `verified_controlled_type2_chain` | A5 firmware triggers the Variant; post-update internal STATUS and bus-visible read support the controlled deviation. |
| N1 (`type2_trigger_negative`) | `trigger_contradicted` | A4 firmware executes, but its COMMAND value does not satisfy the A5 trigger. |
| N2 (P1 Reference control) | trigger and expected behavior supported; `deviation_observed=false` | The matching Reference run behaves as specified. |
| U1 (`type2_unknown`) | `unknown` | Removing the explicit observation binding prevents the final inference. |

These outcomes and their content-addressed IDs are asserted by portable tests and compared against the final research freeze. The earlier full scientific freeze passed **1528 tests, with 29 skipped**; the smaller consolidated suite is the current regression entry point.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/chipchain/firmware/` | Deterministic MMIO static grounding, execution binding, and firmware capabilities. |
| `src/chipchain/hardware/` | Hardware behavior contract. |
| `src/chipchain/cross_layer/` | Controlled Type-II verifier and retained public contract/compatibility primitives. |
| `src/chipchain/workflow/`, `src/chipchain/cli.py` | Thin artifact loading, orchestration, and command-line output. |
| `examples/` | Three portable synthetic outcomes sharing small fixtures. |
| `tests/` | Identity, provenance, fail-closed, component and golden regressions. |
| `experiments/` | Frozen synthetic-source and collector material used by local historical replay. |
| `samples/`, `output/` | Local input and result workspaces; real data and runtime outputs are ignored by Git. |

## Test

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
```

The portable example tests run in a fresh clone. Additional read-only regression tests replay locally frozen simulator and compatibility artifacts when those workspaces are available; otherwise they explicitly skip. Tests block network connections and external process launches by default.

## Current scope and future work

The verifier is bound to the reviewed synthetic Ibex source delta, platform identities, 32-bit MMIO mapping, complete local evidence window, and controlled Reference/Variant comparison. It does not infer arbitrary path feasibility, external control, exploitability, physical-board behavior, or safety from a negative/unknown result. Type I and Type III, validated external SI/log adapters, broader platforms, and real-hardware verification remain future work.

Historical research phases and their exact implementations remain available from the repository's stable Git tags. The current mainline presents the Type-II method and runnable evidence path without requiring readers to reconstruct the development chronology.
