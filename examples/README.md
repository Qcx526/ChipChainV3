# Portable synthetic Type-II examples

Three small artifact indexes replay the controlled Ibex MMIO experiment without a model, simulator or local `output/` workspace:

| Directory | Expected result | Input distinction |
| --- | --- | --- |
| `type2_positive/` | P1: `verified_controlled_type2_chain` | A5 firmware on the Variant, with A5 Reference control (N2). |
| `type2_trigger_negative/` | N1: `trigger_contradicted` | A4 firmware does not meet COMMAND=A5. |
| `type2_unknown/` | U1: `unknown` | A5 run without the explicit observation binding. |

Run from the repository root:

```bash
.venv/bin/python -m chipchain.cli analyze --manifest examples/type2_positive/manifest.json --output output/type2-positive
```

`type2_positive/fixtures/` contains the shared, minimal replay bytes: synthetic source manifests and patch, two small firmware ELF images, four static/runtime/bridge/capability object groups, their raw bus/processor records and process logs. The other examples reference those same bytes; they do not duplicate a simulated workspace. `manifest.json` and per-run `run.json` files are file indexes, not domain objects. The original research workspaces under `output/` remain ignored by Git.

These fixtures establish the exact controlled synthetic identities asserted by tests. They do not contain a real silicon observation or a general `.si` parser. See [README](../README.md) for outcome interpretation and [methodology](../docs/methodology.md) for the evidence boundaries.
