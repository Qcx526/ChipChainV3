# ProcessorFuzz hardware deliveries

`real_case_001/` contains the immutable hardware-team ZIP and deterministic
acceptance artifacts. A directory name is an indexing convenience; testcase
identity comes from the `.si` bytes. Package discovery does not establish
that every file belongs to one trusted execution or build chain.

The contained ELF is a hardware-supplied trigger-validation test program.
It is not customer firmware. General firmware-analysis validation uses
independently authored project firmware samples; future customer firmware
must be introduced as a separate evidence source.

For a new hardware delivery, preserve its original package under
`samples/<tool>/real_case_NNN/raw/` and follow the
[Hardware Sample Adaptation Guide](../../docs/hardware-sample-adaptation.md).
The developer-only `scripts/inspect_hardware_sample.py` inventories a ZIP,
TAR, or extracted directory before a dedicated adaptation Codex compares it
with existing adapters. Its inventory and brief are not scientific evidence
or trusted provenance bindings. Keep reviewed expected artifacts and focused
regression tests with each adapted case; an incomplete case may remain
`UNKNOWN` / `NOT_ESTABLISHED`.

## 新样本适配

如需使用 Codex 适配新的 ProcessorFuzz 硬件交付样本，请直接复制：

`docs/hardware-sample-adaptation.md` 中的 **Codex 快速适配入口**。
