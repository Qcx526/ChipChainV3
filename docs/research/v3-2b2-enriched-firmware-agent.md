# V3-2B2 — Enriched Firmware Context Envelope & Controlled DeepSeek Comparison

## A. Implementation Summary

基线 `v3-2a3-stable` / `da039c1fadf5c19fabe2a826f53edca92d8c5bc7`。
完成独立 `firmware-analysis-envelope/v2`、174 条 exact reasoning evidence union、
显式 enriched Agent/runner 路径、既有 persistence/reviewed validator 的 v2 支持。

2026-09-14 完成 **一次**真实调用，完整机器校验通过：**machine-valid / pending human review / NOT reviewed**。
本轮人工语义审计为 **mixed results，存在新结构错误，不应仅凭机器通过接受**。
未调 prompt、重跑、修改 A3 selection、reviewed-export、进入 angr/runtime/Cross-Layer。

## B. Files Changed

修改：`agents/firmware.py`、`agents/firmware_evidence.py`、`agents/model_outputs/firmware.py`、
`integrations/deepseek_firmware.py`、`execution/reviewed_output.py`（均位于 `src/chipchain/`），root README。
新增：`src/chipchain/agents/projections/firmware_envelope.py`、
`tests/unit/test_firmware_envelope.py`、`tests/integration/test_firmware_envelope_local.py`、本文。

A1/A3 frozen projection、domain schemas、prompt、ARM decoder、Ghidra backend 没有修改。

## C. Experimental Control

R1 input=A1；B2 input=A1+A3。真实 provider 配置与 R1 invocation 逐字段比较完全一致：
`deepseek-flash`、`firmware-security-agent/v1`、temperature=0、max_tokens=8192、timeout=180、
max_retries=0、thinking=disabled、function_calling、strict=false、ModelFirmwareAnalysisReport。
没有新增针对 read/write、UART path 或 IRQ prose 的机器语义 gate。

R1 报告内容只在 B2 provider 完成后读取用于比较；没有放进 model context。
同一 model alias 不保证供应商内部权重跨时间不变；这是单样本、单次 paired comparison，不能推导统计改善。

## D. Envelope v2 Architecture

```text
firmware-analysis-envelope/v2
├── firmware_projection        原 A1.1 v1 JSON object
├── relevant_static_structure  原 A3 v1 compact JSON object
└── static_source_binding      显式 ELF fingerprint + A2 semantic source hash
```

无 nested JSON string，无双重转义，不重写两个 frozen component。
A3 冻结 wire 只含 A2 semantic source hash，不直接含 ELF fingerprint；为满足同 ELF 验证，
新增 envelope-level `static_source_binding`，在发送前对 full A2 source hash 和 A1 artifact fingerprint 交叉检查。
Agent enriched API 因此显式接收 `relevant_static_structure` 和 `static_source`，只做内存验证，不运行 Ghidra/读 ELF。

## E. A1 Component Identity

`firmware-analysis-projection/v1`，39,438 characters，57 observations、55 behaviors、57 evidence、0 runtime。
SHA256：`48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803`。
从 envelope 提取后按 frozen serializer 重建，长度和 SHA 与 R1 一致。

## F. A3 Component Identity

`firmware-relevant-static-structure/v1`，16,631 characters。
34 functions、23 MMIO sites、22 confirmed calls、12 caller-seed-only unresolved calls、
14 vector groups、51 non-null vector indices、172 exact evidence。
SHA256：`4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304`。
Seed/one-hop/unresolved policy、named-column codec 和 evidence identity 均未改。

## G. Evidence Union

A1=57，A3=172，overlap=55，exact union=174。所有 overlap 完整 EvidenceRef 相等。
`collect_firmware_evidence(inputs)` 保持 A1-only；新增
`collect_firmware_reasoning_evidence(inputs, relevant_static_structure=None)` 默认仍为原 registry，
显式提供 typed A3 时校验 codec、case/artifact 和 exact collisions，再深复制合并。
不存在未知 ID 的修复、drop、nearest match。

## H. 128-Item Compatibility Resolution

Model envelope 中 A1 和 A3 继续各自保留 57/172 catalog，不把174塞入v1。
`MAX_CONTEXT_ITEMS=128`、`MAX_CONTEXT_CHARS=64000` 均未改。
新增 `MAX_REASONING_EVIDENCE=256` 只约束 enriched reasoning registry，属于 model-context safety bound，非 domain limit。

## I. Envelope Codec / Determinism

JSON sort_keys=True、compact separators、ensure_ascii=False、UTF-8。
两个 component 均为原 canonical wire object；恢复后重序列化必须精确一致。
重建 envelope 字节/hash 一致；拒绝重复 JSON key、版本、case/ELF/source hash、evidence collision、
非 canonical components、path/oracle content 和超限内容。
没有 research markdown、metrics.json、R1/human audit 或本地路径进入 message。

## J. Final Context Size / SHA256

**56,408 characters**；低于 B2 58,000 和全局 64,000。
余量分别 1,592 / 7,592 chars。两个 components 为 56,069，envelope/source binding 开销339。

```text
6afef3295f8c54ee7fef65446db0a91169ee833d3ede4314e38e45ca0d7c5016
```

## K. Firmware Agent Enriched Path

`invoke(inputs)` 继续 `firmware_context(inputs)` v1。
显式 `invoke(inputs, relevant_static_structure=..., static_source=...)` 使用 v2。
Agent 无自动 IO/Ghidra/A3 build；runner `--context-mode enriched_v2 --ghidra-home ...` 负责 fresh deterministic preparation。
Runner 默认 `v1`，保留历史行为。`--preflight-only` 不读 `.env`/key、不构建 provider。

## L. Hydration / Grounding With A3 Evidence

Model schema仍为 ID-only `ModelFirmwareAnalysisReport`。A1-only、A3-only、shared IDs 均可引用。
Hydration 得到原 canonical FirmwareAnalysisReport 的完整 EvidenceRefs，随后 exact evidence 和 report/IR/reference gates。
没有 evidence_ids 泄漏到 canonical report，没有可直接注入 arbitrary evidence dict 的 hydration 参数。

## M. ProcessorBehaviorIR Preservation

B2 canonical IR 与 R1 历史 AnalysisRun 中的 IR 完整对象相等，55 个 A1 behaviors。
A3 新增行为数0。模型无法替换 IR。enriched persistence 同时核对 v1 behavior fields、decoded facts 和 exact IR evidence。

## N. Real-Run Epistemic Policy Preservation

沿用所有 claim 必须 cite evidence、禁止 VERIFIED、RUNTIME 必须有 runtime-scope evidence。
A3-only 静态 evidence 不获得 runtime scope。
新增测试明确证明语义上错误的 read/write prose 不会被新 gate 自动纠正；它属于本次人工审计对象。

## O. Persistence

成功目录：
`output/fuzzware:heat-press:scenario-13/104a5332-3cf3-4263-b988-8b5b0b82f14e/`。
包含原五文件 analysis_run.json、firmware_analysis_report.json、analysis_input.json、invocation.json、invocation_attempts.jsonl。

analysis_input.json 为真正发送的 v2 envelope，沿用 writer 在末尾附加1个LF的历史惯例；
context SHA 按 sent text 计算，validator 明确接受单终止LF排除。canonical report 已 hydration。
没有保存 raw provider body/tool calls/headers/secret；只保留 validated report、allowlisted usage/response metadata。
目录由 UUID exclusive creation 创建，不覆盖已有 run。

## P. Reviewed Exporter Compatibility

扩展同一 exporter validator，根据显式 envelope_version 区分 v2，支持 v1 Firmware、v2 Firmware和历史Hardware。
v2 复验 components/hash、union grounding、A1 IR、artifact/source binding 和额外 tool provenance。
本轮仅在 synthetic tests 中执行 exporter；**真实 B2/R1 未 reviewed-export**。

## Q. Offline Tests

新增35个unit tests：component exact recovery、determinism/hash、两个 size guards、path/oracle neutrality、
source/ELF/case identity、shared equality/collision、256独立bound、三类 evidence hydration、unknown拒绝、
v1 context regression、A3不可赋予runtime、persistence sent-context equality、no-overwrite、secret/raw保护、
synthetic v2 exporter、component/evidence/IR/provenance损坏拒绝、provider settings/baseline拒绝、无新prose gate。
旧 Firmware/Hardware suites 继续通过。新增1个 real deterministic opt-in integration，无模型调用。

## R. Exact Test Results — Before Real API

```text
pytest -q
628 passed, 10 skipped in 9.28s

python -m pip check
No broken requirements found.

python -m compileall -q src tests
exit 0

git diff --check
exit 0

real deterministic B2 preflight
1 passed in 11.53s
```

## S. Real Deterministic Preflight

显式四个冻结artifact → A1 → Ghidra 10.1.4 → Cortex-M vectors → A3 → v2。
生产入口没有把已保存的 A2/A3 JSON 当truth。API前核对 A1/A3长度/hash、所有A3计数、57/172/55/174、
0 runtime、model/settings，并打印安全 preflight。真实调用前的 fresh rebuild 与独立测试结果相同。

```bash
CHIPCHAIN_GHIDRA_HOME=/home/qcx/fuzz/gdbfuzz/dependencies/ghidra \
CHIPCHAIN_FUZZWARE_ROOT=/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
.venv/bin/python -m pytest -q -s tests/integration/test_firmware_envelope_local.py
```

## T. Real DeepSeek Invocation

**1 provider call，attempt_index=1，无retry**。started `2026-09-14T06:47:51.876774+00:00`，
succeeded `2026-09-14T06:48:06.500605+00:00`。
请求/返回模型均 deepseek-flash。usage：input 19,891、output 3,956、total23,847 tokens。
run ID `104a5332-3cf3-4263-b988-8b5b0b82f14e`。
完整 schema/hydration/exact grounding/report-IR/epistemic/persistence校验成功。
6 findings、3 paths、10 reachability（8 static + 2 unknown，0 runtime）、5 anchors。
没有第二次semantic retry，没有根据结果修改prompt/selection/production code。

## U. Full Safe invocation.json

```json
{
  "case_id": "fuzzware:heat-press:scenario-13",
  "run_id": "104a5332-3cf3-4263-b988-8b5b0b82f14e",
  "attempt_index": 1,
  "provider": "deepseek",
  "model": "deepseek-flash",
  "prompt_id": "firmware-security-agent",
  "prompt_version": "v1",
  "context_sha256": "6afef3295f8c54ee7fef65446db0a91169ee833d3ede4314e38e45ca0d7c5016",
  "agent_role": "firmware",
  "projection_version": "firmware-analysis-projection/v1",
  "temperature": 0,
  "max_tokens": 8192,
  "timeout_seconds": 180,
  "max_retries": 0,
  "thinking": "disabled",
  "structured_output_method": "function_calling",
  "strict": false,
  "usage": {
    "input_tokens": 19891,
    "output_tokens": 3956,
    "total_tokens": 23847
  },
  "response_metadata": {
    "id": "b6d8bee5-4da1-4ea0-962e-1248bca313a3",
    "model_name": "deepseek-flash"
  },
  "context_characters": 56408,
  "observation_count": 57,
  "observation_counts_by_kind": {
    "static_instruction_site": 23,
    "mmio_model": 32,
    "environment_input": 2
  },
  "observation_counts_by_scope": {
    "static": 23,
    "configuration": 33,
    "artifact": 1
  },
  "behavior_count": 55,
  "evidence_count": 57,
  "runtime_observation_count": 0,
  "stub_ir_equal": true,
  "claim_counts": {
    "findings": 6,
    "external_input_paths": 3,
    "reachable_behaviors": 10,
    "issue_anchors": 5
  },
  "model_output_schema": "ModelFirmwareAnalysisReport",
  "context_mode": "enriched_v2",
  "envelope_version": "firmware-analysis-envelope/v2",
  "base_projection_version": "firmware-analysis-projection/v1",
  "base_projection_sha256": "48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803",
  "base_projection_characters": 39438,
  "relevant_structure_version": "firmware-relevant-static-structure/v1",
  "relevant_structure_sha256": "4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304",
  "relevant_structure_characters": 16631,
  "a1_evidence_count": 57,
  "a3_evidence_count": 172,
  "evidence_overlap_count": 55,
  "merged_evidence_count": 174
}
```

## V. Compact B2 Claim Index

下表从 canonical report 生成。每行完整列出behavior/evidence IDs；summary/entry保持原报告文字。
`ReachableBehavior` 没有summary字段，使用其behavior/path references说明。这里保留错误原文供人工审查，不认可其结论。

| Type / ID | Summary / entry point | Epistemic / reachability | Behavior IDs | Evidence IDs |
|---|---|---|---|---|
| findings / `f-uart-irq-mmio` | UART/USART interrupt handlers (f80abc/f80ad0/f80adc/f80ae8) contain unresolved computed/ambiguous call sites targeting 529828 (IrqHandler f815a4), whose body contains MMIO read sites s815aa (m20, UARTClass::IrqHandler) and s815b0 (m1). This is a candidate external-input-driven MMIO path, but the call targets are unresolved and vector binding does not establish interrupt occurrence. | inferred / — | s815aa, s815b0, m20, m1 | vector-24, vector-33, vector-34, vector-36, call-80abe, call-80ad2, call-80ade, call-80aea, s815aa, s815b0, m20, m1 |
| findings / `f-reset-systeminit-mmio` | Reset_Handler (f80f34, vector 1) is statically bound; SystemInit (f80eac) is a one-hop confirmed callee of Reset_Handler and contains MMIO read sites s80eba/s80eca/s80ed2/s80eda/s80ee6/s80ef2/s80efe/s80f0a with models m16/m2/m3/m12/m4/m0/m5/m6. Static containment and call edges are established; runtime execution is not. | derived / — | s80eba, s80eca, s80ed2, s80eda, s80ee6, s80ef2, s80efe, s80f0a, m16, m2, m3, m12, m4, m0, m5, m6 | vector-1, call-80f88, s80eba, s80eca, s80ed2, s80eda, s80ee6, s80ef2, s80efe, s80f0a, m16, m2, m3, m12, m4, m0, m5, m6 |
| findings / `f-pio-missing-containment` | MMIO sites at PCs 527694/527696/527706 (PIO_SetPeripheral, s80d4e/s80d50/s80d5a) lack Ghidra function-body containment (containment_status=missing) and are associated with passthrough models m7/m8/m9/m10/m11. No function is guessed for these sites. | derived / — | s80d4e, s80d50, s80d5a, m7, m8, m9, m10, m11 | s80d4e, s80d50, s80d5a, m7, m8, m9, m10, m11, containment-m7, containment-m8, containment-m9, containment-m10, containment-m11 |
| findings / `f-unmodeled-mmio` | Several MMIO read sites are associated with unmodeled models (m21-m31) at PCs 527894/527900/527930/527950/527998, spanning PIO_GetOutputDataStatus, pmc_enable_periph_clk and pmc_disable_periph_clk. Unmodeled status means no deterministic value semantics are available for these accesses. | derived / — | m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, s80e16, s80e1c, s80e3a, s80e4e, s80e7e | m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, s80e16, s80e1c, s80e3a, s80e4e, s80e7e |
| findings / `f-opaque-input-unlinked` | The opaque environment input (6009 bytes) has no recorded MMIO consumption, runtime state or failure outcome and is not deterministically linked to any function, MMIO site, vector or handler. | observed / — | — | input |
| findings / `f-trigger-unlinked` | The Fuzzware interrupt-trigger configuration (round_robin, every 1000 emulator ticks) has no deterministic relation to any Cortex-M vector entry or handler execution. | observed / — | — | trigger |
| external_input_paths / `eip-uart-irq` | UART_Handler (f80abc, vector 24 / external IRQ 8) — UART/USART interrupt vector entries (UART_Handler f80abc, USART0/1/3_Handler f80ad0/f80adc/f80ae8) are statically bound to vector slots. Their bodies contain unresolved computed/ambiguous call sites (call-80abe, call-80ad2, call-80ade, call-80aea) targeting 529828 (IrqHandler f815a4), which contains MMIO sites s815aa (m20) and s815b0 (m1). This is a candidate external-input path, but vector binding does not establish interrupt occurrence and the call targets are unresolved. | inferred / — | s815aa, s815b0, m20, m1 | vector-24, vector-33, vector-34, vector-36, call-80abe, call-80ad2, call-80ade, call-80aea, s815aa, s815b0, m20, m1 |
| external_input_paths / `eip-opaque-input` | unresolved (opaque environment input, 6009 bytes) — An opaque environment input artifact exists but is not deterministically linked to any function, MMIO site, vector or handler. No consumption path is established. | unknown / — | — | input |
| external_input_paths / `eip-interrupt-trigger` | unresolved (Fuzzware interrupt-trigger config, round_robin, every 1000 ticks) — A Fuzzware interrupt-trigger configuration exists, but no deterministic relation connects it to any Cortex-M vector entry or handler execution. | unknown / — | — | trigger |
| reachable_behaviors / `rb-uart-irq-mmio` | Paths: eip-uart-irq | hypothesized / unknown | m20 | m20, s815aa, call-80abe, call-80ad2, call-80ade, call-80aea |
| reachable_behaviors / `rb-uart-irq-mmio-2` | Paths: eip-uart-irq | hypothesized / unknown | m1 | m1, s815b0, call-80abe, call-80ad2, call-80ade, call-80aea |
| reachable_behaviors / `rb-reset-systeminit` | Paths:  | derived / static | m16 | vector-1, s80eba, m16 |
| reachable_behaviors / `rb-reset-systeminit-2` | Paths:  | derived / static | m2 | vector-1, s80eca, m2 |
| reachable_behaviors / `rb-reset-systeminit-3` | Paths:  | derived / static | m3 | vector-1, s80ed2, m3 |
| reachable_behaviors / `rb-reset-systeminit-4` | Paths:  | derived / static | m4 | vector-1, s80ee6, m4 |
| reachable_behaviors / `rb-reset-systeminit-5` | Paths:  | derived / static | m5 | vector-1, s80efe, m5 |
| reachable_behaviors / `rb-reset-systeminit-6` | Paths:  | derived / static | m6 | vector-1, s80f0a, m6 |
| reachable_behaviors / `rb-reset-systeminit-7` | Paths:  | derived / static | m0 | vector-1, s80ef2, m0 |
| reachable_behaviors / `rb-reset-systeminit-8` | Paths:  | derived / static | m12 | vector-1, s80eda, m12 |
| issue_anchors / `a-uart-irq-input` | Candidate external-input anchor: UART/USART interrupt handlers with unresolved computed call sites into IrqHandler (f815a4) containing MMIO read sites m20/m1. Interrupt occurrence and call resolution are not established. | inferred / — | s815aa, s815b0, m20, m1 | vector-24, vector-33, vector-34, vector-36, call-80abe, call-80ad2, call-80ade, call-80aea, s815aa, s815b0, m20, m1 |
| issue_anchors / `a-reset-systeminit` | Reset-path anchor: Reset_Handler -> SystemInit with MMIO read sites and constant/set models. Static containment and call edges established; runtime execution not established. | derived / — | s80eba, s80eca, s80ed2, s80eda, s80ee6, s80ef2, s80efe, s80f0a, m16, m2, m3, m12, m4, m0, m5, m6 | vector-1, call-80f88, s80eba, s80eca, s80ed2, s80eda, s80ee6, s80ef2, s80efe, s80f0a, m16, m2, m3, m12, m4, m0, m5, m6 |
| issue_anchors / `a-pio-containment-gap` | Containment gap anchor: PIO_SetPeripheral MMIO sites (527694/527696/527706) lack function-body containment; no function is guessed. | derived / — | s80d4e, s80d50, s80d5a, m7, m8, m9, m10, m11 | s80d4e, s80d50, s80d5a, m7, m8, m9, m10, m11 |
| issue_anchors / `a-unmodeled-mmio` | Unmodeled MMIO anchor: read sites with unmodeled models (m21-m31) provide no deterministic value semantics. | derived / — | m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31 | m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31 |
| issue_anchors / `a-input-trigger-unlinked` | Unlinked-input anchor: opaque input and interrupt-trigger configuration have no deterministic relation to any function, MMIO site, vector or handler. | observed / — | — | input, trigger |

## W. A3 Evidence Usage by Claim

24 claims：**16**至少引用一条A3-only evidence；**8**只引用A1 registry中证据；
**19**至少引用一条shared evidence（与前两类可重叠）；**5**引用A1-only namespace（input/trigger）。
“A1-only claim”这里指其所有refs属于A1，并不代表其中不含shared refs。

At least one A3-only ID (16):

`f-uart-irq-mmio`, `f-reset-systeminit-mmio`, `f-pio-missing-containment`, `eip-uart-irq`, `rb-uart-irq-mmio`, `rb-uart-irq-mmio-2`, `rb-reset-systeminit`, `rb-reset-systeminit-2`, `rb-reset-systeminit-3`, `rb-reset-systeminit-4`, `rb-reset-systeminit-5`, `rb-reset-systeminit-6`, `rb-reset-systeminit-7`, `rb-reset-systeminit-8`, `a-uart-irq-input`, `a-reset-systeminit`。

All evidence belongs to A1 (8):

`f-unmodeled-mmio`, `f-opaque-input-unlinked`, `f-trigger-unlinked`, `eip-opaque-input`, `eip-interrupt-trigger`, `a-pio-containment-gap`, `a-unmodeled-mmio`, `a-input-trigger-unlinked`。

At least one shared ID (19):

`f-uart-irq-mmio`, `f-reset-systeminit-mmio`, `f-pio-missing-containment`, `f-unmodeled-mmio`, `eip-uart-irq`, `rb-uart-irq-mmio`, `rb-uart-irq-mmio-2`, `rb-reset-systeminit`, `rb-reset-systeminit-2`, `rb-reset-systeminit-3`, `rb-reset-systeminit-4`, `rb-reset-systeminit-5`, `rb-reset-systeminit-6`, `rb-reset-systeminit-7`, `rb-reset-systeminit-8`, `a-uart-irq-input`, `a-reset-systeminit`, `a-pio-containment-gap`, `a-unmodeled-mmio`。

## X. R1 vs B2 Controlled Comparison

| Audit target | R1 | B2 | Assessment |
|---|---|---|---|
| SystemInit directions | 明说 boot-time configuration writes | 明确列举8 sites为MMIO reads | **corrected，仅方向** |
| UARTClass::write分类 | outbound却放ExternalInputPath | 未提write，未建对应path | **not repeated，不能说corrected** |
| ADC physical input | plausible analog input path，缺少结构证据 | 未提ADC input path | **not repeated** |
| Trigger→UART | config can drive UART IRQ | 明确关系未建立，相关paths为unknown | **corrected relationship statement** |
| UART handler uncertainty | 名称推断 externally-facing | 引用vectors/unresolved并限定candidate | 更谨慎，但仍有候选接口推断风险 |
| Unresolved UART kind | 无A2事实 | 把decoder_disagreement说成computed/ambiguous | **new error** |
| Reset→SystemInit | 无此confirmed-edge结论 | 宣称Reset confirmed one-hop callee SystemInit | **new error，严重** |
| Static reset reachability | 无reset static records | 8条static/derived，证据主要vector-1+site/model | **new unsupported structure inference** |
| Missing PIO containment | 无该信息 | 保留3 missing、不猜函数 | 正确使用新证据 |
| Runtime/crash/confirmed vulnerability | 无确认 | 无确认 | maintained boundary |

整体 **mixed**：新增结构证据被使用，但引用正确ID并不保证理解了其内容。
单次结果不能声称可靠改善或稳定能力；机器通过不等于人工接受。

## Y. Semantic Human Audit

**🔴 新错误1：虚构confirmed Reset→SystemInit边。**
`f-reset-systeminit-mmio` / `a-reset-systeminit` 声称SystemInit是Reset_Handler的confirmed one-hop callee，
引用 `call-80f88`。实际 A3：该callsite caller=`f80f34`（Reset_Handler），
target=`0x816cc`，reason=`computed_or_ambiguous`，它在unresolved集合而非confirmed edges。
实际指向SystemInit的confirmed edge是 **`call-80afa: f80af4 (init) → f80eac (SystemInit)`**。
不能用Reset vector绑定替代调用路径证据。8条 `rb-reset-systeminit*` 的static/derived结论因此缺乏所宣称reset path支持；
其中引用vector-1与局部site/model并不能补足缺失调用关系。这些不是RUNTIME claims，但仍是结构语义错误。

**🔴 新错误2：混淆UART unresolved原因。**
`call-80abe/80ad2/80ade/80aea` 在A3中全是 **decoder_disagreement**，target为`0x815a4`。
模型多次描述为computed/ambiguous甚至“targets unresolved”；它没有把这些UART边升级为confirmed，
但混淆了已知静态branch target与未确认的direct-call classification。f/eip/anchor和unresolved questions中均重复。

**🟠 新的不精确概括：SystemInit models。**
`a-reset-systeminit` 概括为constant/set models，遗漏 `m0` 的bitextract和 `m12` 的passthrough。
不改变read方向，但说明完整evidence引用仍未保证准确逐项总结。

**🟠 残余符号推断风险。**
`eip-uart-irq` 仍创建candidate external-input path，status=inferred；模型明确说未证实interrupt occurrence、
未解决call，且最终说明symbols不是verified physical interfaces。因此不能说它确认了物理UART/ADC路径，
也不能把该candidate当作确定性输入路径。ADC/write旧推断没有重复，不构成主动纠正的证据。

**正确保留的边界。**
SystemInit八站点确实都说read；trigger relation与opaque consumption未建立；3个missing PIO sites未猜函数；
没有RUNTIME reachability、VERIFIED、crash outcome或confirmed vulnerability/root cause。
“missing relation”不是不可达或永不执行的negative proof。

**仍缺的确定性证据。**
需要区分直接BL、tail branch和computed call的可审计关系；真实reset/init调用链证据；
明确的中断控制器/trigger→vector映射；外围设备寄存器语义与物理输入来源；opaque input消费位置及运行trace。
这些缺口应先界定，再决定是否进入后续angr/runtime工作，本阶段未执行。

## Z. Git Status / Preservation

没有git add/commit/push/tag。真实B2未reviewed-export，README为machine-valid / pending human review。
对60个受保护的源码/历史输出文件逐项hash比较全部不变；四个corpus fingerprint不变。
R1、两个v4-pro pilots、A2/A3历史输出和reviewed/v3-1b1原字节保留。

## Final 34 Answers

1. A1 v1与R1 byte-identical：是。
2. A3与冻结基线byte-identical：是。
3. Envelope版本：`firmware-analysis-envelope/v2`。
4. MAX_CONTEXT_ITEMS=128未改。
5. 模型保留两个catalog，内部174条exact union，独立256 safety bound。
6. 55 overlap完整对象相等。
7. B2可引用A3-only，实际有16 claims这样引用。
8. Hydration仍得到canonical full EvidenceRefs。
9. IR与R1完全一致，55 A1 behaviors。
10. Context 56,408 characters。
11. SHA `6afef3295f8c54ee7fef65446db0a91169ee833d3ede4314e38e45ca0d7c5016`。
12. 同时≤58,000和≤64,000。
13. 没有local paths/oracle/research/R1 audit进入context。
14. Prompt仍firmware-security-agent v1。
15. Requested model=deepseek-flash。
16. Returned model_name=deepseek-flash。
17. 恰好一次provider call。
18. 完整机器校验成功。
19. 6 findings / 3 paths / 10 reachability / 5 anchors。
20. 16 claims cite A3-only。
21. 八个SystemInit sites全部正确称read，但其reset-path推断错误。
22. UART write/ADC未重复，记录为not repeated；SystemInit方向有明确corrected证据。
23. 没有将UARTClass::write建为ExternalInputPath。
24. 没将UART unresolved边升为confirmed，但把disagreement误称computed/ambiguous。
25. 没宣称configured trigger确定到handler，明确未建立关系。
26. 没确认physical UART/ADC input；仍有inferred candidate UART path风险。
27. 0 RUNTIME reachability，8 static + 2 unknown。
28. 没有crash或confirmed vulnerability/root cause。
29. 新错误包括Reset→SystemInit confirmed边、8条unsupported reset static reachability、UART unresolved分类，以及models概括遗漏。
30. 未持久化raw provider output。
31. 未执行真实reviewed export；仅synthetic exporter tests。
32. 历史R1/A2/A3输出未改。
33. Mixed results，不足以宣布可靠改善。
34. 仍缺call/tail/computed关系、reset-init链、trigger-vector映射、peripheral/physical来源和input消费/runtime证据，详见Y。
