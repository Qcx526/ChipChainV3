# V3-2B-R1 — ID-Based Evidence Binding & deepseek-flash Baseline

稳定基线仍为 `v3-2a1-1-stable` / `e7262ce19d58b1d570946dd3c9f15f7e3c050c6e`。
R1 保留未冻结的 V3-2B 集成代码；未 reset、commit/push/tag，也不执行真实 reviewed export。

## A. R1 Summary

```text
unchanged firmware-analysis-projection/v1
→ StructuredReportRuntime[ModelFirmwareAnalysisReport]
→ evidence_ids
→ deterministic registry hydration (deep copy)
→ canonical FirmwareAnalysisReport (full EvidenceRefs)
→ exact evidence / claim cross-reference / existing IR gates
→ real-run evidence + epistemic + runtime-scope policy
→ validated local output
```

Shared DeepSeek 默认改为 deepseek-flash。模型选择证据引用，由 ChipChain 保有 deterministic facts 的写入责任。
没有忽略 summary/location/artifact/status mismatch，也没有修补模型生成的 EvidenceRef。

## B. Why Previous V3-2B Was Not Accepted

两次 v4-pro 调用是 **pre-baseline rejected pilot runs**：model preference mismatch，且均没有
accepted FirmwareAnalysisReport。pilot A 连接失败，pilot B 收到响应但 exact EvidenceRef grounding 失败。
当时接口要求模型重写完整 EvidenceRef，存在不必要的事实复制负担；R1 修复接口，不将 pilot 结果冒充 flash。
安全诊断没有记录具体不一致字段，不能据此声称已确定 pilot B 改写了哪个字段。

## C. Files Changed

新增 `agents/model_outputs/firmware.py` 及包入口、`tests/unit/test_firmware_model_outputs.py` 和本文。
修改 Firmware Agent、新增的 V3-2B runner、公共 DeepSeek defaults、同一 reviewed exporter、`.env.example`，
以及相关 fake-provider/workflow tests 和 local integration。README/pilot 研究文档同步状态。
未修改 `.env`、domain schema、A1 analyzer/decoder、projection v1、prompt v1、workflow 代码或依赖。
完整累计工作区文件见 Z（其中包括上轮尚未提交的 V3-2B 文件）。

## D. deepseek-flash Default / Config Policy

`DeepSeekConfig.model = deepseek-flash`。Firmware 解析依次为 shell `CHIPCHAIN_FIRMWARE_MODEL`、
显式选择 env-file 中的同名值、deepseek-flash；不读取 Hardware variable 作为回退。
Hardware 显式变量继续有效。未来 Cross-Layer 可沿用公共默认，但本轮不实现 Cross-Layer environment 或 runner。
`.env.example` 两侧示例均为 deepseek-flash；真实 `.env` 原字节不改。

Corrected Firmware runner 还在任何 artifact IO/API 之前强制 `config.model == deepseek-flash`。
显式配置其他模型仍可被通用配置对象表示，但不能误用于本轮 corrected baseline。

## E. Model-Facing Firmware Report Schema

Agent-internal 模块定义五个 Pydantic contracts：ModelFirmwareFinding、ModelExternalInputPath、
ModelReachableBehavior、ModelFirmwareIssueAnchor、ModelFirmwareAnalysisReport。
报告 top-level 字段保持一致，claim 用 `evidence_ids: list[Identifier]` 替换 evidence。
使用 extra=forbid；完整 EvidenceRef field 或放进 evidence_ids 的对象都被 structured parser 拒绝。

## F. Evidence-ID Contract

只允许选择 supplied catalog 中存在的 ID。未知 ID 拒绝，同一 claim 重复 evidence ID 拒绝；
不去重、不找近似 ID、不删除未知引用。ID 顺序保留。transport 可以有空列表，真实运行另要求有 claim 就有 evidence。
模型仍可选择与 prose 不相关但合法的 ID；合法引用不等于推断成立，须人工审核。

## G. Deterministic Evidence Hydration

`hydrate_firmware_report(model_report, inputs)` 调用原 `collect_firmware_evidence`，覆盖 observation、
behavior、decoded instruction 三层；同 ID 不同完整对象仍失败。每个 ID 解析为 registry 中 EvidenceRef 的 deep copy。
Hydration 不改输入、不改 transport report，输出对象互相隔离，重复生成完全一致。
只有测试 helper 将 canonical fixture 编码为 ID-only payload；production 没有修复旧 full-evidence 输出的兼容分支。

## H. Cross-Reference Grounding

四类 collection 内分别检查 finding_id/path_id/reachability_id/anchor_id 唯一性。
Anchor finding refs 必须存在；ReachableBehavior external_input_path_ids 必须存在。
同一检查函数用于 transport hydration、canonical evidence gate 和 reviewed validation。
Behavior references 继续交给原 `_validate_report_ir`，其代码未变，没有第二套 behavior truth registry。

## I. Canonical FirmwareAnalysisReport Preservation

`domain/firmware.py`、`domain/run.py` 和其他 domain files 没有改动。
AgentOutput、AnalysisRun、成功 report 文件和 future reviewed/cross-layer input 仍使用完整 exact EvidenceRef。
原 20 个 canonical evidence mutation 回归保留，直接验证最终 exact gate，而不是把篡改的引用转换为 IDs 后丢失差异。

## J. FirmwareSecurityAgent Flow

有模型时 StructuredReportRuntime 使用 ModelFirmwareAnalysisReport，再 hydrate、exact grounding、原 AgentOutput/IR 校验。
无模型 stub 不走 transport 或 hydration。usage/response metadata 接口不变。
成功 invocation 记录 `model_output_schema=ModelFirmwareAnalysisReport`，以区分旧的 full-evidence transport。

## K. Real-Run Epistemic Policy

四类结构化对象存在时必须有 evidence，禁止 VERIFIED。RUNTIME 必须有 runtime observation supplied evidence；
STATIC 不因缺 CFG 被 schema 禁止。当前 Heat_Press runtime=0。
未新增确定性 crash、物理接口、漏洞或 root cause 事实；自由文本 overclaim 仍需人工审核。

## L. Safe Failure Diagnostics

新增可区分 reason codes：unknown_evidence_id、duplicate_evidence_id、unknown_behavior_id、unknown_finding_id、
unknown_external_input_path_id、duplicate_claim_id、runtime_without_runtime_evidence、verified_model_claim、missing_claim_evidence。
Behavior error 仅识别原 IR validator 的固定内部错误，不重新收集 behavior truth。
失败仍只写 allowlisted category/type/usage/metadata；不写模型 IDs、prose、完整 rejected report、raw response/tool calls/body。
写盘前实际 key 检查、logging/tracing 关闭、max_retries=0、thinking disabled、function_calling/strict=False 均保留。

## M. Offline Tests

覆盖 exact hydration、顺序/deep-copy/输入不变、未知/重复 evidence IDs、完整 EvidenceRef 注入拒绝、
四类 claim ID 唯一性、finding/path refs、原 IR behavior gate、全部 safe reason codes、default/env role 隔离、
non-flash 预检拒绝、stub 不 hydration、canonical persistence、claim counts 和 reviewed cross-reference 拒绝。
旧 20 个 canonical mutation tests 保留，新增 ID-only model schema tests。所有默认 tests 离线；local integration 不调用 provider。

## N. Exact Test Results

真实调用前全部通过：

```text
pytest -q: 514 passed, 7 skipped in 6.18s
python -m pip check: No broken requirements found.
python -m compileall -q src tests: exit 0
git diff --check: exit 0
explicit Heat_Press local integration: 1 passed in 1.21s
```

相对上轮 476 passed 新增 38 个实例。无 dependency change。

## O. Pre-Invocation Baseline

```text
observations = 57 (23 static instruction / 32 MMIO model / 2 environment input)
behaviors = 55
evidence = 57
runtime observations = 0
context characters = 39438
context SHA256 = 48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803
projection = firmware-analysis-projection/v1
prompt = firmware-security-agent v1
resolved requested model = deepseek-flash
```

除统计/长度外，runner 本轮明确 pin 上述 SHA256；同长度但 hash 不同也拒绝 API。
Local test 用相同长度的 target identity 变化验证此拒绝路径。四个实际 artifact 的 frozen fingerprint 不变。

## P. Previous Rejected Pilot Runs

- Pilot A：`98b38d95-0b81-4330-aff8-7429157b7ab2`，deepseek-v4-pro，connection failure。
- Pilot B：`9824162f-023d-45ae-82e2-0fa510cc06bf`，deepseek-v4-pro，evidence_mismatch。

两目录下原始 failure/attempt 文件全部保留，R1 开始时记录字节 SHA256，结束时复核。它们不计为 accepted baseline。

## Q. Corrected deepseek-flash Real Invocation

**一次调用成功，零 retry；完整 Agent run 和 runtime persistence 校验通过。尚未人工接受/冻结。**

```text
run_id = b47c9cc6-b958-4c6a-a40b-eb436e431f26
requested model = deepseek-flash
returned model_name = deepseek-flash
input / output / total tokens = 12547 / 3619 / 16166
findings / external_input_paths / reachable_behaviors / issue_anchors = 8 / 4 / 6 / 3
stub_ir_equal = true
```

执行命令：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 CHIPCHAIN_FIRMWARE_MODEL=deepseek-flash \
  .venv/bin/python -m chipchain.integrations.deepseek_firmware \
  --corpus-root /home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
  --env-file .env --attempt-index 1
```

成功后重新读取持久化 AnalysisRun/report，调用 canonical grounding/real-run gate，并与重新生成的 deterministic
stub IR 比较相等；analysis_input.json == firmware_context(inputs) + 单个 LF。
Stages 为 hardware=not_applicable、firmware=completed、ir_aggregation=completed、cross_layer=not_applicable。
没有 hardware/cross_layer report。收到输出后未修改 prompt、执行代码或进行第二次调用。

## R. Full Validated firmware_analysis_report.json

完整 canonical JSON（74,105 bytes，未删字段或截断）：
[firmware_analysis_report.json](../../output/fuzzware:heat-press:scenario-13/b47c9cc6-b958-4c6a-a40b-eb436e431f26/firmware_analysis_report.json)。
报告已通过机器校验，**不表示已获人工接受**。其中包含 hydration 后的完整 exact EvidenceRefs。
本文链接原 runtime 文件，不将真实报告副本放入 synthetic fixtures 或 reviewed 目录。

## S. Full Safe invocation.json

```json
{
  "case_id": "fuzzware:heat-press:scenario-13",
  "run_id": "b47c9cc6-b958-4c6a-a40b-eb436e431f26",
  "attempt_index": 1,
  "provider": "deepseek",
  "model": "deepseek-flash",
  "prompt_id": "firmware-security-agent",
  "prompt_version": "v1",
  "context_sha256": "48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803",
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
    "input_tokens": 12547,
    "output_tokens": 3619,
    "total_tokens": 16166
  },
  "response_metadata": {
    "id": "f8d8900b-ca3a-4ceb-a674-3ea708421440",
    "model_name": "deepseek-flash"
  },
  "context_characters": 39438,
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
    "findings": 8,
    "external_input_paths": 4,
    "reachable_behaviors": 6,
    "issue_anchors": 3
  },
  "model_output_schema": "ModelFirmwareAnalysisReport"
}
```

## T. Claim Audit

| 项目 | 审核结果 |
| --- | --- |
| execution | 没有宣称具备执行 trace；多处明确 execution 未建立。但下列 boot-time writes 和 can-drive 表述过强 |
| runtime reachability | 6 个 ReachableBehavior 全为 unknown/hypothesized；0 RUNTIME、0 STATIC |
| crash / vulnerability / root cause | 没有声称 crash 已发生或确认漏洞/根因；明确缺少 failure outcome 和 faulting PC |
| physical interface | 根据已有函数符号推断 UART/ADC 路径；不是实测物理接口或 opaque input 消费链 |
| evidence grounding | 四类共 21 个对象均有 exact supplied evidence，未伪造或改写 EvidenceRef |
| behavior grounding | 仅引用 supplied IR IDs；claim/finding/path cross refs 和各 collection ID 唯一性通过 |
| MMIO configuration vs runtime | 多处明确是 configured models，不证明执行；不能因此忽略具体语义错误 |
| input existence vs consumption | 明确 opaque artifact 存在不证明消费、执行或 failure outcome |

**必须在人工审核中标出的具体问题：**

1. `f-systeminit-mmio` 将所列 sites 描述为 **boot-time configuration writes**。
   实际这些 site 的 mnemonic 全为 `ldr`，对应 MMIO behaviors 全是 `direction=read`。
   这是与当前 deterministic input 直接矛盾的读写方向表述；不能把此 finding 当成正确描述。
2. `ep-uart-write` 自称 outbound、not an inbound data source，却被放入 ExternalInputPath。
   引用存在并不能使它成为外部输入路径，分类需要人工纠正/后续规则审查。
3. `ep-interrupt-trigger` 以 observed status 描述配置，并说它 can drive interrupt-driven code paths，例如 UART IRQ。
   配置证据只证明 trigger 参数，未证明实际 IRQ routing 或 handler 执行；这种能力关联不是 observed fact。
   同一报告的 unresolved question 又承认 trigger 是否到达 handler 未建立，应保留这种不一致作为 baseline 结果。
4. `f-uart-irq-mmio` 中 only sites / externally-facing path 的排他性判断缺乏完整 CFG/调用关系/板级接口证据。
   UART/ADC 函数符号确实在输入中，但从符号及 MMIO 配置到外部输入路径仍是未验证推断。

有用结果是按 UART IRQ/write、ADC、SystemInit、PMC、PIO/pinMode 和 unmodeled MMIO 整理了审查线索，
并明确多项缺失证据。**8 findings 不是 8 个漏洞。** exact hydration 解决引用事实复制问题，不验证模型 prose 的蕴含关系。

模型明确指出缺少：runtime trace、opaque input 的 MMIO consumption/runtime state/failure outcome、
UART handler 的实际执行及外部数据消费、周期性 trigger 是否到达该 handler/其他 site、
unmodeled m21–m31 的语义、opaque input 到 ADC 的关联、crash/failure outcome 和 faulting PC。

## U. Output Paths / SHA256

目录：`/home/qcx/ChipChainV3/output/fuzzware:heat-press:scenario-13/b47c9cc6-b958-4c6a-a40b-eb436e431f26/`。

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `analysis_input.json` | 39439 | `f8701d30d4fd7a9afeeb70bea9acfa144dc845488f49b8e5b1285fef1180266e` |
| `analysis_run.json` | 200131 | `001ac278630d7e8d9308d8e5639c7abca6404ff37f6eaa39d10bb62afa9cb4be` |
| `firmware_analysis_report.json` | 74105 | `bf695eb18c27577e9af84704e2d9e133fb4ecd188c42677b57f3d2b3ed02f7e8` |
| `invocation.json` | 1392 | `cec94e4437dd0ae64e9e12f41802fb3cf9e9e04a6d93ed7a66af2497f503422c` |
| `invocation_attempts.jsonl` | 959 | `dac76236224941317ef14b6bfa1d91de3be7d36b2678bbc3fab3b427dbf7aa55` |

analysis_input 文件为 39,439 bytes，因为 writer 附加一个 LF；真实模型 text 为 39,438 chars/bytes。
context SHA256 是 O 中的 `48bd...`；文件 SHA256 是上表 `f870...`，两者区别已验证，没有任意 strip。

## V. Historical Hardware Regression

Hardware Agent、prompt、projection、已持久化历史结果未改；公共默认模型按 R1 要求改为 deepseek-flash，
显式 Hardware override 仍有效。原 Hardware tests 通过，12 个 frozen reviewed 文件逐字节不变。
两个旧 v4-pro pilot 的 4 个 diagnostic 文件与 R1 开始时 hash 相同；真实 `.env` 也逐字节不变。

## W. Reviewed Export Status

Exporter 继续支持 canonical Firmware report，并补充 path/claim uniqueness 与 invocation claim counts 校验。
仅执行 synthetic exporter tests，没有对真实 corrected run 或 pilots 执行 export，没有 human_accepted 标记。
真实五文件仍 Git ignored；完整 baseline 等用户审核后决定是否冻结。

## X. Known Limitations

- 单个样本、一次 corrected response，不足以评估模型可靠性或修复接口后的成功率。
- Hydration 保证 EvidenceRef 完整精确，不保证所选证据与 claim 相关，更不验证自然语言。
- 上述读写方向错误、输入路径分类和 IRQ/物理接口关联 overclaim 是真实 baseline 的缺陷，原报告未改写。
- 没有 runtime、coverage、input consumption 或 crash evidence；没有漏洞确认。
- 没有修改 prompt/projection、新增 target/dependency，未运行 Ghidra/angr/emulation/fuzzing 或真实 Cross-Layer。

## Y. Recommended Next Deterministic Capability

优先增加从 ELF 产生可引用的 basic blocks、CFG/call graph、MMIO site 与函数/调用者的联系。
对 IRQ 推断还需要 vector table/handler mapping，不能以 round_robin 配置替代。
结合既有 decoder 的 direction facts可帮助审查 read/write 描述；运行/输入消费结论另外需要独立 trace。
本轮仅记录这些方向，没有实施或新增调用。

## Z. Git Status

```text
 M .env.example
 M README.md
 M src/chipchain/agents/firmware.py
 M src/chipchain/execution/reviewed_output.py
 M src/chipchain/integrations/deepseek.py
 M src/chipchain/integrations/deepseek_hardware.py
 M tests/firmware_fakes.py
 M tests/integration/test_case_lifecycle.py
 M tests/integration/test_fuzzware_local.py
 M tests/integration/test_langchain_workflows.py
 M tests/unit/test_deepseek_integration.py
 M tests/unit/test_firmware_grounding.py
 M tests/unit/test_langchain_agents.py
?? docs/research/v3-2b-deepseek-firmware-agent.md
?? docs/research/v3-2b-r1-evidence-binding.md
?? src/chipchain/agents/model_outputs/__init__.py
?? src/chipchain/agents/model_outputs/firmware.py
?? src/chipchain/integrations/deepseek_firmware.py
?? tests/unit/test_deepseek_firmware.py
?? tests/unit/test_firmware_model_outputs.py
```

结束检查：`.env`、两个旧 pilot 的 4 个文件、12 个 Hardware reviewed 文件与开始时逐字节相同。
新 run 五个文件均被 Git 忽略；全量 key 比较与 raw-field 检查通过；新文件空白检查和 `git diff --check` 通过。
Domain、tools/analyzers/decoders、prompts、projection、agent contracts、Hardware Agent、workflows、依赖声明与 HEAD 无差异。
未 git add/commit/push/tag，未对任何真实 run reviewed-export。

## Final 23 Answers

1. **Default now deepseek-flash？** 是。
2. **Firmware 会意外 fallback 到 v4-pro？** 不会。通用 config 可显式 override，但 corrected runner 在 API 前拒绝非 flash。
3. **LLM 仍生成完整 EvidenceRef？** 不再接受；模型输出 schema 不含该对象。
4. **Evidence 输出什么？** 每个 claim 的 `evidence_ids: list[str]`。
5. **谁转为 exact EvidenceRef？** ChipChain deterministic `hydrate_firmware_report`，从 supplied registry deep-copy。
6. **未知 ID 可通过？** 不能。
7. **模型能改 location/summary/artifact/status？** 不能通过 EvidenceRef 接口改；canonical 对象全部取自输入。模型 prose 仍可出错。
8. **Canonical report/AnalysisRun schemas 不变？** 是。
9. **external_input_path_ids grounded？** 是，未知 ID 拒绝。
10. **claim IDs unique？** 是，各 collection 分别唯一。
11. **Prompt v1 unchanged？** 是。
12. **Projection v1 unchanged？** 是。
13. **Context SHA256 与原值完全一致？** 是，`48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803`。
14. **Corrected call 请求 flash？** 是，显式 `deepseek-flash`。
15. **Provider model_name？** `deepseek-flash`。
16. **完整 Agent run 成功？** 是，一次调用，所有机器校验及持久化完成；尚未人工接受。
17. **零 runtime 下声称 RUNTIME reachability？** 没有，6 项均为 unknown/hypothesized。
18. **Crash 或 confirmed vulnerability？** 没有。仍有 SystemInit writes 错误及物理/IRQ path 过强推断，不能把 findings 当成漏洞。
19. **Canonical report 已保存？** 是，同时保存 AnalysisRun，EvidenceRefs 完整精确。
20. **Raw provider output 已保存？** 没有，仅保存 validated canonical result 和 safe metadata。
21. **Reviewed export 执行？** 未对真实 run 执行；只有 synthetic exporter tests。
22. **历史 Hardware behavior/output 改变？** Agent/prompt/projection 和历史结果未改；公共默认按要求统一 flash，显式 override 保留。
23. **下一项 deterministic enrichment？** CFG/call graph、MMIO site/函数联系及 IRQ vector/handler mapping；runtime/消费结论另需 trace。

本轮结束；不修改 prompt，不为润色答案重跑，不自行冻结或导出 reviewed snapshot。
