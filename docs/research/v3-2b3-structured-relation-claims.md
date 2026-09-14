# V3-2B3 — Structured Relation Claims & Support-Gated Firmware Reasoning

基线 `v3-2a4-stable` / `4876d81057518a1f0280dbd8edb96a7d4b4f2d8c`。
本阶段改变 context representation、model-facing schema 与 prompt version，
因此与 B2 的比较是 engineering / semantic-safety comparison，**不是 same-prompt 单变量实验**。

## 架构与冻结边界

显式流水线：四 artifacts → A1 → fresh Ghidra A2 → A3 → A4 → relation projection v1
→ envelope v3 → deepseek-flash → model report v2 → support/evidence/IR/epistemic gates
→ canonical FirmwareAnalysisReport + 独立 FirmwareRelationSupportReport。

A1 projection v1、A3 projection v1、B2 envelope v2、A4 catalog v1、A4 builder/checker 和
Firmware prompt v1 保持原样。没有修改 domain FirmwareAnalysisReport、AnalysisRun、ProcessorBehaviorIR。
没有 angr、CFGFast、symbolic execution、runtime replay 或 Cross-Layer。

`FirmwareSecurityAgent.invoke(inputs)` 和显式 A3/A2 参数的 `invoke(...)` 分别保留 v1/v2。
新增 `invoke_supported(inputs, static_relation_catalog=..., relation_projection=...,
relevant_static_structure=...)`，返回 `(FirmwareAgentOutput, FirmwareRelationSupportReport)`。
Agent 不读 ELF、不运行 Ghidra/A3/A4 builder；runner 执行这些确定性准备。

## Relation projection v1

`firmware-relation-projection/v1` 使用冻结 A3 的 named-column table helper。
每种 kind 独立表，common fields 和 dictionary indices 消除重复。
不做 first-N/top-k，不丢弃 unresolved、MMIO 或 vectors。

完整保留 **131** 条关系：22 direct_call、6 direct_branch、6 unresolved、
23 containment、23 direction、51 vector_dispatch。
模型可恢复 ID、typed kind/status、source/target 类型与 ID、site、全部 typed attributes。
不仅保留关键语义，parse 后还重建完整 A4 catalog 并校验其原 SHA256。

压缩规则均显式记录在 model-visible `relation_semantics`：

- capabilities 由冻结 A4 kind/status 决定，全局语义表声明支持范围；不重复发送每条十余个 bool。
- 公共 limitations 提取到 catalog 一处，其余逐关系保存。
- function 地址来自 function_endpoints；站点型 source 地址等于 site_address。
- 若 evidence IDs 恰为 `[relation_id]`，通过 group policy 精确恢复；MMIO 的两类关系共享按 PC 索引的证据列表。
- source ID 若等于 relation ID 或 `mmio-<PC hex>`，用具名 policy 表示；否则显式携带。
- A3 的相关函数名只是 display labels；entry_address 由同一 function identity table 恢复。
- A1 已携带的 57 个 EvidenceRefs 不重复发送；delta 仅为 117 个 A3-only references。
- delta 使用 profile/entry 表；仅当每个 evidence location.address 等于其唯一引用 relation site 时，才复用该地址。

构建时校验 A1 57、A3 172、overlap 55、union 174；同 ID 不同对象拒绝。
解析时必须提供冻结 A1 base，重建 exact union 并校验全部关系 evidence IDs。
不把 A4 的 129547-char 完整 JSON 发送给模型，也不额外发送完整 A3。
函数名称与其他可见值通过现有 neutrality 检查。

projection hard budget 为 17000 chars；envelope v3 hard budget 为 58000，同时检查全局 64000。
超预算失败，不截断、不调用 API。A1 base 原始 canonical 字符串保持 39438 chars。

## Structured output 与 support gate

新增 model-only `ModelFirmwareAnalysisReportV2`：四类 report item 均要求非空
`support_claim_ids`，同时保留原有 `evidence_ids`。canonical domain report 不含 support 字段。

Support union：

1. `relation_fact`：support ID、relation ID、expected kind/status/source/target；
   控制转移必须精确给出 expected_transfer_kind，MMIO direction 给出 expected_direction，
   vector 给出 expected_vector_index/expected_binding_status；不适用的字段为 null。
2. `static_call_path`：source/target function IDs 和非空、显式有序 edge_relation_ids。
3. `runtime_reachability` / `physical_input_path` / `trigger_to_handler`：显式声明所引用关系，
   当前静态支持 checker 返回 unsupported。

首先检查 support identity、引用和 exact typed fact；已确认的直接关系及路径复用冻结 A4 checker。
正确描述 unresolved 或 missing 本身可 supported，这不提升其为 confirmed call/containment。
重复、未知、未使用 support claims 拒绝；support 可被多个 Firmware items 共享。
任何被引用 support 是 unsupported 或 incompatible，整个输出在 `relation_support_validation` 拒绝。
不寻找替代路径，不自动修补模型输出，不把错误引用转换成另一个正确关系。

随后执行原 evidence hydration、finding/path references、IR 和真实运行 epistemic gate。
模型不允许靠断言生成 verified 事实，也不能凭静态证据获得 runtime reachability。

**Gate 只检查 structured support，不证明自由文本与 support 完全相符。**
不使用 regex、关键词、NLP 或另一个 LLM 审读 summary；synthetic test 明确保留这一限制。
例如合法的 static-call support 仍可能被自由文本夸大，必须另做语义审计。

## Prompt v2 与 provider

独立新增 `agents/prompts/firmware_v2.py`，descriptor 为 `firmware-security-agent / v2`。
v1 文本与 descriptor 不变。v2 使用通用规则，不提历史 run 或特定错误站点：
关系类型/状态/端点权威；branch != call；static != runtime；vector binding != handler execution；
函数名不证明物理接口；每个非空 Firmware claim 引用 supported structured support；不得编造 ID。

真实模型固定 deepseek-flash：temperature=0、thinking=disabled、max_tokens=8192、
max_retries=0、function_calling、strict=false、timeout=180 秒。
先完整离线测试，再 fresh preflight，再一次真实调用。响应通过任一 gate 失败便停止，不调 prompt、不改 projection、不放宽 checker、不重跑。
纯 transport failure 也不自动重试；额外一次重试需要人工决定。

## Persistence 与 reviewed compatibility

成功运行在新的 UUID 目录显式保存六个文件：

```text
analysis_run.json
firmware_analysis_report.json
firmware_relation_support.json
analysis_input.json
invocation.json
invocation_attempts.jsonl
```

analysis_input 是真正发送的 envelope v3，writer 追加单个 LF，context hash 排除这个 LF。
support artifact 只存 typed support、result/reason code、relation IDs、引用它的 Firmware claim IDs；
不复制 provider raw message/tool calls 或任意模型 prose。
失败只保存安全 failure.json 与 invocation_attempts.jsonl，不保存 rejected report。

既有 exporter 支持 Hardware historical、Firmware v1/v2/v3。
v3 重新解析投影、恢复 A4 并核对 hash、验证 A1/ELF/IR/evidence/provenance、重跑 support checks；
真实 Heat_Press 还检查冻结 A4 baseline。统计与 artifact 引用必须一致。
测试仅对 synthetic temporary runs 执行 exporter；本阶段不执行真实 reviewed export。

## 复现命令

离线：

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
```

fresh preflight（不读 key、不调用 API）：

```bash
.venv/bin/python -m chipchain.integrations.deepseek_firmware \
  --context-mode relation_v3 --preflight-only \
  --corpus-root /home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
  --ghidra-home /home/qcx/fuzz/gdbfuzz/dependencies/ghidra
```

真实关系 + fake-model 回归仍无网络：

```bash
CHIPCHAIN_FUZZWARE_ROOT=/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
CHIPCHAIN_GHIDRA_HOME=/home/qcx/fuzz/gdbfuzz/dependencies/ghidra \
.venv/bin/python -m pytest -q -s tests/integration/test_firmware_relations_local.py
```

实际一次调用只在前置验证通过后执行：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 .venv/bin/python -m chipchain.integrations.deepseek_firmware \
  --context-mode relation_v3 --env-file .env \
  --corpus-root /home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
  --ghidra-home /home/qcx/fuzz/gdbfuzz/dependencies/ghidra
```

## 本轮验证与真实运行记录

API 前验证结果：

```text
pytest -q: 719 passed, 12 skipped in 15.75s
pip check: No broken requirements found.
compileall: exit 0
git diff --check: exit 0
Fresh deterministic preflight + real-relation fake-model regression:
1 passed in 16.13s
```

真实关系 fake-model 回归：6 类正确陈述通过、14 项错误陈述被拒绝，包括
computed→confirmed、UART branch→call、vector→call、八个 SystemInit read→write。
默认离线 suite 新增 53 项 B3 测试；旧路径和 frozen A4 的测试继续通过。

| Component | Characters | SHA256 |
|---|---:|---|
| A1 v1 | 39438 | `48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803` |
| A3 v1 | 16631 | `4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304` |
| B2 envelope v2 | 56408 | `6afef3295f8c54ee7fef65446db0a91169ee833d3ede4314e38e45ca0d7c5016` |
| A4 v1 | 129547 | `fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902` |
| Relation projection v1 | **16824** | `f65dd1b99fc621fb6ccda0e45d7254a233351185258d820d8736949c74c635b2` |
| Envelope v3 | **56523** | `b7722ef471a05bd7e83e2042ae2ac7a4ed125b01a5aeb624581ea1994994adab` |

投影比 17000 上限少 176 字符，envelope 比 58000 少 1477 字符；没有达到可选的 15000 目标，
保留完整关系和明确 codec 规则优先。没有删除任何关系来满足预算。

API 前已核对 55 个既有 output 文件全部 byte-identical，包括 R1、B2、pilots、A2/A3/A4 历史结果和 reviewed snapshots。
首次真实响应后的源码保持冻结；下文仅记录实际结果与审计。

## 唯一一次真实调用：schema gate 未通过

Run ID：`a8b049f2-16f4-465c-8d93-8fc618540f0d`。
模型 `deepseek-flash`，prompt v2，context hash 与 preflight 一致。
开始于 2026-09-14 09:36:23.415722 UTC，安全失败记录于 09:36:43.869082 UTC。

真实 provider call **1 次**，retry **0 次**。Provider 返回内容和 usage，
随后在 `structured_output_parsing` 阶段失败，reason=`schema_or_tool_response`。
没有进入 deterministic relation-support validation，也没有 canonical accepted report。

Token usage：input **20488**，output **8192**，total **28680**。
output 恰好等于 max_tokens，上限导致截断是一种合理怀疑，**不是已确认原因**：
安全 diagnostics 仅保存异常类型 AgentStructuredOutputError → ValueError，
未保存 finish_reason、invalid tool-call body 或原始响应，无法进一步确认。

按本阶段策略立即停止。未重试、未修改 prompt v2、relation projection 或 support checker，
也没有提高 max_tokens 或切换模型。

仅保留：

- [failure.json](../../output/fuzzware:heat-press:scenario-13/a8b049f2-16f4-465c-8d93-8fc618540f0d/failure.json)
- [invocation_attempts.jsonl](../../output/fuzzware:heat-press:scenario-13/a8b049f2-16f4-465c-8d93-8fc618540f0d/invocation_attempts.jsonl)

未生成成功的 analysis_run.json、firmware_analysis_report.json、firmware_relation_support.json、
analysis_input.json 或 invocation.json。发送的 context version/count/hash 已由 fresh preflight 和 attempt record 标识；
不为失败调用伪造成功 invocation artifact。

### 完整安全 failure.json（本次不存在成功 invocation.json）

```json
{
  "case_id": "fuzzware:heat-press:scenario-13",
  "run_id": "a8b049f2-16f4-465c-8d93-8fc618540f0d",
  "attempt_index": 1,
  "timestamp": "2026-09-14T09:36:43.869082+00:00",
  "provider": "deepseek",
  "model": "deepseek-flash",
  "prompt_id": "firmware-security-agent",
  "prompt_version": "v2",
  "context_sha256": "b7722ef471a05bd7e83e2042ae2ac7a4ed125b01a5aeb624581ea1994994adab",
  "status": "failed",
  "category": "structured_output_parsing",
  "failure_category": "structured_output_parsing",
  "reason_code": "schema_or_tool_response",
  "exception_type": "AgentStructuredOutputError",
  "usage": {
    "input_tokens": 20488,
    "output_tokens": 8192,
    "total_tokens": 28680
  },
  "response_metadata": {
    "id": "c9f41643-9762-41d8-b811-ed0b3e3c106c",
    "model_name": "deepseek-flash"
  },
  "diagnostics": [
    {
      "exception_type": "AgentStructuredOutputError"
    },
    {
      "exception_type": "ValueError"
    }
  ]
}
```

### Firmware claim index / structured support index

没有已接受的 Firmware claims，亦无通过 schema 的 support claim index。
模型实际尝试生成多少 findings/paths/reachable behaviors/anchors/support claims **无法确定**；
不能把“接受数量为 0”写成“模型生成数量为 0”。
也无法确定返回内容包含多少 unsupported/incompatible support claims，因为 gate 尚未执行。

### B2 regression audit

| 项目 | Deterministic / fake-model 结果 | 本次真实响应语义审计 |
|---|---|---|
| call-80f88 | 正确 unresolved fact 可通过；错误 Reset→SystemInit confirmed call 被拒绝 | 无可验证报告，无法判定是否复现 |
| call-80afa | init→SystemInit confirmed call 支持 | 无法评估模型是否使用 |
| UART b.w family | branch 保留；call 声明被拒绝 | 无法评估 |
| SystemInit 八 reads | A1 read/ldr 保留；八项 write 声明拒绝 | 无法评估 |
| vector-1 | Reset dispatch 支持；Reset→SystemInit call 拒绝 | 无法评估 |
| trigger→handler | unsupported；引用即拒绝（offline fake test） | 无法评估 |
| Physical/runtime claims | 静态关系不足，引用即拒绝（offline fake tests） | 无法评估 |

### 语义审计状态与下一步建议

本轮 **machine-rejected at schema gate / no accepted report / not reviewed-exported**。
没有可开展逐条自由文本语义审计的成功报告；不宣称 B2 的错误在真实模型中已经消失，
也不把 fake-model regression 成功等同于真实语义改善。实际改进已证实的范围是可复现的
context 编解码、typed support gates 和失败时拒绝接受结果。

建议下一阶段先做独立的 **B3 output-budget / structured-output patch**，由人工审核后决定。
优先调查固定 8192-token 预算下输出规模与工具响应完整性；未来可设计更简洁的报告要求，
以及只记录 finish_reason/解析错误类别的安全诊断，但本轮不实现、不回调模型验证。
在真实输出尚未稳定通过 schema/support gates 前增加 A5/angr，会同时增加上下文和归因复杂度。

即使后续支持校验成功，仍需人工检查自由文本是否超出所引事实、混淆 static/runtime 或
把 symbol 当物理接口。本轮不是与 B2 的 controlled single-variable experiment。

未进入 A5/angr 或 Cross-Layer；未执行真实 reviewed export，未执行 Git add/commit/push/tag。
