# V3-2B — Real DeepSeek Firmware Security Agent Integration

基线：`v3-2a1-1-stable` / `e7262ce19d58b1d570946dd3c9f15f7e3c050c6e`。

**R1 注记：本文中的两次 v4-pro 调用均为 pre-baseline rejected pilot runs。**
它们存在 model preference mismatch，且没有 accepted FirmwareAnalysisReport；不能视为正式 Firmware baseline。
下文保留 pilot 当时的配置/诊断记录（包括旧的 v4-pro fallback），不代表当前默认策略。
R1 已将默认模型统一为 `deepseek-flash`，并引入 evidence-ID transport + deterministic hydration；
corrected baseline 单独记录在 [R1 报告](v3-2b-r1-evidence-binding.md)。两个旧 runtime 目录保持原始字节。

**集成代码及离线验证完成，但尚未得到合格的真实 FirmwareAnalysisReport。**
第一次尝试发生连接失败；按本轮授权显式执行一次新的 attempt 2，provider 返回了结构化响应，
但 A1.1 exact EvidenceRef grounding gate 拒绝了它。未修改 prompt、未放宽 gate、未第三次调用。
没有将失败结果包装成研究发现或 accepted snapshot。

## A. Implementation Summary

```text
4 explicit frozen artifacts
→ unchanged Fuzzware ingestion / ARM decoder
→ 57 observations / 55 behaviors / 57 evidence / 0 runtime
→ unchanged firmware-analysis-projection/v1 (39438 chars)
→ ChatDeepSeek / function_calling / firmware-security-agent v1
→ exact evidence + finding grounding
→ existing Agent output / IR grounding
→ real-run epistemic policy
→ validated AnalysisRun + allowlisted persistence (only on success)
```

第二次真实尝试停在 exact evidence grounding，后续成功路径仅由离线 fake-provider tests 验证。

## B. Files Changed

- `.env.example`：新增空 `CHIPCHAIN_FIRMWARE_MODEL`，无真实密钥。
- `src/chipchain/integrations/deepseek.py`：显式 descriptor role、独立模型环境变量。
- `src/chipchain/integrations/deepseek_hardware.py`：显式 HARDWARE role，其他行为保留。
- `src/chipchain/agents/firmware.py`：structured-output method、usage 和 response metadata 接口。
- `src/chipchain/integrations/deepseek_firmware.py`：新增单样本 opt-in runner、baseline gate、real-run policy、provenance/persistence。
- `src/chipchain/execution/reviewed_output.py`：同一 exporter 支持 Firmware，保留历史 Hardware 格式。
- `tests/unit/test_deepseek_firmware.py`：45 个新增 offline 测试实例。
- `tests/unit/test_deepseek_integration.py`：既有 descriptor 测试改为显式 Hardware role。
- `tests/integration/test_fuzzware_local.py`：增加真实 runner input 与冻结输入一致性检查。
- `README.md`、本文：阶段状态、调用方式和真实失败结果。

未修改 domain/contracts、A1 analyzer/YAML/ELF/BIN/ARM decoder、projection v1、prompt、workflow 或依赖。

## C. DeepSeek Config Generalization

`DeepSeekConfig.descriptor(agent_role)` 必须显式指定角色。
`load_deepseek_config(..., agent_role=...)` 依角色选择 `CHIPCHAIN_HARDWARE_MODEL` 或
`CHIPCHAIN_FIRMWARE_MODEL`。旧调用默认 HARDWARE 以保持兼容，两个 runner 自身都显式传 role。
Firmware 不回退到 Hardware 环境变量。未配置 Firmware 时保留既有默认 `deepseek-v4-pro`。

本地显式选择的 `.env` 有 key，但没有 Firmware model；Hardware 配置为 `deepseek-flash`。
本轮先询问模型偏好，在继续独立实现/测试期间未收到答复，再明确告知按用户允许的默认策略执行。
实际两次命令均显式指定 `CHIPCHAIN_FIRMWARE_MODEL=deepseek-v4-pro`；没有修改 `.env`，没有自动切换模型。
不推测 provider 后端 revision。

文件只在显式入口读取、禁用 interpolation、shell 优先，不修改进程环境；文件不能授予 real opt-in。

## D. Hardware Compatibility

Hardware runner 仍读取自己的模型配置，只将 `descriptor()` 改成 `descriptor(AgentRole.HARDWARE)`。
既有 Hardware 测试保持通过；没有调用 Hardware Agent 的真实 provider，也没有写 Hardware output。

## E. FirmwareSecurityAgent Runtime Support

增加 optional `structured_output_method`、`last_usage`、`last_response_metadata`，行为与 Hardware 对齐。
使用既有 `StructuredReportRuntime` 和 `with_structured_output`；返回 metadata 仅允许
`id/request_id/model/model_name`。没有新 HTTP client、JSON repair 或 retry framework。

## F. Real Firmware Runner

显式入口：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 CHIPCHAIN_FIRMWARE_MODEL=deepseek-v4-pro \
  .venv/bin/python -m chipchain.integrations.deepseek_firmware \
  --corpus-root /home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
  --env-file .env --attempt-index 1
```

以上记录实际第一次命令，不表示授权继续重跑。本轮已用完两次尝试；grounding failure 后停止。

`prepare_firmware_input()` 只读四个明确路径，并核对冻结 SHA256/size，再构造中性
`elf/bin/yaml/opaque` IDs、原 target 和 case ID，调用原 analyzer；不读 corpus README，不复制 binary。
`run_real_firmware()` 每次调用只 invoke 一次，`--attempt-index` 只记人工尝试序号、不触发循环。

## G. Pre-Invocation Baseline

调用之前同时验证：

| 项目 | 结果 |
| --- | ---: |
| observations | 57 |
| static instruction / MMIO model / environment input | 23 / 32 / 2 |
| behaviors | 55 |
| evidence | 57 |
| static / configuration / artifact scopes | 23 / 33 / 1 |
| runtime observations | 0 |
| context characters | 39,438 |

本阶段 runner 既检查 <=40k，也严格要求冻结长度 39,438；任何变化均拒绝 API 调用。
工具版本仍为 Capstone 5.0.9 / pyelftools 0.33 / PyYAML 6.0.3。

## H. Projection / Context Identity

`firmware-analysis-projection/v1` 原文件没有改动。真实 local integration 比较 runner input 与
A1.1 canonical input 完全相等，验证 `firmware_projection_sha256(projection)` 与
`sha256(firmware_context(inputs).encode('utf-8'))` 相等。

```text
context_sha256 = 48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803
context_characters = 39438
```

两个 attempt 使用相同模型、prompt、四文件 fingerprint 和 context hash。
投影不含本地路径、crash-analysis、crashing_input 或 benchmark oracle；固定版本字符串的 `/v1`
不属于文件路径。路径未进入模型消息。SystemMessage 仍为未经修改的 Firmware prompt v1。

## I. Real-Run Epistemic Policy

真实报告的 FirmwareFinding / ExternalInputPath / ReachableBehavior / FirmwareIssueAnchor：
若对象存在则 evidence 非空，epistemic_status 不能为 VERIFIED。空报告合法，STATIC 推断不一刀切禁止。
这些规则是 integration policy，没有修改通用 schema 或通用 Firmware Agent 的历史行为。

## J. Runtime Reachability Gate

`firmware_evidence_scopes(inputs)` 把三层 supplied evidence ID 映射到提供它的 observation scopes；
same-ID conflict 先由共用 registry 拒绝。RUNTIME reachability 必须至少引用一个 runtime scope 的 evidence。
Generic observations 无 scope 时为 UNKNOWN，不能因为 evidence summary 含 runtime 字样就升级。

当前 typed A1 details 没有 runtime producer，所以真实 Heat_Press 不会通过 RUNTIME claim。
正向测试使用带明确 scope 的 synthetic generic observation 扩展验证 registry/policy；没有修改 A1 contracts、
没有声称当前投影已支持真实 runtime ingestion。STATIC 与自由文本推断仍需人工审核，gate 不是语义蕴含证明器。

## K. Provenance

成功路径记录 Firmware prompt v1、显式 Firmware real model descriptor，以及三个 ToolDescriptor：
Fuzzware ingestion、Capstone ARM decoder、firmware-analysis-projection/v1。
projection descriptor 放在 integration 中，以避免修改冻结投影内容。记录已安装 runtime package versions，
不 dump config/model 对象。保留 `capture_provenance` 对未配置角色的 unknown placeholders。

本轮没有成功 AnalysisRun，所以真实 provenance 仅有安全 attempt identity/diagnostics；完整成功路径由 fake tests 验证。

## L. Persistence

API 前 `mkdir(exist_ok=False)` 预留 `output/<case_id>/<run_id>/`。成功路径应恰好产生：
analysis_run.json、firmware_analysis_report.json、analysis_input.json、invocation.json、invocation_attempts.jsonl。
`analysis_input.json` 为真正发送的 compact JSON，只附加一个 LF。

所有文档在写盘前重新校验 report/IR、projection、evidence/finding、provenance、hash/counts 和安全字段；
借用 exporter 的纯校验函数，不执行 export 或 human acceptance。已有结果不覆盖。
中途文件写入失败时清理本次新建的结果文件，保留尝试诊断。

**两次真实 run 都失败，因此当前各目录仅含 failure.json 和 invocation_attempts.jsonl。**
没有 analysis_run.json、firmware_analysis_report.json、analysis_input.json 或 invocation.json。

## M. Failure Diagnostics

第一次连接失败，安全链为 AgentExecutionError → OpenAIConnectionError → APIConnectionError → ConnectError。
之后只检查 provider DNS/TCP 连通性（成功，未调用模型），再单独执行新的 attempt 2。

第二次 provider 返回 parsed structured response，但 exact evidence gate 报 `evidence_mismatch`。
诊断没有保存被拒绝的 EvidenceRef，因而不能区分 invented ID 与同 ID 字段被改写，更不能审核完整 prose。
没有为了诊断重新请求、修复 JSON、换模型或放宽验证。

## N. Secret / Raw Response Protection

成功文件和 failure/attempt 文本写盘前比较实际 API key；匹配则拒绝，错误不输出 key。
成功文档还经过 field/content safety checks。禁止 raw provider body/message/tool_calls/headers 持久化。
真实入口关闭 logging、tracing；模型 max_retries=0、streaming=False、thinking disabled、function_calling、strict=False。
未开启 debug/verbose；显式配置工厂会拒绝已开启的 LangChain debug/verbose。

## O. Firmware Reviewed Export Support

同一个 `export_reviewed_output` 从 validated AnalysisRun 判断单侧类型；Firmware 使用自己的 report 文件。
它重新校验 FirmwareAnalysisProjection、report 与 embedded report equality、projection/IR behavior IDs、
exact evidence、finding refs、角色 provenance、stage statuses、context SHA256 与字符数。
兼容 exact file bytes 或仅排除一个末尾 LF；不任意 strip 空白。

Exporter 也重做 real-run evidence/epistemic policy。需要 explicit `accepted=True`；本轮只在 pytest 临时目录中
导出 synthetic fixture，**未对真实 run 执行 reviewed export**。

## P. Hardware Reviewed Export Regression

历史 Hardware invocation 不需要新增 agent_role、scope counts 或 projection_version 字段。
原 Hardware context 重建、grounding、hash 和 allowlist 校验保留。12 个冻结文件与 HEAD 逐字节相同。

## Q. Offline / Fake-Model Tests

新增 45 个实例覆盖角色配置/默认隔离/import opt-in、真实 ChatDeepSeek tool binding、usage/metadata、
输入/IR 不变、四类对象无 evidence/VERIFIED 拒绝、runtime 正反例/嵌套 scopes、空报告/STATIC 接受、
预留目录/不覆盖、精确 context/hash、成功五文件、九类失败不落正式结果、secret/raw 拒绝、
synthetic Firmware reviewed export 和 report/hash/evidence/behavior/finding/provenance/version/counts 等损坏拒绝。
默认不访问网络或真实 corpus；真实 corpus test 显式 opt-in，仍不调用 LLM。

## R. Exact Test Results

所有检查在真实调用之前完成：

```text
pytest -q: 476 passed, 7 skipped in 6.97s
explicit Heat_Press local integration: 1 passed in 1.37s
python -m pip check: No broken requirements found.
python -m compileall -q src tests: exit 0
git diff --check: exit 0
```

无新增 dependency，无需重建 fresh environment。调用后只补充文档，没有修改 prompt、projection 或其他执行代码。

## S. Real Invocation

| 项目 | Attempt 1 | Attempt 2 |
| --- | --- | --- |
| requested model | deepseek-v4-pro | deepseek-v4-pro |
| returned model_name | 未返回 | deepseek-v4-pro |
| run_id | 98b38d95-0b81-4330-aff8-7429157b7ab2 | 9824162f-023d-45ae-82e2-0fa510cc06bf |
| 结果 | connection failure | exact EvidenceRef grounding failure |
| input tokens | 未返回 | 15103 |
| output tokens | 未返回 | 864 |
| total tokens | 未返回 | 15967 |
| context chars | 39438 | 39438 |

两个输出目录分别是：

```text
/home/qcx/ChipChainV3/output/fuzzware:heat-press:scenario-13/98b38d95-0b81-4330-aff8-7429157b7ab2/
/home/qcx/ChipChainV3/output/fuzzware:heat-press:scenario-13/9824162f-023d-45ae-82e2-0fa510cc06bf/
```

这是两次显式 application invocation，零自动 retry；只有第二次返回了模型响应。
第一次没有 usage 不等价于已证实零计费。本轮不推断金额。

## T. Full firmware_analysis_report.json

**不存在。** 第二次报告在 grounding gate 失败，被拒绝且未持久化。按失败诊断规则未保存 raw/parsed rejected output，
所以不能完整贴出报告，不能以 fake report 或重构内容代替真实结果。

## U. Full safe invocation.json

**不存在。** invocation.json 属于成功结果五文件之一。本轮只有下方完整安全 failure.json，以及每次 started/failed JSONL。
它们不是成功 invocation.json 的替代品。

Run `98b38d95-0b81-4330-aff8-7429157b7ab2`：

```json
{
  "case_id": "fuzzware:heat-press:scenario-13",
  "run_id": "98b38d95-0b81-4330-aff8-7429157b7ab2",
  "attempt_index": 1,
  "timestamp": "2026-09-12T10:08:19.855554+00:00",
  "provider": "deepseek",
  "model": "deepseek-v4-pro",
  "prompt_id": "firmware-security-agent",
  "prompt_version": "v1",
  "context_sha256": "48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803",
  "status": "failed",
  "category": "provider_execution",
  "failure_category": "provider_execution",
  "reason_code": "provider_invocation",
  "exception_type": "AgentExecutionError",
  "usage": {},
  "response_metadata": {},
  "diagnostics": [
    {
      "exception_type": "AgentExecutionError"
    },
    {
      "exception_type": "OpenAIConnectionError"
    },
    {
      "exception_type": "APIConnectionError"
    },
    {
      "exception_type": "ConnectError"
    },
    {
      "exception_type": "ConnectError"
    }
  ]
}
```

Run `9824162f-023d-45ae-82e2-0fa510cc06bf`：

```json
{
  "case_id": "fuzzware:heat-press:scenario-13",
  "run_id": "9824162f-023d-45ae-82e2-0fa510cc06bf",
  "attempt_index": 2,
  "timestamp": "2026-09-12T10:09:09.902834+00:00",
  "provider": "deepseek",
  "model": "deepseek-v4-pro",
  "prompt_id": "firmware-security-agent",
  "prompt_version": "v1",
  "context_sha256": "48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803",
  "status": "failed",
  "category": "agent_post_validation",
  "failure_category": "agent_post_validation",
  "reason_code": "evidence_mismatch",
  "exception_type": "AgentStructuredOutputError",
  "usage": {
    "input_tokens": 15103,
    "output_tokens": 864,
    "total_tokens": 15967
  },
  "response_metadata": {
    "id": "1f568585-8426-4b6b-b859-6fffb6a6e61b",
    "model_name": "deepseek-v4-pro"
  },
  "diagnostics": [
    {
      "exception_type": "AgentStructuredOutputError"
    }
  ]
}
```

## V. Real Report Claim Audit

| 人工审核问题 | 本轮能够确认的内容 |
| --- | --- |
| execution / runtime reachability claim | 无法审核被拒绝响应；没有接受此类结论 |
| crash claim | 无法审核；未产生 crash observed deterministic fact |
| physical UART/Wi-Fi/Bluetooth path | 无法审核；runner 没有构造 ExternalInputPath |
| confirmed vulnerability / root cause | 无法审核；没有 accepted 漏洞或根因结论 |
| MMIO configuration vs runtime | 输入严格区分；模型如何表达无法从 sanitized diagnostics 判断 |
| input existence vs consumption | 输入仅证明 artifact/configuration；没有实际消费证据 |
| exact supplied evidence | 未通过；至少一个 EvidenceRef 不属于 exact supplied catalog |
| supplied behavior IDs | 本次在 evidence gate 已失败，后续 IR output gate 未完成 |
| requested missing evidence | 原报告未保存，不能归因给模型或杜撰其请求 |

Input/IR 在架构上仍由确定性分析产生，模型返回类型只包含报告；fake test 验证输入和 IR 不变。
真实失败路径没有有效 AgentOutput，不能声称已经完成成功路径中的 real_output == stub 比较。
当前 context 本身已有 unresolved questions，但它们不能冒充模型的真实回复。

## W. Output Files and SHA256

所有真实输出都在 Git ignored 的 runtime 目录；未写入 reviewed 区域。
`analysis_input.json` 不存在，因此没有其文件 SHA256。实际发送前的 text SHA256 与长度见 H，
不能将重新推导的“若写盘”hash 宣称为已存在文件的 hash。

| Run | 文件 | Bytes | SHA256 |
| --- | --- | ---: | --- |
| 1 | `failure.json` | 920 | `5e5b6548f60939c1c08dd5a17e87ab836c59f4bb3e24da05a3b25126076b9108` |
| 1 | `invocation_attempts.jsonl` | 1189 | `29c726b595fcd3ddd201ef96682269cd64947c2b2ce873fba089842d408ea415` |
| 2 | `failure.json` | 886 | `676feaf86ed24ee4a6fdd6db0c62853e1bb9e52910e4dba76e903c9a9be41064` |
| 2 | `invocation_attempts.jsonl` | 1191 | `6ddfa8a51d2212662c4d37734da5c65325122d51104c386550402e64916be582` |

## X. Known Limitations

1. 当前没有成功的真实 FirmwareAnalysisReport，不能冻结为“真实验证已成功”。
2. Evidence mismatch 的安全类别不能解释具体哪些字段被改；按要求没有保存 rejected/raw response，不能事后恢复。
3. 当前静态 sites 和 MMIO 配置没有 CFG、call graph、真实执行/覆盖/MMIO consumption 证据。
4. Exact grounding 不证明自然语言 claim 被 evidence 蕴含；STATIC overclaim、物理接口或根因归因仍需人工审核。
5. 只有单个 ARM Heat_Press 样本；没有新增 target，没有 Cross-Layer pairing。
6. projection v1 身份/内容策略的既有保守限制不变；本轮不修改它来适应模型输出。

## Y. Recommended Next Deterministic Evidence

本轮首先需要人工决定 grounding failure 的后续诊断/实验方案；不自动调 prompt 或重跑。
若后续扩充固件确定性能力，最有帮助的是从已有 ELF 建立可引用的 basic blocks、CFG/call graph 和
MMIO site 到函数/调用者的关联，支持审查有限 STATIC 推断。runtime/输入消费结论还需要独立的
trace/coverage/MMIO consumption 证据，不能由静态结构替代。以上只是后续方向，本轮未执行。

## Z. Git Status

未执行 git add/commit/push/tag，未对真实 run reviewed-export。下方为本轮工作区状态：

```text
 M .env.example
 M README.md
 M src/chipchain/agents/firmware.py
 M src/chipchain/execution/reviewed_output.py
 M src/chipchain/integrations/deepseek.py
 M src/chipchain/integrations/deepseek_hardware.py
 M tests/integration/test_fuzzware_local.py
 M tests/unit/test_deepseek_integration.py
?? docs/research/v3-2b-deepseek-firmware-agent.md
?? src/chipchain/integrations/deepseek_firmware.py
?? tests/unit/test_deepseek_firmware.py
```

最终检查：4 个真实 diagnostic 文件均被 Git 忽略；修改/新增文件及真实 diagnostic 均通过实际 key 比较；
诊断 JSON 通过 raw/secret field scan；12 个 Hardware reviewed 文件与 HEAD byte-identical；新文件无行末空白；
`git diff --check` exit 0。发送前 context 为 39,438 UTF-8 bytes（也是 39,438 characters）。

## Final 20 Answers

1. **真实 DeepSeek Firmware Agent call 成功了吗？** Provider 在第二次返回了响应，但完整 Agent run 失败，没有合格报告。
2. **Requested model？** 两次均为显式 `deepseek-v4-pro`；使用本轮允许的未配置 Firmware 时的默认策略。
3. **Returned model_name？** 第二次 `deepseek-v4-pro`；第一次未返回。
4. **发送的确为 projection v1？** 是，未修改的 serializer 输出作为 HumanMessage，hash 与 A1.1 相同。
5. **仍是 39,438 字符？** 是，也是 39,438 UTF-8 bytes。
6. **路径/crash-analysis/crashing_input 到达模型？** 没有，这些未出现在发送的投影中。
7. **模型修改 IR？** 模型只返回报告，没有 IR 写入通道；本次没有有效 real_output，成功后的 stub equality 检查未完成。
8. **引用 invented/altered EvidenceRef？** 至少一个引用未通过 exact equality；安全诊断不能区分具体改动。
9. **未知 behavior ID？** 无法确认；evidence gate 先失败，未保存报告，后续 IR gate 未完成。
10. **零 runtime 下声称 RUNTIME？** 无法从失败诊断审核，不能假称模型保持了该边界。
11. **声称 crash？** 无法审核，未接受任何 crash 结论。
12. **无证据物理接口？** 无法审核；runner 未构造此类 path。
13. **confirmed vulnerability/root cause？** 无法审核；没有 accepted 漏洞/根因结果。
14. **实际有用 findings/hypotheses？** 没有可接受或可复核的真实 findings；有效实验结果是 exact grounding 拒绝了首次返回的响应。
15. **模型明确说缺什么证据？** 未保存被拒绝报告，未知，不以输入 unresolved_questions 冒充模型回答。
16. **analysis_run/report 持久化？** 没有；只有安全 failure/attempt diagnostics。
17. **raw provider output 落盘？** 没有。
18. **Firmware reviewed export 支持但未执行？** 已支持且 synthetic tests 通过；未对真实 run 执行。
19. **历史 Hardware runs/snapshots 改变？** 未写 Hardware runtime，12 个 frozen snapshot 文件逐字节不变。
20. **最有帮助的下一项 deterministic capability？** 可引用的 basic blocks、CFG/call graph 和 MMIO site/函数关联；runtime 结论另需独立执行和输入消费证据。本轮均未实现。

已停止。本轮未修改 prompt，未第三次调用，未执行真实 reviewed export 或 Git add/commit/push/tag。
