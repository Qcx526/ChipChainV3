# V3-2B3-R2 — Orphan Support Claim Policy & Referenced-Support Enforcement

基线：`v3-2b3-r1-stable` / `b06e5e67b12dc1944226d37d29b5a54d0cd6b43c`。

## 唯一核心政策变化

旧 v1 拒绝任何没有被 Firmware item 引用的 support。R2 对全部 schema-valid support
执行同一 `evaluate_support()`，只要求**被引用的 support 必须 supported**。
孤立 support 保留为 `usage_status=orphaned` 的诊断，允许 supported、unsupported、incompatible。
它不能产生或隐式支持 findings、external input paths、reachable behaviors 或 issue anchors。

新政策实现独立位于 `agents/relation_support_v2.py`。旧 `relation_support.py` 未改动，
包括 v1 contract、v1 unused-support 拒绝、fact matcher、evaluator 和 v1 artifact validator。
Agent 的显式 `invoke_supported` 切换到 v2；旧 v1/enriched_v2 Agent 路径不变。

顺序固定为：schema 重验 → Firmware IDs/references → support IDs 唯一 → 每个非空
Firmware item 的 support IDs 非空且无重复 → 被引用 support 存在 → 建立引用映射 →
**全部 support 确定性评估** → 拒绝被引用的 unsupported/incompatible → evidence hydration →
canonical report / IR / epistemic gates。继续使用 `unsupported_relation_claim` /
`incompatible_relation_claim` 安全 reason codes，在 v2 中这两个拒绝仅针对 referenced support。
失败不持久化 rejected structured result，也不为统计目的保存该响应。

## v2 artifact 与 exporter

`firmware-relation-support/v2` 的每项包含 typed support claim、usage_status、result、
reason_code、relation_ids 和 referencing_firmware_claims。referenced 必须至少有一条引用且
result=supported；orphaned 必须引用为空，三种 result 都允许。未知 relation 的孤立 claim
保留 `incompatible / unknown_relation_id`。

报告与成功 invocation 均具有以下七个计数，由 entries 确定性复算并验证：

- generated_support_claim_count
- referenced_support_claim_count
- orphan_support_claim_count
- referenced_supported_count
- orphan_supported_count
- orphan_unsupported_count
- orphan_incompatible_count

原 invocation 的 structured_support_claim_count 仍表示所有生成 support 数量；
supported_support_claim_count 表示全部 evaluated supported 数量，包括 supported orphan。
新计数区分 usage，不能用旧 supported 总数代替 referenced 数量。

Exporter 按 artifact schema 选择 v1/v2 合同及 invocation schema。
v2 从 canonical 四类 items 和 audit 的显式引用重建 model-only report，重新执行相同
wiring/evaluation/gates，要求完整审计 equality，并检查 invocation 七个计数。
孤立 incompatible/unsupported 可作为诊断通过 exporter 校验，这不代表认可该 claim。
伪造 usage、result、reason、relation IDs、计数或丢失必要引用会被拒绝。

边界：canonical report 已剥离 support 字段，因此 audit 本身是重建 wiring 的来源；
这里验证内部一致性，不声称存在独立签名的原始 wiring，或能识别所有协调篡改。
自由文本与 typed support 的语义一致性仍须人工审核，代码不新增 prose 猜测规则。

## 冻结输入与实验约束

Prompt v2、ModelFirmwareAnalysisReportV2、relation projection v1、envelope v3、A4
catalog/builder/checker 均未修改。A1/A3/envelope v2 身份不变。

| 身份 | 字符数 | SHA256 |
|---|---:|---|
| Prompt v2 text | — | `10573f3efba97bed7a44d491e4915197f57d771e90b4143248bf19842b685bff` |
| ModelFirmwareAnalysisReportV2 canonical schema | — | `512974761886482b973ed4230e02f6aa56be9812b3a62be1588e0aa0bb516248` |
| A1 | 39438 | `48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803` |
| A3 | 16631 | `4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304` |
| B2 envelope v2 | 56408 | `6afef3295f8c54ee7fef65446db0a91169ee833d3ede4314e38e45ca0d7c5016` |
| A4 | 129547 | `fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902` |
| Relation projection v1 | 16824 | `f65dd1b99fc621fb6ccda0e45d7254a233351185258d820d8736949c74c635b2` |
| Envelope v3 | 56523 | `b7722ef471a05bd7e83e2042ae2ac7a4ed125b01a5aeb624581ea1994994adab` |

任何 model-visible identity 变化会在生产 preflight 拒绝 API 调用。
真实配置固定 deepseek-flash、temperature=0、thinking=disabled、max_tokens=16384、
max_retries=0、function_calling、strict=false、timeout=180 秒。
v1/enriched_v2 默认预算保持 8192。

与 R1 相比输入、prompt、schema 和 provider 设置相同，但 **support acceptance policy 改变**，
远端模型服务也可能随时间漂移。这个单次观察不构成统计意义上的严格可重复实验。

## 合成验证覆盖

新增三类孤立结果及未知 relation 诊断；全部孤立且 Firmware report 为空；所有 support 先评估
再拒绝；support 拒绝后不能执行 hydration；四类 Firmware items 共享有效 support。
保留 branch/call、read/write、vector misuse、trigger/runtime/physical、broken path、
未知 ID、重复 ID、缺失/重复 support reference 等拒绝测试。

v2 round trip、全部 entry 再评估、完整 audit equality、七计数的 report 与 invocation 篡改，
以及 v1 synthetic artifact/exporter 兼容均覆盖。
Synthetic exporter 测试仅在 pytest 临时目录运行，不对真实 output 执行 reviewed export。

大输出基准仍为 102496 字符，四类各 40 项，共 160 个 Firmware items，两个 shared supports
各被 160 items 引用；另加一个 unknown-relation orphan 后仍通过完整 Agent 与 audit 校验。
Prompt/schema hash 以及三种模式预算继续固定。

## API 前实际验证结果

```text
针对性测试（补充最终两个测试之前）：102 passed in 13.09s
pytest -q：770 passed, 12 skipped in 21.14s
python -m pip check：No broken requirements found.
python -m compileall -q src tests：exit 0
git diff --check：exit 0
fresh deterministic / fake model preflight：1 passed in 16.93s
```

以上 Python 命令均使用仓库 `.venv/bin/python`。默认离线测试不连接 provider。
显式 local preflight 从四个原始 artifacts 重新执行 A1 → fresh Ghidra A2 → A3 → A4 →
relation projection → envelope v3，不以保存的 A4 或输出为生产事实。

| 真实关系类别 | 数量 |
|---|---:|
| direct_call | 22 |
| direct_branch | 6 |
| control_transfer_unresolved | 6 |
| mmio_function_containment | 23 |
| mmio_access_direction | 23 |
| vector_dispatch | 51 |
| 总计 | 131 |

实际 model context=56523 chars，projection=16824 chars，registry union=174（57 A1 +
172 A3，重叠 55；relation delta 117），runtime observations=0。
6 项正确真实 relation facts 通过、14 项错误 referenced facts 拒绝，另有 1 项
错误 Reset→SystemInit 孤立 support 保留为 incompatible 诊断。

生产 preflight 固定以下真实事实：call-80f88 是 unresolved/indirect_call/blx；
call-80afa 是 f80af4→f80eac confirmed direct_call；四个 UART b.w 站点保持 direct_branch；
SystemInit 八站点保持 ldr/read；vector-1 仅是到 f80f34 的 dispatch。
源码快照确认 prompt/schema/projection/envelope/A4 和 v1 evaluator 未改，
API 调用前 59 个既有 output 文件逐字节保持一致。

## 实际 R2 单次调用结果

新 run ID：`8b099ab7-d3a8-401d-b8d5-43e63c13642d`。真实 provider call **1 次**，
retry **0 次**，attempt_index=1。CLI 因校验拒绝返回 exit 1；随后停止模型调用。

| 指标 | B3 pilot | B3-R1 | B3-R2 |
|---|---|---|---|
| run ID | a8b049f2-16f4-465c-8d93-8fc618540f0d | 759757ba-92ba-420d-ae25-3f9595d91159 | 8b099ab7-d3a8-401d-b8d5-43e63c13642d |
| max_tokens | 8192 | 16384 | 16384 |
| input / output / total tokens | 20488 / 8192 / 28680 | 20488 / 14112 / 34600 | **20488 / 16241 / 36729** |
| finish_reason | 未记录 | tool_calls | **tool_calls** |
| structured parsing | FAIL | PASS | **PASS** |
| support wiring | 未进入 | unused support 拒绝 | **PASS** |
| 全部 typed support evaluation | 未进入 | 未进入 | **已执行** |
| referenced support enforcement | 未进入 | 未进入 | **FAIL** |
| safe reason | schema_or_tool_response | unused_support_claim | **incompatible_relation_claim** |
| evidence hydration | 未执行 | 未执行 | 未执行 |
| accepted canonical report | 无 | 无 | 无 |

R2 的 orphan policy 修正已生效；本次失败发生在全部 deterministic support evaluation 完成后，
至少一个**被 Firmware claim 显式引用**的 support 为 incompatible。
这符合预设的“referenced support fails”结果：模型仍对供 canonical claims 使用的 typed
relations 产生不兼容解释。不能将它归因为 orphan，也不能据此确定具体哪个 relation 错误。

按失败保存边界，不保留 rejected typed output 或原始 provider 响应。安全日志没有 support
IDs、计数、逐条结果、引用表或正文。generated/referenced/orphan counts 及三个结果的精确分布
均**无法确定**，不能把未知写为 0。可确认 referenced incompatible 数量至少为 1。

### Referenced / orphan support index 与 canonical claim index

本次没有通过 support gate 的报告，也没有可持久化的 support audit，故无法列出可靠的
referenced support index、orphan support index 或 canonical Firmware claim index。
不从 rejected/raw response 恢复这些内容，不编造 support IDs、Firmware IDs 或计数。

### Evidence / IR / epistemic gates

Support gate 拒绝后没有执行 evidence hydration、canonical report 验证、后续 IR / epistemic gates
或成功持久化。输入及 deterministic stub IR 仍为 A1 原始 55 behaviors、0 runtime observations；
本次没有持久化的 accepted ProcessorBehaviorIR 可供比较，也没有 accepted RUNTIME claim。
不能把后续 gates 的“未执行”写为“通过”。

### B2 回归与人工语义审计

| 回归点 | Fresh deterministic / fake validation | 本次真实输出可审计结论 |
|---|---|---|
| Reset→SystemInit false call | call-80f88 unresolved/indirect_call/blx；错误 referenced direct call 拒绝；同类孤立错误保留 | 具体 claim 未保存；无法确定是否复现或仅存在于 orphan |
| UART b.w / direct-call 混淆 | 四站点保持 direct_branch，错误 direct_call 拒绝 | 无法确定模型解释 |
| SystemInit read/write | 八站点 ldr/read，错误 write 拒绝 | 无法确定模型解释 |
| vector-1 过度解释 | dispatch→f80f34；不证明 Reset→SystemInit 调用 | 无法确定模型解释 |
| trigger→handler | frozen checker unsupported，referenced 拒绝；orphan 诊断保留 | 无法确定是否生成 |
| physical UART/ADC input | 静态 facts 不证明物理输入路径 | 无法确定是否生成 |
| runtime reachability | runtime observations=0；static support 不证明执行可达 | 无 accepted report，未进入后续 runtime gate |
| crash/vulnerability claims | typed support gate 不解析或证明自由文本 | 无可审计正文 |

没有 machine-valid B3 canonical report 可交给人工逐条语义审核。
能审计的是本轮配置、冻结输入、验证顺序和 referenced-incompatible 拒绝行为。
即使未来 machine accepted，也不意味着 model 没有关系错误：invalid orphan 必须记录为模型错误，
合法 typed support 也不自动证明 Firmware 自由文本、物理路径或漏洞结论。

### 安全持久化

本次目录仅有以下两个文件，既有历史 run 不复用、不覆盖：

- [failure.json](../../output/fuzzware:heat-press:scenario-13/8b099ab7-d3a8-401d-b8d5-43e63c13642d/failure.json)：SHA256 `02681305977678a3a0effc743e52ed53dd36826fd4cc5328ceb62925a46e2295`
- [invocation_attempts.jsonl](../../output/fuzzware:heat-press:scenario-13/8b099ab7-d3a8-401d-b8d5-43e63c13642d/invocation_attempts.jsonl)：SHA256 `1b4bfaf9f9067692f2c8236521307fde817ede596e9b7ce6794e21726caf786f`

完整安全 failure.json：

```json
{
  "case_id": "fuzzware:heat-press:scenario-13",
  "run_id": "8b099ab7-d3a8-401d-b8d5-43e63c13642d",
  "attempt_index": 1,
  "timestamp": "2026-09-15T01:34:21.642810+00:00",
  "provider": "deepseek",
  "model": "deepseek-flash",
  "prompt_id": "firmware-security-agent",
  "prompt_version": "v2",
  "context_sha256": "b7722ef471a05bd7e83e2042ae2ac7a4ed125b01a5aeb624581ea1994994adab",
  "status": "failed",
  "max_tokens": 16384,
  "category": "relation_support_validation",
  "failure_category": "relation_support_validation",
  "reason_code": "incompatible_relation_claim",
  "exception_type": "RelationSupportError",
  "usage": {
    "input_tokens": 20488,
    "output_tokens": 16241,
    "total_tokens": 36729
  },
  "response_metadata": {
    "finish_reason": "tool_calls",
    "id": "8d45b1d9-16d1-42a2-9941-6db47476e3ef",
    "model_name": "deepseek-flash"
  },
  "diagnostics": [
    {
      "exception_type": "RelationSupportError"
    }
  ]
}
```

没有 analysis_run.json、firmware_analysis_report.json、firmware_relation_support.json、
analysis_input.json 或 invocation.json。没有 AIMessage、raw tool args、provider body/headers 或 partial response。
成功路径的六文件/v2 support 持久化由 synthetic tests 验证，本次真实运行未到达成功路径。
未对任何真实 run 执行 reviewed export。

## 后续边界

建议下一步仍停留在 B3：人工决定一个独立的 referenced-support 诊断/映射补丁范围，
先解决模型对被引用 typed relations 的解释问题，再评估 A5 angr 的必要性。
当前安全日志不足以定位具体 relation，不据此擅改 prompt/schema/checker 或削弱 referenced gate。
本轮不运行第二次调用、不进入 A5/angr 或 Cross-Layer，不 add/commit/push/tag。

## 最终保全检查

调用结束后，所有 src 源码与 API 前快照一致；没有根据模型结果修改接受政策。
59 个历史 output 文件和所有旧研究/架构文档逐字节不变。新增 output 仅本次新 run 的两份安全日志，
包含同一 attempt_index=1 的 started/failed 记录。root README 追加当前 R2 状态；原 B3/R1 文档不改写。
