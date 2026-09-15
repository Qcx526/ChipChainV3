# V3-2B3-R3 — Safe Referenced-Support Failure Diagnostics

稳定基线：`v3-2b3-r2-stable` / `5754d155894d524c2a679e0a5ebb5229b67decb0`。
R2 run `8b099ab7-d3a8-401d-b8d5-43e63c13642d` 已证明至少一个 referenced support incompatible，
但原日志没有具体 support/relation/Firmware IDs。R3 只增加安全错误定位，不更改接受政策。

## Evaluation 与 enforcement

`evaluate_relation_support_v2` 保留 schema、Firmware IDs、support IDs 和引用验证，调用原
`evaluate_support()` 完成所有 referenced/orphan supports 的评估，返回内部 `CompleteSupportEvaluation`。
内部 entry 允许 referenced unsupported/incompatible；它不是 accepted support artifact。

`enforce_referenced_support` 先从完整评估构造和复验诊断，再用固定文本异常拒绝失败的 referenced support。
顶层 reason 仍取模型顺序中首个失败的 result，与 R2 完全相同；不会因诊断列表排序改变 reason。
异常 `RelationSupportValidationErrorV2` 继承旧错误类型，仅新增 typed `failure_diagnostic` 属性；
`str(error)` 仍为 `Model relation support validation failed`，failure_category 仍为 relation_support_validation。
v1 `RelationSupportError`、evaluator 和 artifact 校验未改。

所有 referenced supports supported 时，仍创建原 `FirmwareRelationSupportReportV2`，
进入原 hydration/canonical/IR/epistemic 流程。其合同和 schema 不改；orphan 三类结果仍仅诊断。
成功目录仍六文件，不生成 failure diagnostic。

## 安全诊断合同

新增 `agents/relation_support_diagnostics.py`，schema 为 `firmware-relation-support-failure/v1`。
顶层只包含 schema_version、failure_reason_code、九个计数和 failed_referenced_supports：

- generated_support_claim_count、referenced_support_claim_count、orphan_support_claim_count；
- referenced_supported_count、referenced_unsupported_count、referenced_incompatible_count；
- orphan_supported_count、orphan_unsupported_count、orphan_incompatible_count。

每个失败 entry 仅含 support ID、claim type、referenced usage、result/reason、relation IDs、
引用它的 collection/claim ID、expected typed semantics 和 actual relation snapshots。
全部失败 referenced entries 都保留；orphan 只参与总计数，不出现在失败列表。

Expected 分为 relation_fact、static_call_path、unsupported semantic 三种类型；
保留 safe expected endpoints/kind/status/direction/transfer/vector 字段，或明确路径的有序 edge IDs。
Actual 仅含 relation ID、kind/status、无地址/标签的 source/target identity 和 typed attributes：
transfer_kind/call_semantics/original_reason/mnemonic、direction/mnemonic 或 vector_index/binding_status。
Unknown relation 的 snapshot wrapper 保留请求的 relation ID，`actual=null`。

所有 identifiers 使用原 SafeID（1–160 个限定字符）；其他文本为 Literal/Enum。
计数限制为 0–2^32−1，vector index 为 1–2^32−1，诊断集合最多 4096 项。
Mnemonic 采用显式枚举；不在枚举中的实际助记符以 `not_allowlisted` 标记，不复制任意字符串。
这只限制诊断表达，不改变 A4 数据或支持关系评估。

### Direction mismatch 的两个层次

冻结的 model fact matcher 对 expected read/write 不符返回 `relation_fact_mismatch`；
R3 不将它改写为另一个 checker reason。
诊断额外记录 `mismatch_detail=direction_mismatch`，同时保存 expected write 与 actual read/ldr。
因此既能定位方向错误，也保持 R2/A4 reason 与接受语义一致。

### 确定性与复验

失败项按 `(result, support_claim_id, claim_type)` 排序；引用按 `(collection, claim_id)` 排序；
snapshots 按 relation ID 排序。Expected path 的 edge_relation_ids 保留原始顺序，不能排序成另一条路径。
保存 JSON 使用 sorted keys，hash 按实际 UTF-8 文件字节计算。

`validate_failure_diagnostic(diagnostic, complete_evaluation, catalog)` 从完整评估重算全部九计数，
重建全部 failed entries/expected/actual，再要求 exact equality；创建异常之前强制调用。
Standalone JSON 合同检查内部算术、失败数量、ID 对齐和排序。
由于文件刻意不含 supported/orphan 全条目，脱离完整 evaluation 的 JSON 无法独立推导这些省略项的数量；
完整复验明确需要 evaluation/catalog 上下文，不将内部算术检查冒充完整证明。

## 隐私与持久化边界

不包含 Firmware summary、entry point prose、unresolved questions、evidence IDs/summaries、raw encoding、
raw AIMessage/tool args/provider body/headers/partial response 或 exception message。
失败 output 不能因 schema 已通过而整体保存。

新 artifact 在输出前重新通过合同校验、现有 `_safety` 和 `_check_secret`。
上限 `MAX_RELATION_SUPPORT_FAILURE_BYTES = 256 * 1024`，按最终序列化字节计算。
超限、安全拒绝或诊断无法表达时不截断、不写部分诊断，仍拒绝模型报告，基本日志记录
`diagnostic_persisted=false`。正常写入后记录 true、schema、SHA256 和 failed_referenced_support_count。
`failure.json` 不内联诊断内容。

Schema/wiring/transport 等前置失败不生成新 artifact。
成功 support 后的其他 gate 失败也不会伪造 relation failure diagnostic。
Referenced support failure 的目录至多三文件：failure.json、invocation_attempts.jsonl、
firmware_relation_support_failure.json；不存在 canonical accepted 文件。
新诊断不进入 reviewed output；成功 v1/v2 exporter 不要求它。

## 冻结输入与设置

Prompt/schema/relation projection/envelope/A4 builder/checker、domain report/IR 均未修改。
生产 preflight 继续固定以下身份，任何漂移拒绝 API：

| 身份 | 字符数 | SHA256 |
|---|---:|---|
| Prompt v2 | — | `10573f3efba97bed7a44d491e4915197f57d771e90b4143248bf19842b685bff` |
| Model schema v2 | — | `512974761886482b973ed4230e02f6aa56be9812b3a62be1588e0aa0bb516248` |
| A1 | 39438 | `48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803` |
| A3 | 16631 | `4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304` |
| A4 | 129547 | `fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902` |
| Relation projection | 16824 | `f65dd1b99fc621fb6ccda0e45d7254a233351185258d820d8736949c74c635b2` |
| Envelope v3 | 56523 | `b7722ef471a05bd7e83e2042ae2ac7a4ed125b01a5aeb624581ea1994994adab` |

Provider 固定 deepseek-flash、temperature=0、thinking=disabled、max_tokens=16384、max_retries=0、
function_calling、strict=false、timeout=180。不增加输出预算、不增加自动重试。

## Synthetic 验证

覆盖 Reset 间接调用错误、UART branch-as-call、SystemInit write/read、vector misuse、trigger→handler、
unknown relation、错误 static path；单个报告完整包含多个失败，不只取首错。
覆盖 orphan 不进入 failed list、九计数复算、协调篡改计数/actual 拒绝、排序确定性、typed field 范围。

PRIVATE summary、raw provider body 不写入任何失败文件；真实配置 secret 和可识别 credential 两类扫描均覆盖。
预算测试既覆盖 runner 的基本日志 fallback，也构造 300 个失败项超过实际 256 KiB，确认整份诊断省略。
成功含 bad orphan 的六文件路径保持；旧 v1/v2 exporter、schema failure 两日志路径及大输出回归继续运行。

使用 pristine R2 stable 源码生成合成成功 support artifact 的固定 SHA256：
`701135ba9c7727ca069c1f6767f6e7a831bbba8cab823c6db2cc2324aabbc60b`。
R3 相同合成输入要求输出字节 hash 一致。

## API 前验证记录

```text
旧 R2 相关回归：104 passed in 12.30s
最终全量离线 pytest -q：801 passed, 12 skipped in 24.50s
python -m pip check：No broken requirements found.
python -m compileall -q src tests：exit 0
git diff --check：exit 0
```

命令均使用仓库 `.venv/bin/python`。默认 pytest 禁止真实网络调用。
最终全量覆盖 31 个新增 R3 单元测试；开发中修正了一个误将 synthetic inputs 目录
视为诊断输出的测试断言，最终全量已通过。
API 前源码快照确认 11 个冻结源文件逐字节未改，61 个历史 output 文件保持不变，
`output/reviewed/` 仍只有 `v3-1b1` 子目录。

Fresh deterministic preflight：**1 passed in 17.65s**。
从四个原始 artifacts 重新执行 A1 → fresh Ghidra A2 → A3 → A4 → relation projection → envelope v3，
不以旧 output 作为事实来源。131 relations 的分类为 22 direct calls、6 direct branches、
6 unresolved transfers、23 MMIO containment、23 MMIO direction、51 vectors；runtime observations=0。
A1 evidence=57、A3=172、交集55、union=174；projection=16824 chars、context=56523 chars。

6 项有效真实 facts 通过，14 项错误 referenced facts 拒绝并验证安全 expected/actual diagnostic；
另验证错误 Reset-call orphan 仍被保留于成功 v2 audit，而不触发 failure artifact。
所有生产 semantic hashes/pins 与 R2 一致。

## 实际 R3 单次调用

Run ID：`db343655-ddd8-4b69-8dec-4d0149e38abf`。
真实 provider call **1 次**，retry **0 次**，attempt_index=1。
CLI 因 referenced support 校验拒绝返回 exit 1；随后停止，没有根据结果修改源码。

| 指标 | R3 结果 |
|---|---|
| model | deepseek-flash |
| max_tokens | 16384 |
| input / output / total tokens | **20488 / 14949 / 35437** |
| finish_reason | **tool_calls** |
| structured parsing | **PASS** |
| complete support evaluation | **已执行** |
| referenced enforcement | **FAIL / incompatible_relation_claim** |
| diagnostic_persisted | **true** |
| failure diagnostic bytes | **57213**（小于 262144） |
| evidence hydration | **未执行** |
| canonical / IR / epistemic gates | **未执行** |
| accepted canonical report | **无** |

| Usage | Supported | Unsupported | Incompatible | 总计 |
|---|---:|---:|---:|---:|
| Referenced | 66 | 0 | **37** | **103** |
| Orphaned | 1 | 0 | 2 | **3** |
| 全部 | 67 | 0 | 39 | **106** |

37 个失败 support 包含 34 个 relation_fact（reason=relation_fact_mismatch）和
3 个 static_call_path（reason=broken_explicit_path）。全部 result=incompatible、usage=referenced。
涉及 34 个不同 A4 relation IDs、四个 findings 和两个 issue anchors；诊断没有复制任何 rejected Firmware prose。
两项 incompatible orphan 只计数，不进入失败列表；本文件没有保存它们的 IDs/正文，不能猜测其内容。

## 全部 37 项失败 support 索引

下表完全由安全诊断派生，不使用 rejected Firmware prose。
Expected/Actual 列只显示不相等字段，值的顺序均为 **模型 expected → A4 actual**。
共同字段规则：

- call 行：relation_fact，kind=direct_call、status=confirmed_static、transfer_kind=direct_call 均相同；
  source 为 call-80bd2/80bdc 的 f80af4，或 call-8125a 的 f81234。Actual call_semantics=true、
  mnemonic=null、original_reason=null；错误仅 target。
- containment 行：relation_fact，kind=mmio_function_containment、source=mmio-<地址> 相同；
  expected 与 actual 的 status/target 如表。target 为函数或 null，没有额外 attributes prose。
- path 行：static_call_path，只引用表中一条 edge；source 分别 f80af4、f80af4、f81234，
  actual 是相应 confirmed direct_call。错误的 path target 如表。
- vector 行：relation_fact，kind=vector_dispatch、status=confirmed_static、source=vector-N、
  vector_index=N、binding_status=function_entry 均相同；错误仅 target。
- 每个 relation_fact 未适用的 expected direction/transfer/vector/binding 字段均为 null。
  此处没有把省略字段解释为不同值；完整 typed expected/actual 在输出 JSON 中。

| Support ID | Claim type / reason | Referencing Firmware collection:ID | Relation ID | Expected → Actual 差异 |
|---|---|---|---|---|
| sc-call-80bd2 | relation_fact / relation_fact_mismatch | findings:F-direct-calls | call-80bd2 | target_entity_id: f8106c → f81052 |
| sc-call-80bdc | relation_fact / relation_fact_mismatch | findings:F-direct-calls | call-80bdc | target_entity_id: f81052 → f81044 |
| sc-call-8125a | relation_fact / relation_fact_mismatch | findings:F-direct-calls | call-8125a | target_entity_id: f80db0 → f8106c |
| sc-mmio-cont-80d4e | relation_fact / relation_fact_mismatch | findings:F-mmio-containment<br>issue_anchors:A-mmio-irqhandler | mmio-containment-80d4e | status: confirmed_static → missing; target_entity_id: f815a4 → null |
| sc-mmio-cont-80d50 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment<br>issue_anchors:A-mmio-irqhandler | mmio-containment-80d50 | status: confirmed_static → missing; target_entity_id: f815a4 → null |
| sc-mmio-cont-80d5a | relation_fact / relation_fact_mismatch | findings:F-mmio-containment<br>issue_anchors:A-mmio-irqhandler | mmio-containment-80d5a | status: confirmed_static → missing; target_entity_id: f815a4 → null |
| sc-mmio-cont-80e16 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80e16 | status: missing → confirmed_static; target_entity_id: null → f80e14 |
| sc-mmio-cont-80e1c | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80e1c | status: missing → confirmed_static; target_entity_id: null → f80e14 |
| sc-mmio-cont-80e3a | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80e3a | status: missing → confirmed_static; target_entity_id: null → f80e28 |
| sc-mmio-cont-80e4e | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80e4e | status: missing → confirmed_static; target_entity_id: null → f80e28 |
| sc-mmio-cont-80e7e | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80e7e | status: missing → confirmed_static; target_entity_id: null → f80e6c |
| sc-mmio-cont-80eba | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80eba | status: missing → confirmed_static; target_entity_id: null → f80eac |
| sc-mmio-cont-80eca | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80eca | status: missing → confirmed_static; target_entity_id: null → f80eac |
| sc-mmio-cont-80ed2 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80ed2 | status: missing → confirmed_static; target_entity_id: null → f80eac |
| sc-mmio-cont-80eda | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80eda | status: missing → confirmed_static; target_entity_id: null → f80eac |
| sc-mmio-cont-80ee6 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80ee6 | status: missing → confirmed_static; target_entity_id: null → f80eac |
| sc-mmio-cont-80ef2 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80ef2 | status: missing → confirmed_static; target_entity_id: null → f80eac |
| sc-mmio-cont-80efe | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80efe | status: missing → confirmed_static; target_entity_id: null → f80eac |
| sc-mmio-cont-80f0a | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-80f0a | status: missing → confirmed_static; target_entity_id: null → f80eac |
| sc-mmio-cont-81022 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-81022 | status: missing → confirmed_static; target_entity_id: null → f80fac |
| sc-mmio-cont-81044 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-81044 | status: missing → confirmed_static; target_entity_id: null → f81044 |
| sc-mmio-cont-81054 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-81054 | status: missing → confirmed_static; target_entity_id: null → f81052 |
| sc-mmio-cont-8131c | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-8131c | status: missing → confirmed_static; target_entity_id: null → f81234 |
| sc-mmio-cont-8147c | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-8147c | status: missing → confirmed_static; target_entity_id: null → f81478 |
| sc-mmio-cont-815aa | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-815aa | status: missing → confirmed_static; target_entity_id: null → f815a4 |
| sc-mmio-cont-815b0 | relation_fact / relation_fact_mismatch | findings:F-mmio-containment | mmio-containment-815b0 | status: missing → confirmed_static; target_entity_id: null → f815a4 |
| sc-path-init-adcdisable | static_call_path / broken_explicit_path | findings:F-static-paths | call-80bd2 | target_function_id: f8106c → f81052 |
| sc-path-init-adctiming | static_call_path / broken_explicit_path | findings:F-static-paths | call-80bdc | target_function_id: f81052 → f81044 |
| sc-path-pinmode-pioconf | static_call_path / broken_explicit_path | findings:F-static-paths | call-8125a | target_function_id: f80db0 → f8106c |
| sc-vec-11 | relation_fact / relation_fact_mismatch | findings:F-vec-table | vector-11 | target_entity_id: f81174 → f81176 |
| sc-vec-27 | relation_fact / relation_fact_mismatch | findings:F-vec-table | vector-27 | target_entity_id: f81084 → f81094 |
| sc-vec-28 | relation_fact / relation_fact_mismatch | findings:F-vec-table | vector-28 | target_entity_id: f81094 → f810cc |
| sc-vec-29 | relation_fact / relation_fact_mismatch | findings:F-vec-table | vector-29 | target_entity_id: f810cc → f81104 |
| sc-vec-30 | relation_fact / relation_fact_mismatch | findings:F-vec-table | vector-30 | target_entity_id: f81104 → f8113c |
| sc-vec-33 | relation_fact / relation_fact_mismatch | findings:F-vec-table<br>issue_anchors:A-vec-uart | vector-33 | target_entity_id: f80abc → f80ad0 |
| sc-vec-34 | relation_fact / relation_fact_mismatch | findings:F-vec-table<br>issue_anchors:A-vec-uart | vector-34 | target_entity_id: f80ad0 → f80adc |
| sc-vec-56 | relation_fact / relation_fact_mismatch | findings:F-vec-table | vector-56 | target_entity_id: f80f34 → f81084 |

## B2 错误映射与新观察

以下“未出现”只指**失败 referenced-support 索引**，不能当作对未保存 Firmware prose 或两个错误 orphan 的证明。

| 检查点 | Safe typed diagnostic 结论 |
|---|---|
| call-80f88 | 未出现在失败索引；无法说本次具体生成了何种非失败/orphan 描述，更不能回推 R2 |
| call-80f88 被改成 direct_call→f80eac | 本次失败索引没有这种错误 |
| UART call-80abe/80ad2/80ade/80aea 被改成 direct_call | 未出现在失败索引；vector-33/34 的 UART-related target ID 错误是另一类事实错误 |
| SystemInit read→write | 没有 direction mismatch；八站点出现的是 **containment confirmed→missing** 的错误，与读写方向无关 |
| vector-1 misuse | 未出现在失败索引；有 vector-11/27/28/29/30/33/34/56 的 target ID 错误 |
| trigger→handler | 失败索引无此 claim type；referenced unsupported=0；不能由省略的 orphan 内容推断模型从未生成相关文本 |
| runtime/physical/vulnerability prose | 本次没有 accepted report，诊断不含这些 prose；不作内容审计结论 |

新观察到的具体错误模式：

1. **调用目标 ID 重述错误（3 项）**：保持正确 relation kind/status/source，却改写 target。
2. **MMIO containment 状态/目标反置（23 项）**：3 个 missing 被改成 confirmed→f815a4；
   其余 20 个 confirmed 被改成 missing/null，包括 SystemInit 八站点。
3. **错误端点传播到显式路径（3 项）**：使用正确 edge ID，却期待 edge 不到达的 target。
4. **vector 目标 ID 错配（8 项）**：dispatch kind、vector index 和 binding status 均正确，target 错误。

这是新获得的 typed 错误证据，并非新增 checker reason categories：实际 reason 仍是已有
relation_fact_mismatch 和 broken_explicit_path。若干相邻 vector targets 的值呈错位模式，
但诊断不能证明模型内部产生错误的机制，也不能据此断言 lossless projection 有 bug。

## 与历史比较及结论边界

| 阶段 | 可确认结果 |
|---|---|
| B3 pilot | schema FAIL；未进入 support gate |
| B3-R1 | schema PASS；unused support 拒绝；尚未逐条评估 |
| B3-R2 | schema PASS；全部评估；至少一个 referenced incompatible；具体 IDs 未保存 |
| B3-R3 | schema PASS；全部评估；37 referenced incompatible，完整 safe typed failure index 可审计 |

R3 解释了**本次**报告失败的具体机制，并提供 R2 同类问题的实证例子；
不能恢复 R2 的原始响应，因此不能声称这 37 项就是 R2 的失败项。
R2→R3 接受政策、输入、prompt、schema、provider 设置保持一致，仅增加诊断。
远端服务和单次生成仍可能变化；R3 不是对 R2 错误列表的严格重放。

本次已展示这个模型响应对明确静态事实的重述存在可定位错误，机器 gate 正确拒绝。
当前没有证据要求修改 checker 或继续提高 token budget，也没有必要仅为了获得一次 PASS 连续打补丁。
建议先人工审核并冻结这个可解释的负结果；若产品目标要求稳定 accepted B3 报告，再单独设计
有明确假设和评价标准的 B3 binding/representation 实验，不把修正后的数据冒充本次模型输出。

A5 angr 应作为独立的确定性证据扩展阶段规划，不是修复这些已知 target/status 错误的前提，
也不能自动解决模型对现有事实的误读。本轮不运行 angr，不进入 Cross-Layer，不修模型错误。

## 持久化文件

- [failure.json](../../output/fuzzware:heat-press:scenario-13/db343655-ddd8-4b69-8dec-4d0149e38abf/failure.json)：1233 bytes；SHA256 `7fa9d2ebb0dc3a113fb6c50ec228df6bbca86bed939bd913260673ca414a2133`
- [firmware_relation_support_failure.json](../../output/fuzzware:heat-press:scenario-13/db343655-ddd8-4b69-8dec-4d0149e38abf/firmware_relation_support_failure.json)：57213 bytes；SHA256 `2760b484c98900558ac4b07760826ec1796f61118d6f1b7a377ec1d4656be8db`
- [invocation_attempts.jsonl](../../output/fuzzware:heat-press:scenario-13/db343655-ddd8-4b69-8dec-4d0149e38abf/invocation_attempts.jsonl)：1544 bytes；SHA256 `a88fc47714032b0541ab3f30f63245d949adc96c218b4266ac76a2b22ac544e7`

失败目录恰好三文件。没有 analysis_run.json、firmware_analysis_report.json、firmware_relation_support.json、
analysis_input.json 或 invocation.json，没有 accepted ProcessorBehaviorIR；原 deterministic A1 输入仍为 55 behaviors。
无 raw provider output、无 reviewed export、无第二次调用。

## 最终保全检查

所有源码与 API 前快照一致；61 个历史 output 文件及所有旧研究/架构文档逐字节不变。
新增 output 仅同一新 run 的三份失败文件，attempt_index=1 的 started/failed 两条记录；
reviewed 子目录仍只有 v3-1b1。最终 git diff --check 通过。未 add/commit/push/tag。
