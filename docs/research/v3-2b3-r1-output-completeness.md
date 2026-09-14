# V3-2B3-R1 — Structured Output Completeness & Output-Budget Patch

稳定 Git 基线仍为 `v3-2a4-stable` / `4876d81057518a1f0280dbd8edb96a7d4b4f2d8c`。
在当前未冻结的 B3 工作区继续实施，没有 reset 或撤销 B3 有效实现。

## 实验边界

原 B3 pilot `a8b049f2-16f4-465c-8d93-8fc618540f0d` 使用 8192 输出预算，
实际 output 8192 tokens，在 structured-output parsing 失败，未进入 relation-support gate。
旧日志没有 finish_reason，因此原结果不能单独确认 JSON 被截断。
原记录保持不变，见 [B3 pilot 文档](v3-2b3-structured-relation-claims.md)。

B3-R1 是新的 corrected output-budget experiment，不是对旧 run 的 retry。
只改变 relation_v3 的 max_tokens 为 16384，并增加安全完成状态诊断。
不修改 prompt、model schema、投影、支持关系语义、A4 builder/checker 或 domain contracts。
所有旧样本、历史输出和 reviewed snapshots 保持原样。本轮不 reviewed-export。

## 输出预算策略

`DeepSeekConfig.max_tokens` 全局默认仍是 8192。
Firmware runner 在 `relation_v3` 模式使用 `dataclasses.replace` 构造独立配置，
以 `B3_RELATION_MAX_TOKENS = 16384` 显式覆盖，不修改调用方传入的配置。

| 模式 | 默认运行有效 max_tokens |
|---|---:|
| v1 | 8192 |
| enriched_v2 | 8192 |
| relation_v3 | 16384 |

其余真实配置不变：deepseek-flash、temperature=0、thinking=disabled、
max_retries=0、function_calling、strict=false、timeout=180 秒。
Relation v3 的 started/failed/succeeded attempt record 与成功 invocation 均记录有效预算。
Exporter 验证新 relation_v3 的 16384 设置，并核对带预算的 attempt 与 invocation 一致；
旧 v1/v2 和历史不含新诊断字段的日志仍能解析。

## 安全完成诊断

`StructuredReportRuntime` 仅从已返回的 AIMessage metadata 读取 finish_reason：
stop、length、tool_calls、content_filter、unknown。其他返回值归一为 unknown，缺失则不添加。
不保存整个 metadata、AIMessage、工具参数、partial JSON、header 或 provider body。

失败时可记录 `structured_output_parse_stage`：

- `pydantic_validation`：直接得到 Pydantic ValidationError；
- `malformed_tool_arguments`：直接 JSONDecodeError，或 AIMessage 有 invalid_tool_calls；
- `missing_structured_result`：没有解析错误对象但缺少 structured result；
- `unknown`：其余不能可靠分类的情况。

仍保留大类 `structured_output_parsing / schema_or_tool_response`；不读取异常消息来猜原因。
这些字段仅辅助诊断，接受/拒绝逻辑、evidence hydration 和 relation-support 语义保持不变。

## 大型 fake structured-output 回归

新增合法 model-facing JSON：**102496 字符**。不是 tokenizer 的 8K/16K 等价模拟。
包含 40 findings、40 paths、40 reachable behaviors、40 anchors，共 160 个 Firmware items。
只创建两个 support claims：一个 relation fact、一个显式 static-call path，
每个均由全部 160 个 items 共享引用，无须逐项复制 support。

经真实 LangChain fake model 的 structured parser、ModelFirmwareAnalysisReportV2、
relation-support gate、evidence hydration、canonical FirmwareAnalysisReport 和 IR 合同完整通过；
最后一条完整 summary 保持一致，证明这条路径没有内部 8K 字符截断。

新增测试另覆盖三模式有效预算、配置不变性、finish_reason allowlist、安全 parse 分类，
以及失败时只保存两份安全日志且只调用一次 provider。沿用全部 B3/A4 support 拒绝回归。

## 冻结语义身份

| 内容 | SHA256 |
|---|---|
| Prompt v2 SYSTEM_PROMPT UTF-8 文本 | `10573f3efba97bed7a44d491e4915197f57d771e90b4143248bf19842b685bff` |
| ModelFirmwareAnalysisReportV2 canonical JSON schema | `512974761886482b973ed4230e02f6aa56be9812b3a62be1588e0aa0bb516248` |
| A1 v1 | `48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803` |
| A3 v1 | `4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304` |
| B2 envelope v2 | `6afef3295f8c54ee7fef65446db0a91169ee833d3ede4314e38e45ca0d7c5016` |
| A4 v1 | `fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902` |
| Relation projection v1，16824 chars | `f65dd1b99fc621fb6ccda0e45d7254a233351185258d820d8736949c74c635b2` |
| Envelope v3，56523 chars | `b7722ef471a05bd7e83e2042ae2ac7a4ed125b01a5aeb624581ea1994994adab` |

Schema identity 使用 `json.dumps(model_json_schema(), sort_keys=True, separators=(',', ':'))`。
R1 fresh preparation 增加以上 prompt/schema/projection/envelope pins，任何变化均拒绝 API。
原 A1/A3/A4 hashes、131 relations 的六类计数、174-entry registry、0 runtime observations，
以及 call-80f88、call-80afa、UART branch、SystemInit 八 reads、vector-1 pins 继续检查。

## 验证顺序与实际结果

首先执行全量 pytest、pip check、compileall 和 git diff --check。
全部通过后显式运行四 artifacts → A1 → fresh Ghidra A2 → A3 → A4 → relation projection → envelope v3。
不加载保存的 A4/projection 作为生产事实。
然后仅执行一次新 run ID 的真实 deepseek-flash 调用；任何 transport/schema/support/grounding 失败均停止。

API 前验证：

```text
新增 capacity/diagnostics tests: 18 passed in 2.78s
pytest -q: 737 passed, 12 skipped in 18.14s
python -m pip check: No broken requirements found.
python -m compileall -q src tests: exit 0
git diff --check: exit 0
```

与本轮开始时的文件哈希核对，以下源码 byte-identical：

| 文件身份 | SHA256 |
|---|---|
| Prompt v2 文件 | `545b8b3e872ce531bdb2d7f4821a77baad6204ebc663d66c9963522f926a8893` |
| Model schema v2 文件 | `bae3380cee5c6ddd988c05b9262ac2af00e05e2552d9855f9127d8b3ef74b513` |
| B3 support checker 文件 | `029fe87223dbacc3071d7eb0d607603ce2417bad744ff3748a93ccc3c0af5b2b` |
| A4 claim checker 文件 | `5841acd402b73bc37a9c7464aac0986050ce42831a56d9e843069f7925638e0f` |

57 个既有 output 文件逐字节不变。原 B3 pilot 文档也未改写。


Fresh deterministic preflight 与真实关系 fake-model 回归：**1 passed in 17.79s**。
全部 131 条关系保持，reasoning union=174，runtime observations=0；
6 项正确 relation facts 通过、14 项错误控制转移/向量/MMIO 声明拒绝。
投影 16824 chars、envelope 56523 chars 及其 SHA256 与 pilot 完全一致。

## 实际 R1 结果：Outcome C

新的 corrected output-budget run ID：`759757ba-92ba-420d-ae25-3f9595d91159`。
这是独立新实验，attempt_index=1，不是旧 pilot 的 retry。
本轮 provider call **1 次**，retry **0 次**。

| 指标 | B3 pilot | B3-R1 |
|---|---|---|
| max_tokens | 8192 | **16384** |
| input tokens | 20488 | **20488** |
| output tokens | 8192 | **14112** |
| total tokens | 28680 | **34600** |
| safe finish_reason | 未记录 | **tool_calls** |
| structured parsing | 失败 | **通过** |
| support validation | 未进入 | **进入，拒绝** |
| safe reason | schema_or_tool_response | **unused_support_claim** |
| evidence hydration | 未执行 | 未执行 |
| canonical accepted run | 无 | 无 |

这符合预设 Outcome C：输出已通过 schema，B3 support gate 实际执行并拒绝模型输出。
此处失败发生在 support 引用完整性检查：至少一个生成的 support claim 没有被任何
Firmware finding/path/reachability/anchor 引用。按照冻结规则，unused support 不能被丢弃后接受。
不修改 prompt/schema/projection，不删除模型多余 support，不放宽 checker，不重跑。

**逐条 relation fact / static path compatibility checks 尚未执行。**
`validate_relation_support` 在构建引用映射后先拒绝 unused claims，随后才评价各 support 的 typed relation。
因此不能由这个失败类别推断已有 support 全部 supported，或模型没有复现 B2 的错误。
Evidence hydration 在 support gate 返回成功后才执行，本次没有执行。

### 完整安全 failure.json

```json
{
  "case_id": "fuzzware:heat-press:scenario-13",
  "run_id": "759757ba-92ba-420d-ae25-3f9595d91159",
  "attempt_index": 1,
  "timestamp": "2026-09-14T13:12:19.177294+00:00",
  "provider": "deepseek",
  "model": "deepseek-flash",
  "prompt_id": "firmware-security-agent",
  "prompt_version": "v2",
  "context_sha256": "b7722ef471a05bd7e83e2042ae2ac7a4ed125b01a5aeb624581ea1994994adab",
  "status": "failed",
  "max_tokens": 16384,
  "category": "relation_support_validation",
  "failure_category": "relation_support_validation",
  "reason_code": "unused_support_claim",
  "exception_type": "RelationSupportError",
  "usage": {
    "input_tokens": 20488,
    "output_tokens": 14112,
    "total_tokens": 34600
  },
  "response_metadata": {
    "finish_reason": "tool_calls",
    "id": "60d5c93c-1c2e-4105-a9d8-8a31e7c2b027",
    "model_name": "deepseek-flash"
  },
  "diagnostics": [
    {
      "exception_type": "RelationSupportError"
    }
  ]
}
```

### Claim index 与 B2 审计范围

Schema 确实通过，但整个 typed model response 在 support gate 拒绝后未持久化。
遵循本轮失败输出白名单，仅保留 failure.json 和 invocation_attempts.jsonl；
没有保留 rejected structured arguments、partial JSON 或任意模型正文。
因此无法安全恢复 Firmware claim index、support claim IDs/数量或引用表，不能伪造索引。
唯一可确认的模型引用问题是：**存在至少一个 unused support claim**。

| B2 回归点 | Fresh deterministic / fake regression | 本次真实模型解释 |
|---|---|---|
| call-80f88 | unresolved/indirect_call/blx；错误 confirmed call 拒绝 | 未保存可审计报告，无法确定 |
| call-80afa | f80af4→f80eac confirmed direct_call | 无法确定 |
| UART b.w family | confirmed direct_branch；direct_call 拒绝 | 无法确定 |
| SystemInit 八站点 | ldr/read；write 声明拒绝 | 无法确定 |
| vector-1 | Reset dispatch；不证明函数调用 | 无法确定 |
| trigger/runtime/physical | 静态事实不能支持相应正向 claim | 无法确定 |

Support gate 已进入，故可以确认**引用完整性 gate 生效**；
它提前停止，不能把未执行的单条关系检查写成成功或失败。

### 输出路径与 SHA256

- [failure.json](../../output/fuzzware:heat-press:scenario-13/759757ba-92ba-420d-ae25-3f9595d91159/failure.json)
  SHA256：`1b338202e22e27415cb9a23345e70672ba31d74ad6eddf50f86e774134e0e31a`
- [invocation_attempts.jsonl](../../output/fuzzware:heat-press:scenario-13/759757ba-92ba-420d-ae25-3f9595d91159/invocation_attempts.jsonl)
  SHA256：`222debf38c0362c94f8a7ce3bcd4369bd77f3a6d88222ac57b221531830c73bf`

没有生成 analysis_run.json、firmware_analysis_report.json、firmware_relation_support.json、
analysis_input.json 或 invocation.json。失败记录中的 context SHA 与 preflight 相同；
有效预算在 started/failed 两条记录均为 16384。未 reviewed-export。

## 解释与下一步

结果**增强输出预算不足假设**：相同 prompt/schema/context 下，新响应正常结束于 tool_calls，
生成 14112 tokens（超过旧 8192 上限、低于新 16384 上限），并通过 schema。
但旧 pilot 没有 finish_reason，不能据此回溯断言旧 provider 一定截断 JSON。
这是一次配对实验观察，不是对所有解析失败原因的普遍证明。

目前 B3 已越过本次 structured-output 完整性问题，尚未产生 canonical accepted report。
可以人工审查 unused-support 引用完整性这一结构性问题，但没有足够保存内容开展逐条报告语义审计。
建议下一步仍是 **B3 support/reference review**，由人工决定后续独立补丁；
先让模型按冻结合同正确使用其生成的 support claims，再讨论 A5/angr。
本轮不实施 prompt/schema 调整，不删除 unused support，不重新调用模型，也不运行 angr。
