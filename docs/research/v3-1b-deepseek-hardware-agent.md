# V3-1B — Real DeepSeek Hardware Security Agent Integration

在 `v3-1a2-stable` 基线上接通真实 HardwareSecurityAgent。
2026-09-12 完成 driver/743 与 driver/820 的真实 DeepSeek 调用、Pydantic/post-check 校验和持久化。
仅接通 Hardware Agent；未进入 V3-1C、V3-2 或 Cross-Layer 集成，未新增 deterministic parser。

## Integration 与配置

使用官方 [langchain-deepseek / ChatDeepSeek](https://docs.langchain.com/oss/python/integrations/chat/deepseek)。
直接依赖新增 `langchain-deepseek>=1.1,<1.2`、`python-dotenv>=1.1,<2`。
后者仅为显式读取指定 `.env`，使用 `dotenv_values(..., interpolate=False)`，不发现其他文件、
不修改 os.environ、不在 import 时加载。没有自行编写 HTTP client、provider registry、retry transport 或 JSON repair。
`langchain-openai` 与 `openai` 是 integration 的传递依赖，不是 ChipChain 的直接依赖。

真实模型配置为 **deepseek-v4-pro**，temperature **0**、max_tokens **8192**、timeout **180s**、
max_retries **0**、streaming **false**、thinking **disabled**。
模型名来自 integration config，HardwareSecurityAgent 内没有 DeepSeek/model name。
可通过 `CHIPCHAIN_HARDWARE_MODEL=deepseek-v4-flash` 切换，而不修改 Agent。
本次 `.env` 中已有模型值未通过标识校验，因此命令显式设置任务要求的 `deepseek-v4-pro`；
未输出该未识别值或凭据，未覆盖用户已有 `.env`。之后仍建议使用下方一致的运行方式。

官方 [DeepSeek tool calls](https://api-docs.deepseek.com/guides/tool_calls/) 支持函数调用；
本次复用 `BaseChatModel.with_structured_output(HardwareAnalysisReport, method="function_calling", include_raw=True)`。
不使用 `create_agent`，不启用 strict=True，不切换 json_mode，也没有 tool execution loop。
首次成功请求已验证现有 schema 与该路径兼容；这不表示 API 或生成输出永不失败。

## 显式真实运行

从 repository root 执行。先在本地配置被 Git 忽略的 `.env`（不要在聊天或命令行打印 key）：

```text
DEEPSEEK_API_KEY=<在本地填写>
CHIPCHAIN_HARDWARE_MODEL=deepseek-v4-pro
```

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 CHIPCHAIN_HARDWARE_MODEL=deepseek-v4-pro \
  .venv/bin/python -m chipchain.integrations.deepseek_hardware \
  --env-file .env --sample /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743

CHIPCHAIN_ENABLE_REAL_LLM=1 CHIPCHAIN_HARDWARE_MODEL=deepseek-v4-pro \
  .venv/bin/python -m chipchain.integrations.deepseek_hardware \
  --env-file .env --sample /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/820
```

环境变量覆盖所选文件值。只有进程环境中的 explicit opt-in 启用网络；即使 `.env` 写有 enable=1
也不能独自启用调用。未 opt-in 在读取 `.env`/corpus 前返回配置错误；缺 key 返回固定配置错误。
本次用户明确回复“已配置，执行 743 和 820 真实调用”之后才开始真实调用。
默认 pytest 的 socket/subprocess guards 保持，且移除真实 DeepSeek key 和 opt-in，真实调用使用独立 CLI。

## Secret 与 persistence

`.env` 初始以 0600 创建；`.gitignore` 包含 `.env`、`.env.*` 和 `!.env.example`。
可提交的 `.env.example` 只有空 key 和默认配置。凭据用 SecretStr 包装，不进入 model descriptor。
真实入口关闭 tracing 和 transport logging；如果 LangChain debug/verbose 已开启则拒绝构造。
异常只输出固定消息；failure.json 只保存原因码、数值 usage、异常类型、HTTP status/校验类型等安全诊断，
不保存异常正文、response body、Pydantic input/context 或认证配置。
发送 context 前、写入文件前均检查真实 key 不在待发送/持久化文本中。

每次调用前独占创建 `output/<case_id>/<UUID>/`；所有文件使用 exclusive create，不覆盖原 run。
成功必须写入：

- `analysis_run.json`：已有 AnalysisRun schema，case/run ID、UTC timing、阶段、model/prompt/runtime provenance。
- `hardware_analysis_report.json`：经过 Pydantic、Agent 引用及 real grounding gate 的正式报告。
- `analysis_input.json`：实际 bounded host-only context，便于复核；不是原始 VCD/RTLIL/log。
- `invocation.json`：allowlisted model settings、token usage、input digest/counts、stub IR comparison。

失败目录只记录 failure.json，不把未经校验的 raw response 当作正式结果；目录保留供审核。
所有真实结果均位于 Git-ignored output，离线 pytest 只在 pytest temporary directories 验证 writer。

## Prompt 与 post-validation

hardware prompt 从 v1 升为 **v2**（ID 仍为 `hardware-security-agent`），Firmware/Cross-Layer 保持 v1。
新增通用规则：编码不等于执行/退休，mutation 不等于漏洞，divergence 不等于已验证因果；
不补造 trace/instruction/register values；异常状态须有证据；引用完整复制已有 EvidenceRef；
trigger 保持 hypothesized/inferred；信息不足写 unresolved questions。没有任何 743/820、寄存器、
mnemonic 或 cover 名称等样本答案进入 system prompt。真实尝试之间未改变 prompt 来美化结果。

已有 behavior/case ID 与候选状态校验保留。发现此前 Hardware Agent 没有输入 EvidenceRef 全字段
对照检查，因此本轮补齐：未知 ID、同 ID 改 summary/location/status、未知 finding ID 均明确失败。
真实入口还要求 findings/hypotheses/abnormal states 引用 evidence；存在 input behaviors 时须引用相关 ID；
模型不得自行 verified，trigger status 只允许 hypothesized/inferred。旧 domain schema 不因此大改。
校验不会自动删引用、补字段或重写响应，也不能自动证明自然语言结论被 evidence 蕴含，仍需人工审核。

## 输入与 oracle 隔离

```text
EnCorpusIbexDriverAnalyzer.ingest
→ A1 analysis_input() host-only projection
→ A2 RiscVInstructionDecoder.enrich
→ HardwareSecurityAgent(model=ChatDeepSeek)
→ validated report + unchanged deterministic IR
→ explicit AnalysisRun mapping and persistence
```

743 的 raw ingestion 确实有 mutation/formal/local/GPR oracle，但它们没有进入上述模型投影。
743 实际模型输入只有三条 host ID instruction observations 及其解码、原 EvidenceRef、case/target、
VCD artifact provenance 和 A1 unresolved limitations；**没有 x28/x10 architectural differences**。
820 的模型输入没有有效 instruction observation，也没有 mutation/formal/waveform oracle。
不能要求模型“识别”这些不可见事实，否则等于要求它猜 benchmark answer。

两个 local projection tests 确认全部 observation role=analysis_input、oracle observation IDs 不在 context，
没有 reference_driver.rtlil/verify.log/raw VCD 内容。成功运行后另从 corpus 重新生成投影，
逐字比对落盘 analysis_input.json 并核对 SHA-256，两者一致。
743 context **21264 characters / 3 observations / 3 behaviors**；820 **701 / 0 / 0**，均低于 64000 字符限制。
同一个 input 先经 stub 再经真实 Agent，input JSON 和 deterministic IR 完全一致，仅 reasoning report 不同。

## 743 真实结果与人工审核

成功 run ID：`cbbc76b9-ffc0-43ca-8f97-0bc9657e796b`。
目录：`output/encorpus:ibex:driver:743/cbbc76b9-ffc0-43ca-8f97-0bc9657e796b/`。

| 项目 | 实际结果 |
| --- | --- |
| Findings | 1：三个不同时刻 30/40/50 ns 的 host ID 编码被观察到，valid/executing signals 存在；不建立 retirement/commitment |
| Trigger hypotheses | 0；没有把编码序列提升为 trigger |
| Abnormal states | 0；没有虚构寄存器值或差异 |
| Behavior IDs | 三个原 `id-encoding:30/40/50:instruction` ID |
| Unresolved | 保留 A1 限制；缺 retirement/commitment、register/memory values、miter divergence evidence |
| Usage | input **10187** / output **970** / total **11157** tokens |

finding ID 为 `encorpus:ibex:driver:743:f1`，epistemic_status=derived。
三个引用均完整匹配输入，EvidenceRef IDs 为：

```text
encorpus:ibex:driver:743:proof.vcd:e:393223ad51c2f08c34c5
encorpus:ibex:driver:743:proof.vcd:e:517913821aa2738905bc
encorpus:ibex:driver:743:proof.vcd:e:73de2b2c636d91cda059
```

人工审核问题：

| 问题 | 结论 |
| --- | --- |
| 是否理解 addi/lui/lw 三条解码？ | 输入确有三条解码，但报告只总结观察时刻，没有解释 mnemonic/operands；不能据此确认语义理解能力 |
| 是否区分 mutation 与 trigger？ | 未获 mutation oracle，也未生成 trigger；本次不足以评估 mutation 因果推理能力 |
| 是否识别 x28/x10 差异？ | 差异未提供，报告未虚构；这是隔离符合预期，不是模型识别失败 |
| 是否虚构执行/退休？ | 未发现；明确声明缺 retirement/commitment evidence |
| 是否过度解释 EVS053/cover？ | 未提及，模型也未接收这些 oracle |
| 是否保持 hypothesis？ | 未生成 hypothesis，不能借空列表宣称已验证真实 hypothesis 生成质量 |
| 是否询问 harness/replay？ | 743 没有明确补充这两项，仅列缺 stage/value/divergence；完整性仍不足 |

## 820 真实结果与人工审核

成功 run ID：`052f4061-ba4c-4155-a067-efdd538e021c`。
目录：`output/encorpus:ibex:driver:820/052f4061-ba4c-4155-a067-efdd538e021c/`。
findings、trigger_hypotheses、abnormal_states、processor_behavior_ids 均为 **[]**。
没有 evidence references，因为输入为空且没有生成 claims。
unresolved 明确保留“未提取到有效 host ID encoding”，并指出缺 trace、stage、harness 和 replay constraints。
没有补造指令、寄存器值或假定 instruction sequence 存在。
usage：input **3513** / output **243** / total **3756** tokens。

报告同时回显 A1 的固定 limitation，例如 ID-stage encoding changes 的一般边界。
这类模板文字不应被解读为 820 本身已有指令事件；更合适的质量目标是让摘要清晰区分一般限制和样本事实。
“no evidence exists”也应仅在本次 supplied projection 范围内理解，不能推广到完整 corpus。

## 失败尝试与质量限制

本次共执行 **5 次显式 CLI 调用尝试**：743 四次、820 一次；SDK automatic retries=0。

| Sample / run ID | 结果 |
| --- | --- |
| 743 / `85872a32-39fe-469e-8dd8-abe1ee596eed` | structured_output failure；最初诊断仅记录类别，没有正式 report |
| 743 / `aa4ddde0-dc99-4006-b4b6-7da114c23a46` | execution_or_persistence failure；没有正式 report |
| 743 / `baf27a81-c61e-4160-9b85-23b358edff4a` | provider_invocation failure；没有 HTTP status/usage 可供判断 |
| 743 / `cbbc76b9-ffc0-43ca-8f97-0bc9657e796b` | validated + persisted |
| 820 / `052f4061-ba4c-4155-a067-efdd538e021c` | validated + persisted |

失败后的更改只补充安全诊断，未放宽 schema、证据检查或修改 prompt，未使用 JSON repair/json_mode。
前三次未保存 raw response，无法回溯确定失败根因，也无法判断首个被拒绝输出是否含 unsupported claims。
不能把后续成功解释为已证明修复了某个 provider/schema bug。
失败尝试的 token usage 未知；两次成功合计 **14913 tokens** 不是整个尝试过程的完整计费总量。
没有为获取更漂亮结论额外重跑成功样本，没有批量调用其他 corpus。

对两份已接受报告，未发现虚构 evidence/register/instruction、越过 execution/retirement 边界或 oracle 泄漏。
最大的质量问题是**保守而浅的摘要、模板限制回显，以及没有充分使用 decoded operands**；
本次没有真实 trigger hypothesis，因此无法声称已经证明 Hardware Agent 的 trigger 推理质量。
schema/引用验证通过不等于安全结论被证明，更不等于硬件漏洞确认。

## Provenance 与 fresh environment

两份 AnalysisRun 的 hardware model descriptor 均为 hardware / deepseek / deepseek-v4-pro / real，
hardware prompt ID/version 为 hardware-security-agent/v2；未配置角色保持 unknown，阶段 not_applicable。
Capstone descriptor 复用 A2；runtime_packages 扩展既有字典记录 integration 的发行版本，不新增 domain schema。
usage 保存在 invocation.json，不加入 HardwareAnalysisReport，不保留 raw response/model authentication config。

创建 `/tmp/chipchain-v3-1b-fresh-3vzcq8u2`，以 `python -m pip install '.[test]'`
从 pyproject 构建安装非 editable wheel。之后重新安装最终源码 wheel，再对 installed package 执行离线测试。
`python -I` 从 /tmp 验证 import ChatDeepSeek 和 ChipChain integration，确认模块来自 site-packages。
fresh 环境未重复产生真实 API 费用。

| Dependency | 当前环境 | Fresh 环境 |
| --- | --- | --- |
| Python | 3.12.13 | 3.12.13 |
| langchain-deepseek | 1.1.0 | 1.1.0 |
| langchain-openai（传递） | 1.6.2 | 1.6.2 |
| openai（传递） | 3.13.0 | 3.13.0 |
| python-dotenv | 1.2.3 | 1.2.3 |
| langchain | 1.2.10 | 1.2.10 |
| langchain-core | 1.6.2 | 1.6.3 |
| langgraph / prebuilt | 1.0.10 / 1.0.8 | 1.0.10 / 1.0.8 |
| capstone | 5.0.9 | 5.0.9 |
| pydantic | 2.13.4 | 2.13.5 |
| pytest | 9.1.1 | 9.1.1 |

## 验证命令与覆盖

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
git check-ignore .env
git status --short --untracked-files=all

CHIPCHAIN_ENCORPUS_IBEX_ROOT=/home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex \
  .venv/bin/python -m pytest -q tests/integration/test_encorpus_local.py

/tmp/chipchain-v3-1b-fresh-3vzcq8u2/bin/python -m pytest -q -o pythonpath=
/tmp/chipchain-v3-1b-fresh-3vzcq8u2/bin/python -m pip check
```

原 220 项离线测试保留；prompt provenance 断言相应更新为 hardware=v2，其余=v1。
新增 25 项 offline tests，包括 factory、key/config、opt-in、secret/import 边界、实际 ChatDeepSeek
tool binding + Pydantic parser、未知/篡改 evidence、finding refs、real status gate、stub IR 相等、
mandatory persistence、collision-before-call、response/exception secret 拒绝。
原四项 optional corpus tests 保留，新增两个 host-only model projection checks。
最终结果：

```text
当前环境：245 passed, 6 skipped in 2.87s
Fresh installed package：245 passed, 6 skipped in 3.01s
显式 local corpus tests：6 passed in 3.09s
两环境 pip check：No broken requirements found.
```

compileall、git diff --check 通过；git check-ignore .env 输出 `.env`，Git index 不含 `.env`。
使用实际 key 对 Git 候选文件和所有 runtime JSON 做仅返回通过/失败的扫描，通过；
全部 runtime JSON 都被 Git 忽略。两份 AnalysisRun/report 已从磁盘重新加载并验证 ID、引用与 model/prompt provenance。
默认 suite 始终不读取真实 key、调用 API 或创建 repository output。

正式结果仍须人工审核。本轮不更改 deterministic extraction、不扩展 parser，不实现 Firmware/Cross-Layer 模型、
provider framework、批处理或 billing 系统。未执行 git add/commit/push/tag。
