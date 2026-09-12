# V3-1B.1 — Operational Evidence Projection & Real-Agent Validation

本轮修正 B 的证据投影和调用诊断，不改变核心 Agent、prompt v2、解析器或指令语义。
按用户明确配置使用 **deepseek-flash**，原样读取 `.env`，没有使用需求附件中的 pro override。
2026-09-12 两个样本均产生新的 validated/persisted report，旧 B runs 全部保留。

## 三层边界

| 层次 | 范围 | 模型可见性 |
| --- | --- | --- |
| Benchmark-only answer | 精确 injected RTL mutation location/connection、root cause、mutation family、labels/expected answer | 隐藏 |
| Operational deterministic evidence | 既有工具提取的 selected DUT/reference local/GPR differences、ID encoding、formal cover/error 结果 | 经过明确 projection 可见 |
| Raw benchmark/reference internals | 整份 RTL/golden/reference、patch implementation、完整 VCD/log | 不发送 |

reference 参与对比本身不是隐藏理由。关键是 pipeline 正常可获得的测试结果与已知 benchmark
答案之间的区别。局部状态观察在此 corpus 的 waveform 测试环境中可用，不意味着硅片外部一定可观测。
差异只证明给定波形中的值不等，不证明 cause、漏洞、verified trigger 或原始程序完成执行。
formal cover hit 和 EVS053 作为历史工具输出保留；SVA/reset harness 不完整，未做独立 replay。

## Projection 实现

新增 `tools/hardware/encorpus/projection.py` 的 `build_hardware_analysis_projection`；
原 `EnCorpusIngestionResult.analysis_input()` 委托该函数，real runner 随后继续 A2 enrich。
策略集中在 adapter 层，不散落在 prompt serialization 中。

A1 历史 `oracle` 容器未重构，其内仍混有 benchmark answers 和可投影的比较/工具结果。
不把整个容器直接发给模型；逐条检查 observation kind、deterministic analyzer ID、source artifact
格式/身份以及已支持 signal pair 或 formal property/code。未经认可的来源默认排除。
批准的 observation 仅在副本上把 role 改为 analysis_input，其 details、summary、EvidenceRef、
behavior identity/status/attributes 全部原样保留；不重新解释或生成差异事实。

MutationAnchor 的 analysis_input 仍被 validator 拒绝。删除的是“所有 comparative/formal
kind 都只能属于 oracle”的旧限制。模型输入仍拒绝任何保留 benchmark_oracle role 的对象。
不复制 mutation objects/IR、oracle limitations、artifact role explanations、raw RTL 或 hidden labels。
采用明确的 operational limitations 保留 harness、可观测性、GPR layout 和未知值边界。
`analyze()` 的旧 host-only 接口和 `ingest()` 的确定性 extraction 保持；本轮 real path 使用后者的显式 projection。

formal/local observations 没有自动生成 behavior；它们的模型 findings 可以仅引用 EvidenceRef。
real grounding gate 改为：如果所引用 evidence 对应已有 behavior，须引用相关 behavior ID；
不强迫 formal/local claim 引用同 Case 中无关的 instruction。已有未知证据/behavior/finding ID 检查保持。
不增加 memory/control-flow lifting、新 parser、Firmware 或 Cross-Layer 模型。

## 新 context

| Kind / 数量 | 743 | 820 |
| --- | ---: | ---: |
| INSTRUCTION_ENCODING_OBSERVED | 3 | 0 |
| LOCAL_EFFECT_OBSERVED | 3 | 6 |
| ARCHITECTURAL_PROPAGATION_OBSERVED | 2 | 1 |
| FORMAL_RESULT | 2 | 2 |
| MUTATION_PRESENT | 0 | 0 |
| 总 observations | 10 | 9 |
| Behaviors | 5 | 1 |
| Context characters | 35452 | 16152 |

743 SHA-256：`fd36deab7e5a26435b255fbc57bd548dbd7e50ff5fffa91d1b97703555b063ad`

820 SHA-256：`b10f773a346bfc6e2f33b01d0ce7a2c8fb26925e6b6ea26f5bf93880c77c6d07`

743 保留三条 addi/lui/lw 解码；新增运行证据包含：

- LSU `ls_fsm_ns` 在 50/70 ns、`ls_fsm_cs` 在 60 ns：host=2、reference=0。
- x28 在 50 ns：host=0、reference=1；x10 在 70 ns：host=0x1000、reference=0。
- 历史 cover hit 8 cycles 及独立 EVS053 trace error。

820 仍没有有效 instruction observation。可见证据包含：

- `debug_mode_q` 在 100/230/330/410/490/540 ns：host=0、reference=1。
- x10 在 580 ns：host=0、reference=0x378。
- 历史 cover hit 59 cycles 及 EVS053。

以上均是 A1 已提取结果。未添加波形扫描、instruction guesses 或隐藏 mutation 位置。
context 不在本文整份输出；每个 run 的 analysis_input.json 可本地审查。

## 模型配置与诊断

旧 factory 的正则只接受版本化 model ID，错误拒绝了用户的 `deepseek-flash`。
现在接受规范 DeepSeek 标识以及该 alias，仍拒绝空值、异常字符与两个旧历史名称。
不改名、不自动映射、不修改 `.env`。本次请求与 API 返回的 model_name 都是 **deepseek-flash**，
不能据此宣称其具体 backend revision。正常 `.env` 的 deepseek-v4-pro/flash 也已离线验证可直接使用。
`.env.example` 保留空 key 和 pro 示例；shell override 是可选功能。

真实运行命令：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 .venv/bin/python -m chipchain.integrations.deepseek_hardware \
  --env-file .env --sample /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743

CHIPCHAIN_ENABLE_REAL_LLM=1 .venv/bin/python -m chipchain.integrations.deepseek_hardware \
  --env-file .env --sample /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/820
```

手动技术重试可指定 `--attempt-index 2`，每次仍新 UUID、不自动 retry、不循环调用。
model settings 延续 B：temperature=0、function_calling、strict 未启用、thinking disabled、8192 max tokens。
prompt 内容没有改动，仍为 hardware-security-agent/v2。

每次预先创建独占目录并写 `invocation_attempts.jsonl` 的 started 行，终态另追加一行。
包含 attempt index、UTC timestamp、provider/model、prompt ID/version、context hash、status、usage（如可用）。
失败区分 provider_execution、structured_output_parsing、agent_post_validation，以及 setup/persistence 阶段。
仍使用原异常类，增加安全 failure_category，避免破坏既有 workflow error 分类。
usage 在 parsing check 前提取，因此解析失败也可保留已返回 counters。
API 返回的 ID/model_name 只允许短标识字符，不保存原始 metadata/response/auth 配置。
旧失败文件不追加或回填猜测诊断。

## 真实 attempts 与输出

| Sample | Attempt | Run ID | 结果 |
| --- | ---: | --- | --- |
| 743 | 1 | `8eae2090-1c8b-450c-8d35-3de378a7723b` | 校验并持久化成功 |
| 820 | 1 | `5654af01-03e0-4f9b-b192-ad29b267eebd` | provider_execution；APIConnectionError / ConnectError；usage 未知 |
| 820 | 2 | `a663c6f7-ea28-4929-b788-d059475d28e9` | 校验并持久化成功 |

第二次 820 未修改 prompt/schema/投影或放宽校验，只做明确连接失败重试。
成功目录为：

```text
output/encorpus:ibex:driver:743/8eae2090-1c8b-450c-8d35-3de378a7723b/
output/encorpus:ibex:driver:820/a663c6f7-ea28-4929-b788-d059475d28e9/
```

各包含 `analysis_run.json`、`hardware_analysis_report.json`、`invocation.json`、
`analysis_input.json` 和 `invocation_attempts.jsonl`。失败目录含 attempts 和安全 failure.json。
AnalysisRun 中记录同一 case/run ID、deepseek-flash、prompt v2、runtime 和 projection ToolDescriptor v1。
成功记录确认 stub/real deterministic IR 相等。未覆盖旧 B 743/820 报告或失败记录。

## 新 743 报告审核

4 findings、1 hypothesis、2 abnormal states：

- F1 正确列出三条 decoded instructions 和 30/40/50 ns，明确 ID encoding 不证明 retirement。
- F2 总结 LSU sampled mismatches；F3 正确引用 x28/x10 的时间及两侧值。
- F4 保留 cover 8 cycles/EVS053 与 harness 限制，没有称其为 bug verified。
- H1 将 50 ns 的 load 编码、LSU 差异与 70 ns x10 差异作可能关联，状态 hypothesized，
  明确没有 execution/retirement/causality 证据。没有猜注入位置。
- unresolved 包含 execution/commitment/retirement、因果链接、cover/error 关系、harness 和数据端序等。

usage：input **14421** / output **6488** / total **20909**。
API response ID：`fa742e13-f13c-4215-9b25-e88d3b119fbf`。

**需要人工标记的过度概括：** abnormal state A1 使用 “held ... across 50–70 ns”，
把三个离散的且涉及不同 FSM signals 的比较点写成持续区间。当前投影不能证明两个 signal
在整个区间持续保持该值，不能作为持续时间事实引用。F4 的 “a separate configuration” 也比
当前 formal details 所提供的关系更具体；现有证据只保留两个独立日志事件，configuration 关系未知。
这些问题没有通过修改 prompt 或重跑报告掩盖，原始 validated report 保留供审核。

## 新 820 报告审核

3 findings、1 hypothesis、2 abnormal states：

- F1 正确列出六个 debug_mode_q sampled differences；F2 正确描述 580 ns x10 两侧值。
- F3 正确描述 cover 59 cycles/EVS053，保留 incomplete harness 和未验证结论。
- H1 将 debug-mode difference 与后续 x10 difference 作 hypothesized association，
  明确缺 instruction trace、harness、replay，不声称已验证 causal chain。
- 没有生成 instruction behavior、mnemonic、指令序列或任何具体执行/退休事件。

usage：input **8026** / output **5167** / total **13193**。
API response ID：`d089c837-bc60-4fb5-a3b1-84cfc42ddd48`。

**仍有措辞和引用粒度问题：** 第一条 unresolved 回显通用 A1 limitation 为
“Host ID-stage encoding changes appear ...”，容易被读作 820 有编码事件，与另一条
“No known valid ... encodings were extracted” 冲突。只能视为一般边界文字，不能作为样本事实。
S1 概述六个时刻，但其自身只引用首末时刻 evidence；完整输入/F1 有六组支持，S1 的引用覆盖仍不完整。
F2 使用 “reads” 描述 register snapshot，虽然随即限定 read/write direction unknown，措辞仍可改进。
保留这些观察，不声称 schema/reference checks 能发现全部语义问题。

## 与 B 对照及完成边界

| 指标 | 743 旧 B → B.1 | 820 旧 B → B.1 |
| --- | --- | --- |
| Observations | 3 → 10 | 0 → 9 |
| Behaviors | 3 → 5 | 0 → 1 |
| Findings | 1 → 4 | 0 → 3 |
| Hypotheses | 0 → 1 | 0 → 1 |
| Abnormal states | 0 → 2 | 0 → 2 |

证据使用明显更具体，候选关联仍是未验证 hypothesis；字段变多不是成功标准。
**同时模型由旧 deepseek-v4-pro 改为用户配置的 deepseek-flash，故这不是受控单变量实验，
不能把全部质量变化归因于 projection。** 两次成功的 tokens 合计 34102，失败 usage 未知。
隐藏 mutation/root-cause markers 的不变性由测试保证；这里指直接 benchmark answer 字段，
不表示改变真实硬件后其 operational waveform 也应不变。

没有发现阻止冻结集成和证据投影机制的新增技术 blocker。
但存在上述自然语言过度概括及引用粒度问题，人工审核不能省略；未验证 trigger/security impact。
本轮停止，不进入 V3-2/V3-5，不规划新 parser 或自动因果验证系统。

## Tests / validation

本轮新增 16 项离线测试：三层投影、隐藏答案不变性、运行证据敏感性、source policy、
empty instruction 保留、model alias/env、三个 failure categories、formal claim 无关 behavior 防护。
更新旧“所有 reference/formal 都隐藏”断言；保持原确定性提取与既有 workflow 测试。
默认 socket/subprocess guards 及 key/opt-in 清理保持，未增加默认真实 API tests。

```text
pytest -q: 261 passed, 6 skipped in 3.05s
explicit local corpus: 6 passed in 3.14s
pip check: No broken requirements found.
compileall / git diff --check: passed
git check-ignore .env: .env
```

真实输出和 `.env` 继续被 Git 忽略；没有 key 进入报告/Git 候选文件。
没有执行 git add/commit/push/tag。完整 Git status 见完成报告；其中仍包含未提交的 B 实现。
