# V3-1B2 — Structured Hardware Relation Claims & Support-Gated Hardware Agent

基线：`v3-1a3-stable` / `a453559971c21a773cec2fba4b2ae8549a890dd1`。
Hardware A3 已冻结。本阶段实现新的显式 supported Agent 路径，保留 legacy invoke、prompt v2、
canonical HardwareAnalysisReport、B.1 projection、旧 runner 和 reviewed snapshot。

## Scientific goal 与 trust boundary

模型生成 item → support_claim_ids → typed support → 冻结 A3 checker → 所有 referenced supports
必须 supported → exact evidence hydration → canonical grounding / epistemic / IR gates。
该 gate 证明事实支持绑定，不证明自由文本 entailment，也不证明 trigger hypothesis 正确。

A3 三个合同模块字节不变，没有新增 RTL/VCD/formal 分析，没有放宽 checker。

| Case | A3 chars | A3 catalog SHA256 |
| --- | ---: | --- |
| 743 | 29316 | `e9f0da2fea7df21b9a028c38b685292895d160ad3b521b77e4bd568cace23753` |
| 820 | 18257 | `5715a6e9a2ad6611c4f8c03767a7da89490ca471cad1030a47fca56de1311dda` |

| Case | Frozen B.1 context SHA256 |
| --- | --- |
| 743 | `fd36deab7e5a26435b255fbc57bd548dbd7e50ff5fffa91d1b97703555b063ad` |
| 820 | `b10f773a346bfc6e2f33b01d0ce7a2c8fb26925e6b6ea26f5bf93880c77c6d07` |

## Projection 与 envelope

`agents/projections/hardware_relations.py` 只接收 HardwareRelationCatalog，重新验证后顺序保留所有 relation，
没有 top-k、ranking、截断或 artifact IO。版本 `hardware-relation-projection/v1`，hard cap 20000 chars。
每行保存 relation ID/kind/status/source observation/evidence IDs/typed attributes/capabilities。

Compact instruction 保留时间、ID stage、signal、raw encoding bits/width/representation，及 decode
status/mnemonic/operand_text/width/decoder descriptor。省略重复 EvidenceRef、backend spelling、operand AST、
decode mode/reason；这些仍保存在冻结 A3 catalog 和原 B.1 context。Formal 省略 raw_result，
保留 property/error/cycles/interpretation_boundary。Local/register 属性原样保留。

`capability_defaults` 明确列出所有能力 false，每行 `capabilities` 仅列 true 覆盖。
结合两者可以精确恢复每行完整 A3 capabilities，包括 execution/commit/retirement=false。
Envelope builder 重建 A3 catalog 并与输入绑定，重建 projection 作逐字节比对，不能删 relation 或伪造能力。

`hardware-analysis-envelope/v2` 把旧 B.1 context 原样保存为 JSON string，另带 relation projection 和 bindings：
case、B.1 SHA、A3 SHA、projection SHA/version。保留原 context 字节，避免嵌入时重序列化改变旧 SHA。
Envelope hard cap 64000 chars，超限 fail closed，不截断任何 evidence/limitation/relation。

## API 前冻结的 model-visible identities

以下身份在首次 API 前记录；743 与 820 使用同一 prompt/schema，实现与配置不得在两例之间修改。

- Prompt：`hardware-security-agent/v3`
- Prompt SHA256：`55f6f1d4fe648923b049538cd772f3018de2f7b505c048033d60e7c9d55ed3f4`
- `ModelHardwareAnalysisReportV2` canonical JSON schema SHA256：
  `525788ea78dcd18e1523ac88decdee0e6d0ccadaad06dfa22f1899ac326f134a`

| Case | Projection chars | Projection SHA256 |
| --- | ---: | --- |
| 743 | 10273 | `d89463d9a53683a91bfa1a6bbfcc2c1ddc4a58755f8b2a602cca9982233b1d5b` |
| 820 | 8300 | `cc5546bb6fb138537e74ec2c79b5bd52061006003326520b05009b89bbc7fb9c` |

| Case | Envelope chars | Envelope SHA256 |
| --- | ---: | --- |
| 743 | 49968 | `6624c1eca0b46049eca7bc89a5bb0c9d9a9b0551bb97058fc9d3fc8c43fbc687` |
| 820 | 26543 | `652295e1c43f4e2e0d62ef23bb8f01b9cbf19ef229c6df6393e747204395ba04` |

743 保留 10/10（3 instruction、3 local、2 register、2 formal）；820 保留 9/9（0 instruction、6 local、1 register、2 formal）。
两次 fresh ingestion/projection/envelope bytes 与 SHA 均相同。Oracle-independence synthetic regression 通过。
不会把 mutation anchor、RTL location/connection、benchmark family/root cause 加入 context。

## Prompt v3 与 model-only schema

`agents/prompts/hardware_v3.py` 使用通用科学规则，没有 sample ID 或旧报告特定错误提示。
明确 sampled point≠interval；encoding/decode≠execution/commit/retirement；register difference≠read/write；
difference≠causality；formal event 不建立相同或不同 configuration；hypothesis≠verified trigger。

`agents/model_outputs/hardware_v2.py` 定义 ModelHardwareAnalysisReportV2、finding、trigger、abnormal state
及两种 support adapters。每个非空 item 必须有非空 evidence_ids/support_claim_ids；引用列表不重复，
support IDs 全 report 唯一。所有 top-level collections 必填，允许显式空列表，避免缺字段默认成空报告。
输出只返回 evidence IDs，hydrate 后 canonical 仍是原 EvidenceRef；domain 没有新增 support 字段。

Fact support 保存 relation_id/expected_kind/status/compact expected_attributes，semantic support 保存枚举
semantic_kind、relation IDs、expected attrs/status、interval start/end。所有 A3 unsupported semantic kinds
仍可通过 schema 表达，然后由 deterministic gate 拒绝被引用的 unsupported 结果。

Adapter 用明确绑定 relation 恢复仅未暴露的 deterministic 字段，再把模型实际提供的每个字段覆盖进 expected
对象并调用 A3 exact matcher；不修复模型的时间、signal、值、mnemonic、status 等错误。
如果错误 expected fields 违反 A3 属性结构，adapter 返回 incompatible / exact_fact_mismatch；
未知 fact relation 返回 incompatible / unknown_relation；没有对应 instruction fact 的 820 semantic claim
返回 unsupported / missing_relation。未暴露的 raw log/backend fields 不属于模型 assertion。
A3 原有 classes/checker 未改动。

## Referenced / orphan policy、hydration 与 epistemic gates

schema → report IDs/references → support IDs/wiring → evaluate ALL supports → enforce referenced supports
→ failure diagnostic（若拒绝）→ evidence hydration → canonical assembly/grounding → epistemic/IR gates。
VERIFIED trigger 在 canonical CandidateStatus 构造前显式拒绝，以固定错误类别代替依赖 schema 隐式报错。

- 每个 referenced support 必须存在且 supported；任何 referenced incompatible/unsupported 都拒绝整个报告。
- Orphan 全部求值，可以 supported/unsupported/incompatible，但不支撑 item、不产生 finding，不因 orphan 本身拒绝。
- 同 evidence ID 不同 EvidenceRef 拒绝；未知 evidence/behavior/finding ID 拒绝。
- 每个 referenced support 至少与 item evidence 有交集，item evidence 必须包含于其 supports 的 evidence 联集。
- 需要相关 deterministic behavior 时沿用旧真实 Hardware gate；IR 完整保留，与 stub IR 比较。
- finding/state 不允许 verified；trigger 必须 hypothesized/inferred。
- Hypothesis 可以引用若干 supported sampled facts 并保持 tentative；若 typed support 宣称 causal_link /
  trigger_condition_verified，则 referenced 时拒绝。事实支持不验证假设本身。

## Audit artifacts 与 safe failure diagnostics

成功 `hardware-relation-support/v1` 保存每个 generated support、usage_status、result/reason、relation IDs、
referencing_hardware_claims（仅 collection/claim_id，不重复 summary）。所有计数从 entries 重算：generated、
referenced、orphan，以及两种 usage 下三种结果数量。Referenced 必须非空 references 且 supported；orphan references=[]。

`revalidate_hardware_support_artifact()` 为未来审核导出准备：重建 item wiring、重新调用 A3 checker、
重新 hydration 并与完整 canonical report 比较；不信任 persisted supported status。
本阶段仅测试该 helper，没有改动 reviewed exporter，也不导出真实 reviewed snapshot。

失败 `hardware-relation-support-failure/v1` 保存**所有** failed referenced supports，保留 typed kind/result/reason、
refs、expected semantics 与 actual compact A3 snapshots。Orphan 错误只计入 counts，不进入 failed list。
不会保存 finding/hypothesis/state summary、unresolved_questions、raw AIMessage、tool args 或 provider body。

Expected attributes 被展开为 typed field paths：数值、bool、null，以及确实出现在 deterministic catalog 的
字符串可保存；不在该词汇表的模型字符串仅保存 SHA256/字符数，避免把任意模型 prose 夹带进诊断。
实际 snapshot 只来自 approved compact catalog，不含 raw formal log/EvidenceRef prose。
整个 diagnostic 上限 256 KiB；超限不截断、不落盘，但报告仍拒绝，基础 failure/attempt 记录保留。
所有文件在写入前执行 API-key secret scanner；安全异常停止实验。

## Runner、provider 与 persistence

显式 `HardwareSecurityAgent.invoke_supported()` 使用 model schema v2、prompt v3、function_calling。
旧 invoke 保持 HardwareAnalysisReport + prompt v2。共享 runtime 只新增可选 strict 参数，默认不传，
仅 B2 显式 strict=False；既有 Firmware/Hardware 行为保持。

新 runner `integrations/deepseek_hardware_supported.py` 限定：
`deepseek-flash`、temperature=0、thinking disabled、max_tokens=16384、max_retries=0、timeout=180、
function_calling、strict=false。不修改 global DeepSeekConfig 默认 8192，也不更改旧 B/B.1 runner。
记录 requested/returned model，两者预期一致；不匹配停止实验，不换模型。

成功仅在所有 gates 后写入 analysis_run、hardware_analysis_report、hardware_relation_support、analysis_input、
invocation、invocation_attempts。写入前检查全部内容，IO 失败清理本次新目录的部分 accepted files。
失败目录仅允许 failure.json、invocation_attempts.jsonl，以及安全生成的 hardware_relation_support_failure.json。
失败记录包含安全 category/reason、usage、finish_reason、diagnostic persisted/SHA、failed referenced count。
不保存 rejected output 正文，不自动 reviewed-export。

## Predetermined experiment protocol

用户已明确授权两次调用：743 一次、820 一次，无 retry。全部 deterministic preflight、完整测试、
本文的 model-visible identity 记录完成后才允许 API。

源码 snapshot 覆盖 src/tests/scripts 的代码与 JSON/TOML、pyproject；manifest 保存在 repository 外的本地临时文件。
CLI 在首例前、每例前后检查 source snapshot，且重新检查两例 prepared identities。
743 的 schema/support rejection 不取消独立预定的 820 评估；配置、source drift、identity 或 persistence safety
问题停止整个实验。首次 API 后不修改实现、prompt、schema、projection 或 checker；只追加实验记录。

```bash
# 离线 preflight / validation
CHIPCHAIN_ENCORPUS_IBEX_ROOT=/home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex \
  .venv/bin/python -m pytest -q -s tests/integration/test_hardware_supported_local.py
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check

# 本轮预定实验由操作者明确执行一次；不是自动 retry 命令。
CHIPCHAIN_ENABLE_REAL_LLM=1 .venv/bin/python -m chipchain.integrations.deepseek_hardware_supported \
  --corpus-root /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex \
  --env-file .env --freeze-manifest /tmp/chipchain-b2-freeze.json
```

## Offline verification before API

API 前最终验证（2026-09-15）：

| Check | Exact result |
| --- | --- |
| Full offline pytest | `976 passed, 27 skipped in 26.71s` |
| 新增 B2 unit tests | `74 passed in 3.80s` |
| Real local deterministic preflight | `6 passed in 3.62s` |
| pip check | `No broken requirements found.` |
| compileall src tests | exit 0 |
| git diff --check | exit 0 |

27 个默认 skips 包含既有 21 个 opt-in tests 和新增 6 个真实本地测试；新增 6 个已显式运行并通过。
配置已在本地验证为 deepseek-flash、temperature 0、timeout 180、key 已配置，未输出密钥。

Source snapshot：148 files；SHA256 `795b45c73c8141865b2e40df6f0750a292759ed8fcb4c1706748f4906db49121`。
Freeze manifest SHA256：`44e501502178152103c30f8a1d9fc89f43fb11d7d19ce69f8b9986ba57175cdb`；文件 `/tmp/chipchain-b2-freeze.json`。

新增测试包括真实 LangChain parser、官方 ChatDeepSeek 离线 binding/provider
参数、所有正向与不支持语义、orphan 三种结果、全部 reference/epistemic gates、三个失败 support 同时诊断、
未知属性字符串脱敏、diagnostic cap、secret scanner、persistence rollback、两例预定执行与 safety stop、
legacy compatibility，以及真实 743/820 的全部 facts、fresh determinism 和历史错误回归。

## Real experiment results and human audit

预定两例均已完成；以下是 API 后追加的真实记录。Machine success 不等于 human acceptance。
审核将检查每个 canonical item/support index，以及 summary 是否把采样写成 interval、encoding 写成执行/退休、
register snapshot 写成 read/write、association 写成因果、formal result 写成 configuration 关系。
没有接受的 canonical report 时不保存或重构其被拒绝的 prose。


### Predetermined invocation outcomes

实际 provider calls = **2**（743 一次、820 一次），retry = **0**。
两例 requested_model / returned_model 均为 `deepseek-flash`；finish_reason 均为 `tool_calls`。
两例均通过 structured schema、全部 referenced supports、evidence/behavior/finding grounding、epistemic gate
及 deterministic IR equality；均生成完整六文件成功目录，没有 failure 文件，也没有 reviewed export。

| Case | Input tokens | Output tokens | Total tokens | Generated / referenced / orphan | Referenced supported | Canonical items |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| 743 | 24596 | 7286 | 31882 | 13 / 13 / 0 | 13 | 10 findings、1 hypothesis、2 states |
| 820 | 16265 | 5697 | 21962 | 9 / 9 / 0 | 9 | 9 findings、2 hypotheses、2 states |

合计 53844 tokens。Input tokens 包含 system prompt 和 tool schema，不等于 envelope 字符数。
两例 referenced unsupported/incompatible 均为 0；orphan 三种结果计数均为 0。
以下条目是 machine-accepted canonical output 的原文索引，**不表示人工已批准研究结论**。

### 743 invocation / structured parsing / support validation

Run ID：`e4636d59-ef13-42d3-ab19-acedb3b60143`。目录：`output/encorpus:ibex:driver:743/e4636d59-ef13-42d3-ab19-acedb3b60143`。

Start：`2026-09-15T07:40:07.795577+00:00`；terminal：`2026-09-15T07:40:29.961485+00:00`。Schema passed；support passed；stub_ir_equal=true；failure count=0。

成功文件：analysis_run.json、hardware_analysis_report.json、hardware_relation_support.json、analysis_input.json、invocation.json、invocation_attempts.jsonl。

### 743 canonical claim index

| Collection | Item ID | Summary (original) | Epistemic status | Evidence IDs | Behavior IDs | Support claim IDs |
| --- | --- | --- | --- | --- | --- | --- |
| findings | F1 | At 30 ns the host ID-stage signal miter.\host.u_ibex_core.if_stage_i.instr_rdata_alu_id_o carried encoding 0x00130e13 (00000000000100110000111000010011), deterministically decoded as addi x28, x6, 1. This is a sampled encoding observation at the ID stage; execution, commitment and retirement are not established. | derived | encorpus:ibex:driver:743:proof.vcd:e:393223ad51c2f08c34c5<br>encorpus:ibex:driver:743:proof.vcd:e:d2ce3400b7a9e0beff76<br>encorpus:ibex:driver:743:proof.vcd:e:b78c6ec69a291ec648ec<br>encorpus:ibex:driver:743:proof.vcd:e:931ef11e2f1a5479220d | encorpus:ibex:driver:743:id-encoding:30:instruction | SC1<br>SC4 |
| findings | F2 | At 40 ns the host ID-stage signal miter.\host.u_ibex_core.if_stage_i.instr_rdata_alu_id_o carried encoding 0x00001537 (00000000000000000001010100110111), deterministically decoded as lui x10, 1. This is a sampled encoding observation at the ID stage; execution, commitment and retirement are not established. | derived | encorpus:ibex:driver:743:proof.vcd:e:517913821aa2738905bc<br>encorpus:ibex:driver:743:proof.vcd:e:ecf8c4145465d0000055<br>encorpus:ibex:driver:743:proof.vcd:e:91911e7cc77e021484d8<br>encorpus:ibex:driver:743:proof.vcd:e:1b687ca645de20ffb2f7 | encorpus:ibex:driver:743:id-encoding:40:instruction | SC2<br>SC5 |
| findings | F3 | At 50 ns the host ID-stage signal miter.\host.u_ibex_core.if_stage_i.instr_rdata_alu_id_o carried encoding 0x007e2503 (00000000011111100010010100000011), deterministically decoded as lw x10, 7(x28). This is a sampled encoding observation at the ID stage; execution, commitment and retirement are not established. | derived | encorpus:ibex:driver:743:proof.vcd:e:73de2b2c636d91cda059<br>encorpus:ibex:driver:743:proof.vcd:e:ce89d98c9a6bfcf95a2c<br>encorpus:ibex:driver:743:proof.vcd:e:59e6d84cb4b7389f4b10<br>encorpus:ibex:driver:743:proof.vcd:e:ff2000de1a069cbb0111 | encorpus:ibex:driver:743:id-encoding:50:instruction | SC3<br>SC6 |
| findings | F4 | At 50 ns the host load/store unit next-state signal miter.\host.u_ibex_core.load_store_unit_i.ls_fsm_ns sampled 010 while the reference counterpart sampled 000. This is a single sampled local-state difference; no continuous interval, causality or trigger is established. | derived | encorpus:ibex:driver:743:proof.vcd:e:10ed0b58a3e33c874ba0<br>encorpus:ibex:driver:743:proof.vcd:e:a0a5483e63ce6ef601dd | [] | SC7 |
| findings | F5 | At 50 ns the host register-file storage bits [927:896] associated with x28 sampled 0x0 while the reference counterpart sampled 0x1. This is a sampled register-state difference; read/write direction, access and retirement are not established. | derived | encorpus:ibex:driver:743:proof.vcd:e:ffa2157cabe3e075f7cd<br>encorpus:ibex:driver:743:proof.vcd:e:58a85d92588f7178b4af | encorpus:ibex:driver:743:difference:81047f8de03d:50:register-state | SC8 |
| findings | F6 | At 60 ns the host load/store unit current-state signal miter.\host.u_ibex_core.load_store_unit_i.ls_fsm_cs sampled 010 while the reference counterpart sampled 000. This is a single sampled local-state difference; no continuous interval, causality or trigger is established. | derived | encorpus:ibex:driver:743:proof.vcd:e:6e12af461737cdbdbe4d<br>encorpus:ibex:driver:743:proof.vcd:e:698356dd10673f36c839 | [] | SC9 |
| findings | F7 | At 70 ns the host load/store unit next-state signal miter.\host.u_ibex_core.load_store_unit_i.ls_fsm_ns sampled 010 while the reference counterpart sampled 000. This is a single sampled local-state difference; no continuous interval, causality or trigger is established. | derived | encorpus:ibex:driver:743:proof.vcd:e:4b6e934660eface20f8f<br>encorpus:ibex:driver:743:proof.vcd:e:0295323b28a6949e593f | [] | SC10 |
| findings | F8 | At 70 ns the host register-file storage bits [351:320] associated with x10 sampled 0x1000 while the reference counterpart sampled 0x0. This is a sampled register-state difference; read/write direction, access and retirement are not established. | derived | encorpus:ibex:driver:743:proof.vcd:e:c7a34ab5ba2be0840468<br>encorpus:ibex:driver:743:proof.vcd:e:ce47f3b8d64408638a67 | encorpus:ibex:driver:743:difference:96a610aee373:70:register-state | SC11 |
| findings | F9 | The historical verify.log records cover property miter.i_miter.c_propagated as covered in 8 cycles. This is a bounded historical formal cover observation only; it establishes neither a shared nor separate formal configuration, nor a verified trigger, root cause or security impact. | observed | encorpus:ibex:driver:743:verify.log:e:17c2859a6158ac39aea4 | [] | SC12 |
| findings | F10 | The historical verify.log records formal trace error EVS053 (no trace satisfying the configurations exists for any max_length). This is a bounded historical formal result only; it establishes neither a verified trigger, root cause, vulnerability nor formal causality. | observed | encorpus:ibex:driver:743:verify.log:e:96d008706271fd5077e8 | [] | SC13 |
| trigger_hypotheses | H1 | Tentative: the host/reference divergence in the load/store unit FSM state (host 010 vs reference 000 at 50/60/70 ns) may be associated with the sampled lw x10, 7(x28) encoding at 50 ns and the sampled x28/x10 register-state differences. This remains a hypothesis: the supplied evidence is sampled points only, no continuous interval, no execution/retirement, no read/write direction and no causal linkage is established. | hypothesized | encorpus:ibex:driver:743:proof.vcd:e:73de2b2c636d91cda059<br>encorpus:ibex:driver:743:proof.vcd:e:10ed0b58a3e33c874ba0<br>encorpus:ibex:driver:743:proof.vcd:e:a0a5483e63ce6ef601dd<br>encorpus:ibex:driver:743:proof.vcd:e:6e12af461737cdbdbe4d<br>encorpus:ibex:driver:743:proof.vcd:e:698356dd10673f36c839<br>encorpus:ibex:driver:743:proof.vcd:e:4b6e934660eface20f8f<br>encorpus:ibex:driver:743:proof.vcd:e:0295323b28a6949e593f<br>encorpus:ibex:driver:743:proof.vcd:e:ffa2157cabe3e075f7cd<br>encorpus:ibex:driver:743:proof.vcd:e:58a85d92588f7178b4af<br>encorpus:ibex:driver:743:proof.vcd:e:c7a34ab5ba2be0840468<br>encorpus:ibex:driver:743:proof.vcd:e:ce47f3b8d64408638a67 | encorpus:ibex:driver:743:id-encoding:50:instruction<br>encorpus:ibex:driver:743:difference:81047f8de03d:50:register-state<br>encorpus:ibex:driver:743:difference:96a610aee373:70:register-state | SC3<br>SC6<br>SC7<br>SC8<br>SC9<br>SC10<br>SC11 |
| abnormal_states | S1 | Sampled host/reference divergence in the load/store unit FSM: host ls_fsm_ns = 010 vs reference 000 at 50 ns and 70 ns, and host ls_fsm_cs = 010 vs reference 000 at 60 ns. Recorded as sampled local-state differences only; no continuous interval, causality or trigger is established. | derived | encorpus:ibex:driver:743:proof.vcd:e:10ed0b58a3e33c874ba0<br>encorpus:ibex:driver:743:proof.vcd:e:a0a5483e63ce6ef601dd<br>encorpus:ibex:driver:743:proof.vcd:e:6e12af461737cdbdbe4d<br>encorpus:ibex:driver:743:proof.vcd:e:698356dd10673f36c839<br>encorpus:ibex:driver:743:proof.vcd:e:4b6e934660eface20f8f<br>encorpus:ibex:driver:743:proof.vcd:e:0295323b28a6949e593f | [] | SC7<br>SC9<br>SC10 |
| abnormal_states | S2 | Sampled host/reference divergence in register-file storage: x28 bits [927:896] host 0x0 vs reference 0x1 at 50 ns, and x10 bits [351:320] host 0x1000 vs reference 0x0 at 70 ns. Recorded as sampled register-state differences only; read/write direction, access and retirement are not established. | derived | encorpus:ibex:driver:743:proof.vcd:e:ffa2157cabe3e075f7cd<br>encorpus:ibex:driver:743:proof.vcd:e:58a85d92588f7178b4af<br>encorpus:ibex:driver:743:proof.vcd:e:c7a34ab5ba2be0840468<br>encorpus:ibex:driver:743:proof.vcd:e:ce47f3b8d64408638a67 | encorpus:ibex:driver:743:difference:81047f8de03d:50:register-state<br>encorpus:ibex:driver:743:difference:96a610aee373:70:register-state | SC8<br>SC11 |

### 743 generated support index

| Support ID | Usage | Claim type / semantic kind | Relation IDs | Result | Reason | Referenced by |
| --- | --- | --- | --- | --- | --- | --- |
| SC1 | referenced | relation_fact / instruction_encoding_observed | hwrel:18b53562dff1433df965947ec63544e767988ea4b143b872c0062e2c6a190f51 | supported | exact_fact_match | findings:F1 |
| SC2 | referenced | relation_fact / instruction_encoding_observed | hwrel:36b19996c0986d5842441bf16a704bf18a8e1d1f7b548086c76354e24cb197cf | supported | exact_fact_match | findings:F2 |
| SC3 | referenced | relation_fact / instruction_encoding_observed | hwrel:cf49fcb2378a2cba7c3443887da56ba7cf592a8e42bb690f8f471753354cb07c | supported | exact_fact_match | findings:F3<br>trigger_hypotheses:H1 |
| SC4 | referenced | semantic_claim / instruction_encoding_observed | hwrel:18b53562dff1433df965947ec63544e767988ea4b143b872c0062e2c6a190f51 | supported | exact_fact_match | findings:F1 |
| SC5 | referenced | semantic_claim / instruction_encoding_observed | hwrel:36b19996c0986d5842441bf16a704bf18a8e1d1f7b548086c76354e24cb197cf | supported | exact_fact_match | findings:F2 |
| SC6 | referenced | semantic_claim / instruction_encoding_observed | hwrel:cf49fcb2378a2cba7c3443887da56ba7cf592a8e42bb690f8f471753354cb07c | supported | exact_fact_match | findings:F3<br>trigger_hypotheses:H1 |
| SC7 | referenced | relation_fact / sampled_local_state_difference | hwrel:ac07a4b8531f03052f209448d030d2dd4aae82303f1fb014ae44d57d64276b52 | supported | exact_fact_match | abnormal_states:S1<br>findings:F4<br>trigger_hypotheses:H1 |
| SC8 | referenced | relation_fact / sampled_register_state_difference | hwrel:d96113c5e0e3f2585ea343280e26075e67d8c416fca6a80f656a255c3dd66ba4 | supported | exact_fact_match | abnormal_states:S2<br>findings:F5<br>trigger_hypotheses:H1 |
| SC9 | referenced | relation_fact / sampled_local_state_difference | hwrel:82f2e95654a365bbb55c35f8d1c8e97fc3edcec37e4d0dae257348356b18a320 | supported | exact_fact_match | abnormal_states:S1<br>findings:F6<br>trigger_hypotheses:H1 |
| SC10 | referenced | relation_fact / sampled_local_state_difference | hwrel:a28f6bd364b9aa640c8bb8e8c14e68fd2d7a2c44e267e51cb7f769b52be634d2 | supported | exact_fact_match | abnormal_states:S1<br>findings:F7<br>trigger_hypotheses:H1 |
| SC11 | referenced | relation_fact / sampled_register_state_difference | hwrel:ce98e185b3aa3cd4f72d9393f4876ccbebe9a8b3502378422c76694136327801 | supported | exact_fact_match | abnormal_states:S2<br>findings:F8<br>trigger_hypotheses:H1 |
| SC12 | referenced | relation_fact / formal_cover_hit | hwrel:5155f8c4e7d91a83994991c28995deb6ae1c20ba40e542f51295428bd3177909 | supported | exact_fact_match | findings:F9 |
| SC13 | referenced | relation_fact / formal_trace_error | hwrel:99db94ca3f949eed5941bf2bed6006117d3cdd630cddf75b4aa681acf98e8158 | supported | exact_fact_match | findings:F10 |

### 743 unresolved questions (original)

- Whether the sampled ID-stage encodings at 30/40/50 ns correspond to instructions that were executed, committed or retired is not established by the supplied evidence.
- Whether the host/reference load/store unit FSM divergence is a continuous interval, and whether it is causally linked to the sampled lw encoding or the register-state differences, is not established.
- Read/write direction and access semantics for the sampled x28 and x10 register-state differences are unknown.
- Whether the historical cover hit (miter.i_miter.c_propagated, 8 cycles) and trace error (EVS053) share a formal configuration, and whether either relates to the sampled waveform differences, is not established; the SVA/reset harness is incomplete.
- Physical observability of the internal local-state signals on-chip is not established; they are available only in this corpus test setup.
- No mutation identity, root cause, verified trigger or vulnerability conclusion can be drawn from the supplied evidence.

### 820 invocation / structured parsing / support validation

Run ID：`05660d2d-c2e7-480d-9758-6d75f0b9ff9b`。目录：`output/encorpus:ibex:driver:820/05660d2d-c2e7-480d-9758-6d75f0b9ff9b`。

Start：`2026-09-15T07:40:30.009930+00:00`；terminal：`2026-09-15T07:40:48.279090+00:00`。Schema passed；support passed；stub_ir_equal=true；failure count=0。

成功文件：analysis_run.json、hardware_analysis_report.json、hardware_relation_support.json、analysis_input.json、invocation.json、invocation_attempts.jsonl。

### 820 canonical claim index

| Collection | Item ID | Summary (original) | Epistemic status | Evidence IDs | Behavior IDs | Support claim IDs |
| --- | --- | --- | --- | --- | --- | --- |
| findings | hwfind:local:debug_mode_q:100 | At sampled time 100 ns, the host ID-stage controller debug_mode_q signal reads 0 while the reference reads 1. This is a single sampled local-state difference; it does not establish a continuous interval, causality, or any trigger. | derived | encorpus:ibex:driver:820:proof.vcd:e:5863a8d7eff3da238439<br>encorpus:ibex:driver:820:proof.vcd:e:feeacffcd930f5f13810 | [] | sc:rel:local:100 |
| findings | hwfind:local:debug_mode_q:230 | At sampled time 230 ns, the host ID-stage controller debug_mode_q signal reads 0 while the reference reads 1. Sampled local-state difference only; no interval or causal claim. | derived | encorpus:ibex:driver:820:proof.vcd:e:b2669b642a3636eca7e3<br>encorpus:ibex:driver:820:proof.vcd:e:82e0b370fa1dbe8f8516 | [] | sc:rel:local:230 |
| findings | hwfind:local:debug_mode_q:330 | At sampled time 330 ns, the host ID-stage controller debug_mode_q signal reads 0 while the reference reads 1. Sampled local-state difference only; no interval or causal claim. | derived | encorpus:ibex:driver:820:proof.vcd:e:36c362b2e829e6f0b6f7<br>encorpus:ibex:driver:820:proof.vcd:e:3e9b913ee2d7287a3f50 | [] | sc:rel:local:330 |
| findings | hwfind:local:debug_mode_q:410 | At sampled time 410 ns, the host ID-stage controller debug_mode_q signal reads 0 while the reference reads 1. Sampled local-state difference only; no interval or causal claim. | derived | encorpus:ibex:driver:820:proof.vcd:e:d1fca4bee719ebbd2b73<br>encorpus:ibex:driver:820:proof.vcd:e:e5f72b7fff84bcc383a1 | [] | sc:rel:local:410 |
| findings | hwfind:local:debug_mode_q:490 | At sampled time 490 ns, the host ID-stage controller debug_mode_q signal reads 0 while the reference reads 1. Sampled local-state difference only; no interval or causal claim. | derived | encorpus:ibex:driver:820:proof.vcd:e:657f3a0a7668ab1083fc<br>encorpus:ibex:driver:820:proof.vcd:e:fc4772333bab09f400e4 | [] | sc:rel:local:490 |
| findings | hwfind:local:debug_mode_q:540 | At sampled time 540 ns, the host ID-stage controller debug_mode_q signal reads 0 while the reference reads 1. Sampled local-state difference only; no interval or causal claim. | derived | encorpus:ibex:driver:820:proof.vcd:e:33cf907b7de18f09d1e3<br>encorpus:ibex:driver:820:proof.vcd:e:3c9fb4546669f9cdee92 | [] | sc:rel:local:540 |
| findings | hwfind:reg:x10:580 | At sampled time 580 ns, the host register-file slice for x10 (bits 351:320) reads 0x00000000 while the reference reads 0x00000378. This is a sampled register-state difference; it does not establish a read or write, an access direction, or retirement. | derived | encorpus:ibex:driver:820:proof.vcd:e:62e1de41ad8113751693<br>encorpus:ibex:driver:820:proof.vcd:e:e328518d5eac0afd5647 | encorpus:ibex:driver:820:difference:96a610aee373:580:register-state | sc:rel:reg:x10:580 |
| findings | hwfind:formal:cover:c_propagated | Historical formal log records cover property miter.i_miter.c_propagated covered in 59 cycles. This is a bounded historical tool result; the SVA/reset harness is incomplete, so no verified trigger, shared/separate configuration, or security impact is established. | observed | encorpus:ibex:driver:820:verify.log:e:c5b1c1f116ba4180f47b | [] | sc:rel:formal:cover |
| findings | hwfind:formal:trace_error:evs053 | Historical formal log records error EVS053 (no trace satisfying these configurations exists for any max_length). This is a bounded historical tool result; it establishes neither a shared nor separate formal configuration, nor a vulnerability or root cause. | observed | encorpus:ibex:driver:820:verify.log:e:9f30d4dd2269b85c0db9 | [] | sc:rel:formal:error |
| trigger_hypotheses | hwtrig:debug_mode_divergence | Tentative hypothesis: the host/reference divergence in the ID-stage controller debug_mode_q signal may be associated with a debug-mode entry/exit condition in the host design. This is not verified: no instruction trace, no decoded instruction, no continuous interval, and no causal linkage are available; the sampled points are isolated observations and the formal harness is incomplete. | hypothesized | encorpus:ibex:driver:820:proof.vcd:e:5863a8d7eff3da238439<br>encorpus:ibex:driver:820:proof.vcd:e:feeacffcd930f5f13810<br>encorpus:ibex:driver:820:proof.vcd:e:b2669b642a3636eca7e3<br>encorpus:ibex:driver:820:proof.vcd:e:82e0b370fa1dbe8f8516<br>encorpus:ibex:driver:820:proof.vcd:e:36c362b2e829e6f0b6f7<br>encorpus:ibex:driver:820:proof.vcd:e:3e9b913ee2d7287a3f50<br>encorpus:ibex:driver:820:proof.vcd:e:d1fca4bee719ebbd2b73<br>encorpus:ibex:driver:820:proof.vcd:e:e5f72b7fff84bcc383a1<br>encorpus:ibex:driver:820:proof.vcd:e:657f3a0a7668ab1083fc<br>encorpus:ibex:driver:820:proof.vcd:e:fc4772333bab09f400e4<br>encorpus:ibex:driver:820:proof.vcd:e:33cf907b7de18f09d1e3<br>encorpus:ibex:driver:820:proof.vcd:e:3c9fb4546669f9cdee92 | [] | sc:rel:local:100<br>sc:rel:local:230<br>sc:rel:local:330<br>sc:rel:local:410<br>sc:rel:local:490<br>sc:rel:local:540 |
| trigger_hypotheses | hwtrig:x10_divergence | Tentative hypothesis: the host/reference divergence in the x10 register-file slice may be associated with a host-side write or update to x10 that the reference does not perform. This is not verified: the sampled register difference does not establish read/write direction, an executing instruction, retirement, or causality, and no instruction encoding was extracted. | hypothesized | encorpus:ibex:driver:820:proof.vcd:e:62e1de41ad8113751693<br>encorpus:ibex:driver:820:proof.vcd:e:e328518d5eac0afd5647 | encorpus:ibex:driver:820:difference:96a610aee373:580:register-state | sc:rel:reg:x10:580 |
| abnormal_states | hwstate:debug_mode_q_host_ref_divergence | Across six sampled times (100, 230, 330, 410, 490, 540 ns) the host ID-stage controller debug_mode_q reads 0 while the reference reads 1. These are isolated sampled points, not a continuous interval, and no causal or trigger relationship is established. | derived | encorpus:ibex:driver:820:proof.vcd:e:5863a8d7eff3da238439<br>encorpus:ibex:driver:820:proof.vcd:e:feeacffcd930f5f13810<br>encorpus:ibex:driver:820:proof.vcd:e:b2669b642a3636eca7e3<br>encorpus:ibex:driver:820:proof.vcd:e:82e0b370fa1dbe8f8516<br>encorpus:ibex:driver:820:proof.vcd:e:36c362b2e829e6f0b6f7<br>encorpus:ibex:driver:820:proof.vcd:e:3e9b913ee2d7287a3f50<br>encorpus:ibex:driver:820:proof.vcd:e:d1fca4bee719ebbd2b73<br>encorpus:ibex:driver:820:proof.vcd:e:e5f72b7fff84bcc383a1<br>encorpus:ibex:driver:820:proof.vcd:e:657f3a0a7668ab1083fc<br>encorpus:ibex:driver:820:proof.vcd:e:fc4772333bab09f400e4<br>encorpus:ibex:driver:820:proof.vcd:e:33cf907b7de18f09d1e3<br>encorpus:ibex:driver:820:proof.vcd:e:3c9fb4546669f9cdee92 | [] | sc:rel:local:100<br>sc:rel:local:230<br>sc:rel:local:330<br>sc:rel:local:410<br>sc:rel:local:490<br>sc:rel:local:540 |
| abnormal_states | hwstate:x10_host_ref_divergence | At sampled time 580 ns the host x10 register-file slice (bits 351:320) reads 0x00000000 while the reference reads 0x00000378. This is a single sampled register-state difference; read/write direction, executing instruction, and retirement are not established. | derived | encorpus:ibex:driver:820:proof.vcd:e:62e1de41ad8113751693<br>encorpus:ibex:driver:820:proof.vcd:e:e328518d5eac0afd5647 | encorpus:ibex:driver:820:difference:96a610aee373:580:register-state | sc:rel:reg:x10:580 |

### 820 generated support index

| Support ID | Usage | Claim type / semantic kind | Relation IDs | Result | Reason | Referenced by |
| --- | --- | --- | --- | --- | --- | --- |
| sc:rel:local:100 | referenced | relation_fact / sampled_local_state_difference | hwrel:1aeaebeeab2a13db74ffe3568307dc92efc7f3f6537aa9da5c24dfc91606f629 | supported | exact_fact_match | abnormal_states:hwstate:debug_mode_q_host_ref_divergence<br>findings:hwfind:local:debug_mode_q:100<br>trigger_hypotheses:hwtrig:debug_mode_divergence |
| sc:rel:local:230 | referenced | relation_fact / sampled_local_state_difference | hwrel:e1dc688248720ea6a57b0c513a58d7981e91d3df7e64e9a5bb0bedb8e07e4666 | supported | exact_fact_match | abnormal_states:hwstate:debug_mode_q_host_ref_divergence<br>findings:hwfind:local:debug_mode_q:230<br>trigger_hypotheses:hwtrig:debug_mode_divergence |
| sc:rel:local:330 | referenced | relation_fact / sampled_local_state_difference | hwrel:152a981b198c5abc4e17d24be2e9be42b29e49adff190627d2a03615ac7af0b0 | supported | exact_fact_match | abnormal_states:hwstate:debug_mode_q_host_ref_divergence<br>findings:hwfind:local:debug_mode_q:330<br>trigger_hypotheses:hwtrig:debug_mode_divergence |
| sc:rel:local:410 | referenced | relation_fact / sampled_local_state_difference | hwrel:10ca17abd65c09c1f38dade7f84f1b3cee187f422cf847375139e2bfd0d52ca5 | supported | exact_fact_match | abnormal_states:hwstate:debug_mode_q_host_ref_divergence<br>findings:hwfind:local:debug_mode_q:410<br>trigger_hypotheses:hwtrig:debug_mode_divergence |
| sc:rel:local:490 | referenced | relation_fact / sampled_local_state_difference | hwrel:e14042e9c7176be30410dbfd47667543d0904c3755a04f2b9ccdf2f66b7e3189 | supported | exact_fact_match | abnormal_states:hwstate:debug_mode_q_host_ref_divergence<br>findings:hwfind:local:debug_mode_q:490<br>trigger_hypotheses:hwtrig:debug_mode_divergence |
| sc:rel:local:540 | referenced | relation_fact / sampled_local_state_difference | hwrel:dd465dc62c7957d4c1e1c245a2bb81e409675e5ba51f13e32f48824a92c8740a | supported | exact_fact_match | abnormal_states:hwstate:debug_mode_q_host_ref_divergence<br>findings:hwfind:local:debug_mode_q:540<br>trigger_hypotheses:hwtrig:debug_mode_divergence |
| sc:rel:reg:x10:580 | referenced | relation_fact / sampled_register_state_difference | hwrel:c2526c5c19cff3918c62edbb0234232e2d4dbb12ca0372371021bacf9eae490f | supported | exact_fact_match | abnormal_states:hwstate:x10_host_ref_divergence<br>findings:hwfind:reg:x10:580<br>trigger_hypotheses:hwtrig:x10_divergence |
| sc:rel:formal:cover | referenced | relation_fact / formal_cover_hit | hwrel:b638d4a8bdfae85d70a3deec1af7b7035cdd2bf6e9fa24e919ee45214bbf2bde | supported | exact_fact_match | findings:hwfind:formal:cover:c_propagated |
| sc:rel:formal:error | referenced | relation_fact / formal_trace_error | hwrel:5bb46b6b3f82201e01fc5627e297c3b6a1d481e5d508f2322e010997aba19dd0 | supported | exact_fact_match | findings:hwfind:formal:trace_error:evs053 |

### 820 unresolved questions (original)

- No instruction encodings were extracted for the host ID stage; instruction decode, execution, commitment and retirement remain unsupported.
- The six debug_mode_q samples are isolated points; whether the host/reference divergence persists continuously between them is unknown and cannot be established from sampled data.
- No causal or trigger relationship is established between the debug_mode_q divergence and the x10 register-state divergence; the two signals are distinct and cannot be combined into one continuous state.
- The historical formal cover hit (miter.i_miter.c_propagated, 59 cycles) and trace error (EVS053) are bounded by an incomplete SVA/reset harness; no independent formal replay, shared/separate configuration, verified trigger, or security impact is established.
- Whether the host x10 slice difference reflects a write, a read, or an unrelated state difference is unknown; access direction and retirement are not observable in the supplied evidence.
- Physical observability of the internal waveform signals on silicon is not established; internal waveform availability does not imply on-chip visibility.
- No mutation identity, root cause, or vulnerability information is available in the supplied catalog.


### 743 semantic audit（助手逐项审阅，供人工决定）

| Items | 审阅结论 |
| --- | --- |
| F1/F2/F3 | encoding、decode、时间与 A3 一致；明确否认 execution/commit/retirement。 |
| F4/F6/F7 | 三个独立 sampled local facts，分别保留 ns@50、cs@60、ns@70；未声称连续保持。 |
| F5/F8 | x28/x10 值、bit ranges 与 A3 一致；明确否认访问方向/退休。 |
| F9/F10 | cover 8 / EVS053 正确；未推定 shared/separate configuration 或 formal causality。 |
| H1 | 明确 tentative、hypothesized、may be associated；引用七个 supported supports，未宣称因果已验证。概述与 constraint 用泛称 FSM state 合并了 ns/cs 两种信号，阅读时仍应以独立时间/信号事实为准。 |
| S1 | 独立列出 ls_fsm_ns@50/@70 与 ls_fsm_cs@60，明确不是连续区间。 |
| S2 | 两个 sampled register differences 正确，没有读写或因果断言。 |

未发现旧 B.1 的确定性语义升级在本例重现。SC1/SC4、SC2/SC5、SC3/SC6 重复表达同一 instruction fact，
属于冗余 supported support，不是违规 orphan。Machine-valid；研究解释和异常性仍待人工确认，不声明 verified trigger。

### 820 semantic audit（助手逐项审阅，供人工决定）

| Items | 审阅结论 |
| --- | --- |
| 六个 hwfind:local:debug_mode_q:* | 六个 exact sampled facts 正确，没有连续区间或因果断言；“signal reads 0”是采样读数措辞。 |
| hwfind:reg:x10:580 | 时间、值和 slice 正确；使用 “slice reads ...”，但同句明确不证明 read/write/access direction。为避免歧义，研究叙述宜理解为 sampled value，不能当成 register_read。 |
| 两个 formal findings | cover 59 / EVS053 正确；明确不支持 shared/separate configuration、root cause/vulnerability。 |
| hwtrig:debug_mode_divergence | 推测 debug-mode entry/exit condition，标为 hypothesized 且明确缺失指令/连续/因果证据。属于候选机制，不能由 signal 名称验证 entry/exit 行为。 |
| hwtrig:x10_divergence | **主要语义审阅问题**：提出 “host-side write or update to x10 that the reference does not perform”。support 只有 sampled register difference，不能证明哪一侧发生写入/更新；即使 tentative，仍是未获方向性证据支持的机制猜测。后文确实承认方向和因果未知，故并非 typed verified/write claim，但不能当作已支持的写入解释。 |
| hwstate:debug_mode_q_host_ref_divergence | “Across six sampled times”随后明确 isolated points、not continuous interval，未重现持续区间断言。 |
| hwstate:x10_host_ref_divergence | 单点 register value 正确，明确方向/执行/退休未知。 |

本例 **machine-valid / semantic concern flagged / human acceptance pending**。
`hwtrig:x10_divergence` 引用的 `sc:rel:reg:x10:580` 是 referenced/supported 的 sampled fact；
没有 typed register_write、causal_link 或 verified trigger support。这个结果展示了 factual-support gate
与完整 hypothesis prose entailment 的剩余差距，不应改写为“语义全通过”。没有进行 prompt tuning 或真实重试。

### Historical B.1 regression audit

| Historical risk | 743 本轮 | 820 本轮 |
| --- | --- | --- |
| 连续 held across interval | 未出现；明确三个点且 ns/cs 分开 | 明确六个 isolated points，不是 interval |
| 相同/不同 formal configuration | 未推定 | 未推定 |
| encoding → execution/retirement | 明确否认 | 没有发明 instruction，明确没有 encoding |
| register read/write promotion | 未断言 read/write | 没有 typed read/write；“reads”读数措辞有歧义，x10 hypothesis 引入未证实的 host-side write/update 猜测 |
| lw→LSU→x10 causal trigger | 仅 tentative association，明确无 causal linkage | 没有 debug→x10 因果断言 |
| mutation / root cause | 无肯定声明 | 无肯定声明 |

22 个 generated supports 中 19 个 relation_fact、3 个 instruction_encoding_observed semantic_claim；
全部 referenced/supported，没有 unsupported semantic kinds，也没有 orphan。
未出现执行/退休、interval、causal verification、same configuration 或 mutation/root-cause typed promotion。
820 的 write/update 问题发生在 hypothesis 自由文本，而不是 support 的 semantic_kind。
不能从两次实验估计失败率或证明泛化，也不是与 B.1 的单变量比较（prompt、schema、context 与预算均不同）。

### Post-call integrity / preservation / next recommendation

CLI 在两例之前、之间和结束后均通过源码快照检查。随后独立重新检查同一 148-file snapshot，完全一致。
调用后没有修改任何实现、prompt、schema、projection、checker 或 tests；仅追加本研究记录并更新 README 状态。

既有 69 个 output 文件逐文件 SHA 不变，其中 output/reviewed 12 个全部不变；全部旧 743/820 运行、A3 catalogs
与 v3-1b1 reviewed snapshot 原样保留。新产生 12 个 runtime 文件，全部处于两例新 UUID 目录、被 Git 忽略。
再次从 fresh deterministic input 重建并复核两个 persisted support audits、canonical report 和 IR，全部一致；
每例 attempt log 恰好 started/succeeded 两条，证明本 runner 每例只执行一次 invocation、无 retry。
所有新输出通过 secret scanner；未保存 raw provider output，也没有 rejected prose。没有 reviewed export。

Hardware B2 已在 **typed support / referenced-orphan policy / hydration / safe failure diagnostics / canonical gate**
层面与 Firmware B3-R2/R3 建立对应边界；这不是完整自由文本语义正确性的对称保证。
两边都仍须人工审阅模型解释，不能凭 machine-valid 宣称触发条件或漏洞已验证。

建议先人工审阅本次结果，再安排一个有边界的 **Hardware B2 hypothesis-semantics correction/design**：
区分 sampled factual basis 与候选方向/机制，避免 tentative prose 把 unknown write direction 包装为已有依据；
保留 A3 checker，不为 PASS 扩张能力，不在本轮修改或重试。完成该决定后再回 Firmware A6。
现在不应直接把这些自由文本 hypothesis 当作可信 Cross-Layer 因果接口。

未执行 git add/commit/push/tag；未进入 Firmware A6 或 Cross-Layer。
