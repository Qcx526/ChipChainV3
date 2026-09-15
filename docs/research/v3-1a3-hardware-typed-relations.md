# V3-1A3 — Typed Hardware Observation Semantics & Claim-Support Contracts

基线：`v3-2a5-stable` / `47c096c15e058c481f062da63067cf8bf715b14f`。
Firmware A5 static reachability frozen。Hardware A3 已实现；本页记录离线合同、真实本地验证与待人工审核结果。
本阶段没有调用 DeepSeek、HardwareSecurityAgent 或任何网络模型，没有修改 prompt/report/IR。

## Source boundary 与 oracle isolation

唯一 builder 输入是 `HardwareAgentInput`，额外显式传入 operational projection 的 `ToolDescriptor`。
真实入口执行已有 EnCorpus ingestion → `EnCorpusIngestionResult.analysis_input()` → A2
`RiscVInstructionDecoder.enrich()` → typed catalog。不存在新的 VCD scan 算法、formal run、RTL parser、
mutation extraction、simulation 或解码猜测；fresh ingestion 仅重用冻结的本地 reader。

通用 builder 不导入 EnCorpus，不接收 ingestion container，不读取 artifact、不执行 IO，也不调用 Agent。
入口重新验证完整输入，拒绝 benchmark_oracle role、mutation_present、非 typed observation、
未知 epistemic status、重复 behavior identity、冲突 evidence ID 和错配 decode。
输入必须经过 producer 的 operational availability policy；字段检查不是对任意恶意 producer 内容的语义审查。

Catalog 从 allowlist 字段构造，不复制 Case metadata、artifact metadata/path、ground truth、oracle limitations、
mutation details 或 behavior 自由 attributes/summary。EvidenceRef 是已批准 operational evidence 的原样身份，
并非重新扫描 artifact 的内容证明。旧 projection 中的 host/reference 是差异两侧，不表示谁是真值。

Oracle independence 测试实际构造两个经过验证的 `EnCorpusIngestionResult`：保持 operational evidence 不变，
改变 hidden mutation module/signal/location/host+reference connections、mutation summary、oracle limitations、
artifact benchmark-family metadata 和 RTL path。分别 projection/enrich/build，catalog 字节与 SHA 相同。
这项测试同时覆盖 synthetic、真实 743 和真实 820，不是修改 AgentInput 中未使用的字段。

## Versioned relation contract

Schema：`hardware-observation-relations/v1`。一个 operational observation → 一条 canonical relation。
ID 为 `hwrel:` + SHA256(canonical JSON `[observation_id, relation_kind]`)，不依赖列表下标。
每条 relation 保存 kind/status/source_observation_id、排序 evidence IDs、typed attributes/endpoints 和派生 capabilities。

| Existing observation | Typed relation | 属性与范围 |
| --- | --- | --- |
| INSTRUCTION_ENCODING_OBSERVED | instruction_encoding_observed | exact time、ID stage、signal、raw bits/width/representation、既有 decode |
| LOCAL_EFFECT_OBSERVED | sampled_local_state_difference | exact time、host/reference signal/width/range/raw value；local_state |
| ARCHITECTURAL_PROPAGATION_OBSERVED | sampled_register_state_difference | 同上并保留 register_name；register_state；不命名为因果传播 |
| FORMAL_RESULT / cover_hit | formal_cover_hit | property_name、cycles、raw_result、interpretation_boundary |
| FORMAL_RESULT / trace_error | formal_trace_error | error_code、raw_result、interpretation_boundary |

**Status 保留 producer 原值。** 冻结 ingestion 的 waveform observation 是 `derived`（确定性提取），
formal observation 是 `observed`；不为符合命名而改写旧 epistemic status。两种都仅支持各自提取事实，
canonical catalog 不允许 unsupported/inferred/verified 输入 relation。`unsupported` 是 checker 结果。

Instruction attributes 中 `decoded_instruction` 可为 null；存在时原样保留整个既有 `DecodedInstruction`：
`status` 对应 decoded_status，`mnemonic`、typed `operands`/`operand_text`、`instruction_width_bits`、
`decoder`（name/version/configuration SHA）、mode、reason、representation 和 evidence 均未重写。
嵌套 decode 的 epistemic_status 始终为 derived；unsupported/invalid/unknown decode 没有 decode support。
不复制这些字段为另一套冗余真值，也不把 decode 拆成第二条 relation。

Endpoints 从 attributes 派生并校验：instruction_sample、signal_sample、register_sample、formal_property、
formal_tool_event。采样端点保留 exact time；register 端点额外保留 register_name；双侧顺序为 host、reference。
Signal width 与 bit range/value 长度一致；paired values 必须不同；解码绑定 observation、raw word、stage、
width、representation、architecture 及对应 sample evidence。Formal 文本限 8192 字符，超长拒绝，不截断。
这仍是 canonical deterministic artifact，**不是 model-facing compact projection**。

## Capabilities 与 claim support

Capabilities 由 relation kind/status 和是否有成功 deterministic decode 派生，catalog validator 重算比对。
Producer 无法通过修改 bool 把事实升级。执行、commit、retirement、continuous interval、register read/write、
causal propagation、trigger、root cause、mutation identity、physical observability、same formal configuration、
formal causality 和 vulnerability 能力均为 `Literal[False]`。

`HardwareRelationFactClaim` 明确给出 relation_id、expected_kind/status 和完整 expected typed attributes。
`HardwareSemanticClaim` 使用枚举区分六种正向声明与不支持的语义；正向声明必须提供一个明确 relation、
对应完整 attributes 和正确 status，不允许凭 prose 或空属性自动匹配。典型调用：

```python
from chipchain.tools.hardware.relation_claims import HardwareRelationFactClaim, check_hardware_claim

relation = catalog.relations[0]
result = check_hardware_claim(catalog, HardwareRelationFactClaim(
    claim_id="sample-fact", relation_id=relation.relation_id,
    expected_kind=relation.kind, expected_status=relation.status,
    expected_attributes=relation.attributes,
))
assert result.status == "supported"
```

| 情形 | 结果 |
| --- | --- |
| exact typed fact 与 kind/status/attributes 一致 | supported |
| 既有 fact 的时间、信号、值、register、mnemonic、kind 或 status 错误 | incompatible |
| catalog 有对应事实类别，但显式 relation ID 不存在 | incompatible / unknown_relation |
| 正向 claim 没有引用/对应事实类别不存在（如 820 instruction） | unsupported / missing_relation |
| 正向 claim 没有完整 exact attributes | unsupported / missing_exact_attributes |
| 正向 claim 提供多条 relation，未定义合并规则 | unsupported / ambiguous_support |
| decode 不存在/未成功，或 execution/interval/read/write/causal 等能力缺失 | unsupported / semantic_power_unavailable |

不支持的 typed claim：instruction_executed/committed/retired、continuous_interval_difference、
register_read/write、causal_link、trigger_condition_verified、root_cause、physical_observability、
same_formal_configuration、formal_event_causality、mutation_location/connection/family、vulnerability_verified。
Interval 明确保存 start/end（检查时间先后），但不会凭离散采样推导区间。
Checker 不使用 NLP、prose regex 或 LLM judge；调用时重新验证 catalog，拒绝绕过模型校验的实例修改。

## Historical B.1 failure modes now expressible

- sampled point ≠ continuous interval：743 三个 LSU 点跨两个 signal，不能拼成某信号持续保持 50–70 ns。
- encoding / decode ≠ execution、commit、retirement：ID-stage word 只能支持 encoding 与确定性解码事实。
- register snapshot ≠ read/write：x10/x28 值差异没有访问方向证明。
- formal result ≠ same configuration / causality：cover 与 EVS053 共同出现不证明它们属于同一配置或有因果联系。
- local/register difference ≠ causal propagation、verified trigger、root cause 或物理可观测性。
- benchmark mutation ≠ runtime evidence：没有 mutation relation；不得从 operational difference 还原 injected connection。

743/820 旧模型报告原样保留。本阶段把人工审核发现的风险变成显式 typed regressions，
没有声称能够自动审查或修正旧报告自由文本。

## Real 743 catalog

Case `encorpus:ibex:driver:743`：10 relations = 3 instruction + 3 local + 2 register + 2 formal；
5 behaviors，24 个唯一 evidence IDs。Instruction signal 为
`miter.\host.u_ibex_core.if_stage_i.instr_rdata_alu_id_o`，32-bit、`decompressed_word`、ID stage。
Decoder 为 Capstone 5.0.9，原 RV32 descriptor/mode 保留。

| Time (ns) | Encoding | Deterministic decode |
| --- | --- | --- |
| 30 | 0x00130e13 | addi x28, x6, 1 |
| 40 | 0x00001537 | lui x10, 1 |
| 50 | 0x007e2503 | lw x10, 7(x28) |

Local signal 的共同前缀为 `miter.\{host,reference}.u_ibex_core.load_store_unit_i.`。

| Time (ns) | Signal | Width/range | Host raw bits | Reference raw bits |
| --- | --- | --- | --- | --- |
| 50 | ls_fsm_ns | 3 / [2:0] | 010 | 000 |
| 60 | ls_fsm_cs | 3 / [2:0] | 010 | 000 |
| 70 | ls_fsm_ns | 3 / [2:0] | 010 | 000 |

Register signal 为 `miter.\{host,reference}.gen_regfile_ff.register_file_i.rf_reg_q`。

| Time (ns) | Register | Width/range | Host raw bits | Reference raw bits |
| --- | --- | --- | --- | --- |
| 50 | x28 | 32 / [927:896] | 00000000000000000000000000000000 | 00000000000000000000000000000001 |
| 70 | x10 | 32 / [351:320] | 00000000000000000001000000000000 | 00000000000000000000000000000000 |

Formal：`miter.i_miter.c_propagated` cover hit **8 cycles**；独立 trace error **EVS053**。
raw_result 与 interpretation_boundary 从原 FormalResultDetails 保留；没有 configuration linkage。

## Real 820 catalog

Case `encorpus:ibex:driver:820`：9 relations = **0 instruction** + 6 local + 1 register + 2 formal；
1 behavior，16 个唯一 evidence IDs。没有通过 generic limitation 生成 instruction。
`decoder_descriptors=[]` 表示没有附着的 decode；入口仍执行同一个冻结 A2 enrich。

| Time (ns) | Signal | Width/range | Host raw bits | Reference raw bits |
| --- | --- | --- | --- | --- |
| 100 / 230 / 330 / 410 / 490 / 540 | debug_mode_q（六个独立采样点） | 1 / null | 0 | 1 |

Signal 前缀为 `miter.\{host,reference}.u_ibex_core.id_stage_i.controller_i.`。

| Time (ns) | Register | Width/range | Host raw bits | Reference raw bits |
| --- | --- | --- | --- | --- |
| 580 | x10 | 32 / [351:320] | 00000000000000000000000000000000 | 00000000000000000000001101111000 |

即 host=0，reference=0x378；register signal 与 743 相同。
Formal：`miter.i_miter.c_propagated` cover hit **59 cycles**；独立 trace error **EVS053**。

## Real claim regression matrices

| 743 typed claim | Result |
| --- | --- |
| addi encoding @30 / deterministic decode | supported |
| addi executed / retired | unsupported |
| LSU local sample @50 | supported |
| LSU continuously held 50–70，引用 ns@50/cs@60/ns@70 | unsupported |
| x10 sample @70 | supported |
| x10 read / write | unsupported |
| cover 8 cycles / EVS053 observed | supported |
| cover + EVS053 same configuration / formal causality | unsupported |
| lw@50 → LSU → x10 verified trigger | unsupported |
| x10 exact host/reference 值颠倒 | incompatible |

| 820 typed claim | Result |
| --- | --- |
| debug_mode_q @100 | supported |
| x10 @580 | supported |
| x10 read / write | unsupported |
| instruction encoding / decode（无 relation） | unsupported |
| debug_mode difference caused x10 difference | unsupported |
| cover 59 cycles / EVS053 observed | supported |
| cover + EVS053 same configuration / formal causality | unsupported |
| x10 exact host/reference 值颠倒 | incompatible |

## Source identity, canonical serialization 与 artifacts

source 绑定 case、architecture、projection descriptor/version、operational projection SHA、observation/behavior 数、
evidence registry SHA/count/IDs、实际附着 decoder descriptors。Projection SHA 对排序后的 allowlist
observation identity/status/attributes/evidence IDs/behavior IDs、case/architecture/descriptor 和 evidence SHA 哈希。
Evidence SHA 来自按 evidence_id 排序的完整 operational EvidenceRef；同 ID 不同内容 fail closed。
无 artifact metadata、benchmark answer 或 wall-clock/run UUID 进入 catalog identity。

此 operational SHA **不是**旧 model context SHA。显式真实入口单独严格核对冻结 B.1 context：

| Case | Frozen B.1 model context SHA256 |
| --- | --- |
| 743 | `fd36deab7e5a26435b255fbc57bd548dbd7e50ff5fffa91d1b97703555b063ad` |
| 820 | `b10f773a346bfc6e2f33b01d0ce7a2c8fb26925e6b6ea26f5bf93880c77c6d07` |

Codec 提供 serialize/parse/sha256，使用 ASCII canonical JSON、排序 keys、无额外空格/尾换行。
Relations 按 exact time（整数 femtosecond 比较，不浮点）、kind、relation_id 排序；无 time 的 formal 在后。
Evidence IDs 排序、endpoints 按派生顺序，descriptor registry 按 canonical JSON 排序。
Typed operands 和原 decode evidence 的内部顺序保持原样。parse 不验证 artifact 内容/哈希真实性；
需要独立审计来源时应重新运行 builder，与 catalog bytes/SHA 比较。
两次 fresh ingestion/projection/enrich/build 与 serialize→parse→serialize 均逐字节一致。

| Case | Serialized chars = ASCII bytes | Catalog SHA256 |
| --- | ---: | --- |
| 743 | 29316 | `e9f0da2fea7df21b9a028c38b685292895d160ad3b521b77e4bd568cace23753` |
| 820 | 18257 | `5715a6e9a2ad6611c4f8c03767a7da89490ca471cad1030a47fca56de1311dda` |

| Case | Operational projection SHA256 | Evidence registry SHA256 |
| --- | --- | --- |
| 743 | `bae978ab83412b8758fa7d6627283b00f2de526f57be74cadd09a50bf81d9833` | `5d960173b59379e896dda475e42ec0f5caaefefed9ccb020bb7150b32abe8916` |
| 820 | `45ad00d94191c54c53f7303946ec3281112bb7a06a35762c7740f9244d30f9fb` | `c486803cfd2e93fc848e6077be5a137b0ce27d2e0bfb1102e76bc63d56234a99` |

本轮显式保存两个新文件（被 Git 忽略）：

- `output/encorpus:ibex:driver:743/fb6aa19d-5155-4be4-9304-50bca79e155f/hardware_typed_relations.json`
- `output/encorpus:ibex:driver:820/8e3c5526-b7fb-490e-9f6c-cdd8b64c081a/hardware_typed_relations.json`

没有生成 AnalysisRun、HardwareAnalysisReport 或 reviewed export。
CLI 默认仅验证并打印摘要；只有显式 `--persist` 才向新 UUID 目录写入。
CLI 限于这两个冻结 context 的 preflight；通用 builder 不限制 corpus、case 或 workspace path。

```bash
.venv/bin/python -m chipchain.integrations.hardware_typed_relations \
  --sample /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743 --persist
# 将 743 替换为 820 可复现另一例；每次保存新的 UUID。

CHIPCHAIN_ENCORPUS_IBEX_ROOT=/home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex \
  .venv/bin/python -m pytest -q -s tests/integration/test_hardware_typed_relations_local.py
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
git status --short --untracked-files=all
```

## Validation, preservation 与 next step

最终验证（2026-09-15，本地 Python 3.12.13）：

| Check | Exact result |
| --- | --- |
| Full offline pytest | `902 passed, 21 skipped in 24.59s` |
| A3 unit tests | `74 passed in 1.03s` |
| Real local 743/820 integrations | `8 passed in 2.91s` |
| pip check | `No broken requirements found.` |
| compileall src tests | exit 0 |
| git diff --check | exit 0 |
| 新增未跟踪文件 whitespace/conflict 检查 | passed |

默认离线 21 skips 包含既有 13 个 opt-in tests 和新增 8 个真实本地测试；后者已单独显式启用并全部通过。
文件 SHA 核对：原有 90 source、46 test、20 doc、67 output 文件均未改变，
其中 `output/reviewed/` 12 个文件全部原样；原有文件只有 README 阶段说明发生变化。
新增两个被忽略的 deterministic output 文件，未修改既有 output。
Git 为 1 个 modified README + 7 个 untracked additions；未 add/commit/push/tag。

默认 pytest 的既有 autouse fixture 阻断网络和外部进程；
真实测试只读取本地样本并运行原 Python ingestion/Capstone。DeepSeek calls = 0；network model calls = 0。

只新增三个硬件合同模块、独立 deterministic integration 入口、unit/local integration tests、本页文档，
并更新 README 的阶段状态。HardwareSecurityAgent、hardware prompt v2、HardwareAnalysisReport、ProcessorBehaviorIR、
EnCorpus/A2/B.1、Firmware A5 以及既有 source/tests/docs/output 全部保持原样（README 阶段说明除外）。

剩余边界：A3 不提供执行、退休、连续区间或因果证明，不接受模型报告，不检查自由文本与 typed support
是否语义一致，也没有 compact model projection、ModelHardwareAnalysisReportV2 或 support_claim_ids。
推荐人工审核 A3 后进入 **Hardware B2 structured support claims**：建立 bounded input projection、模型
claim schema、明确 referenced-support policy、grounding/binding、错误诊断和自由文本限制，再独立授权真实调用。
不应为获得 supported 结果扩张 A3 capabilities。本轮未进入 Hardware B2、Firmware A6 或 Cross-Layer。
