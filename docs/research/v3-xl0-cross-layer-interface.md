# V3-XL0 — Cross-Layer Interface & Hardware Trigger Contract Foundation

基线：`v3-doc1-report-walkthrough-stable`，commit `a6073466dcd314023bbd282c605b7cf47fabf036`。

XL0 建立表达 `FirmwareExecutionEvidence ⊨ ? HardwareTriggerCondition` 所需的接口和静态比较规则。
本阶段没有在真实 case 上回答该公式。真实 Heat_Press ↔ Ibex 743/820 均不具备配对资格；
正向 candidate 全部来自明确标记的 synthetic fixture，不能解释成真实漏洞或攻击链。

## 实现范围与文件

独立包 `src/chipchain/cross_layer/` 不接入旧 `domain/cross_layer.py`、workflow 或 Agent。

| 文件 | 职责 |
| --- | --- |
| `eligibility.py` | 外部 pairing manifest、目标兼容性、pair descriptor |
| `trigger.py` | 显式 typed builder input、七类必要 atom、condition |
| `contracts.py` | Firmware 引用、逐 atom 结果、candidate 与能力边界 |
| `facts.py` | 对已有 IR/A4/A5 合同的内存引用解析；不读文件、不建立另一份 truth database |
| `adapters.py` | 架构相关的有限规范化和显式 decoder operand 映射 |
| `matcher.py` | 配对 gate、同一 candidate site 字段比较、all-of 聚合、重新验证 |
| `codec.py` | canonical JSON、parse、SHA256；不依赖时钟或运行 UUID |
| `__init__.py` | 显式公共 API |

新增测试为 `tests/cross_layer_fakes.py`、三个 `tests/unit/test_cross_layer_*.py` 和
`tests/integration/test_cross_layer_pairing_local.py`。根 README 更新当前阶段和入口。
没有改动 CaseBundle、AnalysisRun、两侧 evidence registry、provenance、既有工具/模型/prompt descriptors、
workflow routing、ground-truth isolation 或 workspace 设计。没有新增依赖、solver、scheduler、数据库或持久化副作用。

## C–E：Pair contract、architecture compatibility 与 target binding

版本为 `cross-layer-pair/v1`。`CrossLayerPairDescriptor` 绑定两侧 case ID、完整 TargetDescriptor、
manifest、binding source、共同 board/processor identity、eligibility 和 reason codes，具有内容导出的 `xlpair:` ID。
构造和解析都会重新计算 eligibility；不能将未知 pair 的结果字段手工改成 eligible。

检查 architecture，并在双方明确提供时逐字比较 `isa_variant`、`word_size_bits`、`endianness`。
不推断 ISA 子集兼容、不展开 ISA 别名。任何确定的不兼容优先为 `ineligible`；
不存在确定冲突但架构 UNKNOWN 时为 `unknown`。可选字段单侧缺失不视为冲突。
即便两边 processor_id 字符串相同，也不会自行认为它们是同一个板卡、session 或配置实例。

`CrossLayerPairManifest` 是调用者提供的确定性外部元数据，必须带 manifest ID、两侧准确 case ID、
各自 identity、非空 evidence IDs。两侧 identity 必须一致才能绑定；不一致为 `target_identity_mismatch`。
仅接受 `explicit_manifest`、`shared_platform_identity`、`shared_session_identity`、
`synthetic_test_fixture`，无 manifest 为 `unknown`，没有 `llm_inferred`。
枚举值本身不是证明；manifest 的准确性仍由提供该外部资料的调用方负责。

同架构而无 manifest 为 `unknown / target_identity_unbound`。不同架构不能因为 manifest 而获得资格。
`match_trigger_condition` 首先重新验证 pair，仅 `eligible` 可以继续；其他结果抛出 `PairNotEligible`，
在读取 condition 或 firmware facts 前就退出，不产生 candidate。

## F–H：Hardware trigger contract、atom 与布尔/顺序语义

版本为 `hardware-trigger-condition/v1`。唯一构造入口接收 `HardwareTriggerConditionInput` 的 typed fields。
condition 包含 hardware case ID、architecture、source kind/source IDs、可选 `source_hardware_hypothesis_id`、
epistemic status、`all_of_atoms` 与 `context_notes`。内容导出的 ID 前缀为 `hwcondition:`。
不接受 summary parser，不读取 Hardware B2 report prose，不自动把 A3 sampled differences 转成必要条件。

source kind 可以是 `hardware_relation`、`hardware_trigger_hypothesis`、`external_verified_spec`、
`synthetic_fixture`。显式研究注释决定必要条件，source IDs 用于追踪来源，不代表 XL0 验证了这个条件。
只允许 observed/derived/inferred/hypothesized；任何 hardware hypothesis 来源或 hypothesis ID 都强制
`hypothesized`。即便 external source 名称含 verified，XL0 也不能生成 verified condition。

| Atom | typed requirements 与当前边界 |
| --- | --- |
| instruction | architecture；mnemonic、operand pattern、encoding/mask、representation、stage requirement 可选；不要求 exact encoding |
| register_state | register、eq/neq/masked_eq/in_range；描述所需状态，不是写操作 |
| mmio_access | resource address、read/write/either、可选值约束与 width_bits |
| csr_access | CSR identity/address、方向、可选值约束；不硬编码某 ISA 的 CSR 命名表 |
| privilege_state | architecture + mode；各架构保留自己的词汇，unknown 不匹配 |
| hardware_state | 内部状态 identity + 数值约束；当前 firmware 证据不能证明它，结果 unknown |
| ordering | before/after atom IDs，可选 event/time gap；只消费已有明确静态 witness |

OperandPattern 支持 destination/source registers、base register、exact immediate 或 inclusive range。
只允许一个 immediate constraint；空 pattern、重复 atom、倒置 range、缺字段或越界 mask 会被拒绝。
encoding 比较必须声明具体 representation，不跨 memory bytes / decompressed word 等表示直接等同。
没有 encoding 也可以仅要求 mnemonic，或 mnemonic 加有限 operand 字段。

`all_of_atoms` 中所有 `purpose=required` atom 都是必要条件，至少一个 required atom。
没有任意 AND/OR/NOT 表达式树。背景文字进入 `context_notes`，不成为 matcher fact。
只有显式 `verification_only_metadata` 才返回 not_applicable，不计入必要条件。
ordering endpoints 必须引用同一 condition 内两个不同的 required、non-ordering atoms。

只接受绑定 A5 CFG 后校验过的显式 witness。图路径中两个已选择站点按顺序出现，可以支持 **该静态路径上的** order；
两个点各自 reachable 不能推出 order，逆向路径也不排除另一条正向路径，因而无正向 witness 时仍 unknown。
节点地址只证明节点层级顺序，XL0 不猜测同一 basic block 内的指令顺序。
图边数不是执行 event 数，故 max_gap_events/max_gap_time 在已有静态顺序时仍缺失，整体 atom 最多 partial。
不运行 timing solver、CFGEmulated、SimulationManager、claripy、SAT/SMT 或 symbolic execution。

## I：Firmware comparable references 与 authority boundary

`FirmwareCrossLayerFactRef` 只保存 source kind/ID、case ID、architecture、源 artifact canonical SHA256、
site ID 与 derived capabilities。真正的字段仍从调用者提供的冻结输入解析，不复制 A4/A5 形成新的长期数据库。
`FirmwareFactSources` 深拷贝并验证已有 IR/A4/A5 合同，不修改调用方对象或两侧 registry。
引用解析精确比对源 ID、case、architecture、SHA、site 和 capabilities，拒绝过期或手工增强的引用。

| 来源 | XL0 暴露的事实 |
| --- | --- |
| processor_behavior | firmware origin、observed/derived 且有 evidence 的 deterministic IR；验证 decoder evidence 后暴露 decoded mnemonic/encoding/stage 与 adapter 支持的有限显式 operands |
| firmware_static_relation | 原 A4 relation ID/SHA；confirmed MMIO direction 可比较方向，但指令 PC 不能当作 MMIO resource address |
| firmware_static_reachability | 原 A5 catalog SHA + query identity；必须提供匹配 CFG 并通过已有 witness validator，保留 status/capabilities |

IR 必须来自确定性工具的输入边界，不是 Agent 聚合输出。summary、operand_text、backend_operand_text、
通用 attributes 中的任意自然语言均不参与事实解释。类型和哈希验证也不等于验证了外部生产者的诚实性。

当前生产 IR 的通用 metadata 没有统一的 register-state、CSR-state 或 privilege 证明合同，XL0 不假装已经具备。
为验证这几类 matcher 算法，synthetic ProcessorBehavior 可以带明确的 `xl0-synthetic-comparable/v1`
scalar annotation，必须显式启用 `FirmwareFactSources(..., synthetic=True)` 并通过严格 typed schema。
这些 annotations 不能用于真实生产来源；生成的 candidate 必须标记 synthetic/not real vulnerability。
单独的 register write 或有 `value` 但没有明确 `state_value` 的 fixture 仍不证明所需 register state。
未来 adapter 应从真正确定性状态工具输出扩展这一边界，不能把本教学 annotation 当作真实数据接入方案。

## J–K：逐 atom matching 与 candidate aggregation

版本为 `cross-layer-trigger-match/v1`。调用者用 `FirmwareAtomBinding` 显式选择每个 atom 的 firmware site 和事实引用。
所选引用必须全部指向同一 site；不能把不同位置的 mnemonic、register、value 拼成一个满足条件的事实。
同址多份来源字段相互矛盾时返回 unknown / conflicting_firmware_sources，不挑选有利的一份。

| Atom status | 精确含义 |
| --- | --- |
| matched | 当前确定性抽象下所有要求的字段一致；不代表执行或触发 |
| partial | 至少一个要求字段吻合，其他要求缺失，且没有确定字段冲突 |
| conflict | 明确选择的同一 candidate site 上有确定字段不一致；不是“未找到证据” |
| unknown | 没有可比较字段、缺少证明能力、无 ordering witness 或来源不一致；不是否定证据 |
| not_applicable | 仅显式 verification-only metadata |

例如 synthetic `lw x10,7(x28)` 完整字段匹配为 matched；仅已知 `lw` 为 partial；
同址 `sw` 为 conflict。所需 MMIO write 与同址 confirmed read 为 conflict。
内部 FSM state 在只有 firmware facts 时为 unknown。

| Candidate overall_status | all-of 聚合规则 |
| --- | --- |
| full_static_match | 所有 required atoms 都 matched |
| partial_static_match | 至少一个 required matched，其余有 partial/unknown，且无 conflict |
| conflict | 任一 required conflict，优先于其他状态 |
| insufficient_information | 没有任何 required matched 且无 conflict；包括全部 unknown、全部 partial、无 facts |

即便 full_static_match，也只是分别检查必要条件的静态字段；不证明这些点属于同一可执行或输入驱动路径。
candidate 始终 hypothesized，`supports_static_cross_layer_match` 仅在 full_static_match 为 true；
`static_path_only=true`，runtime_order/runtime_trigger/path_feasibility/exploitability/vulnerability_verification 全为 false。
保留 source identities、missing constraints、limitations，不能升级成 vulnerability 或 attack chain。

## L–O：Architecture adapters

核心 matcher 不分支硬编码 ARM/RISC-V/PowerPC；使用 `CrossLayerArchitectureAdapter` 的 normalize_register、
normalize_instruction、compare_operand_pattern、normalize_privilege 和 decoded_fields。

RISC-V v1 规范化 x0..x31，保留 mnemonic，且只对有限明确 load/store、立即数算术和 lui/auipc decoder operand 形状
映射寄存器/base/immediate。不解析 operand text，不声称实现完整 ISA semantics 或执行行为。
ARM 支持 r0..r15 以及 sp/lr/pc 的寄存器名规范化；保留 mnemonic/encoding，不猜 Thumb predicates、writeback、隐式寄存器或 operand roles。
PowerPC 是独立 Architecture.POWERPC，规范化 r0..r31，保留 mnemonic/encoding；synthetic `lwz` 正向测试确保不会被丢入 UNKNOWN。
其他架构使用保守 literal adapter，没有已支持寄存器映射时保持字段未知。

## P–Q：真实本地负向结果

只读以下已有 `analysis_input.json` 的 target/case metadata，没有重新 ingestion、调用 Agent 或重新运行工具：

| 层 / case | 已有 run | metadata |
| --- | --- | --- |
| Heat_Press scenario 13 | `104a5332-3cf3-4263-b988-8b5b0b82f14e` | ARM / sam3x / ARMv7-M Thumb / 32-bit / little-endian |
| Ibex 743 | `e4636d59-ef13-42d3-ab19-acedb3b60143` | RISC-V / ibex / 32-bit / unknown endianness |
| Ibex 820 | `05660d2d-c2e7-480d-9758-6d75f0b9ff9b` | RISC-V / ibex / 32-bit / unknown endianness |

Firmware 从 `firmware_projection.case` 读取，Hardware 从 `b1_context` JSON string 的 `case` 读取。
这不引用旧 LLM report 的 summary 或结论。

两组 eligibility 均为 **ineligible**，reasons 都精确为 `architecture_mismatch`、`target_identity_unbound`。
没有对应同一 board/processor/session 的 pairing manifest。结果正确，不是要绕过的失败。

| 配对 | Pair descriptor canonical SHA256 |
| --- | --- |
| Heat_Press ↔ Ibex 743 | `f66760e622c6007f37b29f017395446eb569fd7cf7cd4467dcff79ec6ad46635` |
| Heat_Press ↔ Ibex 820 | `7a5ac4557fbb26f830bb9b8fb2ef215e5cf36e7d67dd47b7211fc7e2d6368d50` |

两例均测试：即使 condition/sources 尚未构造，也会先抛出 PairNotEligible，没有生成 CrossLayerTriggerCandidate。
本地运行 `python -m pytest -q -s tests/integration/test_cross_layer_pairing_local.py` 为 `2 passed in 0.07s`。
干净 checkout 缺少忽略的 runtime outputs 时这两项 skip；可设置 `CHIPCHAIN_XL0_OUTPUT_ROOT` 指向已有 output 根目录。
不会为了让测试通过而启动分析或复制真实 sample/output 到 Git fixture。

## T–U：序列化、determinism 与 provenance

pair、condition、candidate 都有 serialize/parse/sha256，canonical JSON sorted keys、固定分隔符、UTF-8/ASCII escapes。
禁止 duplicate JSON keys、非有限数值、未知合同字段。builder 对 set-like source IDs、atom IDs、bindings 和 references 排序；
有语义顺序的 operand source registers、context notes 和 A5 witness 保留顺序。
ID 来自版本化内容 SHA256，既不使用 wall clock/UUID/object repr，也不依赖 set iteration。
两次 fresh synthetic build 和 round-trip bytes/SHA 一致。

candidate 绑定 firmware/hardware case IDs、pair ID/SHA、condition ID/SHA、全部 firmware source refs、
matcher version/policy/adapter version。A5 reference 又绑定 catalog SHA，其内含 CFG/source hashes。
JSON parse 检查内部合同和内容 ID；若要信任外部 candidate 的字段比较结论，必须调用 `revalidate_candidate`
并提供原 pair、condition、sources 和显式 bindings，重新执行 matcher。自洽 SHA 不是事实真实性或语义正确性的证明。
XL0 没有自动文件写入：所有输出是内存模型，持久化仍由未来调用方显式触发。

## 最小调用形状

```python
from chipchain.cross_layer import (
    build_cross_layer_pair, build_hardware_trigger_condition,
    FirmwareFactSources, FirmwareAtomBinding, match_trigger_condition,
)

# manifest 和 typed_input 是显式研究输入；deterministic_ir 来自工具，而不是 report。
pair = build_cross_layer_pair(
    firmware_case_id=firmware_case_id, hardware_case_id=hardware_case_id,
    firmware_target=firmware_target, hardware_target=hardware_target, manifest=manifest,
)
condition = build_hardware_trigger_condition(typed_input)
sources = FirmwareFactSources(
    case_id=firmware_case_id, target=firmware_target, processor_ir=deterministic_ir,
)
ref = sources.reference("processor_behavior", behavior_id)
candidate = match_trigger_condition(
    pair=pair, condition=condition, sources=sources,
    bindings=[FirmwareAtomBinding(atom_id=atom_id, site_id=ref.site_id, firmware_fact_refs=[ref])],
)
```

以上展示 API 数据流，变量由调用方提供，不是 Heat_Press/Ibex 正向示例。
完整可执行 synthetic examples 在 `tests/cross_layer_fakes.py` 和 matcher tests 中。

## V–Y：科学边界与后续接口

same mnemonic ≠ same execution；same instruction ≠ trigger；same address ≠ 跨目标同一硬件资源；
static reachable ≠ runtime reachable；path exists ≠ path feasible；sampled hardware difference ≠ trigger condition；
hardware hypothesis ≠ verified trigger；firmware behavior ≠ attacker controllability；partial match ≠ satisfiable trigger；
candidate ≠ vulnerability；candidate ≠ attack chain；association ≠ causality。

A3 描述硬件采样观察，B2 的 supported 只检查 typed supports；两者都没有验证哪组前置条件会导致真实 trigger。
A5 reachable_static 以 `firmware_path_refs` 附加，最多支持已验证 witness 的静态 order。
`not_found_within_bound` 留作 unknown/missing constraint，不能映射成 conflict 或 unreachable。
FakeRet witness 保留 `static_path_assumes_callee_returns`，不会升级到 runtime/feasible/input-driven。

未来 A6 source kind `firmware_constrained_path` 只预留常量，XL0 的可接受 enum 明确不含它；
未实现 SAT/UNSAT/UNKNOWN feasibility evidence、约束求解或外部输入控制分析。
未来 Cross-Layer Agent 只能消费 eligible pair、typed condition/facts、deterministic match results 和 retrieved KG context；
Agent 可选择、组织和提出假设，不能把全文 report prose 当 authority。当前没有 Agent 或 prompt 修改。
稳定的 pair/condition/atom/candidate/source IDs 可供未来 V3-RPT0 生成 evidence graph/condition table，当前未实现 renderer。

下一阶段建议优先 **pairing-data ingestion**：先取得目标/配置相同的 firmware 与 hardware 材料、
可追溯的板卡或 processor/session manifest、真实硬件 trigger 的 typed 条件及来源、对应 firmware 地址/指令/资源映射。
有了真正 eligible pair 后再扩展 XL1 确定性匹配和生产 fact adapters。A6 则仍需明确状态模型、入口、输入约束、
路径语义与 solver 证据；静态路径存在本身不能填补这个缺口。即使有 A6，也仍需独立硬件 trigger 验证和可控性证据。

## R–S、Z–AB：验证与历史保护

测试覆盖七类 atom、精确/masked encoding、有限 operands、register state/write 区分、MMIO/CSR direction/value、
privilege、内部状态 unknown、all-of 聚合、metadata、未知/异构/无绑定配对、PowerPC、A4 PC/resource 区分、
A5 static witness/缺失/timing 边界、跨 case/site 引用拒绝、能力/哈希篡改、输入不变、codec round-trip 与 fresh-build determinism。
原全局测试 fixture 禁止网络和外部工具，并清除真实调用许可；全量旧测试中的 fake/stub Agent 路径正常保留。

本地 Python 使用 `.venv/bin/python`。最终验证：

```text
.venv/bin/python -m pytest -q
1064 passed, 27 skipped in 26.74s

.venv/bin/python -m pip check
No broken requirements found.

.venv/bin/python -m compileall -q src tests
exit 0

git diff --check
exit 0
```

新增 XL0 单元测试 86 项、本地 metadata integration 2 项，全部通过。
27 项 skipped 为原有需要额外本地数据或显式环境配置的测试，不含本次两组真实 metadata 负向测试。
另外检查全部 14 个新增文件的行尾空白和末尾换行，因为 `git diff --check` 不覆盖 untracked 文件。

阶段开始为 270 个既有文件建立 SHA256 快照，完成后逐一核对。
唯一变化的既有文件是 root README：原 96 个 src 文件、50 个 tests 文件、81 个 output 文件均逐字节不变；
其中 output/reviewed 的 12 个文件、DOC-1 教学目录的 9 个文件都不变。
Hardware B2、Firmware B3/A5 outputs 未改动，output 下没有新增或删除文件。
没有 DeepSeek 或其他真实 Agent 调用、Ghidra/angr/formal 执行、prompt 修改、reviewed export。

Git 状态为 `M README.md` 加 14 个 untracked 新文件（本研究文档、8 个生产模块、5 个测试/fixture 文件）。
没有 git add、commit、push 或 tag。XL0 完成后停止，等待人工审核。
