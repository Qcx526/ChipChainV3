# V3-XL1 — HardwareBehaviorContract Foundation

状态：实现候选，**尚未冻结**。没有进入 R1.2 或后续 matcher 阶段。

起始 `main` / `ec02a117e414f26e32043a7d9c0bd3964c6485ea`，
对应 `v3-r1-1-boundary-refactor-stable`。
A6 科学基线 `v3-fw-a6-stable`；审计基线 `v3-r1a-audit-stable`。

## 本阶段解决什么

以前的 XL0 能表达必要条件，但不能把它当成包含预期硬件偏差、观察方法和适用边界的完整合同。
本阶段增加独立的 `hardware` package，以 Pydantic 建立六部分要求对象：

```text
Platform + Preconditions + Trigger + Deviation + ObservationRequirement + Scope
```

它回答“在什么目标上，需要满足什么条件，再检查什么偏差、怎样取证”。
它不回答“这份固件已经触发漏洞了吗”。

**固件满足 Trigger ≠ 硬件 Deviation 发生 ≠ Deviation 已被客观观察。**

`AnalysisCapability ≠ TargetInputCapability`。没有外部输入能力证据，不能因某个寄存器是分析入口而认为它可被攻击者控制。

## 参考工程：可读性值得借鉴，判定仍需独立核验

只读查看了 CrossLayersAnalyzer 的提交
`af38979d4545f8b8b030cc3eb78000d887d00c47`，没有执行其程序、复制源码或 dataclass。

[S1 报告](https://github.com/Qcx526/CrossLayersAnalyzer/blob/af38979d4545f8b8b030cc3eb78000d887d00c47/out/reports/S1_positive_controlled.md)
把分析对象、硬件合同、程序摘要、候选原因和未决事项分开，适合作为面向验收者的表达参考。
借鉴的是“先回答读者关心的问题，再提供证据与边界”。

不过，[S2 负例报告](https://github.com/Qcx526/CrossLayersAnalyzer/blob/af38979d4545f8b8b030cc3eb78000d887d00c47/out/reports/S2_negative_constant.md)
统计可行候选为 0，末尾仍宣称存在满足可达性与可控性的候选；负例标题也超出了其静态分析证据能支持的强度。
[分析入口](https://github.com/Qcx526/CrossLayersAnalyzer/blob/af38979d4545f8b8b030cc3eb78000d887d00c47/src/crosslayer/pipeline.py)
还在缺少显式入口时把默认输入寄存器注册成输入入口。这不能作为真实目标可控性的依据。
这里仅评价所查文件，不以这些样例证明或否定整个项目的准确率。

XL1 新报告的计数和缺项直接读取 typed contract；不从模板固定宣称“存在候选”，不调用 LLM。
此次没有更换历史硬件、固件验收报告，也没有改变现有 Agent 输出。

## Schema 和关键语义

Schema：`hardware-behavior-contract/v1`。

| 部分 | 表达内容 | 未知如何处理 |
|---|---|---|
| Platform | 复用 TargetDescriptor；另加 platform_id、rtl_identity、rtl_revision、silicon_revision | 可选身份用 null；architecture 复用 UNKNOWN；不从 RISCV 推断 Ibex |
| Preconditions | condition_id、condition_kind、description、formalization_status、required_relation | 结构关系可缺失；缺失时不能 formalized |
| Trigger | 指令、指令序列、CSR/MMIO 访问、顺序或结构化谓词 | 已填写 typed payload 也不证明已执行或因果关系 |
| Deviation | affected_component、expected_behavior、deviating_behavior、specification_ref、first_divergence_point、hardware_constraint_status | 空列表表示 missing；没有 deviation_observed 字段 |
| ObservationRequirement | observable_target、judgement_kind、required_backend、两种观察判据、evidence_requirement、deviation_ids | 只有观察要求，没有 actual_observed 或实际观测结果字段 |
| Scope | 架构、平台、RTL/芯片修订集合、适用类型、来源权威、假设与盲区 | 未指定集合不表示“全部适用”；UNKNOWN 不会被当成通配匹配结果 |

顶层另有 architecture、source_case_id、source_artifact_ids、evidence_ids、source_artifacts、evidence、provenance、limitations、unclassified_atoms，以及 contract_id / contract_sha256。

Precondition 类型：`privilege`、`execution_context`、`register_state`、`CSR_state`、`memory_attribute`、`protection_state`、`microarchitectural_state`、`hardware_mode`、`ordering_precondition`、`other`。

Trigger 类型：`instruction`、`instruction_sequence`、`register_state`、`CSR_access`、`MMIO_access`、`memory_operation`、`interrupt`、`exception`、`ordering`、`timing_window`、`concurrency`、`transaction`、`other`。

Deviation 类型：`wrong_value`、`missing_update`、`unexpected_update`、`missing_exception`、`unexpected_exception`、`access_control_violation`、`ordering_violation`、`protocol_violation`、`state_corruption`、`timing_deviation`、`information_leakage`、`other`、`unknown`。

Observation 类型：`architectural_state`、`RTL_signal`、`register_value`、`memory_value`、`exception_state`、`protocol_event`、`timing_measurement`、`statistical_measurement`、`board_trace`、`other`。

所有要求共用 `condition_id` 命名空间；Deviation / Observation 没有再增加一套重复的 ID 字段。
`ObservationRequirement.deviation_ids` 必须引用本合同的 Deviation condition_id。

`Predicate` 支持 eq / neq / masked_eq / in_range / present / before，严格区分整数、字符串和布尔操作数；范围与掩码需自洽。
指令、访问和事件顺序复用 XL0 的既有 typed atom 值类型，**没有修改它们**。
非指令类触发只提供保守的结构化谓词容器，尚不是完整的时序逻辑语言。
多个触发要求共同构成要求集合；传输顺序仍保留，不能解释成已经观察到的执行轨迹。

空组件列表表示没有提供该部分，不能解释成“不需要任何前置条件”或“不存在偏差”。
未知标量用 null 或类型内的 unknown；formalization_status 为 unknown 的对象可以保留部分已知参数，但不能被称为完整建模或 verified。

## 来源、证据与验证

每个六部分对象和条件都要求显式绑定 source_artifact_ids 和 provenance。
SourceArtifact 只保存稳定 ID、内容 SHA-256、source_kind，不存主机路径。
支持 EnCorpus、RTL mutation 描述、formal result、CVE/erratum metadata、Hardware A3、XL0、manual_research_input 和 synthetic_fixture。
不提供 LLM source_kind；不会从自由文本报告自动提取合同。

EvidenceRef 复用项目既有类型，registry 内 ID 唯一；它引用的 artifact 必须存在于 source registry。
一个条件引用的 EvidenceRef，其 artifact 也必须在该条件绑定的 sources 中。
provenance 的 source_kind 必须匹配 registry，并覆盖该对象所有 source。
manual / synthetic 来源的证据不能标为 deterministic_analyzer。
Deviation.specification_ref 是已绑定 source artifact ID，不是未校验的任意外部引用。

这些验证保证引用与声明的来源类型一致，不证明调用者提交的哈希对应真实文件，更不证明其研究描述正确。
领域模型不读取文件。示例显式计算本地源文件哈希；adapter 还核验 XL0 artifact hash 与输入 XL0 canonical bytes 一致。

观察要求中的 evidence_ids 支持“为何制定这个观察要求”，**不是实际观测结果**。
即使这些引用中包含 observed / derived 的采样事实，也不能据此把合同标成偏差已发生。
`actual_observed`、`deviation_observed`、`verified` hardware_constraint_status、confidence 等字段或状态均被拒绝。
未来实际观测记录需要单独设计并绑定测量条件；本阶段没有创建这种记录。

重复的 registry ID、condition ID、atom ID、引用 ID、provenance 和适用集合元素会被拒绝。
合同、平台、指令/特权 atom 架构必须相容；平台和已声明修订必须落在 Scope 明确约束内。
UNKNOWN 架构的指令不能标成 formalized。

## 确定性身份

`canonical_payload` = schema_version + 经过规范化的全部 authored input，排除输出的 contract_id / contract_sha256。
UTF-8 JSON，键排序，无额外空白，禁止非有限数值。

```text
contract_sha256 = SHA256(canonical_payload)
contract_id = "hwbehavior:" + contract_sha256
```

这是 payload hash，不是包含 hash 自身的完整 JSON 文件 hash。

| 集合语义：排序 | 顺序语义：保留 |
|---|---|
| source_artifacts、evidence、引用 IDs、provenance | trigger 条目顺序，包括 ordering constraints |
| preconditions、deviation、observation、unclassified_atoms | instructions 序列及指令 source_registers 位置 |
| 适用架构/平台/修订集合 | Predicate.operands，如范围下限/上限、值/掩码 |
| assumptions、unmodeled_aspects、blind spots、limitations | ordering 的 before/after 方向不交换 |

不依赖时钟、运行 UUID、文件存储位置或临时输出目录。schema 没有这些字段，也没有 LLM 文本/置信度字段。
描述、限制和 EvidenceRef.summary 是**显式来源绑定的研究输入**，保留在内容身份中；修改这些内容会改变 hash。
这不是自然语言语义去重算法，也不能识别调用者是否把 LLM 文本冒充人工输入。
adapter 拒绝 hardware_trigger_hypothesis 来源及带 source_hardware_hypothesis_id 的输入，且不会复制 XL0 context_notes 到条件描述。
旧 XL0 本身的内容 hash 仍完整绑定原对象，不重写其既有身份定义。

serialize / parse / renderer / summary 都在边界重验合同；嵌套模型并非深度不可变，非法原地修改会在这些边界失败。
parse 还拒绝重复 JSON key。ID 不符的完整合同不能通过解析。

## XL0 → XL1 显式部分转换

`materialize_xl0` 必须显式调用；调用者提供 Platform、source/evidence registry 和 XL0 artifact ID。
没有 workflow 自动接入或隐式文件写入。

| XL0 输入 | 默认输出 | 解释 |
|---|---|---|
| required instruction | Trigger instruction，partially_formalized | 保存指令字段，不提升执行/因果能力 |
| required CSR/MMIO access | Trigger CSR_access / MMIO_access，partially_formalized | 保存访问条件 |
| required ordering | 两端均已映射到 Trigger 时保留；否则 unclassified | 不用前置状态冒充触发事件端点 |
| register_state / hardware_state / privilege_state | unclassified，state_timing_unknown | 默认不猜测状态处于触发之前还是触发之中 |
| verification_only_metadata | unclassified，verification_metadata | 不是必要触发条件 |

如研究者提供显式 `state_roles`，并提供绑定 manual_research_input artifact 的 role_provenance：

- precondition：register_state → register_state；hardware_state → microarchitectural_state；privilege_state → privilege。
- trigger：register_state → register_state；hardware_state / privilege_state → other + typed predicate。
- 不能将 instruction、ordering 或 verification metadata 通过此参数重新分类。

角色声明是一项带来源的人工研究决定，转换本身才是确定性程序操作。
所有转换仍为 partial；转换不了的 atom 保留原 typed payload 与原因。
原 XL0 object、condition_id、codec 和 schema 完全不改；没有 XL1 → XL0 等价降级。
Deviation 与 Observation 始终为空，绝不从 trigger 名字补造。

## 真实来源演示：743 的采样指令，不是漏洞触发证明

本地没有找到可直接使用的独立 XL0 condition JSON。
因此演示明确分两步：研究者从已有 A3 输出选择一个指令编码关系，构造新的 XL0 要求；再调用 adapter 转成部分 XL1。
这不是“找到了历史 XL0 合同”，也不是从采样指令自动发现异常原因。

来源：
`output/encorpus:ibex:driver:743/fb6aa19d-5155-4be4-9304-50bca79e155f/hardware_typed_relations.json`。

选中关系：
`hwrel:18b53562dff1433df965947ec63544e767988ea4b143b872c0062e2c6a190f51`。

编码 `0x00130e13`，解码 `addi x28, x6, 1`，ID 阶段，decompressed_word。
来源 capability 明确不支持 trigger causality、instruction execution / retirement 或 vulnerability。
4 个 EvidenceRef 指向本地 proof.vcd 的源赋值位置（包括带 carry-forward 语义的位置）；未重新执行仿真。

| 来源 | SHA-256 |
|---|---|
| 原 A3 JSON | e9f0da2fea7df21b9a028c38b685292895d160ad3b521b77e4bd568cace23753 |
| proof.vcd | f6be33b33c557cc1f8d849da580b7a0ce7d7646a3eadbff7d0d3c06a159e66e8 |
| 本次显式 XL0 要求 | a14c809662b97c65b2dbca0f824ec2e76710de2c1df7e7dc65933b2e6ea0eb2c |
| 人工选择记录 | ed89939ec6ad6db5e388c9a1d50939b30c1d2d7bbfcfd2f995f0e9536f954ac4 |

新合同 ID：`hwbehavior:48dba3c5ba26c30d65fba23d8293c7689443bbd362a0616e698a19c4492b197c`。

本次显式新建、被 Git 忽略的结果目录：
`output/encorpus:ibex:driver:743/xl1-48dba3c5ba26c30d/`。
包含 hardware_behavior_contract.json、report-xl1-zh.md、selected_xl0_condition.json、manual_selection.json。
未覆盖任何本阶段开始前的 output。

结果：1 项部分结构化 Trigger；Preconditions、Deviation、Observation 均 missing；Scope 部分结构化。
Platform 的 Ibex 名称来自明确研究输入，位宽、ISA variant、RTL/芯片修订、具体平台保持 UNKNOWN；没有按 RISCV 推断这些值。
报告的第一段会直接告诉验收者：它是要求说明，不是实验成功报告。

### 可复现的显式调用

从仓库根目录，在 `PYTHONPATH=src .venv/bin/python` 下执行下列代码。
只读已有材料，显式创建新的 XL1 预览文件；已有目标文件内容不同时拒绝覆盖。
不依赖网络，不运行 LLM、模拟器、fuzzer 或源数据分析器。

```python
"""Explicit local demonstration: selected A3 encoding -> XL0 -> partial XL1.

No analyzer/LLM run; only existing artifact reads and explicit new preview writes.
"""
import hashlib
import json
from pathlib import Path

from chipchain.cross_layer.trigger import (
    HardwareTriggerConditionInput, build_hardware_trigger_condition,
    hardware_trigger_condition_sha256, serialize_hardware_trigger_condition,
)
from chipchain.domain.evidence import EvidenceRef
from chipchain.hardware.behavior_contract import (
    Platform, Provenance, SourceArtifact, formalization_summary,
    serialize_hardware_behavior_contract,
)
from chipchain.hardware.behavior_contract_materialization import materialize_xl0
from chipchain.hardware.behavior_contract_report import render_hardware_behavior_contract

source_path = Path('output/encorpus:ibex:driver:743/fb6aa19d-5155-4be4-9304-50bca79e155f/hardware_typed_relations.json')
vcd_path = Path('samples/hardware/encorpus/ibex/driver/743/proof.vcd')
source = json.loads(source_path.read_text())
relation_id = 'hwrel:18b53562dff1433df965947ec63544e767988ea4b143b872c0062e2c6a190f51'
relation = next(r for r in source['relations'] if r['relation_id'] == relation_id)
assert relation['kind'] == 'instruction_encoding_observed'
assert not relation['capabilities']['supports_trigger_causality']
decoded = relation['attributes']['decoded_instruction']
assert decoded['status'] == 'decoded'
manual_input = {
    'source_kind': 'manual_research_input',
    'selection': relation_id,
    'purpose': 'Explicit instruction condition to investigate; no causal trigger claim.',
    'processor_id': 'ibex',
    'platform_id': None,
    'revision': None,
}
manual_bytes = json.dumps(manual_input, sort_keys=True, separators=(',', ':')).encode()
manual = SourceArtifact(artifact_id='research:xl1:743:selection', source_kind='manual_research_input',
                        sha256=hashlib.sha256(manual_bytes).hexdigest())
manual_origin = Provenance(source_kind='manual_research_input', source_artifact_ids=[manual.artifact_id],
                           source_ids=[relation_id])
xl0 = build_hardware_trigger_condition(HardwareTriggerConditionInput(
    hardware_case_id=source['source']['case_id'], architecture=source['source']['architecture'],
    source_kind='hardware_relation', source_ids=[relation_id], epistemic_status='derived',
    all_of_atoms=[dict(atom_id='selected:instruction-encoding', kind='instruction',
        architecture=decoded['architecture'], mnemonic=decoded['mnemonic'],
        encoding=int(decoded['raw_encoding'], 16), representation=decoded['representation'],
        stage_requirement=decoded['source_stage'],
        operand_pattern=dict(destination_register='x28', source_registers=['x6'], immediate_exact=1))],
    context_notes=['Explicit research selection of a sampled encoding; no execution or trigger causality asserted.'],
))
refs = [EvidenceRef.model_validate(e) for e in decoded['evidence']]
assert {e.artifact_id for e in refs} == {'encorpus:ibex:driver:743:proof.vcd'}
sources = [
    SourceArtifact(artifact_id='xl0:743:selected-instruction', source_kind='xl0_trigger',
                   sha256=hardware_trigger_condition_sha256(xl0)),
    SourceArtifact(artifact_id='hardware-a3:743:relations', source_kind='hardware_a3',
                   sha256=hashlib.sha256(source_path.read_bytes()).hexdigest()),
    SourceArtifact(artifact_id=refs[0].artifact_id, source_kind='encorpus_observation',
                   sha256=hashlib.sha256(vcd_path.read_bytes()).hexdigest()),
    manual,
]
platform = Platform(target=dict(architecture=source['source']['architecture'], processor_id='ibex'),
                    source_artifact_ids=[manual.artifact_id], provenance=[manual_origin])
result = materialize_xl0(xl0, platform=platform, source_artifacts=sources, evidence=refs,
                         xl0_artifact_id='xl0:743:selected-instruction')
assert not result.deviation and not result.observation and not result.preconditions
folder = Path('output') / source['source']['case_id'] / ('xl1-' + result.contract_sha256[:16])
folder.mkdir(parents=True, exist_ok=True)
files = {
    'hardware_behavior_contract.json': serialize_hardware_behavior_contract(result).encode(),
    'report-xl1-zh.md': render_hardware_behavior_contract(result).encode(),
    'selected_xl0_condition.json': serialize_hardware_trigger_condition(xl0).encode(),
    'manual_selection.json': manual_bytes,
}
for name, content in files.items():
    target = folder / name
    if target.exists():
        assert target.read_bytes() == content, f'Refuse to overwrite different output: {target}'
    else:
        target.write_bytes(content)
print(json.dumps(dict(contract_id=result.contract_id, contract_sha256=result.contract_sha256,
    xl0_id=xl0.condition_id, output=str(folder), sources=[s.model_dump() for s in sources],
    summary={k:v.model_dump() for k,v in formalization_summary(result).items()}), indent=2))
```

## Synthetic complete contract 和报告

`tests/unit/test_hardware_behavior_contract.py::complete_input` 是唯一完整示例，明确 test-only。
它使用 RISCV 架构标签的 synthetic core，预先进入 test mode，先设 x1 为 4294967295，再按合成定义加 1。
合成规格要求结果为 0；偏差要求定义为结果不为 0；观察要求是在 synthetic_test_backend 比较结果。
这不是在断言实际 RISC-V 指令集含有 synthetic_set / synthetic_add，也没有声称任何现有处理器有这个缺陷。
fixture 中的 EvidenceRef 只指向合成规格，**不包含执行结果**。

renderer 纯函数输出中文 Markdown，结构如下：

1. 先看结论：条目数量、缺项、实际观测未记录。
2. 平台及前置/触发/偏差/观察要求；以第几项要求呈现，而不是先堆长 ID。
3. 适用范围、假设和未分类原因。
4. 分部分建模计数。
5. 验收前尚需补充的规格、观察方法及适用范围。
6. 科学边界，以及最后的 ID/hash/EvidenceRef 定位。

同一规范化合同输出同一文本；集合重排不影响文本。
计数、缺项、补充事项均按模型字段生成，不固定套用成功结论。
来源中的 Markdown/HTML 特殊字符被转义，以减少排版歧义。
没有宣称这是面向所有硬件异常的完整自然语言解释器。

## Formalization summary 的含义

逐一计数 Preconditions / Trigger / Deviation / Observation 中的 formalization_status；Scope 算一个组件；unclassified_atoms 单列 unknown。
每组记录 total、formalized、partially_formalized、unformalized、unknown、missing。
空组 total=0、missing=true，不算 100% 完成。

formalized 表示该类要求具备所需的结构参数，不表示已经存在可执行 checker，更不表示要求成立。
状态由显式输入声明，并由 schema 检查必要字段；没有对所有数学约束求解或验证其可满足性。
UNKNOWN 参数不能通过缺字段冒充完整要求；但 schema 不能判断一段人工描述是否科学正确。
没有 confidence、risk score、漏洞分数或攻击成功率，也没有把 formalization ratio 作为概率。

## 验证记录

最终结果见下表；所有 pytest 均设 `CHIPCHAIN_ENABLE_REAL_LLM=0`。

| 检查 | 结果 |
|---|---|
| XL1 新增专项 | 54 passed in 0.34s |
| XL1 + 既有 XL0 / A6 专项 | 256 passed in 2.67s |
| full pytest（最终代码） | 1222 passed, 27 skipped in 31.07s |
| `.venv/bin/python -m pip check` | No broken requirements found. |
| `.venv/bin/python -m compileall -q src tests` | exit 0 |
| `git diff --check` | exit 0 |

专项命令：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q tests/unit/test_hardware_behavior_contract*.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q \
  tests/unit/test_hardware_behavior_contract*.py \
  tests/unit/test_cross_layer_contracts.py \
  tests/unit/test_cross_layer_eligibility.py \
  tests/unit/test_cross_layer_matcher.py \
  tests/unit/test_firmware_a6.py \
  tests/unit/test_firmware_a6_evidence.py \
  tests/unit/test_firmware_grounding.py \
  tests/integration/test_firmware_a6_workflow.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
git status --short --untracked-files=all
```

## 完成核对：逐项回答 48 个问题

| # | 回答 |
|---|---|
| 1 | 起始 HEAD ec02a117e414f26e32043a7d9c0bd3964c6485ea，tag v3-r1-1-boundary-refactor-stable。 |
| 2 | 仅新增 hardware 包中的 __init__.py、behavior_contract.py、behavior_contract_materialization.py、behavior_contract_report.py；三份对应 unit test；本研究文档，共 8 个 Git 可见新文件。另有被忽略的新 XL1 预览目录。 |
| 3 | 没有修改冻结 XL0 文件。 |
| 4 | 没有修改 A6。 |
| 5 | hardware-behavior-contract/v1。 |
| 6 | Platform 与 Scope 是带来源对象；其余四部分是带来源的 typed requirement 列表。 |
| 7 | Platform 复用 TargetDescriptor；加平台、RTL 身份/修订、芯片修订，详见 schema 部分。 |
| 8 | 10 种 Precondition 类型，完整列表见 schema；结构化要求为 Predicate。 |
| 9 | 14 种 Trigger 类型，完整列表见 schema；指令/访问/顺序具有专门 payload。 |
| 10 | 13 种 Deviation 类型；区分正常和偏离规格的要求，没有发生标记。 |
| 11 | 10 种 ObservationRequirement 类型；与实际观测分离。 |
| 12 | typed 架构/平台/修订约束、synthetic_only/rtl_revision_only/specified_targets/unknown、silicon applicability、source authority。 |
| 13 | null / unknown；空组件列表表示 missing，未分类 atom 保留 typed 原值和原因。 |
| 14 | Provenance 绑定 source_artifact_ids/source_kind/source_ids/transformation，并核对 registry 类型与覆盖范围。 |
| 15 | EvidenceRef registry 唯一；引用及其 artifact 必须存在并绑定到相应 requirement。 |
| 16 | schema + canonical authored payload 的 SHA-256，ID 前缀 hwbehavior:。 |
| 17 | source/evidence registries、引用集合、provenance、非 Trigger 的要求集合、Scope 适用集合、说明集合排序。 |
| 18 | trigger 条目、ordering constraints、instructions、source_registers 和 Predicate operands 保留顺序。 |
| 19 | 无自动 timestamp/UUID/path 字段参与身份；调用者须使用稳定来源身份。旧来源内容 hash 保留其既有语义。 |
| 20 | 按每组显式 formalization_status 计数；空组标 missing；Scope 单独一项，unclassified 单列。 |
| 21 | 没有概率/置信度比率；formalized 也不意味着已实现 checker 或约束已满足。 |
| 22 | 显式 XL0 输入及来源 registry；检查上游 digest，单向保守转换，规则见上表。 |
| 23 | 默认无 state atom 自动升为 Precondition；有 manual research 角色声明时，register/hardware/privilege state 分别进入 register_state/microarchitectural_state/privilege。 |
| 24 | required instruction、CSR/MMIO、端点已归类的 ordering 自动进入 Trigger；显式角色也可指定 state trigger。 |
| 25 | 时间角色不明或端点未分类时保留 UnclassifiedAtom；verification metadata 不进入 Trigger。 |
| 26 | 没有修改原 XL0 object 或 ID；专项比较转换前后序列化结果。 |
| 27 | 没有生成真实 Deviation；真实例与 adapter 输出保持 missing。 |
| 28 | 没有生成真实 Observation；真实例与 adapter 输出保持 missing。 |
| 29 | Synthetic wrapping-adder 完整要求：test mode、设值/加法、预期结果 0、偏差非 0、测试后端比较。 |
| 30 | source_kind synthetic_fixture、scope synthetic_only、明确 test-only；不是漏洞或执行证据。 |
| 31 | 中文报告先结论和缺项，再六部分、未分类、完整性、验收缺口、科学边界、追溯信息。 |
| 32 | renderer 是重验后的 deterministic 纯函数；不访问文件、不调用模型。 |
| 33 | 没有新增或执行 LLM 调用。 |
| 34 | 没有修改 Agent prompt。 |
| 35 | 没有修改 paired workflow，也没有自动消费 XL1。 |
| 36 | 没有实现 matcher。 |
| 37 | 没有实现 FirmwareCapability。 |
| 38 | 没有实现 E0–E4 全局 schema，也没有重标旧 Evidence。 |
| 39 | 新增 54 项 XL1 测试；与既有 XL0/A6 合计 256 项专项通过，exact result 见验证记录。 |
| 40 | full pytest exact result 见验证记录。 |
| 41 | pip check: No broken requirements found. |
| 42 | compileall: exit 0。 |
| 43 | git diff --check: exit 0；新文件另做尾部空白检查。 |
| 44 | 既有 tracked 文件逐字节 hash、HEAD 与 tags 核对保持；CURRENT_STATE、README、冻结文档、历史测试/输出均未修改。只创建本阶段新预览文件。 |
| 45 | 不求解约束、不验证来源真实性、不测量偏差、不做匹配；schema 只部分描述复杂并发/时序/统计语义；manual 输入仍需人工审阅。 |
| 46 | 实际适用平台/修订、状态的时间角色、偏差/规格、首分歧、观察方法/后端、实机适用性、输入可控性不能从当前 XL0 自动补齐。 |
| 47 | 建议先做 XL1.1 matcher preparation：梳理可匹配字段与所需固件事实边界，用 synthetic 正/负/UNKNOWN 样例评审；暂不直接建立大而全的 FirmwareCapability。 |
| 48 | 上一条仅 proposal；本阶段没有执行后续能力开发。 |

建议下一次人工评审重点：先读 743 的新中文报告，确认能看懂“现在知道什么、还缺什么”；再审阅完整 synthetic contract 的偏差与观察分离，以及手工指定 state_roles 的边界。
评审通过后，才决定下一阶段匹配接口的具体范围。
