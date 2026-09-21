# V3-FW-CAP0 — FirmwareCapability Foundation

状态：实现候选，尚未冻结；未进入 matcher。

起始：`main` / `34f6629475b5bdc224a8b2d9a5017145b8a2f291` / `v3-xl1-stable`。
XL1、A6、R1.1 保持冻结。本阶段仅新增三个 firmware 模块、三份 unit test 和本文档。
README、CURRENT_STATE、XL1/A6 实现、既有 prompts/workflow 和历史文档均未修改。

## 研究问题和能力边界

FirmwareCapability 描述：在明确入口、条件和约束下，固件可以提供哪些行为原语。
模型结构为 `Origin + Entry + Conditions + Primitives + Constraints + Evidence + Scope`。

以下不是同一件事：

- 代码中有一个事实，与固件能够在所需条件下产生该行为。
- 存在固件漏洞，与存在任意读写或控制流劫持能力。
- 内存写入，与任意写入；受输入影响，与外部输入可控。
- 静态可达，与运行时可达；源指令退休，与外部输入能够到达该位置。
- 分析器能观察/分析某资源，与目标使用者能够控制该资源。

CAP0 是来源绑定的结构化说明，不是路径求解器、攻击能力认证器或跨层 matcher。
真实 A6 转换结果是 **normal_behavior / 部分建模 / external control NOT ESTABLISHED**。
它可以给下一阶段提供保守输入，不能替代入口可达性、输入权限、路径条件或实验验证。

## 与既有 ProcessorBehavior 的关系

既有 `domain.behavior.BehaviorKind` 保持不变。它描述共有行为 IR，没有完整入口/约束/控制权限语义。
CAP0 不自动从 IR summary 推断能力，以下只是明确的概念对应关系：

| 既有 IR | CAP0 原语 | 还缺什么 |
|---|---|---|
| INSTRUCTION | INSTRUCTION_EXECUTION | 执行依据、入口与成立条件 |
| CONTROL_TRANSFER | DIRECT_CONTROL_TRANSFER / INDIRECT_CONTROL_TRANSFER | 确定性目标或目标未知状态；取边和可控性分别建模 |
| MEMORY_ACCESS | MEMORY_READ / MEMORY_WRITE | 读写方向、地址/值/宽度/长度 |
| MMIO_ACCESS | MMIO_READ / MMIO_WRITE | 外设资源身份和具体访问约束 |
| CSR_ACCESS | CSR_READ / CSR_WRITE | CSR 身份、权限与值约束 |
| EXCEPTION / INTERRUPT | EXCEPTION_RETURN / INTERRUPT_HANDLING | 不一一等价，必须另有具体行为依据 |
| REGISTER_ACCESS / PRIVILEGE / dependencies | Conditions、Constraints 或未来额外能力 | 不能因为名字相似直接提升为控制权限 |

READ_OOB / WRITE_OOB / CONTROL_FLOW_HIJACK 等属于另一层能力声明，不能由通用 MEMORY_ACCESS / CONTROL_TRANSFER 或 crash finding 自动生成。

## Schema

版本：`firmware-capability/v1`。公共构建、解析、序列化、摘要函数位于 `firmware/capability.py`。
所有对象采用 Pydantic，未知字段拒绝；复用 Architecture、TargetDescriptor、EvidenceRef。
为保持冻结边界，CAP0 的 Formalization、Predicate、SourceArtifact、Provenance 独立定义，不导入、移动或修改 XL1 同名类型。

| 部分 | 主要字段与语义 |
|---|---|
| 顶层 | architecture、source_case_id、origin、entry、conditions、primitives、constraints、scope、source_artifacts、evidence、retirement_evidence、provenance、limitations，及 ID/hash |
| Origin | normal_behavior / vulnerability_derived / manual_research_input / synthetic_fixture / unknown；漏洞来源必须有 finding_ids 及对应 vulnerability-source provenance |
| Entry | entry_id、kind、pc、function_id/name、interface_id、ownership_status、execution_status、reachability_status、retirement_observation_ids |
| Condition | condition_id、kind、formalization_status、结构 Predicate、说明与来源 |
| Primitive | primitive_id、architecture、entry_id、kind、basis、formalization_status、control、condition/constraint IDs、source_pc、instruction_sequence、source_registers、target_status、transfer_kind |
| Constraints | discriminated typed union，详见下节 |
| Scope | TargetDescriptor、origin_kind、firmware_artifact_ids、platform_id、site_pcs、function_ids、适用类型、假设、未建模内容与限制 |
| RetirementEvidence | 架构、源 PC、encoding、cycle、trace_line、原 observation_id 和证据绑定；interpretation 固定为 source_instruction_retired_only |

Entry 类型：code_site、function、external_interface、interrupt_handler、exception_handler、boot_entry、callback、unknown。
Entry **不是自动的 attacker entry**。唯一函数归属可以填入上下文；ambiguous/missing 不能填猜测函数。
execution_status 仅 static_only / source_instruction_retired / unknown；reachability_status 仅 static_reachable / unknown。
没有可由退休记录直接填写的“从外部接口运行时可达”状态。

Condition 类型：path、input、function_state、register_state、memory_state、privilege、execution_context、ordering、other。
Predicate 支持 eq/neq/in_range/present/before，严格操作数类型和数量，范围不能倒置。

Primitive taxonomy：

```text
INSTRUCTION_EXECUTION
DIRECT_CONTROL_TRANSFER, INDIRECT_CONTROL_TRANSFER
MEMORY_READ, MEMORY_WRITE
MMIO_READ, MMIO_WRITE
CSR_READ, CSR_WRITE
EXCEPTION_RETURN, INTERRUPT_HANDLING
READ_OOB, WRITE_OOB, WRITE_BOUNDED
PARTIAL_ADDRESS_CONTROL, PARTIAL_VALUE_CONTROL, LENGTH_CONTROL
CONTROL_FLOW_INFLUENCE, CONTROL_FLOW_HIJACK, CALLBACK_INFLUENCE
DENIAL_OF_SERVICE, OTHER, UNKNOWN
```

没有 ARBITRARY_WRITE 枚举或隐式 upgrade 函数。
完整的架构枚举支持 ARM、RISCV、POWERPC、X86、UNKNOWN；**当前 A6 adapter 的输入范围仍是冻结 A6 RV32IC resolver**，不宣称已经实现其他架构的自动提取。

## 控制权限与 Type I / Type II

每个 Primitive 都有独立的 ControlAuthority：

```text
status:
  not_established
  firmware_determined
  input_influenced
  bounded_external_control
  full_external_control
  vulnerability_derived_control
  unknown

dimensions:
  address / value / length / target / execution_context

support_basis:
  not_established / explicit_research_definition /
  synthetic_definition / independent_capability_evidence
```

正向控制声明必须有维度、对应 typed constraint 和支持该声明的证据，不能只有 bool。
full_external_control 的地址/值维度必须声明全部控制位，且不能同时声明受限数字范围或固定值。
完整 32 位“值”控制仍不意味着“地址”控制或任意写；其他资源约束始终有效。

CAP0 尚无自动控制能力验证器。正向控制声明仅接收 manual_research_input / synthetic_fixture 的显式支持；schema 检查绑定与内部一致性，不认证人工描述是否正确。
`independent_capability_evidence` 是**显式来源声明**，不是调用了某个未实现的验证器。
不能仅凭 A4、A5、A6、runtime_trace、Fuzzware observation 的来源类别或 finding 引用建立控制权限。

- Type II：正常行为来源，可以说明普通指令、CSR/MMIO 操作、控制转移；无需先有漏洞。真实 A6 adapter 输出属于这一类，但不建立外部触发能力。
- Type I：漏洞来源必须绑定 finding ID；Primitive 仍需单独显式定义和独立来源支持。只有漏洞记录或 crash 描述不能生成 WRITE_OOB / CONTROL_FLOW_HIJACK。

测试里有一份“漏洞记录 + 独立人工能力定义”的正向模型样例，以及仅 crash 记录被拒绝的反例。
两者都是测试构造，并不证明当前真实固件存在任何漏洞。

## Constraints 的精确含义

| 类型 | 结构 |
|---|---|
| target_resource | memory / mmio / csr / register / control_flow / instruction / other / unknown，以及资源 identity |
| address / value | NumericDomain：exact 或 inclusive minimum/maximum；可附 mask/masked_value；controlled_bits 是位掩码；bit_width 是声明的数值域宽度 |
| access_width | 正的精确 bit 数 |
| length | byte 数或含端点上下界 |
| register / CSR / privilege / execution_context | 明确 identity |
| target_set | 具体目标地址集合 |
| ordering | before_primitive_id、after_primitive_id、可选 max_gap_events |

MMIO 地址使用 resource_kind=mmio + address；不从数值地址自行猜测 SRAM/MMIO/CSR 分类。
NumericDomain 目前支持非负 64 位数值，禁止倒置范围、空 domain、非法掩码、越界控制位。
负位移不在这里表达为地址，应由上游先形成明确地址或保持未知。

WRITE_BOUNDED 必须提供 memory 资源、有限地址边界和长度边界；这里的 address 是访问起始地址范围，不能自动证明所有访问字节都落在目标对象边界内。
不同约束之间没有全局 SMT 求解；复杂约束可满足性仍是 UNKNOWN。
字段冲突会拒绝，例如 CSR_WRITE 不能带普通内存 address constraint；WRITE_BOUNDED 不能把 resource 改为 CSR。
数值/控制位不能超出给出的访问位宽。

Synthetic A：SRAM 起始地址 `0x20000000..0x2000000f`，每次写 1 byte，访问宽度 8 bit；声明的值控制掩码为 `0xff`，数值域宽度 32，值限于 0..255。
Synthetic B：CSR_WRITE，明确 synthetic CSR identity，32 bit 访问及完整 32 bit 值域/控制位。
测试证明两者的 typed 资源和约束不同，不能把 A 改名后附上 B 的 CSR 约束通过 validation。
**没有实现 A↔B matcher，也没有产生任何硬件合同匹配结论。**

## Evidence 与来源校验

SourceArtifact 保存 artifact_id、sha256、source_kind、hash_kind。hash_kind 区分实际 file_bytes 与冻结 A6 canonical payload hash。
source_kind 支持 firmware_a6/a5/a4、processor_behavior_ir、runtime_trace、fuzzware_observation、firmware_vulnerability_record、manual_research_input、synthetic_fixture。
这些是来源类别；CAP0 只新增 A6 adapter，没有凭空实现其他上游提取器。
firmware_vulnerability_record 是显式来源绑定用途，不代表当前 LLM findings 已通过漏洞验证。

每个重要对象都继承来源绑定；provenance 必须覆盖该对象的 sources，来源类型必须匹配 registry。
EvidenceRef 必须存在，其 artifact 必须属于引用它的对象的 sources。
人工/合成证据不能伪装成 deterministic analyzer 输出；source kind 没有 llm。

唯一性检查覆盖 artifact/evidence/condition/primitive/constraint/observation IDs，以及引用集合和 provenance。
Entry/Primitive 的 retirement observation 必须有相同 PC、架构和绑定证据；退休证据只支持源指令事件。
scope 架构和 origin 与顶层一致，固件源、site/function applicability 需与 entry 及 registry 相容。

领域模型不读取文件、不检查物理样本路径、不验证来源签名。哈希本身只标识内容，不证明内容科学正确。
真实预览由独立显式调用验证源文件 hash/size 和 ELF 中的指令字节。

## UNKNOWN / missing 与 formalization

可选地址、函数、接口、平台身份使用 null；未建立的控制使用 not_established；没有具体间接目标使用 indirect_unknown。
空 conditions/constraints/primitives 列表是 missing，不代表无需条件、无限资源或不存在行为。
正式建模对象缺少必要结构字段会拒绝；未知架构/primitive/basis/scope 不能伪装为 formalized。

formalization_summary 分别统计 entry、conditions、primitives、constraints、scope 的 total / formalized / partially_formalized / unformalized / unknown / missing。
Entry/Scope 各算一项；空列表 missing=true，不计为 100% 完成。
formalized 是字段层面的结构化程度，不是路径可行证明、能力概率、风险分数或可利用性置信度。
来源与控制权限的科学真实性仍需独立审核。

## 确定性身份

```text
canonical payload = schema_version + 全部 authored input（不含自身 ID/hash）
capability_sha256 = SHA256(UTF-8 canonical payload)
capability_id = "fwcap:" + capability_sha256
```

JSON 对象键排序、紧凑分隔符、禁止非有限数值。解析拒绝重复 JSON key，公共 build/parse/serialize/render/summary 边界重验模型。
对嵌套可变列表进行非法修改，会在这些边界被 identity validation 拒绝。

| 集合语义，规范排序 | 保持原顺序 |
|---|---|
| source/evidence registry、provenance、引用 IDs、finding IDs | constraints 条目，包括 ordered constraints |
| conditions、primitives、retirement_evidence | instruction_sequence |
| control dimensions、scope 固件/位置/函数集合、target_set | source_registers 的位置 |
| assumptions、unmodeled_aspects、limitations | Predicate.operands 与 ordering before/after 方向 |

NumericDomain 的范围上下界是命名字段，不交换。
没有 timestamp/run UUID/host path/temp output/LLM confidence/raw LLM summary 字段；输出目录由调用者使用 capability hash 选择。
来源 ID、人工描述和 EvidenceRef.summary 是显式 authored 内容，修改会改变 hash；模型不能判断调用者是否把 LLM 文本冒充人工描述。
A6 materializer 只接收 typed catalog，不接收 Agent report/free text，也不复制 raw LLM summary。
退休 cycle 是已有轨迹中的语义定位，不是生成时的墙上时钟时间。

## A6 → partial capability

输入：一个已通过内容哈希校验的 FirmwareControlFlowGroundingCatalog 和其中的 fact_id。
转换前深拷贝重验，不修改调用者对象、A6 schema 或 ID。

1. 选择唯一 transfer fact，限 resolved_direct / indirect。
2. 用冻结 RV32IC producer 对原编码重算目标语义并核验 fact ID。A6 旧 ID 的计算发生于 Pydantic 默认字段填充前，不能另创全字段 hash 来替代它。
3. resolved_direct → DIRECT_CONTROL_TRANSFER + 原 source_pc + 单元素静态 target_set。保留 direct_call/direct_jump/conditional_branch 差异。
4. indirect → INDIRECT_CONTROL_TRANSFER，target_status=indirect_unknown，不提供 target_set；return 保留 transfer_kind，不猜测是否属于 exception return。
5. 同 site 的 unique ownership 只填函数上下文；ambiguous/missing 不填具体 owner，也不 nearest-symbol guess。
6. 同 site、encoding 一致的 RuntimeRetirementObservation → source_instruction_retired，保留原 observation ID / cycle / line / trace evidence；不生成 taken-edge。
7. origin 恒 normal_behavior；control 恒 not_established；path condition 保持 unknown。没有漏洞 primitive 或输入控制升级分支。

未支持/未解决的 A6 指令拒绝转换，不能因为解码到了 opcode 就声称有完整能力。
当前只支持当前安装版本可复现的冻结 A6 RV32IC producer；其他 producer 或后端版本不匹配会 fail closed，不修改历史 ID 以强行兼容。

## 真实 partial preview

已通过本地 identity 验证，并创建新的 ignored 目录：

`output/ibex-simple-system:hello-test:paired-workspace/fw-cap0-a7d884ec659e96b6/`

文件：firmware_capability.json、report-fw-cap0-zh.md、preview_manifest.json。
manifest 中的相对路径是调用者复现信息，不进入 capability identity。
没有改写历史 A6 run、旧 XL1 预览、样本或 reviewed output。

| 身份 | 值 |
|---|---|
| 来源 A6 run | 100fcbb2-6ac4-4eb5-821c-09a688957a51（仅用于定位旧文件） |
| Catalog 文件 hash | d9e87443a6137c17395a3ea84f6940b9e621eb43ced899af17556508ffd5afa6 |
| Catalog canonical payload hash | 3c1cb735faa96d41b031df6198179407dfbd7f9f504dcf76710ed127e1648596 |
| ELF hash | 44ac617845e3a99e36b419c028349f86c7bb64d2b33cc6d9711623281a61625c |
| RVFI trace hash | 21748f4370611590e76926ed47a659dbf94ad78d208b1c3ed8db70c09f4ec4b9 |
| A6 fact ID | a6-transfer:278b90251a75894a3bbf939d |
| Capability ID | fwcap:a7d884ec659e96b689a69266e5b43ef99f05d5f07340e7fc5def431a9aedc749 |

已核对：ELF 15856 bytes；trace 118205 bytes；加载段内 `0x100080` 的 4 字节为 `6f00602c`；静态正确目标是 `0x100346`。
对应轨迹有源指令退休记录，cycle 6、line 2。这里只使用源指令退休事实，没有从下一行偷偷推导 runtime taken edge。
该源 site 的 owner 是 missing；报告保持 UNKNOWN，没有借用邻近函数。

报告首屏明确“正常固件行为”“外部控制 NOT ESTABLISHED”。
其含义是：镜像中存在一个确定性解析的直接转移，且历史轨迹记录了源指令退休；外部入口、控制权限、路径可行性、安全影响仍未建立。

### 可复现的显式调用

从仓库根目录，在 `PYTHONPATH=src .venv/bin/python` 下运行下列代码。
只读取已有 catalog、ELF、trace；不运行真实分析工作流、LLM、仿真或 fuzzing。
仅显式写入新的预览目录；重复执行须得到完全相同内容，否则拒绝覆盖。

```python
"""Explicit local CAP0 preview; no workflow, simulator, network or LLM call."""
from io import BytesIO
from pathlib import Path
import hashlib
import json
from elftools.elf.elffile import ELFFile
from chipchain.firmware.control_flow_grounding import parse_catalog, serialize_catalog
from chipchain.firmware.capability_materialization import materialize_a6
from chipchain.firmware.capability import serialize_firmware_capability
from chipchain.firmware.capability_report import render_firmware_capability

run = Path('output/ibex-simple-system:hello-test:paired-workspace/100fcbb2-6ac4-4eb5-821c-09a688957a51')
catalog_path = run / 'firmware_control_flow_grounding.json'
catalog_bytes = catalog_path.read_bytes()
catalog = parse_catalog(catalog_bytes.decode())
assert catalog.catalog_sha256 == '3c1cb735faa96d41b031df6198179407dfbd7f9f504dcf76710ed127e1648596'
before = serialize_catalog(catalog)
paths = {'elf': Path('samples/firmware/ibex-simple-system/hello-test/hello_test.elf'),
         'runtime-selection-trace': run / 'simulation/trace_core_00000000.log'}
verified = []
for source in catalog.source_artifacts:
    raw = paths[source.artifact_id].read_bytes()
    assert len(raw) == source.size_bytes
    assert hashlib.sha256(raw).hexdigest() == source.sha256
    verified.append(dict(artifact_id=source.artifact_id, sha256=source.sha256,
                         size_bytes=source.size_bytes, path=str(paths[source.artifact_id])))
fact = next(f for f in catalog.transfer_facts if f.instruction_pc == 0x100080)
assert fact.resolved_target_pc == 0x100346
elf = ELFFile(BytesIO(paths['elf'].read_bytes()))
segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
            and s['p_vaddr'] <= fact.instruction_pc
            and fact.instruction_pc + len(bytes.fromhex(fact.instruction_encoding)) <= s['p_vaddr'] + s['p_filesz']]
assert len(segments) == 1
segment = segments[0]
offset = fact.instruction_pc - segment['p_vaddr']
assert segment.data()[offset:offset+4].hex() == fact.instruction_encoding
capability = materialize_a6(catalog, fact_id=fact.fact_id)
assert serialize_catalog(catalog) == before
assert capability.origin.kind == 'normal_behavior'
assert capability.primitives[0].control.status == 'not_established'
folder = Path('output') / catalog.case_id / ('fw-cap0-' + capability.capability_sha256[:16])
folder.mkdir(parents=True, exist_ok=True)
manifest = dict(schema_version='fw-cap0-local-preview/v1', source_catalog=str(catalog_path),
    source_catalog_file_sha256=hashlib.sha256(catalog_bytes).hexdigest(),
    source_catalog_payload_sha256=catalog.catalog_sha256,
    selected_fact_id=fact.fact_id, capability_id=capability.capability_id,
    capability_sha256=capability.capability_sha256, verified_files=verified)
# Manifest paths are caller-side reproduction metadata, never capability identity fields.
files = {'firmware_capability.json': serialize_firmware_capability(capability),
         'report-fw-cap0-zh.md': render_firmware_capability(capability),
         'preview_manifest.json': json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)+'\n'}
for name, content in files.items():
    target = folder / name
    if target.exists():
        assert target.read_text() == content, f'Refuse to overwrite different historical output: {target}'
    else:
        target.write_text(content)
print(json.dumps(dict(output=str(folder), **manifest), indent=2))
```

## Synthetic complete capability 与测试

`tests/unit/test_firmware_capability.py::synthetic_input` 为 test-only 完整示例：
合成 callback 入口 `0x1000`；输入长度 1；受限 SRAM 地址写入；明确 8 bit 值控制及资源/宽度/长度限制；来源与 Scope 均标 synthetic。
fixture 是 authored capability definition，不含真实 provider output、二进制或漏洞执行结果。

测试覆盖身份稳定、round-trip、重复 JSON key、集合排序和有序字段保留；架构/来源/证据/约束冲突；Origin 区分；缺项统计；禁止能力升级；A6 direct/indirect/owner/retirement 边界；原对象不变；中文报告首屏和 deterministic rendering。
错误 `0x1002c6` 目标不仅在旧 catalog hash 下被拒绝，即使构造测试重算 catalog/fact ID，仍会因与冻结解码语义不符被 adapter 拒绝。
A4/A5/Fuzzware/runtime 来源类别不能单独建立 external control 也有反例测试。

最终验证：

| 检查 | Exact result |
|---|---|
| CAP0 新增专项 | 69 passed in 0.69s |
| CAP0 + A6 / XL1 / XL0 专项 | 325 passed in 3.58s |
| Full pytest | 1291 passed, 27 skipped in 31.30s |
| pip check | No broken requirements found. |
| compileall | exit 0 |
| git diff --check | exit 0 |

专项命令：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q tests/unit/test_firmware_capability*.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q \
  tests/unit/test_firmware_capability*.py \
  tests/unit/test_firmware_a6*.py \
  tests/unit/test_firmware_grounding.py \
  tests/integration/test_firmware_a6_workflow.py \
  tests/unit/test_hardware_behavior_contract*.py \
  tests/unit/test_cross_layer_contracts.py \
  tests/unit/test_cross_layer_eligibility.py \
  tests/unit/test_cross_layer_matcher.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
git status --short --untracked-files=all
```

Git 可见新增文件仅为：

```text
?? docs/research/v3-fw-cap0-firmware-capability.md
?? src/chipchain/firmware/capability.py
?? src/chipchain/firmware/capability_materialization.py
?? src/chipchain/firmware/capability_report.py
?? tests/unit/test_firmware_capability.py
?? tests/unit/test_firmware_capability_materialization.py
?? tests/unit/test_firmware_capability_report.py
```

既有 268 个 tracked 文件按 SHA-256 核对保持；HEAD 和 tags 保持。
ignored output 仅新建 CAP0 目录；没有 force-add，没有 git add/commit/push/tag。
`git diff --check` 不覆盖 untracked 内容，因此另外检查了这 7 个新文件的尾部空白和文件末尾换行。

## 完成核对：58 项回答

| # | 回答 |
|---|---|
| 1 | 起始 HEAD 34f6629475b5bdc224a8b2d9a5017145b8a2f291；main；v3-xl1-stable。 |
| 2 | 新增 capability.py、capability_materialization.py、capability_report.py；对应三份 unit test；本文，共 7 文件。另有 ignored preview 的三个文件。 |
| 3 | 未修改 XL1 实现、类型、测试或研究文档。 |
| 4 | 未修改 A6；仅调用原模型、resolver 和 codec。 |
| 5 | firmware-capability/v1。 |
| 6 | Origin、Entry、Conditions、Primitives、Constraints、Evidence、Scope，另含来源 registry、provenance、limitations 和身份字段。 |
| 7 | normal_behavior / vulnerability_derived / manual_research_input / synthetic_fixture / unknown。 |
| 8 | code_site / function / external_interface / interrupt_handler / exception_handler / boot_entry / callback / unknown。 |
| 9 | 完整 taxonomy 见 schema；覆盖正常指令/控制转移/访存/MMIO/CSR/异常中断，以及受限写/越界/部分控制/控制流影响等。不是对 frozen BehaviorKind 的修改。 |
| 10 | Origin 显式区分；漏洞 origin 需绑定 finding ID；normal behavior 不自动变漏洞能力。 |
| 11 | 每个 Primitive 带 ControlAuthority，含状态、维度、支持依据及证据绑定；没有 controllable bool。 |
| 12 | input_influenced 是独立状态；renderer 不据此建立 external control，A6 adapter 始终 not_established。 |
| 13 | resource、address/value NumericDomain、access width、length、register/CSR、privilege/context、target set、ordering。 |
| 14 | target architecture、固件来源、platform/site/function、origin_kind、适用类型、假设/未建模/限制。 |
| 15 | null、unknown、not_established、indirect_unknown；空列表 missing，不是无条件或任意资源。 |
| 16 | SourceArtifact 有稳定 ID/hash/kind/hash_kind；Provenance 有 source references、source IDs 和 transformation；类型和覆盖必须一致。 |
| 17 | registry 唯一；引用必须存在，EvidenceRef.artifact_id 必须绑定到使用它的对象。 |
| 18 | SHA256(canonical authored payload)，前缀 fwcap:；排除自身 ID/hash。 |
| 19 | registry、provenance、引用/条件/primitive 集合、scope 集合、targets 和说明集合排序。 |
| 20 | constraints 的顺序、instruction_sequence、source_registers、Predicate.operands 和 ordering 方向保留。 |
| 21 | 没有运行 timestamp/UUID/path/raw LLM 字段参与身份。显式来源描述参与内容身份；调用者路径仅留在 preview manifest。 |
| 22 | entry/conditions/primitives/constraints/scope 分组统计四种 formalization 状态及 missing。 |
| 23 | 不使用 confidence、风险/可利用性分数或能力概率。 |
| 24 | typed A6 catalog + fact_id；catalog hash、源绑定、冻结 producer 语义/身份均校验。 |
| 25 | resolved_direct → DIRECT_CONTROL_TRANSFER、保留 PC/transfer_kind、target_set 为原目标；仍不证明取边。 |
| 26 | indirect → INDIRECT_CONTROL_TRANSFER / indirect_unknown，无具体 target_set。 |
| 27 | 对应 site/encoding 的退休记录用于 source_instruction_retired 和带来源的 RetirementEvidence。 |
| 28 | 没有；adapter control=not_established，retirement 也不能支持通用 taken-edge。 |
| 29 | unique owner 只进入 Entry/Scope 的函数上下文。 |
| 30 | ambiguous/missing 不选 owner；多记录冲突按 ambiguous；不 nearest-symbol guess。 |
| 31 | A6 adapter 不生成 WRITE_OOB 等漏洞 primitive；schema 可容纳明确来源的独立 authored 定义。 |
| 32 | A6 adapter 不生成 CONTROL_FLOW_HIJACK；crash finding 单独不能建立该能力。 |
| 33 | 没有读取 raw LLM summary；不接收模型报告作为转换输入。 |
| 34 | 没有修改 A6 object；测试和真实预览都比较转换前后 canonical serialization。 |
| 35 | 已建立真实 partial preview，只创建新的 ignored output。 |
| 36 | Catalog payload SHA 3c1cb735faa96d41b031df6198179407dfbd7f9f504dcf76710ed127e1648596；fact a6-transfer:278b90251a75894a3bbf939d；capability fwcap:a7d884ec659e96b689a69266e5b43ef99f05d5f07340e7fc5def431a9aedc749。其他输入 hash 见真实预览表。 |
| 37 | 是，origin=normal_behavior，报告首屏写明正常固件行为。 |
| 38 | 是，报告首屏 external control: NOT ESTABLISHED，模型 control=not_established。 |
| 39 | 合成 callback、输入长度条件、SRAM 有限地址/长度写入、8 位值控制、Scope 和来源证据；另有完整 32 位 CSR 值控制的区分测试。 |
| 40 | 是，synthetic_fixture / synthetic_only / test-only；没有真实 provider output。 |
| 41 | 先看结论 → 当前已建立 → 控制能力 → 条件 → 缺口 → Scope → 建模完整性 → 科学边界 → 追溯。 |
| 42 | 是，重验 typed contract 后纯函数渲染；无 IO、随机值或 LLM。 |
| 43 | 未修改 Cross-Layer Agent / prompt。 |
| 44 | 未修改 paired workflow。 |
| 45 | 未实现 matcher，也没有兼容/不兼容自动判定 API。 |
| 46 | 未调用真实 LLM/API/网络；未执行仿真或 fuzzing。 |
| 47 | 69 passed in 0.69s。 |
| 48 | 含新增测试及旧 A6/XL1/XL0 的专项：325 passed in 3.58s；其中 CAP0 69 项，既有专项 256 项。 |
| 49 | 1291 passed, 27 skipped in 31.30s。 |
| 50 | No broken requirements found. |
| 51 | compileall exit 0。 |
| 52 | git diff --check exit 0；额外检查 untracked 文件空白。 |
| 53 | 未修改历史 artifacts；旧 tracked 内容、HEAD/tags 保持。 |
| 54 | 真实上游仍不能客观提取外部入口/输入控制、WRITE_OOB/任意写/HIJACK、完整路径条件、目标取边、安全影响；CAP0 未新增 MMIO/CSR 等自动提取器。 |
| 55 | Type I 缺独立验证的漏洞与具体能力之间的证据链、精确地址/值/长度/权限边界、输入来源和控制程度验证。LLM finding 不能替代它们。 |
| 56 | Type II 缺更多正常行为的确定性提取、真实入口及路径条件、资源/权限/时序约束、与硬件目标身份的对应和必要的运行验证。 |
| 57 | 建议下一阶段审阅后进入最小 deterministic capability-contract compatibility foundation，而非端到端攻击判断。 |
| 58 | 仅 proposal，范围如下；本次没有执行。 |

## 下一阶段最小 proposal（未执行）

建议先用 synthetic fixture 评审一个纯函数式、三态的兼容性接口：

- 输入：已验证的 FirmwareCapability 与 HardwareBehaviorContract，不读报告自由文本，不调用 LLM。
- 先比架构/平台/适用镜像或修订边界；缺必要身份返回 UNKNOWN。
- 仅比较首批明确同类的 primitive/resource/typed constraint，例如 memory 与 CSR 的资源区分、具体 CSR 身份、精确值或闭区间边界。
- 输出逐字段 `compatible / incompatible / unknown` 及证据/来源引用；compatible 只表示已检查要求相容，绝不表示完整 Trigger 已满足、偏差发生或攻击成立。
- synthetic 正例、资源不同负例、范围不覆盖负例，以及缺身份/控制/条件的 UNKNOWN 例。

先明确哪些条件属于必须满足的要求、哪些只是未提供，而后再讨论范围包含逻辑；不默认 UNKNOWN 是通配符。
本轮真实 A6 direct transfer 不能硬凑匹配任何已缺 Deviation/Observation 的硬件样例。
评审后再决定是否扩大到路径、外部输入能力和执行验证；本阶段到此停止。
