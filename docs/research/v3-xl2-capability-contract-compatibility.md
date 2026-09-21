# V3-XL2 — Deterministic Capability–Contract Compatibility Foundation

状态：实现候选，尚未冻结；本阶段完成后停止。

起始 `main` / `6acfbd25ab0db5293c1385927cb6b24b5c60a67d` / `v3-fw-cap0-stable`。
XL1 基线 `v3-xl1-stable`，A6 基线 `v3-fw-a6-stable`。
本阶段没有修改 FW-CAP0、XL1、A6、XL0、Agent、prompt、paired workflow、README 或 CURRENT_STATE。

## 目的与边界

XL2 只比较两个来源绑定的 typed 声明：固件提供的行为/约束，与硬件声明的 Trigger/Preconditions 要求。

**compatibility ≠ satisfiability ≠ reachability ≠ runtime trigger ≠ deviation ≠ vulnerability ≠ attack chain。**

- COMPATIBLE：在当前支持的字段范围内，相关要求有足够信息完成比较，且未发现冲突。
- INCOMPATIBLE：针对本次输入的某项必要要求，存在明确 typed 字段冲突；不代表整个固件不存在其他能力，也不代表漏洞不可利用。
- UNKNOWN：必要信息不足、语义不受支持，或相关条件尚未建立。没有把 UNKNOWN 当成兼容或冲突。

兼容性记录只派生自输入合同，不新增执行、触发、偏差或漏洞证据。
本阶段没有生成 cross-layer candidate 或 attack chain 对象。
内部 alternatives 只是对输入中已经存在的固件原语分别比较，不是生成攻击候选。

## 新增文件和 API

```text
src/chipchain/cross_layer/capability_compatibility.py
src/chipchain/cross_layer/capability_compatibility_report.py
tests/unit/test_capability_compatibility.py
tests/unit/test_capability_compatibility_report.py
docs/research/v3-xl2-capability-contract-compatibility.md
```

主要 API：

- `compare_capability_contract(firmware, hardware)`：纯确定性比较，重验输入身份，不读文件、不改输入。
- `compare_numeric_domains(provided, required, quantifier=...)`：方向明确的数值域包含 helper。
- `serialize_compatibility_result` / `parse_compatibility_result`：canonical JSON 与严格解析。
- `validate_compatibility_replay(result, firmware, hardware)`：在当前规则下重新比较，验证记录确实由指定输入派生。
- `render_capability_compatibility(result)`：typed result → 中文 Markdown 纯函数。

FW-CAP0/XL1 的重复类型保持原位；新模块使用显式比较 helper，没有进行 shared types 重构。

## 结果 schema、逐项记录与 provenance

Schema：`capability-contract-compatibility/v1`。
规则版本：`xl2-typed-subset/v1`。
模型：`CapabilityContractCompatibilityResult`。

结果包含输入双方 ID/hash、规则版本、platform_result、requirement_results、overall_result、checked_dimensions、unsupported_dimensions、missing_information，以及原始 source/evidence references、limitations。

每项 RequirementResult 区分 platform / precondition / trigger / unclassified，记录字段检查、原因码及固件原语的 alternatives。
alternative 引用实际 Primitive/Constraint/Condition IDs；requirement 另有 context_primitive_ids、firmware_constraint_ids、firmware_condition_ids 和来源/证据指针。
平台及上下文解释中的引用可能覆盖多个关联输入；它们表示比较所读的来源，不表示每条来源单独证明整个结论。

引用使用 `(side, identity)` 命名空间，避免 firmware/hardware 重名 artifact 或 evidence 混淆。
来源保留原 hash 和 hash_kind；EvidenceReference 只指向已有 EvidenceRef，不制造新的 observation。
provenance 固定为 `derived_from_typed_contracts`。

Deviation 和 Observation 分别保留在 `downstream_verification_requirements`：

- `missing`：原合同缺项。
- `present_not_assessed`：有明确 requirement IDs，但未验证。

它们**不参与兼容性聚合**。`unassessed_contract_sections` 还记录 runtime execution、path feasibility、joint satisfiability、安全影响、未声明的控制需求、Scope 自由文本假设，以及缺失的 Preconditions/Trigger 等。
没有“完整合同已满足”的 bool。

解析校验内部聚合、ID/hash、字段覆盖与引用一致性。它不能凭一个文件的自洽 hash 验证外部事实；验证实际输入与当前规则需使用 replay API。

## 平台与适用范围 gate

| 维度 | 规则 |
|---|---|
| Architecture | 任一 UNKNOWN → UNKNOWN；明确同架构 → compatible；明确不同 → incompatible |
| Platform | 优先使用 HW Scope.applicable_platforms，否则使用明确 HW platform_id；FW platform_id 缺失或范围中有 UNKNOWN → UNKNOWN；明确包含/排除分别 compatible/incompatible |
| Processor | 明确相同 processor_id 可比较；不同名称仅在双方明确同一 platform_id 时按身份冲突比较，否则 UNKNOWN，避免把 Ibex 与某配置名称直接判为不同处理器 |
| Scope 类型 | 任一 applicability unknown → UNKNOWN；synthetic_only 不跨到未声明 synthetic 的范围；这里只比较声明，不认证来源真实适用性 |
| Word size / endianness | HW 明确要求时检查；FW 缺失 → UNKNOWN，明确不同 → incompatible |
| ISA variant | 字符串不是本版的 ISA 语义模型；HW 明确给出时 UNKNOWN |
| RTL / silicon 身份与修订 | CAP0 没有对应字段，HW 给出要求时 UNKNOWN；不拿固件 ELF hash 代替 RTL identity |

同架构绝不等于同平台。平台范围、CSR 或状态 identity 都按显式标识符比较，不做拼写相似度、别名猜测或 ISA 名称解析。

## 白名单与当前实际可检查范围

| FW Primitive | HW Trigger | 支持内容 |
|---|---|---|
| CSR_READ / CSR_WRITE | CSR_access | access direction、resource=csr、精确 CSR identity；有值要求时比较明确数值域 |
| MMIO_READ / MMIO_WRITE | MMIO_access | access direction、resource=mmio、地址；HW 给出 width 时比较宽度；有值要求时比较明确数值域 |
| INSTRUCTION_EXECUTION | instruction | 识别白名单映射；架构由平台 gate 检查；CAP0 没有足够指令字段时必须 UNKNOWN |

CSR identity 不同 → incompatible；缺失或 UNKNOWN → UNKNOWN。
CSR 数字地址没有 CAP0 对应字段，不能把 identity 字符串自动解释成 CSR address；返回 UNKNOWN。
access=either 接受明确 read 或 write，不改变原语本身类型。

MMIO exact 地址按单点要求检查；FW exact 相同或 FW range 包含该点 → compatible；明确排除 → incompatible；缺地址/边界 → UNKNOWN。
双方 width 明确且不等 → incompatible；HW 要求 width 而 FW 未给出 → UNKNOWN。
数值超出 helper 的非负 64 位支持范围 → UNKNOWN，不让类型构造失败变成伪结论。

CAP0 `instruction_sequence: list[Identifier]` 没有独立的 mnemonic / encoding / encoding representation / operand pattern / stage 字段。
因此本版**不把字符串当助记符，不把十六进制字符串当已确定表示的指令编码**。
INSTRUCTION_EXECUTION ↔ instruction 能识别类型关系，但 HW 要求的这些指令字段不能比较时仍 UNKNOWN。
这意味着当前 v1 不提供非平凡 instruction 完整正例；此限制优于修改 frozen schema 或猜测表示。

DIRECT_CONTROL_TRANSFER / INDIRECT_CONTROL_TRANSFER 不重分类成 INSTRUCTION_EXECUTION。
instruction_sequence、时序窗口、并发、事务、异常/中断等未列明的 Trigger，以及其他原语配对，均不凭名称匹配。

## Resource mismatch

显式 disjoint 资源类别可以形成冲突：例如声明的 MEMORY_WRITE / WRITE_BOUNDED 属于 memory，不能满足 CSR_access 或 MMIO_access 的资源类别要求。
这是一条明确的资源类别规则，不是把所有“不在白名单”的配对判不兼容。

对于 DIRECT_CONTROL_TRANSFER ↔ instruction 等没有安全关系的配对，结果是 UNKNOWN / NO_SUPPORTED_MAPPING。
不能因为当前系统没有 extractor/mapping，就证明固件绝无这种行为。

## 数值域方向与量词

**方向固定：FW 提供域包含 HW 要求域。不是交集判断。**

| FW | HW | 前提 | 结果 |
|---|---|---|---|
| exact 0 | exact 0 | 单点无量词歧义 | compatible |
| exact 5 | exact 0 | 单点 | incompatible |
| [0,255] | exact 0 | 单点 | compatible |
| [0,255] | exact 256 | 单点 | incompatible |
| [0,1024] | [0,255] | 显式 contains_all | compatible |
| [0,255] | [0,1024] | 显式 contains_all | incompatible |
| [0,255] | [128,512] | 显式 contains_all；有交集仍不覆盖 | incompatible |
| [0,255] | [0,1024] | 量词未指定 | UNKNOWN |

独立 helper 的 `quantifier='contains_all'` 是调用者明确的数学问题。
**真实 XL1 in_range 没有 existential/universal 量词字段，所以主 matcher 不替它传 contains_all，而返回 UNKNOWN / RANGE_QUANTIFIER_UNSPECIFIED。**
eq 的单点没有这个歧义，可以直接比较。

只支持 exact 或完整 inclusive min/max。mask/masked_eq/neq 等暂不求解。
controlled_bits 只是控制位声明，不会自动转换成可提供的数值范围；只有控制位而无 exact/range 时 UNKNOWN。
即便数值域覆盖成立，也没有证明输入能选择那个值、路径可达或行为可执行。

## Preconditions 与显式控制要求

前置条件必须先获得**唯一且单一的固件 Primitive 上下文**。
多个 Trigger 映射到不同 Primitive 时，没有时间状态模型，前置条件返回 UNKNOWN；不把不同执行时刻的状态凑成全局状态。

| HW Precondition | 支持的 FW 信息 |
|---|---|
| privilege | 被选中 Primitive 引用的 privilege IdentityConstraint；或同 subject 的 privilege Condition.eq |
| register_state | 被选中 Primitive 引用的 register_state Condition.eq；寄存器名称与 subject 必须一致 |
| execution_context | 被选中 Primitive 引用的 execution_context IdentityConstraint；或同 subject 的 execution_context Condition.eq |

只比较已结构化 eq 和明确标量，严格区分 bool/int/string；缺失 → UNKNOWN，明确冲突 → incompatible。
privilege 的 subject 白名单为 `privilege` / `execution_mode`；execution_context 为 `execution_context` / `mode`。
同一上下文出现不同状态声明时 UNKNOWN，不在本版求解矛盾。
不从函数名、code site、CSR 指令或退休事实推断权限或执行上下文。

XL1 没有统一 requires_external_control 字段。本版不新增该字段，也不凭直觉增加控制要求。
提供一个精确的显式 Predicate 约定，须由合同作者写出：

```text
Precondition.kind = other
Predicate.subject = external_control.<dimension>
Predicate.operator = eq
Predicate.operands = [true]
```

维度只允许 address / value / length / target / execution_context。
这是一条新 matcher 白名单语义，不改变 frozen schema，不从说明文本提取。

仅比较已选中 Primitive 的对应维度：bounded_external_control / full_external_control 可支持声明级比较；not_established、input_influenced、firmware_determined、unknown 均不能建立该需求。
vulnerability_derived_control 本身没有明确外部 actor 含义，也不自动提升为外部控制。
缺依据返回 UNKNOWN，不是 incompatible。
若 HW 没有这项显式要求，FW control=not_established 不会阻止其他行为字段兼容。

## Ordering

先分别比较非 ordering Trigger，只有两个端点都唯一匹配到不同固件 Primitive，才比较 FW OrderingConstraint。
端点通过 RequirementResult.matched_primitive_ids 连接，**不是比较两边 ID 字符串是否相等**。

- 同向、明确的声明顺序 → 该顺序字段 compatible；不代表观察到 runtime order。
- 同一已映射事件对的明确反向声明 → incompatible。
- 缺声明、端点不唯一、重复使用同一原语当两个事件、同时有正反顺序等 → UNKNOWN。
- FW max_gap_events 已知且不大于 HW 上界 → 此上界要求 compatible。
- FW 上界未知或更宽 → UNKNOWN；较宽上界不证明实际间隔必然超限。
- HW max_gap_time / time_unit → UNKNOWN，CAP0 没有可比较的时间域。

constraints list 的顺序从未被当成运行顺序。

## 聚合与部分合同

字段层：任一明确冲突 → incompatible；全部明确兼容且非空 → compatible；否则 unknown。

对一个 Trigger 的多个 FW alternatives：有一个完整兼容选择即可支持这项要求；全部明确冲突才是 incompatible；没有兼容选择且仍有 unknown → unknown。
因此 diagnostics 中可能保留未选 alternative 的 unsupported 字段，它们不是最终被选中的必需字段。
报告首屏按 requirement outcome 解释，不把一个未使用选择的冲突误写成整体冲突。

整体聚合平台 gate、所有 Trigger/Preconditions 及保留的未分类项：

```text
any required row incompatible -> overall incompatible
all required rows compatible and nonempty -> overall compatible
otherwise -> overall unknown
```

没有 HW Trigger 时补充 UNKNOWN 缺项行；空检查列表也返回 UNKNOWN。
平台检查已发现明确冲突时仍可形成 incompatible；它不是“零检查”。
当前所有 XL1 unclassified_atoms 都保守列为未知项，没有依据丢弃它们。

HW Preconditions 缺失记录在 unassessed sections，不捏造一条默认前置条件。
Deviation/Observation 缺失不会被改写为已满足，也不作为 FirmwareCapability 的匹配对象。
因此部分合同可以在其实际可检查的 Trigger/Platform 上返回 compatible，但**绝不是完整 HardwareBehaviorContract satisfied**。
联合可满足性、不同原语能否在同一执行中组合，始终未评估。

## 身份、序列化与重放

```text
result_sha256 = SHA256(canonical payload)
result_id = "xlcompat:" + result_sha256
```

payload 包含 schema、双方完整 content ID/hash、matcher_version、确定性比较输出、引用、coverage 与边界说明；不含自身 result_id/hash。
UTF-8、键排序、无额外空白；来源/证据/引用 ID、alternatives、coverage 和说明集合排序；逐要求/逐字段记录顺序保留。
matcher 不改变输入的 instruction sequence、register positions、range operands 或 ordered constraints。
规则版本来自实现常量，不允许调用者传任意规则标签来伪装不同算法；测试模拟规则版本变更，验证结果 ID 必变。

没有时间戳、运行 UUID、主机路径、LLM prose/confidence、risk、probability 或 exploitability 字段。
输入 content hash 会绑定其本来已声明的内容；matcher 不读自由文本研究说明来判断语义。
输出文件 manifest 中的定位路径与文件 hash 是调用者复现元数据，不参与 result identity。

parse 检查重复 JSON key、输出身份、聚合及引用；replay 则重新运行当前规则核验输入与结果对应。
历史规则版本与当前规则不同会拒绝 replay，不会修改历史结果以强行通过。

## Synthetic 结果

所有小型 fixtures 均位于新的 Python 测试文件；复用旧 fixture factory 构造新对象，没有修改 frozen fixtures，没有真实 provider output。

| 样例 | 结果 |
|---|---|
| CSR_WRITE、同平台/CSR identity、提供值域包含要求值 | COMPATIBLE |
| bounded memory write 对 CSR access | INCOMPATIBLE / EXPLICIT_RESOURCE_CLASS_CONFLICT |
| MMIO range [0x1000,0x10ff] 对 0x2000 | INCOMPATIBLE / REQUIRED_DOMAIN_NOT_CONTAINED |
| CSR identity 缺失或 UNKNOWN | UNKNOWN |
| typed external_control.value=true，FW not_established/input_influenced | UNKNOWN / EXTERNAL_CONTROL_NOT_ESTABLISHED |
| DIRECT_CONTROL_TRANSFER 对 instruction | UNKNOWN / NO_SUPPORTED_MAPPING |
| INSTRUCTION_EXECUTION 的字符串序列恰含 addi，但没有 typed mnemonic | UNKNOWN，不用相同字符串制造正例 |
| 一个 CSR alternative 匹配，另一个不匹配 | 要求 COMPATIBLE；未使用选择的冲突不会变整体冲突 |
| 一个选择明确冲突，另一个未支持 | UNKNOWN，不把未知选择排除成全局负例 |

## 真实 CAP0 × 743 XL1 预览

已只读解析并验证附件指定的两个 frozen 对象：

| 项目 | 身份 |
|---|---|
| FirmwareCapability | fwcap:a7d884ec659e96b689a69266e5b43ef99f05d5f07340e7fc5def431a9aedc749 |
| HardwareBehaviorContract | hwbehavior:48dba3c5ba26c30d65fba23d8293c7689443bbd362a0616e698a19c4492b197c |
| FW JSON 文件 hash | 3aea6d0d6674470cb25807201aedcfa8e6e8c0dd9088cc89aa94f04f5a4d27f9 |
| HW JSON 文件 hash | 9846073912361f768f903fb171f6a74879c1b04167fbad92d914f3723ff198c2 |
| XL2 结果 | xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded |

结果 **UNKNOWN**，具体原因：

1. Architecture：RISCV/RISCV，compatible。
2. Platform：双方缺少可比较的具体 platform identity，UNKNOWN。
3. Processor：`ibex-simple-system:small` 与 `ibex` 未建立同平台身份关系，UNKNOWN，不武断按字符串不同判冲突。
4. Scope：硬件适用范围仍 unknown。
5. Trigger mapping：固件 DIRECT_CONTROL_TRANSFER 对硬件 instruction/addi，没有白名单映射；UNKNOWN / NO_SUPPORTED_MAPPING。
6. 前置条件缺失、偏差/观察缺失及部分定义保留为未评估范围；未尝试满足这些缺项。

没有为了这组对象产生 positive 而改映射，没有重提取能力，也没有改原预览文件。
本次只验证两个冻结输入自身的 ID/hash 及结果重放，不重新执行之前 A6/EnCorpus 的原始分析。

新建 ignored 目录：
`output/ibex-simple-system:hello-test:paired-workspace/xl2-34bfee41ac1fc6b4/`

包含 compatibility_result.json、report-xl2-zh.md、preview_manifest.json。
报告首屏直接说明无法判断、平台缺口和不受支持的原语配对；之后列逐字段结果、冲突/缺项、下游未评估项、科学边界与追溯。

### 显式复现代码

从仓库根目录，以 `PYTHONPATH=src .venv/bin/python` 执行。
不读 .env，不联网，不调用 LLM，不运行仿真；仅显式写新的 ignored 输出，已有文件内容不同时拒绝覆盖。

```python
"""Explicit read-only input comparison; only the new ignored preview is written."""
from pathlib import Path
import hashlib
import json
from chipchain.firmware.capability import parse_firmware_capability
from chipchain.hardware.behavior_contract import parse_hardware_behavior_contract
from chipchain.cross_layer.capability_compatibility import (
    compare_capability_contract, serialize_compatibility_result, validate_compatibility_replay,
)
from chipchain.cross_layer.capability_compatibility_report import render_capability_compatibility

fw_path = Path('output/ibex-simple-system:hello-test:paired-workspace/fw-cap0-a7d884ec659e96b6/firmware_capability.json')
hw_path = Path('output/encorpus:ibex:driver:743/xl1-48dba3c5ba26c30d/hardware_behavior_contract.json')
fw_bytes, hw_bytes = fw_path.read_bytes(), hw_path.read_bytes()
fw = parse_firmware_capability(fw_bytes.decode())
hw = parse_hardware_behavior_contract(hw_bytes.decode())
assert fw.capability_id == 'fwcap:a7d884ec659e96b689a69266e5b43ef99f05d5f07340e7fc5def431a9aedc749'
assert hw.contract_id == 'hwbehavior:48dba3c5ba26c30d65fba23d8293c7689443bbd362a0616e698a19c4492b197c'
result = compare_capability_contract(fw, hw)
validate_compatibility_replay(result, fw, hw)
assert result.overall_result == 'unknown'
assert fw_path.read_bytes() == fw_bytes and hw_path.read_bytes() == hw_bytes
folder = Path('output') / fw.source_case_id / ('xl2-' + result.result_sha256[:16])
folder.mkdir(parents=True, exist_ok=True)
manifest = dict(schema_version='xl2-local-preview/v1', matcher_version=result.matcher_version,
    firmware_capability_id=fw.capability_id, hardware_contract_id=hw.contract_id,
    firmware_input_path=str(fw_path), hardware_input_path=str(hw_path),
    firmware_file_sha256=hashlib.sha256(fw_bytes).hexdigest(),
    hardware_file_sha256=hashlib.sha256(hw_bytes).hexdigest(),
    result_id=result.result_id, result_sha256=result.result_sha256, overall_result=result.overall_result)
files = {'compatibility_result.json': serialize_compatibility_result(result),
         'report-xl2-zh.md': render_capability_compatibility(result),
         'preview_manifest.json': json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)+'\n'}
for name, content in files.items():
    target = folder / name
    if target.exists():
        assert target.read_text() == content, f'Refuse to overwrite differing output: {target}'
    else:
        target.write_text(content)
print(json.dumps(dict(output=str(folder), **manifest), indent=2))
```

## 验证结果与历史保护

| 检查 | Exact result |
|---|---|
| XL2 新增专项 | 67 passed in 1.08s |
| XL2 + FW-CAP0 / XL1 / A6 / XL0 专项 | 392 passed in 4.76s |
| Full pytest | 1358 passed, 27 skipped in 33.37s |
| pip check | No broken requirements found. |
| compileall | exit 0 |
| git diff --check | exit 0 |

命令：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q tests/unit/test_capability_compatibility*.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q \
  tests/unit/test_capability_compatibility*.py \
  tests/unit/test_firmware_capability*.py \
  tests/unit/test_hardware_behavior_contract*.py \
  tests/unit/test_firmware_a6*.py \
  tests/unit/test_firmware_grounding.py \
  tests/integration/test_firmware_a6_workflow.py \
  tests/unit/test_cross_layer_contracts.py \
  tests/unit/test_cross_layer_eligibility.py \
  tests/unit/test_cross_layer_matcher.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
git status --short --untracked-files=all
```

既有 275 个 tracked 文件按 SHA-256 核对保持，HEAD/tags 保持。
只读输入原预览；output 仅新增本阶段目录。没有改 .env/.gitignore、README、CURRENT_STATE、历史输出、reviewed snapshots、教程或 DATA1A 记录。
没有 git add/commit/push/tag，也没有 force-add。
新 untracked 文件另检查尾部空白和文件末尾换行，因为 git diff --check 不检查未跟踪文件。

最终 Git status：

```text
?? docs/research/v3-xl2-capability-contract-compatibility.md
?? src/chipchain/cross_layer/capability_compatibility.py
?? src/chipchain/cross_layer/capability_compatibility_report.py
?? tests/unit/test_capability_compatibility.py
?? tests/unit/test_capability_compatibility_report.py
```

## 完成报告：64 项回答

| # | 回答 |
|---|---|
| 1 | 起始 main / 6acfbd25ab0db5293c1385927cb6b24b5c60a67d / v3-fw-cap0-stable。 |
| 2 | 新增 compatibility 模块、renderer、两份 unit test 和本文共 5 文件；另新建 ignored 三文件预览。没有修改旧文件。 |
| 3 | 未修改 FW-CAP0。 |
| 4 | 未修改 XL1。 |
| 5 | 未修改 A6/XL0。 |
| 6 | schema capability-contract-compatibility/v1；规则 xl2-typed-subset/v1。 |
| 7 | compatible / incompatible / unknown，各有逐字段 outcome、coverage 和 reason。 |
| 8 | COMPATIBLE 仅表示有足够信息检查的受支持字段兼容，不表示任何执行或触发成功。 |
| 9 | INCOMPATIBLE 表示本次输入对象的一项必要要求有明确 typed 冲突，不是全固件不可能性证明。 |
| 10 | UNKNOWN 表示信息不足、未支持语义或条件未建立，不被自动转换为其他两态。 |
| 11 | 任一 required row incompatible 主导；否则所有必要行兼容且非空才 compatible；其余 unknown。alternative 内使用明确的选择规则，见聚合章节。 |
| 12 | 空检查 → UNKNOWN；HW 无 Trigger 时补 UNKNOWN 缺项行，不能靠零冲突成功。 |
| 13 | 明确同架构通过；不同冲突；任一 UNKNOWN 则未知。 |
| 14 | 精确平台/Scope membership；缺失未知。不同 processor 名称只在明确同平台上下文中判冲突，不从 architecture 推平台。 |
| 15 | INSTRUCTION_EXECUTION↔instruction 类型映射；CSR_READ/WRITE↔CSR_access；MMIO_READ/WRITE↔MMIO_access。instruction 具体字段仍受 CAP0 表达限制。 |
| 16 | DIRECT/INDIRECT_CONTROL_TRANSFER↔instruction 无映射；序列/并发/时序窗口等未支持类型不靠字符串猜测。 |
| 17 | CSR resource、方向和 exact identity；值要求另比较数值域；数字 CSR 地址缺 CAP0 字段时 UNKNOWN。 |
| 18 | MMIO resource、方向、exact/range 对硬件地址点、必要 width 和值要求；缺字段 UNKNOWN。 |
| 19 | FW 提供域须包含 HW 要求域；不是求交集。 |
| 20 | 两个 exact 相等 compatible，不同 incompatible；缺值 UNKNOWN。 |
| 21 | HW exact 在 FW inclusive range 内 compatible，否则 incompatible；范围缺边界 UNKNOWN。 |
| 22 | 仅 helper 的显式 contains_all 能做全范围包含；XL1 in_range 未声明量词，主 matcher UNKNOWN。 |
| 23 | 显式 memory/mmio/csr 资源类别互不代替；bounded MEMORY_WRITE→CSR 为明确冲突。未知映射不自动变资源冲突。 |
| 24 | 只检查显式的 other / external_control.<dimension> / eq true typed predicate；不凭直觉增加控制要求。 |
| 25 | 没有。input_influenced 不能支持外部控制要求；若没有外部控制要求，也不因此否定普通行为比较。 |
| 26 | 单一映射上下文内的 privilege/register_state/execution_context eq；以及精确声明的 external control predicate。 |
| 27 | privilege IdentityConstraint 或同 subject 的已结构化 Condition.eq；不从 CSR/退休记录推断。 |
| 28 | register_state Condition.eq 与明确同名 subject；register identity 本身不说明寄存器值。 |
| 29 | execution_context IdentityConstraint 或同 subject Condition.eq；函数名/site 不提供执行上下文。 |
| 30 | 两端先唯一兼容映射到不同 Primitive，再比较显式 OrderingConstraint；缺端点/时间域/发生次数 UNKNOWN。 |
| 31 | Deviation 不参与兼容性聚合；只保留下游 requirement IDs 或 missing。 |
| 32 | Observation 不参与兼容性聚合；不验证观察发生。 |
| 33 | derived_from_typed_contracts；双方 ID/hash、被比较原语/约束/条件、source/evidence pointers。没有新增执行证据。 |
| 34 | SHA256(canonical schema + 输入身份 + 规则版本 + 比较输出)，ID 前缀 xlcompat:，排除自身 ID/hash。 |
| 35 | 是；规则版本变更测试验证 ID 改变；旧记录在新规则下不能伪装通过 replay。 |
| 36 | 没有运行时间/UUID/主机路径/LLM 字段参与；路径只在调用者 manifest。 |
| 37 | 未调用 LLM。 |
| 38 | 未做字符串相似度、embedding 或自然语言语义匹配；仅比较明确 identity token 和 typed 字段。 |
| 39 | Synthetic CSR positive：COMPATIBLE。 |
| 40 | Synthetic memory→CSR：INCOMPATIBLE。 |
| 41 | Synthetic MMIO [0x1000,0x10ff]→0x2000：INCOMPATIBLE。 |
| 42 | Synthetic CSR identity missing/UNKNOWN：UNKNOWN。 |
| 43 | Synthetic DIRECT_CONTROL_TRANSFER→instruction：UNKNOWN / NO_SUPPORTED_MAPPING。 |
| 44 | fwcap:a7d884ec659e96b689a69266e5b43ef99f05d5f07340e7fc5def431a9aedc749。 |
| 45 | hwbehavior:48dba3c5ba26c30d65fba23d8293c7689443bbd362a0616e698a19c4492b197c。 |
| 46 | 真实 preview overall=UNKNOWN；结果 ID xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded。 |
| 47 | 架构兼容；平台身份缺失；processor 名称可比性不足；硬件 Scope 未知；DIRECT_CONTROL_TRANSFER→instruction 无支持映射。缺失的前置/偏差/观察及部分定义保持未评估。 |
| 48 | 没有为了真实 preview 扩大或修改映射；没有重新提取输入能力。 |
| 49 | 没有新 candidate/attack chain 对象；只有对既有 Primitive 的 comparison alternatives。 |
| 50 | 第一屏给三态结果、该结果含义、主要缺口/冲突，以及未证明触发/偏差/漏洞/攻击链的边界。 |
| 51 | renderer 是 typed result 的 deterministic 纯函数。 |
| 52 | 67 passed in 1.08s。 |
| 53 | XL2 + FW-CAP0/XL1/A6/XL0：392 passed in 4.76s，含旧专项 325 项与新增 67 项。 |
| 54 | 1358 passed, 27 skipped in 33.37s。 |
| 55 | No broken requirements found. |
| 56 | compileall exit 0。 |
| 57 | git diff --check exit 0；新文件额外空白检查通过。 |
| 58 | 既有 275 个 tracked 文件、HEAD/tags 和原预览保持；只创建新 ignored 预览目录。 |
| 59 | 尚不支持 typed instruction 内容、CSR 数字地址、范围量词推断、mask/neq、跨原语前置状态、复杂时序/并发/中断/异常、修订/ISA 语义、全局约束求解。 |
| 60 | 走向 Trigger satisfaction 尚需完整可执行要求、真实目标身份对应、固件成立条件/路径/资源约束验证，以及必要时输入控制、联合可满足性和执行证据。 |
| 61 | Deviation verification 还需规格/预期结果、明确偏差定义、同版本硬件的验证后端和可追溯观察判据；本次 743 合同缺这些内容。 |
| 62 | Verified cross-layer chain 还需可信固件能力来源、硬件触发与偏差之间的证据链、同配置可复现执行、观察/反例/因果与安全影响验证；兼容性不能替代这些步骤。 |
| 63 | 建议先做真实输入身份和可比较要求的补全评审，再选择同类 CSR/MMIO 的最小实证比较；不要优先追求把现有 UNKNOWN 改成 positive。 |
| 64 | 下节仅 proposal，本阶段没有执行。 |

## 下一阶段最小 proposal（未执行）

建议把下一阶段限定为“真实输入身份与支持字段覆盖审查”：

1. 为真实 paired 平台核对处理器配置、RTL/固件来源和身份对应，明确哪些相同、哪些仍 UNKNOWN。
2. 选择一个具有明确硬件要求和固件确定性 CSR/MMIO 事实的最小案例，审核资源/身份/方向/数值语义和条件；没有合适输入就记录缺口。
3. 若确需指令比较，先单独设计带架构、编码表示、操作数位置的 typed 固件指令字段演进，保留 frozen CAP0/XL1，不解析 instruction_sequence 字符串制造事实。
4. 仅在输入可靠后运行新的 compatibility 预览；仍不把 compatible 提升为 trigger satisfied。

不建议为 743 的 addi 条件硬套现有直接跳转能力，也不建议立即接入 Agent 自动推断攻击链。
后续 trigger satisfaction 与 deviation verification 应分别立项，明确真实验证证据和验收条件。
