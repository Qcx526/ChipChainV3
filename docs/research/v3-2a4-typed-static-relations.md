# V3-2A4 — Typed Static Relation Semantics & Claim-Support Contracts

基线：`v3-2b2-stable`，commit `36bac832e460fca833155ab390775bb681239228`。
A4 是独立的 deterministic tool result，不是 Agent projection 或 domain IR 扩展。
本阶段从四个真实输入重新构建 A1、fresh Ghidra A2、A3，再生成 A4；不调用模型。

## 问题与实现边界

B2 曾引用 `call-80f88`，把 unresolved/computed 目标误解为
`Reset_Handler → SystemInit` confirmed direct call。Evidence ID 存在仅能证明引用有来源，
不能证明模型所声称的关系类型、端点、方向或运行时意义。

A4 将这几件事分开表达：

- `relations.py`：架构中立 endpoint、typed attributes、status、capabilities、catalog 与 codec。
- `relation_builder.py`：A1/A2/A3 canonical 校验、显式 ELF 字节的 Thumb 解码和关系映射。
- `relation_claims.py`：只检查调用方给出的 typed claim 和 relation IDs，不读取任何 LLM prose。

未修改 A1 analyzer、A2 extractor/ARM decoder、A3 selection/codec、A1 projection v1、
envelope v2、Firmware prompt v1、`ModelFirmwareAnalysisReport`、`FirmwareSecurityAgent`、
`EvidenceRef` 或 `ProcessorBehaviorIR`。没有新依赖，没有新 Agent、workflow 或 persistence side effect。

## 关系合同

版本：`firmware-static-relations/v1`。

| Relation kind | 端点 | 含义 |
|---|---|---|
| `direct_call` | function → function | 已确认的静态直接调用 |
| `direct_branch` | function → function/address | 确定的直接分支，`call_semantics=false` |
| `control_transfer_unresolved` | function/instruction_site → function/address/null | 控制转移仍无法确认为直接关系 |
| `mmio_function_containment` | mmio_site → function/null | 静态地址归属，不表示执行 |
| `mmio_access_direction` | mmio_site，target=null | A1 的 read/write/unknown 与 mnemonic |
| `vector_dispatch` | vector_entry → function/address/null | 向量词的静态绑定 |

`RelationEndpoint` 使用 `entity_type`、`entity_id`、可选 `address`，不以函数名作 identity。
允许的 entity type 还包含 `handler`；本轮已确认向量以 function endpoint 表达。
真实函数沿用 A2 的 `f<entry hex>`。引用到的 A2 functions 仅保存一个最小 identity table；
未知 function ID 或同 ID 不同 entry address 均拒绝。

`StaticRelationFact` 保存 relation ID、kind、status、source/target、site address、
受 `detail_type` discriminator 控制的 attributes、evidence IDs、capabilities 和 enum limitations。
不接受任意属性字典、自然语言 proof 或额外字段。重复 relation ID/evidence ID 拒绝。
本轮所有关系均有静态 site address；站点型 source 的地址必须一致。

| Status | 意义 |
|---|---|
| `confirmed_static` | 对这一有限静态关系已有足够确定性事实 |
| `unresolved` | 尚未确立相应的直接关系或方向 |
| `missing` | 当前结构没有归属，不是“不存在函数”的证明 |
| `conflict` | 例如多个归属候选，不能选择一个当作 confirmed |

不使用 `verified` 表示静态程序关系。真实 catalog 的 conflict 为 0；
A1 方向发生冲突时 builder 直接拒绝，不能任意选择 read 或 write。

### Capabilities

静态支持能力由 kind + status 精确决定，不能由调用方随意添加：
`supports_direct_call`、`supports_direct_branch`、`supports_static_dispatch`、
`supports_mmio_containment`、`supports_mmio_direction`。
unknown direction 没有 confirmed direction capability。

下列字段在所有 A4 关系中均为 `Literal[False]`：

- `supports_runtime_execution`、`supports_runtime_reachability`；
- `supports_interrupt_occurrence`、`supports_handler_execution`；
- `supports_physical_interface`、`supports_input_consumption`。

Vector 另有 `no_interrupt_occurrence`、`no_handler_execution` enum limitations。
函数名 `UART_Handler`、`ADC_Handler`、`write`、`IrqHandler` 不进入能力推导。

## Canonical identity 与 evidence

Builder 接收 typed A1 input、A2 structure、vectors、A3 relevant structure、显式 `elf_bytes`。
它通过冻结 A3 builder 再构建一次，核对传入 A3 是否与 A1/A2/vectors 一致；
检查 ELF 的长度和 SHA256 后，才允许解码。它不打开文件、不读取 `.env`、不自动写输出。

Catalog 绑定：

| 输入 | SHA256 |
|---|---|
| A1 projection v1 | `48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803` |
| A2 semantic identity | `6543602aa35ebd6ee720168b7b40a5b7c7411dd431cb203b4b98d5f6d1602343` |
| Vectors semantic identity | `9bc24c0728ca5e2eeeeea76c847bbdb5e28694c4fc042932c14c00e150e388ef` |
| A3 v1 | `4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304` |
| ELF，261365 bytes | `73f667524ed0ff8f24b460d4678b74f15eec13d954b93cdc92c839c2c3f1044e` |

A2/vectors 复用 A3 已冻结的 `recursively-sorted-source-collections/v1` semantic hash policy，
并非任意 pretty JSON 文件的哈希。A1 identity 是冻结投影的 canonical hash。
Decoder descriptor 为 Capstone `5.0.9` / `instruction_decoder`，
adapter policy 为 `thumb-m-linear-a2-bounds/v1`。

Catalog 保存 exact A1+A3 reasoning registry 的 **174 个 ID**，以及每条关系的引用子集，
不增加 EvidenceRef identity，不在 A4 复制完整 EvidenceRef objects。
`parse_firmware_static_relations(text, evidence_registry=registry)` 要求外部 exact registry；
不能用序列化内容自己声明的一组 ID 作为外部证据权威。
Builder 验证 canonical 来源；单独 parse 是结构与 ID membership 校验，不重新运行 Ghidra，
也不能替代对来源和文件哈希的验证。

## 独立控制转移分类

22 条 A3 confirmed direct calls 原样映射，保留 caller/callee、site、证据 ID。
12 条 relevant unresolved sites 各有一条 A4 relation，保留原 A2 reason 和原 target。

对 unresolved site，从 A2 caller entry 开始，合并相邻 body ranges，只在覆盖该 PC 的连续前缀中
读取 ELF executable bytes，调用现有 `ArmThumbInstructionDecoder.decode_site`。
沿用 decoder 的 4096-byte 函数上限；边界不成立、body 有间隙、未文件映射或解码失败时，
保留 `boundary_unconfirmed`，不从任意 PC 单独猜测指令边界。

当前 adapter 识别立即数 `b` 为 direct branch，立即数 `bl`/`blx` 为 direct call，
寄存器 `blx` 为 indirect call，`bx` 为 indirect branch；其他 computed/未知形式保守保留。
仅原 reason 为 `decoder_disagreement` 或 `instruction_boundary_unconfirmed`、
且新旧目标不冲突时，才可能确认为直接关系；direct call 还需精确 callee entry。
原 reason 为 `computed_or_ambiguous` 的 site 始终保留 unresolved，显示目标不会被当作已解出的立即数。

这是线性指令边界校验，不是 CFG、ABI、路径可达性或运行时执行证明。
本阶段不采用 tail-call 命名、不添加 speculative tail transfer capability。

### 完整 12-site 实测表

表中的 decoded target 仅指 Capstone 唯一立即数目标；`—` 不表示原 A2 target 一定为空。

| Site | Caller | 原 A2 reason | Capstone | Decoded target | A4 kind | A4 status |
|---|---|---|---|---|---|---|
| `0x80abe` | `f80abc` | decoder_disagreement | b.w | `0x815a4` | direct_branch | confirmed_static |
| `0x80ad2` | `f80ad0` | decoder_disagreement | b.w | `0x815a4` | direct_branch | confirmed_static |
| `0x80ade` | `f80adc` | decoder_disagreement | b.w | `0x815a4` | direct_branch | confirmed_static |
| `0x80aea` | `f80ae8` | decoder_disagreement | b.w | `0x815a4` | direct_branch | confirmed_static |
| `0x80f88` | `f80f34` | computed_or_ambiguous | blx | — | control_transfer_unresolved | unresolved |
| `0x8108c` | `f81084` | computed_or_ambiguous | blx | — | control_transfer_unresolved | unresolved |
| `0x810b2` | `f81094` | computed_or_ambiguous | blx | — | control_transfer_unresolved | unresolved |
| `0x810ea` | `f810cc` | computed_or_ambiguous | blx | — | control_transfer_unresolved | unresolved |
| `0x81122` | `f81104` | computed_or_ambiguous | blx | — | control_transfer_unresolved | unresolved |
| `0x8115a` | `f8113c` | computed_or_ambiguous | blx | — | control_transfer_unresolved | unresolved |
| `0x8118e` | `f8117e` | decoder_disagreement | b.w | `0x81728` | direct_branch | confirmed_static |
| `0x81328` | `f81234` | decoder_disagreement | b.w | `0x80e6c` | direct_branch | confirmed_static |

六个 `blx` 的 `transfer_kind=indirect_call`。特别是 `call-80f88`：
`source=f80f34`，原 A2 target `0x816cc`（endpoint `f816cc`），
`decoded_target_address=null`，`call_semantics=false`。
它不是 `f80f34 → f80eac` confirmed direct call。

## MMIO 与 vector

23 个 MMIO PC 分别生成 containment 和 direction 两类关系：

- 20 个 `confirmed_static` containment；
- `0x80d4e`、`0x80d50`、`0x80d5a` 仍为 `missing`，target=null；
- read **23**、write **0**、unknown **0**，方向仅来自 A1；synthetic tests 另覆盖 write/unknown/conflict。

SystemInit 的 `0x80eba`、`0x80eca`、`0x80ed2`、`0x80eda`、`0x80ee6`、
`0x80ef2`、`0x80efe`、`0x80f0a` 均为 `f80eac` 内的 `ldr/read`。
读方向不能支持 configuration-write 声明。

51 个非空 vector indices 各有独立 `vector_dispatch` relation，保留每个原 vector 的 evidence IDs。
从 A3 handler groups 取选中 index，由原 A2 vector bindings 恢复逐 index 绑定。
本例全为 function-entry confirmed_static；非 entry 绑定保守 unresolved，不把 inside-function 地址当入口。
Vector 0 初始栈指针与空条目不产生 dispatch relation。
`vector-1 → f80f34` 仅证明 Reset 静态绑定，不证明 Reset_Handler 调用 SystemInit。

## Claim-support 合同

`StaticRelationClaim`：claim ID、typed ClaimKind、source、可选 target、显式 relation IDs。
`StaticCallPathClaim`：claim ID、source/target function IDs、**有序** edge relation IDs。
函数身份必须精确一致；claim 若提供 address，地址也必须一致。

| 结果 | 限定意义 |
|---|---|
| `supported` | 所引用 typed relations 蕴含这个有限静态 claim |
| `unsupported` | 当前所给事实没有建立 claim；不是绝对否定 |
| `incompatible` | 所引用关系的 type/status/endpoints/direction 与 claim 不兼容，或引用未知 relation ID |

检查器不解析 summary，不搜索关键词，不使用 regex/NLP，也不改写模型输出。

- direct_call 只接受 confirmed_static direct_call、精确 caller/callee。
- direct_branch 与 unresolved relation 均不能支持 direct_call。
- mmio_read/write 检查方向；unknown/missing 返回 unsupported。
- vector_dispatch 只支持静态绑定。
- path 中每条边必须是 confirmed direct_call，首尾和每一相邻端点均精确连接。
- 不搜索替代路径、不丢弃坏引用、不把 branch/unresolved 当 path edge。
- runtime_reachability、physical_input_path、trigger_to_handler 一律 unsupported：A4 没有相应能力。
  即使所引静态调用路径有效，也不能升级到 runtime。

### B2 错误回归

| Claim | 结果 |
|---|---|
| `call-80afa`: `f80af4(init) → f80eac(SystemInit)` direct_call | supported |
| 用 `call-80f88` 证明 `f80f34 → f80eac` direct_call | incompatible |
| UART 四站点 direct_call | 各 incompatible |
| UART 四站点 direct_branch | 各 supported |
| SystemInit 八站点 mmio_read | 各 supported |
| SystemInit 八站点 mmio_write | 各 incompatible |
| `vector-1 → f80f34` vector_dispatch | supported |
| 用 vector-1 证明 Reset→SystemInit direct_call | incompatible |
| trigger_to_handler | unsupported |
| static call 引用支持 runtime_reachability | unsupported |
| vector/symbol 支持 physical_input_path | unsupported |

真实显式 claim regressions 共 **31**：supported **14**、incompatible **14**、unsupported **3**。
这是 synthetic typed claims 对真实确定性事实的兼容性检查，不是重新审判完整 B2 自然语言报告。

## 实测关系计数与确定性

| 指标 | 数量 |
|---|---:|
| confirmed direct_call | 22 |
| confirmed direct_branch | 6 |
| unresolved control transfer | 6 |
| MMIO containment confirmed / missing / conflict | 20 / 3 / 0 |
| MMIO direction read / write / unknown | 23 / 0 / 0 |
| vector_dispatch | 51 |
| 总关系 | **131** |
| A1+A3 registry | 174 |

`serialize_firmware_static_relations` 重新校验嵌套对象，按
`kind → site address → source ID → target ID → relation ID` 排序。
Evidence IDs、function identities、limitations、warnings 作为集合排序。
JSON 使用 UTF-8、sort_keys、compact separators；claim path 列表不被重排。
两次 build 字节相同，parse/serialize 精确往返。没有加入时间、随机 ID、机器路径或显示名。

真实 catalog：**129547 字符**；SHA256：

```text
fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902
```

此结果不是 model context，不受 A1/A3/envelope 的字符预算约束，本轮不进行额外压缩。
无自动 persistence；调用方需要保存时，显式写入新的 `output/<case_id>/<run_id>/`，不覆盖历史目录。
测试的 audit JSON 保存在 pytest 临时工作区，未作为真实 fixture 提交。

## 使用与复现

```python
from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
from chipchain.tools.firmware.relation_builder import build_firmware_static_relations
from chipchain.tools.firmware.relations import (
    serialize_firmware_static_relations, parse_firmware_static_relations,
    firmware_static_relations_sha256,
)

# inputs/structure/vectors/relevant 均来自本次显式 canonical 构建。
result = build_firmware_static_relations(
    inputs, structure, vectors, relevant, elf_bytes=elf_bytes,
)
registry = collect_firmware_reasoning_evidence(inputs, relevant)
wire = serialize_firmware_static_relations(result)
assert parse_firmware_static_relations(wire, evidence_registry=registry) == result
sha256 = firmware_static_relations_sha256(result)
```

本地真实验证使用既有 Ghidra 10.1.4 PUBLIC、Java 11、Capstone 5.0.9：

```bash
CHIPCHAIN_GHIDRA_HOME=/home/qcx/fuzz/gdbfuzz/dependencies/ghidra \
CHIPCHAIN_FUZZWARE_ROOT=/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
.venv/bin/python -m pytest -q -s tests/integration/test_static_relations_local.py
```

测试显式读取冻结的 ELF/BIN/config/input 四个 artifacts 并核对全部大小和哈希，
调用 A1 analyzer 后运行 fresh Ghidra，不读取历史 output 作为 canonical 输入。
只有指定的 headless subprocess 被放行；网络仍被 suite fixture 阻断，API keys/LLM opt-in 被清除。
真实测试也检查冻结 A1/A3/envelope v2 hash 和全部 canonical input 对象未变。

离线默认运行不会启动 Ghidra，缺少两个显式路径时真实测试 skip：

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
```

本轮 exact validation：

```text
Synthetic A4 tests: 38 passed in 1.59s
Full pytest: 666 passed, 11 skipped in 12.64s
Fresh real integration: 1 passed in 11.78s
python -m pip check: No broken requirements found.
python -m compileall -q src tests: exit 0
git diff --check: exit 0
```

修改前后 SHA256 核对的 107 个既有文件全部未变：76 个 source 文件、31 个历史 output 文件。
其中包含 R1、B2、两个 rejected pilots，以及 `output/reviewed/v3-1b1` 的 12 个 snapshot 文件。
未新增 reviewed export。Git 仅有本阶段 README 修改和六个新增文件，未执行 add/commit/push/tag。

## 限制与下一阶段

A4 只赋予既有事实明确语义，不建立 trigger→handler、数据依赖、物理接口、CFG 路径或执行证明。
线性前缀解码仍受静态函数边界和反汇编解释限制；source hashes 标识来源，不使来源成为运行时真值。
直接分支可能在 ABI 下有进一步意义，本轮没有相应 proof，因此仅称 direct_branch。

建议下一阶段先做 **B3 structured relation claims**：要求模型显式声明关系种类、端点和 relation IDs，
再使用本轮 checker。这样能先暴露 B2 的关系误用，减少新增工具事实仍被误读的问题。
是否引入 envelope v3 由 B3 单独设计，当前 envelope v2 不接入 A4。

之后 A5/angr 可提供带工具身份、输入哈希和限制的 `static_cfg_edge`、`static_path`、
受约束路径可达性或 data dependency facts，通过后续版本的 typed details 和 capabilities 接入。
它们仍不自动支持真实执行、物理输入或实际中断。A4 当前 enum 不提前加入这些未来类型。
本轮不进入 B3/A5，不运行 angr/CFGFast/symbolic execution，不调用 DeepSeek，不 reviewed-export。
