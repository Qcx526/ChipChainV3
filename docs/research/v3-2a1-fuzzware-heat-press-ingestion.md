# V3-2A1 — Fuzzware Heat_Press Deterministic Firmware Ingestion

基线：`v3-2a0-firmware-recon` / `5d4e9c28b4efa1c58898add9aadbea41d2264dae`。
本阶段实现 `four explicit artifacts → bounded adapter → typed FirmwareObservation → deterministic IR → FirmwareAgentInput`，已完成真实本地四文件 ingestion 和无模型 stub 验证。没有进入 V3-2B。

## A. Implementation Summary

新增 `FuzzwareHeatPressScenarioAnalyzer`，遵循现有 FirmwareAnalyzer 的 `analyze(case_id, target, artifacts)` 协议。它只读取已声明 fingerprint 的四个本地文件，不发现 companion、不执行脚本、无自动持久化。IR behaviors 在 deterministic adapter 中产生，FirmwareSecurityAgent 只负责传播已有 IR。

实际支持范围是 A0 已研究的 Heat_Press scenario 13 YAML/ELF subset。生产代码没有样本 hash/PC/32-model-count whitelist；其他匹配子集的 synthetic bytes 用于测试，不因此宣称支持第二个真实 target。

## B. Files Changed

| 文件 | 修改 |
| --- | --- |
| `pyproject.toml` | 直接声明 YAML/ELF 依赖 |
| `src/chipchain/domain/case.py` | 增加 FIRMWARE_CONFIG / FIRMWARE_INPUT |
| `src/chipchain/domain/instruction.py` | 增加 architecture-neutral MEMORY_BYTES |
| `src/chipchain/tools/contracts.py` | 三种 typed firmware observations、scope 和 details 校验 |
| `src/chipchain/tools/architecture/arm.py`、`__init__.py` | ArmThumbInstructionDecoder 与导出 |
| `src/chipchain/tools/firmware/__init__.py` | firmware 工具包 |
| `src/chipchain/tools/firmware/fuzzware/__init__.py`、`readers.py`、`heat_press.py` | 有界 reader 和具体 analyzer |
| `src/chipchain/agents/contracts.py` | Firmware oracle role 拒绝、nested decoded evidence membership |
| `src/chipchain/agents/context.py` | 显式 FirmwareObservation union；仅固件 context 压缩重复 evidence |
| `tests/firmware_fakes.py` | 测试内生成微型 ELF/BIN/config/input |
| `tests/unit/test_arm_decoding.py`、`test_fuzzware_ingestion.py` | 离线解析、语义、边界测试 |
| `tests/integration/test_fuzzware_local.py` | 默认 skip 的显式真实资源测试 |
| `README.md`、本文 | 当前入口与实际边界 |

未改 EvidenceLocation、FirmwareAnalysisReport、firmware prompt v1、workflow routing、ground-truth label、硬件 parser/decoder/prompt、reviewed exporter 或 workspace policy。

## C. Dependencies

| 直接依赖范围 | 当前 `.venv` | fresh venv |
| --- | --- | --- |
| `PyYAML>=6.0.3,<7` | 6.0.3 | 6.0.3 |
| `pyelftools>=0.33,<1` | 0.33 | 0.33 |
| `capstone>=5.0.9,<6`（已有） | 5.0.9 | 5.0.9 |

ELF 使用 pyelftools；只有 synthetic test fixture 使用 struct 生成 ELF。analyzer 的 `dependency_versions` 暴露精确版本，`descriptor.configuration_sha256` 包含 reader policy version、bounds 和依赖版本。decoder descriptor 含 Capstone version，`decoder_mode=thumb-m-little` 直接保存完整模式配置，不重复一个等价模式 hash。

## D. Supported Fuzzware Subset

仅支持 ARM32 little-endian、调用方声明的 M-profile/Thumb 固件，以及当前五区域 memory map、一个 round_robin trigger、五类 MMIO models。不实现 include、handlers、exit_at、自定义 hook、其他 fuzz_mode、QEMU/Fuzzware replay、CFG 或完整 Fuzzware 配置语言。

当前只对这一个真实 target 做过验证。对未知 critical fields、错误类型、不支持结构和损坏文件显式抛 `FirmwareIngestionError`（ValueError 子类）；不返回半个成功 batch。无法确认某个指令 site 是单独的有记录降级：保留合法 MMIO config facts，增加 unresolved question。

## E. Four-Artifact Boundary

根目录：`/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments`。

| 相对路径 | 类型 / format | bytes / SHA-256 |
| --- | --- | --- |
| `02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.elf` | firmware_binary / elf | 261365 / `73f667524ed0ff8f24b460d4678b74f15eec13d954b93cdc92c839c2c3f1044e` |
| `02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.bin` | firmware_binary / bin | 24896 / `1f7654deeec0d26307f35ea683c891965aa671fd891ae24af1aa8949ede43620` |
| `04-crash-analysis/13/config.yml` | firmware_config / yaml | 4253 / `2d91c058a4326ddde28be2bc27afd6a073b9b8aabf1816f6bac22e76dcc33bc2` |
| `04-crash-analysis/13/crashing_input` | firmware_input / opaque | 6009 / `0eca471106cf883c5941a03376c4ee3aa4b6cebd26636fc401e50c168644ee22` |

这些 expected fingerprints 仅放在真实 integration test。生产 analyzer 要求每个 ArtifactRef 声明 size_bytes/sha256，核对实际读取字节；不要求等于上表常量。四个 ID、规范化路径和 role/format 必须互异且恰好覆盖四个输入角色。外部路径合法，不要求位于 samples/firmware。

唯一文件内容入口是 `read_artifact`。它打开明确的 ArtifactRef，检查 regular-file/大小，读取至多 cap+1 字节，检查读取前后 size/mtime 与内容 fingerprint。特殊文件以非阻塞方式打开后拒绝，避免 FIFO 等待。

YAML 的 text.file 只规范化后与显式 BIN 路径比较，匹配后仍通过 BIN ArtifactRef 读取；不打开 YAML 提到的路径。README、run.sh、syms.yml、valid_basic_blocks、base_inputs、bug-details、patch 和 P2IM source 都不读取。新增含 root cause 的 companion 不影响结果，测试也审计了只发生四次内容 open。

## F. FirmwareObservation Contract

`FirmwareObservations.observations` 显式支持 `FirmwareObservation | DeterministicObservation`，保留既有 generic synthetic 流程。

| kind | details discriminator | 强制 scope |
| --- | --- | --- |
| STATIC_INSTRUCTION_SITE | static_instruction_site | STATIC |
| MMIO_MODEL | mmio_model | CONFIGURATION |
| ENVIRONMENT_INPUT | opaque_input | ARTIFACT |
| ENVIRONMENT_INPUT | interrupt_trigger | CONFIGURATION |

ObservationScope 定义 ARTIFACT / STATIC / CONFIGURATION / RUNTIME / UNKNOWN；当前 details 与 kind/scope 的组合严格校验，不能将上述配置强制改为 RUNTIME。EpistemicStatus 仍描述观察/推导状态，不能替代 scope。

role 复用 ObservationRole，默认 BENCHMARK_ORACLE；只有 analyzer 明确投影后设置 ANALYSIS_INPUT。FirmwareAgentInput 会拒绝非分析角色的 typed observation；generic 类型不能在 JSON round-trip 中悄悄吞掉 typed 字段，因为 union 明确且 extra fields 被拒绝。

Details：

- StaticInstructionSiteDetails：VA、ELF offset、BIN offset、memory-order raw bytes、16/32-bit 宽度、可选 function、raw symbol value、canonical function start、MEMORY_BYTES、ISA mode。
- MmioModelDetails：PC、MMIO address、access_size_bytes、model kind、config key、机器可读 parameters。参数仅接受有界 UInt32 或最多 32 项的 UInt32 list；按 model kind 验证精确 keys，不允许 nested dict、object 或任意 YAML dump。
- OpaqueInputDetails：artifact ID、长度、SHA-256；没有 bytes 字段。
- InterruptTriggerDetails：config key、every_nth_tick、round_robin、`tick_unit=emulator_tick`。没有“发生中断”字段。

## G. YAML Parser

使用定制 SafeLoader，构造前限制语法节点/深度/collection/scalar，拒绝 alias、重复 mapping key、非字符串 key、unsafe/custom tag。随后校验精确 layout 和 scalar types；bool 不能当地址、大小或 interval integer。

Top-level 必须恰好为 `interrupt_triggers`, `memory_map`, `mmio_models`。memory_map 必须包含 `irq_ret/mmio/nvic/ram/text`；普通区域只有 base_addr/size/permissions，text 额外需要 file。验证 ARM32 range 不 wrap、区域不重叠、各角色权限与研究配置一致。

MMIO model groups 是五种已知类型的非空子集。每项必须有 pc/addr/access_size，PC 为偶数且在 text 范围，MMIO address/width 在 MMIO 范围；config key 跨组不能重复。

| model kind | 精确参数 |
| --- | --- |
| bitextract | left_shift、mask、size；shift ≤31、size ∈1/2/4 |
| constant | val |
| passthrough | init_val |
| set | 非空 vals list |
| unmodeled | 无额外参数 |

| 单文件 / 解析维度 | 上限 |
| --- | ---: |
| ELF / BIN 各自 | 4 MiB |
| config | 256 KiB |
| opaque input | 1 MiB |
| YAML nesting / nodes | 12 / 8192 |
| YAML map 或 list 长度 / scalar 字符 | 256 / 512 |
| MMIO entries | 128 |
| model key / parameters / value list | 128 字符 / 4 keys / 32 项 |
| ELF program headers / sections | 32 / 256 |
| symbols / symbol string table | 10000 / 1 MiB |
| function name / 单函数 decode bytes | 256 字符 / 4096 bytes |

这些是单个 parser 输入边界，不是 case/sample 数据集数量限制。多于此范围显式 unsupported，不静默截断。

## H. ELF Reader

pyelftools 只在已读取的 bounded BytesIO 中运行，不打开其他文件。接受 ELF32 / little-endian / EM_ARM / ET_EXEC；拒绝 ELF64、BE、其他架构、header/table/range 错误。提取 entry、PT_LOAD 的 offset/VMA/PADDR/filesz/memsz/flags，以及有大小、已定义 STT_FUNC symbols。

验证 header entry sizes、section/segment ranges、symbol count/string table/link/name bounds、地址不 wrap、LOAD ranges 不重叠。目标 entry 必须声明 Thumb state，canonical entry 必须落在文件支持的 executable LOAD 内。ELF class/machine 并不证明具体 MCU；M-profile decoder 模式是本 analyzer 的明确支持前提，不推导 arbitrary ARM ISA compatibility。

## I. ELF / BIN Consistency

image base 来自已校验 config.text.base_addr。对每个 `PT_LOAD` 的所有 file-backed bytes：

```text
BIN offset = p_paddr - image_base
ELF[p_offset : p_offset+p_filesz] == BIN[offset : offset+p_filesz]
```

VMA 用于指令定位，PADDR/LMA 用于加载镜像映射。filesz ≤ memsz；BSS 和 no-file LOAD 不从 BIN 读取/补造数据。任何范围越界或不一致会终止整个 ingestion。

真实 Heat_Press：code LOAD 22692 bytes；RAM `.relocate` 的 VMA `0x20070000`、LMA `0x858a4`、filesz 2204。两段与 BIN 一致，RAM VMA 没有被当作 BIN offset。BIN 是一致性验证输入；指令 EvidenceRef 定位 ELF 字节，已核对的 image offset 则存 details。

## J. ARM / Thumb Decoder

`ArmThumbInstructionDecoder` 使用 Capstone 5，模式 THUMB + MCLASS + LITTLE_ENDIAN。raw_encoding 是按递增内存地址排列的小写 hex 字节，例如 `99 69 → "9969"`，不按 numeric word 变成 `"6999"`，不沿用 RISC-V MSB-first bit-vector 的解释。

结构化 operands 只覆盖可靠的 register/immediate/memory(base+displacement)。machine register 统一 r0…r15，sp/lr/pc 对应 r13/r14/r15；backend alias 保留在 operand_text/backend_operand_text。register lists、shifted operand、writeback、indexed memory 或特殊形式保留 display，但 structured operands 为空。独立 `lsls r2,r5,#31` 的显式 immediate 可表示，与 `add.w ..., r2, lsl #2` 的 shifted operand 不同。

不是 ARM semantic lifter，也不生成 CFG、taint、寄存器运行值或异常分析。

## K. Static Instruction Site Extraction

按配置的所有 distinct PC 排序，找包含该 PC 的 sized STT_FUNC；若多个候选，稳定选择最小 function range 后按地址/名字排序。canonical start 为 raw_symbol_value & ~1，同时保留 raw value。函数必须在单一 executable file-backed LOAD 内，且不超过 4096 bytes。

从 function start 顺序解码至 PC，只有正好命中 16/32-bit 指令边界才产生 STATIC_INSTRUCTION_SITE。缺符号、函数过大、不可解码 prefix 或 PC 位于 32-bit 指令中间：保留该 PC 所属全部 MMIO_MODEL，记录原因；direction 为 unknown。没有硬编码 A0 的两个演示 PC。

## L. MMIO Model Extraction

32 entries 全部产生 CONFIGURATION observations，包含 23 PC / 19 MMIO addresses 的多对多关联。一个配置 key 对应一条 MMIO_ACCESS behavior，summary 为 configured access-site association，`evidence_scope=configuration`。

direction 仅在同一 PC 的 confirmed decode 为受支持简单 load/store 且字节宽度与配置一致时填 read/write，同时追加该指令的 ELF EvidenceRef。其余填 unknown。不能根据 model_kind 猜方向，不能把 val/init_val/vals/mask 变成读回值或寄存器值。

## M. Environment Input Extraction

6009-byte input 只用于校验 size/hash，输出 OpaqueInputDetails；不投送原始字节、hex dump 或输入 offset mapping。`crashing_input` 是文件名，不赋予 ChipChain 的 crash confirmed 语义。

第二条环境 observation 记录周期 1000 emulator ticks 的 round_robin 配置。1000 ticks 不等于 1000ms。两个环境 observations 都不生成 ProcessorBehavior，尤其不生成 INTERRUPT/EXCEPTION。

## N. Oracle Isolation

边界落实在四文件 reader 和 FirmwareAgentInput role validation，不依赖 prompt。BENCHMARK_ORACLE 默认角色会被拒绝；显式添加 README/known root cause 文件不会被读取。所有输出 EvidenceRef 只关联本 case 四个已声明 inputs，nested decoded evidence 也接受 membership 校验。

**V3-2B blocker：真实 model context 必须使用 neutral artifact projection。** 当前 ArtifactRef.path 仍保留 `04-crash-analysis/13/crashing_input`，它本身具有答案提示。本阶段没有 LLM，因此不重构路径投影、不把现有 context 标为可直接用于真实模型。

## O. ProcessorBehavior Mapping

仅产生：23 条 INSTRUCTION（static）和 32 条 MMIO_ACCESS（configuration association）。均为 origin=firmware、architecture=ARM，含 EvidenceRef。成功指令含 DecodedInstruction。

没有 DATA_DEPENDENCY、CONTROL_DEPENDENCY、EXCEPTION、INTERRUPT、runtime MMIO，也没有 external-input path、ReachableBehavior 或 vulnerability finding。配置输入的范围描述不等于现场执行证据。

## P. FirmwareAgentInput / Context Integration

`FirmwareObservations → FirmwareAgentInput → model_dump/model_validate` 保留 typed kind/role/scope/details；`_SideContext` 显式包含 FirmwareObservation union member。

完整 model JSON 会重复同一 EvidenceRef 于 observation、behavior、decoded instruction。为保持当前 64000-character 上限，**仅 firmware context** 用可逆引用压缩：所有 observation.evidence 原文保留，完全相同的 nested evidence list 替换为 evidence_ids，可在同一 context 的 observation evidence 中解析。若找不到完全相同的 ref，则保留 nested 原文；相同 ID 对应不同 observation evidence 时拒绝序列化。typed details、所有 observations、所有 behaviors 和证据内容均保留，不截断、不随机删项。

这不是 FirmwareAgentInput 持久化格式改变：domain round-trip 仍使用完整 EvidenceRef；context 是模型投影，恢复 nested evidence_ids 后可重建 behaviors。Hardware context 继续既有序列化；generic firmware observation 的 nested evidence 结构保留。全局 128-item/64000-char 限制不变。

调用示例（`case` 的四个 ArtifactRef 由调用方显式构造并声明 fingerprint）：

```python
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.context import firmware_context
from chipchain.agents.firmware import FirmwareSecurityAgent

analyzer = FuzzwareHeatPressScenarioAnalyzer()
batch = analyzer.analyze(
    case_id=case.case_id, target=case.target, artifacts=case.firmware_artifacts,
)
inputs = FirmwareAgentInput(case=case, deterministic_observations=batch)
context = firmware_context(inputs)
output = FirmwareSecurityAgent().invoke(inputs)  # 无 model，仅 stub 合同/IR 验证
```

没有自动接 workflow，没有保存 stub 为真实 report。

## Q. Heat_Press Scenario 13 Real Results

与 A0 四个 fingerprint 全部一致；integration 用中性 case ID `fuzzware:heat-press:scenario-13`，artifact IDs 为 elf/bin/yaml/opaque。计数和 context length 来自实际运行：

| 项目 | 实测 |
| --- | ---: |
| MMIO_MODEL | 32 |
| distinct PCs / MMIO addresses | 23 / 19 |
| STATIC_INSTRUCTION_SITE | 23 |
| successful decodes | 23 |
| unsupported/unresolved sites | 0 |
| ENVIRONMENT_INPUT | 2 |
| observations 总数 | 57 |
| STATIC / CONFIGURATION / ARTIFACT / RUNTIME | 23 / 33 / 1 / 0 |
| INSTRUCTION / MMIO_ACCESS behaviors | 23 / 32 |
| unique EvidenceRef IDs | 57 |
| opaque input bytes（文件长度，不进入 context） | 6009 |
| context characters | **62793** |
| context observations / artifacts / questions | 57 / 4 / 2 |

Model kinds：bitextract=2、constant=5、passthrough=9、set=5、unmodeled=11。当前所有 23 sites 都可顺序确认，未决问题仍保留两条全局语义限制：不证明执行/可达，不具有 input consumption/runtime/failure outcome。

context 长度依赖调用方 ID/path/name；长标识可能超过限制，此时明确失败而非截断。A1 验证的是当前真实四文件 case 的大小。

## R. Claims Explicitly NOT Made

本阶段不声称 crash occurred、HardFault、runtime MMIO/interrupt、external-input reachability、已覆盖指令、crash path、vulnerable location、root cause 或 exploitability。无模型 FirmwareSecurityAgent 的报告保留 stub unresolved message、空 findings/issue anchors/input paths/reachability；没有被保存成真实固件安全报告。

## S. Synthetic Tests

默认测试不读外部 corpus。新增微型 ELF fixture 在测试中构造 code LOAD、RAM VMA/flash LMA 的 data LOAD 和不对应 BIN bytes 的 BSS LOAD；测试 MMIO model 五类参数、32-bit Thumb 中间 PC、无符号/过大函数/失败 prefix、ELF64/BE/non-ARM/损坏 ranges、LOAD mismatch、YAML duplicate/tag/layout/alias/bounds/types、未声明路径拒绝、fingerprint 校验。

合同测试覆盖 fail-closed role、kind/scope/details、typed round-trip、context evidence 引用解析、冲突 ID 拒绝、nested membership、opaque bytes 隐藏、配置参数不提升为 runtime state，以及 stub 的空 path/reachability/findings。ARM 测试覆盖 memory order、16/32-bit、canonical registers 和不可表示 operands 的 display fallback。全部既有 Hardware 回归保持。

## T. Real Local Test

显式运行：

```bash
CHIPCHAIN_FUZZWARE_ROOT=/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
  .venv/bin/python -m pytest -q -s tests/integration/test_fuzzware_local.py
```

默认未设置变量时 skip；设置了变量但目录缺失/hash 不符时失败，不伪装 skip。不使用 .env，不自动发现真实资源。

## U. Fresh Environment Verification

新建 `/tmp/chipchain-v3-2a1-fresh-14ozo6da`，从 pyproject 安装普通 wheel（非借用现有 site-packages），包括 `[test]` 与 build isolation。初次仅使用旧 wheel 目录未找到 PyYAML；随后从本机 pip HTTP cache 的 wheel ZIP 恢复本地文件到 `/tmp/chipchain-v3-2a1-offline-wheels`，没有联网、没有重打包 installed site-packages 伪造依赖。

```bash
.venv/bin/python -m venv /tmp/chipchain-v3-2a1-fresh-14ozo6da
/tmp/chipchain-v3-2a1-fresh-14ozo6da/bin/python -m pip install --no-index \
  --find-links=/tmp/chipchain-v3-2a1-offline-wheels \
  --find-links=/tmp/chipchain-v3-r0-wheels '.[test]'
```

在最终代码检查后重新构建安装项目 wheel；从 `/tmp` 用 `python -I` import yaml/elftools/capstone 和已安装 analyzer，确认使用 fresh site-packages 中的 ChipChain。fresh Python 再运行仓库离线 pytest 和 pip check；pytest 的既有 pythonpath=src 配置仍作用于源树测试，isolated import 单独验证了 wheel 包内容。

Resolved runtime：PyYAML 6.0.3、pyelftools 0.33、Capstone 5.0.9、Pydantic 2.13.4、LangChain 1.2.10、langchain-core 1.6.2、LangGraph 1.0.10、langgraph-prebuilt 1.0.8、langchain-deepseek 1.1.0、pytest 9.1.1。导入 installed integration class 不表示实例化模型或调用 API。

## V. Exact Test Results

最终精确结果：

```text
当前 .venv：python -m pytest -q
371 passed, 7 skipped in 4.30s

显式真实 Heat_Press：pytest -q -s tests/integration/test_fuzzware_local.py
1 passed in 0.29s

Fresh venv：python -m pytest -q
371 passed, 7 skipped in 4.22s

当前 .venv / fresh venv：python -m pip check
No broken requirements found.

当前 .venv：python -m compileall -q src tests
exit 0; no output

git diff --check
exit 0; no output
```

相对 304 passed / 6 skipped 基线，新增 67 个默认离线测试实例和 1 个默认 skip 的真实 integration test。曾有一个新增测试错误地将独立 lsls 的 immediate 视为 shifted operand；已用真正的 `add.w ..., lsl #2` 验证 display fallback，未修改真实统计来迎合 parser。

另外检查了所有新增 untracked 文本的 whitespace，以及 `output/reviewed/v3-1b1/` 的 12 个 tracked 文件：逐文件与 HEAD 原始字节一致。

## W. Dependencies / pip check

当前 venv 和 fresh venv 均执行 `python -m pip check`；结果见 V。PyYAML 不再依赖 transitive 偶然安装。整个安装过程都带 `--no-index`，build dependencies 也从指定本地 wheel 目录获取。

## X. Documentation

本文记录实现、输入边界、解析规则、真实统计、context 投影及验证。README 仅更新阶段与入口链接；R0 架构文档不重写。A0 调研结论保持原始记录，不用新实现回改旧阶段工具版本或结果。

## Y. Architecture Concerns

FirmwareObservation 的 scope/role 与通用 IR/report 分开；没有创建 Cortex-M-only FirmwareAnalysisReport。MEMORY_BYTES 是通用表示，ARM register normalization 属于 architecture adapter，Fuzzware model key/parameters 属于 corpus adapter。MMIO address 与 PC 分别保存在 details，未滥用 EvidenceLocation.address 承载两个地址或 file offset。

没有通用 firmware framework、scheduler、Batch domain、数据库或重试队列。文件/函数/条目上限是解析边界，不限制 ChipChain case 数量。

## Z. Deferred Work

**进入 V3-2B 前最重要的一项确定性能力：neutral firmware evidence/context projection**，消除 corpus path/name 等答案提示，同时保留可追溯 artifact identity。这是当前真实模型接入的具体 blocker；本轮不实现、更不绕过它调用模型。

其他待有真实 artifacts 再做：第二 target、更多 YAML 结构、独立 runtime trace/coverage/MMIO consumption、input→behavior 对应、full CFG/ARM lifting、exception/crash state、真实 FirmwareAgent 推理及 reviewed exporter。没有独立 runtime evidence 时，不能以解析更多 config 代替执行证明。

未来真实 Firmware Agent 成功 run 应显式持久化 `output/<case>/<run>/analysis_run.json` 与 `firmware_analysis_report.json`，人工接受后再导出 reviewed。A1 没有生成这类真实报告；`output/reviewed/v3-1b1/` 的 743/820 字节保持不变。

## AA. Git Status

最终 `git status --short --untracked-files=all`：

```text
 M README.md
 M pyproject.toml
 M src/chipchain/agents/context.py
 M src/chipchain/agents/contracts.py
 M src/chipchain/domain/case.py
 M src/chipchain/domain/instruction.py
 M src/chipchain/tools/architecture/__init__.py
 M src/chipchain/tools/contracts.py
?? docs/research/v3-2a1-fuzzware-heat-press-ingestion.md
?? src/chipchain/tools/architecture/arm.py
?? src/chipchain/tools/firmware/__init__.py
?? src/chipchain/tools/firmware/fuzzware/__init__.py
?? src/chipchain/tools/firmware/fuzzware/heat_press.py
?? src/chipchain/tools/firmware/fuzzware/readers.py
?? tests/firmware_fakes.py
?? tests/integration/test_fuzzware_local.py
?? tests/unit/test_arm_decoding.py
?? tests/unit/test_fuzzware_ingestion.py
```

8 个修改文件、10 个新增文件，均未 staging。未 git add/commit/push/tag。没有真实 ELF/BIN/input fixture 被放入 repository；Fuzzware corpus 的 Git status 仍干净。

## 最后 15 个明确回答

1. **能否不依赖 LLM 确定性 ingest？能，真实四文件已通过。**
2. **事实类型能否区分？能，typed scope 与 kind/details 强制一致。**
3. **是否产生 RUNTIME observation？否，0。**
4. **BENCHMARK_ORACLE 能否进入 FirmwareAgentInput？不能，validator 拒绝。**
5. **是否读取四个 ArtifactRef 以外的文件内容？否，config path 只用于匹配，companion 不读取。**
6. **6009-byte 全量内容是否进入 context？否，只有 identity/size/hash。**
7. **input 存在是否触发 crash claim？否。**
8. **32 个模型是否全部保留且不称为 runtime MMIO？是。**
9. **指令是否来自真实字节和确认边界？是，ELF/BIN 比对后从 sized function start 顺序解码。**
10. **静态解码是否等于执行/外部可达？否。**
11. **参数是否成为 observed runtime value？否，只是配置。**
12. **真实 context 是否满足 64k / 128 items？是，62793 chars，57 observations、4 artifacts、2 questions。**
13. **默认 pytest 是否离线且独立于 corpus？是，真实 test 默认 skip。**
14. **是否执行真实 LLM/network/emulation/fuzzing？全部没有；也未读取 .env。**
15. **B 前最重要的单项确定性能力？中性的 firmware operational context projection，消除路径/命名答案泄漏。**
