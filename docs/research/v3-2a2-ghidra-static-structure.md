# V3-2A2 — Ghidra Static Structure & Cortex-M IRQ Mapping

## A. Implementation Summary

基线 `v3-2b-r1-stable` / `bf08bceac2bbe066844842023b355f9e18851313`。
本阶段实现显式 ELF → 本机 Ghidra headless → 严格 JSON → 独立 ELF/Capstone 核对，
以及 A1 MMIO site 的函数归属比较和有界 Cortex-M 向量映射。只产生静态结构结果。

Firmware R1 run `b47c9cc6-b958-4c6a-a40b-eb436e431f26` 仍为
**machine-valid / human-rejected / NOT reviewed**。本阶段不修改该运行和两个历史 rejected pilots，
不运行任何 Firmware Agent 或真实模型，不修改 prompt v1 / projection v1，不进行 reviewed export。

## B. Files Changed

- `scripts/ghidra/ExportFirmwareStructure.java`：Java headless pre/post script。
- `src/chipchain/tools/firmware/ghidra/`：`models.py`、`elf.py`、`normalize.py`、`process.py`、
  `associations.py`、`api.py`、`__init__.py`、`__main__.py`。
- `src/chipchain/tools/architecture/cortex_m.py`：架构专用向量表解析。
- `tests/ghidra_fakes.py`、`tests/unit/test_ghidra_structure.py`、
  `tests/unit/test_ghidra_process.py`、`tests/integration/test_ghidra_local.py`。
- root `README.md` 和本文。

没有改变既有 domain、A1 analyzer、IR、Agent、prompt、projection、dependency 或 workspace 规则。

## C. Local Ghidra Environment

在修改生产代码之前只读检查安装、application.properties、ARM.ldefs、launch.properties 和 headless 启动。
使用已有 GDBFuzz 安装；没有网络下载、安装、Java 升级或替换。

| 项目 | 实际值 |
|---|---|
| Ghidra | **10.1.4 PUBLIC**, build 20220519 |
| Home | `/home/qcx/fuzz/gdbfuzz/dependencies/ghidra` |
| analyzeHeadless | `/home/qcx/fuzz/gdbfuzz/dependencies/ghidra/support/analyzeHeadless` |
| Java runtime | `11.0.32+9-post-1ubuntu1-22.04-Ubuntu` |
| Java vendor | Ubuntu |
| Java home | `/usr/lib/jvm/java-11-openjdk-amd64` |
| Language | `ARM:LE:32:Cortex` |
| Compiler spec | `default` |

Java identity 在真实 postScript 中记录，非根据环境变量猜测。脚本 API 按安装中实际 class
的 `javap` 签名核对，包括 `HeadlessScript.analysisTimeoutOccurred` 和 analysis options API。
生产入口只接受显式 home，不扫描 filesystem。

## D. Ghidra Execution Boundary

启动前校验 ELF 261365 bytes、SHA256
`73f667524ed0ff8f24b460d4678b74f15eec13d954b93cdc92c839c2c3f1044e`。
同名但 fingerprint 不符的文件失败。ELF 从 corpus 复制到隔离临时目录并设为只读，
Ghidra 只接收该副本，不接收 corpus 路径。后台当然还会读取自身安装、Java 和 ChipChain 脚本；
**唯一传入的研究输入是 ELF**。不自动打开 BIN、config、opaque input、README、source、patch 或漏洞说明。

仅使用显式 argv、`shell=False`、新进程组；外层默认 300 秒、最大 600 秒，
Ghidra 每文件分析上限 240 秒、1 CPU。stdout/stderr 合计上限 1 MiB，超过则终止进程组；
export 上限 16 MiB。退出、超时、超量都回收子进程并清理临时目录。
环境仅保留固定 PATH/locale 和受控 Java home/cache/temp properties，不继承任意调试或 API 配置。
这不是操作系统级 filesystem/network sandbox；只读边界由显式单文件导入和关闭外部/debug 分析建立。

Ghidra 原始日志只存在临时目录/受限 pipe，返回固定安全错误摘要，不进入语义 JSON 或 EvidenceRef。
`extract_heat_press_structure` 不持久化；CLI 是调用方显式触发的输出入口，创建新 UUID 目录。

## E. Headless Export Script

Java `HeadlessScript`，无外部 Java dependency。通过 FunctionManager、Listing/Instructions、
ReferenceManager、symbol/source 和 memory API 提取。禁用名称含 Decompiler、DWARF、PDB、External
的所有布尔 analysis options，并显式关闭 `Call Convention ID`；不导出 C pseudocode、
高层变量或 decompiler data flow。安装中 `javap DecompilerCallConventionAnalyzer` 确认该
显示名称不含 Decompiler 的 analyzer 也使用反编译器，所以最终配置额外禁用它，并重新验证两次。
早期探查保留该默认项，未使用其调用约定/伪代码输出；交付结果全部来自关闭后的最终配置。

语义文件使用 UTF-8，字典排序；Python 进一步按地址、ID、symbol 和 range 排序，
不保存时间戳、临时项目路径或日志。Ghidra metadata overlay 和人工 `EXTERNAL` memory block
不算目标内存；其余目标 memory 必须与 ELF PT_LOAD 覆盖一致。

## F. Static Structure Contracts

独立 tool-level `StaticFunction`、`StaticCallEdge`、`GhidraStaticStructureResult`，
以及 `MmioFunctionBinding`。函数含 identity、entry、半开 body ranges、size、source、symbols、thunk/external 标志。
通用函数/调用合同无 Thumb 专用字段；程序身份显式为 `Architecture.ARM`。
当前 ELF adapter 和 call normalization 是 Cortex-M 边界，尚未实现 RISC-V/PowerPC backend。
`VectorHandlerBinding` 位于架构专用模块。

Python 拒绝重复 JSON key、未知字段、缺失字段、类型错误、重复 ID、非法范围、错误程序/工具身份、
不兼容 memory、非 executable callsite 和 ELF bytes 不一致。未解析 caller/callee、多个 targets、
边界或解码冲突明确保留 unresolved，不能成为 confirmed edge。
完整 graph **不进入 FirmwareObservations、ProcessorBehaviorIR 或 Agent context**。

## G. Function Extraction

**183 functions**：146 `IMPORTED`，37 `ANALYSIS`；DEFAULT / USER_DEFINED / UNKNOWN 为 0。
名字保留为符号标签，不能凭名称推断物理接口。Ghidra body ranges 不等于 ELF symbol size；
`PIO_SetPeripheral @ 0x80d3e` body 仅 `[0x80d3e,0x80d48)` 与 `[0x80d60,0x80d64)`。
不能用 ELF 的较大 symbol range 静默填补 Ghidra body 缺口。

## H. Direct Call Extraction

Ghidra 导出 **306 call sites**。经独立确认后得到 **238 resolved direct call edges**，
另 **68 unresolved**：31 computed/ambiguous、32 decoder disagreement、
3 missing caller、2 instruction boundary unconfirmed。计数为 callsite edges，非去重后的函数对。

## I. Ghidra / Capstone Cross-Check

从 pyelftools ELF PT_LOAD 提取实际 bytes，以独立 ELF STT_FUNC entry/size 作为解码起点和界限，
调用既有 `ArmThumbInstructionDecoder`（Capstone 5.0.9，Thumb M little，函数最大 4096 bytes）。
只接受合法边界上的 `bl`，且 bytes、caller containment、callee entry 和 immediate target 一致。
分析生成但缺少独立 ELF function bound 的调用不强行确认。不存在 Ghidra 自证 instruction boundary。

特别是 Ghidra `Shared Return Calls=true` 可能把 tail branch 标为 call；Capstone 不同意时保留冲突。
`UART_Handler` 的 `0x80abe` 实际 bytes `00f071bd`，解码 **`b.w #0x815a4`**，
不是本阶段接受的 `bl`。该站点保存为 `decoder_disagreement`，不计入 238 条 confirmed call edges。

## J. MMIO → Function Bindings

23 个 unique PCs：**20 unique containment，3 missing，0 ambiguous**。
32 个 MMIO behavior bindings（27 unique、5 missing）各自保留 A1 evidence、behavior ID 和 static address containment basis。
20 个已归属 PCs 涉及 **10 个 unique Ghidra functions**；A1 labels 涉及 11 个函数，差异是
`PIO_SetPeripheral` 的 3 个站点缺少 Ghidra body containment。缺失不意味着该代码不存在或不会执行。

| MMIO PC | A1 function | Ghidra function/entry | Entry comparison | Mnemonic | A1 direction |
|---|---|---|---|---|---|
| `0x80d4e` | `PIO_SetPeripheral` | **missing** | unresolved | `ldr` | read |
| `0x80d50` | `PIO_SetPeripheral` | **missing** | unresolved | `ldr` | read |
| `0x80d5a` | `PIO_SetPeripheral` | **missing** | unresolved | `ldr` | read |
| `0x80e16` | `PIO_GetOutputDataStatus` | `PIO_GetOutputDataStatus @ 0x80e14` | match | `ldr` | read |
| `0x80e1c` | `PIO_GetOutputDataStatus` | `PIO_GetOutputDataStatus @ 0x80e14` | match | `ldr` | read |
| `0x80e3a` | `pmc_enable_periph_clk` | `pmc_enable_periph_clk @ 0x80e28` | match | `ldr` | read |
| `0x80e4e` | `pmc_enable_periph_clk` | `pmc_enable_periph_clk @ 0x80e28` | match | `ldr.w` | read |
| `0x80e7e` | `pmc_disable_periph_clk` | `pmc_disable_periph_clk @ 0x80e6c` | match | `ldr` | read |
| `0x80eba` | `SystemInit` | `SystemInit @ 0x80eac` | match | `ldr` | read |
| `0x80eca` | `SystemInit` | `SystemInit @ 0x80eac` | match | `ldr` | read |
| `0x80ed2` | `SystemInit` | `SystemInit @ 0x80eac` | match | `ldr` | read |
| `0x80eda` | `SystemInit` | `SystemInit @ 0x80eac` | match | `ldr` | read |
| `0x80ee6` | `SystemInit` | `SystemInit @ 0x80eac` | match | `ldr` | read |
| `0x80ef2` | `SystemInit` | `SystemInit @ 0x80eac` | match | `ldr` | read |
| `0x80efe` | `SystemInit` | `SystemInit @ 0x80eac` | match | `ldr` | read |
| `0x80f0a` | `SystemInit` | `SystemInit @ 0x80eac` | match | `ldr` | read |
| `0x81022` | `adc_init` | `adc_init @ 0x80fac` | match | `ldr` | read |
| `0x81044` | `adc_configure_trigger` | `adc_configure_trigger @ 0x81044` | match | `ldr` | read |
| `0x81054` | `adc_configure_timing` | `adc_configure_timing @ 0x81052` | match | `ldr` | read |
| `0x8131c` | `pinMode` | `pinMode @ 0x81234` | match | `ldr` | read |
| `0x8147c` | `_ZN9UARTClass5writeEh` | `write @ 0x81478` | match | `ldr` | read |
| `0x815aa` | `_ZN9UARTClass10IrqHandlerEv` | `IrqHandler @ 0x815a4` | match | `ldr` | read |
| `0x815b0` | `_ZN9UARTClass10IrqHandlerEv` | `IrqHandler @ 0x815a4` | match | `ldr` | read |

## K. A1 Symbol vs Ghidra Function Comparison

20/23 entry-address matches；17 exact name matches，3 name differences，3 missing containment，
0 A1 missing，0 matched-site entry conflicts，0 ambiguous containment。
三个名字差异发生在 UART C++ methods：`_ZN9UARTClass5writeEh` → `write`（1 PC），
`_ZN9UARTClass10IrqHandlerEv` → `IrqHandler`（2 PCs），入口相同，Ghidra GNU demangling 开启。
名称差异不覆盖 A1 字段，也不视为地址冲突。

## L. Cortex-M Vector Table Evidence

ELF 提供显式 `STT_OBJECT exception_table`：地址 **0x80000**，size **244 bytes**，
范围 **[0x80000, 0x800f4)**，61 个 32-bit little-endian words。
没有依赖名称为 `.vectors` 的真实 section；边界来自 symbol + size。
初始 SP `0x20088000`，Reset word `0x80f35` 与 ELF entry 一致（canonical `0x80f34`）。
不扫描到“看起来不像地址”为止，也不使用 `_sfixed` 的整个 text 区间推测向量长度。

## M. Vector → Handler Bindings

61 words = 1 initial SP + 15 core slots + 45 external IRQ slots。
core slots 中 10 个非空 handler entries、5 个零值；external slots 中 41 个非空、4 个零值。
**51 个非空 handler entries 全部映射到 function entry**，共 14 个不同函数入口。
9 个 null entries 明确保留；没有 inside-function、outside-executable、non-Thumb 或 ambiguous handler。
外部编号仅为 vector index - 16；不根据编号猜厂商 peripheral 名称。

## N. Handler → Function Bindings

下表合并相同地址，覆盖全部 51 个非空 entries。所有地址由 raw Thumb value 清除 bit 0 得到；
重复的 default handler 地址保留全部 ELF aliases，不根据 alias 集合替每个 IRQ 选择外围设备名称。

| Vector indices | Canonical handler | Ghidra function ID | ELF symbolic labels |
|---|---|---|---|
| 1 | `0x80f34` | `f80f34` | Reset_Handler |
| 2, 3, 4, 5, 6, 12, 16, 17, 18, 19, 20, 21, 22, 23, 25, 35, 37, 38, 39, 40, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 57, 58, 59, 60 | `0x81174` | `f81174` | ADC_Handler / BusFault_Handler / CAN0_Handler / CAN1_Handler / DACC_Handler / DMAC_Handler / DebugMon_Handler / EFC0_Handler / EFC1_Handler / EMAC_Handler / HSMCI_Handler / HardFault_Handler / MemManage_Handler / NMI_Handler / PMC_Handler / PWM_Handler / RSTC_Handler / RTC_Handler / RTT_Handler / SMC_Handler / SPI0_Handler / SSC_Handler / SUPC_Handler / TC0_Handler / TC1_Handler / TC2_Handler / TC3_Handler / TC4_Handler / TC5_Handler / TC6_Handler / TC7_Handler / TC8_Handler / TRNG_Handler / TWI0_Handler / TWI1_Handler / USART2_Handler / UsageFault_Handler / WDT_Handler / __halt |
| 11 | `0x81176` | `f81176` | SVC_Handler |
| 14 | `0x8117a` | `f8117a` | PendSV_Handler |
| 15 | `0x8117e` | `f8117e` | SysTick_Handler |
| 24 | `0x80abc` | `f80abc` | UART_Handler |
| 27 | `0x81094` | `f81094` | PIOA_Handler |
| 28 | `0x810cc` | `f810cc` | PIOB_Handler |
| 29 | `0x81104` | `f81104` | PIOC_Handler |
| 30 | `0x8113c` | `f8113c` | PIOD_Handler |
| 33 | `0x80ad0` | `f80ad0` | USART0_Handler |
| 34 | `0x80adc` | `f80adc` | USART1_Handler |
| 36 | `0x80ae8` | `f80ae8` | USART3_Handler |
| 56 | `0x81084` | `f81084` | UOTGHS_Handler |

## O. UART / ADC Symbol Interpretation Boundary

Vector 24（external IRQ 8）raw `0x80abd` → `0x80abc`，ELF label `UART_Handler`。
存在一条独立解码确认的静态 `b.w` branch 到 `UARTClass::IrqHandler @ 0x815a4`；
这是具体 branch target 证据，但本阶段没有将 tail branch 升格为 confirmed direct-call edge，
更不表示运行时调用、输入可达或已验证的物理 UART input。
该 MMIO-containing method 有一条 confirmed BL 到 `RingBuffer::store_char`。

`ADC_Handler` 是 `0x81174` 共享 default handler 的众多别名之一；不能把所有指向该地址的
38 个 vector entries 都标成 ADC。该 default handler 没有 confirmed outgoing direct calls。
没有证据把 Fuzzware interrupt trigger configuration 接到 UART/ADC handler；vector 表和 config
是两个独立静态/配置事实集合，没有建立运行时触发关系。

## P. Determinism / Repeatability

最终同一 ELF、Ghidra 版本、Java、script 和 options 连续运行两次。
规范化结构 JSON **byte-identical**；vector JSON 也逐字节相同。
不靠排除随机时间或 temp path 达成相等，因为这些字段根本不进入语义结果。

Structure SHA256：`afe0242bb3f17e98bfbed887710b79677c35ec1988a2a01dd69fc8f7062c9e8c`。

## Q. Heat_Press Real Results — Direct Call Neighborhoods

下面的 callers/callees 是去重的函数集合，incoming/outgoing 是 callsite edge 数。
只计 238 条 confirmed direct-call edges；0 不等于没有间接调用、tail branch 或运行路径。
名称重载时用 entry 地址区分。

| MMIO-containing function | Unique callers / incoming edges | Direct callers | Unique callees / outgoing edges | Direct callees |
|---|---|---|---|---|
| `PIO_GetOutputDataStatus @ 0x80e14` | 1 / 1 | `digitalWrite @ 0x8133c` | 0 / 0 | — |
| `pmc_enable_periph_clk @ 0x80e28` | 3 / 4 | `init @ 0x80af4`, `pinMode @ 0x81234`, `init @ 0x8152c` | 0 / 0 | — |
| `pmc_disable_periph_clk @ 0x80e6c` | 0 / 0 | — | 0 / 0 | — |
| `SystemInit @ 0x80eac` | 1 / 1 | `init @ 0x80af4` | 0 / 0 | — |
| `adc_init @ 0x80fac` | 1 / 1 | `init @ 0x80af4` | 0 / 0 | — |
| `adc_configure_trigger @ 0x81044` | 1 / 1 | `init @ 0x80af4` | 0 / 0 | — |
| `adc_configure_timing @ 0x81052` | 1 / 1 | `init @ 0x80af4` | 0 / 0 | — |
| `pinMode @ 0x81234` | 3 / 6 | `begin @ 0x80148`, `setup @ 0x804a4`, `digitalWrite @ 0x8133c` | 3 / 6 | `PIO_Configure @ 0x80db0`, `pmc_enable_periph_clk @ 0x80e28`, `adc_disable_channel @ 0x8106c` |
| `write @ 0x81478` | 0 / 0 | — | 0 / 0 | — |
| `IrqHandler @ 0x815a4` | 0 / 0 | — | 1 / 1 | `store_char @ 0x813e6` |

`PIO_SetPeripheral` 不在此表：其 3 个 A1 PCs 没有 Ghidra containment，不能伪造已关联邻域。

## R. SystemInit Direction Audit

`0x80eba, 0x80eca, 0x80ed2, 0x80eda, 0x80ee6, 0x80ef2, 0x80efe, 0x80f0a`
全部属于 `SystemInit @ 0x80eac`，mnemonic 全为 **ldr**，A1 MMIO direction 全为 **read**。
A2 没有改动这 8 个 site 或其余 A1 facts。R1 prose 中的 write 表述不因此成为事实。

## S. Claims Explicitly NOT Made

不声称 execution、IRQ occurrence、opaque bytes consumption、runtime reachability、physical UART/ADC
input path、crash、vulnerability 或 interrupt config → handler connection。
不进行模型 prose 的 NLP validator，不产出新的 FirmwareAnalysisReport。

## T. Synthetic Tests

新增 49 个默认离线测试，使用生成 ELF/export JSON，覆盖 strict schema、重复 function/edge/site ID、
目标身份、memory、ELF bytes、caller/callee unresolved、非指令边界、独立 BL target、排序、provenance，
以及 MMIO missing/unique/overlap、A1 name/entry 比较与不变性、向量 section 有界解析、
Thumb bit、entry/inside/outside/null/non-Thumb、无边界 unresolved 和符号语义限制。

Process 测试使用 fake headless；超时、退出失败、日志超量和已关闭 pipes 的等待超时使用极小的
stdlib Python 子进程。只在这些测试里允许该明确子进程，Python 网络 guards 继续启用。
验证 companion 文件不会被读取、ELF fingerprint 不符在进程前失败、env 不继承 debug settings，
成功/失败均清理 `.gpr/.rep` 临时项目。

## U. Real Ghidra Integration Test

```bash
CHIPCHAIN_GHIDRA_HOME=/home/qcx/fuzz/gdbfuzz/dependencies/ghidra \
CHIPCHAIN_FUZZWARE_ROOT=/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
.venv/bin/python -m pytest tests/integration/test_ghidra_local.py -q -s
```

两个 opt-in 变量均存在才运行；缺失 skip，显式无效路径 fail。
Ghidra runner 仅读取 ELF；**集成测试中的独立 A1 复核**另外读取既定 BIN/config/opaque 文件，
并前后校验四个 fingerprint。这些 companion 不传入 Ghidra。没有调用 Firmware Agent 或模型，
没有读取 `.env`。测试创建两个 temporary projects，每次结束后为空，并验证 observation JSON 不变。
初次验收检查曾错误假设 23/23 containment、4 个 SystemInit site；实测纠正为 20/23 和 8 个，
没有为满足这些假设扩大 Ghidra body 或改变数据。

## V. Exact Test Results

```text
.venv/bin/python -m pytest -q
563 passed, 8 skipped in 8.03s

explicit real Ghidra integration (two independent extractions)
1 passed in 19.72s

.venv/bin/python -m pip check
No broken requirements found.

.venv/bin/python -m compileall -q src tests
exit 0

git diff --check
exit 0
```

## W. Tool Provenance

- Script v1 SHA256：`34707a3452b654c31dbe5b130516ee383b446a92bada9849fcdecbd960d8b9ed`。
- Configuration SHA256：`3674fae7dbdac8251a8e03c83256eed18603d9aa990d4b4680ea3f30d5ce09e1`。
- ToolDescriptor：`ghidra-headless / 10.1.4 / firmware_static_structure`。
- Decoder：`capstone / 5.0.9 / instruction_decoder`；ELF metadata 使用既有 pyelftools。
- Configuration hash 覆盖 script hash、所有导出的布尔 analysis options、明确 language/compiler、
  `static-structure-normalization/v1`、1 CPU、240 秒分析上限、Capstone mode、4096-byte 独立函数界限。
- Ghidra 非布尔默认项由既有 10.1.4 安装提供，未手动改变；不宣称跨版本或被改装安装结果一致。
- `Call Convention ID=false`、`Decompiler Parameter ID=false`、`Decompiler Switch Analysis=false`、DWARF 系列 false、
  `External Entry References=false`；`Demangler GNU=true`、`Shared Return Calls=true`、
  `Function Start Search=true`、`Disassemble Entry Points=true`。完整布尔选项保存在 JSON 内并参与 hash。

显式保留的本次输出：`output/fuzzware:heat-press:scenario-13/790d34d9-dfad-4c54-885b-b266ecfb7a52/`，包含 `ghidra_static_structure.json`、
`cortex_m_vectors.json`、`mmio_function_associations.json`，均受现有 Git ignore 规则保护。
这是独立 tool result 目录，不冒充 Agent AnalysisRun，也不包含 FirmwareAnalysisReport。

## X. Limitations / Unresolved

3 个 missing containment PCs：`0x80d4e, 0x80d50, 0x80d5a`。
68 个 unresolved call sites 保留各自地址、target、caller 和 reason，不静默删除。
Ghidra 默认函数边界可能不完整；A2 不修复函数体、不构建全 CFG、不进行 decompiler 或数据流分析。
调用确认依赖 ELF function bound；stripped ELF/超大函数/indirect calls 不保证支持。
向量表策略需要可靠 extent，没有元数据时返回 unresolved。
没有 A3 reachability、angr、symbolic execution 或 path solving。

## Y. Recommended A3 Input

建议后续单独设计有预算的 relevant-subgraph projection：23 个 site IDs、原 A1 mnemonic/direction、
32 个 MMIO behavior IDs，20 个可靠 site→function bindings（10 个 functions），3 个 missing 标记；
再带这些函数的一跳 confirmed callers/callees、callsite evidence、必要的 unresolved/tail-branch 状态。
向量部分只选择与种子函数有明确结构联系的 entries，保留 raw/canonical address、symbol source、
shared aliases 与 static-only 限制。不得加入“config IRQ reaches UART”、physical input 或运行可达性推断。
本阶段只提出输入候选，没有实现 projection、改变 128-item/64k 预算、改 prompt 或运行模型。

## Z. Git Status / Preservation

既有 tracked 代码没有修改，只有 README 修改和上述新脚本、工具、测试、本文未跟踪文件。
ELF/BIN/config/opaque input、R1 运行、两个 rejected pilots 和 `output/reviewed/v3-1b1/`
逐文件 SHA256 与工作前快照一致。repo/corpus 未出现 Ghidra `.gpr/.rep`；temporary projects 已清理。
未执行 `git add`、`git commit`、`git push`、`git tag`。不进入 A3。

## Final 23 Questions

1. Ghidra **10.1.4 PUBLIC**。
2. 是，使用已有本机安装，无下载/升级。
3. 是，仅 headless。
4. 唯一研究输入是显式 ELF；另读取工具安装、Java、维护脚本。A1 companion 只由独立测试读取。
5. **183** functions。
6. **238** resolved direct-call edges。
7. **68** unresolved call sites。
8. **10** unique Ghidra MMIO-containing functions；另 3 PCs 缺失归属，A1 总计 11 个 labels。
9. 是，20 个唯一、3 个 missing、0 ambiguous。
10. **20** sites 的 entry matches；3 missing 不计为匹配。
11. 没有任何 A1 direction 改变。
12. SystemInit 的 **8 个 sites 均为 ldr/read**，地址见 R。
13. 是，可靠 symbol-size 边界。
14. `exception_table`，**[0x80000,0x800f4)**，244 bytes。
15. **51** 个 handler entries → **14** 个不同 function entries。
16. 有 `UART_Handler` 和共享 default 地址的 `ADC_Handler` alias。
17. 不证明 physical UART/ADC input path。
18. 没有 Fuzzware interrupt trigger → handler 的 deterministic connection。
19. 没有 runtime reachability claim。
20. 没有调用 DeepSeek，没有修改 prompt/projection。
21. R1 和历史 pilots 原字节保留，没有 reviewed-export。
22. 本阶段 Ghidra projects/temp workspace 已移除；只保留显式静态 JSON 和测试审计结果。
23. 建议投影 site→function、一跳 confirmed calls、相关 bounded vectors 及 unresolved/alias 限制，详见 Y；尚未实现。
