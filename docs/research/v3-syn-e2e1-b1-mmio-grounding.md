# SYN-E2E1-B1 — 确定性固件 MMIO 事实溯源

本阶段完成：**静态事实 ✓，真实运行时观察 ✓，静态—运行时对应 UNKNOWN**。

我们现在能分别回答两个问题：“固件字节里有哪些可确定的 MMIO 访问指令？”以及“这次真实运行接受并完成了哪些 MMIO 事务？”现有证据还不能把某一笔总线事务归属于某个具体 PC；因此没有把这两种事实合成已执行的静态指令，也没有输出硬件触发满足或跨层链结论。

## 人工验收先看这里

以下 P1/N1/N2 是 evaluation-only 引用。生产模型、ID 算法和输入适配器不接收这些标签。

| 验收引用 | 实际 COMMAND 写值 | 实际 STATUS 读值 | PC ↔ 事务绑定 | 可读报告（本地 ignored output） |
|---|---:|---:|---|---|
| R-P1 / N2 | `0xA5` | `0x0` | 3 × UNKNOWN | [中文报告](../../output/syn-e2e1-b1/preview-x2hq53at/runtime/b743198d722d88ba90e4c2e1c6282d9a933a35b53e432671ff8c23008c784215/report-mmio-zh.md) |
| V-P1 | `0xA5` | `0xDEAD` | 3 × UNKNOWN | [中文报告](../../output/syn-e2e1-b1/preview-x2hq53at/runtime/e4f68d69584b0c96e0032082c451296cd9fdedccc615409b0380d01c25d52804/report-mmio-zh.md) |
| R-N1 | `0xA4` | `0x0` | 3 × UNKNOWN | [中文报告](../../output/syn-e2e1-b1/preview-x2hq53at/runtime/51c99e0a749e69cbbde0fcf129d9ce78b040a5a7bbe07dc0f02c94337c7855db/report-mmio-zh.md) |
| V-N1 | `0xA4` | `0x0` | 3 × UNKNOWN | [中文报告](../../output/syn-e2e1-b1/preview-x2hq53at/runtime/6df64e9fa79c8ece009d84083f77d1cde8f4a7836ec20bc1fd1cf145b8fd5726/report-mmio-zh.md) |

每份静态目录都从 ELF bytes 确定出三个目标窗口访问点：

| PC | 指令字节（文件顺序） | 操作 | 有效地址 | 静态写值 |
|---|---|---|---|---|
| `0x100088` | `23a06200` | WRITE | `0x40000` | `1` |
| `0x100090` | `23a26200` | WRITE | `0x40004` | P1=`0xA5`；N1=`0xA4` |
| `0x100094` | `83a38200` | READ | `0x40008` | 不适用 |

另外保留两项非目标访问：`0x1000A0` 向 RAM `0x101000` 写值（静态值 unresolved，因为来自先前 load）；`0x1000AC` 向 SimCtrl `0x20008` 写入 1。没有把不属于目标窗口的访问当作不存在。

四个实际 run 的总线请求周期均为 **11、14、16**，对应响应周期 **12、15、17**；事务 ID 为 1、2、3，byte enable 均为 `0xF`，error 均为 0。这个顺序来自总线 trace，不来自静态表格的排列。读回 `0` / `0xDEAD` 都只叫“observed read value”，B1 不评价正常、异常或偏差。

## 改动范围

起始冻结基线：main，`b3163b947bb1efc1c4a1345269df47b980175724`，tag `v3-syn-e2e1-a-apparatus-stable`。

仅新增四个主要文件：

- `src/chipchain/firmware/mmio_grounding.py`：三个独立事实模型、RV32 有界后端、A 产物只读适配器、UNKNOWN 绑定和小型确定性中文 renderer。
- `tests/unit/test_firmware_mmio_grounding.py`：内存中构造的 synthetic ELF/XML/trace 单元测试。
- `tests/integration/test_syn_e2e1_b1_mmio_grounding.py`：四个真实 A run 的只读集成、静态身份共享、RVFI 边界检查、真实 XL2 UNKNOWN byte replay。
- `docs/research/v3-syn-e2e1-b1-mmio-grounding.md`：本说明与 80 项验收答复。

没有新增 report 模块或 phase-specific helper 文件。renderer 留在同一模块中，只将三类已验证对象确定性转成 Markdown；研究文档记录的是本轮实例，renderer 让调用者能为下一次合法输入复现同样的可读报告。没有改变任何原有 tracked 文件，包括 A 的七个文件、CAP0、XL1、XL2、agent、prompt、workflow、README、CURRENT_STATE。

## 三种对象为何分开

采用用户推荐的最小拆分，没有创建包含多个 RTL run 的巨大科学 catalog：

| 对象 | schema | 身份边界 |
|---|---|---|
| `FirmwareMmioStaticCatalog` | `firmware-mmio-static/v1` | ELF + semantic map + 显式有界指令分析及静态证据 |
| `RuntimeMmioObservationSet` | `firmware-mmio-runtime/v1` | 单个实际执行上下文、ELF、RTL、simulator、bus trace、成功事务 |
| `StaticRuntimeMmioBindingSet` | `firmware-mmio-binding/v1` | 两侧对象引用、候选事实集合、具体 observation、binding rule/version 与状态 |

P1 Reference/Variant 使用同一个 static catalog ID；N1 也在两侧共享另一个 ID。Runtime sets 因实际 RTL、executable 和 trace 身份不同而分别存在。静态 READ 事实没有 runtime read_value 字段。

模型使用架构字段、通用 read/write/address/value/status 和引用；ISA 解码集中在 `extract_rv32_mmio_static_facts` 函数边界。当前 v1 仅实现 RV32、32-bit LW/SW 和固定小程序的直线前缀，其他架构或指令 fail closed。没有引入 ARM/LoongArch 后端、插件框架或完整符号执行器。

### 静态侧

独立 `FirmwareArtifact` 含 file-bytes SHA、architecture、word size、endianness、entry 和 content ID。ELF 必须是 ELF32/little/RISC-V/ET_EXEC。入口开始显式限定 **12 条**指令；API 接受 1–256 的明确边界，任何不支持指令都会拒绝整个提取，不偷偷越过分支或推断可达性。

每个 PC 同时要求唯一、可执行、file-backed 的 ELF section 与 PT_LOAD 映射，且两种映射所得 bytes 一致。指令直接来自这些 bytes；不读取 symbol name、汇编源、objdump 文本或运行时日志来创建静态事实。

只支持 LUI、ADDI、LW、SW。初始只有 x0 确定为 0，其他寄存器未知；LUI 产生常量，ADDI 做有符号 12-bit immediate 加法并按 RV32 截断，LW 使目标寄存器值未知，SW 从当前有限已知状态取地址和值。每个 access 保存所依赖的指令 PC/encoding/mnemonic、源寄存器和 evidence IDs。地址或 store value 无法确定时保留 `unresolved`；read 的 value_status 固定 `not_applicable`。不支持未对齐静态访问，明确拒绝。

`StaticMmioAccessFact` 保存 fact ID、firmware ID/SHA、architecture、PC/encoding/width、operation、address_status/address、width_bits、value_status/value、scope_status/map_id、derivation/source_registers/provenance。三个目标事实进入 `static_facts`；已解析的非目标访问进入 `non_target_accesses`；无法确定地址的访问进入 `unresolved_accesses`，不丢弃。

### Map 语义与来源

目标窗口不是“看起来像 MMIO”的地址启发式。A adapter 从两侧真实 Verilator XML 重新提取四设备地址表和顶层参数，并核对已保存的 elaboration record、XML SHA、RTL tree manifest SHA 和实际源树 bytes。指定 `target_device= SyntheticPeripheral`，得出 `0x40000–0x403FF`。

`PlatformMap` 的科学身份只包含实际 decoded map、architecture、extraction version、规范化配置和显式选中的设备。它不含 XML 路径或整个 RTL 的 hash；Reference/Variant 的语义 map 完全相同：

`mmio-map:e702cd0222bbe54fd79f7f9f541bdf9c7448ddffa438e7eb4b1fb3b396ec5da9`

`PlatformMapEvidence` 是另一个来源对象，完整保存 XML/record/source-manifest artifacts、RTL tree SHA、evidence 和 provenance IDs。两侧 map evidence IDs 不同。静态目录引用 semantic map artifact；运行时 attestation 与独立 `map-source.json` 保留具体来源，没有为达成静态 ID 相等而删除 provenance。

### 运行时侧

`load_apparatus_run` 是只读 API，消费指定 manifest。调用者必须显式给出期望的 base tree、实际 RTL tree、firmware SHA。真实集成中这些 pin 来自冻结 A 基线，不从结果数值或文件名推断。

它重新验证 base/source 文件清单与每个实际文件，匹配唯一的 RTL tree，核对 ELF bytes、simulator executable bytes、输入、recipe、配置和 map 证据；随后读取 `manifest.json`、`trace-binding.json`、raw JSONL、`parsed-trace.json`、stdout/stderr，重算所有可核对的摘要。再次解析 raw trace，要求重新得到的完整 parsed 对象与保存版本一致，不能只相信 manifest 的布尔值。

模块内保留一个明确标为 A v1 的窄 reader，移植冻结 parser 的严格格式/事务/完整性规则；没有动态导入或修改 A runner。B1 另限定 footer cycle/event 数上限，避免恶意 footer 导致无界分配。它仍按 A 的 phase、sequence、epoch、request/response+1 cycle、status window、footer/stop 规则校验。进程日志的 hash、软件正常结束和 `$finish` 文本必须共同成立。没有重新执行模拟器；这是对冻结 producer artifacts 的重验，不是独立重放证明，也不是带签名的来源认证。

只有 accepted request + matching response、error=0 的事务才能形成成功 `RuntimeMmioObservation`；遇到 error、漏响应、截断、缺状态采样或错绑，整体拒绝物化，不输出成功观察或阴性结论。

每个 observation 保存 run_binding_id、transaction_id、request/response cycles、epoch、operation/address/width/be、独立 write_value/read_value、error/completion_status、raw/parsed artifact IDs、evidence 和 provenance。它不叫 ExecutedStaticFact，也没有 PC 字段。

## 身份算法与规范化

所有 content ID 使用 SHA-256，输入为 UTF-8、键排序、紧凑 JSON，`ensure_ascii=False`、禁止非有限数字、无末尾换行。序列化文件多出的末尾换行不计入 canonical-payload SHA。文件输入 SHA 则对原始文件 bytes 计算。解析/序列化会重算所有嵌套 content IDs；来源验证仍必须通过 materializer，而不是仅凭一个自洽的 JSON ID。

- `mmio-static:<sha>`：包括 schema、firmware SHA/ID、architecture、PC、encoding、operation/address/width/value 状态与值、derivation、map semantic ID 和静态证据引用。
- `fwmmio-static:<sha>`：整个静态语义目录，排除自身 ID/SHA。包括显式 instruction_count，未把运行时选择带入静态推导。
- `mmio-run:<sha>`：实际 firmware、RTL、simulator、software input、单运行执行配置、raw/parsed trace、semantic map。执行配置提取 target config、clock/reset、runtime options、tools；不使用 differential variant-patch specification。
- `mmio-runtime:<sha>`：run scientific binding + 实际 transaction/cycles/epoch/operation/address/width/values/completion + trace/evidence 引用。
- `fwmmio-runtime:<sha>`：run binding、ordered observations/runtime_sequence、trace sources/evidence、producer version。明确排除单独寻址的 `source_attestation`。
- `mmio-runtime-attestation:<sha>`：保留 upstream apparatus run ID、原始 manifest/binding/logs/recipe 的 artifacts 与具体 map source。A 的额外差分元数据、manifest 中的定位路径可以改变这个来源侧对象，不能改变 observation/set 的科学身份。
- `mmio-binding:<sha>`：两侧科学集合 IDs、候选静态 IDs、观察 ID、rule version、UNKNOWN/reason 与空 bridge evidence 列表。`fwmmio-binding:<sha>` 对这些绑定形成独立集合身份。

set-like 的 source artifacts、evidence、source/evidence IDs、candidate IDs、bridge evidence IDs 规范排序后计算身份；输入顺序颠倒不改变语义 ID。map entries/config 规范排序并拒绝重复。**不能排序掉的语义顺序**：derivation 指令、static_sequence、runtime_sequence、实际事务的 cycle/order、绑定列表的 runtime 遍历顺序。静态顺序与运行时顺序各自保存，不互相代替。

Host path、workspace 名、timestamp、run UUID、人类标签和 objdump prose 不直接进入科学事实 ID。复制同样的 bytes 到另一目录不改变结果。重新构建若改变 simulator 实际 bytes，则 runtime 身份可以改变，这是 executable identity 的变化，不是直接使用路径寻址。

## 为什么绑定仍为 UNKNOWN

冻结工作区包含真实 `trace_core_00000000.log`，确实有 PC、instruction bytes、cycle、PA、load/store value。我们逐份检查了四个 run，不是因“没找到文件”而跳过。

源码 `samples/hardware/ibex-simple-system/source/rtl/ibex_tracer.sv` 的 1126–1132 行将计数器在 reset 清零；1149–1167 行在 `rvfi_valid` 的 posedge 写退休记录。总线 monitor 则从启动计数、独立记录 reset_epoch，并以 request/response phase 识别事务。

| 访问点 | RVFI PC | RVFI cycle | bus request cycle | bus response cycle |
|---|---|---:|---:|---:|
| ENABLE | `0x100088` | 8 | 11 | 12 |
| COMMAND | `0x100090` | 11 | 14 | 15 |
| STATUS | `0x100094` | 13 | 16 | 17 |

上表是**人工诊断对照**，没有变成 binding rule。看到这组偏移并不足以为任意 input 证明退休阶段与某笔被接受事务的映射。更直接的缺口是：A manifest/trace-binding 没有 processor trace SHA，也没有共享 transaction ID 或经过审核的 cycle/epoch bridge。给同目录 RVFI 文件在 B1 新算一个 SHA，只能证明本轮读到的文件身份，不能补成 A 当时已经绑定的运行证据。

因此选择 `unbound-no-attested-pc-transaction-bridge/v1`。每个 runtime observation 保留所有目标或地址未解析的静态候选，不按唯一地址、相同值或第三行对应第三行选择一个 site。共有 **12 条 UNKNOWN 绑定**；即使只剩一个静态候选仍 UNKNOWN。该版本不提供 `bound`、`not_same` 或 `incompatible` 构造器，避免暗示跨层匹配结果。

已保存的 processor-trace diagnostic 文件只用于人工复核，明确标成 unattested，未进入静态推导或正向绑定证据。

## 本轮实际产物和身份

新预览工作区：`output/syn-e2e1-b1/preview-x2hq53at`。

`local-reproduction-manifest.json` 记录旧 workspace 定位、输入 manifest 相对路径、producer 文件 SHA、四组结果定位及身份；该 local manifest 不作为科学 ID。`static/` 仅保存两份静态目录，`runtime/` 分别保存四组 observations、bindings、map-source、中文报告和 processor-trace diagnostic。

| 固件 | ELF file-bytes SHA | Static catalog ID |
|---|---|---|
| P1 | `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641` | `fwmmio-static:049287cc59e8c8be32c4f1fcf61b5a125833e3a173509573a098af35cb2ba2fa` |
| N1 | `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920` | `fwmmio-static:bc5ba678b36283d55b518b36b9386500cd0a2c256768165167cf9e9f550a87de` |

| evaluation-only 引用 | Runtime set ID | Binding set ID |
|---|---|---|
| R-P1 / N2 | `fwmmio-runtime:b743198d722d88ba90e4c2e1c6282d9a933a35b53e432671ff8c23008c784215` | `fwmmio-binding:8cef4c3e1ad5945cda83c5a433e28e4ef75eff758d29cbed396b6cd28b0cddb6` |
| V-P1 | `fwmmio-runtime:e4f68d69584b0c96e0032082c451296cd9fdedccc615409b0380d01c25d52804` | `fwmmio-binding:46d73acfb4fb62e25d362786ad30f1f7c4a762384a03a29ee83a23723d3a2597` |
| R-N1 | `fwmmio-runtime:51c99e0a749e69cbbde0fcf129d9ce78b040a5a7bbe07dc0f02c94337c7855db` | `fwmmio-binding:2b7d8c047d9ecbe10c34a392c5574e13054f6cce65a6fd4c48fed3e5e3d3d7c7` |
| V-N1 | `fwmmio-runtime:6df64e9fa79c8ece009d84083f77d1cde8f4a7836ec20bc1fd1cf145b8fd5726` | `fwmmio-binding:f48d0c23ede21983b0b6a7d507ce818c7b12eac09d04e2961624a9d491ff63b0` |

输入仍为 `output/syn-e2e1-a/experiment-tn2kt3tu/`。base tree 为 `030425ba50863f72ccf05051d35c198811d5248be1f79c3ce5d430968a315c5d`；两侧 RTL tree 分别为 `f882b80ccd16c9de7828b399196f079ee3b982e43fc54784c3f6e015430f4e1b` 与 `805480e150a838026c0b47dfe375a0548064381a4b175d79f9ea6bf02089b440`。已重算实际 tree/ELF/trace 等身份，没有创建替代 A run。

## 复现与验证

真实 artifact 集成没有 opt-in 仿真开关，因为它只读本地文件，不启动任何工具。若冻结 A workspace 缺失，测试明确 skip/BLOCKED local dependency；不能据此宣称验收通过。本轮文件存在，四个 run 的全部集成检查实际运行通过。

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q \
  tests/unit/test_firmware_mmio_grounding.py \
  tests/integration/test_syn_e2e1_b1_mmio_grounding.py \
  tests/integration/test_syn_e2e1_apparatus.py
# 82 passed, 1 skipped in 4.05s

CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
# 1440 passed, 28 skipped in 35.31s

.venv/bin/python -m pip check
# No broken requirements found.
.venv/bin/python -m compileall -q src tests
# exit 0
git diff --check
# exit 0
```

第一条命令包括：47 个新 unit cases、7 个新真实 artifact/replay 集成 cases、28 个原 A fast cases。唯一 skip 是 A 的显式真实 simulator 重建测试；本阶段没有必要再跑 Verilator，**不是 B1 的真实输入被跳过**。

集成新增了本地 real XL2 regression：重新 parse CAP0/XL1，compare + replay，序列化逐字节等于冻结结果，仍为 `xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded` / overall `unknown`。

API 本身没有隐式写文件。调用者使用 `load_apparatus_run(...)` 得到 `(static, runtime, bindings, map_source)`，可调用 `serialize(...)` 与 `render_report(...)`；只有调用者显式 `write_text` 才会持久化。本轮预览由显式调用生成，没有改 A 的原始产物。

## 80 项验收答复

| # | 核对项 | 回答 |
|---:|---|---|
| 1 | 起始 HEAD/tag | main；`b3163b947bb1efc1c4a1345269df47b980175724`；`v3-syn-e2e1-a-apparatus-stable`。 |
| 2 | 新增/修改 | 仅上文 4 个新文件；原有文件无修改。 |
| 3 | SYN-E2E1-A | 七个 tracked 文件与原 output 均未改。 |
| 4 | CAP0 | 未修改。 |
| 5 | XL1/XL2 | 未修改，只重放既有真实 UNKNOWN。 |
| 6 | schema | `firmware-mmio-static/v1`、`firmware-mmio-runtime/v1`、`firmware-mmio-binding/v1`；来源/map/run 有模块内独立辅助 schema/ID。 |
| 7 | 为何分开 | 静态由 ELF/map 决定；运行时与具体 RTL/run 绑定；是否对应是第三个独立结论。 |
| 8 | Static fields | PC/encoding/width、operation、address/value status/value、firmware/architecture/map IDs、scope、derivation、source registers、provenance refs。 |
| 9 | Runtime fields | run binding、事务/cycles/epoch、operation/address/width/be、write/read value、error/completion、raw/parsed artifact refs、provenance。 |
| 10 | Binding fields/status | 集合 refs、全部候选 static IDs、单个 observation ID、rule version、bridge refs、reason；本版只输出 unknown。 |
| 11 | static ID | `mmio-static:` + canonical semantic payload SHA；含 ELF、PC、bytes、地址/值状态、derivation/map。 |
| 12 | runtime ID | `mmio-runtime:` + actual scientific run binding、trace 和具体事务 payload SHA。 |
| 13 | binding ID | `mmio-binding:` + 集合/候选/观察 refs、规则版本与 UNKNOWN payload SHA。 |
| 14 | set-like | source artifacts、evidence 与其 refs、candidate/bridge IDs；规范排序。map/config 也有规范顺序及去重约束。 |
| 15 | 保留顺序 | 指令 derivation、static_sequence、runtime_sequence、事务 cycle、绑定的 runtime 遍历顺序。 |
| 16 | path/time/UUID | 不直接影响科学 ID；local manifest 保存路径；来源 attestation 的原始 artifact hash可反映定位元数据变化，语义观察 ID不受其污染。 |
| 17 | firmware identity | ELF bytes SHA + architecture/endianness/word size/entry，content ID，不使用文件名。 |
| 18 | map semantic ID | decoded address map + extraction version + config + architecture/target device；见上文完整 ID。 |
| 19 | map provenance | 独立 PlatformMapEvidence，保留 XML/record/RTL manifest SHA、RTL tree、evidence 与 provenance refs。 |
| 20 | map 两侧相同 | 是，两个固件四个 run 的 map semantic ID 全同。 |
| 21 | provenance 两侧不同 | 是，RTL/XML 来源和 map evidence ID 不同。 |
| 22 | RV32 instructions | 仅 LUI/ADDI/LW/SW；没有增加 AUIPC 或全 ISA evaluator。 |
| 23 | ELF bytes | 是，直接从唯一 section/PT_LOAD 映射解码并核对 bytes。 |
| 24 | source/objdump authority | 否，API 不接收这些文本来创建静态事实。 |
| 25 | 常量传播 | x0=0；其他初态未知；LUI常量、ADDI符号扩展+RV32截断、LW杀死结果常量、SW读取有限状态。 |
| 26 | unresolved | 独立 status 与 null；未知地址访问另存 unresolved_accesses，未知写值不丢失。 |
| 27 | runtime 补 static | 不允许，专门测试同 ELF 上 runtime= A5 时静态未知仍未知。 |
| 28 | P1 ELF SHA | `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641`。 |
| 29 | N1 ELF SHA | `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920`。 |
| 30 | P1 static facts | 0x100088 WRITE 0x40000=1；0x100090 WRITE 0x40004=A5；0x100094 READ 0x40008，value=N/A。 |
| 31 | N1 static facts | 同三个 PC/operation/address，COMMAND= A4；其余不变。 |
| 32 | P1 static ID | `fwmmio-static:049287cc59e8c8be32c4f1fcf61b5a125833e3a173509573a098af35cb2ba2fa`。 |
| 33 | P1 两侧共享 ID | 是，序列化完整 static catalogs 也完全相同。 |
| 34 | N1 static ID | `fwmmio-static:bc5ba678b36283d55b518b36b9386500cd0a2c256768165167cf9e9f550a87de`。 |
| 35 | runtime 输入 | 指定冻结 A workspace 的四个原 manifest/raw/parsed/binding/logs，加实际 ELF/RTL/simulator/map/input/recipe。 |
| 36 | 重验 A binding | 是，run ID/hash、ELF/RTL/raw/parsed、完整性、退出证据等重算。 |
| 37 | R-P1 runtime | 三笔成功事务；ENABLE=1、COMMAND=A5、STATUS read=0。 |
| 38 | V-P1 runtime | 三笔成功事务；ENABLE=1、COMMAND=A5、STATUS read=DEAD。 |
| 39 | R-N1 runtime | 三笔成功事务；ENABLE=1、COMMAND=A4、STATUS read=0。 |
| 40 | V-N1 runtime | 三笔成功事务；ENABLE=1、COMMAND=A4、STATUS read=0。 |
| 41 | static READ 相同 | 是，同一个 P1 ELF 的 READ fact ID 两侧相同；没有填入 runtime read value。 |
| 42 | runtime STATUS values | 0、DEAD、0、0，仅陈述观测值。 |
| 43 | 称为 deviation？ | 否，runtime schema/报告仅称 observed value；不比较硬件契约。 |
| 44 | PC↔bus bridge | 未建立足够来源绑定的直接 bridge。 |
| 45 | bridge evidence | 只有未由 A manifest hash-attest 的 RVFI diagnostic；无共享 transaction ID、无审核过的 cycle/epoch bridge rule。 |
| 46 | 无 bridge 结果 | 12 条全部 UNKNOWN，bridge evidence refs为空。 |
| 47 | 唯一性猜测 | 没有；单一候选也 UNKNOWN，不按地址/数值/行序配对。 |
| 48 | static order | static_sequence按显式直线 prefix PC顺序，完整含非目标访问。 |
| 49 | runtime order | runtime_sequence来自实际 accepted request cycles/transaction IDs。 |
| 50 | 两种 order 混用 | 没有。 |
| 51 | error transaction | 拒绝整个 runtime materialization，不产生 completed-success observation。 |
| 52 | incomplete trace | 拒绝；不当 negative，也不猜完整窗口。 |
| 53 | wrong firmware | loader、runtime binding 与 join 各自校验；不一致拒绝。 |
| 54 | wrong RTL | 实际源树/manifest/map/runtime binding 交叉核对，不一致拒绝。 |
| 55 | map mismatch | XML/record 不一致拒绝；static/runtime semantic map ID不一致拒绝绑定。 |
| 56 | raw/parsed mismatch | 从raw重解析，canonical parsed必须一致且hash一致，否则拒绝。 |
| 57 | LLM calls | 0。 |
| 58 | Agent | 未使用，也没有创建新的 agent workflow。 |
| 59 | FirmwareCapability | 未创建。 |
| 60 | XL2 新 positive | 未产生，仅重放旧 UNKNOWN。 |
| 61 | Trigger satisfaction | 未创建。 |
| 62 | Deviation verification | 未创建。 |
| 63 | attack chain | 未创建。 |
| 64 | unit tests | 47 个新增 cases，涵盖 ELF/map、有限常量传播、tamper、runtime完整性/错绑、静态隔离、ID/order和UNKNOWN。 |
| 65 | real integration | 7 个新增集成 cases实际通过，包括四个真实run、两侧身份比较、RVFI边界和真实XL2 replay；在82 passed/1 skipped命令中执行，B1无skip。 |
| 66 | full pytest | **1440 passed, 28 skipped in 35.31s**。 |
| 67 | pip check | `No broken requirements found.`，exit 0。 |
| 68 | compileall | `.venv/bin/python -m compileall -q src tests`，exit 0。 |
| 69 | diff check | `git diff --check`，exit 0；新文件另查行末空白。 |
| 70 | A regression | 原28 fast cases通过；A真实重建测试按默认策略skip，未修改A、未重跑仿真。 |
| 71 | XL2 UNKNOWN | `xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded` / unknown，序列化与冻结输出完全相同。 |
| 72 | 历史保护 | 292 个原 tracked 文件、62180 个原有 samples/output 文件逐一 SHA-256 不变；main/HEAD/所有 tags 不变。仅四个新增未暂存文件。 |
| 73 | 现在支持 | 可重算的有界静态 MMIO access facts、独立的来源绑定成功总线 observations、保守的UNKNOWN对应关系和可读报告。 |
| 74 | 仍不支持 | 通用symbolic execution、PC↔bus正向绑定、FirmwareCapability、硬件触发满足、偏差验证或完整跨层链。 |
| 75 | 建议进入 B2？ | 建议先审核B1，再设计B2的最小静态事实适配；不能把当前UNKNOWN当执行证明。 |
| 76 | B2 最小 proposal | 只把resolved static access映射成明确static-only、已来源绑定的能力陈述；runtime observations独立引用，不提升到site执行。若B2要求site执行，先另立bridge attestation/instrumentation阶段。 |
| 77 | CAP0 SourceKind proposal | 仅建议审议新增firmware_mmio_static来源；是否容纳runtime应单独设计，不能复用A6退休来源冒充MMIO执行。本轮未修改enum。 |
| 78 | runtime evidence type proposal | 建议独立MMIO completed-transaction evidence与未来可审计PC/epoch/transaction bridge evidence，保留run/ELF/RTL/trace identities；未接入CAP0。 |
| 79 | pruning gate | 未解锁；还没有完整P1/N1/N2/U1跨层golden regression及全部R2-B条件。新增真实XL2回归只补强其中一项。 |
| 80 | 停止线 | 停止在B1；未执行B2、pruning、git add/commit/push/tag。 |
