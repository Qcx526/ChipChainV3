# V3-2A3 — Bounded Relevant Static-Structure Projection

## A. Implementation Summary

基线：`v3-2a2-stable`，commit `9d7f82ddf6fc79be7c03a6341bb6df5b9af94df6`。
新增独立 deterministic tool result `FirmwareRelevantStaticStructure`，版本
`firmware-relevant-static-structure/v1`。从 canonical A1/A2 构造完整相关子图，
使用可逆的 named-column tables 和证据模板去重满足 18,000 字符上限。

没有调用 Firmware Agent、DeepSeek 或其他模型，没有新增 ProcessorBehavior、reachability、path、finding、
issue anchor 或 FirmwareAnalysisReport。没有进入 B2、修改 prompt/projection v1、运行 angr 或 reviewed-export。

## B. Files Changed

- `src/chipchain/tools/firmware/structure_projection.py`：typed projection、选择、验证、codec、hash。
- `tests/structure_projection_fakes.py`：纯 synthetic A1/A2 graph fixture。
- `tests/unit/test_relevant_static_structure.py`：30 个默认离线测试。
- `tests/integration/test_relevant_static_structure_local.py`：显式真实 A1→新 A2→两次 A3。
- root `README.md` 和本文。

未修改 A1/A2 canonical 合同、analyzer、ARM decoder、Ghidra script/backend、domain、IR、Agent、
prompt、projection v1、依赖或历史输出。A2 association 由既有 `associate_mmio` 重新确定性派生，未改逻辑。

## C. A3 Architecture

```text
FirmwareAgentInput（只作为既有输入合同，不调用 Agent）
+ fresh GhidraStaticStructureResult
+ CortexMVectorResult
    ↓ case/ELF identity & exact evidence checks
A2 MMIO associations
    ↓ fixed seed union + confirmed one-hop selection
FirmwareRelevantStaticStructure（typed records / exact EvidenceRefs）
    ↓ reversible named-column JSON
<= 18,000 characters
```

公开入口：`build_relevant_static_structure(inputs, structure, vectors)`、
`serialize_relevant_static_structure(result)`、`parse_relevant_static_structure(text)`、
`relevant_structure_sha256(result)`。构建和 codec 均无 IO，不自动写文件。

不是把整个 A2 graph 附加到 `firmware_context`，也没有修改已有 128-item/64k 限制。

## D. Seed Policy

v1 seed union = A2 `unique` MMIO-containing functions ∪ bounded vectors 中
`function_entry` 的 distinct handler functions。按 entry/function ID 稳定排序。
每个 seed 保留 `mmio_site` / `vector_handler` reasons，可同时拥有两者。
不以名字、LLM 判断、unresolved targets 或运行猜测选 seed。

## E. MMIO Seeds

真实 **10** 个：

- `PIO_GetOutputDataStatus @ 0x80e14` (`f80e14`)。
- `pmc_enable_periph_clk @ 0x80e28` (`f80e28`)。
- `pmc_disable_periph_clk @ 0x80e6c` (`f80e6c`)。
- `SystemInit @ 0x80eac` (`f80eac`)。
- `adc_init @ 0x80fac` (`f80fac`)。
- `adc_configure_trigger @ 0x81044` (`f81044`)。
- `adc_configure_timing @ 0x81052` (`f81052`)。
- `pinMode @ 0x81234` (`f81234`)。
- `write @ 0x81478` (`f81478`)。
- `IrqHandler @ 0x815a4` (`f815a4`)。

## F. Vector Seeds

真实 **14** 个 distinct function-entry handler seeds；51 个非空 entries 指向它们。
这些是静态 dispatch 相关性，不表示 handler 执行或 IRQ 发生。

- `UART_Handler @ 0x80abc` (`f80abc`)。
- `USART0_Handler @ 0x80ad0` (`f80ad0`)。
- `USART1_Handler @ 0x80adc` (`f80adc`)。
- `USART3_Handler @ 0x80ae8` (`f80ae8`)。
- `Reset_Handler @ 0x80f34` (`f80f34`)。
- `UOTGHS_Handler @ 0x81084` (`f81084`)。
- `PIOA_Handler @ 0x81094` (`f81094`)。
- `PIOB_Handler @ 0x810cc` (`f810cc`)。
- `PIOC_Handler @ 0x81104` (`f81104`)。
- `PIOD_Handler @ 0x8113c` (`f8113c`)。
- `SPI0_Handler @ 0x81174` (`f81174`)。
- `SVC_Handler @ 0x81176` (`f81176`)。
- `PendSV_Handler @ 0x8117a` (`f8117a`)。
- `SysTick_Handler @ 0x8117e` (`f8117e`)。

## G. Seed Overlap

两个 seed class 的交集为空：**0 overlap，24 distinct seeds**。
`UART_Handler` 与含 MMIO 的 `IrqHandler` 是不同函数，不因名称关联而合并 identity。

## H. One-Hop Call Policy

选取 canonical `direct_call_edges` 中所有 `caller ∈ seeds OR callee ∈ seeds` 的边。
不丢 first-N/top-k，不递归处理 newly selected neighbors。每条选中边都触及 seed。
不使用 computed call、unconfirmed target 或 tail-branch disagreement 作为 confirmed edge。

## I. Neighbor Functions

**10** 个 distinct non-seed one-hop neighbors，总 function catalog **34** 个。
所有邻居都由 selected confirmed edge 的 endpoint 引入，没有 two-hop-only function。

- `begin @ 0x80148` (`f80148`)。
- `setup @ 0x804a4` (`f804a4`)。
- `init @ 0x80af4` (`f80af4`)。
- `PIO_Configure @ 0x80db0` (`f80db0`)。
- `adc_disable_channel @ 0x8106c` (`f8106c`)。
- `sysTickHook @ 0x81194` (`f81194`)。
- `digitalWrite @ 0x8133c` (`f8133c`)。
- `tickReset @ 0x813ac` (`f813ac`)。
- `store_char @ 0x813e6` (`f813e6`)。
- `init @ 0x8152c` (`f8152c`)。

## J. Relevant Confirmed Calls

**22** 条，全部满足固定一跳条件。record 保留 edge ID、callsite PC、caller/callee function ID 和 evidence IDs，
不重复函数名字。仅表示直接静态边，不构造传递闭包或 `A reaches C`。

各 seed 的 incoming/outgoing 数量如下；单位是 callsite edges，非去重函数个数。

| Seed function | Incoming confirmed | Outgoing confirmed | Unresolved outgoing |
|---|---:|---:|---:|
| `UART_Handler @ 0x80abc` | 0 | 0 | 1 |
| `USART0_Handler @ 0x80ad0` | 0 | 0 | 1 |
| `USART1_Handler @ 0x80adc` | 0 | 0 | 1 |
| `USART3_Handler @ 0x80ae8` | 0 | 0 | 1 |
| `PIO_GetOutputDataStatus @ 0x80e14` | 1 | 0 | 0 |
| `pmc_enable_periph_clk @ 0x80e28` | 4 | 0 | 0 |
| `pmc_disable_periph_clk @ 0x80e6c` | 0 | 0 | 0 |
| `SystemInit @ 0x80eac` | 1 | 0 | 0 |
| `Reset_Handler @ 0x80f34` | 0 | 0 | 1 |
| `adc_init @ 0x80fac` | 1 | 0 | 0 |
| `adc_configure_trigger @ 0x81044` | 1 | 0 | 0 |
| `adc_configure_timing @ 0x81052` | 1 | 0 | 0 |
| `UOTGHS_Handler @ 0x81084` | 0 | 0 | 1 |
| `PIOA_Handler @ 0x81094` | 0 | 0 | 1 |
| `PIOB_Handler @ 0x810cc` | 0 | 0 | 1 |
| `PIOC_Handler @ 0x81104` | 0 | 0 | 1 |
| `PIOD_Handler @ 0x8113c` | 0 | 0 | 1 |
| `SPI0_Handler @ 0x81174` | 0 | 0 | 0 |
| `SVC_Handler @ 0x81176` | 0 | 0 | 0 |
| `PendSV_Handler @ 0x8117a` | 0 | 0 | 0 |
| `SysTick_Handler @ 0x8117e` | 0 | 2 | 1 |
| `pinMode @ 0x81234` | 6 | 6 | 1 |
| `write @ 0x81478` | 0 | 0 | 0 |
| `IrqHandler @ 0x815a4` | 0 | 1 | 0 |

## K. Relevant Unresolved Calls

v1 **仅选择 caller_function_id ∈ seeds**，共 **12** 条。
不选仅 target 指向 seed 的条目；这是明确冻结的最小必要规则，不是遗漏或可变 heuristic。
selected unresolved 的 known target 不引入函数目录，不变成 confirmed call edge。
记录原 callsite、caller、target（可空）、reason 和 exact evidence IDs。

- `0x80abe`：caller `f80abc`，target `0x815a4`，`decoder_disagreement`。
- `0x80ad2`：caller `f80ad0`，target `0x815a4`，`decoder_disagreement`。
- `0x80ade`：caller `f80adc`，target `0x815a4`，`decoder_disagreement`。
- `0x80aea`：caller `f80ae8`，target `0x815a4`，`decoder_disagreement`。
- `0x80f88`：caller `f80f34`，target `0x816cc`，`computed_or_ambiguous`。
- `0x8108c`：caller `f81084`，target `null`，`computed_or_ambiguous`。
- `0x810b2`：caller `f81094`，target `null`，`computed_or_ambiguous`。
- `0x810ea`：caller `f810cc`，target `null`，`computed_or_ambiguous`。
- `0x81122`：caller `f81104`，target `null`，`computed_or_ambiguous`。
- `0x8115a`：caller `f8113c`，target `null`，`computed_or_ambiguous`。
- `0x8118e`：caller `f8117e`，target `0x81728`，`decoder_disagreement`。
- `0x81328`：caller `f81234`，target `0x80e6c`，`decoder_disagreement`。

## L. MMIO Site Projection

完整 **23/23 unique PC records**，聚合 32 个 MMIO behavior IDs。
每个 record 含 PC、static observation ID、A1 mnemonic/direction、function ID（可空）、
containment status、behavior IDs、evidence IDs。不复制 MMIO model parameters/address/access size。

direction 只读取 A1 MMIO behavior attributes；同 PC 有不同 direction 则显式失败，不选赢家。
mnemonic 来自 A1 decoded instruction，不重新解码、不根据 Ghidra修改。

`0x80d4e, 0x80d50, 0x80d5a` 保持 `function_id=null, containment_status=missing`。
其余 20 个 unique；没有 ambiguous。不从 A1 symbol size 猜 Ghidra body containment。

## M. Function Projection

每条仅保留 function ID、entry、name、source type、seed reasons、seed/one-hop-neighbor role。
不复制 full ranges、body size 或全部 symbols；有意义的 handler aliases 在 vector group 统一保留。
函数名（包括 `write`、`IrqHandler`、`UART_Handler` 和共享 default handler 的名字）仅为 static label。

## N. Vector Handler Grouping

按 canonical handler address/function/binding status 分组，得到 **14 groups**。
每组保留全部 vector indices、core exception labels、external IRQ numbers、symbol aliases、evidence IDs。
可从 groups 精确恢复全部 **51 个非空 vector index → handler address**。
9 个 null indices 单独汇总；initial SP 不提升为 handler。

`0x81174` 组含 38 个 vector indices，`shared_handler=true`，保留包括 `ADC_Handler` 在内的全部 aliases。
Ghidra primary label `SPI0_Handler` 也只是同地址的标签，不能把整个组分类为 ADC 或 SPI。
不生成 peripheral、physical_interface、input_source 字段。

## O. Evidence Catalog / Lossless Compact Wire Format

A3 共 **172 个 unique exact EvidenceRefs**：55 个复用的 A1 static/MMIO refs，
32 个 A2 containment refs、22 个 confirmed call refs、12 个 unresolved call refs、51 个 vector refs。
只收录 projected facts 实际引用的 evidence；没有 orphan catalog entries。
每个对象在 typed catalog 中只出现一次。

直接 JSON object 序列化初步为 67,286 字符；仅去除空白不够。
最终 wire `named-column-tables/v1` 使用可逆去重，不删除事实，也不压缩/改写 summary 文本：

1. record lists 保存为 `{columns, rows}`；字段名只写一次。
2. 同表所有行相同的字段进入 `common`；重复 column values 在确实减少字符时进入具名 `dictionaries`。
   行中的该列整数是表内 dictionary index，原字符串/数组仍原样保留在 dictionary。
3. EvidenceRef 的 source/artifact/analyzer/summary/epistemic 字段组成 exact profiles，重复 profile 只保存一次。
   每条 evidence entry 仍保留原 evidence ID、profile reference 和 location 字段。
4. location 采用 `location.address` 等具名列。统一为 null 的 optional location 字段由既有
   EvidenceRef 默认值还原；非 null 字段全部保存，不丢 address/function/register/time/bit range 等值。
5. `parse_relevant_static_structure` 还原 typed objects，并检查 exact canonical reserialization。
   真实测试逐对象比较所有 restored EvidenceRefs，所有字段与 canonical 原对象相等。

这不是新的 evidence ID 命名空间，不用缩写替换 evidence 内容，也不需要 base64、gzip 或执行模板表达式。
文件可由具名 columns/dictionaries 解读；未来接模型需 B2 明确支持此表示，不能直接当成旧 object-array schema。

## P. Evidence Collision Checks

先调用 `collect_firmware_evidence(inputs)` 建立 A1 registry；检查 A2 calls、unresolved、vectors、
associations 的全部 refs（含未选中项）。same ID / different object 失败；相同对象可去重。
同时校验 artifact ID、A1/A2 case 和 ELF fingerprint。最终 catalog 与实际引用 ID 集合必须完全一致。

## Q. Structured Unresolved Constraints

- Static calls 不建立 runtime execution。
- Vector bindings 不建立 IRQ occurrence。
- Function/symbol names 不建立 physical-interface semantics。
- Opaque input 尚无确定性关系连接到任何 function/MMIO/vector/handler。
- Fuzzware interrupt-trigger configuration 尚无确定性关系连接到具体 vector 或 handler execution。
- 上述三个 missing PCs 尚无 Ghidra body containment。

使用 `not_established`、`missing_relation`、`missing_containment` 状态。
表达的是未建立关系，不能被解释成 unreachable/impossible/never-executes 的 negative proof。

## R. Determinism / SHA256

functions 按 entry/ID，MMIO 按 PC，calls/unresolved 按 callsite，vector groups 按 handler address，
evidence 按 evidence ID；内部 reasons、aliases、indices、IDs 也排序。
同一新生成 A2 result 构建 A3 两次，serialized JSON 和 SHA256 完全相同。
synthetic 测试还打乱 A1/A2 输入集合次序，验证输出不变。

source provenance 保留 A2 schema/tool descriptor，以及全量 structure/vector 的 identity hashes。
source hash policy 明确为 `recursively-sorted-source-collections/v1`；它不是 A2 原始 `semantic_json`
的字节哈希，不宣称两者相等。A3 SHA 则严格针对实际 compact JSON 的 UTF-8 bytes：

```text
4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304
```

## S. Size Budget

| 项目 | Characters |
|---|---:|
| A1.1 context（未修改） | 39,438 |
| A3 actual compact JSON | **16,631** |
| 简单相加 | **56,069** |
| 相对 64,000 的余量 | **7,931** |
| A3 自身硬上限 | 18,000 |

满足硬上限，略高于建议的 12k–16k 目标。没有抬高限制或截断事实。
构建和序列化在超限时都失败，不返回部分成功。上述简单相加不含未来 B2 envelope/prompt 等额外开销。

## T. SystemInit Audit

`SystemInit @ 0x80eac` 的 8 个 projected PCs：
`0x80eba,0x80eca,0x80ed2,0x80eda,0x80ee6,0x80ef2,0x80efe,0x80f0a`。
全部 **mnemonic=ldr, direction=read**。A3 不复制 R1 prose 中的 write 错误，不生成 configuration-write 语义。

## U. UART / IRQ Semantic Boundaries

`write @ 0x81478` 只是函数名，没有 inbound/outbound/interface classification。
`UART_Handler @ 0x80abc` 为 vector seed；其 A2 `b.w` disagreement 继续在 unresolved 中，
不升级为 confirmed call。不把 configured interrupt 与该 handler 相连。
共享 default handler group 的 ADC/SPI 等 aliases 不建立物理外围设备输入事实。

## V. Synthetic Tests

30 tests 覆盖 seed union/双 reason/两类去重、caller/callee 一跳、排除 two-hop、
confirmed-only、完整 caller-seed unresolved、排除 target-only/unrelated unresolved、
23 synthetic PCs 完整性、missing 保留、A1 read/write/unknown 与冲突失败、
符号语义界限、共享 aliases、external indices/null summary、约束状态、
exact evidence catalog/codec roundtrip、A1/A2 collision（含未选择项）、
顺序扰动/输入不变、稳定 hash、size failure 无截断、输入身份/向量冲突、wire corruption。

默认测试继续 offline，不需要 Ghidra；没有新增依赖。

## W. Real Heat_Press Integration

```bash
CHIPCHAIN_GHIDRA_HOME=/home/qcx/fuzz/gdbfuzz/dependencies/ghidra \
CHIPCHAIN_FUZZWARE_ROOT=/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
.venv/bin/python -m pytest -q -s tests/integration/test_relevant_static_structure_local.py
```

两个变量缺一即 skip；显式无效路径 fail。没有读取 `.env`、API key 或调用 Agent。
测试从既定四个 artifact 构建 A1，从显式 ELF 运行一次本机 Ghidra 10.1.4，生成新 A2，
再构建 A3 两次。测试不依赖用户保存的 output JSON。

A2 仍为 183 functions、238 confirmed calls、68 unresolved；20 unique MMIO PCs、3 missing、0 ambiguous；
向量范围 `[0x80000,0x800f4)`，61 words、51 non-null dispatches、14 distinct handlers。
A1 仍为 57 observations、55 behaviors、57 evidence、0 runtime；既有投影为 39,438 字符，hash：
`48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803`。

四个 corpus fingerprint 前后不变，A1/A2/association 原对象 JSON 不变，temporary Ghidra project 已清理。
测试审计输出只用于验证；本轮另由调用方显式复制到 ignored output，测试不依赖持久化副本。

本轮输出目录：`output/fuzzware:heat-press:scenario-13/1e40645e-ef10-4da6-ade5-46a40bd521f8/`，含 `relevant_static_structure.json` 和 `metrics.json`。

## X. Exact Test Results

```text
pytest -q
593 passed, 9 skipped in 8.53s

explicit real A3 integration
1 passed in 10.89s

python -m pip check
No broken requirements found.

python -m compileall -q src tests
exit 0

git diff --check
exit 0
```

## Y. Recommended B2 Merge Policy

B2 应另建显式版本的 projection/codec 合同，选择 A3 已确定的完整集合：
34 functions（24 seeds + 10 neighbors）、23 MMIO sites、22 confirmed calls、12 unresolved calls、
14 vector groups（覆盖全部 51 indices），以及 exact evidence、seed neighborhoods 和 unresolved constraints。
不能把 unresolved edges、handler labels 或一跳邻居升级成 reachability/interface/input claims。
复用 A1 的 MMIO parameters，按 exact ID/object 合并 evidence，不能静默改写或截断。

**字符预算可行不代表可直接接入现有 v1**：A3 catalog 为 172；与 A1 57 条去重后为 **174**，
超过当前 v1 的 128-item evidence catalog 上限。B2 需要明确设计独立 static catalog/引用边界、
codec 和项目数校验，并预算最终 message 的真实长度；不能直接把 catalog 塞进 v1 或暗中提高限制。
本轮只记录这个实际集成约束，没有改变任何既有 limit、schema 或 prompt。

## Z. Git Status / Preservation

仅 root README 修改，本文、新工具模块和三个测试文件未跟踪。
历史 R1 human-rejected run、两个 rejected pilots、reviewed/v3-1b1，以及 A2 已保存输出逐字节不变。
本轮对 66 个受保护的既有源码/历史输出文件完成逐项 SHA256 对照，全部相同。
未执行 git add/commit/push/tag，未 reviewed-export。停止在 A3，不进入 B2。

## Final 30 Questions

1. MMIO seeds：**10**。
2. Vector-handler seeds：**14**。
3. Overlap：**0**。
4. Distinct seeds：**24**。
5. One-hop neighbors：**10**。
6. Total functions：**34**。
7. Selected confirmed edges：**22**。
8. 每条 selected edge 都触及 seed：**是**。
9. Two-hop-only function：**没有**。
10. Relevant unresolved calls：**12**。
11. 23 sites 全部表示：**是**。
12. 三个 missing sites 保持 missing：**是**。
13. 全部非空 vector indices 可恢复：**是，51 个**。
14. Handler groups：**14**。
15. 符号名是否产生物理接口事实：**否**。
16. 是否建立 trigger-config→handler：**否，仍为 missing relation**。
17. SystemInit 八站点仍 ldr/read：**是**。
18. 新 ProcessorBehavior：**0**。
19. 新 reachability/path/finding：**0**。
20. Exact unique EvidenceRefs：**172**。
21. Serialized chars：**16,631**。
22. SHA256：`4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304`。
23. ≤18,000：**是**。
24. A1.1+A3：**56,069** 字符。
25. 64k headroom：**7,931** 字符，未计未来 envelope 开销。
26. Projection v1 未改：**是，原长度/hash 相同**。
27. Prompt v1 未改：**是**。
28. DeepSeek 是否调用：**否**。
29. 历史输出改变/reviewed-export：**没有**。
30. B2 应使用上述完整 bounded subset，保留 exact IDs、未决项及约束；先处理独立 catalog/codec 和 128-item 兼容性，详见 Y。
