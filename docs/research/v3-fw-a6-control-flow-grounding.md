# V3-FW-A6：确定性目标地址与函数归属

A6 将模型曾经算错的目标地址和函数归属转为独立、可重复的静态事实。
不修改 Hardware A3/B2、ARM A4/A5、XL0、Cross-Layer Agent 或配对基线。

## 两个真实失败与正确事实

历史 run `d362bd15-c924-46af-bcae-12aa960afa50` 中：

- `fw-f-002` / `fw-a-001` 把 PC `0x100080`、指令字 `0x2c60006f`
  解释为跳向 `0x1002c6`，并进一步归入 timer handler。JAL 的有符号偏移是
  `0x2c6`，正确目标为 `0x100080 + 0x2c6 = 0x100346`。
- `fw-f-004` 把 `0x1000a0` 归入 puthex。ELF 显示 puts 的范围为
  `[0x100090, 0x1000a4)`，puthex 从 `0x1000a4` 开始，因此该位置属于 puts。

历史模型报告、中文报告与 provider 元数据均保持原样。
测试仅保存最小数字、编码与区间 fixture，不提交真实 ELF 或 provider response body。

## 合同与算法

`firmware-control-flow-grounding/v1` 包含 `ControlTransferFact`、
`FunctionOwnershipFact`、源 artifact SHA/大小、EvidenceRef、函数区间、能力和限制。
个体 fact 和 catalog 均可 canonical serialize；集合按稳定身份排序，JSON key 排序，
身份不使用 UUID、当前时间或机器路径。

ControlTransferFact 保存 PC、地址顺序的编码字节、宽度、助记符与操作数字段、transfer kind、
resolution status、target/fallthrough、decoder/version、来源与 provenance。

RV32 I+C 适配器从编码位域重建并符号扩展 J/B/CJ/CB 偏移，再加 **当前指令 PC**，
按 RV32 地址宽度取模。Capstone 只提供显示解码，不把其操作数字符串当成绝对目标。
支持 JAL、六种 B-type 条件分支、C.J/C.JAL、C.BEQZ/C.BNEZ；
JAL/C.JAL 以 ABI 链接寄存器 x1/x5 判断 call 类别。
条件分支另记 `pc + instruction_width` 的 fallthrough；这不表示条件是否成立。
JALR、C.JR/C.JALR 和特权返回不提供运行时目标。普通非控制指令作为 unsupported 记录，
不会被误称为已解析的控制转移。保留 invalid/unsupported/indirect/ambiguous 的区别。

语义参考：[RISC-V RV32I](https://docs.riscv.org/reference/isa/v20240411/unpriv/rv32.html)
与 [C 扩展](https://docs.riscv.org/reference/isa/v20260120/unpriv/c-st-ext.html)。
同时对照本地冻结 Ibex decoder，并将真实固件中 32 个直接目标与冻结 GNU objdump 逐项比较。

架构字段接受 PowerPC；没有实现的 PowerPC、ARM、RV64 或非小端 RISC-V 目标解析返回
unsupported，保留原架构，不转为 UNKNOWN。原 ARM A4 的目标语义不由 A6 替代。

## 函数包含关系

首选 ELF 中已定义、可执行 section 的 STT_FUNC；函数 ID 绑定源 SHA、符号索引、start/end，
名字仅用于展示。所有范围是半开 `[start, end)`：start 包含，end 不包含。
没有可信 size 时不使用下一个符号补造范围，也不使用最近符号。
重叠候选默认 ambiguous，无候选 missing，只有一个明确区间才能 unique。
可显式传入已有 static_structure / cfg_metadata 区间作为后备；不自动启动新分析器。

目标 `0x100346` 的 reset_handler 标签在该 ELF 中不是有可靠范围的 STT_FUNC，
因此 A6 能确定目标地址，但该位置的函数 owner 保持 missing。
这与“反汇编显示 reset_handler 标签”不矛盾；标签存在不等于函数范围已知。

## 运行事件、静态目标、函数归属分离

RVFI trace 只提供相关 PC 和原始编码；每条编码必须与 ELF file-backed executable segment 匹配。
A6 对每个唯一 PC 建立静态事实，同时查询确定性直接目标的归属。
三种信息不相互升级：trace 事件、静态目标和函数归属不等于路径可行或输入可控。

本机基线得到 308 个 transfer facts（含普通指令的 unsupported 状态）、308 个 ownership facts。
其中直接目标 32，间接 10，unsupported 266；归属 unique 257、missing 51。
所有运行时目标解析、间接目标解析、路径可行性与输入可控性 capability 固定为 false。

## 投影、模型合同与确定性 gate

`firmware-control-flow-grounding-projection/v1` 只投影当前 firmware context 选中的位置，
并加入这些位置的直接目标 owner；默认最多 48 facts、24000 字符，超出预算明确失败。
当前配对上下文选取 7 个位置，投影 7 个 transfer facts、8 个 ownership facts。
源 catalog 始终是校验权威；修改投影不会改变 catalog。

A6 使用独立的 `firmware-a6-envelope/v1` 和 `GroundedFirmwareModelReport`。
模型只能选择两类结构化声明：

- `control_transfer_target`：fact_id、instruction_pc、claimed_target_pc；
- `function_ownership`：fact_id、site_pc、owner_function_id。

`raw_model_summary`、`diagnostic_questions` 都是诊断字段，不进入权威报告。
这比“让模型谨慎计算”更严格：不从自然语言推断声明、不使用 prose regex 做目标计算，
也不允许 generic ELF evidence ID 代替具体 A6 fact ID。

目标事实必须 resolved_direct，且 PC/target 精确相等。错误目标返回 incompatible /
control_transfer_target_mismatch；间接目标返回 unsupported /
indirect_target_not_deterministically_resolved。
函数归属必须 unique 且 site/owner ID 精确相等；错误 owner 返回 incompatible /
function_ownership_mismatch；ambiguous/missing 不接受唯一归属。

每个成功声明都会通过 fact → source → EvidenceRef 绑定。
规范 FirmwareAnalysisReport 只含支持的结构化声明，由程序从事实生成表述；
不复制模型 summary，哪怕结构化部分本身正确，也不把未经检查的自由文本升级为事实。
拒绝条目留在 diagnostic/support JSON。独立接受其他正确声明，不静默修正错误字段。
Cross-Layer Agent 接收规范固件报告与确定性 IR，原接口、prompt、实现保持不变。

此 A6 入口专注这两类事实；旧 ARM supported pipeline 和 legacy pilot 保留用于历史兼容。
不是把旧 pipeline 的所有自然语言声明都称为 A6-certified。

## A4 / A5 只读兼容性

用本地原 ELF 和已有 Ghidra artifacts 重建 A4 并验证冻结 SHA：
`fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902`。
不重新运行 Ghidra、angr，也不改写历史 artifacts。

A4：20 个重叠函数包含事实一致，111 个关系不适用 A6 当前比较，无 mismatch。
A5：34 个函数入口身份一致；没有据此推断可达性。
比较 API 对源身份不同、目标不一致或函数入口不一致返回显式 mismatch diagnostic。

## 显式真实回归命令

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 .venv/bin/python -m chipchain.integrations.paired_baseline \
  --root . --env-file .env --output-root output --firmware-grounding
```

只在离线测试通过后执行一次。继承现有 deepseek-flash 策略，每阶段至多一次调用，
无自动重试。ELF、模拟器及冻结 pair descriptor 的哈希必须先通过检查。

新 run 保存 A6 catalog/projection、schema-valid 原始声明诊断、支持校验、规范固件报告、
两侧其他报告、IR、AnalysisRun、输入/prompt/schema/用量、SHA 清单以及自动中文报告。
解析失败时保持现有安全策略：不转存未校验的 provider response body。

中文输出逐项分开 Raw Model Claim、Deterministic Fact、Validation Status、Canonical Interpretation。
不把“运行 completed”或“本轮没有提出候选”写成平台安全。

## 唯一一次真实回归结果

Run：`b0e049de-7d26-4d50-aa15-e5478f5483bd`。
Hardware、Firmware、IR aggregation、Cross-Layer 均 completed。

- Hardware：4 findings，0 trigger hypotheses，0 abnormal states。
- Firmware：模型提交 8 条结构化声明，6 supported，2 unsupported。
- 拒绝项：`claim-owner-100080`、`claim-owner-1003bc`，原因均为
  `function_ownership_missing`。模型将 ownership fact ID 当成 owner ID 填写；
  A6 没有唯一 owner，故不能支持该断言。
- 正确项：入口目标为 `0x100346`，`0x1000a0` 属于 puts；其余 4 个位置归属分别为
  timer_read 和 timecmp_update。
- IR：14 个原有确定性行为；拒绝声明和模型自由文字未进入 IR 或跨层 context。
- Cross-Layer：本轮没有提出候选，也没有提出攻击链，不作平台安全结论。
- accepted target mismatches = **0**；accepted ownership mismatches = **0**。

原始模型 summary 仍有两处文字错误：timer_read 终点写成 `0x100246`，实际为 `0x10024e`。
这些条目的结构化 owner ID 是正确的，但 summary 本身从未被赋予权威。
规范文本由 A6 事实渲染，使用正确的 `[0x10023e, 0x10024e)`。
不宣称 gate 理解了自由文本；它通过合同隔离使这类错误文字无法成为规范事实。

| Agent | requested / returned | input tokens | output tokens | total | finish |
| --- | --- | ---: | ---: | ---: | --- |
| Hardware | deepseek-flash / deepseek-flash | 6048 | 1003 | 7051 | tool_calls |
| Firmware | deepseek-flash / deepseek-flash | 13445 | 1406 | 14851 | tool_calls |
| Cross-Layer | deepseek-flash / deepseek-flash | 8987 | 1182 | 10169 | tool_calls |
| 合计 | 3 次调用，无重试 | 28480 | 3591 | 32071 | |

输出根目录：
`output/ibex-simple-system:hello-test:paired-workspace/b0e049de-7d26-4d50-aa15-e5478f5483bd/`。
首先阅读自动 `report-zh.md` 和补充核对 `regression-review-zh.md`。
原始诊断、支持结果和最终报告分开保存，无历史改写。

catalog SHA256：
`54c25342fb05a7b66935077716ca3829e5e7ca28d5b457fb3690065643fbd8cd`。
与离线使用同一 ELF/trace 构建的结果一致。

## 验证与保留

新增 72 项测试，覆盖 RV32 signed target、六种条件分支、压缩直接转移、间接跳转、
invalid/unsupported、PowerPC 保留、区间边界/重叠/未知大小、精确 fact-ID support、
历史 wrong/right 两类回归、确定性序列化、A4 mismatch diagnostic 与跨层输入隔离。

完整结果：`1148 passed, 27 skipped in 26.92s`。
`pip check`、`compileall -q src tests` 和 `git diff --check` 均通过。
4047 个既有受保护文件的 SHA 逐项复核无变化。
未修改 A4/A5、Hardware A3/B2、XL0、Cross-Layer Agent/prompt、DATA1A 输入及 reviewed exports。
未执行 git add/commit/push/tag。

## 下一阶段建议

A6 审核通过后，可进入 **DATA1B-R2：受控本地 RTL benchmark** 的方案审核，
限定在当前已支持的直接目标和唯一函数归属范围内，并继续保留静态事实与运行差分的区分。
若候选涉及 missing owner、间接目标或更复杂固件路径，应先补充确定性结构/CFG 信息；
不为推进实验而猜测函数范围。当前不需要先开展全面固件分析，也不在 A6 中实施 RTL 变体。
