# ProcessorFuzz real case 002

本样本是本次任务指定的硬件侧原始交付包。用户明确声明
`DECLARED_TOOL_FAMILY=processorfuzz`；这一声明不是从 ZIP 名称或目录推断的。
用户未额外声明包内每个 ELF 的触发验证用途，因此本轮 CLI 保持
`package_role=unclassified`、`firmware_role=unclassified`、`customer_firmware=null`。
两份硬件侧 ELF 均未作为客户固件输入；客户固件需单独通过通用固件入口分析。

- CASE_ID：`real_case_002`，仅用于仓库组织，不参与科学分支判断。
- RAW_SOURCE：`samples/processorfuzz/real_case_002/raw/testis.zip`。
- SAMPLE_ROOT：`samples/processorfuzz/real_case_002`。
- 原始 ZIP SHA256：`7384a5337a0811c16c52bdd0c82f54e8765623c201223d44570b9c5f0f6b8161`。
- ZIP 大小：4,635,743 字节；124 个成员，包括 105 个文件和 19 个目录；文件展开总计 41,482,615 字节。

`raw/testis.zip` 保持原始字节，未解包替换、重打包或修改。运行过程只读取交付物，
Ghidra 使用项目工具分析 ELF 的临时快照；不执行包内 ELF、模拟器或构建程序。

## 客观结构与旧样本差异

| 材料 | real_case_001 | real_case_002 |
| --- | --- | --- |
| 目标 ELF | 一份 RISC-V 64 位 ELF | 两份 RISC-V 64 位、小端可执行 ELF |
| SI | 两个路径、相同内容 | 四份不同内容 |
| RTL／ISA 执行轨迹 | RTL log、ISA CSV 和 ISA log | `testis/out/trace/` 为空，三类轨迹均缺失 |
| RTL／ISA 签名 | 254 个 128 位 word，3 个不同 | 254 个 128 位 word，全部相同 |
| 反汇编 | `disassembly.asm` 与 ELF 冲突 | `.input_1.asm` 在 595 个可映射指令检查中无冲突；来源仍未绑定 |
| 其他 | transition 数据、笔记、构建产物 | 另有 timer 源码、ELF、目标文件及人工标签 |

两份可执行 ELF 是 `testis/out/tests/.input_1.elf` 和 `testis/usebug/timer.elf`，
入口均为 `0x80000000`。`timer.o` 是 RISC-V 可重定位对象；
`build/` 中另检测到 28 个 x86-64 ELF（模拟器／目标文件），它们不代表目标固件架构。

四份 SI 是 `.input_1.si`、`.input_MPIEnotMIE.si`、`.input_timer_normal.si`、
`.input_timer_with_bug.si`。既有 SI 解析器分别得到 268、268、11、12 条源指令；
源指令不是执行记录。另有 `.S`、`.asm`、`.hex`、`.symbols`、`timer.c`、
`transition.db`、`note.log` 和内容为 `True` 的 `checkbug.txt`。
人工标签和 transition 文本不构成绑定到本次 ELF 的运行或漏洞证据。
corpus／illegal／mismatch 等目录为空；未提供独立 CFG、reverse CFG、覆盖率结果或总线轨迹。
Ghidra 生成的 CFG 仅为静态结果。

## 适配决策与分析选择

扩展现有 `src/chipchain/workflow/processorfuzz.py`，未新增独立适配器。
复用 ZIP、SI、ELF／Ghidra、签名解析和比较逻辑，增加全部三类执行轨迹均缺失时的
`signature_only` 结构分支。该分支不依赖 CASE_ID 或样本目录。
签名解析允许缺少运行来源，并使相应差异判断保持 `UNKNOWN`；
严格的 `RuntimeSource` 和冻结科学核心保持不变。

多 SI／ELF 不再通过猜测消歧。本轮由适配工作显式选择以下两个分析对象：

- `--si-member testis/out/tests/.input_1.si`
- `--elf-member testis/out/tests/.input_1.elf`

选择意图是检查交付包 `out/tests/` 下的测试材料；同目录、同 stem 或显式选择均不证明
SI 来自该 ELF 的构建或执行。其他 SI／ELF 完整保留在清单并标为未绑定，
`timer.elf` 未混入所选 ELF 的静态分析。未提供选择时，多种内容仍被拒绝；
错误成员、歧义签名、格式错误和只提供部分轨迹仍被拒绝。
`.asm` 复用既有反汇编字节检查，匹配也不提升来源状态。

本次扩展范围是 SI、ELF、两份签名存在且三类受支持执行轨迹全部缺失的交付物。
任意其他日志格式不能自动作为受支持轨迹。若部分执行轨迹存在，仍要求完整的原有轨迹输入，
不静默丢弃材料进入无轨迹分支。

## 确定性结果与证据边界

| 项目 | 本轮结果 |
| --- | --- |
| 硬件交付包摄入 | 完成；105 个文件逐一记录路径、大小和 SHA256 |
| 测试材料识别 | SI 源描述及两份 ELF 客观存在；具体触发验证用途未建立 |
| 所选 ELF | SHA256 `9511f8db1e148d10cf103e0589564ce100c8d2168566c3642f36bba6ae4d9f2d` |
| 静态分析 | 522 条指令、3 个函数、135 个基本块；122 个不支持项明确保留 |
| 原始签名比较 | 254 个 word 相同，0 个不同；不表示安全或已证明无偏差 |
| 执行轨迹 | `MISSING`；运行指令计数为 null，不是 0 |
| 运行来源绑定 | `UNKNOWN`；签名 `source=null` |
| SI→ELF／签名同次执行 | `UNKNOWN` |
| architectural differential | `UNKNOWN` |
| 跨层候选 | `INCOMPLETE` |
| Type-II | `NOT_ESTABLISHED`；`not verification-ready` |

尚缺可信硬件行为契约、构建与执行来源绑定、RTL 来源版本，以及冻结验证器要求的
运行与 Reference／Variant 对照输入。因此 `manifest/` 只记录摄入选择，
没有制造 verification-ready Type-II manifest。没有伪造轨迹、运行 PC、次序或来源哈希，
也没有将硬件侧程序提升为客户固件或将模拟材料提升为物理芯片证据。

`expected/` 的 15 个文件直接由下列公共 CLI 生成，未手工修改科学 JSON。
其中 `rtl-signature.json` 和 `isa-signature.json` 保存原始签名解析；
不生成 `rtl-runtime-evidence.json`、`isa-reference-evidence.json` 或 `verification.json`。
完整报告见 [expected/processorfuzz-report.md](expected/processorfuzz-report.md)。

## 复现

从仓库根目录执行。所有输出目录必须不存在或为空；已有结果不会覆盖。

```bash
.venv/bin/python scripts/inspect_hardware_sample.py \
  --input samples/processorfuzz/real_case_002/raw/testis.zip \
  --output output/real_case_002-inspection-replay

CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/python -m chipchain.cli processorfuzz analyze \
  --package samples/processorfuzz/real_case_002/raw/testis.zip \
  --si-member testis/out/tests/.input_1.si \
  --elf-member testis/out/tests/.input_1.elf \
  --output output/real_case_002-replay

diff -r samples/processorfuzz/real_case_002/expected output/real_case_002-replay

CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q \
  tests/unit/test_processorfuzz_ingestion.py \
  tests/integration/test_processorfuzz_real_case.py \
  tests/integration/test_processorfuzz_signature_only.py
```

完整 CLI 静态分析需要仓库固定的 Ghidra 安装。普通测试在禁止网络／外部进程的环境中，
重放经真实 Ghidra 生成的 `ghidra-export.json`，仍实际执行 ELF 字节校验、规范化、
摄入、报告与 CLI 写出，并逐文件比较 expected。检查器的 inventory／brief 仅为开发诊断，
不进入科学证据或身份计算。
