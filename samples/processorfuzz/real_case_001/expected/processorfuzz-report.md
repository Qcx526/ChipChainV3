# ProcessorFuzz 真实交付包验收报告

## 1. Case Summary

Case ID `processorfuzz-si:0f48abbedb080992a588369f82e8475c811f944ed6f44a64d852165a28fda6e1`；ELF SHA256 `649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86`。
该 ZIP 是硬件团队真实交付的触发验证包；包内 ELF 是硬件团队制作的触发测试程序，不是客户固件、生产固件或真实目标固件镜像。它可以帮助理解硬件 trigger reference 并检查证据绑定，但不能证明客户固件包含该触发行为。

| 角色字段 | 值 |
|---|---|
| package_role | `hardware_trigger_validation_package` |
| firmware_role | `hardware_supplied_trigger_test_firmware` |
| firmware_origin | `hardware_department` |
| customer_firmware | `false` |
| role_basis | `hardware_team_delivery_intake` |

包内签名的原始数值确实不同；当前缺少同一执行上下文和完整硬件来源绑定，因此不声称已验证漏洞或 Type-II 链。

## 2. Input Artifact Inventory

归档共 101 个文件：assembly 1、build_metadata 1、disassembly 1、elf 1、human_note 1、isa_csv 1、isa_log 1、isa_signature 1、other 88、rtl_signature 1、rtl_trace 1、si 2、simulator 1。
完整逐文件 SHA256 见 `processorfuzz-case-manifest.json`。以下列出直接用于本轮分析的输入。

| 文件 | 角色 | SHA256 |
|---|---|---|
| `testis/build/RocketTile` | simulator | `4b7bfcc2d3c7594724ad1c1196b3aabdfd44dab334b17438734ddfd76aa7fbcf` |
| `testis/build/Vtop__verFiles.dat` | build_metadata | `f53740fc56ce5907026a925be85caf42c76535e9e529520867d4d8d84ab37a7c` |
| `testis/note.log` | human_note | `00b5c824a6db9e4854cd3e12a2e7f7dadcd7872090c79680c24c1da1b90a73bf` |
| `testis/out/.isa_sig_0.txt` | isa_signature | `3f9463d3d49f73942396edc67223269ab004e05042e58579c51805f797f80a37` |
| `testis/out/.rtl_sig_0.txt` | rtl_signature | `e14bcb08de2e6d62ee0368aa4d244375ca1e64178392b39f5b4866d25f577513` |
| `testis/out/tests/.input_1.S` | assembly | `9b9cb6de2db097855d744a6f8d087db611c66553acf9d34666246ec8030d127c` |
| `testis/out/tests/.input_1.elf` | elf | `649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86` |
| `testis/out/tests/.input_1.si` | si | `cb6dbcbd7d67a78bc5f070342ff03178562ded53edf3f2467db26d999059e1f6` |
| `testis/out/tests/disassembly.asm` | disassembly | `091ef6d7688f7356d776cb03ecd7521241d5cecc70bdd20810bc8523f58bfc9c` |
| `testis/out/trace/isa_1.csv` | isa_csv | `71df08ccfbd1f17a1942f5a01d574ef49c51acd5d0d50e077fc8946fadb8b87c` |
| `testis/out/trace/isa_1.log` | isa_log | `9197d3ba3b3e31b59d893deacfd87f159d51e28f67b7b1ffe32e56c8be2b2093` |
| `testis/out/trace/rtl_1.log` | rtl_trace | `0a5374306877f87ceb9de6d3e89788c23e6614b823c8ee34f84ce2cf5d470379` |
| `testis/tests/.input_918_gen.si` | si | `cb6dbcbd7d67a78bc5f070342ff03178562ded53edf3f2467db26d999059e1f6` |

## 3. Provenance / Binding Status

接受 SI `testis/out/tests/.input_1.si`；ELF `testis/out/tests/.input_1.elf`；RTL `testis/out/trace/rtl_1.log`；ISA CSV `testis/out/trace/isa_1.csv`；ISA log `testis/out/trace/isa_1.log`；RTL/ISA signatures `testis/out/.rtl_sig_0.txt` / `testis/out/.isa_sig_0.txt`。

SI→ELF `UNKNOWN`；RTL→ELF `PARTIAL_BYTE_MATCH`；ISA→ELF `PARTIAL_BYTE_MATCH`；signature 同次执行 `UNKNOWN`；RTL source revision `not_established`。

### 拒绝或待绑定的文件

- `testis/note.log`：UNBOUND。Human note is not runtime evidence。
- `testis/out/tests/disassembly.asm`：CONFLICT_WITH_ELF。278 个映射字节冲突；不能作为 ELF 的权威反汇编。

## 4. ProcessorFuzz SI Testcase

原始 SI SHA256 `cb6dbcbd7d67a78bc5f070342ff03178562ded53edf3f2467db26d999059e1f6`；模式 `p-m`；解析 368 条源指令，209 个标签；这些是测试描述，不是执行记录。

## 5. Firmware Static Analysis Summary

Ghidra+ELF 分析 `693` 条指令、`4` 个函数、`220` 个基本块。CSR 读/写 `52`/`40`；barrier `2`；sfence.vma/TLB invalidate `2`；atomic behaviors `60`；exception return `7`。详见 `firmware-report.md`。

## 6. RTL Runtime Trace Summary

解析 `326` 条有表头约束的前六列记录；ELF 匹配 `321`，冲突 `0`，未映射 `5`。其余列未声称完整解码。

## 7. ISA Reference Trace Summary

CSV 解析 `293` 条 reference 记录；ELF 匹配 `293`，冲突 `0`，未映射 `0`。ISA 不是 DUT RTL。

## 8. Exception / Privilege / CSR Observations

静态 ELF 的 CSR/异常返回语义见固件报告；RTL 和 ISA 仅已解析明确的 PC、指令编码与 mode 列。没有建立完整 CSR 状态或异常事件 schema binding，不能归因 signature word。

## 9. Architectural Differential

原始 128-bit 签名差异 `3` 个 word；正式状态 `UNKNOWN`；trace 对齐 `AMBIGUOUS`。

| word index | RTL raw | ISA raw |
|---:|---|---|
| 37 | `80000002000460000000000000000000` | `00000002000420000000000000000000` |
| 44 | `000000000000b1098000000a00046000` | `000000000000b1090000000a00042000` |
| 48 | `00000000141416730000000000000002` | `00000000000000000000000000000002` |

## 10. Cross-Layer Candidate

固件静态事实与运行片段可供后续建立 Type-II candidate；当前没有可信 HBC，也没有对该非 MMIO 样本适用的冻结 verifier 输入，因此候选状态 INCOMPLETE。Candidate 不等于已验证 Type-II 链。

## 11. Missing Verification Requirements

- SI、ELF、trace、signature 的明确构建和运行来源绑定。
- 完整 RTL source revision 或可信硬件构建 manifest。
- 独立撰写并核验的硬件行为契约，以及适用非 MMIO 资源的运行评估器。

## 12. Scientific Limitations

`note.log` 只作人类笔记；`disassembly.asm` 若冲突则拒绝；签名差异不是漏洞证明。未运行 LLM，未根据包名、文件名或人工 bug 标签推断因果。

General firmware-analysis 的验证依据是独立编写的项目固件样本，不是这个硬件触发测试 ELF。未来客户固件必须作为单独证据来源进入，并通过同一个 generic firmware frontend 分析。
