# Firmware input workspace

此目录用于真实固件侧研究输入，例如 ELF/BIN、GDBFuzz results、Ghidra/angr outputs、
CFG/Call Graph exports。建议按 `fw-case-001/` 等样本子目录组织，不强制内部格式。

实际数据默认被 Git 忽略；R0-C 不分析这些格式。synthetic fixtures 位于 `examples/` 与 `tests/`。
paired CaseBundle 通过 references 复用样本，不复制跨层配对文件。
外部只读 artifact 路径同样合法，不要求样本位于此目录。

当前本地已填充 `ibex-simple-system/hello-test/` 和 `fuzzware-experiments/`
的 Heat_Press scenario 13 输入；这些数据被 Git 忽略。
Ibex 固件源码与硬件源树共同保存于 `../hardware/ibex-simple-system/source/`，不复制第二份。
目录清单、case views 与验证命令见 [workspace 清单](../README.md)。
