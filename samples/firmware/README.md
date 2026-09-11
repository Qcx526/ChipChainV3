# Firmware input workspace

此目录用于真实固件侧研究输入，例如 ELF/BIN、GDBFuzz results、Ghidra/angr outputs、
CFG/Call Graph exports。建议按 `fw-case-001/` 等样本子目录组织，不强制内部格式。

实际数据默认被 Git 忽略；R0-C 不分析这些格式。synthetic fixtures 位于 `examples/` 与 `tests/`。
paired CaseBundle 通过 references 复用样本，不复制跨层配对文件。
外部只读 artifact 路径同样合法，不要求样本位于此目录。
