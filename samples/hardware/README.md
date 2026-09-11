# Hardware input workspace

此目录用于真实硬件侧研究输入，例如 ProcessorFuzz SI、testcase ELF、ISA/RTL trace、
register/CSR snapshot、exception records 和 divergence results。
建议按 `hw-case-001/` 等样本子目录组织，不强制内部格式。

实际数据默认被 Git 忽略；这里不放 synthetic fixtures，也不实现 parser。
synthetic examples/tests 位于 repository 的 `examples/` 与 `tests/`。

paired CaseBundle 同时引用硬件与固件 artifact，不必复制样本到 cross_layer 目录。
此目录只是工作区约定，ArtifactRef 也可引用仓库外的只读材料。
