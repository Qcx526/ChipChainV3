# 摄入选择与来源声明

用户明确指定 `CASE_ID=real_case_002`、`DECLARED_TOOL_FAMILY=processorfuzz`，
原始输入为 `../raw/testis.zip`。ZIP SHA256：
`7384a5337a0811c16c52bdd0c82f54e8765623c201223d44570b9c5f0f6b8161`。
没有另行声明包／ELF 的触发验证角色，故不使用 `--hardware-trigger-validation`。

适配工作选择 `testis/out/tests/.input_1.si` 与 `testis/out/tests/.input_1.elf`
作为分析对象。CLI 的 `--si-member`／`--elf-member` 是精确成员路径索引，
不建立 SI→ELF、同次执行或签名生产来源。其他 SI／ELF 仍完整列于清单且未绑定。

规范、内容寻址的摄入清单由实际代码生成至
[`../expected/processorfuzz-case-manifest.json`](../expected/processorfuzz-case-manifest.json)。
缺失轨迹的路径和哈希为 null；签名不构造运行来源。
这里不复制或编辑原始包成员，也不提供伪造的 Type-II 验证索引。
本样本 **not verification-ready**；复现命令见[样本 README](../README.md)。
