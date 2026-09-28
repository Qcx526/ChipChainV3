# ProcessorFuzz 无执行轨迹交付包报告

摄入完成；执行轨迹缺失，Type-II 为 `NOT_ESTABLISHED`，`not verification-ready`。

具体包／ELF 角色未分类；不能将硬件侧 ELF 当作客户固件，也未证明其触发验证用途。

原始归档 SHA256：`7384a5337a0811c16c52bdd0c82f54e8765623c201223d44570b9c5f0f6b8161`。
文件数：105；逐文件哈希见 `processorfuzz-case-manifest.json`。

分析选择：SI `testis/out/tests/.input_1.si`；ELF `testis/out/tests/.input_1.elf`。
成员选择仅指定分析对象；同名、同目录和显式选择均不证明同一构建或执行。
SI→ELF、签名→程序、签名同次执行、运行来源绑定均为 `UNKNOWN`。

SI 标识 `processorfuzz-si:8c3defeb2dd5fdafcaa1592d7ac6d7c87f9ce1ead133deab75111e4a34bda765`；268 条源指令，属于测试描述。
ELF SHA256 `9511f8db1e148d10cf103e0589564ce100c8d2168566c3642f36bba6ae4d9f2d`；riscv 64 位；Ghidra／ELF 静态分析得到 522 条指令。
静态分析和 CFG 不能建立运行 PC、指令顺序或触发成立；详见 `firmware-report.md`。

RTL 指令日志、ISA CSV、ISA 指令日志均缺失；指令计数为 null（未知），不是执行零条。
未生成运行证据文件；签名文件的 source 为 null，不构造 RuntimeSource 或伪造轨迹哈希。

签名逐项比较：254 个相同 word，0 个不同 word；architectural differential 为 `UNKNOWN`。
签名相同不证明行为一致或安全；签名不同也不证明漏洞。

待绑定／冲突文件：

- `testis/note.log`：UNBOUND；Human note is not runtime evidence。
- `testis/out/tests/.input_1.asm`：UNBOUND；No producer binding。
- `testis/tests/.input_MPIEnotMIE.si`：UNBOUND；Not selected for analysis; no build or execution binding。
- `testis/tests/.input_timer_normal.si`：UNBOUND；Not selected for analysis; no build or execution binding。
- `testis/tests/.input_timer_with_bug.si`：UNBOUND；Not selected for analysis; no build or execution binding。
- `testis/usebug/timer.elf`：UNBOUND；Not selected for analysis; no build or execution binding。

缺少可信硬件行为契约、SI／ELF 构建绑定、签名执行上下文、RTL 来源版本及适用的运行验证输入。
`note.log`、人工 bug 标签、transition 数据及构建产物未转换为执行或因果证据。
未运行交付包内的程序；不声明硬件触发、偏差、客户固件漏洞或物理芯片适用性。
