# Multi-Architecture QEMU Runtime Evidence V1

基线：`42b22268196880af04426fec63476d4655e666db` /
`v3-qemu-runtime-foundation-v1-r1-stable`，tag object
`92473093dbf6aed8fb5f209da32c56768e63a89c`。

本阶段把精确 ELF 的 QEMU 指令回调、静态行为和 Case Assembly 固件侧运行支持接通。
FW-POS 的 `sfence.vma → TLB_INVALIDATE` 与 FW-NEG 的 `fence → MEMORY_BARRIER`
均得到来源绑定支持。硬件触发与异常仍未建立，整体验证准备度仍为 false。
没有修改冻结 QEMU 安装、受控 Ibex/MMIO verifier、原始样本或已有 expected artifacts。

## A. 共享架构及边界

```text
exact ELF + explicit profile + pinned QEMU + content-identified trace plugin
  → complete bounded raw JSONL callback prefix
  → architecture-neutral RuntimeEvent
  → RuntimeSemanticDecoder registry
  → existing StaticBehaviorKind vocabulary
  → exact static/runtime binding
  → runtime-supported firmware capability projection
  → optional Case Assembly runtime projection
  → readable customer report
```

[qemu_evidence.py](../../src/chipchain/runtime/qemu_evidence.py) 是新增模型；旧
`runtime/evidence.py` 保留 ProcessorFuzz 的原有契约。
[acquisition.py](../../src/chipchain/runtime/acquisition.py) 不解释 ISA 语义；
[decoders.py](../../src/chipchain/runtime/decoders.py) 提供显式 ISA 接口；
[binding.py](../../src/chipchain/runtime/binding.py) 只比较来源、字节、解码兼容性与共享行为。
共享绑定没有 RISC-V mnemonic 分支。持久化与源重放位于
[artifacts.py](../../src/chipchain/runtime/artifacts.py)。

## B. Canonical objects 和身份

| 对象 | schema / 内容 ID 前缀 | 主要内容 |
| --- | --- | --- |
| `QemuRuntimeRunDescriptor` | `qemu-runtime-run/v1` / `qemu-runtime-run:` | 精确 ELF identity、完整 profile、QEMU/bundle/plugin hashes、固定采集选项、事件策略 |
| `RuntimeEvents` / `RuntimeEvent` | `qemu-runtime-events/v1` / `qemu-runtime-events:`、`qemu-event:` | run ID、原始流 SHA、连续 sequence、vCPU、PC、完整字节、size、停止结果 |
| `RuntimeSemantics` / `RuntimeSemanticFact` | `runtime-semantics/v1` / `runtime-semantics:`、`runtime-semantic:` | event 引用、ISA decoder ID、解码及共享 `StaticBehaviorKind`；未支持 event 列表 |
| `StaticRuntimeBindings` / `StaticRuntimeBinding` | `static-runtime-bindings/v1` / `static-runtime-bindings:`、`static-runtime-binding:` | analysis/behavior/instruction IDs 与对应 event/semantic IDs、SUPPORTED 或 UNKNOWN 原因 |
| `RuntimeCapabilities` / `RuntimeSupportedCapability` | `runtime-capabilities/v1` / `runtime-capabilities:`、`runtime-supported-capability:` | 静态行为及绑定引用、运行支持、独立保留的控制权/硬件边界 |
| Case runtime projection | `type2-firmware-runtime-projection/v1` / `type2-firmware-runtime-projection:` | 原 case ID、以上 artifact IDs、逐候选事实状态、固件侧准备度增量 |

ID 采用项目既有 canonical JSON SHA256，排除对象自身 ID，纳入明确默认字段。
Run ID 标识科学输入配置，不是一次进程的随机编号；events ID 还包含实际有界事件内容和 raw SHA。
不同配置可以形成不同 run ID；同配置的不同事件前缀也必须有不同 events ID。
对象中没有 host 绝对路径、PID、墙钟时间、UUID 或 LLM 内容。临时日志不参与科学身份。

Capability 是对既有 `StaticBehaviorFact` 的新增支持投影，直接引用其身份和共享 kind；
没有修改 CAP0，也没有另造一套运行时语义枚举。实际控制权限始终 `NOT_ESTABLISHED`。

## C. 插件和有界采集

冻结包内 `libexeclog.so` 仍用于诊断。它的文本包含反汇编、只输出 opcode 的前 32 bits，
且没有本阶段要求的确定性结束协议，因此本阶段使用轻量的
[chipchain_trace.c](../../tools/qemu/plugins/chipchain_trace.c)。
插件只记录 raw 字段，不输出 `TLB_INVALIDATE` 等科学分类。
API 7 声明来自冻结 QEMU 11.1.1；完整来源与协议见
[插件说明](../../tools/qemu/plugins/README.md)。本机 `cc` 将其编译到调用方 output，
编译选项包含 `-Wall -Wextra -Werror`，不修改或重打冻结 QEMU bundle。

原始 JSONL 为 header、连续 event、end。Header 携带 run descriptor ID、QEMU target、
单 vCPU 声明、API 与事件策略；来源配置被替换会导致重放拒绝。
每条指令在 translation 时复制 PC/bytes/size，在 instruction callback 时输出这些字节。

本次策略是从 ELF entry 记录完整前缀，到目标 PC 首次出现后再记录 8 个回调，
或最多记录 20,000 个事件。插件在**下一次未计入证据的回调**写入结束记录并退出，
不会把自身中止掉的 sentinel 指令加入观测前缀。
20 秒 host watchdog 只负责失败保护；超时、缺少 end、计数/序号/策略不一致均拒绝。
若目标窗口未在事件上限前完成，产物明确记录 `event_bound`，不伪装完成目标窗口。

[QEMU 文档](https://www.qemu.org/docs/master/devel/tcg-plugins.html#instructions)
说明指令插桩发生在执行之前。因此 `QEMU_INSTRUCTION_EXECUTION_OBSERVED` 精确表示
模拟器指令执行回调/调度观测，不证明该指令完成，也不表示体系结构或物理退休。
这是所有模型和展示的共同语义边界。

## D–F. 来源、解码与绑定

采集复用 `QemuRuntimeBackend`，仅使用项目安装下的显式 binary。
执行前核对该 binary 与冻结 `SHA256SUMS` 一致，再检查版本。
V1 只允许单 vCPU、generic loader、`bios=none`、无额外 profile 参数；
显式关闭 monitor/serial/network/user config，不引入未绑定的磁盘或 BIOS 文件。
保留实际执行的 `firmware.elf` 副本、编译的 `trace-plugin.so`、原始流与 stdout/stderr。
运行描述符绑定实际 ELF SHA/架构/位宽/端序/entry/mappings、QEMU 版本及 binary/bundle SHA、
插件源码/API header/binary SHA 与完整 profile/policy。执行后再次核对输入字节未变化。

接收 runtime 目录时无需重新启动 QEMU：加载层校验 JSON 内容 ID、冻结 QEMU 身份、
保留插件字节与当前项目插件来源；随后从保留的 ELF 和 raw stream 完整重放所有派生对象，
要求与保存的 JSON 精确一致。手改派生结论后重算 ID 仍不能绕过重放。
内容哈希提供完整性和可追溯性，不是远程证明，也不能认证恶意宿主伪造的整套原始流。
本阶段没有声称提供宿主/编译器可信执行证明。

每条事件都必须落在该 ELF 的唯一 file-backed executable mapping 中，且完整字节相同；
首事件必须对应 ELF entry。静态分析 artifact identity、每条静态指令的 ELF 字节及
behavior→instruction→PC 关系也重新核对。

RISC-V decoder 从字节识别普通 `sfence.vma` 和 `fence`，解码具体寄存器或 fence mask，
再调用未修改的 `classify_riscv()` 得到既有 `TLB_INVALIDATE` / `MEMORY_BARRIER`。
编码字段依据上游 [rv_s](https://github.com/riscv/riscv-opcodes/blob/master/extensions/rv_s)
与 [rv_i](https://github.com/riscv/riscv-opcodes/blob/master/extensions/rv_i)。
本 V1 不覆盖保留 FENCE 形式、PAUSE、FENCE.TSO、压缩指令或其他运行语义，均不猜测。
静态 `fence 0x3,0x3` 与运行 `fence rw,rw` 仅由 ISA decoder 做等价规范化。

绑定条件为：相同精确 ELF、相同架构/位宽、相同 PC、相同完整指令字节、兼容具体解码、
相同受支持语义。错误 ELF/profile、错误字节、错误解码、非法映射直接拒绝；
未观测行为为 `UNKNOWN/NOT_OBSERVED_IN_THIS_RUN`；已观测但未实现语义解码为
`UNKNOWN/UNSUPPORTED_RUNTIME_SEMANTICS`。不凭同名指令或同类语义跨 PC/ELF 绑定。

## G–H. 两个真实样本结果

两案均通过公开 CLI 各采集两次，未经手写 canonical JSON。目录在 ignored
[`output/qemu-runtime-evidence-v1/final/`](../../output/qemu-runtime-evidence-v1/final/)。

| 项目 | FW-POS | FW-NEG-TRIGGER |
| --- | --- | --- |
| ELF SHA | `35f9fff9c00e6a93bb9e6884b8604cd3d36dd35f7fdea408412633c5b7ae9fe4` | `2b6275ffb203f5ffc5411bb9200f5eafaab61fe6615a403697ecabace469e7cd` |
| 目标 PC | `0x80000064` | `0x80000064` |
| 实际 bytes | `73000012` | `0f003003` |
| 解码 | `sfence.vma zero,zero` | `fence rw,rw` |
| 运行语义 | TLB_INVALIDATE | MEMORY_BARRIER |
| 静态↔运行支持 | SUPPORTED | SUPPORTED |
| 目标 sequence（从 0 开始） | 16924 | 16924 |
| 前缀事件数 / 停止原因 | 16933 / target_window_complete | 16933 / target_window_complete |
| 固件候选事实整体运行支持 | SUPPORTED | SUPPORTED |
| 硬件触发 / 硬件异常 | NOT_ESTABLISHED | NOT_ESTABLISHED |
| 完整 Type-II / verification_ready | NOT_VERIFIED / false | NOT_VERIFIED / false |

FW-NEG 的 TLB_INVALIDATE 执行支持没有建立。其 fence 被观测不会自动变成 TLB 操作，
也不证明没有漏洞或硬件安全。

实际 run IDs：

- POS：`qemu-runtime-run:f72718d868d5c5189bef1eec698e503ee258e03dab13c2cba5aab62203644f28`。
- NEG：`qemu-runtime-run:b0b2042ea828cc1e167447c11532cdbb82f3e71579ff167b8a3b3e58714b06e9`。

实际 event artifact IDs：

- POS：`qemu-runtime-events:0b38f952446877cd2f11f1eee6b04fc7180febd103636f9fa3926f5e689dcc76`。
- NEG：`qemu-runtime-events:c326123ac41393f42c6daa8bebd8d8e05c6a30e7a0dbe962136bfa44bd55c12e`。

## I. 客观运行顺序

两案中 `0x8000005c` 的 fence 位于 sequence 16921，目标位于 16924；
只能说前者在这次单 vCPU QEMU 观测中先出现。
完整前缀及目标前后上下文均保留，没有将 host 时间解释为硬件时序或微体系结构邻近性。
没有实现完整运行时调用栈。客户报告中的 `main → … → arch_translation_sync`
仍标为静态调用路径；相同 PC 的实际回调支持不会把整条静态路径升级为运行栈。

## J–K. Case Assembly 和客户报告

旧命令不提供 `--runtime` 时，六份原输出逐字节不变。
提供运行证据时，旧 case ID 和五份基线产物仍逐字节不变：`case-manifest.json`、
`association.json`、`verification-readiness.json`、`analysis-chain.json`、`report.md`。
这些文件继续表示冻结的无运行输入基线；新增 `runtime-projection.json` 明确以原 case ID
为基础表达运行增量，并更新 `attack-chain-report.md` 的客户展示。

新 projection 只有在所有现有静态候选事实都有精确运行支持时，才将固件运行缺口标为
`SATISFIED_FOR_DECLARED_SCOPE`。任何部分覆盖或未支持解码保留 UNKNOWN/缺口。
此状态只适用于声明的固件指令范围，不能满足受控硬件 verifier 的 `RunEvidence`。
硬件契约、reference/variant、source-state 和 hardware-package provenance 缺口全部保留；
不调用冻结 verifier，也不生成验证成功的 chain。

客户报告以“该指令已在来源绑定 QEMU 执行中观察到”为软件侧进展，明确写出真实硬件触发
尚未建立和完整 Type-II 链未验证。SHA/fact/event IDs 留在 JSON，不堆入面向验收者的正文。
示例：[POS 客户报告](../../output/qemu-runtime-evidence-v1/final/case-positive-a/attack-chain-report.md)、
[NEG 客户报告](../../output/qemu-runtime-evidence-v1/final/case-negative-a/attack-chain-report.md)。
这些链接依赖本地 ignored output。

## L–M. 多架构扩展与科研边界

共享 schema/profile 接受 ARM、RISC-V、PowerPC 的 32/64-bit 身份。
registry 为 ARM/PPC 显式保留 unsupported 状态，没有伪造语义。未来接入需要：
已验证的明确 board/load profile、该 ELF 前端支持、ISA decoder 实现和真实采集验收。
现有 ELF 前端尚不接受 AArch64 ELF；本阶段的 ARM64 测试仅验证 schema/profile 可扩展性，
不表示已经跑通 ARM64。ARM/PPC 并未制造科学运行样本。

`QEMU runtime evidence != ProcessorFuzz RTL evidence != hardware trigger != hardware deviation
!= silicon evidence != verified vulnerability`。
QEMU 来源始终是独立项目 FW-POS/FW-NEG；硬件包里的 trigger-test ELF 仍是另一个来源。
没有用 QEMU 修补 SI→ELF、RTL revision、硬件签名或 same-execution provenance 缺口。
没有 LLM 调用，也没有冻结 core 修改。

## N. 重复运行和复现命令

两次运行的五个 canonical JSON、raw JSONL、保留 ELF/plugin、报告及 stdout/stderr
共 11 个文件逐字节相同；每案两份增强装配输出的 7 个文件也相同。
比较记录：[`repeated-run-comparison.json`](../../output/qemu-runtime-evidence-v1/final/repeated-run-comparison.json)。
这是已测试的单 vCPU benchmark 的结果，不承诺任意设备、并发 vCPU 或外部输入的确定性。
不同 compiler 若产生不同插件字节，其 run ID 应相应不同；本机重复编译插件字节一致。

```bash
chipchain runtime qemu \
  --elf samples/firmware/riscv/processorfuzz_real_case_001/positive/firmware.elf \
  --firmware samples/firmware/riscv/processorfuzz_real_case_001/expected/positive \
  --profile riscv64-fw-feasibility \
  --target-pc 0x80000064 --successors 8 --max-events 20000 \
  --output output/qemu-runtime-replay/positive-a
chipchain type2 prepare \
  --firmware samples/firmware/riscv/processorfuzz_real_case_001/expected/positive \
  --hardware samples/processorfuzz/real_case_001/expected \
  --runtime output/qemu-runtime-replay/positive-a \
  --output output/qemu-runtime-replay/case-positive-a
```

把两处输入的 `positive` 改为 `negative_trigger` 即运行负样本。
重复验收使用不同空输出目录；不用人工更改 ELF 或 canonical JSON。
没有显式 target 时，采集固定 `--max-events` 前缀。源码编译需要 host `cc`，不用重新安装 QEMU。

## O. 回归和冻结保护

最终完整测试：`529 passed in 62.76s (0:01:02)`；本阶段定向测试：
`99 passed in 8.25s`。实际命令：

```bash
.venv/bin/pytest -q
.venv/bin/pytest -q tests/unit/test_qemu_acquisition.py tests/unit/test_qemu_runtime_evidence.py tests/integration/test_type2_runtime_projection.py
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests scripts
git diff --check
git status --short --untracked-files=all
```

`pip check`：`No broken requirements found.`；compileall 与 diff check 均 exit 0。
新增 untracked 文件另查 trailing whitespace/final newline，通过。
没有修改或新增 shell 脚本，故 shellcheck/bash -n 无本阶段目标；新增 C 插件在四次真实
采集中均以 `-Wall -Wextra -Werror` 成功编译，并被冻结 QEMU 实际加载。

新增测试使用显式 synthetic callback streams 验证契约，
不将这些短流冒充真实执行；上面的四次公开 CLI 运行提供实际执行验收。
测试保留原离线/禁止外部进程 guard，真实 QEMU 命令在测试套件外显式执行。

冻结哈希审计比较 74 个受保护 tracked 文件及 11,942 个原有本地科学/QEMU 文件，全部不变。
POS/NEG 的旧六份 Case Assembly 输出逐字节不变，ProcessorFuzz 两案 expected outputs 不变。
六个核心文件、两个固件 ELF、两个原始硬件 ZIP 和以下 golden IDs 不变：

- P1：`type2-verification:9c7ef89582f89727fcacdb6b8bb7334ba79733c4182a6e7b341ba324e2fa6b82`。
- N1：`type2-verification:7dc13746b7067f7ce4adf6cc11ba8eeeb01a3b2582b7a2456b005704772477e7`。
- N2：`type2-reference-control:2d1ae9b25f06e6009e54b2081253ad93da1b3f8c1d91e942fd4ef6ed7dea28ab`。
- U1：`type2-verification:21db55b0e4ddb2f545e57ebb731f09bd7bd1b6b465dbe4c63f4c49bd07dd526a`。

审计文件在 `output/qemu-runtime-evidence-audit/` 与本次 final 目录。
安装脚本、bundle 构建脚本、VERSION/SOURCE/SHA256SUMS 均没有修改。
本阶段不执行 Git add/commit/push/tag。

## P–Q. 修改范围与交付

生产新增：acquisition、qemu_evidence、decoders、binding、artifacts、case_assembly_runtime；
原有生产修改仅 CLI、case_assembly 与 customer renderer 的可选 runtime 入口。
新增插件 C/API header/说明，两个 unit 测试文件、一个 integration 测试文件及显式 synthetic
测试 helper；更新根 README、QEMU README 和本文。
实际最终文件列表及 Git 状态以本阶段完成报告为准。停止在固件侧运行支持与可选装配，
没有实现新的硬件触发 verifier 或扩展冻结 Type-II verifier 的适用范围。

## R1 — Freeze Hardening（追加验收，不改写以上 V1 历史）

R1 基于上述未提交 V1 实现，只加固五项边界。冻结 HEAD 仍为
`42b22268196880af04426fec63476d4655e666db`；没有新增 ARM/PowerPC 真实运行，
没有修改 Type-II verifier、QEMU foundation 安装/发布/bundle。以下是 R1 新采集结果，
以上 V1 输出目录和历史结论保留原样。

### R1-1：来源绑定的端序

V1 的 firmware identity 已有 architecture/bit_width/endianness；原 RISC-V decoder
只接受 little-endian，但内部读取字节时仍写了字面量 `"little"`。
R1 将其改为 `identity.endianness`，保留当前仅支持 little-endian RISC-V 的显式兼容检查。
共享 event 保存原始字节，不做整数重解释，不按架构名称猜端序。实际 ELF identity 必须
与 descriptor 和静态分析完全一致；缺失、未知、错误端序拒绝，未实现的解码返回 unsupported。
ARM/PowerPC big-endian tuple 的单元测试仅验证共享模型，不冒充真实执行证据。

### R1-2：Runtime PC 到 ELF VA 的显式映射

新增 `RuntimeImageMapping`，绑定 firmware SHA、identity/relocated 类型和显式地址区间。
每个区间包含 runtime_base、elf_virtual_base、size；区间须有序、不重叠，并在实际固件
地址宽度内由唯一 executable ELF file range 支持。每条指令的完整 byte span 必须映射成功，
之后才能匹配 ELF 字节、静态指令及语义。缺少、错误、歧义或 unsupported mapping 均拒绝；
相同数值 PC 不能绕过检查。语义事实同时保留 runtime PC 与 mapped ELF VA。

当前公开 `riscv64-fw-feasibility` 采集显式声明 identity mapping，两案映射都是
runtime/ELF base `0x80000000`、size `3432`。采集器同时检查 ELF PT_LOAD 的 physical
与 virtual address 相等。relocated mapping 只在纯地址绑定契约和 synthetic 单元测试中支持；
实际采集器拒绝 relocated，不新增 loader/MMU/动态重定位实现。

R1 为冻结前 descriptor 增加必需 mapping 与 header-provenance SHA，因而新 run/event/
projection IDs 有意变化。旧 V1 本地产物仍保留用于历史审计；新版 replay 对缺失字段 fail
closed，需要新采集，不自动猜 identity mapping，也不迁移或改写历史证据。Case IDs 不变。

### R1-3：同次运行、同 vCPU 的顺序

`runtime_order()` 先校验 canonical event identity，只有 same run + same vCPU 的有效
sequence 才产生 OBSERVED_BEFORE/OBSERVED_AFTER。不同 run/vCPU 返回 UNKNOWN；
同一事件返回 SAME_EVENT，冲突的同序号事件不能形成顺序。完整 stream 查询仍校验来源、
连续前缀和事件成员关系。host timestamp 不是 event 字段，也不参与比较。
实际 POS/NEG profile 仍只接受一个 vCPU，当前序号仅说明该次模拟器回调的先后。

### R1-4：插件来源、API 和构建

C 插件及 vendored header 字节均未改变。新增
[`header-provenance.json`](../../tools/qemu/plugins/header-provenance.json) 绑定 QEMU
11.1.1 / tag v11.1.1 / commit `c3d48b7d1e89604920e5b81b91140c2ad39a1943` 的
`include/plugins/qemu-plugin.h`，API 7，GPL-2.0-or-later。原完整 header SHA256：
`335d4e472067e914add598b60d1f7cf0dc029cd48f62f66656d6a88c54d8d9f9`。
已与本地经过验证的 QEMU source 中的文件比对。subset 保留上游 copyright/SPDX，
省略未使用的 GLib 声明，使客户构建不依赖完整 QEMU source 或 GLib 开发包。

新增 `plugin_build.py` 供 acquisition 和独立重建复用。构建前核对冻结 SOURCE、subset
真实哈希、API macro 与 provenance；真实加载还验证 pinned QEMU 插件 ABI。运行 descriptor
绑定 QEMU version/executable/bundle、plugin API/source/header/provenance/binary SHA。
不同二进制必然改变 run ID，经 parent run ID 传递给 event，不往每条 event 复制全部元数据。
保留 `.so` replay 时检查哈希。`plugin-build.json` 是可检查的辅助本地构建记录，包含 compiler
版本/二进制 SHA、确定的 argv template、输入/输出 SHA；不是可信主机证明，不替代 replay。
科学 ID 不包含绝对路径、PID、时钟、临时目录名、随机 UUID 或 LLM 文本。

实际独立重建命令已成功执行：

```bash
.venv/bin/python -m chipchain.runtime.plugin_build --output output/qemu-runtime-evidence-r1/plugin-rebuild
```

编译配方（helper 执行时将源码/输出解析为实际绝对路径，记录中保留相对模板）：

```bash
cc -std=c11 -O2 -fPIC -shared -fvisibility=hidden -Wall -Wextra -Werror -Wl,--build-id=none tools/qemu/plugins/chipchain_trace.c -o output/qemu-runtime-evidence-r1/plugin-rebuild/trace-plugin.so
```

host cc 11.4.0；四次采集与独立构建的 binary SHA 均为：
`61fd2d11e4d1665ba2d69e3172940d8faa6a5b09df3bdfe34faa01f3edfa9ed6`，与 V1 相同。
compiler 元数据不直接加入每个 event ID；换工具链导致 binary 不同则明确产生不同 run identity。
详细来源及命令见 [plugin README](../../tools/qemu/plugins/README.md)。

### R1-5：SUPPORTED 的精确定义

schema 的 `SUPPORTED_DEFINITION` 原文为：

> The exact static firmware fact has a compatible, source-bound QEMU instruction-execution callback observation under the declared run/profile and image mapping. This does not establish instruction completion, physical retirement, memory effects, hardware trigger, deviation, timing, silicon behavior or vulnerability verification.

StaticRuntimeBinding 和 RuntimeSupportedCapability 的 status schema 直接引用此定义。
semantic_status 的 SUPPORTED 仅表示当前 decoder 能识别该回调字节的语义。
QEMU instruction callback 发生在指令执行前，不能据其宣称指令完成、内存副作用完成、
物理退休、真实硬件触发、异常、硬件时序或漏洞成立。模型没有 retired/completed/hardware_effect
推断字段；客户 renderer 也明确写出“指令执行回调观测”及完成性限制。

共享链路保持 Raw Event → Source/Load Mapping → ISA decoder → neutral semantic →
Static-Runtime Binding；仅 RISC-V backend 解码当前 fence/sfence.vma，仍复用静态 frontend
的 `classify_riscv` 策略。ARM/PowerPC 将来扩展 decoder，无须改变共享 event/source/mapping
字段；当前没有声称它们已有实际运行支持或伪造任何运行产物。

### R1 真实重复采集与 Case Assembly

按上文公开 CLI，分别以两个空目录重复采集两案，然后分别执行带/不带 `--runtime` 的
`type2 prepare`。结果位于 `output/qemu-runtime-evidence-r1/`。

| 项目 | FW-POS | FW-NEG-TRIGGER |
| --- | --- | --- |
| ELF SHA256 | `35f9fff9c00e6a93bb9e6884b8604cd3d36dd35f7fdea408412633c5b7ae9fe4` | `2b6275ffb203f5ffc5411bb9200f5eafaab61fe6615a403697ecabace469e7cd` |
| Runtime PC / ELF VA | `0x80000064` / `0x80000064` | `0x80000064` / `0x80000064` |
| Raw bytes | `73000012` | `0f003003` |
| Shared semantic | TLB_INVALIDATE | MEMORY_BARRIER |
| Exact binding | SUPPORTED | SUPPORTED |
| Event count / target sequence | 16933 / 16924 | 16933 / 16924 |
| Verification readiness | false | false |

这些计数是本次实测结果，不是 verifier 硬编码。仍为最多 20000 events、target 首次出现后
保留 8 callbacks；wall-clock timeout 仅作 watchdog。四次均 `target_window_complete`。
新 run IDs：

- POS：`qemu-runtime-run:635d30a2e1af03f22a3ef5156a618692ad4ae435e0ca2a67609845a6e43558c1`。
- NEG：`qemu-runtime-run:74f01e9d92fb8dbb00346ad5986bf5cfb48fd8c96a9abc4e0d7fb961d1f5b04a`。

每案两次采集的 12 个文件（含新增辅助 build record）全部逐字节相同；两份增强 Case
Assembly 的 7 个文件也相同。每案无 runtime 模式的 6 个输出与冻结基线逐字节一致，
Case ID 保持原值。对比记录：
[`repeated-run-comparison.json`](../../output/qemu-runtime-evidence-r1/repeated-run-comparison.json)。

QEMU projection 保持 additive；冻结 readiness 文档继续表示原有 verifier 的证据要求，
独立的 runtime projection 只补充 QEMU 支持信息，不清除硬件验证缺口。
两案 hardware trigger/deviation/silicon applicability 仍 NOT_ESTABLISHED，完整 Type-II
仍 NOT_VERIFIED，readiness=false，ProcessorFuzz differential 仍 UNKNOWN。

### R1 验证与保护

新增 23 个 R1 单元测试，覆盖端序、显式映射/relocation/歧义拒绝、同 run/vCPU 顺序、
API/header/二进制身份及 SUPPORTED 边界。已有 99 个 runtime 定向测试继续通过，包含
错误 firmware SHA、architecture、bit width、instruction bytes 等 provenance 拒绝。

- R1 定向：`23 passed in 1.55s`。
- 原 runtime 定向：`99 passed in 8.99s`。
- 完整 `.venv/bin/pytest -q`：`552 passed in 73.78s (0:01:13)`。
- `.venv/bin/python -m pip check`：`No broken requirements found.`。
- `.venv/bin/python -m compileall -q src tests scripts`：exit 0。
- `git diff --check`：exit 0；新增文件另行检查 whitespace。
- 没有修改 shell 文件，不需要新增 shellcheck/bash -n 目标；插件实际编译加载成功。

重新验证 74 个受保护 tracked 文件、11,942 个原有本地科学/QEMU 文件 SHA 均未变化。
包括两个 firmware ELF、ProcessorFuzz 两案 expected、六个冻结核心文件、P1/N1/N2/U1
及 QEMU foundation；上面的四个 golden IDs 保持原值。HEAD/tag/tag object 未变。
无 LLM 调用；未执行 Git add/commit/push/tag；本轮停止在 R1 hardening。
