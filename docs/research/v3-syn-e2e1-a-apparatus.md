# SYN-E2E1-A — 受控 MMIO 装置与客观 Trace

本阶段验收：**GO（仅限受控装置）**。最小汇编固件已经真实编译，并在两套由同一冻结 Ibex Simple System 源码生成的 Verilator 模拟器上执行。观察到了要求的总线写入、状态变化、读取和 RAM 保存值。没有生成 ChipChain 的触发满足、偏差验证或跨层链结果。

通俗地说：我们在 Ibex 系统旁接了一个可控的实验外设。同一个程序先打开开关，再发送命令，再读回结果。两个版本只有一处状态更新逻辑不同；实测差异确实从这一处开始显现。这证明实验装置能收集可信的对照数据，**不表示发现了真实 Ibex 漏洞**。

## 实测结果（evaluation-only）

本节使用设计中的 P1/N1/N2 标签，方便人工验收。标签及验收期望只存在于测试/文档中；runner、monitor、parser 和运行 manifest 均使用中性 ID。

| 验收引用 | COMMAND 实际写值 | 写入后 STATUS | STATUS 读响应 | RAM result_slot 保存值 |
|---|---:|---:|---:|---:|
| R-P1，同时作为 N2 | `0xA5` | `0` | `0` | `0` |
| V-P1 | `0xA5` | `0xDEAD` | `0xDEAD` | `0xDEAD` |
| R-N1 | `0xA4` | `0` | `0` | `0` |
| V-N1 | `0xA4` | `0` | `0` | `0` |

每组真正执行两次，共 **8 次 Ibex 仿真**；四组各自的两份 parsed trace 完全一致。N2 复用 R-P1 证据，没有伪造第二份独立运行。另有两次直接驱动外设的 RTL 单元仿真，专门检查非法访问、ENABLE 前态、状态保持和复位；它们不算 Ibex 固件运行。

所有 Ibex 运行都实际记录到：

- reset assertion：monitor cycle 3；release：cycle 5；reset epoch 为 1。
- cycle 11：事务 1，`write 0x40000 = 1`，`be=0xF`；cycle 12 成功响应。
- cycle 14：事务 2，`write 0x40004 = 0xA5/0xA4`；cycle 15 成功响应。
- cycle 16：事务 3，`read 0x40008`；cycle 17 返回表中值。
- cycle 20：向 `0x101000` 写入读回值。
- cycle 24：SimCtrl software stop；cycle 26 执行 `$finish`。
- footer：`complete=1, event_count=33, last_cycle=26, reset_epoch_count=1, normal_sim_exit=1`。

P1 两侧第一次差异：**cycle 14、sequence 16、下降沿 `status_sample.status_value`，左侧 0，右侧 57005 (`0xDEAD`)**。此时 COMMAND 请求已被接受，NBA 更新已经完成，COMMAND 响应尚未在下一个上升沿记录。两侧所有 MMIO 请求对应一致，包括 STATUS 读取请求；后续响应和 RAM 数据自然不同。

范围严格限定为 **monitored synthetic-peripheral events/state and explicit RAM result write**，并非处理器全部 RTL 信号的首次差异。N1 在完整的 reset-release 到退出前采样窗口内，每个 STATUS 样本均为零；缺失样本、截断、超时不能给出这种结论。

## 真实证据位置与身份

正式验收工作区：

`output/syn-e2e1-a/experiment-tn2kt3tu/`

入口：`apparatus-result.json`。原始源码清单、source-tree delta、构建命令和 stdout/stderr、Verilator XML、ELF、objdump、运行 JSONL、parsed trace、独立 binding/manifest 全部在该 ignored workspace。每个 run 目录的 `1/` 和 `2/` 是真实重复执行。

| evaluation-only 引用 | 中性 run ID | 第一次执行 manifest（相对工作区） |
|---|---|---|
| R-P1 / N2 | `run:1106ad753d8958d449c56a48062fa0d7c42dca7c836ef0597b90d72853d5a56c` | `runs/1106ad753d8958d449c56a48062fa0d7c42dca7c836ef0597b90d72853d5a56c/1/manifest.json` |
| V-P1 | `run:4c2819eee21c0b55b475715dd790fabb5350636d7edd849e6a21118704e686c5` | `runs/4c2819eee21c0b55b475715dd790fabb5350636d7edd849e6a21118704e686c5/1/manifest.json` |
| R-N1 | `run:ed1ec620205ae4c3505f887071a37e13b9eabb23c69b727f8945f56452d03a94` | `runs/ed1ec620205ae4c3505f887071a37e13b9eabb23c69b727f8945f56452d03a94/1/manifest.json` |
| V-N1 | `run:824f01d3a590b7fd73c262a07f8b1e632af365645a7c1acc4ee89fd7e4d5a47f` | `runs/824f01d3a590b7fd73c262a07f8b1e632af365645a7c1acc4ee89fd7e4d5a47f/1/manifest.json` |

| 身份对象 | SHA-256 |
|---|---|
| frozen source-tree | `030425ba50863f72ccf05051d35c198811d5248be1f79c3ce5d430968a315c5d` |
| common integration patch | `741dbd77474202318f3f0344f7fc947f07ac236c29f2aa7408d9f610c7f1d1bb` |
| variant patch | `acd5a0b8eebe1bf47f739a82ce212d605df01a17ecbabf598db7c312d3d86272` |
| Reference source-tree | `f882b80ccd16c9de7828b399196f079ee3b982e43fc54784c3f6e015430f4e1b` |
| Variant source-tree | `805480e150a838026c0b47dfe375a0548064381a4b175d79f9ea6bf02089b440` |
| COMMAND 0xA5 ELF | `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641` |
| COMMAND 0xA4 ELF | `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920` |

Tree identity 算法：递归列举所有普通文件（拒绝 symlink），以相对路径为 key、文件 SHA-256 为 value，按 key 排序的紧凑 JSON UTF-8 编码（无末尾换行）再取 SHA-256。原 pinned tree 共 3693 个文件。SHA 绑定实际本地冻结树，而不只绑定 upstream commit 名称；上游来源仍为 `405c6d1d8220a18b2f9196141167a5875422dee4`。

每个 manifest 的 `identity_inputs` 记录 firmware/source/input/base-tree/RTL-tree/common-patch/variant-patch/simulator/build-recipe/apparatus-source 身份。`run_case_neutral_id` 是这些输入的规范化内容摘要。`build_recipe_sha256` 关联同目录的完整 `build-recipe.json`，其中含工具、19 个配置项、编译选项、时钟、reset 和 runtime seed。manifest 另存 raw trace、parsed trace、stdout/stderr hashes、normal exit、trace complete；`trace-binding.json` 独立绑定 run、ELF、RTL、raw 和 parsed。

文件字节 hash 和规范化 JSON 内容 hash 是不同字段约定：raw/stdout/stderr/ELF/simulator 是文件字节 hash；parsed trace 和 build recipe 是规范化内容 hash（不计末尾换行）。validator 从内容重算这些身份，不从文件名猜测。

## 装置结构和确定性边界

只新增 7 个候选 tracked 文件，尚未执行 git add：

1. `experiments/syn_e2e1/synthetic_mmio.sv`：公共外设及只读 monitor。
2. `experiments/syn_e2e1/firmware.S`：两个 command immediate 共用的 RV32 汇编源码。
3. `experiments/syn_e2e1/integrate.patch`：只用于 verified disposable copy 的公共集成。
4. `experiments/syn_e2e1/variant.patch`：唯一 STATUS next-state delta。
5. `experiments/syn_e2e1/run.py`：显式离线构建/运行、严格解析、绑定与有限范围对照。
6. `tests/integration/test_syn_e2e1_apparatus.py`：快速对抗测试和 opt-in 真实验收。
7. `docs/research/v3-syn-e2e1-a-apparatus.md`：本文件。

没有修改原有 tracked 文件、production schema、agent、prompt、workflow、matcher、README 或 CURRENT_STATE。没有把整个 Ibex source tree、ELF 或真实 trace 加入 Git。

### 公共集成与 Variant

Common patch 仅改变 disposable wrapper 的 device enum/count、地址表、外设连线与 core fileset。为兼容 pinned Verilator，reset 声明周围有具名 `SYNCASYNCNET` 局部 lint 注释；monitor 内用 `BLKSEQ` 局部注释允许 testbench 计数器的阻塞赋值。它们在两侧完全相同，不改变科学变量。

| 设备 | Base | Mask | 窗口 |
|---|---|---|---|
| RAM | `0x00100000` | `0xFFF00000` | `0x00100000–0x001FFFFF` |
| SimCtrl | `0x00020000` | `0xFFFFFC00` | `0x00020000–0x000203FF` |
| Timer | `0x00030000` | `0xFFFFFC00` | `0x00030000–0x000303FF` |
| SyntheticPeripheral | `0x00040000` | `0xFFFFFC00` | `0x00040000–0x000403FF` |

Runner 从两侧**实际 Verilator elaboration XML**读取地址表、`NrDevices=4` 和 `u_synthetic_mmio` 实例，检查窗口只出现一次、无重叠；19 个配置参数值均与冻结 small 配置核对，两侧全部顶层参数及 map 还必须相同。

根据 pinned `shared/rtl/bus.sv` 的实现，路由到外设的 `device_req` 就是本次选中的被接受请求，host grant 对该选择组合产生。单一 CoreD host、该外设无额外 ready，因此监控的是 device 边界 req，而非未经接受的 CPU 意图。外设在接受请求的上升沿设置响应寄存器，monitor 在**下一上升沿的 pre-NBA**记录响应，事务延迟恰为 1 cycle。

所有访问要求 32-bit aligned 且 `be=0xF`。ENABLE/COMMAND 可读写，STATUS 只读。非法 partial、unaligned、unknown register、STATUS write 都返回 error 且不改变三个状态寄存器。直接 RTL 单元仿真检查上述行为，也检查 partial read 被拒绝。

异步 active-low reset 清零 ENABLE/COMMAND/STATUS 和响应寄存器。Variant 使用 nonblocking assignment：合法 COMMAND 写入时检查**接受该写入之前的 `enable_q`** 与本次 `wdata_i`，满足规定条件才设置 STATUS；此后保持，直到 reset。Reference STATUS 只在 reset 清零，没有其它写入。

两个完整树逐文件比较，仅 `examples/simple_system/rtl/synthetic_mmio.sv` 不同；将 reviewed `variant.patch` 重新应用到 Reference 文件后必须与 Variant 字节相同。patch 只把占位注释替换成三行条件/赋值。monitor 后半段还单独比较字节一致；没有修改 decode、interface、reset、firmware、harness 或 flags。

### Monitor 和完整性

Header：`syn-mmio-trace/v1`；event：`syn-mmio-event/v1`；footer：`syn-mmio-footer/v1`。JSONL 使用固定单一格式字符串以兼容 Verilator 4.210。event 具有 sequence、cycle、reset_epoch、transaction_id、phase、address/we/be/wdata/rdata/error、req/resp valid、reset_n、ENABLE/COMMAND/STATUS 值。无期望值、验收标签或结论字段。

`request`/`response` 在 posedge pre-NBA 记录；`status_sample` 固定在该 cycle 的后续 negedge，因此采到本周期 NBA 完成后的稳定状态。不能根据 `$display` 的源代码排列推断 post-state。reset assertion/release、SimCtrl stop 和固定 RAM result_slot 写入也客观记录。

Parser 拒绝重复 JSON key、额外字段、非整数/非法位值、重复或缺失 sequence、重复事务 ID、无请求响应、未完成请求、错误响应延迟、元数据不匹配、异常 reset epoch、缺失 footer、截断和缺失状态样本。当前 apparatus 只接受一次 reset epoch 的固定 schedule，不宣称支持任意多次复位。

footer 由 monitor 的 `final` 输出，要求已观察到 software stop 且至少过去两拍、无 pending transaction、非 reset。Runner 还要求 subprocess 成功返回、真实 SimCtrl stop 和 Verilog `$finish` 输出、无 timeout；解析要求 footer 计数与实际事件一致，并覆盖 release 到最后完成周期之前的每个状态采样点。单凭“没看到 DEAD”不构成任何通过结论。

### 编译固件与工具

`firmware.S` 关闭压缩和 relaxation；GCC 使用 `-march=rv32imc -mabi=ilp32 -nostdlib -nostartfiles -Wl,--build-id=none`。自定义最小 linker script 固定入口 `0x100080`、result_slot `0x101000`，记录其 SHA。两份源码相同，只有显式 `COMMAND_VALUE` 不同；每份 ELF 独立编译两次并校验字节相同。P1 pair 共用同一个 ELF 文件。

ELF 检查实测为 ELF32、RISC-V、little endian；bounded decoder 直接解析入口 12 条实际指令、跟踪已知寄存器常量，并确认访问地址顺序。原始 objdump 同时保存，未把指令存在当作运行时事件。

| site | PC | 指令字节（文件顺序） | 解析出的访问 |
|---|---|---|---|
| enable_site | `0x100088` | `23a06200` | 32-bit write `0x40000`, value 1 |
| command_site | `0x100090` | `23a26200` | 32-bit write `0x40004`, value 0xA5/0xA4 |
| status_site | `0x100094` | `83a38200` | 32-bit read `0x40008` |
| result_site | `0x1000A0` | `23207e00` | 32-bit write `0x101000`, loaded value |
| normal exit | `0x1000AC` | `23a46200` | 32-bit write `0x20008`, value 1 |

COMMAND 常量的实际 ADDI 位于 `0x10008C`：字节分别 `1303500a` / `1303400a`。上述检查只适用于这个有界装置程序，尚未形成通用 MMIO deterministic producer。

本机工具：GCC `10.2.0`（lowrisc-20220210-1）、FuseSoC `2.4.3`、Verilator `4.210 2021-07-07 rev v4.210`。启动文件 hash 在 `tool-identities.json`。沿用本地 vendored dependencies 与 libelf-0.186，没有下载源码/依赖。运行时显式 `seed=1, rand-reset=0`；reset 延迟 2 cycles、持续 2 cycles。

DATA1A BaseIsa metadata shim 已包含在 SHA-pinned tree 中，未再次改写历史源文件。shim 全文保存在冻结 `docs/research/data1/ibex-simple-system-baseline.json` 的 `compatibility_shim.diff`；delta SHA 为 `2e69217b12c796389c2962ecf83973a08d69bf0fb11c0b78348ee2d81cd03dd7`，文件 SHA 为 `30bdeae59709fb25d75c1caee2b7b94bea20022f39f7a3e3cbde322d51455bac`。原因是 wrapper 消费 `BASE_ISA` 宏，BaseIsa 元数据须正确传递。两侧完全共用，不作为 RTL 科学变量。

### 重复性、离线策略和失败保留

除正式工作区外，`experiment-u95o8ghs` 也完整通过了四组各两次的 Ibex 实验。两个独立 workspace 的 source-tree、ELF、controlled patch、build recipe identities 和四组 parsed traces 均一致。**编译后的 simulator executable hashes 不同**，逐份真实记录；没有宣称编译器输出 bit-for-bit 可复现，也没有用 source hash 替代 binary hash。因此跨工作区中性 run ID 可以不同。每个工作区内同一输入的两个实际运行仍绑定同一 executable。

Runner 不读取 `.env`；子进程只收到显式白名单环境。FuseSoC 使用本地 source 和独立 cache/config，Python socket connect/DNS 被拒绝，git/curl/wget/ssh/pip 被离线拒绝 wrapper 覆盖。本轮无网络请求、无 LLM 调用、无 fuzz、无 Ghidra/angr。这个防护不是操作系统级网络沙箱；不对任意外部工具代码作更强保证。

保留了三个开发失败工作区（不覆盖、不伪造成功）：

- `experiment-jlvyd3hp`：新 monitor 的 WIDTH/BLKSEQ/SYNCASYNCNET lint 失败。修正句柄判断并使用两侧相同的局部 lint 注释。
- `experiment-xjsstkdi`：实际 build 已通过，elaboration reader 漏读 `localparam NrDevices`。修正为读取 param/localparam。
- `experiment-lzdogbz7`：真实 firmware 正常退出，但 Verilator 把拼接格式字符串当作数值，严格 parser 拒绝非 JSONL 输出。改用单一 literal 后从头重建、重新仿真。

这些失败由本轮实现问题导致；pinned 工具实际可用。每个失败目录保留 `blocked.json` 和原始日志，没有将失败输出修补成证据。正式验收采用重新生成的工作区。

## 验证命令与结果

真实集成（包括 8 次 Ibex 仿真、两份 ELF 各重编一次、两侧直接 RTL 协议测试）：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 CHIPCHAIN_SYN_E2E1_REAL=1 .venv/bin/pytest -q -s tests/integration/test_syn_e2e1_apparatus.py -k real_offline
```

记录结果：`1 passed, 26 deselected in 43.51s`。随后仅补充两个快速 parser 拒绝测试；当前快速测试为 `28 passed, 1 deselected in 1.09s`，没有改变实际装置实现。直接 RTL 测试两侧均输出 `RTL unit protocol checks passed`。默认 full pytest 不会重复昂贵仿真，opt-in 缺失则跳过。

独立使用 runner：

```bash
.venv/bin/python experiments/syn_e2e1/run.py --run
```

该命令只收集/验证客观装置记录，不载入 tests 中的验收期望值。真实 test 在 runner 返回后单独评价要求的数值；直接 RTL 单元 harness 的期望参数也只在 tests 侧。

完整回归及保护检查结果见下表 59–64。没有执行 git add、commit、push 或 tag。

## 70 项完成核对

| # | 核对项 | 回答 |
|---:|---|---|
| 1 | 起始 HEAD/tag | main；`9bbb05154a3aef3efcfc3662e646c6100c3c0cb0`；`v3-r2a-syn-e2e1-design-stable`。HEAD/tag 保持。 |
| 2 | 文件 | 上述 7 个新增文件；没有修改现有文件。 |
| 3 | src/chipchain | 未修改。 |
| 4 | 现有 tests | 未修改，只增加一个测试文件。 |
| 5 | pinned Ibex source | 未修改；源树 hash 前后匹配。 |
| 6 | 实验 tracked 文件总数 | 7 个候选文件，均未 stage；当前 Git tracked 数仍为 285。 |
| 7 | disposable workspace | `output/syn-e2e1-a/experiment-tn2kt3tu/`。 |
| 8 | pinned source identity | 见身份表，`030425ba…5d`，3693 个文件的完整 manifest。 |
| 9 | integration SHA | `741dbd77…1bb`，完整值见身份表。 |
| 10 | variant SHA | `acd5a0b8…272`，完整值见身份表。 |
| 11 | 两侧 tree identities | `f882b80c…e1b` / `805480e1…440`；完整值见身份表。 |
| 12 | 实际 diff | 仅 disposable `synthetic_mmio.sv` 的 STATUS next-state 片段。 |
| 13 | 唯一 semantic delta | 是；按 reviewed patch 重放逐字节检查。 |
| 14 | 地址表 | ENABLE=0x40000、COMMAND=0x40004、STATUS=0x40008；window 0x40000–0x403ff。 |
| 15 | elaboration 无冲突 | 两侧 XML 核验 4 devices、map 无重叠、synthetic window 唯一、实例存在和配置相同。 |
| 16 | 协议 | device_req 接受，next-posedge response；每个事务实测延迟 1 cycle。 |
| 17 | 非法访问 | error；状态不变；两侧真实直接 RTL 单元测试通过。 |
| 18 | reset | active-low async 清零，固定 delay=2/duration=2；真实 trace epoch 1、cycle 3–4 reset。 |
| 19 | STATUS sampling | posedge 接受并 NBA 更新，后续 negedge 采 stable post-state。 |
| 20 | firmware source | 共用 `experiments/syn_e2e1/firmware.S`；显式 COMMAND_VALUE define。 |
| 21 | P1 ELF SHA | `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641`。 |
| 22 | P1 是否同一 ELF | 是，同一个路径与完全相同字节 SHA。 |
| 23 | N1 ELF SHA | `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920`。 |
| 24 | 指令/site 核验 | 从 ELF bytes 有界解码，确认 0x40000/04/08、RAM 和 stop 地址；site/encoding 见上表和 inspection JSON。 |
| 25 | compiler | RISC-V GCC 10.2.0；启动文件 hash 记录于 tool-identities.json。 |
| 26 | FuseSoC | 2.4.3；本地固定路径，记录 hash。 |
| 27 | Verilator | 4.210，rev v4.210；记录 hash。 |
| 28 | shim | 使用已嵌入冻结源树的公共 DATA1A shim。 |
| 29 | shim hash/理由 | 上文给出全文位置、delta/file SHA；处理 BaseIsa/BASE_ISA build metadata。 |
| 30 | monitor 相同 | 是，Reference/Variant 字节相同。 |
| 31 | raw schema | 严格 versioned JSONL header/event/footer，原始事实字段，无 oracle。 |
| 32 | 完整性 | footer + count/window/pending/reset 检查 + 实际进程正常退出及 `$finish`。 |
| 33 | matching | monotonic unique transaction ID，metadata/epoch 相同，响应 cycle=request+1。 |
| 34 | reset epoch | assertion 单调递增，release 成对，当前仅接受一次固定 epoch。 |
| 35 | R-P1 ENABLE | cycle 11，事务 1，0x40000/be=F/wdata=1，cycle 12 error=0。 |
| 36 | R-P1 COMMAND | cycle 14，事务 2，0x40004/be=F/wdata=A5，cycle 15 error=0。 |
| 37 | R-P1 STATUS | cycle 14 post-state=0；cycle 17 read=0；全部状态样本为 0。 |
| 38 | V-P1 ENABLE | 同 R-P1 的真实请求/响应值和周期。 |
| 39 | V-P1 COMMAND | 同 R-P1；COMMAND 接受前 enable_value=1。 |
| 40 | V-P1 STATUS | cycle 14 negedge=DEAD，cycle 17 read=DEAD，cycle 20 RAM=DEAD。 |
| 41 | R-N1 | COMMAND=A4，完整窗口 STATUS=0，read/RAM=0，正常完成。 |
| 42 | V-N1 | 同样 COMMAND=A4，完整窗口 STATUS=0，read/RAM=0，正常完成。 |
| 43 | P1 相同输入 | ELF/source/input/base/common/variant patch身份、recipe/tools/config/reset/seed/monitor。 |
| 44 | 按预期不同 | 两侧 RTL tree 和 simulator executable；更新后的 STATUS、read response、RAM result。 |
| 45 | 首次差异 | cycle 14，sequence 16，status_sample.status_value：0→DEAD。 |
| 46 | 是否全 RTL 首次差异 | 否，只声明上述监控域。 |
| 47 | U1 missing binding | 删除 run/RTL 绑定后 INVALID_BINDING；不利用 DEAD、兄弟运行或文件名恢复。 |
| 48 | incomplete | malformed/truncated/footer/status sample/normal-exit 缺失等拒绝；不评价为 N1 通过。 |
| 49 | unexpected diff | unrelated 文件变化或 peripheral 内非 reviewed delta 均拒绝。 |
| 50 | GT input | 未创建；期望只在 tests/本文 evaluation-only 说明。 |
| 51 | runner labels | 无 P1/N1/N2/positive/negative 标签输入；neutral content-derived IDs。 |
| 52 | FirmwareCapability | 未创建。 |
| 53 | XL2 新 positive | 未运行、未产生。 |
| 54 | TriggerSatisfactionResult | 未创建。 |
| 55 | DeviationVerificationResult | 未创建。 |
| 56 | attack chain | 未创建、未声称。 |
| 57 | fast tests | 新增 28 个快速测试用例，覆盖 source/patch/map、parser、binding、controlled differential 和对抗拒绝。 |
| 58 | real test | 上述 opt-in 命令；`1 passed, 26 deselected in 43.51s`，其中 8 次真实 Ibex 仿真、2 次直接 RTL 仿真。 |
| 59 | full pytest | `CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q` → **1386 passed, 28 skipped in 29.54s**。 |
| 60 | pip check | `No broken requirements found.`，exit 0。 |
| 61 | compileall | `.venv/bin/python -m compileall -q src tests experiments`，exit 0。 |
| 62 | diff check | `git diff --check`，exit 0；新增源码/文档另查 trailing whitespace；patch 中空 context 行的单个空格保留 unified diff 语法。 |
| 63 | historical hashes | 285 个原 tracked 文件、4074 个既有 samples/output 文件逐一 SHA-256 未变；HEAD 和所有 tags 未变。 |
| 64 | real XL2 UNKNOWN | 离线 parse/compare/replay 后序列化与冻结结果逐字节相同；`xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded`，overall `unknown`。 |
| 65 | 客观证明 | 真实固件发出并完成指定 MMIO 事务；受控外设在指定条件下发生可重复、来源绑定完整的状态/读回差异。 |
| 66 | 尚不能证明 | 通用 firmware MMIO capability、真实处理器漏洞、固件可达性普遍性质、trigger canonical verification、完整跨层链。 |
| 67 | 下一步 producer | 从 ELF/受绑定 runtime trace 产出中性 MMIO access facts，区分 compiled site 与 actual accepted event，保存 widths/value knowledge/epoch/order/binding。 |
| 68 | 建议 SYN-E2E1-B | 建议在人工审核本阶段后进入；本阶段只完成装置。 |
| 69 | 最小 proposal | 只支持此程序的已知常量 LUI/ADDI/LW/SW 与本 trace schema；严格绑定 ELF、site、run、RTL；缺少绑定/完整性则 unknown；不改 XL2、不接 LLM、不直接输出 chain。设计事实契约后再评估何时接 CAP0。 |
| 70 | 不执行下一阶段 | 已停止在 SYN-E2E1-A；未实现 B 的 producer 或 matcher。 |
