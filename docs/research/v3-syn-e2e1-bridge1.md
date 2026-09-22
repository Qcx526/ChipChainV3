# SYN-E2E1-BRIDGE1：来源绑定的 PC ↔ MMIO 执行桥

## 验收者先读这里

本阶段完成了四次新的真实 Ibex 仿真，每次有三个 MMIO 指令与三个已完成设备事务建立确定对应：**共 12 BOUND，0 UNKNOWN，0 NOT_SAME**。

这意味着：现在可以从固件中的一个具体指令地址，沿着同一次运行的处理器记录，找到它对应的设备总线事务。此前只有静态指令和总线日志，中间缺少可复核的处理器证据，所以旧 B1 的 12 条结果仍然保持 UNKNOWN。

这一步只证明“这条指令产生了这笔事务”。它不判断硬件触发条件是否满足，不把 `0xDEAD` 解释为异常或漏洞，也不构造跨层攻击链。范围仅限当前冻结的单 CoreD Ibex controlled apparatus。

| 运行（仅验收标签） | 目标静态 / 处理器 / 总线数量 | COMMAND 实测写值 | STATUS 实测读值 | BOUND / UNKNOWN / NOT_SAME |
|---|---|---|---|---|
| P1 / A5 + Reference | 3 / 3 / 3 | `0xA5` | `0` | 3 / 0 / 0 |
| P1 / A5 + Variant | 3 / 3 / 3 | `0xA5` | `0xDEAD` | 3 / 0 / 0 |
| N1 / A4 + Reference | 3 / 3 / 3 | `0xA4` | `0` | 3 / 0 / 0 |
| N1 / A4 + Variant | 3 / 3 / 3 | `0xA4` | `0` | 3 / 0 / 0 |

每次运行建立的对应均为：`0x100088 → WRITE 0x40000 = 1`、`0x100090 → WRITE 0x40004 = A5/A4`、`0x100094 → READ 0x40008`。这些 PC/数值只用于结果评价，没有作为生产算法的预期映射。N1 的 A4 也是真实执行，因此同样 BOUND；其是否满足未来触发条件是另一个问题。

## 可直接打开的本地结果

所有原始日志和派生结果位于被 Git 忽略的 `output/syn-e2e1-bridge1/joint-e358hh72/`。以下链接依赖本机工作区，未把运行结果作为 fixture 提交。

- P1 / A5 + Reference：[中文报告](../../output/syn-e2e1-bridge1/joint-e358hh72/23a0dd00244e84db88975c32521db8aba297cd1a1aa96761480de3770844e22d/report-bridge1-zh.md)、[joint run](../../output/syn-e2e1-bridge1/joint-e358hh72/23a0dd00244e84db88975c32521db8aba297cd1a1aa96761480de3770844e22d/joint-run.json)、[执行桥](../../output/syn-e2e1-bridge1/joint-e358hh72/23a0dd00244e84db88975c32521db8aba297cd1a1aa96761480de3770844e22d/execution-bridges.json)。

- P1 / A5 + Variant：[中文报告](../../output/syn-e2e1-bridge1/joint-e358hh72/b6bc3e5db8117977e92da6e7a0145f7d45fce172984358b7cac9c5e975e197de/report-bridge1-zh.md)、[joint run](../../output/syn-e2e1-bridge1/joint-e358hh72/b6bc3e5db8117977e92da6e7a0145f7d45fce172984358b7cac9c5e975e197de/joint-run.json)、[执行桥](../../output/syn-e2e1-bridge1/joint-e358hh72/b6bc3e5db8117977e92da6e7a0145f7d45fce172984358b7cac9c5e975e197de/execution-bridges.json)。

- N1 / A4 + Reference：[中文报告](../../output/syn-e2e1-bridge1/joint-e358hh72/13a5fb2663a187808e054177d6128dabaf00856ecbb3392a0883efc22eac3455/report-bridge1-zh.md)、[joint run](../../output/syn-e2e1-bridge1/joint-e358hh72/13a5fb2663a187808e054177d6128dabaf00856ecbb3392a0883efc22eac3455/joint-run.json)、[执行桥](../../output/syn-e2e1-bridge1/joint-e358hh72/13a5fb2663a187808e054177d6128dabaf00856ecbb3392a0883efc22eac3455/execution-bridges.json)。

- N1 / A4 + Variant：[中文报告](../../output/syn-e2e1-bridge1/joint-e358hh72/1cc6d619f93fbb08ee572f42ea4c0296370ee16092dce9a5fd68500e5e3d1d3e/report-bridge1-zh.md)、[joint run](../../output/syn-e2e1-bridge1/joint-e358hh72/1cc6d619f93fbb08ee572f42ea4c0296370ee16092dce9a5fd68500e5e3d1d3e/joint-run.json)、[执行桥](../../output/syn-e2e1-bridge1/joint-e358hh72/1cc6d619f93fbb08ee572f42ea4c0296370ee16092dce9a5fd68500e5e3d1d3e/execution-bridges.json)。

每个运行目录还包含 `trace_core_00000000.log`、`synthetic-mmio.jsonl`、`process.stdout.log`、`process.stderr.log`、`parsed-bus-trace.json`、`processor-observations.json`、`static-mmio.json`、`runtime-mmio.json` 和本地运行命令。顶层 `local-reproduction-manifest.json` 索引四次运行及 collection 时的代码 SHA。

## 基线与文件边界

起始及结束均为 `main` / `caf786eb5fd879a612e745f5a6b05f440477bae9`，B1 标签为 `v3-syn-e2e1-b1-mmio-grounding-stable`。A / CAP0 / XL1 / XL2 分别保持 `v3-syn-e2e1-a-apparatus-stable`、`v3-fw-cap0-stable`、`v3-xl1-stable`、`v3-xl2-stable`。

仅新增以下五个文件，原有 tracked 文件没有修改：

- [确定性模型、parser、materializer、匹配及中文渲染](../../src/chipchain/firmware/mmio_execution_bridge.py)
- [显式四次运行的 collector](../../experiments/syn_e2e1/bridge_run.py)
- [合成单元测试](../../tests/unit/test_firmware_mmio_execution_bridge.py)
- [真实运行与只读重放测试](../../tests/integration/test_syn_e2e1_bridge1.py)
- 本文。

没有改动 `mmio_grounding.py`、冻结 A runner、固件、外设、bus monitor、旧 manifest 或旧 preview。没有重新 FuseSoC / Verilator build。新 runner 调用冻结 B1 API，并在**新目录**创建明确命名的 B1 compatibility projection，以复用严格的总线验证；该 projection 不代表旧 A 已采集了本次 processor attestation。继承的旧 apparatus/differential 元数据不进入新的 scientific identity。

## 证据链及完整性

```text
实际 ELF bytes → StaticMmioAccessFact
                       ↕ ELF + PC + encoding + memory semantics
新进程的 RVFI text → ProcessorMemoryObservation
                       ↕ 同一个 joint run + 完整语义唯一双射
新进程的 bus JSONL → accepted request / completed response
                       ↓
              AttestedMmioExecutionBinding
```

运行前校验 base tree、两棵 RTL tree、ELF、模拟器、build recipe、software input 和 runtime options，四组都通过后才启动进程；每次运行结束再核验输入。固定选项为 `+verilator+seed+1 +verilator+rand+reset+0 --term-after-cycles=10000`。没有编译或插入 marker，没有调用网络、`.env`、LLM 或 Agent。

严格 parser 检查冻结 tracer 的完整 header、tab 分隔结构、每列语法、编码与 mnemonic 一致性、寄存器/地址/读写值关系及严格递增的模拟时间和 processor cycle。只接受本实验所需 LUI / ADDI / LW / SW。`trace_sequence` 是从实际行派生的零起点序号，并非 tracer 原生输出的 RVFI order。格式缺失、重复、不支持的 encoding、partial-store 问号记录、坏地址、坏值或截断均拒绝。

地址准确命名为 `rvfi_mem_addr_printed_as_PA`，来源是 tracer 的 `PA` 字段。文本没有输出数值 byte mask，因此 `byte_mask=null`、`mask_status=not_emitted_by_text_tracer`；32-bit 宽度由对齐 LW/SW 解码得到。processor-side 的全字访问约束来自已审查指令及平台，bus-side 必须实际 `byte_enable=15`，不会伪造观测 mask。

完整性规则为 `ibex-straight-line-entry-through-simctrl-stop/v1`：重新从 ELF 提取静态 catalog；12 行退休记录逐条覆盖 ELF 入口开始的直线指令前缀，PC/encoding 与真实 ELF bytes 完全一致；最后一行为 SimCtrl stop store，值 1，且与 bus software-stop 事件相符。冻结 B1 parser 检查 reset、完整目标窗口、request/response 和 footer，所有目标响应必须先于 stop。缺一条有效行也失败。原始 processor text 没有 footer，本实现没有给它虚构 footer；证明范围是**入口到 software-stop 的目标执行窗口**，不是所有末尾 CPU cycle。

平台证明绑定完整批准 RTL tree、实际 elaboration/map 配置及 reviewed source 文件。`NrHosts=1`，唯一 host 是 `CoreD`，CPU data port 接到该 host，取指走独立连接；目标外设没有 DMA 或第二个 bus master。配置还要求 `NrDevices=4`、`SecureIbex=0`、`WritebackStage=0`、`BaseIsa=0`。未审查 source/config 在入口 BLOCKED；缺少对应平台条件时匹配器返回 UNKNOWN。内容哈希提供可复核的本地来源绑定，不是对任意外部日志的硬件签名认证。

审查依据如下（SHA 固定于生产模块）：

| 文件 | 核对内容 | SHA256 |
|---|---|---|
| `rtl/ibex_tracer.sv` | header；Time/Cycle/PC/Insn；RVFI memory address/data；退休时记录 | `6241602443ec15517914fc3231e9c860229aea52dc571b5a94769a0510963925` |
| `rtl/ibex_core.sv` | LSU address/store、load writeback、word mask 语义 | `88b8bf3907472f1d413380f62234a7fbf53cb1de392a6660e6ef2d684a2416fd` |
| `shared/rtl/bus.sv` | host 到 device 的请求、grant 和 response 路径 | `b24c2cbe36cee25230c61d533258a66707ee03c7c3857cc97494c8d95a2a2953` |
| A 集成后的 `examples/simple_system/rtl/ibex_simple_system.sv` | CoreD 单 host / 目标外设连接 | `5e3ca1b92f450fde2b2f2bdaca73d68ba1aa4c47aa072c797adf2406430446e1` |

## 确定性匹配与身份

规则 `ibex-rvfi-bus-semantic-bijection/v1` 分两段：

1. Static → Processor：相同 ELF，比较 PC、encoding、operation、resolved address、width 和可解析的静态 write value。静态 READ 不比较运行时读值。字段冲突为 NOT_SAME；缺信息或多个候选为 UNKNOWN；错误 ELF 拒绝。
2. Processor → Bus：必须同一 joint run；比较 `(operation, address, width, byte enable, value)` 的完整签名，并在完整目标集合上要求唯一一对一双射。WRITE 比较 store value；本平台已核对 load writeback 语义，所以 READ 必须比较 processor load value 与 bus response read value。缺字段为 UNKNOWN_INSUFFICIENT，重复签名为 UNKNOWN_AMBIGUOUS，签名集合明确冲突为 NOT_SAME。

即使某地址唯一或只剩一个候选，也必须满足所有语义、平台、来源和完整性条件。两条相同 `WRITE 0x40004=A5` 对两笔相同事务仍为 UNKNOWN_AMBIGUOUS；不利用顺序强行消歧。不使用固定 cycle offset，也不按数组/table 顺序 zip。runner 对已校验输入记录的遍历不参与证据配对。

所有语义 ID 复用 B1 canonical JSON / SHA256 内容寻址，排除 ID 自身和明确的 collection 元数据。`JointRun` 使用 `joint-mmio-execution-run/v1`，`mmio-joint-run:<sha>` 绑定自身 ELF / RTL / simulator / input / execution context / 两种 trace SHA、完整性状态及平台 proof。它不绑定另一 run、参考/变体配对关系、标签、期望、目录或主机时间。

stdout/stderr 可能含 PID、主机 wall-time，所以单独放入 `CollectionAttestation`：其 ID 同时绑定 stdout/stderr 原始 SHA、return code 和本次 joint evidence digest。该对象嵌入 joint 文件，materializer 重读真实文件并逐项重建整个 joint，包括 collection；因此日志篡改会失败，但 PID 变化不改变语义 ID。完全相同科学输入与证据的重跑允许共享 semantic joint ID，具体采集来源由 collection attestation / 本地记录区分。

`ProcessorMemoryObservation` 的 `mmio-processor:<sha>` 包含 joint ID、firmware、trace artifact、PC/encoding、operation/address/width、mask 缺失说明、write/read value、派生序号及 processor cycle。Binding ID 包含两段状态、所选证据引用、joint ID 和规则版本。`BridgeSet` 内容寻址包含整套静态/运行时集合引用、platform/source evidence、观测及 bindings；只排除嵌套 collection。改变 rule version 会改变 binding ID 及集合身份。

materializer 不信任 manifest 中单独声明的 SHA：重读 ELF、两种 trace、stdout/stderr，重算 SHA、重新解析、重建 joint，与声明对象完全比较；runner 还校验实际 simulator 和 source tree。静态 READ 保持 `value=null`；同一 ELF 在 Reference/Variant 上静态 catalog 字节完全一致，`0xDEAD` 只属于运行时观测。

## 实际输入和结果身份

以下 P1/N1、Reference/Variant 仅作验收索引，生产接口接收实际内容身份，不接收 expected PC/transaction/outcome。

### P1 / A5 + Reference

| 字段 | 实际值 |
|---|---|
| `firmware_sha256` | `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641` |
| `rtl_tree_sha256` | `f882b80ccd16c9de7828b399196f079ee3b982e43fc54784c3f6e015430f4e1b` |
| `simulator_sha256` | `92348a7a075602e6299d59e0f854ac8117856c0480813356173e0a8f667f0196` |
| `bus_trace_sha256` | `7c2b4822bfed95f27046935e81b2ead796ef6c884d5483f56640aa2251d2d13c` |
| `processor_trace_sha256` | `3bf33502c710e859fdf7c046dbf5de5c209ebdfb54fda6262d50522e668d2d89` |
| `joint_run_id` | `mmio-joint-run:d713c57f0829e716556a750724b3c537fd47c4ca34df8963b12149b831edf3d6` |
| `collection.attestation_id` | `mmio-joint-collection:7997eb31a953af392d6889020887c069b39f320defe003b8029a4272aabc2116` |
| `collection.stdout_sha256` | `ab00b4f46a8a7a3b9d12baecd2cfa9d383c9873baf8bf69bf1e71241c988c6a5` |
| `collection.stderr_sha256` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `bridge_set_id` | `mmio-execution-bridges:c0e94c39906649cefbf394c888f75b54e86f9014283fbae07903aaf9f84815fe` |

### P1 / A5 + Variant

| 字段 | 实际值 |
|---|---|
| `firmware_sha256` | `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641` |
| `rtl_tree_sha256` | `805480e150a838026c0b47dfe375a0548064381a4b175d79f9ea6bf02089b440` |
| `simulator_sha256` | `e5c3cf4c5870c9c5f0ca9bbab501454e6bbf052e110f7f783d96ceb8a95d4b6c` |
| `bus_trace_sha256` | `cac0ee2e2f0aeb3f46b9483f9525a7589d8059fd7d176b8d47b7ce96ae3b87ad` |
| `processor_trace_sha256` | `0ef674ea688856664e04fcd154791193b7cfc924f478109deccd6ed7a26c014f` |
| `joint_run_id` | `mmio-joint-run:1282d94da83b1cf4ff2ea334fc31649a85b9328d40c3548314e672e83819f52c` |
| `collection.attestation_id` | `mmio-joint-collection:f76abc2c8728e27bacc6a7ac699698da47714bbf0fb0ea8d7c8daf4570cefc25` |
| `collection.stdout_sha256` | `4c80cace63a3dca311a1f34f16a604d95d05937683eff0dddd4d8ca6fa43fc51` |
| `collection.stderr_sha256` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `bridge_set_id` | `mmio-execution-bridges:020f787844c2543c6124c16b4d979ec01e5b09086c541ef3dd6a12c4f233f9c1` |

### N1 / A4 + Reference

| 字段 | 实际值 |
|---|---|
| `firmware_sha256` | `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920` |
| `rtl_tree_sha256` | `f882b80ccd16c9de7828b399196f079ee3b982e43fc54784c3f6e015430f4e1b` |
| `simulator_sha256` | `92348a7a075602e6299d59e0f854ac8117856c0480813356173e0a8f667f0196` |
| `bus_trace_sha256` | `adbb7b25d439876258ad3b62caaf601bfe4ab4753712d835c6bf3483132c1d41` |
| `processor_trace_sha256` | `202e2e8bd9c6615a1a7e934710ecd40ff3158b067646d0f508bebc9e930ce4a8` |
| `joint_run_id` | `mmio-joint-run:79975649fad83fae4d7a63ba6981223d728ee8ea2e0926ee1eee515de64266e6` |
| `collection.attestation_id` | `mmio-joint-collection:505a1789674cf760600732946bd07bf9d725da56a5e58f74dde562fc4419e2cc` |
| `collection.stdout_sha256` | `657dfd31a2da94165132b4e1160408f001c780dd447cde1f9e53a6554382416f` |
| `collection.stderr_sha256` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `bridge_set_id` | `mmio-execution-bridges:bd68a2f6ff6b2ce22a0144430dfe0b1b322c532b27f32639998af2c926265132` |

### N1 / A4 + Variant

| 字段 | 实际值 |
|---|---|
| `firmware_sha256` | `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920` |
| `rtl_tree_sha256` | `805480e150a838026c0b47dfe375a0548064381a4b175d79f9ea6bf02089b440` |
| `simulator_sha256` | `e5c3cf4c5870c9c5f0ca9bbab501454e6bbf052e110f7f783d96ceb8a95d4b6c` |
| `bus_trace_sha256` | `adbb7b25d439876258ad3b62caaf601bfe4ab4753712d835c6bf3483132c1d41` |
| `processor_trace_sha256` | `202e2e8bd9c6615a1a7e934710ecd40ff3158b067646d0f508bebc9e930ce4a8` |
| `joint_run_id` | `mmio-joint-run:cac2c2c743b089c650c8e15cc17f1c4f1187e566805832a49b47d4749b806fc9` |
| `collection.attestation_id` | `mmio-joint-collection:57e659dc3e928fa81819bbbc15de1aad7d37608620cf088f6ebb70b374511285` |
| `collection.stdout_sha256` | `a2c39b73f9bd4e3b7afdcab12a12604c295820c41f85fddfdd2621cfe6473d03` |
| `collection.stderr_sha256` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `bridge_set_id` | `mmio-execution-bridges:389593f43a85ac0578de4b6cb37c5fba3d7f0380244b07090af29c07853461c8` |

公共 build recipe SHA：`4807dacf3cf2ff3c901a8d31ee26fb91099e1fb41f05e95e849cfd202ebf3c91`。公共 software input SHA：`86b6b68191083af8b0f4ea28fd864af23a470a2a17341406a49ca440d718a681`。execution context SHA：`fca88e3a61f92b285e550884df31940af5827b15edfa916a53d0521c4ef6bf8e`。

N1 两份 trace 的字节恰好相同，但两次运行的 RTL / simulator identity 不同，因此 joint IDs 不同，不会互相混用。

## 验证记录

明确真实执行命令：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 CHIPCHAIN_BRIDGE1_REAL=1 .venv/bin/pytest -q -s tests/integration/test_syn_e2e1_bridge1.py -k new_real_joint
```

实际结果：`1 passed, 4 deselected in 12.97s`。它启动四个新的 simulator processes，build 0 次。

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q tests/unit/test_firmware_mmio_execution_bridge.py tests/integration/test_syn_e2e1_bridge1.py
```

最终代码只读重放及单元测试：`46 passed, 1 skipped in 9.71s`。42 项新增 unit cases；其余四项验证新四组结果精确重放、真实 processor 文件篡改拒绝、旧 B1 12 UNKNOWN、真实 XL2 UNKNOWN。默认 skip 的一项就是须显式启用的新 simulation，已经通过上面的独立真实执行。

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests experiments
git diff --check
```

结果：**`1486 passed, 29 skipped in 40.35s`**；pip：`No broken requirements found.`；compileall exit 0，无输出；diff check exit 0，无输出。新文件还单独进行 whitespace diff 检查（因为 `git diff --check` 默认不覆盖 untracked files）。

采集完成后补了一条负面结果的引用一致性约束：即使 Static→Processor 为 NOT_SAME，只要 Processor→Bus 是 BOUND，就必须保留两侧证据引用。没有改变正面匹配规则。采集时的 producer SHA 仍忠实保留为 `2bc5580e2941590e91e600170130b217ffe8c63a3ceaa7f887e8f4d82b9ff64b`；collector SHA 为 `bb90784d3e9e6b91e626273075c4eab37c0af51a09202e7ee9bc70ffab611c0a`。最终代码已重新解析真实文件并逐字节重放四份 BridgeSet 和中文报告，结果不变；没有改写采集元数据或增加 simulation。

历史保护核对：逐文件 SHA256 验证起始快照中的 **296 个 tracked 文件、62203 个原有 samples/output 文件，变化 0**；HEAD、全部 tags 和 main 分支保持不变。旧 B1 preview 的静态、运行时和绑定 JSON 逐字节重放一致；真实 XL2 的 `xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded` 保持 UNKNOWN。未执行 Git 写入操作。

## 80 项完成答复

| # | 验收问题 | 答复 |
|---|---|---|
| 1 | 起始 HEAD/tag | main / caf786eb5fd879a612e745f5a6b05f440477bae9；v3-syn-e2e1-b1-mmio-grounding-stable。 |
| 2 | 新增/修改文件 | 仅新增本文所列五个文件；已有文件修改 0。 |
| 3 | A 是否修改 | 否；runner、RTL、ELF、monitor、旧 output 均未修改。 |
| 4 | B1 是否修改 | 否；只 import 冻结 API。 |
| 5 | CAP0/XL1/XL2 是否修改 | 均否。 |
| 6 | 重新 build simulator | 0 次。 |
| 7 | 新的 simulation 次数 | 4 次；独立工作目录/进程。 |
| 8 | 冻结 ELF | 保持 A5 42fe38fb…、A4 d2d845e6…；完整 SHA 见实际输入表。 |
| 9 | 两个 simulator SHA | Reference 92348a7a…；Variant e5c3cf4c…；完整 SHA 见实际输入表。 |
| 10 | Joint run schema | joint-mmio-execution-run/v1。 |
| 11 | Joint run ID | mmio-joint-run + canonical SHA256；自身真实输入和两种 trace，collection 独立绑定。 |
| 12 | processor trace SHA | 已绑定，并从真实 bytes 重算核验。 |
| 13 | bus trace SHA | 已绑定，并复用 B1 严格解析/物化。 |
| 14 | stdout/stderr | 原始 SHA 在嵌入的 CollectionAttestation；独立 ID 与 joint evidence digest 交叉绑定并重放核验。 |
| 15 | processor schema | processor-memory-observation/v1；完整 pinned text grammar。 |
| 16 | parser fail closed | header/row/encoding/register/address/value/sequence/尾换行任一失败即拒绝；缺文件不反推 PC。 |
| 17 | processor completeness | ELF 入口至 SimCtrl stop 的连续直线退休前缀；12 行与 ELF bytes 一致；总线目标窗口完整且完成于 stop 前。 |
| 18 | ProcessorMemoryObservation 字段 | joint/fw/trace refs、派生序号、processor cycle、PC、encoding、operation、PA 地址、32-bit width、空 mask 及理由、write/read values。 |
| 19 | observation ID | mmio-processor + canonical SHA256，包含 joint 与 trace evidence，不包含 host path/标签。 |
| 20 | Static→Processor | 同 ELF + PC + encoding + operation + resolved address + width + 静态 write value；READ 不比较静态读值。 |
| 21 | Processor→Bus | 同 joint + 单 CoreD 平台 + 完整窗口 + op/address/width/be/value 唯一双射。 |
| 22 | 地址唯一性 | 不作为绑定依据；必须全语义一致。 |
| 23 | 表格顺序 | 不用于配对。 |
| 24 | 固定 cycle offset | 没有；不同计数原点不做 +3 推断。 |
| 25 | value | WRITE 必须相同，READ 也按已审查 RVFI writeback 语义比较。 |
| 26 | READ value | processor load 与 bus response 一致；不放入 static fact。 |
| 27 | order 唯一证据 | 没有；第一版不靠顺序消歧。 |
| 28 | ambiguity | 返回 unknown / UNKNOWN_AMBIGUOUS，无 mapping。 |
| 29 | duplicate-semantic case | 两个相同 WRITE 对两个相同事务：UNKNOWN_AMBIGUOUS。 |
| 30 | single candidate | 不会自动 BOUND；缺 value 等信息仍 UNKNOWN_INSUFFICIENT。 |
| 31 | 跨 run | 拒绝 CROSS_RUN_OBSERVATION / input binding mismatch。 |
| 32 | single-host 证明 | 批准整棵 RTL + reviewed wrapper/bus/core/tracer + elaborated NrHosts=1/CoreD 连接，无 DMA/第二 master。 |
| 33 | rule version | ibex-rvfi-bus-semantic-bijection/v1。 |
| 34 | bridge ID | canonical content SHA；含引用、joint、状态、规则版本；集合亦内容寻址。 |
| 35 | P1 Reference processor | 3 条目标事件：WRITE 1、WRITE A5、READ 0；PC 100088/100090/100094（十六进制）。 |
| 36 | P1 Reference bus | 3 笔 accepted/completed transactions，与前述 op/address/value 一致。 |
| 37 | P1 Reference bridge | 3 BOUND。 |
| 38 | P1 Variant processor | 3 条目标事件：WRITE 1、WRITE A5、READ DEAD。 |
| 39 | P1 Variant bridge | 3 BOUND。 |
| 40 | N1 Reference bridge | 3 BOUND，COMMAND=A4。 |
| 41 | N1 Variant bridge | 3 BOUND，COMMAND=A4。 |
| 42 | 每 run BOUND | 3；总计 12。 |
| 43 | UNKNOWN | 四个新 run 各 0；旧 B1 仍 12。 |
| 44 | NOT_SAME | 四个新 run 各 0。 |
| 45 | UNKNOWN 原因 | 新真实 run 无；防御分支覆盖 ambiguity、insufficient、platform 和 static unresolved/multiple candidate。 |
| 46 | static READ | value 仍为 null。 |
| 47 | DEAD 污染 static identity | 没有；同 ELF 的两份 static catalog 完全相同。 |
| 48 | A4 execution | BOUND，它确实执行并完成了对应事务。 |
| 49 | A4 trigger mismatch | 未评价。 |
| 50 | DEAD deviation | 未评价，只是 runtime read value。 |
| 51 | 旧 B1 12 UNKNOWN | 保留；测试重放和历史 hash 双重核对。 |
| 52 | 旧结果不回填 | 旧 A 没有本阶段 joint attestation；升级依据只来自新进程/新证据。 |
| 53 | real XL2 UNKNOWN | 保留，固定 compatibility ID 和只读重放一致。 |
| 54 | Ground Truth firewall | runner 读取冻结实际 artifacts/identities，不接收 expected PC/transaction/outcome；期望仅在测试评价。 |
| 55 | P1/N1 labels | 不进入 scientific IDs；本文和测试仅作结果索引。 |
| 56 | LLM calls | 0。 |
| 57 | Agent use | 0；无新增 Agent/workflow，未调用任何模型。 |
| 58 | FirmwareCapability | 未创建。 |
| 59 | Trigger result | 未创建。 |
| 60 | Deviation result | 未创建。 |
| 61 | attack chain | 未创建。 |
| 62 | unit tests | 42 个参数化 cases，覆盖语义冲突、解析/完整性、来源篡改、identity、规则版本及引用一致性。 |
| 63 | ambiguity adversarial | 重复完整语义 UNKNOWN；打乱顺序和修改 cycle 不改变完整语义匹配；缺字段的单候选 UNKNOWN。 |
| 64 | tamper tests | processor/bus/stdout/stderr/ELF bytes、fw/RTL/sim/input/context/processor SHA，以及真实 processor 文件副本篡改。 |
| 65 | real integration 命令 | 见验证记录；CHIPCHAIN_BRIDGE1_REAL=1，-k new_real_joint。 |
| 66 | real integration 结果 | 1 passed, 4 deselected in 12.97s。 |
| 67 | full pytest | 1486 passed, 29 skipped in 40.35s。 |
| 68 | pip check | No broken requirements found.（exit 0）。 |
| 69 | compileall | src tests experiments，exit 0，无输出。 |
| 70 | git diff check | exit 0，无输出；新增文件另检查 whitespace。 |
| 71 | historical hashes | 296 tracked + 62203 原有 samples/output 文件；SHA 变化 0。 |
| 72 | 能够证明 | 当前来源绑定运行中，具体静态 MMIO 指令与 processor event、accepted/completed bus transaction 的确定执行对应。 |
| 73 | 不能证明 | 硬件 trigger、deviation、漏洞、attack chain 或所有 RISC-V 平台的通用对应。 |
| 74 | 是否建议 B2 | 建议人工审核并冻结本阶段后再评审 B2 设计；本轮不执行。 |
| 75 | B2 最小 proposal | 设计只消费已验证 bridge 的 typed execution evidence / capability adapter，保留证据引用、scope 与 UNKNOWN；不修改 CAP0，不直接判 trigger。 |
| 76 | 先做 trigger verifier？ | 建议先审清 B2 typed execution/capability 接口；trigger verifier 独立定义前态、顺序、contract/revision 条件后另行授权。 |
| 77 | pruning gate | 仍关闭；本阶段未建立触发/差分/端到端证据，不满足删减旧链路的依据。 |
| 78 | 是否 pruning | 没有；未进入 R2-B。 |
| 79 | Git 操作 | 仅只读检查；未 add / commit / push / tag。 |
| 80 | 停止线 | 已停在 joint collection → processor observations → execution bridge；不进入 B2，等待人工审核。 |

## 下一步建议（未执行）

先审核四份中文报告和本页证据边界。通过后再确定 B2 的最小输入输出契约：哪些已 BOUND 的执行证据可以进入后续 capability 描述、哪些必须保留 UNKNOWN，以及如何继续引用 joint/static/processor/bus 来源。之后单独设计 trigger verifier。本阶段不开展上述实现，也不冻结或提交 Git。
