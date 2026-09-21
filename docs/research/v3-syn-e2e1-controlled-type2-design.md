# SYN-E2E1：受控 Type-II 跨层 Golden Chain 设计

状态：**DESIGN ONLY，未实现、未运行、没有 positive 实验结果。**
基线：`main / 6278fb7bf550d08b4976a5eeb444c70130a80c13 / v3-xl2-stable`。
本设计只服务于 synthetic / controlled / test-only / methodology-validation。

目标是在预先知道实验结果、但分析器看不到答案的条件下，检验：正常固件行为能否经确定性事实、能力、合同、兼容性、运行观测和受控差分，形成一条可以逐项验收的证据链。
它不证明真实 Ibex、真实 silicon 或公开 CVE 存在漏洞。第一版选择 Type II，不需要先构造或提取固件漏洞能力，不需要 LLM。

**当前完整 P1 仍被缺少的 producer、runtime verifier 和 XL2 的明确边界阻塞。**
不能拿现有 synthetic CSR 单元测试的 COMPATIBLE 代替系统级 Golden Chain。特别是保留完整 RTL revision / 外设状态条件后，冻结 XL2 对 P1 应继续 UNKNOWN。
本阶段没有把这些要求删除，也没有改变 matcher 来追求正例。
逐字段状态与源码哈希见 [gap matrix](v3-syn-e2e1-gap-matrix.json)。

## 1. 平台选择与本地证据

建议复用本地 **Ibex Simple System small 配置**，在新的受控实验副本中增加一个小外设。
不改 `samples/` 中的冻结基线，不覆盖 DATA1A 模拟器、hello_test ELF、历史 trace 或 blocked attempt。
无需另起完整处理器/总线框架：当前总线是一个 host、三个 devices，设备须在请求后一周期响应，足以支持三个 32 位寄存器。

本次只读调查的是仓库里的固定源码快照，不是对 upstream 最新版本的判断：

| 证据（相对 samples/hardware/ibex-simple-system/source/） | 查到的行为 / 未来接入点 |
|---|---|
| `examples/simple_system/rtl/ibex_simple_system.sv:79` | `bus_device_e` 有 Ram/SimCtrl/Timer，`NrDevices=3`；未来增加第四 device，2-bit enum 宽度仍足够 |
| 同文件 `:115` | base/mask 数组定义三个设备窗口；未来加 SyntheticPeripheral 一项 |
| 同文件 `:165`、`:319`、`:344`、`:359` | `u_bus`、RAM、simulator_ctrl、timer 的 req/we/be/addr/wdata/rvalid/rdata/err 接线；新增外设须遵循相同接口 |
| `shared/rtl/bus.sv:9`、`:84` | 下一周期响应假设；地址使用 `(addr & mask) == base`；host grant 不表示设备语义验证成功 |
| `examples/simple_system/ibex_simple_system_core.core:9` | HDL fileset 与 C++ harness 文件；将新外设和 monitor 加入新的实验构建，不能只复制源文件而不纳入 elaboration |
| `examples/simple_system/ibex_simple_system.cc:69` | harness 将顶层时钟/低有效 reset、RAM memutil 注册到 VerilatorSimCtrl |
| `vendor/lowrisc_ip/dv/verilator/simutil_verilator/cpp/verilator_sim_ctrl.cc:241` | 初始 reset 延迟 2 cycles、reset duration 2 cycles；未来显式固定并记录，不能只依赖环境默认值 |
| `examples/sw/simple_system/common/common.mk:33` | GCC、`rv32imc` / `ilp32`、freestanding、链接脚本和 crt0；可新增独立 test 程序复用这些构建基础 |
| `examples/sw/simple_system/common/link.ld:11` | 软件 RAM 从 `0x00100000`，stack 从 `0x00130000`；软件分配区小于硬件 1 MiB RAM 窗口 |
| `rtl/ibex_tracer.sv:170` | RVFI 文本部分显示 PA/store/load，byte/halfword 显示有 `?`；没有完整设备 req/response/err/reset 事务记录 |
| `src/chipchain/tools/paired/ibex.py:29`（项目根） | 现有 parser 只结构化 line/cycle/pc/encoding/mnemonic，内存部分仍 raw text；当前 `prepare_inputs` 仅选取少量记录，不是 MMIO producer |

源文件 SHA256 在 gap matrix 的 `source_evidence` 中。DATA1A 记录 upstream commit
`405c6d1d8220a18b2f9196141167a5875422dee4`，同时固定 small 配置和 BaseIsa 构建元数据 shim。
新的实验必须包含这套配置的身份与 elaboration 检查；加入外设后的 target 不能冒用旧
`ibex-simple-system:6e7ba1a16803af4942efe44ebcd65d853efd3c45d5bccf086a22bab6a20bdec2` 身份。
本次没有运行 FuseSoC、Verilator、GCC、Ghidra、angr、formal 或 fuzzing。

## 2. 寄存器和协议设计（尚未实现）

| 窗口 | 当前硬件解码范围 |
|---|---|
| SimCtrl | `0x00020000–0x000203ff` |
| Timer | `0x00030000–0x000303ff` |
| RAM | `0x00100000–0x001fffff` |
| 建议 synthetic peripheral | `0x00040000–0x000403ff`，mask=`0xfffffc00` |

四个窗口两两不相交；此结论仅适用于本次固定 Simple System map，不能扩展到其他 SoC。
还需未来 elaboration 后核对有效 decode 和正负访问测试。

| 寄存器 | 地址 | 访问 | 复位值 / 意义 |
|---|---|---|---|
| ENABLE | `0x00040000` | R/W，aligned 32-bit | 0；精确值 1 使能受控条件 |
| COMMAND | `0x00040004` | R/W，aligned 32-bit | 0；保存最后完整写入值 |
| STATUS | `0x00040008` | R/O，aligned 32-bit | 0；客观比较对象 |

提案限定合法完整 word 访问：`be=0xf`、地址 4-byte aligned。部分写、错误地址、STATUS 写都返回 error、不能改变状态；reference/variant 行为相同。
设备每次接收有效 request 后一周期给出 response；读请求采样对应状态并在响应时返回。
reset 清零全部寄存器，reset 期间不接受事务。后续 byte/halfword 支持不属于第一版。

- Reference：合法 ENABLE/COMMAND 写入按上述规则保存；STATUS 始终保持 `0x00000000`。
- Variant：唯一改变是合法 COMMAND 写入、其值等于 `0x000000a5` 且该次写入前 `ENABLE==1` 时，将 STATUS 置为 `0x0000dead`。
- STATUS 在下一次 reset 前保持；其他输入不改变 STATUS。实验每次均从同样 reset/内存初始化开始。
- ENABLE 写入事件、ENABLE 当前状态是两种不同事实。前者作为 trigger sequence 的第一步，后者在 COMMAND 时刻是状态 precondition；两者都保留。
- ENABLE 写入后被覆盖或发生 reset 时，不能仅凭 earlier-before-later 推断 trigger 成立。

Reference 和 Variant 都包含新增外设、相同总线接线、相同 monitor。共同平台扩展不算二者之间的 controlled difference。
二者间只允许一个局部 RTL 状态更新差异，未来保存 reviewed patch 和完整源树 manifest；不以不同编译选项/不同外设地址实现变体。

## 3. 固件、四个 case 与因果对照

第一版固件使用确定性的最小例程：依次写 ENABLE=1、写 COMMAND、读 STATUS，然后将读值保存到 RAM 中的 result slot 并正常退出。
读 STATUS 后不以其值选择不同代码路径，以减少除目标值之外的控制流差异。
未来可用极小汇编例程、或 volatile C + 编译后逐字节核验来保证受支持的 RV32 指令形式；本阶段未写两者。

P1 与 N2 **使用同一个 ELF SHA、同一输入、同一初始化与配置**。N1 可使用单个 COMMAND 立即数不同的独立 ELF，明确声明其与 P1 不构成单变量硬件因果对照；N1 的 reference companion 则使用 N1 自己的同一 ELF。
外部软件输入第一版为空/固定，固定 input manifest 的字节哈希；不能把“无输入”当缺失 identity。

| Case | 固件 / 硬件 | 实验 Ground Truth（未来验收期待，不是本次结果） | 方法链停止位置 |
|---|---|---|---|
| P1 | ENABLE=1，COMMAND=0xa5；Variant + 相同固件的 Reference companion | MMIO 要求兼容；真实请求顺序满足；Variant STATUS=0xdead，Reference=0；同源差分成立 | 仅 1–8 层全部建立才 verified controlled synthetic chain |
| N1 | COMMAND 改为 0xa4；Variant（及同固件 Reference companion） | 精确值与要求不符；真实 COMMAND 也不满足；完整观察窗口内 STATUS=0 | 在 compatibility 的 command-value requirement 或 runtime trigger gate 停止；不能把一次无偏差外推为硬件安全 |
| N2 | P1 原样固件；Reference | 固件行为和 trigger 序列发生；该次 reference 运行 STATUS=0，无受控偏差 | 第 6 层不成立；trigger satisfied ≠ deviation occurred；reference 偏差缺席仍是有效对照 |
| U1 | P1 分析输入的受控副本，删除 observation-to-run binding | 其余事实可保持；trace 值即使看起来为 0xdead，也无法绑定确切 run/RTL/config | 第 6/7 层 UNKNOWN，最终 UNKNOWN；不得猜测来源或从 GT 补齐 |

N2 不能把 variant-specific 合同错误地绑定给 reference target。未来 reference/variant 分别有准确的合同/目标绑定，使用相同 MMIO trigger 定义与 normative STATUS specification。reference 的偏差谓词是待检测条件，而非声称 reference 实际具有偏差。
P1/N2 可共享一次 reference 运行作为明确引用的对照，不能复制后伪装为独立试验。

当前冻结管线的诚实预测：完整合同的 P1/N2 compatibility 会因 revision/state 等缺口 UNKNOWN；N1 若全部必要固件原语都具有明确 exact 域，可以由明确 command 值冲突主导 INCOMPATIBLE；若 producer 还留有未知 alternative，则仍 UNKNOWN。
这些是设计层预测，不是已运行的四个 case。四个期望验收结果必须等 gap 解决后才能作为 pruning golden gate。

## 4. Ground Truth manifest 与 visibility firewall

未来 `controlled_ground_truth.json` 为 **evaluation-only**。本阶段只设计结构，不创建实际 manifest，也不填写虚假的 artifact SHA。
推荐最小结构如下；`null` 表示本阶段尚未构建，未来 evaluator 要求必需 identity 非空：

```json
{
  "schema_version": "controlled-ground-truth/v1-proposed",
  "synthetic": true,
  "controlled": true,
  "purpose": "test-only/methodology-validation",
  "cases": [{
    "case_id": "P1",
    "firmware_artifact": {"sha256": null},
    "software_input": {"sha256": null},
    "reference_rtl": {"source_tree_sha256": null},
    "variant_rtl": {"source_tree_sha256": null},
    "controlled_difference": {"patch_sha256": null, "allowed_component": "synthetic peripheral STATUS next-state"},
    "expected_firmware_behavior": ["ENABLE=1", "COMMAND=0xa5", "STATUS read"],
    "expected_trigger_requirements": ["same reset epoch", "ENABLE remains 1", "full-word COMMAND=0xa5 after ENABLE write"],
    "expected_deviation": {"reference_status": 0, "variant_status": 57005},
    "expected_observation": {"internal_status": "post-update value", "bus_status_read": "same value"},
    "expected_analysis_outcome": "verified_controlled_synthetic_cross_layer_chain"
  }]
}
```

N1/N2/U1 各自独立 entry，expected_outcome 分别是 trigger_not_satisfied、no_controlled_deviation、unknown；另记录预期停止层和该层理由。

数据隔离必须同时落实到读取接口和实验步骤：

1. 分析输入允许列表只有 artifact refs/哈希、平台规范/适用要求、ELF/RTL、运行配置与原始 trace。使用中性 analysis_case_id；P1/N1/N2/U1、positive/negative 等标签只存在 evaluator 映射。
2. Analyzer/matcher/Agent API 没有 GT 参数，不接收整个实验目录，不扫描 sibling files，不自动读取 `controlled_ground_truth.json`。未来 runner 将允许列表路径传入，GT 放在 evaluator 独立可见目录。
3. 分析产物先固定哈希；evaluator 才读取 GT，对实际 outcome/trace 等断言；expected fields 不回流到 fact producer、CAP、contract 或 verification result。
4. 测试更换 GT 标签/expected values 后，分析对象字节与 identity 必须不变，只有 evaluation result 可变化。去掉 GT 文件仍能完成分析。
5. 运行监控器记录原始请求/响应/STATUS，不直接输出 `P1_PASS`/`trigger_satisfied`/`deviation_verified`。这些由独立 verifier 按合同与证据计算。
6. 正常 STATUS 规范、已声明的硬件条件是科学输入；测试 case 的预期结局是 oracle。前者必须来自独立、可审阅的 specification/RTL 事实，不能由 GT 文件自动复制生成。

第一版若硬件合同由研究者显式 materialize，应标注 manual/controlled source、原文件哈希和逐字段来源；它验证消费合同的方法闭环，**不声称已经从未知 RTL 自动发现了 trigger/偏差**。
合成 source 可以含我们故意设计的语义，仍必须与 evaluator 的 case 标签/结果清单隔离。

## 5. 预期 typed 对象及 frozen schema 约束

### HardwareBehaviorContract（XL1-style，保留六部分）

| 部分 | 要求形态 |
|---|---|
| Platform | RISC-V/32/little、具体 controlled target platform_id、实际 rtl_identity/rtl_revision；引用源树/配置，不沿用旧 DATA1A ID |
| Preconditions | reset 已完成、COMMAND 接收前 ENABLE register state=1；独立 typed relation，并注明时间点/epoch 绑定需求 |
| Trigger | ENABLE word-write=1；COMMAND word-write=0xa5；OrderingTriggerAtom 的 endpoints 指向这两个 trigger condition IDs |
| Deviation | wrong_value，component=STATUS；expected STATUS=0，deviating STATUS=0xdead；specification_ref 必须绑定 normative spec 来源 |
| Observation | RTL_signal STATUS post-update + register/bus-visible STATUS read；比较谓词、backend 和 evidence requirement；关联 deviation ID |
| Scope | 指定实验 targets/revisions、controlled synthetic 来源、范围只到本外设和本配置；没有 silicon 适用性声明 |

reset/ENABLE 状态既不能借函数名推断，也不能为了让 matcher 通过而改叫 privilege/execution_context。
Ordering atom 不表达“中间没有覆盖写/reset”，这部分由真实状态和连续监控验证器承担。
Deviation/Observation 作为 requirements 存在时不意味着实际观测已发生。

### FirmwareCapability（CAP0）

- 语义 origin=`normal_behavior`；没有 finding_ids，不是 vulnerability_derived。
- MMIO_WRITE ENABLE、MMIO_WRITE COMMAND、MMIO_READ STATUS 三个独立 Primitive；exact address/value（写入）/width=32、ResourceConstraint(mmio)；读出的 STATUS 值不能从 expected oracle 写进能力。
- 拟议 deterministic producer 逐字节验证已编译 RV32 指令及有限常量传播、基本块内顺序，保留源 PC、ELF SHA、具体 derivation/evidence IDs。跨未知分支、未知寄存器值、无法绑定到目标 map 时输出 UNKNOWN，不声称任意固件全面支持。
- 一般使用 basis=`static_instruction`，不把 bus transaction 冒充 `RetirementEvidence`。运行事件属于独立 record；若显式引用退休，需要符合 A6 的 source-retirement 语义。
- ControlAuthority=`not_established`；本 Type-II 实验没有外部攻击者控制要求，不能从固定写值推导 attacker powers。
- 静态行为是进入有界例程后的条件行为。入口执行/路径条件未建立时保留 Condition/UNKNOWN；实际执行由后面的 runtime evidence 建立，不能为了 comparison 清空真实 conditions。

**两个 schema 陷阱：**

1. CAP0 `scope.applicability=synthetic_only` 要求 `origin.kind=synthetic_fixture`。本设计要表达正常固件行为，故采用 `normal_behavior + specified_firmware_sites`，HW 用明确 `specified_targets`；synthetic/controlled 标签放实验 manifest、source provenance、scope 限定与报告。不能填不合法组合，也不能利用少报适用性绕过 gate。
2. CAP0 `SourceKind` 和 `Provenance.transformation` 是封闭枚举，没有通用 `firmware_mmio`。最小 controlled prototype 可如实绑定 generated synthetic source（`synthetic_fixture`）与显式输入（`explicit_input`），单独保存 producer schema/version 和派生链；不能冒充 `firmware_a6`/`a6_partial_v1`。推广到真实 MMIO producer 若需新来源类型，须单独版本化设计，不能本轮修改 CAP0。

当前 `materialize_a6` 仅产 direct/indirect control transfer；Fuzzware MMIO configuration、普通 `mmio_access` IR 摘要、RVFI raw text 和 ELF instruction site 均不能直接当作上述完整 capability。
未来需要 **FirmwareMmioFactCatalog producer → 显式 CAP materializer**，此外还需独立 bus trace producer。

## 6. XL2 gap 与 P1 的诚实准入

| 要求 | 当前 producer/contract | 当前 matcher | 后续最小工作 |
|---|---|---|---|
| MMIO 资源/方向 | schema 已有；Ibex 自动 producer 无 | 支持明确 MMIO 枚举/资源/方向 | ELF 事实与 CAP materializer |
| 地址/值/宽度 | NumericConstraint / MMIOTriggerAtom 已有 | 支持 exact、FW range 包含 HW point、exact width | 保留缺失/不支持为 UNKNOWN；不以文本补值 |
| 平台 | 两侧 platform_id 已有 | exact gate 已有 | 新 controlled 平台构建与身份绑定 |
| RTL revision / ISA variant | XL1 已有，CAP0 缺对应字段/语义 | UNKNOWN | 单独评审版本化 applicability/binding verifier 与匹配接口 |
| ENABLE/reset 状态 | XL1 能表达要求；缺状态事实 producer | 该类型不支持；多原语 precondition context 也不支持 | 保留要求并新增有明确时间语义的 verifier，另审 compatibility 扩展 |
| Ordering | schema 已有；自动 MMIO producer 缺 | 只比较已唯一映射的端点及声明顺序 | 静态 producer + 独立 runtime order/state 检查 |
| path/entry/control | 现有 A6 只能部分表达 | 未建立的条件阻止 positive | 有界执行证据，作用域不扩张；不新增无根据控制要求 |
| Deviation/Observation | XL1 requirements 已有 | 下游未评估 | actual records + differential verifier |

本设计选择保留完整合同和 UNKNOWN，不提出“拿掉 revision/precondition 就算 golden success”。
之后若授权完整 SYN-E2E1 实现，应先审核新契约/验证层的语义边界；必要时使用**另一个明确版本的 matcher/适用性验证接口**，保留 XL2 v1 的原行为和回归。
单独的 runtime verifier 不能改写冻结 XL2 UNKNOWN 为 COMPATIBLE；总报告须并列保存原结果及新版本结果/各自输入身份。若审核不允许这些扩展，P1 只能保持阻塞，不能满足 pruning gate。

## 7. Runtime trigger evidence：选择外设 bus-event trace

现有 RVFI trace 有内存显示，但当前 parser 不结构化完整内存协议，不能证明外设接受了请求、响应无误或状态保持。
第一版建议在共同 wrapper/peripheral 边界加入相同 **synthetic peripheral bus-event monitor**；RVFI 作为 PC/指令辅助绑定，不作为唯一 oracle。

拟议事件必需字段：schema/producer version、run/RTL/config/ELF/input identity、reset epoch、monotonic cycle、phase、sequence number、request/response 类型、address、we、be、wdata/rdata、error、source monitor identity。
request/response 用唯一 transaction ID 对应；同一 clock 边沿的顺序要明确。设备 request 是在固定总线协议下的接收事件，配合下一周期 response 验证完成，不能只看 CPU store encoding。

明确采样规则：request 在有效上升沿采样；更新后的 STATUS 在 NBA 完成后的稳定采样点记录（例如后续负沿，并保留对应 acceptance cycle）。不要用竞态敏感的 `$display` 先后顺序推断状态因果。

Trigger verifier 必须检查：

1. 记录来源、完整性、target/run/hash 绑定和 reset 初始化正确；监控覆盖完整分析窗口，结束 footer/计数存在。
2. ENABLE 地址的完整 word 写确实被接受且成功响应，wdata=1。
3. COMMAND 地址的完整 word 写确实被接受且成功响应，wdata=0xa5。
4. 两次请求在同一个 reset epoch，ENABLE 先于 COMMAND；中间没有 reset 或改变 ENABLE 的写。
5. COMMAND 前的客观 ENABLE state=1，不能只依赖之前的一次写记录。
6. 错误响应、trace 缺段/重复序号、未知 byte lane、未完成事务 → UNKNOWN/invalid evidence，不提升为成功。

第一版不需要推导外部输入可控、不使用 instruction-list 顺序替代 runtime 顺序、不证明所有路径可达。
negative 的“没有偏差”必须限定在从 reset 至正常完成的完整受控窗口；缺 trace/timeout 不能算 N1/N2 成功。

## 8. 实际观察与 differential record（future schemas）

建议独立 `HardwareDeviationObservation`：

```text
schema_version, observation_id, content_sha256
run_id, platform_binding_id, rtl_source_sha256, config_sha256
firmware_sha256, input_sha256, backend_descriptor
requirement_id, observable_target, sampling_phase, cycle, reset_epoch
observed_value, width_bits, completeness
trace_artifact_sha256, event_ids / source locations
```

它记录客观值与绑定，不凭存在就写 verified。将记录与 XL1 的 expected/deviation predicates 比较，产生独立 DeviationVerificationResult，取 observed / not_observed_in_complete_window / unknown（拟议语义，非本轮新领域实现）。
第一观测点是 internal STATUS；第二点为完整 STATUS read response。两者不一致时不能出链，应报告 protocol/measurement conflict。

建议独立 `ControlledHardwareDifferential`：

```text
schema_version, differential_id, content_sha256
reference_run_id, variant_run_id
firmware_sha256, software_input_sha256, initial_memory_sha256
simulator_engine_version, toolchain_identity, harness_sha256, build_options_sha256
config_sha256, reset_schedule_sha256, clock_policy, seed, observation_window
reference_rtl_sha256, variant_rtl_sha256, allowed_patch_sha256
reference_executable_sha256, variant_executable_sha256
compared_signals/events, alignment_policy, completeness
first_divergence, expected_vs_observed, source_refs, trace_refs
result, unknown_reasons
```

“同一模拟器”指同一 Verilator 引擎版本、harness、构建规则和配置；不同 RTL elaboration 会得到不同 executable SHA，必须分别保存，不能要求二者二进制相同或隐藏差异。
检查除允许 RTL patch 及其派生构建产物外的实验输入相同。初始 RAM/seed/clock/reset/中断输入也必须固定；不能仅比 ELF hash。

按 cycle/phase 对齐，禁止用宽松重排抹平 timing 差异；第一次分歧预期为 COMMAND 接收后 STATUS 更新点。这里的 first divergence 只对明确列出的 monitor 信号/事件全集成立，不冒充所有内部 RTL net 的首次分歧。
后续 STATUS bus response/result RAM 的差别是待核验的下游结果，不能用“除了 RTL 其余必须相同”错误拒绝目标输出差分。
仅 stderr/stdout 字符串不同或 simulator exit=0 都不能单独证明受控偏差。

## 9. 八层判定与报告

| 层 | 必需证据 | 失败/未知处理 |
|---|---|---|
| 1 FirmwareCapability established | ELF 字节绑定、有界 MMIO 事实、逐字段来源、conditions | 未建立则 UNKNOWN，不由 GT 补齐 |
| 2 HardwareBehaviorContract established | 受控规范/RTL identity、完整要求与 scope，manual source 明示 | 要求缺失保持缺失，不能用 schema-valid 代替语义验证 |
| 3 Compatibility | 受支持要求逐项结果，revision/state/conditions 的适用性也有已审核机制 | frozen XL2 UNKNOWN 保留；未解决前不能进入 final positive |
| 4 Runtime firmware behavior | 完整已绑定 bus requests/responses | 静态存在不能替代发生 |
| 5 Trigger satisfaction | exact ENABLE/COMMAND/value/width/order/state/epoch | N1 在此不成立；无 trace 为 UNKNOWN |
| 6 Deviation observation | internal STATUS + bus read（完整窗口） | N2 无偏差；U1 binding 缺失为 UNKNOWN |
| 7 Reference/variant differential | 单变量输入审计、同源对照、第一次可观测分歧 | 配置/固件/input 不同不能作因果对照 |
| 8 Controlled chain verification | 前七层关联同组对象，无未建立必要条件 | 仅 P1 满足全部时可 verified controlled synthetic chain |

四个 Golden 的 evaluator PASS 不同于四个都返回 verified：
P1 要求八层正向成立；N1 要求拒绝 trigger 且完整窗口无偏差；N2 要求 trigger 已发生但偏差不成立；U1 要求准确停在缺失绑定并传播 UNKNOWN。
反例若被“成功”提升为链，应视为 golden regression 失败。

未来报告第一屏统一模板：

```text
受控跨层验证报告（synthetic / controlled / 方法验证）
Case: <evaluator 显示标签；分析 identity 单列>
结论: 已验证受控链 / 触发不成立 / 未观察到受控偏差 / UNKNOWN
固件行为     <状态 + 最短事实 + evidence link>
硬件要求     <状态 + 目标 identity>
兼容性       <matcher version + 三态 + 必要缺口>
运行时触发   <状态 + 请求/响应与时序>
硬件偏差     <STATUS 实际值及窗口>
Reference 对照 <两侧实际值 + 输入相同性>
下一步       <缺失什么，不能由什么代替>
边界: 仅本 synthetic 方法验证；不证明真实 silicon 漏洞。
```

由 typed verification records 确定性渲染；GT expected/actual 对照另列 evaluation 区域，不能混入分析事实。
允许以后附 LLM 通俗解释，但 canonical 判定和验证报告在无 LLM 时必须完整可用。

## 10. 实现提案、验收和停止线

建议下一步先做 **SYN-E2E1-A：最小外设 reference/variant 与客观日志闭环**，审核后才实现：

1. 独立实验工作区，固定来源/配置/构建工具；实现共同外设接口、唯一 variant 状态差异、共同 monitor 和极小正常固件。
2. 对相同固件运行 reference/variant，保存完整 bus/status 事件与身份；N1/N2/U1 断言从此阶段开始覆盖。这里完成的只是实验 apparatus，不命名为全链 verified。
3. 有界 MMIO fact producer/CAP materializer、独立硬件要求来源，以及 GT allowlist firewall。不能以手写 CAP fixtures 冒充自动生产器。
4. 对 gap G05/G06/G08/G09 做单独接口评审；必要时授权新增版本化适用性/状态比较记录与 matcher API，保存 frozen XL2 的未知结果。禁止就地修改已冻结语义。
5. 独立 runtime trigger / observation / differential / chain verifier 与中文报告；四个 case 的完整 golden regression 存在后，才讨论 R2-B。

优先完成第 1–2 项的受控物理模拟证据，再判断 producer/合同接入所需的确切语义，避免先写一个只会输出 PASS 的框架。
潜在新 schema：FirmwareMmioFactCatalog、ControlledRunBinding、MmioBusEventTrace、PlatformApplicabilityVerification、TriggerSatisfactionResult、HardwareDeviationObservation、DeviationVerificationResult、ControlledHardwareDifferential、ControlledChainVerification、ControlledGroundTruth/Evaluation。
它们均为提案；可合并最小实现，但不能把 requirement 与 actual observation 或 GT 混为一个对象。

本阶段冻结保持：A6、XL0、XL1、FW-CAP0、XL2；未改 Agent、prompt、workflow、production/tests。
完整审计、pruning gate、测试与 64 项完成答复见 [R2-A audit](v3-r2a-core-pruning-audit.md)。
