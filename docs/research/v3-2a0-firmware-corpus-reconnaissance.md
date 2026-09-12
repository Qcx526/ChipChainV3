# V3-2A0 — Firmware Corpus Reconnaissance

本轮结论：**V3-2A1 starts with Fuzzware**，首样本为 `P2IM/Heat_Press`，使用其 `04-crash-analysis/13` 配置和输入。只消费四个明确文件，先建立静态指令、配置 MMIO 模型和环境输入 artifact 的确定性证据；不把模型配置解释为运行 trace，不宣称本地复现漏洞。

调查日期：2026-09-12。ChipChain 基线 `v3-1b2-stable`，commit `d9ded761b998fc0164f663e247210767d2f5370c`。本轮仅新增本文；未实现 A1。

以下路径缩写均指 repository 外的只读资源，**不是未来 domain validator 的路径限制**：

| 缩写 | 本地根目录 | 调查时 HEAD；工作区均干净 |
| --- | --- | --- |
| P | `/home/qcx/ChipChainV3_res/firmware/p2im-real_firmware` | `d4c7456574ce2c2ed038e6f14fea8e3142b3c1f7` |
| F | `/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments` | `1b03b728ea660b777571bf2a6c1ecfa9072f0bf5` |

全文证据来自这些本地文件、ELF 元数据、短窗口解码和仓库 contracts；没有访问文档中的外部链接。含 CVE/root cause 的文字仅用于本研究的 oracle 边界审查，本文也不得作为未来 Agent 的整体输入。

## A. P2IM Corpus Overview

排除 `.git` 后 587 个文件；`binary/` 有 **9 个无扩展名的 ARM ELF**，全部由 `file` 确认为 ELF32 little-endian、EABI5、带 debug_info、未 stripped。不是因为目录叫 binary 就把它们当 raw BIN。没有独立 `.bin`、`.hex` 或 `.map` 文件。

| Target | 平台证据 | ELF CPU attribute | 本地工程材料 |
| --- | --- | --- | --- |
| CNC | `CNC/Makefile`、`stm32f407vg_flash.ld` | 7E-M | grbl、HAL、CMSIS、USB、Makefile/linker |
| Console | `Console/README.md` 的 `frdm-k64f` | Cortex-M4 | RIOT 2018.04 patch；完整 RIOT 源码不在本目录 |
| Drone | STM32F103C8 工程、`.ioc`、linker | 7-M | STM32CubeIDE 工程、Drivers、Src/Inc、startup |
| Gateway | README 的 NUCLEO_F103RB | 7-M | StandardFirmata Arduino sketch、afl hook |
| Heat_Press | README 的 `arduino:sam:arduino_due_x_dbg` | 7-M | HeatPress sketch、ModbusRtu、afl hook |
| PLC | README 的 NUCLEO_F429ZI | 7E-M | Modbus sketch、ModbusRtu、afl hook |
| Reflow_Oven | README 的 NUCLEO_F103RB | 7-M | Arduino sketch、afl hook |
| Robot | NUCLEO-F103RB.xml、STM32F103xB linker | 7-M | CMSIS/HAL、MPU6050、startup、IDE 工程 |
| Steering_Control | README 的 Arduino Due | 7-M | Arduino sketch、afl hook |

9 个应用目录与 9 个 ELF 对应；README 仍将 Soldering_Iron 列为 TODO，不能计入这个本地 corpus。Arduino core/library 的外部下载说明不意味着依赖已经齐全。`deps/arduino-cli` 是构建辅助，不是第十个 firmware target。

`P/README.md` 的 aflCall 段及 `P/PLC/afl_call.c:3–23` 说明固件含 fuzz harness hypercall，`svc 0x3f` 在预期 QEMU 环境被截获；原始研究固件不等于未经改动的客户部署镜像。这里只记录，不替换 SVC、不重建。

## B. Fuzzware Corpus Overview

排除 `.git` 后 706 个文件，93 个 `.elf`、93 个 `.bin`、181 个 `.yml`；93 个 ELF 的 `e_machine` 均为 ARM（40）。CPU attributes 包含 7-M、7E-M、Cortex-M3/M4、6S-M；3 个 uEmu ELF 缺 CPU name attribute，因此不能仅凭 ELF machine 精确填写 MCU。

| 实验分组 | 本地 image/target 目录数 | 样本性质 |
| --- | ---: | --- |
| `01-access-modeling-for-fuzzing/p2im-unittests` | 47 | F103 21、K64F 9、SAM3X 17；外设单元测试，非 47 个真实产品 |
| `01-access-modeling-for-fuzzing/pw-discovery` | 10 | synthetic password targets |
| `02-comparison-with-state-of-the-art/P2IM` | 10 | 包含额外 Soldering_Iron；不能直接等同 P 的 9 个构建 |
| `02-comparison-with-state-of-the-art/uEmu` | 11 | 10 个不同 ELF SHA-256；目录名不等于唯一镜像 |
| `03-fuzzing-new-targets/zephyr-os/prebuilt_samples` | 12 | 10 个 CVE 命名构建、2 个 false-positive 构建 |
| `03-fuzzing-new-targets/contiki-ng/prebuilt_samples` | 3 | CVE/已知 issue 的重建变体 |

因此 93 是 image pair 数；其中 57 是单元测试或 synthetic，另 36 个目录包含真实应用/OS 衍生 benchmark 构建，仍不能称为 36 个独立部署产品。README 所述 p2im unit tests 为 46，而本地实际有 47 个 ELF：本报告采用本地计数，不猜测多出的原因。

`04-crash-analysis/` 有 **61 个编号入口**：01–45 各有 config/input/run.sh，46–61 的脚本转到 Zephyr/Contiki PoC；这不是 61 个新固件。17 还留有 `crashing_input_buggy_emu`。新的 OS 构建按 README 有选择性修复/revert，不能忽略 benchmark 构建历史。

## C. Corpus Directory / Sample Structure

```text
P/
  binary/{PLC,Robot,Heat_Press,...}        # 无扩展名 ELF
  PLC/{modbus.ino,ModbusRtu.h,afl_call.c,README.md}
  Robot/{src,inc,CMSIS,HAL_Driver,startup,LinkerScript.ld,...}
  Console/{patch,README.md}               # 非完整 source checkout
F/
  01-access-modeling-for-fuzzing/{p2im-unittests,pw-discovery}/...
  02-comparison-with-state-of-the-art/P2IM/Heat_Press/
    Heat_Press.elf, Heat_Press.bin, config.yml, syms.yml
    valid_basic_blocks.txt, base_inputs/random
  03-fuzzing-new-targets/{zephyr-os,contiki-ng}/
    building/, rebuild_targets.sh, prebuilt_samples/<variant>/
      *.elf, *.bin, config.yml, valid_basic_blocks.txt, POC*/
  04-crash-analysis/<number>/{config.yml,crashing_input,run.sh,README.md?}
```

遍历未发现 symlink；没有本地 fuzzware-project campaign 目录、独立 crash_contexts.txt、完整执行 trace 或 coverage-over-time 输出。56 个 `.txt` 文件为 46 个 valid-basic-block lists 和 10 个 milestone lists；不可把文件名中的 block/milestone 当作已执行证据。61 个常规 `crashing_input` 分布在 numbered cases 和 OS PoC，另有一个 buggy-emulator 输入。P2IM 对比分组 10 个 `base_inputs` 目录提供 seed。

## D. Firmware Sample Unit

合理 unit 是 **一个明确 firmware build + 一个执行/分析环境配置 + 可选输入或运行记录**。同一镜像可以有多个配置/输入场景；一个 ELF 足以进行 image-level 静态分析，但不足以自动构造完整输入路径或 crash case。

| 层次 | 内容 | 本轮首样本处理 |
| --- | --- | --- |
| Required | 可执行字节、架构与加载布局、明确身份 | F 的 Heat_Press ELF/BIN pair + crash 13 config；四文件方案要求 input 也存在 |
| Optional | symbols、source、linker/map、seed、reproducer | 本样本 symbols 已在 ELF；source 需验证同构建关系 |
| Generated | 模型生成结果、CFG、coverage、trace、寄存器/异常记录、analysis outputs | 按 producer 和原始 artifact 记录；模型配置与运行事件分开 |
| Benchmark labels | CVE、人工 root cause、expected answer、false-positive/security 分类 | 不进入默认 analysis input |

CaseBundle 引用外部 artifact 路径与 fingerprint，不复制真实 image 到 tests/examples/samples。配对时同时引用两侧 artifact，不创建 cross_layer 副本。`samples/firmware/` 是推荐 workspace，`examples/`、`tests/` 的 synthetic fixtures 是另一类数据，`output/` 才是未来显式触发的持久化结果位置。

## E. Two Representative P2IM Samples

### PLC：串口 Modbus 输入和可用 C++ symbols

选择它因为有明确输入处理源码和完整可读 ELF，而非目录排序靠前。

- `P/binary/PLC`：781168 bytes，ELF entry `0x08000d3d`，Thumb-2/7E-M。LOAD 包含 FLASH `0x08000000`、data VMA `0x20000000` / LMA `0x08006034`，BSS 从 `0x20000104` 开始。
- `P/PLC/README.md:4` 指定 NUCLEO_F429ZI。`modbus.ino:24–34` 建立 `Modbus slave(1,0,0)`，19200 baud，循环调用 `slave.poll(au16data,16)`；RS-232/USB-FTDI 是代码注释中的连接选项，不是现场接线证明。
- `ModbusRtu.h:785–835` 的 poll 检查可用数据并调用 getRxBuffer；`:915–925` 读取 `port->read()` 到 `au8Buffer`。这是静态输入处理路径证据；不证明某个输入触及危险行为，更不证明 crash。
- `nm -S -C` 给出 1102 行 symbols，包括 `Modbus::getRxBuffer()` at `0x080006b5`、`Modbus::poll(unsigned short*, unsigned char)` at `0x08000b55`；Thumb symbol 低位需保留原值并规范化代码地址。
- 本地 P 中没有此 target 的 MMIO runtime model、input replay log、crash dump；源码/符号并不是 fuzz trace。Arduino board package 不完整，不能要求 A1 重建后才能开始。

### Robot：I2C 传感器、定时器回调和执行器输出

选择它与 PLC 的协议缓冲区输入形成差异：传感器读取、定时器回调、PWM 输出。

- `P/binary/Robot`：984816 bytes，entry `0x080057e9`，7-M/Thumb-2，691 行 nm symbols。`Robot/LinkerScript.ld:63–64` 指定 FLASH `0x08000000/128K`、RAM `0x20000000/20K`，与 STM32F103xB 工程一致；这些是 linker 边界，不是 Fuzzware 扩大的 emulator RAM 区域。
- `Robot/src/main.c:119–121` 的 `_i2c_read_reg` 调用 `HAL_I2C_Mem_Read`；`:188–253` 的 callback 更新 MPU6050、计算 pitch/PID 并写 GPIO 和 TIMER CCR；`:294–303` 设置函数指针并启动定时器中断。
- `src/stm32f1xx_it.c:190–195`：TIM2_IRQHandler 调 HAL_TIM_IRQHandler。`:146–147` 的 UART 是 transmit 日志路径；即使 UART init 开启 TX_RX，也不能把它自动升级为应用的串口接收入口。
- `CMSIS/device/stm32f103xb.h:403–414,622–642` 给 I2C1 base `0x40005400` 和 DR offset `0x10`。`HAL_Driver/Src/stm32f1xx_hal_i2c.c:2579,2711` 等位置有 DR 读到 buffer 的语句。因此 `0x40005410` 是有源代码布局依据的静态 MMIO 地址，不是观测到的访问。
- Symbols：`_i2c_read_reg` `0x08004ee9`、HAL_I2C_Mem_Read `0x08001f6d`、HAL_TIM_PeriodElapsedCallback `0x08004f79`。源码展示静态数据/控制关系；函数指针、ISR 时序和具体读值未被 runtime 证明。

## F. Two Representative Fuzzware Samples

### Heat_Press + crash 13：首样本

选择理由：真实控制应用衍生固件、较小镜像、symbols、32 个具体 MMIO model entries、独立输入文件、少量 YAML keys，目录名不含 CVE 答案。

- 基础 target：`F/02-comparison-with-state-of-the-art/P2IM/Heat_Press/`。ELF 261365 bytes；BIN 24896 bytes，entry `0x00080f35`，7-M/Thumb-2。BIN vector 前两个 word 为 SP `0x20088000` 和 reset `0x00080f35`。
- ELF 的两个 LOAD 文件区分别为 22692 和 2204 bytes；按 **physical/load address** 从 `0x80000` 映射到 BIN 后逐段字节一致。第二段 VMA `0x20070000`、LMA `0x858a4`，不可把 RAM VMA 当成 BIN offset。`.bss` 无对应文件内容。
- 781 行 nm symbols；有 UART_Handler `0x80abd`、UARTClass::IrqHandler `0x815a5`、Modbus::getRxBuffer `0x801ad`、Modbus::poll `0x8043b`。`syms.yml` 可用，但首版直接从 ELF 读 symbols，避免双重来源。
- `F/04-crash-analysis/13/config.yml` 有 32 个 model entries：bitextract 2、constant 5、passthrough 9、set 5、unmodeled 11；共 23 个不同 PC、19 个不同 MMIO address。interrupt 为每 1000 emulator ticks、round_robin；这不是 1000ms。
- `crashing_input` 为 6009 bytes，`run.sh:9` 给出 `fuzzware emu -v -t -M` 复现入口；只读取脚本，未执行。`base_inputs/random` 是另一份 2250-byte seed，不等于该 crash input。
- P 中 HeatPress 源码描述 Modbus master（19200 baud、poll/query，以及 Serial.readBytes）。它是接口语义的辅助线索；**P 和 F 的 Heat_Press ELF 并不相同，连 LOAD code bytes/长度也不同**，不能用 P 的函数地址或源码行直接作为 F 的确定性二进制定位。
- crash 13 README 描述具体函数、覆盖对象和 exploitability：全部属于 oracle。此处仅确认存在这种标注，不将其作为首 adapter 输出。没有独立保存的 crash PC/LR/异常 transcript，所以首样本只能说“存在 corpus 提供的 reproducer artifact”，不能说“本地已经观察到或复现 crash”。

### Zephyr CVE-2020-10064：不同输入模式与嵌入式寄存器转录

选择理由：与 UART/Modbus target 不同，有 radio/SPI 相关代码、fuzzed interrupt、PoC 和工具寄存器转录；也能暴露 oracle 风险。

- 路径 `F/03-fuzzing-new-targets/zephyr-os/prebuilt_samples/CVE-2020-10064/`；ELF 1886152 bytes，entry `0x00402dcd`，ELF attribute Cortex-M4，2968 行 nm symbols，BIN、valid_basic_blocks、基础配置和 POC/config/input/run.sh 齐全。
- `building/build_sample_CVE-2020-10064.sh` 指定 `sam4e_xpro`、Zephyr 2.2.0、BASE_COMMIT `38970c07abfcddcfc6a5958189f096a55c49594a`。`docker_build_802154_sample.sh` 使用 echo_server、overlay-802154.conf。这是构建元数据，未执行重建、未验证板级部署。
- ELF 中有 rf2xx_iface_frame_read `0x4021b9`、ieee802154_recv/reassemble、spi_sam_transceive_sync 等；结合构建 metadata，支持无线帧处理栈的静态存在性。不能据此推断 Wi-Fi/Bluetooth，更不能把 PoC 全部字节解释为无线 payload。
- POC config 有 54 个 model entries（5 bitextract、13 constant、25 passthrough、2 set、9 unmodeled）。例如 PC `0x40a93e` 对 MMIO `0x40088008` 的 4-byte read 模型，mask `0xff`、输入 size 1；解码为 `ldr r2,[r0,#8]`，紧随 `strb r2,[r5,r3]`。它位于 ELF 的 SPI 处理函数范围，仍只是静态字节 + 配置给出的 MMIO 关联。
- 中断 trigger 是 `arch_cpu_idle` / `fuzz_mode: fuzzed`，不同于 Heat_Press 的周期 round_robin。配置还设 handlers/exit_at，跳过日志、sleep 等函数；仿真执行环境与硬件有差别。
- `POC/crashing_input` 10700 bytes；README:18–42 有 Unicorn register transcript：PC `0x0040daba`、LR `0x00407987`、r2 `0xfffffffb`。这是文档内的**断点寄存器转录**，PC 对应 memmove symbol 的规范化地址；不是 crash PC、不是 HardFault dump。它支持作者记录的一次 emulator 停止状态，未在本地重放验证。
- README 的 root cause、预期 crash、其他 CVE 干扰、函数链都是人工解释。原始 README 默认隐藏；今后若要提取 transcript，需独立的 operational projection、标明转录来源与未复现状态，不能冒充新产生的 tool output。

## G. Executable Firmware Artifacts

P 的 9 个预编译文件全是有 debug info 的 ELF；有 200 个 `.c`、267 个 `.h`、5 个 `.ino`、3 个 `.ld`，另有 Makefile、IDE 配置、补丁，源码依赖完整性因 target 而异。F 有 93 对 ELF/BIN，没有 `.hex`、`.map`、`.ld`、完整 `.c/.h` source files；有 16 个 `.patch` 和构建脚本，不应称为完整源树。

ELF 可提供 segment/section、VMA/LMA、entry、symbols、架构和 debug 元数据；BIN 只有字节，必须结合加载配置。HEX 尚无本地需求，不建议 A1 添加 HEX parser。symbol/function 存在不保证它执行过；debug_info 也不证明磁盘 source 与该 build 完全一致。

代表 ELF SHA-256：

| Artifact | SHA-256 |
| --- | --- |
| P/binary/PLC | `783108cf8b9cf7f703a4164dfee7d12d9a9f79d663328a21454a70a7003c2b08` |
| P/binary/Robot | `724ea82d567b9eefb23e6d75cc90ac0ccdbcd0c7aeca0cca964de46ec188f547` |
| F 的 Zephyr CVE-2020-10064 ELF | `b21c9a08567a0465963fdddac49bfd81d379616478bd2e6154369fae121f6ffc` |

## H. External Input Representation

| 样本 | PhysicalExternalInterface 的证据 | EmulatedEnvironmentInput 的证据 | 未证明的关系 |
| --- | --- | --- | --- |
| P PLC | 源码 serial read → Modbus buffer/poll | aflCall 仅表示 harness 控制；P 无输入流记录 | 哪一条真实线缆、哪个输入到危险代码/crash |
| P Robot | MPU6050/I2C source call；UART transmit 是输出 | P 无已保存 emulator input/model | 具体 sensor 值、ISR 执行序列、攻击者控制范围 |
| F Heat_Press | ELF 的 UART handler/Modbus symbols 提供静态候选 | config 中 PC-address model、输入 artifact、round_robin trigger | input offset → 第几次 MMIO read → Modbus message → crash |
| F Zephyr | build overlay + ELF radio/SPI symbols | bitextract、fuzzed interrupts、PoC input | input offset → 完整射频 frame、真实设备可利用性 |

能确定“环境模型存在”时先采用 `EmulatedEnvironmentInput`；只有 MMIO 地址而无外设/来源依据时采用 `UnknownExternalOrigin`。不要把任一 read 自动构造成从物理接口到任意函数的 ExternalInputPath。

需要分别立证：input exists；input reaches function；input reaches sensitive behavior；input causes crash。静态候选链可以进入 unresolved_questions；LLM 不能补造缺失的 execution/dataflow。

## I. MMIO / Peripheral Representation

Heat_Press 的 emulator memory map 为 MMIO `[0x40000000,0x60000000)`、`nvic` `[0xe0000000,0xf0000000)`、RAM `[0x20070000,0x200b0000)`、text `[0x80000,0x87000)`、irq_ret `[0xfffff000,0x100000000)`。这些宽泛配置区间不是芯片 datasheet 精确外设表，`nvic` 区名也不意味着全区每个地址都是 NVIC 寄存器。

具体证据：`13/config.yml` 的 `pc_000815b0_mmio_400e0818` 为 access_size 4、bitextract mask `0xff`、left_shift 0、size 1；`pc_000815aa_mmio_400e0814` 为 set `{0,1,2,3}`。32 entries 保留 model 类型和原始参数；constant 的 val、passthrough 的 init_val 都是配置，不是当次读回值；同一 PC 可对应多个 addr。

静态解码确认 `0x815aa: ldr r5,[r3,#0x14]`、`0x815b0: ldr r1,[r3,#0x18]` 的 read 方向与 4-byte 宽度。地址来自 config，并非静态 operand 已自行解析出 r3 数值。A1 应分开记录这两种依据。

P Robot 的 `I2C1_BASE + offsetof(DR) = 0x40005410` 和回调对 TIMER CCR 的写提供静态平台映射。中断配置/ISR/vector 存在性仅表示可配置行为，不能创建“interrupt occurred”事件。ADC/GPIO/I2C/SPI/Serial 在 F 单元测试目录也有明确覆盖目标；目录名字、通用 vendor header 中的 USB/Ethernet 定义都不足以证明某个应用实际使用这些接口。

## J. Crash / Exception / Fuzz Evidence

| 命题 | Heat_Press / crash 13 | Zephyr 10064 | 证据强度 |
| --- | --- | --- | --- |
| A crash observed | corpus README 声称发生；无独立 raw dump | README 描述 crash，附有断点状态 | 作者记录，非本地新观察 |
| B crash input exists | 6009 bytes 文件 | 10700 bytes 文件 | 本轮可直接确认 |
| C crash reproducible | 有 run.sh；未执行 | 有 run.sh；未执行 | 复现配方存在 ≠ 本地已复现 |
| D vulnerable location known | 人工 README 指定 | CVE/README/patch 指定 | benchmark-only answer |
| E security vulnerability confirmed | README security/exploitability 判断 | benchmark 归类，另有其他样本 false positive | 非本轮独立确认 |
| F CVE known | 该条目未给 CVE | 目录/metadata 给 CVE | 标签存在性，不是 agent 推理成果 |

F/04-crash-analysis/README.md 说明原实验按 PC/LR 聚类、人工分析；genstats crashcontexts 原本能生成 crash reason/register state。当前本地没有这些独立统计输出。栈 dump、按输入的全程 trace、异常类型和 MMIO 消费顺序都不能从 input 文件长度推出。Zephyr transcript 的 SP 值不是 stack memory dump，也没有 xPSR/完整 fault status。不能将 emulator invalid access 自动命名为 Cortex-M HardFault。

复现存在版本风险：crash README 建议早期 fuzzware-emulator commit `075dbb5`；17 的 buggy emulator 输入和 45/56/57 false-positive 标注说明 emulator 假设会影响结论。本轮不安装、构建或运行这些工具。

## K. Static vs Runtime Reachability Evidence

| 现有 artifact | 能证明 | ReachabilityKind 使用边界 |
| --- | --- | --- |
| ELF symbol/source declaration | function exists | 对从外部输入的可达性仍 UNKNOWN |
| 短窗口 decode 的 branch/call | 静态局部控制转移边 | STATIC 仅用于这条局部边；不代表从入口可达 |
| PLC source call / Robot callback registration | source-level 候选路径 | STATIC 并说明条件、source/build 关系 |
| valid_basic_blocks.txt | IDAPython 识别的块地址集合 | 既无 CFG edges，也无 entry path；更非 RUNTIME |
| 未来 CFG + entry-path analysis | 在分析假设下静态可达 | STATIC，需记录入口和模型假设 |
| 未来按 run/input 绑定的 coverage | 对该 run 的 block coverage | RUNTIME，不推出所有 CFG 边或 crash 路径 |
| Zephyr 文档中的 Unicorn breakpoint transcript | 作者记录的某次停在该 PC 的状态 | 审查提取后可作为有限 emulator RUNTIME 证据，不能自动关联完整外部输入路径 |
| 未来独立 trace/crash dump | trace execution / crash state | RUNTIME；只有与输入和顺序绑定才建立 crash-path execution |

`F/02-comparison-with-state-of-the-art/README.md:38–39` 明确 valid lists 由 IDAPython 预生成。本轮读取的 Heat_Press list 为 1837 行，Zephyr list 7316 行。它们不是 fuzz 覆盖率分母之外的执行证据。

STATIC/RUNTIME/UNKNOWN 三态可继续使用，无 blocking enum 扩展。需要在 observations/evidence 增加证据范围语义：symbol presence、local edge、entry reachability、coverage、trace、crash。`OBSERVED` 表示“观察到文件里的配置事实”不等于 RUNTIME；必要时不给 ReachableBehavior，避免将 UNKNOWN 填成肯定路径。

## L. Operational Evidence vs Benchmark Oracle

沿用 V3-1B.1 三层分离：

| 层次 | 本地例子 | 未来默认策略 |
| --- | --- | --- |
| Operational deterministic evidence | ELF bytes/symbols、config memory map/models、input bytes、独立 coverage/register/exception records | 按事实范围允许；不赋予额外安全含义 |
| Benchmark-only answer | CVE 名称、漏洞函数标签、root cause、expected crash、手工 bug location、exploitability、groundtruth.csv、password milestone 答案 | 默认拒绝进入 agent |
| Raw hidden/reference material | crash README、bug-details、CVE build/patch narratives、含答案的目录/文件名 | 保留本地供评估；不整份投送 |

“Groundtruth” 标题之下的 valid_basic_blocks 仍是可由静态工具生成的地址集合，不因来自 benchmark 就自动变成漏洞 oracle；只是不能冒充 coverage。同理 fuzz input 可以是操作证据，含 input 的 README 中的漏洞解释却应隐藏。预生成模型的具体生成 run/version 未完整保存：记录 `corpus-supplied model configuration`，不能标为本轮 analyzer 观测到的 runtime MMIO。

当前 `agents/context.py` 会投送 ArtifactRef 的 **path**、Case 的 name/id 和 target，隐藏 ground_truth_label 并不足够。Zephyr 的 CVE path 本身泄漏标签，未来真实调用前必须审查中性标识/路径投影；完整解析出的 symbol 字符串也可能带已知答案提示。首样本用无 CVE 的 Heat_Press，首 adapter 不递归扫描 README/patch/bug-details、不根据已知漏洞函数筛选指令。`crashing_input` 名称只提示操作测试背景，不能作为已证实 crash/vulnerability 标签。

## M. EvidenceRef Mapping

已阅读当前 `domain/evidence.py`；ArtifactRef 持有 path/hash/size，EvidenceRef 通过 artifact_id 关联，EvidenceLocation 不负责打开文件。

| 定位对象 | 当前表示 | Gap / 首版处理 |
| --- | --- | --- |
| Firmware VA / instruction PC | location.address | 可用；明确 address_space=firmware VA，Thumb 规范化但保留 raw symbol |
| File offset | 无专门字段 | 非 blocking：typed observation details 存 offset/length，ref 指向同一 artifact；不能冒充 address |
| Function | location.function | 可用，symbol 来源与大小必须明确 |
| Basic block | location.basic_block | 可用 string ID/address 文本；不附带 CFG/coverage 含义 |
| Instruction | address + instruction_index | 可用；index 不是 input offset |
| Register | location.register（wire alias） | 可用，例如 r2；数值在 observation details |
| MMIO address 与访问 PC | 一个 location 只有一个 address | 用两个不同 evidence refs + details.pc/mmio_address 关联，不能互相覆盖 |
| Input offset | 无专门字段 | 非 blocking：artifact ref + details.offset/length；暂无 offset→read 的记录 |
| Crash PC | location.address | 可用，但必须有 actual crash evidence；memmove breakpoint PC 不填 crash |
| Exception type / fault status | 无 typed exception 字段 | 非 blocking，future observation details；source line/summary 可定位原记录 |
| YAML field / source line | location.line | 可用；details 保留 model key/field path；未来考虑通用 selector |
| Emulator tick / execution sequence | time 仅 s/ms/us/ns/ps/fs | 非 blocking：details.tick/sequence + 单位；不能把 every_nth_tick 写成毫秒 |

**EvidenceRef 无首条 pipeline 的 blocking 扩展需求。** 首版若需要机器可读 offset/两个地址，可放最小 typed details；后续通用 file_offset/address_space/selector 建议不在 A0 实现。EvidenceSourceType 使用 ARTIFACT 或 DETERMINISTIC_ANALYZER，转录不要伪造为本次工具运行。

## N. ProcessorBehaviorIR Mapping

以下是候选映射，A0 没有创建 IR/report artifact。所有 origin 为 firmware；architecture 为 ARM，平台具体信息在 target/details。

| 真实事实 → 候选 BehaviorKind | 来源及 epistemic scope | 明确不能推出 |
| --- | --- | --- |
| Heat_Press BIN offset `0x15b0` bytes `99 69` → INSTRUCTION `ldr r1,[r3,#0x18]` | static bytes，Capstone DERIVED；ELF file offset 为 `0x95b0` | 当前寄存器值、执行次数 |
| 上述指令 + config pc `0x815b0`/addr `0x400e0818`/width 4 → MMIO_ACCESS read | derived，**config-associated static access site** | 本地 observed MMIO read 或从物理 UART 输入的完整路径 |
| `0x815b4: uxtb r1,r1` → REGISTER_ACCESS / 局部 DATA_DEPENDENCY | static decoded semantics；需保留 producer | 实际 r1 值、跨函数 taint |
| `0x815ac: lsls r2,r5,#31`、`0x815ae: bpl 0x815ba` → CONTROL_TRANSFER，可能局部 CONTROL_DEPENDENCY | static/derived 条件控制关系 | 分支实际选向、从 reset 可达 |
| `0x815b6: bl 0x813e6` → CONTROL_TRANSFER | static call target | 该 callee 在 fuzz run 执行过 |
| Robot DR read → MEMORY_ACCESS/MMIO_ACCESS；buffer assignment → 局部 DATA_DEPENDENCY | source-static；源代码和 CMSIS 布局 | 相同源码必然对应 F 的另一构建 |
| Robot TIM2_IRQHandler → INTERRUPT handler 存在 / CONTROL_TRANSFER | static declaration/call；配置事实 | interrupt occurred |
| Zephyr `0x40a93e ldr`、`0x40a940 strb` → MMIO_ACCESS/MEMORY_ACCESS，局部 DATA_DEPENDENCY | static + model relation | 不能把有效地址推成已知 runtime buffer |
| Zephyr README register transcript → REGISTER_ACCESS 的 state snapshot（如采用） | 作者保存的 emulator runtime transcript，需单独提取来源 | 不是 read/write 动作本身、不是 crash PC；首版延后，避免强塞错 kind |
| 输入文件存在 / MMIO range config | observation，**不必产生任何行为** | input bytes 不天然是 processor behavior |
| 将来的实际 fault record → EXCEPTION | runtime，须有 PC/type/tool/input binding | 现有 crash README 不足以新建 verified HardFault |

这也说明不应要求每一条 FirmwareObservation 都产生 ProcessorBehavior。当前 IR attributes 可表示 `evidence_scope=static`、`association=configured`、MMIO address、access size 等 scalar；复杂 model 参数保留在 typed observation，避免塞 JSON 字符串到扁平 Metadata。

ARM Thumb 指令长度为 16/32 bit，不能复用 RISC-V decode mode。现有 DecodedOperand 不完整覆盖 Thumb register lists、shift、writeback：A1 最小指令 site 可先保留 bytes/mnemonic/operand_text 和受支持 operands，不能伪造完整 operand AST；全 ARM decoder 属于延后范围。

## O. FirmwareAnalysisReport Mapping

| Contract | Deterministic tools 可直接提供 | Agent 可基于证据做什么 | 缺证据或需额外分析 |
| --- | --- | --- | --- |
| FirmwareFinding | case/fact IDs、summary of exact observation、evidence、behavior refs | 有范围限定的安全意义、候选解释 | 漏洞确认不是靠一个 MMIO 模型；允许空 findings |
| ExternalInputPath | source 中明确入口、emulator MMIO site、关联证据 | 区分物理/仿真/未知来源，解释已有路径 | MMIO read 不足以构成端到端 path；完整 dataflow/CFG/trace 待工具产生 |
| ReachableBehavior | 局部 static edges；将来 coverage/trace 的具体关联 | 解释路径条件、缺失边 | function symbol / valid list 不直接填 runtime；环境→行为绑定不能臆造 |
| FirmwareIssueAnchor | observation/PC/异常记录和已存在 finding/behavior IDs | 作为待验证 issue 的定位锚点 | 人工 root cause/CVE 标签不作默认 anchor；本轮首样本尚无 actual crash PC |
| FirmwareAnalysisReport | case_id、IR behavior IDs、unresolved_questions | 组织可信的 reasoning/report | 不把 deterministic adapter 变成完整 vulnerability analyzer |

当前 Report 无阻断首个 A1 的 schema 问题；external input kind、reachability basis、register/exception structured detail 更适合先放 observation。LLM 可提出可验证 hypothesis，不能作为 CFG、MMIO event、crash location 的第一生产者。Ghidra/angr/动态工具才可能补充更广 CFG、静态入口分析、路径约束或输入到行为的对应关系；本轮均不运行。

## P. Current Schema Gaps

- **A0 blocker：无。** 只需研究文档。
- **A1 实施前必须明确的 contract 工作：** 通用 DeterministicObservation 只有 summary/evidence/behaviors，无法稳定区分 config model 与 runtime event，也缺机器可读 model 参数；真实 corpus 已支持最小 typed firmware observation。应明确 discriminator、证据范围和默认角色策略，并验证非分析材料不能进入输入。这是 A1 的小范围工作，不是现在修改 domain。
- `FirmwareObservations.observations` 和 `_SideContext.observations` 当前按 generic base 类型声明；若 A1 增加 subclass，必须测试 model_dump/roundtrip/context projection 不丢 typed details，不能假设 subclass 自动全部序列化。Agent validator 目前只对 HardwareObservation 检查 oracle role，不能假装 firmware 已有等价保护。
- **非 blocking：** EvidenceLocation offset/address-space/selector、Report 的 explicit input origin/basis、Cortex-M fault details、ARM complex operands。最小 adapter 可在 typed details/现有 evidence 与 unresolved_questions 表达，不重构通用 report。
- **未来真实 Agent blocker：** 含 CVE 路径/标识的 context 泄漏、缺少可审查 operational projection。首样本中性身份与输入 allowlist 可减少风险，但进入 B 前仍需验证。128-item / 64000-char 现有 context 边界要测量，不为全 corpus 放宽或偷偷截断。

## Q. Corpus / Cortex-M / ARM / Architecture-Neutral Boundary

| 层次 | 例子 | 放置位置建议 |
| --- | --- | --- |
| Corpus-specific | P 的 aflCall、F model key/bitextract/set、run.sh、CVE 编号、IDA block list | adapter/details/benchmark evaluation；不进通用 report enum |
| MCU/board-specific | STM32F103 I2C1 `0x40005410`、SAM UART/SPI、RAM/FLASH 大小 | target metadata、平台映射与 evidence |
| Cortex-M-specific | NVIC/SCB、xPSR、PendSV、HardFault、vector table、exception return | 有证据时用平台 details，IR 表达统一 exception/interrupt |
| ARM-specific | ELF e_machine ARM、Thumb state/16–32bit、r0–r15、BL/BPL | ARM decode adapter，保留 ISA mode |
| Architecture-neutral | MMIO/memory access、external/environment input、control transfer、exception、evidence/provenance | 共用 IR/report |

当前 EnCorpus Ibex 是 RISC-V，不能因为两侧都有 MMIO/exception 就称 ARM firmware 能直接与 Ibex 配对验证；价值在统一行为语义和未来架构兼容样本的匹配，非本轮 cross-layer 结论。

## R. Candidate FirmwareObservation Semantics

建议 A1 **三种最小 category**，名称仅供下一阶段定稿，不在 A0 建空 class/module：

| Category | 真实依据与最小 details | 决策 |
| --- | --- | --- |
| static_instruction_site | Heat_Press 23 个配置 PC；image ref、VA/offset、raw bytes、ISA mode、可选 symbol、decode result | A1 required；从已有模型 PC 定位，非漏洞函数标签筛选 |
| mmio_model | 32 entries；pc/address/access_size、model kind、typed parameters、config key/line、scope=config | A1 required；不命名成 runtime MMIO observation |
| environment_input | config interrupt trigger 和 6009-byte 输入；用小型 details discriminator 区分 trigger 配置 / opaque input artifact(length/hash) | A1 required；不建立 offset→read 因果映射，不输出全量输入 bytes |

Image architecture/layout/symbol index 可作为 adapter metadata 和 evidence，不必再创建十几个 observation 类。共用 role 与 scope 概念需要明确：analysis_input 仅来自 allowlist；benchmark oracle 不混入 production batch；scope 分 static/config/runtime，epistemic status 不替代 scope。

Deferred：runtime MMIO events、coverage/reachability、exception/crash state、register snapshots、physical protocol parsing、跨函数 data/control dependencies、完整 ARM instruction decoder。源文件目前没有独立 runtime records 支撑这些类作为首版必需品。

Unnecessary：CVEObservation、ExploitabilityObservation、UARTPacketObservation（仅因输入文件存在）、照搬 Hardware mutation/formal/differential waveform 层次、Cortex-M-only report、Batch domain/scheduler/database。

## S. Candidate Deterministic Toolchain

本轮实际使用 `file 5.41`、GNU readelf/nm/objdump 2.38、Python pathlib/struct/hashlib、现有 PyYAML 6.0.3、Capstone 5.0.7。均为本地只读 inspection；没有安装新依赖。

- readelf 可读 header/attributes/LOAD/symbols；nm `-S -C` 可读 C++ symbols。系统 objdump 报 `can't disassemble for architecture UNKNOWN!`，`arm-none-eabi-objdump` 不在 PATH。
- 使用已有 Capstone ARM + THUMB + MCLASS 模式，只解码 Heat_Press UARTClass::IrqHandler 74 bytes 和 Zephyr SPI 24 bytes；这不是全固件 CFG/parser。无需为 A0 安装大型 toolchain。
- 下一阶段可用严格有界 ELF32 little-endian reader（segment/section/symbol bounds 检查）、safe YAML reader、现有 Capstone 做选中 site 的静态 decode。工具版本和输入 SHA-256 都进 provenance；所有 unsupported/malformed 情况明确返回未解析原因。
- P 中部分 vendor source 不是 UTF-8，inspection 使用 Latin-1 fallback 读取定位；未来 source ingestion 应记录 encoding，不能静默损坏内容。
- 不运行 QEMU/P2IM/Fuzzware/GDBFuzz/Ghidra/angr，不执行 corpus 的 shell/build 脚本、不联网、不读取 `.env`、不调用 ChatDeepSeek。

## T. P2IM vs Fuzzware Comparison

| 维度 | P2IM 本地目录 | Fuzzware 本地目录 |
| --- | --- | --- |
| Real firmware quality | 9 个真实控制应用衍生构建，含 fuzz hook | 真实应用/OS + synthetic/test 混合，需分组；部分为特定 CVE 重建 |
| ELF/BIN | 9 个 extensionless ELF；无独立 BIN | 93 ELF/BIN pairs；Heat_Press pair 已核对 LOAD |
| Symbols | 全部 unstripped/debug_info，代表 symbols 丰富 | 代表 symbols 丰富；额外 syms/config maps |
| Source | 较强但依赖不齐，Console 仅 patch | 本地无完整 `.c/.h` 源树；build/revert patches 不能替代源码 |
| External input | source 可定位 Modbus/I2C 等静态入口 | image symbols + MMIO config + input artifacts，物理来源仍需验证 |
| MMIO metadata | headers/HAL/linker 的静态平台映射 | model 按 PC/address/size/value 保存，直接适合小 adapter |
| Runtime/fuzz evidence | 本地无 campaign 记录 | reproducer/model、部分文档转录；无独立完整 campaign outputs |
| Crash evidence | 未随该目录提供 | 61 个编号入口、输入文件、人工分析；未本地复现 |
| Oracle leak risk | 相对较低，但 harness/source 注释需审查 | CVE path/root cause/patch/groundtruth 风险高；Heat_Press 可限四文件 |
| Reproducibility | 预编译可 fingerprint；重建缺依赖 | pair/config/input 可固定；replay 依赖旧 emulator，Contiki 重建 README 明示二进制不完全可复现 |
| Future hardware matching | 源码到 MMIO/中断行为线索强 | PC/addr/model 结构更容易转统一 IR；与 Ibex ISA 不同 |
| Initial implementation complexity | 仅 ELF 简单；源码到具体 MMIO/input 分析更复杂 | 全 corpus 复杂，但 Heat_Press 32 entries/four-file slice 有界 |

## U. Recommended First Corpus

**选 Fuzzware。** 它提供已保存的可解析模型和 input artifact，可以在不运行仿真、不读 oracle 的前提下建立第一条真实 firmware evidence pipeline。选择 Fuzzware 的 P2IM 衍生 target，不等于把两个 corpus 同时作为首 adapter 的依赖。

## V. Recommended First Target

**`02-comparison-with-state-of-the-art/P2IM/Heat_Press` + `04-crash-analysis/13` 场景。** 它比 CVE 命名的 Zephyr target 小，基础配置无需 handlers/symbol hooks，32 个 model entries/23 个 PC 足够测试范围和证据语义。选择理由是 artifact 完整性与边界，不是事先知道 bug 在哪里。

未来 case 身份可取中性 `fuzzware:heat-press:scenario-13`，保持 build/config/input fingerprint。首阶段成功标准是 ingestion/provenance/IR 合法、证据不过界；并非发现特定漏洞或输出非空 findings。

## W. Exact Files for V3-2A1

**只解析以下四个原始文件**（总计 296523 bytes）。所有路径均明确引用外部资源。

1. `/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments/02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.elf`
2. `/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments/02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.bin`
3. `/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments/04-crash-analysis/13/config.yml`
4. `/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments/04-crash-analysis/13/crashing_input`

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| Heat_Press.elf | 261365 | `73f667524ed0ff8f24b460d4678b74f15eec13d954b93cdc92c839c2c3f1044e` |
| Heat_Press.bin | 24896 | `1f7654deeec0d26307f35ea683c891965aa671fd891ae24af1aa8949ede43620` |
| 13/config.yml | 4253 | `2d91c058a4326ddde28be2bc27afd6a073b9b8aabf1816f6bac22e76dcc33bc2` |
| 13/crashing_input | 6009 | `0eca471106cf883c5941a03376c4ee3aa4b6cebd26636fc401e50c168644ee22` |

`13/config.yml` 的相对 file 引用解析到第 2 个文件，并要求与调用方显式 ArtifactRef/fingerprint 对应；不递归加载任意 YAML 路径/脚本。路径允许 repository 外位置，不硬编码 samples 根目录。

不纳入首 parser：基础 config.yml（已被场景配置覆盖）、syms.yml（ELF 已给 symbols）、valid_basic_blocks.txt（无需全固件块表）、base_inputs/random（非本场景输入）、run.sh（A0 已审查配方）、README/bug-details/patch、P 中另一版 Heat_Press/source。四文件列表不是“先读四个然后隐式补读整目录”。

## X. Proposed V3-2A1 Pipeline

```text
four explicit ArtifactRefs + target identity
  → bounded Fuzzware Heat_Press scenario adapter
  → FirmwareObservation[] (static site / MMIO model / environment input)
  → ProcessorBehaviorIR (deterministic producer; static/config scope)
  → FirmwareObservations batch → FirmwareAgentInput validation
```

最小实施步骤：

1. 检查 fingerprint、字节/条目上限，拒绝损坏 ELF/YAML、未知 unsafe tag 和含歧义的重复 key；读取 ELF32 LE ARM 的架构、entry、LOAD、必要 symbol ranges。明确 unsupported，而非猜测或重建。
2. 对照 BIN 和 ELF 的 file-backed LOAD 数据；处理 VMA/LMA、BSS 无文件字节和 Thumb 低位。读取 config memory map/interrupt_triggers/mmio_models，不执行 handlers/script，不读取外部 labels。
3. 产生 32 个 model facts，保留 23 个不同 PC 和 19 个不同地址之间的一对多关系。对配置 PC 在有符号界定的代码范围内做有界静态 decode，确认指令边界/read-write-width；无法确认时保留 model fact 和 unresolved，不造 decode。静态指令事实与 config association 分开。
4. input 只产生存在性、长度/hash/角色、opaque environment-input observation；不输出全 6009 bytes 到 Agent，不反推输入消费顺序或 crash 原因。interrupt trigger 记录配置，不发明发生过的 interrupt。
5. 将有依据的 instruction/MMIO/control facts 由 deterministic adapter 映射到 IR；可用通用 `ProcessorBehavior` 和现有 evidence，不要求完整 ARM decoder 或 CFG。config-only/input-only observation 可不产生 behavior。model val 不成为 observed register value。
6. 建立有来源的 bounded batch 与 FirmwareAgentInput，测试 typed details 序列化、evidence artifact membership、oracle 拒绝、静态/运行范围和 context 大小。offline stub 验证即可；不需要真实模型，不生成虚假的成功安全报告。

排除：已知漏洞函数、CVE/expected crash answer、root cause、manual bug location、exploitability；也不把未知 crash PC/HardFault/input mapping 填成事实。选取 PC 的依据是全部有效 model entries 和代码边界，不是 README 的漏洞位置。

未来 V3-2B 成功真实 Firmware Agent run 必须显式持久化 `output/<case_id>/<run_id>/analysis_run.json` 与 `firmware_analysis_report.json`；人工接受后再导出 `output/reviewed/<phase>/<safe-case>/<run_id>/`。当前 `execution/reviewed_output.py` 只支持 Hardware；A0 不扩 exporter，也不生成 Firmware report。`output/reviewed/v3-1b1/` 的 743/820 snapshots 保持冻结。

## Y. Commands Executed

执行类别及具体作用如下；Python inspection 均通过 heredoc 临时运行，未写生产 parser、未 import corpus 代码。没有执行任何 corpus 提供的复现命令。

```bash
# ChipChain baseline / contracts / read-only inventory
pwd
git rev-parse HEAD
git status --short --untracked-files=all
rg --files -g AGENTS.md -g '!output/**' -g '!samples/**'
cat src/chipchain/domain/firmware.py src/chipchain/agents/firmware.py \
    src/chipchain/agents/contracts.py src/chipchain/agents/prompts/firmware.py \
    src/chipchain/tools/contracts.py src/chipchain/domain/behavior.py \
    src/chipchain/domain/evidence.py
cat src/chipchain/domain/instruction.py src/chipchain/agents/context.py \
    src/chipchain/domain/case.py
# Python subprocess 对 P、F 分别执行：git -C <root> rev-parse HEAD / status --short
# pathlib.rglob inventory，排除 .git，计数 extension、ELF、target、input、symlink
# pathlib 读取各级 README/config/run/build/source/linker，不执行其中的代码
# rg -n 定位 Modbus port->read、Robot I2C/ISR/MMIO、F 的 block-list 来源与构建脚本
# file <P/binary/*>；readelf -h -l -A <四个代表 ELF>；nm -S -C <四个代表 ELF>
# readelf -A <93 个 F ELF>；struct 读取各自 e_machine；hashlib.sha256 指纹和去重
objdump -d --start-address=0x815a4 --stop-address=0x815ee \
  /home/qcx/ChipChainV3_res/firmware/fuzzware-experiments/02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.elf
# 上一命令不支持 ARM；改用现有 Capstone，两段短窗口，没有安装软件
# yaml.safe_load：3 份代表配置，统计 keys/models；struct：ELF LOAD↔BIN 对比
# file/readelf/objdump/nm --version；capstone.__version__ / yaml.__version__
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
git status --short --untracked-files=all
```

可重复的核心 inspection 片段（本轮实际采用这些读取方式，以下缩写变量与本文一致）：

```python
from pathlib import Path
from collections import Counter
import hashlib, struct, yaml
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
F = Path('/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments')
files = [p for p in F.rglob('*') if p.is_file() and '.git' not in p.parts]
print(Counter(p.suffix for p in files))
d = yaml.safe_load((F / '04-crash-analysis/13/config.yml').read_text())
print({kind: len(entries) for kind, entries in d['mmio_models'].items()})
b = (F / '02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.bin').read_bytes()
print(hashlib.sha256(b).hexdigest(), struct.unpack_from('<II', b))
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
for insn in md.disasm(b[0x15a4:0x15ee], 0x815a4):
    print(hex(insn.address), insn.bytes.hex(), insn.mnemonic, insn.op_str)
```

Inspection 中两次小脚本分别因缺 CPU name attribute、vendor header 非 UTF-8 停止；已改为显式 unknown 和 Latin-1 fallback 读取所需片段。它们未修改输入，最终计数/结论使用修正后的输出。

## Z. Files Changed

仅新增 `docs/research/v3-2a0-firmware-corpus-reconnaissance.md`。无生产 source、dependency、prompt、schema、CaseBundle、workspace 或 exporter 改动；没有新增真实 firmware fixture，没有修改 corpus 或 reviewed snapshots。

## AA. Exact Test Results

使用本仓库 `.venv`：

```text
.venv/bin/python -m pytest -q
304 passed, 6 skipped in 3.33s

.venv/bin/python -m pip check
No broken requirements found.

.venv/bin/python -m compileall -q src tests
exit 0; no output

git diff --check
exit 0; no output
```

默认测试保留 socket/DNS/subprocess 阻断与真实调用 opt-in 隔离，未调用真实 LLM/网络。文档新增为 untracked，另用 `git diff --no-index --check /dev/null <document>` 检查其 whitespace；没有 whitespace 诊断，返回 1 表示相对空文件存在新增内容。未为检查而 staging。

## AB. Risks / Unknowns

- 有 reproducer 文件和旧版本配方，不等于本地可复现；未确定 crash13 的实际 PC/异常/寄存器/输入消费顺序。
- config 模型是保存的分析结果/仿真配置，缺完整生成 run provenance；任何 runtime claim 都应等待独立记录。
- P/F 同名 Heat_Press 不是同一构建；P source 仅作接口线索，不能给 F 强加源代码定位。
- Zephyr 文档 transcript 是作者转录的断点状态，与人工漏洞答案混排；CVE 路径也泄漏，不能直接进 Agent。
- static block lists 不是 CFG 或 coverage；symbol、局部 branch、外部输入可达、实际执行是不同证据等级。
- vendor source encoding、第三方编译依赖、ARM decoder 复杂 operands、Thumb instruction boundary 需要下一阶段明确处理。
- ARM firmware 对 RISC-V Ibex 没有直接 ISA 兼容性；本轮不做 cross-layer 配对或安全影响判断。
- 没有对真实硬件输入可控性、攻击者能力、漏洞确认或 CVE 有效性作外部验证；所有这类 corpus 标签留在 benchmark/reference。

## AC. Git Status

开始时工作区干净，结束时：

```text
?? docs/research/v3-2a0-firmware-corpus-reconnaissance.md
```

P、F 的 `git status --short` 结束时仍为空。未执行 git add/commit/push/tag。未进入 V3-2A1、V3-2B 或 Cross-Layer。

## 最后 15 个明确回答

1. **首 corpus：Fuzzware。**
2. **首 target：P2IM/Heat_Press + crash 13 场景。**
3. **首 parser artifacts：W 节四个精确路径的 ELF、BIN、13/config.yml、13/crashing_input。**
4. **可用 ELF：有，261365 bytes，ARM/Thumb-2，可读 LOAD 和 entry。**
5. **Symbols：有，781 行 nm 输出，UART/Modbus 等符号可定位。**
6. **确定性输入：能确认 emulator model/trigger 和 opaque input artifact；不能直接认定物理报文。**
7. **确定性 MMIO：能确认 32 配置 entries、23 PC、19 地址及部分静态读指令；无本地 runtime MMIO 事件。**
8. **真实 crash/fuzz evidence：有 corpus reproducer 和生成模型；首样本无独立 crash dump，未重放。Zephyr 另有作者保存的寄存器转录。**
9. **静态证据：ELF symbols、source calls、短窗口 branches、IDA block lists；后者连完整入口可达性都不能单独证明。**
10. **Runtime 证据：经审查的 register/trace/coverage 可证明对应 emulator run 的有限执行；现有 Zephyr transcript 仅支持作者的 breakpoint 状态，首样本没有本地 execution 证明。**
11. **隐藏 oracle：CVE/漏洞函数标签/root cause/expected answer/人工 bug location/exploitability、相关 README/patch 和泄漏身份路径。**
12. **EvidenceRef blocking extension：不需要；offset/双地址等暂由最小 typed details 和多条 refs 表达。**
13. **FirmwareAnalysisReport blocking schema problem：没有；保持三态 reachability 和未决问题，不能强填完整输入路径。**
14. **最小 A1：四文件有界 adapter + 三类最小 observations + 有证据范围的静态 IR + FirmwareAgentInput 离线验证，处理 typed serialization/oracle 边界。**
15. **真实 LLM：不需要；本轮没有调用，Firmware prompt v1 保持不变。**
