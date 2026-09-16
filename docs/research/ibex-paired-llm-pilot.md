# Ibex 配对基线的三 Agent 真实分析试运行

本入口将工程内 Ibex Simple System 模拟器和 `hello_test.elf` 重新运行，
再把实际产物交给现有 LangGraph 工作流的 Hardware、Firmware、Cross-Layer 三个阶段。
这是当前配对基线的最小分析接入，不代表完整 RTL 审计、漏洞检测或受控变异实验已经实现。

## 执行

从 repository root 执行，使用本地 `.env` 中的 DeepSeek key：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 .venv/bin/python -m chipchain.integrations.paired_baseline \
  --root . --env-file .env --output-root output
```

硬件、固件分别读取 `CHIPCHAIN_HARDWARE_MODEL` 和 `CHIPCHAIN_FIRMWARE_MODEL`；
此次 Cross-Layer 明确复用硬件模型配置。每阶段最多一次调用，无自动重试；
上游失败后跨层阶段保持 blocked。每次运行使用新的 UUID。
模型设置为 temperature=0、max_tokens=16384、timeout=180 秒、thinking disabled。
实际费用以 provider 计费为准；各阶段 token 数记录在 invocation 文件中。

## 数据如何进入模型

1. 校验本地 ELF、模拟器与 DATA1A 冻结 SHA/大小一致，核对冻结 pair descriptor。
2. 在新的 output 目录执行真实 RTL 仿真，保存 stdout、stderr、ASCII、trace、计数器和 FST。
3. 解析每条 RVFI 文本记录，逐条核对指令字节与 ELF 可执行 segment 一致。
4. 硬件上下文含完整记录数及助记符统计、控制台输出和选定的原始记录。
   选取规则为第一条、最后一条，以及每个低于 `0x100000` 地址的第一次内存访问；
   地址阈值只是取样规则，不自动推断外设语义。不会向模型发送全部 1183 条记录。
5. 固件上下文含 ELF header、函数符号和上述位置的静态 RV32+C 解码。
   静态指令来自 ELF；借用 trace PC 选择位置，不把静态证据升级为固件 runtime path。
6. 两侧 Agent 接收独立 observation，工作流合并确定性 IR，再调用 Cross-Layer Agent。

observer 是工作流的显式可选参数。未提供时仍使用原有 stub，不隐式读取文件或调用模型。
硬件和跨层试运行使用 ID-only 输出合同，由程序绑定原始 EvidenceRef；
固件继续使用已有 ID-only 合同。每个报告继续检查 case、behavior、evidence 和 finding 引用。
这属于 generic evidence binding，**没有运行 A3/B2、A4/B3 typed relation-support gate**；
引用有效不等于结论成立，不得将此次输出宣传为 support-certified。

## 结果与验收

输出目录为 `output/<case_id>/<run_id>/`，默认被 Git 忽略。包含：

- 原始仿真产物、执行命令与输入身份；
- 两侧 observation、选取审计和中立 artifact ID 的 CaseBundle；
- 每阶段的 analysis input、prompt、output schema、invocation 状态及用量；
- 校验通过的各侧报告、AnalysisRun 和聚合 IR；
- 源码 SHA 清单与产物 SHA 清单；
- 本次人工可读的中文解读另存为 `report-zh.md`，不自动标记 reviewed。

运行成功只证明这些模型阶段和输入绑定完成。没有异常证据时，候选应保持为空或明确说明不足。
未运行 formal、参考 ISA 差分、Ghidra、angr、攻击路径验证或修改硬件。
后续需要通过独立证据验证模型叙述，再决定是否开展受控变异实验。

## 已知限制

当前适配器专用于这份小型 RV32+C baseline，设有上下文预算；超出预算会拒绝而不静默截断。
保留全部 raw trace 以便审计，但选取内容不覆盖所有动态行为。
函数符号名称不能证明函数含义，也不能证明外部输入可达。
平台身份仍依赖冻结记录和本地模拟器 SHA；本入口不重新编译 RTL。
运行库继续依赖冻结环境中的外部 libelf 路径。

## 本机真实结果（2026-09-16）

- 首轮 `ce792caa-e2a4-4118-965a-35f5e2c53d34`：硬件 structured output 被拒绝，固件完成，跨层 blocked。
- 修正后的 `d362bd15-c924-46af-bcae-12aa960afa50`：三个真实 Agent 和 IR aggregation 均 completed。
- 成功 run：硬件 4 findings，固件 6 findings / 1 static reachable behavior / 2 issue anchors；跨层候选为 0。
- 成功 run 用量 29294 tokens；两轮共 5 次调用、47890 tokens，没有自动重试。
- 全量测试：`1076 passed, 27 skipped in 27.22s`。

**语义验收尚未通过。** 固件模型把入口偏移 `0x2c6` 算成错误的目标 `0x1002c6`；
正确值为 `0x100080 + 0x2c6 = 0x100346`（reset_handler）。它还把 puts 内的
`0x1000a0` 错归到 puthex。原始模型报告保持不变，更正在输出目录的 `semantic_review.json`。

完整中文说明保存在本机
`output/ibex-simple-system:hello-test:paired-workspace/d362bd15-c924-46af-bcae-12aa960afa50/report-zh.md`。
下一步优先补充确定性的跳转目标、函数区间归属和配置摘要，不把引用校验当作语义支持证明。
