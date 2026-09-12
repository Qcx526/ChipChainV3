# Analysis result workspace

本工作区分为两层：

| 位置 | 用途 | Git policy |
| --- | --- | --- |
| `output/<runtime-case>/<run-id>/` | 原始本地运行结果、临时失败记录及调试材料 | 默认 ignored |
| `output/reviewed/<phase>/<safe-case-slug>/<run-id>/` | 人工接受并经显式验证、安全检查的研究快照 | 可跟踪，提交仍由人工执行 |

真实 Hardware/Firmware/Cross-Layer LLM 成功后必须先持久化结构化 report 和 AnalysisRun。
如果要供远程研究审核，应再通过 reviewed exporter 生成可提交快照。
本轮仅实现并验证 Hardware exporter，未实现未来 Firmware/Cross-Layer 导出流程。

显式命令（从 repository root 执行；`--accepted` 表示该 run 已被人工接受用于分享）：

```bash
.venv/bin/python -m chipchain.execution.reviewed_output \
  output/encorpus:ibex:driver:743/8eae2090-1c8b-450c-8d35-3de378a7723b \
  --phase v3-1b1 --accepted --env-file .env
```

不会调用模型、改原运行目录或执行 Git 操作。目标存在则拒绝；如需另一份快照，使用新 phase/experiment
或新 run ID。`--env-file` 只在显式提供时读取 DEEPSEEK_API_KEY 做内容匹配，import 不加载秘密。
省略时仍执行结构和常见凭据/raw-response 检查，但不能证明未知任意秘密不存在，人工安全审核仍必要。

当前仅复制五个允许文件：analysis_run.json、hardware_analysis_report.json、analysis_input.json、
invocation.json、invocation_attempts.jsonl。failure/debug/raw response/ELF/VCD/RTLIL/.env 等文件不复制。
允许文件内发现不安全内容则拒绝整次导出，不做内容清洗、JSON repair 或报告重写。

校验完成状态、run/report equality、case/run ID、context/IR、证据引用、model/provider/prompt 一致性、
context SHA256 和每行 attempts schema。已脱敏的 failed attempt 可保留，但当前 run 仍须有成功记录。
manifest 记录 phase、原 case/run ID、安全 slug、Agent/model/prompt、状态及五个原样复制文件的
SHA256/size_bytes；manifest 不保存绝对本机路径，也不循环记录自己的哈希。
哈希识别内容，不是数字签名或因果正确性证明。

B.1 writer 对发送给模型的 context 文本计算 hash，然后落盘时附加一个 LF。
exporter 只允许精确文件 bytes 或排除单个 terminal LF 这两种已记录口径；不任意 trim 或重排 JSON。
manifest 的文件 hash 始终覆盖完整原文件 bytes（含换行）；`.gitattributes` 为 reviewed JSON/JSONL
禁用 checkout 换行转换，以保留跨平台哈希一致性。

目录名使用 `encorpus-ibex-driver-743` 等安全 slug，JSON 内 domain case ID 不变。
manifest 不保存本机路径；为保持原始证据和 context 完整，复制的 analysis_input.json 中仍保留
原 artifact provenance 路径。它们是历史来源引用，不要求远程审核者拥有相同本机路径。

当前接受的真实 B.1 快照：

- [743 manifest](reviewed/v3-1b1/encorpus-ibex-driver-743/8eae2090-1c8b-450c-8d35-3de378a7723b/manifest.json)
- [820 manifest](reviewed/v3-1b1/encorpus-ibex-driver-820/a663c6f7-ea28-4929-b788-d059475d28e9/manifest.json)

它们是真实模型输出，不是 synthetic fixtures。人工接受不等于已验证硬件 trigger；
已知的持续时间措辞、通用限制回显及引用粒度问题仍见
[B.1 研究审核](../docs/research/v3-1b1-operational-evidence.md)，本轮没有修写这些原报告。

R0-C 返回可序列化的 AnalysisRun，不自动写文件。调用方可显式调用 `model_dump_json()`
并保存到所选输出位置；组织目录时应自行将 case ID 映射为安全的文件名。
domain model 不依赖 `output/` 相对路径。此目录中的 README 已承担占位作用。
