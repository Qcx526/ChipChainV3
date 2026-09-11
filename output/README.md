# Analysis result workspace

未来持久化结果统一使用本工作区，推荐 `output/<case_id>/<run_id>/`，保存 AnalysisRun JSON
及后续 report、IR、graph export、verification/evaluation artifacts。实际运行数据默认忽略 Git。

R0-C 返回可序列化的 AnalysisRun，不自动写文件。调用方可显式调用 `model_dump_json()`
并保存到所选输出位置；组织目录时应自行将 case ID 映射为安全的文件名。
domain model 不依赖 `output/` 相对路径。此目录中的 README 已承担占位作用。
