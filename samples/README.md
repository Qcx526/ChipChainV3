# Real sample workspace

这里存放项目实际使用的研究输入；`examples/` 与 `tests/` 继续只保存 synthetic 数据。
当前本地材料已复制到工程目录，并逐文件核对源文件的 SHA256；原外部资源未移动、未删除。
实际内容默认被 Git 忽略，因此 clone 仓库不会自动获得这些本地材料。

| 材料 | 项目内位置 | 用途 |
| --- | --- | --- |
| Ibex Simple System 源树 | `hardware/ibex-simple-system/source/` | 完整 tracked source（含同树 firmware source），base `405c6d1d8220a18b2f9196141167a5875422dee4` + DATA1A metadata shim |
| 兼容 shim / 模拟器 | `hardware/ibex-simple-system/compatibility-shim.patch`、`bin/Vibex_simple_system` | 保存实际 effective metadata 与已验证 simulator bytes |
| hello_test ELF/BIN/disassembly | `firmware/ibex-simple-system/hello-test/` | 后续 golden/mutant 共用的固件输入；源码只保存于上面的同树 source |
| EnCorpus Ibex 743/820 | `hardware/encorpus/ibex/driver/{743,820}/` | 原始 RTLIL、VCD、verify log；共享 reference.v/miter.tcl 在 ibex 根 |
| Heat_Press scenario 13 | `firmware/fuzzware-experiments/` | ELF、BIN、config.yml、opaque input；保留已有 reader 所需相对布局 |

`local-manifest.json` 是被忽略的本机导入清单：每个文件的来源、项目内路径、size、SHA256。
当前导入 3715 个来源文件，共 76,042,820 bytes（约 72.5 MiB），不含本地 case/manifest 文件。
Ibex source 不是 Git checkout；不要在这里进行 mutation，后续实验仍使用独立 worktree。
工具链、Verilator 安装、Python 环境仍在外部资源目录；样本在工程内不等于构建环境已完全自包含。

## Local CaseBundle views

所有 `ArtifactRef.path` 以 repository root 为相对路径基准；从工程根运行示例。
这些是新工作区视图，未改写历史 AnalysisRun、pair descriptor 或 DATA1A manifest。

- `hardware/encorpus/ibex/driver/743/case.json`
- `hardware/encorpus/ibex/driver/820/case.json`
- `firmware/fuzzware-experiments/heat-press-case.json`
- `hardware/ibex-simple-system/case.json`
- `firmware/ibex-simple-system/hello-test/case.json`
- `firmware/ibex-simple-system/hello-test/paired-case.json`

paired view 同时引用两侧材料，不创建 `samples/cross_layer/`，不重复复制 artifact。
DATA1A trace、FST、stdout、counters 和其他实验结果仍在 `output/paired/ibex-simple-system/data1a-r1/`，
硬件 case 直接引用那里已有的 trace。`paired-case.json` 的 CaseBundle 配对不重新计算或替换冻结 XL0 pair。

```python
from pathlib import Path
from chipchain.domain.case import CaseBundle

case = CaseBundle.model_validate_json(Path(
    "samples/firmware/ibex-simple-system/hello-test/paired-case.json"
).read_text())
assert case.is_paired
```

## Read-only local ingestion checks

从项目根显式运行已有真实样本 integration tests：

```bash
CHIPCHAIN_ENCORPUS_IBEX_ROOT="$PWD/samples/hardware/encorpus/ibex" \
  .venv/bin/python -m pytest -q tests/integration/test_encorpus_local.py
CHIPCHAIN_FUZZWARE_ROOT="$PWD/samples/firmware/fuzzware-experiments" \
  .venv/bin/python -m pytest -q tests/integration/test_fuzzware_local.py
```

这些测试不调用真实模型。EnCorpus 的 oracle 材料继续由已有 ingestion/projection 边界处理；
放入 samples 不会改变其科学角色。Heat_Press 与 EnCorpus Ibex 仍不是同一 target 的 eligible pair。
外部只读 artifact 路径仍合法，domain validator 不限制到本目录。

本次整理验证：全部 3715 个导入文件与源文件 SHA 相同，六个 CaseBundle 的全部 artifact refs 可解析且 fingerprint 一致。
项目内路径的真实 ingestion checks：`7 passed in 3.28s`。
完整回归：`1064 passed, 27 skipped in 28.61s`；pip check、compileall、git diff --check 通过。
既有 source/tests、synthetic case JSON、DATA0/DATA1A 文档与历史 output 未改写；未重跑仿真、未调用真实模型。
