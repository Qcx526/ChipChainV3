# V3-R1.1 — Narrow Boundary Refactor

## Baseline and scope

起点：`main`，HEAD `a9c7e3d96e7bcf78b7c669b5abb5d47e4b5e9294`，tag `v3-r1a-audit-stable`；开始前工作区 clean，`git diff --check` exit 0。A6 scientific baseline 为 `v3-fw-a6-stable` / `39e72ee3a5cc1dd2eb1bb3db10ed218b93894c5e`。本轮没有创建或修改任何 tag。

本阶段只建立 current-state single source of truth、迁移纯人类可读 renderer 并保留兼容路径。
**behavior-preserving refactor ≠ new scientific capability**。没有新检测能力或新科学实验。

实际变更仅 8 个授权文件：

| 文件 | 操作 |
| --- | --- |
| `README.md` | 修正当前时态漂移、链接 CURRENT_STATE，保留历史段落与结论 |
| `CURRENT_STATE.md` | 新增唯一当前状态入口 |
| `src/chipchain/reporting/__init__.py` | 新增仅含 docstring 的 package |
| `src/chipchain/reporting/firmware_grounding.py` | 新增 renderer 唯一实现，与 A6 旧源文件逐字节一致 |
| `src/chipchain/firmware/grounding_report.py` | 保留文件，改为兼容导出，不保留第二份实现 |
| `src/chipchain/integrations/paired_baseline.py` | 仅替换 renderer import，一行变更 |
| `tests/unit/test_reporting_compatibility.py` | 新增独立 frozen-output oracle、兼容身份与导入边界测试 |
| `docs/research/v3-r1-1-boundary-refactor.md` | 本研究记录 |

授权可改的 `tests/unit/test_firmware_a6_evidence.py` 实际未修改，继续通过旧 import 调用，保留原有行为回归。没有修改 scope 外的已有文件，也没有额外必须修改文件，因此无需 REVIEW_REQUIRED 扩展。

## Reporting boundary and compatibility

唯一 renderer implementation 位于 `chipchain.reporting.firmware_grounding.render_report`。它读取调用方给定目录中的既有 JSON，返回 Markdown 字符串，不生成事实、不调用模型、不改变 support 校验。

旧路径保留：

```python
from chipchain.firmware.grounding_report import render_report
from chipchain.reporting.firmware_grounding import render_report as new_render_report
assert render_report is new_render_report
```

旧文件只有 docstring、显式 import 和 `__all__`。reporting package 初始化只有 docstring，没有 provider import、Agent 构造、业务注册、文件写入或 logging。

`paired_baseline.py` 经完整文件比对，唯一差异为：

```diff
-from chipchain.firmware.grounding_report import render_report
+from chipchain.reporting.firmware_grounding import render_report
```

没有改变 CLI/default flag、LLM配置/模型、simulation command、A6 catalog/preflight、prompt/schema/context、选址、support、IR、Cross-Layer、写文件、run status 或 retry。`--firmware-grounding` 仍为显式 opt-in。

迁移没有调整文案、Markdown表头/格式、排序、escaping、unknown措辞、候选边界、token/call统计、artifact links或读取逻辑。Python函数的定义模块改为 reporting 是此次边界迁移本身；不承诺外部依赖 `__module__` 字符串的未知消费者无需适配，但旧函数 import/call API 兼容。

## Independent baseline parity oracle

Oracle **在搬迁前**从冻结 Git 对象产生：

```text
v3-fw-a6-stable:src/chipchain/firmware/grounding_report.py
commit: 39e72ee3a5cc1dd2eb1bb3db10ed218b93894c5e
source SHA256: f6f20e147c05a0834d81f443556cf1dc1b70a7ba78ca78af3f98adc43ce6f485
```

步骤：读取 `git show` 字节，确认与搬迁前文件相同；在独立 ModuleType 中 compile/exec 冻结源码；对 `synthetic_artifacts()` 构造的三个临时目录运行旧 renderer；记录完整返回值 UTF-8 bytes 的长度和 SHA256，然后才搬迁。旧输出全文仅临时保存在 `/tmp` 供一次逐字节比较，仓库只提交测试中的三个小型 golden hash/length 常量，不复制真实 provider response 或 ignored output。

| 合成场景 | 输出字节数 | 完整 UTF-8 输出 SHA256 |
| --- | ---: | --- |
| supported_rejected | 2968 | `7557f14a99085fe74a7781366565f62fa5cd94d85b67fe4cdb3122fb5484948b` |
| missing_validation | 1952 | `e05a9b47f7340b682863f4ada842e51257d322ecd59cd3e67a7a19f6f068e0e7` |
| candidate_exists | 2240 | `e7353e594c5170f5585afe6c0fd918cf95eabd7399ac3158aea134ce5c65c949` |

Case A 覆盖 supported target、incompatible/rejected owner、两条 raw摘要、精确 evidence 展示、canonical interpretation、escaping、0候选警示、两条合成调用/26 tokens。
Case B 缺少 A6 raw/support/context 和 cross报告，保持“未产生可用的 A6 声明校验结果”、未知研究上下文、跨层报告不可用及0调用语义。
Case C 有一条 synthetic candidate，保持“仍需独立验证”，另覆盖返回模型名 fallback、缺失 usage/finish 的 unknown 展示。

这些是 renderer 输入fixture，不表示执行了任何模型或分析器。地址、ID、文字和用量均合成；不依赖用户主机绝对路径、真实 sample、网络或 Git 可用性。正常pytest只比较已固定的hash，不执行`git show`、不重算golden。

三场景迁移后均与保存的旧输出 **逐字节相同**；pytest同时检查完整输出length/SHA与关键语义文本。新实现源文件也与冻结旧源文件 **逐字节相同**。没有通过更新golden解决失败；三个oracle自生成后未变。

复核oracle来源可在有Git历史的审计环境离线执行以下方法，但它不是测试运行时依赖，且不应写回golden：

```python
import hashlib, runpy, subprocess, tempfile, types
from pathlib import Path

source = subprocess.check_output([
    'git', 'show', 'v3-fw-a6-stable:src/chipchain/firmware/grounding_report.py'
])
assert hashlib.sha256(source).hexdigest() == 'f6f20e147c05a0834d81f443556cf1dc1b70a7ba78ca78af3f98adc43ce6f485'
frozen = types.ModuleType('frozen_a6_renderer')
exec(compile(source, '<frozen A6 renderer>', 'exec'), frozen.__dict__)
helpers = runpy.run_path('tests/unit/test_reporting_compatibility.py')
for scenario, expected in helpers['BASELINE_ORACLES'].items():
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        helpers['write_synthetic_artifacts'](directory, scenario)
        output = frozen.render_report(directory).encode('utf-8')
        assert len(output) == expected['bytes']
        assert hashlib.sha256(output).hexdigest() == expected['sha256']
```

## Import isolation validation

初版 smoke 测试拟启动子进程，被既有 `tests/conftest.py` 的 offline boundary 拦截。该失败是测试方法与套件约束冲突，不是renderer parity失败；没有修改conftest、没有绕过套件的网络/外部工具保护。

最终pytest测试只清除新旧reporting模块缓存，在可恢复的上下文中拦截provider/Agent/runtime/logging imports及文件修改，禁写bytecode，实际重新导入两条路径并验证同一函数身份，然后恢复缓存与父包属性。

另外在pytest外做独立干净解释器 smoke（`python -I -B`）：拦截 provider/Agent/runtime/logging imports；audit hook拒绝open写模式、mkdir/remove/rename/chmod、子进程、network connect/bind；检查无provider模块载入、无stdout/stderr。exit 0。

因此没有在生产reporting导入中观察到provider/model/API创建、业务文件写入、logging或注册逻辑。Python标准module加载本身与业务runtime注册区分；`-B`排除了正常解释器bytecode缓存写入。

## README drift corrections and CURRENT_STATE scope

README顶部新增CURRENT_STATE入口。DATA1A与XL0“当前阶段”改为历史阶段限定；保留DATA1A恢复时待冻结、XL0当时没有真实Cross-Layer接入的事实。Hardware B2待审核、本轮B3/B3-R2/B3-R3调用等表述加明确阶段限定；保留原负结果与未知原因。没有删去历史段落或实验结论。

“真实Cross-Layer Agent集成仍未进入”改为XL0阶段的历史状态，并指向后续实际paired/A6入口。不带flag的generic路径与A6路径分别说明；15条投影事实明确为冻结样本结果而非普遍限制。

CURRENT_STATE集中记录两个冻结基线、R1.1性质、当前真实CLI与opt-in flag、真实链路、XL0 eligibility/matcher差异、paired Hardware generic与B2支持pipeline差异、A4/A5 not_comparable条件、IR和A6 catalog范围、七组科学边界以及未建立的能力。它只索引历史，不复制所有实验。

## Validation

A6与reporting专项：**92 passed in 1.61s**，包括原有wrong/correct target、wrong/correct owner、ambiguous/indirect、raw隔离和全部新增reporting测试。

完整执行：

```text
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
1168 passed, 27 skipped in 29.97s

.venv/bin/python -m pip check
No broken requirements found.

.venv/bin/python -m compileall -q src tests
exit 0

git diff --check
exit 0
```

新旧import均通过；`old.render_report is new.render_report`成立。三个baseline完整输出长度/SHA及临时旧输出bytes均一致。未修改任何schema、prompt、support semantics、A6 facts或Cross-Layer逻辑。27项skip保持环境依赖语义，不改称执行通过。

## Historical protection and Git scope

开始时保护快照：255个tracked文件、4064个本地samples/output文件、29个tag。

- 仅3个既有tracked文件变动：README、旧renderer facade、paired_baseline import。
- 其余 **252个tracked文件字节不变**，包括R1-A五个audit snapshot、两个A6文档、所有原tests、reviewed/tutorial/DATA1A/B3资料。
- 原有116个production Python中，114个不变；另外2个是授权的facade/import变更。新增2个reporting Python文件。
- **4064个本地samples/output文件全部SHA未变**；没有改写任何真实输出/样本、负例、A6回归。
- 29个tag名称集合及commit指向全部不变；HEAD仍为起始baseline。
- 唯一新增研究记录为本文。没有scope外修改，无production module删除。
- 本轮provider/LLM/API调用 **0**，真实simulator运行 **0**。没有RTL mutation、新fuzzing、R1.2或XL1实现。
- 没有执行git add/commit/push/tag；由用户审核后决定冻结。

最终Git状态应仅包含：

```text
 M README.md
 M src/chipchain/firmware/grounding_report.py
 M src/chipchain/integrations/paired_baseline.py
?? CURRENT_STATE.md
?? docs/research/v3-r1-1-boundary-refactor.md
?? src/chipchain/reporting/__init__.py
?? src/chipchain/reporting/firmware_grounding.py
?? tests/unit/test_reporting_compatibility.py
```

## Remaining architecture debt and next proposal

R1-A发现的paired runner多职责、generic/typed支持并存、tools依赖AgentInput、多套canonicalization/registry/projection与历史版本兼容仍存在。本阶段没有借移动renderer改变它们。

建议 **有条件GO到狭窄R1.2**，前提是人工审核并冻结本阶段。最小下一步可先审查并抽离 `integrations.deepseek_hardware.validate_real_report` 这一共享硬件报告gate到独立validator模块，保留旧路径兼容导出，仅调整paired入口的gate import，以减小EnCorpus integration耦合。需先确认public消费者、import副作用、拒绝原因/异常类型与报告接受行为的baseline parity；任一项UNKNOWN则停留在审计，不迁移。

不同时迁移paired_agents/grounded_agent，不拆runner、不统一support策略、不删文件、不新增检测语义。该提案尚未执行，R1.1在此结束。
