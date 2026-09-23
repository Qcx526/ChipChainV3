"""File-backed orchestration of existing controlled Type-II scientific APIs.

The manifest is a path index, not a new scientific model. The frozen verifier
replays the supplied ELF, raw traces, bridge and capability evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from chipchain.cross_layer.type2_verifier import (
    ControlledSourceEvidence, ObservationBinding, RunEvidence, StateBinding,
    Type2VerificationResult, verify_type2,
)
from chipchain.firmware.capability import FirmwareCapability
from chipchain.firmware.mmio_execution_bridge import BridgeSet, PlatformProof
from chipchain.firmware.mmio_grounding import (
    FirmwareMmioStaticCatalog, RuntimeMmioObservationSet, canonical, read_json,
)
from chipchain.hardware.behavior_contract import HardwareBehaviorContract

VERSION = "chipchain-type2-existing-artifacts/v1"
RUN_FIELDS = frozenset({"static", "bridge", "runtime", "platform", "capabilities", "inputs",
                        "elf", "bus", "processor", "stdout", "stderr", "observation_binding"})
SOURCE_FIELDS = frozenset(ControlledSourceEvidence.__dataclass_fields__)


@dataclass(frozen=True)
class Analysis:
    result: Type2VerificationResult
    contract: HardwareBehaviorContract
    state_binding: StateBinding | None
    target: RunEvidence
    reference: RunEvidence | None


def _index(path: Path, fields: frozenset[str]) -> dict:
    value = read_json(path.read_bytes())
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"Invalid artifact index fields: {path}")
    return value


def _file(base: Path, name: str) -> Path:
    if not isinstance(name, str) or not name:
        raise ValueError("Artifact path must be a nonempty string")
    path = (base / name).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def _run(path: Path) -> RunEvidence:
    index = _index(path, RUN_FIELDS)
    def raw(key: str) -> bytes:
        return _file(path.parent, index[key]).read_bytes()
    def model(key: str, cls):
        return cls.model_validate_json(raw(key))
    capabilities = read_json(raw("capabilities"))
    inputs = read_json(raw("inputs"))
    if not isinstance(capabilities, list) or not isinstance(inputs, dict):
        raise ValueError("Run capabilities and inputs have invalid shape")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in inputs.items()):
        raise ValueError("Run inputs must be string-to-string")
    binding = None if index["observation_binding"] is None else model(
        "observation_binding", ObservationBinding)
    return RunEvidence(
        static=model("static", FirmwareMmioStaticCatalog),
        bridge=model("bridge", BridgeSet), runtime=model("runtime", RuntimeMmioObservationSet),
        platform=model("platform", PlatformProof),
        capabilities=tuple(FirmwareCapability.model_validate(item) for item in capabilities),
        inputs=inputs, elf_bytes=raw("elf"), bus_bytes=raw("bus"),
        processor_bytes=raw("processor"), stdout_bytes=raw("stdout"),
        stderr_bytes=raw("stderr"), observation_binding=binding,
    )


def analyze_manifest(path: str | Path) -> Analysis:
    """Read an explicit artifact index, then call the frozen verifier without IO side effects."""
    path = Path(path).resolve()
    index = _index(path, frozenset({"schema_version", "contract", "state_binding",
                                    "controlled_source", "target_run", "reference_run"}))
    if index["schema_version"] != VERSION:
        raise ValueError("Unsupported artifact index version")
    source_index = index["controlled_source"]
    if source_index is None:
        source = None
    else:
        if not isinstance(source_index, dict) or set(source_index) != SOURCE_FIELDS:
            raise ValueError("Invalid controlled source index")
        source = ControlledSourceEvidence(**{
            key: _file(path.parent, source_index[key]).read_bytes() for key in SOURCE_FIELDS})
    contract = HardwareBehaviorContract.model_validate_json(
        _file(path.parent, index["contract"]).read_bytes())
    state = None if index["state_binding"] is None else StateBinding.model_validate_json(
        _file(path.parent, index["state_binding"]).read_bytes())
    target = _run(_file(path.parent, index["target_run"]))
    reference = None if index["reference_run"] is None else _run(
        _file(path.parent, index["reference_run"]))
    result = verify_type2(contract=contract, target=target, reference=reference,
                          state_binding=state, controlled_source=source)
    return Analysis(result=result, contract=contract, state_binding=state,
                    target=target, reference=reference)


def summary(analysis: Analysis) -> dict:
    result = analysis.result
    control = result.reference_control
    return {
        "result_id": result.result_id, "contract_id": analysis.contract.contract_id,
        "final_status": result.final_status, "trigger": result.trigger.status,
        "deviation": result.deviation.status, "observation": result.observation.status,
        "differential": result.differential.status,
        "reference_control": {
            "result_id": control.verification_id, "trigger": control.trigger_status,
            "expected_behavior": control.expected_behavior_status,
            "deviation_observed": control.deviation_observed,
        },
    }


def report(analysis: Analysis) -> str:
    item = summary(analysis)
    labels = {"verified_controlled_type2_chain": "受控合成 Type-II 链条已验证",
              "trigger_contradicted": "触发条件与观测证据矛盾",
              "deviation_contradicted": "观测与偏差条件矛盾",
              "unknown": "证据不足，无法判定"}
    control = item["reference_control"]
    status_text = {"supported": "有证据支持", "contradicted": "与证据矛盾", "unknown": "尚不能判定"}
    def readable(value: str) -> str:
        return f"{status_text[value]}（{value}）"
    explanations = {
        "verified_controlled_type2_chain": "触发条件、偏差、客观观测和 Reference/Variant 对照均有证据支持。Reference 触发同一条件后表现为预期值，未观测到偏差。",
        "trigger_contradicted": "已执行的 MMIO 访问与合同的触发值冲突；不能把后续读值解释为这条触发链的偏差。",
        "deviation_contradicted": "触发成立，但后续观测与要求的偏差不符。",
        "unknown": "已有证据不足以完成链条；请查看下方缺失项。",
    }
    reasons = {
        "PINNED_VARIANT_SCOPE": "目标、RTL 修订和合成来源吻合",
        "EXACT_EXECUTED_MMIO": "源指令与精确 MMIO 事务已绑定",
        "EXECUTED_CONFLICTING_MMIO": "已执行访问与要求的值冲突",
        "ACCEPTED_REQUEST_ORDER": "同一 reset epoch 中的访问顺序成立",
        "ACCEPTED_ENABLE_PRESTATE": "COMMAND 前的 ENABLE 状态成立",
        "ORDER_ENDPOINT_MISSING": "缺少满足条件的两个顺序端点",
        "COMMAND_ENDPOINT_MISSING": "缺少满足条件的 COMMAND 端点",
        "SCOPE_OR_SOURCE_BINDING_MISSING": "目标范围或来源绑定不完整",
        "OBSERVATION_BINDING_MISSING": "缺少明确的内部状态与总线读值绑定",
        "INTERNAL_AND_BUS_STATUS_AGREE": "更新后的内部状态与总线读值一致",
        "DIFFERENTIAL_REQUIREMENTS_MISSING": "Reference/Variant 对照所需证据不全",
        "PINNED_CONTROLLED_REFERENCE_VARIANT_DIFFERENCE": "受控 Reference/Variant 差异成立",
    }
    conditions = analysis.result.trigger.conditions
    lines = [
        "# ChipChain Type-II 验证报告", "",
        f"**结论：{labels[item['final_status']]}。**", "",
        explanations[item["final_status"]], "",
        f"- 硬件触发：{readable(item['trigger'])}", f"- 行为偏差：{readable(item['deviation'])}",
        f"- 客观观测：{readable(item['observation'])}",
        f"- Reference/Variant 对照：{readable(item['differential'])}", "",
        "## 触发条件逐项", "",
        "| 条件 | 判定 | 依据或阻断原因 |", "| --- | --- | --- |",
    ]
    for condition in conditions:
        reason = reasons.get(condition.reason_code, condition.reason_code)
        lines.append(f"| `{condition.requirement_id}` | {readable(condition.status)} | {reason} |")
    if item["final_status"] == "trigger_contradicted":
        lines += ["", "触发已被反证；后续偏差与对照保持未判定，不表示每项上游证据都缺失。"]
    elif analysis.result.observation.reason_code == "OBSERVATION_BINDING_MISSING":
        lines += ["", "## 关键阻断点", "",
                  "缺少内部 STATUS 样本与总线读值的显式观测绑定；已有读值不能直接升级为偏差证明。"]
    elif item["final_status"] == "unknown":
        missing = sorted({need for condition in conditions for need in condition.missing_requirements})
        lines += ["", "## 待核对项", "",
                  *[f"- `{need}`" for need in missing],
                  f"- 客观观测：`{analysis.result.observation.reason_code}`",
                  f"- 对照判断：`{analysis.result.differential.reason_code}`"]
    lines += [
        "", "## Reference 对照运行", "",
        f"- 触发：{readable(control['trigger'])}",
        f"- 预期行为：{readable(control['expected_behavior'])}",
        f"- 观测到偏差：{'否' if control['deviation_observed'] is False else '是' if control['deviation_observed'] is True else '未判定'}", "",
        "## 如何理解", "",
        "supported 表示所需证据成立；contradicted 表示证据与条件矛盾；unknown 表示尚不能判定。",
        "该结论仅适用于已固定的合成 RTL、固件和执行证据；不证明真实芯片存在漏洞，",
        "也不证明外部用户能控制固件执行路径。", "",
        f"验证对象：`{item['result_id']}`。详细条件、证据 ID 和缺失项见 `verification.json`。", "",
    ]
    return "\n".join(lines)


def write_result(analysis: Analysis, directory: str | Path, *, verbose_artifacts: bool = False) -> Path:
    """Persist only when explicitly called; normal output has three files."""
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise FileExistsError(f"Result directory is not empty: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "summary.json").write_text(canonical(summary(analysis)) + "\n")
    (directory / "verification.json").write_text(canonical(analysis.result) + "\n")
    (directory / "report.md").write_text(report(analysis))
    if verbose_artifacts:
        (directory / "contract.json").write_text(canonical(analysis.contract) + "\n")
        if analysis.state_binding:
            (directory / "state-binding.json").write_text(canonical(analysis.state_binding) + "\n")
        for prefix, run in (("target", analysis.target), ("reference", analysis.reference)):
            if run is None:
                continue
            for name, value in (("static", run.static), ("runtime", run.runtime),
                                ("bridge", run.bridge), ("platform", run.platform),
                                ("observation-binding", run.observation_binding)):
                if value is None:
                    continue
                (directory / f"{prefix}-{name}.json").write_text(canonical(value) + "\n")
            (directory / f"{prefix}-capabilities.json").write_text(canonical(
                [value.model_dump(mode="json") for value in run.capabilities]) + "\n")
    return directory
