"""Explicit, read-only Ibex driver ingestion. No model calls or workflow hooks."""

import hashlib
import stat
from pathlib import Path

from chipchain.domain.behavior import BehaviorKind, ProcessorBehavior, ProcessorBehaviorIR
from chipchain.domain.case import ArtifactRef, ArtifactType, TargetDescriptor
from chipchain.domain.common import AnalysisLayer, Architecture, EpistemicStatus
from chipchain.domain.evidence import BitRange, EvidenceLocation, EvidenceRef, EvidenceSourceType, EvidenceTime
from chipchain.tools.contracts import (
    FormalResultDetails, HardwareObservation, HardwareObservationKind as Kind,
    HardwareObservations, MutationAnchorDetails, ObservationRole, SignalValue, WaveformObservationDetails,
)
from chipchain.tools.hardware.encorpus.models import (
    ArtifactRole as Role, ClassifiedArtifact, EnCorpusIngestionResult, EnCorpusOracle, IngestionError,
)
from chipchain.tools.hardware.encorpus.readers import (
    MAX_BYTES, Signal, Value, parse_driver_mutation, parse_formal_log, parse_vcd,
)

ANALYZER_ID = "encorpus-ibex-driver-v1"
FORMAL_BOUNDARY = (
    "Historical corpus result only; SVA/reset harness is incomplete. "
    "No independent formal replay, verified trigger, or security impact is established."
)
ANALYSIS_LIMITATIONS = [
    "Host ID-stage encoding changes in a supplied formal witness; not a retired instruction trace.",
    "No instruction decoder, read/write inference, full control flow, or trigger causality is extracted.",
]
ORACLE_LIMITATIONS = [
    FORMAL_BOUNDARY,
    "Golden-derived mutation and host/reference comparisons are benchmark oracle information.",
    "GPR packing is the A0-checked Ibex 32-bit rf_reg_q[1023:32] layout; other layouts are rejected.",
    "Only debug_mode_q and LSU ls_fsm_cs/ls_fsm_ns are compared as local state; no bug-site causality is inferred.",
]
FILES = {
    "host_driver.rtlil": (ArtifactType.HARDWARE_DESCRIPTION, "rtlil"),
    "reference_driver.rtlil": (ArtifactType.HARDWARE_DESCRIPTION, "rtlil"),
    "proof.vcd": (ArtifactType.HARDWARE_TRACE, "vcd"),
    "verify.log": (ArtifactType.OTHER, "log"),
}
HOST = "miter.\\host."
REFERENCE = "miter.\\reference."
ID_BASE = "u_ibex_core.if_stage_i."
ENCODINGS = [ID_BASE + "instr_rdata_id_o", ID_BASE + "instr_rdata_alu_id_o"]
VALID = ID_BASE + "instr_valid_id_q"
EXECUTING = "u_ibex_core.id_stage_i.instr_executing"
PC = ID_BASE + "pc_id_o"
GPR = "gen_regfile_ff.register_file_i.rf_reg_q"
LOCAL = [
    "u_ibex_core.id_stage_i.controller_i.debug_mode_q",
    "u_ibex_core.load_store_unit_i.ls_fsm_cs",
    "u_ibex_core.load_store_unit_i.ls_fsm_ns",
]


def _read(path: Path) -> tuple[str, str, int]:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise IngestionError(f"Not a regular artifact: {path}")
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise IngestionError(f"Artifact exceeds 16 MiB reader limit: {path}")
        return data.decode("ascii"), hashlib.sha256(data).hexdigest(), len(data)
    except (OSError, UnicodeError) as exc:
        raise IngestionError(f"Cannot read ASCII artifact {path}: {exc}") from exc


def _evidence(artifact_id, *, line, summary, signal=None, time=None, bit_range=None, register=None):
    identity = repr((artifact_id, line, signal, time, bit_range, register)).encode()
    return EvidenceRef(
        evidence_id=f"{artifact_id}:e:{hashlib.sha256(identity).hexdigest()[:20]}",
        source_type=EvidenceSourceType.DETERMINISTIC_ANALYZER, artifact_id=artifact_id,
        analyzer=ANALYZER_ID, summary=summary, epistemic_status=EpistemicStatus.DERIVED,
        location=EvidenceLocation(line=line, signal=signal, time=time, bit_range=bit_range,
                                  register_name=register),
    )


def _wave_evidence(artifact_id, signal, value, time, bit_range=None, register=None):
    return _evidence(artifact_id, line=value.line, summary="Value at this time carried from source assignment.",
                     signal=signal.name, time=time, bit_range=bit_range or signal.bit_range, register=register)


def _signal_value(signal, value, role, bit_range=None):
    return SignalValue(signal=signal.name, role=role, width=len(value.bits),
                       bit_range=bit_range or signal.bit_range, value=value.bits,
                       declaration_line=signal.line)


def _known(bits):
    return not any(c in bits for c in "xz")


def _extract_waveform(text, artifact_id, case_id, *, include_oracle):
    selected = {HOST + n for n in [*ENCODINGS, VALID, EXECUTING, PC]}
    if include_oracle:
        selected.update(side + n for side in [HOST, REFERENCE] for n in [GPR, *LOCAL])
    wave = parse_vcd(text, select=lambda name: name in selected)
    signals = wave.signals
    encoding_name = next((HOST + name for name in ENCODINGS if HOST + name in signals), None)
    required = [HOST + VALID, HOST + EXECUTING, HOST + PC]
    if encoding_name is None or any(name not in signals for name in required):
        raise IngestionError("Unsupported Ibex VCD layout: missing host ID encoding/valid/executing/PC")
    if signals[encoding_name].width != 32 or signals[HOST + PC].width != 32 or any(
        signals[HOST + n].width != 1 for n in [VALID, EXECUTING]
    ):
        raise IngestionError("Unsupported host ID signal widths")
    local = []
    if include_oracle:
        for side in [HOST, REFERENCE]:
            s = signals.get(side + GPR)
            if s is None or s.width != 992 or s.bit_range != BitRange(msb=1023, lsb=32):
                raise IngestionError("Unsupported Ibex GPR layout: expected rf_reg_q[1023:32]")
        for name in LOCAL:
            h, r = signals.get(HOST + name), signals.get(REFERENCE + name)
            if (h is None) != (r is None):
                raise IngestionError("Unpaired local state signal")
            if h is not None:
                if h.width != r.width or h.bit_range != r.bit_range:
                    raise IngestionError("Mismatched local state layout")
                local.append(name)
        if not local:
            raise IngestionError("Unsupported Ibex layout: no supported local state pair")
    analysis, oracle, last_pairs = [], [], {}
    previous_encoding = None
    missing_values = False
    oracle_missing_values = False

    def difference(name, hs, rs, hv, rv, time, register=None, bit_range=None):
        nonlocal oracle_missing_values
        if not _known(hv.bits + rv.bits):
            oracle_missing_values = True
            last_pairs[name] = None
            return
        pair = (hv.bits, rv.bits)
        changed = hv.bits != rv.bits and pair != last_pairs.get(name)
        last_pairs[name] = pair
        if not changed:
            return
        evidence = [_wave_evidence(artifact_id, s, v, time, bit_range, register)
                    for s, v in [(hs, hv), (rs, rv)]]
        token = hashlib.sha256(name.encode()).hexdigest()[:12]
        oid = f"{case_id}:difference:{token}:{time.value}"
        behaviors = []
        if register:
            behaviors.append(ProcessorBehavior(
                behavior_id=oid + ":register-state", kind=BehaviorKind.REGISTER_ACCESS,
                architecture=Architecture.RISCV, origin=AnalysisLayer.HARDWARE,
                summary=f"{register} host/reference state differs in the supplied witness; access direction unknown.",
                evidence=evidence, epistemic_status=EpistemicStatus.DERIVED,
                attributes={"register": register, "observation": "register_state_difference",
                            "host_value": hex(int(hv.bits, 2)), "reference_value": hex(int(rv.bits, 2)),
                            "time_value": time.value, "time_unit": time.unit},
            ))
        oracle.append(HardwareObservation(
            observation_id=oid,
            kind=Kind.ARCHITECTURAL_PROPAGATION_OBSERVED if register else Kind.LOCAL_EFFECT_OBSERVED,
            summary=f"Observed unequal {'GPR' if register else 'local state'} values; causality not established.",
            evidence=evidence, behaviors=behaviors, epistemic_status=EpistemicStatus.DERIVED,
            details=WaveformObservationDetails(time=time, host=_signal_value(hs, hv, "host", bit_range),
                reference=_signal_value(rs, rv, "reference", bit_range), register_name=register,
                observation_stage="register_state" if register else "local_state"),
        ))

    for raw_time, values in wave.frames:
        time = EvidenceTime(value=raw_time * wave.scale, unit=wave.unit)
        stage_signals = [signals[n] for n in [encoding_name, *required]]
        stage = [values.get(s.code) for s in stage_signals]
        if all(v is not None and _known(v.bits) for v in stage):
            encoding, valid, executing, pc = stage
            if valid.bits == executing.bits == "1":
                if encoding.bits != previous_encoding:
                    evidence = [_wave_evidence(artifact_id, s, v, time) for s, v in zip(stage_signals, stage)]
                    hex_word = f"0x{int(encoding.bits, 2):08x}"
                    oid = f"{case_id}:id-encoding:{time.value}"
                    behavior = ProcessorBehavior(
                        behavior_id=oid + ":instruction", kind=BehaviorKind.INSTRUCTION,
                        architecture=Architecture.RISCV, origin=AnalysisLayer.HARDWARE,
                        summary="Host ID-stage instruction encoding observed; retirement not established.",
                        evidence=evidence, epistemic_status=EpistemicStatus.DERIVED,
                        attributes={"encoding": hex_word, "pc": int(pc.bits, 2), "observation_stage": "id",
                                    "time_value": time.value, "time_unit": time.unit},
                    )
                    analysis.append(HardwareObservation(
                        observation_id=oid, kind=Kind.INSTRUCTION_ENCODING_OBSERVED,
                        role=ObservationRole.ANALYSIS_INPUT, summary=behavior.summary,
                        evidence=evidence, behaviors=[behavior], epistemic_status=EpistemicStatus.DERIVED,
                        details=WaveformObservationDetails(time=time, observation_stage="id",
                            host=_signal_value(stage_signals[0], encoding, "host")),
                    ))
                previous_encoding = encoding.bits
            else:
                previous_encoding = None
        else:
            missing_values = True
            previous_encoding = None
        if include_oracle:
            for name in [*local, GPR]:
                hs, rs = signals[HOST + name], signals[REFERENCE + name]
                hv, rv = values.get(hs.code), values.get(rs.code)
                if hv is None or rv is None:
                    oracle_missing_values = True
                    continue
                if name != GPR:
                    difference(name, hs, rs, hv, rv, time)
                else:
                    for register in range(1, 32):
                        # VCD string is MSB-first; x31 is the first 32-bit word.
                        start = (31 - register) * 32
                        bit_range = BitRange(msb=32 * register + 31, lsb=32 * register)
                        difference(f"x{register}", hs, rs, Value(hv.bits[start:start+32], hv.line),
                                   Value(rv.bits[start:start+32], rv.line), time, f"x{register}", bit_range)
        if len(analysis) + len(oracle) > 4096:
            raise IngestionError("Observation limit exceeded; no truncated result returned")
    limitations = list(ANALYSIS_LIMITATIONS)
    if missing_values:
        limitations.append("Some selected values were absent or unknown; no difference/encoding was inferred from them.")
    if not analysis:
        limitations.append("No known valid host ID instruction encodings were extracted.")
    oracle_limits = []
    if oracle_missing_values:
        oracle_limits.append("Some oracle comparison values were absent or unknown; no difference was inferred from them.")
    return HardwareObservations(case_id=case_id, observations=analysis, unresolved_questions=limitations), oracle, oracle_limits


def _roles(directory):
    specs = [
        (directory / "host_driver.rtlil", [Role.ANALYSIS_INPUT, Role.BENCHMARK_ORACLE],
         "Host design also contains injected buggy labels; raw RTL is not included in the analysis projection."),
        (directory / "reference_driver.rtlil", [Role.BENCHMARK_ORACLE], "Golden comparison design."),
        (directory / "proof.vcd", [Role.VERIFICATION_EVIDENCE, Role.BENCHMARK_ORACLE, Role.ANALYSIS_INPUT],
         "Mixed host/reference witness; only projected host ID facts are analysis input, not raw VCD content."),
        (directory / "verify.log", [Role.VERIFICATION_EVIDENCE, Role.BENCHMARK_ORACLE],
         "Known historical propagation result and trace errors; excluded from analysis input."),
        (directory.parent.parent / "reference.v", [Role.SUPPORTING_CONTEXT, Role.BENCHMARK_ORACLE],
         "Shared golden source; classified but not read by ingestion."),
        (directory.parent.parent / "miter.tcl", [Role.SUPPORTING_CONTEXT, Role.VERIFICATION_EVIDENCE],
         "Observable construction recipe; classified but not executed or parsed."),
    ]
    return [ClassifiedArtifact(path=str(p), roles=roles, explanation=why) for p, roles, why in specs]


class EnCorpusIbexDriverAnalyzer:
    """Implements HardwareAnalyzer; analyze returns only analysis-safe observations.

    ingest explicitly returns benchmark information in a separate oracle object.
    Neither entry point runs workflows, tools, models, or implicit persistence.
    """

    @staticmethod
    def _directory(path):
        directory = Path(path).resolve()
        if directory.parent.name != "driver" or not directory.name.isdecimal() or not directory.is_dir():
            raise IngestionError("Expected an existing Ibex driver/<numeric-id> sample directory")
        return directory

    def analyze(self, *, case_id: str, target: TargetDescriptor, artifacts: list[ArtifactRef]) -> HardwareObservations:
        if target.architecture != Architecture.RISCV or target.processor_id.lower() != "ibex":
            raise IngestionError("Analyzer supports only explicitly identified RISC-V Ibex targets")
        if target.word_size_bits not in {None, 32}:
            raise IngestionError("Analyzer supports only 32-bit Ibex")
        traces = [a for a in artifacts if Path(a.path).name == "proof.vcd"]
        if len(traces) != 1 or traces[0].format != "vcd":
            raise IngestionError("Expected exactly one proof.vcd artifact with format=vcd")
        artifact = traces[0]
        self._directory(Path(artifact.path).parent)
        text, sha, size = _read(Path(artifact.path))
        if ((artifact.sha256 is not None and artifact.sha256 != sha)
                or (artifact.size_bytes is not None and artifact.size_bytes != size)):
            raise IngestionError("Input VCD fingerprint mismatch")
        return _extract_waveform(text, artifact.artifact_id, case_id, include_oracle=False)[0]

    def ingest(self, sample_directory: str | Path, *, case_id: str | None = None) -> EnCorpusIngestionResult:
        directory = self._directory(sample_directory)
        identity = f"encorpus:ibex:driver:{directory.name}"
        case_id = case_id or identity
        artifacts, texts = [], {}
        for name, (kind, format_name) in FILES.items():
            text, sha, size = _read(directory / name)
            texts[name] = text
            artifacts.append(ArtifactRef(artifact_id=f"{case_id}:{name}", artifact_type=kind,
                path=str(directory / name), format=format_name, sha256=sha, size_bytes=size))
        mutation = parse_driver_mutation(texts["host_driver.rtlil"], texts["reference_driver.rtlil"])
        analysis, oracle, wave_limits = _extract_waveform(texts["proof.vcd"], f"{case_id}:proof.vcd", case_id, include_oracle=True)
        limitations = [*ORACLE_LIMITATIONS, *wave_limits]
        if mutation is not None:
            evidence = [_evidence(f"{case_id}:{name}", line=line, signal=mutation.signal,
                                 summary="Raw module-level driver connection in the host/reference comparison.")
                        for name, line in [("host_driver.rtlil", mutation.host_line),
                                           ("reference_driver.rtlil", mutation.reference_line)]]
            oracle.insert(0, HardwareObservation(
                observation_id=f"{case_id}:mutation", kind=Kind.MUTATION_PRESENT,
                summary="One injected driver connection differs from the supplied golden design; security impact unknown.",
                evidence=evidence, epistemic_status=EpistemicStatus.DERIVED,
                details=MutationAnchorDetails(module=mutation.module, signal=mutation.signal,
                    reference_connection=mutation.reference, host_connection=mutation.host,
                    source_location=mutation.source),
            ))
        else:
            limitations.append("Host/reference exports contain no connection difference; no mutation claim emitted.")
        formal = parse_formal_log(texts["verify.log"])
        for result in formal:
            line = result.pop("line")
            oracle.append(HardwareObservation(
                observation_id=f"{case_id}:formal:{line}", kind=Kind.FORMAL_RESULT,
                summary="Historical formal tool result recorded; interpretation remains bounded by the missing harness.",
                evidence=[_evidence(f"{case_id}:verify.log", line=line, summary=result["raw_result"])],
                details=FormalResultDetails(**result, interpretation_boundary=FORMAL_BOUNDARY),
            ))
        if not any(r["category"] == "cover_hit" for r in formal):
            limitations.append("No supported cover hit recorded; trace errors do not establish cover success.")
        if not any(o.kind == Kind.LOCAL_EFFECT_OBSERVED for o in oracle):
            limitations.append("No known unequal values found in the selected local-state pairs; other local effects not evaluated.")
        return EnCorpusIngestionResult(
            sample_identity=identity, target=TargetDescriptor(processor_id="ibex", architecture=Architecture.RISCV,
                                                             word_size_bits=32),
            observations=analysis,
            processor_behavior_ir=ProcessorBehaviorIR(case_id=case_id, behaviors=[b for o in analysis.observations for b in o.behaviors]),
            oracle=EnCorpusOracle(observations=oracle, limitations=limitations,
                processor_behavior_ir=ProcessorBehaviorIR(case_id=case_id, behaviors=[b for o in oracle for b in o.behaviors])),
            artifacts=artifacts, artifact_roles=_roles(directory),
        )
