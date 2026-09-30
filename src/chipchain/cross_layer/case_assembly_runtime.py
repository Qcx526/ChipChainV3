"""Additive firmware-only runtime projection over the frozen case assembly.

The baseline case and its hardware evidence keep their original identities.
This projection consumes a replay-validated runtime bundle; it cannot upgrade
ProcessorFuzz provenance or make the controlled Ibex verifier applicable.
"""
from __future__ import annotations

from chipchain.firmware.static_ir import FirmwareStaticAnalysis, content_id


SCHEMA = "type2-firmware-runtime-projection/v1"
FIRMWARE_RUNTIME_REQUIREMENT = "firmware_specific_runtime_execution_and_source_binding"


def build_runtime_projection(*, firmware: FirmwareStaticAnalysis, evidence,
                             case_manifest: dict, association: dict,
                             readiness: dict) -> dict:
    """Project exact per-fact runtime support without changing baseline objects."""
    if evidence.run.firmware != firmware.artifact:
        raise ValueError("Case firmware and runtime firmware identity disagree")
    by_fact = {row.static_behavior_id: row for row in evidence.bindings.bindings}
    events = {event.event_id: event for event in evidence.events.events}
    facts = {fact.fact_id: fact for fact in firmware.behaviors}
    instructions = {instruction.fact_id: instruction for instruction in firmware.instructions}
    selected_ids = sorted({fact_id
                           for relation in association["semantic_candidate_relations"]
                           for fact_id in relation["firmware_behavior_fact_ids"]})
    rows = []
    for fact_id in selected_ids:
        fact = facts[fact_id]
        instruction = instructions[fact.instruction_id]
        binding = by_fact.get(fact_id)
        if binding is None:
            raise ValueError("Runtime evidence omits a static candidate binding")
        if (binding.static_instruction_id != instruction.fact_id
                or binding.pc != instruction.pc or binding.kind != fact.kind):
            raise ValueError("Runtime binding and static candidate disagree")
        observations = []
        for event_id in binding.source_event_ids:
            event = events[event_id]
            elf_va = evidence.run.image_mapping.elf_address(event.pc, len(event.instruction_bytes) // 2)
            if elf_va != instruction.pc or event.instruction_bytes != instruction.raw_bytes:
                raise ValueError("Runtime event and static candidate instruction disagree")
            observations.append({"event_id": event.event_id, "sequence": event.sequence,
                                 "vcpu": event.vcpu, "pc": event.pc,
                                 "elf_virtual_address": elf_va,
                                 "instruction_bytes": event.instruction_bytes})
        rows.append({
            "static_behavior_id": fact_id,
            "static_instruction_id": instruction.fact_id,
            "pc": instruction.pc, "instruction_bytes": instruction.raw_bytes,
            "kind": fact.kind.value, "status": binding.status, "reason": binding.reason,
            "source_event_ids": list(binding.source_event_ids),
            "semantic_fact_ids": list(binding.semantic_fact_ids),
            "observations": observations,
        })
    supported = [row for row in rows if row["status"] == "SUPPORTED"]
    all_supported = bool(rows) and len(supported) == len(rows)
    runtime_status = "SUPPORTED" if all_supported else "UNKNOWN"
    kind_rows = []
    for relation in association["semantic_candidate_relations"]:
        matching = [row for row in rows if row["kind"] == relation["kind"]]
        kind_rows.append({
            "kind": relation["kind"],
            "status": ("SUPPORTED" if matching and all(
                row["status"] == "SUPPORTED" for row in matching) else "UNKNOWN"),
            "scope": "supported_static_candidate_facts_in_this_bounded_qemu_run",
            "reason": ("NO_SUPPORTED_STATIC_KIND_FACT" if not matching else
                       "ALL_CANDIDATE_FACTS_OBSERVED" if all(
                           row["status"] == "SUPPORTED" for row in matching) else
                       "SOME_CANDIDATE_FACTS_NOT_OBSERVED_IN_THIS_RUN"),
            "static_behavior_ids": [row["static_behavior_id"] for row in matching],
        })
    fields = {
        "schema_version": SCHEMA,
        "base_case_id": case_manifest["case_id"],
        "firmware_analysis_id": firmware.analysis_id,
        "firmware_elf_sha256": firmware.artifact.sha256,
        "run_id": evidence.run.run_id,
        "runtime_event_artifact_id": evidence.events.artifact_id,
        "runtime_semantic_artifact_id": evidence.semantics.artifact_id,
        "static_runtime_binding_artifact_id": evidence.bindings.artifact_id,
        "runtime_capability_artifact_id": evidence.capabilities.artifact_id,
        "runtime_binding_status": runtime_status,
        "runtime_binding_scope": "all_supported_static_candidate_facts_in_this_bounded_qemu_run",
        "firmware_facts": rows,
        "candidate_kind_support": kind_rows,
        "baseline_runtime_binding_status": association["runtime_binding_status"],
        "firmware_runtime_requirement": {
            "requirement": FIRMWARE_RUNTIME_REQUIREMENT,
            "status": "SATISFIED_FOR_DECLARED_SCOPE" if all_supported else "MISSING",
            "scope": "firmware_instruction_execution_only_not_hardware_RunEvidence",
        },
        "effective_missing_requirements": [requirement for requirement in readiness[
            "missing_requirements"] if not (
                all_supported and requirement == FIRMWARE_RUNTIME_REQUIREMENT)],
        "hardware_package_evidence_gaps": list(readiness["hardware_package_evidence_gaps"]),
        "hardware_trigger_status": association["hardware_trigger_status"],
        "hardware_differential_status": association["hardware_differential_status"],
        "hardware_deviation_status": "NOT_ESTABLISHED",
        "silicon_applicability_status": "NOT_ESTABLISHED",
        "hardware_package_verification_status": association["hardware_package_verification_status"],
        "verification_ready": readiness["ready"],
        "verifier_applicability_status": readiness["verifier_applicability_status"],
        "verifier_invoked": False,
        "full_type2_chain_status": "NOT_VERIFIED",
        "scientific_boundary": (
            "QEMU firmware instruction execution observations only; not ProcessorFuzz RTL, "
            "hardware trigger, hardware deviation, silicon evidence or vulnerability verification"),
    }
    return {**fields, "projection_id": content_id("type2-firmware-runtime-projection", fields)}
