"""Real deterministic B2 preflight only; Python networking remains blocked."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from chipchain.agents.context import MAX_CONTEXT_ITEMS, firmware_context
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
from chipchain.agents.projections.firmware_envelope import parse_firmware_envelope, envelope_components, compact, serialize_firmware_envelope
from chipchain.integrations.deepseek_firmware import prepare_firmware_input, prepare_enriched_context, enriched_preflight_summary
from chipchain.tools.firmware.structure_projection import serialize_relevant_static_structure

_POPEN=subprocess.Popen


def test_real_b2_deterministic_preflight(tmp_path,monkeypatch):
    home=os.environ.get('CHIPCHAIN_GHIDRA_HOME');root=os.environ.get('CHIPCHAIN_FUZZWARE_ROOT')
    if not home or not root:
        pytest.skip('Set explicit Ghidra and Fuzzware roots')
    home=Path(home)
    def headless_only(argv,**settings):
        assert argv[0]==str((home/'support/analyzeHeadless').resolve()) and settings['shell'] is False
        return _POPEN(argv,**settings)
    monkeypatch.setattr(subprocess,'Popen',headless_only)
    inputs=prepare_firmware_input(Path(root));before=inputs.model_dump_json()
    relevant,source,context,metadata=prepare_enriched_context(inputs,home)
    envelope=parse_firmware_envelope(context)
    base,restored,registry=envelope_components(envelope)
    assert compact(envelope.firmware_projection)==firmware_context(inputs)
    assert compact(envelope.relevant_static_structure)==serialize_relevant_static_structure(relevant)
    assert serialize_firmware_envelope(envelope)==context
    assert restored==relevant and len(registry)==174
    assert registry==collect_firmware_reasoning_evidence(inputs,relevant)
    assert len(base.evidence_catalog)==57 and len(relevant.evidence_catalog)==172 and MAX_CONTEXT_ITEMS==128
    assert len(context)<=58000
    # Stub parity checks no provider invocation; actual model path covered by fake models.
    stub=FirmwareSecurityAgent().invoke(inputs)
    enriched=FirmwareSecurityAgent().invoke(inputs,relevant_static_structure=relevant,static_source=source)
    assert enriched.processor_behavior_ir==stub.processor_behavior_ir and len(stub.processor_behavior_ir.behaviors)==55
    assert inputs.model_dump_json()==before
    system=[site for site in relevant.mmio_sites if site.function_id=='f80eac']
    assert len(system)==8 and all(site.mnemonic=='ldr' and site.direction=='read' for site in system)
    assert len(relevant.unresolved_call_sites)==12
    summary=enriched_preflight_summary(context,metadata)
    (tmp_path/'preflight.json').write_text(json.dumps(summary,indent=2))
    (tmp_path/'envelope.json').write_text(context)
    print(json.dumps({'audit_directory':str(tmp_path),**summary},sort_keys=True))
