"""Fresh B3 deterministic preparation and real-sample preflight pins. No API calls."""
from pathlib import Path
from collections import Counter
import hashlib
import json
from chipchain.agents.context import firmware_context
from chipchain.agents.runtime import AgentExecutionError
from chipchain.agents.projections.firmware_envelope import build_firmware_envelope, envelope_metadata, firmware_envelope_sha256
from chipchain.agents.projections.firmware_relations import build_firmware_relation_projection
from chipchain.agents.projections.firmware_envelope_v3 import build_firmware_envelope_v3, serialize_firmware_envelope_v3, envelope_v3_metadata
from chipchain.tools.firmware.ghidra.api import extract_heat_press_structure
from chipchain.tools.firmware.structure_projection import build_relevant_static_structure
from chipchain.tools.firmware.relation_builder import build_firmware_static_relations
from chipchain.tools.firmware.relations import firmware_static_relations_sha256

A4_SHA = 'fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902'
COUNTS = {'direct_call':22,'direct_branch':6,'control_transfer_unresolved':6,
          'mmio_function_containment':23,'mmio_access_direction':23,'vector_dispatch':51}


def validate_b3_semantic_pins(context, metadata):
    """R1 changes output capacity only; any model-visible semantic drift refuses API."""
    from chipchain.agents.prompts.firmware_v2 import SYSTEM_PROMPT
    from chipchain.agents.model_outputs.firmware_v2 import ModelFirmwareAnalysisReportV2
    expected = dict(relation_projection_characters=16824,
        relation_projection_sha256='f65dd1b99fc621fb6ccda0e45d7254a233351185258d820d8736949c74c635b2',
        merged_evidence_count=174, a4_relation_count=131)
    schema = json.dumps(ModelFirmwareAnalysisReportV2.model_json_schema(),sort_keys=True,separators=(',',':'))
    if (any(metadata.get(k)!=v for k,v in expected.items()) or len(context)!=56523 or
        hashlib.sha256(context.encode()).hexdigest()!='b7722ef471a05bd7e83e2042ae2ac7a4ed125b01a5aeb624581ea1994994adab' or
        hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()!='10573f3efba97bed7a44d491e4915197f57d771e90b4143248bf19842b685bff' or
        hashlib.sha256(schema.encode()).hexdigest()!='512974761886482b973ed4230e02f6aa56be9812b3a62be1588e0aa0bb516248'):
        raise AgentExecutionError('B3 semantic input identity changed; API call refused')


def validate_relation_baseline(catalog):
    facts = {r.relation_id:r for r in catalog.relations}
    if len(catalog.relations)!=131 or Counter(r.kind.value for r in catalog.relations)!=COUNTS or firmware_static_relations_sha256(catalog)!=A4_SHA:
        raise AgentExecutionError('A4 baseline identity/count mismatch; API call refused')
    unresolved = facts['call-80f88']
    call = facts['call-80afa']
    if (unresolved.kind,unresolved.status,unresolved.attributes.transfer_kind,unresolved.attributes.mnemonic,
        unresolved.attributes.original_target_address)!=(
            'control_transfer_unresolved','unresolved','indirect_call','blx',0x816cc):
        raise AgentExecutionError('A4 unresolved regression pin changed; API call refused')
    if (call.kind,call.status,call.source.entity_id,call.target.entity_id)!=(
            'direct_call','confirmed_static','f80af4','f80eac'):
        raise AgentExecutionError('A4 confirmed call pin changed; API call refused')
    for pc in (0x80abe,0x80ad2,0x80ade,0x80aea):
        r=facts[f'call-{pc:x}']
        if (r.kind,r.status,r.attributes.mnemonic,r.target.entity_id)!=('direct_branch','confirmed_static','b.w','f815a4'):
            raise AgentExecutionError('A4 branch pin changed; API call refused')
    for pc in (0x80eba,0x80eca,0x80ed2,0x80eda,0x80ee6,0x80ef2,0x80efe,0x80f0a):
        r=facts[f'mmio-direction-{pc:x}']
        if (r.attributes.direction,r.attributes.mnemonic)!=('read','ldr') or facts[f'mmio-containment-{pc:x}'].target.entity_id!='f80eac':
            raise AgentExecutionError('A4 MMIO pin changed; API call refused')
    r=facts['vector-1']
    if (r.kind,r.status,r.target.entity_id)!=('vector_dispatch','confirmed_static','f80f34'):
        raise AgentExecutionError('A4 vector pin changed; API call refused')


def prepare_relation_context(inputs, ghidra_home):
    from chipchain.integrations.deepseek_firmware import validate_firmware_baseline, validate_enriched_baseline
    if ghidra_home is None:
        raise AgentExecutionError('Relation v3 requires explicit Ghidra home')
    validate_firmware_baseline(inputs,firmware_context(inputs))
    artifact=next(a for a in inputs.case.firmware_artifacts if a.artifact_id=='elf')
    path=Path(artifact.path)
    source,vectors=extract_heat_press_structure(path,ghidra_home=ghidra_home,
        script_path=Path(__file__).resolve().parents[3]/'scripts/ghidra/ExportFirmwareStructure.java')
    relevant=build_relevant_static_structure(inputs,source,vectors)
    old=build_firmware_envelope(inputs,relevant,source)
    validate_enriched_baseline(relevant,envelope_metadata(old))
    if firmware_envelope_sha256(old)!='6afef3295f8c54ee7fef65446db0a91169ee833d3ede4314e38e45ca0d7c5016':
        raise AgentExecutionError('Frozen envelope v2 pin changed; API call refused')
    catalog=build_firmware_static_relations(inputs,source,vectors,relevant,elf_bytes=path.read_bytes())
    validate_relation_baseline(catalog)
    projection=build_firmware_relation_projection(inputs,relevant,catalog)
    envelope=build_firmware_envelope_v3(inputs,projection,static_relation_catalog=catalog)
    context=serialize_firmware_envelope_v3(envelope)
    metadata=envelope_v3_metadata(envelope)
    validate_b3_semantic_pins(context,metadata)
    return relevant,source,catalog,projection,context,metadata
