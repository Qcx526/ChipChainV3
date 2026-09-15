"""Explicit synthetic fixtures: not real firmware and not a verified vulnerability."""
from chipchain.cross_layer import (
    FirmwareAtomBinding, FirmwareFactSources, HardwareTriggerConditionInput,
    CrossLayerPairManifest, build_cross_layer_pair, build_hardware_trigger_condition,
)
from chipchain.domain.behavior import ProcessorBehavior, ProcessorBehaviorIR
from chipchain.domain.case import TargetDescriptor
from chipchain.domain.common import Architecture
from chipchain.domain.evidence import EvidenceRef, EvidenceLocation
from chipchain.domain.instruction import DecodedInstruction, DecodedOperand
from chipchain.domain.provenance import ToolDescriptor


def target(architecture=Architecture.RISCV, **updates):
    return TargetDescriptor(architecture=architecture, processor_id='synthetic-processor', **updates)


def pair(architecture=Architecture.RISCV, *, manifest=True, firmware_case_id='synthetic-fw'):
    metadata = CrossLayerPairManifest(manifest_id='synthetic-pairing', firmware_case_id=firmware_case_id,
        hardware_case_id='synthetic-hw', binding_source='synthetic_test_fixture',
        firmware_identity='synthetic-board-1', hardware_identity='synthetic-board-1',
        evidence_ids=['synthetic-explicit-binding']) if manifest else None
    return build_cross_layer_pair(firmware_case_id=firmware_case_id, hardware_case_id='synthetic-hw',
        firmware_target=target(architecture), hardware_target=target(architecture), manifest=metadata)


def condition(*atoms, architecture=Architecture.RISCV, **updates):
    fields = dict(hardware_case_id='synthetic-hw', architecture=architecture, source_kind='synthetic_fixture',
        source_ids=['synthetic-not-real-vulnerability'], epistemic_status='hypothesized', all_of_atoms=list(atoms))
    fields.update(updates)
    return build_hardware_trigger_condition(HardwareTriggerConditionInput(**fields))


def evidence(site=256):
    return EvidenceRef(evidence_id=f'synthetic-evidence:{site}', source_type='synthetic', artifact_id='synthetic-artifact',
        analyzer='synthetic-deterministic-fixture', location=EvidenceLocation(address=site),
        summary='Synthetic fields only', epistemic_status='derived')


def instruction(identity='inst', *, mnemonic='lw', complete=True, architecture=Architecture.RISCV, site=256):
    ops = [DecodedOperand(kind='register', register='x10'),
           DecodedOperand(kind='memory', base='x28', displacement=7)] if complete else []
    decoded = DecodedInstruction(observation_id=identity, architecture=architecture, raw_encoding='0x007e2503',
        instruction_width_bits=32, representation='instruction_word', source_stage='static', status='decoded',
        mnemonic=mnemonic, operand_text='x10, 7(x28)' if complete else '', operands=ops,
        decoder=ToolDescriptor(tool_name='synthetic', tool_version='1', tool_role='decoder'),
        decoder_mode='synthetic', evidence=[evidence(site)])
    return ProcessorBehavior(behavior_id=identity, kind='instruction', architecture=architecture, origin='firmware',
        summary='Synthetic instruction; not a real vulnerability', evidence=[evidence(site)],
        epistemic_status='derived', decoded_instruction=decoded)


def annotated(kind, identity='state', *, architecture=Architecture.RISCV, site=256, **fields):
    return ProcessorBehavior(behavior_id=identity, kind=kind, architecture=architecture, origin='firmware',
        summary='Synthetic typed annotation; not real execution evidence', evidence=[evidence(site)],
        epistemic_status='derived', attributes={'fixture_schema': 'xl0-synthetic-comparable/v1', **fields})


def sources(*behaviors, architecture=Architecture.RISCV, case_id='synthetic-fw', **kwargs):
    return FirmwareFactSources(case_id=case_id, target=target(architecture), synthetic=True,
        processor_ir=ProcessorBehaviorIR(case_id=case_id, behaviors=list(behaviors)), **kwargs)


def binding(source, atom_id='a', behavior_id='inst', *, kind='processor_behavior'):
    ref = source.reference(kind, behavior_id)
    return FirmwareAtomBinding(atom_id=atom_id, site_id=ref.site_id, firmware_fact_refs=[ref])
