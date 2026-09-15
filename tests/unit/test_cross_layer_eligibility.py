"""Architecture compatibility is necessary, explicit target binding is also necessary."""
import pytest
from chipchain.cross_layer import *
from chipchain.domain.common import Architecture
from tests.cross_layer_fakes import pair, target


@pytest.mark.parametrize('architecture', list(Architecture))
def test_no_shared_manifest_is_never_eligible(architecture):
    value = pair(architecture, manifest=False)
    assert value.eligibility == 'unknown'
    assert 'target_identity_unbound' in value.reasons


@pytest.mark.parametrize('architecture', [Architecture.ARM, Architecture.RISCV, Architecture.POWERPC, Architecture.X86])
def test_explicit_pair(architecture):
    value = pair(architecture)
    assert value.eligibility == 'eligible'
    assert value.board_or_processor_identity == 'synthetic-board-1'
    assert value.firmware_target.architecture == architecture


def test_unknown_never_silently_matches():
    assert pair(Architecture.UNKNOWN).eligibility == 'unknown'


@pytest.mark.parametrize('field,a,b', [('architecture','arm','riscv'), ('isa_variant','v1','v2'),
    ('word_size_bits',32,64), ('endianness','little','big')])
def test_compatibility_mismatches(field, a, b):
    p = pair()
    fw = p.firmware_target.model_dump(); hw = p.hardware_target.model_dump()
    fw[field], hw[field] = a, b
    value = build_cross_layer_pair(firmware_case_id=p.firmware_case_id, hardware_case_id=p.hardware_case_id,
        firmware_target=type(p.firmware_target)(**fw), hardware_target=type(p.hardware_target)(**hw), manifest=p.manifest)
    assert value.eligibility == 'ineligible'
    assert field + '_mismatch' in value.reasons


@pytest.mark.parametrize('field,value', [('isa_variant','rv32i'), ('word_size_bits',32), ('endianness','little')])
def test_optional_fields_compared_only_when_both_known(field, value):
    p = pair()
    hw = target(**{field: value})
    result = build_cross_layer_pair(firmware_case_id=p.firmware_case_id, hardware_case_id=p.hardware_case_id,
        firmware_target=p.firmware_target, hardware_target=hw, manifest=p.manifest)
    assert result.eligibility == 'eligible'


def test_mismatched_identity_and_wrong_cases():
    p = pair(); fields = p.manifest.model_dump(); fields['hardware_identity'] = 'other-board'
    kwargs = dict(firmware_case_id=p.firmware_case_id, hardware_case_id=p.hardware_case_id,
        firmware_target=p.firmware_target, hardware_target=p.hardware_target)
    assert build_cross_layer_pair(**kwargs, manifest=CrossLayerPairManifest(**fields)).reasons == ['target_identity_mismatch']
    fields['hardware_case_id'] = 'other-case'
    with pytest.raises(ValueError, match='case IDs'):
        build_cross_layer_pair(**kwargs, manifest=CrossLayerPairManifest(**fields))


def test_no_llm_binding_or_unjustified_eligibility():
    p = pair(); fields = p.manifest.model_dump(); fields['binding_source'] = 'llm_inferred'
    with pytest.raises(ValueError): CrossLayerPairManifest(**fields)
    fields = pair(manifest=False).model_dump(); fields['eligibility'] = 'eligible'
    with pytest.raises(ValueError): CrossLayerPairDescriptor(**fields)


@pytest.mark.parametrize('binding_source', ['explicit_manifest','shared_platform_identity','shared_session_identity'])
def test_external_binding_sources(binding_source):
    p = pair(); m = p.manifest.model_dump(); m['binding_source'] = binding_source
    value = build_cross_layer_pair(firmware_case_id=p.firmware_case_id, hardware_case_id=p.hardware_case_id,
        firmware_target=p.firmware_target, hardware_target=p.hardware_target, manifest=CrossLayerPairManifest(**m))
    assert value.eligibility == 'eligible' and value.binding_source == binding_source
