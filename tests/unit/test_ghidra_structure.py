"""Offline contract, byte validation, structure association and bounded vector tests."""
from copy import deepcopy
import json
import struct

import pytest
from pydantic import ValidationError

from chipchain.tools.architecture.cortex_m import vector_table
from chipchain.tools.firmware.ghidra.elf import parse_elf
from chipchain.tools.firmware.ghidra.models import GhidraStaticStructureResult, StaticFunction, semantic_json
from chipchain.tools.firmware.ghidra.normalize import normalize_export
from chipchain.tools.firmware.ghidra.process import GhidraError
from tests.ghidra_fakes import BASE, exported, function, normalize, vector_elf


def test_direct_edges_sorted_independently_decoded_and_provenance_recorded():
    elf,value=exported()
    result=normalize(elf,value)
    assert [e.call_site_address for e in result.direct_call_edges]==[BASE,BASE+4]
    assert not result.unresolved_call_sites
    assert result.tool.tool_version=='synthetic-1' and result.java_runtime_version=='test-java'
    assert result.decoder.tool_name=='capstone' and result.tool.configuration_sha256
    value['functions'].reverse();value['call_sites'].reverse();value['memory'].reverse()
    assert semantic_json(normalize(elf,value))==semantic_json(result)
    assert GhidraStaticStructureResult.model_validate_json(semantic_json(result))==result
    assert 'runtime' not in result.model_dump()  # separate static result, no FirmwareAnalysisReport


@pytest.mark.parametrize('field,value',[
    ('schema_version','bad'),('ghidra_version','other'),('language_id','ARM:BE:32:v7'),
    ('compiler_spec_id','other'),('processor','RISCV'),('endianness','big'),('word_size_bits',64),
    ('word_size_bits','32'),('image_base',BASE+4),('executable_sha256','0'*64),('entry_points',[]),
])
def test_identity_or_schema_rejected(field,value):
    elf,raw=exported();raw[field]=value
    with pytest.raises(GhidraError): normalize(elf,raw)


@pytest.mark.parametrize('mutation', ['missing','extra','duplicate_function','duplicate_site','negative_address',
                                      'memory_conflict','memory_gap','raw_bytes','decompiler','call_convention'])
def test_strict_export_validation(mutation):
    elf,raw=exported()
    if mutation=='missing':del raw['java_vendor']
    if mutation=='extra':raw['raw_log']='not allowed'
    if mutation=='duplicate_function':raw['functions'].append(deepcopy(raw['functions'][0]))
    if mutation=='duplicate_site':raw['call_sites'].append(deepcopy(raw['call_sites'][0]))
    if mutation=='negative_address':raw['functions'][0]['entry_address']=-1
    if mutation=='memory_conflict':raw['memory'][0]['start']=0
    if mutation=='memory_gap':raw['memory'][0]['end']-=2
    if mutation=='raw_bytes':raw['call_sites'][0]['raw_encoding']='ffffffff'
    if mutation=='decompiler':raw['analysis_options']['Decompiler Parameter ID']='true'
    if mutation=='call_convention':raw['analysis_options']['Call Convention ID']='true'
    with pytest.raises(GhidraError):normalize(elf,raw)


def test_duplicate_json_keys_rejected():
    elf,_=exported()
    with pytest.raises(GhidraError,match='schema'):
        normalize_export(b'{"x":1,"x":2}',elf,case_id='x',expected_version='x',script_sha256='a'*64)


def test_duplicate_edge_id_rejected():
    elf,raw=exported();result=normalize(elf,raw).model_dump()
    result['direct_call_edges'][1]['edge_id']=result['direct_call_edges'][0]['edge_id']
    with pytest.raises(ValidationError,match='Duplicate'):GhidraStaticStructureResult.model_validate(result)


def test_call_outside_executable_rejected():
    elf,raw=exported();raw['call_sites'][0]['call_site_address']=0x20000000
    with pytest.raises(GhidraError,match='outside executable'):normalize(elf,raw)


@pytest.mark.parametrize('changes,reason',[
    ({'caller_function_id':None},'missing_caller'),
    ({'callee_function_id':None},'missing_callee'),
    ({'target_address':BASE+9},'callee_entry_conflict'),
    ({'caller_function_id':f'f{BASE+8:x}'},'caller_containment_conflict'),
    ({'computed':True},'computed_or_ambiguous'),
    ({'target_count':0},'computed_or_ambiguous'),
])
def test_unresolved_call_references(changes,reason):
    elf,raw=exported();raw['call_sites'][0].update(changes)
    result=normalize(elf,raw)
    assert len(result.direct_call_edges)==1
    assert result.unresolved_call_sites[0].reason==reason


def test_wrong_target_and_non_call_cannot_be_confirmed():
    elf,raw=exported()
    raw['call_sites'][0].update(callee_function_id=f'f{BASE:x}',target_address=BASE)
    result=normalize(elf,raw)
    assert result.unresolved_call_sites[0].reason=='decoder_disagreement'
    raw['call_sites']=[dict(raw['call_sites'][0],call_site_address=BASE+8,caller_function_id=f'f{BASE+8:x}',
                            raw_encoding='7047',instruction_size=2)]
    result=normalize(elf,raw)
    assert not result.direct_call_edges
    assert result.unresolved_call_sites[0].reason=='instruction_boundary_unconfirmed'


def test_mid_instruction_boundary_stays_unresolved():
    elf,raw=exported()
    raw['call_sites']=[dict(raw['call_sites'][0],call_site_address=BASE+2,raw_encoding='02f8',instruction_size=2)]
    assert normalize(elf,raw).unresolved_call_sites[0].reason=='instruction_boundary_unconfirmed'


def test_mmio_containment_comparison_conflict_and_immutability(tmp_path):
    from tests.firmware_fakes import make_case
    from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
    from chipchain.tools.firmware.ghidra.associations import associate_mmio
    case=make_case(tmp_path)
    batch=FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id,target=case.target,artifacts=case.firmware_artifacts)
    before=batch.model_dump_json()
    elf,raw=exported();result=normalize(elf,raw)
    relations=associate_mmio(result,batch)
    assert relations.sites[0].containment=='unique' and relations.sites[0].entry_match
    assert relations.sites[0].name_match and relations.sites[0].directions==['read']
    assert len(relations.bindings)==5
    assert all(b.binding_basis=='static address containment' for b in relations.bindings)
    result.functions[0].name='symbolic_label'
    assert associate_mmio(result,batch).sites[0].name_match is False
    # A second body overlaps the actual MMIO PC; never choose one silently.
    result.functions.append(StaticFunction(**function(BASE+2,2,'overlap')))
    conflict=associate_mmio(result,batch)
    assert conflict.sites[0].containment=='ambiguous' and conflict.warnings
    assert all(b.function_id is None for b in conflict.bindings)
    result.direct_call_edges=[]
    result.functions=result.functions[1:]
    assert associate_mmio(result,batch).sites[0].entry_match is False
    result.functions=[]
    assert associate_mmio(result,batch).sites[0].containment=='missing'
    assert batch.model_dump_json()==before


def test_vector_section_bound_thumb_entry_inside_and_outside():
    meta=parse_elf(vector_elf())
    functions=[StaticFunction(**function(BASE+20,4,'UART_Handler'))]
    result=vector_table(meta,functions)
    assert result.status=='bounded' and result.extent_sources==['section:.vectors']
    assert (result.extent.start,result.extent.end)==(BASE,BASE+20)
    assert [b.binding_status for b in result.bindings]==[
        'initial_stack_pointer','function_entry','inside_function','outside_executable','null_entry']
    assert result.bindings[1].canonical_handler_address==BASE+20
    assert result.bindings[2].canonical_handler_address==BASE+22
    assert result.bindings[2].function_id==functions[0].function_id
    assert result.bindings[1].core_exception_name=='Reset'
    # The result contains static binding only, no inferred UART interface or occurrence.
    assert 'physical-input' in result.warnings[0]
    assert 'not interrupt occurrence' in result.bindings[1].evidence[0].summary
    assert 'UART' not in result.model_dump_json()  # no promotion from the containing function name


def test_vector_missing_extent_does_not_guess():
    elf,_=exported()
    result=vector_table(parse_elf(elf),[])
    assert result.status=='unresolved' and not result.bindings


def test_vector_non_thumb_and_missing_function():
    meta=parse_elf(vector_elf([0x20001000,BASE+21,BASE+22,BASE+23,0]))
    result=vector_table(meta,[])
    assert result.bindings[1].binding_status=='no_function'
    assert result.bindings[2].binding_status=='non_thumb'


@pytest.mark.parametrize('change',['oversized','reset_conflict','unbacked'])
def test_invalid_vector_bound_is_unresolved(change):
    data=bytearray(vector_elf())
    if change=='oversized':struct.pack_into('<I',data,0x300+40+20,23)
    if change=='reset_conflict':struct.pack_into('<I',data,0x104,BASE+23)
    if change=='unbacked':struct.pack_into('<I',data,0x300+40+12,0x40000000)
    assert vector_table(parse_elf(bytes(data)),[]).status=='unresolved'
