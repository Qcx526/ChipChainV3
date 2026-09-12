"""Memory order, Thumb boundaries and deliberately limited operand semantics."""

import pytest

from chipchain.domain.evidence import EvidenceRef
from chipchain.tools.architecture.arm import ArmThumbInstructionDecoder, memory_direction


def decode(code):
    return ArmThumbInstructionDecoder().decode_site(function_bytes=bytes.fromhex(code),function_address=0x1000,
        pc=0x1000,observation_id='site',evidence=[EvidenceRef(evidence_id='e',source_type='synthetic',artifact_id='elf',summary='Code')])


@pytest.mark.parametrize('code,mnemonic,width', [('9969','ldr',16),('d3f88410','ldr.w',32),('d161','str',16)])
def test_memory_order_width(code,mnemonic,width):
    result=decode(code)
    assert result.raw_encoding==code and result.mnemonic==mnemonic and result.instruction_width_bits==width
    assert result.status=='decoded' and result.representation=='memory_bytes' and result.architecture=='arm'
    assert result.decoder.tool_name=='capstone' and result.operands


def test_register_aliases_are_canonical():
    result=decode('6846') # mov r0, sp
    assert [o.register_name for o in result.operands]==['r0','r13']
    result=decode('7047') # bx lr
    assert result.operands[0].register_name=='r14'
    result=decode('7846') # mov r0, pc
    assert result.operands[-1].register_name=='r15'


@pytest.mark.parametrize('code',['38b5','38bd','01eb8200','03f8041b'])
def test_unrepresentable_operands_keep_display(code):
    result=decode(code)
    assert result.status=='decoded' and result.mnemonic and result.operand_text
    assert result.backend_operand_text==result.operand_text and result.operands==[]


def test_direction_requires_simple_matching_decode():
    assert memory_direction(decode('9969'),4)=='read'
    assert memory_direction(decode('d161'),4)=='write'
    assert memory_direction(decode('9969'),1)=='unknown'
    assert memory_direction(decode('38bd'),4)=='unknown'
    assert memory_direction(None,4)=='unknown'
