"""Small synthetic A1 + canonical static graph, independent of Ghidra installation."""
from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.tools.architecture.cortex_m import CortexMVectorResult, VectorHandlerBinding
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from chipchain.tools.firmware.ghidra.models import AddressRange, StaticCallEdge, StaticFunction, UnresolvedCallSite
from chipchain.tools.firmware.ghidra.normalize import evidence
from tests.firmware_fakes import BASE, make_case
from tests.ghidra_fakes import exported, function, normalize


def projection_inputs(tmp_path):
    case = make_case(tmp_path)
    batch = FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id,target=case.target,artifacts=case.firmware_artifacts)
    inputs = FirmwareAgentInput(case=case, deterministic_observations=batch)
    elf, raw = exported()
    structure = normalize(elf, raw)
    structure.direct_call_edges=[]
    structure.functions=[StaticFunction(**function(BASE+offset, 4, name)) for offset,name in
        [(0,'UARTClass::write'),(8,'caller'),(16,'callee'),(24,'two_hop_only'),(32,'ADC_Handler'),(40,'unrelated')]]
    ref=case.firmware_artifacts[0]
    structure.program=structure.program.model_copy(update={'sha256':ref.sha256,'size_bytes':ref.size_bytes})
    def edge(pc,caller,callee):
        return StaticCallEdge(edge_id=f'edge-{pc:x}',call_site_address=pc,
            caller_function_id=f'f{caller:x}',callee_function_id=f'f{callee:x}',
            evidence=[evidence(f'e-{pc:x}',pc,'Synthetic confirmed direct call')])
    structure.direct_call_edges=[edge(BASE,BASE,BASE+16),edge(BASE+8,BASE+8,BASE),
                                 edge(BASE+16,BASE+16,BASE+24)]
    structure.unresolved_call_sites=[UnresolvedCallSite(call_site_address=BASE+offset,
        caller_function_id=f'f{BASE+caller:x}',target_address=BASE+target,reason=reason,
        evidence=[evidence(f'u-{offset}',BASE+offset,'Synthetic unresolved call')])
        for offset,caller,target,reason in [(2,0,40,'decoder_disagreement'),(18,16,0,'computed_or_ambiguous'),
                                           (42,40,24,'missing_callee')]]
    bindings=[VectorHandlerBinding(vector_index=0,exception_number=None,external_irq_number=None,
        core_exception_name=None,raw_handler_value=0x20001000,canonical_handler_address=None,function_id=None,
        symbol_names=[],binding_status='initial_stack_pointer',evidence=[evidence('vector-0',BASE,'Stack')])]
    for i,addr,names in [(1,BASE,['UARTClass::write']),(2,BASE+32,['ADC_Handler','Default_Handler']),
                         (3,BASE+32,['ADC_Handler','Default_Handler'])]:
        bindings.append(VectorHandlerBinding(vector_index=i,exception_number=i,external_irq_number=None,
            core_exception_name={1:'Reset',2:'NMI',3:'HardFault'}[i],raw_handler_value=addr|1,
            canonical_handler_address=addr,function_id=f'f{addr:x}',symbol_names=names,
            binding_status='function_entry',evidence=[evidence(f'vector-{i}',BASE+i*4,'Synthetic static vector')]))
    vectors=CortexMVectorResult(status='bounded',extent=AddressRange(start=BASE,end=BASE+16),
                                extent_sources=['synthetic section'],bindings=bindings)
    return inputs,structure,vectors
