"""Small deterministic normalization adapters, with no operand-text parser."""
from typing import Protocol
from chipchain.domain.common import Architecture
from chipchain.domain.instruction import DecodedInstruction
from .trigger import OperandPattern


class CrossLayerArchitectureAdapter(Protocol):
    architecture: Architecture
    version: str

    def normalize_register(self, name: str) -> str | None: ...
    def normalize_instruction(self, mnemonic: str) -> str: ...
    def compare_operand_pattern(self, pattern: OperandPattern, fields: dict) -> list[bool | None]: ...
    def normalize_privilege(self, mode: str) -> str | None: ...
    def decoded_fields(self, instruction: DecodedInstruction) -> dict: ...


class ConservativeAdapter:
    """Preserve ISA vocabulary; unknown operands and privilege synonyms stay unknown."""
    def __init__(self, architecture, register_prefix, register_count):
        self.architecture = architecture
        self.prefix = register_prefix
        self.count = register_count
        self.version = f'{architecture.value}-literal-fields/v1'

    def normalize_register(self, name):
        name = name.strip().lower()
        if name in {f'{self.prefix}{i}' for i in range(self.count)}:
            return name
        return None

    def normalize_instruction(self, mnemonic):
        return mnemonic.strip().lower()

    def normalize_privilege(self, mode):
        value = mode.strip().lower()
        return None if value == 'unknown' else value

    def compare_operand_pattern(self, pattern, fields):
        result = []
        for key in ('destination_register', 'base_register'):
            want = getattr(pattern, key)
            if want is not None:
                actual = fields.get('operand.' + key)
                a, b = self.normalize_register(want), self.normalize_register(actual) if actual else None
                result.append(a == b if a is not None and b is not None else None)
        if pattern.source_registers:
            actual = fields.get('operand.source_registers')
            a = [self.normalize_register(v) for v in pattern.source_registers]
            b = [self.normalize_register(v) for v in actual] if actual is not None else None
            result.append(a == b if b is not None and None not in a + b else None)
        if pattern.immediate_exact is not None or pattern.immediate_range is not None:
            actual = fields.get('operand.immediate')
            if actual is None:
                result.append(None)
            elif pattern.immediate_exact is not None:
                result.append(actual == pattern.immediate_exact)
            else:
                result.append(pattern.immediate_range.minimum <= actual <= pattern.immediate_range.maximum)
        return result

    def decoded_fields(self, instruction):
        # No guesses about Thumb predicates, writeback, implicit operands, PPC roles, etc.
        return {}


class RISCVAdapter(ConservativeAdapter):
    def __init__(self):
        super().__init__(Architecture.RISCV, 'x', 32)
        self.version = 'riscv-decoded-explicit-operands/v1'

    def decoded_fields(self, instruction):
        ops, mnemonic = instruction.operands, self.normalize_instruction(instruction.mnemonic)
        result = {}
        # Only explicit decoder operands and these small, documented instruction forms.
        if mnemonic in {'lb', 'lbu', 'lh', 'lhu', 'lw', 'lwu', 'ld', 'sb', 'sh', 'sw', 'sd'}:
            if len(ops) == 2 and ops[0].kind == 'register' and ops[1].kind == 'memory':
                result['operand.base_register'] = ops[1].base
                result['operand.immediate'] = ops[1].displacement
                if mnemonic.startswith('l'):
                    result['operand.destination_register'] = ops[0].register_name
                else:
                    result['operand.source_registers'] = [ops[0].register_name]
        elif mnemonic in {'addi', 'andi', 'ori', 'xori', 'slti', 'sltiu'}:
            if len(ops) == 3 and [o.kind for o in ops] == ['register', 'register', 'immediate']:
                result = {'operand.destination_register': ops[0].register_name,
                          'operand.source_registers': [ops[1].register_name], 'operand.immediate': ops[2].immediate}
        elif mnemonic in {'lui', 'auipc'}:
            if len(ops) == 2 and [o.kind for o in ops] == ['register', 'immediate']:
                result = {'operand.destination_register': ops[0].register_name, 'operand.immediate': ops[1].immediate}
        return result


class ARMAdapter(ConservativeAdapter):
    def __init__(self):
        super().__init__(Architecture.ARM, 'r', 16)

    def normalize_register(self, name):
        return super().normalize_register({'sp': 'r13', 'lr': 'r14', 'pc': 'r15'}.get(name.lower(), name))


class PowerPCAdapter(ConservativeAdapter):
    def __init__(self):
        super().__init__(Architecture.POWERPC, 'r', 32)


def architecture_adapter(architecture):
    factories = {Architecture.RISCV: RISCVAdapter, Architecture.ARM: ARMAdapter,
                 Architecture.POWERPC: PowerPCAdapter}
    return factories[architecture]() if architecture in factories else ConservativeAdapter(architecture, '', 0)
