"""Synthetic targets share the same case and processor behavior contracts."""

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from chipchain.domain.behavior import BehaviorKind, ProcessorBehavior, ProcessorBehaviorIR
from chipchain.domain.case import CaseBundle, TargetDescriptor
from chipchain.domain.common import AnalysisLayer, Architecture, Endianness

from .test_domain import assert_round_trip


@pytest.mark.parametrize("family,variant,width,byte_order", [
    ("arm", "armv8-a/aarch64", 64, "little"),
    ("riscv", "rv32imac", 32, "little"),
    ("powerpc", "powerpc-booke", 32, "big"),
])
def test_target_case_construction_and_serialization(
    load_case: Callable[[str], CaseBundle],
    family: str, variant: str, width: int, byte_order: str,
) -> None:
    target = TargetDescriptor.model_validate({
        "architecture": family,
        "processor_id": "synthetic-processor",
        "isa_variant": variant,
        "word_size_bits": width,
        "endianness": byte_order,
    })
    assert target.architecture == Architecture(family)
    assert target.architecture != Architecture.UNKNOWN
    assert target.isa_variant == variant
    assert target.word_size_bits == width
    assert target.endianness == Endianness(byte_order)
    assert target.model_dump(mode="json")["architecture"] == family
    assert target.model_dump(mode="json")["endianness"] == byte_order
    assert_round_trip(target)

    data = load_case("paired").model_dump()
    data["target"] = target.model_dump()
    case = CaseBundle.model_validate(data)
    assert case.target == target
    assert case.is_paired
    assert case.model_dump(mode="json")["target"]["architecture"] == family
    assert_round_trip(case)


@pytest.mark.parametrize("name", ["hardware_only", "firmware_only", "paired"])
def test_existing_fixtures_allow_unknown_target_details(
    load_case: Callable[[str], CaseBundle], name: str,
) -> None:
    case = load_case(name)
    assert case.target.isa_variant is None
    assert case.target.word_size_bits is None
    assert case.target.endianness == Endianness.UNKNOWN
    assert_round_trip(case)


@pytest.mark.parametrize("width", [0, -1, True, 32.5, "32"])
def test_word_size_rejects_nonpositive_or_noninteger_values(width: object) -> None:
    with pytest.raises(ValidationError, match="word_size_bits"):
        TargetDescriptor.model_validate({"processor_id": "synthetic", "word_size_bits": width})


@pytest.mark.parametrize("width", [24, 128])
def test_target_metadata_does_not_assume_an_isa_taxonomy(width: int) -> None:
    target = TargetDescriptor(
        processor_id="synthetic", isa_variant="open-synthetic-variant", word_size_bits=width,
    )
    assert target.word_size_bits == width
    assert target.isa_variant == "open-synthetic-variant"
    assert_round_trip(target)


@pytest.mark.parametrize("architecture", [Architecture.ARM, Architecture.RISCV, Architecture.POWERPC])
def test_architecture_families_share_exact_processor_behavior_ir(
    architecture: Architecture,
) -> None:
    ir = ProcessorBehaviorIR(case_id="synthetic:paired", behaviors=[
        ProcessorBehavior(
            behavior_id=f"synthetic:{layer.value}:behavior",
            kind=BehaviorKind.REGISTER_ACCESS,
            architecture=architecture,
            origin=layer,
            summary="Synthetic behavior; no ISA semantics asserted",
        )
        for layer in (AnalysisLayer.HARDWARE, AnalysisLayer.FIRMWARE)
    ])
    assert type(ir) is ProcessorBehaviorIR
    assert all(type(item) is ProcessorBehavior for item in ir.behaviors)
    assert all(item.architecture == architecture for item in ir.behaviors)
    assert_round_trip(ir)
