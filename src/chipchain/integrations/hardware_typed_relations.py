"""Explicit local deterministic Hardware A3 export; no model or Agent invocation."""

import argparse
from pathlib import Path
from uuid import uuid4

from chipchain.agents.context import hardware_context
from chipchain.agents.contracts import HardwareAgentInput
from chipchain.tools.architecture.riscv import RiscVInstructionDecoder
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer
from chipchain.tools.hardware.encorpus.projection import PROJECTION_DESCRIPTOR
from chipchain.tools.hardware.relation_builder import build_hardware_relation_catalog
from chipchain.tools.hardware.relations import (
    HardwareRelationCatalog, hardware_relation_catalog_sha256,
    serialize_hardware_relation_catalog, sha256_text,
)

FROZEN_CONTEXT_SHA256 = {
    "encorpus:ibex:driver:743": "fd36deab7e5a26435b255fbc57bd548dbd7e50ff5fffa91d1b97703555b063ad",
    "encorpus:ibex:driver:820": "b10f773a346bfc6e2f33b01d0ce7a2c8fb26925e6b6ea26f5bf93880c77c6d07",
}


def prepare_local_catalog(sample: Path) -> tuple[HardwareAgentInput, HardwareRelationCatalog]:
    projected = EnCorpusIbexDriverAnalyzer().ingest(sample).analysis_input()
    inputs = HardwareAgentInput(case=projected.case, deterministic_observations=
                                RiscVInstructionDecoder().enrich(projected.deterministic_observations))
    # Production preflight pins frozen B.1 input, independently of catalog identity.
    expected = FROZEN_CONTEXT_SHA256.get(inputs.case.case_id)
    if expected is None or sha256_text(hardware_context(inputs)) != expected:
        raise ValueError("Local frozen B.1 context preflight failed")
    return inputs, build_hardware_relation_catalog(inputs, projection_descriptor=PROJECTION_DESCRIPTOR)


def persist_hardware_relation_catalog(catalog: HardwareRelationCatalog, output_root: Path) -> Path:
    """Caller explicitly chooses output root; domain paths remain unrestricted."""
    text = serialize_hardware_relation_catalog(catalog)
    case_id = catalog.source.case_id
    if case_id in (".", "..") or any(c in case_id for c in "/\\\x00"):
        raise ValueError("Case ID is not a safe output directory component")
    directory = output_root / case_id / str(uuid4())
    directory.mkdir(parents=True, exist_ok=False)
    destination = directory / "hardware_typed_relations.json"
    with destination.open("x", encoding="utf-8") as handle:
        handle.write(text)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--output-root", type=Path, default=Path("output"))
    parser.add_argument("--persist", action="store_true", help="Explicitly save one new deterministic catalog")
    args = parser.parse_args()
    _, catalog = prepare_local_catalog(args.sample)
    print(f"{catalog.source.case_id}: {len(catalog.relations)} relations, "
          f"{len(serialize_hardware_relation_catalog(catalog))} chars, sha256={hardware_relation_catalog_sha256(catalog)}")
    if args.persist:
        print(persist_hardware_relation_catalog(catalog, args.output_root))


if __name__ == "__main__":
    main()
