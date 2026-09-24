# Firmware Static IR → CAP0 mapping audit

The general frontend produces `FirmwareStaticAnalysis/v2` for ARM, RISC-V and PowerPC, with analyzer, Ghidra, exporter SHA and semantics producer identities. The frozen `FirmwareCapability/v1` contract remains unchanged. `static_capability.py` projects only semantically expressible facts from **explicitly declared synthetic fixtures**; it refuses an arbitrary real ELF because CAP0's frozen source-kind enum has no honest general Ghidra-static source kind. This is a visible provenance boundary, not a file-path inference. The authentic ProcessorFuzz delivery contains hardware-supplied trigger-test firmware, not customer firmware. Its report uses a separate `general-static-capability/v1` projection carrying explicit Ghidra/ELF provenance and `STATIC_ONLY` status. It is not mislabeled as frozen CAP0 or substituted into the frozen verifier.

| Static IR kind | CAP0 primitive | Current handling |
|---|---|---|
| `INSTRUCTION` | `INSTRUCTION_EXECUTION` | One static-only site. |
| `DIRECT_CALL`, `DIRECT_BRANCH`, `CONDITIONAL_BRANCH` | `DIRECT_CONTROL_TRANSFER` | Requires exact target-set constraint; unresolved target becomes indirect/partial. A conditional branch does not prove the condition is taken. |
| `INDIRECT_CALL`, `INDIRECT_BRANCH`, `RETURN` | `INDIRECT_CONTROL_TRANSFER` | Target remains unknown; return is not asserted to reach a particular site. |
| `MEMORY_LOAD`, `MEMORY_STORE` | `MEMORY_READ`, `MEMORY_WRITE` | Exact address/width/value retained when proven. Without a typed resource, target resource remains partially formalized. |
| Memory behavior bound to unique `MMIO_REGISTER` | `MMIO_READ`, `MMIO_WRITE` | Promotion requires exact resource binding and width; unbound/ambiguous operations stay memory. |
| `MMIO_READ`, `MMIO_WRITE` | Same | Only if an upstream fact has an independently established MMIO resource. |
| RISC-V `SYSTEM_REGISTER_READ/WRITE` | `CSR_READ/WRITE` | Only RISC-V CSR identity is semantically valid. |
| ARM system-register and PowerPC SPR access | — | Remains in Static IR; CAP0 CSR is not an honest substitute. |
| `EXCEPTION_RETURN` | `EXCEPTION_RETURN` | Partial unless a target resource is objectively known. |
| `MEMORY_BARRIER`, `INSTRUCTION_BARRIER` | — | Requires future CAP0 primitive extension. |
| `ATOMIC_LOAD`, `ATOMIC_STORE`, `TLB_INVALIDATE` | — | Requires future CAP0 primitive extension. |
| `OTHER`, `UNKNOWN` | — | Preserved in Static IR and report; unsupported is not safe. |

Each projected CAP0 capability is one source PC and remains `static_only`. Origin and source artifacts are marked `synthetic_fixture`, with ELF SHA, canonical analysis-byte hash, instruction ID and behavior ID. Control authority is always `not_established`; no retirement, order, hardware trigger or deviation evidence is fabricated. The controlled demo's candidate matcher consumes this general frontend projection, and `capability-continuity.json` binds its three MMIO sites to the reviewed frozen runtime CAP0 capabilities. Only the original runtime capabilities enter the frozen verifier.

The typed hardware resource catalog declares exact ENABLE, COMMAND and STATUS addresses and widths for the controlled synthetic case. Generic Ghidra memory facts at those addresses bind to these resources, and the synthetic projection contains two `MMIO_WRITE` and one `MMIO_READ` site. Matching CAP0 constraints against an HBC creates only `CrossLayerCandidate`; the existing verifier alone checks runtime order, pre-state, observation binding and Reference/Variant differential.
