# Type-II evidence method

ChipChain uses “Type-II” for a normal firmware behavior that triggers a hardware deviation observable under a controlled hardware comparison. The firmware need not be malicious. The current result is a controlled synthetic experiment, so it establishes neither physical silicon behavior nor an attacker's ability to induce the execution.

## Claim ladder

| Claim | Required evidence | What it does not imply |
| --- | --- | --- |
| Static MMIO fact | Exact ELF bytes, decoded instruction and target map | The instruction was executed. |
| Execution binding | Same-run retired source instruction and completed MMIO transaction, both provenance-bound | Trigger preconditions were satisfied. |
| Trigger supported | Exact access width/value, ordering, reset epoch, required pre-state and target revision | Hardware deviated. |
| Deviation supported | Specification-backed expected and deviating values, complete relevant trace window | Observation is independent or correctly attributed. |
| Objective observation supported | Post-update internal sample and completed bus-visible read linked to the same run | A physical chip is vulnerable. |
| Controlled Type-II positive | All gates above plus matching Reference control, approved source delta and differential | An external user can control the firmware path. |

The P1 positive is possible because the Variant's accepted ENABLE=1 write precedes the COMMAND=A5 write in one reset epoch, the pre-state is established, its post-update STATUS is `0xDEAD`, and the bus read agrees. The matching Reference executes the trigger but reads the specified `0` and records no deviation. The controlled source proof binds the single reviewed RTL change.

N1 executes COMMAND=A4: the A5 trigger is contradicted even though the instructions and bus transactions are bound. N2 is the Reference control inside P1: trigger supported, expected behavior supported, deviation not observed. U1 removes the explicit observation binding: available facts cannot be promoted to a verified chain, so the final status is `unknown`.

## Fail-closed behavior

Invalid content IDs, altered source patch bytes, changed raw traces, mismatched capabilities, platform revisions or source provenance are errors or unknown according to the frozen verifier's contracts. An absent optional link is not silently reconstructed. A valid negative/unknown result still exits normally; invalid input exits with an error and does not yield an accepted result.

The canonical `verification.json` is authoritative for condition statuses, evidence IDs, reason codes and missing requirements. `report.md` is a presentation of that result. It does not create additional findings or change scientific identities.

The general `FirmwareCapability` contract can represent static behavior and limited execution evidence. Its `control_authority` remains `not_established` for these normal firmware runs. No step converts an observed read value directly into a vulnerability claim, and no negative or unknown result proves the platform safe.
