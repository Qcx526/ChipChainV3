# Local research inputs

`samples/hardware/` and `samples/firmware/` are local workspaces for real hardware and firmware materials. Actual contents are ignored by Git. The three reviewed synthetic architecture samples under `samples/firmware/` are explicit exceptions. A fresh clone does not need local research inputs to run the portable synthetic Type-II examples and tests.

The controlled verifier consumes already-grounded canonical objects and their replay bytes through an explicit manifest. The [ProcessorFuzz delivery](processorfuzz/real_case_001/README.md) is a separate, reviewed real-package ingestion path with a pinned original ZIP, per-file hashes and explicit provenance conflicts. Merely placing files in a workspace does not establish binding. Read-only artifact paths outside this repository remain valid; the workspace layout is a convention, not a domain rule.

Historic real corpus studies and their original ingestion code remain available on stable Git tags. Do not commit customer binaries, raw traces, RTL exports or simulator output as examples.
