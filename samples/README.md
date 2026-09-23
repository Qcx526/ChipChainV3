# Local research inputs

`samples/hardware/` and `samples/firmware/` are local workspaces for real hardware and firmware materials. Actual contents are ignored by Git. A fresh clone does not need these inputs to run the portable synthetic Type-II examples and tests.

The current controlled backend consumes already-grounded canonical objects and their replay bytes through an explicit manifest. It does not automatically ingest arbitrary files placed here. Read-only artifact paths outside this repository are valid; the workspace layout is a convention, not a domain rule.

Historic real corpus studies and their original ingestion code remain available on stable Git tags. Do not commit customer binaries, raw traces, RTL exports or simulator output as examples.
