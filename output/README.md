# Local analysis results

Runtime output is ignored by Git. `chipchain analyze --output output/type2-positive` writes `summary.json`, `verification.json`, and `report.md` to the caller's chosen directory; `--verbose-artifacts` adds selected validated intermediate objects. Analysis through the Python API is read-only until `write_result` is called explicitly.

Historical local research collections may remain in this workspace for read-only regression replay. They are not part of the portable repository and should not be committed.
