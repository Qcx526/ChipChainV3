# ProcessorFuzz hardware deliveries

`real_case_001/` contains the immutable hardware-team ZIP and deterministic
acceptance artifacts. A directory name is an indexing convenience; testcase
identity comes from the `.si` bytes. Package discovery does not establish
that every file belongs to one trusted execution or build chain.

The contained ELF is a hardware-supplied trigger-validation test program.
It is not customer firmware. General firmware-analysis validation uses
independently authored project firmware samples; future customer firmware
must be introduced as a separate evidence source.
