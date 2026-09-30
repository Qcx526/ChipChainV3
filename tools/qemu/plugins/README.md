# ChipChain raw instruction callback plugin

This additive plugin is compiled into the caller's output directory by
`chipchain.runtime.acquisition`. It does not change the frozen QEMU installation,
bundle, setup scripts, or `libexeclog.so`. A host C compiler (`cc`) is required.

`chipchain_trace.c` produces only machine-readable raw instruction callback
observations: sequence, vCPU, virtual PC, exact instruction bytes, and size.
It does not decode instructions or classify scientific behavior. Unlike
`execlog`, it retains all instruction bytes, has no disassembly-text dependency,
and declares an objectively bounded observation prefix.

The header carries the content-addressed run descriptor ID and declared policy;
the terminal record records the stopping result. The first callback
through the selected instruction plus N successors is recorded, or the maximum
event count is recorded when the target window has not completed. At the next
callback, the plugin emits the terminal record, flushes the stream, and exits
without recording that sentinel instruction. The process exit follows QEMU's
own `contrib/plugins/stoptrigger.c` pattern. A host watchdog without a complete
terminal record is a failed acquisition, never a shorter scientific trace.
Only one vCPU is accepted in V1.

[QEMU's plugin documentation](https://www.qemu.org/docs/master/devel/tcg-plugins.html#instructions)
states that instruction instrumentation runs before instruction execution and
does not prove completion. Consequently the evidence means
`QEMU_INSTRUCTION_EXECUTION_OBSERVED`, specifically the pre-instruction
execution callback. It never means architectural or physical retirement.
Observed sequence establishes callback order within the declared run only.

## Pinned plugin API provenance

`qemu-plugin-v7.h` is a minimal declaration-only subset of QEMU 11.1.1's
`include/plugins/qemu-plugin.h`, API version 7. The declarations and struct/enum
layouts used here match that header; unused GLib-dependent declarations are
omitted so this small plugin needs no GLib development package.

- Upstream tag: `v11.1.1`.
- Upstream commit: `c3d48b7d1e89604920e5b81b91140c2ad39a1943`.
- Original complete header SHA256:
  `335d4e472067e914add598b60d1f7cf0dc029cd48f62f66656d6a88c54d8d9f9`.
- Signed source archive and verification provenance remain in
  [`../SOURCE`](../SOURCE).
- Upstream license and attribution are retained in the subset header.
- Each acquisition records the exact plugin source, subset header, and compiled
  shared-object SHA256, alongside the pinned QEMU executable identity.

The raw protocol is `chipchain-qemu-trace/v1`, JSON Lines: exactly one header,
contiguous zero-based event records, and exactly one end record. Duplicate JSON
fields, extra records/fields, malformed bytes, missing or inconsistent end
records, run-descriptor/target/profile mismatches, non-entry prefixes, and event bytes outside
the unique executable ELF mapping are rejected. Nothing from human-readable
disassembly or wall-clock time enters this protocol.

## R1 provenance and rebuild audit

The source and subset header bytes remain unchanged in R1. Their digests are:

- `chipchain_trace.c`: `079ceca32e377656c673950b7971bffd65d43964d215c6d1f05f5d58df37bad1`.
- `qemu-plugin-v7.h`: `b097fe65bcfdb50949a824c65be796a5d5925c0f72033c06e086b8addacb4678`.

[`header-provenance.json`](header-provenance.json) pins the upstream QEMU tag,
commit, original full-header digest, subset digest, API 7 and GPL-2.0-or-later
license. The original complete header in the verified local QEMU source was
checked against the digest above. The subset preserves the original copyright
attribution and SPDX text. It is vendored so rebuilding this small plugin does
not require a QEMU source tree or GLib development headers on a customer host.

Before compilation, the build helper compares that record with the frozen
`tools/qemu/SOURCE`, the actual subset bytes and its API macro. Actual plugin
loading additionally checks API compatibility in the pinned QEMU process; its
header and plugin version must agree with API 7. The filename alone establishes
none of these conditions.

From the project root, an independent rebuild is:

```bash
.venv/bin/python -m chipchain.runtime.plugin_build --output output/qemu-plugin-rebuild
```

Acquisition invokes the same helper automatically. The exact compile recipe is:

```bash
cc -std=c11 -O2 -fPIC -shared -fvisibility=hidden \
  -Wall -Wextra -Werror -Wl,--build-id=none \
  tools/qemu/plugins/chipchain_trace.c \
  -o output/qemu-plugin-rebuild/trace-plugin.so
```

Use an output directory without existing build artifacts. The helper records
`plugin-build.json` next to the generated `.so`: source/header/provenance hashes,
API version, compiler version and compiler executable SHA, path-independent
command template, resulting binary SHA and a deterministic build-record ID.
It includes no timestamps, PIDs or host absolute paths. This is inspectable local
build provenance, not trusted-host attestation. It is an auxiliary record;
compiler version is not an input to every event ID.

The canonical run binds actual plugin binary SHA, source SHA, subset-header SHA,
header-provenance SHA and API version. Changing the binary changes the run ID
even if its source or filename stays the same. The retained `.so` is checked
against this identity on evidence replay. Generated binaries remain in ignored
`output/`; they are not committed or installed into the frozen QEMU bundle.

On the R1 validation host (`cc` 11.4.0), the resulting plugin SHA256 is
`61fd2d11e4d1665ba2d69e3172940d8faa6a5b09df3bdfe34faa01f3edfa9ed6`,
identical to the V1 plugin binary. Different toolchains may produce different
bytes; those differences are explicitly represented in instrumentation/run identity.

`SUPPORTED` means a compatible, source-bound QEMU instruction callback for the
exact static fact under its declared profile and image mapping. It never asserts
instruction completion, physical retirement, memory side-effect completion,
hardware trigger/deviation, hardware timing, silicon behavior or vulnerability
verification. Event order is only within the same run and vCPU.
