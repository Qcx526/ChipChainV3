# Multi-Architecture QEMU Runtime Foundation V1

This phase adds a project-managed diagnostic QEMU environment on top of frozen commit `1a32c6a0e57f5b2ab851f327bcf6db02d21a924f`. It does not change the Type-II verifier, canonical runtime evidence, case assembly, or customer attack-chain conclusions.

## Runtime architecture boundary

The bundle targets Linux x86_64 and includes six system emulators: `arm-softmmu`, `aarch64-softmmu`, `riscv32-softmmu`, `riscv64-softmmu`, `ppc-softmmu`, and `ppc64-softmmu`. Installation is verified as a whole. An installed emulator is **not** an assertion that a particular firmware image can boot on one of its machines.

[`QemuRunProfile`](../../src/chipchain/runtime/qemu_profile.py) declares architecture family, width, exact emulator basename, machine, optional CPU, boot/load strategy, BIOS choice and extra argv. [`QemuRuntimeBackend`](../../src/chipchain/runtime/qemu_profile.py) resolves only the selected installation's `bin/` path and checks the pinned version before it constructs an argv tuple. It never searches `PATH` for a system QEMU. The first explicitly declared profile is the RV64 `virt` diagnostic benchmark; this is not a default for other RISC-V firmware. ARM and PowerPC require their own declared board/profile before acquisition, even though their emulators are in the bundle. Unknown board compatibility remains unknown.

The shared [firmware static IR](../../src/chipchain/firmware/static_ir.py) already represents `arm`, `riscv`, and `powerpc` identities and architecture-neutral behavior kinds such as `TLB_INVALIDATE` and `MEMORY_BARRIER`. Mnemonic interpretation remains in `semantics_arm.py`, `semantics_riscv.py`, and `semantics_powerpc.py`; [cross-layer case assembly](../../src/chipchain/cross_layer/case_assembly.py) compares supported behavior kinds rather than adding a QEMU- or mnemonic-specific match. The hardware behavior contract and resource catalog are not changed for this phase. The existing ProcessorFuzz adapter remains one hardware-delivery path, not a generic hardware schema.

Future QEMU raw observations should retain sequence, vCPU, architecture, width, PC, instruction bytes, and optional memory access as raw data. An architecture-specific runtime decoder may map the actual instruction into the **existing** shared semantic vocabulary. This phase creates no canonical `RuntimeObservation`, `RuntimeEvidence`, execution bridge, verifier input, or case identity from QEMU logs.

## Evidence scope

```text
Exact firmware ELF + declared QEMU profile + project-local emulator
    → bounded diagnostic plugin log
    → possible observation of emulator-side instruction dispatch
```

Even if an expected instruction appears in a log, that does not establish physical CPU retirement, silicon behavior, or a hardware trigger. **QEMU runtime evidence is not ProcessorFuzz RTL execution evidence. QEMU runtime evidence is not physical silicon evidence. QEMU machine compatibility is not target-board equivalence.** A subsequent instruction in the log supports only emulator-side control-flow continuation. Raw diagnostic logs stay under ignored `output/` and do not alter the scientific or customer reports.

Official QEMU source provenance and the exact installed bundle are recorded in [QEMU metadata](../../tools/qemu/README.md). The [QEMU TCG plugin documentation](https://www.qemu.org/docs/master/devel/tcg-plugins.html) describes `libexeclog.so` and notes that Capstone is needed for disassembly text.

## Pinned local build and installation

The signed official `qemu-11.1.1.tar.xz` from `https://download.qemu.org/qemu-11.1.1.tar.xz` has SHA256 `079ffbff8a7111bbc89022107cbabf3bbfd614d5fc9d7cc675991196aca12482`. Its detached signature verified against the release-key fingerprint `CEACC9E15534EBABB82D3FA03353C9CEF108B584`. The source corresponds to upstream tag `v11.1.1`. The build also pins Capstone 5.0.9 source SHA256 `0619da31af08152600af95c481527ef6d756c0a8404fca7544a4fdf6dfc2c0f9`; its ARM, AArch64, RISC-V and PowerPC decoders were linked statically. QEMU configure reported TCG, TCG plugins and Capstone enabled. Exact configure flags and source details are in [`SOURCE`](../../tools/qemu/SOURCE).

The local bundle is `tools/qemu/qemu_11.1.1-chipchain-linux-x86_64.tar.xz`, SHA256 `ee91518f709ab198ad55440b424e7e1022711e909ffea7f8e3ee770e4e40f4f8`. It is ignored by Git. The archive has 27 regular files: the six system binaries, `lib/qemu/plugins/libexeclog.so`, and selected ARM/RISC-V/PowerPC firmware and device-tree assets. The installed tree occupies about 419 MiB on this host; the compressed bundle is about 32 MiB. The validated build host is Ubuntu 22.04.5 LTS, x86_64, glibc 2.35. Runtime dynamic libraries include host GLib and Pixman, so no other distribution compatibility is claimed.

The builder's six version/machine probes and three representative plugin smokes passed. The customer setup script installed the pinned archive into `tools/qemu/install/` and passed `--verify-only` there. It also installed the same archive to ignored `output/qemu-foundation/alternate-install/` with `--offline --archive --install-dir`, then passed `--verify-only --install-dir` there. Both installations validated all six binaries and AArch64, RV64 and PPC64 plugin loading. The three representative binaries expose `-device loader,help`; this only establishes loader availability, not board compatibility.

## Published customer setup acceptance

The pinned QEMU bundle was published as the GitHub Release asset referenced by
`tools/qemu/SOURCE`.

A fresh repository clone with no existing `tools/qemu/install/`, no cached
QEMU bundle, no `--archive`, and no `--offline` successfully completed:

```bash
./scripts/setup_qemu.sh
```

The setup downloaded the exact pinned Release asset, verified the archive
SHA256, validated all six system emulators, and passed representative
plugin-load smoke checks for AArch64, RISC-V 64, and PowerPC 64.

A subsequent:
```bash
./scripts/setup_qemu.sh --verify-only
```
also passed.

This establishes the default online customer installation path for the
published project-managed QEMU bundle. It does not establish firmware/board
compatibility for arbitrary ARM, RISC-V, or PowerPC binaries, and it does not
change the scientific status of QEMU diagnostic logs. QEMU execution remains
distinct from ProcessorFuzz RTL execution and physical-silicon evidence.

## First RV64 execution feasibility

The ELF entry `0x80000000` and the key instruction PC `0x80000064` were derived from each frozen `firmware-analysis.json`, then checked against the ELF bytes. The explicit `RISCV64_FW_FEASIBILITY` profile selects the local `qemu-system-riscv64`, machine `virt`, TCG, one vCPU, no BIOS, and generic ELF loader. This profile is benchmark-specific and does not imply an automatic profile for other RV64 firmware.

The diagnostic commands, run from the repository root, were:

```bash
timeout --signal=INT --kill-after=2s 3s \
  tools/qemu/install/bin/qemu-system-riscv64 \
  -M virt -accel tcg -smp 1 -nographic -bios none \
  -device loader,file=samples/firmware/riscv/processorfuzz_real_case_001/positive/firmware.elf,cpu-num=0 \
  -monitor none \
  -plugin tools/qemu/install/lib/qemu/plugins/libexeclog.so,ifilter=sfence.vma \
  -d plugin -D output/qemu-foundation/fw-pos/execlog-filtered.log

timeout --signal=INT --kill-after=2s 3s \
  tools/qemu/install/bin/qemu-system-riscv64 \
  -M virt -accel tcg -smp 1 -nographic -bios none \
  -device loader,file=samples/firmware/riscv/processorfuzz_real_case_001/negative_trigger/firmware.elf,cpu-num=0 \
  -monitor none \
  -plugin tools/qemu/install/lib/qemu/plugins/libexeclog.so,ifilter=fence \
  -d plugin -D output/qemu-foundation/fw-neg/execlog-filtered.log
```

The actual Python profile runner used absolute forms of the same local emulator, ELF, plugin and log paths. Both invocations returned `timeout` status 124 after the bounded three-second interval; QEMU itself did not report a startup or loader error. The diagnostic logs are ignored local outputs, not canonical artifacts. Repetition counts can depend on emulator scheduling and the timeout and are not scientific identities.

| Firmware | Static fact at `0x80000064` | QEMU plugin observation | Scope |
| --- | --- | --- | --- |
| FW-POS | ELF bytes `73000012`; `sfence.vma zero,zero` | Two log lines at PC `0x80000064` with opcode `0x12000073` and `sfence.vma zero,zero` | The opcode is the little-endian interpretation of the frozen bytes; QEMU-side execution callback observed. |
| FW-NEG-TRIGGER | ELF bytes `0f003003`; `fence 0x3,0x3` | Two log lines at PC `0x80000064` with opcode `0x0330000f` and `fence rw,rw`; the same run also logged `fence` at `0x8000005c` | QEMU-side execution callback observed; `fence rw,rw` is the emulator's disassembly of the same instruction bytes. |

The observed target PC means these firmware images did not fail before the named instruction in this declared QEMU profile. It does not identify which command/input iteration caused a callback, prove physical retirement, or establish the hardware-team ProcessorFuzz trigger or deviation. No QEMU log was imported into `case-manifest.json`, `association.json`, the Type-II verifier, or `attack-chain-report.md`; their runtime-binding and trigger conclusions remain unchanged.
