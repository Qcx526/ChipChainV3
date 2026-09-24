# Firmware Analysis Report

> 输入角色：硬件团队提供的 trigger-test firmware；不是客户固件、生产固件或真实目标镜像。

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:13b0933b79d5fd458b61ea5915e1517afc0f6ab2b7e09b2b6cc3443a252ecb96` |
| architecture | `riscv` |
| bit_width | `64` |
| endianness | `little` |
| elf_sha256 | `649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86` |
| arm_profile | `not applicable` |
| arm_cpu_name | `not established` |
| entry_address | `0x80000000` |
| function_count | `4` |
| basic_block_count | `220` |
| instruction_count | `693` |
| cfg_edge_count | `226` |
| direct_call_count | `3` |
| indirect_call_count | `0` |
| unresolved_call_count | `0` |
| memory_load_count | `47` |
| memory_store_count | `68` |
| mmio_read_count | `0` |
| mmio_write_count | `0` |
| system_register_read_count | `52` |
| system_register_write_count | `40` |
| barrier_count | `2` |
| atomic_count | `60` |
| tlb_invalidate_count | `2` |
| exception_return_count | `7` |
| unsupported_count | `147` |
| unresolved_address_count | `175` |
| ambiguous_ownership_count | `0` |
| ghidra_language | `RISCV:LE:64:default` |
| ghidra_version | `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` |
| producer | `{'analyzer': 'chipchain-general-firmware/v2', 'ghidra': '12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093', 'exporter_sha256': 'b006cc85631d9ef7f9232a03dbc05ce418296f885f427b9e2bd2762f46b9cbbe', 'semantics': 'chipchain-three-isa-semantics/r1', 'semantics_sha256': '0454ca318a5af7dd42e71e7f3b0e92f11424ffe035184b88f90d2ec92d3532ca'}` |

### Evidence-backed behavior examples

| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |
|---|---|---|---|---|---|---|---|
| `0x80000008` | `entry` | `ld ra,0x0(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:e6a8e6789ec977932bccd44bb505da545f29c8acf4699bc00ec710658c546acb` | partial |
| `0x8000000c` | `entry` | `ld sp,0x8(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:75a8289e93198b75ff97d0a03caec592041aebf0de7898086bb6800858759863` | partial |
| `0x80000010` | `entry` | `ld gp,0x10(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:944cc5f9e0f592c26bab0a6b54e810900b44e05438258c13751e3b17138b04a5` | partial |
| `0x80000014` | `entry` | `ld tp,0x18(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:220d8ce46d1c1f37b256cc5a5efe05edd8f33363eac7dfd70b469965ee208b19` | partial |
| `0x80000018` | `entry` | `ld t0,0x20(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:14764dc2abe44f4cea8173c01640ee90f6d09e0d069b3bd31788ae32bfd20523` | partial |
| `0x8000001c` | `entry` | `ld t1,0x28(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:26a59469bf87c8241efae3ad8675d2feb356880da8906d2dad92b2941e1c4f74` | partial |
| `0x80000020` | `entry` | `ld t2,0x30(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:afd878bb6b72d4bcc63e87357ec842ad3209938e16703286aae1e9cf506fb825` | partial |
| `0x80000024` | `entry` | `ld s0,0x38(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:cbb2a60659055c40ba077b516e36c1d0c3c83e16a303c887af0922bf84a9f645` | partial |
| `0x80000028` | `entry` | `ld s1,0x40(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:bf7301ab4626776549b7c2fced1d9f9affab582d3b69cfdebc45268ea01668c1` | partial |
| `0x8000002c` | `entry` | `ld a0,0x48(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:94abb8577e86839463239630140e3c47456170a6d00abb7763ef58e30bd890d6` | partial |
| `0x80000030` | `entry` | `ld a1,0x50(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:6887f11c70ec7b624e849ee7800eb471c81514838e982de5276ada0b6faa78c7` | partial |
| `0x80000034` | `entry` | `ld a2,0x58(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:8fabd2e9d3e8d8525186287239d1af78c9eaeb3f8cbcb50a60010e7d53c0738d` | partial |

## 2. Binary / Architecture Identity

ELF SHA256 `649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86`；RISCV 64-bit little；入口 `0x80000000`。
PT_LOAD 段 8 个；节 14 个。

## 3. Program Structure

识别 4 个函数、220 个基本块、693 条指令和 226 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x80000000` | `entry` | 0x80000000–0x80000087 | `fwfunction:72d175e167ddd0c704d063e2c9286c68beec0560dc4ab3a74de8a4cacc7dc348` |
| `0x80000088` | `init_freg` | 0x80000088–0x80000113 | `fwfunction:bcdb298c4ff9915f3782c109febec7034760639daf7026922b0b5c47d7bc28a0` |
| `0x8000035c` | `reset_vector` | 0x8000035c–0x8000046f | `fwfunction:42225c1604bf2741393c88a0e6190c7f5a14ff69bc754958b7c3bdcc253af5ef` |
| `0x800007c8` | `_l96` | 0x800007c8–0x80000843 | `fwfunction:2776c74cef58c5862fce6edce006fe6240f26b8c37966fd8f08a93563e1d1510` |

## 5. Basic Blocks and CFG

| 基本块 | 结束 | 所属函数数 | 出边数 |
|---|---:|---:|---:|
| `0x80000000` | `0x80000087` | 1 | 1 |
| `0x80000088` | `0x80000113` | 1 | 0 |
| `0x80000114` | `0x80000117` | 0 | 1 |
| `0x80000118` | `0x80000227` | 0 | 1 |
| `0x80000228` | `0x8000023f` | 0 | 1 |
| `0x80000240` | `0x800002bb` | 0 | 1 |
| `0x800002bc` | `0x8000034b` | 0 | 1 |
| `0x8000034c` | `0x80000357` | 0 | 1 |
| `0x80000358` | `0x8000035b` | 0 | 1 |
| `0x8000035c` | `0x80000363` | 1 | 1 |
| `0x80000364` | `0x80000367` | 1 | 2 |
| `0x80000368` | `0x800003cf` | 1 | 2 |
| `0x800003d0` | `0x800003e3` | 1 | 1 |
| `0x800003e4` | `0x80000417` | 1 | 2 |
| `0x80000418` | `0x8000041b` | 1 | 1 |
| `0x8000041c` | `0x8000042f` | 1 | 1 |
| `0x80000430` | `0x8000045b` | 1 | 1 |
| `0x8000045c` | `0x8000046f` | 1 | 0 |
| `0x80000480` | `0x80000483` | 0 | 1 |
| `0x80000484` | `0x8000048f` | 0 | 1 |
| `0x80000490` | `0x80000493` | 0 | 2 |
| `0x80000494` | `0x80000497` | 0 | 1 |
| `0x80000498` | `0x800004a3` | 0 | 1 |
| `0x800004a4` | `0x800004a7` | 0 | 1 |
| `0x800004a8` | `0x800004bb` | 0 | 1 |
| `0x800004bc` | `0x800004c7` | 0 | 1 |
| `0x800004c8` | `0x800004d7` | 0 | 1 |
| `0x800004d8` | `0x800004db` | 0 | 1 |
| `0x800004dc` | `0x800004eb` | 0 | 1 |
| `0x800004ec` | `0x800004ef` | 0 | 1 |
| `0x800004f0` | `0x800004ff` | 0 | 1 |
| `0x80000500` | `0x8000050f` | 0 | 0 |
| `0x80000510` | `0x80000513` | 0 | 2 |
| `0x80000514` | `0x8000053f` | 0 | 1 |
| `0x80000540` | `0x80000543` | 0 | 1 |
| `0x80000544` | `0x80000547` | 0 | 1 |
| `0x80000548` | `0x8000054b` | 0 | 1 |
| `0x8000054c` | `0x8000055b` | 0 | 1 |
| `0x8000055c` | `0x8000055f` | 0 | 1 |
| `0x80000560` | `0x80000563` | 0 | 1 |
| `0x80000564` | `0x80000577` | 0 | 1 |
| `0x80000578` | `0x8000057b` | 0 | 1 |
| `0x8000057c` | `0x8000057f` | 0 | 1 |
| `0x80000580` | `0x80000597` | 0 | 1 |
| `0x80000598` | `0x8000059b` | 0 | 1 |
| `0x8000059c` | `0x8000059f` | 0 | 1 |
| `0x800005a0` | `0x800005ab` | 0 | 1 |
| `0x800005ac` | `0x800005bb` | 0 | 0 |
| `0x800005bc` | `0x800005bf` | 0 | 1 |
| `0x800005c0` | `0x800005c3` | 0 | 1 |
| `0x800005c4` | `0x800005d3` | 0 | 0 |
| `0x800005d4` | `0x800005df` | 0 | 1 |
| `0x800005e0` | `0x800005ef` | 0 | 1 |
| `0x800005f0` | `0x800005f3` | 0 | 1 |
| `0x800005f4` | `0x80000603` | 0 | 1 |
| `0x80000604` | `0x80000607` | 0 | 1 |
| `0x80000608` | `0x8000060f` | 0 | 1 |
| `0x80000610` | `0x8000061f` | 0 | 0 |
| `0x80000620` | `0x80000623` | 0 | 1 |
| `0x80000624` | `0x80000633` | 0 | 0 |
| `0x80000634` | `0x80000643` | 0 | 1 |
| `0x80000644` | `0x80000647` | 0 | 1 |
| `0x80000648` | `0x8000064b` | 0 | 2 |
| `0x8000064c` | `0x8000065f` | 0 | 1 |
| `0x80000660` | `0x80000663` | 0 | 1 |
| `0x80000664` | `0x80000667` | 0 | 2 |
| `0x80000668` | `0x8000066b` | 0 | 1 |
| `0x8000066c` | `0x80000677` | 0 | 1 |
| `0x80000678` | `0x8000067b` | 0 | 1 |
| `0x8000067c` | `0x8000067f` | 0 | 2 |
| `0x80000680` | `0x8000068f` | 0 | 1 |
| `0x80000690` | `0x8000069f` | 0 | 1 |
| `0x800006a0` | `0x800006ab` | 0 | 1 |
| `0x800006ac` | `0x800006af` | 0 | 1 |
| `0x800006b0` | `0x800006b3` | 0 | 1 |
| `0x800006b4` | `0x800006c3` | 0 | 1 |
| `0x800006c4` | `0x800006c7` | 0 | 1 |
| `0x800006c8` | `0x800006d7` | 0 | 1 |
| `0x800006d8` | `0x800006db` | 0 | 1 |
| `0x800006dc` | `0x800006e7` | 0 | 1 |
| `0x800006e8` | `0x800006f7` | 0 | 1 |
| `0x800006f8` | `0x800006fb` | 0 | 1 |
| `0x800006fc` | `0x800006ff` | 0 | 1 |
| `0x80000700` | `0x80000703` | 0 | 1 |
| `0x80000704` | `0x80000707` | 0 | 1 |
| `0x80000708` | `0x8000070b` | 0 | 1 |
| `0x8000070c` | `0x8000070f` | 0 | 2 |
| `0x80000710` | `0x80000713` | 0 | 1 |
| `0x80000714` | `0x80000717` | 0 | 1 |
| `0x80000718` | `0x8000071b` | 0 | 1 |
| `0x8000071c` | `0x8000071f` | 0 | 1 |
| `0x80000720` | `0x80000723` | 0 | 2 |
| `0x80000724` | `0x80000733` | 0 | 1 |
| `0x80000734` | `0x80000747` | 0 | 1 |
| `0x80000748` | `0x8000075b` | 0 | 1 |
| `0x8000075c` | `0x8000075f` | 0 | 1 |
| `0x80000760` | `0x80000763` | 0 | 1 |
| `0x80000764` | `0x80000773` | 0 | 1 |
| `0x80000774` | `0x80000777` | 0 | 2 |
| `0x80000778` | `0x8000077b` | 0 | 1 |
| `0x8000077c` | `0x8000077f` | 0 | 1 |
| `0x80000780` | `0x80000783` | 0 | 2 |
| `0x80000784` | `0x80000787` | 0 | 1 |
| `0x80000788` | `0x80000793` | 0 | 1 |
| `0x80000794` | `0x80000797` | 0 | 1 |
| `0x80000798` | `0x8000079b` | 0 | 1 |
| `0x8000079c` | `0x8000079f` | 0 | 1 |
| `0x800007a0` | `0x800007a3` | 0 | 1 |
| `0x800007a4` | `0x800007a7` | 0 | 1 |
| `0x800007a8` | `0x800007ab` | 0 | 1 |
| `0x800007ac` | `0x800007af` | 0 | 1 |
| `0x800007b0` | `0x800007b3` | 0 | 1 |
| `0x800007b4` | `0x800007b7` | 0 | 1 |
| `0x800007b8` | `0x800007c7` | 0 | 1 |
| `0x800007c8` | `0x800007cb` | 1 | 1 |
| `0x800007cc` | `0x800007cf` | 1 | 1 |
| `0x800007d0` | `0x800007d3` | 1 | 1 |
| `0x800007d4` | `0x800007e3` | 1 | 1 |
| `0x800007e4` | `0x800007e7` | 1 | 1 |
| `0x800007e8` | `0x800007eb` | 1 | 1 |
| `0x800007ec` | `0x800007ef` | 1 | 1 |
| `0x800007f0` | `0x800007f3` | 1 | 1 |
| `0x800007f4` | `0x800007f7` | 1 | 1 |
| `0x800007f8` | `0x80000807` | 1 | 1 |
| `0x80000808` | `0x8000080b` | 1 | 1 |
| `0x8000080c` | `0x8000081b` | 1 | 1 |
| `0x8000081c` | `0x8000082b` | 1 | 1 |
| `0x8000082c` | `0x8000082f` | 1 | 1 |
| `0x80000830` | `0x80000833` | 1 | 1 |
| `0x80000834` | `0x80000843` | 1 | 0 |
| `0x80000844` | `0x80000847` | 0 | 1 |
| `0x80000848` | `0x80000857` | 0 | 1 |
| `0x80000858` | `0x8000085b` | 0 | 1 |
| `0x8000085c` | `0x8000085f` | 0 | 1 |
| `0x80000860` | `0x80000863` | 0 | 1 |
| `0x80000864` | `0x80000867` | 0 | 1 |
| `0x80000868` | `0x8000086b` | 0 | 1 |
| `0x8000086c` | `0x80000877` | 0 | 1 |
| `0x80000878` | `0x8000087b` | 0 | 1 |
| `0x8000087c` | `0x8000087f` | 0 | 1 |
| `0x80000880` | `0x80000883` | 0 | 1 |
| `0x80000884` | `0x80000893` | 0 | 1 |
| `0x80000894` | `0x800008a3` | 0 | 1 |
| `0x800008a4` | `0x800008af` | 0 | 1 |
| `0x800008b0` | `0x800008b3` | 0 | 1 |
| `0x800008b4` | `0x800008b7` | 0 | 2 |
| `0x800008b8` | `0x800008c3` | 0 | 1 |
| `0x800008c4` | `0x800008c7` | 0 | 1 |
| `0x800008c8` | `0x800008d7` | 0 | 1 |
| `0x800008d8` | `0x800008e7` | 0 | 1 |
| `0x800008e8` | `0x800008eb` | 0 | 1 |
| `0x800008ec` | `0x800008ef` | 0 | 1 |
| `0x800008f0` | `0x800008f3` | 0 | 1 |
| `0x800008f4` | `0x80000903` | 0 | 1 |
| `0x80000904` | `0x80000907` | 0 | 2 |
| `0x80000908` | `0x8000090b` | 0 | 1 |
| `0x8000090c` | `0x8000090f` | 0 | 1 |
| `0x80000910` | `0x80000913` | 0 | 1 |
| `0x80000914` | `0x8000091f` | 0 | 1 |
| `0x80000920` | `0x80000923` | 0 | 1 |
| `0x80000924` | `0x80000927` | 0 | 1 |
| `0x80000928` | `0x8000092b` | 0 | 1 |
| `0x8000092c` | `0x8000092f` | 0 | 1 |
| `0x80000930` | `0x80000933` | 0 | 1 |
| `0x80000934` | `0x8000093f` | 0 | 1 |
| `0x80000940` | `0x8000094b` | 0 | 1 |
| `0x8000094c` | `0x8000094f` | 0 | 1 |
| `0x80000950` | `0x8000095b` | 0 | 1 |
| `0x8000095c` | `0x8000095f` | 0 | 1 |
| `0x80000960` | `0x80000963` | 0 | 1 |
| `0x80000964` | `0x80000967` | 0 | 1 |
| `0x80000968` | `0x8000096b` | 0 | 1 |
| `0x8000096c` | `0x8000096f` | 0 | 1 |
| `0x80000970` | `0x80000973` | 0 | 1 |
| `0x80000974` | `0x80000977` | 0 | 1 |
| `0x80000978` | `0x8000097b` | 0 | 1 |
| `0x8000097c` | `0x8000097f` | 0 | 1 |
| `0x80000980` | `0x80000983` | 0 | 1 |
| `0x80000984` | `0x80000987` | 0 | 2 |
| `0x80000988` | `0x80000997` | 0 | 1 |
| `0x80000998` | `0x8000099b` | 0 | 1 |
| `0x8000099c` | `0x8000099f` | 0 | 1 |
| `0x800009a0` | `0x800009a3` | 0 | 1 |
| `0x800009a4` | `0x800009a7` | 0 | 1 |
| `0x800009a8` | `0x800009ab` | 0 | 1 |
| `0x800009ac` | `0x800009bb` | 0 | 1 |
| `0x800009bc` | `0x800009bf` | 0 | 1 |
| `0x800009c0` | `0x800009cf` | 0 | 1 |
| `0x800009d0` | `0x800009df` | 0 | 1 |
| `0x800009e0` | `0x800009e3` | 0 | 1 |
| `0x800009e4` | `0x800009f3` | 0 | 1 |
| `0x800009f4` | `0x80000a03` | 0 | 1 |
| `0x80000a04` | `0x80000a13` | 0 | 1 |
| `0x80000a14` | `0x80000a23` | 0 | 1 |
| `0x80000a24` | `0x80000a33` | 0 | 1 |
| `0x80000a34` | `0x80000a37` | 0 | 1 |
| `0x80000a38` | `0x80000a3b` | 0 | 1 |
| `0x80000a3c` | `0x80000a3f` | 0 | 1 |
| `0x80000a40` | `0x80000a4b` | 0 | 1 |
| `0x80000a4c` | `0x80000a4f` | 0 | 1 |
| `0x80000a50` | `0x80000a57` | 0 | 1 |
| `0x80000a58` | `0x80000a5b` | 0 | 1 |
| `0x80000a5c` | `0x80000a5f` | 0 | 1 |
| `0x80000a60` | `0x80000a63` | 0 | 1 |
| `0x80000a64` | `0x80000a67` | 0 | 1 |
| `0x80000a68` | `0x80000a87` | 0 | 1 |
| `0x80000a88` | `0x80000a8f` | 0 | 1 |
| `0x80000a90` | `0x80000a93` | 0 | 2 |
| `0x80000a94` | `0x80000a9f` | 0 | 1 |
| `0x80000aa0` | `0x80000aa3` | 0 | 1 |
| `0x80000aa4` | `0x80000aa7` | 0 | 1 |
| `0x80000aa8` | `0x80000ab7` | 0 | 1 |
| `0x80000ab8` | `0x80000abb` | 0 | 1 |
| `0x80000abc` | `0x80000abf` | 0 | 1 |
| `0x80000ac0` | `0x80000ac3` | 0 | 1 |
| `0x80000ac4` | `0x80000ac7` | 0 | 1 |
| `0x80000ac8` | `0x80000ad3` | 0 | 1 |
| `0x80000ad4` | `0x80000ad7` | 0 | 1 |
| `0x80000ad8` | `0x80000adf` | 0 | 0 |
| `0x80000ae0` | `0x80000ae3` | 0 | 0 |

## 6. Call Analysis

| 调用点 | 类型 | 目标 | 解析状态 |
|---|---|---|---|
| `0x80000084` | direct | 0x8000035c | resolved |
| `0x8000040c` | direct | 0x80000088 | resolved |
| `0x8000070c` | direct | 0x800007c8 | resolved |

## 7. Memory Access Analysis

普通 LOAD/STORE 保留为内存行为；没有硬件资源目录时不升级为 MMIO。

| PC | 指令 | 行为 | 地址 | 已知值 | 状态 |
|---|---|---|---|---|---|
| `0x80000008` | `ld ra,0x0(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000000c` | `ld sp,0x8(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000010` | `ld gp,0x10(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000014` | `ld tp,0x18(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000018` | `ld t0,0x20(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000001c` | `ld t1,0x28(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000020` | `ld t2,0x30(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000024` | `ld s0,0x38(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000028` | `ld s1,0x40(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000002c` | `ld a0,0x48(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000030` | `ld a1,0x50(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000034` | `ld a2,0x58(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000038` | `ld a3,0x60(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000003c` | `ld a4,0x68(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000040` | `ld a5,0x70(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000044` | `ld a6,0x78(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000048` | `ld a7,0x80(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000004c` | `ld s2,0x88(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000050` | `ld s3,0x90(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000054` | `ld s4,0x98(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000058` | `ld s5,0xa0(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000005c` | `ld s6,0xa8(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000060` | `ld s7,0xb0(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000064` | `ld s8,0xb8(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000068` | `ld s9,0xc0(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000006c` | `ld s10,0xc8(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000070` | `ld s11,0xd0(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000074` | `ld t3,0xd8(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000078` | `ld t4,0xe0(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000007c` | `ld t5,0xe8(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000080` | `ld t6,0xf0(t6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000124` | `sd sp,0x58(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000012c` | `sd sp,0x70(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000134` | `sd sp,0x78(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000013c` | `sd sp,0x80(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000144` | `sd sp,0x88(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000014c` | `sd sp,0x90(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000154` | `sd sp,0x98(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000015c` | `sd sp,0xa0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000168` | `sd sp,0xa8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000170` | `sd sp,0xb0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000178` | `sd sp,0xb8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000180` | `sd sp,0xc0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000188` | `sd sp,0xc8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000190` | `sd sp,0xd0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000198` | `sd sp,0xd8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001a0` | `sd sp,0xe0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001a8` | `sd sp,0xe8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001b0` | `sd sp,0xf0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001b8` | `sd sp,0xf8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001c0` | `sd sp,0x100(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001c8` | `sd sp,0x108(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001d4` | `sd sp,0x110(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001dc` | `sd sp,0x118(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001e4` | `sd sp,0x138(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001ec` | `sd sp,0x140(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001f4` | `sd sp,0x148(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800001fc` | `sd sp,0x150(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000204` | `sd sp,0x158(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000020c` | `sd sp,0x160(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000214` | `sd sp,0x168(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000021c` | `sd sp,0x170(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000022c` | `sd sp,0x40(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000234` | `sd sp,0x48(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000023c` | `sd sp,0x50(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000248` | `sd zero,0x0(ra)` | MEMORY_STORE | unknown | 0 | partial |
| `0x8000024c` | `sd sp,0x10(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000250` | `sd gp,0x18(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000254` | `sd tp,0x20(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000258` | `sd t0,0x28(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000025c` | `sd t1,0x30(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000260` | `sd t2,0x38(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000264` | `sd s0,0x40(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000268` | `sd s1,0x48(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000026c` | `sd a0,0x50(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000270` | `sd a1,0x58(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000274` | `sd a2,0x60(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000278` | `sd a3,0x68(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000027c` | `sd a4,0x70(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000280` | `sd a5,0x78(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000284` | `sd a6,0x80(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000288` | `sd a7,0x88(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000028c` | `sd s2,0x90(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000290` | `sd s3,0x98(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000294` | `sd s4,0xa0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000298` | `sd s5,0xa8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000029c` | `sd s6,0xb0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800002a0` | `sd s7,0xb8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800002a4` | `sd s8,0xc0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800002a8` | `sd s9,0xc8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800002ac` | `sd s11,0xd8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800002b0` | `sd t3,0xe0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800002b4` | `sd t4,0xe8(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x800002b8` | `sd t5,0xf0(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000354` | `sw gp,-0x350(t5)` | MEMORY_STORE | unknown | 1 | partial |
| `0x800004a0` | `lhu a4,-0x1e(ra)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004c4` | `lwu s5,0x0(s10)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004d4` | `amoadd.d tp,s1,(s9)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800004d4` | `amoadd.d tp,s1,(s9)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800004e8` | `amoxor.w a3,ra,(s11)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800004e8` | `amoxor.w a3,ra,(s11)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800004fc` | `sc.w tp,t4,(t3)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000558` | `lr.d s8,(t1)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000574` | `sh t3,-0x1e(a1)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000594` | `amomaxu.w sp,s11,(t3)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000594` | `amomaxu.w sp,s11,(t3)` | ATOMIC_STORE | unknown | 4292870144 | partial |
| `0x800005a8` | `lbu a2,0x0(s2)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800005dc` | `sh sp,-0x14(t1)` | MEMORY_STORE | unknown | not established | partial |
| `0x800005ec` | `amoswap.d s7,ra,(a5)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800005ec` | `amoswap.d s7,ra,(a5)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000600` | `amoand.d s0,ra,(t5)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000600` | `amoand.d s0,ra,(t5)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000640` | `amoxor.w t0,t0,(a3)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000640` | `amoxor.w t0,t0,(a3)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000674` | `lb s0,0x1d(a3)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000068c` | `amoxor.d a0,s8,(s2)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x8000068c` | `amoxor.d a0,s8,(s2)` | ATOMIC_STORE | unknown | not established | partial |
| `0x8000069c` | `amoor.d s4,sp,(s9)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x8000069c` | `amoor.d s4,sp,(s9)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800006a8` | `lbu s4,0x8(a6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800006c0` | `amomaxu.w t5,a3,(sp)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800006c0` | `amomaxu.w t5,a3,(sp)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800006d4` | `lr.w t1,(t3)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800006e4` | `lw gp,0x4(s5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800006f4` | `amomax.w a6,s5,(sp)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800006f4` | `amomax.w a6,s5,(sp)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000730` | `amoor.w gp,t0,(s6)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000730` | `amoor.w gp,t0,(s6)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000744` | `lw a5,0x8(a6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000770` | `amomax.d s10,s10,(s9)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000770` | `amomax.d s10,s10,(s9)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000790` | `lw s8,0x4(gp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800007c4` | `amomaxu.w a5,a3,(s1)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800007c4` | `amomaxu.w a5,a3,(s1)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800007e0` | `amoswap.d s4,a0,(a2)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800007e0` | `amoswap.d s4,a0,(a2)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000804` | `amomin.d sp,s2,(s11)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000804` | `amomin.d sp,s2,(s11)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000818` | `amoadd.w s10,t2,(a6)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000818` | `amoadd.w s10,t2,(a6)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000828` | `amoxor.d a5,s3,(ra)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000828` | `amoxor.d a5,s3,(ra)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000874` | `lbu ra,0x5(s10)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000890` | `lr.w a4,(s3)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800008a0` | `amoand.d sp,s11,(s4)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800008a0` | `amoand.d sp,s11,(s4)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800008ac` | `lhu sp,-0x12(a3)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800008c0` | `sh t5,0x6(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x800008d4` | `lr.w t4,(s5)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800008e4` | `amomin.w s3,t3,(a4)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800008e4` | `amomin.w s3,t3,(a4)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000900` | `amomaxu.w s0,sp,(s11)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000900` | `amomaxu.w s0,sp,(s11)` | ATOMIC_STORE | unknown | not established | partial |
| `0x8000091c` | `lb sp,0x0(s10)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000093c` | `lb s2,0x1f(t5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000948` | `ld t1,0x0(t0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000958` | `sb t1,0x15(a7)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000994` | `amomax.w s5,a6,(a2)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000994` | `amomax.w s5,a6,(a2)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800009b8` | `sc.w a6,s5,(tp)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800009dc` | `amoswap.d s0,s11,(s2)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800009dc` | `amoswap.d s0,s11,(s2)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800009f0` | `amominu.d s11,t1,(a7)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800009f0` | `amominu.d s11,t1,(a7)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000a00` | `amoxor.d t0,a0,(a5)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000a00` | `amoxor.d t0,a0,(a5)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000a10` | `amomax.d a5,a6,(t1)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000a10` | `amomax.d a5,a6,(t1)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000a20` | `amoor.w a3,s4,(a0)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000a20` | `amoor.w a3,s4,(a0)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000a48` | `lb ra,0x6(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000a9c` | `lhu t2,-0x4(s6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000ab4` | `amoor.d s3,a5,(s6)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000ab4` | `amoor.d s3,a5,(s6)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000ad0` | `lwu ra,0xc(t1)` | MEMORY_LOAD | unknown | not established | partial |

## 8. Hardware-facing Behaviors

当前分析没有硬件资源目录，MMIO 计数为 0。已解析内存地址仍需资源绑定，才能被解释为硬件寄存器访问。

## 9. System/Register/Barrier/Atomic Behaviors

| PC | 所属函数 | 指令 | 行为 | 寄存器 | 证据 ID |
|---|---|---|---|---|---|
| `0x80000120` | `unresolved` | `csrr sp,0x0100` | SYSTEM_REGISTER_READ | 0x0100 | `fwbehavior:1b1685aa726678c3d81e298da1e516ea8fc40c03119faf0ab99598a071a356a5` |
| `0x80000128` | `unresolved` | `csrr sp,0x0104` | SYSTEM_REGISTER_READ | 0x0104 | `fwbehavior:1ba14aaafb00184b98396b18e2cc2cab0fc8b20c1c0cf94426a242c150747d70` |
| `0x80000130` | `unresolved` | `csrr sp,0x0105` | SYSTEM_REGISTER_READ | 0x0105 | `fwbehavior:33ee5a69da1107f4cc7fe79448ba6810ef34a7639f47234d4fcc79d2dbb1c458` |
| `0x80000138` | `unresolved` | `csrr sp,0x0106` | SYSTEM_REGISTER_READ | 0x0106 | `fwbehavior:08fd8e88fe70f9805f62ca9584a610b7a2bdaaed513ecd1866ae74e0980e6253` |
| `0x80000140` | `unresolved` | `csrr sp,0x0140` | SYSTEM_REGISTER_READ | 0x0140 | `fwbehavior:7bb385ab406444df544fa64bb62cf20b2dbc710cd984a82a854ea2580d0c2c06` |
| `0x80000148` | `unresolved` | `csrr sp,sepc` | SYSTEM_REGISTER_READ | sepc | `fwbehavior:c1a70fdc7a7314a9c5c93c9e0e4320f5ccd8308d9e1f565353c4a59b9ae74934` |
| `0x80000150` | `unresolved` | `csrr sp,0x0142` | SYSTEM_REGISTER_READ | 0x0142 | `fwbehavior:3ed31227024d30c954173b89cfb82caae11a60f52ee3935e8dd5d02606221bf7` |
| `0x80000158` | `unresolved` | `csrr sp,0x0143` | SYSTEM_REGISTER_READ | 0x0143 | `fwbehavior:7314e3f0b7996c06ccc78759a5b189d2eebe1ab420963a576d763f36cda49303` |
| `0x80000160` | `unresolved` | `csrr sp,0x0144` | SYSTEM_REGISTER_READ | 0x0144 | `fwbehavior:9ba58c0243c4a95a1eaa8a0371e7b83d88dddcbed34d535a6bb2fd8465307dc3` |
| `0x8000016c` | `unresolved` | `csrr sp,0x0180` | SYSTEM_REGISTER_READ | 0x0180 | `fwbehavior:4a914ad86158f7ce173d1f3d44852c3b03e5681a3f9c7c58e9e05cf845d6cfbd` |
| `0x80000174` | `unresolved` | `csrr sp,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | `fwbehavior:a5802553e2424e057a139de4bdfd452020c686c56f13265c7db8b2654c697793` |
| `0x8000017c` | `unresolved` | `csrr sp,0x0300` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:42b4db22592f567c1f8291cbeb992d73fc8050d74f9b89ffd7b43525de504af8` |
| `0x80000184` | `unresolved` | `csrr sp,0x0302` | SYSTEM_REGISTER_READ | 0x0302 | `fwbehavior:a8a30209c3784b7cc93c335b9a20023f3dbcb336ec7ed21033f199f6f8dda7d6` |
| `0x8000018c` | `unresolved` | `csrr sp,0x0303` | SYSTEM_REGISTER_READ | 0x0303 | `fwbehavior:2555fab1664e93d5fe4a22aecef333bfdf7bc2d8f0f8aa35cd1f4c16e055abda` |
| `0x80000194` | `unresolved` | `csrr sp,0x0304` | SYSTEM_REGISTER_READ | 0x0304 | `fwbehavior:01d06933fbd254b356cbc97000b873cf87a064c2f7d68bea3b39e58675b99a62` |
| `0x8000019c` | `unresolved` | `csrr sp,0x0305` | SYSTEM_REGISTER_READ | 0x0305 | `fwbehavior:88cf522f7fa011b67f8179b40544b8fd63094d99cd2153e4dccebbcf0ceafbb4` |
| `0x800001a4` | `unresolved` | `csrr sp,0x0306` | SYSTEM_REGISTER_READ | 0x0306 | `fwbehavior:29e4aed66f97d264e9ca41ffe05edf24f2bfadc11454396e0b46b1603557f0fa` |
| `0x800001ac` | `unresolved` | `csrr sp,0x0340` | SYSTEM_REGISTER_READ | 0x0340 | `fwbehavior:41efb14a136c2f4e74c66620e9f3c7a7e91f3aff644fedacf8b7bd99376869f5` |
| `0x800001b4` | `unresolved` | `csrr sp,mepc` | SYSTEM_REGISTER_READ | mepc | `fwbehavior:c74b5600e97d4eec9d9ff2d0045f41d301e6e83b5e46ee14ac672d02cdc9bd3b` |
| `0x800001bc` | `unresolved` | `csrr sp,0x0342` | SYSTEM_REGISTER_READ | 0x0342 | `fwbehavior:27fcae1d789088d82ea6ebafbdd72a87a597d502c65c3033e8c1d09af94fd753` |
| `0x800001c4` | `unresolved` | `csrr sp,0x0343` | SYSTEM_REGISTER_READ | 0x0343 | `fwbehavior:f18cce82adeb44d2558982959c9821bb11e7e1d50e4be0dda1b9765902d84c8f` |
| `0x800001cc` | `unresolved` | `csrr sp,0x0344` | SYSTEM_REGISTER_READ | 0x0344 | `fwbehavior:d4d802fbc85607d60da876ab43283e571c30bf0ed61aa37b6d34036add246024` |
| `0x800001d8` | `unresolved` | `csrr sp,0x03a0` | SYSTEM_REGISTER_READ | 0x03a0 | `fwbehavior:4254da74a881259dfe6d9288393558420afc608cf828b73b4cb58c78a24b5ff4` |
| `0x800001e0` | `unresolved` | `csrr sp,0x03b0` | SYSTEM_REGISTER_READ | 0x03b0 | `fwbehavior:aeb402734ffd7620df50c891df14108b424acd574b05c39ff5c9093177a6fa91` |
| `0x800001e8` | `unresolved` | `csrr sp,0x03b1` | SYSTEM_REGISTER_READ | 0x03b1 | `fwbehavior:39fedb79d02b577e5acbaa6854b34b42ba15968a119c2f78a664f4053ec2bff9` |
| `0x800001f0` | `unresolved` | `csrr sp,0x03b2` | SYSTEM_REGISTER_READ | 0x03b2 | `fwbehavior:9f4df99ae364fae5f34f2e3f0b47ff80881091aab5c84e817ca890dc5e220ef9` |
| `0x800001f8` | `unresolved` | `csrr sp,0x03b3` | SYSTEM_REGISTER_READ | 0x03b3 | `fwbehavior:40e8c09983ac051b4c64029837a3e0d9202ad063d0285f5c7a47a85a86d5da63` |
| `0x80000200` | `unresolved` | `csrr sp,0x03b4` | SYSTEM_REGISTER_READ | 0x03b4 | `fwbehavior:5ff417ad4e83059628c4663f55a7e2ae76aa4217ff8651562ef8701587bd29ef` |
| `0x80000208` | `unresolved` | `csrr sp,0x03b5` | SYSTEM_REGISTER_READ | 0x03b5 | `fwbehavior:4b5a4dfb1aebc18937c5d7bb29b3cb97453993b61bd92b0d126033f98af9749a` |
| `0x80000210` | `unresolved` | `csrr sp,0x03b6` | SYSTEM_REGISTER_READ | 0x03b6 | `fwbehavior:a977e277600f99a6acc4b1d8f7963049e5e718f18d64532dd65a73195fa5e3c9` |
| `0x80000218` | `unresolved` | `csrr sp,0x03b7` | SYSTEM_REGISTER_READ | 0x03b7 | `fwbehavior:98965d6de52486239275c09a43900ef2418a266bbb86fb388bc36f250077b839` |
| `0x80000224` | `unresolved` | `csrs 0x0300,a0` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:b34cae9b19d495c2a061081ee0f2b47b7a476f66c08414157f159ca569689ef4` |
| `0x80000224` | `unresolved` | `csrs 0x0300,a0` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:01577527498378443c0a713f9be84996cb8a6adfb118a3ae9e787fb84014a769` |
| `0x8000035c` | `reset_vector` | `csrwi 0x0300,0x0` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:cbfcf6fb4e0042ea1519bebb4b0483b4216255688269e5631320e2f76c082a7f` |
| `0x80000360` | `reset_vector` | `csrr a0,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | `fwbehavior:8555f662fb780999e5dcf6904ba528da908a51db3a021d717d2baceaf7d9f1a9` |
| `0x80000370` | `reset_vector` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:ff6a07d071cb64b13081342d49c392847c3bba68a9ebfe2d4843b79a3fcc4b24` |
| `0x80000374` | `reset_vector` | `csrwi 0x0302,0x0` | SYSTEM_REGISTER_WRITE | 0x0302 | `fwbehavior:5619dfc8e59ee5519d3ac095e49536aff4a75668d9d362a9ba7b8dbe9e5ea4c2` |
| `0x80000378` | `reset_vector` | `csrwi 0x0303,0x0` | SYSTEM_REGISTER_WRITE | 0x0303 | `fwbehavior:05b4c6b154d7a8c8a13e6a57da565d34c0f272d251146aeabce812187a6a71cd` |
| `0x8000037c` | `reset_vector` | `csrwi 0x0304,0x0` | SYSTEM_REGISTER_WRITE | 0x0304 | `fwbehavior:55eb075cf1ccc0d1135ba40c1b0292fde0532908f27620e69d623bdec760bc64` |
| `0x80000388` | `reset_vector` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:bfeb10022e20d84853c4cd2d6b18b65ce5258011b22e988bd08fa3589fd3629a` |
| `0x8000038c` | `reset_vector` | `csrwi 0x0180,0x0` | SYSTEM_REGISTER_WRITE | 0x0180 | `fwbehavior:3dc3299a31a8ef887a9bf1f123740c3729757e457095d8da5919e30e33fd60fe` |
| `0x80000398` | `reset_vector` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:b6724dd552e8a1a5e0bf3135f7d3057f2c15ddd63d1d17e05083b45e970978a0` |
| `0x800003a8` | `reset_vector` | `csrw 0x03b0,t0` | SYSTEM_REGISTER_WRITE | 0x03b0 | `fwbehavior:049231abd2222289397b007b28d9195b190cdb14ac231c0941a425c03be46837` |
| `0x800003b0` | `reset_vector` | `csrw 0x03a0,t0` | SYSTEM_REGISTER_WRITE | 0x03a0 | `fwbehavior:25527170b3e4d55cf48ae271870b9f86f5ffd322ea342ee3338c4ad9679769c8` |
| `0x800003bc` | `reset_vector` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:317d73c6add1cb2a4b69e5ecb52c2a0efdc108c318347dec5f504fbc0fe07b0c` |
| `0x800003d0` | `reset_vector` | `fence 0xf,0xf` | MEMORY_BARRIER | — | `fwbehavior:0f1f70893d57bb47d7c7525705bdc4f21c5bf654d47b16d399a9e22bfbe714bd` |
| `0x800003ec` | `reset_vector` | `csrw 0x0105,t0` | SYSTEM_REGISTER_WRITE | 0x0105 | `fwbehavior:08b5cdc25a5e878dace314a69ff590b2cb85558d501bc4de614d59b111d786f0` |
| `0x800003f8` | `reset_vector` | `csrs 0x0302,t0` | SYSTEM_REGISTER_READ | 0x0302 | `fwbehavior:98eb6c78affdd513bdc962f67e0dbb14a900e471408e267f53524aa6aa562672` |
| `0x800003f8` | `reset_vector` | `csrs 0x0302,t0` | SYSTEM_REGISTER_WRITE | 0x0302 | `fwbehavior:56bee95f43c7e5a596401092e6558d17e9f05961e16ddfb1b9066f2a4bf7cef2` |
| `0x80000404` | `reset_vector` | `csrs 0x0300,a0` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:7385b40267c3ca9f56f9be8bedfbf8c05d1679da91f167394b0fe167a78b2bc2` |
| `0x80000404` | `reset_vector` | `csrs 0x0300,a0` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:d98132b18e751134c6bd9c1b4b4349dadd03fcec6ea70f09e993e3316d736dc2` |
| `0x80000408` | `reset_vector` | `csrwi fcsr,0x0` | SYSTEM_REGISTER_WRITE | fcsr | `fwbehavior:772d5b9151056ffac987c14c911727c94f10c868d4b9d73e6ed5ad8ef62a5577` |
| `0x80000410` | `reset_vector` | `csrw 0x0b02,zero` | SYSTEM_REGISTER_WRITE | 0x0b02 | `fwbehavior:1007805e9d25773d5d61b8b716dfafc7f7c24641d8fefa6ebb0d6ff816bf7790` |
| `0x80000414` | `reset_vector` | `csrr a0,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | `fwbehavior:432451a1ff3a77423923570d2c0730d8fe4c5f36ddcbeba421ce9c92694bfc6f` |
| `0x80000418` | `reset_vector` | `csrrci a3,0x03b1,0x16` | SYSTEM_REGISTER_READ | 0x03b1 | `fwbehavior:b06c235016293de677e7119950d14e2409de73b55622207f6f64f3558e91e4ff` |
| `0x80000418` | `reset_vector` | `csrrci a3,0x03b1,0x16` | SYSTEM_REGISTER_WRITE | 0x03b1 | `fwbehavior:45c2454cd26454ddc4ee3bb789120862723c24785aab88f98653833ad1f4637e` |
| `0x8000042c` | `reset_vector` | `csrrw a3,0x0142,a3` | SYSTEM_REGISTER_READ | 0x0142 | `fwbehavior:f1df8cd63b45f90d5fd8efe2b743a6c40ff9a0f1db8d4a6a557cf6635d386fe2` |
| `0x8000042c` | `reset_vector` | `csrrw a3,0x0142,a3` | SYSTEM_REGISTER_WRITE | 0x0142 | `fwbehavior:dc8f863c167fb26c66e1f30891ddc86d334cf6d6127783c5d1299aacdd6f1252` |
| `0x80000458` | `reset_vector` | `csrrw a4,0x0300,a0` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:e97237ced0cf27e7dca149e1d1a5d19aaef5f5390d9d3f71db26186a3888a04c` |
| `0x80000458` | `reset_vector` | `csrrw a4,0x0300,a0` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:e2ad91374b04f661af0565cfd0565d4d5586a1a77ab72d971ac6ab5464215028` |
| `0x80000464` | `reset_vector` | `csrw mepc,t0` | SYSTEM_REGISTER_WRITE | mepc | `fwbehavior:7f5f775a2bea46824b6569e66984e76d3ca0d208e0cf7cc12208116456ccede4` |
| `0x8000046c` | `reset_vector` | `mret` | EXCEPTION_RETURN | — | `fwbehavior:b8b0f9a223911c777a1c4b9929a8f32c71f71918cc38ba621dc672bf8afefd0e` |
| `0x800004b8` | `unresolved` | `csrrw a2,sepc,s0` | SYSTEM_REGISTER_READ | sepc | `fwbehavior:c322dc1321c6091fb7975a041a3a0c96c388c4abd988ceac29454c5ddf63e484` |
| `0x800004b8` | `unresolved` | `csrrw a2,sepc,s0` | SYSTEM_REGISTER_WRITE | sepc | `fwbehavior:c40ae3be8e6ae3a3d477f1cb788f0839a11207156aad09edfb412b4bee2d6c3e` |
| `0x800004d4` | `unresolved` | `amoadd.d tp,s1,(s9)` | ATOMIC_LOAD | — | `fwbehavior:0671a09720cf6dac8ce7f69c598199948da04d99ca1cd402366d3ee475706528` |
| `0x800004d4` | `unresolved` | `amoadd.d tp,s1,(s9)` | ATOMIC_STORE | — | `fwbehavior:82b352aefc726c041a2565cebc7bb66d506cc852b4c0448219f1cbd5ef369117` |
| `0x800004d8` | `unresolved` | `fence 0xf,0xf` | MEMORY_BARRIER | — | `fwbehavior:4bb628928016cc4d2e7329c598c86f0521b1dbb87c885fd9d308e114ae14d6d2` |
| `0x800004e8` | `unresolved` | `amoxor.w a3,ra,(s11)` | ATOMIC_LOAD | — | `fwbehavior:c6375d0634252830db2ea68cf45588ddb5bbb8e807e4b8cc4d3022c2c054cbe3` |
| `0x800004e8` | `unresolved` | `amoxor.w a3,ra,(s11)` | ATOMIC_STORE | — | `fwbehavior:f07da849fc2881d24930b36d73f6d3a8d9ae4e3b48333258bf92ed55b8bff176` |
| `0x800004fc` | `unresolved` | `sc.w tp,t4,(t3)` | ATOMIC_STORE | — | `fwbehavior:c01915e58fd35448debc391b587226d0e70d824b2a6001bfa87f25b750bd0b08` |
| `0x80000508` | `unresolved` | `csrw sepc,a0` | SYSTEM_REGISTER_WRITE | sepc | `fwbehavior:0daa1944f3e6a873836e6f673f901a5c5f68949b9c13298fa44d9eec99324cba` |
| `0x8000050c` | `unresolved` | `sret` | EXCEPTION_RETURN | — | `fwbehavior:3a16b314409189773e825b0282f54dce4d4a1843cd92746f12e8b740a7bc4921` |
| `0x8000053c` | `unresolved` | `csrrc s9,0x0100,a4` | SYSTEM_REGISTER_READ | 0x0100 | `fwbehavior:c8c462e3bfa0966a32ceffee7ed915555a9d071a0fcf270eedba5d844703827b` |
| `0x8000053c` | `unresolved` | `csrrc s9,0x0100,a4` | SYSTEM_REGISTER_WRITE | 0x0100 | `fwbehavior:f9d2b778cb32be3061ff9034cd2e7d44fe49d43c4107062b232cb111b6ff85aa` |
| `0x80000558` | `unresolved` | `lr.d s8,(t1)` | ATOMIC_LOAD | — | `fwbehavior:7f7a1bf98d506fe9a9ffeed24076d85740aa2df46b8be8df902ff1af4b1ead78` |
| `0x80000594` | `unresolved` | `amomaxu.w sp,s11,(t3)` | ATOMIC_LOAD | — | `fwbehavior:7b2c3645e850042db54e2c6271c351dffaaa985219c028415c1e7aeabfc76224` |
| `0x80000594` | `unresolved` | `amomaxu.w sp,s11,(t3)` | ATOMIC_STORE | — | `fwbehavior:b711c6d340d60c1e851dcfbdf51aaed6635853b942929e37138c5c5d4e61b4f8` |
| `0x800005b4` | `unresolved` | `csrw mepc,ra` | SYSTEM_REGISTER_WRITE | mepc | `fwbehavior:30e220150066f784adc019ebb44f28cbe0589a0c795af6022bad39162475eede` |
| `0x800005b8` | `unresolved` | `mret` | EXCEPTION_RETURN | — | `fwbehavior:1453ba41868e050a275b40fb602c9fe2dd75d51f25f95988b0f62c004fd3eba3` |
| `0x800005cc` | `unresolved` | `csrw mepc,t0` | SYSTEM_REGISTER_WRITE | mepc | `fwbehavior:336d95b71524322c71340f7a5e12f78279949097c537af6e0639bb71e39c3070` |
| `0x800005d0` | `unresolved` | `mret` | EXCEPTION_RETURN | — | `fwbehavior:3153e0f3160d2bcaade8c46f7f77981d169d552626feb28898a205efb6b88180` |
| `0x800005ec` | `unresolved` | `amoswap.d s7,ra,(a5)` | ATOMIC_LOAD | — | `fwbehavior:b77aad05172c1ff71f1019e35b7912a04f56128a1d43c1f03eefbe6de069e6c6` |
| `0x800005ec` | `unresolved` | `amoswap.d s7,ra,(a5)` | ATOMIC_STORE | — | `fwbehavior:34b86b0a9ba9d8ea87609aa1c47b917ba074609fecea573c2543d593185e57e1` |
| `0x80000600` | `unresolved` | `amoand.d s0,ra,(t5)` | ATOMIC_LOAD | — | `fwbehavior:799484e5c76b3530dc65451d3435ea3987d45cc21beb735b63aef54939c2de22` |
| `0x80000600` | `unresolved` | `amoand.d s0,ra,(t5)` | ATOMIC_STORE | — | `fwbehavior:507a10da50095fa1d83fffdc6446222c05f9fbc5a18584dcd8718b2d8cbf0ec5` |
| `0x8000060c` | `unresolved` | `csrrw sp,0x0144,s7` | SYSTEM_REGISTER_READ | 0x0144 | `fwbehavior:dbb2bfa89eb4b8d60dc7a54a64a7d9762476f23ee645e7d86f6619dda40b0961` |
| `0x8000060c` | `unresolved` | `csrrw sp,0x0144,s7` | SYSTEM_REGISTER_WRITE | 0x0144 | `fwbehavior:695d6e06aed88eece5478d33bf4340223c06c37f2f76d48bbef5a2d0bf385249` |
| `0x80000618` | `unresolved` | `csrw mepc,a6` | SYSTEM_REGISTER_WRITE | mepc | `fwbehavior:c6be1829fe6fd4017afb6b3d95cfb172e77b9830191a1bafd3e35b88fde1c784` |
| `0x8000061c` | `unresolved` | `mret` | EXCEPTION_RETURN | — | `fwbehavior:21f4f1dd9df39edfc0ea1596cdc731d3f07df2e6622ce9ed66dcc118337fc3da` |
| `0x8000062c` | `unresolved` | `csrw uepc,t0` | SYSTEM_REGISTER_WRITE | uepc | `fwbehavior:54b34ba99fb39aa3bfac9ff9b2404aaa38dd59f369f8c90bbc4dc54dfa738725` |
| `0x80000630` | `unresolved` | `uret` | EXCEPTION_RETURN | — | `fwbehavior:ed6d4c4010227acf4a7c759980707ea97841e04526be308dae80f088de4a716a` |
| `0x80000640` | `unresolved` | `amoxor.w t0,t0,(a3)` | ATOMIC_LOAD | — | `fwbehavior:933c7c7ee10bd2d977229462f81bdd69335854a99689f81a099d393458e5a4fc` |
| `0x80000640` | `unresolved` | `amoxor.w t0,t0,(a3)` | ATOMIC_STORE | — | `fwbehavior:0be4146fbe40896d7382da32647aa3531e48e42a0cfa1f067a81b7b416197c32` |
| `0x8000065c` | `unresolved` | `sfence.vma t3,a6` | TLB_INVALIDATE | — | `fwbehavior:8169d52da640df6c6dbb6dd3971cba6cd52b3d9c16a6cf0fd76d9c195aa14a3e` |
| `0x8000068c` | `unresolved` | `amoxor.d a0,s8,(s2)` | ATOMIC_LOAD | — | `fwbehavior:3fc9b84169aad3836aaacbee0365a196addfe70bed038959434d1c97b53bb1a6` |
| `0x8000068c` | `unresolved` | `amoxor.d a0,s8,(s2)` | ATOMIC_STORE | — | `fwbehavior:0bae1d6ddfd1ebb23be5633ad5b777c9bf259dd01f8ca3eb9498a371c264cca7` |
| `0x8000069c` | `unresolved` | `amoor.d s4,sp,(s9)` | ATOMIC_LOAD | — | `fwbehavior:37c8f4b1e67965b61895e11db1cdf6383a37d639caef95a69aa1fcefd2624d47` |
| `0x8000069c` | `unresolved` | `amoor.d s4,sp,(s9)` | ATOMIC_STORE | — | `fwbehavior:29486d63e8b478cce3a57f6b642b37b70bfd476d3c17d4fe1c8e9ae383730f74` |
| `0x800006ac` | `unresolved` | `csrrwi s9,0x0342,0xb` | SYSTEM_REGISTER_READ | 0x0342 | `fwbehavior:eb7e2cd0e000eb3b89dd32833831671325088a407aa76c53263e4dcbc6d18f22` |
| `0x800006ac` | `unresolved` | `csrrwi s9,0x0342,0xb` | SYSTEM_REGISTER_WRITE | 0x0342 | `fwbehavior:ceb117a8ffdb258e8f1fd247dec0d3769aef98cf46a6fc8f5500e601be2c9afe` |
| `0x800006c0` | `unresolved` | `amomaxu.w t5,a3,(sp)` | ATOMIC_LOAD | — | `fwbehavior:f336256114dba018a5bdb25d3165c7c0c9782ba22b864d62b638824e65a91744` |
| `0x800006c0` | `unresolved` | `amomaxu.w t5,a3,(sp)` | ATOMIC_STORE | — | `fwbehavior:e8d5bd33ffc41a5868fc06f12c5f1c92bafbc36af5de81e3cebf7a8fe299b664` |
| `0x800006d4` | `unresolved` | `lr.w t1,(t3)` | ATOMIC_LOAD | — | `fwbehavior:86e91c761636b46c1cb78caf98fb8e40aa68d2046c9852a5ccfe014f0aef56ca` |
| `0x800006f4` | `unresolved` | `amomax.w a6,s5,(sp)` | ATOMIC_LOAD | — | `fwbehavior:826d02af9c9c36c3d937512e50e53ccfa26541e0f3311702c00909e036a6f363` |
| `0x800006f4` | `unresolved` | `amomax.w a6,s5,(sp)` | ATOMIC_STORE | — | `fwbehavior:a7fbcd49b42187b27498b766869e311791d8fc0ffa81456345d84efe2f917bee` |
| `0x80000730` | `unresolved` | `amoor.w gp,t0,(s6)` | ATOMIC_LOAD | — | `fwbehavior:25d9ed72e34b3ac76cbf59d5cd8d469a389f2efdf0ac4192a312e1ef2d76785b` |
| `0x80000730` | `unresolved` | `amoor.w gp,t0,(s6)` | ATOMIC_STORE | — | `fwbehavior:eb033357917304f9b4a7ed7b3ea42e6ad091bdf939945730af27a7dc8abae161` |
| `0x80000758` | `unresolved` | `sfence.vma s2,t0` | TLB_INVALIDATE | — | `fwbehavior:48858bcb08f0c926781ce6ba1663c8b02eaae4f4a2e7684de05e6543c4fc5aaa` |
| `0x80000770` | `unresolved` | `amomax.d s10,s10,(s9)` | ATOMIC_LOAD | — | `fwbehavior:30915c195638d96891e7eb45c0279f2fb0451ec9e8442412df60962854b9bf90` |
| `0x80000770` | `unresolved` | `amomax.d s10,s10,(s9)` | ATOMIC_STORE | — | `fwbehavior:a5dfda16103be5cfe51e7c58e47607f2bb97e8212481d9e0e5d0dd29772e7c37` |
| `0x80000784` | `unresolved` | `csrrsi a4,0x0300,0x13` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:f939bc449553a3bb39e08e1a96731afeba0beb05a2ded6f96b08f374eb16c51e` |
| `0x80000784` | `unresolved` | `csrrsi a4,0x0300,0x13` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:7fccd73a045cc89465aecfc8a6c69c0118e00f99029c91322434d9ae6bdfe156` |
| `0x800007c4` | `unresolved` | `amomaxu.w a5,a3,(s1)` | ATOMIC_LOAD | — | `fwbehavior:1585498700894a7700db14ba2a80d4572037a8193b2c382c1d1c87b0160c8f2e` |
| `0x800007c4` | `unresolved` | `amomaxu.w a5,a3,(s1)` | ATOMIC_STORE | — | `fwbehavior:8e98f801acfd3b7629eb3ef228c78a8bec334944edca7af0e6be9c222d2cd66b` |
| `0x800007e0` | `_l96` | `amoswap.d s4,a0,(a2)` | ATOMIC_LOAD | — | `fwbehavior:51b3e098dc8636308949373a28d3a10487338bd766a971d331cdf73336e468dc` |
| `0x800007e0` | `_l96` | `amoswap.d s4,a0,(a2)` | ATOMIC_STORE | — | `fwbehavior:fd2da7e471838f67c8c777c7820b4ac92d02f5c58b6ea0b6acdb243196048318` |
| `0x800007e4` | `_l96` | `csrrsi t5,0x03a0,0xb` | SYSTEM_REGISTER_READ | 0x03a0 | `fwbehavior:6e8f2e39c9d05d67306ab7b1e22612e30aa2501d70cc869eb0cbdf1ded691f0f` |
| `0x800007e4` | `_l96` | `csrrsi t5,0x03a0,0xb` | SYSTEM_REGISTER_WRITE | 0x03a0 | `fwbehavior:1795ef84e16854de30d01b7a5cefd79c27a361c333f302a2f75253c1169319c1` |
| `0x80000804` | `_l96` | `amomin.d sp,s2,(s11)` | ATOMIC_LOAD | — | `fwbehavior:c147651bdc6c36a814e8d00213a43f10ba2f4fd282d65aaffdeb408bc4118138` |
| `0x80000804` | `_l96` | `amomin.d sp,s2,(s11)` | ATOMIC_STORE | — | `fwbehavior:8a793751c16864de270ca078e8ec7d06604511404c62362c93fdd78ee1b902b8` |
| `0x80000818` | `_l96` | `amoadd.w s10,t2,(a6)` | ATOMIC_LOAD | — | `fwbehavior:457c9575ba8ba62f1d1764c0bcccac42dde5ed08e34a9c410619c7af217873e0` |
| `0x80000818` | `_l96` | `amoadd.w s10,t2,(a6)` | ATOMIC_STORE | — | `fwbehavior:41059f4d894ca3a7074e348d055ded20032b34ed79cc8b3d3028a2ecf8722ecc` |
| `0x80000828` | `_l96` | `amoxor.d a5,s3,(ra)` | ATOMIC_LOAD | — | `fwbehavior:1af5a2d197b1445713d08247609ae7606fa8d81cd9a861d2e92e3d98b5a04936` |
| `0x80000828` | `_l96` | `amoxor.d a5,s3,(ra)` | ATOMIC_STORE | — | `fwbehavior:99baaf914cfb3d24d3e01e6d6656ac618009812ac7d421fba5d8ef072633cab6` |
| `0x8000082c` | `_l96` | `csrrci s10,0x0343,0x4` | SYSTEM_REGISTER_READ | 0x0343 | `fwbehavior:f723aab44878af7f9fe52edb02c7ab4ee6f4cfcc9103b2464cc73b7f0ca58dc3` |
| `0x8000082c` | `_l96` | `csrrci s10,0x0343,0x4` | SYSTEM_REGISTER_WRITE | 0x0343 | `fwbehavior:2345bfe3963ff5a2ce8b836d86a3431cb80f4bab66ce976060adf62af90e4457` |
| `0x8000083c` | `_l96` | `csrw sepc,a1` | SYSTEM_REGISTER_WRITE | sepc | `fwbehavior:cb01b2958d286dcbcef21b3c4f7b18a188fa281d66def03ffa0917686f5817c5` |
| `0x80000840` | `_l96` | `sret` | EXCEPTION_RETURN | — | `fwbehavior:29b62c373620e7e8484a98317bef7dd82a61c6da41996472a5ebf86e789b1910` |
| `0x80000854` | `unresolved` | `csrrw a7,0x03b6,s9` | SYSTEM_REGISTER_READ | 0x03b6 | `fwbehavior:694f02820f5d8611f49a5587d63da2a90a14635e1b6a86eec4e64dfcd90fd28a` |
| `0x80000854` | `unresolved` | `csrrw a7,0x03b6,s9` | SYSTEM_REGISTER_WRITE | 0x03b6 | `fwbehavior:306dc5ff6f4acce3114a1d2659034ae9efa0a63634e46020aea1c657ecd6c727` |
| `0x80000890` | `unresolved` | `lr.w a4,(s3)` | ATOMIC_LOAD | — | `fwbehavior:f420d66356dd59d8f10b9e3e6ab23645a269b4b69d5a1053b40de58a26ff32a4` |
| `0x800008a0` | `unresolved` | `amoand.d sp,s11,(s4)` | ATOMIC_LOAD | — | `fwbehavior:9166f75bd03b4eaa45e812d810889cbf3870f325c1d4bc47a3a3c0bcfaa9ac5c` |
| `0x800008a0` | `unresolved` | `amoand.d sp,s11,(s4)` | ATOMIC_STORE | — | `fwbehavior:b93858a0693fe9b464b129747a23528ff90d5887ba6c8a2e34228ee73b0ffde7` |
| `0x800008d4` | `unresolved` | `lr.w t4,(s5)` | ATOMIC_LOAD | — | `fwbehavior:2ee815b8e14b7098e633dfa24538b58c2c47b36d509ac76be9593c537abac462` |
| `0x800008e4` | `unresolved` | `amomin.w s3,t3,(a4)` | ATOMIC_LOAD | — | `fwbehavior:0722ddf5f07ccb2932b6213d3ea9d718057c1c4c923102b436b7d30159875ebd` |
| `0x800008e4` | `unresolved` | `amomin.w s3,t3,(a4)` | ATOMIC_STORE | — | `fwbehavior:0008a4a7d626c5f1530f33c09d8c71e95e25112e555618e5b221309371360bea` |
| `0x80000900` | `unresolved` | `amomaxu.w s0,sp,(s11)` | ATOMIC_LOAD | — | `fwbehavior:729f62288cf319e34bc801314277137d60cdbd0802629a8b5c9b5abbd33d8906` |
| `0x80000900` | `unresolved` | `amomaxu.w s0,sp,(s11)` | ATOMIC_STORE | — | `fwbehavior:1dcaae078bad8360224b249c8c220cf6630787eb674638ab1a31a6d5b974bd6a` |
| `0x80000994` | `unresolved` | `amomax.w s5,a6,(a2)` | ATOMIC_LOAD | — | `fwbehavior:84c1172ba5249ae1feb90b73db245afdb1c2bd251e1353799c3b116b2c0a64ab` |
| `0x80000994` | `unresolved` | `amomax.w s5,a6,(a2)` | ATOMIC_STORE | — | `fwbehavior:9bf29c193ff1c525514f3aa22b88e28c42e585a90cbfcb61b48b7ae12662b117` |
| `0x800009b8` | `unresolved` | `sc.w a6,s5,(tp)` | ATOMIC_STORE | — | `fwbehavior:b8e63ab8ce68d0316b52b01e32710d07c7f04f620dae4205b9a009bfda8e1783` |
| `0x800009cc` | `unresolved` | `csrrc s6,0x03b2,s6` | SYSTEM_REGISTER_READ | 0x03b2 | `fwbehavior:05f4f347b30c63a38d01c5415a395dd93032db31ef4a54b812fa5e72023473d1` |
| `0x800009cc` | `unresolved` | `csrrc s6,0x03b2,s6` | SYSTEM_REGISTER_WRITE | 0x03b2 | `fwbehavior:5b7f76ae9bc9e6736f9fb1d525cf76dbd3f20973f18865ea7184444636230377` |
| `0x800009dc` | `unresolved` | `amoswap.d s0,s11,(s2)` | ATOMIC_LOAD | — | `fwbehavior:846b1bf5634854b5e74db65a68d26fc2b65239fc84c048e95d0d70cacbd6648c` |
| `0x800009dc` | `unresolved` | `amoswap.d s0,s11,(s2)` | ATOMIC_STORE | — | `fwbehavior:7ef0841badcc2228227e767e6fcffbcc0786ab54053a8a398653cacb5f50daa4` |
| `0x800009f0` | `unresolved` | `amominu.d s11,t1,(a7)` | ATOMIC_LOAD | — | `fwbehavior:0a00624b87bd69ef79fff963b33473d2850cd1eabcbfd8abeef18d4d61ba8afe` |
| `0x800009f0` | `unresolved` | `amominu.d s11,t1,(a7)` | ATOMIC_STORE | — | `fwbehavior:297468e4c6f8ef40d7ad77d410df6bc960d8a4b98583439d5ef5e197f5746b27` |
| `0x80000a00` | `unresolved` | `amoxor.d t0,a0,(a5)` | ATOMIC_LOAD | — | `fwbehavior:e6ee8b8bb1c2630793a4fd9469853733552e44e96169572efd4800743683e85c` |
| `0x80000a00` | `unresolved` | `amoxor.d t0,a0,(a5)` | ATOMIC_STORE | — | `fwbehavior:9f65d5f7b87f6bdcba299bf59f3994c5ea06b3e5018892d4dea88baf08c8baef` |
| `0x80000a10` | `unresolved` | `amomax.d a5,a6,(t1)` | ATOMIC_LOAD | — | `fwbehavior:1c0697455b2be58d92d76fdc802259fe71b09491d09439c06e4285dea2837de1` |
| `0x80000a10` | `unresolved` | `amomax.d a5,a6,(t1)` | ATOMIC_STORE | — | `fwbehavior:711f05f1fd8f63bbbcb321e361e868758c12dc7814b121146df1354e6928e80e` |
| `0x80000a20` | `unresolved` | `amoor.w a3,s4,(a0)` | ATOMIC_LOAD | — | `fwbehavior:6947d5ead96388949196925a4a19222646c5c24af0de7c0ddbfb3af524aa9934` |
| `0x80000a20` | `unresolved` | `amoor.w a3,s4,(a0)` | ATOMIC_STORE | — | `fwbehavior:bdfa911818518e954d19af5e63c2fc4bbf41899604106736cf04f4b2982b87a7` |
| `0x80000a30` | `unresolved` | `csrrc a6,0x03b7,s3` | SYSTEM_REGISTER_READ | 0x03b7 | `fwbehavior:3962f58a183d91c847a81a05931748340ecb79b5370abecf98fe21be6c17acd0` |
| `0x80000a30` | `unresolved` | `csrrc a6,0x03b7,s3` | SYSTEM_REGISTER_WRITE | 0x03b7 | `fwbehavior:5f4943d180427e70c7215006cb7f540439d6a13471e48f36bd20306082f2ee6b` |
| `0x80000a34` | `unresolved` | `csrrsi tp,0x0344,0x13` | SYSTEM_REGISTER_READ | 0x0344 | `fwbehavior:773c7a800791e670ef2b6254dfd30a38e1904682b9ad68dd32d287f9a3039c8d` |
| `0x80000a34` | `unresolved` | `csrrsi tp,0x0344,0x13` | SYSTEM_REGISTER_WRITE | 0x0344 | `fwbehavior:6c151eb079f635fe249fb0cdd963b063dc974ebf44bad0909eb9b44b685e8fd5` |
| `0x80000a54` | `unresolved` | `csrrw a3,0x0300,t4` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:091f59903b1806d88cfaa5cc6ef05f5f0a27a51d69465b358b216e0d43cfe1cb` |
| `0x80000a54` | `unresolved` | `csrrw a3,0x0300,t4` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:049cf672e5e0193d5f0d333b850e57d7c5acbf7bc2d2958d3e5e159efeb64538` |
| `0x80000a8c` | `unresolved` | `csrrc a4,0x0144,s0` | SYSTEM_REGISTER_READ | 0x0144 | `fwbehavior:0cecb84defdbd6557ca74ae0a38c7f7d2514db47317de99f629dc21391ad097a` |
| `0x80000a8c` | `unresolved` | `csrrc a4,0x0144,s0` | SYSTEM_REGISTER_WRITE | 0x0144 | `fwbehavior:2ff682c0756b2c6bd91e40b2a8de76d9bf405ee72fb57c7c3ee693344ae6fab9` |
| `0x80000ab4` | `unresolved` | `amoor.d s3,a5,(s6)` | ATOMIC_LOAD | — | `fwbehavior:f3a20bab8b9a007fe0a9c81ef37f4d6d17373d18cf3eeff230af9a1ce4fdbfa2` |
| `0x80000ab4` | `unresolved` | `amoor.d s3,a5,(s6)` | ATOMIC_STORE | — | `fwbehavior:5c0be909ab46a7622a23e541724ad915a0a232db582d497e2d745e1dda96e15d` |

## 10. Unresolved / Unsupported Facts

- Unsupported instructions/semantics: 147
- Unresolved call targets: 0
- Unknown memory addresses: 175
- Ambiguous ownership: 0
- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.

Unresolved ≠ nonexistent. Unsupported ≠ safe.

- `0x80000008` `83b00f00` `ld ra,0x0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e6a8e6789ec977932bccd44bb505da545f29c8acf4699bc00ec710658c546acb`
- `0x8000000c` `03b18f00` `ld sp,0x8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:75a8289e93198b75ff97d0a03caec592041aebf0de7898086bb6800858759863`
- `0x80000010` `83b10f01` `ld gp,0x10(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:944cc5f9e0f592c26bab0a6b54e810900b44e05438258c13751e3b17138b04a5`
- `0x80000014` `03b28f01` `ld tp,0x18(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:220d8ce46d1c1f37b256cc5a5efe05edd8f33363eac7dfd70b469965ee208b19`
- `0x80000018` `83b20f02` `ld t0,0x20(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:14764dc2abe44f4cea8173c01640ee90f6d09e0d069b3bd31788ae32bfd20523`
- `0x8000001c` `03b38f02` `ld t1,0x28(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:26a59469bf87c8241efae3ad8675d2feb356880da8906d2dad92b2941e1c4f74`
- `0x80000020` `83b30f03` `ld t2,0x30(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:afd878bb6b72d4bcc63e87357ec842ad3209938e16703286aae1e9cf506fb825`
- `0x80000024` `03b48f03` `ld s0,0x38(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:cbb2a60659055c40ba077b516e36c1d0c3c83e16a303c887af0922bf84a9f645`
- `0x80000028` `83b40f04` `ld s1,0x40(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:bf7301ab4626776549b7c2fced1d9f9affab582d3b69cfdebc45268ea01668c1`
- `0x8000002c` `03b58f04` `ld a0,0x48(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:94abb8577e86839463239630140e3c47456170a6d00abb7763ef58e30bd890d6`
- `0x80000030` `83b50f05` `ld a1,0x50(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6887f11c70ec7b624e849ee7800eb471c81514838e982de5276ada0b6faa78c7`
- `0x80000034` `03b68f05` `ld a2,0x58(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8fabd2e9d3e8d8525186287239d1af78c9eaeb3f8cbcb50a60010e7d53c0738d`
- `0x80000038` `83b60f06` `ld a3,0x60(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:66a16710117c56ae2f4c88cf806f5c4413a947c6d235ec57e3bc744787799ab2`
- `0x8000003c` `03b78f06` `ld a4,0x68(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:12edae559c924e5c25981295a90ac529420e7c5568cbab43bf092ebc3064b627`
- `0x80000040` `83b70f07` `ld a5,0x70(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:15437a63e9faca1acff72a0f506b5a1c41ec789ea91f3500f1294ebb3fcdbdb5`
- `0x80000044` `03b88f07` `ld a6,0x78(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:3810c2776c54cd07b570cc74728989cd0f482d3f35a252828b805df597a4f532`
- `0x80000048` `83b80f08` `ld a7,0x80(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:940cd9a18303526a6a989a78dee89d6b4c7376da8c63d7589a41ce330af03ade`
- `0x8000004c` `03b98f08` `ld s2,0x88(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:28cbd50da26b15432fdf4d59de59f6fb55128db45a7cd94aab9f962f2c3a0954`
- `0x80000050` `83b90f09` `ld s3,0x90(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:69137bb2d295e329f2def1dd82ac3136bf27448b47388277971b651f4dc5ebf6`
- `0x80000054` `03ba8f09` `ld s4,0x98(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c2f373331b33059351e8f71cbbda4b63b70020108564f9bf559b5e3273d6b016`
- `0x80000058` `83ba0f0a` `ld s5,0xa0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:173be850a5948f3ef76002d354f08a2dd617f20c4a9b0c0db06695c889d1df2a`
- `0x8000005c` `03bb8f0a` `ld s6,0xa8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c2fc3867ff78bc438d439bc022854d01763c25719715110921b132062f160a5b`
- `0x80000060` `83bb0f0b` `ld s7,0xb0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ae1c756f21b5812d9a2012632c4f02cff7ada4757951ee9f58d6fdb7d6e5db01`
- `0x80000064` `03bc8f0b` `ld s8,0xb8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6eb3a32d7e893eb70717151024d7b3a8246bf24458103bb54f79dcfdaed4abb2`
- `0x80000068` `83bc0f0c` `ld s9,0xc0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:03e415a581d29f0185a58d72b20de05a82bd5aeaaa77176faac6effd375b8688`
- `0x8000006c` `03bd8f0c` `ld s10,0xc8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:4925e5ed34136fb0651a90fdae0720fc6490c33f16ff6aa32f6c70725159bb0d`
- `0x80000070` `83bd0f0d` `ld s11,0xd0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8b3d589d7fbea81e2cc0278fbc22763870965e499a384a3848443e7f08b5fe13`
- `0x80000074` `03be8f0d` `ld t3,0xd8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:76fc4d347a2fb302caaf1d4d9e8b5ac4cd000b3453d8f957e7d60bd666431c4c`
- `0x80000078` `83be0f0e` `ld t4,0xe0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c96e391c552cc537a9cbb685136f537f92394bdd45bcade1ecd30f655a7102a6`
- `0x8000007c` `03bf8f0e` `ld t5,0xe8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:30509ea505ed2bffcff7005edf202e7a7560a1d31f215336571bd0bcc002c033`
- `0x80000080` `83bf0f0f` `ld t6,0xf0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:7cfb0751268e5c455f04caf3fa7c56ddbae3d14f896abb89e265cb4c4bfd3171`
- `0x80000090` `07a00f00` `flw ft0,0x0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:ed0f19727834054b4666a0680d200d483ec397b1cab0a0e933e347e31ef0686f`
- `0x80000094` `87a08f00` `flw ft1,0x8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:ba23e363c474c0e46659f6d8736971e66eb04b3b5e09c7d24155fc1b228bda06`
- `0x80000098` `07a10f01` `flw ft2,0x10(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:a31d0c21c4cf042ec4350eb4d445cd5056189e17ed8ca3c551967cb4f92a4391`
- `0x8000009c` `87b18f01` `fld ft3,0x18(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:5e18da6f7d3b37cea45525cf058eeaa98f1221500afa3e866f4e10fa63ccede5`
- `0x800000a0` `07b20f02` `fld ft4,0x20(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:7305d3672c1f543d5b226aa58211bb7c43fa750ba744240fafc90a6eef8a091f`
- `0x800000a4` `87b28f02` `fld ft5,0x28(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:82e747d327c3c79a7a9f452f5dc4e8f81ca34a877e2e32a861e4ecf37e0d7ff4`
- `0x800000a8` `07b30f03` `fld ft6,0x30(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:48cb58240f47420dbed69d5f8f933b4053752406f86b7e7b724f84f14edfb9c7`
- `0x800000ac` `87a38f03` `flw ft7,0x38(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:ce1ee7d2f947a79dcf474e7a54c987c17a07b057530fa64c213d6356eb4ace68`
- `0x800000b0` `07b40f04` `fld fs0,0x40(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:b4003f147b821e493a2ff25cb1b223572294e79989c9e2ff797fc04531537af3`
- `0x800000b4` `87b48f04` `fld fs1,0x48(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:62965f0e9a9a75389af73b6813848e8617fcb3aacd994f7e01bfcd735a7dea23`
- `0x800000b8` `07a50f05` `flw fa0,0x50(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:619a1584bdab9e22188605564cb1e1e7a01f369318b1dc18f4127cdc53113f9b`
- `0x800000bc` `87b58f05` `fld fa1,0x58(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:3bae6e94274dbd261edfb1848c813ef023097973e1a4408f42e63cd875f39cbf`
- `0x800000c0` `07b60f06` `fld fa2,0x60(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:ff97764b3bbbf79f2556815677758a48dc7a8922d18d15df50c1e2edc25cf8ab`
- `0x800000c4` `87b68f06` `fld fa3,0x68(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:74d1d9235dec6e07af337b1f7cead60717115a2a28636554effb286808723f04`
- `0x800000c8` `07a70f07` `flw fa4,0x70(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:4cd853d2cedfb2e05b7ac0bdb7534e78a3f6e8d6df54609c1ef03b45d8273a8c`
- `0x800000cc` `87b78f07` `fld fa5,0x78(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:be97c2560b4fdabf143615fab349246634c6508f92365f44e6a66727ac986adf`
- `0x800000d0` `07b80f08` `fld fa6,0x80(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:a20a65aef563ded4026384a20b4332699cd3f717c062f36e3fe5ff3cf464eb1c`
- `0x800000d4` `87a88f08` `flw fa7,0x88(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:39773e6bd477b39a5bd536a753b5cfe19c067580df7e7aba34396d2e63bda0e4`
- `0x800000d8` `07a90f09` `flw fs2,0x90(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:756812fc5d2608307421dbda20e1e84d9cfb761562ba9286a1c667025b2c2381`
- `0x800000dc` `87a98f09` `flw fs3,0x98(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:86ecc8d6baed997f9cdb7b1b87155a939fecf876747cf764592294e8854e1601`
- `0x800000e0` `07ba0f0a` `fld fs4,0xa0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:e80c92a3ec3595debdc24805cc85feaa4af989cf9dcf66a7bfb35b80a9f8c034`
- `0x800000e4` `87aa8f0a` `flw fs5,0xa8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:50c79c3cc0baa960a740314edb1ce007e0c087cad9c2b8e8a51a2a28b9f96bc6`
- `0x800000e8` `07bb0f0b` `fld fs6,0xb0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:60d262cab5c71683e0a88061172e5c7adbe6c571be3e2b2a09a9ecf830ae349f`
- `0x800000ec` `87bb8f0b` `fld fs7,0xb8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:d4ade0ab08be8f43198266dd9b8c167210d1414a522ceef9a6ac78f2a5b4a222`
- `0x800000f0` `07bc0f0c` `fld fs8,0xc0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:f0dc29c1f24b7c2463f9d508032d00b91f31ca9ad8381c0b4c71bee7ca2c7148`
- `0x800000f4` `87bc8f0c` `fld fs9,0xc8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:f6b457811527205e8a37d7c7bbf6f038e6868c0ab9a90560f89ecfb10908fb2a`
- `0x800000f8` `07bd0f0d` `fld fs10,0xd0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:ba742fd50864c9ca3cb4ee21ab8b8c1acbf3183b6110b2e3900c822d41db8bfa`
- `0x800000fc` `87bd8f0d` `fld fs11,0xd8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:8b60a220d3e3e2cace1776d1ca6cfc202e4c12014215757f32ec096644035198`
- `0x80000100` `07be0f0e` `fld ft8,0xe0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:68fa93271877066810c76c73844d3be2725045a5d683e74c109c4d30bc88a94d`
- `0x80000104` `87ae8f0e` `flw ft9,0xe8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:2f6341cacd958210876b55e7aad980e63375c14538aebd8ed087f09e768892d0`
- `0x80000108` `07af0f0f` `flw ft10,0xf0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:2c58663c6b4fda1b6c84133c3864430a14978722c17614e41ffb418af511a5a1`
- `0x8000010c` `87af8f0f` `flw ft11,0xf8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:8c62c13cef6e123bbab8319e96f0071bf4379631af06e8b43d2f62dfe7d9b6be`
- `0x80000114` `73000000` `ecall` → UNKNOWN, unsupported; Unsupported mnemonic ecall; `fwbehavior:76c5edf15ed19f4b26e820ff3bf1f5f763ca7957d5298472e7f208e91dcb9a24`
- `0x80000124` `23bc2004` `sd sp,0x58(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:21df8dbc6dd7668f63a4536cf07342964e2c46d5561156094a3731d2b0778b69`
- `0x8000012c` `23b82006` `sd sp,0x70(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:9d7ef590088a81db95f0008144564ee2dc1a5e42a7ecc97fe21141999dfff421`
- `0x80000134` `23bc2006` `sd sp,0x78(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:2dbc8ccc22c75e92b22cadbfe89bd8b8e9586d99f16d3db67dac44d3278ec845`
- `0x8000013c` `23b02008` `sd sp,0x80(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:e145637d5ac935653339fde541e080135ac260b2e4cfb9fd2b2429a7691272b5`
- `0x80000144` `23b42008` `sd sp,0x88(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:41bfe1a6dd5f53886d031c2b0c0e7e240a119b217cb55295c0000f03e7b07595`
- `0x8000014c` `23b82008` `sd sp,0x90(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:2188efe0604f2bc5af4ab252861374ff8a9df37f8f3a4be2fcf7ae1f14e08944`
- `0x80000154` `23bc2008` `sd sp,0x98(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:f53b87bc6e0dd7ef85405df8a6c941e6fc199bf0255606cbc5920b3b645139a9`
- `0x8000015c` `23b0200a` `sd sp,0xa0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:3e61c54fa7df5d2ea34a4aaf51d5eaec671eb29b25193f923de06bdf33db1847`
- `0x80000168` `23b4200a` `sd sp,0xa8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:ef5c3450fe8fe9fe3802da21253c8e1f3661b91180aea00b92a1a5c99cee7404`
- `0x80000170` `23b8200a` `sd sp,0xb0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:1830f4886be32d7b0a8a99d62bd4b49f6ccc6d05b34031dbdd295914bca29b40`
- `0x80000178` `23bc200a` `sd sp,0xb8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:aa920c19fdb4e09cb576ea2a88a8f1ac88791a0d7b17a4e53ca42e2910646822`
- `0x80000180` `23b0200c` `sd sp,0xc0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:f50b464a8f7b0af764cb0ba45217d7be2af5fe91efefff5eaeaaf73ce987a121`
- `0x80000188` `23b4200c` `sd sp,0xc8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:74fb1c8909c674683efa8e8c2a9d15cc7c29c57760815aa7505d23213e1c9ff7`
- `0x80000190` `23b8200c` `sd sp,0xd0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:5f384fca532fb24efc1d7ccde3dd122ddc9c2b58bf2caced6705077029ae5103`
- `0x80000198` `23bc200c` `sd sp,0xd8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:a5296353ebfa5057d92d35ade9f945863ed363cc2edd0f383fa7a7fb25a8719b`
- `0x800001a0` `23b0200e` `sd sp,0xe0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:faa8232b90df535bcb1cb1c5f43b58afbcffd9ccfea059b6dedbb37cb7f99a1f`
- `0x800001a8` `23b4200e` `sd sp,0xe8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:fe2ddd6b930975325c845809cb1e70eafe5eacdac9f61f9bccd43a39507eb194`
- `0x800001b0` `23b8200e` `sd sp,0xf0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:03dc6163543966dcbc43ec758f2fc418851f05f5af7fea16ae4b05ca85bb003b`
- `0x800001b8` `23bc200e` `sd sp,0xf8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:440aa16cde1119f49fb3de5533e08e58d0441673efb3b9539f3d6cf2971f5014`
- `0x800001c0` `23b02010` `sd sp,0x100(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:059b2d60e1cec1802930c5d46d17ea90ab4d3c49f520423c47ebd85140dbc50d`
- `0x800001c8` `23b42010` `sd sp,0x108(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:ced8cf380c20ad6ef8de0f575b2fe59fd53f40b5d37e78b806e422add834af26`
- `0x800001d4` `23b82010` `sd sp,0x110(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:6b5fc761d4ff1f0db2e0001f3b41fe0b5fe5de3b9c2135e84eb4e89c469d24d2`
- `0x800001dc` `23bc2010` `sd sp,0x118(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:82e70dce42f3ae598cf27ce5f6a1fc8d86055a8b820e90a0eb3c4d0fbc6f0951`
- `0x800001e4` `23bc2012` `sd sp,0x138(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:daec67752f2d553827f086c6bcdc478e93fd14e8e93a8095d6973ddb58ddb826`
- `0x800001ec` `23b02014` `sd sp,0x140(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:a09b50510979505a79e4e0344c1074348c6671140a253bc598dbdfc845ae2919`
- `0x800001f4` `23b42014` `sd sp,0x148(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:667e98737419c08a3fe4d201bc07fbbe1ade4f8c54797fc4cde045557667a152`
- `0x800001fc` `23b82014` `sd sp,0x150(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:5885fda352142319c9b86e2e944b852994fb1d9957a4c3cb607ee6523cdf3860`
- `0x80000204` `23bc2014` `sd sp,0x158(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:29b14de4fa771b82034a0b1df241a7e6114a771300d306f4c030883efbca1ff4`
- `0x8000020c` `23b02016` `sd sp,0x160(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:50d53f6b6af4163b7380d7c3246ef7ff5a00c062bd77bd3f5193a764a8f9ea95`
- `0x80000214` `23b42016` `sd sp,0x168(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:d77220ae078c9bdf8780a2f08ce5d86f8304632701fc46cb920aebc052f49a5f`
- `0x8000021c` `23b82016` `sd sp,0x170(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:7a3a4d8626c088425b8e5ffce90d45bd12cb4275f03532ede538b4e9bfd88a6f`
- `0x80000228` `73211000` `frflags sp` → UNKNOWN, unsupported; Unsupported mnemonic frflags; `fwbehavior:0e5eddbb2b53408ad5f0248e52ac138e8be73af03636e54b7dfacacc8800014d`
- `0x8000022c` `23b02004` `sd sp,0x40(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:a46226ca4b80b2a677d53cfd5bed202232481bd96d4bacca60404e22f53c896b`
- `0x80000230` `73212000` `frrm sp` → UNKNOWN, unsupported; Unsupported mnemonic frrm; `fwbehavior:5e57f1edc1ef335641dd335f65fbb056beebf241e1327fd30c3a1182f4727bf2`
- `0x80000234` `23b42004` `sd sp,0x48(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:f778736ed70925b66e28ae3c1224cee0454d01bb899e0441398b48821b6ca3e7`
- `0x80000238` `73213000` `frcsr sp` → UNKNOWN, unsupported; Unsupported mnemonic frcsr; `fwbehavior:53feff825f106a4a15bcd488e767f3aa1a5d43ed2871ace1302f7c2ee1b22e97`
- `0x8000023c` `23b82004` `sd sp,0x50(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:75786095b056678e7784d2f52c3df4b4c6c6730706e1e625f8e17ff30f8ddbb5`
- `0x80000248` `23b00000` `sd zero,0x0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:ec9900dccd98e84cac01ced5b276cb4f658f82739ade289f7e41638999b4c0ab`
- `0x8000024c` `23b82000` `sd sp,0x10(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:74a308fad1e84b7ff0d12dfa5bb48b6d478d58dae7e06cd14c391aeb754cd099`
- `0x80000250` `23bc3000` `sd gp,0x18(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:cb959ca838e3fdfb0aa7bc01dc6c78966a7e8f81134caccc2cfc13450e41705d`
- `0x80000254` `23b04002` `sd tp,0x20(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:4f2d67a60fe2e80583241b19e6f4358c827d54297cd9c99340c3e0f1ef47731c`
- `0x80000258` `23b45002` `sd t0,0x28(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:3fcc725189ee6d23f8536009c8482b7bb8aa110969bbac3e31322c9a5448304d`
- `0x8000025c` `23b86002` `sd t1,0x30(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:4b24a096e35b01c8ef752be43af666dc6635db9de3f2a11211098c426d27a544`
- `0x80000260` `23bc7002` `sd t2,0x38(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:5828f19882aa5ebaee4d9583f2546afbebe4af202d5f29c28101d92f70fb54db`
- `0x80000264` `23b08004` `sd s0,0x40(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:09b72716841a6374ba0f7eba4671bed227ec465ac5d5a46725c54549e12fb2a1`
- `0x80000268` `23b49004` `sd s1,0x48(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:0d967a9937be12617a45b2c5f2eefeb03411e374f3c8957c966b9429323b4908`
- `0x8000026c` `23b8a004` `sd a0,0x50(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:cc051e15930f15be7a8211e3a57b9aa86f500ad0bfa63c05af37e5972e1b33f6`
- `0x80000270` `23bcb004` `sd a1,0x58(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:7c69849593f9bd131725acc3f6f35d22cbffc86ee0e0bd8f7006bec310ddba7e`
- `0x80000274` `23b0c006` `sd a2,0x60(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:76f535af2187b5e93fefe03ddec474d1ed7a60e51ae0250e007ee0bff8339a6c`
- `0x80000278` `23b4d006` `sd a3,0x68(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:d7b79a0cf9d9fac13dfdeabd58db0aa51861687620552440df023fb7d9fd6dad`
- `0x8000027c` `23b8e006` `sd a4,0x70(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:6acbe4868c0ac8cf9651db8650fcc23fc7679107a5d681d1b2fb021f342abf6a`
- `0x80000280` `23bcf006` `sd a5,0x78(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:a1b878f31356f82151c15b80efc6d0dcab210072498af96ff0af0679aaf5ba6e`
- `0x80000284` `23b00009` `sd a6,0x80(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:46a026bcd9476e8f5019e3fbe01d71d29e46707dd2c264d647ba8bbe15254008`
- `0x80000288` `23b41009` `sd a7,0x88(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:b3c0ef63fa399508a0811ee7daecf6ab2180123cb2fa98add86f10de7e89f704`
- `0x8000028c` `23b82009` `sd s2,0x90(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:651ee1fe0586933fd538027c1833f98e0960b3c88c87b724c8386519bf1d7857`
- `0x80000290` `23bc3009` `sd s3,0x98(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:63778b3390cf6d3477f35b076ae1b36cd17e39b4aadc11f361525bafe863c22d`
- `0x80000294` `23b0400b` `sd s4,0xa0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:df8b826d3c57916d55c727cc3665c71c6368301abd97ba51ecd5dde31e706765`
- `0x80000298` `23b4500b` `sd s5,0xa8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:7c470d28e58203c12fea286058d5f2a365706c9bd919faf4dee878936e8ccb66`
- `0x8000029c` `23b8600b` `sd s6,0xb0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:640c0e07f9ce448b8a9f2db05193b8679e649ba1db75c9a70b13485945accfb2`
- `0x800002a0` `23bc700b` `sd s7,0xb8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:8bbdfd6557ca44d78528dde7572d7ca5f13efb3ce4cd4ef733922d9ec3c81886`
- `0x800002a4` `23b0800d` `sd s8,0xc0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:a750c9290bd9c1ad484a1a042054b05d3129923e4ab1d8d1a4ae1b11e64e47cd`
- `0x800002a8` `23b4900d` `sd s9,0xc8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:fe84a8d276e8fdb278639461c3db3c27e76983a1099cc0557d3c860c0122e5bf`
- `0x800002ac` `23bcb00d` `sd s11,0xd8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:660208d2380e2da69b995f3b9b5bb67c8be67d03c081e66daabfbd69571b2432`
- `0x800002b0` `23b0c00f` `sd t3,0xe0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:3667951b6385ee6210110a11e72dd5021f9c3605d0cce180bc5c39cf13926744`
- `0x800002b4` `23b4d00f` `sd t4,0xe8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:9217aaf6a6e47f093353800082d073fd24dab98b03c29b76a89090e3e5b9edd9`
- `0x800002b8` `23b8e00f` `sd t5,0xf0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:b3b4feccd7a2845c170ef35da275396c689946cdf9dbb0f39026704e953a6222`
- `0x800002c4` `27a41000` `fsw ft1,0x8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:b533223f85f9c827625ca527223e9b1e556e47c7857246479b751754f8d5114c`
- `0x800002c8` `27a82000` `fsw ft2,0x10(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:a42d26f7b1677092a773a9b50dfa3b86db1893568c16507a4e3dba0088824d14`
- `0x800002cc` `27ac7002` `fsw ft7,0x38(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:56faf67dd72b685a6109885a7c283e517975aa3dce901bca7cbcf5d1b5ee00e5`
- `0x800002d0` `27a49004` `fsw fs1,0x48(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:fb5fab7ee7a0647bf33f9d1cb3aae7bf2df052be45e39ef7fcb65b7a57398484`
- `0x800002d4` `27a8a004` `fsw fa0,0x50(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:a178be05c138e8710012ae5618dfea6ec6a50718fb9065f70f7e0d8f7739ea2c`
- `0x800002d8` `27a0c006` `fsw fa2,0x60(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:f2eba0db2e6261c15b28465f081b3667f5f601aa16898da0a0afa3368895fa00`
- `0x800002dc` `27a4d006` `fsw fa3,0x68(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:2298f5498430e9b90a262c9188227e4186f35ba31311ded835d620fa98b3a08c`
- `0x800002e0` `27a4500b` `fsw fs5,0xa8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:6a35961e38b9ed97cf8c20d1c27a2fe4a8673f305b9f1e8d68d6e07e2b1c8c91`
- `0x800002e4` `27a8600b` `fsw fs6,0xb0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:badb50d819322868356b2551e35cc106835332945c924581c79c88f6df80600c`
- `0x800002e8` `27a4900d` `fsw fs9,0xc8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:226948cc826d33c4eae129ff9f1902dcbda121c950574156e7713d65f78fc8fd`
- `0x800002ec` `27a8a00d` `fsw fs10,0xd0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:ec945b2d3d722ccb9ec119c0bb45ec3b322dad4b91d75b0a0a5cabf41aacfaf6`
- `0x800002f0` `27a0c00f` `fsw ft8,0xe0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:956038a64e3587657e43a38a5c22bd0cf26a9dd28f88720f1015405162f764c9`
- `0x800002f4` `27a4d00f` `fsw ft9,0xe8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:0e6160be264fbaf794c367a8e68b5a67da942fdc675f98392c5c63f29d65a2d7`
- `0x800002f8` `27a8e00f` `fsw ft10,0xf0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:8c9d4490d302b59741995f750d6251a979f88ebf0a7c7e788f2affd72a728ecd`
- `0x800002fc` `27acf00f` `fsw ft11,0xf8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:cd68e4f4fa63a69fb4bbaded4cc66827018756707b39ae0457a96d6fcabc3c1a`
- `0x80000308` `27b00000` `fsd ft0,0x0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:b0573faf782a37338c710c6a6c28dfba8a19fb3067536d27db6f0aba787a272c`
- `0x8000030c` `27bc3000` `fsd ft3,0x18(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:42931497bb7ecef472d30d1f9ca388d3ed2d2e6332da4e2ce4f20c62d0fe850c`
- `0x80000310` `27b04002` `fsd ft4,0x20(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:e5e3a23887c89b090eedc37bfa72139035ea1e821684e36b93122b035ba99c6d`
- `0x80000314` `27b45002` `fsd ft5,0x28(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:9e5db344dac4d2c52d56dc9c9d494c61b94c452a1751aac710f5e55753ed72f2`
- `0x80000318` `27b86002` `fsd ft6,0x30(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:93b5f67143e7d176cc757e879f84ad2535e6c7696c92aa1fa5c8d76198358910`
- `0x8000031c` `27b08004` `fsd fs0,0x40(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:9e4426bf2190e89d821247bfef1a54b2f163ce0115d9038384ccddd1756735e1`
- `0x80000320` `27bcb004` `fsd fa1,0x58(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:76358aee1eb6b90d7c43859a97e5e060fb0dbdd6e0bf5ca7c3caa07cb8eef139`
- `0x80000324` `27b8e006` `fsd fa4,0x70(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:ed1354d41e7a66422a506247e6fdac90e98255118291722955d3e4697ab4a6ee`
- `0x80000328` `27bcf006` `fsd fa5,0x78(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:decb2298a1aa75fbbb7a207fbec6d47d08162d3f5bbadd50ba5e9d76b290d26a`
- `0x8000032c` `27b00009` `fsd fa6,0x80(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:283669f5c0d57abb332198c2b83457acaabb8108c4a19ca394b2beb1fe589d48`
- `0x80000330` `27b41009` `fsd fa7,0x88(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:85515fbdab3c3ee3b33272cfe24af68b9dce61c93c0a62ca26305a174cfe478e`
- `0x80000334` `27b82009` `fsd fs2,0x90(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:01cd70dc516086b47adc7d76fda6facdbd6ad6013bb9e22829b1788e357bad8b`
- `0x80000338` `27bc3009` `fsd fs3,0x98(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:d50a15af74b4efb36bed9930bf9887831d863da617ad8d447c3820d4405b624d`
- `0x8000033c` `27b0400b` `fsd fs4,0xa0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:03e8178c7f9e87f0f547df6680e7846cb1243ba850714c1fe81ee925359778f4`
- `0x80000340` `27bc700b` `fsd fs7,0xb8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:8ff6beb5733a818b9d4e31707694bf8e020e6ecd487c50580fe708a61b1ff034`
- `0x80000344` `27b0800d` `fsd fs8,0xc0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:eec02bff8cc88dc96346600ba2b273ca91e6474f0463b6c2e7eb4831f3849f76`
- `0x80000348` `27bcb00d` `fsd fs11,0xd8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:e54b22512cd82c33c2f586ab249ed8b339a7ff6bfc4e351689d84d31e4c9b770`
- `0x80000354` `23283fca` `sw gp,-0x350(t5)` → MEMORY_STORE, partial; unknown; `fwbehavior:6feba183bdedbc655a8f2e77d3ec91d596ee5839bc8d13780a90a51f8d5e1ca0`
- `0x800003e0` `73000000` `ecall` → UNKNOWN, unsupported; Unsupported mnemonic ecall; `fwbehavior:aa19088575bed3ae380e43b579d14bdf0e4c0729dec7d6224d173b1194ac82e0`
- `0x80000480` `bb555703` `divuw a1,a4,s5` → UNKNOWN, unsupported; Unsupported mnemonic divuw; `fwbehavior:d215804585c244fe207435e1c07654ba0b3eb70d77aa4c61c8fa008354c8fb41`
- `0x8000048c` `27a07501` `fsw fs7,0x0(a1)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:44925c1a0c1982de976d14da36cb7715104d930c014f41dae6173bf97f760c24`
- `0x800004a0` `03d720fe` `lhu a4,-0x1e(ra)` → MEMORY_LOAD, partial; unknown; `fwbehavior:448d60f0cde0d0694af83b17ad959a77beddef2964a1a46b354463ddab17f29c`
- `0x800004c4` `836a0d00` `lwu s5,0x0(s10)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e3858dbac58cb1350dda9debdb7184e45490b6e7064607879f3abc20c7c3b130`
- `0x800004d4` `2fb29c00` `amoadd.d tp,s1,(s9)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:0671a09720cf6dac8ce7f69c598199948da04d99ca1cd402366d3ee475706528`
- `0x800004d4` `2fb29c00` `amoadd.d tp,s1,(s9)` → ATOMIC_STORE, partial; unknown; `fwbehavior:82b352aefc726c041a2565cebc7bb66d506cc852b4c0448219f1cbd5ef369117`
- `0x800004e8` `afa61d20` `amoxor.w a3,ra,(s11)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:c6375d0634252830db2ea68cf45588ddb5bbb8e807e4b8cc4d3022c2c054cbe3`
- `0x800004e8` `afa61d20` `amoxor.w a3,ra,(s11)` → ATOMIC_STORE, partial; unknown; `fwbehavior:f07da849fc2881d24930b36d73f6d3a8d9ae4e3b48333258bf92ed55b8bff176`
- `0x800004ec` `533315d0` `fcvt.s.wu ft6,a0,rup` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.wu; `fwbehavior:43beb9a83bd4f99b0efc187b71f3c0e543825a5b89876c4714905351d388a451`
- `0x800004fc` `2f22de19` `sc.w tp,t4,(t3)` → ATOMIC_STORE, partial; unknown; `fwbehavior:c01915e58fd35448debc391b587226d0e70d824b2a6001bfa87f25b750bd0b08`
- `0x80000544` `d3f923d0` `fcvt.s.l fs3,t2,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.l; `fwbehavior:7a61d061fb62b62a96139eeabad6a16814c54681bab48f5bbb712d173120eeb6`
- `0x80000548` `3bd1dc03` `divuw sp,s9,t4` → UNKNOWN, unsupported; Unsupported mnemonic divuw; `fwbehavior:f7f965bce0ce36a95d548fede1c129764178fc01c7f77314d40e6b1be4d3ac03`
- `0x80000558` `2f3c0310` `lr.d s8,(t1)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:7f7a1bf98d506fe9a9ffeed24076d85740aa2df46b8be8df902ff1af4b1ead78`
- `0x80000560` `d37321c0` `fcvt.l.s t2,ft2,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.l.s; `fwbehavior:945c386e6d73e66d5352efd78617e6eb0b00453e7b55977dc7c227c9be1022b3`
- `0x80000574` `2391c5ff` `sh t3,-0x1e(a1)` → MEMORY_STORE, partial; unknown; `fwbehavior:454b0230ce9dd172dcdf7a15856fcfb7c22e12577d5e43fd32489c2d64813edd`
- `0x80000578` `d33c35d0` `fcvt.s.lu fs9,a0,rup` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.lu; `fwbehavior:ec417cd91b79323ab26330cb4d27996a6eb742bec6a4ebe6e4f93eb24e040785`
- `0x80000594` `2f21bee1` `amomaxu.w sp,s11,(t3)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:7b2c3645e850042db54e2c6271c351dffaaa985219c028415c1e7aeabfc76224`
- `0x80000594` `2f21bee1` `amomaxu.w sp,s11,(t3)` → ATOMIC_STORE, partial; unknown; `fwbehavior:b711c6d340d60c1e851dcfbdf51aaed6635853b942929e37138c5c5d4e61b4f8`
- `0x80000598` `537635c0` `fcvt.lu.s a2,fa0,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.lu.s; `fwbehavior:109378fb4559f10665ad4100e5d6d8c6be8b8a4467d25b4c6fda830ea2e8f885`
- `0x8000059c` `538c2ec0` `fcvt.l.s s8,ft9,rne` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.l.s; `fwbehavior:d07ed4ac437ab7069189fb28bf86e7700c119ea196c441833700c81dc75f2468`
- `0x800005a8` `03460900` `lbu a2,0x0(s2)` → MEMORY_LOAD, partial; unknown; `fwbehavior:891ca01075df3c82a6dda26a7683d938c5aee9ef28c404ec693d8edda76ad861`
- `0x800005bc` `3333c703` `mulhu t1,a4,t3` → UNKNOWN, unsupported; Unsupported mnemonic mulhu; `fwbehavior:4a63ef1d37e2fa80893cd1e33f9b6e7d064ca2000a4ecab454313a3c40313eae`
- `0x800005dc` `231623fe` `sh sp,-0x14(t1)` → MEMORY_STORE, partial; unknown; `fwbehavior:5d1310d8ad97a8fa31b1747c710b19721b15d8eb144e3bd71434da9e2541841d`
- `0x800005ec` `afbb1708` `amoswap.d s7,ra,(a5)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:b77aad05172c1ff71f1019e35b7912a04f56128a1d43c1f03eefbe6de069e6c6`
- `0x800005ec` `afbb1708` `amoswap.d s7,ra,(a5)` → ATOMIC_STORE, partial; unknown; `fwbehavior:34b86b0a9ba9d8ea87609aa1c47b917ba074609fecea573c2543d593185e57e1`
- `0x800005f0` `4749f4f9` `fmsub.s fs2,fs0,ft11,ft11,rmm` → UNKNOWN, unsupported; Unsupported mnemonic fmsub.s; `fwbehavior:84dda971c0651b452e8abfe7b7667f3ac443f10f852d711465632e160d3f8efc`
- `0x80000600` `2f341f60` `amoand.d s0,ra,(t5)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:799484e5c76b3530dc65451d3435ea3987d45cc21beb735b63aef54939c2de22`
- `0x80000600` `2f341f60` `amoand.d s0,ra,(t5)` → ATOMIC_STORE, partial; unknown; `fwbehavior:507a10da50095fa1d83fffdc6446222c05f9fbc5a18584dcd8718b2d8cbf0ec5`
- `0x80000620` `3399cc03` `mulh s2,s9,t3` → UNKNOWN, unsupported; Unsupported mnemonic mulh; `fwbehavior:26d64650280add0b9232f5bc466292f822077585cde1cdc180d9714ec97351b5`
- `0x80000640` `afa25620` `amoxor.w t0,t0,(a3)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:933c7c7ee10bd2d977229462f81bdd69335854a99689f81a099d393458e5a4fc`
- `0x80000640` `afa25620` `amoxor.w t0,t0,(a3)` → ATOMIC_STORE, partial; unknown; `fwbehavior:0be4146fbe40896d7382da32647aa3531e48e42a0cfa1f067a81b7b416197c32`
- `0x80000644` `b3913702` `mulh gp,a5,gp` → UNKNOWN, unsupported; Unsupported mnemonic mulh; `fwbehavior:339a922e1dfe2b8bb55fadda6eb4419aaacdbc354b0b5d37fdd1831c06b8520e`
- `0x80000660` `33993402` `mulh s2,s1,gp` → UNKNOWN, unsupported; Unsupported mnemonic mulh; `fwbehavior:d600e3937b4b8dec8fda8d6f20cb93f646a8a11eef09f8a3f9d223fbd997917a`
- `0x80000674` `0384d601` `lb s0,0x1d(a3)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a63b95a617c4e0041f66a8ea6ef3b0eeb300e368d06cbd07951bcd22b040f4d5`
- `0x8000068c` `2f358921` `amoxor.d a0,s8,(s2)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:3fc9b84169aad3836aaacbee0365a196addfe70bed038959434d1c97b53bb1a6`
- `0x8000068c` `2f358921` `amoxor.d a0,s8,(s2)` → ATOMIC_STORE, partial; unknown; `fwbehavior:0bae1d6ddfd1ebb23be5633ad5b777c9bf259dd01f8ca3eb9498a371c264cca7`
- `0x8000069c` `2fba2c40` `amoor.d s4,sp,(s9)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:37c8f4b1e67965b61895e11db1cdf6383a37d639caef95a69aa1fcefd2624d47`
- `0x8000069c` `2fba2c40` `amoor.d s4,sp,(s9)` → ATOMIC_STORE, partial; unknown; `fwbehavior:29486d63e8b478cce3a57f6b642b37b70bfd476d3c17d4fe1c8e9ae383730f74`
- `0x800006a8` `034a8800` `lbu s4,0x8(a6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:79bb4a1130785cb942549e4b3cfee79ee5dac43c3a63e34e729719472ef33ad8`
- `0x800006b0` `d3a1c808` `fsub.s ft3,fa7,fa2,rdn` → UNKNOWN, unsupported; Unsupported mnemonic fsub.s; `fwbehavior:4ad6ae62e439bc2450d48507b473fdb140e371629169f171e9e0d4963eb5acdd`
- `0x800006c0` `2f2fd1e0` `amomaxu.w t5,a3,(sp)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:f336256114dba018a5bdb25d3165c7c0c9782ba22b864d62b638824e65a91744`
- `0x800006c0` `2f2fd1e0` `amomaxu.w t5,a3,(sp)` → ATOMIC_STORE, partial; unknown; `fwbehavior:e8d5bd33ffc41a5868fc06f12c5f1c92bafbc36af5de81e3cebf7a8fe299b664`
- `0x800006c4` `53a02ba1` `feq.s zero,fs7,fs2` → UNKNOWN, unsupported; Unsupported mnemonic feq.s; `fwbehavior:9dcf4ff1c220209866a1937c83ffdd51ac05a79f953bbc268996ba9e464999fd`
- `0x800006d4` `2f230e10` `lr.w t1,(t3)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:86e91c761636b46c1cb78caf98fb8e40aa68d2046c9852a5ccfe014f0aef56ca`
- `0x800006e4` `83a14a00` `lw gp,0x4(s5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:76b8fe6082b06c9136043bde37092d7671aabc3039c9f069bcaa7eed8d242134`
- `0x800006f4` `2f2851a1` `amomax.w a6,s5,(sp)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:826d02af9c9c36c3d937512e50e53ccfa26541e0f3311702c00909e036a6f363`
- `0x800006f4` `2f2851a1` `amomax.w a6,s5,(sp)` → ATOMIC_STORE, partial; unknown; `fwbehavior:a7fbcd49b42187b27498b766869e311791d8fc0ffa81456345d84efe2f917bee`
- `0x80000700` `538b1ad0` `fcvt.s.wu fs6,s5,rne` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.wu; `fwbehavior:3d85f9db522f99ba86f0b77cade5369f8a22d94e91e251acc9876886349bc392`
- `0x80000704` `d3a6b7a1` `feq.s a3,fa5,fs11` → UNKNOWN, unsupported; Unsupported mnemonic feq.s; `fwbehavior:0dd905948ef1bd7809004708228d0b9dbdf0a1c15f2ffac3d6fbe28e913e676e`
- `0x80000718` `53a0bea0` `feq.s zero,ft9,fa1` → UNKNOWN, unsupported; Unsupported mnemonic feq.s; `fwbehavior:412574f2568477fd4b59da6d46e1313c60ea16bd030fb1e611ac1a9bc5b85ddd`
- `0x80000730` `af215b40` `amoor.w gp,t0,(s6)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:25d9ed72e34b3ac76cbf59d5cd8d469a389f2efdf0ac4192a312e1ef2d76785b`
- `0x80000730` `af215b40` `amoor.w gp,t0,(s6)` → ATOMIC_STORE, partial; unknown; `fwbehavior:eb033357917304f9b4a7ed7b3ea42e6ad091bdf939945730af27a7dc8abae161`
- `0x80000744` `83278800` `lw a5,0x8(a6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0908eff73d7c3275cd51cad675dd3a6a62d2932247859eb5ca6c1133441a1ebf`
- `0x8000075c` `d3a38719` `fdiv.s ft7,fa5,fs8,rdn` → UNKNOWN, unsupported; Unsupported mnemonic fdiv.s; `fwbehavior:b0126c47b0d1431c76625d392e38e339935d8d245522122c80dc804882daef24`
- `0x80000760` `5319b720` `fsgnjn.s fs2,fa4,fa1` → UNKNOWN, unsupported; Unsupported mnemonic fsgnjn.s; `fwbehavior:f286252a4709ca7e3d32a33e017864e5d78d54fb50b265081dcf1c5e7675a082`
- `0x80000770` `2fbdaca1` `amomax.d s10,s10,(s9)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:30915c195638d96891e7eb45c0279f2fb0451ec9e8442412df60962854b9bf90`
- `0x80000770` `2fbdaca1` `amomax.d s10,s10,(s9)` → ATOMIC_STORE, partial; unknown; `fwbehavior:a5dfda16103be5cfe51e7c58e47607f2bb97e8212481d9e0e5d0dd29772e7c37`
- `0x8000077c` `33ad8402` `mulhsu s10,s1,s0` → UNKNOWN, unsupported; Unsupported mnemonic mulhsu; `fwbehavior:fb9d2040f1e73e7f9250b5157140f9946c71b88fb73518ecce350e7711517a03`
- `0x80000790` `03ac4100` `lw s8,0x4(gp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:98ddb92fbd30a02c55abbccd793a618e726df113d541f35b669204d6ac990e96`
- `0x80000794` `d3080af0` `fmv.w.x fa7,s4` → UNKNOWN, unsupported; Unsupported mnemonic fmv.w.x; `fwbehavior:d4d52ada7f19b5114953c03434fc3c6bd1348bd6a2478e680b5a6e0dd4db9d0f`
- `0x80000798` `33e91803` `rem s2,a7,a7` → UNKNOWN, unsupported; Unsupported mnemonic rem; `fwbehavior:5a9fd2b7353f4bef548f0ae500e9ffb55026eeca0b1d979373e577e9317c6277`
- `0x8000079c` `d3870bf0` `fmv.w.x fa5,s7` → UNKNOWN, unsupported; Unsupported mnemonic fmv.w.x; `fwbehavior:80da917ee3dae787394045407b89aebd1ef394ea9289270da21292f278c84d80`
- `0x800007a0` `bbfc0002` `remuw s9,ra,zero` → UNKNOWN, unsupported; Unsupported mnemonic remuw; `fwbehavior:9d8818098ae2da6abd1d24e38fc5d8769cc6d0f72d821ddcfb30394678918d99`
- `0x800007ac` `d31c01e0` `fclass.s s9,ft2` → UNKNOWN, unsupported; Unsupported mnemonic fclass.s; `fwbehavior:7c14aa6fb40cfdbce71e09024ab8b1e6ed966f180eb95e880f702101ed6fc12f`
- `0x800007b4` `538a5120` `fsgnj.s fs4,ft3,ft5` → UNKNOWN, unsupported; Unsupported mnemonic fsgnj.s; `fwbehavior:d7656d5e52a348e8a1f1412a5dd2d871eb5bbd1024a7e0731aa9ef20f843ee96`
- `0x800007c4` `afa7d4e0` `amomaxu.w a5,a3,(s1)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:1585498700894a7700db14ba2a80d4572037a8193b2c382c1d1c87b0160c8f2e`
- `0x800007c4` `afa7d4e0` `amomaxu.w a5,a3,(s1)` → ATOMIC_STORE, partial; unknown; `fwbehavior:8e98f801acfd3b7629eb3ef228c78a8bec334944edca7af0e6be9c222d2cd66b`
- `0x800007cc` `c7f12108` `fmsub.s ft3,ft3,ft2,ft1,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fmsub.s; `fwbehavior:fa41d48a1b3898e5fce236acb1655b93f643d28b2542b54afd626040b962ea83`
- `0x800007d0` `53230721` `fsgnjx.s ft6,fa4,fa6` → UNKNOWN, unsupported; Unsupported mnemonic fsgnjx.s; `fwbehavior:d32dc63b4e9805a8dffdbf1e3035fdd3a61f08d6fb7f880c636db541d5db70e3`
- `0x800007e0` `2f3aa608` `amoswap.d s4,a0,(a2)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:51b3e098dc8636308949373a28d3a10487338bd766a971d331cdf73336e468dc`
- `0x800007e0` `2f3aa608` `amoswap.d s4,a0,(a2)` → ATOMIC_STORE, partial; unknown; `fwbehavior:fd2da7e471838f67c8c777c7820b4ac92d02f5c58b6ea0b6acdb243196048318`
- `0x800007e8` `53350658` `fsqrt.s fa0,fa2,rup` → UNKNOWN, unsupported; Unsupported mnemonic fsqrt.s; `fwbehavior:a9980ca5acaf7029e7b659cd7745389e34fc4c1874886e690fb9f11e89de7448`
- `0x800007ec` `33dda702` `divu s10,a5,a0` → UNKNOWN, unsupported; Unsupported mnemonic divu; `fwbehavior:f0617de1bec92017d5617642937759cde6f754a9ed43455a1d982f413407c0ad`
- `0x800007f4` `d3a935c0` `fcvt.lu.s s3,fa1,rdn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.lu.s; `fwbehavior:eb5ae09a436f558f134fc11ffde1cd1e437fa3ef6b7b4ef671f3381bf8a01927`
- `0x80000804` `2fb12d81` `amomin.d sp,s2,(s11)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:c147651bdc6c36a814e8d00213a43f10ba2f4fd282d65aaffdeb408bc4118138`
- `0x80000804` `2fb12d81` `amomin.d sp,s2,(s11)` → ATOMIC_STORE, partial; unknown; `fwbehavior:8a793751c16864de270ca078e8ec7d06604511404c62362c93fdd78ee1b902b8`
- `0x80000808` `3b04c103` `mulw s0,sp,t3` → UNKNOWN, unsupported; Unsupported mnemonic mulw; `fwbehavior:93f4a52b6c73916d3da3bfd85e741a17d4e1743992703dad580c522dffcb802d`
- `0x80000818` `2f2d7800` `amoadd.w s10,t2,(a6)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:457c9575ba8ba62f1d1764c0bcccac42dde5ed08e34a9c410619c7af217873e0`
- `0x80000818` `2f2d7800` `amoadd.w s10,t2,(a6)` → ATOMIC_STORE, partial; unknown; `fwbehavior:41059f4d894ca3a7074e348d055ded20032b34ed79cc8b3d3028a2ecf8722ecc`
- `0x80000828` `afb73021` `amoxor.d a5,s3,(ra)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:1af5a2d197b1445713d08247609ae7606fa8d81cd9a861d2e92e3d98b5a04936`
- `0x80000828` `afb73021` `amoxor.d a5,s3,(ra)` → ATOMIC_STORE, partial; unknown; `fwbehavior:99baaf914cfb3d24d3e01e6d6656ac618009812ac7d421fba5d8ef072633cab6`
- `0x80000830` `4b17d069` `fnmsub.s fa4,ft0,ft9,fa3,rtz` → UNKNOWN, unsupported; Unsupported mnemonic fnmsub.s; `fwbehavior:1ffc00d8e0bf81f5cdbd1b700769c27919b13aeb271390510aad0761e02bb93d`
- `0x80000858` `c737a931` `fmsub.s fa5,fs2,fs10,ft6,rup` → UNKNOWN, unsupported; Unsupported mnemonic fmsub.s; `fwbehavior:685476cdbf0569babd19c591a61b951aebaee3aaafffaf462b33c4b21376bdc2`
- `0x8000085c` `532723c0` `fcvt.l.s a4,ft6,rdn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.l.s; `fwbehavior:b130ab5d7c5575d305aac4e94638b1240cde37a5f3aabead83d3dad2684fddc1`
- `0x80000860` `33062803` `mul a2,a6,s2` → UNKNOWN, unsupported; Unsupported mnemonic mul; `fwbehavior:af7ad8989343be018d98afd502cb2084df7b6819574e1084833045508f9f94ef`
- `0x80000864` `33428c03` `div tp,s8,s8` → UNKNOWN, unsupported; Unsupported mnemonic div; `fwbehavior:4b733418d7569f202bf20b5c3ac19fc28442188365ccbcec2f467dd1a459a12e`
- `0x80000868` `bbf1b403` `remuw gp,s1,s11` → UNKNOWN, unsupported; Unsupported mnemonic remuw; `fwbehavior:e85121cd7148d958d1c2dade7b35d5584fa3186adb5c1a415811b5d9fff32199`
- `0x80000874` `83405d00` `lbu ra,0x5(s10)` → MEMORY_LOAD, partial; unknown; `fwbehavior:bbc387fe210c7c8282787cdb7243647abfc1bd3eb4bf36a00ea5defe36982ec8`
- `0x8000087c` `3b053a02` `mulw a0,s4,gp` → UNKNOWN, unsupported; Unsupported mnemonic mulw; `fwbehavior:99bee8fee5aa6b563ba5f7690c88589c7f23f316bbc9267207d87548308313d6`
- `0x80000880` `b3a4c803` `mulhsu s1,a7,t3` → UNKNOWN, unsupported; Unsupported mnemonic mulhsu; `fwbehavior:b50e35b2657a6335312ba117d051b25fd70ce55287db172fbf56386819d72e22`
- `0x80000890` `2fa70910` `lr.w a4,(s3)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:f420d66356dd59d8f10b9e3e6ab23645a269b4b69d5a1053b40de58a26ff32a4`
- `0x800008a0` `2f31ba61` `amoand.d sp,s11,(s4)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:9166f75bd03b4eaa45e812d810889cbf3870f325c1d4bc47a3a3c0bcfaa9ac5c`
- `0x800008a0` `2f31ba61` `amoand.d sp,s11,(s4)` → ATOMIC_STORE, partial; unknown; `fwbehavior:b93858a0693fe9b464b129747a23528ff90d5887ba6c8a2e34228ee73b0ffde7`
- `0x800008ac` `03d1e6fe` `lhu sp,-0x12(a3)` → MEMORY_LOAD, partial; unknown; `fwbehavior:477a0832d353a727c17c5a07b035593637d3b5fd798d32db423bff6690f18b9d`
- `0x800008b0` `bbf30e02` `remuw t2,t4,zero` → UNKNOWN, unsupported; Unsupported mnemonic remuw; `fwbehavior:8443185ca656c48a8c65d915c11db52b1744870f8fb3c8950dfcbbcf13f9f67f`
- `0x800008c0` `2313e101` `sh t5,0x6(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:bcd709a43bf429a09fb28df9cb18c2de1ec978252ded52ab420c0ffffe7139a2`
- `0x800008c4` `53984629` `fmax.s fa6,fa3,fs4` → UNKNOWN, unsupported; Unsupported mnemonic fmax.s; `fwbehavior:10f24ff856bb15764ddbd0dfb86deba01019744962035d712591068836ce0e5f`
- `0x800008d4` `afae0a10` `lr.w t4,(s5)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:2ee815b8e14b7098e633dfa24538b58c2c47b36d509ac76be9593c537abac462`
- `0x800008e4` `af29c781` `amomin.w s3,t3,(a4)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:0722ddf5f07ccb2932b6213d3ea9d718057c1c4c923102b436b7d30159875ebd`
- `0x800008e4` `af29c781` `amomin.w s3,t3,(a4)` → ATOMIC_STORE, partial; unknown; `fwbehavior:0008a4a7d626c5f1530f33c09d8c71e95e25112e555618e5b221309371360bea`
- `0x800008e8` `d3904011` `fmul.s ft1,ft1,fs4,rtz` → UNKNOWN, unsupported; Unsupported mnemonic fmul.s; `fwbehavior:1dc5cb34de7ee235ae80adf55f45463c78105180e897d2d6e6a6589758c75e8e`
- `0x800008f0` `53993bd0` `fcvt.s.lu fs2,s7,rtz` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.lu; `fwbehavior:c0fb312785599095a294fac89c981b61e1c8398cf779370ae11787ea86b862a4`
- `0x80000900` `2fa42de0` `amomaxu.w s0,sp,(s11)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:729f62288cf319e34bc801314277137d60cdbd0802629a8b5c9b5abbd33d8906`
- `0x80000900` `2fa42de0` `amomaxu.w s0,sp,(s11)` → ATOMIC_STORE, partial; unknown; `fwbehavior:1dcaae078bad8360224b249c8c220cf6630787eb674638ab1a31a6d5b974bd6a`
- `0x80000908` `538fcca0` `fle.s t5,fs9,fa2` → UNKNOWN, unsupported; Unsupported mnemonic fle.s; `fwbehavior:109481c6d227ac03cf9bb962d1fb5dfb27a9d6dc2786d43f84011e23552613cc`
- `0x80000910` `5314aaa0` `flt.s s0,fs4,fa0` → UNKNOWN, unsupported; Unsupported mnemonic flt.s; `fwbehavior:c32853a6ab2f30bd058eb9354849d49ad9a331099eda1b560de9e8c38939a1dd`
- `0x8000091c` `03010d00` `lb sp,0x0(s10)` → MEMORY_LOAD, partial; unknown; `fwbehavior:788766736c35cff8eecb6973398e0c21d475580548b73fa9970a3bd3f84e9099`
- `0x80000924` `bb0dab03` `mulw s11,s6,s10` → UNKNOWN, unsupported; Unsupported mnemonic mulw; `fwbehavior:dbbf1f1cc0c550fe0ac92b5ced13b97f56eca8c62bbd3f9f12af6aaddf311dc8`
- `0x80000928` `335a4003` `divu s4,zero,s4` → UNKNOWN, unsupported; Unsupported mnemonic divu; `fwbehavior:92de636200c39a61a4f49a20e73b8a377ebb1479348f63155522e6f2389fbd00`
- `0x8000092c` `bb842202` `mulw s1,t0,sp` → UNKNOWN, unsupported; Unsupported mnemonic mulw; `fwbehavior:6be8c9e508f47aef2ef83efc4f9c730ab863d86b9fcb3f96f8590718b7d7ee51`
- `0x80000930` `d3a07f21` `fsgnjx.s ft1,ft11,fs7` → UNKNOWN, unsupported; Unsupported mnemonic fsgnjx.s; `fwbehavior:38d07aab08a8b0de7a1e4394b79bf3c77fc6a57555f34288de6c8bfda965ef3d`
- `0x8000093c` `0309ff01` `lb s2,0x1f(t5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:09c72a407fb94579c5959be47cfb5b30cc509f4163f5b5cddea5c5602d923687`
- `0x80000948` `03b30200` `ld t1,0x0(t0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:16bb4cf457d5c8b1aee7fe32f5d6b9d9943d9aa5ce64430480b6c409408a6ded`
- `0x8000094c` `d3b336c0` `fcvt.lu.s t2,fa3,rup` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.lu.s; `fwbehavior:10179e0a59a439a95a3b44dcf39a77280ca0bc96a8f7945708f52cded56ae0b8`
- `0x80000958` `a38a6800` `sb t1,0x15(a7)` → MEMORY_STORE, partial; unknown; `fwbehavior:f1d99cd88add1c3f24acfe286dce5f0f188ef9381f9ca2e39a411966e99cdbce`
- `0x80000960` `b31a1c02` `mulh s5,s8,ra` → UNKNOWN, unsupported; Unsupported mnemonic mulh; `fwbehavior:b0f6235c970d6c61d2b42ccc6756832139e6dc06a0c22f481032564f574b7732`
- `0x8000096c` `53fe03d0` `fcvt.s.w ft8,t2,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.w; `fwbehavior:ccf2d27425ec79030945bf3153f675674a83dd361e9673e4bbecc1d2c776a1b0`
- `0x80000970` `d301d1a0` `fle.s gp,ft2,fa3` → UNKNOWN, unsupported; Unsupported mnemonic fle.s; `fwbehavior:c117a5f61d9ae297e0a69e31170e17c496451cbb443d7080136f9527accc6104`
- `0x80000974` `bb6eff02` `remw t4,t5,a5` → UNKNOWN, unsupported; Unsupported mnemonic remw; `fwbehavior:deccc115e350c7e1f4e524bbd50c4aed18c2cc0f07208ab7422ef9b4072594ad`
- `0x80000978` `33f6f002` `remu a2,ra,a5` → UNKNOWN, unsupported; Unsupported mnemonic remu; `fwbehavior:94072ed8ea6f12ade9fe9c54fb9c55b50dee8cd9386552376dfed51b4853800f`
- `0x80000980` `b3c09003` `div ra,ra,s9` → UNKNOWN, unsupported; Unsupported mnemonic div; `fwbehavior:c3f10a58bfcfeec430b89dd5b25b919923c603dd3048d4d8d28c3c3eb13133c0`
- `0x80000994` `af2a06a1` `amomax.w s5,a6,(a2)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:84c1172ba5249ae1feb90b73db245afdb1c2bd251e1353799c3b116b2c0a64ab`
- `0x80000994` `af2a06a1` `amomax.w s5,a6,(a2)` → ATOMIC_STORE, partial; unknown; `fwbehavior:9bf29c193ff1c525514f3aa22b88e28c42e585a90cbfcb61b48b7ae12662b117`
- `0x80000998` `b3003e03` `mul ra,t3,s3` → UNKNOWN, unsupported; Unsupported mnemonic mul; `fwbehavior:2a859f7b0927e622a488868e8665a68f7a55050e9b397597eaecf65b8b45cce8`
- `0x8000099c` `33592d03` `divu s2,s10,s2` → UNKNOWN, unsupported; Unsupported mnemonic divu; `fwbehavior:d28f5b328fba2936d15765b5d515745f571647262a2f0f32d8bcea890ed3f3f2`
- `0x800009a0` `bbd4b802` `divuw s1,a7,a1` → UNKNOWN, unsupported; Unsupported mnemonic divuw; `fwbehavior:b6c29474442f2ab5a1bac2751012e16dcd657a314d8d7d2740fc38119b8cc9da`
- `0x800009a4` `c793fec1` `fmsub.s ft7,ft9,ft11,fs8,rtz` → UNKNOWN, unsupported; Unsupported mnemonic fmsub.s; `fwbehavior:ad78a44fad6315443b738cce114c4c7421ec64189a737eabd09f22f3d3428cd5`
- `0x800009a8` `d3133ed0` `fcvt.s.lu ft7,t3,rtz` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.lu; `fwbehavior:d9d20bc7992b2482d5637e7bae6749fd6681f8aaa78a85bf060a47b8a882184e`
- `0x800009b8` `2f285219` `sc.w a6,s5,(tp)` → ATOMIC_STORE, partial; unknown; `fwbehavior:b8e63ab8ce68d0316b52b01e32710d07c7f04f620dae4205b9a009bfda8e1783`
- `0x800009dc` `2f34b909` `amoswap.d s0,s11,(s2)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:846b1bf5634854b5e74db65a68d26fc2b65239fc84c048e95d0d70cacbd6648c`
- `0x800009dc` `2f34b909` `amoswap.d s0,s11,(s2)` → ATOMIC_STORE, partial; unknown; `fwbehavior:7ef0841badcc2228227e767e6fcffbcc0786ab54053a8a398653cacb5f50daa4`
- `0x800009e0` `437e11c0` `fmadd.s ft8,ft2,ft1,fs8,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fmadd.s; `fwbehavior:4f5ba3e4f8e469253a6ee0b1dbac57c05e687f4da4744bb6615ea39df872db23`
- `0x800009f0` `afbd68c0` `amominu.d s11,t1,(a7)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:0a00624b87bd69ef79fff963b33473d2850cd1eabcbfd8abeef18d4d61ba8afe`
- `0x800009f0` `afbd68c0` `amominu.d s11,t1,(a7)` → ATOMIC_STORE, partial; unknown; `fwbehavior:297468e4c6f8ef40d7ad77d410df6bc960d8a4b98583439d5ef5e197f5746b27`
- `0x80000a00` `afb2a720` `amoxor.d t0,a0,(a5)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:e6ee8b8bb1c2630793a4fd9469853733552e44e96169572efd4800743683e85c`
- `0x80000a00` `afb2a720` `amoxor.d t0,a0,(a5)` → ATOMIC_STORE, partial; unknown; `fwbehavior:9f65d5f7b87f6bdcba299bf59f3994c5ea06b3e5018892d4dea88baf08c8baef`
- `0x80000a10` `af3703a1` `amomax.d a5,a6,(t1)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:1c0697455b2be58d92d76fdc802259fe71b09491d09439c06e4285dea2837de1`
- `0x80000a10` `af3703a1` `amomax.d a5,a6,(t1)` → ATOMIC_STORE, partial; unknown; `fwbehavior:711f05f1fd8f63bbbcb321e361e868758c12dc7814b121146df1354e6928e80e`
- `0x80000a20` `af264541` `amoor.w a3,s4,(a0)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:6947d5ead96388949196925a4a19222646c5c24af0de7c0ddbfb3af524aa9934`
- `0x80000a20` `af264541` `amoor.w a3,s4,(a0)` → ATOMIC_STORE, partial; unknown; `fwbehavior:bdfa911818518e954d19af5e63c2fc4bbf41899604106736cf04f4b2982b87a7`
- `0x80000a3c` `53cf3fc0` `fcvt.lu.s t5,ft11,rmm` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.lu.s; `fwbehavior:589f95b8d9c99db4c69b89749f0924cdd4b90a0e65b27da9a3568695f348c08f`
- `0x80000a48` `83806700` `lb ra,0x6(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:9c8dd0c194748cb8301958368d140a017000264c378d0115a8985b9bbc49bc9a`
- `0x80000a4c` `b3c74003` `div a5,ra,s4` → UNKNOWN, unsupported; Unsupported mnemonic div; `fwbehavior:a27c220eebb04917bc28d125f57fb613d98d9b2704e993f5f6b7deb632507e56`
- `0x80000a5c` `d3a7e010` `fmul.s fa5,ft1,fa4,rdn` → UNKNOWN, unsupported; Unsupported mnemonic fmul.s; `fwbehavior:b38a515d93491da17a502a55b3e50b1879b2a8e1a38c144f4cf8ad913178ff51`
- `0x80000a60` `53945a28` `fmax.s fs0,fs5,ft5` → UNKNOWN, unsupported; Unsupported mnemonic fmax.s; `fwbehavior:22af9233c9a1d166755b136653446522b637927e713c14a113402d313e046ee5`
- `0x80000a64` `53036ba1` `fle.s t1,fs6,fs6` → UNKNOWN, unsupported; Unsupported mnemonic fle.s; `fwbehavior:c3fd8766fa1a5e98e827538b9a66c518757de95694e325e42a3c8592eb2a4e15`
- `0x80000a84` `731f3e00` `fscsr t5,t3` → UNKNOWN, unsupported; Unsupported mnemonic fscsr; `fwbehavior:f7af55cfeaada0f5b0fa7080cd16908435d167a6118a1329407c62059947bd05`
- `0x80000a9c` `8353cbff` `lhu t2,-0x4(s6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:7d9cec8bbbc09d4cdfd45138602a7315686e534cb1eaf7d210bb9ff8f2144036`
- `0x80000aa0` `d3a750a1` `feq.s a5,ft1,fs5` → UNKNOWN, unsupported; Unsupported mnemonic feq.s; `fwbehavior:25002cb442a094dcb65e6615c30a053637f3c5a71f479b57b7a4589e9478e495`
- `0x80000ab4` `af39fb40` `amoor.d s3,a5,(s6)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:f3a20bab8b9a007fe0a9c81ef37f4d6d17373d18cf3eeff230af9a1ce4fdbfa2`
- `0x80000ab4` `af39fb40` `amoor.d s3,a5,(s6)` → ATOMIC_STORE, partial; unknown; `fwbehavior:5c0be909ab46a7622a23e541724ad915a0a232db582d497e2d745e1dda96e15d`
- `0x80000abc` `539f7429` `fmax.s ft10,fs1,fs7` → UNKNOWN, unsupported; Unsupported mnemonic fmax.s; `fwbehavior:32a88a4acc455c85c04924e615e04f83427cb4cf7817256ad9e2026c75f5e095`
- `0x80000ac0` `b3279402` `mulhsu a5,s0,s1` → UNKNOWN, unsupported; Unsupported mnemonic mulhsu; `fwbehavior:f418e1d956edab65c249623a343d03904ebabe9df23ddde3bd56870825d9d1d1`
- `0x80000ac4` `534e0558` `fsqrt.s ft8,fa0,rmm` → UNKNOWN, unsupported; Unsupported mnemonic fsqrt.s; `fwbehavior:eeda62f680aa0e46c2922c3848bc4052388142649c8623b06fba735ce9679764`
- `0x80000ad0` `8360c300` `lwu ra,0xc(t1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ba1613ff12cd0120065677df29f5bed9a7f50f11d4fab3dfb43f91d951ff18b0`
- `0x80000ad8` `73000000` `ecall` → UNKNOWN, unsupported; Unsupported mnemonic ecall; `fwbehavior:50f2bab5c97f8bdecf6b55464c9d27da6b487ecae6472a5e2532cafc7a1741a5`
- `0x80000adc` `731000c0` `unimp` → UNKNOWN, unsupported; Unsupported mnemonic unimp; `fwbehavior:1345cbd5adfe68939d6222edec6a2cc811bf56581cf1aa181f6fd9a9cf6988a4`
- `0x80000ae0` `731000c0` `unimp` → UNKNOWN, unsupported; Unsupported mnemonic unimp; `fwbehavior:07081a49e3145b07a3025f15efa371aafc7ac76fa32504139ffa6b6173880219`

## 11. Provenance and Toolchain

Analysis `firmware-static:13b0933b79d5fd458b61ea5915e1517afc0f6ab2b7e09b2b6cc3443a252ecb96`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `RISCV:LE:64:default` 导出结构；每条指令 bytes 与 SHA256 为 `649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
