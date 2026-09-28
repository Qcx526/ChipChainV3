# Firmware Analysis Report

> 输入固件角色未分类；静态分析不证明客户固件具有相同指令行为。

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:fb40dd28d5bace9e7e1c7a44b51ef9a7feb26061d8bf358c80972361643b46bf` |
| architecture | `riscv` |
| bit_width | `64` |
| endianness | `little` |
| elf_sha256 | `9511f8db1e148d10cf103e0589564ce100c8d2168566c3642f36bba6ae4d9f2d` |
| arm_profile | `not applicable` |
| arm_cpu_name | `not established` |
| entry_address | `0x80000000` |
| function_count | `3` |
| basic_block_count | `135` |
| instruction_count | `522` |
| cfg_edge_count | `133` |
| direct_call_count | `2` |
| indirect_call_count | `0` |
| unresolved_call_count | `0` |
| memory_load_count | `37` |
| memory_store_count | `68` |
| mmio_read_count | `0` |
| mmio_write_count | `0` |
| system_register_read_count | `50` |
| system_register_write_count | `36` |
| barrier_count | `3` |
| atomic_count | `27` |
| tlb_invalidate_count | `1` |
| exception_return_count | `5` |
| unsupported_count | `122` |
| unresolved_address_count | `132` |
| ambiguous_ownership_count | `0` |
| ghidra_language | `RISCV:LE:64:default` |
| ghidra_version | `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` |
| producer | `{'analyzer': 'chipchain-general-firmware/v2', 'ghidra': '12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093', 'exporter_sha256': 'b006cc85631d9ef7f9232a03dbc05ce418296f885f427b9e2bd2762f46b9cbbe', 'semantics': 'chipchain-three-isa-semantics/r1', 'semantics_sha256': '0454ca318a5af7dd42e71e7f3b0e92f11424ffe035184b88f90d2ec92d3532ca'}` |

### Evidence-backed behavior examples

| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |
|---|---|---|---|---|---|---|---|
| `0x80000008` | `entry` | `ld ra,0x0(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:facc2eaa8f4d4b1968f884cd42cd8b4f0b012e617ec9af7ff9107307cabd91cd` | partial |
| `0x8000000c` | `entry` | `ld sp,0x8(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:b59c8dc65f16340f8337ab43d05a49f936ccf1736d62162703bed24d73b4f83b` | partial |
| `0x80000010` | `entry` | `ld gp,0x10(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:77a2d6882786ce6e12cb472e05111f9dc653d4365171ba572bc14cc6aae03bc3` | partial |
| `0x80000014` | `entry` | `ld tp,0x18(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:7b824ede6524e3c798c5c10ae87cce88c742eeef2def24bee8b5bef58d67e870` | partial |
| `0x80000018` | `entry` | `ld t0,0x20(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:8e63f804f2f5b9dc68ce3553a3f8c2a1ab2ced02ad16e74b0d5ac2f627cf297c` | partial |
| `0x8000001c` | `entry` | `ld t1,0x28(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:81d8f6858000eb5cd852a701a48a98f670ef5e64d66a6c558d41469321c5c703` | partial |
| `0x80000020` | `entry` | `ld t2,0x30(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:ce51a9216808ab583acf03ea1337d013b0e9a4c2ddfbb5e209b243ac08d566b5` | partial |
| `0x80000024` | `entry` | `ld s0,0x38(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:f754d627cc7965d5629fb9426da0f434a1724f6e8f03c4ce477bb1228738ca08` | partial |
| `0x80000028` | `entry` | `ld s1,0x40(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:6a391e9e0e10148870dc7f5570c31c67958162b04734949fee0465c4d07f014b` | partial |
| `0x8000002c` | `entry` | `ld a0,0x48(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:c01c53f7f1a8079e96cff43d6d022e0d7f51649b877c4ffd36f86cac16e7e34a` | partial |
| `0x80000030` | `entry` | `ld a1,0x50(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:0b05fdde57d4d64d4ee81eb03a75df291f5e0da543ca8494097a0d15eb005ceb` | partial |
| `0x80000034` | `entry` | `ld a2,0x58(t6)` | MEMORY_LOAD | not established | not established | `fwbehavior:307029a15ca2f8bfb4fb8fca9beb9c30b271a8ee5d2e691f301a1289b1fb7e75` | partial |

## 2. Binary / Architecture Identity

ELF SHA256 `9511f8db1e148d10cf103e0589564ce100c8d2168566c3642f36bba6ae4d9f2d`；RISCV 64-bit little；入口 `0x80000000`。
PT_LOAD 段 8 个；节 14 个。

## 3. Program Structure

识别 3 个函数、135 个基本块、522 条指令和 133 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x80000000` | `entry` | 0x80000000–0x80000087 | `fwfunction:20bff442ae1f4f6ccada38475ee8a38ba514db8865ba597378b053b950abff6a` |
| `0x80000088` | `init_freg` | 0x80000088–0x80000113 | `fwfunction:1d8b86d29ee1112c9b27c29cab8a63bf1c5a7cfa051d913e561ce6fee0444dfb` |
| `0x8000035c` | `reset_vector` | 0x8000035c–0x8000045b | `fwfunction:0e607477c039795a1173ce85311f4bf2464716b638293ddb74668147991b0721` |

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
| `0x80000418` | `0x80000443` | 1 | 1 |
| `0x80000444` | `0x80000447` | 1 | 1 |
| `0x80000448` | `0x8000045b` | 1 | 0 |
| `0x80000480` | `0x80000483` | 0 | 1 |
| `0x80000484` | `0x8000048f` | 0 | 1 |
| `0x80000490` | `0x80000493` | 0 | 1 |
| `0x80000494` | `0x800004a3` | 0 | 1 |
| `0x800004a4` | `0x800004a7` | 0 | 1 |
| `0x800004a8` | `0x800004b7` | 0 | 1 |
| `0x800004b8` | `0x800004bb` | 0 | 1 |
| `0x800004bc` | `0x800004bf` | 0 | 1 |
| `0x800004c0` | `0x800004c3` | 0 | 1 |
| `0x800004c4` | `0x800004c7` | 0 | 1 |
| `0x800004c8` | `0x800004d7` | 0 | 1 |
| `0x800004d8` | `0x800004e7` | 0 | 1 |
| `0x800004e8` | `0x800004f3` | 0 | 1 |
| `0x800004f4` | `0x800004f7` | 0 | 1 |
| `0x800004f8` | `0x800004fb` | 0 | 1 |
| `0x800004fc` | `0x80000507` | 0 | 1 |
| `0x80000508` | `0x8000050b` | 0 | 1 |
| `0x8000050c` | `0x80000517` | 0 | 1 |
| `0x80000518` | `0x8000051b` | 0 | 1 |
| `0x8000051c` | `0x80000527` | 0 | 1 |
| `0x80000528` | `0x80000537` | 0 | 1 |
| `0x80000538` | `0x8000053b` | 0 | 1 |
| `0x8000053c` | `0x8000054b` | 0 | 0 |
| `0x8000054c` | `0x8000054f` | 0 | 1 |
| `0x80000550` | `0x8000055b` | 0 | 1 |
| `0x8000055c` | `0x8000055f` | 0 | 1 |
| `0x80000560` | `0x80000563` | 0 | 1 |
| `0x80000564` | `0x80000567` | 0 | 1 |
| `0x80000568` | `0x80000593` | 0 | 1 |
| `0x80000594` | `0x80000597` | 0 | 1 |
| `0x80000598` | `0x800005a3` | 0 | 1 |
| `0x800005a4` | `0x800005ab` | 0 | 1 |
| `0x800005ac` | `0x800005af` | 0 | 1 |
| `0x800005b0` | `0x800005b3` | 0 | 1 |
| `0x800005b4` | `0x800005b7` | 0 | 1 |
| `0x800005b8` | `0x800005bf` | 0 | 1 |
| `0x800005c0` | `0x800005cb` | 0 | 1 |
| `0x800005cc` | `0x800005db` | 0 | 0 |
| `0x8000065c` | `0x8000065f` | 0 | 1 |
| `0x80000660` | `0x80000663` | 0 | 1 |
| `0x80000664` | `0x80000667` | 0 | 1 |
| `0x80000668` | `0x8000066b` | 0 | 1 |
| `0x8000066c` | `0x8000066f` | 0 | 1 |
| `0x80000670` | `0x80000673` | 0 | 1 |
| `0x80000674` | `0x80000677` | 0 | 2 |
| `0x80000678` | `0x8000067b` | 0 | 1 |
| `0x8000067c` | `0x8000068b` | 0 | 1 |
| `0x8000068c` | `0x8000068f` | 0 | 1 |
| `0x80000690` | `0x80000693` | 0 | 1 |
| `0x80000694` | `0x80000697` | 0 | 1 |
| `0x80000698` | `0x8000069b` | 0 | 1 |
| `0x8000069c` | `0x8000069f` | 0 | 1 |
| `0x800006a0` | `0x800006a3` | 0 | 1 |
| `0x800006a4` | `0x800006b7` | 0 | 1 |
| `0x800006b8` | `0x800006bb` | 0 | 1 |
| `0x800006bc` | `0x800006bf` | 0 | 1 |
| `0x800006c0` | `0x800006c3` | 0 | 1 |
| `0x800006c4` | `0x800006c7` | 0 | 1 |
| `0x800006c8` | `0x800006db` | 0 | 1 |
| `0x800006dc` | `0x800006e7` | 0 | 1 |
| `0x800006e8` | `0x800006eb` | 0 | 1 |
| `0x800006ec` | `0x800006ef` | 0 | 1 |
| `0x800006f0` | `0x800006f3` | 0 | 1 |
| `0x800006f4` | `0x80000703` | 0 | 0 |
| `0x80000704` | `0x80000707` | 0 | 1 |
| `0x80000708` | `0x8000070b` | 0 | 1 |
| `0x8000070c` | `0x8000070f` | 0 | 1 |
| `0x80000710` | `0x8000071f` | 0 | 1 |
| `0x80000720` | `0x80000723` | 0 | 1 |
| `0x8000075c` | `0x8000075f` | 0 | 1 |
| `0x80000760` | `0x80000763` | 0 | 1 |
| `0x80000764` | `0x80000773` | 0 | 1 |
| `0x80000774` | `0x80000777` | 0 | 1 |
| `0x80000778` | `0x80000787` | 0 | 1 |
| `0x80000788` | `0x8000078b` | 0 | 1 |
| `0x8000078c` | `0x8000078f` | 0 | 1 |
| `0x80000790` | `0x80000793` | 0 | 1 |
| `0x80000794` | `0x800007a3` | 0 | 1 |
| `0x800007a4` | `0x800007a7` | 0 | 1 |
| `0x800007a8` | `0x800007c7` | 0 | 1 |
| `0x800007c8` | `0x800007d7` | 0 | 1 |
| `0x800007d8` | `0x800007e7` | 0 | 1 |
| `0x800007e8` | `0x800007eb` | 0 | 1 |
| `0x800007ec` | `0x800007f7` | 0 | 1 |
| `0x800007f8` | `0x800007fb` | 0 | 1 |
| `0x800007fc` | `0x800007ff` | 0 | 1 |
| `0x80000800` | `0x80000803` | 0 | 1 |
| `0x80000804` | `0x80000817` | 0 | 1 |
| `0x80000818` | `0x8000081b` | 0 | 1 |
| `0x8000081c` | `0x8000081f` | 0 | 1 |
| `0x80000820` | `0x8000082b` | 0 | 1 |
| `0x8000082c` | `0x8000082f` | 0 | 1 |
| `0x80000830` | `0x80000833` | 0 | 1 |
| `0x80000834` | `0x80000837` | 0 | 1 |
| `0x80000838` | `0x8000083b` | 0 | 1 |
| `0x8000083c` | `0x8000083f` | 0 | 1 |
| `0x80000840` | `0x80000843` | 0 | 1 |
| `0x80000844` | `0x80000847` | 0 | 1 |
| `0x80000848` | `0x80000853` | 0 | 1 |
| `0x80000854` | `0x80000857` | 0 | 1 |
| `0x80000858` | `0x80000867` | 0 | 1 |
| `0x80000868` | `0x80000873` | 0 | 1 |
| `0x80000874` | `0x80000877` | 0 | 1 |
| `0x80000878` | `0x8000087b` | 0 | 1 |
| `0x8000087c` | `0x8000087f` | 0 | 2 |
| `0x80000880` | `0x80000883` | 0 | 1 |
| `0x80000884` | `0x80000887` | 0 | 1 |
| `0x80000888` | `0x80000897` | 0 | 1 |
| `0x80000898` | `0x800008a3` | 0 | 1 |
| `0x800008a4` | `0x800008bb` | 0 | 1 |
| `0x800008bc` | `0x800008cb` | 0 | 0 |
| `0x800008f8` | `0x80000903` | 0 | 1 |
| `0x80000904` | `0x80000907` | 0 | 1 |
| `0x80000908` | `0x8000090b` | 0 | 2 |
| `0x8000090c` | `0x8000090f` | 0 | 1 |
| `0x80000910` | `0x80000923` | 0 | 1 |
| `0x80000924` | `0x8000092b` | 0 | 0 |
| `0x8000092c` | `0x8000092f` | 0 | 0 |

## 6. Call Analysis

| 调用点 | 类型 | 目标 | 解析状态 |
|---|---|---|---|
| `0x80000084` | direct | 0x8000035c | resolved |
| `0x8000040c` | direct | 0x80000088 | resolved |

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
| `0x800004a0` | `amomax.d t3,s9,(t3)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800004a0` | `amomax.d t3,s9,(t3)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800004b4` | `amoadd.w gp,t5,(gp)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800004b4` | `amoadd.w gp,t5,(gp)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800004d4` | `amoadd.w a4,s3,(s1)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800004d4` | `amoadd.w a4,s3,(s1)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800004e4` | `amoor.d a0,s2,(a6)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800004e4` | `amoor.d a0,s2,(a6)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800004f0` | `sd s7,0x0(t3)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000514` | `lbu s8,0x1f(t4)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000534` | `amoand.d t3,s3,(s7)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000534` | `amoand.d t3,s3,(s7)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000558` | `sb s0,-0x1f(s4)` | MEMORY_STORE | unknown | not established | partial |
| `0x800005c8` | `sd t4,-0x8(gp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000688` | `amoadd.d s3,a4,(tp)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000688` | `amoadd.d s3,a4,(tp)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800006b4` | `lwu a6,-0x18(a6)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000071c` | `amominu.w s0,t4,(s7)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x8000071c` | `amominu.w s0,t4,(s7)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000770` | `amomax.d s5,s10,(a3)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000770` | `amomax.d s5,s10,(a3)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000784` | `amoswap.d s2,s3,(s8)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000784` | `amoswap.d s2,s3,(s8)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800007a0` | `amoand.w t5,ra,(t4)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800007a0` | `amoand.w t5,ra,(t4)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800007e4` | `lr.d s3,(a4)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000828` | `lh a7,0x4(s1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000850` | `sb s4,0xa(ra)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000864` | `amoadd.d a6,sp,(s10)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000864` | `amoadd.d a6,sp,(s10)` | ATOMIC_STORE | unknown | not established | partial |
| `0x80000870` | `lwu s8,0x0(t4)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000894` | `amoor.w s11,t5,(a7)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x80000894` | `amoor.w s11,t5,(a7)` | ATOMIC_STORE | unknown | not established | partial |
| `0x800008a0` | `lbu s3,0x1f(s4)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800008b8` | `amoswap.d s7,tp,(t4)` | ATOMIC_LOAD | unknown | not established | partial |
| `0x800008b8` | `amoswap.d s7,tp,(t4)` | ATOMIC_STORE | unknown | 4292870144 | partial |
| `0x80000900` | `lbu a2,-0x1d(a7)` | MEMORY_LOAD | unknown | not established | partial |

## 8. Hardware-facing Behaviors

当前分析没有硬件资源目录，MMIO 计数为 0。已解析内存地址仍需资源绑定，才能被解释为硬件寄存器访问。

## 9. System/Register/Barrier/Atomic Behaviors

| PC | 所属函数 | 指令 | 行为 | 寄存器 | 证据 ID |
|---|---|---|---|---|---|
| `0x80000120` | `unresolved` | `csrr sp,0x0100` | SYSTEM_REGISTER_READ | 0x0100 | `fwbehavior:dddfc8984b335114d964282b5db770fd6a1e6df8a9681b307c711132d3588e3b` |
| `0x80000128` | `unresolved` | `csrr sp,0x0104` | SYSTEM_REGISTER_READ | 0x0104 | `fwbehavior:3a42896c59abaf8ba6a60e8de9452a56177ac94320e368f52dc3908da7e88aee` |
| `0x80000130` | `unresolved` | `csrr sp,0x0105` | SYSTEM_REGISTER_READ | 0x0105 | `fwbehavior:989fc5d4fd4a7d0a44b077d8218b10174ce95aea60ffa2c2b3eef3234ac84d78` |
| `0x80000138` | `unresolved` | `csrr sp,0x0106` | SYSTEM_REGISTER_READ | 0x0106 | `fwbehavior:318997ad4f81c59eb55a909d091735fecced78028704cb3eb09dbc7453d6b029` |
| `0x80000140` | `unresolved` | `csrr sp,0x0140` | SYSTEM_REGISTER_READ | 0x0140 | `fwbehavior:36b5f963fe7384c3ca31ab458d84fec3522b477b4a747b9e65b227934197b7a7` |
| `0x80000148` | `unresolved` | `csrr sp,sepc` | SYSTEM_REGISTER_READ | sepc | `fwbehavior:c243c3c679370a99a22b9ea3b0367f0d9ea82b673e96ec44b5a76555800ea315` |
| `0x80000150` | `unresolved` | `csrr sp,0x0142` | SYSTEM_REGISTER_READ | 0x0142 | `fwbehavior:ab6c9f784615cb87d3a7f8d859aeef9fde61a132033f6b0d9be5e0261222a9c4` |
| `0x80000158` | `unresolved` | `csrr sp,0x0143` | SYSTEM_REGISTER_READ | 0x0143 | `fwbehavior:3661d9c5b0d66f1faaff3d9ae0f1a4f7be6707688516bb2d447873009382799c` |
| `0x80000160` | `unresolved` | `csrr sp,0x0144` | SYSTEM_REGISTER_READ | 0x0144 | `fwbehavior:f9a76e5e1e184b1328447018c7056f8b7134360baa3053613307925eeef3b651` |
| `0x8000016c` | `unresolved` | `csrr sp,0x0180` | SYSTEM_REGISTER_READ | 0x0180 | `fwbehavior:bbfb1a48ab2d0932e5f0f37e5b9d32ca2eef6e80151220eff32571f9409375da` |
| `0x80000174` | `unresolved` | `csrr sp,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | `fwbehavior:c236a911c4c109a03f163b6de2f4f498585349e041193245dd7fcacc7c16a858` |
| `0x8000017c` | `unresolved` | `csrr sp,0x0300` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:a44f83e853b6915dc64b98280f940360dfd27c8b01e37fc8ca0e43f4b5a2d9d9` |
| `0x80000184` | `unresolved` | `csrr sp,0x0302` | SYSTEM_REGISTER_READ | 0x0302 | `fwbehavior:76a96e33f3ba57de2355baa50fa8f21f0a4032160af1d5b181b809ee362ee48a` |
| `0x8000018c` | `unresolved` | `csrr sp,0x0303` | SYSTEM_REGISTER_READ | 0x0303 | `fwbehavior:e16ca7e48d3598b866b51a6552e27633c594918a28224d38cf142051214cd4f4` |
| `0x80000194` | `unresolved` | `csrr sp,0x0304` | SYSTEM_REGISTER_READ | 0x0304 | `fwbehavior:518a4f79c95d82bbca0c5295db9ca75b90d9612b95665adb970508e3bf2c7551` |
| `0x8000019c` | `unresolved` | `csrr sp,0x0305` | SYSTEM_REGISTER_READ | 0x0305 | `fwbehavior:c86a42ebbd9c07bdf9253ddd8efc1517825588c83ec1e953d1af82f324faea62` |
| `0x800001a4` | `unresolved` | `csrr sp,0x0306` | SYSTEM_REGISTER_READ | 0x0306 | `fwbehavior:6985dab9f65881daeaa3d558ee4339240d174936acba1c03c8aa87125af0787c` |
| `0x800001ac` | `unresolved` | `csrr sp,0x0340` | SYSTEM_REGISTER_READ | 0x0340 | `fwbehavior:daf4bb4ca1eb2b28e2f336643395583aa9054bdf8805f556cfffa520acfbe909` |
| `0x800001b4` | `unresolved` | `csrr sp,mepc` | SYSTEM_REGISTER_READ | mepc | `fwbehavior:7d83baf5d9e95cb248d223350b87b5aae5b03c52990774edde3f95fb361e17c8` |
| `0x800001bc` | `unresolved` | `csrr sp,0x0342` | SYSTEM_REGISTER_READ | 0x0342 | `fwbehavior:bcfddedcc6566034fd2b53d979fafb3816c5eb60f86604710ccd406db73daf61` |
| `0x800001c4` | `unresolved` | `csrr sp,0x0343` | SYSTEM_REGISTER_READ | 0x0343 | `fwbehavior:af54d12e187fa6d5c47496521d851b78e7f6f85fe67025ffafde64ac0fa2106a` |
| `0x800001cc` | `unresolved` | `csrr sp,0x0344` | SYSTEM_REGISTER_READ | 0x0344 | `fwbehavior:eb394d44b61255af1452ec9a249f16bdc78a0198a41d33abdfc13466f694d37a` |
| `0x800001d8` | `unresolved` | `csrr sp,0x03a0` | SYSTEM_REGISTER_READ | 0x03a0 | `fwbehavior:1a218a8375d0d54fe7150efbf186a00b622bd0a054a50b94611f9e47d26c0ca1` |
| `0x800001e0` | `unresolved` | `csrr sp,0x03b0` | SYSTEM_REGISTER_READ | 0x03b0 | `fwbehavior:003bf517f0671cbedba6ee675a5559ac9f35367910a4592c8fdd20ec5c53279f` |
| `0x800001e8` | `unresolved` | `csrr sp,0x03b1` | SYSTEM_REGISTER_READ | 0x03b1 | `fwbehavior:f9ced000ad66747cec8d2da9e5caa744ee51a1b9ba345a86eeb4e174a41a6267` |
| `0x800001f0` | `unresolved` | `csrr sp,0x03b2` | SYSTEM_REGISTER_READ | 0x03b2 | `fwbehavior:1b3aba98051d83f6ee6b92d5e044469b8748905aae5ec9e72b1b5d80123d52ce` |
| `0x800001f8` | `unresolved` | `csrr sp,0x03b3` | SYSTEM_REGISTER_READ | 0x03b3 | `fwbehavior:f66b47572d74d8281e7fcc7359014f7930a20c972e69a2bab336b0cd40ea877c` |
| `0x80000200` | `unresolved` | `csrr sp,0x03b4` | SYSTEM_REGISTER_READ | 0x03b4 | `fwbehavior:32da788f5a59e7874315015a526b0c3c17db50ef6c1858857bd2cfefe34a04b2` |
| `0x80000208` | `unresolved` | `csrr sp,0x03b5` | SYSTEM_REGISTER_READ | 0x03b5 | `fwbehavior:e5043d556ef30533233a8c019039fde6de1aeadc1bc63d6c32f226d8e4bb62c8` |
| `0x80000210` | `unresolved` | `csrr sp,0x03b6` | SYSTEM_REGISTER_READ | 0x03b6 | `fwbehavior:2fec4234b80e5a8ab571e132efd1e6a67e066d030a5cb2c7d4243a216e0373f6` |
| `0x80000218` | `unresolved` | `csrr sp,0x03b7` | SYSTEM_REGISTER_READ | 0x03b7 | `fwbehavior:9079e5c908c9a0db28c59e72647270f9efdeb7c4409d832909cfb3cf80ddfa8b` |
| `0x80000224` | `unresolved` | `csrs 0x0300,a0` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:19b0a7db8ba5741b57a8729aadec6279eeb38ef395b7d1c98192f29052a1d66f` |
| `0x80000224` | `unresolved` | `csrs 0x0300,a0` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:f40c665f01cf6eda12870c0ab629388f6611f0da682130815338d5d6a2f89472` |
| `0x8000035c` | `reset_vector` | `csrwi 0x0300,0x0` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:9a8b3290d3cfd50b9081012401ddf1f2bda3446dd5192cb148347cf1ac2842a6` |
| `0x80000360` | `reset_vector` | `csrr a0,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | `fwbehavior:40964d5c3bf862109afea4bc581e1720984463a8d03a2694c9cb7cfdeb12c3bb` |
| `0x80000370` | `reset_vector` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:3ef701b76a1f54558bfd1ff3f8626d32a82e4b8b303d62a2b875542138bb1338` |
| `0x80000374` | `reset_vector` | `csrwi 0x0302,0x0` | SYSTEM_REGISTER_WRITE | 0x0302 | `fwbehavior:5e00c64ea416b7281f9e1afeb1a56b649428f66c23f2884275e8a5ba13748833` |
| `0x80000378` | `reset_vector` | `csrwi 0x0303,0x0` | SYSTEM_REGISTER_WRITE | 0x0303 | `fwbehavior:4046a556905cb153b7ce5548d8e8316047f81dbd9a40fef2de55b7df27e67d56` |
| `0x8000037c` | `reset_vector` | `csrwi 0x0304,0x0` | SYSTEM_REGISTER_WRITE | 0x0304 | `fwbehavior:e1e0ef9fb2460e61c4ddf2fb2212c5d2e4bf07ff6591529b21e2c61efae49acd` |
| `0x80000388` | `reset_vector` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:aa87d5247283db25a49b06c5cb6c63b8fce99b7018897b2354f345d260fba5f5` |
| `0x8000038c` | `reset_vector` | `csrwi 0x0180,0x0` | SYSTEM_REGISTER_WRITE | 0x0180 | `fwbehavior:b4822795e40cc32efb4dceac0f481f260038d3facaa400a38e47df436390eec5` |
| `0x80000398` | `reset_vector` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:998367a59eb6f592a5b676b5abf7807a70a07ae6e5f2f0cdb3ddf76eda398711` |
| `0x800003a8` | `reset_vector` | `csrw 0x03b0,t0` | SYSTEM_REGISTER_WRITE | 0x03b0 | `fwbehavior:bcfd64715f95c342330c918613c6f9c95ac90364671c9ff4cd34f54a040a98bf` |
| `0x800003b0` | `reset_vector` | `csrw 0x03a0,t0` | SYSTEM_REGISTER_WRITE | 0x03a0 | `fwbehavior:4ad650e0fde090476dd2327eed8a8eb010cfd503b1b335cf938124afa79cfcef` |
| `0x800003bc` | `reset_vector` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:c46c586aa9d04f93e702b72aa85bc546668586e6f6b75ac351a8f9a41b5f6777` |
| `0x800003d0` | `reset_vector` | `fence 0xf,0xf` | MEMORY_BARRIER | — | `fwbehavior:562ede0ae509bda90929afdd661b3ef3517a3d51de0b869d2c0c75cc359ff353` |
| `0x800003ec` | `reset_vector` | `csrw 0x0105,t0` | SYSTEM_REGISTER_WRITE | 0x0105 | `fwbehavior:fb01ee95f2a47979158f33ae863acd1672b277ccb106660d91227e17124da708` |
| `0x800003f8` | `reset_vector` | `csrs 0x0302,t0` | SYSTEM_REGISTER_READ | 0x0302 | `fwbehavior:20a721ce44574c35f05d314704a809f215cdbe98bc36813534c0d52d25f69f03` |
| `0x800003f8` | `reset_vector` | `csrs 0x0302,t0` | SYSTEM_REGISTER_WRITE | 0x0302 | `fwbehavior:19772db202caf9ca7d3277e4356ddbcf4431ac52c5018952496f9db5aa2a97c9` |
| `0x80000404` | `reset_vector` | `csrs 0x0300,a0` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:4dadf4139b7dbf0bbc68d6f49bc0c70f82dfd46511746c83f58fc77ad5a6203c` |
| `0x80000404` | `reset_vector` | `csrs 0x0300,a0` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:e1fcdf31894752fee4332d26f71603e75edbf2e5840539018e4c0c4a52cbacca` |
| `0x80000408` | `reset_vector` | `csrwi fcsr,0x0` | SYSTEM_REGISTER_WRITE | fcsr | `fwbehavior:e1f5498dccc14adb578c3e1bcf1f2a396e4e4143468223691955c32e21b94b16` |
| `0x80000410` | `reset_vector` | `csrw 0x0b02,zero` | SYSTEM_REGISTER_WRITE | 0x0b02 | `fwbehavior:745cbd9d5ba1fa142999b82d96aaa3faaba8198a6821bd617023ec23bfa7a1fd` |
| `0x80000414` | `reset_vector` | `csrr a0,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | `fwbehavior:70fd964fd4c57d72ae4860468e664843653043736d4016cc763bf21b837c3ed9` |
| `0x80000440` | `reset_vector` | `csrrc a3,fcsr,a3` | SYSTEM_REGISTER_READ | fcsr | `fwbehavior:018c94928a3e0244b4d83509858a67e3ff9f18807eadfb373b3fb20754af4bc9` |
| `0x80000440` | `reset_vector` | `csrrc a3,fcsr,a3` | SYSTEM_REGISTER_WRITE | fcsr | `fwbehavior:ca4a59f9f575917aa1a114a9b3075e7352fc4b51638d4f83c9dc14627936e343` |
| `0x80000444` | `reset_vector` | `csrrwi a3,0x0302,0x1f` | SYSTEM_REGISTER_READ | 0x0302 | `fwbehavior:50b05f0e7146b8fb415296ede927b2f0c2e86f369a8ab63999f91c01cec4a63a` |
| `0x80000444` | `reset_vector` | `csrrwi a3,0x0302,0x1f` | SYSTEM_REGISTER_WRITE | 0x0302 | `fwbehavior:89eee71425f008ecd00f30413ad0a5cc10486d4fc460238b7fe5e720b59e0fbf` |
| `0x80000450` | `reset_vector` | `csrw mepc,t0` | SYSTEM_REGISTER_WRITE | mepc | `fwbehavior:acfe7b2dd32ac681083cc02f3be605808515777628b2ff7de43fe20f91c8a05d` |
| `0x80000458` | `reset_vector` | `mret` | EXCEPTION_RETURN | — | `fwbehavior:14117b508aea0f851ea29ef673729800d3562df658610ad0b1e94d1703049e42` |
| `0x800004a0` | `unresolved` | `amomax.d t3,s9,(t3)` | ATOMIC_LOAD | — | `fwbehavior:66eae8b307dd58fc4240f12adaa2687978d2610f8bb12c8da1399d99eba328bc` |
| `0x800004a0` | `unresolved` | `amomax.d t3,s9,(t3)` | ATOMIC_STORE | — | `fwbehavior:7379a2ddbc2edde10713362cefc6d48ddbea2b3724a00c91764e5da3fb47865e` |
| `0x800004b4` | `unresolved` | `amoadd.w gp,t5,(gp)` | ATOMIC_LOAD | — | `fwbehavior:6b4799ae97b87a2209dd3157041c0bb002d46c294058835f76c21de4424c90c1` |
| `0x800004b4` | `unresolved` | `amoadd.w gp,t5,(gp)` | ATOMIC_STORE | — | `fwbehavior:0f45ce53fd2cd7ac6e2e958902a20d62cb111ccbeea540fe2d634fc2e1ab0853` |
| `0x800004d4` | `unresolved` | `amoadd.w a4,s3,(s1)` | ATOMIC_LOAD | — | `fwbehavior:a9a3d7e47c18b2a2bca752d5c4e37446c03c2b62aef33f6fdc44995a0426b230` |
| `0x800004d4` | `unresolved` | `amoadd.w a4,s3,(s1)` | ATOMIC_STORE | — | `fwbehavior:8bbad71278b68a40dc237028cccc16e33c1b1e307d148f3037d8d1d7bc51fde4` |
| `0x800004e4` | `unresolved` | `amoor.d a0,s2,(a6)` | ATOMIC_LOAD | — | `fwbehavior:127051e0926c66ebdc2c79c6be332564bbfc9d4336352f5d479845383713ea67` |
| `0x800004e4` | `unresolved` | `amoor.d a0,s2,(a6)` | ATOMIC_STORE | — | `fwbehavior:1f3ee5683076383a70e96628da1393c485ea9596792274cd11711e25e1e528cf` |
| `0x800004f4` | `unresolved` | `csrrci a7,0x03b0,0x1f` | SYSTEM_REGISTER_READ | 0x03b0 | `fwbehavior:cd5d313ea905db7fdc10d81692e4bd98809bf6fe79e696cf469f90e299c79304` |
| `0x800004f4` | `unresolved` | `csrrci a7,0x03b0,0x1f` | SYSTEM_REGISTER_WRITE | 0x03b0 | `fwbehavior:2fb767aceee6caf13471cd7a33e575ebe47e5f0daf2bcafdabc373b460b773f8` |
| `0x80000534` | `unresolved` | `amoand.d t3,s3,(s7)` | ATOMIC_LOAD | — | `fwbehavior:b1d03842058b8527fcf96853680920aa6c91a9010edc086513a71eae12301a18` |
| `0x80000534` | `unresolved` | `amoand.d t3,s3,(s7)` | ATOMIC_STORE | — | `fwbehavior:d777a4cada9704dc1f412be931e8b46e5ef5ab6f71af20a62997aee68562c66c` |
| `0x80000544` | `unresolved` | `csrw mepc,a3` | SYSTEM_REGISTER_WRITE | mepc | `fwbehavior:8425a0bbd16f4d4af20b863aa373b4ab84e7279b20b75230e60d1bfc6eb6c367` |
| `0x80000548` | `unresolved` | `mret` | EXCEPTION_RETURN | — | `fwbehavior:c2227f5472121f6f93248c9de493fe20ca73e7b5c1d6de59d46bb885b1e9f76d` |
| `0x80000560` | `unresolved` | `csrrci ra,0x0105,0x1f` | SYSTEM_REGISTER_READ | 0x0105 | `fwbehavior:092f8c203ea9d99fb234e67b2a4cd0d1e2fe0f5d1f59355c0a5b88ef1a12cb5f` |
| `0x80000560` | `unresolved` | `csrrci ra,0x0105,0x1f` | SYSTEM_REGISTER_WRITE | 0x0105 | `fwbehavior:02b9e8988f4c2ecdc48d0881d60c97411b4bfb719df65034f36efec85f128479` |
| `0x80000590` | `unresolved` | `csrrc t2,0x0306,t1` | SYSTEM_REGISTER_READ | 0x0306 | `fwbehavior:efc62ce49db9d2a9b3710f603ec0869efa156603bb2375d523bd00cbd400f089` |
| `0x80000590` | `unresolved` | `csrrc t2,0x0306,t1` | SYSTEM_REGISTER_WRITE | 0x0306 | `fwbehavior:06a6749cbfcfd76c535e059b744669f03cc834e51a6aadaa71200bce4a5eec91` |
| `0x800005a8` | `unresolved` | `csrrc a1,0x0b00,sp` | SYSTEM_REGISTER_READ | 0x0b00 | `fwbehavior:d0725fddeec65494cf67d5f1de02624734fc191a59b2d8335f850fdd7a525b26` |
| `0x800005a8` | `unresolved` | `csrrc a1,0x0b00,sp` | SYSTEM_REGISTER_WRITE | 0x0b00 | `fwbehavior:bdc98f40c55bffe465f44cff7f50c65b3b58695031169d273010e023c09d41fb` |
| `0x800005b0` | `unresolved` | `fence.i` | INSTRUCTION_BARRIER | — | `fwbehavior:7b61ccedaa8cada905283034ed87298f9de57dc46751e02558a28d4bc03d06f0` |
| `0x800005d4` | `unresolved` | `csrw sepc,a7` | SYSTEM_REGISTER_WRITE | sepc | `fwbehavior:4d4030747aba3db0392bd1d408de341cba1184f04cbb84094879f6afa0ef40fc` |
| `0x800005d8` | `unresolved` | `sret` | EXCEPTION_RETURN | — | `fwbehavior:bcb69e729e1b54f860c34cf8f364556c2ee6945f84d0a7f03e2e85612cb54e7f` |
| `0x80000670` | `unresolved` | `csrrwi s11,0x0143,0x7` | SYSTEM_REGISTER_READ | 0x0143 | `fwbehavior:a2047c0d224cc6c7d411bd2f3abb76ce810d9e6bf43cd753d4734cdc99220a73` |
| `0x80000670` | `unresolved` | `csrrwi s11,0x0143,0x7` | SYSTEM_REGISTER_WRITE | 0x0143 | `fwbehavior:5d915412af5e95c5ad360cdf43d362e5d2317e51b8b14f00431b359ef5d3f11c` |
| `0x80000688` | `unresolved` | `amoadd.d s3,a4,(tp)` | ATOMIC_LOAD | — | `fwbehavior:55b5fbf5fe4fa75db4825ffff4ded3ec4c8a7ada55074cb2894f3d381ed9ae8f` |
| `0x80000688` | `unresolved` | `amoadd.d s3,a4,(tp)` | ATOMIC_STORE | — | `fwbehavior:18495e12e47a6dfcc6bdbac17679014ed327f2989e57b42aba7e5155e5831000` |
| `0x80000690` | `unresolved` | `csrrwi s0,0x0343,0x0` | SYSTEM_REGISTER_READ | 0x0343 | `fwbehavior:dccaf17c793ffef79ff5ec922b8c7534cd691afb926fa729db911cb384b28ab2` |
| `0x80000690` | `unresolved` | `csrrwi s0,0x0343,0x0` | SYSTEM_REGISTER_WRITE | 0x0343 | `fwbehavior:0328f3aed35bc2d9b92ceb5c06c445a40a9fb2b70263853d2a4770791eb58e29` |
| `0x800006d8` | `unresolved` | `csrrw s4,0x0142,s8` | SYSTEM_REGISTER_READ | 0x0142 | `fwbehavior:bcea178791170e1646dcb1f0565e0f3bb59f748124d7832fa143412c8b24b1fd` |
| `0x800006d8` | `unresolved` | `csrrw s4,0x0142,s8` | SYSTEM_REGISTER_WRITE | 0x0142 | `fwbehavior:e5acd1967d1ef990d3a14cf261bd78c14107a37a48644e38e50740808bd0bc2c` |
| `0x800006e8` | `unresolved` | `csrrwi t0,mepc,0x1f` | SYSTEM_REGISTER_READ | mepc | `fwbehavior:5753f4e69e4f1231c236c90e0271a89c56951465fd3d549fd3e6c128c285912b` |
| `0x800006e8` | `unresolved` | `csrrwi t0,mepc,0x1f` | SYSTEM_REGISTER_WRITE | mepc | `fwbehavior:186134098cb9e807f67727d7e0bf6e76e844561283ec57a85eaa0472e8d27981` |
| `0x800006fc` | `unresolved` | `csrw sepc,a6` | SYSTEM_REGISTER_WRITE | sepc | `fwbehavior:a808a975a374c68865445eb1357af241714d8428badb7a732620c6f62b32efad` |
| `0x80000700` | `unresolved` | `sret` | EXCEPTION_RETURN | — | `fwbehavior:dfaed4d01123bfada5566a2fb3c008b3fca6775afb11d9d4501d4e336f16ec05` |
| `0x80000708` | `unresolved` | `csrrwi a0,0x03b9,0x0` | SYSTEM_REGISTER_READ | 0x03b9 | `fwbehavior:6599837eb6a99cca44025481b005d2e754cdecb351eb45a25e691479a3c1620b` |
| `0x80000708` | `unresolved` | `csrrwi a0,0x03b9,0x0` | SYSTEM_REGISTER_WRITE | 0x03b9 | `fwbehavior:42935929def63add607905f756e1911c5730ecbfc338f057bada2fd492e152ac` |
| `0x8000071c` | `unresolved` | `amominu.w s0,t4,(s7)` | ATOMIC_LOAD | — | `fwbehavior:7fdc356f6da304ce6db0c18cccd6e478badebb055e01c6ccea718436280fef5d` |
| `0x8000071c` | `unresolved` | `amominu.w s0,t4,(s7)` | ATOMIC_STORE | — | `fwbehavior:c5ea7426424916c8ad6bd0964d0b94204334b3cfad9fb44779e9cca638d06579` |
| `0x80000770` | `unresolved` | `amomax.d s5,s10,(a3)` | ATOMIC_LOAD | — | `fwbehavior:6cad1ce756b4e7ba28dad46e62d49eadbb4d84f9f3a9ae42efd5929bc24e2e49` |
| `0x80000770` | `unresolved` | `amomax.d s5,s10,(a3)` | ATOMIC_STORE | — | `fwbehavior:e1998f76f5409a5c8740d3d7cb9f65e64a5e98cf063a0f07c9225026db3afbd3` |
| `0x80000784` | `unresolved` | `amoswap.d s2,s3,(s8)` | ATOMIC_LOAD | — | `fwbehavior:2c11dcb65a4001f6d5d6c963167c11de5deace5f9a6d39243bab849c2881c434` |
| `0x80000784` | `unresolved` | `amoswap.d s2,s3,(s8)` | ATOMIC_STORE | — | `fwbehavior:ed80968c599bff6865d8b4f33b3673a43db801fa82577bfed511ea4c18a0869d` |
| `0x800007a0` | `unresolved` | `amoand.w t5,ra,(t4)` | ATOMIC_LOAD | — | `fwbehavior:8583ebe10bad19d8e046d72c6923c78beacba694e46b85a5c37062e5dd562787` |
| `0x800007a0` | `unresolved` | `amoand.w t5,ra,(t4)` | ATOMIC_STORE | — | `fwbehavior:2ac2929666692879268ae49f0b749b2d453b3279caf8984bc4b792fd8cc6cf6c` |
| `0x800007c4` | `unresolved` | `csrrs t4,0x03a0,s10` | SYSTEM_REGISTER_READ | 0x03a0 | `fwbehavior:b04dd00c244b7b9c034dafdd61abe983e8a6bb52e9dec3ad8744f73802a5ce3a` |
| `0x800007c4` | `unresolved` | `csrrs t4,0x03a0,s10` | SYSTEM_REGISTER_WRITE | 0x03a0 | `fwbehavior:bdd076d1257c245d55a973d496c06f5ecba623ee202e96785f89abaa889f08e8` |
| `0x800007d4` | `unresolved` | `csrrw a5,0x03b5,gp` | SYSTEM_REGISTER_READ | 0x03b5 | `fwbehavior:97e2bc97465e8b04c339e2916aa65e66ee6e84fc22fbcf6a449cf7522bae1884` |
| `0x800007d4` | `unresolved` | `csrrw a5,0x03b5,gp` | SYSTEM_REGISTER_WRITE | 0x03b5 | `fwbehavior:0e44614444afa8ba318cfb91a3db5577747851a4368c10a27944cb4b903b7c58` |
| `0x800007e4` | `unresolved` | `lr.d s3,(a4)` | ATOMIC_LOAD | — | `fwbehavior:efb7230bc991210a992c98236f72cbb8e763442acbcf05f08acb2a134b9cd3e4` |
| `0x80000814` | `unresolved` | `csrrs tp,0x0b00,a2` | SYSTEM_REGISTER_READ | 0x0b00 | `fwbehavior:344b3cf206229d9c869c1d5272ab324865daf0cc5cd0463a64b9ab5f5b6baa3d` |
| `0x80000814` | `unresolved` | `csrrs tp,0x0b00,a2` | SYSTEM_REGISTER_WRITE | 0x0b00 | `fwbehavior:c43be97b88c230b962db6e3d7882011b841c2480e98146c757c1110dd4ff77d1` |
| `0x80000864` | `unresolved` | `amoadd.d a6,sp,(s10)` | ATOMIC_LOAD | — | `fwbehavior:12456a09f3954d5dd4d8e459b82c820d7093c3bcf2e48b938a4c8bf241ec4317` |
| `0x80000864` | `unresolved` | `amoadd.d a6,sp,(s10)` | ATOMIC_STORE | — | `fwbehavior:917a4457df99a87546ee1441ce6202a33b5775a1c4307ba0a4e673780f83d48b` |
| `0x80000894` | `unresolved` | `amoor.w s11,t5,(a7)` | ATOMIC_LOAD | — | `fwbehavior:9bb7372ff8a9b55c0ae7e10d6e83a4670d208e3cc86ceef2f8a04e7adf5358dd` |
| `0x80000894` | `unresolved` | `amoor.w s11,t5,(a7)` | ATOMIC_STORE | — | `fwbehavior:6df694c70dd797d7c7963054a8236453a2bead3d1b22e866a126b80fab988cfa` |
| `0x800008b8` | `unresolved` | `amoswap.d s7,tp,(t4)` | ATOMIC_LOAD | — | `fwbehavior:8a29f30f65a978ef47479267dc878da7c2a482b650c9dd52725038cd754eb119` |
| `0x800008b8` | `unresolved` | `amoswap.d s7,tp,(t4)` | ATOMIC_STORE | — | `fwbehavior:bb751d5ec28cae10dc8e9529bfe3feee3a2321029ff937b9a8ae079d620bdad5` |
| `0x800008c4` | `unresolved` | `csrw mepc,s6` | SYSTEM_REGISTER_WRITE | mepc | `fwbehavior:ee263367cf990923d1c0895a406851e93a73e0b8c668f7b68e82f8ffce3cc2c4` |
| `0x800008c8` | `unresolved` | `mret` | EXCEPTION_RETURN | — | `fwbehavior:09a4c4f4b5fd53438f6fef9608da3d91e6284fa82be8e03e91a944be01a1c83f` |
| `0x8000090c` | `unresolved` | `fence 0xf,0xf` | MEMORY_BARRIER | — | `fwbehavior:874f407c805b31902310f3355c57317f74b61bd42890a19d7283b6323049e49b` |
| `0x80000920` | `unresolved` | `sfence.vma s6,sp` | TLB_INVALIDATE | — | `fwbehavior:41c28ffb2fae17a0faaa13aa04d2690de22c34cb4808ef9619946f20632b0ec6` |

## 10. Unresolved / Unsupported Facts

- Unsupported instructions/semantics: 122
- Unresolved call targets: 0
- Unknown memory addresses: 132
- Ambiguous ownership: 0
- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.

Unresolved ≠ nonexistent. Unsupported ≠ safe.

- `0x80000008` `83b00f00` `ld ra,0x0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:facc2eaa8f4d4b1968f884cd42cd8b4f0b012e617ec9af7ff9107307cabd91cd`
- `0x8000000c` `03b18f00` `ld sp,0x8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b59c8dc65f16340f8337ab43d05a49f936ccf1736d62162703bed24d73b4f83b`
- `0x80000010` `83b10f01` `ld gp,0x10(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:77a2d6882786ce6e12cb472e05111f9dc653d4365171ba572bc14cc6aae03bc3`
- `0x80000014` `03b28f01` `ld tp,0x18(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:7b824ede6524e3c798c5c10ae87cce88c742eeef2def24bee8b5bef58d67e870`
- `0x80000018` `83b20f02` `ld t0,0x20(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8e63f804f2f5b9dc68ce3553a3f8c2a1ab2ced02ad16e74b0d5ac2f627cf297c`
- `0x8000001c` `03b38f02` `ld t1,0x28(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:81d8f6858000eb5cd852a701a48a98f670ef5e64d66a6c558d41469321c5c703`
- `0x80000020` `83b30f03` `ld t2,0x30(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ce51a9216808ab583acf03ea1337d013b0e9a4c2ddfbb5e209b243ac08d566b5`
- `0x80000024` `03b48f03` `ld s0,0x38(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f754d627cc7965d5629fb9426da0f434a1724f6e8f03c4ce477bb1228738ca08`
- `0x80000028` `83b40f04` `ld s1,0x40(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6a391e9e0e10148870dc7f5570c31c67958162b04734949fee0465c4d07f014b`
- `0x8000002c` `03b58f04` `ld a0,0x48(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c01c53f7f1a8079e96cff43d6d022e0d7f51649b877c4ffd36f86cac16e7e34a`
- `0x80000030` `83b50f05` `ld a1,0x50(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0b05fdde57d4d64d4ee81eb03a75df291f5e0da543ca8494097a0d15eb005ceb`
- `0x80000034` `03b68f05` `ld a2,0x58(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:307029a15ca2f8bfb4fb8fca9beb9c30b271a8ee5d2e691f301a1289b1fb7e75`
- `0x80000038` `83b60f06` `ld a3,0x60(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ccf89857b5fad8daeb0af3e55d8d3f2785228c67c87a790bcbdb3ae5ed2a7bfa`
- `0x8000003c` `03b78f06` `ld a4,0x68(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d4449fb0d8a605911b6c3a303269a43d79a42b2647c782d044ce0540325ba4e0`
- `0x80000040` `83b70f07` `ld a5,0x70(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:7239cd951570e5165cdcaccf824642aaa8c5f2b9767bc07ff900629bf743056e`
- `0x80000044` `03b88f07` `ld a6,0x78(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:229db846c8a6ddb1d56218f517e52624551471e999a519e51ccc5fe00d15bcd0`
- `0x80000048` `83b80f08` `ld a7,0x80(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:060d836f9780d4afc0d654f67a87b55b18db7d0bee64824832026f580168c343`
- `0x8000004c` `03b98f08` `ld s2,0x88(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b153856144def27bfc9042c8951b92ac8c6263552d19f6fcbc8071b732093009`
- `0x80000050` `83b90f09` `ld s3,0x90(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:849597e09ee3f635943de147c761396cb11629a96bec5e6cde394a93450657cd`
- `0x80000054` `03ba8f09` `ld s4,0x98(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:aa947061d49bb331c5b1225d05bbec35091ac1b2a9859875238cdaa5d1d3eae1`
- `0x80000058` `83ba0f0a` `ld s5,0xa0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:115cf710f5de90a83ee0bac0a861a41daf4ac06beb67e593acadc30a3f997a87`
- `0x8000005c` `03bb8f0a` `ld s6,0xa8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:4a1426378063a43e35232ba068c6d43ee0171067ecc0a1d112064b8f4ee2e5cb`
- `0x80000060` `83bb0f0b` `ld s7,0xb0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5711166d828d325114c1873d984bacc79f8721d477eed21e474fbb82bbed8fb5`
- `0x80000064` `03bc8f0b` `ld s8,0xb8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:504b1cf44b579a0c46d59455e27bcb652007532cbb67ffca628978551137d879`
- `0x80000068` `83bc0f0c` `ld s9,0xc0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:728fe2cf53f4dde3686269a59e8f90b9efb9d76ec2d5baa467c1cf5bcdaae177`
- `0x8000006c` `03bd8f0c` `ld s10,0xc8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:fb38a2ef9fe1813bb8389517d3ac3db06a15d1011a91fa6c56db98758074a92e`
- `0x80000070` `83bd0f0d` `ld s11,0xd0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ed60b0942253a035939d782faaddee4b35e10aab0ad9c52df1d2556c873b7dbc`
- `0x80000074` `03be8f0d` `ld t3,0xd8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f4e5f7a2a7e003cda03252d06769ca6c8cebaa0fb9559b9a264f63548d787c30`
- `0x80000078` `83be0f0e` `ld t4,0xe0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:67af99b800c30e6e6cf24b75ce6f7189b467b9ce25efe85be27283fe681f6d1d`
- `0x8000007c` `03bf8f0e` `ld t5,0xe8(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0a73e3b3bb19439be2ecfbd113cdfaa07f5d55c7d5ab0dd0cfe5226204db6109`
- `0x80000080` `83bf0f0f` `ld t6,0xf0(t6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:fcc636f05040158c4c52d59c2e9e9da57cca37af835ac2f43d772b1a07a3a5cc`
- `0x80000090` `07a00f00` `flw ft0,0x0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:e99b542970499d4894496779cf8ceaaca295f0ab189ff4668184c8f4d7068d5b`
- `0x80000094` `87a08f00` `flw ft1,0x8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:d589babe2557439ca18b1028d2babc47ebd0190bb016e92197bdb7d69f2d88c3`
- `0x80000098` `07a10f01` `flw ft2,0x10(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:f3795bd061a8bab197fff82e6867765d556114b9a9cd4e9694d58cf15a7cbed1`
- `0x8000009c` `87b18f01` `fld ft3,0x18(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:7b48c7fec6b1d045c0b5e15679c68373bb0dac60f9b171338fdb542b8048bc5c`
- `0x800000a0` `07b20f02` `fld ft4,0x20(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:7c3c5f6ec799a7a41526e3e515add94461302aeba2f3d0d3625d9603d3f16731`
- `0x800000a4` `87b28f02` `fld ft5,0x28(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:60731cd3c8c2d2fd13947d28ca328ead44bdef9e73e8fa8796ddd1aeab3b9fdd`
- `0x800000a8` `07b30f03` `fld ft6,0x30(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:f7a9b00518beca3bd548f5f6f85067bcfd79af1104793c1bd29a427fa0235f74`
- `0x800000ac` `87a38f03` `flw ft7,0x38(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:f9dccc6aa044b638fcb9dd77fe39ec5f5a47713796e87f1e22beb0a48319f1ec`
- `0x800000b0` `07b40f04` `fld fs0,0x40(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:8d32aa321196c5ec7559b3508138f74c47678a7e79b5abf8f7ffe2bae92349d9`
- `0x800000b4` `87b48f04` `fld fs1,0x48(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:268d7ad340ed09a451f259e4566301f93d5ef80dc654681a0cc042b193a3b496`
- `0x800000b8` `07a50f05` `flw fa0,0x50(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:99eee9b220f8fe482772a2598eb1838afe9843ddd166bc291bff63a14fe2e4d5`
- `0x800000bc` `87b58f05` `fld fa1,0x58(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:83431e275244117cf02a69cddbe2f2afc6a317c35e102786645a7d47dd120679`
- `0x800000c0` `07b60f06` `fld fa2,0x60(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:4f2f990a86b95b52cc5761603a555c3f12386cc21555183106232d2692e9eb5a`
- `0x800000c4` `87b68f06` `fld fa3,0x68(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:708f4682158f70a1d04d2860e6e19a8b2eb4e6c8879fe1b632055097dff782d7`
- `0x800000c8` `07a70f07` `flw fa4,0x70(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:5f7f19372f75b312249a137c7398fc3dd83f2a3ec3b493373c32ec0ca62b49ae`
- `0x800000cc` `87b78f07` `fld fa5,0x78(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:90c8b0bd72b44364f25f113f183c534a6d6cb4b447b6600211c00e3133550b21`
- `0x800000d0` `07b80f08` `fld fa6,0x80(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:c745fa2e09aff40834085ad8962bde24fad1a86ad8d3c9669c9fce472b58e43f`
- `0x800000d4` `87a88f08` `flw fa7,0x88(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:1a71d7947ea286e5779a3b21ffa576ef8d72272724108c44599d957e8dc217b9`
- `0x800000d8` `07a90f09` `flw fs2,0x90(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:6deac3cf57efacbfb6f82fc3339d6e52a8e1c64511dca7ebd6677456a53065c7`
- `0x800000dc` `87a98f09` `flw fs3,0x98(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:dc1fa06b1c749c45766b64a51b66c95bf5370c06032563ea75e9a82f9262d9d3`
- `0x800000e0` `07ba0f0a` `fld fs4,0xa0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:8f55beab87246f6f9d12b71c2b5f0940445f718537fba4f48a0fca47d45d1258`
- `0x800000e4` `87aa8f0a` `flw fs5,0xa8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:0b9adb8d6262d723d258aa6532c5094cf0942c6aaadc5a1059ce19660ab7a284`
- `0x800000e8` `07bb0f0b` `fld fs6,0xb0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:be00f705fa862d97b161c20cff74296e0743a70f4274ed30adad467d66c73c90`
- `0x800000ec` `87bb8f0b` `fld fs7,0xb8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:0d40a48fba2853528775827671993be96216a2c2de3a8b3b96147545a4e4680c`
- `0x800000f0` `07bc0f0c` `fld fs8,0xc0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:eef84d8f33ab614bc30ffeaf0d694adda86cb4d6e17015f7923ef297311fcbd6`
- `0x800000f4` `87bc8f0c` `fld fs9,0xc8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:70b7d1367eda27d51cec350a6a365663d4738d9b5ed20866da94854471ec45dc`
- `0x800000f8` `07bd0f0d` `fld fs10,0xd0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:430abd247d2bb3f063dccae7ecd9302c1e1d6a0ece4e6e1eb9b6e4d278c68555`
- `0x800000fc` `87bd8f0d` `fld fs11,0xd8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:1be4d30ffe73622473c3e88887b20b1b58604fcc1a031bd3f19c4600ee6d12f4`
- `0x80000100` `07be0f0e` `fld ft8,0xe0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic fld; `fwbehavior:8a470a1c6d15cc95aed3286c4cf0c22b3b674437b5dc14c635b18fe43b45c8c0`
- `0x80000104` `87ae8f0e` `flw ft9,0xe8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:8732918557989fa91cdb5b0a0a8f7ccb6caf9e110772f8221d79e927eac013e4`
- `0x80000108` `07af0f0f` `flw ft10,0xf0(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:878f8b1461bf04bad0859c59af5501c6377042f41563a7dc20fdb0f9eda92370`
- `0x8000010c` `87af8f0f` `flw ft11,0xf8(t6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:c0c56f7666264c8a04fbe579e2337ec64e11cd63ea9f9a376408b05174bccb1f`
- `0x80000114` `73000000` `ecall` → UNKNOWN, unsupported; Unsupported mnemonic ecall; `fwbehavior:4bb235d5e0db2e05ef82888044662d35d1a3d4a4edaf5e3a7cb44b5aba8180be`
- `0x80000124` `23bc2004` `sd sp,0x58(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:bf28185b4ba19b4a7a09634452b47d848e2255c99f56e40c0b14992949e3e75f`
- `0x8000012c` `23b82006` `sd sp,0x70(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:c647807f512a9720a256cec4f4ed488ada94bb5696bdaab957908316a36025f9`
- `0x80000134` `23bc2006` `sd sp,0x78(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:3cc9ea35fefd53fd595d9dff9bb99ac2d2889c0f7829c3aae9e61b5fa041a0aa`
- `0x8000013c` `23b02008` `sd sp,0x80(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:043ebc87c2ef09f6b13d0b187bc5ad2ca1ae8798d52e751a1d2481205f2643ca`
- `0x80000144` `23b42008` `sd sp,0x88(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:0e64c92d534093a6aa03ab37b705636ce896c8499f3ccfb05abee90b02787f35`
- `0x8000014c` `23b82008` `sd sp,0x90(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:df8927dfb805ba4dd1939c9bc27342b2c45d5e5717e1bd4a421d086deeeea643`
- `0x80000154` `23bc2008` `sd sp,0x98(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:e00feb87da2cde5e5a69b5f3c0a6c3ff1e96d8d97fa47eb4f4307dd76d696c26`
- `0x8000015c` `23b0200a` `sd sp,0xa0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:7446ec84565aa1414f7b500ac325c11135906fea6ad496cfc92a10737195f45e`
- `0x80000168` `23b4200a` `sd sp,0xa8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:a75606bc40dc4ac7556838a251db5e5ae6097e53cf8be4676136aeff56ff04e0`
- `0x80000170` `23b8200a` `sd sp,0xb0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:e5589a2c12a81cbd00cbe047ca8252e388222083460e9711e2738cb3c5df7db1`
- `0x80000178` `23bc200a` `sd sp,0xb8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:15e5be4afbbe3eff8c32971cb3196caf72d9d1e377098dba2af22e4a8849b8f8`
- `0x80000180` `23b0200c` `sd sp,0xc0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:0a1a3d2a017b496e26a9af0e89f938257ab39e5a90342d97c5b81b9cc38ccc39`
- `0x80000188` `23b4200c` `sd sp,0xc8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:42ba50d364e1dc800ac23d9bf41ea79604bdae741d9dd280aa1abd76790abf96`
- `0x80000190` `23b8200c` `sd sp,0xd0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:7de9eaa9b06eb5109c7d068855bacf4e65be4a3ccf899f29ab9efb3da3dcb2ac`
- `0x80000198` `23bc200c` `sd sp,0xd8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:182a5c4da4d1f6f4ac51aec5328e339c7a5f0b275c0177f4382bfec4c3565a4e`
- `0x800001a0` `23b0200e` `sd sp,0xe0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:d5e0ac01a753dcfc763d20ccee33cff786bbbddd861d45628914023c6a32b1f2`
- `0x800001a8` `23b4200e` `sd sp,0xe8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:bc860e2d3efd9fb41d5af88874e1c37fcc059a3b3266544f6d1c4856f2519d68`
- `0x800001b0` `23b8200e` `sd sp,0xf0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:f76f6b31cf35c69f8302aab5b72bdcabac35bbaa71d31113fb047a0f17ecbb28`
- `0x800001b8` `23bc200e` `sd sp,0xf8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:1f9375bedffcb9a9c568317f13ce9970a3eb2d6817cb2f6a52ae76f810f0b5a8`
- `0x800001c0` `23b02010` `sd sp,0x100(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:eaedc1138da585383f076dea9c98a58a298849718d0ef27ba03b90c1afd38daa`
- `0x800001c8` `23b42010` `sd sp,0x108(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:13c30a3b35d34732d26cd9f72660d3af93baedf7019fef8b140bbf3b98fff5fc`
- `0x800001d4` `23b82010` `sd sp,0x110(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:4cc19389f8b7fae3c2d6fbed24f22ea57dabd77e67ceb8028dba9a6f405dd54a`
- `0x800001dc` `23bc2010` `sd sp,0x118(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:91a9b11d9d57578ef24d5802f94a37f20e7f49cc7532ce920c6349732263a45d`
- `0x800001e4` `23bc2012` `sd sp,0x138(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:ab43f5d0cb6ebe4469b446950374a54e76d95f8d8a22baf9b97baf66a3210973`
- `0x800001ec` `23b02014` `sd sp,0x140(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:49ea75a292ddc63da436410508e62d427f2b4e53691810b79e490e405759ab96`
- `0x800001f4` `23b42014` `sd sp,0x148(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:64977f580c6c92faae612487a21a5125fb06e7afb59cb0fa67741552e875748f`
- `0x800001fc` `23b82014` `sd sp,0x150(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:8dc352eda733d353cfd7a661129c9bd6e6c6c91420923f7bb46cae1fb8c9acaf`
- `0x80000204` `23bc2014` `sd sp,0x158(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:cdc8d7711dec823c29e5288f78495e2fe6218b92f2ae4c133852a8d46ab72964`
- `0x8000020c` `23b02016` `sd sp,0x160(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:c50977685ed495a1302bb86b1d90ff695cd2069e05a884e156b80285943c0e69`
- `0x80000214` `23b42016` `sd sp,0x168(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:d759597cfcba9f8718dd5947478690e3c2bcb8754d749de8978b9a137c05874e`
- `0x8000021c` `23b82016` `sd sp,0x170(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:ac8eb9008d2bbb7f110118fa8325132e594aef28966f535130289314fe4a7588`
- `0x80000228` `73211000` `frflags sp` → UNKNOWN, unsupported; Unsupported mnemonic frflags; `fwbehavior:6e2c2e5d2772a381aaeccf27dc1cb27bbeeec01b0d04c16ee32e93de4ceec9c6`
- `0x8000022c` `23b02004` `sd sp,0x40(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:9c7934c2d8442c47b659e57b62e2a1e546b6b26c38984b31f6d28ba238399ffa`
- `0x80000230` `73212000` `frrm sp` → UNKNOWN, unsupported; Unsupported mnemonic frrm; `fwbehavior:a32213db92e7db2c39c7ca84b59f40514ac9816014be9dc96e9b17c4aa6aea36`
- `0x80000234` `23b42004` `sd sp,0x48(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:5fd4bc8e65005fbb7ebef0eb2359ecb965a1bcdbdf738c3a97903072cd004c62`
- `0x80000238` `73213000` `frcsr sp` → UNKNOWN, unsupported; Unsupported mnemonic frcsr; `fwbehavior:e7b7c250e9faf0dd0d8a0b53a53bb55fece2bc1066c601e1049c0291c9927fef`
- `0x8000023c` `23b82004` `sd sp,0x50(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:312638708140615cba42a997bd6f09bc69f781307dfa108053a34e69ebf61e6b`
- `0x80000248` `23b00000` `sd zero,0x0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:b7620c60e7ee8886aac3c3bf31d89627aac168d25bb69c81d95f87b3c65f6353`
- `0x8000024c` `23b82000` `sd sp,0x10(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:61707fdc7934c5a714d544dd9ae44e353c68a78cfb5dd2bf30d7cc488b0a1f6d`
- `0x80000250` `23bc3000` `sd gp,0x18(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:638ff58fa7a31853f3ea006ec92a188fe72954bde29d4001870051a2a41060b7`
- `0x80000254` `23b04002` `sd tp,0x20(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:82924b7bfa321545ae902d3e9c44cd93e8c9017a7b4d32b1f8b2c11e05dacc5e`
- `0x80000258` `23b45002` `sd t0,0x28(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:ea621212f8e78219b8b09f2697e01ab84d9cc39669e6850ffd8517552f2ac34c`
- `0x8000025c` `23b86002` `sd t1,0x30(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:101a65dfa312a70742df6f34da6004fe8ed5a0da6985db9bd50ed88a8716a303`
- `0x80000260` `23bc7002` `sd t2,0x38(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:9c30c41d9d8b74f8f4eab2431fa6c253d8bf5fb7c0724ad574dfabe2dbc49d3c`
- `0x80000264` `23b08004` `sd s0,0x40(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:3a32e482eea9175c8d0235322b9cfe32ac5d9147dce281d759eba64660141553`
- `0x80000268` `23b49004` `sd s1,0x48(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:10cf137419fcac319dd9bae2f327b04cabbad5fa2de078d8c390476787bdcaec`
- `0x8000026c` `23b8a004` `sd a0,0x50(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:6130959ee5b53c18667c404198cd8b1b94b36334d3fdcf392ed52eab9308a847`
- `0x80000270` `23bcb004` `sd a1,0x58(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:2580e58faa91431c960fcc56d4a2cb4c044ac58e5c9f58d77f1feef8f0696e6d`
- `0x80000274` `23b0c006` `sd a2,0x60(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:43c8813095751df838037dfb3343526d3aabb8717ef033ebda6ac9d084b300de`
- `0x80000278` `23b4d006` `sd a3,0x68(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:3381542a2fdb4ba14d5f946f741bc0784e95eb33e4ac81fcb69154efc463cbe4`
- `0x8000027c` `23b8e006` `sd a4,0x70(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:1a572deb8535f23d6998aae57f70355e7ac0e179b684e1d284093217f379de5b`
- `0x80000280` `23bcf006` `sd a5,0x78(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:856b56826a550610592eac2ea65f4322c52b77c91a1caceadae18089503de351`
- `0x80000284` `23b00009` `sd a6,0x80(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:7095c72d92a681c58ffc51fb41b8865c2ab94c900655620d67c6998bf59c92e1`
- `0x80000288` `23b41009` `sd a7,0x88(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:bd38211eedb588f52e2e0228a8c48c9ab35f740233c9f4142879c69cdc313cdd`
- `0x8000028c` `23b82009` `sd s2,0x90(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:d54899c04f271ab7b70dfcdf6864254100ec96a7d66150b87df62944dca514b4`
- `0x80000290` `23bc3009` `sd s3,0x98(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:f57666ba0b8ceabb0b20c888f72ef5cffeda598bab10222f4d7709e3b5f859d4`
- `0x80000294` `23b0400b` `sd s4,0xa0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:13263ea705a1f2816eb6653ccd79d103f6561bda89e89bc85d2be21d031e5632`
- `0x80000298` `23b4500b` `sd s5,0xa8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:d784ad3021c20a55c0a12270fabac4dc1283a32f9925f66e61009fd083b4f161`
- `0x8000029c` `23b8600b` `sd s6,0xb0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:56cc11c55d570a33af787bc33cfde19abe14b2cca1a32d6ec6e0cf54d9d0160a`
- `0x800002a0` `23bc700b` `sd s7,0xb8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:4dead484d9558b86560d2d03c7c4990b29b4217633367097e87a221f3b890a05`
- `0x800002a4` `23b0800d` `sd s8,0xc0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:c7775d4b6f206d5ba47137da209280f94db061b54c493dfaa21835184a481b29`
- `0x800002a8` `23b4900d` `sd s9,0xc8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:70743a7ccbf6163672219d86964eabf182704defa0f915eca17ddc8af6585452`
- `0x800002ac` `23bcb00d` `sd s11,0xd8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:bbc2e4512519647592373a5ca2d808e9782b9f87fe76f21d7bee7d586f9f388e`
- `0x800002b0` `23b0c00f` `sd t3,0xe0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:e8f92efe93e4d0309ac4dae09479b8fea3b38f4c58da2e2882974f40a334599a`
- `0x800002b4` `23b4d00f` `sd t4,0xe8(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:858f3835b364dafe0ea0107e9b21a9503c5a2322b6cfc3850835f55044b6a453`
- `0x800002b8` `23b8e00f` `sd t5,0xf0(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:c64b5545f5fd726b01ce2928f08c790baddad5f441e8e70e483fc57fa5746cbe`
- `0x800002c4` `27a41000` `fsw ft1,0x8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:05c8e676631f01e57e6e84cad038283e5c98660a3f293b6ad8d843d7119a44ff`
- `0x800002c8` `27a82000` `fsw ft2,0x10(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:23867760c2fbd2cd284017256c2210a5db85d72254f2db4b24ff7baa8775a29f`
- `0x800002cc` `27ac7002` `fsw ft7,0x38(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:c2638b5f91b4ed2f94e619eee987b0acf638dee6abea961f6da48cb753ae6d79`
- `0x800002d0` `27a49004` `fsw fs1,0x48(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:697292170b0cdb70c8d4caf2d10926ff7bd02d75c0b2ddd87ec0a5d7d6559090`
- `0x800002d4` `27a8a004` `fsw fa0,0x50(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:1e5d18ad065788d1c139f5ccf3f8fb4d740e6f3850fadd59fff49e9ca4ad6afe`
- `0x800002d8` `27a0c006` `fsw fa2,0x60(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:32d5f5a3de85978a9943d5334e02f1153995f7b2b599e94587a5621f6d6f7417`
- `0x800002dc` `27a4d006` `fsw fa3,0x68(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:3a1d32587d4cb30a82325d994b080d2733a40eb417e8c1dc74681fd7e82d442c`
- `0x800002e0` `27a4500b` `fsw fs5,0xa8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:3d8800082429fe339af5a770eda8c0b7e27126d26593b26b103835999dec67af`
- `0x800002e4` `27a8600b` `fsw fs6,0xb0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:117c5197b69f8fc8ef37aba7a93f8a252a5d8a67a18c37623535304622803f94`
- `0x800002e8` `27a4900d` `fsw fs9,0xc8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:d28bf34527d50d4e835f188d75777adda83a97185611a651a57aa695b98690fc`
- `0x800002ec` `27a8a00d` `fsw fs10,0xd0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:3327fcbce1993b92562709c03ca14cd47d03cb9e10ab774a3f289a751e3991eb`
- `0x800002f0` `27a0c00f` `fsw ft8,0xe0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:a3eb24951af4420bb59998bbc8ccab49a4deff3775475c1f7b312b0135e5f6d9`
- `0x800002f4` `27a4d00f` `fsw ft9,0xe8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:f1a28ad0bef8f750e7aa0e532c34d75723f43f1d1f2d7dc2416096471d8ea6c1`
- `0x800002f8` `27a8e00f` `fsw ft10,0xf0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:483c28af9c6caf790236ce5e276477bc4cacfc4b959a607c7428892aa972e257`
- `0x800002fc` `27acf00f` `fsw ft11,0xf8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:1c5246f52f745ec59497aa102ae881f7721b2ef38a699bb576549dc5e67ecb80`
- `0x80000308` `27b00000` `fsd ft0,0x0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:2d05750ad0972118856775eeb21da3856ee1c9fbc58935054eb6711c1f112371`
- `0x8000030c` `27bc3000` `fsd ft3,0x18(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:8816dbec13a00d8201a4735463263a6961568406c0a0cf311bb3dd33667b3bf1`
- `0x80000310` `27b04002` `fsd ft4,0x20(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:e7f5d1f9236fde4d394066e0397b472434b671dfc688785f71f4dedf7ce75c41`
- `0x80000314` `27b45002` `fsd ft5,0x28(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:8c3699c6a3c57a842d732f36a117a0c02182df352d6f43b606828296c7e0e077`
- `0x80000318` `27b86002` `fsd ft6,0x30(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:77c534e6df61dcd7c7bdf829d89d0757f7f516784997610161ac123932bcc22a`
- `0x8000031c` `27b08004` `fsd fs0,0x40(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:5034717468ab3121d499f7bfe84a1ea0725f71071a1e5e241020a221b335ddb4`
- `0x80000320` `27bcb004` `fsd fa1,0x58(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:91a70a57ade09f7976394b97065e2485efb61cd589e100b8e1c00d879e508272`
- `0x80000324` `27b8e006` `fsd fa4,0x70(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:5f741587953f7b0cc59c81bad4edb6817788082ef3fe3cd1456915468b3359ce`
- `0x80000328` `27bcf006` `fsd fa5,0x78(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:7c177703dcd9c29f070fc9df40ac9e548429bc9fbdbdfdded7d77944ccf167eb`
- `0x8000032c` `27b00009` `fsd fa6,0x80(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:8ddd9557c56725bfb43a29537ec43b6a0df53060ff3a9dbae98410c72a6beb53`
- `0x80000330` `27b41009` `fsd fa7,0x88(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:7baa845782a95915da80b53e3f3791377c7afecf02a6ccc813fdd2243dcb2114`
- `0x80000334` `27b82009` `fsd fs2,0x90(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:4413e5fdbafa5d4c1954d3bf332e624a3f38f047f03a1f6f6dab22c024aa1eb0`
- `0x80000338` `27bc3009` `fsd fs3,0x98(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:099f4029b4fbee809821cdf051107d80b9e24417791abb21802714ebde231590`
- `0x8000033c` `27b0400b` `fsd fs4,0xa0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:048f6822cc38e9340948fe0985d9af866f3d969e8ebbf2ddf000a015b4b2eb8b`
- `0x80000340` `27bc700b` `fsd fs7,0xb8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:a04ef5529e9642cf121cba8fa80d78e00dbe278c0cd841a6de6572fdd01a4fa8`
- `0x80000344` `27b0800d` `fsd fs8,0xc0(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:561baca81b5e78e8d882b97ed8181e29c91dfafbb9cc8565cdf144ff1c9196a7`
- `0x80000348` `27bcb00d` `fsd fs11,0xd8(ra)` → UNKNOWN, unsupported; Unsupported mnemonic fsd; `fwbehavior:b5dddef5c403f453e9dce0fd4734c3ba269240bd10cf46cab464fc75dbd15ae7`
- `0x80000354` `23283fca` `sw gp,-0x350(t5)` → MEMORY_STORE, partial; unknown; `fwbehavior:785b8ade5417ac7c984022c9d55cfaa3f33dcd3384bbb28be0cc5ecd37b355be`
- `0x800003e0` `73000000` `ecall` → UNKNOWN, unsupported; Unsupported mnemonic ecall; `fwbehavior:748820935a746fa3c946802d8ace46c70210fc77068e05055f6491556e87a3b4`
- `0x80000480` `4bcda421` `fnmsub.s fs10,fs1,fs10,ft4,rmm` → UNKNOWN, unsupported; Unsupported mnemonic fnmsub.s; `fwbehavior:7651410cc9f3afc216267364c573c12aaa67ea1c3877429564103f3d58f48b67`
- `0x80000490` `53ba17d0` `fcvt.s.wu fs4,a5,rup` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.wu; `fwbehavior:e9495a98710408997ffc3a371eca410a35496344ff96390f3960dfe05abd3853`
- `0x800004a0` `2f3e9ea1` `amomax.d t3,s9,(t3)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:66eae8b307dd58fc4240f12adaa2687978d2610f8bb12c8da1399d99eba328bc`
- `0x800004a0` `2f3e9ea1` `amomax.d t3,s9,(t3)` → ATOMIC_STORE, partial; unknown; `fwbehavior:7379a2ddbc2edde10713362cefc6d48ddbea2b3724a00c91764e5da3fb47865e`
- `0x800004a4` `d3860de0` `fmv.x.w a3,fs11` → UNKNOWN, unsupported; Unsupported mnemonic fmv.x.w; `fwbehavior:33dbf494b2d7376fc75e6aacd2a486b5b14c3861ab2df4eba1074adc3573752a`
- `0x800004b4` `afa1e101` `amoadd.w gp,t5,(gp)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:6b4799ae97b87a2209dd3157041c0bb002d46c294058835f76c21de4424c90c1`
- `0x800004b4` `afa1e101` `amoadd.w gp,t5,(gp)` → ATOMIC_STORE, partial; unknown; `fwbehavior:0f45ce53fd2cd7ac6e2e958902a20d62cb111ccbeea540fe2d634fc2e1ab0853`
- `0x800004b8` `c7fa3548` `fmsub.s fs5,fa1,ft3,fs1,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fmsub.s; `fwbehavior:eb37f56b12f7e168911e8512db30ae7d10f80bd811ef7d62fe82cc45e6248d60`
- `0x800004c0` `53360258` `fsqrt.s fa2,ft4,rup` → UNKNOWN, unsupported; Unsupported mnemonic fsqrt.s; `fwbehavior:477601f816177cf03d965c0e5db5210ed142f383d95598800cb48cd5e26d2bfc`
- `0x800004d4` `2fa73401` `amoadd.w a4,s3,(s1)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:a9a3d7e47c18b2a2bca752d5c4e37446c03c2b62aef33f6fdc44995a0426b230`
- `0x800004d4` `2fa73401` `amoadd.w a4,s3,(s1)` → ATOMIC_STORE, partial; unknown; `fwbehavior:8bbad71278b68a40dc237028cccc16e33c1b1e307d148f3037d8d1d7bc51fde4`
- `0x800004e4` `2f352841` `amoor.d a0,s2,(a6)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:127051e0926c66ebdc2c79c6be332564bbfc9d4336352f5d479845383713ea67`
- `0x800004e4` `2f352841` `amoor.d a0,s2,(a6)` → ATOMIC_STORE, partial; unknown; `fwbehavior:1f3ee5683076383a70e96628da1393c485ea9596792274cd11711e25e1e528cf`
- `0x800004f0` `23307e01` `sd s7,0x0(t3)` → MEMORY_STORE, partial; unknown; `fwbehavior:d3b5f28ae536277b17213cc204e8b86c55b99b86351c5525cb684e7bb87eb6d8`
- `0x800004f8` `bbc5c102` `divw a1,gp,a2` → UNKNOWN, unsupported; Unsupported mnemonic divw; `fwbehavior:26eb17ad851473d4bd6132aed83d3f6afc9360bf5ddb3a92e5b8b6c16149990d`
- `0x80000504` `272e0501` `fsw fa6,0x1c(a0)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:fec7195e90f916b42610edd0b4f301f0eaf2422a68684a9053c4041a2d51c78f`
- `0x80000508` `d3c53bd0` `fcvt.s.lu fa1,s7,rmm` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.lu; `fwbehavior:e7929f28d53128c81d12d5813c2424fac397e042d8d7a76b329990db452da8df`
- `0x80000514` `03ccfe01` `lbu s8,0x1f(t4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:cfdf8366927ea2c2461a6be5a71db6ad5af69bd52f0241ee0e45ae467e584d19`
- `0x80000524` `0720cc01` `flw ft0,0x1c(s8)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:ee87d261a1f3db794d4ae03701bef9db8c9983228cdbc0274cd36fbb32d95792`
- `0x80000534` `2fbe3b61` `amoand.d t3,s3,(s7)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:b1d03842058b8527fcf96853680920aa6c91a9010edc086513a71eae12301a18`
- `0x80000534` `2fbe3b61` `amoand.d t3,s3,(s7)` → ATOMIC_STORE, partial; unknown; `fwbehavior:d777a4cada9704dc1f412be931e8b46e5ef5ab6f71af20a62997aee68562c66c`
- `0x80000538` `d3022f29` `fmin.s ft5,ft10,fs2` → UNKNOWN, unsupported; Unsupported mnemonic fmin.s; `fwbehavior:7038c4c568b21fe1103860972c26863ef7f2aa4c206ba21017ac6c3a940a79b5`
- `0x80000558` `a3008afe` `sb s0,-0x1f(s4)` → MEMORY_STORE, partial; unknown; `fwbehavior:042d2f3d7584f7609af4121fe359aad68620c24ed0667add64b7e380db4a0ba1`
- `0x800005a0` `87a7c901` `flw fa5,0x1c(s3)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:9a73d4b70d3f86880c5a289f0d97fbbcfa98b110440067c28ea5eebec7cc75c9`
- `0x800005ac` `33456902` `div a0,s2,t1` → UNKNOWN, unsupported; Unsupported mnemonic div; `fwbehavior:9de71362926c497d1bd30dc55e1a46239e00699e75bf998efbde1171a2c392c7`
- `0x800005b4` `d3c711d0` `fcvt.s.wu fa5,gp,rmm` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.wu; `fwbehavior:9332e1270603cf0fb5e64a720de943dd483bf87473a5d8b8f87cf000fb48d399`
- `0x800005c8` `23bcd1ff` `sd t4,-0x8(gp)` → MEMORY_STORE, partial; unknown; `fwbehavior:99e50ea3a9e45eecc511f0e690c579da22194aa49ac1ead7cd63f219ded4363c`
- `0x8000065c` `b3ae9103` `mulhsu t4,gp,s9` → UNKNOWN, unsupported; Unsupported mnemonic mulhsu; `fwbehavior:2e0494a1ba9fd6bde818d5bbb9eeb013dc135b2ee70bdc44a1520aef4aeb1547`
- `0x80000660` `d3ade221` `fsgnjx.s fs11,ft5,ft10` → UNKNOWN, unsupported; Unsupported mnemonic fsgnjx.s; `fwbehavior:be0a84a0fcb702db331bcc4ae317fba0459a3dc092980d82a5291d514bba289b`
- `0x80000664` `3bfe2502` `remuw t3,a1,sp` → UNKNOWN, unsupported; Unsupported mnemonic remuw; `fwbehavior:fea8ad3b2f610fa35477e5c72f5f7ac1dc70a519cd939d1c072558b8d7e820fd`
- `0x8000066c` `bbfa8703` `remuw s5,a5,s8` → UNKNOWN, unsupported; Unsupported mnemonic remuw; `fwbehavior:dc065529a1f2cc015fc331acbb2cca8b8adcf4a57bf48eebe1c15c7e6f715d33`
- `0x80000678` `47ceeee0` `fmsub.s ft8,ft9,fa4,ft8,rmm` → UNKNOWN, unsupported; Unsupported mnemonic fmsub.s; `fwbehavior:c30b9cf36106d24c8d428112a3a14d47c8b4c9805781cc5cd92dcac67fc38864`
- `0x80000688` `af39e200` `amoadd.d s3,a4,(tp)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:55b5fbf5fe4fa75db4825ffff4ded3ec4c8a7ada55074cb2894f3d381ed9ae8f`
- `0x80000688` `af39e200` `amoadd.d s3,a4,(tp)` → ATOMIC_STORE, partial; unknown; `fwbehavior:18495e12e47a6dfcc6bdbac17679014ed327f2989e57b42aba7e5155e5831000`
- `0x8000068c` `53826621` `fsgnj.s ft4,fa3,fs6` → UNKNOWN, unsupported; Unsupported mnemonic fsgnj.s; `fwbehavior:9597c82382833864a7da6098612e3c280d4d240f24521131c068ef873618ba50`
- `0x80000694` `532770a1` `feq.s a4,ft0,fs7` → UNKNOWN, unsupported; Unsupported mnemonic feq.s; `fwbehavior:9cd41210c0930ab6ec5fdf29f0cc2c541926c9dddb5069117920ea74e8564d6f`
- `0x80000698` `c77cef70` `fmsub.s fs9,ft10,fa4,fa4,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fmsub.s; `fwbehavior:be75f70dd197094910527666c9ced002d7b6c177b9f99876e2907aee6cf88ec2`
- `0x800006a0` `531c61a1` `flt.s s8,ft2,fs6` → UNKNOWN, unsupported; Unsupported mnemonic flt.s; `fwbehavior:aa0a4c1ff7eb9e47baca9c34e303f86e323bc17c25153fa4aa0f3ecb68f4a2a8`
- `0x800006b4` `036888fe` `lwu a6,-0x18(a6)` → MEMORY_LOAD, partial; unknown; `fwbehavior:2ac27e14045c5f0983580c340bd1fa9951bf1aface354415fdca6b690a5af6e0`
- `0x800006b8` `33be8a02` `mulhu t3,s5,s0` → UNKNOWN, unsupported; Unsupported mnemonic mulhu; `fwbehavior:a442ed45dc781ee009a0f5022f6c19c7b650ae6d608dea523a8432cecd9a1d04`
- `0x800006bc` `d33314d0` `fcvt.s.wu ft7,s0,rup` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.wu; `fwbehavior:10ee9fbec49102efdc8ee7fee11faead0ea542de674f66cde2ca5f816b5cd400`
- `0x800006c0` `533b34d0` `fcvt.s.lu fs6,s0,rup` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.s.lu; `fwbehavior:afd268a4cc72f200030eed02bae68874855bb0e7a2b85c6b68433a49444bc058`
- `0x800006c4` `bb5ae303` `divuw s5,t1,t5` → UNKNOWN, unsupported; Unsupported mnemonic divuw; `fwbehavior:b4963900db1b50fa5c11d38c2f43edd641ba16886e493908a75c9a7fd833fa39`
- `0x800006e4` `87290800` `flw fs3,0x0(a6)` → UNKNOWN, unsupported; Unsupported mnemonic flw; `fwbehavior:2d8f7759e124e3434ff656f95e293fe51ccd5b1db04661805f807ddaafdba0c4`
- `0x800006ec` `d30f8120` `fsgnj.s ft11,ft2,fs0` → UNKNOWN, unsupported; Unsupported mnemonic fsgnj.s; `fwbehavior:35aab31081bbd1dd9355843ac770e0c19df44d970451c5c1bba7e2a9080c5fc2`
- `0x80000704` `b35b6202` `divu s7,tp,t1` → UNKNOWN, unsupported; Unsupported mnemonic divu; `fwbehavior:8a96237bc7ce1ee8f72a840b39ff8ad942c26a8f5547534cf4d1a7a3ab2d1200`
- `0x8000070c` `d381e929` `fmin.s ft3,fs3,ft10` → UNKNOWN, unsupported; Unsupported mnemonic fmin.s; `fwbehavior:a5df13b5c8764994bcb51c727ec8cddaa3fa8c2eb67007f77aa2d6989a59eaa0`
- `0x8000071c` `2fa4dbc1` `amominu.w s0,t4,(s7)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:7fdc356f6da304ce6db0c18cccd6e478badebb055e01c6ccea718436280fef5d`
- `0x8000071c` `2fa4dbc1` `amominu.w s0,t4,(s7)` → ATOMIC_STORE, partial; unknown; `fwbehavior:c5ea7426424916c8ad6bd0964d0b94204334b3cfad9fb44779e9cca638d06579`
- `0x8000075c` `43168511` `fmadd.s fa2,fa0,fs8,ft2,rtz` → UNKNOWN, unsupported; Unsupported mnemonic fmadd.s; `fwbehavior:0a8f084dcde64900ccd8280a04cc035a6e1bd909d2bb8907f56f071d345c5a9f`
- `0x80000760` `d37d07c0` `fcvt.w.s s11,fa4,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.w.s; `fwbehavior:2fca695ca6baf52f31eb9f176acf0a90305408c91551d62d9d07b4d53ba6561d`
- `0x80000770` `afbaa6a1` `amomax.d s5,s10,(a3)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:6cad1ce756b4e7ba28dad46e62d49eadbb4d84f9f3a9ae42efd5929bc24e2e49`
- `0x80000770` `afbaa6a1` `amomax.d s5,s10,(a3)` → ATOMIC_STORE, partial; unknown; `fwbehavior:e1998f76f5409a5c8740d3d7cb9f65e64a5e98cf063a0f07c9225026db3afbd3`
- `0x80000774` `b379f702` `remu s3,a4,a5` → UNKNOWN, unsupported; Unsupported mnemonic remu; `fwbehavior:e25788dd7487976fb648adf75adddf496b822f85d22a7164c4959e127d41a432`
- `0x80000784` `2f393c09` `amoswap.d s2,s3,(s8)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:2c11dcb65a4001f6d5d6c963167c11de5deace5f9a6d39243bab849c2881c434`
- `0x80000784` `2f393c09` `amoswap.d s2,s3,(s8)` → ATOMIC_STORE, partial; unknown; `fwbehavior:ed80968c599bff6865d8b4f33b3673a43db801fa82577bfed511ea4c18a0869d`
- `0x80000788` `d3060c58` `fsqrt.s fa3,fs8,rne` → UNKNOWN, unsupported; Unsupported mnemonic fsqrt.s; `fwbehavior:b3c347dd5de078f526b70d4ce935b9eab1d6f0200b696f2fc83dacce08982b8b`
- `0x8000078c` `531abd20` `fsgnjn.s fs4,fs10,fa1` → UNKNOWN, unsupported; Unsupported mnemonic fsgnjn.s; `fwbehavior:e0c67e14278110effbd04c8342be3a4dbdece8b1d5ec77529e95aa18cfc4d0fc`
- `0x80000790` `53f61dc0` `fcvt.wu.s a2,fs11,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.wu.s; `fwbehavior:0ebb595a0bdf45373899bf27566e770f213dbb2742ed3158fb550e53882f9eba`
- `0x800007a0` `2faf1e60` `amoand.w t5,ra,(t4)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:8583ebe10bad19d8e046d72c6923c78beacba694e46b85a5c37062e5dd562787`
- `0x800007a0` `2faf1e60` `amoand.w t5,ra,(t4)` → ATOMIC_STORE, partial; unknown; `fwbehavior:2ac2929666692879268ae49f0b749b2d453b3279caf8984bc4b792fd8cc6cf6c`
- `0x800007a4` `53090ac0` `fcvt.w.s s2,fs4,rne` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.w.s; `fwbehavior:3fcb3486289bf5574a2fd17e9d979e7a0f967c96a1199062c0e34b48a8c611bc`
- `0x800007e4` `af390710` `lr.d s3,(a4)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:efb7230bc991210a992c98236f72cbb8e763442acbcf05f08acb2a134b9cd3e4`
- `0x800007e8` `d30219c0` `fcvt.wu.s t0,fs2,rne` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.wu.s; `fwbehavior:1b78e2d2b1f9b6d3df3534a9c9bd2e7acb6608343ceedabe6af6336cf7dc4187`
- `0x800007f4` `2726aefe` `fsw fa0,-0x14(t3)` → UNKNOWN, unsupported; Unsupported mnemonic fsw; `fwbehavior:68b0e66d1426ade7f0b7de4ce75809b2f7b0611bd13d5e5a95e9a25fa4c1d435`
- `0x800007f8` `b371e202` `remu gp,tp,a4` → UNKNOWN, unsupported; Unsupported mnemonic remu; `fwbehavior:d9af06b860e9e7dd68329d5c34a9f3a20bc182250aba7e6eebf21932fcd8fc38`
- `0x800007fc` `bb812a03` `mulw gp,s5,s2` → UNKNOWN, unsupported; Unsupported mnemonic mulw; `fwbehavior:8361ae3420c350caa384df1fac471c80aaa3d2fd81415a811f6d48a6be916bc6`
- `0x80000818` `cbabef61` `fnmsub.s fs7,ft11,ft10,fa2,rdn` → UNKNOWN, unsupported; Unsupported mnemonic fnmsub.s; `fwbehavior:c7233adc84d0eba9f96bd90ee265534fad4a968b796f250cfd7e8eec8f409a57`
- `0x8000081c` `3bd7b302` `divuw a4,t2,a1` → UNKNOWN, unsupported; Unsupported mnemonic divuw; `fwbehavior:52857405fe6b0a16c4e1da1b0253d85aa12aee359d0bfcb6979c2d2dc25ca9e7`
- `0x80000828` `83984400` `lh a7,0x4(s1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:967076f08917e835cc3b0b0a330c754912d8615c17917b1fa4296bbae699778b`
- `0x80000830` `3359cb03` `divu s2,s6,t3` → UNKNOWN, unsupported; Unsupported mnemonic divu; `fwbehavior:d9b8cadf2a2c5026699f1697b450e00f4ec200db497a0be68d7754dfd98b9d69`
- `0x80000838` `33755803` `remu a0,a6,s5` → UNKNOWN, unsupported; Unsupported mnemonic remu; `fwbehavior:bfa823d170f8aede785c5267be795704ebfc09ccd0385fbd4e5362323b9ec183`
- `0x8000083c` `d3877729` `fmin.s fa5,fa5,fs7` → UNKNOWN, unsupported; Unsupported mnemonic fmin.s; `fwbehavior:0413cdec1e9cc94a4edb47720de75806c22a3551670fe14c9b19274771345224`
- `0x80000840` `33c71203` `div a4,t0,a7` → UNKNOWN, unsupported; Unsupported mnemonic div; `fwbehavior:5df54dca24886ce662fbdfc5b43e3c0e3733cafee1ded758ee62f55d139c2c78`
- `0x80000850` `23854001` `sb s4,0xa(ra)` → MEMORY_STORE, partial; unknown; `fwbehavior:13e9197f3340adf63332b7dd7b16721bd851326d6e19516cd83f7dbb96dcf52c`
- `0x80000854` `d3fe3ec0` `fcvt.lu.s t4,ft9,dyn` → UNKNOWN, unsupported; Unsupported mnemonic fcvt.lu.s; `fwbehavior:d3b723d3235405631505aa33de42c280426cc9820339f00bcd75f711efa39dc5`
- `0x80000864` `2f382d00` `amoadd.d a6,sp,(s10)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:12456a09f3954d5dd4d8e459b82c820d7093c3bcf2e48b938a4c8bf241ec4317`
- `0x80000864` `2f382d00` `amoadd.d a6,sp,(s10)` → ATOMIC_STORE, partial; unknown; `fwbehavior:917a4457df99a87546ee1441ce6202a33b5775a1c4307ba0a4e673780f83d48b`
- `0x80000870` `03ec0e00` `lwu s8,0x0(t4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f68080afe675e93937e41be1d7ce6be122cf2b969319b5cdab9b6a505d2e53b7`
- `0x80000874` `33092003` `mul s2,zero,s2` → UNKNOWN, unsupported; Unsupported mnemonic mul; `fwbehavior:71bb77fe337c3e5c244fb0001fb90b91639b877f801f6d8406928ee63368ccca`
- `0x80000878` `4fa2ea19` `fnmadd.s ft4,fs5,ft10,ft3,rdn` → UNKNOWN, unsupported; Unsupported mnemonic fnmadd.s; `fwbehavior:7980a8a39cbc7ad0f3c8d840d338997f4219a8eaf56ebcebf08bf70cae9d2f95`
- `0x80000894` `afade841` `amoor.w s11,t5,(a7)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:9bb7372ff8a9b55c0ae7e10d6e83a4670d208e3cc86ceef2f8a04e7adf5358dd`
- `0x80000894` `afade841` `amoor.w s11,t5,(a7)` → ATOMIC_STORE, partial; unknown; `fwbehavior:6df694c70dd797d7c7963054a8236453a2bead3d1b22e866a126b80fab988cfa`
- `0x800008a0` `8349fa01` `lbu s3,0x1f(s4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:fd514b21f60813b0ae798a1f4946580b2bbe88ae35fdcdb50ab7a801cc47a151`
- `0x800008b8` `afbb4e08` `amoswap.d s7,tp,(t4)` → ATOMIC_LOAD, partial; unknown; `fwbehavior:8a29f30f65a978ef47479267dc878da7c2a482b650c9dd52725038cd754eb119`
- `0x800008b8` `afbb4e08` `amoswap.d s7,tp,(t4)` → ATOMIC_STORE, partial; unknown; `fwbehavior:bb751d5ec28cae10dc8e9529bfe3feee3a2321029ff937b9a8ae079d620bdad5`
- `0x80000900` `03c638fe` `lbu a2,-0x1d(a7)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e84af6debed8f33f246bd217cb3133910eb1585ee6444dde49378f3b5d568ac5`
- `0x80000924` `73000000` `ecall` → UNKNOWN, unsupported; Unsupported mnemonic ecall; `fwbehavior:fc1fb07c92f2b10accf9b223d1cf8fc463fedb2bd149fe5e5a3df29deb3abb43`
- `0x80000928` `731000c0` `unimp` → UNKNOWN, unsupported; Unsupported mnemonic unimp; `fwbehavior:06b020350ae0b93f7e7f2a600095b62dd723b099931ecd6f074c010710f0961a`
- `0x8000092c` `731000c0` `unimp` → UNKNOWN, unsupported; Unsupported mnemonic unimp; `fwbehavior:2c91470a61b78691faf652b52f9d5d3a0c4269eec2105eb532b9f59276e6b856`

## 11. Provenance and Toolchain

Analysis `firmware-static:fb40dd28d5bace9e7e1c7a44b51ef9a7feb26061d8bf358c80972361643b46bf`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `RISCV:LE:64:default` 导出结构；每条指令 bytes 与 SHA256 为 `9511f8db1e148d10cf103e0589564ce100c8d2168566c3642f36bba6ae4d9f2d` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
