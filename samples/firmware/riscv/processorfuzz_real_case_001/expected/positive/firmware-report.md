# Firmware Analysis Report

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:1008a3556c52e9f4bbe4f49b4c237e685963ff1a066c65d61e9112a476f6ba2c` |
| architecture | `riscv` |
| bit_width | `64` |
| endianness | `little` |
| elf_sha256 | `35f9fff9c00e6a93bb9e6884b8604cd3d36dd35f7fdea408412633c5b7ae9fe4` |
| arm_profile | `not applicable` |
| arm_cpu_name | `not established` |
| entry_address | `0x80000000` |
| function_count | `33` |
| basic_block_count | `164` |
| instruction_count | `858` |
| cfg_edge_count | `252` |
| direct_call_count | `71` |
| indirect_call_count | `0` |
| unresolved_call_count | `0` |
| memory_load_count | `118` |
| memory_store_count | `112` |
| mmio_read_count | `0` |
| mmio_write_count | `0` |
| system_register_read_count | `2` |
| system_register_write_count | `3` |
| barrier_count | `1` |
| atomic_count | `0` |
| tlb_invalidate_count | `1` |
| exception_return_count | `0` |
| unsupported_count | `15` |
| unresolved_address_count | `230` |
| ambiguous_ownership_count | `0` |
| ghidra_language | `RISCV:LE:64:default` |
| ghidra_version | `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` |
| producer | `{'analyzer': 'chipchain-general-firmware/v2', 'ghidra': '12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093', 'exporter_sha256': 'b006cc85631d9ef7f9232a03dbc05ce418296f885f427b9e2bd2762f46b9cbbe', 'semantics': 'chipchain-three-isa-semantics/r1', 'semantics_sha256': '0454ca318a5af7dd42e71e7f3b0e92f11424ffe035184b88f90d2ec92d3532ca'}` |

### Evidence-backed behavior examples

| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |
|---|---|---|---|---|---|---|---|
| `0x80000010` | `_start` | `csrwi 0x0304,0x0` | SYSTEM_REGISTER_WRITE | 0x0304 | not established | `fwbehavior:14c01a995486f1fd6953a85bb7e603c50238df6ffd5ab483b870578d85b1309e` | supported |
| `0x80000014` | `_start` | `csrci 0x0300,0x8` | SYSTEM_REGISTER_READ | 0x0300 | not established | `fwbehavior:ab44c5441ad9357cf0d19fbe1456f399e78bb68df5ee81e2730eb38aa5ea9f3f` | supported |
| `0x80000014` | `_start` | `csrci 0x0300,0x8` | SYSTEM_REGISTER_WRITE | 0x0300 | not established | `fwbehavior:b14ee4eb945e4b244496ecd06de0a593561986fb4914b75a591c86d4bf628c49` | supported |
| `0x80000020` | `_start` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | not established | `fwbehavior:527b58b657da2d32939d38e557dab389b575902b4b73fc7eb528329efdbe68f3` | supported |
| `0x80000034` | `_start` | `bgeu t0,t1,0x80000044` | CONDITIONAL_BRANCH | 0x80000044 | not established | `fwbehavior:a925d17572e4df5118f872343b8208672f28d56a85c5bafd3ac6c8b0f1366ff7` | supported |
| `0x80000038` | `_start` | `sd zero,0x0(t0)` | MEMORY_STORE | not established | 0 | `fwbehavior:5071612030bcec758e31f1e3fc2bdb93762638448db2f21f1f0c577b415e6489` | partial |
| `0x80000040` | `_start` | `j 0x80000034` | DIRECT_BRANCH | 0x80000034 | not established | `fwbehavior:5c98d4af962e432241264ab9a8533a2bded9d0e63732dbfbffa83c358fb6e44b` | supported |
| `0x80000044` | `_start` | `jal ra,0x800004e0` | DIRECT_CALL | 0x800004e0 | not established | `fwbehavior:95a5a21f08bd49d6500a63fe1fdca285093c7eee249d065de600e6cc7b9ef004` | supported |
| `0x80000048` | `_start` | `wfi` | UNKNOWN | not established | not established | `fwbehavior:2465032d00e73675b6a4b311be9205a04c93be545bd46bcdbc6941d2dc207d38` | unsupported |
| `0x8000004c` | `_start` | `j 0x80000048` | DIRECT_BRANCH | 0x80000048 | not established | `fwbehavior:f74e99e8e0c7e867dd92d358086ff84b870bf886a4b472400114b29dd0195934` | supported |
| `0x80000050` | `_trap` | `j 0x80000050` | DIRECT_BRANCH | 0x80000050 | not established | `fwbehavior:a687f0d523851f53fb447daf759f309f4b9d9fc1638c42f903b36ee40f8d2613` | supported |
| `0x80000054` | `arch_hart_id` | `csrr a0,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | not established | `fwbehavior:5368c08717388353681657e28da388743d1ef4a15a96e06d2832d2ff1fe24c0e` | supported |

## 2. Binary / Architecture Identity

ELF SHA256 `35f9fff9c00e6a93bb9e6884b8604cd3d36dd35f7fdea408412633c5b7ae9fe4`；RISCV 64-bit little；入口 `0x80000000`。
PT_LOAD 段 2 个；节 7 个。

## 3. Program Structure

识别 33 个函数、164 个基本块、858 条指令和 252 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x80000000` | `_start` | 0x80000000–0x8000004f | `fwfunction:8a65f999e8fc498c0b7dcd4b27306f0bbb59ef4dacb46f8e64b678964760f31d` |
| `0x80000050` | `_trap` | 0x80000050–0x80000053 | `fwfunction:d80cf69a10b2cc889a3a9c60b848c58a898de5f1508c6da16b222a22ade580d3` |
| `0x80000054` | `arch_hart_id` | 0x80000054–0x8000005b | `fwfunction:82dedc88b645cd20b908a8aa7b3022dc1a29e01277b1194c11fa3f7485896e62` |
| `0x8000005c` | `arch_memory_order` | 0x8000005c–0x80000063 | `fwfunction:8d9c2035cb30f4394e598e58aee05de5a3af6f4e423cdb15cea7568efac4d11b` |
| `0x80000064` | `arch_translation_sync` | 0x80000064–0x8000006b | `fwfunction:49d1e8bb003265ea5770d29e7e7c002335840706eb52531d2ddef18c334c6977` |
| `0x8000006c` | `checksum_word` | 0x8000006c–0x8000007f | `fwfunction:286c604cc04a9fccf260b8c5d46d39cde9abdabb6f20ee362eb7e33d9fca3c86` |
| `0x80000080` | `service_page_valid` | 0x80000080–0x800000a3 | `fwfunction:eac9d5a31797ebc52a487dc3b1df3da624337ea4b663c55ad77d2de30fe5f942` |
| `0x800000a4` | `command_checksum` | 0x800000a4–0x8000013b | `fwfunction:dda8af7e1794d3ea138aedaa137c40f0523f2b8bda11d261f26e051868b3af2a` |
| `0x8000013c` | `command_validate` | 0x8000013c–0x8000023b | `fwfunction:f2b0daa53ceb1ee7138ed4e124ff15b3c0887331f2b048dee6e85d6cd4c67eee` |
| `0x8000023c` | `controller_reject` | 0x8000023c–0x8000026b | `fwfunction:ab980569d5830a2d6ae49d891babad708121f9c3f360fddf30ca37a87b4e97cd` |
| `0x8000026c` | `controller_dispatch` | 0x8000026c–0x80000337 | `fwfunction:3e40ffb966b4432d6b55aa647b4bac5e2ec615e4cb6c7efe2345c276d9a61f0f` |
| `0x80000338` | `controller_init` | 0x80000338–0x8000036f | `fwfunction:564cc76f4304cf94ac398afffecef63a9c17c44f366f2eb5216a7386432e7332` |
| `0x80000370` | `controller_step` | 0x80000370–0x8000043b | `fwfunction:3ed99c60e6aff19fd47a10167c071d528c54021f9a1ee11f5175d15dc89d4277` |
| `0x8000043c` | `app_run` | 0x8000043c–0x800004df | `fwfunction:3cb236afdcdbcd0bd3e3b1b9700b559b87db12902be6befb7282554201727687` |
| `0x800004e0` | `main` | 0x800004e0–0x8000051f | `fwfunction:29378f463f1f7acd4a1f869b33278a8c578d33a9c1a8b55c515b3a1340b08e49` |
| `0x80000520` | `root_index` | 0x80000520–0x80000527 | `fwfunction:0f8cb7db112b6534703dcc07144d123405e4937f53dfb587555d0e39c5b64c3f` |
| `0x80000528` | `middle_index` | 0x80000528–0x8000052f | `fwfunction:8a4dce4365b7df379436940ca6ff912b1be7b61b2810fbcf83c0945396e15f84` |
| `0x80000530` | `table_pointer_pte` | 0x80000530–0x8000053f | `fwfunction:49aa7b720124647a39e7b2d8a156b2073ab3d4b44ecd755a7262342309d6ecb4` |
| `0x80000540` | `tables_ready` | 0x80000540–0x800005d3 | `fwfunction:2a33f2d9583085dd127f20bae64dbde2550f47f34819873f75e4c8ebabec3033` |
| `0x800005d4` | `page_slot` | 0x800005d4–0x80000607 | `fwfunction:e6d9158e00cb44a38c7b08a707b7cd200868e71acfe58a6e12dbe4e44056ca87` |
| `0x80000608` | `pte_physical_page` | 0x80000608–0x80000613 | `fwfunction:1c1df35fd773010c934efcc95d9d6917ac6112454b9b4882145f592e69d3de87` |
| `0x80000614` | `leaf_pte_valid` | 0x80000614–0x80000677 | `fwfunction:7f3d103388cb0bca6c380655eb65a53b4e016ef72a8ae326b5d9421b05705681` |
| `0x80000678` | `pager_encode` | 0x80000678–0x8000070f | `fwfunction:689d3b18c04af238a530865986b3c5bbcc884bd335d844db249d5151487a6402` |
| `0x80000710` | `pager_init` | 0x80000710–0x800007e3 | `fwfunction:c18b4cc2a650ee1e9926a82f9fcf1303534a8224e84ce5c0212a26f802166f54` |
| `0x800007e4` | `pager_commit` | 0x800007e4–0x8000086b | `fwfunction:983e7a215dd1a40742605e7917ab89efe3070970b22969d9a81505216a1d65ab` |
| `0x8000086c` | `pager_lookup` | 0x8000086c–0x80000923 | `fwfunction:c9a9957188dd07b071b9adab5cd323058b7ccbfea13d6dcdb8952b50b14a0a2b` |
| `0x80000924` | `pager_apply` | 0x80000924–0x80000a87 | `fwfunction:cb4c7ae073eb8dada289ae60dc5ea2fff78557904f2348f86c31cc514ef1f9ce` |
| `0x80000a88` | `mailbox_write_command` | 0x80000a88–0x80000adf | `fwfunction:9bb0c079d1609738b37f603acfcd4c8483fd309cd23599703ccf9848faa3ef91` |
| `0x80000ae0` | `stage_command` | 0x80000ae0–0x80000b2f | `fwfunction:e3d1766da172c9fe431ef6ef44dd17628ff1edd3fdd1aac98e6e8b18780a3d22` |
| `0x80000b30` | `platform_init` | 0x80000b30–0x80000c27 | `fwfunction:22e805781039486b9c9baae38ad4207c1218f1665fc27eec968c5d37e002ca4c` |
| `0x80000c28` | `platform_poll` | 0x80000c28–0x80000cfb | `fwfunction:bc61b0818b384a028dc9867f8e4e7be528b10e366309b982c2a00b88408d88ba` |
| `0x80000cfc` | `platform_publish` | 0x80000cfc–0x80000d4f | `fwfunction:e84df71bfa73545d0c9c5420c25436292a3de99ceddccb741c34ddaeb037bd7c` |
| `0x80000d50` | `platform_idle` | 0x80000d50–0x80000d67 | `fwfunction:3b67711e6ecf49f1aec60fea8b23ccc99e2ded7195428fead86371b24b783f71` |

## 5. Basic Blocks and CFG

| 基本块 | 结束 | 所属函数数 | 出边数 |
|---|---:|---:|---:|
| `0x80000000` | `0x80000033` | 1 | 1 |
| `0x80000034` | `0x80000037` | 1 | 2 |
| `0x80000038` | `0x80000043` | 1 | 1 |
| `0x80000044` | `0x80000047` | 1 | 2 |
| `0x80000048` | `0x8000004f` | 1 | 1 |
| `0x80000050` | `0x80000053` | 1 | 1 |
| `0x80000054` | `0x8000005b` | 1 | 0 |
| `0x8000005c` | `0x80000063` | 1 | 0 |
| `0x80000064` | `0x8000006b` | 1 | 0 |
| `0x8000006c` | `0x8000007f` | 1 | 0 |
| `0x80000080` | `0x8000008f` | 1 | 2 |
| `0x80000090` | `0x8000009b` | 1 | 0 |
| `0x8000009c` | `0x800000a3` | 1 | 0 |
| `0x800000a4` | `0x800000a7` | 1 | 2 |
| `0x800000a8` | `0x80000133` | 1 | 1 |
| `0x80000134` | `0x8000013b` | 1 | 0 |
| `0x8000013c` | `0x8000013f` | 1 | 2 |
| `0x80000140` | `0x8000015b` | 1 | 2 |
| `0x8000015c` | `0x80000173` | 1 | 3 |
| `0x80000174` | `0x8000017f` | 1 | 2 |
| `0x80000180` | `0x80000187` | 1 | 2 |
| `0x80000188` | `0x8000018b` | 1 | 2 |
| `0x8000018c` | `0x80000197` | 1 | 3 |
| `0x80000198` | `0x800001a3` | 1 | 2 |
| `0x800001a4` | `0x800001ab` | 1 | 2 |
| `0x800001ac` | `0x800001b7` | 1 | 2 |
| `0x800001b8` | `0x800001bf` | 1 | 2 |
| `0x800001c0` | `0x800001d3` | 1 | 1 |
| `0x800001d4` | `0x800001e3` | 1 | 2 |
| `0x800001e4` | `0x800001ef` | 1 | 2 |
| `0x800001f0` | `0x800001f7` | 1 | 2 |
| `0x800001f8` | `0x80000203` | 1 | 1 |
| `0x80000204` | `0x8000020f` | 1 | 3 |
| `0x80000210` | `0x8000021b` | 1 | 2 |
| `0x8000021c` | `0x80000223` | 1 | 1 |
| `0x80000224` | `0x80000233` | 1 | 0 |
| `0x80000234` | `0x8000023b` | 1 | 0 |
| `0x8000023c` | `0x8000026b` | 1 | 1 |
| `0x8000026c` | `0x80000293` | 1 | 2 |
| `0x80000294` | `0x8000029b` | 1 | 2 |
| `0x8000029c` | `0x800002ab` | 1 | 2 |
| `0x800002ac` | `0x800002bf` | 1 | 3 |
| `0x800002c0` | `0x800002d7` | 1 | 2 |
| `0x800002d8` | `0x800002e3` | 1 | 2 |
| `0x800002e4` | `0x800002ff` | 1 | 2 |
| `0x80000300` | `0x8000031b` | 1 | 3 |
| `0x8000031c` | `0x80000337` | 1 | 0 |
| `0x80000338` | `0x8000036f` | 1 | 1 |
| `0x80000370` | `0x8000038f` | 1 | 2 |
| `0x80000390` | `0x800003a3` | 1 | 3 |
| `0x800003a4` | `0x800003a7` | 1 | 2 |
| `0x800003a8` | `0x800003b3` | 1 | 3 |
| `0x800003b4` | `0x800003bf` | 1 | 2 |
| `0x800003c0` | `0x800003d7` | 1 | 3 |
| `0x800003d8` | `0x800003e7` | 1 | 1 |
| `0x800003e8` | `0x800003ff` | 1 | 0 |
| `0x80000400` | `0x80000417` | 1 | 2 |
| `0x80000418` | `0x8000042b` | 1 | 2 |
| `0x8000042c` | `0x8000043b` | 1 | 2 |
| `0x8000043c` | `0x80000467` | 1 | 2 |
| `0x80000468` | `0x80000483` | 1 | 1 |
| `0x80000484` | `0x8000048b` | 1 | 2 |
| `0x8000048c` | `0x8000048f` | 1 | 1 |
| `0x80000490` | `0x8000049b` | 1 | 3 |
| `0x8000049c` | `0x800004a7` | 1 | 2 |
| `0x800004a8` | `0x800004ab` | 1 | 2 |
| `0x800004ac` | `0x800004bb` | 1 | 2 |
| `0x800004bc` | `0x800004df` | 1 | 1 |
| `0x800004e0` | `0x8000051f` | 1 | 4 |
| `0x80000520` | `0x80000527` | 1 | 0 |
| `0x80000528` | `0x8000052f` | 1 | 0 |
| `0x80000530` | `0x8000053f` | 1 | 0 |
| `0x80000540` | `0x8000054f` | 1 | 2 |
| `0x80000550` | `0x8000058f` | 1 | 4 |
| `0x80000590` | `0x800005bf` | 1 | 3 |
| `0x800005c0` | `0x800005cf` | 1 | 0 |
| `0x800005d0` | `0x800005d3` | 1 | 0 |
| `0x800005d4` | `0x800005d7` | 1 | 2 |
| `0x800005d8` | `0x800005e7` | 1 | 2 |
| `0x800005e8` | `0x800005f7` | 1 | 0 |
| `0x800005f8` | `0x800005ff` | 1 | 0 |
| `0x80000600` | `0x80000607` | 1 | 0 |
| `0x80000608` | `0x80000613` | 1 | 0 |
| `0x80000614` | `0x8000061b` | 1 | 2 |
| `0x8000061c` | `0x8000062b` | 1 | 2 |
| `0x8000062c` | `0x80000637` | 1 | 2 |
| `0x80000638` | `0x8000063f` | 1 | 2 |
| `0x80000640` | `0x8000066b` | 1 | 1 |
| `0x8000066c` | `0x80000673` | 1 | 0 |
| `0x80000674` | `0x80000677` | 1 | 0 |
| `0x80000678` | `0x80000683` | 1 | 2 |
| `0x80000684` | `0x8000068b` | 1 | 2 |
| `0x8000068c` | `0x8000069b` | 1 | 2 |
| `0x8000069c` | `0x800006a3` | 1 | 2 |
| `0x800006a4` | `0x800006ab` | 1 | 2 |
| `0x800006ac` | `0x800006b7` | 1 | 2 |
| `0x800006b8` | `0x800006df` | 1 | 0 |
| `0x800006e0` | `0x800006e7` | 1 | 0 |
| `0x800006e8` | `0x800006ef` | 1 | 0 |
| `0x800006f0` | `0x800006f7` | 1 | 0 |
| `0x800006f8` | `0x800006ff` | 1 | 0 |
| `0x80000700` | `0x80000707` | 1 | 0 |
| `0x80000708` | `0x8000070f` | 1 | 0 |
| `0x80000710` | `0x80000743` | 1 | 1 |
| `0x80000744` | `0x8000076b` | 1 | 2 |
| `0x8000076c` | `0x800007e3` | 1 | 4 |
| `0x800007e4` | `0x800007eb` | 1 | 2 |
| `0x800007ec` | `0x8000080b` | 1 | 3 |
| `0x8000080c` | `0x8000080f` | 1 | 2 |
| `0x80000810` | `0x8000081b` | 1 | 3 |
| `0x8000081c` | `0x8000083f` | 1 | 3 |
| `0x80000840` | `0x80000853` | 1 | 0 |
| `0x80000854` | `0x8000085b` | 1 | 0 |
| `0x8000085c` | `0x80000863` | 1 | 1 |
| `0x80000864` | `0x8000086b` | 1 | 1 |
| `0x8000086c` | `0x80000887` | 1 | 2 |
| `0x80000888` | `0x8000089b` | 1 | 3 |
| `0x8000089c` | `0x800008af` | 1 | 3 |
| `0x800008b0` | `0x800008d3` | 1 | 3 |
| `0x800008d4` | `0x800008eb` | 1 | 2 |
| `0x800008ec` | `0x8000090b` | 1 | 0 |
| `0x8000090c` | `0x80000913` | 1 | 1 |
| `0x80000914` | `0x8000091b` | 1 | 1 |
| `0x8000091c` | `0x80000923` | 1 | 1 |
| `0x80000924` | `0x8000093b` | 1 | 2 |
| `0x8000093c` | `0x80000947` | 1 | 2 |
| `0x80000948` | `0x80000957` | 1 | 2 |
| `0x80000958` | `0x80000963` | 1 | 2 |
| `0x80000964` | `0x8000096b` | 1 | 3 |
| `0x8000096c` | `0x8000097f` | 1 | 3 |
| `0x80000980` | `0x8000098b` | 1 | 2 |
| `0x8000098c` | `0x800009b7` | 1 | 2 |
| `0x800009b8` | `0x800009bf` | 1 | 3 |
| `0x800009c0` | `0x800009d7` | 1 | 3 |
| `0x800009d8` | `0x800009f3` | 1 | 0 |
| `0x800009f4` | `0x80000a03` | 1 | 2 |
| `0x80000a04` | `0x80000a0b` | 1 | 3 |
| `0x80000a0c` | `0x80000a1f` | 1 | 3 |
| `0x80000a20` | `0x80000a2f` | 1 | 2 |
| `0x80000a30` | `0x80000a43` | 1 | 3 |
| `0x80000a44` | `0x80000a4f` | 1 | 1 |
| `0x80000a50` | `0x80000a57` | 1 | 1 |
| `0x80000a58` | `0x80000a5f` | 1 | 1 |
| `0x80000a60` | `0x80000a67` | 1 | 1 |
| `0x80000a68` | `0x80000a6f` | 1 | 1 |
| `0x80000a70` | `0x80000a77` | 1 | 1 |
| `0x80000a78` | `0x80000a7f` | 1 | 1 |
| `0x80000a80` | `0x80000a87` | 1 | 1 |
| `0x80000a88` | `0x80000adf` | 1 | 0 |
| `0x80000ae0` | `0x80000b2f` | 1 | 2 |
| `0x80000b30` | `0x80000b73` | 1 | 1 |
| `0x80000b74` | `0x80000b87` | 1 | 3 |
| `0x80000b88` | `0x80000c27` | 1 | 2 |
| `0x80000c28` | `0x80000c2b` | 1 | 2 |
| `0x80000c2c` | `0x80000c5b` | 1 | 2 |
| `0x80000c5c` | `0x80000c67` | 1 | 2 |
| `0x80000c68` | `0x80000c73` | 1 | 1 |
| `0x80000c74` | `0x80000c8b` | 1 | 0 |
| `0x80000c8c` | `0x80000cf3` | 1 | 2 |
| `0x80000cf4` | `0x80000cfb` | 1 | 0 |
| `0x80000cfc` | `0x80000d1b` | 1 | 2 |
| `0x80000d1c` | `0x80000d37` | 1 | 1 |
| `0x80000d38` | `0x80000d4f` | 1 | 1 |
| `0x80000d50` | `0x80000d67` | 1 | 1 |

## 6. Call Analysis

| 调用点 | 类型 | 目标 | 解析状态 |
|---|---|---|---|
| `0x80000044` | direct | 0x800004e0 | resolved |
| `0x800000c8` | direct | 0x8000006c | resolved |
| `0x800000d4` | direct | 0x8000006c | resolved |
| `0x800000e4` | direct | 0x8000006c | resolved |
| `0x800000f0` | direct | 0x8000006c | resolved |
| `0x80000100` | direct | 0x8000006c | resolved |
| `0x8000010c` | direct | 0x8000006c | resolved |
| `0x80000118` | direct | 0x8000006c | resolved |
| `0x80000160` | direct | 0x800000a4 | resolved |
| `0x80000190` | direct | 0x80000080 | resolved |
| `0x80000208` | direct | 0x80000080 | resolved |
| `0x8000025c` | direct | 0x80000cfc | resolved |
| `0x800002b4` | direct | 0x80000924 | resolved |
| `0x800002d0` | direct | 0x80000cfc | resolved |
| `0x800002f4` | direct | 0x80000cfc | resolved |
| `0x80000308` | direct | 0x80000054 | resolved |
| `0x80000314` | direct | 0x80000cfc | resolved |
| `0x80000360` | direct | 0x80000cfc | resolved |
| `0x80000398` | direct | 0x80000c28 | resolved |
| `0x800003ac` | direct | 0x8000013c | resolved |
| `0x800003cc` | direct | 0x8000026c | resolved |
| `0x8000040c` | direct | 0x8000023c | resolved |
| `0x80000420` | direct | 0x8000023c | resolved |
| `0x80000434` | direct | 0x8000023c | resolved |
| `0x80000494` | direct | 0x80000370 | resolved |
| `0x800004b8` | direct | 0x80000cfc | resolved |
| `0x800004bc` | direct | 0x80000d50 | resolved |
| `0x800004ec` | direct | 0x80000b30 | resolved |
| `0x800004f0` | direct | 0x80000710 | resolved |
| `0x80000500` | direct | 0x80000338 | resolved |
| `0x80000504` | direct | 0x8000043c | resolved |
| `0x8000055c` | direct | 0x80000520 | resolved |
| `0x80000580` | direct | 0x80000530 | resolved |
| `0x80000590` | direct | 0x80000528 | resolved |
| `0x800005b4` | direct | 0x80000530 | resolved |
| `0x8000064c` | direct | 0x80000608 | resolved |
| `0x8000076c` | direct | 0x80000520 | resolved |
| `0x8000077c` | direct | 0x80000530 | resolved |
| `0x80000798` | direct | 0x80000528 | resolved |
| `0x800007a8` | direct | 0x80000530 | resolved |
| `0x800007c4` | direct | 0x8000005c | resolved |
| `0x80000804` | direct | 0x80000540 | resolved |
| `0x80000814` | direct | 0x80000614 | resolved |
| `0x80000834` | direct | 0x8000005c | resolved |
| `0x80000838` | direct | 0x80000064 | resolved |
| `0x80000894` | direct | 0x80000540 | resolved |
| `0x800008a4` | direct | 0x800005d4 | resolved |
| `0x800008cc` | direct | 0x80000614 | resolved |
| `0x800008d8` | direct | 0x80000608 | resolved |
| `0x80000964` | direct | 0x80000540 | resolved |
| `0x80000974` | direct | 0x800005d4 | resolved |
| `0x800009b8` | direct | 0x80000614 | resolved |
| `0x800009cc` | direct | 0x80000678 | resolved |
| `0x800009f8` | direct | 0x8000086c | resolved |
| `0x80000a04` | direct | 0x80000614 | resolved |
| `0x80000a14` | direct | 0x800007e4 | resolved |
| `0x80000a24` | direct | 0x80000608 | resolved |
| `0x80000a38` | direct | 0x800007e4 | resolved |
| `0x80000b0c` | direct | 0x800000a4 | resolved |
| `0x80000b1c` | direct | 0x80000a88 | resolved |
| `0x80000b7c` | direct | 0x80000a88 | resolved |
| `0x80000ba0` | direct | 0x80000ae0 | resolved |
| `0x80000bb8` | direct | 0x80000ae0 | resolved |
| `0x80000bd0` | direct | 0x80000ae0 | resolved |
| `0x80000be8` | direct | 0x80000ae0 | resolved |
| `0x80000c00` | direct | 0x80000ae0 | resolved |
| `0x80000c04` | direct | 0x8000005c | resolved |
| `0x80000c8c` | direct | 0x8000005c | resolved |
| `0x80000ce0` | direct | 0x8000005c | resolved |
| `0x80000d1c` | direct | 0x8000005c | resolved |
| `0x80000d58` | direct | 0x8000005c | resolved |

## 7. Memory Access Analysis

普通 LOAD/STORE 保留为内存行为；没有硬件资源目录时不升级为 MMIO。

| PC | 指令 | 行为 | 地址 | 已知值 | 状态 |
|---|---|---|---|---|---|
| `0x80000038` | `sd zero,0x0(t0)` | MEMORY_STORE | unknown | 0 | partial |
| `0x800000ac` | `sd ra,0x18(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x800000b0` | `sd s0,0x10(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x800000b4` | `sd s1,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x800000bc` | `lw a1,0x0(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800000cc` | `lw a1,0x4(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800000d8` | `ld s1,0x8(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800000f4` | `ld s1,0x10(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000110` | `lw a1,0x18(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000120` | `ld ra,0x18(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000124` | `ld s0,0x10(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000128` | `ld s1,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000144` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000148` | `sd s0,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000150` | `lw a5,0x4(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000168` | `lw a4,0x1c(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000174` | `lw a5,0x0(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000018c` | `ld a0,0x8(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000198` | `ld a5,0x10(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800001ac` | `lw a5,0x18(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800001c0` | `ld a0,0x18(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800001e4` | `ld a5,0x8(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800001f0` | `ld a5,0x10(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800001f8` | `lw a0,0x18(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000204` | `ld a0,0x8(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000210` | `ld a5,0x10(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000021c` | `lw a0,0x18(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000224` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000228` | `ld s0,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000240` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000244` | `lw a5,0x8(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000024c` | `sw a5,0x8(a0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000260` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000270` | `sd ra,0x28(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000274` | `sd s0,0x20(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000278` | `sd s1,0x18(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000027c` | `sd s2,0x10(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000284` | `sd zero,0x8(sp)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000288` | `lw a5,0x0(a1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800002c0` | `ld a5,0x8(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800002c4` | `sd a5,0x10(s2)` | MEMORY_STORE | unknown | not established | partial |
| `0x800002c8` | `ld a1,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800002e8` | `sw a5,0x0(a0)` | MEMORY_STORE | unknown | 4 | partial |
| `0x800002ec` | `lwu a1,0x4(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000300` | `lwu s0,0x4(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000320` | `ld ra,0x28(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000324` | `ld s0,0x20(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000328` | `ld s1,0x18(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000032c` | `ld s2,0x10(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000033c` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000344` | `sw a5,0x0(a0)` | MEMORY_STORE | unknown | 1 | partial |
| `0x80000348` | `sw zero,0x4(a0)` | MEMORY_STORE | unknown | 0 | partial |
| `0x8000034c` | `sw zero,0x8(a0)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000350` | `sw zero,0xc(a0)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000354` | `sd zero,0x10(a0)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000364` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000374` | `sd ra,0x38(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000378` | `sd s0,0x30(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000037c` | `sd s1,0x28(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000380` | `lw a4,0x0(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800003b4` | `lw a5,0x4(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800003b8` | `lw a4,0xc(s1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800003c0` | `sw a5,0xc(s1)` | MEMORY_STORE | unknown | not established | partial |
| `0x800003d8` | `lw a5,0x4(s1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800003e0` | `sw a5,0x4(s1)` | MEMORY_STORE | unknown | not established | partial |
| `0x800003ec` | `ld ra,0x38(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800003f0` | `ld s0,0x30(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800003f4` | `ld s1,0x28(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000418` | `lw a1,0x4(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000440` | `sd ra,0x28(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000444` | `sd s0,0x20(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000448` | `sd s1,0x18(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000044c` | `sd s2,0x10(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000450` | `sd s3,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000454` | `sd s4,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000045c` | `lw a4,-0x458(a4)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000484` | `lw a5,0x0(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004a0` | `lw a5,0x0(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004b0` | `lwu a1,-0x4a0(a1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004c0` | `ld ra,0x28(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004c4` | `ld s0,0x20(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004c8` | `ld s1,0x18(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004cc` | `ld s2,0x10(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004d0` | `ld s3,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004d4` | `ld s4,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800004e4` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x800004e8` | `sd s0,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000508` | `lw a0,0x8(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000510` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000514` | `ld s0,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000544` | `lw a5,-0x540(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000554` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000558` | `sd s0,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000574` | `ld s0,0x0(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800005a8` | `ld s0,0x0(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800005c0` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800005c4` | `ld s0,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800005ec` | `sw a0,0x0(a1)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000644` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000660` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800006d4` | `sd a5,0x0(a2)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000714` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000718` | `sd s0,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000720` | `sw zero,-0x71c(a5)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000750` | `sd zero,0x0(a3)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000758` | `sd zero,0x0(a3)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000760` | `sd zero,0x0(a5)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000794` | `sd a0,0x0(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x800007c0` | `sd a0,0x0(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x800007d0` | `sw a5,-0x7cc(a4)` | MEMORY_STORE | unknown | 1 | partial |
| `0x800007d4` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800007d8` | `ld s0,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800007f0` | `sd ra,0x18(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x800007f4` | `sd s0,0x10(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x800007f8` | `sd s1,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000830` | `sd s1,0x0(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000840` | `ld ra,0x18(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000844` | `ld s0,0x10(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000848` | `ld s1,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000870` | `sd ra,0x38(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000874` | `sd s0,0x30(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000878` | `sd s1,0x28(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000087c` | `sd s2,0x20(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000880` | `sd s3,0x18(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000890` | `sd zero,0x0(a1)` | MEMORY_STORE | unknown | 0 | partial |
| `0x800008b0` | `lwu a5,0xc(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800008c4` | `ld s3,0x0(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800008e8` | `sd s0,0x0(s2)` | MEMORY_STORE | unknown | not established | partial |
| `0x800008f0` | `ld ra,0x38(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800008f4` | `ld s0,0x30(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800008f8` | `ld s1,0x28(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800008fc` | `ld s2,0x20(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000900` | `ld s3,0x18(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000928` | `sd ra,0x28(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x8000092c` | `sd s0,0x20(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000930` | `sd s1,0x18(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000934` | `sd s2,0x10(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000948` | `sd zero,0x0(a1)` | MEMORY_STORE | unknown | 0 | partial |
| `0x8000094c` | `lw a5,0x0(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000970` | `ld a0,0x8(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000980` | `ld a5,0x8(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x8000098c` | `lw s1,0xc(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009a4` | `ld a0,0x0(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009a8` | `sd a0,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x800009ac` | `lw a4,0x0(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009c4` | `lw a1,0x18(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009c8` | `ld a0,0x10(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009dc` | `ld ra,0x28(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009e0` | `ld s0,0x20(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009e4` | `ld s1,0x18(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009e8` | `ld s2,0x10(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x800009f4` | `ld a0,0x8(a0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000a20` | `ld a0,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000a28` | `sd a0,0x0(s2)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000a30` | `ld a1,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000a34` | `lw a0,0xc(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000a44` | `ld a5,0x10(s0)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000a48` | `sd a5,0x0(s2)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000a88` | `lw a3,0x0(a1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000aa4` | `sw a3,0x18(a4)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000aa8` | `lw a3,0x4(a1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000aac` | `sw a3,0x1c(a4)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000ab0` | `ld a3,0x8(a1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000ab4` | `sd a3,0x20(a4)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000ab8` | `ld a4,0x10(a1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000ac8` | `sd a4,0x8(a0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000acc` | `lw a5,0x18(a1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000ad0` | `sw a5,0x10(a0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000ad4` | `lw a5,0x1c(a1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000ad8` | `sw a5,0x14(a0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000ae4` | `sd ra,0x28(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000ae8` | `sd s0,0x20(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000af0` | `sw a1,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000af8` | `sw a5,0x4(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000afc` | `sd a2,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000b00` | `sd a3,0x10(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000b04` | `sw a4,0x18(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000b10` | `sw a0,0x1c(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000b20` | `ld ra,0x28(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000b24` | `ld s0,0x20(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000b34` | `sd ra,0x38(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000b38` | `sd s0,0x30(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000b3c` | `sd s1,0x28(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000b40` | `sd zero,0x0(sp)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000b44` | `sd zero,0x8(sp)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000b48` | `sd zero,0x10(sp)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000b4c` | `sd zero,0x18(sp)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000b58` | `sw zero,0x0(a5)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000b5c` | `sw zero,0x4(a5)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000b60` | `sw zero,0x8(a5)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000b64` | `sw zero,0xc(a5)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000b68` | `sd zero,0x10(a5)` | MEMORY_STORE | unknown | 0 | partial |
| `0x80000c10` | `sw a5,0x3f4(a4)` | MEMORY_STORE | unknown | 5 | partial |
| `0x80000c14` | `ld ra,0x38(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000c18` | `ld s0,0x30(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000c1c` | `ld s1,0x28(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000c30` | `sd ra,0x18(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000c34` | `sd s0,0x10(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000c38` | `sd s1,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000c3c` | `sd s2,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000c48` | `lw a5,0x3bc(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000c50` | `lw s1,0x3b8(s1)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000c6c` | `sw a5,0x39c(a4)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000c74` | `ld ra,0x18(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000c78` | `ld s0,0x10(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000c7c` | `ld s1,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000c80` | `ld s2,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000ca4` | `lw a3,0x18(a4)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000ca8` | `sw a3,0x0(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000cac` | `lw a3,0x1c(a4)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000cb0` | `sw a3,0x4(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000cb4` | `ld a4,0x20(a4)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000cb8` | `sd a4,0x8(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000cc8` | `ld a4,0x8(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000ccc` | `sd a4,0x10(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000cd0` | `lw a4,0x10(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000cd4` | `sw a4,0x18(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000cd8` | `lw a5,0x14(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000cdc` | `sw a5,0x1c(s0)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000ce8` | `sw s1,0x4(s2)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000d00` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000d04` | `sd s0,0x0(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000d10` | `sd a1,0x304(a5)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000d24` | `sw s0,0x2e8(a5)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000d28` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000d2c` | `ld s0,0x0(sp)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000d3c` | `lw a5,0x2d4(a5)` | MEMORY_LOAD | unknown | not established | partial |
| `0x80000d48` | `sw a5,0x2c8(a4)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000d54` | `sd ra,0x8(sp)` | MEMORY_STORE | unknown | not established | partial |
| `0x80000d5c` | `ld ra,0x8(sp)` | MEMORY_LOAD | unknown | not established | partial |

## 8. Hardware-facing Behaviors

当前分析没有硬件资源目录，MMIO 计数为 0。已解析内存地址仍需资源绑定，才能被解释为硬件寄存器访问。

## 9. System/Register/Barrier/Atomic Behaviors

| PC | 所属函数 | 指令 | 行为 | 寄存器 | 证据 ID |
|---|---|---|---|---|---|
| `0x80000010` | `_start` | `csrwi 0x0304,0x0` | SYSTEM_REGISTER_WRITE | 0x0304 | `fwbehavior:14c01a995486f1fd6953a85bb7e603c50238df6ffd5ab483b870578d85b1309e` |
| `0x80000014` | `_start` | `csrci 0x0300,0x8` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:ab44c5441ad9357cf0d19fbe1456f399e78bb68df5ee81e2730eb38aa5ea9f3f` |
| `0x80000014` | `_start` | `csrci 0x0300,0x8` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:b14ee4eb945e4b244496ecd06de0a593561986fb4914b75a591c86d4bf628c49` |
| `0x80000020` | `_start` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:527b58b657da2d32939d38e557dab389b575902b4b73fc7eb528329efdbe68f3` |
| `0x80000054` | `arch_hart_id` | `csrr a0,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | `fwbehavior:5368c08717388353681657e28da388743d1ef4a15a96e06d2832d2ff1fe24c0e` |
| `0x8000005c` | `arch_memory_order` | `fence 0x3,0x3` | MEMORY_BARRIER | — | `fwbehavior:f8166ef2398b72f33ea02844d9b02d13caeff502ab5e834862f9180dd6a6c3f5` |
| `0x80000064` | `arch_translation_sync` | `sfence.vma zero,zero` | TLB_INVALIDATE | — | `fwbehavior:a851877f101a3f0e1a869d88467c73f8400d5efd27d5be2acc57690a92aa53da` |

## 10. Unresolved / Unsupported Facts

- Unsupported instructions/semantics: 15
- Unresolved call targets: 0
- Unknown memory addresses: 230
- Ambiguous ownership: 0
- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.

Unresolved ≠ nonexistent. Unsupported ≠ safe.

- `0x80000038` `23b00200` `sd zero,0x0(t0)` → MEMORY_STORE, partial; unknown; `fwbehavior:5071612030bcec758e31f1e3fc2bdb93762638448db2f21f1f0c577b415e6489`
- `0x80000048` `73005010` `wfi` → UNKNOWN, unsupported; Unsupported mnemonic wfi; `fwbehavior:2465032d00e73675b6a4b311be9205a04c93be545bd46bcdbc6941d2dc207d38`
- `0x80000078` `3b85a702` `mulw a0,a5,a0` → UNKNOWN, unsupported; Unsupported mnemonic mulw; `fwbehavior:2479820efef723b0b240f691597c28b512795f4e709e9b28352f704bc7fcfd97`
- `0x800000ac` `233c1100` `sd ra,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:2dd7d05f1aa164c7211de339a3e86f2298e1d79f3a4f74bb662fb7e9f946b431`
- `0x800000b0` `23388100` `sd s0,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:b25e3ee66a07ff26a74356b48c3e24a9b04a3ba5f5458af6e379b72db2b5f1d3`
- `0x800000b4` `23349100` `sd s1,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:d92478ab70157b86e1001af292e168235a2cbed2cb18b46fc435620eff0b9e6f`
- `0x800000bc` `83250500` `lw a1,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:be0aef07aa39ab3bca6b018cb00cfa8c877250b2064b9edd6f7139759485939c`
- `0x800000cc` `83254400` `lw a1,0x4(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e3838f56e789b9438203bddea4107a84ee85a9b8256037be0acfb159ebb2a315`
- `0x800000d0` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:47c5b9811537daaa3d104aed167e81230711c88ce9db8df4abcfd458fa0f92f9`
- `0x800000d8` `83348400` `ld s1,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:2a3c0b60b59f099d430b3e4d1500a3c1a0700f2da570517473ff5c02175e67f4`
- `0x800000dc` `9b850400` `sext.w a1,s1` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:9b09965013837a6bff7b84e4d32b4be09bfff9efee59b437d8b02cdce295aaca`
- `0x800000e0` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:c02e1e9a5ac6af1c9a2533127db1eb713b3e5091048262cc6a82449b4c1d61b9`
- `0x800000ec` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:bdebdfb365798cf8d8a130ad45c15d3edc830b2ad4609994d22b944f47151c35`
- `0x800000f4` `83340401` `ld s1,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:77d68ae4e2f1fb1b6bb0147fd2d0b56ae7d90f277bf00a9d11598ec9b12ef412`
- `0x800000f8` `9b850400` `sext.w a1,s1` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:09ec0f1f90f3cfbd50f9f34decdd04308edf0eb8a791c58a1de146a5a5e27f79`
- `0x800000fc` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:e6db919f702e7a560bf5b8dfc00a2d70832c19b95357cd4e7b4068581d9cea51`
- `0x80000108` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:9a6e7b581495887ae96eff0ce0f708e18e61eb20f8fa0a9580034fa4d5b68fd1`
- `0x80000110` `83258401` `lw a1,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:cdb9f5732a617b3343e2f3ad7b457d9695fc5a7325c03bc15d2b10f14f295285`
- `0x80000114` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:b99de38314f9a5ddcfbb64002b68d2e62a4b1465d37597c1d9e4a2d91afbe017`
- `0x8000011c` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:2ad1d9aa2ff411eb4322059715ab572041e569c701e07f132788b0c48c7d5f1c`
- `0x80000120` `83308101` `ld ra,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:70e00972997fc8061949ed2308176852df0a5760fc0b328c46b15b2108562af7`
- `0x80000124` `03340101` `ld s0,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:595d6d8c533e79b2bd4d018330f082f6a171d0b3fff931688e0f98bf17840e28`
- `0x80000128` `83348100` `ld s1,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0f21049a2d8beebd3005593cb3d4f720ccc2ae5e1999afec5e49c9c4554780e1`
- `0x80000144` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:ec7a32f4da7a5a6d9f84133a933b48781cb5f6ca6e24aa30b74cd13dacb638cd`
- `0x80000148` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:ba6d964da0c658a424d2f8a51d1c50baf862fc9a80c17c109645bf2c8e20df50`
- `0x80000150` `83274500` `lw a5,0x4(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b5dccb88f3379bb0967557c62cf16ce3f34ac9ef15ce51fc347c18849b818fb5`
- `0x80000164` `9b070500` `sext.w a5,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:1ea535ee7be4edf6e706b3229f98eb54ba990aea0446d3216e8417d8c4444b62`
- `0x80000168` `0327c401` `lw a4,0x1c(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0693564731430aecaaa79ffb9392b0ac5a366a2fc2a732827c91019e20d23de8`
- `0x80000174` `83270400` `lw a5,0x0(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8e312882c32469974658583da4a8fc2d1a52da98e34c7b316b5d24f97435c9f1`
- `0x8000018c` `03358400` `ld a0,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:284089f91a8ff85f0dd88f682a57d0853ddb9a46fce03ee7b9ab8cbca1b64529`
- `0x80000198` `83370401` `ld a5,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5313a2e4409375bd4a19683f643d55839d078da31ecce73967cfe5e597af0826`
- `0x800001ac` `83278401` `lw a5,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:1fae0475377b5b5f3509a1dc0507e6fd66e15fc45ae8ae484655f53ac2da0f0a`
- `0x800001c0` `03358401` `ld a0,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6dd72ecd6f768129fe1e1db7fc984b05a93982bd2b81366109292ae14e2dc956`
- `0x800001e4` `83378400` `ld a5,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:04a9107a1557f8ea7ec160c55c6efba95451ea6de51e667248398485a743c2cd`
- `0x800001f0` `83370401` `ld a5,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5461beb8e24245b7f42d6a8668aab2f277d9877f1136e44b8b688b45c134fd4f`
- `0x800001f8` `03258401` `lw a0,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a641b223316c76859f6b4d37bed13ab9f617782d28fdad56ba7e1e0a9515d9cd`
- `0x80000204` `03358400` `ld a0,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:4909eb8c2dce0c64fb6148150977603878831a890458db023b1b430a88827784`
- `0x80000210` `83370401` `ld a5,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5fa11da69198a60c27ae7fd3f1ca018329c9158663cec9aaede5065e69c519a6`
- `0x8000021c` `03258401` `lw a0,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a531d2d44ba5c2fc2c704f10dec7d8f01ab045a315002499354c069c78df6a51`
- `0x80000224` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6295c82be071dfe66a2a91a1f6311c487545ef411e9482121f91ba36bedee90b`
- `0x80000228` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:df1f4b55d8a4048e36ee9fe5ecdade3c1d16b82f3762d47af110058566dbc459`
- `0x80000240` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:114fd05f53ad93948325346c13efdd3b87cca6f47f1f81083b2020b7a101fd80`
- `0x80000244` `83278500` `lw a5,0x8(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:028a4c3ba64033fccfa640f667ec8a421551959effed333f2f0e7d469075f025`
- `0x8000024c` `2324f500` `sw a5,0x8(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:bbca26dd93448f6094e05ee80581d0b397b8eed28cc50e496c63d057d8d56c1c`
- `0x80000260` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ba42179ad303db69cd462e9e0829b761d72ec191e4f0cfd93dbf543730585be8`
- `0x80000270` `23341102` `sd ra,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:8793a4efff6eaaec060c126f52aa1775dee6077ef585a44bc03c97de4f18ee46`
- `0x80000274` `23308102` `sd s0,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:c4a0a5f1dfed1fe78a6f1283bfe02e11086fbcceadd03f57ac4e0459c675e882`
- `0x80000278` `233c9100` `sd s1,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:238e9ede0bf07070d8b81959c71326fea2747d34e98839b9cbf5457bc320a368`
- `0x8000027c` `23382101` `sd s2,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:206e985797c267837685653c2f923522c2884c6635ad1b23cce567f5f8d99b58`
- `0x80000284` `23340100` `sd zero,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:91ec0bb35b53964395092064917370fef149f6b3df10d3f4fc1425fb1b7a1209`
- `0x80000288` `83a70500` `lw a5,0x0(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ab1ee39a51efc4361c8a54307da2a7122da6ca1dd1539d36bb9404a6a27337f9`
- `0x800002c0` `83378400` `ld a5,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:1a2bce427a842e4cbc93b1206437278e57edafcec887d29c2434d2168dfe9787`
- `0x800002c4` `2338f900` `sd a5,0x10(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:f16bfb8e7bfadf8dfcbc62f0e35733d5334d6b5ca16b454c40a70f64ba7b3f17`
- `0x800002c8` `83358100` `ld a1,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:881c852080783f048c381df0a359011b570bd94f526cadf21831d89c0e9615ed`
- `0x800002e8` `2320f500` `sw a5,0x0(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:2559269b59b9aa5b34d0cbf3dca1c252e9783cee8150dc6a6eead5dc296fa9f2`
- `0x800002ec` `83654500` `lwu a1,0x4(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8b4ea292d0dea282702dd0b515accddeebb700489e175c933358982ac6bd512a`
- `0x80000300` `03644500` `lwu s0,0x4(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:07cf4fc86a76d668f701c2bdfc23a01f28e5f0128c06b96d4859a75bbe38adee`
- `0x80000320` `83308102` `ld ra,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:033557d8439630342ed3e3ef3002d6b807e4674b41508cc6e48bcb85b9df0494`
- `0x80000324` `03340102` `ld s0,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a502aef7bcc94943fbeac87f913db25e2a7654abd08e52a73c73d92e7ab74850`
- `0x80000328` `83348101` `ld s1,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:200edc23fd02d4c9219951a3fee4de2f8c5a9ec0ee8fbe55bb81f853dd35fc6a`
- `0x8000032c` `03390101` `ld s2,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:4721fdd533eaa91fad07eb283ff78692f9fe10b2bdf5e39e4db646b84adaaf75`
- `0x8000033c` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:4104c6dc1ef798add78a1b3e94a3d2ae7497d2c1dfbc0d783896a498d2c46f78`
- `0x80000344` `2320f500` `sw a5,0x0(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:6b4677480c6ff9ad52be85e275d4b45c8b6cfe412df8c6227857522a6a495cae`
- `0x80000348` `23220500` `sw zero,0x4(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:9dba2c472ab3bb9c45362fdc731309ec86db694a8ebee32fec8165bdcad4586f`
- `0x8000034c` `23240500` `sw zero,0x8(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:a54e20d8f4c6d34afe23edcad2637ed7c8faa1f00cd58def6e48502745f71164`
- `0x80000350` `23260500` `sw zero,0xc(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:d14c177c01d5bba16d6c2e54a40eec6dccb83e90c56df701ec829627e1a0e296`
- `0x80000354` `23380500` `sd zero,0x10(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:c0fd97f1ab0ccf2b201b685962608f97b5b3b12ec21620a51d651a216ae583a9`
- `0x80000364` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:1df3e887907f81cc241b4cdfa431b48ac2b5f9d2a80ed2f10621851c7d3ce695`
- `0x80000374` `233c1102` `sd ra,0x38(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:1bb235c113da4be1573cdd9c00fb6308e567b21698e1336d25dbad2c6b8d56e9`
- `0x80000378` `23388102` `sd s0,0x30(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:06ebf2549d9a8502031927addf55a33fe02afadbc1563344949442f0b535be50`
- `0x8000037c` `23349102` `sd s1,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:3677f967c6b8d61372d8667e6b082173f5d2073eab2071259b758c2472db4250`
- `0x80000380` `03270500` `lw a4,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ed1557c872ee8b5da80c25b4abeb0c7f26d0d6e2a78156403e57ff0789777803`
- `0x800003b4` `83274100` `lw a5,0x4(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b60138631ff3198e273ccb8351975d6eb259300d277fe58d4519a0aa1e8b4ed8`
- `0x800003b8` `03a7c400` `lw a4,0xc(s1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a19c91152572ee3e554c59acf93b4f0046184d280a05693b552e90f4c9f1d6a7`
- `0x800003c0` `23a6f400` `sw a5,0xc(s1)` → MEMORY_STORE, partial; unknown; `fwbehavior:b6455238c9e7c56a6ecd73ecf692ee958fd8a7410c9abb306927bf6417081802`
- `0x800003d8` `83a74400` `lw a5,0x4(s1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:3d482c634fca6caf41c1131913cc1657509e9624ea2ba901e3536c9ab9f82b8a`
- `0x800003e0` `23a2f400` `sw a5,0x4(s1)` → MEMORY_STORE, partial; unknown; `fwbehavior:e11fae434bd032995518453822b9e850fecb8baff96fa36a3fda30baf2cda314`
- `0x800003ec` `83308103` `ld ra,0x38(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8f93833ef83dc5620f96af31d86196d0dd5852a904572a866182ada9836371c0`
- `0x800003f0` `03340103` `ld s0,0x30(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0ed41d0eee05adc4a4071c33deb12a2e19eb2638a2cea1621185d20800b0cca0`
- `0x800003f4` `83348102` `ld s1,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:277da9c78d4b60b6d855e9df81a363da7087713abd30be7ccdc624c038f059fd`
- `0x80000418` `83254100` `lw a1,0x4(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d6ec414896b773db2fe9bc0691ee1007111066a2f32a37289f94b49daf16c480`
- `0x8000042c` `bb05a040` `negw a1,a0` → UNKNOWN, unsupported; Unsupported mnemonic negw; `fwbehavior:7a068444b552d459187d28ef25de261639102a16989621f10bc238c60d92bb1c`
- `0x80000440` `23341102` `sd ra,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:4e3643a6ff2fc1a090c8da31c2708a5a9276d190e2357e840d4ee9d28167da7b`
- `0x80000444` `23308102` `sd s0,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:4fc9370ffe35a579296406a9eb0fb68281e9d56dfc1baa8f7b71069a70400526`
- `0x80000448` `233c9100` `sd s1,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:4448c92fb45cce2990e5c93ff428536b33cbc6cb0f8342237b37b50869d92c92`
- `0x8000044c` `23382101` `sd s2,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:0e7c36dcf186321e4c72217ec8339ae583a7160e5b0d9bc4c1240c9616c039cb`
- `0x80000450` `23343101` `sd s3,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:cae8f0e7345252f1cda00c8ec8288b693fbc723e18736674ca72e07e1b2bbc35`
- `0x80000454` `23304101` `sd s4,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:8a3218a1439ac4038db1b930357f8a39265153a6f38bc939fb247589566ccf20`
- `0x8000045c` `032787ba` `lw a4,-0x458(a4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6023b13ba2abc550fb4672adc91679e32a3e9a58107a521c31c40b9f99e95c55`
- `0x80000484` `83270400` `lw a5,0x0(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f6ead10672dc96d20667e01a4aa99847433d4dbefba839d773586a3cf906c393`
- `0x800004a0` `83270400` `lw a5,0x0(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5eec39d2d0460c9924e1a4afe4603091d7adbab1504ef0e199b2a41b7ac7e0e6`
- `0x800004b0` `83e505b6` `lwu a1,-0x4a0(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:005ad8fc1e3b2becd0506bb8d8376b5c6b1a68e1f5bb1771e3a9b9daa7e3b52c`
- `0x800004c0` `83308102` `ld ra,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c171c08d477cec7dd6d81bb0d2dc53362ed5d4ad1f4b21bd4c3406992ed5e1ed`
- `0x800004c4` `03340102` `ld s0,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:00fd892c83920db9a6f92aa4559a45db3df92b651f75a7fdbeca7eb07ec633fb`
- `0x800004c8` `83348101` `ld s1,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:571df914e08409ca78059bff90eecfc4723b8a3c2a243e365d160aa674106f84`
- `0x800004cc` `03390101` `ld s2,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:670aca60cd392e068b10f76901fb0cff8e0330d9e88b15219ff5ffeb9566c6f3`
- `0x800004d0` `83398100` `ld s3,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:3a114ce17e549d9d3a2ed2bcecb773d91dc679f4ef93d1ecb2be825daa920790`
- `0x800004d4` `033a0100` `ld s4,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:16020ce9de0385fb5d3af598e11cb2825c811261bc3ca739e3e3680bef0b91fb`
- `0x800004e4` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:a1efe1def360a615bddfcf21dcf8f024cae6eaab422e7eb10f9d2b483025fbff`
- `0x800004e8` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:0048584dcd09023ee618d24fd66b6345458faf673173899d2743444c4c3b776b`
- `0x80000508` `03258400` `lw a0,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:abc9172fedbf4fda774cf04bf3ab8987040bb8e76d6a1e9ea14a2eb86f9ad118`
- `0x80000510` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a296fb38dca9393e2c6d75f259dfabc8471f82857125ec1fc32dfaa079f95bfa`
- `0x80000514` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:36f86edd61071ec95e2e6628149f7925578a506fc9da62145427a59908af0c10`
- `0x80000544` `83a707ac` `lw a5,-0x540(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:40c8a326c661dca354015612e5a3f1ddb0f01b1b130fb73230c5e99e883cef46`
- `0x80000554` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:83ebdd2587f4de345c525c928ca48d581c8e3d67c91dd5efffc061f6d33ef2e8`
- `0x80000558` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:d7a644211b98d3836bc7defe5c8a170a4c378205913558a196e1fc856469b9b8`
- `0x80000574` `03340500` `ld s0,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:dbe1a051a95873481b336bb6ffdde4e1c1673957cc64872299a3927fc5b97c5a`
- `0x800005a8` `03340500` `ld s0,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:170e3ac97a08a8fe2f9e0e45d82d3ac13c7a73f922b2e31efd27905d43d11ba8`
- `0x800005c0` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:1db248763ebd2a5a96d0f2fcc22562683bdabe11f524c9ac8e66e630255dd606`
- `0x800005c4` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:2cd154a126f414f61c1f9178b8ad4b027f1340e050541057df0fd56826a687d2`
- `0x800005ec` `23a0a500` `sw a0,0x0(a1)` → MEMORY_STORE, partial; unknown; `fwbehavior:8dd4c701b637102a78ba7704e5eca10de1a49e66114e83f0c03aa4445951db0b`
- `0x80000644` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:db8454e8bcf30859ebfaab032f467f5133e3f7ee5d1e749d95cc5537fef5cc4b`
- `0x80000660` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:785d42704985ea9d8819cf8d9f562b942f63a5d4bf47c7a4d78b62bc9e8cb5d1`
- `0x800006d4` `2330f600` `sd a5,0x0(a2)` → MEMORY_STORE, partial; unknown; `fwbehavior:28c964663621a2f5e19191f86968349e8a691a8fe2f9570108aa8c4c2173cc4a`
- `0x80000714` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:115acdae555b7c4920d328629bf754b5cf794734179653adacd9a7e33848a809`
- `0x80000718` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:491e377a612c108f0fc50f996533946a2fb2d2ce08a322402ff8409deb234cf9`
- `0x80000720` `23a2078e` `sw zero,-0x71c(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:b40f04f9d27f49a92d8d931bd61874b4f25e5075f8ff9824e18d90c7dd9c19bd`
- `0x80000750` `23b00600` `sd zero,0x0(a3)` → MEMORY_STORE, partial; unknown; `fwbehavior:7b8486b758827dc88227d901bedda0cf99cec627e64f50328fd666454abff8b5`
- `0x80000758` `23b00600` `sd zero,0x0(a3)` → MEMORY_STORE, partial; unknown; `fwbehavior:e823651ce0dd53a644b06cbcdec29b5ccb369bd75b4469fd85c3f0c3c963ff10`
- `0x80000760` `23b00700` `sd zero,0x0(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:19b4f8abde052a619e55a742a7e374a7e89cbc02cff1246b14c9f120dc00fe39`
- `0x80000770` `1b040500` `sext.w s0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:cc7a09afd66de0cb62b3e03d2d5684ad477d92a3073796c20a48e7137f768abf`
- `0x80000794` `2330a400` `sd a0,0x0(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:5e0f13508278a2befc33464eb4f8b98d635255b742c33c396728977a077354da`
- `0x8000079c` `1b040500` `sext.w s0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:7e2777eeca09c35f9a28f0925652557f167b0a5371c880837cd350229d96eb84`
- `0x800007c0` `2330a400` `sd a0,0x0(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:8289ef16fe286a710764727b3f350444ddaae0cf9b718f5a3251acf2906a8985`
- `0x800007d0` `232af782` `sw a5,-0x7cc(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:bbfb7651611eb8b7ee26d7f963e424f9df1972135038b3bcb39775e25f755cce`
- `0x800007d4` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e8d703ae67d6b65c46e3e1a7be2f83e892f1faab34a2b018b449b51247b370dc`
- `0x800007d8` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:98c9a82ed5d5c8cb8cd34f627f3e8682036db5366fc2b4b1f72b71ceaf7e5299`
- `0x800007f0` `233c1100` `sd ra,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:eb49da6de75a3ada43273d32cff27de96cbdd947c6ec2711e7b40e0fb5f610fd`
- `0x800007f4` `23388100` `sd s0,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:d946aa4c6011152fa1014717d71b60628b80f84c2cbb74ec2df4392051f08c8a`
- `0x800007f8` `23349100` `sd s1,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:b0c17fb39de8ff4bdce874a7fc4e61deec369841adee59f6f1e0e3405d57bbcb`
- `0x80000830` `23309400` `sd s1,0x0(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:5d78ddfc36e95bcea972480ace779a223e46973db75cb8526ce086cc02b9c457`
- `0x80000840` `83308101` `ld ra,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:491fd00fa5d49c6c8ffb6a120bc20eeebbebba383644c60d5171c067c7ad5862`
- `0x80000844` `03340101` `ld s0,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b3317442e8db600302a9f14104105aad401f686fb9ee605351613a55c616386d`
- `0x80000848` `83348100` `ld s1,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a483a5577881d0d4927291c96c2bce1eb91da758f4aec7388c08617525cf016c`
- `0x80000870` `233c1102` `sd ra,0x38(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:8df22ab75a60b14698fb29bbc32e572ac5bc295a60e3d0867dbf19402349d4bf`
- `0x80000874` `23388102` `sd s0,0x30(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:176129b70332445be50c897e8af76d26fc870b038cc07d695baea71394e7f84a`
- `0x80000878` `23349102` `sd s1,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e6abf3581363e199e754939f7111cfda02460ea06eb0fe544e7ba04bddbaad3d`
- `0x8000087c` `23302103` `sd s2,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:675f587d96d18124e167e6a5705bce46ff03c76c630c7aa31aae287040417f2a`
- `0x80000880` `233c3101` `sd s3,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:1ca3372920a5654cad45ed1b49923c93857075d3d76b91f12585e84283010249`
- `0x80000890` `23b00500` `sd zero,0x0(a1)` → MEMORY_STORE, partial; unknown; `fwbehavior:7a74fe361e622d4e08ffbb78ec029ee7e2974e8697ef7d91b989a4fb5adc9af3`
- `0x800008b0` `8367c100` `lwu a5,0xc(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0062d5f94037fa7facaf71552a6631c0304e981053abd25b8ea3357436d1ef8a`
- `0x800008c4` `83b90700` `ld s3,0x0(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:4c9b74070bad06caa15b8d762f1a80f72cee37d29166ac5bfd6cb177cba6ee30`
- `0x800008e8` `23308900` `sd s0,0x0(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:620eae0adbe00a2454c9373ede4b3bccc9588283a3dc81e0ab0ba510028da96c`
- `0x800008f0` `83308103` `ld ra,0x38(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8c48bbc5c15b2629a7c0ee2fb11d1f1b2ec6746d275ee6bcc7c4d624f52773dc`
- `0x800008f4` `03340103` `ld s0,0x30(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:baa6418577b8269bf8e5b6ceeca4f8c23f7a1a2fcf4cea3ca41d3ffd97211caa`
- `0x800008f8` `83348102` `ld s1,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:42793e2ea5b445b5d482969d7e181c01e79009296654549bdd4d0664f2c2b2dd`
- `0x800008fc` `03390102` `ld s2,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a03d0d555676c925d9e3f53e49774d50119aaa1218d80d751f7af9255374530f`
- `0x80000900` `83398101` `ld s3,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:71e4a6f77936068379bafada8bfddfff5611cae3d8eea15925693d8c3755f962`
- `0x80000928` `23341102` `sd ra,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:70d8dcc365738587e33bf936d8974f45391f8ecd787878066b642cd0d30746d8`
- `0x8000092c` `23308102` `sd s0,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:2125ab55e98c38a5cda1252fe8ce79690efe322572050959472ec5012bd8c947`
- `0x80000930` `233c9100` `sd s1,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:31f85c45261b6ef407832e39aabde6d6df1a86150729d828088fc98874bdc502`
- `0x80000934` `23382101` `sd s2,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e4d9561a261706ea2b78b7c75095da52b0f5e50a67b7509e0c5cfbafc9f15e2b`
- `0x80000948` `23b00500` `sd zero,0x0(a1)` → MEMORY_STORE, partial; unknown; `fwbehavior:491c5698518c723fdf2d2888925eda4b56b8d78e8c4cd07e867dddd4562b57ff`
- `0x8000094c` `83270500` `lw a5,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f10ec4acfcbf1150af814807ba3175757c83c210c488d863f8ee214aa487ed72`
- `0x80000970` `03358400` `ld a0,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:9f5b80e0a3c294dd17e5e0dcfc1afd0cfd7adb0bc9d630c9e0b3169c73d7028d`
- `0x80000980` `83378400` `ld a5,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:9741844ed9d0b1427c0854e62586dad44e918d551913ccb49642a5d40e020684`
- `0x8000098c` `8324c100` `lw s1,0xc(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:171bea67bc583026af3baa54e0a5a4cb1f3b51063d3a07889be3e16feef08c2e`
- `0x800009a4` `03b50700` `ld a0,0x0(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6dea3619f41ce3cb649ec703ac98e0d0b1114fb1b71006fb894ba608b258ddd0`
- `0x800009a8` `2330a100` `sd a0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:532c93347e72af3c4feb0645dc0e9410ddb7bf6ce2a08c49bdd4b2d4dbc14c87`
- `0x800009ac` `03270400` `lw a4,0x0(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:93deeb253ec796756e6f4ce673a32171d264301d287e05058f568821a188cfdc`
- `0x800009c4` `83258401` `lw a1,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d523d7e9bfb1e513907e50ccf8f57a7676cdc16a077a2087c3ff0acb42cce2b8`
- `0x800009c8` `03350401` `ld a0,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:dc4b7376cc229e943c469cd1d260a0daab52b58bd9c1fc55b97bd86607cc4f32`
- `0x800009dc` `83308102` `ld ra,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6ab2ba7d753a8aef99b69f62ba724c16c794729407ebcdafabac99b5834f4f2e`
- `0x800009e0` `03340102` `ld s0,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8a5180818025bd0842fd182ff0a70926c8112cbf123007a180dbfb4514a01b38`
- `0x800009e4` `83348101` `ld s1,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:3c96cd441711b09f12f3a1d747d26941791cfcedf47622e62ca7321ea19538f3`
- `0x800009e8` `03390101` `ld s2,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b253b3b43a9a61bfdfe191bdd40fe6bf49abb74bd806db16320bae639e15a22e`
- `0x800009f4` `03358500` `ld a0,0x8(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a716549d190846b6cec1a2bfe5d34a546c31be55cb5759e2a26fcbc79b7d9151`
- `0x80000a20` `03350100` `ld a0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:2b2f41e077318af7407fcddd60857b626a0a1146dfe6b634367f042c7bcab045`
- `0x80000a28` `2330a900` `sd a0,0x0(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:e6f56daba15da911efa575dcbd008df096d9a2a20e96c3a54ca39d1098bf356e`
- `0x80000a30` `83350100` `ld a1,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:093556e47dc913de7c7159440aa4102fbef58047d538030cc3421a3e62e41e5b`
- `0x80000a34` `0325c100` `lw a0,0xc(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:39e2d4768720dfd5f294732dd4c97075c950830f50d979e7322ecdfd4dd7c487`
- `0x80000a44` `83370401` `ld a5,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8a528b5246bde0d5ba35a8ed8e89a0acc2f671eed6c06bebcbd92502ae85af4e`
- `0x80000a48` `2330f900` `sd a5,0x0(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:a9e360d823ebee7dd629038996aba37bcaf05eeb75d65edd3a965b4e8ba7e0ee`
- `0x80000a88` `83a60500` `lw a3,0x0(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f6af19d7ad7d3c1c56d0abff123313151d7ebd3da7d0ae37683b2bb398ac3498`
- `0x80000aa4` `232cd700` `sw a3,0x18(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:c3ed18a65f209b9f8df8a52330475318ff0b3443ed4e0382d280fc3fe09be586`
- `0x80000aa8` `83a64500` `lw a3,0x4(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:4d4d215528f2a53cc43d182b8a1850dc59b4bd7a87e5e58bfc6f27c50b04e835`
- `0x80000aac` `232ed700` `sw a3,0x1c(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:d22801dfefa18d938717f0c7a34bc8ee7ef28eaa7b875f18c40c3d0a162e76d7`
- `0x80000ab0` `83b68500` `ld a3,0x8(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:cfe8c26d0fbba4cedc778fdd18e5c54eda85d3bc339c7f769c93035fd3947f1d`
- `0x80000ab4` `2330d702` `sd a3,0x20(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:7405e5bdcba0c32d4526b74faf6e9a53a16d30e2f7ff271d4874426c5bb3312f`
- `0x80000ab8` `03b70501` `ld a4,0x10(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:cc10dfcf9a772eedca789dd9535946c3fcb7b102554b53b36cb61e88724342b9`
- `0x80000ac8` `2334e500` `sd a4,0x8(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:180d6a5b2fcad533b8745e202fcad34738e5c505659537c2ed246e21e2a93488`
- `0x80000acc` `83a78501` `lw a5,0x18(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:650237209075ee521887ca58edae1e121aa6d5f793daedbbf04b51e1439a8f75`
- `0x80000ad0` `2328f500` `sw a5,0x10(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:f7a094c8f94c24bc572736f98303eeb426291debed9c20ab53d3c5722198dbdc`
- `0x80000ad4` `83a7c501` `lw a5,0x1c(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:12489b1af54b51db75a341a5f86d0a1b8031dbdc3aaeb18265d7fca61d48c93a`
- `0x80000ad8` `232af500` `sw a5,0x14(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:af13064780406b4bc5382643c5210cc2795917237426b4a233d26bb3c68d723e`
- `0x80000ae4` `23341102` `sd ra,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:f1f9cce12f9b59a2c0308d0865cb4c84ab1573b12cbdfb94fae0e7859172e16b`
- `0x80000ae8` `23308102` `sd s0,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:b681536ab5ee7df61756262b22bc788a190e7cd32bf8b645b6a2369704397ebf`
- `0x80000af0` `2320b100` `sw a1,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:94a610753253070531b5d4dbf2665fa2c5302954157e8b6632ab467a2c1c55d6`
- `0x80000af8` `2322f100` `sw a5,0x4(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:6ecd6bfce793ca72c615a95ce0dcf4b98dd9c423ed5c85d2636f62565c8a6a87`
- `0x80000afc` `2334c100` `sd a2,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e352d407d4806516f609d8b97fd450c1bffffbdd4532a26511afd9b36647e91a`
- `0x80000b00` `2338d100` `sd a3,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:eda6f3a47d185dc453df7ae058ccc607262f206d29cd76b2abd7522b209d1319`
- `0x80000b04` `232ce100` `sw a4,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:1da5a1f79a9787ef32312e7f037347bc9b95d0c19096e85b8fbc7e4faf70ee3b`
- `0x80000b10` `232ea100` `sw a0,0x1c(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:c1b6b591f896bf5fffdd0e8457329d0474208ced5c2832a72bf4916ada9d2b73`
- `0x80000b20` `83308102` `ld ra,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e01af5e9dbaa5f5ce18bd790d0f7ffda9d9bbb9214bf33097b9f4d95c6f6c9e2`
- `0x80000b24` `03340102` `ld s0,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:1352cecc81df1ff38966d172aee2f6f2b1db6b6344cea3669e3d4da0a29eb511`
- `0x80000b34` `233c1102` `sd ra,0x38(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:8b0ce9886d97dcc4c0ae4913772fcf288a3242be2fa85dc740ad94507e60afc3`
- `0x80000b38` `23388102` `sd s0,0x30(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:0e7351686519153551a47f1e47427d880156574dcc79cf552e0e0debc126f6fc`
- `0x80000b3c` `23349102` `sd s1,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:8751268710cb6080cf9442c3335088de582e146485fd69d38b6c8eb1527f2c37`
- `0x80000b40` `23300100` `sd zero,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e01055724bd78cdb6079b133399131efe98a2f3f3353f7601cb1c984936f9f44`
- `0x80000b44` `23340100` `sd zero,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:2b2bd5fb98ee7c3188f7baa6e237865cc1be6b348dcd47bbc68de4255eab13f7`
- `0x80000b48` `23380100` `sd zero,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:7f44c37fb567bf1162fba3c83b7a5b06e616eb9c118262c97c0af7eed47ba061`
- `0x80000b4c` `233c0100` `sd zero,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:d2a6f3ec768dc147235b488c7e07ad1977c518a21fc3e21e42e097668e54fb53`
- `0x80000b58` `23a00700` `sw zero,0x0(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:14aed3f572052e2f99a9945bc9026034a83e9d6626e8c8d2d631b809748e4f48`
- `0x80000b5c` `23a20700` `sw zero,0x4(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:4a9967bb736e758d95203987abc664f12b78cc0617ba4873bf6a2629d9598e08`
- `0x80000b60` `23a40700` `sw zero,0x8(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:0a6286c2417711194b40aff0aa4ff31d23d6446b009a73bbeb6d79d72a5f1b92`
- `0x80000b64` `23a60700` `sw zero,0xc(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:a32d2af1c08a3e2bf123e680afa816811cc8e88de720f339af998b6162b3868d`
- `0x80000b68` `23b80700` `sd zero,0x10(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:87b9c14b6b24038ff94793628f2322981eadb6d5e7af5095d66a2bda98c9fe37`
- `0x80000c10` `232af73e` `sw a5,0x3f4(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:dc6ba31d13a20051905e2ddcc3a331bb30305a79652c3a28fe6a835bef97626d`
- `0x80000c14` `83308103` `ld ra,0x38(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:fc4b165b6edc6bbe3969944fbdcd7969ae58e4e0de097741bc006635288d1639`
- `0x80000c18` `03340103` `ld s0,0x30(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5f6ae5097b7e0ae67e7cde2b3ecec241d4e4b90c06fe888452671d6aa48e3bb2`
- `0x80000c1c` `83348102` `ld s1,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e95d13d9b1301015c0bd912dfd1a0d78cf4764702bb4140664c4b671f35512e5`
- `0x80000c30` `233c1100` `sd ra,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:de92ba2ad1bf615daa315c3976cef9c97851a541aebaf1b682bd2cd672057d61`
- `0x80000c34` `23388100` `sd s0,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:91b79c1b0ce31b34e7ddadc6b1cb72adc45f16767bea0af21a84e3b6ecd1c8ff`
- `0x80000c38` `23349100` `sd s1,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e6e9bf63f0b624f8cc179de31024148923c5ab4da1a5a2c1e4a29df8a49777dc`
- `0x80000c3c` `23302101` `sd s2,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:fdd7db799f2d3c4151910cb46f81fb9340c4b57223bda753be5bcf7ff01c099c`
- `0x80000c48` `83a7c73b` `lw a5,0x3bc(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:2948dbc8404a80e94704592a57c25db87ba90d5eec2f55d7c19971bb39a72603`
- `0x80000c50` `83a4843b` `lw s1,0x3b8(s1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5644f3e26e643d6dc5a3c36f78f7ee28f9ecbc7815230a91c2abde67e0bc7110`
- `0x80000c6c` `232ef738` `sw a5,0x39c(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:afe770a35a8ae58f63177ec203ac69eb714d2b112345c96c424fcd2be1e400ef`
- `0x80000c74` `83308101` `ld ra,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:194b606351c7f9bcd9ce50fe4e4412bee38dabe16c8e0eb4719e12211bb015ef`
- `0x80000c78` `03340101` `ld s0,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:506b67f6908326d55b223b2e19e2b11cc690dac39c51b08836e29543cad8a192`
- `0x80000c7c` `83348100` `ld s1,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:438ec6b9e46f62c04251757364b1771cbd4687c17f632e36674d53de4787dbd3`
- `0x80000c80` `03390100` `ld s2,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:82d6ecf470cdedf7e5a0c279c5cc627214bdd0bfb7564b964270d4e9888b359a`
- `0x80000ca4` `83268701` `lw a3,0x18(a4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:1a276fabe6ca086a66e96c76d8a38d9ee176754b56abc94ce5138a5ae09db147`
- `0x80000ca8` `2320d400` `sw a3,0x0(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:fc828e83b24ec4d93e878f81248760cf9a46b51861dd0ed842406572cb0b8559`
- `0x80000cac` `8326c701` `lw a3,0x1c(a4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6de4fed21272bfe1025d3c16f3773dfb1d134ed07143a3efd65356eb4c12d827`
- `0x80000cb0` `2322d400` `sw a3,0x4(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:f5e8c13ba805024aed1aba6e2a504f546b8ae68d209ea0a825e0702b6ce06de2`
- `0x80000cb4` `03370702` `ld a4,0x20(a4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:454045731cfcf2d95e1fb8452cde159bdbb2575774f22546efed9763f32c5306`
- `0x80000cb8` `2334e400` `sd a4,0x8(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:360e45a94783840398cf49c91d6ec24795edbd89e6d7c9b812582d471ab4b242`
- `0x80000cc8` `03b78700` `ld a4,0x8(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:738f154d57193e4404cb4c2b058e2d76ffb19badda9a860817e24beba92f907c`
- `0x80000ccc` `2338e400` `sd a4,0x10(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:edbad8d938ddc7ac3553d08039104009a78b2e9f2d8c17ef11506c8f09013061`
- `0x80000cd0` `03a70701` `lw a4,0x10(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:44ce824a9071881d1472cd7182c142fa83b05dd23019ed8148a85e4b79023376`
- `0x80000cd4` `232ce400` `sw a4,0x18(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:50b6d55f5e4fa10edbaa056ef65c1af76c63015ad5832764f3973e62f2396f03`
- `0x80000cd8` `83a74701` `lw a5,0x14(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:40ed8dd7dc3e7c9394cf35965ab8f870ef4392df3982431268b3521ec809230a`
- `0x80000cdc` `232ef400` `sw a5,0x1c(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:b4344cd351ffc89247ce43bbf2fbda3d1c7900259ed9d0090ff4b1c38fd04823`
- `0x80000ce8` `23229900` `sw s1,0x4(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:5998a5d1499bf3e3c08719c1c31be4757db627655c634852791613df911303d1`
- `0x80000d00` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:3c78672e1a2cbd556f67bc3af448be11e855ebc3307e5d4315b2ea732e2f5cf9`
- `0x80000d04` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:87cf5d3a633b2ab3e16a36ee23f57a6f2fe74ac461f656998d2a3dda9de3ce7e`
- `0x80000d10` `23b2b730` `sd a1,0x304(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:6e367c803f2abb4d0b6b09dbbbd79b3e1d9b06b95dfb427a01ddee46869249f8`
- `0x80000d24` `23a4872e` `sw s0,0x2e8(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:91ac8366fcd8b4caeb4db765f62b3f6b5784ad7f78637d20c84bc75f7443050e`
- `0x80000d28` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b1c23f9856b6b6fc0685b0616e0d4c742146c7766f2b6e30ecd485bc95d6b303`
- `0x80000d2c` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:285b62cb70e5c8f90b81ed5578f50a55f344b242d462425d6f851d5a338fd074`
- `0x80000d3c` `83a7472d` `lw a5,0x2d4(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a1108e69392b9280d1e0cbaea688fe45840d7732c44592c84349e163cf4a91f5`
- `0x80000d48` `2324f72c` `sw a5,0x2c8(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:ba0e398f37ca3db8b49e1c345c990f0d18409de16266430b3e51ac729f9f8ca0`
- `0x80000d54` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:01cb931d067b106745375f031bdbf98c7c6e7d2087818de0cbff6794b027af25`
- `0x80000d5c` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:da76811a944540cc9992554340df0c17da4677acea54ed06d772e7b3f8e54f80`

## 11. Provenance and Toolchain

Analysis `firmware-static:1008a3556c52e9f4bbe4f49b4c237e685963ff1a066c65d61e9112a476f6ba2c`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `RISCV:LE:64:default` 导出结构；每条指令 bytes 与 SHA256 为 `35f9fff9c00e6a93bb9e6884b8604cd3d36dd35f7fdea408412633c5b7ae9fe4` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
