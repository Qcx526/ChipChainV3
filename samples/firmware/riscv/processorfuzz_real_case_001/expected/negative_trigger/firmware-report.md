# Firmware Analysis Report

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:a1e879fe3c03e7abbc670231c56773479c543605e759effe739675cfc481dfc0` |
| architecture | `riscv` |
| bit_width | `64` |
| endianness | `little` |
| elf_sha256 | `2b6275ffb203f5ffc5411bb9200f5eafaab61fe6615a403697ecabace469e7cd` |
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
| barrier_count | `2` |
| atomic_count | `0` |
| tlb_invalidate_count | `0` |
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
| `0x80000010` | `_start` | `csrwi 0x0304,0x0` | SYSTEM_REGISTER_WRITE | 0x0304 | not established | `fwbehavior:706ca45e03e6bf4f1200b9dea9ee40cbb1f1fc95afbed74a8d58683de1ee8d04` | supported |
| `0x80000014` | `_start` | `csrci 0x0300,0x8` | SYSTEM_REGISTER_READ | 0x0300 | not established | `fwbehavior:6dc4cc1761379ad828e24b6b08f3684b28614ff5a970602c3d30f39be01b408f` | supported |
| `0x80000014` | `_start` | `csrci 0x0300,0x8` | SYSTEM_REGISTER_WRITE | 0x0300 | not established | `fwbehavior:dcb4fcc44445ae500a48ede9aa8c7b40804b2c92b49decf0cb025c1114e7e45f` | supported |
| `0x80000020` | `_start` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | not established | `fwbehavior:16e6494f447500b82a0539a0bfe9c5035282d2277b99c148c4a7b58bf3a504a8` | supported |
| `0x80000034` | `_start` | `bgeu t0,t1,0x80000044` | CONDITIONAL_BRANCH | 0x80000044 | not established | `fwbehavior:a7634aa7b44c1ee39f4ec4818c29139c96eb3270d55ebf63472d80e78b32b4ca` | supported |
| `0x80000038` | `_start` | `sd zero,0x0(t0)` | MEMORY_STORE | not established | 0 | `fwbehavior:b67e1f42d810ec423270c3e846f405cc099da9063191cd109020fa0c78bbd207` | partial |
| `0x80000040` | `_start` | `j 0x80000034` | DIRECT_BRANCH | 0x80000034 | not established | `fwbehavior:e3d61bee022d8d41ffe6c2dc3fe2560a16ad3b19c2844ade54d58558c6136c0e` | supported |
| `0x80000044` | `_start` | `jal ra,0x800004e0` | DIRECT_CALL | 0x800004e0 | not established | `fwbehavior:aac6caccdf5d080fdba5c49549092e38269d12e6dd787a2a3f3d0579480290b2` | supported |
| `0x80000048` | `_start` | `wfi` | UNKNOWN | not established | not established | `fwbehavior:06a7409989076e538d806e3ef8b015a833e3aff2c590230acef85d92e35ea6e0` | unsupported |
| `0x8000004c` | `_start` | `j 0x80000048` | DIRECT_BRANCH | 0x80000048 | not established | `fwbehavior:dcbaec0a411a4a6fa9414b04726e3399367ae1a0f51b600f79ef88f309d10eda` | supported |
| `0x80000050` | `_trap` | `j 0x80000050` | DIRECT_BRANCH | 0x80000050 | not established | `fwbehavior:c4ddb1cc0f069e9c37e27e385d6e46cbb2ee1efa966cb5e7152facbc0fe01c8b` | supported |
| `0x80000054` | `arch_hart_id` | `csrr a0,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | not established | `fwbehavior:a5a2a052a6384075610c9657ba06a20c4363392b3117e6b6a56de91fcfbf56d7` | supported |

## 2. Binary / Architecture Identity

ELF SHA256 `2b6275ffb203f5ffc5411bb9200f5eafaab61fe6615a403697ecabace469e7cd`；RISCV 64-bit little；入口 `0x80000000`。
PT_LOAD 段 2 个；节 7 个。

## 3. Program Structure

识别 33 个函数、164 个基本块、858 条指令和 252 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x80000000` | `_start` | 0x80000000–0x8000004f | `fwfunction:08c559db829714298c465b2d75d0188afb7f10a27f77a07fb146feacc5a98d42` |
| `0x80000050` | `_trap` | 0x80000050–0x80000053 | `fwfunction:67082f8906e2bee2dc228bd8478482a944693fc6cd4efbf33417ed172cc272d3` |
| `0x80000054` | `arch_hart_id` | 0x80000054–0x8000005b | `fwfunction:32304df65471f05a43d84e4a92724511102dda56bb52a64edc451b618d5a9bda` |
| `0x8000005c` | `arch_memory_order` | 0x8000005c–0x80000063 | `fwfunction:aa762609022f49fe1af838c7de33d684f2d603d5bed38054be4d8433431434de` |
| `0x80000064` | `arch_translation_sync` | 0x80000064–0x8000006b | `fwfunction:5828570547dffa42545798ed9a6a6541ab6a81720158c5429e33ab9d6acd515e` |
| `0x8000006c` | `checksum_word` | 0x8000006c–0x8000007f | `fwfunction:ddb8826e962e25a1dd74ced7e8eea2a468927bd839d230be364d052b730aad4b` |
| `0x80000080` | `service_page_valid` | 0x80000080–0x800000a3 | `fwfunction:96967d0abd736f4c7e95adcb5b267f989f7839c87cb2a74d9ecdd81dbdc8de7a` |
| `0x800000a4` | `command_checksum` | 0x800000a4–0x8000013b | `fwfunction:a57ee7cc7c937a77051374e0a64bb979988e2db8099f657b68b3a7beb002e01d` |
| `0x8000013c` | `command_validate` | 0x8000013c–0x8000023b | `fwfunction:f876c51447863ab6d8328b4ca2cf3874d7902cd135738f2945f623db69d26bda` |
| `0x8000023c` | `controller_reject` | 0x8000023c–0x8000026b | `fwfunction:838d07f2defc336620fd455f1844f8f29efdcf5e0b3706b3a13b49bbf23b45ae` |
| `0x8000026c` | `controller_dispatch` | 0x8000026c–0x80000337 | `fwfunction:b153b10cf5b5c424b7889b71544708f8b469e0ba70ad2ad6085684af2fc190d8` |
| `0x80000338` | `controller_init` | 0x80000338–0x8000036f | `fwfunction:aed8566d3dc1796c202f451bf26ed0c965e72750d1fdd74d55a85efd9f8c6299` |
| `0x80000370` | `controller_step` | 0x80000370–0x8000043b | `fwfunction:d575a9e640e5f1c87ed79240518572ad7672993dcfb509b3f4ea819e48775bde` |
| `0x8000043c` | `app_run` | 0x8000043c–0x800004df | `fwfunction:eb2dc44177f2af05b706a2e447eda4f7c94b41ba3406658df3d733e88112ed03` |
| `0x800004e0` | `main` | 0x800004e0–0x8000051f | `fwfunction:607bc9091161894b30d82ef931c263e2dd3a5d53e0a263dacb89e6dc61cdd6ed` |
| `0x80000520` | `root_index` | 0x80000520–0x80000527 | `fwfunction:7f59fc993f06adb2a38939962f302374653bd269f1af1b43646c56de2c257625` |
| `0x80000528` | `middle_index` | 0x80000528–0x8000052f | `fwfunction:c9ac80800a601df80dd55046a2d3d7709ca002ba33713832a11250773159b63e` |
| `0x80000530` | `table_pointer_pte` | 0x80000530–0x8000053f | `fwfunction:173e17b9a5109b1d64dd5e6f1970757968e9d78e76e85b0a6f3569cdb06e7186` |
| `0x80000540` | `tables_ready` | 0x80000540–0x800005d3 | `fwfunction:69f8c1e877319ca87c389ccd977aa387e0e1acdc3586fedb31faea6e9690869c` |
| `0x800005d4` | `page_slot` | 0x800005d4–0x80000607 | `fwfunction:df1dded5e86484de363601998de9f405bc9f22f7c91992bfa8287c2b5bfae4bf` |
| `0x80000608` | `pte_physical_page` | 0x80000608–0x80000613 | `fwfunction:01ec68df85f8d2fd82e69ff7643a701e43ea9fcd7910ec2a08caebd08f41b330` |
| `0x80000614` | `leaf_pte_valid` | 0x80000614–0x80000677 | `fwfunction:71cf0495c0d641eb2589ab9825e95c8126ec1d0792dc2d166e95299b1d79b2b8` |
| `0x80000678` | `pager_encode` | 0x80000678–0x8000070f | `fwfunction:141967208b6c1813d908a872ff9c02a71683c4514b00e63f67e5acaa8b18ed76` |
| `0x80000710` | `pager_init` | 0x80000710–0x800007e3 | `fwfunction:572b1b3d8eb7ed2b3e2f4a75f1892c8335914f06eb9bf09b5cc900de080ad526` |
| `0x800007e4` | `pager_commit` | 0x800007e4–0x8000086b | `fwfunction:3aa76696883ac871a696f7b8698d63eb914e00cd5d20ba9d7311f38a3b028cd8` |
| `0x8000086c` | `pager_lookup` | 0x8000086c–0x80000923 | `fwfunction:663b96da6dd75b8aba23d40685454490e4fc0ea9f4a6e2b343ebcd4587837cc5` |
| `0x80000924` | `pager_apply` | 0x80000924–0x80000a87 | `fwfunction:a255655e4c59eaab8683cd1326e966ad1868c98846608e5f2f8b871b13432a0a` |
| `0x80000a88` | `mailbox_write_command` | 0x80000a88–0x80000adf | `fwfunction:e575a8a95a109c695cb626bb055f07566a5d398f4bbdfaa0cd80f54dca3d6eda` |
| `0x80000ae0` | `stage_command` | 0x80000ae0–0x80000b2f | `fwfunction:e1b4a40af50822a090a4fa64d6280e46e3b5924a30553c1a7a47695fda97466f` |
| `0x80000b30` | `platform_init` | 0x80000b30–0x80000c27 | `fwfunction:f4868cae378d7a2876803455b12431382219848826f6c71e5cc2a08c29a202c9` |
| `0x80000c28` | `platform_poll` | 0x80000c28–0x80000cfb | `fwfunction:f008995e0caa34a8db0aaf9df9b69a79f8a01f483960bb74c9c375b7173ffc54` |
| `0x80000cfc` | `platform_publish` | 0x80000cfc–0x80000d4f | `fwfunction:f1ea87b021dd91be853848d9da9418c8b673508f464c565a8d1c431c8409e7da` |
| `0x80000d50` | `platform_idle` | 0x80000d50–0x80000d67 | `fwfunction:477e4e80e88acc1fc70193f6e02b1f0c9d0aa74fce88a7af66cdc696e10a8776` |

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
| `0x80000010` | `_start` | `csrwi 0x0304,0x0` | SYSTEM_REGISTER_WRITE | 0x0304 | `fwbehavior:706ca45e03e6bf4f1200b9dea9ee40cbb1f1fc95afbed74a8d58683de1ee8d04` |
| `0x80000014` | `_start` | `csrci 0x0300,0x8` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:6dc4cc1761379ad828e24b6b08f3684b28614ff5a970602c3d30f39be01b408f` |
| `0x80000014` | `_start` | `csrci 0x0300,0x8` | SYSTEM_REGISTER_WRITE | 0x0300 | `fwbehavior:dcb4fcc44445ae500a48ede9aa8c7b40804b2c92b49decf0cb025c1114e7e45f` |
| `0x80000020` | `_start` | `csrw 0x0305,t0` | SYSTEM_REGISTER_WRITE | 0x0305 | `fwbehavior:16e6494f447500b82a0539a0bfe9c5035282d2277b99c148c4a7b58bf3a504a8` |
| `0x80000054` | `arch_hart_id` | `csrr a0,0x0f14` | SYSTEM_REGISTER_READ | 0x0f14 | `fwbehavior:a5a2a052a6384075610c9657ba06a20c4363392b3117e6b6a56de91fcfbf56d7` |
| `0x8000005c` | `arch_memory_order` | `fence 0x3,0x3` | MEMORY_BARRIER | — | `fwbehavior:3f86041f6bf997e9595ff9290867b558be784c4b3133d2555aa961a06570d8c1` |
| `0x80000064` | `arch_translation_sync` | `fence 0x3,0x3` | MEMORY_BARRIER | — | `fwbehavior:5488cb02c8c83c1e93c6c80cf52b624048f188bf487fb04cea99279c11023528` |

## 10. Unresolved / Unsupported Facts

- Unsupported instructions/semantics: 15
- Unresolved call targets: 0
- Unknown memory addresses: 230
- Ambiguous ownership: 0
- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.

Unresolved ≠ nonexistent. Unsupported ≠ safe.

- `0x80000038` `23b00200` `sd zero,0x0(t0)` → MEMORY_STORE, partial; unknown; `fwbehavior:b67e1f42d810ec423270c3e846f405cc099da9063191cd109020fa0c78bbd207`
- `0x80000048` `73005010` `wfi` → UNKNOWN, unsupported; Unsupported mnemonic wfi; `fwbehavior:06a7409989076e538d806e3ef8b015a833e3aff2c590230acef85d92e35ea6e0`
- `0x80000078` `3b85a702` `mulw a0,a5,a0` → UNKNOWN, unsupported; Unsupported mnemonic mulw; `fwbehavior:22013ddf81fdf4b9edbf4617e8a3e5e4c4ff7f4a13658a5a3c2d8943e44c3410`
- `0x800000ac` `233c1100` `sd ra,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:a7a183f24ebbd698aefb9e5e089a397e7de15bf6ea96e1c34e5090fcba7160b4`
- `0x800000b0` `23388100` `sd s0,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:5a17fa1e66d1339049070decd6acc793a2bae8b214b015c45fd6bb65ed84862c`
- `0x800000b4` `23349100` `sd s1,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:c30db7e58ffd29e669ac62751c35375b34fb1484a5ac0052b1c40d35a7489440`
- `0x800000bc` `83250500` `lw a1,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:db04bab2d2d6172f8990fc3658c09459644e0de72953573fbf13a1ba608ce4ac`
- `0x800000cc` `83254400` `lw a1,0x4(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d84de60ccd857a29fb4c6647a7286e5f2e93b1cdd367af56c46e2dfbe8191557`
- `0x800000d0` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:f8db5f8703de26672d887fd66b5127b4a24401dc83c4551e3ab3bb69cb279a46`
- `0x800000d8` `83348400` `ld s1,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0bf1ed55472bf7e6cc6486a879bf04cf3cba04aa9108ffb24e330d044dccead3`
- `0x800000dc` `9b850400` `sext.w a1,s1` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:de2aae3efa2ab66bb7066492de5ccfe7633ea4c6a02e00b53b9b37123f2fa83c`
- `0x800000e0` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:8814fe3c5c1f07d648a5855906c5e601542b13811c76313861df3b4b7ef1bbff`
- `0x800000ec` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:0c9054b5ef01ee93a047d10a2e4022b70ce804a55db9b2eca027aec309675b46`
- `0x800000f4` `83340401` `ld s1,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:958547bfcd9db639c95432c1687424442c162a8c5ac3680e1584ba6ab3a688b0`
- `0x800000f8` `9b850400` `sext.w a1,s1` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:1e2d2956c59e7227bdd97f013b8a838099766ef207ab18ab71ab873638cbb437`
- `0x800000fc` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:ffc4efacce2b670ee744493086fa10cd1fbc3bf2b6f68d27c9e37b002fa05531`
- `0x80000108` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:e6b273ce64e5068d9073ac6524efbfd151b319e90fa6f4d3698904ac0db348e1`
- `0x80000110` `83258401` `lw a1,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:34bb6e0ab2fd2cd9c8e0aa0327d11143801a4385219a9ddb683be63a9e49f683`
- `0x80000114` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:73baded1ac33d04af0b3d9313ba39ba9f184f24350f4e0cc2617dd75be59cd1f`
- `0x8000011c` `1b050500` `sext.w a0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:03c2cd04becfa4d7d32a9defa152e6200db82771db5060f262b6b4afcddfdf3b`
- `0x80000120` `83308101` `ld ra,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:57d69a825ecbdb295904ba86e2682d890ff95f1f147f2e4112d92715b4c3b3e0`
- `0x80000124` `03340101` `ld s0,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:3fd7f852183c3485518480650b02b0efe63ca98827ca6fc8d5222809610d08b2`
- `0x80000128` `83348100` `ld s1,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a789b473504fa2e065593ae106dc07e979d8480c08a741e6d05e852f4d22a8f1`
- `0x80000144` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:b31d3e3f0d63fd51990ddc8b70a85016300eb29a400eb27bb54aadc1881edb36`
- `0x80000148` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:b3212e95f3ecd946af68cbbbc681a4f2edcca5fbb2ee2334a9c88d0c55b84ca8`
- `0x80000150` `83274500` `lw a5,0x4(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f0cdbf3b58304749aabf9f21a186ed252950b2213133900e4ba8458cab8c72fe`
- `0x80000164` `9b070500` `sext.w a5,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:9a9b00c529a070294c5cee8989c3485636ecbd44e33df73c5ddf8b8b680319d8`
- `0x80000168` `0327c401` `lw a4,0x1c(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e4fb1acdce901d33b2a8e09c9962e91d0791dd00aae80cf9271a0441daa43013`
- `0x80000174` `83270400` `lw a5,0x0(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c462996fea490a11591a3e7926b67ec8b5fb2ef9a850a1f81d506d29833e198e`
- `0x8000018c` `03358400` `ld a0,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f1ea0f20427024295e6fd106ec9dc1c7c27414a6052f6342adf36fe7e0db60fa`
- `0x80000198` `83370401` `ld a5,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:23c7e4e14918edd69be57b7d926f8dca3bff3386d6d361b230badb25baea149e`
- `0x800001ac` `83278401` `lw a5,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:20b63cfc05d6ce08fae60dd008d613af5bbf599f30a840ad888e345db67a2219`
- `0x800001c0` `03358401` `ld a0,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5db07d682d3c04ff8fd019a6fb532a30aee5d9bd3b9658fe5439979c531a50ba`
- `0x800001e4` `83378400` `ld a5,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:2184233563ec00648b9154c51219eef562baaa51ef20c9c812c1ea0e870351cd`
- `0x800001f0` `83370401` `ld a5,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:10bd24453d06dd03ac13aceb437a4bce22a01c3e8e6fad4b00528ebef479d32d`
- `0x800001f8` `03258401` `lw a0,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:7f31b9220a6f52102f705502b97c01cd26c6af23487c8c15acc24ab06c91b027`
- `0x80000204` `03358400` `ld a0,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:226185f1257d01dd40bf7520491467c7837a294d48e98aa8de6a07c7b1f2ee7c`
- `0x80000210` `83370401` `ld a5,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:008b775810c2959a73720c984459661cac779b26f1df46c0f396a635b8639ce9`
- `0x8000021c` `03258401` `lw a0,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6e01da0112d14a9b1d8665ce52c60b437baa2f4a776866c52ed455d5d1c4814a`
- `0x80000224` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8085f0b05f7a3d5a4978492488b6c720503646d12ad8b5e7bc28e2007694fcbf`
- `0x80000228` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8c2c1db77c4d199ce28bc5193fe923173856608b27b0bdae094081bbd33c129a`
- `0x80000240` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:5d3dc961a6c31ccf5146b6e060e2c6905ee38acf4557583bc9f161d3e1d2c21e`
- `0x80000244` `83278500` `lw a5,0x8(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:cfaaa4c5cb70776e139c104bb2a4f53aac7fbd46e97867e9d4feebe7396845a3`
- `0x8000024c` `2324f500` `sw a5,0x8(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:e0df00b864e6f897175cc6eebad65d74461e021fa82f239bf5daf45f7b309177`
- `0x80000260` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b006210412810bb15dc5c58c6477339c9185f7cd9f4b0ff2ce708286fea4b48c`
- `0x80000270` `23341102` `sd ra,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:39ca89fb6e6c38aba68c1d003438146a4f477c06d9a197c0087b96b1881cbd96`
- `0x80000274` `23308102` `sd s0,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:5ccfc66bb343425256ca25336b5a18082e7fba61cfc221a48887c1d352a25481`
- `0x80000278` `233c9100` `sd s1,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:becc30f48d1fe6fded1d06c4784a57b4a6e200c8df0340758f37700066f79f6d`
- `0x8000027c` `23382101` `sd s2,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:f078c88de972421e238d59f035e9cdcd1b19baf9492e198440e47fb454f3c7ac`
- `0x80000284` `23340100` `sd zero,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:27d84868b79072e79d78e8ff20a558821c151f395a0b7c2a3bb22dfec31a8342`
- `0x80000288` `83a70500` `lw a5,0x0(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:0dbe6a2592d50081bfbbf5b583f307a31d6be181a29bc76f6d9026f85f49dad4`
- `0x800002c0` `83378400` `ld a5,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:9b47a25a7e33d69e0583631f5f49a1307e4ec7d771dcef931324a2f2ca029fb3`
- `0x800002c4` `2338f900` `sd a5,0x10(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:61f22603e4a1243129f4f5eba058120f82d453bf82f3607aea35b45f88d48705`
- `0x800002c8` `83358100` `ld a1,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:fc32099189d11be601f960229d02ed0cc0b21df3b42a2b5df4c06357cf44bbe8`
- `0x800002e8` `2320f500` `sw a5,0x0(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:f25b2ab2297eac5e2e41da79a3368a3a1550df8c0c6d811a830ed123328d6d2f`
- `0x800002ec` `83654500` `lwu a1,0x4(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:218710b3501d9ef50a1764a660dfbbf0fe124775558b0f62912c2384e9f30ac0`
- `0x80000300` `03644500` `lwu s0,0x4(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c280e6888eaf5440387f95eddc6f998e161844377eca65f2c1cd80b8bd5ffffc`
- `0x80000320` `83308102` `ld ra,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:fcb49e9979e22d3f61d72b2d94276918f5948c0116e3754ba6bf20091bb10d72`
- `0x80000324` `03340102` `ld s0,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:717770e998cdfa9082b3bfcf84290577e57320b8335c72890cece57110db0614`
- `0x80000328` `83348101` `ld s1,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:56eadf04bc6add36c5f8a40f9d800ab53bbcc1ef0121393de378fa43dbb687a4`
- `0x8000032c` `03390101` `ld s2,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:7094f3ddfc6b7da1b5fa03135a35d99de6a851faf75e0d79d3ffdd583063f8aa`
- `0x8000033c` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:326dbebf50535ff12b80e72e0346dff9f141793d38abaebfdea561c116a95b81`
- `0x80000344` `2320f500` `sw a5,0x0(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:1810639363a6d4951f218fb18d352d659dcacb81be51429aee7077e592a39cf7`
- `0x80000348` `23220500` `sw zero,0x4(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:7dd2629fb036a9c8044c59b4dfaf7b8ea9a7923a43776f86ceb7a2f07eb7577b`
- `0x8000034c` `23240500` `sw zero,0x8(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:f3255f5cfe4fa002ce2eb960e3fc3fc89bdcf8b7243b6d0ed62ca5ada173820b`
- `0x80000350` `23260500` `sw zero,0xc(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:2bae25b2028e9cc0d16afa2f0ccbe2dda0b15fe698d9f0a7809d4376ff1d6fa7`
- `0x80000354` `23380500` `sd zero,0x10(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:b3c16fbb5ae8ec172f9309af780392e2957099718cb447a3ad5946f0752e9fa4`
- `0x80000364` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:905e9161426bc7853d9a67531769f5ff8fe4626c88df33632a81a1d00714ba57`
- `0x80000374` `233c1102` `sd ra,0x38(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:edfac3b47969cdb277434aa07f434a984ad10b3e64ebfe9a303c7d94a3a87c54`
- `0x80000378` `23388102` `sd s0,0x30(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:a9d623913252b4753355315a248ac7d2442f0ed8ea2c659b13e6e24c5ff92c24`
- `0x8000037c` `23349102` `sd s1,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:c2e03a999057e3de89b724b4b5cd8ba488e21e3fe03e5de41d46d541ae946458`
- `0x80000380` `03270500` `lw a4,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c447cdeda430c943f115d701bcac9695c2d33c0924ddf83e676d14cb40ac7584`
- `0x800003b4` `83274100` `lw a5,0x4(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a06b8691356f44e9d39a0df82bd1fac3b89560cafc94c39f70e3272afbea6a1f`
- `0x800003b8` `03a7c400` `lw a4,0xc(s1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:16d8073cfa8dd359c96cd09d79ba3656af1f608fef7713460d71fdf90b7596a4`
- `0x800003c0` `23a6f400` `sw a5,0xc(s1)` → MEMORY_STORE, partial; unknown; `fwbehavior:48c10ba9dc55e6d278fd5ff920703fa928008584acd4c1a7da75d0329c8af530`
- `0x800003d8` `83a74400` `lw a5,0x4(s1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8b04eee3ced061a97d8c345afa2946dad7ebc5ddd24a9d2f490cb77f3f06021b`
- `0x800003e0` `23a2f400` `sw a5,0x4(s1)` → MEMORY_STORE, partial; unknown; `fwbehavior:101c3f25290c3b8299f14c12e5e5cf52139295dc7c39b0c8991a4c10c49c4e0d`
- `0x800003ec` `83308103` `ld ra,0x38(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5f875b7bf02f183de5fc90886c7b100d619e0fc17490a1f944fcddb60330b35c`
- `0x800003f0` `03340103` `ld s0,0x30(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:69f2d42429fa2ea495768ba208bc50968dfc18a98e4b2ac1626759ffc341f802`
- `0x800003f4` `83348102` `ld s1,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f8b0e2e38f859e02c6e8f2c249c54ef07af7b703fb724a9acb3be23b3822e6e1`
- `0x80000418` `83254100` `lw a1,0x4(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:90454fc576dc5f339502fa6cbc0bcf5ef7ef57299c88e678c4eea5cd9447129d`
- `0x8000042c` `bb05a040` `negw a1,a0` → UNKNOWN, unsupported; Unsupported mnemonic negw; `fwbehavior:19f9106d90f11561bc67a882cf1d62014248e5ad0a5df885bda315d794996605`
- `0x80000440` `23341102` `sd ra,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:0011ad85f1eb56046da5d3a2cc0c835e6354cc68c358edb6355636c4cbc691d1`
- `0x80000444` `23308102` `sd s0,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e4d8a3468ab5ac6012b2e26597b6d86d7db815f2fba0168856aaa98215162515`
- `0x80000448` `233c9100` `sd s1,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:4f2340858b1d602b2822e2173837a2256eea25a7550f0a0c5ce89d0f3aac4920`
- `0x8000044c` `23382101` `sd s2,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:58818f5bd9c5bfb566746f6a0724f544fe9f118bb328144ee71f6ea60181c58b`
- `0x80000450` `23343101` `sd s3,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:21fd0bbf216b2cfff71049f995259522303431f4d41eca22df900adc1cf285cf`
- `0x80000454` `23304101` `sd s4,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:f90e94d5257bd79f607e09af06213cc9ab6aa2aaa2650ea64f4ba09c816764bd`
- `0x8000045c` `032787ba` `lw a4,-0x458(a4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d5ce7468820b7f531fcce3ba5369ecd6d92d344bdc2d5d75ae654767ec268459`
- `0x80000484` `83270400` `lw a5,0x0(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:11cead3818e76b1ad23f823126067e4ba1ebb5459a441108106c2aba78e939fd`
- `0x800004a0` `83270400` `lw a5,0x0(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:fe4b4bac4a5ebb847a15e2e3e166f59f8f964296b72fdca09e42709a1ba1bbdb`
- `0x800004b0` `83e505b6` `lwu a1,-0x4a0(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a12c3cbd9eca55881a29873b612a0ec4dfbde18d3c2ef8a431dd0d198efae0dc`
- `0x800004c0` `83308102` `ld ra,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:858bdf708fc032a7d5fcb51836b9d1d02d322adeaef29e6dec6b9b69c3e8e3b8`
- `0x800004c4` `03340102` `ld s0,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b5862c6e83236c29bb15b2dba991a124ac1192862aa669bd985db4e775bb4ebb`
- `0x800004c8` `83348101` `ld s1,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8085548cc982a73b2b03ff05cba11d3282afd1be4d0cf76b430966ddfdbf0e9f`
- `0x800004cc` `03390101` `ld s2,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8234544ed2ec32d5caedca1d7f5a74023fe3e6585501df0bd6edf7ee71ce5160`
- `0x800004d0` `83398100` `ld s3,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:78f10101fccb59e1e83408a00b4612b8ba9dcc5f0e488f07a9d633599eb0b3c0`
- `0x800004d4` `033a0100` `ld s4,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8e077e450474ebd57f5dc9f0d27cedcb7b7ccdb9f6605869f22e096741980b71`
- `0x800004e4` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:a4c5979df4e1392d4e1365aba1e2f03f495b0bccee52047fe6c11429843494f1`
- `0x800004e8` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:6a433840f911a4ba3951c52453b4fa056539847f100fbb93420c8d6ea7740286`
- `0x80000508` `03258400` `lw a0,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e4b6892ca9b3f0ddbfc90fc11a35f84a9ad41132574f6d3ca35c5e37b8b36a7b`
- `0x80000510` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:1057833ed9e06690c9628056352268a6a3697ff664a12da2e06595de826b6b80`
- `0x80000514` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:bf2f40f04adda9cb1d717e7c262add459f3c06ce0fea8b71fd40ecbfa2ab8e00`
- `0x80000544` `83a707ac` `lw a5,-0x540(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f61f63ba361d0c222b9878beb91141cbeced6a9cc60535154b77faef855f97c1`
- `0x80000554` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:024066f40cdec0badb0d1abe2adf0b2ee143a300e511ee54378c7239873166e9`
- `0x80000558` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:fb1d2e71342ea946123ff9bcdf61cee5b1c43f39afc04724eb7a7e70bd9ea537`
- `0x80000574` `03340500` `ld s0,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5f32364ef3ac84a5192634b7cab61539eedfaf716ad77415aba70c64d2e4ca0f`
- `0x800005a8` `03340500` `ld s0,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b546fbf9ea6b7a99f4434a7fa4c2762725d32b767ce1d3708f429cb05a6693d2`
- `0x800005c0` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6148b7dbaaba4b898bf66f984eeba1af8b88344a16d5c83a5e8b829a0e8ce1a4`
- `0x800005c4` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:adc7c3a04ff9f466764abc8d52859f438a3931dcf2c015c93ed0ecce6b3ba228`
- `0x800005ec` `23a0a500` `sw a0,0x0(a1)` → MEMORY_STORE, partial; unknown; `fwbehavior:87606b4f79ad1acbbcb2aa5dec218664a6047e20480da532f90d7d68f4834078`
- `0x80000644` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:540633f59f8e3d2b148bd30777e9e93a3cbc2e94997b74aa17d5608ac03bb08d`
- `0x80000660` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c5361fec910ef10376b691b5e8c695176b12b82d45e8dd81eaec63773407b28c`
- `0x800006d4` `2330f600` `sd a5,0x0(a2)` → MEMORY_STORE, partial; unknown; `fwbehavior:6ae72dc26b0c694fc7e31dec1ddc23bcdf9a3d41d9a5d65c2f02f257f526dde5`
- `0x80000714` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:91660213271d6c556507af42466afaddfa764454506d45304bff10816269c9ee`
- `0x80000718` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:eb2ef68ff4b9ef8559598c9b6ddaaaea06de1d0c1073f84a580df6ec83711638`
- `0x80000720` `23a2078e` `sw zero,-0x71c(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:25dbabfb604f3d11d7abd7769a1aef9309feaed7e5a340d88a97ccc1d7ca16a7`
- `0x80000750` `23b00600` `sd zero,0x0(a3)` → MEMORY_STORE, partial; unknown; `fwbehavior:6f64da411c27574a83d19f9f2f64c570c551d3a6c9de0b0bc0084e7755ad6163`
- `0x80000758` `23b00600` `sd zero,0x0(a3)` → MEMORY_STORE, partial; unknown; `fwbehavior:a9f23c2b9b89ba399d603d98653ac2658b2b8d58a69a1dedd141cc2bd08f7826`
- `0x80000760` `23b00700` `sd zero,0x0(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:c7f4f824e1452a9b05eb559580fc89f3e610fc391230c888ffcabe787ba80dd7`
- `0x80000770` `1b040500` `sext.w s0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:89b6e0f34d7c416a05cf96397707f9f7de63c162a95618a460052e00a23a6453`
- `0x80000794` `2330a400` `sd a0,0x0(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:622041baabba40917f03807df4fb78d6ac2022a3b74f5f6431c323c234c5466a`
- `0x8000079c` `1b040500` `sext.w s0,a0` → UNKNOWN, unsupported; Unsupported mnemonic sext.w; `fwbehavior:0e1bb1171dadcff089b185d38af18282bdb20554e5879517054b780769d121b1`
- `0x800007c0` `2330a400` `sd a0,0x0(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:6e2cfcf7e624ab0ba88649c7af88891a4bc2668df3399d84bf7feee262678450`
- `0x800007d0` `232af782` `sw a5,-0x7cc(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:7bd07a844ffcb6c224feff6b859d64ecfc0f3ea989ec545b62771647e275ddbe`
- `0x800007d4` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c9e12551c3bd9cb3a36a499b18c47c0619a2c9b8ca1542382b38959f8548a902`
- `0x800007d8` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:237e8978ab22f9c1f278c14a7e14577eb7e1571f6392ecce34cafb8e598f6152`
- `0x800007f0` `233c1100` `sd ra,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e5ae30a981e36285ec1e780d87d48faf25c9779444dd25411a3a586c6cdf7a7d`
- `0x800007f4` `23388100` `sd s0,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:3477fa55cb80b1df16c51fedee9433b357870db7622798531b8ecf0a9f7f58b2`
- `0x800007f8` `23349100` `sd s1,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:d7272ac559270c8212ee5f96dda2b10d723ed59ed93999ed2dc4dfe4f07db007`
- `0x80000830` `23309400` `sd s1,0x0(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:6d2d55b979ecaa55ece1e1b4ca3a5817acaa73eafd397ec6ef7f32d4912bbbc0`
- `0x80000840` `83308101` `ld ra,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:94f7f679bb1986b4a3f0413ff092dc2f5165de6826fe957e0025cf112c46a769`
- `0x80000844` `03340101` `ld s0,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ac04695a160b380dccb8fd5189541dddbf363eea6b6088739b9221f61671560c`
- `0x80000848` `83348100` `ld s1,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:73d8a7d749bbe55856ca0a682488980650a6188954109bc917a4ffbd4aff3d56`
- `0x80000870` `233c1102` `sd ra,0x38(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:8b5f77232592f74766802a21db7bcb90638fb5fd94823e8743d161d32840a708`
- `0x80000874` `23388102` `sd s0,0x30(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:3a2b86995667a02987c9c231c7f5277ad780b5d35b422c34e9336b62c9b9bc90`
- `0x80000878` `23349102` `sd s1,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:cff0211fe79fb9c8617c28f1499f53348fd53343a47addbe2da7cd809d6f022f`
- `0x8000087c` `23302103` `sd s2,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:a2d66771e8fd9960d28ee476518102d49a2a25af335b79a525969ddc81072e36`
- `0x80000880` `233c3101` `sd s3,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:de0156069663f56aee9a12a79f11f8a2d3cbc7fac14ae6af1102828dd6126495`
- `0x80000890` `23b00500` `sd zero,0x0(a1)` → MEMORY_STORE, partial; unknown; `fwbehavior:7555dc9832c3834173032962ec494a0221e667debc18f30a0e036a54a2923bff`
- `0x800008b0` `8367c100` `lwu a5,0xc(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:34fd8fa748eb9b1c79ec2dc61f1aea53a0eae51c56197c332801d9d6247d80a1`
- `0x800008c4` `83b90700` `ld s3,0x0(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:300a6e0d806aa9e7465995b01d05f085368db8672353cb9be418f9923e828a6f`
- `0x800008e8` `23308900` `sd s0,0x0(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:6c5ff42abcecea23ef750f918663b028f2b25d8637e3e3ae6a31b3d0915ed2c1`
- `0x800008f0` `83308103` `ld ra,0x38(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:8508a04a429bac8f0d596983366d2cf62bc657ff434f1bdfe36b34b28d51ea32`
- `0x800008f4` `03340103` `ld s0,0x30(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:88f39aa95fde02f4ab28528660d855839caeceb364552268f98898e6bda1bd36`
- `0x800008f8` `83348102` `ld s1,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:da794fe1bbdd35777d2780a176df2e2a404d18960d296e96eebfd8d4106264d4`
- `0x800008fc` `03390102` `ld s2,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e8517168e4cf1ad93aa12e6beec69c8a2a1cbfd7f3260f546ed5f404e4f38a05`
- `0x80000900` `83398101` `ld s3,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ce5be58d492f01aebee2625c845c55ee0e49c2a5d3c1b6de036dca957cca0931`
- `0x80000928` `23341102` `sd ra,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:bdacf97b746d2b0bdb19993164210e30d8f868331a060ea6e865f2cffbf8478b`
- `0x8000092c` `23308102` `sd s0,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:588295fc0b8fdaba4ea095e26742a3c4ffadfe1840fdbd5b077b2acc8e9fbd8b`
- `0x80000930` `233c9100` `sd s1,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:dbe508740493aca7ab673344d416df161187085089fec140b7f4e668dce2a0c9`
- `0x80000934` `23382101` `sd s2,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:21b442ef278e626797f31bcbd2a8830fbe968e6d2ccbfe7b30f353ee9c7e4e82`
- `0x80000948` `23b00500` `sd zero,0x0(a1)` → MEMORY_STORE, partial; unknown; `fwbehavior:dfbb40ca80b264a6c1e78891a366fad6ea1d99e36e79f58507a4c078e356fac3`
- `0x8000094c` `83270500` `lw a5,0x0(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:34b04830dfa99f391684af6c3ab27f327fcf41c2d9d167b40953522a64f898d4`
- `0x80000970` `03358400` `ld a0,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:3107ad5d95b5bdd66f726fea91216c8ec0bbf26232f51d3004f464c14807d345`
- `0x80000980` `83378400` `ld a5,0x8(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:69867e7685fbb24384ba9d4a4bbeed754b9aa9e2257f081bdfda3f0fa8e2162b`
- `0x8000098c` `8324c100` `lw s1,0xc(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:bd7bba802527194eb962b5f4bb3771dbe50743cdbca82ec6ce437a8a8193d961`
- `0x800009a4` `03b50700` `ld a0,0x0(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c7e8ba11f99138e95a76cf69c8cd1a6b2ff7fee9cbb44dcf5579e76c14fd731b`
- `0x800009a8` `2330a100` `sd a0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:65570c8e0a1cdb86bab4b5bb6694f0f8c0a7c01c146c695a89a24a2eafcc70bd`
- `0x800009ac` `03270400` `lw a4,0x0(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5a871b3ce6de3b569d73f4daafabb7ff3ca335c6d365c85f05664a94a1686edd`
- `0x800009c4` `83258401` `lw a1,0x18(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:658a7b2f5128086e90f38b7c6d9e0be0183bd59531cdc251b185169f310d7b07`
- `0x800009c8` `03350401` `ld a0,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:3caba938c0e5fedae8f49e725c7f863a3c50a54773fce9064165b2c7c12b0b9f`
- `0x800009dc` `83308102` `ld ra,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:6a0ddd11dfbfd114998e4f4b24e50efb110ccca13489e495bce4e430c9f4164a`
- `0x800009e0` `03340102` `ld s0,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a7d875206126c7158aaa6c293f3b797665f826d46398cf4675e93cc3af3e9e6e`
- `0x800009e4` `83348101` `ld s1,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:2ef689e8a73ecfa638b03291ca2ca4f3bd170091aeeda6ed58c831db53908c49`
- `0x800009e8` `03390101` `ld s2,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ac5edf40e5fe0a5ede051c47094b802c8c6422f743d1af9e3336a3f339882736`
- `0x800009f4` `03358500` `ld a0,0x8(a0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d5a7bd45579373891a09fb7542fac584c1357c57659d1524774a18d1ed819f9c`
- `0x80000a20` `03350100` `ld a0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:33d1ab30b7f09dd8908f3d32ad44e8e15fd58f411356b1c1794a73413f960046`
- `0x80000a28` `2330a900` `sd a0,0x0(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:52e026162a7d9d42fc17027c1c61e783a1da5fe4e23e1db33c6ee9769f2411c0`
- `0x80000a30` `83350100` `ld a1,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:bb623814c4795d562e4399c7c043d8f4424f1f80472748f289b2ef324aba69ad`
- `0x80000a34` `0325c100` `lw a0,0xc(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:f44b056d5900e9d62f6ce9e8b387d0ca689134ad0c48acce39c3f82b27fcad65`
- `0x80000a44` `83370401` `ld a5,0x10(s0)` → MEMORY_LOAD, partial; unknown; `fwbehavior:5f313381827e5eea6f6e3b0d183d9ae1573e7508f91f5d0f9b61b8f30c92d0d2`
- `0x80000a48` `2330f900` `sd a5,0x0(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:ee08f9b99ab0512a90a071be464cf7e4831429c34e16cd02146ec93bc6a00f1f`
- `0x80000a88` `83a60500` `lw a3,0x0(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:ea35cdaf5b0018f4485c14cf87984d837f3213f85ac6305c69a8a5b92e19fdd4`
- `0x80000aa4` `232cd700` `sw a3,0x18(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:d77a625e150937132a54d90fee4c6948db29b6fa1b28d7544badacde0887c34d`
- `0x80000aa8` `83a64500` `lw a3,0x4(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:efda92abdad08ae8f646425b2894cb503a164f54e27f3ed8870d1b92c89c744b`
- `0x80000aac` `232ed700` `sw a3,0x1c(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:6c9139b4fe669ffab46b64306f6d3fdd12651dc403214490577f2777ec5f3ea2`
- `0x80000ab0` `83b68500` `ld a3,0x8(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a21e57d1bff0010dd534d5b5b850a5d6c56adc7e366af9e1d6a70034f602cf55`
- `0x80000ab4` `2330d702` `sd a3,0x20(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:93e6786d696f49a56a46d07c799a1adc4e79bfd5578d5ed2d2977c3f04d946db`
- `0x80000ab8` `03b70501` `ld a4,0x10(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:fa0ae43e5c0dffdb5cf1aab34a0166d6019ee1bbeb7c62b00c5c089d786a2bb1`
- `0x80000ac8` `2334e500` `sd a4,0x8(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:dd3b5321d2083211f23395b4e6c3021b3e8e94906acecd9ff77273dfeb808a8f`
- `0x80000acc` `83a78501` `lw a5,0x18(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:c3f173460d5d5fbe5091a7be75e0d97913eca427fc8e4c3c77cba069520e5204`
- `0x80000ad0` `2328f500` `sw a5,0x10(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:42c4a046c754f0f5301882b80fb97dde7c3dabdd76d5d4e8e26eae8523d1e55d`
- `0x80000ad4` `83a7c501` `lw a5,0x1c(a1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:4418302bf1de7317dc69328995959428b7197efb9ae30d549babb5e2623cd252`
- `0x80000ad8` `232af500` `sw a5,0x14(a0)` → MEMORY_STORE, partial; unknown; `fwbehavior:39a44e651bcfb2b9cded17c419b8c7ac4195ad4338b9e7fb097b2b3cda2c85ad`
- `0x80000ae4` `23341102` `sd ra,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:9c36cb3c618fbc08fdd1c807b92ec242be2c5b7f9a832c898833633e2e205081`
- `0x80000ae8` `23308102` `sd s0,0x20(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:4e60a18e47dd447be8a1d4dbe2b3f88b91ed8a0120fdaecdd57d64f01737264c`
- `0x80000af0` `2320b100` `sw a1,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e9a3b5e5622b23c5e75ca15d9a6dd9b33503587b0f16fd696ad923ec0c44b757`
- `0x80000af8` `2322f100` `sw a5,0x4(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:9bc544c522a35ead351b850d500d514a5c853c19d67bb042550f1ed5e9c2a6f3`
- `0x80000afc` `2334c100` `sd a2,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:e91f1d7902b72b0af8f102f94f330afdc258c531aaeb91102b165fec3232e262`
- `0x80000b00` `2338d100` `sd a3,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:22e05b38d0c1c01283fa9a80c277fdcf6c90bc819e801e1d2d1eb7b327d1c913`
- `0x80000b04` `232ce100` `sw a4,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:d0ce116e7904419d5f1d9f34efe3ef8fe6e4e3dcf3195666dc1253e18c91bb86`
- `0x80000b10` `232ea100` `sw a0,0x1c(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:ca79c7221ab69776897a295a583f375120259ad21da9a70b37f0f569da657f2a`
- `0x80000b20` `83308102` `ld ra,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d08cd406c44b0e1aa43b17c7c36504bfe1e77a25091b61c8c15d65e614d40fe2`
- `0x80000b24` `03340102` `ld s0,0x20(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:7591066a39396ba3e30fd4af401b7891ce36c1bddd5115c07b5532be82b12e04`
- `0x80000b34` `233c1102` `sd ra,0x38(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:4bec344b43fd669d695edaf530158c42c8345126f40d15fc98aa614c996d1178`
- `0x80000b38` `23388102` `sd s0,0x30(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:75b0131c80c929e30a400fb825080d1142fcf6c3a53f3fbf1e9d7b8994347851`
- `0x80000b3c` `23349102` `sd s1,0x28(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:004918b7a7531e217322387b6a7f1376603286b87fb7d0d1cce9617ebea8cbf3`
- `0x80000b40` `23300100` `sd zero,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:a3c4435f6514652eea56cc81f8d11bd753d45499a5e8f49c2d563de425d8dfaf`
- `0x80000b44` `23340100` `sd zero,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:c44d99c4bfff5040097240231ab85f15655f2709553baa10d54befb508b50120`
- `0x80000b48` `23380100` `sd zero,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:f3903c03de7c4c444183cdff8c52025b223c796e54b116f756f6833f750cc384`
- `0x80000b4c` `233c0100` `sd zero,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:c086aa97fb049c62cbc54afa93fa461adeb336eb404429bb23b980765403f96c`
- `0x80000b58` `23a00700` `sw zero,0x0(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:c17b3556251bb75f0d20002d0082314da97c14f20c5744484675c809427abf8e`
- `0x80000b5c` `23a20700` `sw zero,0x4(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:f2453aae843f568d05bbbff0754dd6c8e95fac93f78cac0adaaaea35238c1948`
- `0x80000b60` `23a40700` `sw zero,0x8(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:abba56d612ec59a13ff792f84bf06dd1e0455dd86ba5077b5fb762f62cb50117`
- `0x80000b64` `23a60700` `sw zero,0xc(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:b5f8888a94234c6310f2b15bfc1e90ed31ceae0f6fe3bae3ea603cede45b9fff`
- `0x80000b68` `23b80700` `sd zero,0x10(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:937c1109de919d462c5e11d40e8b39071e47c554f90d34444757356cefbcaa5f`
- `0x80000c10` `232af73e` `sw a5,0x3f4(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:6461a95c41083f4992b8d1de051b81c780e89c5d8dfb2d8f170e3af7b54ba05c`
- `0x80000c14` `83308103` `ld ra,0x38(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d33a4be954b47978725a15d6f4fee57aa3da7ec20d28c6124a96bac740210bf6`
- `0x80000c18` `03340103` `ld s0,0x30(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a36f0f410321d8769102385cfe897d7051b6fbc67c316703cd0c166fae7f96d6`
- `0x80000c1c` `83348102` `ld s1,0x28(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:bdc0214187e553daeabfa202f213186d1cd04f6037ef3ab3889dc56838284ed3`
- `0x80000c30` `233c1100` `sd ra,0x18(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:c0f1cd2ca565ebbc96f75c3e9cd8bfd78d2cd17e0e0b87dbda7e8b41baf427ad`
- `0x80000c34` `23388100` `sd s0,0x10(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:43363dc028388e10d751b631f1b05d8d936ff3bfd498f611063886871524633f`
- `0x80000c38` `23349100` `sd s1,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:b318465978908a4ae54cf83316b003beeb979c9c57f9d74e7d0e697d29addff9`
- `0x80000c3c` `23302101` `sd s2,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:1ed782d34f28d3a471ceb0481fe90885b1e0c8a7f65d2481e890cade342d542e`
- `0x80000c48` `83a7c73b` `lw a5,0x3bc(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:40f7c7a5dd156bed6898a18d24ce29d2ec58182051d463025358e9654b8b24cf`
- `0x80000c50` `83a4843b` `lw s1,0x3b8(s1)` → MEMORY_LOAD, partial; unknown; `fwbehavior:b1283fd9ef6840610fa9a8f7bffe5cc6a99c5cd40773a98d57bb3b8397881c1c`
- `0x80000c6c` `232ef738` `sw a5,0x39c(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:3ef012080a06912b03188e62599eee1e751199fd702a9927e20d1b190afdda92`
- `0x80000c74` `83308101` `ld ra,0x18(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:425f0da3a946f7ce98a009224e3efa5bcb7902cc79afabeca8a09ea2969ee93a`
- `0x80000c78` `03340101` `ld s0,0x10(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:00296057c97dede196ad074a76ba6235d8a2bd72d77768ee309b767f16f42898`
- `0x80000c7c` `83348100` `ld s1,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:370db9f8d69906c5decb65191b86f0d1e0c3472427cdc891d30b982342195cf2`
- `0x80000c80` `03390100` `ld s2,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:dc2d1cc872ca82eacc2e2f283c161cdff86844d195a5949de10add5755d79649`
- `0x80000ca4` `83268701` `lw a3,0x18(a4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:023e2b0454c2a6ecc1581b06aa21433e57139102c3128a0b6db44462855313d8`
- `0x80000ca8` `2320d400` `sw a3,0x0(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:46d462ca90de8e2d265b5db4807c903bfb230e3f7501d7fd117f5502a8e74a5a`
- `0x80000cac` `8326c701` `lw a3,0x1c(a4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:2ec8876fe4c0797118c5548d1b02936e8c5cad372711b8192105132251e40bf9`
- `0x80000cb0` `2322d400` `sw a3,0x4(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:57708433e2009df3519cca699c5faf815619f16cb45849d4b503d8de7183720a`
- `0x80000cb4` `03370702` `ld a4,0x20(a4)` → MEMORY_LOAD, partial; unknown; `fwbehavior:d06f038a0fe0de1a9b7ffbfebeda0891a5511c48fd45f4134e50d8dada5c4755`
- `0x80000cb8` `2334e400` `sd a4,0x8(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:db4a6f0ff8bebdcbe0095b85da2f950f6b02517c76f859e4b03deacda3364a5f`
- `0x80000cc8` `03b78700` `ld a4,0x8(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:a6af54d2385d7f09e9fd1b677bb4d9b31fe1319afdb52a1f73b1df7da7d1789b`
- `0x80000ccc` `2338e400` `sd a4,0x10(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:61d6760b8ae02feeb95bed76bd4bbc9138004769f6c12c2b5642455313abdbd7`
- `0x80000cd0` `03a70701` `lw a4,0x10(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:79c53fc2ed39d11cfc7fbbe19cadce866638da656fe5f3be732b4e6ecdc08c11`
- `0x80000cd4` `232ce400` `sw a4,0x18(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:a6f5ba793b0b204962b9dd2b209d8dfa109ffe4f5949049dbf124a377b88d908`
- `0x80000cd8` `83a74701` `lw a5,0x14(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:3d84e2362bbdabcccf014aeaf29efad38acbe5bc1e1c8cfb8b2235ca9b69b8f7`
- `0x80000cdc` `232ef400` `sw a5,0x1c(s0)` → MEMORY_STORE, partial; unknown; `fwbehavior:dedddbccca6ab48d5bfec57dfb36dd84edacccf28b40644d2de7545c83289fad`
- `0x80000ce8` `23229900` `sw s1,0x4(s2)` → MEMORY_STORE, partial; unknown; `fwbehavior:56d03ae723dd1123cdfdcd333bdadcea7c9be85e59633b0b6cdbbf4fea39c464`
- `0x80000d00` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:a3f0c4832b26b2568712240e6064e56611e7a8d1d51632efd297619d11b81694`
- `0x80000d04` `23308100` `sd s0,0x0(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:1c1faf29eb6d9f9d0fefc8f835e2728987b5bbae9dbaa1ed3035ed4608feb7b6`
- `0x80000d10` `23b2b730` `sd a1,0x304(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:0dab3d00cee4368651214eb935a5edfaea86ff66410b313bf73387744ed7d978`
- `0x80000d24` `23a4872e` `sw s0,0x2e8(a5)` → MEMORY_STORE, partial; unknown; `fwbehavior:c6c475a27a612dc829e54f5c8182d9a2f4f3a59d42a503c71c38b2d48d81e463`
- `0x80000d28` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:82ce5745cffcdb4a58294d755d272720707610f01cc5a7ed6c2e644047e59041`
- `0x80000d2c` `03340100` `ld s0,0x0(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:7d17d027e7af6b0203b7e52e900d75d9ebc6328a742d32d7e5cd5d89c4d5bd5d`
- `0x80000d3c` `83a7472d` `lw a5,0x2d4(a5)` → MEMORY_LOAD, partial; unknown; `fwbehavior:e3dd4bfaef19dee0c7e56e8b59ded38f4f63a8c41df86d15425019e2c6f7a33a`
- `0x80000d48` `2324f72c` `sw a5,0x2c8(a4)` → MEMORY_STORE, partial; unknown; `fwbehavior:eb71997f41a8d96c94dcc5b2ea79d78b012d1e94f465e168640342363614f4a4`
- `0x80000d54` `23341100` `sd ra,0x8(sp)` → MEMORY_STORE, partial; unknown; `fwbehavior:f118597bc52fdb5b8a4db5479fa6a68bdda5aa6456cee5e545c5d5afc117f7ca`
- `0x80000d5c` `83308100` `ld ra,0x8(sp)` → MEMORY_LOAD, partial; unknown; `fwbehavior:08d2cb97691daf5b210d9eaaa7c34cd1b3fed1408c7b85ee0135d12b1b805c92`

## 11. Provenance and Toolchain

Analysis `firmware-static:a1e879fe3c03e7abbc670231c56773479c543605e759effe739675cfc481dfc0`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `RISCV:LE:64:default` 导出结构；每条指令 bytes 与 SHA256 为 `2b6275ffb203f5ffc5411bb9200f5eafaab61fe6615a403697ecabace469e7cd` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
