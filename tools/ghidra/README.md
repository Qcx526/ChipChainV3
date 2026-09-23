# Project-managed Ghidra

`install/` contains the working Ghidra 12.3 DEV distribution used by the firmware frontend. It is intentionally Git-ignored because the distribution is about 879 MB; it remains inside the repository workspace. `VERSION`, `SOURCE`, and `SHA256SUMS` are tracked candidates. `SOURCE` records the upstream revision and SHA256 of a locally created bundle; the original upstream archive is unavailable, so its hash is not claimed.

The frontend discovers `tools/ghidra/install/` by default and accepts `--ghidra-home` as an explicit override. A fresh clone needs to provide this pinned distribution before running Ghidra; portable canonical artifacts and tests can be read without it.
