# Offline full-program instruction capture

From the clean repository root, under the caller's retained external one-HARD-CPU reservation:

```sh
/usr/bin/python3.9 -I -B evaluation/full-program-provider/reproduce.py \
  --out target/evaluation/e9-full-address-provider-v1
```

The output directory must be absent. The existing `evaluation/admission/processes.py` owns four fixed stages: bounded tool-version metadata, vendored Zydis, modern e9tool, then full CSV capture. Bounds are 30/180/180/30 wall seconds; each child also inherits that CPU-second limit, a 16 MiB per-file ceiling and no core dumps. Each combined log is capped at 1 MiB. One CPU plus `make -j1` limits concurrency. The 128 MiB storage check is **post-stage admission**, not a claimed instantaneous quota. No whole program or modern rewriting backend is executed.

The root supplies the CPU lease and trusted installed compiler/CRT/runtime premise. The script records stable selected tool/library hashes and actual version text; this is not a new semantic admission or a full transitive compiler dependency manifest. Source is pinned modern E9 commit5e098f79, original is the pinned PLDI2020 e9patch890f76cb. Copied source is exactly133 Git-authenticated files/13,059,771 bytes in the same output directory. No dependency fetch occurs. Receipt and all stage logs remain there on success or failure; no failed stage is retried. Later stages stay UNRUN.

On closed capture success, the receipt pins the provider executable, all CSV/JSON files and the raw instruction-row count. `CSV_CAPTURED_UNVALIDATED` does not prove complete coverage or authorize rewriting. Supply the exact `.DISASM.csv` and hash to the separately reviewed bridge only after establishing its explicit complete-code/noncode-gap premise. Its1MiB CSV/ledger,1,024 sites,4,096 RPC messages and16MiB original/output bounds are unchanged. Omitted bytes, unsupported geometry and cap excess remain refusals; never fill gaps or select a fitting subset.

Provider source: https://github.com/GJDuck/e9patch at `5e098f7920b5b5535f553de599c94ee980e97e29`. The default source and original paths can be set explicitly with `--source` and `--original`. The installed tool hashes bind the measured environment. Copy closed receipts, logs and capture files into `ignored/` before any build-cache cleanup.
