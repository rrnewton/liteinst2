# Finite cached CALL owner experiment

This opt-in experiment compares two original CALL-register programs with maintained-map and maps-differential runtime lanes. One target hits the sealed directory and performs a real PUSH of the original next PC before the cached transfer. The other target misses before any CALL effect, drains, and executes the original CALL. Each lane retains the complete source, actual owner/window/directory and protected observation, all seven native frames, and the full 520-byte stack window. The original 392/522 cohorts, RET continuation, whole-profile qualification and performance remain pending.

The published production changes are disabled by default. Only the distinct `build-persistent-call*.sh` recipes enable CALL dispatch, and only the two `build-persistent-call-owner*.sh` recipes enable this finite capture. The existing generic and older profile recipes remain unchanged. Standalone native136 tests use supplied numeric bindings and do not grant production window authority.

Use a clean Linux x86-64 checkout at an explicit full revision, Python 3.11 or newer with assertions enabled, GCC/binutils/GDB, the repository's locked offline Rust dependencies, and one externally reserved CPU. All commands below must inherit the same singleton affinity. `--cpu` must match that CPU. Keep the reservation through the prerequisite and owner commands; there is no retry, case selector, host-core fallback or implicit latest-receipt selection.

The commands are a reproduction recipe, not a claim that the historical private R5 collector ran at these installed paths. The public adapters are source-reviewed separately from their historical donor execution.

## Prepare the archive once

```sh
python3 -B evaluation/inprocess/call_owner/prepare_archive.py \
  --expect-revision FULL_COMMIT_SHA --cpu RESERVED_CPU \
  --output target/evaluation/inprocess/call-archive-attempt-1
```

This separate command calls the unchanged `page_selected_generic_build.Build.prepare()` and `finish()` with scalar-region, scalar-span, linked-epoch and mov-guard. It builds and inspects the ordinary baseline bridge and observer as part of that established preparation; it executes no subject. It retains the existing Build limits: build 120 CPU seconds / 150 wall seconds / 2 GiB / 128 MiB output; metadata 30 / 60 / 512 MiB / 64 MiB; inspection 10 / 20 / 256 MiB / 4 MiB. These are archive-preparation limits, not widened owner or native limits. The process capture cap remains 16 MiB.

Keep its private `receipt.json` and retained `artifacts/decoder.a` in place. Authenticate the whole receipt SHA-256. Its complete source, locked registry, resolved features, tool versions, ten actual decoder dep-info sources, Cargo configuration, command captures and archive exports are rechecked by both following runners. A matching archive digest alone does not establish build provenance. No archive or raw record is included in the source publication packet.

## Produce both finite prerequisites

First run the existing public CALL/PUSH217 recipe in [call_push_native/README.md](../call_push_native/README.md), on this same revision and CPU. Then run both existing component recipes:

```sh
python3 -B evaluation/inprocess/call_dispatch_component/run.py \
  --expect-revision FULL_COMMIT_SHA --cpu RESERVED_CPU \
  --archive target/evaluation/inprocess/call-archive-attempt-1/artifacts/decoder.a \
  --archive-sha256 AUTHENTICATED_ARCHIVE_SHA256 \
  --output target/evaluation/inprocess/call-components-attempt-1
```

Both exact component populations are required. Next run the full 136-pair / 272-lane native comparison using [call_dispatch_native/README.md](../call_dispatch_native/README.md). It requires explicit hashes for the archive receipt, both-components receipt and complete CALL/PUSH217 receipt. It does not inherit success from any historical failed reader run.

## Run all six owner subjects

```sh
python3 -B evaluation/inprocess/call_owner/run.py \
  --expect-revision FULL_COMMIT_SHA --cpu RESERVED_CPU \
  --archive-receipt target/evaluation/inprocess/call-archive-attempt-1/receipt.json \
  --archive-receipt-sha256 ARCHIVE_RECEIPT_SHA256 \
  --components-receipt target/evaluation/inprocess/call-components-attempt-1/receipt.json \
  --components-receipt-sha256 COMPONENT_RECEIPT_SHA256 \
  --native136-receipt target/evaluation/inprocess/call-native136-attempt-1/receipt.json \
  --native136-receipt-sha256 NATIVE136_RECEIPT_SHA256 \
  --output target/evaluation/inprocess/call-owner-attempt-1
```

Every output directory must be new. The runner checks exact current revision/source, CPU, hardware and whole prerequisite files, aliases and captures. It resolves installed source directly; it pins the complete original 592-file roster and actual imported/module/header closure without copying that tree or replacing module globals.

The original seed, complete application symbol/copy oracle, and two fresh full bridge builds are mandatory. Each bridge must pass its own actual compiler-M closure, complete 60-entry / 59-function provider census, ELF restrictions, reset inspection and `fast_bytes` execution. File-only GDB reconstructs all 116 types / 1,249 fields from actual DWARF and compares them with the independent source schema. Compile-only success cannot satisfy this gate.

The fixed order is native, maintained and differential for mode 0, then the same three for mode 1. A native subject uses 5 CPU seconds / 15 wall seconds; a gated subject uses 30 / 60. Both retain 512 MiB address-space and 16 MiB output bounds. Full bridge builds retain 30 / 60 / 512 MiB / 16 MiB. The protected record remains exactly 990,144 raw bytes plus a 64-byte footer, under the unchanged strict 4 MiB cap. The unchanged process owner reaps each child and closes every owned descriptor. A reaped failed subject remains failed while later fixed cases can still run; no subject is retried or omitted.

A finite pass requires native app40 controls for each mode, owner164 and pair40 for each of the four gated lanes, and terminal73 / TLS33 / probe22 / subentry19 / effect12 for each gated lane. It also requires full-state native-to-owner before/terminal/next joins, actual source and stack provenance, the genuine next ordinary TRACE close, the read-only window binding and all existing lifetime/rseq guards. Hash summaries are transport identifiers, not substitutes for those actual byte comparisons.

Private receipts retain full command argv, logs, actual artifact bytes and failures. `summary.json` contains compact numeric outcomes, hardware, command/capture hashes and receipt identity without host paths. A `passed` owner result means only this six-subject finite experiment. It grants no original392/522, whole-profile, RET-continuation, performance or within-10x claim. Earlier failed attempts remain separately failed.
