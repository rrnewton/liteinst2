D01 retained both full program candidates. The overall result remains **FAILED_OR_INCOMPLETE, exit 2**, at source `ccd88c3aa96e7e9a590838d5d8c01cccebbca139`. This diagnostic draft records one capture and one full two-program producer attempt: no retry, subset, changed cap or performance result.

All 13 capture commands reported PASS: two builds, one target description, and two sets of assembly, link and three disassemblies. Each producer returned 0 and `PRODUCER_COMPLETE_UNVERIFIED`. [programs.csv](programs.csv) retains all 187 heads / 42 selected jumps: checksum 80/16 with 19 images; rle-roundtrip 107/26 with 29 images. Each used one routed-JMP pair, U/L/J work 1/1/1 under fixed budgets 2/1/2, and zero forward-Jcc calls. All 16/26 baseline calls remain recorded.

Both outer commands returned **2**, with cleanup complete, zero reaped descendants, source unchanged and empty private logs. Capture and producer have `configuration_complete=false`: 13 ABSENT, one READ and two READ_DENIED Cargo configuration observations (errno 1, no lookup stat). The two denied lookups share one repository ancestor. Their contents remain unknown; denial proves neither absence nor that Cargo ignored them. This failure remains despite `diagnostic_capture_complete=true` and retained output stability being true.

W01/N01 are NOT_EVALUATED. Artifact completeness, independent artifact/image association verification, classification, native correctness, qualification, corpus success and performance eligibility remain false. Debug text is diagnostic only; candidate publication and COMPLETE custody do not satisfy these gates.

The owner reported an AMD EPYC Zen 5 host. UTC start times, reserved CPUs, and recorded 1/5/15-minute system loads were:

| Command | UTC start, 2026-10-30 | CPUs | Load before | Load after |
|---|---|---|---|---|
| Capture/build | 08:21:21.234476 | 120,221,245,246 | 81.16,66.87,64.41 | 79.88,67.86,64.81 |
| Producer driver | 08:22:04.993984 | 161,187,217,222 | 84.34,69.69,65.48 | 84.34,69.69,65.48 |

Outer bounds were 1,200 wall seconds and 8 MiB output. Capture used four Cargo jobs, offline/locked release builds, incremental=0, optimization=3, debug info=0, assertions=true, overflow checks=true, test=false; both compiler-artifact messages agree. Owner-reported versions: runtime Python 3.9.25, owner Python 3.12.15+meta, rustc 1.97.1 (8bab26f4f 2026-07-14). These conditions are not benchmark results.

Profiles: capture `offline-whole-capture-adjacent-routed-jmp-u2-l1-j2-v1`; material/selection `offline-whole-authored-adjacent-routed-jmp-short-t3-pending-2g-v1`; importer `elf-disassembly-null-jumps-adjacent-routed-jmp-short-t3-pending-v1`. The full pending-selected roster and old profile histories are retained.

The producer child limit was 20 CPU seconds, 30 wall seconds and 16 MiB per file. The collector cap remained 64 MiB of actual reads per program, 16 MiB per file and 256 members per directory. Recorded reads were 2,025,434 and 2,828,822 bytes. A cap breach remains failure, with no widening/retry. The profile's 2 GiB virtual span is an address-space planning bound, not a file-size allowance. Child receipts report ECHILD, unchanged inputs, no timeout and no unexpected descendants. No candidate native correctness run is represented here.

[identities.csv](identities.csv) records bytes/SHA-256 for release executables and key products. Executable identities come from the authenticated closed capture; mutable build outputs were not reread. All 110 pinned capture files and 150 producer files were rehashed; COMPLETE members match the closed inventories. [provenance.json](provenance.json) binds the full inventories without duplicating logs or Debug text. Draft checks were limited to hashes and scalar/count comparisons; the D01 roster-join verdict is retained. Host paths/names are omitted.

Reproduce at the exact clean revision with pinned tools/settings and fresh locations. Substitute local absolute locations for these variables. Use the new capture's actual closed digest, retaining configuration observations and nonzero exits:

```sh
python3 -B evaluation/offline-corpus/build_adjacent_routed_jmp_whole.py \
  --raw "$CAPTURE" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_CACHE" --user-home "$USER_HOME"
python3 -B evaluation/offline-corpus/reproduce_whole.py \
  --capture "$CAPTURE" --capture-sha256 "$CAPTURE_SHA256" \
  --output "$OUTPUT" \
  --placement-profile offline-whole-authored-adjacent-routed-jmp-short-t3-pending-2g-v1
```

The build driver invokes `cargo build --release --locked --offline --package liteinst-rewrite --example adjacent_routed_jmp_disassembly_sites --message-format=json`, and the equivalent `--package liteinst2 --bin elf-exec-oracle` build. It requests the oracle's `target` description; assembles each authored source with `as --64`; links statically with `-nostdlib --build-id=none -z noexecstack` and the authored linker script; and disassembles `_start`, `kernel` and `null_hook` with `objdump -d -w --insn-width=16 --disassemble=SYMBOL`. The producer executable receives original, complete ledger plus its SHA, complete policy plus its SHA, and a new product directory. This draft executed none of these commands, changed no tracked files and read no active validation logs.
