# Authored two-return native profiler evaluation

This increment adds one exact 36-byte zero/nonzero leaf with two ordinary RETs. It supplements the existing 19-byte fixture. All four original native modes remain required. This is partial evidence for claim 4; it makes no performance, arbitrary-exit, admission, or preemption-clock claim.

Run the finite reproduction script from a clean checkout of the reported source revision, with Rust 1.97.1, GCC, the locked offline Cargo dependencies, Linux x86-64, and ptrace permitted for owned children:

```sh
python3 -B evaluation/native-two-returns/reproduce.py \
  --raw "$PWD/ignored/two-return-reproduction" \
  --toolchain "$RUST_TOOLCHAIN" --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

The script runs the four required workspace commands, one native compile, and eight native modes serially. It uses one target directory, four Cargo jobs, and no incremental compilation. It stops at the first failed command and retains the failure and unrun phases. The unchanged `required-gates.py` keeps 180/180/360/180-second workspace limits and four test threads. Native compilation retains 60 CPU seconds, 90 wall seconds, and 128 MiB per file. Native modes retain 20 CPU seconds, 30 wall seconds, and 16 MiB per file through the existing bounded helper. Each native child retains the existing whole 20,000-stop/15-second limits. No child budget resets or comparator masks are added. Operational elapsed times are not throughput or latency benchmarks.

Raw logs, maps, the copied runtime executable, and capture files stay under `ignored/`. Cargo products, including both subject DSOs, remain in the git-ignored `target/` directory; their exact paths and digests are retained in the private artifact record. The structured result includes the exact source revision, source digests, tool versions, hardware, and full command/environment records. Publication must normalize path coordinates and omit usernames and host names; keep only summary CSV/JSON in the tracked results directory. The compiler's actual JSON build-script records identify both DSO producers, and its actual compiler-artifact message identifies the executable copied for native runs. The script checks exact stdout, strict cleanup receipts, and the complete 3,013-file inventory. Independent comparison of the capture contents is a separate evidence step.

All original fixed-leaf model, calibration, and documentation cases remain part of the workspace obligation. The new adapter requires both path orders, exact original head sequences, unchanged full architectural state comparisons, real CALL and RET witnesses, complete journal prefixes, zero unused journal bytes, and the original return word. Three block-local relocation members use a single bundle transaction. Four new setup refusals require missing, duplicate, non-RET, and foreign RET sets to fail before publication. Generation mode serializes validated completed reports separately from journal observations; the controller's intermediate reservation checks remain executed source assertions.
