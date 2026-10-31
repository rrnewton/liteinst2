# Sealed-source loader validation — both full gates failed; targeted controls passed

The gate at `3f4d0bb4d93a6c47154a63018d2ea67fdb32e86d` **failed**: workspace **4,234 passed / 1 failed / 37 ignored**; serial launch **1,039 / 0 / 0**. The six added sealed-source controls produced five passes and one failure. All earlier test identities/statuses remain. Raw 4,237 / 1 / 37 includes three controlled child passes, excluded above.

| Command | Exit | Seconds |
|---|---:|---:|
| `cargo fmt --check` | 0 | 9.866867 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 20.457146 |
| `cargo check --workspace --all-features --all-targets` | 0 | 14.178728 |
| `cargo test -j 16 --workspace --no-fail-fast` | 101 | 820.389660 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 0 | 128.511322 |

Outer: exit 1, 993.522168 s, complete cleanup, zero rescues. Original allocator/owner processes, scope and tag were absent afterward; the shared ledger remained. Host: AMD EPYC Zen 5 dev host, configured stable rustc 1.97.1. [receipt.json](receipt.json) carries exact times, CPUs, load, commands, overrides and private log hashes.

The failing test required `sealed_source_stamp(&mut file, &expected).unwrap() == original` after rejected mutation attempts. One closed diagnostic observed `pwrite` return **EPERM (1)** while mtime and ctime both changed from **1793471268222397231** to **1793471268222631182** (+233,951 ns). Device, inode, size, mode, bytes `01020304` and seal mask `15` stayed equal. Rejected shrink, grow and additional-seal operations caused no further observed change.

Diagnostic reproduction; timestamp changes need not occur on every kernel:

```python
import errno, fcntl, os
fd = os.memfd_create("sealed-diagnostic", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
try:
    os.write(fd, bytes([1, 2, 3, 4]))
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    before = os.fstat(fd)
    try:
        os.pwrite(fd, b"X", 0)
    except OSError as error:
        assert error.errno == errno.EPERM
    else:
        raise AssertionError("sealed write succeeded")
    after = os.fstat(fd)
    assert os.pread(fd, 4, 0) == bytes([1, 2, 3, 4])
    assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) == seals
    print(before.st_mtime_ns, before.st_ctime_ns, after.st_mtime_ns, after.st_ctime_ns)
finally:
    os.close(fd)
```

The correction at `03e1a41315c4859441b9e9c12e57a2fd0ad1a8d0` explicitly narrows that test's across-attempt comparison to device/inode/size/mode. It retains every mutation refusal and exact byte/seal check, and adds separate mtime/ctime mismatch refusals to the actual provenance control. Production code is unchanged: full Stamp equality across bounded reads and against retained ownership remains required. V1 stays failed.

The second full gate at `03e1a41315c4859441b9e9c12e57a2fd0ad1a8d0` also **failed**. Formatting exited 1 for tuple layout; Clippy and check passed. Workspace testing reached its unchanged 900 s bound and exited -9 after 900.274154 s; cleanup completed with eight reaped descendants. Completed summaries contain **2,812 passes / 0 failures / 4 ignores**, excluding the same three controlled child passes. The unfinished `whole_adc_state_oracle` harness has another 35 passing terminals of 39 announced tests; four native ADC-width tests have no terminal result. These are an incomplete prefix, not whole-workspace totals. Rapid-profiler and its six new controls were not reached.

Serial launch completed **1,039 / 0 / 0**, with its complete census unchanged. All required historical groups reached in the workspace match V1: Rapid 15 (+1 ignored), observing-control 8, prefixed PUN 5, short-neighbor 21 and exec-source 8; the mutated-window rejection passed once. V2 outer exited 1 after 1,083.118104 s with complete cleanup; original owner/allocator PIDs, scope and tag were absent afterward. The receipt records all five command times, logs and loads; host load is observational, not a timeout-cause finding.

A separate targeted run at whitespace-only descendant `5f8da296813547a3f606117fb1d6b4b19b2e06e5` passed `cargo fmt --check` (10.557497 s) and all **six** sealed-source controls (6/0/0, 564 filtered; command 9.355170 s). Both direct owners exited 0 with complete cleanup and zero reaped descendants under 180 s/8 MiB each, on four reserved CPUs. This does not repair either failed full gate. Release absence was independently checked; the reviewer missed the brief live process and does not claim an independently observed live lease or allocator starttime. Allocator exit 0 and CPU assignment are root-reported tool evidence.

Reproduce the five commands with tracked `evaluation/short-neighbor-parallel/validate.py --revision <EXACT_REVISION> --output ignored/<FRESH_OUTPUT>` from a clean checkout. V1 used an equivalent private worker; V2 used that exact script. Apply the receipt's explicit environment overrides, a disjoint 16-CPU reservation, and the existing `evaluation/admission/processes.py::run_command` outer ownership limit of 1,200 s / 8 MiB. The script supplies the recorded per-command limits. The separate targeted command is `cargo test -p rapid-profiler --lib sealed_source_tests -- --nocapture`, after formatting at its exact revision, under the receipt’s four-CPU/180s/8MiB ownership bounds. Harness concurrency remains 316, Cargo build jobs 4, test command jobs 16, debug info 0 and incremental compilation off. Other environment was inherited.

This increment concerns copied backing immutability. Unsafe mapping, ABI, no-active-CET, lifetime and reentry contracts remain owed; full owned-session/rendezvous and A5 qualification are not established. No selected-function, accuracy, performance or historical profiler-failure claim changes.
