# Executable identity without tracer-wide map limits

The executable backing check now queries its one owned temporary mapping with
Linux `PROCMAP_QUERY`. Unrelated tracer mappings no longer consume the child's
source-inventory allowance or participate in this identity observation. Exact
mapping bounds, protection, offset, file identity, name, descriptor stability
and physical cleanup remain required. Only `ENOTTY` enters the original bounded
text fallback; stopped-child map limits remain 64 KiB and 512 rows.

This supports claim 4's systematic validation. It is a functional fix, with no
throughput or timing-accuracy claim.

Tested source: `b26c900be977d176e791fdc38cc19dcd3fc32147`, including main
`783abb5727ceac2bbd439f093872251b371a557c`. Hardware: **AMD EPYC Zen 5 dev host**,
AMD family 26/model 17/stepping 0, 316 available CPUs; Linux 7.1.3 and Rust
1.97.1. Compilation uses four jobs. Tests retain default affinity and libtest
parallelism except the separately named serial launch check. Development/test
profiles use opt-level 0, debug information 0, assertions and overflow checks on.

| Check | Result |
|---|---|
| Launch library, default parallelism | 742 passed, 0 failed |
| Full workspace, default parallelism | 2,513 passed, 0 failed, 4 ignored |
| B3 integration, 25 default-parallel runs | All passed; each includes the original five native cases plus two new parser controls |
| Mapping pressure and concurrent changes | 553 measured maps, 516 owned pressure maps; 128 queries plus one baseline; 134 churn cycles |
| Resource cleanup | Five controls, six trajectories; includes actual query/read EFAULT, real ENOTTY fallback, and the required invalid-unmap SIGABRT |
| Formatting, strict workspace Clippy, all-target/all-feature check | Passed |
| Serial launch and three historical allocation regressions | Passed |

Workspace totals count 99 outer libtest groups. Five nested summaries are
excluded from the 104 observed summaries. The custom cleanup harness is reported
separately. Command wall durations and private log hashes are in
[commands.csv](commands.csv); exact commands, revision and numeric results are
in [receipt.json](receipt.json). All 35 command closures had exit zero, complete
cleanup and zero rescued descendants. Raw logs remain private under `ignored/`.

Reproduce at the tested source revision, setting `TOOLCHAIN` to the Rust 1.97.1
toolchain directory and `CARGO_HOME` to its populated cache:

```sh
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$PWD/ignored/NEW_EXEC_IDENTITY_RUN"
```

The script does not set `RUST_TEST_THREADS` or restrict CPU affinity. It requires
the atomic-query pressure result on this validation profile. The native test
separately reports older-kernel `ENOTTY` compatibility without atomic-query
credit; the legacy text path retains its original capacity limits.

The baseline at `6fc7b8ce823c4fde4a850bc8b4798069faad53f5` failed exactly the three
reported library cases. The [diagnostic-only patch](diagnostics.patch) preserved
all errors and printed the parser category plus counts:

| Native case | Error | Tracer maps | Capture bytes |
|---|---|---:|---:|
| `admitted_exec_native_first_user_and_retired_history_are_exact` | RowLimit | 705 | 36,184 |
| `admitted_exec_native_source_reply_refusal_keeps_new_mm_held` | RowLimit | 657 | 33,832 |
| `admitted_exec_native_source_profile_bound_refuses_after_exec` | RowLimit | 585 | 30,304 |

To repeat the diagnosis, apply that patch at the baseline revision and run
`cargo test -p liteinst-launch --lib` with default test parallelism; actual map
counts vary. The bound was hard-coded at 512, and the capture belonged to the
multithreaded tracer, not the stopped exec child. Thread stacks, allocator arenas
and concurrent test mappings all share that tracer address space. The pressure
test additionally creates and counts more than 512 owned VMAs, so its regression
coverage does not depend on a particular harness thread count.

The reported intermittent five-test B3 refusal and unexpected SIGABRT did **not**
reproduce in 25 baseline diagnostic runs. Their particular cause remains
unconfirmed. The new query avoids the tracer-wide multi-read capture implicated
by the refusal path; 25 post-fix B3 runs passed. Those passes do not establish the
cause of the earlier abort. Two focused Clippy attempts failed on redundant
expressions before equivalent simplifications; both are retained as failed
attempts in the receipt.
