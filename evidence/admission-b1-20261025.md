# B0 qualification and cooperative B1 evidence

The accepted stack subsequently passed [validation on the extended core](admission-rebase-20261025.md).
The original source identities and measurements below remain historical.

Recorded 2026-10-25 06:15:44 EDT. Validated code revision:
`642d8a99f6fbb78eee49161d0330ea5551110770`, consuming core A1
`c6cc3fb62d2b839a2318d112a6dbca76bce4c2ec`. The tracked worktree matched the
code revision before and after validation and the diagnostic measurements.

## Result and supported scope

B0 supplies the all-start runtime scan, versioned complete/partial entry facts,
mock page/dependency ledger and conservative A0 exporter. Its qualified
CALL-return rule records a verified CALL fallthrough before admitting the
caller, including a return destination on a page that has never executed.
Records survive generation changes. NX state or an empty ledger never proves
that no saved continuation exists.

B1 now captures executable and interpreter entry, gates initial executable
mappings, publishes genuine A1 CPUID generalized puns through a remote adapter,
and admits competing first faults once under actual all-thread exclusion.
The supported concurrent envelope is a fixed group of two through eight
cooperative workers, immutable private code, supplied complete instruction-head
facts, declared resume heads and explicit ownership of external access/aliases.
The factory leader stays held after registration. Unsupported operations refuse.

This is the roadmap's early closed-world milestone. The native evidence uses
four workers on Linux x86-64 with the declared System V/extended-state contract,
no CET or AMX, and no application access to instrumentation-private frames.
Other selected instruction classes remain B2 work; general thread, signal,
loader, alias, JIT and mapping lifecycle support remains B3 work. The custom
interpreter fixture does not establish arbitrary dynamic-loader support.
No real-application, Intel, CET or browser release result is claimed here.

## Native correctness evidence

The workspace contains 44 admission tests and 52 launch tests. The launch
tests use generated ELF fixtures and real owned processes; ptrace denial fails
the tests rather than skipping them. Important covered obligations are:

- Executable and custom-interpreter instruction one are captured before original
  execution; bootstrap restores source bytes, GPRs and true first-user XSTATE.
- Real single-task and all-task leases borrow their stopped owners. Independent
  GETREGS checks confirm every registered task remains stopped while publication
  maps code, changes permissions, writes exact native MOV stores and synchronizes
  the child mm. Other workers never run during that transaction.
- Four workers first fault on the same NX page. Exactly one publication completes,
  all four logical executions produce observations, and each worker exits with
  its expected result. Pending faults acknowledge the completed generation.
- A five-byte E9 fetch crossing a page boundary brings both complete pages into
  one publication. Source successor bytes that the pun consumes stay unchanged.
- Actual CALL instructions push returns into a still-NX destination. Native
  stack and kernel permissions are checked; selected publication overlapping the
  retained obligation refuses with unchanged source. A clean destination works.
- Independent raw-ptrace execution compares GPRs, flags, full kernel XSTATE and
  initialized stack bytes against instrumentation. Four fixed worker stacks
  permit exact RSP equality. The single-task oracle separately checks the exact
  terminal-minus-entry stack displacement. Negative controls reject RSP drift,
  register/flag changes, XSTATE changes and memory changes.
- Unowned signals, unsupported lifecycle syscalls, ineligible puns, excessive
  planning and noncooperating workers refuse within bounded control waits.
  Whole-group cleanup, poisoned leases, callback errors, unwinding and a
  poisoned result's panicking destructor retain cleanup ownership.

The core path uses `GeneralizedPunOnly` and `ReplaceFirst` with native CPUID
semantics. It neither silently falls back to the trap reference nor casts a
child address into a supervisor function pointer. A genuine callback function
value supplies an address reserved in the child with `MAP_FIXED_NOREPLACE`;
collisions refuse. Generated code, source dependencies and exact store envelopes
are covered by the held lease; a receipt follows verified RX restoration and
child-mm sync-core. All supplied heads form a conservative resume superset.

Two independent reviews closed at the validated revision with no remaining
findings. Fixes included deferred exec PKRU initialization, exact RSP oracle
coverage, poisoned-result destructor unwinding, enforcing the 64-plan cap before
planning candidate 65, numeric PID ownership after reaping, and counting only
delivered observations. Cleanup helpers have additive unexpected-exit tests.
No assertion, comparator, tolerance, ignore list or coverage gate was weakened.
Raw native SYSCALL single-stepping still exposes debugger TF in R11 and remains
explicitly unqualified for observation.

## Required validation

All commands passed with four build jobs, four test threads, incremental builds
disabled, offline dependency resolution and one target directory. Workspace
totals are **287 passed, 0 failed, 4 pre-existing ignored**. The ignored tests
are existing core timing/stress opt-ins; no admission or launch test is ignored.

| Command | Exit | Seconds |
| --- | ---: | ---: |
| `cargo fmt --check` | 0 | 0.415 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 0.416 |
| `cargo test --workspace` | 0 | 12.142 |
| `cargo check --workspace --all-features --all-targets` | 0 | 0.215 |

Platform: AMD EPYC 9D85, Linux x86-64, rustc 1.97.1
(`8bab26f4f`, LLVM 22.1.6). The exact kernel release is retained in the private
environment record. The slot occupied 1.6 GiB after validation.

## Diagnostic timings

After correctness validation, each of the same-page and cross-page native race
fixtures ran sequentially 32 times in the debug build. All 64 runs retained
every correctness assertion and passed. Every run collected four competing
faults, completed one selected publication, delivered four callbacks and reaped
its tasks. Same-page runs admitted two pages including the clean factory;
cross-page runs admitted three. Both left three original executable pages NX.

| Fixture | Gate startup p50 / p95 / p99 ms | Selected bundle first-touch p50 / p95 / p99 ms | First-fault rendezvous p50 / p95 / p99 microseconds |
| --- | --- | --- | --- |
| Same page | 33.461 / 34.988 / 37.463 | 21.945 / 25.090 / 25.276 | 33.661 / 219.039 / 708.464 |
| Cross-page E9 | 33.829 / 34.530 / 34.554 | 24.745 / 26.494 / 27.690 | 32.698 / 51.968 / 64.938 |

Gate startup includes bootstrap, NX setup, clean factory admission and worker
registration; it excludes exec-checkpoint capture. First-touch measures
successful bundle preparation, validation and publication after collective
exclusion. Rendezvous measures first observed task stop through verified
all-task exclusion; it excludes execution time before that observation.
These separate timings are not an end-to-end application startup measurement.
Clean factory first-touch p50/p95/p99 was 3.900/4.363/6.077 ms in the same-page
runs and 4.079/4.177/4.734 ms in cross-page runs.

Quantiles use nearest rank; with 32 samples p99 is the sample maximum. Shared
machine load and the debug build make these diagnostic costs, not reliable tail
estimates or a speedup/release-performance claim. No threshold was added.

Reproduce a measured fixture with
`LITEINST_TEST_GATE_METRICS=1 cargo test -p liteinst-launch --test concurrent_gate four_workers_fault_one_nx_page_before_one_publication -- --exact --nocapture --test-threads=1`;
use `four_workers_share_one_publication_with_cross_page_e9_fetch` for the other
fixture. Collection invoked the already-built test binary to exclude rebuilds.

## Private capture identities

Raw logs and per-sample JSON remain in the ignored target directory. No raw log,
host path or internal hostname is part of this receipt. Paths below are relative
to the checkout:

- Required checks and exact source/log digest manifest:
  `target/li2adm-evidence/642d8a99f6fb-required-20261025T101435Z/`.
- Metrics, test-binary/source digests, per-run log digests and environment:
  `target/li2adm-evidence/642d8a99f6fb-metrics-20261025T101509Z/`.

| Capture | SHA-256 |
| --- | --- |
| Required-check `manifest.json` | `f517586fcd0beff53de97d3d9e6da5183e0e8b057e4ce6ba8d890ecc2302aec8` |
| Required-check `2-test.log` | `da4056962fec004689790a6fd6dfd06598e02882d77459a7b78fb7bf62d2ed90` |
| Metric `metrics.json` | `fe4111f300223fda8ac7e7a6e4e5c08a1ac550ba345da883c7fc0c6b262a7f31` |
| Metric `environment.json` | `578c0e24d7b20b4078eca3c2597490a1e505dded2cec0ff6dc40422f8ef5a53b` |

The earlier [B0/checkpoint receipt](admission-20261024.md) remains historical.
Its pre-replay revisions and original capture hashes are not substituted for
the current exact-source evidence above.
