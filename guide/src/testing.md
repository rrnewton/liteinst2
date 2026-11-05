# Testing your instrumentation

Instrumentation fails in ways ordinary code does not: it can corrupt
the program it observes, or observe it incompletely while looking
healthy. This chapter is about testing against both.

## Test the uninstrumented behaviour first

Your oracle is the program *without* your hooks. Record its outputs,
exit codes, and relevant state transitions; then require the
instrumented run to match everywhere your tool claims transparency.
LiteInst's own suite is built this way: native oracle drivers run the
same workload patched and unpatched and compare full machine state —
one `#[test]` oracle often performs hundreds of state comparisons.
Borrow that shape even at small scale: one workload, two modes, exact
comparison.

Run the library's suite the way CI does (`.github/workflows/ci.yml`:
format and clippy gates, then debug *and* release workspace tests):

```console
$ cargo fmt --all -- --check
$ cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
$ cargo test --locked --workspace --all-targets --all-features
$ cargo test --locked --release --workspace --all-targets --all-features
$ cargo package --locked
```

## Test the refusals, not just the successes

For every site class your client handles, write the test where the
planner *refuses* — a straddler with no sound pun, an interior entry, a
split site without a staleness budget — and assert your fallback (trap,
skip, or abort) engages. A client that has never exercised
`TrapRequired` in testing will meet it first in production.

## Test under concurrency and signals

The interesting failures are races: a thread fetching mid-publication,
a signal landing on a relocated PC, a neighbour site sharing a store
tail. LiteInst's opt-in stress tests exist for exactly this and make
good templates:

```console
$ cargo test --release --test stress live_probe_stress_matrix -- --ignored --exact --nocapture
$ cargo test --release --test stress probe_overhead_benchmark -- --ignored --exact --nocapture
$ cargo test --release --lib rapid::tests::live::benchmark_single_byte_toggle_latency -- --ignored --exact --nocapture
```

`live_probe_stress_matrix` runs 128 rapid probes, a million opcode
stores, guarded jump probes, 10,000 activation cycles, and concurrent
signal delivery at default scale (scalable via `LITEINST_STRESS_*`
environment variables). Note also what the suite does for hygiene:
the test that deliberately faults (`relocated_fault_pc_translation`)
delegates its SIGSEGV to a bounded child process so it cannot mutate
the harness's signal state. Steal that pattern for your own
fault-injection tests.

## Test at the right layer

If you build on LiteInst directly, the above is your job. If you build
a Reverie tool, test the *tool* across backends instead: the same tool
must produce the same observable behaviour under ptrace and in-guest
execution, and Reverie's conformance harness exists for that. The
Reverie guide's testing chapter covers it; do not re-implement it at
the patching layer.

> 🚧 **Under construction — client test skeleton.** TODO: a copyable
> test skeleton for a new client crate: dual-mode oracle harness,
> one refusal test, one signal-PC translation test, wired into
> `cargo test` without fixture-driver environment variables.
> <!-- UC: testing-skeleton -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`testing-skeleton`).
