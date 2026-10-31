# Workspace validation at 5d1

The five-command suite completed once at `5d1f888f5d2a4f4ff6fa5dcfbbdc851228c85e73`, with unchanged sources, normal exit 0 and complete owner cleanup. Workspace summaries contain **4,048 passed, 0 failed and 37 ignored**; the separate serial launch contains **1,039 passed, 0 failed and 0 ignored**. All **122 required regression names passed**. The ignored names, reasons and multiplicities match the prior census exactly.

| Command | Wall bound (s) | Actual (s) | Exit |
| --- | ---: | ---: | ---: |
| `cargo fmt --check` | 180 | 13.273907 | 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 180 | 16.775211 | 0 |
| `cargo check --workspace --all-features --all-targets` | 180 | 10.079501 | 0 |
| `cargo test -j 16 --workspace --no-fail-fast` | 900 | 887.656656 | 0 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 180 | 128.067985 | 0 |

The outer owner took 1,055.951318 seconds under its original 1,200-second bound. Every owner retained its 8 MiB output cap and separate three-second cleanup budget; no owner rescued descendants. The machine was an AMD EPYC Zen 5 development host with Rust 1.97.1. Sixteen CPUs were reserved while `RUST_TEST_THREADS=316` remained in force; the final command explicitly selected one test thread. The receipt records the exact CPU IDs, load averages, unoptimized dev/test settings, commands, source and log hashes. These are correctness-command durations, not performance measurements.

Counts include both `rapid_profiler` doctest groups. The workspace has 110 outer summary occurrences; three successful nested `controlled_oracle` summaries (one pass and 35 filtered cases each) are excluded **only from totals** to avoid double counting. All 113 raw summaries remain in the private audit: 4,051 passes, zero failures, 37 ignored and 105 filtered. The serial command has 27 summaries. Custom harnesses without libtest summaries receive no invented counts. Workspace and serial overlap and are not additive unique coverage.

[receipt.json](receipt.json) is the compact projection of the authenticated closures and independent audit. It preserves all five command outcomes and groups all ignored outcomes by reason. Exact required and ignored names remain in the authenticated private audit, along with raw logs. The separate [192-pair release evidence](../native-d96/README.md) and [roster repair](../roster-v1/README.md) remain distinct. This suite does not qualify PMU accuracy, cadence, strict 2 ms, performance or the full A5 matrix. Earlier failures are unchanged.

A separate minimum-version command at the same revision checked only `rapid-profiler --all-targets --all-features` using explicit Rust 1.85.0 cargo/rustc/rustdoc. It exited normally in 10.913299 seconds, with unchanged sources, complete cleanup and no rescued descendants. Four CPUs were reserved. Its command retained a 180-second timeout followed by a five-second TERM-to-KILL grace period; the outer owner retained 1,200 seconds and 8 MiB. This is not a full Rust 1.85 workspace or runtime result and is not part of the five-command totals.

Reproduce from a clean checkout of the exact revision with Python 3.9 and an offline Rust 1.97.1 toolchain/cache. Keep the later public receipt outside that checkout in `RECEIPT`. Variables substitute local paths: `ROOT` is the checkout, `USER_HOME` the user home, `TOOLCHAIN` the directory containing `bin/cargo`, `CARGO_HOME` the offline cache, and `RUN_TMP` a private temporary directory. `RUN` is a fresh relative path below `ignored/`; `OWNER_LOG` is a fresh absolute path below `${ROOT}/target/evaluation/`. The snippet reuses the existing owner and validator. The allocator reserves CPUs; affinity alone is not a reservation.

```sh
export ROOT USER_HOME TOOLCHAIN CARGO_HOME RUN_TMP RUN OWNER_LOG RECEIPT
cd "$ROOT"
cpuset-alloc run --cores 16 --sample-s 1 --tag accuracy-workspace-reproduce -- \
  /usr/bin/python3.9 -B - <<'PY'
import hashlib, importlib.util, json, os
from pathlib import Path
from string import Template
r = json.loads(Path(os.environ['RECEIPT']).read_text())
root = Path(os.environ['ROOT']).resolve()
assert Path.cwd() == root and len(os.sched_getaffinity(0)) == 16
expand = lambda s: Template(s).substitute(os.environ)
env = {k: expand(v) for k, v in r['outer']['environment'].items()}
Path(env['TMPDIR']).mkdir(parents=True, exist_ok=True)
log = Path(os.environ['OWNER_LOG'])
assert not log.exists()
log.parent.mkdir(parents=True, exist_ok=True)
for name, pin in r['source']['reproduction_sources'].items():
    raw = (root / name).read_bytes()
    assert len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256']
spec = importlib.util.spec_from_file_location('validation_owner', root / 'evaluation/admission/processes.py')
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
result = owner.run_command([expand(x) for x in r['outer']['command']], env, log, 1200, 8388608)
print(json.dumps(result))
raise SystemExit(int(result['exit_code'] != 0 or result['termination'] is not None
                     or not result['cleanup_complete'] or result['reaped_descendants'] != 0))
PY
```

`validate.py` checks the exact revision and tracked-source cleanliness, preserves 316 test threads, runs the fixed five commands without retries, and records each outcome. Inspect every resulting owner and log rather than treating the presence of a closure file as success. New failure, timeout, ignored or unresolved outcomes must remain visible under the same bounds.

To reproduce only the separate minimum-version check, set `MSRV_TOOLCHAIN` to the Rust 1.85.0 toolchain directory and use the same outer owner/env with four allocator-reserved CPUs, a fresh log and the exact `minimum_version_check.command` array from the receipt. Its expanded command is:

```sh
/usr/bin/timeout --signal=TERM --kill-after=5s 180s /usr/bin/env \
  RUSTC="$MSRV_TOOLCHAIN/bin/rustc" RUSTDOC="$MSRV_TOOLCHAIN/bin/rustdoc" \
  "$MSRV_TOOLCHAIN/bin/cargo" check -p rapid-profiler --all-targets --all-features
```
