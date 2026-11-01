# Workspace correctness recipe

`workspace.py` is a portable source-only reproducer for the five commands used
by the full-v8 correctness gate at
`73d732679676db31f59f2d1b2b57a00db362c3c2`. This new script is **UNRUN**. The
historical result came from a different private runner, SHA256
`e23d4cf629a374f8db7e148563bf240a047e37915ee8e6f72b9220c7931a550a`;
publishing this recipe does not change that attribution or rerun any result.

The fixed commands, in order, are:

| Command | Wall limit |
| --- | ---: |
| `cargo fmt --check` | 180 s |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 180 s |
| `cargo check --workspace --all-features --all-targets` | 180 s |
| `cargo test -j 12 --workspace --no-fail-fast` | 900 s |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 180 s |

Each command has an 8 MiB capture limit. The pinned process owner retains its
three-second cleanup bound. Cargo jobs and the test harness use twelve CPUs;
the last command uses one test thread. Incremental compilation is disabled,
development/test debug information is zero, and Cargo is offline. The script
constructs the recorded environment instead of inheriting Cargo/Rust overrides.
It sets no additional CPU, address-space or file rlimits on these five commands.
Use the same toolchain and an already populated offline dependency cache.

Supply a SHA-pinned **already admitted cumulative capacity budget**. Its portable
schema is exactly these four keys; slot values are `[allocated, apparent]` bytes:

```json
{
  "schema": 1,
  "initial_slot": [17779499008, 16846597859],
  "increment_reserve": 2214592512,
  "ceilings": [19994091520, 19061190371]
}
```

These are the unchanged full-v8 budget numbers, translated without its private
authority paths. They document that historical admission, not a new admission
for another checkout. The operator supplies the budget admitted for the intended
run. Do not reset the initial values to current usage or increase the ceilings
to make a run fit. The script requires `ceilings = initial_slot + reserve`, a
reserve of exactly 2 GiB + 64 MiB, and both ceilings strictly below 20 GB.
Before and after the commands it measures allocated and apparent slot usage
separately with `du --count-links`, including `ignored` and `target`, and requires
each to stay below its fixed ceiling. These scans retain the original 30 CPU
seconds, 256 MiB address space, 64 KiB file/capture, zero core and 45-second owner
limits. Completed build bytes consume the existing reservation.

Copy this script outside the checkout before selecting the inspected revision;
its own SHA256 is recorded independently. This permits a later published recipe
to inspect the historical source without pretending the script existed there.
Use canonical absolute paths, a clean tracked tree, a fresh output name and an
external disjoint twelve-CPU reservation. For example, after saving the admitted
budget as `$BUDGET`:

```sh
REPO=/absolute/checkout
RECIPE=/absolute/recipes/workspace.py
TOOLCHAIN=/absolute/rust-toolchain
BUDGET=/absolute/admitted-workspace-budget.json
CPUSET_ALLOC=/absolute/path/to/cpuset-alloc
REV=73d732679676db31f59f2d1b2b57a00db362c3c2
TAG=early-entry-workspace-reproduction-01
git -C "$REPO" checkout --detach "$REV"
mkdir -p "$REPO/ignored"
BUDGET_SHA=$(sha256sum "$BUDGET" | cut -d ' ' -f 1)
env AGENT_UTILS_ENGINE=python PYTHONDONTWRITEBYTECODE=1 \
  "$CPUSET_ALLOC" run --cores 12 --tag "$TAG" -- \
  /usr/bin/python3 -I -B "$RECIPE" \
  --root "$REPO" --revision "$REV" --toolchain "$TOOLCHAIN" \
  --budget "$BUDGET" --budget-sha256 "$BUDGET_SHA" \
  --output "$REPO/ignored/$TAG"
```

The script checks the observed affinity has twelve CPUs; it does not claim an
independent allocator live witness. It checks the exact revision, clean tracked
tree, source roster and frozen source/tool/script/budget hashes around each
command. Original owner logs use a fresh `target/evaluation/$TAG` directory.
Each owner result is fsynced before capture reads; cleanup must be complete, and
the complete capture must match the owner's hash. Copies, plan and final receipt
remain under the fresh ignored output. A failing command prevents later gate
commands from running; safe source/capacity postflight can still run. There is no
retry. Failed or unknown outcomes remain explicit, and incomplete cleanup leaves
captures unread.

A PASS means these five commands and their source/capacity postflight closed
normally with no rescues. Complete test names, ignored cases and nested child
counts still require separate census review. This recipe does not execute the
separate fresh-release native/state campaigns, qualify the failed strict
20,000-step profile, qualify a wider instruction-budget profile, or measure performance.
