# Overlapping source redirects

At revision `392e4fbf82df434da0e782ff15556ad1a2b66812`, the focused campaign passed 225 tests (13 core, 195 rewrite-library, 17 example), and two isolated native tests passed. The native tests cover 24 authored layouts: 192 original, 192 linked and 192 restored traces, 96 exact source-relay visits and 48 callbacks. The full correctness gate also passed at that exact revision: 4,376 workspace tests passed with 39 unchanged ignores, and 1,039 serial launch tests passed. Its complete prior census plus exactly 20 additions matched; 4,379 raw workspace passes include the same three controlled child rows.

The artifact-only family puts two correlated `E9 rel32` redirects in six source bytes: original `V` reaches the victim body; the selected short redirect reaches synthetic `V+1`, then the selected body. `V+1` gains no original-head authority. Both size bounds and distinct permitted pages are certified before one encode per role; actual fields, mappings, source ownership and pending ranges still pass. Old modes are unchanged.

Source controls include 60 layouts (selected lengths 2–4, victim lengths 6–15, both orders), boundary and ownership refusals. Native layouts use selected lengths 2/3/4, victim lengths 6/9/10/15 and two seeds. Registers, flags, XSAVE, stack/data and callbacks are compared across all three phases; ten malformed preflights per layout also refuse. No asynchronous/live-publication, whole-program or performance qualification is claimed.

The [historical 512 MiB corpus](../full-program-bounded-hull/README.md) remains failed: 2,053 sites/13,143 heads, 2,034 atomically withheld plans, 19 refusals, no candidate. These recorded correctness campaigns execute no full-program corpus; any later corpus result has a separate receipt. Focused compilation at `46cd0093028b27a9075bbb6291efa3a1d973a46e` also remains failed (exit 101, `E0282`; later stages unstarted). The fix added a `Result<_, Refusal>` annotation; no assertion or case was removed.

[receipt.json](receipt.json) records commands, bounds, exact roster digests, capture hashes, CPU affinity/load and closure evidence. [results.csv](results.csv) is the compact stage table. Hardware was an AMD EPYC Zen 5 dev host. Timings include command startup/build work and are not benchmarks.

Copy [reproduce.py](reproduce.py) to `/tmp/overlap-reproduce.py` before switching a fresh checkout below. Use Linux x86-64, the oracle’s required ptrace facilities, offline Cargo dependencies and the pinned Rust binaries. Externally reserve twelve CPUs (`taskset` only applies affinity); set `CPUS` and `TOOLCHAIN_BIN` accordingly. Each phase requires a fresh output name:

```sh
git checkout --detach 392e4fbf82df434da0e782ff15556ad1a2b66812
taskset -c "$CPUS" /usr/bin/python3 -I -B /tmp/overlap-reproduce.py --root "$PWD" --toolchain-bin "$TOOLCHAIN_BIN" --phase focused --name overlap-focused-reproduction
taskset -c "$CPUS" /usr/bin/python3 -I -B /tmp/overlap-reproduce.py --root "$PWD" --toolchain-bin "$TOOLCHAIN_BIN" --phase native --name overlap-native-reproduction
```

The script pins exact HEAD/tree, clean tracked files and tools. Canonical sorted-name digests check every test identity, with duplicate/non-`ok` rejection and exact summaries/native lines. Commands run once under the tracked owner: 300-second wall/8 MiB capture; focused processes retain 600 CPU seconds/4 GiB AS/512 MiB files. Native AS is separately 8 GiB for the retained 4 GiB `PROT_NONE` arena, with unchanged 20 CPU/30 wall seconds per body and 20,000 steps/15 seconds per trace. The whole-program 1 GiB limit is unchanged.

Fresh JSON/CSV outputs go to `ignored/<name>/`; raw captures stay private under `target/evaluation/<name>/` and are read after owner closure. The script has no independent live witness, unlike the measured runs. It runs no corpus or full gate. The separately measured five-command gate is described below.


The unchanged [validate.py](../short-neighbor-parallel/validate.py) recipe ran fmt, strict Clippy, workspace check, workspace tests and serial launch tests once. Every command exited zero; outer elapsed time was 957.6717400599737 seconds under a 1,200-second wall and 8 MiB capture. Stage walls remained 180/180/180/900/180 seconds with 8 MiB captures. [results.csv](results.csv) gives the five stage times; [receipt.json](receipt.json) retains exact argv, loads and capture hashes. The gate has independent full raw process identity and clean release evidence. Its separately closed census reader exited zero in 0.7490808269940317 seconds with zero rescues; that short metadata reader has **no independent live witness**.

To repeat the five-command recipe after the same checkout/toolchain preparation, choose another fresh output name and keep the twelve-CPU reservation. This invocation uses the unchanged tracked owner and validator; it records a new command result, not the historical independent census or live witness. `TOOLCHAIN_BIN` is the pinned directory used above, and `CARGO_BIN` is the caller's Cargo shim directory (not used instead of the pinned compiler):

```sh
taskset -c "$CPUS" /usr/bin/python3 -I -B - "$PWD" "$TOOLCHAIN_BIN" "$CARGO_BIN" <<'PY'
import hashlib, importlib.util, json, os, sys
from pathlib import Path
root, toolchain, cargo_bin = map(lambda p: Path(p).resolve(), sys.argv[1:])
os.chdir(root)
assert __debug__ and len(os.sched_getaffinity(0)) == 12
helper = root / "evaluation/admission/processes.py"
recipe = root / "evaluation/short-neighbor-parallel/validate.py"
assert hashlib.sha256(helper.read_bytes()).hexdigest() == "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
assert hashlib.sha256(recipe.read_bytes()).hexdigest() == "968956df64edd3f5754a0adbd4b900ac68535d188be01af0628eff94d2ed6d10"
env = {k: v for k, v in os.environ.items() if not (k.startswith("CARGO_") or k.startswith("RUST"))}
env.update(PATH=f"{toolchain}:{cargo_bin}:/usr/bin:/bin", RUSTC=str(toolchain / "rustc"), RUSTDOC=str(toolchain / "rustdoc"), CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="12", CARGO_TARGET_DIR=str(root / "target"), CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", RUST_TEST_THREADS="12", CARGO_NET_OFFLINE="true", PYTHONDONTWRITEBYTECODE="1", GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_0="index.threads", GIT_CONFIG_VALUE_0="1", GIT_CONFIG_KEY_1="core.preloadIndex", GIT_CONFIG_VALUE_1="false")
logs = root / "target/evaluation/overlap-full-reproduction"
logs.mkdir(parents=True, exist_ok=False)
spec = importlib.util.spec_from_file_location("validation_owner", helper)
owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
result = owner.run_command([sys.executable, str(recipe), "--revision", "392e4fbf82df434da0e782ff15556ad1a2b66812", "--output", str(root / "ignored/overlap-full-reproduction")], env, logs / "outer.log", 1200, 8388608)
with (logs / "owner-closed.json").open("x") as stream:
    json.dump(result, stream, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
assert result["exit_code"] == 0 and result["termination"] is None
assert result["cleanup_complete"] and result["reaped_descendants"] == 0
PY
```
