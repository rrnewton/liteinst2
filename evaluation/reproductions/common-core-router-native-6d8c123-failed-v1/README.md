# Failed synthetic router bootstrap: records and reproduction

This immutable cohort records source **`6d8c123531f30e1a841c52c8955d46f294811172`** on **AMD EPYC Zen 5 dev host**. The native command exited **101**. The strict helper recorded ECHILD with no unexpected descendants, cleanup events, timeout, abort or cleanup error. Its elapsed time was 0.15368607197888196 seconds. The helper wrapper and enclosing caller both exited 1 after their actual direct-child waits. Durations are operational observations, not performance measurements.

`Router::new` refused `prior_stack.ss_flags == 0` at `tests/support/e9_common_router_native.rs:154:9`; its unchanged assertion requires `SS_DISABLE == 2`. This proves an enabled alternate stack existed. The saved flags do not establish its installer, address, size or owner. Source order shows one preparatory reference child was stepped and reaped before the refusal. No candidate child, router signal-state mutation or trace followed. The controls directory was empty, and all completed roundtrip/negative/child/comparison counts remain null. The planned four roundtrips, twelve comparisons, two negatives, ten children and 34 stops per positive are not completed results.

`summary.json`, `commands.json`/CSV and `sources.json` retain the exact failure, bounded contexts, saved build identity and selected source/Git-object map. The normalized diagnostic omits only the thread PID and generic backtrace hint; its complete original stderr digest remains. The binary build passed separately. Full saved source/tool/product/metadata snapshots were equal before and after the failed native invocation. The helper's `inputs_unchanged` means request/helper bytes only. The reporter read saved records and source pins; it did not reopen the product or runtime.

The complete original native caller is exported as **`run.py`**, SHA256 `00661a3ab0b0f9abbae99403075dcdf0cec49fb1bb93368b8a9864c537bdf9fd`. It accepts an explicit binding and fresh raw directory. `build.py` is the exact validation driver for this tested revision; `launch-historical.py` is the exact enclosing native caller source. The historical launcher pins a particular old binding and ignored coordinates, so it is provenance rather than a fresh-host invocation.

The new **`launch.py`** is an unexecuted, parameterized version of that small outer caller. It retains the 145-second wait, immediate group SIGKILL on timeout and ten-second direct-child reap bound. It also puts the started-record write inside the cleanup scope and explicitly refuses optimized Python. Its only command remains the unchanged `run.py`; it adds no native cases or synchronization behavior. Its final outer closure proves only the direct parent wait; the inner strict receipt remains the descendant-absence authority.

To reproduce the failure mechanism, save these sources outside the checkout before selecting the exact tested revision. In a clean checkout at that revision, with an available offline Rust toolchain and sufficient admitted resources, use fresh ignored output coordinates:

```sh
python3.9 -B "$EXPORTED_BUILD" --repo "$REPO" --output "$FRESH_BUILD" --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --phase native-build
```

The build retains `cargo build -p liteinst2 --bin elf-exec-oracle --message-format=json`, four CPUs/jobs, 180 seconds, an 8 MiB log, zero debug information and unchanged debug assertions. Preserve its actual enclosing parent record as well. The native caller requires that parent source/command/start/closure/stream record; a terminal exit alone is insufficient. The earlier validation packet exports the corresponding build parent template. No compiler or native command was executed to prepare this report.

Create a **fresh reviewed binding**, using the exact existing caller schema, before running the native command. `binding.example.json` and `product.example.json` show normalized field shapes, not authority: their string placeholders intentionally fail the caller. Substitute real absolute paths, booleans, byte counts, whole hashes and six-field owner tuples from the fresh epoch. Do not copy historical inode/ctime values into a new binding. `source-manifest.json` contains the exact seven committed source byte hashes for this revision; copying those bytes is valid only when the fresh whole build source snapshot joins them literally.

The binding requires these eleven keys:

- `schema: 1`, `authority: ROOT_REVIEWED_SYNTHETIC_ROUTER_CONTROL_INPUTS`, exact `repo`, `revision`, and fixed `caller_sha256`.
- `source_manifest`: the canonical ignored copy of the seven-source map; `build` and `build_launch`: complete closed build and parent records; `build_parent_source`: the exact parent source.
- `tools`: fresh `python`, `timeout`, `git`, `helper` records, each with `path`, `resolved`, `lookup_stat`, `stat`, `bytes`, `sha256`. The unchanged caller independently fixes executable paths and helper/observer source hashes.
- `files`: every admitted ignored metadata file, each `{sha256, bytes, stat}`; `stat` is `[dev, ino, mode, size, mtime_ns, ctime_ns]`. Include the native caller, source manifest, build command/log/before/after/summary/product, build driver, and build parent source/command/start/closed/streams. The caller checks every admitted record before and after.

`product.json` uses the exact Cargo artifact object from the complete build log, matching the intended binary target/profile; it separately records the fresh executable's whole SHA256, bytes, canonical path, dev/inode/mode/mtime/ctime/uid/gid and the build log/summary hashes. The native caller independently rechecks the executable and the entire current source epoch against these records. A fresh caller binding must be reviewed alongside actual capacity, tool/configuration and build records; the examples do not manufacture that admission.

Copy the exact `run.py` into a canonical ignored location included in that binding. Once the binding's actual whole digest is supplied, invoke the new outer wrapper with fresh raw and launch directories:

```sh
python3.9 -B "$EXPORTED_LAUNCH" --repo "$REPO" --caller "$IGNORED_CALLER" --binding "$FRESH_BINDING" --binding-sha256 "$BINDING_SHA256" --raw "$FRESH_RAW" --new-launch "$FRESH_LAUNCH"
```

The native request remains **60 CPU seconds / 90 wall seconds / 64 MiB per file**, CPUs 0–3. The unchanged inner wrapper is GNU timeout 100 seconds with ten-second kill-after and a 115-second direct parent. File caps are per file, not aggregate disk reservations. No threshold, source-owner comparison, native assertion, case or full-state comparator is changed. The exact diagnostic depends on the fresh environment; a new observation is not assumed to match the historical outcome.

Public path roles are reversible using the corresponding private role map. Raw logs, owners, private bindings and captures remain ignored. This is a bounded invocation recipe with explicit input prerequisites, not an automated fresh-build admission system or a promise of universal failure reproduction. A successor bootstrap and any successful controls must appear as a distinct tested cohort. This failure establishes no completed native control, common-corpus result, normal-loader qualification or full A3 completion.
