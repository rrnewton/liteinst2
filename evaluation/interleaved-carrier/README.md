# Finite interleaved ELF carrier check

The owned-neighbor ET_EXEC writer can place separately backed RX images below
or between original LOAD segments. The read-only metadata carrier still follows
the original loads. Original headers retain their relative order, PHDR/INTERP
precede LOADs, and all original/new page ownership and resource checks apply.
The append-only API and the existing ET_DYN path retain their previous behavior.

`reproduce.py` builds a small fixture emitter, then runs an original freestanding
ET_EXEC and three rewritten variants through the normal kernel loader. Their
RX image addresses are below, between, and above the original load segments.
All four must produce exactly `42\n` and exit zero. This checks those finite
layouts; it does not establish arbitrary dynamic-loader or machine-state
coverage. The separate structural tests cover page overlap, BSS, metadata,
header order, unchanged bytes, address/span budgets, and ET_DYN refusal by the
new API.

From a clean checkout, with cached dependencies and Rust 1.97.1:

```sh
python3.9 -B evaluation/interleaved-carrier/reproduce.py \
  --toolchain "$LI2_TOOLCHAIN" --user-home "$LI2_USER_HOME" \
  --cargo-home "$LI2_CARGO_HOME" --raw ignored/a3/interleaved-carrier-run
```

The raw directory must be new and its parent must exist. The script selects up
to four available CPUs, uses one target directory, disables incremental builds,
and requires 2 GB of headroom below the slot's 20 GB cap. It keeps fixed
120 CPU-second / 180 wall-second / 128 MiB compiler bounds and
2 CPU-second / 5 wall-second / 1 MiB fixture bounds, plus separate supervisor
cleanup. Every child must close with ECHILD and no rescued descendants.

The development build has opt-level 0 and debug-info 0, with assertions and
overflow checks enabled. Recorded elapsed times are validation diagnostics,
not performance measurements. Keep logs and generated ELFs under `ignored/`.
The script emits a compact receipt, complete numeric CSVs, and commands with
private paths replaced by roles for publication under `evaluation/`.
