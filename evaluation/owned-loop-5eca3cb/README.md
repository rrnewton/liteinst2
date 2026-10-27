# Caller-owned preemption client at 5eca3cb

At `5eca3cb8db9cd548bb398fd3a94e2440d6f48cf5`, the standalone owned-buffer client passes: **64 bytes transformed, stops at taken edges 16/32/48, 63 taken edges, 64 encounters, three parked-buffer checks and checksum 8352**. It compares the whole guarded buffer with both native execution and an independent Rust model, joins the worker, and releases its data allocation before reporting success. Code owners remain process-lived.

[Result JSON](result.json) records the exact source/tool/binary hashes, Rust 1.97.1, observed CPU fields and actual Cargo cache status (`fresh=false` here). The owner hardware label is **AMD EPYC Zen 5 dev host**. The native helper closes with ECHILD and the outer parent closes successfully without rescued descendants. This is functional evidence; the earlier four-loop release throughput cohort remains separate in [software-preemption-2b18607](../software-preemption-2b18607/).

Reproduce from a clean checkout at this exact revision with an offline cache:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/software-preemption/verify_owned_loop.py \
  --revision 5eca3cb8db9cd548bb398fd3a94e2440d6f48cf5 \
  --raw "$PWD/ignored/owned-loop-new" \
  --toolchain "$TOOLCHAIN_ROOT" --user-home "$CLIENT_HOME" \
  --cargo-home "$CARGO_CACHE"
```

Arguments must be canonical absolute directories; `TOOLCHAIN_ROOT` contains `bin/cargo` and `bin/rustc`. [invocation.json](invocation.json) records the actual command and outer closure. The script reuses the single `target/` directory, checks a clean revision, builds once, runs the exact selected executable, and checks its complete expected output. Build limits are 120 CPU/180 wall seconds; native limits are 20 CPU/30 wall seconds. Raw requests, receipts and logs stay ignored. Run this historical script with Python assertions enabled; the publishing revision adds an explicit refusal of optimized Python. The recorded execution used assertions throughout.

`new_owned_loop` admits a bounded copied integer-loop CFG, not memory safety or progress. Clients still supply valid ABI/memory/entry exclusion and encounter bounds. This result adds no general ELF, asynchronous cancellation, code retirement or full-XSAVE/whole-stack qualification. The four-literal admission profile is unchanged.
