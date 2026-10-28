# Twenty streamed epochs at b895189

All 26 release-recipe stages passed at
`b8951894cb31bcc2d5276112c47f43f5ae97ba3f`. Each child has an ECHILD proof,
complete parent cleanup and zero rescued descendants.

[Separate required gates](gates.json) passed all seven checks at the same revision:
workspace 2,571 passed / 0 failed / 8 ignored in 307.643 seconds; serial launch
1,039/0/0 in 124.118 seconds; staged allocation 3 passed and prefixed-pun 36 passed.
Format, strict workspace Clippy and workspace check also passed. All seven
commands closed cleanly with zero rescued descendants. The workspace count
uses 100 outer terminal groups (101 Cargo groups), excluding four nested
summaries in this campaign. The host exposed 316 CPUs. No affinity change or
`RUST_TEST_THREADS` override was used; libtest kept its defaults except serial
launch's explicit `--test-threads=1`.
These functional gates are separate from the native evidence and add no profiler
accuracy or throughput claim. Their durations are operational.

The new process made 160 original and 160 installed exact-work calls, alternating
lengths 1 and 64. Twenty epochs used three slots and 17 replacements. Forty
four-call drains exported 160 raw rows and 320 events. Actual ownership was
120 sampled / 40 removed, with six whole calls in every active window and two
in every off window. The independent parser required observed coverage in all
40 windows; it did not substitute nominal ownership counts. Calls and
retirements finished by the observed window end, and replacements met the
arm-minus-10-ms cutoff. The nominal schedule was 800 ms with a 2 second backstop.

[cases.csv](cases.csv), [commands.csv](commands.csv) and [receipt.json](receipt.json)
record exact numbers, normalized commands, source/tool/binary hashes and review
references. All 25 prior stages passed again, including 978/844/844 inherited
state comparisons, 12 exact-work populations (288 calls), timed epochs, both
retirement cases and the two-buffer drain. The concurrent-mode state oracle has
no competing controller. Its boundary remains gate entry through post-POP,
including inherited GPR/flags/XSAVE/data and `[S-128, stack_end)`, then a real
outer return after harness-context restoration. Setup and the remaining stack
are excluded from comparisons; the absolute deadline includes setup.

Full input, original calls, 512-word journals, full Report/terminal fields,
batch owners, returns and retirement permits are Rust source assertions.
This export checks closed JSON metadata, not saved CSV bodies, machine state
or executable bytes. CSV hashes are producer-recorded. Mandatory hooks remain
active off-epoch. There is no new full-state, timing-accuracy, performance,
indefinite-service or complete-A5 credit.

The AMD EPYC Zen 5 dev host reported AMD family 26/model 17/stepping 0.
Rust/Cargo were 1.97.1; GCC was 11.5.0. Release artifacts use opt 3/debug 0 with
assertions and overflow checks. The ordinary binary was rebuilt; oracle and
libtest were cached. The new stage has 20 CPU seconds, 30 wall seconds and
1 MiB output, with a 55 second parent bound. Worker and controller use distinct
CPUs; raw ticks are uncalibrated.

Two development Clippy attempts remain FAILED for `needless_range_loop`;
an equivalent `iter_mut().enumerate()` fixture correction passed. An intervening
edit-script assertion failed before writing (executor report). Final eight Rust
controls and eleven synthetic Python controls passed. No native stage failed
in this campaign. Earlier failures remain in the [ordinary](../ordinary-interval-ff18353/README.md),
[exact-work](../exact-work-723f09e/README.md), [concurrent](../concurrent-epochs-84d0040/README.md),
[creation-identity](../creation-identity-088dc0a/README.md),
[reachable-allocation](../reachable-allocation-48f2225/README.md) and
[merge](../merged-af5a1ef/README.md) reports. The separate backing-child and
`orig_rax` failures remain unresolved.

From the clean tested checkout with the recorded tools:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision b8951894cb31bcc2d5276112c47f43f5ae97ba3f \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed --streamed-epochs \
  --raw "$REPO/ignored/NEW_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`python3 -B project.py --raw "$CLOSED_RUN" --root-meta "$CLOSED_COMMAND_RECORDS" --out "$NEW_OUTPUT"`
reproduces this exact JSON/CSV projection; it runs no workload.

Run the separate gates from the same clean revision:

```sh
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```

The native `project.py` command above reproduces only native metadata. The
existing gate projector independently consumes its closed receipt and logs:

```sh
python3 -B evaluation/merged-af5a1ef/summarize.py \
  --closed "$CLOSED_GATES" \
  --sha256 a4c8426b1ec093bc2c8245c8258ce878db4611f90ce59a73e6b26a722d923bb2 \
  --revision b8951894cb31bcc2d5276112c47f43f5ae97ba3f \
  --output "$NEW_GATES_JSON"
```
