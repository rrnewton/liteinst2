# Ordinary-program interpreter publication

Dynamically linked `/bin/true` now completes through real temporary syscall and
RDTSC patches in its initial interpreter. Both the production and observed
release bridges published patches for **2 RDTSC and 6 syscall executions**, restored all eight
publications and returned all eight effects. Native, production and observed
programs exited zero with identical empty stdout.

The exact native qualification revision is
`0d1f6db865c64f8086863fdee00eac350ef0e97a`. This supports claims 1, 2 and 4 within
the finite singleton profile. It is not full B2 qualification.

The observer retained genuine NX and UD2 frames, complete ucontext/siginfo and
initialized FP state, real syscall inputs/results and hardware clock results.
The unchanged readers verified each source page before publication and after
restoration, the E9 landing, protection/generation/backing observations and
callback completion. A real TRACE also witnesses the original AND at RDTSC
PC+2, after the interpreter clock at file-backed offset `0x1fd98`.

| Executed cohort | Result |
| --- | --- |
| Original six-owner positive | Six restored publications; five returned effects; terminal exit remains restored |
| All 49 negative controls | 48 required failed operations and one refused original site |
| All 17 inactive-rseq pairs | Two completed pairs and 15 required refusals |
| Registered-rseq fallback | Native/gated pair passes without publication |
| Ordinary interpreter qualification | Three successful programs; eight restored publications per controlled lane |

The final interpreter cohort retained 55 commands and 115 captures. Independent
saved-data replay checked the original prerequisite readers, both 16-translation-unit
bridge builds, actual compiler header dependencies, archive/tool/ELF/DWARF
identities, namespace descriptors and the exact public projection.

This profile explicitly disables rseq for ordinary `/bin/true`. Registered
ACTIVE publication remains refused. It retains eight owners without recycling;
subsequent selected instructions use the existing route. CPUID-NX composition
is not enabled. The prior default-rseq completion result is separate, and
[the release matrix](rseq-native-boundary-4649d36.md) still records default
`/bin/ls` as failed. Full saved-state checks are local to the observed process;
arbitrary syscall memory, clocks and full native/controlled process state are
not asserted equal.

Both C bridges use `-O2`; their Rust decoder archive is a locked offline release
build. Hardware is an AMD EPYC 9D85 158-Core Processor, x86_64, kernel 7.1.3;
the numeric receipt retains exact kernel/compiler/source hashes. All subjects
use one reserved CPU and the unchanged 30 CPU-second, 60 wall-second, 512 MiB
and 16 MiB bounds. Observation adds work; this cohort makes no performance claim.

At the exact revision, reserve one CPU and run the tracked scripts in order:

```sh
python3 evaluation/inprocess/page_selected_oneshot.py --expect-revision "$REV"
python3 evaluation/inprocess/page_selected_oneshot_failure.py --expect-revision "$REV" --positive-receipt "$POSITIVE"
python3 evaluation/inprocess/page_selected_rseq_application.py --expect-revision "$REV" --fast-memset
python3 evaluation/inprocess/page_selected_oneshot_registered_run.py --expect-revision "$REV" --positive-receipt "$POSITIVE" --negative-receipt "$NEGATIVE" --rseq-receipt "$RSEQ" --initial-interpreter
```

`REV` is the full revision above. The three receipt variables name the fresh
private receipts produced by the preceding same-revision runs. The final
[numeric receipt](results/20261028T204736.739668Z-page-selected-oneshot-interpreter-0d1f6db865c6.json)
records exact reproduction arguments, hardware, identities and ordered publication
results. The public data contains summaries, not raw signal records or logs.

Current main `abab69594a19140fe5e6f78492da883803dfbe4c` is merged. The page-entry
and in-process qualification sources are byte-identical to the native-qualified
revision above. At merged source revision
`22ad885df4e56412eca45b1b197696b188a7ca3f`, all
[six required checks](results/20261028T211106.723742Z-checks-22ad885df4e5.json)
passed: formatting, strict Clippy, all-feature checking, 350 recorder tests,
3,056 workspace tests (36 ignored) and 1,039 serial launch tests. Recorder,
workspace and serial runs took 172.4, 357.7 and 136.4 seconds under their
unchanged 180, 900 and 180 second bounds. The 69 new upstream test instances
are included in the workspace total. The
[pre-merge checks](results/20261028T204906.265896Z-checks-0d1f6db865c6.json)
also passed at the native qualification revision.
