ADDS deterministic clocks and tagged getpid/gettid to the launcher through genuine original-PC NX and restored one-shot UD2 handoffs.

Evidence supports claims 2 and 4 within the stated finite profiles.

`deterministic-builtins-v1` returns clock `0x1122334400000000 + (ordinal << 8)`, RDTSCP AUX `0xc001c0de`, and PID/TID tags `0x4c320001`/`0x4c320002`. Replacements preserve original syscall inputs and apply the required RCX/R11 clobbers without claiming a native syscall. Forwarding retains lifecycle/rseq guards. Source restoration precedes the effect.

Fresh native results are exact **`d0585497`**, containing main `0a8fb30d` (full revision below). The [builtin result](results/20261028T152430.999268Z-page-selected-provider-builtins-d058549715fe.json) passes 759 commands and **18 invocations**: two native baselines, two configured, two bridge/native-policy and twelve required failures. Interpreter-entry clocks and first-main RDTSC are observed before setup. Each gated positive has six clocks/ten syscalls and **eight restored owners, seven returns and exit RESTORED**. Each configured positive has four replacements/six native calls, including exit.

Sixteen records check full ucontexts/kernel FP, source/data/stack, registers, flags and terminal interlocks. Live captures are not independent full live XSAVE. Failures retain exit 125 and pre-dispatch clobbers, including two genuine callback faults and forbidden prctl. Positives match 42-byte output; native clocks/PIDs remain distinct.

The run retains 385 original provider cases, 51 callback controls, four launcher pairs and registered-rseq fallback (four NX events/zero publication). Fresh same-revision companions pass: [six-owner publication](results/20261028T152207.556183Z-page-selected-oneshot-d058549715fe.json), [49 failure controls](results/20261028T152225.820894Z-page-selected-oneshot-failure-d058549715fe.json) (48 failed operations/one clean fallback), and [17 rseq cases](results/20261028T152403.779859Z-page-selected-rseq-application-fast-memset-d058549715fe.json) (two completions/fifteen refusals). Their command counts are 34/76/75. The [CPUID-NX result](results/20261028T153248.054566Z-page-selected-cpuid-nx-d058549715fe.json) passes 716 commands: 385 original cases, 51 callbacks and 57 NX controls, including 16 required failures. All five boundary lanes retain identical 128-byte output; gated lanes have four admissions/one refault. All five profiles retain unchanged sources and zero final errors.

At a checkout of the exact native revision below, use one reserved CPU and run in order; receipt variables require fresh passed results:

```sh
REV=d058549715fec9a4a02423b197350fccae9042d8
python3 evaluation/inprocess/page_selected_oneshot.py --expect-revision "$REV" --library-root /usr/lib64
python3 evaluation/inprocess/page_selected_oneshot_failure.py --expect-revision "$REV" --positive-receipt "$POSITIVE_RECEIPT"
python3 evaluation/inprocess/page_selected_rseq_application.py --expect-revision "$REV" --fast-memset
python3 evaluation/inprocess/page_selected_provider_builtins.py --expect-revision "$REV" --positive-receipt "$POSITIVE_RECEIPT" --negative-receipt "$FULL49_RECEIPT" --rseq-receipt "$FULL17_FAST_RSEQ_RECEIPT"
python3 evaluation/inprocess/page_selected_cpuid_nx_run.py --expect-revision "$REV"
python3 evaluation/inprocess/page_b2_reference.py --expect-revision "$REV"
```

Hardware: AMD EPYC 9D85, Linux 7.1.3, GCC 11.5.0, Rust/Cargo 1.97.1; no root/effective capabilities. Builtin bounds remain 30 CPU/60 wall seconds, 512 MiB memory/16 MiB capture.

The [finite reference](results/20261028T152003.077090Z-b2-callback-reference-d058549715fe.json) passes 96 commands at `d058`: five raw/model/explicit-trap trajectories (ten reaped children), five genuine-NX C trajectories, **17 effects per lane/seven classes**. Full-state comparison uses fresh same-subject XSAVE format and **fixture-only PID173**. No restored-reference, selected-first-interpreter, whole-program, performance or full-B2 credit.

Scope: cooperative singleton, reserved signals/private entry, same-page unregistered patches. CPUID-NX is separate; registered coverage has an inactive critical-section pointer. B2/B3/B4 remain open. The historical [matrix](results/native-pages-94a552a.json) completes disabled-rseq `/bin/ls`; default-rseq ls exits -9/reportless, cause unproven. No application speedup is claimed.

Earlier results retain their actual revisions. Fresh `d058` artifacts qualify the changed core; the old 701-entry identity claim is not reused. Prior failed attempts remain failed.

All six [required checks](results/20261028T153825.986826Z-checks-3a3cc4fea1ec.json) pass at `3a3cc4fea1ec8e0787000bd5f54d64a7d65ca53e`: **350 recorder tests; fmt; strict workspace/all-target/all-feature Clippy; 2,931 workspace passed, zero failed, 33 ignored across 103 harnesses; workspace check; 1,039 serial launch passed, zero failed across 27 harnesses**. Workspace/serial times are 393.876/128.299 seconds under unchanged 900/180-second limits. Source, configuration and process cleanup stayed intact. Only six inventory/parser files differ from native `d058`; runtime, fixtures and native readers are unchanged. Reproduce on four reserved CPUs with `python3 evaluation/inprocess/checks.py --expect-revision 3a3cc4fea1ec8e0787000bd5f54d64a7d65ca53e`.
