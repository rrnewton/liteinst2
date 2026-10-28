# Profiling ordinary C calls to an unchanged scalar leaf

Revision `d33e9e50a87409c0e19852deb51df1168d469f0f` adds a separate normal-caller
profile. Application C makes ordinary function-pointer calls without a per-call
SDK invocation, reserved RBX value or substituted return address. One thread
attaches before the work and checkpoints after the caller returns. Existing
gated profiles retain their contracts and checks.

The subject is the unchanged FreeBSD 14.1 `strnlen` translation unit pinned in
`tools/rapid-profiler/strnlen-work/UPSTREAM.json`. Its compiled body is 41 bytes,
with 13 reachable heads, 14 edges and returns at offsets 34 and 40. A separate
67-byte compiled C helper makes two calls, stores both results and returns their
sum. The recipe authenticates both complete ELF files and the helper's complete
body before execution.

The release qualification passed on an **AMD EPYC Zen 5 dev host**, using Rust
1.97.1 and GCC 11.5.0. The recipe took 114 seconds; this is an operational duration,
not a throughput measurement.

| Validation | Result |
| --- | --- |
| Native original/instrumented execution | 17 pairs, 34 children, 4,044 full-state comparisons, 0 mismatches |
| Physical transfers | 68 target CALLs, 68 target RETs, 34 outer caller RETs |
| Stable population | Two seeds × all eight inputs; complete reachable head/edge/RET union per seed |
| Concurrent owner transition | One additional pair switches epochs at the first pre-RET stop; actual controller-helper join |
| Input operands | 696 one-byte reads checked against actual input bounds |
| Ordinary-call consumer | 8 original and 8 installed calls; matching results and complete guarded inputs |
| Runtime accounting | 7 next-entry acknowledgements, 1 post-return checkpoint; 4 sampled, 2 closed, 2 removed |
| Complete accounting | 2 generations, 16 events, all 512 journal words, 2 Reports, actual worker join |
| Abandonment | Sampled and closed pending receipts retained through actual TLS exit; 2 reattachment refusals; no checkpoint |
| New release controls | 9 runtime, 4 caller, 8 oracle, 2 child and 9 parser methods; new loader-contract refusal also passes |

Native comparisons retain all registers, defined flags, XSAVE, the entire data
page and the contiguous protected stack including both calls' full red zones.
The oracle observes both actual CALL/RET continuations and checks callee-save
restoration before repairing its own harness state for the outer return.
Every pair keeps the original absolute 15-second deadline and continuous
20,000-step child limit. Candidate children used 5,587–6,277 steps.

The runtime retains each original receipt at pre-RET. The next authenticated
entry confirms the preceding return under the normal-CALL/no-reentry contract;
the final receipt requires an unsafe same-thread checkpoint after application
work has returned. These acknowledgements remain distinct from the native
oracle's physical RET observations. A pending closed receipt also retains its
epoch permit after Report retirement. Reports and checkpoints authorize no code
reclamation; source and generated owners remain process-lived.

The new profile currently requires one attached thread and a complete 5–80-byte
scalar, read-only leaf with no CALL or edge back to entry, at most four RETs and
32 calls between drains. Continuous source/input custody, normal returns and no
signals, nonlocal exits, active CET or unload remain caller obligations. This
supports **claim 4, systematic validation**. It does not complete A5's arbitrary
application support. Raw callback ticks are uncalibrated; no timing accuracy,
overhead or throughput result is claimed.

The first release attempt at `23eddd7b866ab0d1a2bb6ead0c42b533d78ba05d` failed
before the actual caller CALL: single-stepping a fixture deadline query remained
inside the vDSO clock routine until the step limit. The correction moved that
same absolute check to the supervising parent, retaining its checks around every
step. The failed attempt remains recorded in `receipt.json`; limits and state
comparators were not relaxed.

The recipe also reruns the existing named, selected and whole-function suites.
Their compact CSV rows are included: named and selected checksum cases each
retain 4 pairs and 978 comparisons; gated strnlen retains 16 pairs and 1,668
comparisons. All three retain 8 original and 8 installed calls and their loader
refusals. All stages closed normally, with no cleanup rescues.

Reproduce at the recorded revision with a new absolute `$RAW` under `ignored/`:

```sh
$PYTHON -B tools/rapid-profiler/verify_normal_interval.py \
  --revision d33e9e50a87409c0e19852deb51df1168d469f0f \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`receipt.json` records normalized commands, exact source/tool/artifact hashes,
hardware, review bindings and closure summaries. CSVs retain scalar results;
they do not independently replay the full native state, journals or Reports.
Raw logs, environments, captures and manifests remain ignored.

At this exact source revision, default workspace testing on 316 available CPUs
passed **2,962 tests, 0 failed, 33 ignored** in 331 seconds. Serial launch passed
1,039 tests; staged-allocation and prefixed-pun checks passed 3 and 36. Formatting,
strict workspace Clippy and all-target compilation passed. All seven historical
exec-admission/allocation regressions were present and passed.
`workspace-checks.json` records the exact commands and closure results.

```sh
$PYTHON -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```
