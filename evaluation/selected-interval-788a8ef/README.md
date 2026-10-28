# Profiling a selected function after stripping

Revision `788a8ef154630246f0e600b7738b053a5f7c2793` qualifies the new
`TrustedFunctionSelection` / `LoadedIntegerLeaf::load_selected` path. It locates a
function by an independently supplied ELF virtual address and complete extent,
binds the entire final file, and resolves the address through the retained module
handle. The selected function needs no exported name. Existing ABI, complete CFG,
all-return patchability, live-page identity and ownership requirements still apply.

The release run on an **AMD EPYC Zen 5 dev host** passed on its first complete
attempt, with Rust 1.97.1 and GCC 11.5.0. The unchanged compiler-produced checksum
leaf was localized and stripped: 44 bytes at ELF VA 4160, inside a 13,072-byte
final object. The runner authenticated pre-strip metadata and unchanged executable
bytes before making a separate candidate copy.

| Population | Result |
| --- | --- |
| Selected original/instrumented state | 4 pairs, 8 children, 978 full-state comparisons, 0 mismatches |
| Selected functional calls | 8 original and 8 installed; all results and input bytes match |
| Installed ownership outcomes | 4 sampled, 3 closed, 1 removed; rearm produces a second generation |
| Complete accounting | 8 rows, 16 events, 4 history actions, two Reports with 2 records each |
| Selected pre-load refusals | 3 expected refusals, 0 subject calls |
| Retained named-function prerequisite | 4 pairs, 978 comparisons, 8 original and 8 installed calls; short-return refusal retained |
| Pure release controls | 24 admission, 4 state, 7 consumer, 6 provenance and 8 parser methods; 0 failures |

The state comparison includes registers, flags, XSAVE, protected stack, data and
source/image bytes, through the actual outer return. Each pair retains its
15-second deadline and continuous 20,000-step bound. Native producers also check
the complete admitted RET set, all 512 journal words, complete Reports and worker
join; compact CSV is not a replay of those full objects. All 22 bounded helper
stages and their 23 parent owners completed normally, with ECHILD and no rescues;
the additional whole-recipe owner also closed normally.

This is one controlled compiler-produced leaf and supports **claim 4: systematic
validation**. It does not establish arbitrary stripped-function discovery,
complete real-application coverage, profiler accuracy or performance. The CSV
callback ticks are uncalibrated observations, not overhead measurements. The
wrong-file and changed-byte cases are pre-load refusals, not native wrong-base
injections. Broader A5 workload, lifecycle, daemon and accuracy gates remain open.

Reproduce from the recorded revision with the specified toolchain and fresh
absolute `$RAW` under the checkout's `ignored/` directory:

```sh
$PYTHON -B tools/rapid-profiler/verify_selected_interval.py \
  --revision 788a8ef154630246f0e600b7738b053a5f7c2793 \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

The recipe records exact build commands, tools, source/artifact digests and
closure receipts. `receipt.json` retains the summarized result and complete
normalized command population. All compact CSV rows are included, including the
named-function prerequisite. Raw logs and machine-specific captures remain in
ignored storage. The command path tokens in this publication replace concrete
workspace paths; no test population or result was changed for publication.

The seven hand-back checks also passed at this source revision. The default
workspace run used all 316 available CPUs without a test-thread override:
**2,910 passed, 0 failed, 33 ignored** (328 seconds). All five historical
allocation/exec-identity failure cases were present and passed. Serial launch
passed 1,039 tests; the focused staged-allocation and prefixed-pun suites passed
3 and 36. Formatting, strict workspace Clippy and all-target compilation passed.
`workspace-checks.json` records exact commands, bounds and closed-process results.
These wall durations are operational validation times, not performance evidence.
