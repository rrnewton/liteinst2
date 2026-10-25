# Selected-instruction reference increment

Recorded 2026-10-25 13:24:34 EDT.

Validated source: `6465ca5380046ebc96cf9f63ddd6117a78bf7749`, descended from
accepted replay `f36e0ec722e6e89cc859456076fa16c36af45e9c` and core
`6e99b849513799a35e6be3827ad484e4c5521e6d`. This receipt covers a B2
single-task reference increment, not unrestricted B2 completion.

The increment adds typed selected inputs, results and faults; exact register
completion; an explicitly selected page trap/interpreter owner; and a native
SYSCALL mechanism that authenticates kernel entry/exit without debugger TF
leakage. Script rows validate before consumption. Alias input declarations do
not invent return semantics. The [contract](../crates/liteinst-launch/SELECTED.md)
records the supported operations and ownership conditions.

All changes are in the launch crate. Core contracts, admission scanning, A1
publication and concurrent CPUID restrictions are unchanged. Existing tests,
assertions, comparators and ignore lists are unchanged. Embedded candidates
remain gated; no implicit fallback or policy deselection was added.

Two independent adversarial reviewers approved the exact source revision.
Review explicitly checked assertion weakening, changed tolerances/exemptions,
skipped cases, relabelled failures and deleted checks; none were found.

## Scope and evidence

The new suites contain 14 pure semantic tests, 13 independent block/page tests,
33 native CPU cases and seven native syscall tests. Tests and instruction
invocations are different denominators. The bounded block interpreter uses its
own decoder and effects; the native observer uses raw ptrace and original
instructions with CONT. Both compare complete register/flag/XSTATE images and
fixed application memory. Nondeterministic native samples are replayed exactly;
separate native-provider runs verify each sample's actual application dataflow.

The nine-row masked-CPUID chain requires three CPUID, two RDRAND, two RDSEED,
one RDTSC and one RDTSCP callback. Both random success and failure are forced;
failure must zero its destination. The CPUID results hide the random features,
but the program deliberately executes those instructions. Separate fixtures
cover explicit RDPID policy, executable/interpreter instruction one, cross-page
RDSEED, scripted getpid/gettid, typed alias faults and unchanged-source/NX
refusals for undeclared aliases and embedded candidates.

Native SYSCALL evidence includes literal and ignored-prefix encodings,
forced -EFAULT and getpid, kernel completion and original continuation, full
state/memory, actual exit, NX fetch faults, and direct RF-bearing input.
getpid comparisons first assert each exact child PID, then substitute only that
declared external identity; -EFAULT comparisons need no substitution. The direct
RF result does not qualify RF-bearing input through the inserted-trap wrapper.
The wrapper requires caller-certified TF/RF-clear original entries.

The initial -EFAULT fixture used a NULL pointer with stdout on /dev/null, whose
write can succeed without reading that pointer. It was corrected to an invalid
access_ok extent; the required -EFAULT and is_error assertions were retained.
That developmental failed run remains separate from the final clean validation.

## Validation at the exact source revision

All checks passed with four build jobs, four workspace test threads, offline
resolution, incremental compilation disabled and one target directory. The
aggregate command deadline was 360 seconds, matching the expanded core
campaign's declared cap; no command timed out.

| Command | Exit | Seconds |
| --- | ---: | ---: |
| `cargo fmt --check` | 0 | 1.016 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 1.267 |
| `cargo test --workspace` | 0 | 269.642 |
| `cargo check --workspace --all-features --all-targets` | 0 | 0.766 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 0 | 5.175 |

Workspace outer harness totals: **797 passed, zero failed, four pre-existing
ignored**. Five successful nested core child summaries are excluded from that
total. The separate serial launch rerun passed **119 tests, zero failed or
ignored**, including 14 pure semantic tests and the original 50 B1 integration
tests. It is not a claim of 119 native instruction samples.

The uncaptured serial output contains **zero capability-fault diagnostics**:
all 33 configured CPU cases completed natively on this host. Each case has one
raw original sample, one exact scripted replay and one separately checked
native-provider execution. Thus the table describes 33 raw samples and 66 gate
callbacks, split into 33 scripted and 33 native completions, with no native
capability faults. Random carry outcomes are hardware-dependent; deterministic
success/failure requirements are established separately by the forced fixtures.

| CPU class | Native fixture cases / raw samples | Scripted replays | Native gate completions |
| --- | ---: | ---: | ---: |
| CPUID | 3 | 3 | 3 |
| RDRAND, bare 32-bit | 8 | 8 | 8 |
| RDSEED, bare 32-bit | 8 | 8 | 8 |
| RDPID, class-only policy | 8 | 8 | 8 |
| RDTSC | 3 | 3 | 3 |
| RDTSCP | 3 | 3 | 3 |

The separate block/page suite establishes 17 forced scripted completions:
CPUID 3, RDRAND 2, RDSEED 4, RDPID 2, RDTSC 3, RDTSCP 1, SYSCALL 2. It also
establishes three explicit provider faults (RDRAND, INT80, SYSENTER), one
exhausted-provider callback with no completion, and 20 pre-admission refusal
fixtures with zero callbacks: 11 prefix/default-RDPID, three embedded patterns,
six alias-declaration cases. The 192 pure width transitions are not live sites.

The syscall suite establishes nine raw completed samples, seven direct-controller
completions and two native page-gate completions. Separate exit cases terminate
once through each mechanism; the selected exit has one callback and no fabricated
completion. One NX fetch fault occurs before syscall entry, and nine direct API
requests refuse before execution. Fixture addresses are reused across processes;
these counts are invocations, not globally unique addresses.

Hardware qualification is Linux x86-64 on AMD EPYC 9D85 (family 26, model 17,
stepping 0), with Rust/Cargo 1.97.1. This is one AMD environment, not an Intel,
CET or cross-vendor qualification. No unexplained state or fault mismatch remains
in the final tests.

Private captures, 132 Rust/Cargo source hashes, eight capture hashes and nine
native test-binary identities remain under ignored
`target/li2adm-evidence/6465ca538004-b2-required-20261025T171939Z/`.
No raw logs, private paths or host names are published.

| Capture | SHA-256 |
| --- | --- |
| Exact source/log `manifest.json` | `a755a71b9f53356c55a94ce218040359ed0888ca70c0250069197ae907669f44` |
| Hardware/capability `qualification.json` | `41912f17ae1b16fdbd69f1e2457666dcbb9de252b32b7acb774d9e2c6609c47f` |

## Remaining work

Prefixed random encodings and default-policy RDPID can still encounter selected
suffixes with no backstop and refuse. RDPID-only positive policy does not prove
default-policy coverage. Pure all-width/all-GPR support does not prove every
live encoding. Alias returns, general syscall replacement, full-class A1
publication, multi-task providers, signals/lifecycle/JITs and cross-vendor/CET
qualification remain open. Hook cost was not measured; no performance or
release-completion claim is made.
