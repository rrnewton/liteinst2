# Original-site identity and termination syscall qualification

Tested source: `aa8aa54ceeab9f35c8583fa65ee452fe4bcfeaa2`.
All three final receipts authenticate the same 1,523 tracked source files,
manifest SHA-256 `d9337cabffb267c404917617cf17914504b5d489236a3767cc030e7574d458ce`.
This report and its receipts are later evidence additions. The
[profile contract](runtime-kernel-profile.md) describes the explicit opt-in
`IdentityAndTermination` extension; default native refusal remains unchanged.

The finite profile executes original native64 getpid/gettid/exit/exit_group
at the captured current PC. Returning operations require actual ENTRY and EXIT,
complete state and source reauthentication, exact original `orig_rax` lineage,
a private neutral return, and restored NX fetch pages before committing a fresh
origin. Termination instead requires real pre-exit, recorded release, actual
terminal status, matching natural-parent evidence and original pidfd readiness.
It creates no returning state or fictional NX observation after mm destruction.
The public retained journal and full private native/census histories have
separate accounting and retention contracts.

Six added native controls exercise private and public getpid→scripted
CPUID→ordinary execution→exit, gettid→exit_group, a real two-page SYSCALL fetch,
default/native-CPU refusals, provider faults and unsupported syscall encodings,
and stale replies with physical custody. They compare complete GPR/XSTATE/mask,
full original source and stack, map/control identities, raw wait/effect records,
complete census lineage and unchanged post-terminal markers. The two-page case
places actual SYSCALL at `0x400fff`; the initial MOV starts at `0x400ffd`.
Scripted CPU values supply no native CPU execution claim. Every successful
native body requires exact application and broker physical cleanup.

These observations support candidate claims **1** (original-byte page admission),
**2** (unprivileged first-instruction custody within the stated profile) and
**4** (explicit mechanism and failure validation). They establish no software
preemption clock, performance result, arbitrary application coverage or completed
B3/B4 gate. Loader/TLS/I/O, ordinary memory/stack/indirect execution and connected
thread/signal/fork/mapping/JIT paths remain outside this finite runtime increment.
The compiler-produced C consumer has not run in this revision.

## Reproduce

Use a clean checkout of the exact tested source with the compatible recorded
hardware/toolchain. The separate `cpuset-alloc` helper reserves eight CPUs for
each extra cohort; those cohorts use default libtest parallelism.

```sh
python3 evaluation/admission/run.py --expect-revision aa8aa54ceeab9f35c8583fa65ee452fe4bcfeaa2
cpuset-alloc run --cores 8 --tag li2adm-aa8aa-unit -- python3 evaluation/admission/default_parallel.py --expect-revision aa8aa54ceeab9f35c8583fa65ee452fe4bcfeaa2 --cohort unit
cpuset-alloc run --cores 8 --tag li2adm-aa8aa-fork -- python3 evaluation/admission/default_parallel.py --expect-revision aa8aa54ceeab9f35c8583fa65ee452fe4bcfeaa2 --cohort fork
```

The fixed six command limits remain 180/180/180/360/180/180 seconds, with four
build jobs and four workspace test threads. Each extra cohort runs four times
with its original 180-second bound and no test-thread override. Incremental
compilation stays disabled; all builds use one target tree. Original three-second
operation deadlines and all six lifetime limits, including 64 MiB evidence
storage, remain unchanged. No retired or unused reservation is refunded.

Hardware: AMD EPYC 9D85, x86-64, family 26/model 17/stepping 0, microcode
`0xb101066`; 316 visible logical CPUs. Linux upstream `7.1.3`, Rust `1.97.1`
(`8bab26f4f`, 2026-07-14), Cargo `1.97.1` (`c980f4866`, 2026-06-30).
The invoker was non-root with zero effective capabilities. The full run observed
316 CPUs in its affinity; each extra cohort observed eight. JSON retains exact
source, hardware, toolchain, command, environment, inventory and cleanup metadata.
Raw captures stay private with their SHA-256 hashes in those receipts.

## Final observations

| Command/cohort | Outcome | Elapsed seconds |
| --- | --- | ---: |
| Recorder | 284 passed | 9.525 |
| Format | Passed | 3.353 |
| Strict workspace Clippy | Passed | 19.843 |
| Workspace tests | 1,936 passed, four unchanged ignores, 89 harnesses | 350.626 |
| All-features/all-targets check | Passed | 14.000 |
| Serial launch | 856 passed, 27 harnesses | 97.329 |
| Default-parallel launcher units | 564 passed in each of four repetitions | 4.561 / 4.560 / 4.579 / 4.541 |
| Default-parallel fork cohort | Seven passed in each of four repetitions | 0.279 / 0.286 / 0.271 / 0.269 |

The exact serial native inventory contains 81 cases: the old 75-name prefix plus
six kernel controls. The increment adds 64 pure Rust methods and six native
methods; old runtime138, static50, dynamic15 and matrix388 inventories remain.
The separate backing-cleanup helper retains its three controls and four
trajectories. Eleven additive recorder methods preserve all old 273 methods.
These counts are test cases/invocations, not independent instruction samples
or a probabilistic reliability estimate. All 14 final command cleanups completed
with zero descendants reaped by the outer recorder. Each new native control and
the original reset unit regression has six saved successful outcomes across
the full run, serial run and four unit repetitions. Each of the seven fork
cases has six outcomes across the full run, serial run and four separate fork
repetitions.

| Receipt | SHA-256 |
| --- | --- |
| [Six commands](results/20261026T205651.382513Z-aa8aa54ceeab.json) | `0fb5fcf1c31059d48ecad297859d306f7d4d996ad6bbe10d0b447379c567fb3b` |
| [Four unit repetitions](results/20261026T210517.573662Z-default-parallel-aa8aa54ceeab.json) | `dad767dc56fafe48e15831607e4632ae78a53868a6a4104e85a187ae5edc03e6` |
| [Four fork repetitions](results/20261026T210544.251413Z-default-parallel-fork-aa8aa54ceeab.json) | `8bd499d40b8787d69fb3633f23f358561b55b8aa91e5f031ca37f5fd181124f2` |

## Preserved failures and corrections

Nine failed qualification receipts were each committed unchanged before their
corrections. The first four stopped during compilation/strict Clippy and never
reached workspace/native testing. Corrections preserved the census unsafe-code
ban through a safe exact-allocation boundary, required the actual retained
pre-exit release header, and repaired test integration/style without dropping
assertions or methods. Later commands remained `not_run` after each failure.

The next four runs failed closed during launcher testing, before a required
outer summary. Improved bounded private diagnostics eventually retained the
actual cross-page child wait: SIGCHLD, CLD_DUMPED, SIGSEGV and exact PID match.
Earlier empty diagnostics do not prove the same inner termination reason.
Static inspection of the saved build found excessive nested constructor frame
reservations around eleven inline control profiles. The correction preserves
all eleven distinct observations in exact prepaid heap capacity, initialized
one at a time; all bytes remain charged alongside the smaller header. Neither
the saved status nor the frame inspection establishes the historical fault PC.
No stack limit or evidence cap was increased.

The ninth run reached an exact refusal-phase assertion: the journal reported
Raw/AdmissionRejected where the unchanged oracle required Original/AdmissionRejected.
The coordinator had synchronized diagnostic prefixes before recording the error,
so the copied state incorrectly became its failure phase. It now records the
first error before synchronization, preserving both the original phase and all
later retained prefixes. Earlier native failures and completed records remain
immutable. No assertion was changed to accept the observed wrong phase.

Every failed command's outer cleanup completed; its actual adopted-descendant
count is retained below. Those cleanups do not convert failed native bodies into
successful ones. All failures remain failed; later passing runs supply evidence
only for their exact revised source.

| Failed source/receipt | Stopped command | Outer adoptees reaped | Receipt SHA-256 |
| --- | --- | ---: | --- |
| [64df3ec87268](results/20261026T202032.107752Z-64df3ec87268.json) | clippy | 0 | `19beac65801286aca05b9805dd4ba2804846fc62d43e34baeaa22ab9b6d025a1` |
| [4611b66a4a25](results/20261026T202610.012154Z-4611b66a4a25.json) | clippy | 0 | `72af1a9dd100717b8b5acbca060f3db8f9e7d8be3dc38e7803863d09af96eea5` |
| [328a4e34a673](results/20261026T203013.833874Z-328a4e34a673.json) | clippy | 0 | `6f9eda9b40af4457b5963b9ae24de11a277d78632a4ed32844e9b1bf3e52d146` |
| [69201429de71](results/20261026T203535.147521Z-69201429de71.json) | clippy | 0 | `b04641456a5f2aa2fa7eee04d9b115e4edfca3e2e32cf6dbdd643ffa1f5eebd9` |
| [c65b5a1ea206](results/20261026T203747.205163Z-c65b5a1ea206.json) | workspace_tests | 5 | `78d09684772cc33b3ec0810b81691d38c5d6fc34f674ca2561adfd5b95cc64d5` |
| [29a540392cca](results/20261026T204116.753454Z-29a540392cca.json) | workspace_tests | 5 | `59fd829e08e7811e058d8aa82385b19eea7668a218a66f3f1a661ed3e6372bbc` |
| [c5081f1dcb41](results/20261026T204435.712548Z-c5081f1dcb41.json) | workspace_tests | 5 | `b6d60b70f850327e1b0b1f10a581604bc4d3ccc7c1980121a97e4d1d5378f5ad` |
| [fa12329fd56f](results/20261026T204700.391376Z-fa12329fd56f.json) | workspace_tests | 5 | `dec7b726d50369473da97db2d29b2016f70f32c9b5c852741ed273a4bbadf688` |
| [2cf447bb0a22](results/20261026T205219.188425Z-2cf447bb0a22.json) | workspace_tests | 3 | `62f75c241354d208bb9144d4355a2ceecfbe55e1e16db508a267cfe5f21c7d6c` |

The preserved SIGSEGV artifact also has [static constructor-frame evidence](runtime-kernel-stack-inspection.md), including separate manual and script-generated JSON summaries. Read-only reproduction confirms 2,810,352 bytes of explicit reservations along the identified nested path if reached. It does not establish the historical fault address, actual stack extent, deepest call reached, or a proven stack-overflow cause. This evidence adds no native qualification or performance claim.
