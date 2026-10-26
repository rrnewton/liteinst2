# Compiler-produced C consumer and failed-construction cleanup

The opt-in failed-construction cleanup API qualifies at source
`871928eb99b2a4d9e04d61020fa8384f14446737`. The compiler-produced C artifact
executes successfully as a reference but remains refused by runtime startup.
This supplements the finite native syscall profile in
[runtime-kernel-results.md](runtime-kernel-results.md); it does not establish
admitted C execution, general application support or complete B3/B4.

## Preserved attempts

All result files below retain their original bytes. A successful prerequisite
is separate from the later consumer result. No failed run was reclassified.

| Exact source | Experiment | Result and receipt |
| --- | --- | --- |
| `dac54672601ba6af3e8cdffae627397b4f89ca4d` | Six-command qualification | Passed; [JSON](results/20261026T211914.455840Z-dac54672601b.json), SHA256 `24d6f05838b530247a89ed7d16fa62729ee7eb2c14b8dddef7df851b1df73cba`. |
| `dac54672601ba6af3e8cdffae627397b4f89ca4d` | Initial consumer | Failed preflight because `ld.lld` was absent from PATH; all eight commands remained not_run. [JSON](results/20261026T212647.030833Z-runtime-consumer-dac54672601b.json), SHA256 `7a4b51630b38c095f6edf6c4450c23f4c22570ee0d2283f081544619e74599e4`. |
| `2204ca30d1a30a0589a42b761b4cb26a07c4db78` | Qualification with installed linker available | Failed: workspace exceeded its unchanged 360-second bound, exit -9. Outer cleanup completed and reaped one adoptee. Later checks and the consumer did not run. [JSON](results/20261026T213043.765824Z-2204ca30d1a3.json), SHA256 `3f4e9e449f988d917a1b7f4bd723043e5c34fc22421c7cdcb98f7faa12b5f6b0`. |
| `a2ed122cad449df1cb7530032bf34e0d4dd77135` | Qualification with prospective CPU selection | Passed; [JSON](results/20261026T214109.070327Z-a2ed122cad44.json), SHA256 `8248d968913b0b80f145a81d15cab8c31943839b6b1654fbb3be3fe1f102459a`. |
| `a2ed122cad449df1cb7530032bf34e0d4dd77135` | Consumer with original linker layout | C compilation, linking and reference execution succeeded; reference exited 7. Runtime construction refused a visible file-page alias. Consumer exit 1; outer cleanup completed and reaped one adoptee. [JSON](results/20261026T214847.495009Z-runtime-consumer-a2ed122cad44.json), SHA256 `6a69f337638efc713ca8458c3095360e001b8077152bbcfc92966c468ee9e5ad`. |

The three prerequisite source revisions have identical 1,535-file source
manifests, SHA256
`e03d8776adc49a1c91e3e121c27d8166d3e8767640e9493012861c7e736b6e47`.
Both successful runs passed 296 recorder tests and all five Cargo commands:
1,936 workspace tests with four unchanged ignores across 89 harnesses, and 856
serial launch tests across 27 harnesses. All 81 named native cases qualified.
All six commands in each successful run completed cleanup with zero outer
adoptees. Workspace times were 318.494 and 315.353 seconds; serial launch times
were 101.717 and 103.634 seconds. These are qualification elapsed times, not a
performance comparison.

## What the original consumer established

The unchanged C source has SHA256
`692404365c66fdc653f9319e6f4e18bb8f698d9f9b5339e37513c8f36c5a8555`
(588 bytes). Clang 22.1.3 produced a 760-byte object, SHA256
`754c916e183015d086b1676abba8c20b66d3dd8bafb73648b03a9497f5ea75b0`.
LLD 22.1.6 produced a 992-byte ELF, SHA256
`ab1b9f514c4a955cfd6ba471df4289c2d4a01d524e5a0a84d8f372c3ee07b4ae`.
The reference process exited 7 with no output and no outer adoptees.

The original ELF's R segment occupied file bytes `[0, 0x120)` at virtual
address `0x200000`; its RX segment occupied `[0x120, 0x13f)` at `0x201120`.
Both mappings projected onto file page `[0, 0x1000)`. Distinct segment bytes
therefore did not satisfy the runtime's file-page alias rule. Construction
refused before any provider call. Adding `-z separate-code` is an explicit
artifact-layout change; the alias gate remains strict. The resulting artifact
and separate later failure are recorded below.

The failed consumer also returned before its detached tracer's asynchronous
cleanup could be observed by the caller. The outer recorder later reaped one
adoptee, whose role was not captured. This is not proof that the tracer lost a
pin or skipped cleanup. The new opt-in constructor returns the original
launch error with the original cleanup receiver, allowing a bounded wait before
caller exit. Existing constructors and nonblocking Drop retain their contracts.
Cleanup timeout retains observation ownership; it cannot restart execution or
renew the original launch deadline.

## Reproduction environment

The JSON receipts record exact revisions, source/configuration hashes, relative
argv, expected and actual exits, private capture hashes and hardware. Runs used
Linux 7.1.3, AMD EPYC 9D85 (family 26, model 17, stepping 0, microcode
`0xb101066`), Rust 1.97.1 (`8bab26f4f`) and Cargo 1.97.1 (`c980f4866`).
They ran without root or effective capabilities, on eight admitted logical
CPUs. The six-command recorder sets four build jobs and four workspace test threads;
the separate serial command explicitly uses one test thread. It disables
incremental compilation and keeps command bounds of 180/180/180/360/180/180 seconds.

The initial missing-linker correction exposed the installed LLD binary through
a private `ld.lld` symlink, preserving that argv0 flavor. Its resolved ELF
SHA256 was `38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721`
(11,604,312 bytes). The clang executable SHA256 was
`953ea1ca38bec62e4b2b9c916db4d76d5a48edb91e0cce0d5c4d7efe62e34b97`
(130,792 bytes). Both commands' versions and executable identities are bound in
the consumer receipt. The same PATH prepend was used for qualification and the
consumer; prerequisite validation does not itself hash raw PATH. This does not
claim hermetic dynamic-loader/shared-library identity.

To recreate the setup, make an absolute private directory, create its `ld.lld`
symlink to the installed LLD executable, and prepend it to PATH for both commands.
Use an installed `clang`, `cargo`, `rustc`, Python and Git matching the recorded
identities. The exact driver commands are:

```text
python3 evaluation/admission/run.py --expect-revision <40hex>
python3 evaluation/admission/runtime_kernel_consumer.py --expect-revision <same-40hex> --correctness-receipt evaluation/admission/results/<passing-run>.json --correctness-sha256 <64hex>
```

Both commands inherited eight reserved logical CPUs. After the preserved
workspace timeout, the prospective allocator invocation was
`cpuset-alloc run --cores 8 --sample-s 2 --max-irq-rate 100 --tag <run-tag> -- <command>`.
The earlier invocation used the allocator's 0.3-second default sample and no
device-IRQ ceiling. Missing IRQ data or fewer than eight eligible CPUs refuses
the new invocation; there is no fallback. This policy does not prove the
historical timeout's cause, physical-core isolation, exclusion of unrelated
host workloads, or an uncontended whole run. The completed outer neighbor
oracle and controlled oracle accounted for most of the observed timeout-run
increase; the historical causal mechanism remains unproved.

The tracked drivers preserve failed receipts, bound command output privately
and stop after failure. Public JSON contains typed summaries, not host paths,
raw logs, process identifiers or register/map dumps. No deadline, test inventory,
native comparator, lifetime limit or zero-adoptee acceptance rule is relaxed.

## Qualified constructor cleanup

The first run of this increment at
`9318018aac5d935a7c047a7f175a568b70cd1841` passed 299 recorder tests, formatting
and strict Clippy, then failed the workspace command. Both new native test
wrappers passed crate-qualified names to a registry of exact libtest names.
The unchanged guard refused them before either native body ran. The launcher
reported 571 passed and two failed; check and serial remained not_run. All four
completed command cleanups had zero outer adoptees. The unchanged
[failed receipt](results/20261026T221442.904521Z-9318018aac5d.json), SHA256
`1e54c620f97c73ef14efa31b0a9511d46765db5e8483b4138e04c90f8c888109`,
was archived before correction. Source-only reviews missed this registration
mismatch; they were not execution evidence.

Commit `871928eb99b2a4d9e04d61020fa8384f14446737` changes only those two
arguments to the exact literal identities already present in the registry and
corpus. It changes no native body, assertion, count, deadline or guard.
The source manifest covers 1,541 files, SHA256
`86b7175de27ec4fa562f9fd028c02d61ebdb012901ae81e11a230289ee5a389b`.

| Qualification at that exact source | Observed result | Receipt SHA256 |
| --- | --- | --- |
| [Six fixed commands](results/20261026T221825.003792Z-871928eb99b2.json) | 299 recorder tests; formatting; strict Clippy; 1,945 workspace passes plus four unchanged ignores across 89 harnesses; all-target check; 865 serial passes across 27 harnesses. All 83 named native cases pass in both workspace and serial cohorts. | `f66dfe38b9de326ed85cc576fb80b06bd5a4d55a9336efb97bbf32c292d67421` |
| [Default-parallel unit cohort](results/20261026T222704.419804Z-default-parallel-871928eb99b2.json) | Four runs, each 573 passed; 4.850/4.859/5.904/5.602 seconds. | `8ac7e8164deef7a19d2435c4e2c1e03db966013122e2c7d8b2567510e73d3b4a` |
| [Default-parallel fork cohort](results/20261026T222736.871181Z-default-parallel-fork-871928eb99b2.json) | Four runs, each seven passed; 0.344/0.303/0.301/0.313 seconds. | `0ed7f217544827bc7e2048b5235d09e1e4c08c219d22fea95e0351d625fd5016` |

The six command times were 10.706/3.390/12.871/335.526/15.051/108.108 seconds
in recorder/fmt/Clippy/workspace/check/serial order. All fourteen qualification
command cleanups completed with zero outer adoptees. Default-parallel runs use
no test-thread override, on eight reserved logical CPUs. Each new native cleanup
case therefore ran six times: workspace, serial and four unit repetitions. This
is not six executions of every case in the 83-case native inventory. All 296
previous recorder identities and all 81 previous named native cases remain.

The two new native controls cover a real visible-file-page alias refusal and
an explicitly injected owner error after a genuine held EXEC but before Ready.
The alias fixture is a literal ELF with the earlier compiler artifact's load
geometry; it is separate from the compiler consumer. Both controls retain
original application and broker pins, observe cancellation inside actual
provider destruction, require two positive-duration waits to time out while the
real owner is held at a cleanup gate, preserve the exact first error, and then
release the gate. Completion requires the original owner's actual receipt plus
independent pinned physical-cleanup observations. Their watchdog cannot count
as an explicit release. No original application instruction or provider decision
is allowed on these failure paths. Seven pure transport controls separately
cover error/result caching, invalid duration, disconnection and cancellation;
synthetic channel receipts receive no native credit.

The public API is `DynamicAdmissionSession::launch_runtime_with_cleanup`.
A returned `DynamicRuntimeLaunchFailure` keeps the first error separate from
`NotStarted`, `Pending`, `Complete`, `Failed` or `Disconnected` cleanup status.
`wait_cleanup` only observes the original completion receiver. A timeout retains
it; actual results are cached. Existing constructors and nonblocking Drop are
unchanged. Provider destructor panics still propagate; the retained-handle
contract applies to returned errors and a caller that keeps its process alive.
Actual mask-restoration failure is not a native case in this increment.

To reproduce the default-parallel additions at the same source and environment:

```text
python3 evaluation/admission/default_parallel.py --expect-revision 871928eb99b2a4d9e04d61020fa8384f14446737 --cohort unit
python3 evaluation/admission/default_parallel.py --expect-revision 871928eb99b2a4d9e04d61020fa8384f14446737 --cohort fork
```

## Separate-code consumer: preserved bootstrap refusal

The unchanged C source and object hashes above remain identical. The revised
LLD command includes `-z separate-code` and produced an 8,864-byte ELF, SHA256
`37a69af5dd1e0cc1ef6372f154ee91aa9a13980fce547569bdc609a27a160eff`.
Its R segment has file offset 0, virtual address `0x200000` and length 288;
its RX segment has offset `0x1000`, virtual address `0x201000` and length 4096.
The original 31-byte text is unchanged; the rest of the RX segment is `0xcc`
padding. The two PT_LOADs project to distinct file pages. This artifact has no
PT_LOAD file-page alias; the earlier aliased artifact remains refused.

All seven preparation/reference commands passed, including reference exit 7.
Runtime construction then returned
`Control(Invalid("initial bootstrap final mapping differs"))` before any provider
call. The example retained the first `runtime_launch` failure, waited for the
actual cleanup receipt and exited 1. Its cleanup_complete field is true, and all
eight outer command cleanups completed with zero adoptees. False writer/archive/
artifact summary fields are unchecked early-return fields, not evidence that
those objects changed.

The [failed consumer receipt](results/20261026T222759.649412Z-runtime-consumer-871928eb99b2.json)
has SHA256 `18a24779bf5ca615be37b4c7cdbbbf6c7974d480e62922c88d11ff74caef061a`.
It authenticates the passing six-command prerequisite, all eight private captures,
exact tools and all four artifacts. The example ELF is 70,580,968 bytes, SHA256
`1882169b1fa4cd672ebfd4f5c5d987e8860357cd299e1b18735d341d11e83669`.
No consumer success, native callback or state/journal validation is credited.
The four new receipts were archived unchanged in
`ff2234b3bb5c52cabcb1bf34f894d3becfbc0b4f` before further source corrections.

Source inspection finds that the bootstrap comparator requires one unchanged
mapping row per original row, apart from clearing execute permission. The
artifact's file-contiguous, adjacent R/RX mappings suggest coalescing after
quarantine as a possible explanation. The failed run did not retain its actual
post-quarantine mapping rows, so this is a source hypothesis, not an established
historical cause. Supporting such topology changes requires a separately proved
mapping/source identity contract and actual native evidence; this report makes
no such claim.

These results add failure-custody evidence to claim 4 while retaining the finite
page-admission and selected-instruction controls relevant to claims 1 and 2.
They supply no in-place preemption clock or claim 3 evidence. General loader,
stack/memory, signals/threads, lifecycle composition, useful scale and admitted
application support remain open.
