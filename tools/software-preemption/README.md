# Finite software-preemption prototype

`liteinst-preempt` installs a real observing trampoline at the one near backward branch in each of four private, authored functions. The corpus is countdown/JNZ, signed/JG, unsigned/JB, and direct/JMP. Each function is call-free, has complete decoded entry heads, and uses no application stack storage beyond its ordinary call/return. Unsupported calls, indirect transfers, short backward encodings, and a missing or second backward site refuse before publication. This is a finite static corpus, not an arbitrary ELF instrumenter or complete progress guarantee.

The software clock counts **taken backward branch decisions BEFORE the branch executes**. It evaluates the original Jcc condition using saved RFLAGS; an unconditional backward JMP is always taken. Untaken conditional branches are encounters but consume no clock quantum. At a positive quantum boundary the actual callback sends `(logical site offset, taken-edge count, branch encounters, saved state)` to its controller and blocks until the controller returns the exact matching resume. The original branch executes only after that return. Neither a timeout nor ptrace triggers preemption, and no callback edits RIP/RSP or unwinds through generated code. Calls/indirect branches, multiple sites, external application concurrency, asynchronous cancellation, and mid-instruction stops are outside this increment.

The instance belongs to one worker's TLS and authenticates process/thread, exact managed control, and original logical PC. The enabled control has no remaining writer. Publication and retirement require the sole main thread and a lease over the complete original and generated dependencies; workers receive a callable address only after final RX permissions, byte checks and publication receipt. Every successful run joins its worker. No mapping becomes RWX. Failure retains executable/control owners until process exit; this is not a drain claim. The strict helper owns bounded abnormal-process cleanup. The callback's two-second wait is a failure backstop, not optional success or a scheduling threshold.

Qualification executes 512 independent native SETcc truth-table checks; 16 native and 16 counter-only cells; 96 stop/resume cells covering four input sizes, three quanta and two repeats. Every one of the 256 actual stops compares the whole 4 KiB result page and progress counter before and after a one-millisecond parked interval. All 48 paired stop sequences compare the exact ordered projection `(logical site offset, taken-edge count, branch encounters, [RAX, RCX, RDX], RFLAGS & 0x8d5)`. This repeated-run comparison omits other registers, RSP, instance addresses and the remaining flag bits; the separate comparison across each parked wait retains all 18 saved context words exactly. Results and whole-page canaries must match independent formulas and the native function. The callback compares its entire 18-word saved context across each wait. It uses the core's unchanged GPR/RFLAGS/extended-state-preserving trampoline, but this packet does **not** add an independent ptrace XSAVE/full-application-stack comparison for this new corpus. It cannot claim that distinct qualification.

Each release benchmark has native, counter-only, and stop/resume modes, two warmups and seven measured repetitions per mode. All run 128 calls of 256 iterations (32,768 work units); the stop quantum is 64, producing exactly 510 stops per stop/resume repetition. Timing encloses the actual work and all callback/controller scheduling overhead, excludes mapping/planning/thread creation, and contains no ptrace or deliberate parked delay. These are synchronous full-state callbacks, not a claimed minimal inline decrement. Raw CSV rows are authoritative; the caller adds per-mode medians/min/max. There is no performance threshold, success claim, or estimated speedup before execution.

## Build and run

Run from a clean committed checkout on Linux x86-64. `evaluate.py` builds the release binary, records the exact revision and source/tool/product owners, and runs the fixed qualification and four benchmarks. All detailed records go to a fresh directory under `ignored/`; the caller uses four available CPUs and four Cargo jobs. The recipe requires the existing offline Cargo dependencies. It never downloads or cleans the target directory.

```sh
python3 -B tools/software-preemption/evaluate.py \
  --repo "$PWD" --raw "$PWD/ignored/preemption-new" \
  --toolchain /absolute/rust-toolchain \
  --user-home /absolute/user-home --cargo-home /absolute/cargo-home
```

The release build inside that recipe is:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 \
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 CARGO_PROFILE_RELEASE_DEBUG=0 \
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
cargo build --locked --offline --release --bin liteinst-preempt
```

First run the two pure tests with `cargo test --bin liteinst-preempt`, then the strict qualification. The fixed caller subsequently runs all four benchmarks in declared order and stops on any failure, retaining all remaining rows UNRUN. The reproduction recipe constructs the binding from its actual successful build and current owners. Each of the five commands uses 60 CPU seconds, 90 wall seconds, 1 MiB per-file output, outer timeout 100 seconds/kill-after 10, direct-parent wait 115 seconds and failure cleanup 10. The unchanged bounded helper requires ECHILD and no unexpected descendants. Resource failures remain failures. The caller checks exact source/tool/product ownership before and after; its small free-filesystem check is not a managed-slot quota proof or a full dynamic-loader closure.

```sh
python3 -B tools/software-preemption/run.py \
  --binding ABSOLUTE_ROOT_REVIEWED_BINDING.json \
  --binding-sha256 EXACT_BINDING_SHA256 --raw NEW_ABSOLUTE_IGNORED_DIRECTORY
```

The build object joins the exact build command, actual waited closure and saved evidence files. The small caller does not parse Cargo logs or independently establish build provenance. Build/tool/source/runtime admission remains the root's task. Result sources and failed records must be preserved if later corrections are needed.

The first measured result is [the d07873a receipt](../../evaluation/software-preemption-d07873a/README.md). The convenient `evaluate.py` wrapper was added afterward and is source-reviewed, not executed in that historical run. Configuration snapshots may contain `READ_DENIED`; equality establishes continuity of those observations, not complete readable Cargo configuration closure. The tracked wrapper itself is included in the source snapshot.

## Explicit inline clock profile

The default commands and historical results above remain the full-callback profile. The separate `inline-clock-v1` profile has passed its finite native qualification and release measurements; see [the 2b18607 result](../../evaluation/software-preemption-2b18607/README.md). It accepts only the exact four authored function byte strings. Calls, general ELF discovery, multiple sites, artifact emission, frame metadata and asynchronous entry are unsupported.

Its generated gate counts encounters and taken decisions with MOV/LEA, tests the original branch condition, and decrements a positive remainder without changing flags or RSP. RCX is saved in a separate owned RW page and restored before the original branch or the unchanged full-save helper. Counter mode never calls the callback. Stop mode enters that helper only at zero; the callback authenticates the already-charged words, parks before the original branch, accepts the exact resume, then refills the quantum. It does not charge the edge twice.

The clock page is retained by the plan, image and executable owners. A non-Send worker lease and a per-invocation guard exclude private entry before the first spill. The unsafe mapping/run contracts also require the caller to exclude arbitrary external entry, recursive callbacks and signal-handler entry; a source address already known to an installer is not hidden by the type system. Controller reads of generated words occur only at the authenticated event/resume handoff or after worker join. Mapping retention on failure is not execution drainage.

Before the inline qualification and benchmarks, a mandatory gate command runs 28 sibling pairs (56 children): three conditional sites, both outcomes, remainders 1 and 2, two seeds; and the direct branch with those remainders and seeds. The candidate executes the real installed source transfer and gate. It stops at the original-body boundary or immediately before the slow helper saves any state. The existing register/architectural-XSAVE comparator is reused, with the entire 64 KiB seeded application stack compared exactly. Only the existing debugger TF/RF treatment and logical original-head RIP projection apply. These controls make no whole-stack-after-callback claim.

The separate inline qualification keeps all 96 stop cells, 16 native cells, 16 counter cells, 512 hardware SETcc checks, 256 parked checks and 48 repeated projected sequences. Inline timing keeps all 108 rows, equal work, two warmups, seven measurements and the exact 510-stop formula. The runner performs six fixed commands in order: gates, qualification, then four benchmarks. Every command keeps the old 60 CPU / 90 wall second / 1 MiB file limits and strict helper/parent closure. The extra clock data is exactly 4096 bytes per candidate instance; executable allocation remains 256 candidates, one mapping and at most 8192 bytes.

Root must first admit an actual successful build and its exact current owners using the distinct `ROOT_REVIEWED_INLINE_CLOCK_RELEASE_BINARY` authority and `profile: "inline-clock-v1"`. The legacy binding remains unchanged and cannot activate this profile. Then the explicitly selected runner is:

```sh
python3 -B tools/software-preemption/run.py --profile inline-clock-v1 \
  --binding ABSOLUTE_ROOT_REVIEWED_INLINE_BINDING.json \
  --binding-sha256 EXACT_BINDING_SHA256 --raw NEW_ABSOLUTE_IGNORED_DIRECTORY
```

The convenience `evaluate.py` wrapper defaults to the legacy profile; its explicit inline selection is described below. The result receipt records the exact admitted release build, gate qualification, and timing rows. The core also has eight pure tests and three compile-fail ownership examples.

### One-command inline reproduction

After integrating this profile and its evaluator, use the same fresh release-build admission with an explicit selection:

```sh
python3 -B tools/software-preemption/evaluate.py --profile inline-clock-v1 \
  --repo "$PWD" --raw "$PWD/ignored/preemption-inline-new" \
  --toolchain /absolute/rust-toolchain \
  --user-home /absolute/user-home --cargo-home /absolute/cargo-home
```

The default `--profile full-callback-v1` retains the existing five-command invocation and binding without an added profile field. Inline selection constructs the distinct inline authority plus exact profile field and passes `--profile inline-clock-v1` to `run.py`. Both use the same actual successful release build, whole source/tool/configuration continuity and exact binary owner; selecting a profile supplies no historical result or independent runtime admission.

The build retains 120 CPU / 180 wall seconds / 128 MiB per file, outer 190 seconds / kill-after 10 and direct-parent 205 seconds. Every experimental command retains 60 CPU / 90 wall seconds / 1 MiB, outer 100 / kill-after 10, parent 115 / failure cleanup 10, and four-CPU affinity. Only the whole-experiment parent differs: legacy 650 seconds = five × 115 + 75; inline 765 seconds = six × 115 + the same 75-second caller allowance. A per-command failure is still failed, remaining commands stay UNRUN, and this outer allowance does not widen any measurement or oracle limit. The result receipt records the fresh evaluator invocation separately from the earlier failed fixture attempt; the failed attempt supplied no qualification or benchmark credit.

### Owned-loop client

`BackedgeClockAction::new_owned_loop` admits a copied, call-free integer region
of at most 256 bytes with one supported near backedge. The
[example](../../examples/owned_loop_clock.rs) binds managed control and owned
clock storage, supplies complete entry facts, publishes before spawning, then
uses an exclusive worker lease and matching stop/resume messages.

On Linux x86-64, run `cargo run --example owned_loop_clock` without arguments.
The fixed 64-byte XOR (`0x5a`) and sum checks produce checksum 8352, stops
16/32/48, 63 taken edges, 64 encounters and three parked-buffer checks; join
precedes Arc allocation release.

Clients still own ABI, memory, entry exclusion and work bounds. Code remains
process-lived. This adds no performance, full-XSAVE/whole-stack,
arbitrary-ELF/general-ABI, asynchronous-cancellation or retirement claim.
The four-literal profile and evidence remain unchanged.
