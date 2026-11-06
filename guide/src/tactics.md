# The patching tactics

"Patch this site" is not one operation. Depending on what you can prove
about the program at publication time, LiteInst offers four tactic
families. Choosing among them is the main API decision a client makes,
and the repository's
[patch-site decision tree](https://github.com/rrnewton/liteinst2/blob/main/PATCH_SITE_DECISION_TREE.md)
states the choice exhaustively. This chapter introduces each family
and when to reach for it.

## Quiescent publication

If you can exclude every other thread, signal handler, instruction
fetch, and code writer for the duration of the call, use the quiescent
entrypoints. They prefer generalized short-instruction puns —
install-once, no guarded splits — under a held `QuiescenceLease`.
Publication still prepares Linux sync-core and reserves trap routing
internally; "quiescent" removes the *concurrency* proof burden, not
all machinery. This is the right default at launch time, under a
stopped-task controller, or in a single-threaded preload constructor.

Planning is safe (`plan_install`); the *publication* entrypoints are
`unsafe`: the exclusion is your proof to uphold, and the lease type
exists to make that proof explicit and scoped. They must not be used
as a faster default for threaded applications.

## Concurrent publication (WordPatch++)

If the program keeps running while you patch, use the ordinary
`LiveJumpPatch` / `InstalledHook` entrypoints. Publication is
concurrent-safe: single-store puns where geometry allows, WordPatch++
guards across cache-line splits, and a process SIGTRAP router that the
library owns for the duration. Requirements that surprise people:

* Installation refuses a pre-existing custom SIGTRAP handler (prior
  `SIG_DFL`/`SIG_IGN` only), unless the host supplies exact
  installation/redelivery callbacks through
  `prepare_live_patching_with_signal_runtime`.
* Split sites need a machine/topology-qualified `StalenessBudget`.
  Without one, route the site to your trap fallback.
* Neighbouring sites may share the unchanged tail of their 8-byte
  stores when their displaced intervals are disjoint; overlapping
  writers fail with `Contended` rather than racing.

## Rapid toggles

Some probes must turn on and off millions of times (profilers,
sampling instrumentation). Re-planning a five-byte patch per toggle is
far too slow. The **rapid** family plans an exact one-byte pun once —
the original bytes must encode a free trampoline destination — and then
toggles with a single atomic opcode-byte store. Measured toggle costs
are in [Performance](performance.md).

Rapid puns are also the least general tactic: when the exact pun does
not exist, the planner says so and you pick another family. There is no
approximate rapid mode.

## Synchronized (sync-core) publication

The experimental `patcher::synchronized` API publishes words and
batches behind sync-core barriers. Note precisely what changes:
split members still publish `0xCC` front-fragment guards
(`GuardsPublished` phase) — the barriers replace the *staleness
waits*, not the guards. Its
supported geometry, caller obligations, and terminal-failure behaviour
are narrower than WordPatch++'s; treat it as a specialist tool and read
its contract before use.

## Choosing

| Situation | Tactic |
|---|---|
| All fetchers/writers excluded (launch, stopped task, single thread) | Quiescent |
| Live multithreaded program, install-once or rare changes | Concurrent (WordPatch++) |
| Same site toggled at very high frequency | Rapid (`RapidProbe::install` is standalone; no prior general install needed) |
| Batched split-site publication without caller staleness budgets | Synchronized (experimental; front guards still published — barriers replace the waits) |
| No tactic's preconditions hold | **Trap fallback** (`PunPlan::TrapRequired`) — your controller (e.g. ptrace) handles the site |

The last row is load-bearing: refusing to patch and trapping instead is
a supported, expected outcome, not an error path to hide. Clients that
keep a ptrace slow path follow the decision tree site by site.

## The four families in code

Each listing below is excerpted from a source CI already compiles —
an example or the tactic's own tests — so the shapes cannot drift
from the APIs they teach.

**Quiescent** (`examples/owned_loop_clock.rs`): plan first, then
publish inside a `QuiescenceLease` whose constructor is the caller's
exclusion proof. The callback performs the caller's half of the
hand-off (here, flipping the page to RX) *inside* the lease:

```rust,ignore
        let (installed, receipt) = {
            // SAFETY: sole thread, exact private source/image owners and no
            // invocation/resume. The only callable pointers are made later.
            let mut lease = unsafe { QuiescenceLease::new(&mut candidate, identity, ranges) };
            let result = unsafe {
                planned.publish_with(base as usize as *mut u8, &mut lease, || {
                    if libc::mprotect(
                        base as usize as *mut libc::c_void,
                        4096,
                        libc::PROT_READ | libc::PROT_EXEC,
                    ) != 0
                    {
                        return Err(Refusal::Backend(
                            std::io::Error::last_os_error().to_string(),
                        ));
                    }
                    Ok(())
                })
            }
            .expect("publication must succeed before entry");
            assert!(!lease.is_poisoned());
            result
        };
```

**Concurrent** (`examples/replace_first.rs`): the ordinary
`InstalledHook` entrypoints need no lease and no stopped world —
install once, then activate/deactivate while other threads fetch:

```rust,ignore
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&code, address)?;
    let arena = TrampolineArena::allocate_near(address, 1)?;
    // SAFETY: both aliases and the arena remain live through every function call.
    let hook = unsafe {
        InstalledHook::install_replacing_first_in_arena(
            HookSite::new(&scanner, &scan, &code, address, address, writable.cast()),
            replace_zero,
            StalenessBudget::new(3_000).unwrap(),
            &arena,
        )?
    };
    // SAFETY: code is an extern C function returning u32.
    let function: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(executable) };

    assert_eq!(unsafe { function() }, 1);
    hook.activate()?;
    assert_eq!(unsafe { function() }, 41);
    hook.deactivate()?;
    assert_eq!(unsafe { function() }, 1);
    println!("inactive=1 active=41 restored=1");
```

**Rapid** (`src/rapid.rs` tests): the one-byte pun only exists
because the original instruction *is* the jump encoding with its
opcode byte changed — here `mov eax, <disp32>` whose immediate is
chosen as the displacement to a reserved trampoline page. Planning
proves that exactness or refuses; toggling is then one atomic
opcode store, which the benchmark times in a plain loop:

```rust,ignore
        fn plan_fixture(mapping: &DualMapping) -> (RapidTogglePlan, Placeholder, Vec<u8>, u32) {
            let execute_address = mapping.executable_address(SITE_OFFSET);
            let placeholder = Placeholder::reserve_near(execute_address + 5);
            let target_address = placeholder.address + TARGET_OFFSET;
            let displacement =
                i32::try_from(target_address as i128 - i128::from(execute_address + 5)).unwrap();
            let mut code = vec![0xB8];
            code.extend_from_slice(&displacement.to_le_bytes());
            code.extend_from_slice(&[0xC3, 0x90, 0x90]);
            mapping.write(SITE_OFFSET, &code);
            let scanner = InstructionScanner::default();
            let scan = scanner.scan(&code, execute_address).unwrap();
            let plan = RapidTogglePlan::from_scan(
                &scanner,
                &scan,
                &code,
                execute_address,
                execute_address,
                record_hook,
            )
            .unwrap();
            assert_eq!(plan.target_address(), target_address as u64);
            (plan, placeholder, code, displacement as u32)
        }

```

```rust,ignore
        fn benchmark_single_byte_toggle_latency() {
            let _guard = serial_guard();
            let mapping = DualMapping::new();
            let (probe, _code, _expected) = install_fixture(&mapping);
            for _ in 0..100_000 {
                probe.enable();
                probe.disable();
            }

            let iterations = 10_000_000_u64;
            let start = Instant::now();
            for _ in 0..iterations {
                probe.enable();
                probe.disable();
            }
            let elapsed = start.elapsed();
            let nanos_per_toggle = elapsed.as_nanos() as f64 / (iterations * 2) as f64;
            eprintln!(
                "rapid toggle: {nanos_per_toggle:.3} ns/store over {} stores",
                iterations * 2
            );
            assert!(
```

**Synchronized** (`src/patcher/synchronized.rs`): bind each
`SyncJumpPatch` first (its contract is the long safety list on
`SyncJumpPatch::bind`), then prepare the batch and advance it one
phase at a time. Three process-wide barriers total, however many
members the batch has; every failure is terminal for the handle and
retains writer ownership:

```rust,ignore
// SAFETY: every bind/prepare contract holds for both members.
let mut batch = unsafe {
    SynchronizedBatch::prepare(&[&patch_a, &patch_b], Direction::Apply)
}?;
loop {
    // SAFETY: same contracts, still true at each phase boundary.
    let receipt = unsafe { batch.advance() }?;
    // GuardsPublished -> GuardsSynchronized -> BacksPublished ->
    // BacksSynchronized -> FrontsPublished -> Complete
    if receipt.phase == Phase::Complete {
        break;
    }
}
```
