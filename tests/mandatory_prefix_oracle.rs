#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Prospective required mandatory-prefix positives, never decoder-only coverage.
//! Literal instructions, heads, displacement words and tactic budgets are fixed
//! before execution. The shared native state and fault comparators are unchanged.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, LegalEntry,
    LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, PlannedInstall, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::{HookCallback, HookContext};
use oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, TraceMap};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const PROBE_ID: u64 = 0xe301;
const CHILD: &str = "LITEINST_MANDATORY_PREFIX_CHILD";
const MOVES: [(&str, [u8; 4]); 5] = [
    ("MOVSS xmm0,xmm1", [0xf3, 0x0f, 0x10, 0xc1]),
    ("MOVSD xmm0,xmm1", [0xf2, 0x0f, 0x10, 0xc1]),
    ("MOVDQA xmm0,xmm1", [0x66, 0x0f, 0x6f, 0xc1]),
    ("MOVDQU xmm0,[rdi]", [0xf3, 0x0f, 0x6f, 0x07]),
    ("MOVDQU [rdi],xmm0", [0xf3, 0x0f, 0x7f, 0x07]),
];
const SUCCESSOR: [u8; 6] = [0xb8, 0x31, 0x42, 0x53, 0x64, 0xc3];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tactic {
    B1,
    B2,
    T1(usize),
}
const TACTICS: [Tactic; 5] = [
    Tactic::B1,
    Tactic::B2,
    Tactic::T1(1),
    Tactic::T1(2),
    Tactic::T1(3),
];

impl Tactic {
    fn prefixes(self) -> usize {
        match self {
            Self::B1 | Self::B2 => 0,
            Self::T1(count) => count,
        }
    }

    fn target(self, selected: u64) -> u64 {
        let (next, displacement) = match self {
            Self::B1 => (5, 0x6000_0000_i64),
            Self::B2 => (5, i64::from(0xb800_0000_u32 as i32) + 0x8000),
            Self::T1(1) => (6, 0x31b8_0000 + 0x8000),
            Self::T1(2) => (7, 0x4231_b800 + 0x80),
            Self::T1(3) => (8, 0x5342_31b8),
            Self::T1(_) => unreachable!(),
        };
        u64::try_from(i128::from(selected) + next + i128::from(displacement)).unwrap()
    }
}

unsafe fn clobber_state() {
    // SAFETY: caller-saved state only. No application memory is accessed. The
    // emitter must restore the independently seeded flags, GPRs, x87 and XMMs.
    unsafe {
        core::arch::asm!(
            "add rax, 1",
            "xor ecx, ecx",
            "mov edx, 0x76543210",
            "mov r11d, 0x12345678",
            "pxor xmm0, xmm0",
            "pcmpeqd xmm1, xmm1",
            "pxor xmm15, xmm15",
            "fninit",
            out("rax") _, out("rcx") _, out("rdx") _, out("r11") _,
            out("xmm0") _, out("xmm1") _, out("xmm15") _,
            options(nostack),
        );
    }
}

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the emitter supplies a live frame; assert_trace owns the log.
    unsafe {
        oracle::record_hook_event(PROBE_ID, (*context).instruction_pointer);
        clobber_state();
    }
}

unsafe extern "C" fn fault_observer(_context: *mut HookContext) {
    // The old strict fault API has no event-log argument. Fault comparisons
    // authenticate architectural state, without claiming extra logged events.
    unsafe { clobber_state() };
}

fn permissions(pointer: *mut u8, flags: i32) -> Result<(), Refusal> {
    // SAFETY: the fixture retains this complete source page under its lease.
    if unsafe { libc::mprotect(pointer.cast(), 4096, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn pun_window(selected: u64, prefixes: usize) -> AddressRange {
    let frozen = [0xb800_0000_u32, 0x31b8_0000, 0x4231_b800, 0x5342_31b8][prefixes];
    let low =
        u64::try_from(i128::from(selected) + (5 + prefixes) as i128 + i128::from(frozen as i32))
            .unwrap();
    AddressRange::new(low, 1_usize << (8 * (3 - prefixes))).unwrap()
}

fn prepare(
    native: &NativeOracle,
    bytes: &[u8],
    selected_offset: usize,
    tactic: Tactic,
    index: usize,
    hook: HookCallback,
) -> PlannedInstall {
    let base = native.code.address();
    let selected = base + selected_offset as u64;
    let source = AddressRange::new(base, bytes.len()).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0x80 + index as u8; 32]),
        mapping: base,
        generation: 1,
    };
    let mut heads = vec![selected, selected + 4, selected + 9];
    if selected_offset != 0 {
        assert_eq!(selected_offset, 5);
        assert_eq!(&bytes[..5], &[0xbf, 0, 0, 0, 0]); // MOV EDI,0; preserves flags.
        heads.insert(0, base);
    }
    assert_eq!(&bytes[selected_offset + 4..], &SUCCESSOR);
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared("literal mandatory-prefix and MOV/RET heads".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: heads
            .iter()
            .map(|&address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    };
    let target = tactic.target(selected);
    let permitted = AddressRange::new(target & !4095, 4096).unwrap();
    for prefixes in 0..4 {
        let window = pun_window(selected, prefixes);
        if tactic != Tactic::B1 && prefixes == tactic.prefixes() {
            assert!(window.contains(target));
        } else {
            assert!(
                !permitted.overlaps(window),
                "exact page permits an unintended pun window"
            );
        }
    }
    let allocation = AllocationPolicy {
        ranges: vec![permitted],
        preferred_address: Some(target),
        // B1's constrained byte generator tries 0x60 at zero-based slot 11.
        // The exact page rejects slots 0..10. Pun preference needs one slot.
        max_candidates: if tactic == Tactic::B1 { 12 } else { 1 },
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let mut invalid = entries.clone();
    invalid.entries.push(LegalEntry {
        address: selected + 1,
        requires_endbr: false,
    });
    let mut request = InstallRequest {
        identity,
        code: bytes,
        base_address: base,
        function: source,
        block: source,
        logical_pc: selected,
        entries: &entries,
        hook,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: SearchPolicy {
            tactics: match tactic {
                Tactic::B1 => TacticPolicy::RelocationOnly,
                Tactic::B2 => TacticPolicy::GeneralizedPunOnly,
                Tactic::T1(_) => TacticPolicy::PrefixPunOnly,
            },
            max_upstream_bytes: 0,
            max_displaced_bytes: if tactic == Tactic::B1 { 9 } else { 4 },
            max_sites: 1,
        },
    };
    if selected_offset == 0 {
        request.entries = &invalid;
        assert_eq!(
            plan_install(&request).unwrap_err(),
            Refusal::NotInstructionHead
        );
        native.assert_publication(&[]);
        request.entries = &entries;
    }
    let prepared = plan_install(&request).unwrap_or_else(|error| {
        panic!("required mandatory-prefix case {index} {tactic:?} refused: {error:?}")
    });
    let parts = prepared.plan().parts();
    let image = prepared.image();
    assert_eq!(parts.identity, identity);
    assert_eq!(parts.physical_pc, selected);
    assert_eq!(parts.logical_pc, selected);
    assert_eq!(image.address(), target);
    assert_eq!(parts.allocations.len(), 1);
    assert_eq!(parts.allocations[0].range, permitted);
    assert_eq!(parts.allocations[0].alignment, 4096);
    assert!(permitted.covers(AddressRange::new(target, image.bytes().len()).unwrap()));
    assert_eq!(parts.generated.len(), 1);
    assert_eq!(parts.generated[0].address, target);
    assert_eq!(parts.generated[0].bytes, image.bytes());
    assert_eq!(
        parts.generated[0].program_counters,
        image.program_counter_mappings()
    );
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.writes[0].address, selected);
    assert_eq!(prepared.metrics().upstream_bytes, 0);
    assert_eq!(prepared.metrics().prefix_instructions, 0);
    assert_eq!(
        prepared.metrics().allocation_attempts,
        allocation.max_candidates
    );
    let displacement =
        i32::try_from(i128::from(target) - i128::from(selected) - (5 + tactic.prefixes()) as i128)
            .unwrap()
            .to_le_bytes();
    let expected_heads = if tactic == Tactic::B1 {
        vec![selected, selected + 4]
    } else {
        vec![selected]
    };
    assert_eq!(
        image
            .instruction_boundaries()
            .iter()
            .map(|&(pc, _)| pc)
            .collect::<Vec<_>>(),
        expected_heads
    );
    assert_eq!(
        image
            .entry_routes()
            .iter()
            .map(|&(pc, _)| pc)
            .collect::<Vec<_>>(),
        expected_heads
    );
    assert_eq!(image.entry_routes()[0], (selected, target));
    let routed: Vec<_> = parts
        .obligations
        .iter()
        .filter_map(|entry| match entry {
            EntryObligation::Routed(route) => Some(*route),
            EntryObligation::Preserved(_) => None,
            EntryObligation::Unresolved { .. } => {
                panic!("successful plan retained an unresolved entry")
            }
        })
        .collect();
    match (&parts.kind, tactic) {
        (PlanKind::Relocation, Tactic::B1) => {
            assert_eq!(parts.displaced, AddressRange::new(selected, 9).unwrap());
            assert_eq!(displacement, [0, 0, 0, 0x60]);
            assert_eq!(
                parts.writes[0].bytes,
                [0xe9, 0, 0, 0, 0x60, 0x31, 0x42, 0x53, 0x64]
            );
            assert_eq!(routed.len(), 1);
            assert_eq!(routed[0].original, selected + 4);
            assert_eq!(
                (routed[0].original, routed[0].generated),
                image.entry_routes()[1]
            );
            assert!(parts.requirements.sigill_router);
        }
        (PlanKind::GeneralizedPun(pun), Tactic::B2) => {
            assert_eq!(pun.instruction_len, 4);
            assert_eq!(pun.consumed, AddressRange::new(selected, 5).unwrap());
            assert_eq!(pun.target_window, pun_window(selected, 0));
            assert_eq!(pun.store, parts.writes[0]);
        }
        (PlanKind::PrefixedPun(pun), Tactic::T1(prefixes)) => {
            assert_eq!(pun.instruction_len, 4);
            assert_eq!(pun.prefix_count as usize, prefixes);
            assert_eq!(
                pun.consumed,
                AddressRange::new(selected, 5 + prefixes).unwrap()
            );
            assert_eq!(pun.target_window, pun_window(selected, prefixes));
            assert_eq!(pun.store, parts.writes[0]);
        }
        (kind, _) => panic!("required {tactic:?} became {kind:?}"),
    }
    if tactic != Tactic::B1 {
        let prefixes = tactic.prefixes();
        assert_eq!(parts.displaced, AddressRange::new(selected, 4).unwrap());
        assert!(routed.is_empty());
        assert!(!parts.requirements.sigill_router);
        let mut exact = vec![0x2e; prefixes];
        exact.push(0xe9);
        exact.extend_from_slice(&displacement[..3 - prefixes]);
        assert_eq!(parts.writes[0].bytes, exact);
        let mut fetch = bytes[selected_offset..selected_offset + 5 + prefixes].to_vec();
        fetch[..4].copy_from_slice(&exact);
        assert_eq!(
            &fetch[4..],
            &bytes[selected_offset + 4..selected_offset + 5 + prefixes]
        );
        assert_eq!(&fetch[prefixes + 1..], &displacement);
    }
    prepared
}

fn assert_image(prepared: &PlannedInstall) {
    let image = prepared.image();
    // SAFETY: called only after publication; permanent RX mappings outlive both
    // retirement and this exact byte check. No trace child or writer is active.
    let actual = unsafe {
        std::slice::from_raw_parts(image.address() as usize as *const u8, image.bytes().len())
    };
    assert_eq!(actual, image.bytes(), "generated image bytes changed");
}

fn publish(
    native: &mut NativeOracle,
    prepared: &PlannedInstall,
) -> liteinst2::quiescent::InstalledOnce {
    let parts = prepared.plan().parts();
    let writable = native.code.writable();
    let result = {
        // SAFETY: all original children have been reaped; this owner excludes
        // executors, aliases and saved continuations while publishing.
        let mut lease =
            unsafe { QuiescenceLease::new(native, parts.identity, parts.dependencies.clone()) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        let result = unsafe {
            prepared.publish_with(writable, &mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required publication failed");
        assert!(!lease.is_poisoned());
        result
    };
    assert_eq!(result.1.plan(), prepared.plan());
    native.assert_publication(
        &parts
            .writes
            .iter()
            .map(|edit| (edit.address, edit.bytes.clone()))
            .collect::<Vec<_>>(),
    );
    assert_image(prepared);
    result.0
}

fn retire(
    native: &mut NativeOracle,
    prepared: &PlannedInstall,
    installed: &mut liteinst2::quiescent::InstalledOnce,
) {
    let parts = prepared.plan().parts();
    let mut ranges = parts.dependencies.clone();
    ranges.extend(parts.allocations.iter().map(|allocation| allocation.range));
    let writable = native.code.writable();
    {
        // SAFETY: all installed children, including fault stops, are reaped;
        // source, generated ranges and saved continuations are drained.
        let mut lease = unsafe { QuiescenceLease::new(native, parts.identity, ranges) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required retirement failed");
        assert!(!lease.is_poisoned());
    }
    assert!(installed.is_retired());
    native.assert_publication(&[]);
    assert_image(prepared);
}

fn normal_cycles() {
    let mut retained = Vec::new();
    let mut counts = [0_usize; 6]; // original, refused-preserved, installed, retired, events, routes
    for (move_index, (name, instruction)) in MOVES.iter().enumerate() {
        for (tactic_index, &tactic) in TACTICS.iter().enumerate() {
            let index = move_index * TACTICS.len() + tactic_index;
            let bytes: Vec<_> = instruction.iter().chain(&SUCCESSOR).copied().collect();
            let mut native = NativeOracle::new(&bytes);
            let base = native.code.address();
            let heads = [base, base + 4, base + 9];
            let mut originals = Vec::new();
            for seed in SEEDS {
                for (entry_index, &entry) in heads.iter().enumerate() {
                    let trace = native.trace_original(entry, &heads, &[native.return_pc()], seed);
                    assert_eq!(
                        trace.visits(),
                        heads[entry_index..]
                            .iter()
                            .copied()
                            .chain([native.return_pc()])
                            .collect::<Vec<_>>()
                    );
                    originals.push((entry, trace));
                    counts[0] += 1;
                }
            }
            let prepared = prepare(&native, &bytes, 0, tactic, index, observe);
            let original_map = TraceMap {
                boundaries: heads
                    .iter()
                    .copied()
                    .chain([native.return_pc()])
                    .map(|pc| (pc, pc))
                    .collect(),
                ..TraceMap::default()
            };
            let log = HookEventLog::new();
            for (entry, trace) in &originals {
                native.assert_trace(
                    trace,
                    *entry,
                    &original_map,
                    &[],
                    Some(HookExpectation {
                        log: &log,
                        enabled: &[],
                    }),
                );
                counts[1] += 1;
            }
            let displaced = prepared.plan().parts().displaced;
            let mut boundaries = prepared.image().instruction_boundaries().to_vec();
            boundaries.extend(
                heads
                    .iter()
                    .filter(|&&pc| !displaced.contains(pc))
                    .map(|&pc| (pc, pc)),
            );
            boundaries.push((native.return_pc(), native.return_pc()));
            let owned = if tactic == Tactic::B1 {
                vec![base + 4]
            } else {
                vec![]
            };
            let map = TraceMap {
                boundaries,
                gateways: std::iter::once(base).chain(owned.iter().copied()).collect(),
                generated_ranges: std::iter::once(
                    prepared.image().address()
                        ..prepared.image().address() + prepared.image().bytes().len() as u64,
                )
                .collect(),
            };
            let mut installed = publish(&mut native, &prepared);
            // SAFETY: the oracle owns this readable ten-byte source throughout
            // the synchronous publication and assertion; no child is running.
            let source_bytes = unsafe { core::slice::from_raw_parts(native.code.writable(), 10) };
            if tactic != Tactic::B1 {
                assert_eq!(&source_bytes[4..10], &SUCCESSOR);
            } else {
                assert_eq!(&source_bytes[5..10], &SUCCESSOR[1..]);
            }
            let enabled = [HookEvent {
                probe_id: PROBE_ID,
                logical_pc: base,
            }];
            for (entry, trace) in &originals {
                native.assert_trace(
                    trace,
                    *entry,
                    &map,
                    &owned,
                    Some(HookExpectation {
                        log: &log,
                        enabled: &enabled,
                    }),
                );
                counts[2] += 1;
                counts[4] += trace.visits().iter().filter(|&&pc| pc == base).count();
                counts[5] += usize::from(owned.contains(entry));
            }
            // Handler counts are fork-private; configured route coverage comes
            // from the exact obligations and required native entry calls above.
            assert_eq!(installed.routed_entries(), 0);
            assert_image(&prepared);
            retire(&mut native, &prepared, &mut installed);
            for (entry, trace) in &originals {
                native.assert_trace(
                    trace,
                    *entry,
                    &original_map,
                    &[],
                    Some(HookExpectation {
                        log: &log,
                        enabled: &[],
                    }),
                );
                counts[3] += 1;
            }
            println!(
                "mandatory_prefix normal={name:?} tactic={tactic:?} original=6 refused_preserved=6 installed=6 retired=6 events=2"
            );
            // Retired generated mappings are permanent. Pin all 25 distinct
            // sources so later cycles cannot reuse their dictated image pages.
            retained.push(native);
        }
    }
    assert_eq!(retained.len(), 25);
    assert_eq!(counts, [150, 150, 150, 150, 50, 10]);
    println!(
        "mandatory_prefix normal_cycles=25 midpoint_refusals=25 original=150 refused_preserved=150 installed=150 retired=150 events=50 executed_B1_route_entries=10"
    );
}

fn fault_cycles() {
    let mut retained = Vec::new();
    let mut counts = [0_usize; 3];
    for (move_index, (name, instruction)) in MOVES[3..].iter().enumerate() {
        for (tactic_index, &tactic) in TACTICS.iter().enumerate() {
            let index = 25 + move_index * TACTICS.len() + tactic_index;
            let mut bytes = vec![0xbf, 0, 0, 0, 0]; // MOV EDI,0; defined flags unchanged.
            bytes.extend_from_slice(instruction);
            bytes.extend_from_slice(&SUCCESSOR);
            let mut native = NativeOracle::new(&bytes);
            let base = native.code.address();
            let original_heads = [base, base + 5];
            let originals: Vec<_> = SEEDS
                .iter()
                .map(|&seed| {
                    counts[0] += 1;
                    native.original_fault(&original_heads, seed, (libc::SIGSEGV, 1, 0))
                })
                .collect();
            let prepared = prepare(&native, &bytes, 5, tactic, index, fault_observer);
            let mut installed = publish(&mut native, &prepared);
            for original in &originals {
                native.assert_patched(
                    original,
                    base,
                    prepared.image().instruction_boundaries(),
                    &[],
                );
                counts[1] += 1;
            }
            assert_image(&prepared);
            retire(&mut native, &prepared, &mut installed);
            for original in &originals {
                native.assert_patched(original, base, &[], &[]);
                counts[2] += 1;
            }
            println!(
                "mandatory_prefix fault={name:?} tactic={tactic:?} original=2 installed=2 retired=2 signal=SIGSEGV code=SEGV_MAPERR address=0"
            );
            retained.push(native);
        }
    }
    assert_eq!(retained.len(), 10);
    assert_eq!(counts, [20, 20, 20]);
    println!(
        "mandatory_prefix fault_cycles=10 original=20 installed=20 retired=20 authenticated_fault_hook_events=not_measured"
    );
}

fn bounded(test: &str, mode: &str, cpu_seconds: libc::rlim_t, wall_seconds: u64) {
    if let Ok(actual) = std::env::var(CHILD) {
        assert_eq!(actual, mode);
        match mode {
            "normal" => normal_cycles(),
            "fault" => fault_cycles(),
            _ => unreachable!(),
        }
        return;
    }
    let directory = std::env::temp_dir().join(format!(
        "liteinst-mandatory-prefix-{}-{mode}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let output = |name| std::fs::File::create(directory.join(name)).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, mode)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(output("stdout"))
        .stderr(output("stderr"));
    // SAFETY: the child uses only async-signal-safe setrlimit before exec.
    unsafe {
        command.pre_exec(move || {
            for (resource, value) in [
                (libc::RLIMIT_CPU, cpu_seconds),
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_FSIZE, 256 * 1024),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(wall_seconds) {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
            panic!(
                "mandatory-prefix {mode} exceeded frozen {wall_seconds}s wall budget; evidence {}",
                directory.display()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = std::fs::read_to_string(directory.join("stdout")).unwrap();
    let stderr = std::fs::read_to_string(directory.join("stderr")).unwrap();
    assert!(
        status.success(),
        "mandatory-prefix {mode} failed: {status}; evidence {}\n{stdout}\n{stderr}",
        directory.display()
    );
    print!("{stdout}");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn all_five_mandatory_prefix_forms_execute_all_five_tactics() {
    bounded(
        "all_five_mandatory_prefix_forms_execute_all_five_tactics",
        "normal",
        60,
        90,
    );
}

#[test]
fn both_movdqu_memory_directions_preserve_exact_null_faults() {
    bounded(
        "both_movdqu_memory_directions_preserve_exact_null_faults",
        "fault",
        20,
        30,
    );
}
