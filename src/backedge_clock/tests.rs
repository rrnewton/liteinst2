use super::*;
use crate::controls::ControlIdentity;
use crate::scanner::InstructionScanner;
use crate::trampoline::{HookContext, TrampolinePlan};
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, Register};

fn clock() -> BackedgeClock {
    let p = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            CLOCK_PAGE_BYTES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED);
    unsafe { BackedgeClock::from_owned_mapping(p as usize as u64, CLOCK_PAGE_BYTES) }.unwrap()
}
unsafe extern "C" fn callback(_: *mut HookContext, _: ControlIdentity<'_>) {}

// Independently assemble the old four authored functions, including the actual
// signed displacement. These controls fail if a literal core whitelist drifts.
fn source(kind: usize) -> (Vec<u8>, usize) {
    let mut b = vec![0x31, 0xc0, 0x31, 0xd2];
    if kind == 2 {
        b.extend([0x31, 0xc9]);
    } else {
        b.extend([0x48, 0x89, 0xf9]);
    }
    let target = b.len();
    if kind == 2 {
        b.extend([0x48, 0x83, 0xc0, 3]);
    } else {
        b.extend([0x48, 1, 0xc8]);
    }
    b.extend([0x48, 0xff, 0xc2]);
    b.extend([0x48, 0xff, if kind == 2 { 0xc1 } else { 0xc9 }]);
    b.extend([0x48, 0x89, 6, 0x48, 0x89, 0x4e, 8, 0x48, 0x89, 0x56, 0x10]);
    if kind == 2 {
        b.extend([0x48, 0x39, 0xf9]);
    }
    if kind == 3 {
        b.extend([0x74, 5]);
    }
    let offset = b.len();
    if kind == 3 {
        b.push(0xe9);
    } else {
        b.extend([0x0f, [0x85, 0x8f, 0x82][kind]]);
    }
    let displacement = i32::try_from(target as i64 - (b.len() + 4) as i64).unwrap();
    b.extend(displacement.to_le_bytes());
    b.push(0xc3);
    (b, offset)
}
fn action(kind: usize, mode: ClockMode, page: &BackedgeClock) -> BackedgeClockAction {
    let (bytes, offset) = source(kind);
    let base = page.address() + 0x10000;
    let identity = CodeIdentity {
        source: crate::contracts::SourceIdentity([kind as u8; 32]),
        mapping: base,
        generation: 1,
    };
    BackedgeClockAction::new(
        identity,
        base,
        &bytes,
        base + offset as u64,
        ProbeControl::new_managed_bound(callback, true),
        page.clone(),
        mode,
    )
    .unwrap()
}
fn plan(action: &BackedgeClockAction) -> TrampolinePlan {
    let scan = InstructionScanner::default()
        .scan(&action.source, action.base)
        .unwrap();
    TrampolinePlan::from_backedge_clock(
        &scan,
        action.logical_pc,
        action.logical_pc + if action.condition.is_some() { 6 } else { 5 },
        action,
    )
    .unwrap()
}

#[test]
fn inline_clock_owns_exact_geometry_and_canaries() {
    assert_eq!(core::mem::size_of::<ClockWords>(), 32);
    for (address, len) in [(0, 4096), (1, 4096), (4097, 4096), (4096, 0), (4096, 8192)] {
        assert_eq!(
            unsafe { BackedgeClock::from_owned_mapping(address, len) }.unwrap_err(),
            ClockError::Mapping
        );
    }
    let page = clock();
    let (words, tail) = unsafe { page.snapshot_parked() };
    assert_eq!(words, ClockWords::default());
    assert_eq!(tail, [CLOCK_CANARY; 4064]);
}

#[test]
fn inline_clock_duplicate_reentrant_and_wrong_process_leases_refuse() {
    let mut page = clock();
    for (quantum, work) in [(0, 1), (1, 0), (1, MAX_WORK + 1)] {
        assert!(matches!(
            unsafe { page.acquire(quantum, work) },
            Err(ClockError::Invocation)
        ));
    }
    let lease = unsafe { page.acquire(7, MAX_WORK) }.unwrap();
    assert!(matches!(
        unsafe { page.acquire(7, MAX_WORK) },
        Err(ClockError::Owner)
    ));
    let call = lease.begin_call().unwrap();
    assert!(matches!(lease.begin_call(), Err(ClockError::Invocation)));
    drop(call);
    drop(lease.begin_call().unwrap());
    drop(lease);
    let next = unsafe { page.acquire(3, 4) }.unwrap();
    assert_eq!(
        unsafe { page.snapshot_parked() }.0,
        ClockWords {
            remaining: 3,
            ..ClockWords::default()
        }
    );
    drop(next);
    let original = Arc::get_mut(&mut page.inner).unwrap().pid;
    Arc::get_mut(&mut page.inner).unwrap().pid = original.wrapping_add(1);
    assert!(matches!(
        unsafe { page.acquire(1, 1) },
        Err(ClockError::Owner)
    ));
    Arc::get_mut(&mut page.inner).unwrap().pid = original;
}

#[test]
fn inline_clock_caught_panic_does_not_release_an_existing_lease() {
    fn require_unwind_owner<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    require_unwind_owner::<BackedgeClock>();
    require_unwind_owner::<TrampolinePlan>();
    let page = clock();
    let lease = unsafe { page.acquire(7, MAX_WORK) }.unwrap();
    let before = unsafe { page.snapshot_parked() };
    let outcome = std::panic::catch_unwind(|| {
        drop(page.clone());
        panic!("mapping-owner unwind control");
    });
    assert!(outcome.is_err());
    assert!(matches!(
        unsafe { page.acquire(7, MAX_WORK) },
        Err(ClockError::Owner)
    ));
    assert_eq!(unsafe { page.snapshot_parked() }, before);
    drop(lease);
    drop(unsafe { page.acquire(3, 4) }.unwrap());
}

#[test]
fn inline_clock_requires_exact_managed_writer_and_keeps_enable_immutable() {
    let page = clock();
    let a = action(0, ClockMode::Stop, &page);
    assert_eq!(
        a.control.try_set_enabled(false),
        Err(crate::controls::ManagedControl)
    );
    assert!(a.control.is_enabled());
    let (control, _right) = ProbeControl::new_managed_bound(callback, true);
    let (_other, wrong) = ProbeControl::new_managed_bound(callback, true);
    assert_eq!(
        BackedgeClockAction::new(
            a.identity,
            a.base,
            &a.source,
            a.logical_pc,
            (control, wrong),
            page,
            ClockMode::Stop
        )
        .unwrap_err(),
        ClockError::Source
    );
}

#[test]
fn inline_clock_complete_source_and_site_mutations_refuse() {
    let page = clock();
    for kind in 0..4 {
        let a = action(kind, ClockMode::Stop, &page);
        for index in 0..a.source.len() {
            let mut bad = a.source.clone();
            bad[index] ^= 1;
            assert_eq!(
                BackedgeClockAction::new(
                    a.identity,
                    a.base,
                    &bad,
                    a.logical_pc,
                    ProbeControl::new_managed_bound(callback, true),
                    page.clone(),
                    ClockMode::Stop
                )
                .unwrap_err(),
                ClockError::Source
            );
        }
        assert_eq!(
            BackedgeClockAction::new(
                a.identity,
                a.base,
                &a.source,
                a.logical_pc + 1,
                ProbeControl::new_managed_bound(callback, true),
                page.clone(),
                ClockMode::Stop
            )
            .unwrap_err(),
            ClockError::Source
        );
        assert_eq!(
            BackedgeClockAction::new(
                CodeIdentity {
                    mapping: page.address(),
                    ..a.identity
                },
                page.address(),
                &a.source,
                page.address() + (a.logical_pc - a.base),
                ProbeControl::new_managed_bound(callback, true),
                page.clone(),
                ClockMode::Stop
            )
            .unwrap_err(),
            ClockError::Source
        );
    }
}

#[test]
fn inline_clock_emits_only_exact_flag_neutral_gate_and_original_branch() {
    let page = clock();
    for kind in 0..4 {
        for mode in [ClockMode::Counter, ClockMode::Stop] {
            let a = action(kind, mode, &page);
            let image = plan(&a).emit_at(page.address() + 0x20000).unwrap();
            let gate = image.clock_gate().unwrap();
            assert_eq!(gate.entry, image.address());
            assert_eq!(image.clock(), Some(&page));
            assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
            assert_eq!(image.entry_routes(), &[(a.logical_pc, gate.entry)]);
            assert_eq!(
                image.instruction_boundaries(),
                &[(a.logical_pc, gate.original_body)]
            );
            let len = usize::try_from(gate.observing_entry - gate.entry).unwrap();
            let instructions: Vec<_> =
                Decoder::with_ip(64, &image.bytes()[..len], gate.entry, DecoderOptions::NONE)
                    .into_iter()
                    .collect();
            assert!(!instructions.is_empty());
            assert_eq!(
                instructions
                    .iter()
                    .filter(|i| i.code() == Code::Jrcxz_rel8_64)
                    .count(),
                usize::from(mode == ClockMode::Stop)
            );
            for i in &instructions {
                assert!(matches!(
                    i.mnemonic(),
                    Mnemonic::Mov
                        | Mnemonic::Lea
                        | Mnemonic::Je
                        | Mnemonic::Jle
                        | Mnemonic::Jae
                        | Mnemonic::Jrcxz
                        | Mnemonic::Jmp
                ));
                assert_eq!(i.rflags_modified(), 0);
                assert_ne!(i.memory_base(), Register::RSP);
                assert_ne!(i.op0_register(), Register::RSP);
                if i.is_ip_rel_memory_operand() {
                    assert!(
                        [0, 8, 16, 24]
                            .iter()
                            .any(|&offset| i.ip_rel_memory_address() == page.address() + offset)
                    );
                }
            }
            let body_offset = usize::try_from(gate.original_body - image.address()).unwrap();
            let branch = Decoder::with_ip(
                64,
                &image.bytes()[body_offset..],
                gate.original_body,
                DecoderOptions::NONE,
            )
            .decode();
            let scan = InstructionScanner::default()
                .scan(&a.source, a.base)
                .unwrap();
            let original = scan
                .instructions()
                .iter()
                .find(|i| i.address() == a.logical_pc)
                .unwrap()
                .instruction();
            assert_eq!(branch.code(), original.code());
            assert_eq!(branch.near_branch_target(), original.near_branch_target());
            assert!(
                image
                    .program_counter_mappings()
                    .iter()
                    .any(|m| m.translate(gate.entry) == Some(a.logical_pc))
            );
        }
    }
}

#[test]
fn inline_clock_final_rip_reach_and_frame_emission_refuse() {
    let page = clock();
    let a = action(0, ClockMode::Stop, &page);
    let p = plan(&a);
    assert!(p.emit_at(page.address() + 0x20000).is_ok());
    assert!(p.emit_at(page.address() + 3 * 1024 * 1024 * 1024).is_err());
    assert!(
        p.emit_with_frame_trace_at(page.address() + 0x20000)
            .is_err()
    );
}

#[test]
fn inline_clock_image_retains_the_actual_data_owner_after_plan_drop() {
    let page = clock();
    let weak = Arc::downgrade(&page.inner);
    let a = action(0, ClockMode::Stop, &page);
    let p = plan(&a);
    let image = p.emit_at(page.address() + 0x20000).unwrap();
    drop(page);
    drop(a);
    drop(p);
    assert!(weak.upgrade().is_some());
    drop(image);
    assert!(weak.upgrade().is_none());
}

fn owned_action(
    bytes: &[u8],
    offset: usize,
    page: &BackedgeClock,
    mode: ClockMode,
) -> Result<BackedgeClockAction, ClockError> {
    let base = page.address() + 0x10000;
    BackedgeClockAction::new_owned_loop(
        CodeIdentity {
            source: crate::contracts::SourceIdentity([42; 32]),
            mapping: base,
            generation: 1,
        },
        base,
        bytes,
        base + offset as u64,
        ProbeControl::new_managed_bound(callback, true),
        page.clone(),
        mode,
    )
}

#[test]
fn owned_loop_admits_separate_source_without_changing_literal_profile() {
    let page = clock();
    let before = unsafe { page.snapshot_parked() };
    for kind in 0..4 {
        for mode in [ClockMode::Counter, ClockMode::Stop] {
            let (mut bytes, offset) = source(kind);
            bytes[0] = 0x33; // Different XOR encoding: valid, outside every old literal.
            let action = owned_action(&bytes, offset, &page, mode).unwrap();
            assert_eq!(action.source, bytes);
            assert_eq!(action.condition, [Some(5), Some(15), Some(2), None][kind]);
            assert_eq!(action.clock(), &page);
            assert_eq!(
                action.control().try_set_enabled(false),
                Err(crate::controls::ManagedControl)
            );
            assert_eq!(
                BackedgeClockAction::new(
                    action.identity,
                    action.base,
                    &bytes,
                    action.logical_pc,
                    ProbeControl::new_managed_bound(callback, true),
                    page.clone(),
                    mode,
                )
                .unwrap_err(),
                ClockError::Source
            );
            let image = plan(&action).emit_at(page.address() + 0x20000).unwrap();
            let gate = image.clock_gate().unwrap();
            let end = usize::try_from(gate.observing_entry - image.address()).unwrap();
            for instruction in Decoder::with_ip(
                64,
                &image.bytes()[..end],
                image.address(),
                DecoderOptions::NONE,
            ) {
                assert_eq!(instruction.rflags_modified(), 0);
            }
            let body = usize::try_from(gate.original_body - image.address()).unwrap();
            let relocated = Decoder::with_ip(
                64,
                &image.bytes()[body..],
                gate.original_body,
                DecoderOptions::NONE,
            )
            .decode();
            let original = Decoder::with_ip(
                64,
                &bytes[offset..],
                action.logical_pc,
                DecoderOptions::NONE,
            )
            .decode();
            assert_eq!(relocated.code(), original.code());
            assert_eq!(
                relocated.near_branch_target(),
                original.near_branch_target()
            );
        }
    }
    assert_eq!(unsafe { page.snapshot_parked() }, before);
}

#[test]
fn owned_loop_bounded_whole_region_and_forward_exit_policy() {
    let base = 0x10000;
    for kind in 0..4 {
        let (mut bytes, offset) = source(kind);
        bytes.pop();
        bytes.resize(255, 0x90);
        bytes.push(0xc3);
        assert!(owned_loop::admit(&bytes, base, base + offset as u64).is_ok());
        bytes.insert(255, 0x90);
        assert_eq!(
            owned_loop::admit(&bytes, base, base + offset as u64),
            Err(ClockError::Source)
        );
    }
    // A forward near JZ skips the single unconditional backedge to final RET.
    let bytes = [
        0x90, 0x0f, 0x84, 5, 0, 0, 0, 0xe9, 0xf4, 0xff, 0xff, 0xff, 0xc3,
    ];
    assert_eq!(owned_loop::admit(&bytes, base, base + 7), Ok(None));
    // Forward direct JMP is also legal when every head remains reachable.
    let bytes = [0xeb, 0, 0x90, 0x0f, 0x85, 0xf9, 0xff, 0xff, 0xff, 0xc3];
    assert_eq!(owned_loop::admit(&bytes, base, base + 3), Ok(Some(5)));
}

#[test]
fn owned_loop_rejects_wrong_site_target_size_and_extra_cycles() {
    let base = 0x10000;
    let (bytes, offset) = source(0);
    let pc = base + offset as u64;
    for bad_pc in [base - 1, base, pc + 1, base + bytes.len() as u64] {
        assert_eq!(
            owned_loop::admit(&bytes, base, bad_pc),
            Err(ClockError::Source)
        );
    }
    for (bad, start, site) in [
        (Vec::new(), base, pc),
        (bytes.clone(), 0, offset as u64),
        (bytes.clone(), u64::MAX, u64::MAX),
    ] {
        assert_eq!(
            owned_loop::admit(&bad, start, site),
            Err(ClockError::Source)
        );
    }
    let mut bad = bytes.clone();
    *bad.last_mut().unwrap() = 0x0f;
    assert_eq!(owned_loop::admit(&bad, base, pc), Err(ClockError::Source));
    // Targets: outside source, inside an instruction, self, and forward to RET.
    for target_offset in [-1, 8, offset as i64, (offset + 6) as i64] {
        let mut bad = bytes.clone();
        let displacement = i32::try_from(target_offset - (offset + 6) as i64).unwrap();
        bad[offset + 2..offset + 6].copy_from_slice(&displacement.to_le_bytes());
        assert_eq!(owned_loop::admit(&bad, base, pc), Err(ClockError::Source));
    }
    for condition in (0..16).filter(|cc| ![5, 15, 2].contains(cc)) {
        let mut bad = bytes.clone();
        bad[offset + 1] = 0x80 + condition;
        assert_eq!(owned_loop::admit(&bad, base, pc), Err(ClockError::Source));
    }
    let mut bad = bytes.clone();
    drop(bad.splice(
        offset..offset + 6,
        [0x75, (7i32 - (offset + 2) as i32) as u8],
    ));
    assert_eq!(owned_loop::admit(&bad, base, pc), Err(ClockError::Source));
    let mut bad = bytes.clone();
    bad.pop();
    let displacement = -((bad.len() + 5) as i32);
    bad.push(0xe9);
    bad.extend(displacement.to_le_bytes());
    bad.push(0xc3);
    assert_eq!(owned_loop::admit(&bad, base, pc), Err(ClockError::Source));
    let (mut bad, direct) = source(3);
    bad[direct - 1] = 1; // Forward target inside JMP.
    assert_eq!(
        owned_loop::admit(&bad, base, base + direct as u64),
        Err(ClockError::Source)
    );
}

#[test]
fn owned_loop_rejects_calls_system_stack_and_unreachable_source() {
    let base = 0x10000;
    let (bytes, offset) = source(0);
    let prefixes: &[&[u8]] = &[
        &[0xe8, 0, 0, 0, 0], // Direct CALL.
        &[0xff, 0xd0],
        &[0xff, 0xe0], // Indirect CALL/JMP.
        &[0x0f, 0x05],
        &[0xcc, 0x90],       // SYSCALL/INT3.
        &[0x0f, 0x22, 0xc0], // Privileged MOV to CR0.
        &[0x8e, 0xd8],       // Non-GPR MOV to DS.
        &[0x48, 0xf7, 0xe1],
        &[0xd9, 0xe8], // Implicit MUL state / x87.
        &[0x50],
        &[0x58],
        &[0xc9], // PUSH/POP/LEAVE.
        &[0xfc],
        &[0xe4, 0x80], // Direction flag / port input.
        &[0x48, 0x89, 0xe0],
        &[0x48, 0x8b, 0x04, 0x24], // RSP and [RSP].
        &[0x40, 0xb4, 1],          // SPL alias.
        &[0x64, 0x48, 0x8b, 0],    // Segment-based memory.
        &[0xf0, 0x01, 0],          // Locked arithmetic.
        &[0xc3, 0x90],             // Return before the final byte.
    ];
    for prefix in prefixes {
        let mut bad = prefix.to_vec();
        bad.extend(&bytes[2..]);
        assert_eq!(
            owned_loop::admit(&bad, base, base + (offset + prefix.len() - 2) as u64),
            Err(ClockError::Source)
        );
    }
    let mut bad = bytes.clone();
    bad.pop();
    bad.extend([0xc2, 0, 0]);
    assert_eq!(
        owned_loop::admit(&bad, base, base + offset as u64),
        Err(ClockError::Source)
    );
    let mut bad = bytes.clone();
    *bad.last_mut().unwrap() = 0x90;
    assert_eq!(
        owned_loop::admit(&bad, base, base + offset as u64),
        Err(ClockError::Source)
    );
    let mut bad = vec![0xeb, 2, 0x90, 0x90];
    bad.extend(bytes);
    assert_eq!(
        owned_loop::admit(&bad, base, base + offset as u64 + 4),
        Err(ClockError::Source)
    );
    let (mut bad, direct) = source(3);
    bad[direct - 2] = 0xe3; // Forward JRCXZ.
    assert_eq!(
        owned_loop::admit(&bad, base, base + direct as u64),
        Err(ClockError::Source)
    );
}

#[test]
fn owned_loop_keeps_managed_control_identity_and_nonoverlap_checks() {
    let page = clock();
    let (bytes, offset) = source(0);
    let good = owned_action(&bytes, offset, &page, ClockMode::Stop).unwrap();
    let (control, _writer) = ProbeControl::new_managed_bound(callback, true);
    let (_other, wrong) = ProbeControl::new_managed_bound(callback, true);
    assert_eq!(
        BackedgeClockAction::new_owned_loop(
            good.identity,
            good.base,
            &bytes,
            good.logical_pc,
            (control, wrong),
            page.clone(),
            ClockMode::Stop
        )
        .unwrap_err(),
        ClockError::Source
    );
    assert_eq!(
        BackedgeClockAction::new_owned_loop(
            good.identity,
            good.base,
            &bytes,
            good.logical_pc,
            ProbeControl::new_managed_bound(callback, false),
            page.clone(),
            ClockMode::Stop
        )
        .unwrap_err(),
        ClockError::Source
    );
    for identity in [
        CodeIdentity {
            generation: 0,
            ..good.identity
        },
        CodeIdentity {
            mapping: good.base + 1,
            ..good.identity
        },
    ] {
        assert_eq!(
            BackedgeClockAction::new_owned_loop(
                identity,
                good.base,
                &bytes,
                good.logical_pc,
                ProbeControl::new_managed_bound(callback, true),
                page.clone(),
                ClockMode::Stop
            )
            .unwrap_err(),
            ClockError::Source
        );
    }
    let base = page.address();
    assert_eq!(
        BackedgeClockAction::new_owned_loop(
            CodeIdentity {
                mapping: base,
                ..good.identity
            },
            base,
            &bytes,
            base + offset as u64,
            ProbeControl::new_managed_bound(callback, true),
            page,
            ClockMode::Stop
        )
        .unwrap_err(),
        ClockError::Source
    );
}

#[test]
fn owned_loop_does_not_replace_external_entry_admission() {
    use crate::contracts::{
        EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet, ResumeObligation,
    };
    use crate::planner::HookSemantics;
    use crate::quiescent::{AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy};
    let page = clock();
    let (bytes, offset) = source(0);
    let action = owned_action(&bytes, offset, &page, ClockMode::Stop).unwrap();
    let scope = AddressRange::new(action.base, bytes.len()).unwrap();
    let facts = LegalEntrySet {
        identity: action.identity,
        scope,
        provenance: EntryProvenance::Declared("synthetic ownership facts; no execution".into()),
        completeness: EntryCompleteness::Complete,
        entries: vec![LegalEntry {
            address: action.base,
            requires_endbr: false,
        }],
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy::near(action.logical_pc).unwrap();
    let validate = |entries: &LegalEntrySet, cet: bool| {
        let request = InstallRequest {
            identity: action.identity,
            code: &bytes,
            base_address: action.base,
            function: scope,
            block: AddressRange::new(action.logical_pc, 6).unwrap(),
            logical_pc: action.logical_pc,
            entries,
            hook: unused_owned_hook,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_displaced_bytes: 15,
                max_sites: 1,
            },
        };
        if cet {
            crate::quiescent::plan_backedge_clock_detailed(&request, &action)
                .map(|_| ())
                .map_err(|e| e.reason)
        } else {
            crate::quiescent::validated_source(&request).map(|_| ())
        }
    };
    assert!(validate(&facts, false).is_ok());
    for case in 0..5 {
        let mut bad = facts.clone();
        match case {
            0 => bad.completeness = EntryCompleteness::Incomplete,
            1 => bad.resumes = ResumeObligation::Unresolved,
            2 => bad.identity.generation += 1,
            3 => bad.entries[0].address += 1,
            _ => bad.entries[0].address = scope.end(),
        }
        assert!(validate(&bad, false).is_err());
    }
    let mut cet = facts;
    cet.entries.push(LegalEntry {
        address: action.logical_pc,
        requires_endbr: true,
    });
    assert!(matches!(
        validate(&cet, true),
        Err(crate::contracts::Refusal::UnsupportedSemantics(_))
    ));
}

unsafe extern "C" fn unused_owned_hook(_: *mut HookContext) {}
