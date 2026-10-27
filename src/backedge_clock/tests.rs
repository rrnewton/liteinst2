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
