//! Pure source-storage/geometry controls. Map tables, read outcomes and native
//! stop images are synthetic. No native owner, release or cleanup is exercised.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::linux::remote::dynamic::owner::admission::source_identity::{
    FileIdentity, ImageRole, SourceReadFailure, SourceReadOperation,
};
use crate::linux::remote::dynamic::owner::bootstrap::BootstrapEvidence;
use crate::linux::remote::dynamic::owner::trusted::{
    AdmissionPhase, OwnedSignal, TaskStateSnapshot, TrustedIsland,
};
use liteinst_admission::entries::LegalEntrySet;
use liteinst_admission::scan::{AdmissionOracle, Obligation, Policy, RuntimeScan, Verdict};
use std::time::Duration;

const START: u64 = 0x400000;
fn range(a: u64, b: u64) -> AddressRange {
    AddressRange::new(a, b).unwrap()
}
fn profile() -> InitialCaptureProfile {
    InitialCaptureProfile {
        max_vmas: 2,
        max_windows: 32,
        max_window_bytes: 8192,
        max_total_capture_bytes: 32 * 8192,
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn exact<T>(value: Result<T, GateError>, wanted: &'static str) {
    assert!(matches!(value, Err(GateError::Refused(reason)) if reason == wanted));
}
fn entry(pc: u64) -> EntryEvidence {
    EntryEvidence {
        first_image: crate::FirstImage::Executable,
        executable_entry: pc,
        interpreter_base: 0,
        initial_instruction: pc,
        interpreter: None,
    }
}
fn map_progress(len: usize) -> SourceReadProgress {
    SourceReadProgress {
        started: true,
        attempted: true,
        requested_bytes: MAP_BYTES,
        copied_bytes: len,
        complete: true,
        filesystem_type: Some(libc::PROC_SUPER_MAGIC),
        ..SourceReadProgress::default()
    }
}
fn memory_progress(len: usize) -> SourceReadProgress {
    SourceReadProgress {
        started: true,
        attempted: true,
        requested_bytes: len,
        copied_bytes: len,
        complete: true,
        ..SourceReadProgress::default()
    }
}
fn synthetic_plan(pages: usize, profile: InitialCaptureProfile) -> InitialSourceStorage {
    let mut value = PreparedInitialSources::allocate(profile, until())
        .unwrap()
        .storage;
    let end = START + pages as u64 * 4096;
    let old = format!("{START:08x}-{end:08x} r-xp 00000000 08:01 123 /objects/main  image\n");
    let new = old.replace("r-xp", "r--p");
    value.original_maps[..old.len()].copy_from_slice(old.as_bytes());
    value.quarantine_maps[..new.len()].copy_from_slice(new.as_bytes());
    value.original_read = map_progress(old.len());
    value.quarantine_read = map_progress(new.len());
    value.original = Some(OriginalBinding {
        token: DynamicStop {
            session: 70,
            sequence: 0,
            tid: 100,
            task: None,
        },
        entry: entry(START),
    });
    value.rows.push(SourceVma {
        original_index: 0,
        current_index: 0,
        original_span: (0, old.len() - 1),
        current_span: (0, new.len() - 1),
        start: START,
        end,
        offset: 0,
        file: FileIdentity {
            major: 8,
            minor: 1,
            inode: 123,
        },
        role: ImageRole::Executable,
    });
    value
}
fn fill_snapshots(value: &mut InitialSourceStorage) {
    value.plan_windows().unwrap();
    for slot in &mut value.windows[..value.planned] {
        let geometry = slot.geometry.unwrap();
        let len = extent(geometry.snapshot).unwrap();
        slot.bytes[..len].fill(0x90);
        slot.capture = memory_progress(len);
        validate_heads(&slot.bytes[..len], geometry, &slot.entries).unwrap();
    }
    value.move_snapshots();
}

fn synthetic_boot(tid: i32) -> BootstrapMm {
    let registry = LifecycleRegistry::new(crate::lifecycle::Limits::default(), tid, START).unwrap();
    let task = registry.root_task();
    let record = registry.task(task).unwrap();
    let identity = crate::DynamicTask {
        task,
        process: record.process,
        address_space: record.address_space,
        generation: 0,
    };
    let mut registers =
        RegisterSnapshot::from(unsafe { std::mem::zeroed::<libc::user_regs_struct>() });
    registers.cs = 0x33;
    registers.rip = START;
    registers.rsp = START + 0x8000;
    registers.rax = 7;
    registers.orig_rax = u64::MAX;
    registers.eflags = 0x202;
    let raw = TaskStateSnapshot {
        registers,
        mask: 0x600,
        xstate: (0..832).map(|i| (i % 251) as u8).collect(),
    };
    BootstrapMm {
        island: TrustedIsland {
            address_space: identity.address_space,
            generation: 0,
            range: 0x800000..0x801000,
            page_size: 4096,
        },
        original_executables: Vec::new(),
        mappings: Vec::new(),
        stop: AdmissionStop {
            token: DynamicStop {
                session: 70,
                sequence: 9,
                tid,
                task: Some(task),
            },
            identity,
            phase: AdmissionPhase::EntryReady,
            signal: None,
        },
        evidence: BootstrapEvidence {
            exec_event: raw.clone(),
            exec_exit: raw.clone(),
            entry_trap: raw.clone(),
            restored_entry: raw,
        },
    }
}

#[test]
fn initial_capture_bounds_are_fixed_and_partial_has_no_complete_variant() {
    let p = profile();
    assert_eq!(p.validate().unwrap(), p);
    for changed in [
        InitialCaptureProfile { max_vmas: 0, ..p },
        InitialCaptureProfile { max_vmas: 65, ..p },
        InitialCaptureProfile {
            max_windows: 0,
            ..p
        },
        InitialCaptureProfile {
            max_windows: 65,
            ..p
        },
        InitialCaptureProfile {
            max_window_bytes: 65537,
            ..p
        },
        InitialCaptureProfile {
            max_total_capture_bytes: 8191,
            ..p
        },
        InitialCaptureProfile {
            max_total_capture_bytes: 32 * 8192 + 1,
            ..p
        },
    ] {
        exact(
            changed.validate(),
            "initial runtime capture profile differs",
        );
    }
    exact(
        InitialCaptureProfile {
            max_window_bytes: 4096,
            max_total_capture_bytes: 32 * 4096,
            ..p
        }
        .validate(),
        "initial runtime window cannot contain a whole target page",
    );
    assert_eq!(
        crate::DynamicAdmissionLimits::default().source_fact_bytes,
        64 * 1024 * 1024
    );
    let evidence = PartialEntries::new(range(START, START + 8192), &entry(START));
    assert_eq!(evidence.completeness(), Completeness::Partial);
    assert_eq!(
        evidence.heads().collect::<Vec<_>>(),
        vec![(START, EntryProvenance::Loader)]
    );
}

#[test]
fn initial_capture_large_vma_windows_keep_one_real_mapping_identity() {
    let mut value = synthetic_plan(24, profile());
    let original = value.rows[0];
    value.plan_windows().unwrap();
    assert_eq!(value.planned, 24);
    assert_eq!(value.identities.len(), 1);
    assert_eq!(value.rows.as_slice(), [original]);
    assert_eq!((original.start, original.end), (START, START + 24 * 4096));
    let mut cursor = START;
    for (index, window) in value.windows[..value.planned].iter().enumerate() {
        let id = window.id.unwrap();
        let geometry = window.geometry.unwrap();
        assert_eq!(id.identity(), value.identities[0]);
        assert_eq!(id.index(), index);
        assert_eq!(window.vma, 0);
        assert_eq!(geometry.target.start(), cursor);
        cursor = geometry.target.end();
        assert!(range(original.start, original.end).covers(geometry.snapshot));
        assert!(extent(geometry.snapshot).unwrap() <= 8192);
        assert_ne!(geometry.snapshot, range(original.start, original.end));
    }
    assert_eq!(cursor, original.end);
    assert_eq!(value.rows[0].original_span, original.original_span);
    assert_eq!(value.rows[0].current_span, original.current_span);
    assert!(!value.capture_complete());
}

#[test]
fn initial_capture_scan_closure_includes_last_trailing_head_decode() {
    let vma = VmaGeometry {
        range: range(START, START + 4 * 4096),
        before: Boundary::NonExecutable,
        after: Boundary::NonExecutable,
    };
    let target = range(START + 4096, START + 8192);
    let geometry = WindowGeometry::for_target(vma, target, 8192).unwrap();
    assert_eq!(
        geometry.snapshot,
        range(target.start() - 14, target.end() + 28)
    );
    assert_eq!(
        geometry.head_scope,
        range(target.start() - 14, target.end() + 14)
    );
    let pc = target.end() + 13;
    let entries = PartialEntries {
        heads: [Some(pc), None],
    };
    let mut bytes = vec![0x90; extent(geometry.snapshot).unwrap()];
    let offset = (pc - geometry.snapshot.start()) as usize;
    bytes[offset..offset + 14].fill(0x66);
    bytes[offset + 14] = 0x90;
    validate_heads(&bytes, geometry, &entries).unwrap();
    let snapshot = Snapshot::new(
        MappingId(7),
        Generation(0),
        geometry.snapshot.start(),
        bytes,
        geometry.before,
        geometry.after,
        WriteControl::Owned,
    )
    .unwrap();
    let legal = LegalEntrySet::new(
        MappingId(7),
        Generation(0),
        0,
        snapshot.range(),
        Completeness::Partial,
        entries.heads(),
        [],
    )
    .unwrap();
    let report = RuntimeScan.inspect(&snapshot, target, &legal, &Policy::default());
    assert_eq!(report.verdict(), Verdict::Clean);
    assert_eq!(report.snapshot(), &snapshot);
    assert!(
        !report
            .obligations()
            .contains(&Obligation::InvalidKnownInstruction(pc))
    );
    let mut short = snapshot.bytes().to_vec();
    short.truncate(short.len() - 14);
    exact(
        validate_heads(&short, geometry, &entries),
        "initial runtime full dependency bytes are incomplete",
    );
}

#[test]
fn initial_capture_interior_edges_never_become_nonexecutable() {
    let vma = VmaGeometry {
        range: range(START, START + 6 * 4096),
        before: Boundary::NonExecutable,
        after: Boundary::NonExecutable,
    };
    let first = WindowGeometry::for_target(vma, range(START, START + 4096), 8192).unwrap();
    let middle = WindowGeometry::for_target(vma, range(START + 4096, START + 8192), 8192).unwrap();
    let last =
        WindowGeometry::for_target(vma, range(START + 5 * 4096, START + 6 * 4096), 8192).unwrap();
    assert_eq!(
        (first.before, first.after),
        (Boundary::NonExecutable, Boundary::Unknown)
    );
    assert_eq!(
        (middle.before, middle.after),
        (Boundary::Unknown, Boundary::Unknown)
    );
    assert_eq!(
        (last.before, last.after),
        (Boundary::Unknown, Boundary::NonExecutable)
    );
    let forged = Snapshot::new(
        MappingId(3),
        Generation(0),
        middle.snapshot.start(),
        vec![0x90; extent(middle.snapshot).unwrap()],
        Boundary::NonExecutable,
        middle.after,
        WriteControl::Owned,
    )
    .unwrap();
    exact(
        middle.validate_snapshot(&forged),
        "initial runtime complete snapshot geometry differs",
    );
}

#[test]
fn initial_capture_adjacent_executable_dependencies_refuse_both_directions() {
    let vma = VmaGeometry {
        range: range(START, START + 8192),
        before: Boundary::NonExecutable,
        after: Boundary::NonExecutable,
    };
    exact(
        WindowGeometry::for_target(
            VmaGeometry {
                before: Boundary::Unknown,
                ..vma
            },
            range(START, START + 4096),
            8192,
        ),
        "initial runtime cross-VMA decode closure is unqualified",
    );
    exact(
        WindowGeometry::for_target(
            VmaGeometry {
                after: Boundary::Unknown,
                ..vma
            },
            range(START + 4096, START + 8192),
            8192,
        ),
        "initial runtime cross-VMA decode closure is unqualified",
    );
    let mut value = synthetic_plan(1, profile());
    let old = format!(
        "{START:08x}-00401000 r-xp 00000000 08:01 123 /objects/main  image\n00401000-00402000 r-xp 00000000 08:01 456 /objects/neighbor\n"
    );
    let new = old.replace("r-xp", "r--p");
    value.original_maps.fill(0);
    value.quarantine_maps.fill(0);
    value.original_maps[..old.len()].copy_from_slice(old.as_bytes());
    value.quarantine_maps[..new.len()].copy_from_slice(new.as_bytes());
    value.original_read = map_progress(old.len());
    value.quarantine_read = map_progress(new.len());
    // Own row and raw-line spans are unchanged. The neighbor's logical X is
    // still authoritative even though its current imposed protection is NX.
    exact(
        value.plan_windows(),
        "initial runtime cross-VMA decode closure is unqualified",
    );
    assert_eq!(value.planned, 0);
    assert!(value.windows.iter().all(|slot| !slot.capture.started));
}

#[test]
fn initial_capture_window_and_overlap_limits_refuse_before_source_reads() {
    let p = InitialCaptureProfile {
        max_windows: 1,
        max_total_capture_bytes: 8192,
        ..profile()
    };
    let mut value = synthetic_plan(2, p);
    exact(
        value.plan_windows(),
        "initial runtime window count exceeds its bound",
    );
    assert_eq!(value.planned, 1);
    assert!(value.windows.iter().all(|slot| !slot.capture.started));
    // Two target pages need 8192 source bytes plus overlapping decode context.
    let p = InitialCaptureProfile {
        max_windows: 2,
        max_total_capture_bytes: 8192,
        ..profile()
    };
    let mut value = synthetic_plan(2, p);
    exact(
        value.plan_windows(),
        "initial runtime overlapping capture bytes exceed their bound",
    );
    assert_eq!(value.planned, 1);
    assert!(value.windows.iter().all(|slot| !slot.capture.started));
}

#[test]
fn initial_capture_partial_entries_cannot_admit_selected_sites() {
    let geometry = WindowGeometry::for_target(
        VmaGeometry {
            range: range(START, START + 4096),
            before: Boundary::NonExecutable,
            after: Boundary::NonExecutable,
        },
        range(START, START + 4096),
        8192,
    )
    .unwrap();
    let positive = PartialEntries::new(geometry.head_scope, &entry(START));
    let mut bytes = vec![0x90; 4096];
    bytes[..2].copy_from_slice(&[0x0f, 0xa2]);
    validate_heads(&bytes, geometry, &positive).unwrap();
    let snapshot = Snapshot::new(
        MappingId(9),
        Generation(0),
        START,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        MappingId(9),
        Generation(0),
        0,
        snapshot.range(),
        positive.completeness(),
        positive.heads(),
        [],
    )
    .unwrap();
    let report = RuntimeScan.inspect(&snapshot, geometry.target, &entries, &Policy::default());
    assert_eq!(report.verdict(), Verdict::Refused);
    assert!(
        report
            .obligations()
            .contains(&Obligation::IncompleteEntries)
    );
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(report.snapshot(), &snapshot);
    assert_eq!(report.entries(), &entries);
}

#[test]
fn initial_capture_snapshot_moves_keep_exact_capacity_and_payload_once() {
    let mut value = synthetic_plan(3, profile());
    value.plan_windows().unwrap();
    let allocated = value.allocated_bytes().unwrap();
    let pointers: Vec<_> = value.windows[..value.planned]
        .iter()
        .map(|slot| (slot.bytes.as_ptr(), slot.bytes.capacity()))
        .collect();
    for slot in &mut value.windows[..value.planned] {
        let count = extent(slot.geometry.unwrap().snapshot).unwrap();
        for (index, byte) in slot.bytes[..count].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
    }
    value.move_snapshots();
    assert_eq!(value.allocated_bytes().unwrap(), allocated);
    for (index, slot) in value.windows[..value.planned].iter().enumerate() {
        let snapshot = slot.snapshot.as_ref().unwrap();
        assert_eq!(snapshot.bytes().as_ptr(), pointers[index].0);
        assert_eq!(slot.snapshot_capacity, pointers[index].1);
        assert_eq!(slot.bytes.capacity(), 0);
        assert_eq!(
            snapshot.bytes().len(),
            extent(slot.geometry.unwrap().snapshot).unwrap()
        );
        assert!(
            snapshot
                .bytes()
                .iter()
                .enumerate()
                .all(|(offset, byte)| *byte == (offset % 251) as u8)
        );
        verify_window(slot, &value.identities, index).unwrap();
    }
    assert!(
        value.windows[value.planned..]
            .iter()
            .all(|slot| slot.bytes.capacity() >= 8192 && slot.snapshot.is_none())
    );
}

#[test]
fn initial_capture_entry_path_moves_preallocated_storage_without_losing_bytes() {
    let mut prepared = PreparedInitialSources::allocate(profile(), until()).unwrap();
    let pointer = prepared.storage.entry_path.as_ptr();
    let capacity = prepared.storage.entry_path.capacity();
    let allocated = prepared.allocated_bytes().unwrap();
    let mut input = entry(START);
    input.first_image = crate::FirstImage::Interpreter;
    input.interpreter_base = 0x800000;
    input.initial_instruction = 0x801000;
    input.interpreter = Some(std::path::PathBuf::from(std::ffi::OsString::from_vec(
        b"/objects/interpreter \xff image".to_vec(),
    )));
    let retained = retain_entry(&input, &mut prepared.storage.entry_path).unwrap();
    assert_eq!(retained, input);
    assert_eq!(
        retained
            .interpreter
            .as_ref()
            .unwrap()
            .as_os_str()
            .as_bytes()
            .as_ptr(),
        pointer
    );
    assert_eq!(retained.interpreter.as_ref().unwrap().capacity(), capacity);
    assert_eq!(prepared.storage.entry_path.capacity(), 0);
    prepared.storage.original = Some(OriginalBinding {
        token: DynamicStop {
            session: 70,
            sequence: 0,
            tid: 100,
            task: None,
        },
        entry: retained,
    });
    assert_eq!(prepared.allocated_bytes().unwrap(), allocated);
    let mut storage = initialized(ENTRY_PATH_BYTES).unwrap();
    let original = storage.clone();
    input.interpreter = Some(std::path::PathBuf::from(std::ffi::OsString::from_vec(
        vec![b'x'; ENTRY_PATH_BYTES + 1],
    )));
    exact(
        retain_entry(&input, &mut storage),
        "initial runtime entry path exceeds its bound",
    );
    assert_eq!(storage, original);
    assert!(storage.capacity() >= ENTRY_PATH_BYTES);
}

#[test]
fn initial_capture_retained_identity_index_and_full_snapshot_are_exact() {
    let mut value = synthetic_plan(3, profile());
    fill_snapshots(&mut value);
    let identity = value.identities[0];
    for which in 0..4 {
        let saved = value.windows[0].id;
        let id = value.windows[0].id.as_mut().unwrap();
        match which {
            0 => id.index += 1,
            1 => id.identity.mapping += 1,
            2 => id.identity.generation += 1,
            _ => id.identity.source.0[31] ^= 1,
        }
        exact(
            verify_window(&value.windows[0], &value.identities, 0),
            "initial runtime retained source identity differs",
        );
        value.windows[0].id = saved;
    }
    let slot = &mut value.windows[1];
    let original = slot.snapshot.take().unwrap();
    let geometry = slot.geometry.unwrap();
    let mut shortened = original.bytes().to_vec();
    shortened.truncate(shortened.len() - 14);
    slot.snapshot = Some(
        Snapshot::new(
            MappingId(identity.mapping),
            Generation(0),
            original.range().start(),
            shortened,
            original.before,
            original.after,
            original.writes,
        )
        .unwrap(),
    );
    exact(
        verify_window(slot, &value.identities, 1),
        "initial runtime complete snapshot geometry differs",
    );
    slot.snapshot = Some(original);
    assert_eq!(slot.snapshot.as_ref().unwrap().range(), geometry.snapshot);
    verify_window(slot, &value.identities, 1).unwrap();
}

#[test]
fn initial_capture_current_stop_and_complete_state_cannot_rebind() {
    let mut value = synthetic_plan(1, profile());
    let mut boot = synthetic_boot(100);
    let raw = &boot.evidence.restored_entry;
    value.xstate[..raw.xstate.len()].copy_from_slice(&raw.xstate);
    value.current = Some(CurrentBinding {
        stop: boot.stop.clone(),
        registers: raw.registers,
        signal_mask: raw.mask,
        xstate_len: raw.xstate.len(),
    });
    value.verify_binding(&boot).unwrap();
    let original_stop = boot.stop.clone();
    let original_raw = boot.evidence.restored_entry.clone();
    let retained = value.current.clone();
    let foreign = synthetic_boot(101);
    for which in 0..11 {
        match which {
            0 => boot.stop.token.session += 1,
            1 => boot.stop.token.tid += 1,
            2 => boot.stop.token.task = None,
            3 => boot.stop.token.sequence += 1,
            4 => boot.stop.identity.task = foreign.stop.identity.task,
            5 => boot.stop.identity.process = foreign.stop.identity.process,
            6 => boot.stop.identity.address_space = foreign.stop.identity.address_space,
            7 => boot.stop.identity.generation += 1,
            8 => boot.stop.phase = AdmissionPhase::Restored,
            9 => {
                boot.stop.signal = Some(OwnedSignal {
                    raw: [0; 128],
                    view: crate::SignalStop {
                        signal: libc::SIGUSR1,
                        code: libc::SI_USER,
                        address: None,
                        instruction_pointer: START,
                        pid: 100,
                        sequence: 9,
                    },
                })
            }
            _ => boot.evidence.restored_entry.registers.orig_rax = 57,
        }
        exact(
            value.verify_binding(&boot),
            "initial runtime current complete state binding differs",
        );
        boot.stop = original_stop.clone();
        boot.evidence.restored_entry = original_raw.clone();
        assert_eq!(value.current, retained);
        value.verify_binding(&boot).unwrap();
    }
    for bit in 0..64 {
        boot.evidence.restored_entry.mask ^= 1 << bit;
        exact(
            value.verify_binding(&boot),
            "initial runtime current complete state binding differs",
        );
        boot.evidence.restored_entry.mask ^= 1 << bit;
    }
    for index in 0..original_raw.xstate.len() {
        boot.evidence.restored_entry.xstate[index] ^= 1;
        exact(
            value.verify_binding(&boot),
            "initial runtime current complete state binding differs",
        );
        boot.evidence.restored_entry.xstate[index] ^= 1;
    }
    boot.evidence.restored_entry.xstate.pop();
    exact(
        value.verify_binding(&boot),
        "initial runtime current complete state binding differs",
    );
    boot.evidence.restored_entry = original_raw.clone();
    boot.evidence.restored_entry.xstate.push(0);
    exact(
        value.verify_binding(&boot),
        "initial runtime current complete state binding differs",
    );
    boot.evidence.restored_entry = original_raw;
    value.verify_binding(&boot).unwrap();
    assert_eq!(value.current, retained);
}

#[test]
fn initial_capture_every_snapshot_byte_including_dependency_suffix_is_retained() {
    let mut value = synthetic_plan(4, profile());
    fill_snapshots(&mut value);
    let slot = &value.windows[1];
    let snapshot = slot.snapshot.as_ref().unwrap();
    let geometry = slot.geometry.unwrap();
    assert_eq!(
        snapshot.range(),
        range(geometry.target.start() - 14, geometry.target.end() + 28)
    );
    let mut actual = snapshot.bytes().to_vec();
    verify_window_bytes(snapshot, &actual).unwrap();
    // This includes the complete leading/trailing dependency and last byte of
    // the trailing known-head decode, not just the target page's bytes.
    for index in 0..actual.len() {
        actual[index] ^= 1;
        exact(
            verify_window_bytes(snapshot, &actual),
            "initial runtime original window bytes changed",
        );
        actual[index] ^= 1;
    }
    actual.pop();
    exact(
        verify_window_bytes(snapshot, &actual),
        "initial runtime original window bytes changed",
    );
    actual = snapshot.bytes().to_vec();
    actual.push(0);
    exact(
        verify_window_bytes(snapshot, &actual),
        "initial runtime original window bytes changed",
    );
    assert!(snapshot.bytes().iter().all(|byte| *byte == 0x90));
}

#[test]
fn initial_capture_failed_prefix_and_unwind_keep_initialized_storage() {
    let mut value = synthetic_plan(1, profile());
    value.plan_windows().unwrap();
    value.stage = CaptureStage::Window;
    value.active_window = Some(0);
    let slot = &mut value.windows[0];
    slot.bytes[..5].copy_from_slice(&[9, 8, 7, 6, 5]);
    slot.capture = SourceReadProgress {
        started: true,
        attempted: true,
        requested_bytes: 4096,
        copied_bytes: 5,
        failure: Some(SourceReadFailure {
            operation: SourceReadOperation::PeekMemory,
            timeout: false,
            errno: Some(libc::EIO),
        }),
        ..SourceReadProgress::default()
    };
    let expected_prefix = slot.bytes.clone();
    let allocation = value.allocated_bytes().unwrap();
    let error = Err(GateError::Control(LaunchError::System {
        operation: "PTRACE_PEEKDATA",
        source: std::io::Error::from_raw_os_error(libc::EIO),
    }));
    value.retain_error(&error);
    value.record_aborted();
    assert_eq!(
        value.failure(),
        Some(CaptureFailure {
            stage: CaptureStage::Window,
            window: Some(0),
            kind: CaptureFailureKind::System {
                operation: "PTRACE_PEEKDATA",
                errno: Some(libc::EIO),
                kind: std::io::Error::from_raw_os_error(libc::EIO).kind()
            }
        })
    );
    assert_eq!(value.window_progress(0).unwrap().0, expected_prefix);
    assert_eq!(value.allocated_bytes().unwrap(), allocation);
    assert!(!value.capture_complete() && value.window(0).is_none());
    exact(
        require_complete_read(&value.windows[0].capture, 4096),
        "initial runtime byte read is incomplete",
    );
    let mut unwound = synthetic_plan(1, profile());
    unwound.plan_windows().unwrap();
    unwound.stage = CaptureStage::Window;
    unwound.active_window = Some(0);
    unwound.windows[0].capture.started = true;
    unwound.record_aborted();
    assert_eq!(unwound.failure().unwrap().kind, CaptureFailureKind::Aborted);
    assert_eq!(unwound.windows[0].bytes, vec![0; 8192]);
}

#[test]
fn initial_capture_complete_map_status_needs_exact_nonempty_proc_prefix() {
    let bytes = vec![0x31; MAP_BYTES];
    let good = map_progress(123);
    assert_eq!(observed_maps(&bytes, &good).unwrap(), &bytes[..123]);
    for which in 0..8 {
        let mut changed = good;
        match which {
            0 => changed.started = false,
            1 => changed.attempted = false,
            2 => changed.complete = false,
            3 => changed.requested_bytes -= 1,
            4 => changed.copied_bytes = 0,
            5 => changed.copied_bytes = MAP_BYTES + 1,
            6 => changed.filesystem_type = Some(0),
            _ => {
                changed.failure = Some(SourceReadFailure {
                    operation: SourceReadOperation::ReadMaps,
                    timeout: false,
                    errno: Some(libc::EIO),
                })
            }
        }
        exact(
            observed_maps(&bytes, &changed),
            "initial runtime complete raw map capture is absent",
        );
    }
    // The shared reader separately proves EOF with its bounded extra-byte
    // request. Full capacity is valid only after that complete read proof.
    assert_eq!(
        observed_maps(&bytes, &map_progress(MAP_BYTES)).unwrap(),
        bytes
    );
}

#[test]
fn initial_capture_source_charge_is_bytes_only_and_never_refunded() {
    let p = profile();
    let charge = PreparedInitialSources::reservation_charge(p).unwrap();
    assert_eq!(
        (
            charge.epochs,
            charge.reports,
            charge.origins,
            charge.witnesses,
            charge.plan_history
        ),
        (0, 0, 0, 0, 0)
    );
    let value = PreparedInitialSources::allocate(p, until()).unwrap();
    assert!(value.allocated_bytes().unwrap() <= charge.source_fact_bytes);
    let temporary = super::super::source_identity::initial_temporary_bytes();
    assert!(
        value
            .allocated_bytes()
            .unwrap()
            .checked_add(temporary)
            .unwrap()
            <= charge.source_fact_bytes
    );
    let retained_boundary = charge.source_fact_bytes.checked_sub(temporary).unwrap();
    require_allocation_peak(retained_boundary, charge.source_fact_bytes).unwrap();
    exact(
        require_allocation_peak(retained_boundary + 1, charge.source_fact_bytes),
        "initial runtime allocator exceeded its pre-effect bound",
    );
    exact(
        require_allocation_peak(retained_boundary, charge.source_fact_bytes - 1),
        "initial runtime allocator exceeded its pre-effect bound",
    );
    assert!(
        value.allocated_bytes().unwrap()
            >= p.max_windows * p.max_window_bytes + 4 * MAP_BYTES + MAX_XSTATE
    );
    let registry = LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 4,
        },
        100,
        START,
    )
    .unwrap();
    let space = registry.task(registry.root_task()).unwrap().address_space;
    let limits = super::super::census::Limits {
        epochs: 2,
        source_fact_bytes: charge.source_fact_bytes,
        reports: 1,
        origins: 1,
        witnesses: 1,
        plan_history: 1,
    };
    let mut census = super::super::census::ResumeCensus::new(70, space, 0, limits).unwrap();
    let reservation = census.reserve(charge).unwrap();
    assert_eq!(census.charged().source_fact_bytes, charge.source_fact_bytes);
    assert_eq!(census.used().source_fact_bytes, 0);
    census.finish_reservation(reservation).unwrap();
    assert_eq!(census.charged().source_fact_bytes, charge.source_fact_bytes);
    assert_eq!(census.used().source_fact_bytes, 0);
    let mut short = super::super::census::ResumeCensus::new(
        70,
        space,
        0,
        super::super::census::Limits {
            source_fact_bytes: charge.source_fact_bytes - 1,
            ..limits
        },
    )
    .unwrap();
    let before = (
        short.charged(),
        short.used(),
        short.rows().count(),
        short.history().len(),
    );
    assert_eq!(
        short.reserve(charge).unwrap_err(),
        super::super::census::CensusError::Capacity
    );
    assert_eq!(
        (
            short.charged(),
            short.used(),
            short.rows().count(),
            short.history().len()
        ),
        before
    );
}
