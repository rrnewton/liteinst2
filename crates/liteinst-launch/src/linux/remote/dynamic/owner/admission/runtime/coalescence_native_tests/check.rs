use super::*;

pub(super) fn complete(slot: &StateSlot) {
    assert!(slot.complete);
    assert_eq!(
        [
            slot.registers_request,
            slot.xstate_request,
            slot.mask_request
        ],
        [Some(NativeRequest {
            result: 0,
            errno: None
        }); 3]
    );
    assert_eq!(slot.returned_pointer, slot.requested_pointer);
    assert_eq!(slot.returned_length, slot.state.xstate.len());
    assert!((512..MAX_XSTATE).contains(&slot.returned_length));
    assert_eq!(slot.state.xstate.capacity(), MAX_XSTATE);
}
fn complete_transferred(slot: &StateSlot, moved: &TaskStateSnapshot) {
    assert!(slot.complete);
    assert_eq!(
        [
            slot.registers_request,
            slot.xstate_request,
            slot.mask_request
        ],
        [Some(NativeRequest {
            result: 0,
            errno: None
        }); 3]
    );
    assert_eq!(slot.returned_pointer, slot.requested_pointer);
    assert_eq!(slot.requested_pointer, moved.xstate.as_ptr() as usize);
    assert_eq!(slot.returned_length, moved.xstate.len());
    assert!((512..MAX_XSTATE).contains(&slot.returned_length));
    assert_eq!(moved.xstate.capacity(), MAX_XSTATE);
    assert!(slot.state.xstate.is_empty());
    assert_eq!(slot.state.xstate.capacity(), 0);
}
fn complete_map(map: &MapBuffer) {
    assert!(map.complete);
    assert_eq!(map.length, map.bytes().len());
    assert_eq!(
        map.request,
        Some(NativeRequest {
            result: 0,
            errno: None
        })
    );
    assert_eq!(map.filesystem, Some(libc::PROC_SUPER_MAGIC));
}
fn held(status: Option<(i32, i32)>, pid: i32, signal: i32) {
    let (actual, status) = status.unwrap();
    assert_eq!(actual, pid);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), signal);
    assert_eq!(status >> 16, 0);
}
fn read(progress: &SourceReadProgress, bytes: &[u8]) {
    assert!(
        progress.started && progress.attempted && progress.complete && progress.failure.is_none()
    );
    assert_eq!(
        (progress.requested_bytes, progress.copied_bytes),
        (8192, 8192)
    );
    assert_eq!(progress.filesystem_type, None);
    let request = progress.last_request.unwrap();
    assert_eq!(request.operation, SourceReadOperation::PeekMemory);
    assert_eq!(
        (request.address, request.count, request.errno),
        (END - 8, 8, None)
    );
    assert_eq!((request.result as u64).to_ne_bytes(), bytes[8184..8192]);
}

/// The expected pre/post/final inventories are constructed independently from
/// literal fixture geometry and original raw rows, not production projections.
pub(super) fn bootstrap(
    owner: &Owner,
    before: &support::Before,
    until: Instant,
    unwound: bool,
) -> TaskStateSnapshot {
    let runtime = owner.runtime.as_ref().unwrap();
    let prepared = runtime.bootstrap.as_ref().unwrap();
    let boot = prepared.completed().unwrap();
    let evidence = &boot.evidence;
    assert_eq!(evidence.exec_event, before.state);
    let mut exit = before.state.clone();
    exit.registers.rax = 0;
    assert_eq!(evidence.exec_exit, exit);
    let mut first = exit.registers;
    first.rip = ENTRY + 1;
    first.orig_rax = u64::MAX;
    assert_eq!(evidence.entry_trap.registers, first);
    assert_eq!(evidence.entry_trap.mask, exit.mask);
    let mut restored = evidence.entry_trap.clone();
    restored.registers.rip = ENTRY;
    assert_eq!(evidence.restored_entry, restored);
    assert_eq!(state(owner.pid), restored);
    assert_ne!(restored.registers.rbx, MARKER);
    before.bytes_unchanged(owner, until);
    let progress = prepared.progress();
    assert_eq!(progress.first_failure, None);
    assert!(
        progress.exec_queries_started
            && progress.first_user_queries_started
            && progress.runner_queries_started
    );
    held(progress.exec_wait, owner.pid, libc::SIGTRAP | 0x80);
    held(progress.first_user_wait, owner.pid, libc::SIGTRAP);
    held(progress.runner_wait, owner.pid, libc::SIGTRAP);
    assert!(
        progress
            .effects()
            .iter()
            .all(|effect| effect.is_some_and(|effect| effect.complete))
    );
    let diagnostic = prepared.diagnostics();
    for (slot, moved) in diagnostic.states[..3].iter().zip([
        &evidence.exec_event,
        &evidence.exec_exit,
        &evidence.entry_trap,
    ]) {
        complete_transferred(slot, moved);
    }
    // RESTORED is the explicitly derived expectation, not a fourth query.
    // Its actual readbacks are independently retained in q.states below.
    let derived = &diagnostic.states[3];
    assert!(derived.complete && derived.state.xstate.is_empty());
    assert_eq!(derived.state.xstate.capacity(), 0);
    assert_eq!(
        [
            derived.registers_request,
            derived.xstate_request,
            derived.mask_request
        ],
        [None; 3]
    );
    assert_eq!(
        (
            derived.requested_pointer,
            derived.returned_pointer,
            derived.returned_length
        ),
        (0, 0, 0)
    );
    assert_eq!(evidence.restored_entry.xstate.capacity(), MAX_XSTATE);
    complete_map(diagnostic.exit_maps);
    assert_eq!(diagnostic.exit_maps.bytes(), before.maps);
    complete_map(diagnostic.current_maps);
    assert_eq!(diagnostic.current_maps.bytes(), read_maps(owner.pid));

    let q = runtime.coalescence.as_ref().unwrap();
    let d = q.diagnostics();
    assert_eq!(d.stage, InitialCoalescenceStage::Complete);
    assert_eq!(
        d.first_failure,
        unwound.then_some(InitialBootstrapFailureKind::Unwound)
    );
    assert_eq!(d.plan.pair_range(), BASE..END);
    assert_eq!(d.plan.rx_range(), ENTRY..END);
    assert_eq!(d.plan.original_rows(), rows(&before.maps).len());
    let (executables, ordinal) = maps::counts(&before.maps);
    assert_eq!(d.plan.executable_count(), executables);
    assert_eq!(d.plan.target_executable_ordinal(), ordinal);
    assert!(
        executables >= 2,
        "main RX and actual executable vDSO must both be retained"
    );
    let original_rows = rows(&before.maps);
    assert!(
        original_rows
            .iter()
            .any(|row| row.raw.ends_with(b"[vdso]") && row.permissions == *b"r-xp")
    );
    let (lo, hi) = d.plan.pair_indices();
    assert_eq!(original_rows[lo], before.pair.lower);
    assert_eq!(original_rows[hi], before.pair.upper);
    assert_eq!(hi, lo + 1);
    let ((a, n), (b, m)) = d.plan.pair_spans();
    assert_eq!(&before.maps[a..a + n], before.pair.lower.raw);
    assert_eq!(&before.maps[b..b + m], before.pair.upper.raw);
    assert_eq!(d.original_bytes, before.bytes);
    assert_eq!(d.final_bytes, before.bytes);
    for progress in d.read_progress {
        read(progress, &before.bytes);
    }
    for slot in d.states {
        complete(slot);
        assert_eq!(slot.state, restored);
    }
    for map in d.maps {
        complete_map(map.as_ref().unwrap());
    }
    let actual_before = d.maps[0].as_ref().unwrap().bytes();
    let actual_after = d.maps[1].as_ref().unwrap().bytes();
    let actual_final = d.maps[2].as_ref().unwrap().bytes();
    let island = maps::island(actual_before, &boot.island.range);
    assert_eq!(
        actual_before,
        maps::expected(&before.maps, &before.pair, &island, ordinal, false)
    );
    assert_eq!(
        actual_after,
        maps::expected(&before.maps, &before.pair, &island, ordinal + 1, true)
    );
    assert_eq!(
        actual_final,
        maps::expected(&before.maps, &before.pair, &island, executables, true)
    );
    assert_eq!(actual_final, read_maps(owner.pid));
    assert_eq!(rows(actual_before).len(), original_rows.len() + 1);
    assert_eq!(
        rows(actual_after).len(),
        original_rows.len(),
        "actual kernel merge is required, not optional"
    );
    assert_eq!(rows(actual_final).len(), original_rows.len());
    let projection = d.projection.unwrap();
    assert!(projection.is_merged());
    assert_eq!(projection.cleared_prefix(), executables);
    assert_eq!(projection.plan(), d.plan);
    let before_stop = d.before_stop.unwrap();
    let after_stop = d.after_stop.unwrap();
    let final_stop = d.final_stop.unwrap();
    assert_eq!(before_stop.identity, boot.stop.identity);
    for stop in [before_stop, after_stop, final_stop] {
        assert_eq!(stop.identity, before_stop.identity);
        assert_eq!(stop.token.session, owner.session);
        assert_eq!(stop.token.tid, owner.pid);
        assert_eq!(stop.token.task, before_stop.token.task);
        assert_eq!(stop.phase, AdmissionPhase::Restored);
        assert_eq!(stop.signal, None);
    }
    assert_eq!(
        after_stop.token.sequence,
        before_stop.token.sequence.checked_add(1).unwrap()
    );
    assert_eq!(
        final_stop.token.sequence,
        after_stop
            .token
            .sequence
            .checked_add(u64::try_from(executables - ordinal).unwrap())
            .unwrap()
    );
    assert_eq!(final_stop, &boot.stop);
    let call = d.call;
    held(call.wait, owner.pid, libc::SIGTRAP);
    assert!(call.queries_started && call.complete);
    assert_eq!(call.result, Some(0));
    assert_eq!(
        call.requests,
        [Some(NativeRequest {
            result: 0,
            errno: None
        }); 3]
    );
    assert_eq!(
        call.signal.request,
        Some(NativeRequest {
            result: 0,
            errno: None
        })
    );
    let signal =
        unsafe { std::ptr::read_unaligned(call.signal.bytes.as_ptr().cast::<libc::siginfo_t>()) };
    assert_eq!((signal.si_signo, signal.si_errno), (libc::SIGTRAP, 0));
    assert!(matches!(signal.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
    let trap = call.registers.unwrap();
    assert_eq!(
        (trap.rax, trap.rdi, trap.rsi, trap.rdx),
        (0, ENTRY, 4096, libc::PROT_READ as u64)
    );
    let mut expected_trap = restored.registers;
    expected_trap.rip = boot.island.range.start + 3;
    expected_trap.orig_rax = u64::MAX;
    expected_trap.eflags &= !(0x100 | 0x10000 | 0x40000);
    expected_trap.rax = 0;
    expected_trap.rdi = ENTRY;
    expected_trap.rsi = 4096;
    expected_trap.rdx = libc::PROT_READ as u64;
    expected_trap.r10 = 0;
    expected_trap.r8 = 0;
    expected_trap.r9 = 0;
    expected_trap.rcx = boot.island.range.start + 2;
    expected_trap.r11 = expected_trap.eflags;
    assert_eq!(trap, expected_trap);
    assert_eq!(call.mask, restored.mask);
    assert_eq!(call.returned_length, restored.xstate.len());
    q.validate_allocations(Some(&boot.mappings)).unwrap();
    assert_eq!((d.original_capacity, d.final_capacity), (8192, 8192));
    assert!(d.output_transferred && d.output.is_empty());
    assert!(d.successful_payload_bytes <= d.reserved_payload_bytes);
    let originals = boot
        .original_executables
        .iter()
        .filter(|row| row.start == ENTRY)
        .collect::<Vec<_>>();
    assert_eq!(originals.len(), 1);
    assert_eq!(
        (
            originals[0].start,
            originals[0].end,
            originals[0].file_offset
        ),
        (ENTRY, END, 4096)
    );
    assert_eq!(originals[0].permissions, "r-xp");
    assert_eq!(
        originals[0].pathname.as_deref().unwrap().as_bytes(),
        before.pair.pathname
    );
    assert!(
        boot.original_executables
            .iter()
            .all(|row| row.start != BASE)
    );
    let current = boot
        .mappings
        .iter()
        .filter(|row| row.start == BASE)
        .collect::<Vec<_>>();
    assert_eq!(current.len(), 1);
    assert_eq!(
        (current[0].start, current[0].end, current[0].file_offset),
        (BASE, END, 0)
    );
    assert_eq!(current[0].permissions, "r--p");
    assert_eq!(current[0].pathname, originals[0].pathname);
    assert!(boot.mappings.iter().all(|row| row.start != ENTRY));
    // Full independent descriptor/ownership oracle: retention alone must not
    // preserve an already-wrong inventory. The raw tables above were compared
    // against the complete literal expected projection, not a production view.
    let expected_original = original_rows
        .iter()
        .map(maps::descriptor)
        .collect::<Vec<_>>();
    let expected_current = rows(actual_final)
        .iter()
        .map(maps::descriptor)
        .collect::<Vec<_>>();
    assert_eq!(boot.mappings, expected_current);
    assert_eq!(
        boot.original_executables,
        maps::original_executables(&before.maps)
    );
    assert_eq!(d.retired_descriptors, expected_original);
    let count = original_rows.len();
    assert_eq!((d.pool.len(), d.pool_capacity), (count, count));
    assert_eq!((d.output.len(), d.output_capacity), (0, 0));
    assert_eq!(
        (d.retired_descriptors.len(), d.retired_capacity),
        (count, count + 1)
    );
    assert_eq!(
        (boot.mappings.len(), boot.mappings.capacity()),
        (count, count + 1)
    );
    assert_eq!(boot.original_executables.capacity(), executables);
    for (index, row) in d.pool.iter().enumerate() {
        if index == hi {
            assert_eq!(row.as_ref(), Some(&expected_original[hi]));
        } else {
            assert!(
                row.is_none(),
                "a transferred original descriptor remains in the pool"
            );
        }
    }
    let payload = |row: &crate::MemoryMapping| {
        assert_eq!(row.permissions.capacity(), 4);
        assert_eq!(row.permissions.len(), 4);
        if let Some(path) = &row.pathname {
            assert_eq!(path.capacity(), path.len());
        }
        4 + row.pathname.as_ref().map_or(0, String::len)
    };
    for row in boot
        .mappings
        .iter()
        .chain(&boot.original_executables)
        .chain(d.retired_descriptors)
        .chain(d.pool.iter().flatten())
    {
        let _ = payload(row);
    }
    let original_strings = expected_original
        .iter()
        .map(|row| 4 + row.pathname.as_ref().map_or(0, String::len))
        .sum::<usize>();
    let fixed = 3 * 65536 + 2 * MAX_XSTATE + 2 * 8192;
    let pool_bytes = count * size_of::<Option<crate::MemoryMapping>>();
    let output_bytes = (count + 1) * size_of::<crate::MemoryMapping>();
    let expected_successful = fixed + pool_bytes + output_bytes + original_strings;
    assert_eq!(d.successful_payload_bytes, expected_successful);
    let absorbed_strings = payload(d.pool[hi].as_ref().unwrap());
    let retired_bytes = output_bytes + d.retired_descriptors.iter().map(payload).sum::<usize>();
    let expected_owned = fixed + pool_bytes + absorbed_strings + retired_bytes;
    assert_eq!(q.allocated_bytes().unwrap(), expected_owned);
    let transferred_bytes = output_bytes + boot.mappings.iter().map(payload).sum::<usize>();
    // The moved island's four permission bytes and old descriptor vector were
    // prepaid by bootstrap, not newly allocated by the pair owner.
    assert_eq!(
        expected_owned - retired_bytes + transferred_bytes - 4,
        expected_successful
    );
    assert!(d.reserved_payload_bytes > expected_successful);
    let native = runtime.native.as_ref().unwrap();
    native.require_admission_stop(&boot.stop).unwrap();
    assert_eq!(
        native.admission_current(boot.stop.identity.task).unwrap(),
        boot.stop
    );
    assert!(owner.lifecycle.is_none() && owner.admission.is_none());
    if unwound {
        assert!(q.completed(boot).is_err());
    } else {
        let proof = q.completed(boot).unwrap();
        let (storage, progress) = runtime.sources.original_maps();
        assert_eq!(
            proof
                .original_maps(initial_maps_prefix(storage, progress).unwrap())
                .unwrap(),
            before.maps
        );
        assert_eq!(proof.final_maps(), actual_final);
        assert_eq!(proof.until(), until);
    }
    restored
}

pub(super) fn ready(
    owner: &Owner,
    before: &support::Before,
    actual: &DynamicAdmissionState,
    until: Instant,
) -> TaskStateSnapshot {
    let restored = bootstrap(owner, before, until, false);
    let runtime = owner.runtime.as_ref().unwrap();
    let boot = runtime.bootstrap.as_ref().unwrap().completed().unwrap();
    assert_eq!(runtime.until, until);
    assert_eq!(runtime.stage, RuntimeStage::Ready);
    assert!(runtime.ready_issued && runtime.control_lineage.is_some());
    assert_eq!(actual.task, boot.stop.identity);
    assert_eq!(actual.registers, restored.registers);
    assert_eq!(actual.xstate, restored.xstate);
    assert_eq!(actual.signal_mask, restored.mask);
    let sources = &runtime.sources;
    assert!(
        sources.original_complete() && sources.capture_complete() && sources.recheck_complete()
    );
    assert_eq!(sources.failure(), None);
    assert_eq!(sources.vmas().len(), 1);
    assert_eq!(sources.window_count(), 1);
    let vma = &sources.vmas()[0];
    assert_eq!((vma.start, vma.end, vma.offset), (ENTRY, END, 4096));
    assert_eq!(vma.file.inode, before.pair.inode);
    assert_eq!(
        format!("{:02x}:{:02x}", vma.file.major, vma.file.minor).as_bytes(),
        before.pair.device
    );
    let original_rows = rows(&before.maps);
    assert_eq!(original_rows[vma.original_index], before.pair.upper);
    let (offset, length) = vma.original_span;
    assert_eq!(&before.maps[offset..offset + length], before.pair.upper.raw);
    let window = sources.window(0).unwrap();
    assert_eq!(window.initial_source().source(), vma);
    let container = window.initial_source().container();
    assert_eq!(
        (container.start, container.end, container.offset),
        (BASE, END, 0)
    );
    assert_eq!(container.file, vma.file);
    let baseline = sources.runtime_baseline_maps().unwrap();
    let current_rows = rows(baseline);
    let row = &current_rows[container.current_index];
    assert_eq!((row.start, row.end, row.permissions), (BASE, END, *b"r--p"));
    let (start, length) = container.current_span;
    assert_eq!(&baseline[start..start + length], row.raw);
    assert_eq!(window.vma.current_index, container.current_index);
    assert_eq!(window.vma.current_span, container.current_span);
    assert_eq!(window.target.start(), ENTRY);
    assert_eq!(window.target.end(), END);
    assert_eq!(window.snapshot.range().start(), ENTRY);
    assert_eq!(window.snapshot.range().end(), END);
    assert_eq!(window.snapshot.bytes(), &before.bytes[4096..]);
    assert_eq!(
        window.snapshot.writes,
        liteinst_admission::scan::WriteControl::Owned
    );
    assert_eq!(
        window.snapshot.before,
        liteinst_admission::scan::Boundary::NonExecutable
    );
    assert_eq!(
        window.snapshot.after,
        liteinst_admission::scan::Boundary::NonExecutable
    );
    assert_eq!(window.entries.completeness(), Completeness::Partial);
    assert_eq!(
        window.entries.heads().collect::<Vec<_>>(),
        [(ENTRY, EntryProvenance::Loader)]
    );
    let identity = window.id.identity();
    assert_eq!(
        window.snapshot.mapping,
        liteinst_admission::MappingId(identity.mapping)
    );
    assert_eq!(
        window.snapshot.generation,
        liteinst_admission::Generation(identity.generation)
    );
    assert_eq!(identity.generation, 0);
    let (_, capture, recheck) = sources.window_progress(0).unwrap();
    for progress in [capture, recheck] {
        assert!(
            progress.started
                && progress.attempted
                && progress.complete
                && progress.failure.is_none()
        );
        assert_eq!(
            (progress.requested_bytes, progress.copied_bytes),
            (4096, 4096)
        );
    }
    assert_eq!(
        runtime.pages,
        [RuntimePage {
            address: ENTRY,
            window: 0,
            executable: false
        }]
    );
    let census = runtime.census.as_ref().unwrap();
    assert_eq!(
        (
            census.rows().count(),
            census.active().count(),
            census.history().len()
        ),
        (1, 1, 0)
    );
    let active = census.active().next().unwrap();
    assert_eq!(Some(active.row.id), runtime.initial_origin);
    assert_eq!(active.row.kind, OriginKind::CurrentHeldPc);
    assert_eq!(active.row.pc, ENTRY);
    assert_eq!(active.current, &active.row.initial);
    assert_eq!(active.current.task, boot.stop.identity);
    assert_eq!(active.current.token, boot.stop.token);
    assert_eq!(active.current.registers, restored.registers);
    assert_eq!(active.current.xstate, restored.xstate);
    assert_eq!(active.current.signal_mask, restored.mask);
    assert_eq!(active.current.signal, None);
    assert_eq!(active.current.phase, StopPhase::UserCheckpoint);
    assert_eq!(census.charged(), runtime.startup.charged());
    for charge in [census.used(), census.charged()] {
        assert_eq!(
            (
                charge.epochs,
                charge.origins,
                charge.reports,
                charge.witnesses,
                charge.plan_history
            ),
            (1, 1, 0, 0, 0)
        );
        assert!(charge.source_fact_bytes >= 3 * 65536 + 2 * MAX_XSTATE + 16384);
        assert!(charge.source_fact_bytes <= DynamicAdmissionLimits::default().source_fact_bytes);
    }
    assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
    restored
}
