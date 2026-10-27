//! Additive read-only oracle for the dedicated coalesced fixture. The old
//! single-RX fixture and every old assertion remain unchanged.
use super::*;

pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn one(
    owner: &mut Owner,
    until: Instant,
) {
    super::support::one(owner, until);
}

fn same_architecture(observed: &ObservedStop, expected: &TaskStateSnapshot) {
    assert_eq!(observed.logical_pc, expected.registers.rip);
    assert_eq!(observed.registers, expected.registers);
    assert_eq!(observed.xstate, expected.xstate);
    assert_eq!(observed.signal_mask, expected.mask);
}

// Full resolved header/bytes; this borrowed view grants no native authority.
fn same_history_architecture(observed: census::ObservationView<'_>, expected: &TaskStateSnapshot) {
    assert_eq!(observed.logical_pc, expected.registers.rip);
    assert_eq!(*observed.registers, expected.registers);
    assert_eq!(observed.xstate, expected.xstate.as_slice());
    assert_eq!(observed.signal_mask, expected.mask);
}

fn complete(slot: &StateSlot) {
    assert!(slot.complete);
    for query in [
        slot.registers_request,
        slot.xstate_request,
        slot.mask_request,
    ] {
        assert_eq!(
            query,
            Some(NativeRequest {
                result: 0,
                errno: None
            })
        );
    }
    assert_eq!(slot.returned_pointer, slot.requested_pointer);
    assert_eq!(slot.returned_length, slot.state.xstate.len());
    assert!((512..MAX_XSTATE).contains(&slot.returned_length));
}

pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn check(
    owner: &Owner,
    before: &TaskStateSnapshot,
    expected: &TaskStateSnapshot,
    source: &[u8],
    baseline: &[u8],
    until: Instant,
    opened_maps: impl Fn(&[u8], &[u8]),
) {
    let ordinal = 0;
    owner
        .time_left(until, "ordinary native control observation")
        .unwrap();
    assert_eq!(state(owner.pid), *expected);
    let runtime = owner.runtime.as_ref().unwrap();
    assert_eq!(maps(owner.pid), baseline);
    assert_eq!(
        maps(owner.pid),
        runtime.sources.runtime_baseline_maps().unwrap()
    );
    assert!(runtime.pages.iter().all(|page| !page.executable));
    assert_eq!(runtime.ordinary_attempts.len(), ordinal + 1);
    assert!(runtime.selected_attempts.is_empty() && runtime.selected_pending.is_none());
    assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
    let attempt = &runtime.ordinary_attempts[ordinal];
    assert_eq!(attempt.stage, AttemptStage::Complete);
    assert!(!attempt.failed && !attempt.unwound);
    same_architecture(&attempt.before, before);
    let progress = attempt.native.progress();
    assert_eq!(progress.phase, runtime_native::InstructionPhase::Closed);
    assert!(
        progress.first_failure.is_none() && progress.instruction_completed && progress.nx_closed
    );
    assert_eq!(progress.queries_started, [true; 7]);
    let diagnostic = attempt.native.diagnostics();
    complete(&diagnostic.states[0]);
    assert_eq!(diagnostic.states[0].state, *before);
    complete(&diagnostic.states[4]);
    assert_eq!(diagnostic.states[4].state, *expected);
    complete(&diagnostic.states[8]);
    assert_eq!(diagnostic.states[8].state, *expected);
    // The actual protection requests address only the original upper page.
    // A correct final union alone would not prove this release boundary.
    for (index, protection) in [(2, libc::PROT_READ | libc::PROT_EXEC), (6, libc::PROT_READ)] {
        let registers = diagnostic.states[index].state.registers;
        assert_eq!(
            (registers.rdi, registers.rsi, registers.rdx, registers.rax),
            (ENTRY, 4096, protection as u64, 0)
        );
    }
    for index in 0..7 {
        let (tid, status) = progress.waits[index].unwrap();
        assert_eq!(tid, owner.pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        assert_eq!(status >> 16, 0);
        complete(&diagnostic.states[index + 1]);
        let signal = &diagnostic.signals[index];
        assert_eq!(
            signal.request,
            Some(NativeRequest {
                result: 0,
                errno: None
            })
        );
        let info =
            unsafe { std::ptr::read_unaligned(signal.bytes.as_ptr().cast::<libc::siginfo_t>()) };
        assert_eq!(info.si_signo, libc::SIGTRAP);
        assert_eq!(info.si_errno, 0);
        if index == 3 {
            assert_eq!(info.si_code, libc::TRAP_TRACE);
            assert_eq!(
                unsafe { info.si_addr() } as usize as u64,
                expected.registers.rip
            );
        } else {
            assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
        }
        for (request, value) in diagnostic.debug[index]
            .requests
            .iter()
            .zip(diagnostic.debug[index].values)
        {
            let request = request.unwrap();
            assert_eq!(request.errno, None);
            assert_eq!(request.result as u64, value);
        }
        let dr6 = if ordinal == 0 && index < 3 {
            0xffff_0ff0
        } else {
            0xffff_4ff0
        };
        assert_eq!(diagnostic.debug[index].values, [0, 0, 0, 0, dr6, 0]);
    }
    let effects = progress.effects();
    let mut release = 0;
    let mut private = Vec::new();
    for row in effects {
        let row = row.unwrap();
        assert!(row.complete);
        match row.effect {
            InstructionEffect::OriginalRelease => {
                release += 1;
                assert_eq!(row.result, None);
            }
            InstructionEffect::PrivateRelease { wait } => {
                private.push(wait);
                assert_eq!(
                    row.result,
                    Some(NativeRequest {
                        result: 0,
                        errno: None
                    })
                );
            }
            _ => assert_eq!(
                row.result,
                Some(NativeRequest {
                    result: 0,
                    errno: None
                })
            ),
        }
    }
    assert_eq!(release, 1);
    assert_eq!(private, [0, 1, 2, 4, 5, 6]);
    for (bytes, progress) in attempt.source.bytes.iter().zip(&attempt.source.progress) {
        assert_eq!(bytes, source);
        assert!(
            progress.started
                && progress.attempted
                && progress.complete
                && progress.failure.is_none()
        );
        assert_eq!(progress.copied_bytes, source.len());
        assert_eq!(progress.requested_bytes, source.len());
    }
    assert_eq!(
        diagnostic.maps[0].bytes(),
        runtime.sources.runtime_baseline_maps().unwrap()
    );
    assert_eq!(diagnostic.maps[3].bytes(), diagnostic.maps[0].bytes());
    assert_eq!(diagnostic.maps[4].bytes(), diagnostic.maps[0].bytes());
    assert_eq!(diagnostic.maps[2].bytes(), diagnostic.maps[1].bytes());
    opened_maps(diagnostic.maps[0].bytes(), diagnostic.maps[1].bytes());
    for map in diagnostic.maps {
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
    let opened = rows(diagnostic.maps[1].bytes());
    let fetch = opened
        .iter()
        .find(|row| row.start <= before.registers.rip && before.registers.rip < row.end)
        .unwrap();
    assert_eq!(fetch.permissions, *b"r-xp");
    assert_eq!((fetch.start, fetch.end), (ENTRY, ENTRY + 4096));
    let census = runtime.census.as_ref().unwrap();
    assert_eq!(census.rows().count(), ordinal + 2);
    assert_eq!(census.active().count(), 1);
    assert_eq!(census.history().len(), (ordinal + 1) * 7);
    let history = &census.history()[ordinal * 7..(ordinal + 1) * 7];
    let next_row = census.rows().nth(ordinal + 1).unwrap();
    let old_row = census.rows().nth(ordinal).unwrap();
    let boot = runtime.bootstrap.as_ref().unwrap().completed().unwrap();
    assert_eq!(attempt.stop, boot.stop);
    assert_eq!(old_row.initial.token, boot.stop.token);
    assert_eq!(old_row.initial.task, boot.stop.identity);
    same_architecture(&old_row.initial, before);
    let mut prior_token = attempt.stop.token.clone();
    for (i, record) in history.iter().enumerate() {
        let record = census.history_view(record).unwrap();
        if i == 3 {
            assert!(
                matches!(&record, census::HistoryView::Consumed { origin, .. } if *origin == old_row.id)
            );
            let census::HistoryView::Consumed { evidence, .. } = record else {
                unreachable!("checked resolved consumption");
            };
            assert_eq!(evidence.before.token, &prior_token);
            same_history_architecture(evidence.before, before);
            assert_eq!(
                evidence.successor,
                census::ObservationView::of(&next_row.initial)
            );
            assert!(next_row.initial.token.sequence > prior_token.sequence);
            assert_eq!(next_row.initial.task, attempt.stop.identity);
            assert_eq!(next_row.initial.token.session, owner.session);
            same_architecture(&next_row.initial, expected);
            prior_token = next_row.initial.token.clone();
            continue;
        }
        let census::HistoryView::Refreshed {
            before: from,
            after: to,
            ..
        } = record
        else {
            panic!("missing actual private checkpoint");
        };
        if i < 3 {
            same_history_architecture(from, before);
            same_history_architecture(to, before);
        } else {
            same_history_architecture(from, expected);
            same_history_architecture(to, expected);
        }
        assert_eq!(from.task, attempt.stop.identity);
        assert_eq!(to.task, attempt.stop.identity);
        assert_eq!(from.token.tid, owner.pid);
        assert_eq!(to.token.tid, owner.pid);
        assert_eq!(from.token.task, attempt.stop.token.task);
        assert_eq!(to.token.task, attempt.stop.token.task);
        assert_eq!(to.token.session, owner.session);
        assert_eq!(from.token, &prior_token);
        assert!(to.token.sequence > prior_token.sequence);
        prior_token = (*to.token).clone();
        assert_eq!(to.phase, StopPhase::UserCheckpoint);
        assert_eq!(to.signal, None);
    }
    let active = census.active().next().unwrap();
    assert_eq!(
        prior_token, active.current.token,
        "last retained private checkpoint must be the active current token"
    );
    assert_eq!(Some(active.row.id), runtime.initial_origin);
    assert_ne!(active.row.id, census.rows().nth(ordinal).unwrap().id);
    same_architecture(active.current, expected);
    same_architecture(&active.row.initial, expected);
    assert!(matches!(
        active.row.initial.phase,
        StopPhase::OwnedOrdinaryComplete { .. }
    ));
    assert_eq!(
        active.row.initial.signal.as_ref().unwrap().raw,
        diagnostic.signals[3].bytes
    );
    assert_eq!(active.current.phase, StopPhase::UserCheckpoint);
    assert_eq!(active.current.signal, None);
    let stop = runtime
        .native
        .as_ref()
        .unwrap()
        .admission_current(active.current.task.task)
        .unwrap();
    assert_eq!(stop.token, active.current.token);
    assert_eq!(prior_token, stop.token);
    assert_eq!(stop.identity, active.current.task);
    assert_eq!(stop, *attempt.native.completed().unwrap().final_stop());
    for usage in [census.used(), census.charged()] {
        assert_eq!(
            (
                usage.epochs,
                usage.origins,
                usage.reports,
                usage.witnesses,
                usage.plan_history
            ),
            (1, ordinal + 2, 0, (ordinal + 1) * 7, 0)
        );
        assert!(usage.source_fact_bytes > 0 && usage.source_fact_bytes <= 64 * 1024 * 1024);
    }
    owner
        .time_left(until, "ordinary native control observation complete")
        .unwrap();
}
