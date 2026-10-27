//! Literal architecture and full-byte comparisons. Production validators are
//! deliberately not used to generate expected CALL/RET effects or map rows.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::acquire::{
    StackCaptureAssociation, StackWordView,
};

pub(super) fn setup(before: &TaskStateSnapshot, ordinal: usize) -> TaskStateSnapshot {
    let mut after = before.clone();
    after.registers.orig_rax = u64::MAX;
    match ordinal {
        0 => {
            let value = before.registers.rsp & !4095;
            after.registers.rsp = value;
            after.registers.rip += 7;
            // AND clears CF/OF, defines SF/ZF/PF; literal nonzero canonical
            // page address has low byte zero, hence PF=1, SF=ZF=0. AF is
            // architecturally undefined: this fixture requires actual x86
            // result AF=0, independently observed in the raw lane.
            after.registers.eflags = (before.registers.eflags & !0x8d5) | 4;
        }
        1 => {
            assert_eq!(before.registers.rsp & 4095, 0);
            after.registers.rsp += 4;
            after.registers.rip += 4;
            after.registers.eflags = before.registers.eflags & !0x8d5;
        }
        _ => panic!("unexpected literal stack setup instruction"),
    }
    after
}
pub(super) fn successor(before: &TaskStateSnapshot, target: u64, call: bool) -> TaskStateSnapshot {
    let mut after = before.clone();
    after.registers.rip = target;
    after.registers.orig_rax = u64::MAX;
    after.registers.rsp = if call {
        before.registers.rsp.checked_sub(8).unwrap()
    } else {
        before.registers.rsp.checked_add(8).unwrap()
    };
    after
}
pub(super) fn stack_effect(before: &[u8], start: u64, rsp: u64, next: u64, call: bool) -> Vec<u8> {
    let mut after = before.to_vec();
    if call {
        let offset = usize::try_from(rsp.checked_sub(8).unwrap() - start).unwrap();
        after[offset..offset + 8].copy_from_slice(&next.to_le_bytes());
    }
    after
}
pub(super) fn raw_step(observed: &raw::Step, pc: u64, target: u64, next: u64, call: bool) {
    assert_eq!(observed.before.registers.rip, pc);
    assert_eq!(observed.after, successor(&observed.before, target, call));
    assert_eq!(
        observed.signal,
        (libc::SIGTRAP, 0, libc::TRAP_TRACE, target)
    );
    assert_eq!(
        observed.stack_after,
        stack_effect(
            &observed.stack_before,
            observed.stack_start,
            observed.before.registers.rsp,
            next,
            call
        )
    );
    assert_ne!(observed.after.registers.r12, MARK);
    assert!(!observed.maps.is_empty());
}
pub(super) fn slot(slot: &StateSlot) {
    assert!(slot.complete);
    for actual in [
        slot.registers_request,
        slot.xstate_request,
        slot.mask_request,
    ] {
        assert_eq!(
            actual,
            Some(NativeRequest {
                result: 0,
                errno: None
            })
        );
    }
    assert_eq!(slot.requested_pointer, slot.state.xstate.as_ptr() as usize);
    assert_eq!(slot.returned_pointer, slot.requested_pointer);
    assert_eq!(slot.returned_length, slot.state.xstate.len());
    assert!((512..MAX_XSTATE).contains(&slot.returned_length));
    assert_eq!(slot.state.xstate.capacity(), MAX_XSTATE);
}
fn file(
    capture: &crate::linux::remote::dynamic::owner::admission::runtime_stack::storage::FileCapture,
    bytes: &Vec<u8>,
) -> Vec<u8> {
    assert!(capture.started && capture.complete && !capture.overflow);
    assert_eq!(capture.first_failure, None);
    assert_eq!(bytes.len(), MAX_XSTATE);
    assert_eq!(bytes.capacity(), MAX_XSTATE);
    assert!((1..=MAX_XSTATE).contains(&capture.copied));
    assert!((2..=MAX_XSTATE + 1).contains(&capture.read_calls));
    let first = capture.first_read.unwrap();
    let last = capture.last_read.unwrap();
    assert_eq!(first.count, MAX_XSTATE);
    assert_eq!(first.destination, bytes.as_ptr() as usize);
    assert!(first.request.result > 0 && first.request.result <= MAX_XSTATE as i64);
    assert_eq!(first.request.errno, None);
    assert_eq!(
        last.request,
        NativeRequest {
            result: 0,
            errno: None
        }
    );
    assert_eq!(capture.file_open.unwrap().result, i64::from(first.fd));
    assert_eq!(last.fd, first.fd);
    for request in [
        capture.directory_statfs,
        capture.file_statfs,
        capture.file_close,
        capture.directory_close,
    ] {
        assert_eq!(
            request,
            Some(NativeRequest {
                result: 0,
                errno: None
            })
        );
    }
    assert_eq!(capture.directory_filesystem, Some(libc::PROC_SUPER_MAGIC));
    assert_eq!(capture.file_filesystem, Some(libc::PROC_SUPER_MAGIC));
    bytes[..capture.copied].to_vec()
}
/// Exact independent projection of the literal original two-page RX source.
/// Every unrelated row/suffix remains byte-identical; no production parser or
/// FetchGeometry comparator is consulted.
pub(super) fn opened(baseline: &[u8], actual: &[u8], pc: u64, length: usize) {
    let low = pc & !4095;
    let high = (pc + length as u64 - 1) & !4095;
    let end = high + 4096;
    let mut expected = Vec::new();
    let mut found = 0;
    for row in rows(baseline) {
        if row.start == BASE && row.end == BASE + 8192 {
            found += 1;
            assert_eq!(row.permissions, *b"r--p");
            let first_space = row.raw.iter().position(|b| *b == b' ').unwrap();
            let offset_start = first_space + 6;
            let offset_end = offset_start
                + row.raw[offset_start..]
                    .iter()
                    .position(|b| *b == b' ')
                    .unwrap();
            assert_eq!(
                u64::from_str_radix(
                    std::str::from_utf8(&row.raw[offset_start..offset_end]).unwrap(),
                    16
                )
                .unwrap(),
                0
            );
            for (start, stop, permission) in [
                (BASE, low, *b"r--p"),
                (low, end, *b"r-xp"),
                (end, BASE + 8192, *b"r--p"),
            ] {
                if start == stop {
                    continue;
                }
                assert!(start < stop && BASE <= start && stop <= BASE + 8192);
                expected.extend_from_slice(format!("{start:08x}-{stop:08x} ").as_bytes());
                expected.extend_from_slice(&permission);
                expected.push(b' ');
                expected.extend_from_slice(format!("{:08x}", start - BASE).as_bytes());
                expected.extend_from_slice(&row.raw[offset_end..]);
                expected.push(b'\n');
            }
        } else {
            expected.extend_from_slice(&row.raw);
            expected.push(b'\n');
        }
    }
    assert_eq!(found, 1);
    assert_eq!(actual, expected);
}
pub(super) fn word(
    view: StackWordView<'_>,
    expected: &TaskStateSnapshot,
    expected_maps: &[u8],
    expected_envelope: &[u8],
    envelope_start: u64,
) {
    assert!(view.complete);
    assert_eq!(view.first_failure, None);
    let observation = view.observation;
    slot(&observation.state);
    assert_eq!(observation.state.state, *expected);
    assert_eq!(
        file(&observation.maps_capture, &observation.maps),
        expected_maps
    );
    let smaps = file(&observation.smaps_capture, &observation.smaps);
    assert!(!smaps.is_empty());
    assert!(view.word.complete);
    assert_eq!(view.word.copied, expected_envelope.len());
    assert_eq!(
        &view.word.bytes[..expected_envelope.len()],
        expected_envelope
    );
    assert!(
        view.word.bytes[expected_envelope.len()..]
            .iter()
            .all(|b| *b == 0)
    );
    for index in 0..2 {
        if index * 8 >= expected_envelope.len() {
            assert_eq!(view.word.peek[index], None);
            continue;
        }
        let peek = view.word.peek[index].unwrap();
        assert_eq!(peek.address, envelope_start + 8 * index as u64);
        assert_eq!(peek.request.errno, None);
        assert_eq!(
            peek.request.result as u64,
            u64::from_le_bytes(
                expected_envelope[index * 8..index * 8 + 8]
                    .try_into()
                    .unwrap()
            )
        );
    }
    let pagemap = &view.word.pagemap;
    let pages = ((envelope_start + expected_envelope.len() as u64 - 1) / 4096
        - envelope_start / 4096
        + 1) as usize;
    assert_eq!(pagemap.offset, (envelope_start / 4096) * 8);
    assert_eq!(pagemap.requested, pages * 8);
    assert_eq!(pagemap.copied, pages * 8);
    assert_eq!(
        pagemap.request,
        Some(NativeRequest {
            result: (pages * 8) as i64,
            errno: None
        })
    );
    for entry in pagemap.bytes[..pagemap.copied].chunks_exact(8) {
        let bits = u64::from_le_bytes(entry.try_into().unwrap());
        assert_eq!(bits & ((1 << 63) | (1 << 56)), (1 << 63) | (1 << 56));
        assert_eq!(
            bits & !((1 << 63) | (1 << 56) | (1 << 55) | ((1 << 55) - 1)),
            0
        );
    }
    let access = view.pagemap_access;
    assert!(access.started && access.complete);
    assert_eq!(access.first_failure, None);
    assert_eq!(access.file_open.unwrap().result, i64::from(pagemap.fd));
    for query in [
        access.directory_statfs,
        access.file_statfs,
        access.file_close,
        access.directory_close,
    ] {
        assert_eq!(
            query,
            Some(NativeRequest {
                result: 0,
                errno: None
            })
        );
    }
    assert_eq!(access.directory_filesystem, Some(libc::PROC_SUPER_MAGIC));
    assert_eq!(access.file_filesystem, Some(libc::PROC_SUPER_MAGIC));
}
pub(super) struct CompletionExpected<'a> {
    pub(super) before: &'a TaskStateSnapshot,
    pub(super) after: &'a TaskStateSnapshot,
    pub(super) stack_before: &'a [u8],
    pub(super) ordinal: usize,
    pub(super) call: bool,
    pub(super) next: u64,
}
pub(super) fn completed(
    owner: &Owner,
    original: &Before,
    expectation: CompletionExpected<'_>,
    until: Instant,
) {
    let CompletionExpected {
        before,
        after: expected,
        stack_before,
        ordinal,
        call,
        next,
    } = expectation;
    support::held(owner, until);
    assert_eq!(state(owner.pid), *expected);
    original.require_source(owner, until);
    let stack_expected = stack_effect(
        stack_before,
        original.stack_range.start,
        before.registers.rsp,
        next,
        call,
    );
    assert_eq!(original.read_stack(owner, until), stack_expected);
    let runtime = owner.runtime.as_ref().unwrap();
    let stack = runtime.stack.as_ref().unwrap();
    let attempt = stack.attempts[ordinal].as_ref().unwrap();
    assert_eq!(stack.count, ordinal + 1);
    assert!(stack.failure.is_none() && stack.settlement_failure.is_none());
    assert_eq!(attempt.stage, AttemptStage::Complete);
    assert!(attempt.failure.is_none() && attempt.settlement_failure.is_none());
    assert!(attempt.allocated);
    assert!(attempt.settled > 0);
    assert_eq!(attempt.before.registers, before.registers);
    assert_eq!(attempt.before.xstate, before.xstate);
    assert_eq!(attempt.before.signal_mask, before.mask);
    let progress = attempt.native.progress();
    assert_eq!(progress.phase, runtime_stack_native::StackPhase::Closed);
    assert!(
        progress.first_failure.is_none() && progress.instruction_completed && progress.nx_closed
    );
    assert_eq!(progress.queries_started, [true; 7]);
    assert!(!progress.failed_held_attempted);
    let native = attempt.native.diagnostics();
    assert!(native.claimed);
    assert_eq!(native.states[0].state, *before);
    assert_eq!(native.states[4].state, *expected);
    for state in native.states {
        slot(state);
    }
    let baseline = runtime.sources.runtime_baseline_maps().unwrap();
    assert_eq!(maps(owner.pid), baseline);
    let length = if call { 5 } else { 1 };
    for (index, map) in native.maps.into_iter().enumerate() {
        let map = map.unwrap();
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
        if matches!(index, 1 | 2) {
            opened(baseline, map.bytes(), before.registers.rip, length);
        } else {
            assert_eq!(map.bytes(), baseline);
        }
    }
    for index in 0..7 {
        let (tid, status) = progress.waits[index].unwrap();
        assert_eq!(tid, owner.pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        assert_eq!(status >> 16, 0);
        let signal = &native.signals[index];
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
        for (request, value) in native.debug[index]
            .requests
            .iter()
            .zip(native.debug[index].values)
        {
            let request = request.unwrap();
            assert_eq!(request.errno, None);
            assert_eq!(request.result as u64, value);
        }
        assert_eq!(&native.debug[index].values[..4], &[0; 4]);
        assert_eq!(native.debug[index].values[5], 0);
        assert_eq!(
            native.debug[index].values[4],
            if index >= 3 {
                0xffff_4ff0
            } else {
                native.profile.debug.values[4]
            }
        );
    }
    // These are actual private wait register records: literal mprotect range
    // comes from the encoding, including crossing versus boundary distinction.
    let start = before.registers.rip & !4095;
    let end = (before.registers.rip + length as u64 - 1) & !4095;
    for (index, protection) in [(1, 5), (5, 1)] {
        let regs = native.states[index + 1].state.registers;
        assert_eq!(
            (regs.rdi, regs.rsi, regs.rdx),
            (start, end + 4096 - start, protection)
        );
        assert_eq!(regs.rax, 0);
    }
    let mut releases = Vec::new();
    let mut originals = 0;
    for record in progress.effects() {
        let record = record.unwrap();
        assert!(record.complete);
        match record.effect {
            InstructionEffect::OriginalRelease => {
                originals += 1;
                assert_eq!(record.result, None);
            }
            InstructionEffect::PrivateRelease { wait } => {
                releases.push(wait);
                assert_eq!(
                    record.result,
                    Some(NativeRequest {
                        result: 0,
                        errno: None
                    })
                );
            }
            _ => assert_eq!(
                record.result,
                Some(NativeRequest {
                    result: 0,
                    errno: None
                })
            ),
        }
    }
    assert_eq!(releases, [0, 1, 2, 4, 5, 6]);
    assert_eq!(originals, 1);
    let operand = attempt.operand.operand().unwrap();
    let description = operand.description();
    let geometry = &description.geometry;
    assert_eq!(geometry.pc, before.registers.rip);
    assert_eq!(description.target, expected.registers.rip);
    assert_eq!(geometry.original_rsp, before.registers.rsp);
    let offset = usize::try_from(geometry.envelope.start - original.stack_range.start).unwrap();
    let n = geometry.envelope_length();
    let opened_maps = native.maps[1].unwrap().bytes();
    word(
        attempt.operand.view(),
        before,
        baseline,
        &stack_before[offset..offset + n],
        geometry.envelope.start,
    );
    word(
        native.words[0],
        before,
        opened_maps,
        &stack_before[offset..offset + n],
        geometry.envelope.start,
    );
    word(
        native.words[1],
        expected,
        opened_maps,
        &stack_expected[offset..offset + n],
        geometry.envelope.start,
    );
    word(
        native.words[2],
        expected,
        baseline,
        &stack_expected[offset..offset + n],
        geometry.envelope.start,
    );
    let initial = native.initial.unwrap();
    assert_eq!(initial, &attempt.stop);
    let mut previous = initial;
    for (index, stop) in native.stops.iter().enumerate() {
        let stop = stop.as_ref().unwrap();
        assert_eq!(stop.identity, initial.identity);
        assert_eq!(stop.token.session, initial.token.session);
        assert_eq!(stop.token.tid, initial.token.tid);
        assert_eq!(stop.token.task, initial.token.task);
        assert!(stop.token.sequence > previous.token.sequence);
        assert_eq!(stop.signal, None);
        assert_eq!(
            stop.phase,
            if index == 3 {
                AdmissionPhase::NativeCompleted
            } else {
                AdmissionPhase::Restored
            }
        );
        previous = stop;
    }
    match native.words[0].association.unwrap() {
        StackCaptureAssociation::B { stop, until: bound } => {
            assert_eq!(stop, native.stops[2].as_ref().unwrap());
            assert_eq!(*bound, until);
        }
        _ => panic!("B association differs"),
    }
    match native.words[1].association.unwrap() {
        StackCaptureAssociation::C {
            original,
            raw_wait,
            ordinal,
            until: bound,
        } => {
            assert_eq!(original, native.stops[2].as_ref().unwrap());
            assert_eq!(*raw_wait, progress.waits[3].unwrap());
            assert_eq!(*ordinal, 3);
            assert_eq!(*bound, until);
        }
        _ => panic!("C association differs"),
    }
    match native.words[2].association.unwrap() {
        StackCaptureAssociation::D { stop, until: bound } => {
            assert_eq!(stop, native.stops[6].as_ref().unwrap());
            assert_eq!(*bound, until);
        }
        _ => panic!("D association differs"),
    }
    let census = runtime.census.as_ref().unwrap();
    let current = census
        .current_observation(runtime.initial_origin.unwrap())
        .unwrap();
    assert_eq!(current.token, previous.token);
    assert_eq!(current.task, previous.identity);
    assert_eq!(current.registers, expected.registers);
    assert_eq!(current.xstate, expected.xstate);
    assert_eq!(current.signal_mask, expected.mask);
    assert_eq!(
        runtime
            .native
            .as_ref()
            .unwrap()
            .admission_current(current.task.task)
            .unwrap(),
        *previous
    );
    assert!(runtime.pages.iter().all(|page| !page.executable));
    assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
    for (bytes, progress) in attempt.source.bytes.iter().zip(&attempt.source.progress) {
        assert_eq!(*bytes, original.source);
        assert!(progress.complete && progress.failure.is_none());
        assert_eq!(progress.copied_bytes, 8192);
        assert_eq!(progress.requested_bytes, 8192);
    }
}
