use super::*;
use std::cell::{Cell, RefCell};

#[test]
fn exact_initial_exec_entry_sequence() {
    let mut m = Machine::new();
    assert_eq!(m.phase(), Phase::Initial);
    m.advance(Event::InitialStop).unwrap();
    assert_eq!(m.phase(), Phase::Exec);
    m.advance(Event::ExecStop).unwrap();
    assert_eq!(m.phase(), Phase::Entry);
    m.advance(Event::EntryTrap).unwrap();
    assert_eq!(m.phase(), Phase::Observed);
}
#[test]
fn every_out_of_order_transition_refuses_without_advancing() {
    let phases = [Phase::Initial, Phase::Exec, Phase::Entry, Phase::Observed];
    let events = [Event::InitialStop, Event::ExecStop, Event::EntryTrap];
    for phase in phases {
        for event in events {
            let permitted = matches!(
                (phase, event),
                (Phase::Initial, Event::InitialStop)
                    | (Phase::Exec, Event::ExecStop)
                    | (Phase::Entry, Event::EntryTrap)
            );
            let mut m = Machine { phase };
            if !permitted {
                assert_eq!(m.advance(event), Err(Error::Event));
                assert_eq!(m.phase(), phase);
            }
        }
    }
}

struct Fake {
    words: RefCell<[u64; 3]>,
    writes: RefCell<Vec<(usize, u64)>>,
    fail_write: Cell<Option<usize>>,
    count: Cell<usize>,
}
impl Fake {
    fn new() -> Self {
        Self {
            words: RefCell::new([0x77, 0xffff0ff0, 0x400]),
            writes: RefCell::new(Vec::new()),
            fail_write: Cell::new(None),
            count: Cell::new(0),
        }
    }
    fn index(r: DebugReg) -> usize {
        match r {
            DebugReg::Address => 0,
            DebugReg::Status => 1,
            DebugReg::Control => 2,
        }
    }
}
impl DebugIo for Fake {
    fn read(&self, reg: DebugReg) -> Result<u64> {
        Ok(self.words.borrow()[Self::index(reg)])
    }
    fn write(&self, reg: DebugReg, value: u64) -> Result<()> {
        let at = self.count.get();
        self.count.set(at + 1);
        self.writes.borrow_mut().push((Self::index(reg), value));
        if self.fail_write.get() == Some(at) {
            return Err(Error::Io(5));
        }
        self.words.borrow_mut()[Self::index(reg)] = value;
        Ok(())
    }
}
#[test]
fn typed_debug_offsets_are_only_0_6_7() {
    let base = core::mem::offset_of!(libc::user, u_debugreg);
    assert_eq!(DebugReg::Address.offset(), base);
    assert_eq!(DebugReg::Status.offset(), base + 48);
    assert_eq!(DebugReg::Control.offset(), base + 56);
}
#[test]
fn debug_arms_one_execute_slot_and_restores_every_saved_bit() {
    let io = Fake::new();
    let saved = *io.words.borrow();
    let mut owned = DebugOwner::capture(&io).unwrap();
    owned.arm(0x401000).unwrap();
    assert_eq!(io.words.borrow()[0], 0x401000);
    assert_eq!(io.words.borrow()[2] & (0xff | (15 << 16)), 1);
    io.words.borrow_mut()[1] |= 1;
    owned.cause().unwrap();
    owned.restore().unwrap();
    assert_eq!(*io.words.borrow(), saved);
    assert!(!owned.dirty);
}
#[test]
fn every_enabled_slot_and_global_debug_owner_refuses_before_writing() {
    for bit in [0, 1, 2, 3, 4, 5, 6, 7, 13] {
        let io = Fake::new();
        io.words.borrow_mut()[2] |= 1 << bit;
        assert!(matches!(DebugOwner::capture(&io), Err(Error::DebugOwner)));
        assert!(io.writes.borrow().is_empty());
    }
}
#[test]
fn each_arm_write_failure_retains_restoration_duty() {
    for failure in 0..4 {
        let io = Fake::new();
        let saved = *io.words.borrow();
        let mut owned = DebugOwner::capture(&io).unwrap();
        io.fail_write.set(Some(failure));
        assert_eq!(owned.arm(0x401000), Err(Error::Io(5)));
        assert!(owned.dirty);
        io.fail_write.set(None);
        owned.restore().unwrap();
        assert_eq!(*io.words.borrow(), saved);
    }
}
#[test]
fn each_restore_failure_is_an_error_even_if_final_words_match() {
    for failure in 0..4 {
        let io = Fake::new();
        let mut owned = DebugOwner::capture(&io).unwrap();
        owned.arm(0x401000).unwrap();
        let prior = io.count.get();
        io.fail_write.set(Some(prior + failure));
        assert_eq!(owned.restore(), Err(Error::Readback));
        assert_eq!(io.count.get(), prior + 4);
        assert!(owned.dirty);
    }
}
#[test]
fn unrelated_dr6_cause_never_counts_as_owned_b0() {
    for cause in [0, 2, 3, 4, 8, 1 | (1 << 13), 1 | (1 << 14), 1 | (1 << 15)] {
        let io = Fake::new();
        let owned = DebugOwner::capture(&io).unwrap();
        let old = io.words.borrow()[1];
        io.words.borrow_mut()[1] = (old & !CAUSES) | cause;
        assert_eq!(owned.cause(), Err(Error::Event));
    }
}
#[test]
fn exact_stop_signal_and_event_are_required() {
    let stopped = |sig, event| 0x7f | (sig << 8) | (event << 16);
    assert!(super::stopped(
        stopped(libc::SIGTRAP, libc::PTRACE_EVENT_EXEC),
        libc::SIGTRAP,
        libc::PTRACE_EVENT_EXEC
    ));
    assert!(!super::stopped(
        stopped(libc::SIGTRAP, 0),
        libc::SIGTRAP,
        libc::PTRACE_EVENT_EXEC
    ));
    assert!(!super::stopped(
        stopped(libc::SIGTRAP, libc::PTRACE_EVENT_EXEC),
        libc::SIGTRAP,
        0
    ));
    assert!(!super::stopped(stopped(libc::SIGILL, 0), libc::SIGTRAP, 0));
    assert!(!super::stopped(0, libc::SIGTRAP, 0));
}
#[test]
fn auxv_unique_required_entry_base_and_exact_terminator() {
    let encode = |rows: &[(u64, u64)]| {
        rows.iter()
            .flat_map(|(a, b)| a.to_ne_bytes().into_iter().chain(b.to_ne_bytes()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        auxv(&encode(&[(9, 0x401000), (7, 0x70000000), (0, 0)])),
        Ok((0x401000, 0x70000000))
    );
    for rows in [
        vec![(9, 1), (9, 2), (7, 3), (0, 0)],
        vec![(9, 1), (0, 0)],
        vec![(9, 1), (7, 2)],
        vec![(9, 1), (7, 2), (0, 1)],
        vec![(9, 1), (7, 2), (0, 0), (1, 2)],
    ] {
        assert_eq!(auxv(&encode(&rows)), Err(Error::Shape));
    }
}
#[test]
fn maps_preserve_inode_and_permissions_and_refuse_overlap() {
    let raw = b"00400000-00401000 r--p 00000000 08:01 4 /package/main\n00401000-00402000 r-xp 00001000 08:01 4 /package/main\n";
    let maps = parse_maps(raw).unwrap();
    assert_eq!(maps.len(), 2);
    assert_eq!(
        (
            maps[1].start,
            maps[1].offset,
            maps[1].inode,
            maps[1].permissions
        ),
        (0x401000, 4096, 4, *b"r-xp")
    );
    assert!(matches!(
        parse_maps(b"00400000-00402000 r--p 0 08:01 4\n00401000-00403000 r-xp 1000 08:01 4\n"),
        Err(Error::Shape)
    ));
    assert!(matches!(
        parse_maps(b"00400000-00401000 r--s 0 08:01 4\n"),
        Err(Error::Shape)
    ));
}
#[test]
fn event_address_and_control_are_owned_not_merely_b0() {
    let io = Fake::new();
    let mut owned = DebugOwner::capture(&io).unwrap();
    owned.arm(0x401000).unwrap();
    io.words.borrow_mut()[1] |= 1;
    owned.event_at(0x401000).unwrap();
    io.words.borrow_mut()[0] = 0x402000;
    assert_eq!(owned.event_at(0x401000), Err(Error::DebugOwner));
    io.words.borrow_mut()[0] = 0x401000;
    io.words.borrow_mut()[2] |= 4;
    assert_eq!(owned.event_at(0x401000), Err(Error::DebugOwner));
    owned.restore().unwrap();
}

#[test]
fn child_free_requires_exact_echild_without_consuming_harness_children() {
    assert_eq!(
        child_wait_result(-1, libc::ECHILD, 0, 0).and_then(require_child_free),
        Ok(())
    );
    for error in [0, libc::EINTR, libc::EINVAL, libc::ESRCH] {
        assert_eq!(child_wait_result(-1, error, 0, 0), Err(Error::Io(error)));
    }
    assert_eq!(child_wait_result(1, libc::ECHILD, 0, 0), Err(Error::Child));
}

#[test]
fn child_wait_no_event_is_pending_even_with_stale_echild_errno() {
    for error in [0, libc::ECHILD] {
        let wait = child_wait_result(0, error, 0, 0).unwrap();
        assert_eq!(wait, ChildWait::Pending);
        assert_eq!(require_child_free(wait), Err(Error::Child));
    }
    assert_eq!(
        child_wait_result(0, 0, 0, libc::CLD_EXITED),
        Err(Error::Child)
    );
}

#[test]
fn every_owned_event_stays_pending_for_preflight_and_retains_cleanup_identity() {
    for code in [
        libc::CLD_EXITED,
        libc::CLD_KILLED,
        libc::CLD_DUMPED,
        libc::CLD_TRAPPED,
        libc::CLD_STOPPED,
        libc::CLD_CONTINUED,
    ] {
        let wait = child_wait_result(0, libc::ECHILD, 17, code).unwrap();
        assert_eq!(wait, ChildWait::Event { pid: 17, code });
        assert_eq!(require_child_free(wait), Err(Error::Child));
    }
    for (pid, code) in [(-1, libc::CLD_EXITED), (17, 0), (17, -1), (17, 999)] {
        assert_eq!(child_wait_result(0, 0, pid, code), Err(Error::Child));
    }
}

#[test]
fn child_wait_flags_are_nonconsuming_nonblocking_and_include_all_child_kinds() {
    assert_eq!(
        CHILD_WAIT_FLAGS,
        libc::WEXITED
            | libc::WSTOPPED
            | libc::WCONTINUED
            | libc::WNOHANG
            | libc::WNOWAIT
            | libc::__WALL
    );
}

#[test]
fn cleanup_keeps_exact_terminal_status_and_requires_direct_reaping_before_deadline() {
    let mut evidence = CleanupEvidence {
        direct_pid: Some(17),
        ..CleanupEvidence::default()
    };
    assert_eq!(evidence.finish(false, false), Err(Error::Cleanup));
    assert_eq!(evidence.finish(true, false), Err(Error::Cleanup));
    evidence.note_terminal(17, libc::SIGKILL).unwrap();
    assert_eq!(evidence.terminal_statuses, [(17, libc::SIGKILL)]);
    assert_eq!(evidence.finish(true, false), Ok(()));
    assert_eq!(evidence.finish(false, false), Err(Error::Cleanup));
    assert_eq!(evidence.finish(true, true), Err(Error::Cleanup));
    assert_eq!(evidence.note_terminal(17, 0x137f), Err(Error::Cleanup));
    assert_eq!(evidence.terminal_statuses, [(17, libc::SIGKILL)]);
}

#[test]
fn unexpected_descendant_refuses_even_after_all_terminal_statuses_are_retained() {
    let mut evidence = CleanupEvidence {
        direct_pid: Some(17),
        ..CleanupEvidence::default()
    };
    evidence.note_event(18);
    assert!(evidence.unexpected_child);
    evidence.note_terminal(17, libc::SIGKILL).unwrap();
    assert_eq!(evidence.finish(true, false), Err(Error::Cleanup));
    evidence.note_terminal(18, 7 << 8).unwrap();
    assert_eq!(
        evidence.terminal_statuses,
        [(17, libc::SIGKILL), (18, 7 << 8)]
    );
    assert_eq!(evidence.finish(true, false), Err(Error::Cleanup));
}

#[test]
fn unknown_owner_and_unbounded_terminal_population_never_complete_cleanup() {
    let mut unknown = CleanupEvidence::default();
    unknown.note_terminal(17, libc::SIGKILL).unwrap();
    assert!(unknown.unexpected_child);
    assert_eq!(unknown.finish(true, false), Err(Error::Cleanup));
    let mut bounded = CleanupEvidence {
        direct_pid: Some(17),
        ..CleanupEvidence::default()
    };
    for _ in 0..4096 {
        bounded.note_terminal(17, libc::SIGKILL).unwrap();
    }
    assert_eq!(
        bounded.note_terminal(17, libc::SIGKILL),
        Err(Error::Cleanup)
    );
    assert_eq!(bounded.terminal_statuses.len(), 4096);
    assert_eq!(bounded.finish(true, false), Err(Error::Cleanup));
}

#[test]
fn cleanup_and_drop_share_one_unchanged_five_second_deadline() {
    let saved = Cell::new(None);
    let began = Instant::now();
    let end = cleanup_deadline(&saved, began);
    assert_eq!(end.duration_since(began), Duration::from_secs(5));
    assert_eq!(
        cleanup_deadline(&saved, began + Duration::from_secs(2)),
        end
    );
    let later = began + Duration::from_secs(7);
    assert_eq!(cleanup_deadline(&saved, later), end);
    assert!(later >= end);
}
