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
