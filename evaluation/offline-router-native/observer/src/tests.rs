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

fn kernel_basis_fixture() -> KernelBasis {
    KernelBasis {
        profile: KERNEL_BASIS_PROFILE.to_owned(),
        basis_sha256: [1; 32],
        release: "kernel-release".to_owned(),
        config_gzip_bytes: 3,
        config_gzip_sha256: Sha256::digest(b"cfg").into(),
        config_decoded_bytes: 12,
        config_decoded_sha256: [2; 32],
    }
}
#[test]
fn kernel_basis_requires_the_one_explicit_mode_and_exact_bounds() {
    let good = kernel_basis_fixture();
    assert_eq!(good.validate(), Ok(()));
    for n in [0, KERNEL_GZIP_CAP as u32 + 1] {
        let mut bad = good.clone();
        bad.config_gzip_bytes = n;
        assert_eq!(bad.validate(), Err(Error::Shape));
    }
    for n in [0, KERNEL_DECODED_CAP as u32 + 1] {
        let mut bad = good.clone();
        bad.config_decoded_bytes = n;
        assert_eq!(bad.validate(), Err(Error::Shape));
    }
    for release in [
        "".to_owned(),
        "x".repeat(129),
        "kernel\nrelease".to_owned(),
        "kernel\0release".to_owned(),
        "kérnel".to_owned(),
    ] {
        let mut bad = good.clone();
        bad.release = release;
        assert_eq!(bad.validate(), Err(Error::Shape));
    }
    let mut bad = good.clone();
    bad.profile.push_str("-fallback");
    assert_eq!(bad.validate(), Err(Error::Shape));
    let mut edge = good;
    edge.release = "x".repeat(128);
    edge.config_gzip_bytes = KERNEL_GZIP_CAP as u32;
    edge.config_decoded_bytes = KERNEL_DECODED_CAP as u32;
    assert_eq!(edge.validate(), Ok(()));
}
#[test]
fn kernel_live_config_requires_whole_bytes_procfs_and_exact_uname() {
    let good = kernel_basis_fixture();
    assert_eq!(
        kernel_config_matches(
            &good,
            b"cfg",
            true,
            true,
            "Linux",
            "kernel-release",
            "x86_64"
        ),
        Ok(())
    );
    for (raw, procfs, regular, system, release, machine) in [
        (
            b"cf".as_slice(),
            true,
            true,
            "Linux",
            "kernel-release",
            "x86_64",
        ),
        (
            b"cfgx".as_slice(),
            true,
            true,
            "Linux",
            "kernel-release",
            "x86_64",
        ),
        (
            b"cFg".as_slice(),
            true,
            true,
            "Linux",
            "kernel-release",
            "x86_64",
        ),
        (
            b"cfg".as_slice(),
            false,
            true,
            "Linux",
            "kernel-release",
            "x86_64",
        ),
        (
            b"cfg".as_slice(),
            true,
            false,
            "Linux",
            "kernel-release",
            "x86_64",
        ),
        (
            b"cfg".as_slice(),
            true,
            true,
            "Other",
            "kernel-release",
            "x86_64",
        ),
        (
            b"cfg".as_slice(),
            true,
            true,
            "Linux",
            "other-release",
            "x86_64",
        ),
        (
            b"cfg".as_slice(),
            true,
            true,
            "Linux",
            "kernel-release",
            "i686",
        ),
    ] {
        assert_eq!(
            kernel_config_matches(&good, raw, procfs, regular, system, release, machine),
            Err(Error::Custody)
        );
    }
    let mut bad = good;
    bad.config_gzip_sha256[0] ^= 1;
    assert_eq!(
        kernel_config_matches(
            &bad,
            b"cfg",
            true,
            true,
            "Linux",
            "kernel-release",
            "x86_64"
        ),
        Err(Error::Custody)
    );
}
#[test]
fn config_off_query_never_accepts_success_or_other_unsupported_errors() {
    let good = KernelQuery {
        result: -1,
        errno: libc::EINVAL,
        output: KERNEL_QUERY_SENTINEL,
    };
    assert_eq!(kernel_query_matches(good), Ok(()));
    for mask in [0, 1, 2, 3, 4, u64::MAX] {
        assert_eq!(
            kernel_query_matches(KernelQuery {
                result: 0,
                errno: 0,
                output: mask
            }),
            Err(Error::Entry)
        );
    }
    for error in [0, libc::EFAULT, libc::ENOSYS, libc::EOPNOTSUPP, libc::EPERM] {
        assert_eq!(
            kernel_query_matches(KernelQuery {
                errno: error,
                ..good
            }),
            Err(Error::Entry)
        );
    }
    assert_eq!(
        kernel_query_matches(KernelQuery { output: 0, ..good }),
        Err(Error::Entry)
    );
    assert_eq!(
        kernel_query_matches(KernelQuery {
            result: -22,
            ..good
        }),
        Err(Error::Entry)
    );
}
#[test]
fn old_and_config_off_cet_guards_have_disjoint_acceptance() {
    let absent = b"Name:\tmain\nSeccomp:\t0\n";
    let present =
        b"Name:\tmain\nSeccomp:\t0\nx86_Thread_features:\t\nx86_Thread_features_locked:\t\n";
    let basis = kernel_basis_fixture();
    assert_eq!(request_shstk(absent, None), Err(Error::Entry));
    assert_eq!(request_shstk(present, None), Ok(()));
    assert_eq!(request_shstk(absent, Some(&basis)), Ok(()));
    assert_eq!(request_shstk(present, Some(&basis)), Err(Error::Entry));
    for raw in [
        b"Seccomp:\t0\nx86_Thread_features:\t\n".as_slice(),
        b"Seccomp:\t0\nx86_Thread_features_locked:\t\n",
        b"Seccomp:\t0\nx86_Thread_features:\tshstk\n",
        b"Seccomp:\t0\nx86_Thread_features:\t\nx86_Thread_features:\t\n",
        b"Seccomp:\t0\n x86_Thread_features:\t\n",
        b"Seccomp:\t0\nx86_Thread_features\n",
    ] {
        assert_eq!(absent_shstk(raw), Err(Error::Entry));
    }
}
#[test]
fn config_off_requires_one_canonical_seccomp_zero_observation() {
    assert_eq!(seccomp_zero(b"Seccomp:\t0\n"), Ok(()));
    for raw in [
        b"Name:\tmain\n".as_slice(),
        b"Seccomp:\t1\n",
        b"Seccomp:\t2\n",
        b"Seccomp:\t00\n",
        b"Seccomp:\t0\nSeccomp:\t0\n",
        b"Seccomp:\t0\n Seccomp:\t0\n",
        b"Seccomp:\t0",
        b"Seccomp:\t0\0\n",
        b"Seccomp:\t0\xff\n",
    ] {
        assert_eq!(seccomp_zero(raw), Err(Error::Entry));
    }
}
#[test]
fn reserved_signal_kernel_layout_is_four_native_words() {
    assert_eq!(core::mem::size_of::<KernelSigaction>(), 32);
    assert_eq!(core::mem::offset_of!(KernelSigaction, handler), 0);
    assert_eq!(core::mem::offset_of!(KernelSigaction, flags), 8);
    assert_eq!(core::mem::offset_of!(KernelSigaction, restorer), 16);
    assert_eq!(core::mem::offset_of!(KernelSigaction, mask), 24);
}
#[test]
fn reserved_signal_reset_reads_back_each_exact_default_in_order() {
    let mut calls = Vec::new();
    assert!(reset_reserved_signals_with(|signal, action, old| {
        calls.push((signal, action.is_some(), old.is_some()));
        if let Some(action) = action {
            assert_eq!(*action, KernelSigaction::DEFAULT);
        }
        if let Some(old) = old {
            assert_eq!(*old, KernelSigaction::UNREAD);
            *old = KernelSigaction::DEFAULT;
        }
        0
    }));
    assert_eq!(
        calls,
        [
            (32, true, false),
            (32, false, true),
            (33, true, false),
            (33, false, true)
        ]
    );
}
#[test]
fn every_reserved_signal_reset_or_readback_syscall_failure_stops_immediately() {
    for failed in 0..4 {
        let mut calls = 0;
        assert!(!reset_reserved_signals_with(|_, _, old| {
            let index = calls;
            calls += 1;
            if index == failed {
                return -1;
            }
            if let Some(old) = old {
                *old = KernelSigaction::DEFAULT;
            }
            0
        }));
        assert_eq!(calls, failed + 1);
    }
}
#[test]
fn every_reserved_signal_readback_field_and_unwritten_output_refuses() {
    for signal in [32, 33] {
        for field in 0..5 {
            let mut calls = 0;
            assert!(!reset_reserved_signals_with(|actual_signal, _, old| {
                calls += 1;
                if let Some(old) = old {
                    if actual_signal != signal {
                        *old = KernelSigaction::DEFAULT;
                    } else if field != 4 {
                        *old = KernelSigaction::DEFAULT;
                        match field {
                            0 => old.handler = 1,
                            1 => old.flags = 1,
                            2 => old.restorer = 1,
                            3 => old.mask = 1,
                            _ => unreachable!(),
                        }
                    }
                }
                0
            }));
            assert_eq!(calls, if signal == 32 { 2 } else { 4 });
        }
    }
}
#[test]
fn controlled_signals_still_reject_each_reserved_bit_and_malformed_population() {
    for value in [1_u64 << 31, 1_u64 << 32, (1_u64 << 31) | (1_u64 << 32)] {
        for field in ["SigBlk", "SigIgn"] {
            let raw = if field == "SigBlk" {
                format!("SigBlk:\t{value:016x}\nSigIgn:\t0000000000000000\n")
            } else {
                format!("SigBlk:\t0000000000000000\nSigIgn:\t{value:016x}\n")
            };
            assert_eq!(controlled_signal_status(raw.as_bytes()), Err(Error::Entry));
        }
    }
    for raw in [
        b"SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigIgn:\t0000000000000000\n"
            .as_slice(),
        b"SigBlk:\t0000000000000000\n",
        b"SigBlk:\t0000000000000000\nSigIgn:\t00000000000000000\n",
        b"SigBlk:\t0000000000000000\nSigIgn:\tgggggggggggggggg\n",
    ] {
        assert_eq!(controlled_signal_status(raw), Err(Error::Entry));
    }
}

fn mapped_pin_fixture() -> FilePin {
    FilePin {
        path: PathBuf::from("/fixture/subvolume-a/object"),
        sha256: [7; 32],
        device: 48,
        inode: 71,
        mode: 0o100400,
        bytes: 4096,
        mtime_ns: 3,
        ctime_ns: 4,
    }
}
fn probe_map_fixture(address: u64) -> Mapping {
    Mapping {
        start: address,
        end: address + 4096,
        offset: 0,
        device: 42,
        inode: 71,
        permissions: *b"r--p",
    }
}
fn mapped_identity_fixture() -> MappedFileIdentity {
    calibrated_identity(
        &mapped_pin_fixture(),
        0x10000,
        &[probe_map_fixture(0x10000)],
        b"/fixture/subvolume-a/object",
    )
    .unwrap()
}
fn mapped_object_fixture() -> Object {
    Object {
        file: mapped_pin_fixture(),
        pages: vec![Page {
            relative: 0x1000,
            file_offset: 0,
            permissions_at_exec: *b"r--p",
            permissions_at_entry: *b"r--p",
            file_backed: true,
            bytes: None,
        }],
    }
}

#[test]
fn calibrated_proc_device_does_not_overwrite_or_relax_the_stat_pin() {
    let identity = mapped_identity_fixture();
    assert_eq!(identity.pin, mapped_pin_fixture());
    assert_eq!(identity.pin.device, 48);
    assert_eq!(identity.device, 42);
    let mut row = probe_map_fixture(0x40000);
    assert_eq!(
        identity.check_target(&row, b"/fixture/subvolume-a/object"),
        Ok(())
    );
    // The stat device is not an alternative acceptable maps device.
    row.device = identity.pin.device;
    assert_eq!(
        identity.check_target(&row, b"/fixture/subvolume-a/object"),
        Err(Error::Custody)
    );
}

#[test]
fn calibration_requires_exact_owned_page_offset_inode_and_readonly_permissions() {
    for fault in 0..8 {
        let mut row = probe_map_fixture(0x10000);
        match fault {
            0 => row.start -= 4096,
            1 => row.end += 4096,
            2 => row.start += 4096,
            3 => row.offset = 4096,
            4 => row.inode += 1,
            5 => row.permissions = *b"rw-p",
            6 => row.permissions = *b"r-xp",
            _ => row.permissions = *b"r--s",
        }
        assert_eq!(
            calibrated_identity(
                &mapped_pin_fixture(),
                0x10000,
                &[row],
                b"/fixture/subvolume-a/object"
            ),
            Err(Error::Custody)
        );
    }
    assert_eq!(
        calibrated_identity(&mapped_pin_fixture(), u64::MAX, &[], b"x"),
        Err(Error::Shape)
    );
}

#[test]
fn missing_or_ambiguous_calibration_mapping_refuses() {
    let pin = mapped_pin_fixture();
    assert_eq!(
        calibrated_identity(&pin, 0x10000, &[], b"/fixture/subvolume-a/object"),
        Err(Error::Custody)
    );
    assert_eq!(
        calibrated_identity(
            &pin,
            0x10000,
            &[probe_map_fixture(0x10000), probe_map_fixture(0x10000)],
            b"/fixture/subvolume-a/object"
        ),
        Err(Error::Custody)
    );
}

#[test]
fn calibration_and_child_mapping_reject_same_numeric_identity_on_other_paths() {
    let pin = mapped_pin_fixture();
    let identity = mapped_identity_fixture();
    for target in [
        b"/fixture/subvolume-b/object".as_slice(),
        b"/fixture/subvolume-a/object (deleted)",
        b"/fixture/subvolume-a/alias",
        b"/fixture/subvolume-a/./object",
        b"object",
        b"",
    ] {
        assert_eq!(
            calibrated_identity(&pin, 0x10000, &[probe_map_fixture(0x10000)], target),
            Err(Error::Custody)
        );
        assert_eq!(
            identity.check_target(&probe_map_fixture(0x40000), target),
            Err(Error::Custody)
        );
    }
}

#[test]
fn mapped_witness_binds_every_retained_pin_member() {
    let identity = mapped_identity_fixture();
    assert_eq!(identity.check_pin(&mapped_pin_fixture()), Ok(()));
    for fault in 0..9 {
        let mut pin = mapped_pin_fixture();
        match fault {
            0 => pin.path = PathBuf::from("/fixture/subvolume-b/object"),
            1 => pin.sha256[0] ^= 1,
            2 => pin.device += 1,
            3 => pin.inode += 1,
            4 => pin.mode ^= 1,
            5 => pin.bytes += 1,
            6 => pin.mtime_ns += 1,
            7 => pin.ctime_ns += 1,
            _ => {
                pin.device = 42;
                pin.path = PathBuf::from("/fixture/subvolume-c/object");
            }
        }
        assert_eq!(identity.check_pin(&pin), Err(Error::Custody));
    }
}

#[test]
fn ordinary_equal_stat_and_maps_device_still_needs_the_exact_path_and_inode() {
    let mut pin = mapped_pin_fixture();
    pin.device = 42;
    let identity = calibrated_identity(
        &pin,
        0x10000,
        &[probe_map_fixture(0x10000)],
        b"/fixture/subvolume-a/object",
    )
    .unwrap();
    assert_eq!(
        identity.check_target(&probe_map_fixture(0x40000), b"/fixture/subvolume-a/object"),
        Ok(())
    );
    let mut row = probe_map_fixture(0x40000);
    row.inode += 1;
    assert_eq!(
        identity.check_target(&row, b"/fixture/subvolume-a/object"),
        Err(Error::Custody)
    );
    assert_eq!(
        identity.check_target(&probe_map_fixture(0x40000), b"/fixture/subvolume-b/object"),
        Err(Error::Custody)
    );
}

#[test]
fn bias_joins_the_actual_vma_path_before_returning_any_address() {
    let object = mapped_object_fixture();
    let identity = mapped_identity_fixture();
    let rows = [probe_map_fixture(0x10000)];
    let mut ranges = Vec::new();
    let bias = object_bias(&object, &rows, &identity, |row| {
        ranges.push((row.start, row.end));
        Ok(b"/fixture/subvolume-a/object".to_vec())
    })
    .unwrap();
    assert_eq!(bias, 0xf000);
    assert_eq!(ranges, [(0x10000, 0x11000)]);
    assert_eq!(
        object_bias(&object, &rows, &identity, |_| Ok(
            b"/fixture/subvolume-b/object".to_vec()
        )),
        Err(Error::Custody)
    );
    assert_eq!(
        object_bias(&object, &rows, &identity, |_| Err(Error::Io(libc::EPERM))),
        Err(Error::Io(libc::EPERM))
    );
}

#[test]
fn two_coherent_vmas_with_same_proc_identity_are_not_silently_selected() {
    let object = mapped_object_fixture();
    let identity = mapped_identity_fixture();
    let rows = [probe_map_fixture(0x10000), probe_map_fixture(0x20000)];
    let mut calls = 0;
    assert_eq!(
        object_bias(&object, &rows, &identity, |row| {
            calls += 1;
            Ok(if row.start == 0x10000 {
                b"/fixture/subvolume-a/object".to_vec()
            } else {
                b"/fixture/subvolume-b/object".to_vec()
            })
        }),
        Err(Error::Custody)
    );
    assert_eq!(calls, 0);
}

#[test]
fn map_link_read_errors_empty_and_truncated_targets_remain_failures() {
    for error in [libc::EPERM, libc::EACCES, libc::ENOENT, libc::ESRCH] {
        assert_eq!(
            map_target_with(|_| Err(Error::Io(error))),
            Err(Error::Io(error))
        );
    }
    for size in [0, 4096, 4097] {
        assert_eq!(map_target_with(|_| Ok(size)), Err(Error::Custody));
    }
    let actual = map_target_with(|buffer| {
        let raw = b"/fixture/subvolume-a/object";
        buffer[..raw.len()].copy_from_slice(raw);
        Ok(raw.len())
    })
    .unwrap();
    assert_eq!(
        mapped_path_matches(&actual, &mapped_pin_fixture().path),
        Ok(())
    );
    assert_eq!(
        mapped_path_matches(&actual[..actual.len() - 1], &mapped_pin_fixture().path),
        Err(Error::Custody)
    );
}

#[test]
fn exact_owned_reservation_release_consumes_only_its_own_token() {
    for address in [0, 0x70000000] {
        let mut owner = Some(address);
        let mut calls = Vec::new();
        assert_eq!(
            release_probe_with(&mut owner, |base, bytes| {
                calls.push((base, bytes));
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(owner, None);
        assert_eq!(calls, [(address, 3 * 4096)]);
        assert_eq!(
            release_probe_with(&mut owner, |_, _| panic!("already released")),
            Ok(())
        );
    }
}

#[test]
fn failed_unmap_retains_the_exact_owner_and_cannot_grant_fork_success() {
    let mut owner = Some(0x70000000);
    assert_eq!(
        release_probe_with(&mut owner, |base, bytes| {
            assert_eq!((base, bytes), (0x70000000, 3 * 4096));
            Err(Error::Cleanup)
        }),
        Err(Error::Cleanup)
    );
    assert_eq!(owner, Some(0x70000000));
    assert_eq!(
        release_probe_with(&mut owner, |base, bytes| {
            assert_eq!((base, bytes), (0x70000000, 3 * 4096));
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(owner, None);
}

#[test]
fn real_retained_file_calibration_releases_its_own_mapping_identity() {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct OwnedPath(PathBuf);
    impl Drop for OwnedPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let mut created = None;
    for _ in 0..128 {
        let path = std::env::temp_dir().join(format!(
            "li2-observer-map-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => {
                created = Some((OwnedPath(path), file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("owned fixture: {error}"),
        }
    }
    let (path, mut writer) = created.expect("unique owned fixture");
    let bytes = [0x5a; 4096];
    writer.write_all(&bytes).unwrap();
    drop(writer);
    let meta = std::fs::metadata(&path.0).unwrap();
    let pin = FilePin {
        path: std::fs::canonicalize(&path.0).unwrap(),
        sha256: Sha256::digest(bytes).into(),
        device: meta.dev(),
        inode: meta.ino(),
        mode: meta.mode(),
        bytes: meta.len(),
        mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        ctime_ns: i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
    };
    let held = pin.open().unwrap();
    assert_eq!(pin.contents(&held).unwrap(), bytes);
    let identity = calibrate_file(&pin, &held, Instant::now() + Duration::from_secs(15)).unwrap();
    assert_eq!(identity.pin, pin);
    assert_eq!(pin.contents(&held).unwrap(), bytes);
    let pid = std::process::id() as libc::pid_t;
    let maps = parse_maps(&read_proc(pid, "maps", MAP_CAP).unwrap()).unwrap();
    // Concurrent tests may reuse the released address. Identify only this
    // exclusively created file; no assertion requires an address to stay empty.
    for row in maps.iter().filter(|row| identity.matches(row)) {
        assert_ne!(
            mapping_target(pid, row).unwrap(),
            pin.path.as_os_str().as_encoded_bytes()
        );
    }
}
