//! Independent original-code oracle. The tracer has its own kernel thread and
//! only an atomic CLONE_PIDFD/zero-exit-signal process plus its traced worker.
//! No production owner, lifecycle dispatcher, journal or completion helper is
//! used to derive the expected architectural states.
use super::*;

pub(in crate::linux::remote::dynamic::owner) struct Oracle {
    pub parent: i32,
    pub child: Option<i32>,
    pub original: Frame,
    pub entry: Frame,
    pub creation: Option<Frame>,
    pub newborn: Option<Frame>,
    pub exit: Frame,
    pub entry_info: (usize, [u8; 88]),
    pub exit_info: (usize, [u8; 88]),
}

fn trace(tid: i32, request: u32, address: usize, data: usize) {
    assert_ne!(
        unsafe { libc::ptrace(request, tid, address, data) },
        -1,
        "independent ptrace request {request}: {}",
        io::Error::last_os_error()
    );
}

pub(in crate::linux::remote::dynamic::owner) fn registers(tid: i32) -> RegisterSnapshot {
    let mut value = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    trace(tid, libc::PTRACE_GETREGS, 0, value.as_mut_ptr() as usize);
    unsafe { value.assume_init() }.into()
}

fn set_registers(tid: i32, registers: RegisterSnapshot) {
    let value: libc::user_regs_struct = registers.into();
    trace(
        tid,
        libc::PTRACE_SETREGS,
        0,
        (&value as *const libc::user_regs_struct) as usize,
    );
}

pub(in crate::linux::remote::dynamic::owner) fn memory(
    tid: i32,
    address: u64,
    len: usize,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len + 7);
    for offset in (0..len).step_by(8) {
        let word = unsafe {
            *libc::__errno_location() = 0;
            let word = libc::ptrace(libc::PTRACE_PEEKDATA, tid, address + offset as u64, 0);
            assert_eq!(*libc::__errno_location(), 0, "independent memory read");
            word
        };
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    bytes.truncate(len);
    bytes
}

fn byte(tid: i32, address: u64, expected: u8, replacement: u8) {
    let bytes = memory(tid, address, 8);
    assert_eq!(bytes[0], expected);
    let mut word: [u8; 8] = bytes.try_into().unwrap();
    word[0] = replacement;
    trace(
        tid,
        libc::PTRACE_POKETEXT,
        address as usize,
        u64::from_ne_bytes(word) as usize,
    );
    assert_eq!(memory(tid, address, 8), word);
}

pub(in crate::linux::remote::dynamic::owner) fn frame(tid: i32) -> Frame {
    let registers = registers(tid);
    let mut xstate = vec![0_u8; 64 * 1024];
    let pointer = xstate.as_mut_ptr();
    let mut iov = libc::iovec {
        iov_base: pointer.cast(),
        iov_len: xstate.len(),
    };
    trace(
        tid,
        libc::PTRACE_GETREGSET,
        0x202,
        (&mut iov as *mut libc::iovec) as usize,
    );
    assert_eq!(iov.iov_base, pointer.cast());
    assert!((512..xstate.len()).contains(&iov.iov_len));
    xstate.truncate(iov.iov_len);
    let mut signal_mask = 0_u64;
    trace(
        tid,
        libc::PTRACE_GETSIGMASK,
        8,
        (&mut signal_mask as *mut u64) as usize,
    );
    Frame {
        state: KernelCapturedState {
            registers,
            xstate,
            signal_mask,
        },
        storage: memory(tid, DATA, DATA_BYTES),
        source: memory(tid, BASE, SOURCE_BYTES),
    }
}

fn assert_literal_setup(frame: &Frame, fixture: &Fixture) {
    let registers = &frame.state.registers;
    let actual = [
        registers.rax,
        registers.rcx,
        registers.rdx,
        registers.rbx,
        registers.rsp,
        registers.rbp,
        registers.rsi,
        registers.rdi,
        registers.r8,
        registers.r9,
        registers.r10,
        registers.r11,
        registers.r12,
        registers.r13,
        registers.r14,
        registers.r15,
    ];
    let mut expected =
        std::array::from_fn::<u64, 16, _>(|register| 0x1234_5678_0000_0000 | register as u64);
    expected[0] = fixture.number;
    expected[4] = PARENT_SP;
    if fixture.number == libc::SYS_clone as u64 {
        expected[7] = 0x10f00;
        expected[6] = CHILD_SP;
        expected[2] = 0;
        expected[10] = 0;
        expected[8] = 0;
    }
    assert_eq!(
        actual, expected,
        "all original literal GPR seeds and clone overrides"
    );
    assert_eq!(registers.rip, fixture.selected_pc);
    assert_eq!(registers.orig_rax, u64::MAX);
    assert_eq!(registers.eflags, FLAGS);
    assert_eq!(
        [
            registers.cs,
            registers.ss,
            registers.ds,
            registers.es,
            registers.fs,
            registers.gs
        ],
        [0x33, 0x2b, 0, 0, 0, 0]
    );
    assert_eq!([registers.fs_base, registers.gs_base], [0, 0]);
    // These fixed FXSAVE-prefix bytes independently establish that the original
    // FNINIT/FLD1 and PCMPEQD executed. The complete vector remains compared.
    assert_eq!(&frame.state.xstate[0..2], &0x037f_u16.to_le_bytes());
    assert_eq!(&frame.state.xstate[2..4], &0x3800_u16.to_le_bytes());
    assert_eq!(frame.state.xstate[4], 0x80);
    assert_eq!(&frame.state.xstate[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(
        &frame.state.xstate[32..42],
        &[0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]
    );
    assert_eq!(&frame.state.xstate[160..176], &[0xff; 16]);
    assert_eq!(frame.state.signal_mask, APP_MASK);
    let mut expected_data = (0..DATA_BYTES)
        .map(|i| ((17 * i + 43) & 255) as u8)
        .collect::<Vec<_>>();
    let flags_word = usize::try_from(PARENT_SP - 8 - DATA).unwrap();
    expected_data[flags_word..flags_word + 8].copy_from_slice(&FLAGS.to_le_bytes());
    assert_eq!(frame.storage, expected_data);
    assert_eq!(frame.source, fixture.source);
}

fn syscall_info(tid: i32, operation: u8, number: u64) -> (usize, [u8; 88]) {
    let mut bytes = [0_u8; 88];
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            tid,
            bytes.len(),
            bytes.as_mut_ptr(),
        )
    };
    assert!(result >= 0);
    let length = result as usize;
    assert!(if operation == 1 {
        (80..=88).contains(&length)
    } else {
        (33..=88).contains(&length)
    });
    assert_eq!(bytes[0], operation);
    assert_eq!(
        u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        0xc000003e
    );
    let regs = registers(tid);
    assert_eq!(
        u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        regs.rip
    );
    assert_eq!(
        u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
        regs.rsp
    );
    assert_eq!(regs.orig_rax, number);
    if operation == 1 {
        assert_eq!(
            u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
            number
        );
        for (i, value) in [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                u64::from_ne_bytes(bytes[32 + 8 * i..40 + 8 * i].try_into().unwrap()),
                value
            );
        }
    }
    (length, bytes)
}

// P_ALL|__WNOTHREAD is exclusive only while this tracer cannot run an
// inherited handler that creates another child. Block through raw syscalls,
// including libc-reserved signals; the exec-stopped child receives APP_MASK
// before its first original instruction rather than running copied handlers.
const BLOCKED_MASK: u64 = !((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));
fn block_tracer_signals() -> u64 {
    let mask = u64::MAX;
    let mut previous = 0_u64;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &mask,
                &mut previous,
                8,
            )
        },
        0
    );
    let mut actual = 0_u64;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &mut actual,
                8,
            )
        },
        0
    );
    assert_eq!(actual, BLOCKED_MASK);
    previous
}
fn restore_tracer_signals(previous: u64) {
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &previous,
                std::ptr::null_mut::<u64>(),
                8,
            )
        },
        0
    );
    let mut actual = 0_u64;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &mut actual,
                8,
            )
        },
        0
    );
    assert_eq!(actual, previous);
}

struct Raw {
    parent: i32,
    pins: BTreeMap<i32, OwnedFd>,
    stopped: BTreeMap<i32, i32>,
    terminal: BTreeSet<i32>,
    complete: bool,
}

impl Raw {
    fn launch(fixture: &Fixture) -> Self {
        let path = CString::new(fixture.path.as_os_str().as_encoded_bytes()).unwrap();
        let argv = [path.as_ptr(), std::ptr::null()];
        let env: [*const libc::c_char; 1] = [std::ptr::null()];
        let mut fd = -1_i32;
        let file_guard = crate::TEST_FILE_FORK.lock().unwrap();
        let until = Instant::now() + TIMEOUT;
        // Only async-signal-safe raw syscalls occur in the copied child branch.
        // exit_signal=0 avoids dependence on the host's SIGCHLD disposition.
        let pid = unsafe { libc::syscall(libc::SYS_clone, libc::CLONE_PIDFD, 0, &mut fd, 0, 0) };
        if pid == 0 {
            unsafe {
                if libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) == 0 {
                    let process = libc::syscall(libc::SYS_getpid);
                    let task = libc::syscall(libc::SYS_gettid);
                    if process > 0
                        && task == process
                        && libc::syscall(libc::SYS_tgkill, process, task, libc::SIGSTOP) == 0
                    {
                        libc::syscall(libc::SYS_execve, path.as_ptr(), argv.as_ptr(), env.as_ptr());
                    }
                }
                loop {
                    libc::syscall(libc::SYS_exit_group, 127);
                }
            }
        }
        drop(file_guard);
        assert!(
            pid > 0 && fd >= 0,
            "independent atomic clone: {}",
            io::Error::last_os_error()
        );
        let parent = pid as i32;
        let mut raw = Self {
            parent,
            pins: BTreeMap::from([(parent, unsafe { OwnedFd::from_raw_fd(fd) })]),
            stopped: BTreeMap::new(),
            terminal: BTreeSet::new(),
            complete: false,
        };
        // The all-blocked inherited mask suppresses the legacy exec SIGTRAP.
        // An unblockable pre-exec stop lets the real parent enable TRACEEXEC;
        // its event stop is distinct from that maskable legacy signal.
        let (tid, status) = raw.wait_until(until);
        assert_eq!(tid, parent);
        assert_eq!(status, (libc::SIGSTOP << 8) | 0x7f);
        assert!(
            Instant::now() < until,
            "independent original launch deadline"
        );
        trace(
            parent,
            libc::PTRACE_SETOPTIONS,
            0,
            (libc::PTRACE_O_TRACECLONE
                | libc::PTRACE_O_TRACESYSGOOD
                | libc::PTRACE_O_TRACEEXEC
                | libc::PTRACE_O_EXITKILL) as usize,
        );
        assert!(
            Instant::now() < until,
            "independent original launch deadline"
        );
        raw.resume(parent, libc::PTRACE_CONT);
        let (tid, status) = raw.wait_until(until);
        assert_eq!(tid, parent);
        assert_eq!(
            status,
            (libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f
        );
        assert!(
            Instant::now() < until,
            "independent original launch deadline"
        );
        let mut inherited = 0_u64;
        trace(
            parent,
            libc::PTRACE_GETSIGMASK,
            8,
            (&mut inherited as *mut u64) as usize,
        );
        assert_eq!(inherited, BLOCKED_MASK);
        trace(
            parent,
            libc::PTRACE_SETSIGMASK,
            8,
            (&APP_MASK as *const u64) as usize,
        );
        trace(
            parent,
            libc::PTRACE_GETSIGMASK,
            8,
            (&mut inherited as *mut u64) as usize,
        );
        assert_eq!(inherited, APP_MASK);
        assert!(
            Instant::now() < until,
            "independent original launch deadline"
        );
        raw
    }

    fn resume(&mut self, tid: i32, request: u32) {
        assert!(self.stopped.contains_key(&tid));
        trace(tid, request, 0, 0);
        self.stopped.remove(&tid);
    }

    fn wait(&mut self) -> (i32, i32) {
        let until = Instant::now() + TIMEOUT;
        self.wait_until(until)
    }

    fn wait_until(&mut self, until: Instant) -> (i32, i32) {
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    libc::waitid(
                        libc::P_ALL,
                        0,
                        &mut info,
                        libc::WEXITED
                            | libc::WSTOPPED
                            | libc::WNOHANG
                            | libc::WNOWAIT
                            | libc::__WALL
                            | libc::__WNOTHREAD,
                    )
                },
                0
            );
            let tid = unsafe { info.si_pid() };
            if tid != 0 {
                assert!(
                    !self.terminal.contains(&tid),
                    "retired identity must not be reacquired"
                );
                if let std::collections::btree_map::Entry::Vacant(entry) = self.pins.entry(tid) {
                    // A real waitable stopped/terminal incarnation is still
                    // unreaped. Pin it before any consuming wait or inspection.
                    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, PIDFD_THREAD) };
                    assert!(fd >= 0);
                    entry.insert(unsafe { OwnedFd::from_raw_fd(fd as i32) });
                }
                let mut status = 0;
                assert_eq!(
                    unsafe {
                        libc::waitpid(
                            tid,
                            &mut status,
                            libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                        )
                    },
                    tid
                );
                if libc::WIFSTOPPED(status) {
                    self.stopped.insert(tid, status);
                } else {
                    self.terminal.insert(tid);
                    self.stopped.remove(&tid);
                }
                return (tid, status);
            }
            assert!(Instant::now() < until, "independent original wait deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn collect(&mut self, fixture: &Fixture) -> Oracle {
        let parent = self.parent;
        byte(parent, fixture.selected_pc, 0x0f, 0xcc);
        self.resume(parent, libc::PTRACE_CONT);
        let (tid, status) = self.wait();
        assert_eq!(tid, parent);
        assert_eq!(status, (libc::SIGTRAP << 8) | 0x7f);
        let mut siginfo = [0_u8; 128];
        trace(
            parent,
            libc::PTRACE_GETSIGINFO,
            0,
            siginfo.as_mut_ptr() as usize,
        );
        assert_eq!(
            i32::from_ne_bytes(siginfo[..4].try_into().unwrap()),
            libc::SIGTRAP
        );
        assert!(matches!(
            i32::from_ne_bytes(siginfo[8..12].try_into().unwrap()),
            libc::SI_KERNEL | libc::TRAP_BRKPT
        ));
        let mut registers = registers(parent);
        assert_eq!(registers.rip, fixture.selected_pc + 1);
        assert_eq!(registers.rax, fixture.number);
        assert_eq!(registers.orig_rax, u64::MAX);
        assert_eq!(registers.eflags, FLAGS);
        assert_eq!(registers.cs, 0x33);
        byte(parent, fixture.selected_pc, 0xcc, 0x0f);
        registers.rip = fixture.selected_pc;
        set_registers(parent, registers);
        let original = frame(parent);
        assert_eq!(original.state.registers, registers);
        assert_eq!(original.source, fixture.source);
        assert_eq!(original.state.signal_mask, APP_MASK);
        assert_literal_setup(&original, fixture);
        self.resume(parent, libc::PTRACE_SYSCALL);
        let (tid, status) = self.wait();
        assert_eq!(tid, parent);
        assert_eq!(status, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
        let entry_info = syscall_info(parent, 1, fixture.number);
        let entry = frame(parent);
        let mut expected = original.state.registers;
        expected.rip += 2;
        expected.rcx = expected.rip;
        expected.r11 = FLAGS;
        expected.orig_rax = fixture.number;
        expected.rax = (-libc::ENOSYS as i64) as u64;
        assert_eq!(entry.state.registers, expected);
        assert_eq!(entry.state.xstate, original.state.xstate);
        assert_eq!(entry.state.signal_mask, APP_MASK);
        assert_eq!(entry.storage, original.storage);
        self.resume(parent, libc::PTRACE_SYSCALL);
        let (mut child, mut creation, mut newborn) = (None, None, None);
        let exit;
        let exit_info;
        loop {
            let (tid, status) = self.wait();
            if tid == parent && status >> 16 == libc::PTRACE_EVENT_CLONE {
                assert_eq!(fixture.number, libc::SYS_clone as u64);
                assert_eq!(
                    status,
                    (libc::PTRACE_EVENT_CLONE << 16) | (libc::SIGTRAP << 8) | 0x7f
                );
                let mut value = 0_u64;
                trace(
                    parent,
                    libc::PTRACE_GETEVENTMSG,
                    0,
                    (&mut value as *mut u64) as usize,
                );
                let id = i32::try_from(value).unwrap();
                assert!(id > 0 && id != parent);
                assert!(child.replace(id).is_none());
                assert!(creation.replace(frame(parent)).is_none());
                // Retain the parent until the automatic newborn is observed.
            } else if tid != parent {
                assert_eq!(fixture.number, libc::SYS_clone as u64);
                assert_eq!(
                    status,
                    (libc::SIGSTOP << 8) | 0x7f,
                    "TRACEME automatic newborn differs from seized EVENT_STOP"
                );
                assert!(newborn.replace((tid, frame(tid))).is_none());
            } else {
                assert_eq!(status, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
                exit_info = syscall_info(parent, 2, fixture.number);
                exit = frame(parent);
                break;
            }
            if let (Some(id), Some((observed, _))) = (child, &newborn) {
                assert_eq!(id, *observed);
                if self
                    .stopped
                    .get(&parent)
                    .is_some_and(|status| status >> 16 == libc::PTRACE_EVENT_CLONE)
                {
                    self.resume(parent, libc::PTRACE_SYSCALL);
                }
            }
        }
        let result = child.unwrap_or(parent) as u64;
        assert_eq!(exit.state.registers.rax, result);
        expected.rax = result;
        assert_eq!(exit.state.registers, expected);
        assert_eq!(exit.state.xstate, entry.state.xstate);
        assert_eq!(exit.state.signal_mask, APP_MASK);
        assert_eq!(exit.storage, original.storage);
        assert_eq!(exit.source, fixture.source);
        let newborn = newborn.map(|(_, state)| state);
        if let Some(born) = &newborn {
            let mut expected = entry.state.registers;
            expected.rax = 0;
            expected.rsp = CHILD_SP;
            assert_eq!(born.state.registers, expected);
            assert_eq!(born.state.xstate, entry.state.xstate);
            assert_eq!(born.state.signal_mask, APP_MASK);
            assert_eq!(born.storage, original.storage);
            assert_eq!(born.source, fixture.source);
        }
        Oracle {
            parent,
            child,
            original,
            entry,
            creation,
            newborn,
            exit,
            entry_info,
            exit_info,
        }
    }

    // Never panic or retire an owner on cleanup uncertainty. A detached dedicated
    // tracer thread retains it if the bounded caller stops waiting.
    fn cleanup(&mut self) {
        while !self.complete {
            for (&tid, pin) in &self.pins {
                if physically_gone(pin) {
                    self.stopped.remove(&tid);
                    continue;
                }
                let killed = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pin.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                } == 0;
                if killed
                    && self.stopped.contains_key(&tid)
                    && unsafe { libc::ptrace(libc::PTRACE_CONT, tid, 0, 0) } != -1
                {
                    self.stopped.remove(&tid);
                }
            }
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &mut info,
                    libc::WEXITED
                        | libc::WSTOPPED
                        | libc::WNOHANG
                        | libc::WNOWAIT
                        | libc::__WALL
                        | libc::__WNOTHREAD,
                )
            };
            if result == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                && self.pins.values().all(physically_gone)
            {
                self.complete = true;
                break;
            }
            let tid = unsafe { info.si_pid() };
            if result == 0 && tid != 0 && !self.terminal.contains(&tid) {
                if let std::collections::btree_map::Entry::Vacant(entry) = self.pins.entry(tid) {
                    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, PIDFD_THREAD) };
                    if fd >= 0 {
                        entry.insert(unsafe { OwnedFd::from_raw_fd(fd as i32) });
                    }
                }
                if self.pins.contains_key(&tid) {
                    let mut status = 0;
                    if unsafe {
                        libc::waitpid(
                            tid,
                            &mut status,
                            libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                        )
                    } == tid
                    {
                        if libc::WIFSTOPPED(status) {
                            self.stopped.insert(tid, status);
                        } else {
                            self.terminal.insert(tid);
                            self.stopped.remove(&tid);
                        }
                    }
                }
            }
            if !self.complete {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub(in crate::linux::remote::dynamic::owner) fn original(fixture: Arc<Fixture>) -> Oracle {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let worker = spawn_masked(move || {
        let previous_mask = block_tracer_signals();
        assert_eq!(previous_mask, BLOCKED_MASK);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut raw = Raw::launch(&fixture);
            let oracle = raw.collect(&fixture);
            raw.cleanup();
            assert!(raw.pins.values().all(physically_gone));
            for pin in raw.pins.values() {
                assert_echild(pin);
            }
            oracle
        }));
        let restored = std::panic::catch_unwind(|| restore_tracer_signals(previous_mask));
        let result = match restored {
            Ok(()) => result,
            Err(panic) => Err(panic),
        };
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(3 * TIMEOUT)
        .expect("independent original oracle deadline; retained tracer owns cleanup");
    worker.join().unwrap();
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
