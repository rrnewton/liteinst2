// Independent raw-ptrace and physical-reaper ownership, copied from the
// qualified dynamic_fork oracle. No production owner/registry helper is used.
struct Raw {
    parent: Child,
    pins: BTreeMap<i32, OwnedFd>,
    stopped: BTreeMap<i32, i32>,
    done: bool,
}
fn trace(tid: i32, request: u32, addr: usize, data: usize) {
    assert_ne!(
        unsafe { libc::ptrace(request, tid, addr, data) },
        -1,
        "raw ptrace: {}",
        io::Error::last_os_error()
    );
}
fn raw_registers(tid: i32) -> RegisterSnapshot {
    let mut raw = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    trace(tid, libc::PTRACE_GETREGS, 0, raw.as_mut_ptr() as usize);
    unsafe { raw.assume_init() }.into()
}
fn raw_memory(tid: i32, address: u64, len: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for offset in (0..len).step_by(8) {
        let word = unsafe {
            *libc::__errno_location() = 0;
            let word = libc::ptrace(libc::PTRACE_PEEKDATA, tid, address + offset as u64, 0);
            assert_eq!(*libc::__errno_location(), 0);
            word
        };
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    bytes.truncate(len);
    bytes
}
fn raw_snapshot(tid: i32, code: &[u8]) -> Snapshot {
    assert_eq!(raw_memory(tid, ENTRY, code.len()), code);
    let mut xstate = vec![0; 65536];
    let mut iov = libc::iovec {
        iov_base: xstate.as_mut_ptr().cast(),
        iov_len: xstate.len(),
    };
    trace(tid, libc::PTRACE_GETREGSET, 0x202, (&raw mut iov) as usize);
    xstate.truncate(iov.iov_len);
    let mut mask = 0_u64;
    trace(tid, libc::PTRACE_GETSIGMASK, 8, (&raw mut mask) as usize);
    Snapshot {
        registers: raw_registers(tid),
        xstate,
        stack: raw_memory(tid, STACK, 32),
        data: raw_memory(tid, DATA, RESULT_SIZE),
        mask,
    }
}
impl Raw {
    fn launch(path: &Path) -> Self {
        // This branch is an exec-isolated test process with no other children.
        let mut no_child: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &raw mut no_child,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let mut command = Command::new(path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let parent = command.spawn().unwrap();
        let pid = parent.id() as i32;
        let mut raw = Self {
            parent,
            pins: BTreeMap::new(),
            stopped: BTreeMap::new(),
            done: false,
        };
        raw.pins.insert(pid, pin(pid));
        let (tid, status) = raw.wait();
        assert_eq!(tid, pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        trace(
            pid,
            libc::PTRACE_SETOPTIONS,
            0,
            (libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACEEXEC
                | libc::PTRACE_O_TRACEEXIT
                | libc::PTRACE_O_TRACESYSGOOD
                | libc::PTRACE_O_EXITKILL) as usize,
        );
        raw
    }
    fn resume(&mut self, tid: i32, request: u32, signal: i32) {
        assert!(matches!(request, libc::PTRACE_SYSCALL | libc::PTRACE_CONT));
        trace(tid, request, 0, signal as usize);
        self.stopped.remove(&tid);
    }
    fn wait(&mut self) -> (i32, i32) {
        let until = Instant::now() + TIMEOUT;
        loop {
            // WNOWAIT authenticates a waitable direct/ptraced child before any
            // terminal consumption, so pidfd ownership never follows a reuse.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &raw mut info,
                    libc::WEXITED | libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            };
            assert_eq!(result, 0, "raw waitid: {}", io::Error::last_os_error());
            let tid = unsafe { info.si_pid() };
            if tid != 0 {
                self.pins.entry(tid).or_insert_with(|| pin(tid));
                let mut status = 0;
                assert_eq!(
                    unsafe { libc::waitpid(tid, &raw mut status, libc::WNOHANG | libc::__WALL) },
                    tid
                );
                if libc::WIFSTOPPED(status) {
                    self.stopped.insert(tid, status);
                } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.stopped.remove(&tid);
                }
                return (tid, status);
            }
            assert!(Instant::now() < until, "raw exec event deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn syscall_stop(&mut self, pid: i32, op: u8, number: u64) {
        for _ in 0..16 {
            let (tid, status) = self.wait();
            assert_eq!(tid, pid);
            assert!(libc::WIFSTOPPED(status));
            if libc::WSTOPSIG(status) == libc::SIGCHLD {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                trace(pid, libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
                assert_eq!(info.si_code, libc::CLD_EXITED);
                self.resume(pid, libc::PTRACE_SYSCALL, libc::SIGCHLD);
                continue;
            }
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80);
            let mut info: libc::ptrace_syscall_info = unsafe { std::mem::zeroed() };
            trace(
                pid,
                libc::PTRACE_GET_SYSCALL_INFO,
                std::mem::size_of_val(&info),
                (&raw mut info) as usize,
            );
            assert_eq!(info.arch, 0xc000003e);
            assert_eq!(info.op, op);
            let regs = raw_registers(pid);
            assert_eq!(regs.orig_rax, number);
            assert_eq!(info.instruction_pointer, regs.rip);
            assert_eq!(info.stack_pointer, regs.rsp);
            if op == libc::PTRACE_SYSCALL_INFO_ENTRY {
                assert_eq!(unsafe { info.u.entry.nr }, number);
            }
            return;
        }
        panic!("raw signal forwarding bound");
    }
    fn cleanup(&mut self) -> bool {
        if self.done {
            return true;
        }
        let until = Instant::now() + TIMEOUT;
        loop {
            // No asserting helper is called during ownership cleanup. A failed
            // syscall retains its pinned owner and is retried; only positive
            // SIGKILL or a kernel pre-exit stop permits a CONT below.
            for (&tid, handle) in &self.pins {
                if raw_hup(handle) {
                    self.stopped.remove(&tid);
                    continue;
                }
                let killed = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        handle.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                } == 0;
                if let Some(&status) = self.stopped.get(&tid) {
                    if (killed || status >> 16 == libc::PTRACE_EVENT_EXIT)
                        && unsafe { libc::ptrace(libc::PTRACE_CONT, tid, 0, 0) } != -1
                    {
                        self.stopped.remove(&tid);
                    }
                }
            }
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &raw mut info,
                    libc::WEXITED | libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            };
            if result == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                && self.pins.values().all(raw_hup)
            {
                self.done = true;
                return true;
            }
            let tid = unsafe { info.si_pid() };
            if result == 0 && tid != 0 {
                // A held WNOWAIT child is real ownership, never a /proc PID
                // guess. Do not consume it if its stable descriptor is missing.
                if let std::collections::btree_map::Entry::Vacant(entry) = self.pins.entry(tid) {
                    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, 0) };
                    if fd >= 0 {
                        entry.insert(unsafe { OwnedFd::from_raw_fd(fd as i32) });
                    }
                }
                if self.pins.contains_key(&tid) {
                    let mut status = 0;
                    if unsafe { libc::waitpid(tid, &raw mut status, libc::WNOHANG | libc::__WALL) }
                        == tid
                    {
                        if libc::WIFSTOPPED(status) {
                            self.stopped.insert(tid, status);
                        } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                            self.stopped.remove(&tid);
                        }
                    }
                }
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn raw_hup(handle: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&raw mut poll, 1, 0) == 1 && poll.revents & libc::POLLHUP != 0 }
}
impl Drop for Raw {
    fn drop(&mut self) {
        // This is the exec-isolated reaper process, not the embedding test
        // process. An uncertain foreground deadline must not kill/abort its
        // natural-parent authority. Retain it through bounded nonblocking
        // cleanup passes until both ECHILD and all original HUP witnesses hold.
        while !self.cleanup() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn words(r: RegisterSnapshot) -> [u64; 27] {
    [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ]
}
fn registers(w: [u64; 27]) -> RegisterSnapshot {
    RegisterSnapshot {
        r15: w[0],
        r14: w[1],
        r13: w[2],
        r12: w[3],
        rbp: w[4],
        rbx: w[5],
        r11: w[6],
        r10: w[7],
        r9: w[8],
        r8: w[9],
        rax: w[10],
        rcx: w[11],
        rdx: w[12],
        rsi: w[13],
        rdi: w[14],
        orig_rax: w[15],
        rip: w[16],
        cs: w[17],
        eflags: w[18],
        rsp: w[19],
        ss: w[20],
        fs_base: w[21],
        gs_base: w[22],
        ds: w[23],
        es: w[24],
        fs: w[25],
        gs: w[26],
    }
}
struct Isolated(Option<Child>);
impl Drop for Isolated {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            // The isolated native oracle owns its own bounded cleanup and must
            // finish it; killing its reaper would manufacture orphan zombies.
            // Retain the wait owner if the outer assertion deadline expires.
            std::thread::spawn(move || {
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Err(error) if error.raw_os_error() == Some(libc::ECHILD) => break,
                        _ => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
        }
    }
}
