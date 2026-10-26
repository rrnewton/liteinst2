//! Original instructions run under an independent dedicated raw tracer. No
//! production owner, decoder, mapper, scanner, frame reader or completer is used.
use super::*;
use std::ffi::CString;

#[derive(Clone, Debug)]
pub struct Observation {
    pub kind: Kind,
    pub before: Frame,
    pub entry: Option<Frame>,
    pub after: Frame,
    pub entry_info: Option<(usize, [u8; 88])>,
    pub exit_info: Option<(usize, [u8; 88])>,
}
pub fn trace(pid: i32, operation: u32, address: usize, data: usize) {
    assert_ne!(
        unsafe { libc::ptrace(operation, pid, address, data) },
        -1,
        "raw ptrace {operation}: {}",
        io::Error::last_os_error()
    );
}
fn registers(pid: i32) -> RegisterSnapshot {
    let mut value = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    trace(pid, libc::PTRACE_GETREGS, 0, value.as_mut_ptr() as usize);
    unsafe { value.assume_init() }.into()
}
fn set_registers(pid: i32, value: RegisterSnapshot) {
    let raw: libc::user_regs_struct = value.into();
    trace(
        pid,
        libc::PTRACE_SETREGS,
        0,
        (&raw as *const libc::user_regs_struct) as usize,
    );
    assert_eq!(registers(pid), value);
}
fn memory(pid: i32, address: u64, len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len + 7);
    for offset in (0..len).step_by(8) {
        let word = unsafe {
            *libc::__errno_location() = 0;
            let value = libc::ptrace(libc::PTRACE_PEEKDATA, pid, address + offset as u64, 0);
            assert_eq!(*libc::__errno_location(), 0);
            value
        };
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    bytes.truncate(len);
    bytes
}
fn byte(pid: i32, address: u64, expected: u8, replacement: u8) {
    let mut word: [u8; 8] = memory(pid, address, 8).try_into().unwrap();
    assert_eq!(word[0], expected);
    word[0] = replacement;
    trace(
        pid,
        libc::PTRACE_POKETEXT,
        address as usize,
        u64::from_ne_bytes(word) as usize,
    );
    assert_eq!(memory(pid, address, 8), word);
}
fn architecture(pid: i32) -> Architecture {
    let registers = registers(pid);
    let mut xstate = vec![0; 65536];
    let pointer = xstate.as_mut_ptr();
    let mut iov = libc::iovec {
        iov_base: pointer.cast(),
        iov_len: xstate.len(),
    };
    trace(
        pid,
        libc::PTRACE_GETREGSET,
        0x202,
        (&mut iov as *mut libc::iovec) as usize,
    );
    assert_eq!(iov.iov_base, pointer.cast());
    assert!((512..xstate.len()).contains(&iov.iov_len));
    xstate.truncate(iov.iov_len);
    let mut mask = 0_u64;
    trace(
        pid,
        libc::PTRACE_GETSIGMASK,
        8,
        (&mut mask as *mut u64) as usize,
    );
    Architecture {
        registers,
        xstate,
        mask,
    }
}
fn syscall_info(pid: i32, op: u8, number: u64) -> (usize, [u8; 88]) {
    let mut bytes = [0; 88];
    let len = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            pid,
            bytes.len(),
            bytes.as_mut_ptr(),
        )
    };
    assert!(len >= 0);
    let len = len as usize;
    assert!(if op == 1 {
        (80..=88).contains(&len)
    } else {
        (33..=88).contains(&len)
    });
    assert_eq!(bytes[0], op);
    assert_eq!(
        u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        0xc000003e
    );
    let regs = registers(pid);
    assert_eq!(
        u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        regs.rip
    );
    assert_eq!(
        u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
        regs.rsp
    );
    assert_eq!(regs.orig_rax, number);
    if op == 1 {
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
    } else {
        assert_eq!(
            u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
            regs.rax
        );
        assert_eq!(bytes[32], 0);
    }
    (len, bytes)
}

struct Raw {
    pid: i32,
    pin: OwnedFd,
    stopped: bool,
    terminal: bool,
    complete: bool,
}
impl Raw {
    fn launch(fixture: &Fixture) -> Self {
        let path = CString::new(fixture.path.as_os_str().as_encoded_bytes()).unwrap();
        let argv = [path.as_ptr(), std::ptr::null()];
        let env: [*const libc::c_char; 1] = [std::ptr::null()];
        let until = Instant::now() + TIMEOUT;
        let mut fd = -1;
        let file_fork = FILE_FORK.lock().unwrap();
        assert!(
            Instant::now() < until,
            "raw mapping launch deadline before clone"
        );
        let pid = unsafe { libc::syscall(libc::SYS_clone, libc::CLONE_PIDFD, 0, &mut fd, 0, 0) };
        if pid == 0 {
            unsafe {
                if libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) == 0 {
                    let process = libc::syscall(libc::SYS_getpid);
                    let task = libc::syscall(libc::SYS_gettid);
                    if process > 0
                        && process == task
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
        drop(file_fork);
        assert!(pid > 0 && fd >= 0, "atomic original clone failed");
        let mut raw = Self {
            pid: pid as i32,
            pin: unsafe { OwnedFd::from_raw_fd(fd) },
            stopped: false,
            terminal: false,
            complete: false,
        };
        assert_eq!(raw.wait(until), (libc::SIGSTOP << 8) | 0x7f);
        trace(
            raw.pid,
            libc::PTRACE_SETOPTIONS,
            0,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL)
                as usize,
        );
        raw.resume(libc::PTRACE_CONT, until);
        assert_eq!(
            raw.wait(until),
            (libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f
        );
        let mut inherited = 0_u64;
        trace(
            raw.pid,
            libc::PTRACE_GETSIGMASK,
            8,
            (&mut inherited as *mut u64) as usize,
        );
        assert_eq!(inherited, TRACER_MASK);
        trace(
            raw.pid,
            libc::PTRACE_SETSIGMASK,
            8,
            (&APP_MASK as *const u64) as usize,
        );
        trace(
            raw.pid,
            libc::PTRACE_GETSIGMASK,
            8,
            (&mut inherited as *mut u64) as usize,
        );
        assert_eq!(inherited, APP_MASK);
        raw.resume(libc::PTRACE_SYSCALL, until);
        assert_eq!(raw.wait(until), ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
        let (_, info) = syscall_info(raw.pid, 2, libc::SYS_execve as u64);
        assert_eq!(i64::from_ne_bytes(info[24..32].try_into().unwrap()), 0);
        assert_eq!(registers(raw.pid).rip, BASE + PAGE as u64);
        assert!(Instant::now() < until);
        raw
    }
    fn wait(&mut self, until: Instant) -> i32 {
        assert!(!self.terminal);
        loop {
            let mut status = 0;
            let result = unsafe {
                libc::waitpid(
                    self.pid,
                    &mut status,
                    libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                )
            };
            assert!(result == 0 || result == self.pid);
            if result == self.pid {
                self.stopped = libc::WIFSTOPPED(status);
                self.terminal = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                // Retain the consumed stop/terminal before refusing a late delivery.
                assert!(Instant::now() < until, "raw mapping operation deadline");
                return status;
            }
            assert!(Instant::now() < until, "raw mapping operation deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn resume(&mut self, operation: u32, until: Instant) {
        assert!(self.stopped && !self.terminal);
        assert!(
            Instant::now() < until,
            "raw mapping operation deadline before release"
        );
        trace(self.pid, operation, 0, 0);
        self.stopped = false;
    }
    fn frame(&self) -> Frame {
        assert!(self.stopped && !self.terminal);
        let maps = Maps::read(self.pid, &self.pin);
        let target = maps.target().map(|_| memory(self.pid, TARGET, PAGE));
        Frame {
            architecture: architecture(self.pid),
            data: memory(self.pid, DATA, DATA_BYTES),
            source: memory(self.pid, BASE, SOURCE_BYTES),
            target,
            maps,
        }
    }
    fn checkpoint(&mut self, pc: u64, original: u8, until: Instant) {
        byte(self.pid, pc, original, 0xcc);
        self.resume(libc::PTRACE_CONT, until);
        assert_eq!(self.wait(until), (libc::SIGTRAP << 8) | 0x7f);
        let mut info = [0_u8; 128];
        trace(
            self.pid,
            libc::PTRACE_GETSIGINFO,
            0,
            info.as_mut_ptr() as usize,
        );
        assert_eq!(
            i32::from_ne_bytes(info[..4].try_into().unwrap()),
            libc::SIGTRAP
        );
        assert_eq!(
            i32::from_ne_bytes(info[8..12].try_into().unwrap()),
            libc::SI_KERNEL
        );
        let mut regs = registers(self.pid);
        assert_eq!(regs.rip, pc + 1);
        assert_eq!(regs.orig_rax, u64::MAX);
        byte(self.pid, pc, 0xcc, original);
        regs.rip = pc;
        set_registers(self.pid, regs);
        assert!(Instant::now() < until);
    }
    fn collect(&mut self, fixture: &Fixture) -> Vec<Observation> {
        let mut rows = Vec::new();
        for site in &fixture.sites {
            let until = Instant::now() + TIMEOUT;
            self.checkpoint(site.pc, 0x0f, until);
            let before = self.frame();
            assert_eq!(before.source, fixture.source);
            assert_eq!(before.data, fixture.expected_data());
            if rows.is_empty() {
                assert_literal(&before, fixture);
            }
            let (entry, entry_info, exit_info, after) =
                if matches!(site.kind, Kind::CpuA | Kind::CpuB) {
                    self.checkpoint(site.pc + 2, 0x49, until);
                    let after = self.frame();
                    let host = std::arch::x86_64::__cpuid_count(0, 0);
                    let mut expected = before.architecture.registers;
                    expected.rax = u64::from(host.eax);
                    expected.rbx = u64::from(host.ebx);
                    expected.rcx = u64::from(host.ecx);
                    expected.rdx = u64::from(host.edx);
                    expected.rip += 2;
                    assert_eq!(after.architecture.registers, expected);
                    (None, None, None, after)
                } else {
                    let number = before.architecture.registers.rax;
                    self.resume(libc::PTRACE_SYSCALL, until);
                    assert_eq!(self.wait(until), ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
                    let info = syscall_info(self.pid, 1, number);
                    let entry = self.frame();
                    let mut expected = before.architecture.registers;
                    expected.rip += 2;
                    expected.rcx = expected.rip;
                    expected.r11 = expected.eflags;
                    expected.orig_rax = number;
                    expected.rax = (-libc::ENOSYS as i64) as u64;
                    assert_eq!(entry.architecture.registers, expected);
                    assert_eq!(entry.architecture.xstate, before.architecture.xstate);
                    assert_eq!(entry.architecture.mask, APP_MASK);
                    assert_eq!(entry.data, before.data);
                    assert_eq!(entry.source, before.source);
                    assert_eq!(entry.target, before.target);
                    assert_eq!(entry.maps, before.maps);
                    self.resume(libc::PTRACE_SYSCALL, until);
                    assert_eq!(self.wait(until), ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
                    let exit_info = syscall_info(self.pid, 2, number);
                    let after = self.frame();
                    expected.rax = if site.kind == Kind::Map { TARGET } else { 0 };
                    assert_eq!(after.architecture.registers, expected);
                    (Some(entry), Some(info), Some(exit_info), after)
                };
            assert_eq!(after.architecture.xstate, before.architecture.xstate);
            assert_eq!(after.architecture.mask, APP_MASK);
            assert_eq!(after.data, before.data);
            assert_eq!(after.source, fixture.source);
            assert_eq!(after.maps.outside(), before.maps.outside());
            match site.kind {
                Kind::Map => {
                    assert!(before.target.is_none());
                    assert_eq!(after.target, Some(vec![0; PAGE]));
                    assert_eq!(after.maps.target().unwrap().permissions, "rw-p");
                }
                Kind::SealA | Kind::CpuA => {
                    assert_eq!(before.target.as_ref(), Some(&fixture.a));
                    assert_eq!(after.target.as_ref(), Some(&fixture.a));
                    assert_eq!(after.maps.target().unwrap().permissions, "r-xp");
                }
                Kind::Write => {
                    assert_eq!(before.target.as_ref(), Some(&fixture.a));
                    assert_eq!(after.target.as_ref(), Some(&fixture.a));
                    assert_eq!(after.maps.target().unwrap().permissions, "rw-p");
                }
                Kind::SealB | Kind::CpuB => {
                    assert_eq!(before.target.as_ref(), Some(&fixture.b));
                    assert_eq!(after.target.as_ref(), Some(&fixture.b));
                    assert_eq!(after.maps.target().unwrap().permissions, "r-xp");
                }
                Kind::Unmap => {
                    assert_eq!(before.target.as_ref(), Some(&fixture.b));
                    assert!(after.target.is_none() && after.maps.target().is_none());
                }
            }
            rows.push(Observation {
                kind: site.kind,
                before,
                entry,
                after,
                entry_info,
                exit_info,
            });
            assert!(Instant::now() < until);
        }
        assert_eq!(rows.len(), 7);
        rows
    }
    fn cleanup(&mut self) {
        if self.complete {
            return;
        }
        let until = Instant::now() + TIMEOUT;
        while Instant::now() < until {
            if !self.terminal {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        self.pin.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
                if self.stopped && unsafe { libc::ptrace(libc::PTRACE_CONT, self.pid, 0, 0) } != -1
                {
                    self.stopped = false;
                }
                let mut status = 0;
                let got = unsafe {
                    libc::waitpid(
                        self.pid,
                        &mut status,
                        libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                    )
                };
                if got == self.pid {
                    self.stopped = libc::WIFSTOPPED(status);
                    self.terminal = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                }
            }
            if self.terminal && gone(&self.pin) {
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
                if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                    self.complete = true;
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // The validation command must not survive with an unproved raw owner.
        std::process::abort();
    }
}
impl Drop for Raw {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn original(fixture: Arc<Fixture>) -> Vec<Observation> {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let worker = spawn_masked(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut raw = Raw::launch(&fixture);
            let rows = raw.collect(&fixture);
            raw.cleanup();
            reaped(&raw.pin);
            rows
        }));
        let _ = send.send(result);
    });
    // Launch, seven unchanged operation budgets and physical cleanup.
    let result = match receive.recv_timeout(9 * TIMEOUT) {
        Ok(result) => result,
        Err(_) => std::process::abort(),
    };
    if worker.join().is_err() {
        std::process::abort();
    }
    match result {
        Ok(rows) => rows,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}
