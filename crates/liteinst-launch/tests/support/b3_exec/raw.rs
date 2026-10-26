//! Independent original exec tracer. No production parser, bootstrap or
//! selected completer participates in this reference.
use super::*;
use std::ffi::CString;
#[derive(Clone, Debug)]
pub struct Cpu {
    pub before: Frame,
    pub after: Frame,
}
#[derive(Clone, Debug)]
pub struct Record {
    pub architecture: Architecture,
    pub maps: Maps,
    pub source: Vec<u8>,
    pub data: Vec<u8>,
    pub stack: Stack,
    pub status: i32,
    pub info: Option<(usize, [u8; 88])>,
    pub event: Option<u64>,
    pub siginfo: Option<[u8; 128]>,
}
#[derive(Clone, Debug)]
pub struct Transcript {
    pub old_cpu: Cpu,
    pub before_exec: Frame,
    pub arguments: Vec<u8>,
    pub entry: Frame,
    pub entry_info: (usize, [u8; 88]),
    pub entry_status: i32,
    pub exec: Record,
    pub exit: Record,
    pub trap: Record,
    pub first_cpu: Cpu,
    pub final_cpu: Cpu,
}
pub fn trace(pid: i32, operation: u32, address: usize, data: usize) {
    assert_ne!(
        unsafe { libc::ptrace(operation, pid, address, data) },
        -1,
        "raw ptrace {operation}: {}",
        io::Error::last_os_error()
    );
}
pub fn registers(pid: i32) -> RegisterSnapshot {
    let mut value = std::mem::MaybeUninit::<libc::user_regs_struct>::zeroed();
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
pub fn memory(pid: i32, address: u64, len: usize) -> Vec<u8> {
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
pub fn architecture(pid: i32) -> Architecture {
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
pub fn syscall_info(pid: i32, op: u8, number: u64) -> (usize, [u8; 88]) {
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

fn siginfo(pid: i32) -> [u8; 128] {
    let mut b = [0; 128];
    trace(pid, libc::PTRACE_GETSIGINFO, 0, b.as_mut_ptr() as usize);
    b
}
pub fn stack(pid: i32, maps: &Maps, registers: RegisterSnapshot) -> Stack {
    let map = maps.covering(registers.rsp, 8).clone();
    assert_eq!(map.path.as_deref(), Some("[stack]"));
    assert_eq!(map.permissions, "rw-p");
    let len = usize::try_from(map.end - registers.rsp).unwrap();
    assert!(len <= 65536);
    Stack {
        start: registers.rsp,
        bytes: memory(pid, registers.rsp, len),
        map,
    }
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
        let path = CString::new(fixture.old_path.as_os_str().as_encoded_bytes()).unwrap();
        let argv = [path.as_ptr(), std::ptr::null()];
        let env: [*const libc::c_char; 1] = [std::ptr::null()];
        let until = Instant::now() + TIMEOUT;
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) },
            0
        );
        assert_ne!(action.sa_sigaction, libc::SIG_IGN);
        assert_eq!(action.sa_flags & libc::SA_NOCLDWAIT, 0);
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
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        // Match the unit harness lock order: shared crate custody before the
        // fixture-local reader. Release crate custody immediately after clone.
        #[cfg(test)]
        let shared_file_fork = crate::TEST_FILE_FORK.lock().unwrap();
        let file_fork = FILE_FORK.read().unwrap();
        assert!(Instant::now() < until);
        let mut fd = -1;
        let pid = unsafe { libc::syscall(libc::SYS_clone, libc::CLONE_PIDFD, 0, &mut fd, 0, 0) };
        if pid == 0 {
            unsafe {
                if libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) == 0 {
                    let p = libc::syscall(libc::SYS_getpid);
                    let t = libc::syscall(libc::SYS_gettid);
                    if p > 0 && p == t && libc::syscall(libc::SYS_tgkill, p, t, libc::SIGSTOP) == 0
                    {
                        libc::syscall(libc::SYS_execve, path.as_ptr(), argv.as_ptr(), env.as_ptr());
                    }
                }
                loop {
                    libc::syscall(libc::SYS_exit_group, 127);
                }
            }
        }
        if pid > 0 && fd < 0 {
            std::process::abort();
        }
        assert!(pid > 0 && fd >= 0);
        let mut raw = Self {
            pid: pid as i32,
            pin: unsafe { OwnedFd::from_raw_fd(fd) },
            stopped: false,
            terminal: false,
            complete: false,
        };
        #[cfg(test)]
        drop(shared_file_fork);
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
        drop(file_fork);
        assert_eq!(architecture(raw.pid).mask, TRACER_MASK);
        trace(
            raw.pid,
            libc::PTRACE_SETSIGMASK,
            8,
            (&APP_MASK as *const u64) as usize,
        );
        assert_eq!(architecture(raw.pid).mask, APP_MASK);
        raw.resume(libc::PTRACE_SYSCALL, until);
        assert_eq!(raw.wait(until), ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
        syscall_info(raw.pid, 2, libc::SYS_execve as u64);
        assert_eq!(registers(raw.pid).rip, OLD + PAGE as u64);
        assert!(Instant::now() < until);
        raw
    }
    fn wait(&mut self, until: Instant) -> i32 {
        assert!(!self.terminal);
        loop {
            let mut status = 0;
            let got = unsafe {
                libc::waitpid(
                    self.pid,
                    &mut status,
                    libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                )
            };
            assert!(got == 0 || got == self.pid);
            if got == self.pid {
                self.stopped = libc::WIFSTOPPED(status);
                self.terminal = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                assert!(
                    Instant::now() < until,
                    "raw exec unchanged operation deadline"
                );
                return status;
            }
            assert!(
                Instant::now() < until,
                "raw exec unchanged operation deadline"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn resume(&mut self, operation: u32, until: Instant) {
        assert!(self.stopped && !self.terminal && Instant::now() < until);
        trace(self.pid, operation, 0, 0);
        self.stopped = false;
    }
    fn frame(&self, new: bool) -> Frame {
        assert!(self.stopped && !self.terminal);
        Frame {
            architecture: architecture(self.pid),
            source: memory(self.pid, if new { NEW } else { OLD }, CODE),
            data: memory(self.pid, if new { NEW_DATA } else { OLD_DATA }, DATA_LEN),
            maps: Maps::read(self.pid, &self.pin),
        }
    }
    fn record(
        &self,
        status: i32,
        info: Option<(usize, [u8; 88])>,
        event: Option<u64>,
        signal: Option<[u8; 128]>,
    ) -> Record {
        let architecture = architecture(self.pid);
        let maps = Maps::read(self.pid, &self.pin);
        let stack = stack(self.pid, &maps, architecture.registers);
        Record {
            architecture,
            maps,
            stack,
            source: memory(self.pid, NEW, CODE),
            data: memory(self.pid, NEW_DATA, DATA_LEN),
            status,
            info,
            event,
            siginfo: signal,
        }
    }
    fn checkpoint(&mut self, pc: u64, opcode: u8, until: Instant) {
        byte(self.pid, pc, opcode, 0xcc);
        self.resume(libc::PTRACE_CONT, until);
        assert_eq!(self.wait(until), (libc::SIGTRAP << 8) | 0x7f);
        let info = siginfo(self.pid);
        assert_eq!(
            i32::from_ne_bytes(info[..4].try_into().unwrap()),
            libc::SIGTRAP
        );
        assert_eq!(
            i32::from_ne_bytes(info[8..12].try_into().unwrap()),
            libc::SI_KERNEL
        );
        let mut r = registers(self.pid);
        assert_eq!(r.rip, pc + 1);
        assert_eq!(r.orig_rax, u64::MAX);
        byte(self.pid, pc, 0xcc, opcode);
        r.rip = pc;
        set_registers(self.pid, r);
        assert!(Instant::now() < until);
    }
    fn cpu(&mut self, new: bool, pc: u64, next_opcode: u8, until: Instant) -> Cpu {
        let before = self.frame(new);
        assert_eq!(before.architecture.registers.rip, pc);
        self.checkpoint(pc + 2, next_opcode, until);
        let after = self.frame(new);
        compare::cpu(&before.architecture, &after.architecture);
        assert_eq!(before.source, after.source);
        assert_eq!(before.data, after.data);
        assert_eq!(before.maps, after.maps);
        Cpu { before, after }
    }
    fn collect(&mut self, f: &Fixture) -> Transcript {
        let until = Instant::now() + TIMEOUT;
        self.checkpoint(f.old_cpu, 0x0f, until);
        let old_cpu = self.cpu(false, f.old_cpu, 0xc3, until);
        compare::seeded(
            &old_cpu.before.architecture,
            f.old_cpu,
            OLD_DATA,
            sp(OLD_DATA) - 8,
        );
        assert_eq!(old_cpu.before.data, f.old_memory());
        assert_eq!(old_cpu.before.source, f.old_source);
        // One unchanged deadline spans old exec boundary through ENTRY/EXEC/EXIT
        // and genuine first-user checkpoint. New CPU calls are later operations.
        let until = Instant::now() + TIMEOUT;
        self.checkpoint(f.exec, 0x0f, until);
        let before_exec = self.frame(false);
        let mut expected_exec = old_cpu.after.architecture.clone();
        expected_exec.registers.rsp = sp(OLD_DATA);
        expected_exec.registers.rip = f.exec;
        expected_exec.registers.rax = libc::SYS_execve as u64;
        expected_exec.registers.rdi = INPUT;
        expected_exec.registers.rsi = f.argv;
        expected_exec.registers.rdx = f.envp;
        assert_eq!(before_exec.architecture, expected_exec);
        assert_eq!(before_exec.data, f.old_memory());
        assert_eq!(before_exec.source, f.old_source);
        let arguments = memory(self.pid, INPUT, PAGE);
        assert_eq!(arguments, f.inputs);
        compare::arguments(
            f,
            &before_exec.architecture.registers,
            &before_exec.maps,
            &arguments,
        );
        self.resume(libc::PTRACE_SYSCALL, until);
        let entry_status = self.wait(until);
        assert_eq!(entry_status, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
        let entry_info = syscall_info(self.pid, 1, libc::SYS_execve as u64);
        let entry = self.frame(false);
        compare::entry(&before_exec.architecture, &entry.architecture, f.exec);
        assert_eq!(memory(self.pid, INPUT, PAGE), arguments);
        assert_eq!(entry.source, before_exec.source);
        assert_eq!(entry.data, before_exec.data);
        assert_eq!(entry.maps, before_exec.maps);
        self.resume(libc::PTRACE_SYSCALL, until);
        let status = self.wait(until);
        assert_eq!(
            status,
            (libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f
        );
        let mut former = 0_u64;
        trace(
            self.pid,
            libc::PTRACE_GETEVENTMSG,
            0,
            (&mut former as *mut u64) as usize,
        );
        assert_eq!(former, self.pid as u64);
        let exec = self.record(status, None, Some(former), None);
        compare::new_exec(f, &exec);
        self.resume(libc::PTRACE_SYSCALL, until);
        let status = self.wait(until);
        assert_eq!(status, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
        let info = syscall_info(self.pid, 2, libc::SYS_execve as u64);
        let exit = self.record(status, Some(info), None, None);
        compare::new_exit(&exec, &exit);
        byte(self.pid, f.first_cpu, 0x0f, 0xcc);
        self.resume(libc::PTRACE_CONT, until);
        let status = self.wait(until);
        assert_eq!(status, (libc::SIGTRAP << 8) | 0x7f);
        let info = siginfo(self.pid);
        let trap = self.record(status, None, None, Some(info));
        compare::first_trap(f, &exit, &trap);
        byte(self.pid, f.first_cpu, 0xcc, 0x0f);
        let mut restored = trap.architecture.registers;
        restored.rip = f.first_cpu;
        set_registers(self.pid, restored);
        assert!(Instant::now() < until);
        let first_cpu = self.cpu(true, f.first_cpu, 0x49, Instant::now() + TIMEOUT);
        let mut expected_first = trap.architecture.clone();
        expected_first.registers.rip = f.first_cpu;
        assert_eq!(first_cpu.before.architecture, expected_first);
        assert_eq!(first_cpu.before.source, f.new_source);
        let until = Instant::now() + TIMEOUT;
        self.checkpoint(f.final_cpu, 0x0f, until);
        let final_cpu = self.cpu(true, f.final_cpu, 0xeb, until);
        compare::seeded(
            &final_cpu.before.architecture,
            f.final_cpu,
            NEW_DATA,
            sp(NEW_DATA),
        );
        let values = compare::outputs(first_cpu.after.architecture.registers);
        assert_eq!(final_cpu.before.data, f.new_memory(values));
        assert_eq!(final_cpu.before.source, f.new_source);
        Transcript {
            old_cpu,
            before_exec,
            arguments,
            entry,
            entry_info,
            entry_status,
            exec,
            exit,
            trap,
            first_cpu,
            final_cpu,
        }
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

pub fn original(fixture: Arc<Fixture>) -> Transcript {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let worker = spawn_masked(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut raw = Raw::launch(&fixture);
            let result = raw.collect(&fixture);
            raw.cleanup();
            reaped(&raw.pin);
            result
        }));
        let _ = send.send(result);
    });
    // Constructor + old CPU + exec transaction + two new CPU calls + cleanup.
    let result = match receive.recv_timeout(6 * TIMEOUT) {
        Ok(v) => v,
        Err(_) => std::process::abort(),
    };
    if worker.join().is_err() {
        std::process::abort();
    }
    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}
