//! A separately implemented pristine SEIZE owner. Before the first original
//! signal frame, every observation is a kernel event/syscall/interrupt stop;
//! no entry breakpoint, single step, injected fault or private runner occurs.
use super::*;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc::{Receiver, SyncSender};

const EVENT_STOP: i32 = 128;
const SEIZE: u32 = 0x4206;
const INTERRUPT: u32 = 0x4207;
const GET_SYSCALL_INFO: u32 = 0x420e;
const AUDIT_X86_64: u32 = 0xc000_003e;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyscallInfo {
    pub size: usize,
    pub bytes: [u8; 88],
}
impl SyscallInfo {
    pub fn entry(&self, number: u64, arguments: [u64; 6], pc: u64, sp: u64) {
        assert_eq!(self.size, 80);
        assert_eq!(self.bytes[0], 1);
        assert_eq!(dword(&self.bytes, 4), AUDIT_X86_64);
        assert_eq!(word(&self.bytes, 8), pc);
        assert_eq!(word(&self.bytes, 16), sp);
        assert_eq!(word(&self.bytes, 24), number);
        for (i, arg) in arguments.into_iter().enumerate() {
            assert_eq!(word(&self.bytes, 32 + 8 * i), arg);
        }
    }
    pub fn exit(&self, pc: u64, sp: u64, result: i64, error: bool) {
        assert_eq!(self.size, 33);
        assert_eq!(self.bytes[0], 2);
        assert_eq!(dword(&self.bytes, 4), AUDIT_X86_64);
        assert_eq!(word(&self.bytes, 8), pc);
        assert_eq!(word(&self.bytes, 16), sp);
        assert_eq!(word(&self.bytes, 24), result as u64);
        assert_eq!(self.bytes[32], u8::from(error));
    }
}
#[derive(Clone, Debug)]
pub struct Trace {
    pub rseq_before_exec: [u8; 24],
    pub rseq_after_exec: [u8; 24],
    pub before: State,
    pub signal: [u8; 128],
    pub handler_trap: State,
    pub handler_trap_info: [u8; 128],
    pub handler: State,
    pub frame: Frame,
    pub after_handler: State,
    pub return_input: State,
    pub edited_frame: Frame,
    pub return_entry: State,
    pub entry_info: SyscallInfo,
    pub returned: State,
    pub return_info: SyscallInfo,
    pub landing: Option<State>,
    pub setup: Vec<(State, SyscallInfo, State, SyscallInfo)>,
}
pub struct Ready {
    pub pid: i32,
    pub pin: OwnedFd,
}

pub struct PristineSignalOwner {
    pid: i32,
    pin: OwnedFd,
    retired: bool,
    stopped: Option<i32>,
    cleaned: bool,
    bootstrap: bootstrap::Resources,
    rseq_before_exec: [u8; 24],
    rseq_after_exec: [u8; 24],
}
impl PristineSignalOwner {
    fn launch(image: &Image) -> Self {
        assert_eq!(mask(), TRACER_MASK);
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut action) },
            0
        );
        assert_ne!(action.sa_sigaction, libc::SIG_IGN);
        assert_eq!(action.sa_flags & libc::SA_NOCLDWAIT, 0);
        let bootstrap = bootstrap::Resources::new(&image.path, &[], &[], true);
        let until = Instant::now() + TIMEOUT;
        let fork = FILE_FORK.lock().unwrap();
        let (pid, pin) = bootstrap.spawn();
        let mut owner = Self {
            pid,
            pin,
            retired: false,
            stopped: None,
            cleaned: false,
            bootstrap,
            rseq_before_exec: [0; 24],
            rseq_after_exec: [0; 24],
        };
        drop(fork);
        owner.ptrace(
            SEIZE,
            0,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL)
                as usize,
        );
        owner.ptrace(INTERRUPT, 0, 0);
        assert_eq!(
            owner.wait(until),
            (EVENT_STOP << 16) | (libc::SIGTRAP << 8) | 0x7f
        );
        assert_eq!(owner.registers().cs, 0x33);
        assert_eq!(owner.registers().eflags & ((1 << 8) | (1 << 16)), 0);
        assert_eq!(owner.signal_mask(), TRACER_MASK);
        owner.rseq_before_exec = owner.rseq_configuration();
        assert_eq!(owner.rseq_before_exec, [0; 24]);
        assert!(
            Instant::now() < until,
            "pristine bootstrap release deadline"
        );
        owner.bootstrap.release();
        owner.resume(libc::PTRACE_CONT, 0, until);
        assert_eq!(
            owner.wait(until),
            (libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f
        );
        let exec = owner.registers();
        assert_eq!(exec.rip, ENTRY);
        assert_eq!(exec.cs, 0x33);
        assert_eq!(exec.rax, (-i64::from(libc::ENOSYS)) as u64);
        assert_eq!(owner.signal_mask(), TRACER_MASK);
        owner.ptrace(0x420b, 8, (&raw const APP_MASK) as usize);
        assert_eq!(owner.signal_mask(), APP_MASK);
        owner.resume(libc::PTRACE_SYSCALL, 0, until);
        owner.syscall_stop(until);
        let actual = owner.registers();
        let mut expected = exec;
        expected.rax = 0;
        assert_eq!(actual, expected);
        owner.syscall_info().exit(ENTRY, actual.rsp, 0, false);
        owner.rseq_after_exec = owner.rseq_configuration();
        assert_eq!(owner.rseq_after_exec, [0; 24]);
        assert_eq!(owner.memory(BASE, SOURCE_LEN), image.source);
        owner
    }
    fn ptrace(&self, request: u32, address: usize, data: usize) {
        assert!(!self.retired);
        assert_ne!(
            unsafe { libc::ptrace(request, self.pid, address, data) },
            -1,
            "raw ptrace {request:#x}: {}",
            io::Error::last_os_error()
        );
    }
    fn resume(&mut self, request: u32, signal: i32, until: Instant) {
        assert!(Instant::now() < until, "pristine original release deadline");
        assert!(self.stopped.is_some());
        self.ptrace(request, 0, signal as usize);
        self.stopped = None;
    }
    fn wait(&mut self, until: Instant) -> i32 {
        assert!(!self.retired);
        assert!(self.stopped.is_none());
        loop {
            let mut status = 0;
            let got = unsafe {
                libc::waitpid(
                    self.pid,
                    &raw mut status,
                    libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG,
                )
            };
            if got == self.pid {
                if libc::WIFSTOPPED(status) {
                    self.stopped = Some(status);
                } else {
                    self.retired = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                }
                assert!(Instant::now() < until, "pristine original wait deadline");
                return status;
            }
            if got < 0 {
                let error = io::Error::last_os_error().raw_os_error();
                if error == Some(libc::ECHILD) {
                    self.retired = true;
                }
                assert_eq!(error, Some(libc::EINTR));
            }
            assert!(Instant::now() < until, "pristine original wait deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn syscall_stop(&mut self, until: Instant) {
        assert_eq!(self.wait(until), ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
    }
    fn syscall_info(&self) -> SyscallInfo {
        let mut bytes = [0_u8; 88];
        let size =
            unsafe { libc::ptrace(GET_SYSCALL_INFO, self.pid, bytes.len(), bytes.as_mut_ptr()) };
        assert!(size >= 0);
        SyscallInfo {
            size: size as usize,
            bytes,
        }
    }
    fn rseq_configuration(&self) -> [u8; 24] {
        let mut bytes = [0_u8; 24];
        let got = unsafe { libc::ptrace(0x420f_u32, self.pid, bytes.len(), bytes.as_mut_ptr()) };
        assert_eq!(got, 24, "exact independent native rseq configuration");
        bytes
    }
    fn registers(&self) -> RegisterSnapshot {
        let mut regs = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
        self.ptrace(libc::PTRACE_GETREGS, 0, regs.as_mut_ptr() as usize);
        unsafe { regs.assume_init() }.into()
    }
    fn signal_mask(&self) -> u64 {
        let mut actual = 0_u64;
        self.ptrace(0x420a, 8, (&raw mut actual) as usize);
        actual
    }
    fn memory(&self, address: u64, len: usize) -> Vec<u8> {
        memory(self.pid, &self.pin, address, len)
    }
    fn state(&self) -> State {
        assert!(self.stopped.is_some());
        let mut xstate = vec![0; 64 * 1024];
        let mut vector = libc::iovec {
            iov_base: xstate.as_mut_ptr().cast(),
            iov_len: xstate.len(),
        };
        self.ptrace(libc::PTRACE_GETREGSET, 0x202, (&raw mut vector) as usize);
        assert!((576..xstate.len()).contains(&vector.iov_len));
        xstate.truncate(vector.iov_len);
        State {
            registers: self.registers(),
            xstate,
            mask: self.signal_mask(),
            data: self.memory(DATA, PAGE),
            normal: self.memory(NORMAL, STACK_LEN),
            alternate: self.memory(ALT, STACK_LEN),
        }
    }
    fn siginfo(&self) -> [u8; 128] {
        let mut bytes = [0; 128];
        self.ptrace(libc::PTRACE_GETSIGINFO, 0, bytes.as_mut_ptr() as usize);
        bytes
    }
    fn patch(&self, pc: u64, old: u8, new: u8) {
        let aligned = pc & !7;
        let offset = (pc - aligned) as usize;
        let mut bytes = self.memory(aligned, 8);
        assert_eq!(bytes[offset], old);
        bytes[offset] = new;
        self.ptrace(
            libc::PTRACE_POKEDATA,
            aligned as usize,
            u64::from_le_bytes(bytes.try_into().unwrap()) as usize,
        );
        assert_eq!(self.memory(pc, 1), [new]);
    }
    fn breakpoint(&mut self, pc: u64, original: u8, until: Instant) -> (State, State, [u8; 128]) {
        assert_eq!(self.wait(until), (libc::SIGTRAP << 8) | 0x7f);
        let info = self.siginfo();
        assert_eq!(dword(&info, 0), libc::SIGTRAP as u32);
        assert_eq!(dword(&info, 4), 0);
        assert!([libc::SI_KERNEL, libc::TRAP_BRKPT].contains(&(dword(&info, 8) as i32)));
        let trap = self.state();
        assert_eq!(trap.registers.rip, pc + 1);
        assert!(Instant::now() < until, "post-frame observer deadline");
        self.patch(pc, 0xcc, original);
        let mut regs = trap.registers;
        regs.rip = pc;
        let native: libc::user_regs_struct = regs.into();
        self.ptrace(libc::PTRACE_SETREGS, 0, (&raw const native) as usize);
        let normalized = self.state();
        let mut expected = trap.clone();
        expected.registers.rip = pc;
        assert_eq!(normalized, expected); // RIP-only authenticated observer translation.
        (trap, normalized, info)
    }
    fn run(&mut self, image: &Image, ready: SyncSender<Ready>, sent: Receiver<[u8; 128]>) -> Trace {
        let until = Instant::now() + TIMEOUT;
        let mut setup = Vec::new();
        for call in &image.setup {
            self.resume(libc::PTRACE_SYSCALL, 0, until);
            self.syscall_stop(until);
            let entry = self.state();
            let info = self.syscall_info();
            info.entry(call.number, call.arguments, call.next_pc, SP);
            assert_eq!(entry.registers.rax, (-i64::from(libc::ENOSYS)) as u64);
            assert_eq!(entry.registers.orig_rax, call.number);
            self.resume(libc::PTRACE_SYSCALL, 0, until);
            self.syscall_stop(until);
            let exit = self.state();
            let exit_info = self.syscall_info();
            exit_info.exit(call.next_pc, SP, 0, false);
            let mut expected = entry.clone();
            expected.registers.rax = 0;
            assert_eq!(
                exit, expected,
                "native setup has no undeclared effect at its EXIT"
            );
            setup.push((entry, info, exit, exit_info));
        }
        // This breakpoint cannot execute before the first original frame has
        // been fully constructed. It is not a pre-frame exception.
        self.patch(HANDLER, 0x0f, 0xcc);
        self.resume(libc::PTRACE_CONT, 0, until);
        wait_ready(self.pid, &self.pin, until);
        self.ptrace(INTERRUPT, 0, 0);
        assert_eq!(
            self.wait(until),
            (EVENT_STOP << 16) | (libc::SIGTRAP << 8) | 0x7f
        );
        let before = self.state();
        compare::seeded(image, &before);
        // One pending/delivery deadline starts at this authenticated ready hold.
        // Host scheduling/queueing and all later stops consume the same budget.
        let until = Instant::now() + TIMEOUT;
        ready
            .send(Ready {
                pid: self.pid,
                pin: duplicate(&self.pin),
            })
            .unwrap();
        let expected_signal = sent
            .recv_timeout(until.checked_duration_since(Instant::now()).unwrap())
            .unwrap();
        self.resume(libc::PTRACE_SYSCALL, 0, until);
        assert_eq!(self.wait(until), (SIGNAL << 8) | 0x7f);
        let signal = self.siginfo();
        assert_eq!(signal, expected_signal);
        assert_eq!(self.state(), before);
        self.resume(libc::PTRACE_SYSCALL, SIGNAL, until);
        let (handler_trap, handler, handler_trap_info) = self.breakpoint(HANDLER, 0x0f, until);
        let frame = Frame::from_state(&handler, handler.registers.rsp);
        compare::frame_setup(image, &before, &handler, &frame, &signal);
        assert_eq!(self.memory(BASE, SOURCE_LEN), image.source);
        self.patch(image.handler_after_cpuid, 0x48, 0xcc);
        self.resume(libc::PTRACE_CONT, 0, until);
        let (_, after_handler, _) = self.breakpoint(image.handler_after_cpuid, 0x48, until);
        compare::cpuid(&handler, &after_handler);
        // Record an exact original pre-syscall state, after all handler edits.
        self.patch(image.sigreturn, 0x0f, 0xcc);
        self.resume(libc::PTRACE_CONT, 0, until);
        let (_, return_input, _) = self.breakpoint(image.sigreturn, 0x0f, until);
        assert_eq!(return_input.registers.rsp, frame.address + 8);
        let edited_frame = Frame::from_state(&return_input, frame.address);
        compare::edited_frame(image, &frame, &edited_frame);
        self.resume(libc::PTRACE_SYSCALL, 0, until);
        self.syscall_stop(until);
        let return_entry = self.state();
        let entry_info = self.syscall_info();
        let args = [
            return_input.registers.rdi,
            return_input.registers.rsi,
            return_input.registers.rdx,
            return_input.registers.r10,
            return_input.registers.r8,
            return_input.registers.r9,
        ];
        entry_info.entry(
            libc::SYS_rt_sigreturn as u64,
            args,
            image.sigreturn + 2,
            frame.address + 8,
        );
        let mut expected = return_input.clone();
        expected.registers.rax = (-i64::from(libc::ENOSYS)) as u64;
        expected.registers.orig_rax = libc::SYS_rt_sigreturn as u64;
        expected.registers.rip = image.sigreturn + 2;
        expected.registers.rcx = image.sigreturn + 2;
        expected.registers.r11 = return_input.registers.eflags;
        assert_eq!(return_entry, expected);
        self.resume(libc::PTRACE_SYSCALL, 0, until);
        self.syscall_stop(until);
        let returned = self.state();
        let return_info = self.syscall_info();
        compare::returned(image, &before, &return_input, &returned);
        return_info.exit(
            returned.registers.rip,
            SP,
            returned.registers.rax as i64,
            image.trajectory.edited(),
        );
        let landing = if image.trajectory.edited() {
            self.patch(image.landing_after_cpuid, 0x48, 0xcc);
            self.resume(libc::PTRACE_CONT, 0, until);
            let (_, state, _) = self.breakpoint(image.landing_after_cpuid, 0x48, until);
            compare::cpuid(&returned, &state);
            Some(state)
        } else {
            None
        };
        assert_eq!(self.memory(BASE, SOURCE_LEN), image.source);
        Trace {
            rseq_before_exec: self.rseq_before_exec,
            rseq_after_exec: self.rseq_after_exec,
            before,
            signal,
            handler_trap,
            handler_trap_info,
            handler,
            frame,
            after_handler,
            return_input,
            edited_frame,
            return_entry,
            entry_info,
            returned,
            return_info,
            landing,
            setup,
        }
    }
    fn cleanup(&mut self) -> bool {
        if self.cleaned {
            return true;
        }
        let until = Instant::now() + TIMEOUT;
        loop {
            let killed = if !self.retired {
                (unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        self.pin.as_raw_fd(),
                        libc::SIGKILL,
                        0,
                        0,
                    )
                }) == 0
            } else {
                false
            };
            if killed
                && self.stopped.is_some()
                && unsafe { libc::ptrace(libc::PTRACE_CONT, self.pid, 0, 0) } == 0
            {
                self.stopped = None;
            }
            if !self.retired {
                let mut status = 0;
                let got = unsafe {
                    libc::waitpid(
                        self.pid,
                        &raw mut status,
                        libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG,
                    )
                };
                if got == self.pid {
                    if libc::WIFSTOPPED(status) {
                        self.stopped = Some(status);
                    } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        self.retired = true;
                        self.stopped = None;
                    }
                } else if got == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                {
                    self.retired = true;
                    self.stopped = None;
                }
            }
            if self.retired {
                let mut p = libc::pollfd {
                    fd: self.pin.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                if unsafe { libc::poll(&raw mut p, 1, 0) } == 1
                    && p.revents == libc::POLLIN | libc::POLLHUP
                    && unsafe {
                        libc::waitid(
                            libc::P_PIDFD,
                            self.pin.as_raw_fd() as u32,
                            &raw mut info,
                            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                        )
                    } == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                {
                    self.cleaned = true;
                    return true;
                }
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for PristineSignalOwner {
    fn drop(&mut self) {
        if !self.cleanup() {
            eprintln!("pristine signal owner could not prove physical cleanup");
            std::process::abort();
        }
    }
}
pub fn run(image: &Image, ready: SyncSender<Ready>, sent: Receiver<[u8; 128]>) -> Trace {
    let mut owner = PristineSignalOwner::launch(image);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.run(image, ready, sent)
    }));
    if !owner.cleanup() {
        std::process::abort();
    }
    reaped(&owner.pin);
    match result {
        Ok(trace) => trace,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
