//! Test-only strict block reference. Original selected bytes are never executed:
//! each is intercepted at an authenticated held PC before any resume. Ordinary
//! instructions execute one at a time with an owned, exact TRAP_TRACE receipt.
use super::*;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

pub(super) struct MaskGuard(libc::sigset_t);
impl MaskGuard {
    pub(super) fn new() -> Self {
        // SAFETY: initialized local sigsets; this changes only the caller thread.
        let mut chosen: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sigemptyset(&raw mut chosen) }, 0);
        assert_eq!(
            unsafe { libc::sigaddset(&raw mut chosen, libc::SIGUSR1) },
            0
        );
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &raw const chosen, &raw mut previous)
            },
            0
        );
        Self(previous)
    }
}
impl Drop for MaskGuard {
    fn drop(&mut self) {
        // There is no child cleanup or wait operation in this mask restoration.
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &raw const self.0, std::ptr::null_mut())
            },
            0
        );
    }
}
// This separate raw-tracer mask includes the libc-reserved realtime signals.
// Keep it on the actual tracer thread until its last child is physically reaped.
// The integration binary does not change SIGCHLD disposition concurrently or
// install other-thread waiters/global hooks that reap this thread's children.
const TRACER_MASK: u64 = !((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));
struct TracerMask {
    previous: u64,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl TracerMask {
    fn new() -> Self {
        let mut previous = 0_u64;
        let chosen = TRACER_MASK;
        // SAFETY: local eight-byte kernel sigsets; only the calling thread's
        // mask changes. Using the raw syscall also blocks libc-reserved signals.
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &raw const chosen,
                    &raw mut previous,
                    8_usize,
                )
            },
            0
        );
        let guard = Self {
            previous,
            _thread: std::marker::PhantomData,
        };
        let mut actual = 0_u64;
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    std::ptr::null::<u64>(),
                    &raw mut actual,
                    8_usize,
                )
            },
            0
        );
        assert_eq!(actual, TRACER_MASK);
        guard
    }
}
impl Drop for TracerMask {
    fn drop(&mut self) {
        // Raw::drop has already completed physical cleanup before this field
        // can restore the prior mask. Failure is a command failure, not a leak.
        let restored = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &raw const self.previous,
                std::ptr::null_mut::<u64>(),
                8_usize,
            )
        };
        let mut actual = 0_u64;
        let read = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &raw mut actual,
                8_usize,
            )
        };
        if restored != 0 || read != 0 || actual != self.previous {
            eprintln!("raw strict reference could not restore its tracer mask");
            std::process::abort();
        }
    }
}
fn require_waitable_children() {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // Read only: never mutate a process-global disposition from a test thread.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut action) },
        0
    );
    assert_ne!(
        action.sa_sigaction,
        libc::SIG_IGN,
        "raw child must remain waitable before TRACEME"
    );
    assert_eq!(
        action.sa_flags & libc::SA_NOCLDWAIT,
        0,
        "raw child must not auto-reap before TRACEME"
    );
}
pub(super) fn pin(pid: i32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}
pub(super) fn live(pin: &OwnedFd) {
    let mut p = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut p, 1, 0) }, 0);
    assert_eq!(p.revents, 0);
}
pub(super) fn reaped(pin: &OwnedFd) {
    let mut p = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut p, 1, 0) }, 1);
    assert_eq!(p.revents, libc::POLLIN | libc::POLLHUP);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin.as_raw_fd() as u32,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
pub(super) fn held_mask(pid: i32, pin: &OwnedFd) -> u64 {
    live(pin);
    let mut mask = 0_u64;
    // Linux UAPI PTRACE_GETSIGMASK=0x420a, eight-byte kernel sigset. This is a
    // read on the caller's actual stopped TRACEME/static-gate child, never a
    // request against a DynamicAdmissionSession task owned by another thread.
    assert_eq!(
        unsafe { libc::ptrace(0x420a_u32, pid, 8, &raw mut mask) },
        0
    );
    live(pin);
    mask
}
pub(super) fn nx(pid: i32, pin: &OwnedFd, page: u64) {
    live(pin);
    let file = std::fs::File::open(format!("/proc/{pid}/maps")).unwrap();
    let mut text = String::new();
    file.take(128 * 1024 + 1).read_to_string(&mut text).unwrap();
    assert!(text.len() <= 128 * 1024);
    live(pin);
    let mut found = 0;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next().unwrap().split_once('-').unwrap();
        let start = u64::from_str_radix(start, 16).unwrap();
        let end = u64::from_str_radix(end, 16).unwrap();
        if start <= page && page + PAGE as u64 <= end {
            assert_eq!(fields.next().unwrap(), "r--p");
            found += 1;
        }
    }
    assert_eq!(found, 1);
}

pub(super) struct Raw {
    child: Option<Child>,
    handle: Option<OwnedFd>,
    retired: bool,
    _tracer_mask: TracerMask,
}
impl Raw {
    pub(super) fn launch(fixture: &Fixture) -> Self {
        let fork = FILE_FORK.lock().unwrap();
        let tracer_mask = TracerMask::new();
        require_waitable_children();
        let mut command = Command::new(&fixture.path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: async-signal-safe ptrace only after fork and before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut raw = Self {
            child: Some(command.spawn().unwrap()),
            handle: None,
            retired: false,
            _tracer_mask: tracer_mask,
        };
        drop(fork);
        raw.handle = Some(pin(raw.pid()));
        let status = raw.wait(Instant::now() + TIMEOUT);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        assert_eq!(status >> 16, 0);
        raw.ptrace(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        // The child retained the all-catchable launch mask through exec. Install
        // the exact application mask only at this authenticated held exec stop,
        // before any original setup instruction executes.
        assert_eq!(
            held_mask(raw.pid(), raw.handle.as_ref().unwrap()),
            TRACER_MASK
        );
        let application_mask = MASK;
        raw.ptrace(0x420b_u32, 8, (&raw const application_mask) as usize);
        assert_eq!(held_mask(raw.pid(), raw.handle.as_ref().unwrap()), MASK);
        raw.patch(fixture.marker, 0x90, 0xcc);
        raw.ptrace(libc::PTRACE_CONT, 0, 0);
        let status = raw.wait(Instant::now() + TIMEOUT);
        let info = raw.signal(status);
        assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
        assert_eq!(raw.registers().rip, fixture.marker + 1);
        raw.patch(fixture.marker, 0xcc, 0x90);
        assert_eq!(raw.memory(BASE, fixture.bytes.len()), fixture.bytes);
        let state = raw.state();
        assert_eq!(state.registers.rip, fixture.marker + 1);
        assert_eq!(state.registers.orig_rax, u64::MAX);
        assert_eq!(state.registers.eflags, FLAGS);
        assert_eq!(
            [
                state.registers.cs,
                state.registers.ss,
                state.registers.ds,
                state.registers.es,
                state.registers.fs,
                state.registers.gs
            ],
            [0x33, 0x2b, 0, 0, 0, 0]
        );
        assert_eq!([state.registers.fs_base, state.registers.gs_base], [0, 0]);
        // Independently specified fixed setup fields in the standard FXSAVE
        // prefix of NT_X86_XSTATE. Every remaining byte is still compared.
        assert_eq!(&state.xstate[0..2], &0x037f_u16.to_le_bytes());
        assert_eq!(&state.xstate[2..4], &0x3800_u16.to_le_bytes());
        assert_eq!(&state.xstate[24..28], &0x1f80_u32.to_le_bytes());
        assert_eq!(
            &state.xstate[32..42],
            &[0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]
        );
        assert_eq!(&state.xstate[176..192], &[0xff; 16]);
        assert_eq!(&state.xstate[192..208], &[0xff; 16]);
        assert_eq!(state.mask, MASK);
        for n in 0..16 {
            assert_eq!(model::reg(&state.registers, n), image::seed(n));
        }
        let mut expected_data = vec![0x5a; DATA_LEN];
        let offset = usize::try_from(STACK - 8 - DATA).unwrap();
        expected_data[offset..offset + 8].copy_from_slice(&FLAGS.to_le_bytes());
        assert_eq!(state.data, expected_data);
        raw
    }
    pub(super) fn pid(&self) -> i32 {
        self.child.as_ref().unwrap().id() as i32
    }
    fn ptrace(&self, request: u32, address: usize, data: usize) {
        assert!(!self.retired);
        assert_ne!(
            unsafe { libc::ptrace(request, self.pid(), address, data) },
            -1,
            "raw ptrace {request}: {}",
            io::Error::last_os_error()
        );
    }
    fn wait(&mut self, until: Instant) -> i32 {
        assert!(!self.retired);
        loop {
            let mut status = 0;
            // Only the exclusive unreaped owner uses this numeric wait identity.
            let got =
                unsafe { libc::waitpid(self.pid(), &raw mut status, libc::WNOHANG | libc::__WALL) };
            if got == self.pid() {
                self.retired = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                return status;
            }
            if got == -1 {
                let e = io::Error::last_os_error();
                self.retired = e.raw_os_error() == Some(libc::ECHILD);
                assert_eq!(e.raw_os_error(), Some(libc::EINTR));
            }
            assert!(Instant::now() < until, "raw strict reference wait expired");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn signal(&self, status: i32) -> libc::siginfo_t {
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(status >> 16, 0);
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
        self.ptrace(libc::PTRACE_GETSIGINFO, 0, info.as_mut_ptr() as usize);
        let info = unsafe { info.assume_init() };
        assert_eq!(info.si_signo, libc::SIGTRAP);
        info
    }
    pub(super) fn registers(&self) -> RegisterSnapshot {
        let mut r = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
        self.ptrace(libc::PTRACE_GETREGS, 0, r.as_mut_ptr() as usize);
        unsafe { r.assume_init() }.into()
    }
    fn set_registers(&self, r: RegisterSnapshot) {
        let r: libc::user_regs_struct = r.into();
        self.ptrace(libc::PTRACE_SETREGS, 0, (&raw const r) as usize);
    }
    fn xstate(&self) -> Vec<u8> {
        let mut bytes = vec![0; 64 * 1024];
        let mut v = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        self.ptrace(libc::PTRACE_GETREGSET, 0x202, (&raw mut v) as usize);
        assert!((512..bytes.len()).contains(&v.iov_len));
        bytes.truncate(v.iov_len);
        bytes
    }
    pub(super) fn memory(&self, address: u64, len: usize) -> Vec<u8> {
        assert_eq!(address % 8, 0);
        assert_eq!(len % 8, 0);
        let mut bytes = Vec::with_capacity(len);
        for offset in (0..len).step_by(8) {
            let word = unsafe {
                *libc::__errno_location() = 0;
                let w = libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    self.pid(),
                    address + offset as u64,
                    0,
                );
                assert!(w != -1 || *libc::__errno_location() == 0);
                w as u64
            };
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }
    fn patch(&self, address: u64, expected: u8, replacement: u8) {
        let aligned = address & !7;
        let offset = (address - aligned) as usize;
        let mut word = self.memory(aligned, 8);
        assert_eq!(word[offset], expected);
        word[offset] = replacement;
        self.ptrace(
            libc::PTRACE_POKEDATA,
            aligned as usize,
            u64::from_le_bytes(word.try_into().unwrap()) as usize,
        );
    }
    pub(super) fn state(&self) -> State {
        State {
            registers: self.registers(),
            xstate: self.xstate(),
            mask: held_mask(self.pid(), self.handle.as_ref().unwrap()),
            data: self.memory(DATA, DATA_LEN),
        }
    }
    pub(super) fn authenticate(
        &self,
        fixture: &Fixture,
    ) -> Result<model::Instruction, &'static str> {
        if self.memory(BASE, fixture.bytes.len()) != fixture.bytes {
            return Err("original source bytes differ");
        }
        model::checked_decode(fixture, self.registers().rip)
    }
    pub(super) fn run(
        &mut self,
        fixture: &Fixture,
        replies: &[Reply],
        budget: usize,
    ) -> Result<Trace, &'static str> {
        if replies.is_empty() {
            return Err("empty scripted trajectory");
        }
        let until = Instant::now() + TIMEOUT;
        let mut trace = Trace {
            rows: Vec::new(),
            ordinary: Vec::new(),
            blocks: Vec::new(),
        };
        for _ in 0..budget {
            if Instant::now() >= until {
                return Err("raw strict reference transaction expired");
            }
            let before = self.state();
            let pc = before.registers.rip;
            if fixture.blocks.contains(&pc) {
                trace.blocks.push(pc);
            }
            let instruction = self.authenticate(fixture)?;
            match instruction.effect {
                model::Effect::Selected(selected) => {
                    let reply = replies[trace.rows.len()];
                    let after = before.selected(instruction, reply)?;
                    // Explicit emulation at the held head. There is no resume,
                    // syscall stepping or claim of native selected execution.
                    self.set_registers(after.registers);
                    assert_eq!(self.state(), after);
                    assert_eq!(self.memory(BASE, fixture.bytes.len()), fixture.bytes);
                    trace.rows.push(Row {
                        selected,
                        bytes: fixture.bytes_at(pc).unwrap()[..instruction.len].to_vec(),
                        before,
                        after,
                        reply,
                    });
                    if trace.rows.len() == replies.len() {
                        return Ok(trace);
                    }
                }
                _ => {
                    let expected = before.ordinary(instruction, fixture)?;
                    self.ptrace(libc::PTRACE_SINGLESTEP, 0, 0);
                    let status = self.wait(until);
                    let info = self.signal(status);
                    assert_eq!(
                        info.si_code,
                        libc::TRAP_TRACE,
                        "ordinary instruction lacks owned trace receipt"
                    );
                    let observed = self.state();
                    // No TF/RF/RIP/kernel bookkeeping or XSTATE normalization.
                    assert_eq!(observed, expected, "raw ordinary trace at {pc:#x}");
                    trace.ordinary.push((pc, observed));
                }
            }
        }
        Err("strict fixture instruction budget exhausted")
    }
    pub(super) fn finish(mut self) {
        if !self.cleanup() {
            // A leaked ptrace owner cannot be turned into a passing test or an
            // unbounded detached cleanup thread. The whole command must fail.
            eprintln!("raw strict reference could not prove bounded physical cleanup");
            std::process::abort();
        }
        let handle = self.handle.take().expect("retained original pidfd");
        drop(self.child.take());
        reaped(&handle);
    }
    fn cleanup(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return true;
        };
        let pid = child.id() as i32;
        if !self.retired {
            if let Some(fd) = &self.handle {
                // Stable identity, including constructor/unwind failure paths.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        libc::SIGKILL,
                        0,
                        0,
                    );
                }
            } else {
                // Constructor failed before pidfd installation. SIGCHLD is
                // non-auto-reaping, this tracer blocks every catchable signal,
                // and no other thread waits or changes that disposition. The
                // unreaped Child therefore still pins this numeric identity.
                let _ = child.kill();
            }
        }
        let until = Instant::now() + TIMEOUT;
        let mut direct_terminal = false;
        loop {
            if !self.retired {
                let mut status = 0;
                let got =
                    unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG | libc::__WALL) };
                if got == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                    self.retired = true;
                    direct_terminal = true;
                } else if got == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                {
                    self.retired = true;
                }
            }
            if self.retired {
                if let Some(fd) = &self.handle {
                    let mut p = libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&raw mut p, 1, 0) } == 1
                        && p.revents == libc::POLLIN | libc::POLLHUP
                    {
                        return true;
                    }
                } else if direct_terminal {
                    // Only the partial-constructor path has no pidfd. A real
                    // consumed terminal wait by its natural parent reaped it.
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
impl Drop for Raw {
    fn drop(&mut self) {
        if !self.cleanup() {
            eprintln!("raw strict reference unwind could not prove bounded physical cleanup");
            std::process::abort();
        }
        // Never invoke Child::wait/kill after retirement. No detached reaper.
        drop(self.child.take());
    }
}
