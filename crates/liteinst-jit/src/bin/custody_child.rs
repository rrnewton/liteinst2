//! Owned child for live signal-custody tests.
//!
//! This process deliberately starts from the reviewer-probe
//! initial condition for the two signals used here —
//! default disposition, explicitly unblocked — then queues both
//! from the first CPUID callback while `Executable::run` has them
//! blocked. `refuse` returns NoHandler from that callback;
//! `denied` installs a child-only seccomp filter that makes
//! `rt_sigpending` fail with EPERM and then lets the CPUID be
//! serviced so execution reaches the guest null load. The child
//! exits 0 only on the exact promised result for its mode.

use liteinst_jit::decode::NondetKind;
use liteinst_jit::exec::{Handler, ProcessMemory, Resume};
use liteinst_jit::handler::CaptureHandler;
use liteinst_jit::harness::{MappedGuest, RETURN_SENTINEL};
use liteinst_jit::types::{CountProfile, Generation};
use liteinst_jit::{Executable, GuestState, Refuse, RunError};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Refuse,
    Denied,
}

struct Queued {
    inner: CaptureHandler,
    mode: Mode,
    queued: bool,
}

fn deny_pending_query() {
    // seccomp: return EPERM only for rt_sigpending, allow the rest.
    let mut filter = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::SYS_rt_sigpending as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0005_0000 | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        },
    ];
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: installing this process's own no-new-privs seccomp
    // filter before the callback returns.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(libc::prctl(libc::PR_SET_SECCOMP, 2, &prog), 0);
    }
}

impl Queued {
    fn queue_both(&mut self) {
        if self.queued {
            return;
        }
        self.queued = true;
        // SAFETY: raising two standard signals to this process
        // while run() has them blocked.
        unsafe {
            assert_eq!(libc::raise(libc::SIGUSR1), 0);
            assert_eq!(libc::raise(libc::SIGUSR2), 0);
        }
    }
}

impl Handler for Queued {
    fn syscall(&mut self, state: &mut GuestState, pc: u64, next: u64) -> Result<Resume, Refuse> {
        self.inner.syscall(state, pc, next)
    }

    fn nondet(
        &mut self,
        state: &mut GuestState,
        kind: NondetKind,
        pc: u64,
        next: u64,
    ) -> Result<Resume, Refuse> {
        self.queue_both();
        match self.mode {
            Mode::Refuse => Err(Refuse::NoHandler { src_pc: pc }),
            Mode::Denied => {
                deny_pending_query();
                self.inner.nondet(state, kind, pc, next)
            }
        }
    }
}

fn expect_refuse_custody() {
    // The refusal returned; both signals must still be pending
    // and blocked, exactly as the run() custody contract states.
    let mut pending: libc::sigset_t = unsafe { core::mem::zeroed() };
    let mut current: libc::sigset_t = unsafe { core::mem::zeroed() };
    // SAFETY: queries on this thread after the run returned.
    unsafe {
        assert_eq!(libc::sigpending(&mut pending), 0);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, core::ptr::null(), &mut current),
            0
        );
        assert_eq!(libc::sigismember(&pending, libc::SIGUSR1), 1);
        assert_eq!(libc::sigismember(&pending, libc::SIGUSR2), 1);
        assert_eq!(libc::sigismember(&current, libc::SIGUSR1), 1);
        assert_eq!(libc::sigismember(&current, libc::SIGUSR2), 1);
        // The caller owns them now: consume them explicitly.
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        for want in [libc::SIGUSR1, libc::SIGUSR2] {
            let mut info: libc::siginfo_t = core::mem::zeroed();
            assert_eq!(libc::sigtimedwait(&set, &mut info, &ts), want);
        }
    }
}

fn main() {
    let mode = match std::env::args().nth(1).as_deref() {
        Some("refuse") => Mode::Refuse,
        Some("denied") => Mode::Denied,
        other => panic!("unknown mode {other:?}"),
    };
    // Reviewer-probe initial condition for the two signals used:
    // default disposition, explicitly unblocked.
    // SAFETY: resetting this owned child's dispositions/mask.
    unsafe {
        for sig in [libc::SIGUSR1, libc::SIGUSR2] {
            assert_ne!(libc::signal(sig, libc::SIG_DFL), libc::SIG_ERR);
        }
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, core::ptr::null_mut()),
            0
        );
    }
    let bytes: &[u8] = match mode {
        // xor eax,eax; cpuid; jmp $
        Mode::Refuse => &[0x31, 0xc0, 0x0f, 0xa2, 0xeb, 0xfe],
        // xor eax,eax; cpuid; xor eax,eax; mov rax,[rax]; ret
        Mode::Denied => &[0x31, 0xc0, 0x0f, 0xa2, 0x31, 0xc0, 0x48, 0x8b, 0x00, 0xc3],
    };
    let guest = MappedGuest::map(bytes).expect("map guest");
    let region = guest.region(bytes, Generation(1));
    let mut exec = Executable::prepare(&region, guest.base, CountProfile::BranchesAndInstructions)
        .expect("prepare");
    let mut handler = Queued {
        inner: CaptureHandler::default(),
        mode,
        queued: false,
    };
    let got = exec.run(
        guest.initial_state(),
        &mut handler,
        &ProcessMemory,
        RETURN_SENTINEL,
    );
    eprintln!("{mode:?} returned {got:?}");
    let good = match (mode, &got) {
        (Mode::Refuse, Err(RunError::Refuse(Refuse::NoHandler { .. }))) => true,
        (Mode::Refuse, Err(RunError::Fault(f))) => {
            f.kind == liteinst_jit::exec::FaultKind::AsyncSignal
        }
        (Mode::Denied, Err(RunError::Refuse(Refuse::SignalOwnership { .. }))) => true,
        _ => false,
    };
    if good && mode == Mode::Refuse {
        expect_refuse_custody();
    }
    // SAFETY: exit without running destructors or unblocking.
    unsafe {
        libc::_exit(if good { 0 } else { 3 });
    }
}
