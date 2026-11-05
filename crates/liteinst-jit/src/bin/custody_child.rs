//! Owned child for live signal-custody tests.
//!
//! This process deliberately starts from the reviewer-probe
//! initial condition for the two signals used here —
//! default disposition, explicitly unblocked — then queues both
//! from the first CPUID callback while `Executable::run` has them
//! blocked. `refuse` returns NoHandler from that callback;
//! `denied` installs a child-only seccomp filter that makes
//! `rt_sigpending` fail with EPERM and then lets the CPUID be
//! serviced so execution reaches the guest null load;
//! `partial_ok`/`partial_poll` arm a sigtimedwait interposer that
//! really drains SIGUSR1, then injects EPERM for SIGUSR2;
//! `dequeue_poll` seccomp-denies rt_sigtimedwait and reaches the
//! poll. The child exits 0 only on the exact promised result,
//! pending set, and mask for its mode.

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
    PartialOk,
    PartialPoll,
    DequeuePoll,
    Ordering,
}

struct Queued {
    inner: CaptureHandler,
    mode: Mode,
    queued: bool,
}

fn asyncs() -> Vec<i32> {
    (1..=64)
        .filter(|s| {
            ![
                9,
                19,
                32,
                33,
                libc::SIGSEGV,
                libc::SIGBUS,
                libc::SIGILL,
                libc::SIGFPE,
            ]
            .contains(s)
        })
        .collect()
}

fn bits(set: &libc::sigset_t) -> Vec<i32> {
    (1..=64)
        // SAFETY: membership queries on initialized sets.
        .filter(|n| unsafe { libc::sigismember(set, *n) == 1 })
        .collect()
}

fn current_mask() -> Vec<i32> {
    let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
    // SAFETY: query-only mask read on this thread.
    unsafe {
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, core::ptr::null(), &mut set),
            0
        );
    }
    bits(&set)
}

fn pending_now() -> Vec<i32> {
    let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
    // SAFETY: pending query on this thread (not used in denied mode).
    unsafe {
        assert_eq!(libc::sigpending(&mut set), 0);
    }
    bits(&set)
}

fn full_async_mask() -> Vec<i32> {
    let mut expected = vec![libc::SIGALRM];
    expected.extend(asyncs());
    expected.sort_unstable();
    expected.dedup();
    expected
}

static PARTIAL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ORDERING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ORDER_RAISED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Child-only interposer: really drain SIGUSR1 through the kernel
/// syscall, then fail a SIGUSR2 wait. This makes partial custody
/// progress observable rather than simulating a dequeue.
///
/// # Safety
/// This replaces the process's `sigtimedwait` symbol. Pointers must
/// satisfy the usual `sigtimedwait` contract; non-injected calls
/// delegate directly to the kernel syscall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigtimedwait(
    set: *const libc::sigset_t,
    info: *mut libc::siginfo_t,
    ts: *const libc::timespec,
) -> libc::c_int {
    // SAFETY: the caller passes a live sigset; the direct syscall
    // uses the kernel's 8-byte sigset size on x86-64.
    unsafe {
        if PARTIAL.load(std::sync::atomic::Ordering::SeqCst)
            && libc::sigismember(set, libc::SIGUSR2) == 1
        {
            *libc::__errno_location() = libc::EPERM;
            return -1;
        }
        if ORDERING.load(std::sync::atomic::Ordering::SeqCst)
            && libc::sigismember(set, libc::SIGTERM) == 1
        {
            *libc::__errno_location() = libc::EPERM;
            return -1;
        }
        let result = libc::syscall(libc::SYS_rt_sigtimedwait, set, info, ts, 8usize) as libc::c_int;
        if result == libc::SIGUSR2
            && ORDERING.load(std::sync::atomic::Ordering::SeqCst)
            && !ORDER_RAISED.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            // A lower number arrives only after the higher number
            // has really been dequeued: encounter order is 12,10.
            assert_eq!(libc::raise(libc::SIGUSR1), 0);
        }
        result
    }
}

fn deny_pending_query() {
    deny_syscall(libc::SYS_rt_sigpending);
}

fn deny_syscall(sys: libc::c_long) {
    // seccomp: return EPERM only for the chosen syscall.
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
            k: sys as u32,
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
        // SAFETY: raising standard signals to this process while
        // run() has them blocked. Ordering mode starts with the
        // higher number plus the wait that will fail; SIGUSR1 is
        // queued by the interposer only after SIGUSR2 is consumed.
        unsafe {
            if self.mode == Mode::Ordering {
                assert_eq!(libc::raise(libc::SIGUSR2), 0);
                assert_eq!(libc::raise(libc::SIGTERM), 0);
            } else {
                assert_eq!(libc::raise(libc::SIGUSR1), 0);
                assert_eq!(libc::raise(libc::SIGUSR2), 0);
            }
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
            Mode::PartialOk => {
                PARTIAL.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(Resume::Done)
            }
            Mode::PartialPoll => {
                PARTIAL.store(true, std::sync::atomic::Ordering::SeqCst);
                self.inner.nondet(state, kind, pc, next)
            }
            Mode::DequeuePoll => {
                deny_syscall(libc::SYS_rt_sigtimedwait);
                self.inner.nondet(state, kind, pc, next)
            }
            Mode::Ordering => {
                ORDERING.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(Resume::Done)
            }
        }
    }
}

fn expect_full_mask_and_pending(pending_want: &[i32]) {
    assert_eq!(current_mask(), full_async_mask(), "full async mask");
    assert_eq!(pending_now(), pending_want, "exact pending set");
}

fn expect_refuse_custody(guest_base: u64) {
    // Exact refusal custody: pending exactly [USR1, USR2], mask
    // exactly the exact start mask plus those two bits.
    let mut expected_mask = vec![libc::SIGALRM, libc::SIGUSR1, libc::SIGUSR2];
    expected_mask.sort_unstable();
    assert_eq!(pending_now(), vec![libc::SIGUSR1, libc::SIGUSR2]);
    assert_eq!(current_mask(), expected_mask, "old + exact pending mask");

    // Second run: the inherited pending set is reported once by
    // the Ok custody transition and the inherited mask is kept.
    let b = [0xc3u8];
    let g2 = MappedGuest::map(&b).expect("map second guest");
    let r2 = g2.region(&b, Generation(2));
    let mut e2 = Executable::prepare(&r2, g2.base, CountProfile::BranchesAndInstructions)
        .expect("prepare second");
    let mut h2 = CaptureHandler::default();
    let later = e2
        .run(g2.initial_state(), &mut h2, &ProcessMemory, RETURN_SENTINEL)
        .expect("second run reports custody");
    assert_eq!(later.also_pending, vec![libc::SIGUSR1, libc::SIGUSR2]);
    assert_eq!(
        current_mask(),
        expected_mask,
        "later run keeps inherited mask"
    );
    assert!(pending_now().is_empty());
    let _ = guest_base;

    // Third run: no duplicate custody record, mask unchanged.
    let third = e2
        .run(g2.initial_state(), &mut h2, &ProcessMemory, RETURN_SENTINEL)
        .expect("third run");
    assert!(third.also_pending.is_empty(), "no duplicate signal credit");
    assert_eq!(current_mask(), expected_mask);
}
fn main() {
    let mode = match std::env::args().nth(1).as_deref() {
        Some("refuse") => Mode::Refuse,
        Some("denied") => Mode::Denied,
        Some("partial_ok") => Mode::PartialOk,
        Some("partial_poll") => Mode::PartialPoll,
        Some("dequeue_poll") => Mode::DequeuePoll,
        Some("ordering") => Mode::Ordering,
        other => panic!("unknown mode {other:?}"),
    };
    // Exact reviewer-probe initial condition: every application
    // async signal at default disposition, blocked set exactly
    // {SIGALRM}, nothing pending.
    // SAFETY: resetting this owned child's dispositions/mask.
    unsafe {
        for sig in asyncs() {
            assert_ne!(libc::signal(sig, libc::SIG_DFL), libc::SIG_ERR);
        }
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGALRM);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &set, core::ptr::null_mut()),
            0
        );
    }
    assert_eq!(current_mask(), vec![libc::SIGALRM]);
    assert!(pending_now().is_empty());
    let bytes: &[u8] = match mode {
        // xor eax,eax; cpuid; jmp $
        Mode::Denied => &[0x31, 0xc0, 0x0f, 0xa2, 0x31, 0xc0, 0x48, 0x8b, 0x00, 0xc3],
        _ => &[0x31, 0xc0, 0x0f, 0xa2, 0xeb, 0xfe],
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
    eprintln!("{mode:?} returned {got:?} mask={:?}", current_mask());
    let good = match (mode, &got) {
        (Mode::Refuse, Err(RunError::Refuse(Refuse::NoHandler { src_pc }))) => {
            *src_pc == guest.base + 2
        }
        (Mode::Denied, Err(RunError::Refuse(Refuse::SignalOwnership { signum: 0, taken }))) => {
            taken.is_empty()
        }
        (
            Mode::PartialOk | Mode::PartialPoll,
            Err(RunError::Refuse(Refuse::SignalOwnership { signum, taken })),
        ) => *signum == libc::SIGUSR2 && taken == &vec![libc::SIGUSR1],
        (Mode::DequeuePoll, Err(RunError::Refuse(Refuse::SignalOwnership { signum, taken }))) => {
            *signum == libc::SIGUSR1 && taken.is_empty()
        }
        (Mode::Ordering, Err(RunError::Refuse(Refuse::SignalOwnership { signum, taken }))) => {
            *signum == libc::SIGTERM && taken == &vec![libc::SIGUSR1, libc::SIGUSR2]
        }
        _ => false,
    };
    if good {
        match mode {
            Mode::Refuse => expect_refuse_custody(guest.base),
            Mode::Denied => {
                // rt_sigpending itself is denied in this mode, so
                // only the returned mask can be inspected here.
                assert_eq!(current_mask(), full_async_mask(), "denied full async mask");
            }
            Mode::PartialOk | Mode::PartialPoll => {
                expect_full_mask_and_pending(&[libc::SIGUSR2]);
            }
            Mode::DequeuePoll => {
                expect_full_mask_and_pending(&[libc::SIGUSR1, libc::SIGUSR2]);
            }
            Mode::Ordering => {
                expect_full_mask_and_pending(&[libc::SIGTERM]);
            }
        }
    }
    // SAFETY: exit without running destructors or unblocking.
    unsafe {
        libc::_exit(if good { 0 } else { 3 });
    }
}
