//! Private, fresh-main-thread native witness; root alone builds/runs this file.
//! No complete asynchronous instrumentation or full state-oracle claim.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate liteinst2;

use liteinst2::patcher::synchronized::{
    Direction, Phase, SyncJumpPatch, SyncPatchError, SynchronizedBatch,
};
use liteinst2::patcher::{JumpPatchPlan, PatchError, PatchStrategy};
use liteinst2::scanner::InstructionScanner;
use liteinst2::sync_core::SyncCore;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const NOPS: [&[u8]; 4] = [
    &[0x0f, 0x1f, 0x44, 0, 0],
    &[0x66, 0x0f, 0x1f, 0x44, 0, 0],
    &[0x0f, 0x1f, 0x80, 0, 0, 0, 0],
    &[0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0],
];

// All registered mappings deliberately remain mapped until process exit.
// The registry and late-delivery routes have process-lifetime ownership.
struct Mapping {
    rx: usize,
    rw: usize,
}
impl Mapping {
    fn new() -> Self {
        // SAFETY: fixed valid name/flags and a single owned descriptor.
        let fd = unsafe { libc::memfd_create(c"word-sync-native".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: descriptor is owned and PAGE is the intended mapping size.
        assert_eq!(unsafe { libc::ftruncate(fd, PAGE as libc::off_t) }, 0);
        // SAFETY: kernel chooses two complete, initially unshared virtual ranges.
        let rw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(rw, libc::MAP_FAILED);
        // SAFETY: same complete backing, RX only (no simultaneous RWX mapping).
        let rx = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(rx, libc::MAP_FAILED);
        // SAFETY: mappings retain the backing after this descriptor closes.
        assert_eq!(unsafe { libc::close(fd) }, 0);
        // SAFETY: complete writable page, before execution or registration.
        unsafe {
            std::ptr::write_bytes(rw, 0x90, PAGE);
        }
        Self {
            rx: rx as usize,
            rw: rw as usize,
        }
    }
    fn put(&self, offset: usize, bytes: &[u8]) {
        assert!(offset + bytes.len() <= PAGE);
        // SAFETY: fixture calls this only before execution or under exclusive
        // no-executor ownership in the explicit stale-byte refusal case.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (self.rw + offset) as *mut u8,
                bytes.len(),
            );
        }
    }
    fn snapshot(&self) -> Vec<u8> {
        // SAFETY: entire permanent readable alias exists.
        unsafe { std::slice::from_raw_parts(self.rx as *const u8, PAGE).to_vec() }
    }
    fn assert_bytes(&self, expected: &[u8]) {
        assert_eq!(self.snapshot(), expected);
        // SAFETY: same permanent readable backing via writable alias.
        let actual = unsafe { std::slice::from_raw_parts(self.rw as *const u8, PAGE) };
        assert_eq!(actual, expected);
    }
    fn bind(
        &self,
        site: usize,
        code_len: usize,
        target: usize,
        capability: SyncCore,
    ) -> SyncJumpPatch {
        let original = self.snapshot();
        let code = &original[site..site + code_len];
        let scanner = InstructionScanner::default();
        let address = (self.rx + site) as u64;
        let scan = scanner.scan(code, address).unwrap();
        let plan = JumpPatchPlan::from_scan(
            &scanner,
            &scan,
            code,
            address,
            address,
            (self.rx + target) as u64,
        )
        .unwrap();
        // SAFETY: closed fixture has exact permanent aliases, known 64-byte
        // host cache lines (checked at main), sole declared entry heads,
        // unchanged router/masks and no competing or cross-process writer.
        unsafe { SyncJumpPatch::bind(plan, (self.rw + site) as *mut u8, capability).unwrap() }
    }
    fn function(&self, offset: usize) -> extern "C" fn() -> u32 {
        // SAFETY: authored code at offset follows the no-argument C ABI.
        unsafe { core::mem::transmute(self.rx + offset) }
    }
}

fn fixture(map: &Mapping, site: usize, target: usize, nop: &[u8]) {
    let mut code = nop.to_vec();
    code.extend_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
    map.put(site, &code);
    map.put(target, &[0xb8, 99, 0, 0, 0, 0xc3]);
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "bounded native checkpoint timed out"
        );
        std::thread::yield_now();
    }
}

fn phase_image(
    original: &[u8],
    patches: &[(&SyncJumpPatch, usize)],
    direction: Direction,
    phase: Phase,
) -> Vec<u8> {
    let mut out = original.to_vec();
    for &(patch, offset) in patches {
        let replacement = match direction {
            Direction::Apply => patch.plan().replacement_bytes(),
            Direction::Revert => patch.plan().original_bytes(),
        };
        let front = match patch.plan().strategy() {
            PatchStrategy::GuardedSplit { front_len, .. } => front_len,
            PatchStrategy::AtomicWord => 8,
        };
        if matches!(phase, Phase::FrontsPublished | Phase::Complete) {
            out[offset..offset + 8].copy_from_slice(&replacement);
        } else if front != 8 {
            if matches!(phase, Phase::BacksPublished | Phase::BacksSynchronized) {
                out[offset + front..offset + 8].copy_from_slice(&replacement[front..]);
            }
            if phase != Phase::Prepared {
                out[offset..offset + front].fill(0xcc);
            }
        }
    }
    out
}

fn transition(
    map: &Mapping,
    patches: &[(&SyncJumpPatch, usize)],
    direction: Direction,
    expected_result: u32,
    force_guard: bool,
) -> usize {
    let original = map.snapshot();
    let refs: Vec<_> = patches.iter().map(|&(p, _)| p).collect();
    // SAFETY: each fixture meets bind's closed-world contracts throughout.
    let mut batch = unsafe { SynchronizedBatch::prepare(&refs, direction).unwrap() };
    assert_eq!(batch.receipt().phase, Phase::Prepared);
    map.assert_bytes(&original);
    // SAFETY: no foreign writer and every actual envelope is disjoint.
    let receipt = unsafe { batch.advance().unwrap() };
    assert_eq!(receipt.phase, Phase::GuardsPublished);
    map.assert_bytes(&phase_image(&original, patches, direction, receipt.phase));
    let mut workers = Vec::new();
    let mut baselines = Vec::new();
    if force_guard {
        for (patch_index, &(patch, offset)) in patches.iter().enumerate() {
            if matches!(patch.plan().strategy(), PatchStrategy::AtomicWord) {
                continue;
            }
            let mut entries = vec![(offset, expected_result)];
            let front_len = match patch.plan().strategy() {
                PatchStrategy::GuardedSplit { front_len, .. } => front_len,
                _ => unreachable!(),
            };
            if patch.plan().displaced_len() < front_len {
                // A successor head may lie in the guarded padding, and must
                // resume its unchanged MOV independently of the selected entry.
                entries.push((offset + patch.plan().displaced_len(), 42));
            }
            for (entry, wanted) in entries {
                let before = patch.handled_guard_traps();
                baselines.push((patch_index, before));
                let function = map.function(entry);
                let (tx, rx) = std::sync::mpsc::channel();
                let thread = std::thread::spawn(move || {
                    let result = function();
                    tx.send(result).unwrap();
                });
                wait_until(|| patch.handled_guard_traps() != before);
                assert_eq!(patch.handled_guard_traps(), before + 1);
                assert!(rx.try_recv().is_err(), "guarded call must still be held");
                workers.push((thread, rx, wanted));
            }
        }
    }
    for phase in [
        Phase::GuardsSynchronized,
        Phase::BacksPublished,
        Phase::BacksSynchronized,
        Phase::FrontsPublished,
        Phase::Complete,
    ] {
        // SAFETY: same closed-world contracts; exactly one phase per call.
        let receipt = unsafe { batch.advance().unwrap() };
        assert_eq!(receipt.phase, phase);
        assert_eq!(receipt.failure, None);
        assert_eq!(receipt.writer_ownership_retained, phase != Phase::Complete);
        let any_split = patches
            .iter()
            .any(|&(p, _)| matches!(p.plan().strategy(), PatchStrategy::GuardedSplit { .. }));
        assert_eq!(
            receipt.mutated,
            any_split || matches!(phase, Phase::FrontsPublished | Phase::Complete)
        );
        map.assert_bytes(&phase_image(&original, patches, direction, phase));
    }
    assert_eq!(batch.receipt().synchronizations, 3);
    drop(batch);
    for (thread, rx, wanted) in workers {
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), wanted);
        thread.join().unwrap();
    }
    for (index, &(patch, _)) in patches.iter().enumerate() {
        if let Some(last) = baselines.iter().rev().find(|&&(owner, _)| owner == index) {
            assert_eq!(patch.handled_guard_traps(), last.1 + 1);
        }
    }
    baselines.len()
}

fn all_splits(capability: SyncCore) -> (usize, usize, usize) {
    let mut cases = 0;
    let mut calls = 0;
    let mut traps = 0;
    for nop in NOPS {
        for front in 1..8 {
            let map = Mapping::new();
            let site = 64 - front;
            fixture(&map, site, 256, nop);
            let original = map.snapshot();
            let patch = map.bind(site, nop.len() + 6, 256, capability);
            assert_eq!(patch.plan().displaced_len(), nop.len());
            assert_eq!(
                patch.plan().strategy(),
                PatchStrategy::GuardedSplit {
                    front_len: front,
                    back_len: 8 - front
                }
            );
            let call = map.function(site);
            let successor = map.function(site + nop.len());
            assert_eq!(call(), 42);
            assert_eq!(successor(), 42);
            calls += 2;
            let hits = transition(&map, &[(&patch, site)], Direction::Apply, 99, true);
            traps += hits;
            calls += hits;
            assert_eq!(call(), 99);
            assert_eq!(successor(), 42);
            calls += 2;
            let hits = transition(&map, &[(&patch, site)], Direction::Revert, 42, true);
            traps += hits;
            calls += hits;
            assert_eq!(call(), 42);
            assert_eq!(successor(), 42);
            calls += 2;
            map.assert_bytes(&original);
            cases += 1;
        }
    }
    assert_eq!((cases, calls, traps), (28, 230, 62));
    (cases, calls, traps)
}

fn atomic_cycles(capability: SyncCore) -> usize {
    for nop in NOPS {
        let map = Mapping::new();
        fixture(&map, 32, 256, nop);
        let original = map.snapshot();
        let patch = map.bind(32, nop.len() + 6, 256, capability);
        assert_eq!(patch.plan().strategy(), PatchStrategy::AtomicWord);
        assert_eq!(map.function(32)(), 42);
        transition(&map, &[(&patch, 32)], Direction::Apply, 99, false);
        assert_eq!(map.function(32)(), 99);
        transition(&map, &[(&patch, 32)], Direction::Revert, 42, false);
        assert_eq!(map.function(32)(), 42);
        map.assert_bytes(&original);
        assert_eq!(patch.handled_guard_traps(), 0);
    }
    12
}

fn two_member_batch(capability: SyncCore, mixed: bool) -> (usize, usize) {
    let site_a = if mixed { 32 } else { 63 };
    let map = Mapping::new();
    fixture(&map, site_a, 256, NOPS[0]);
    fixture(&map, 127, 272, NOPS[3]);
    let original = map.snapshot();
    let a = map.bind(site_a, 11, 256, capability);
    let b = map.bind(127, 14, 272, capability);
    assert_eq!(map.function(site_a)(), 42);
    assert_eq!(map.function(127)(), 42);
    let patches = [(&b, 127), (&a, site_a)]; // Caller order differs; stores are ordered by envelope.
    let traps = transition(&map, &patches, Direction::Apply, 99, true);
    assert_eq!(map.function(site_a)(), 99);
    assert_eq!(map.function(127)(), 99);
    let traps = traps + transition(&map, &patches, Direction::Revert, 42, true);
    assert_eq!(map.function(site_a)(), 42);
    assert_eq!(map.function(127)(), 42);
    map.assert_bytes(&original);
    assert_eq!(traps, if mixed { 2 } else { 4 });
    (6 + traps, traps)
}

static SIGNAL_ENTERED: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_PC: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_RELEASE: AtomicBool = AtomicBool::new(true);
static FRAME_UNCHANGED: AtomicBool = AtomicBool::new(false);

extern "C" fn parked_signal(
    signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    if signal != libc::SIGUSR1 || context.is_null() {
        unsafe {
            libc::_exit(91);
        }
    }
    // SAFETY: kernel supplies the native ucontext for this SA_SIGINFO handler.
    let native = unsafe { &*(context as *const libc::ucontext_t) };
    let mut before = [0u8; core::mem::size_of::<libc::ucontext_t>()];
    for (index, byte) in before.iter_mut().enumerate() {
        // SAFETY: exact native context extent; no modification or allocation.
        *byte = unsafe { std::ptr::read_volatile((context as *const u8).add(index)) };
    }
    SIGNAL_PC.store(
        native.uc_mcontext.gregs[libc::REG_RIP as usize] as usize,
        Ordering::Release,
    );
    SIGNAL_ENTERED.fetch_add(1, Ordering::Release);
    while !SIGNAL_RELEASE.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let mut unchanged = true;
    for (index, &byte) in before.iter().enumerate() {
        // SAFETY: same live frame, retained until this actual handler returns.
        unchanged &= byte == unsafe { std::ptr::read_volatile((context as *const u8).add(index)) };
    }
    FRAME_UNCHANGED.store(unchanged, Ordering::Release);
    // Actual return uses the libc-installed kernel restorer and rt_sigreturn.
}

fn saved_head(capability: SyncCore) -> usize {
    let map = Mapping::new();
    let site = 63;
    // tgkill(getpid(), gettid(), SIGUSR1), then the selected MOV EAX,42.
    map.put(
        site - 12,
        &[0xb8, 234, 0, 0, 0, 0xba, 10, 0, 0, 0, 0x0f, 0x05],
    );
    map.put(site, &[0xb8, 42, 0, 0, 0, 0xc3, 0x90, 0x90]);
    map.put(256, &[0xb8, 99, 0, 0, 0, 0xc3]);
    let original = map.snapshot();
    let patch = map.bind(site, 8, 256, capability);
    // SAFETY: authored two-integer C ABI, no clobbered callee-saved registers.
    let call: extern "C" fn(libc::pid_t, libc::pid_t) -> u32 =
        unsafe { core::mem::transmute(map.rx + site - 12) };
    // SAFETY: libc sigaction is plain initialized data; empty handler mask.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    let mut old = action;
    action.sa_sigaction = parked_signal as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut old) },
        0
    );
    let pid = unsafe { libc::getpid() };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t };
    SIGNAL_RELEASE.store(true, Ordering::Release);
    assert_eq!(call(pid, tid), 42);
    assert_eq!(SIGNAL_PC.load(Ordering::Acquire), map.rx + site);
    assert!(FRAME_UNCHANGED.load(Ordering::Acquire));
    SIGNAL_RELEASE.store(false, Ordering::Release);
    FRAME_UNCHANGED.store(false, Ordering::Release);
    let before = SIGNAL_ENTERED.load(Ordering::Acquire);
    let traps = patch.handled_guard_traps();
    let (tx, rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t };
        tx.send(call(pid, tid)).unwrap();
    });
    wait_until(|| SIGNAL_ENTERED.load(Ordering::Acquire) == before + 1);
    assert_eq!(SIGNAL_PC.load(Ordering::Acquire), map.rx + site);
    assert!(rx.try_recv().is_err());
    transition(&map, &[(&patch, site)], Direction::Apply, 99, false);
    SIGNAL_RELEASE.store(true, Ordering::Release);
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 99);
    thread.join().unwrap();
    assert!(FRAME_UNCHANGED.load(Ordering::Acquire));
    assert_eq!(patch.handled_guard_traps(), traps);
    transition(&map, &[(&patch, site)], Direction::Revert, 42, false);
    assert_eq!(call(pid, tid), 42);
    assert_eq!(SIGNAL_ENTERED.load(Ordering::Acquire), 3);
    assert!(FRAME_UNCHANGED.load(Ordering::Acquire));
    map.assert_bytes(&original);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) },
        0
    );
    3
}

fn refusal_cases(capability: SyncCore) -> usize {
    let map = Mapping::new();
    fixture(&map, 63, 256, NOPS[0]);
    fixture(&map, 127, 272, NOPS[1]);
    let original = map.snapshot();
    let a = map.bind(63, 11, 256, capability);
    let b = map.bind(127, 12, 272, capability);
    let a_refs = [&a];
    let refs = [&a, &b];
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&[], Direction::Apply) },
        Err(SyncPatchError::EmptyBatch)
    ));
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&[&a, &a], Direction::Apply) },
        Err(SyncPatchError::OverlappingMembers)
    ));
    map.assert_bytes(&original);
    // Stale second member: all leases must release and no first-member byte may change.
    map.put(128, &[original[128] ^ 1]);
    let stale = map.snapshot();
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&refs, Direction::Apply) },
        Err(SyncPatchError::Patch(PatchError::ExpectedBytesMismatch))
    ));
    map.assert_bytes(&stale);
    map.put(128, &[original[128]]);
    drop(unsafe { SynchronizedBatch::prepare(&refs, Direction::Apply).unwrap() });
    map.assert_bytes(&original);
    // Stale padding outside the eight-byte window is equally authenticated.
    map.put(56, &[original[56] ^ 1]);
    let stale = map.snapshot();
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&a_refs, Direction::Apply) },
        Err(SyncPatchError::Patch(PatchError::ExpectedBytesMismatch))
    ));
    map.assert_bytes(&stale);
    map.put(56, &[original[56]]);
    // A live untouched owner excludes a second prepared owner; dropping it permits retry.
    let held = unsafe { SynchronizedBatch::prepare(&a_refs, Direction::Apply).unwrap() };
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&a_refs, Direction::Apply) },
        Err(SyncPatchError::Patch(PatchError::Contended))
    ));
    map.assert_bytes(&original);
    drop(held);
    drop(unsafe { SynchronizedBatch::prepare(&a_refs, Direction::Apply).unwrap() });
    // Detect the calling thread's blocked SIGTRAP before any mutation.
    let mut mask: libc::sigset_t = unsafe { core::mem::zeroed() };
    let mut previous = mask;
    assert_eq!(unsafe { libc::sigemptyset(&mut mask) }, 0);
    assert_eq!(unsafe { libc::sigaddset(&mut mask, libc::SIGTRAP) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous) },
        0
    );
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&a_refs, Direction::Apply) },
        Err(SyncPatchError::Patch(PatchError::SignalHandlerInstall {
            errno: libc::EPERM
        }))
    ));
    map.assert_bytes(&original);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) },
        0
    );
    // Replaced disposition is detected; no generated execution occurs here.
    let mut router: libc::sigaction = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGTRAP, std::ptr::null(), &mut router) },
        0
    );
    let mut ignored = router;
    ignored.sa_sigaction = libc::SIG_IGN;
    ignored.sa_flags = 0;
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGTRAP, &ignored, std::ptr::null_mut()) },
        0
    );
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&a_refs, Direction::Apply) },
        Err(SyncPatchError::Patch(PatchError::SignalHandlerInstall {
            errno: libc::EPERM
        }))
    ));
    map.assert_bytes(&original);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGTRAP, &router, std::ptr::null_mut()) },
        0
    );
    drop(unsafe { SynchronizedBatch::prepare(&a_refs, Direction::Apply).unwrap() });
    map.assert_bytes(&original);
    // Initial envelope is one whole instruction, not an assertion admitting
    // several short instructions or a first instruction wider than eight bytes.
    for first in [
        &[0x90][..],
        &[0x0f, 0x1f, 0x40, 0][..],
        &[0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0][..],
    ] {
        let invalid = Mapping::new();
        fixture(&invalid, 32, 256, first);
        let before = invalid.snapshot();
        let scanner = InstructionScanner::default();
        let code = &before[32..32 + (first.len() + 6).max(8)];
        let address = (invalid.rx + 32) as u64;
        let scan = scanner.scan(code, address).unwrap();
        let plan = JumpPatchPlan::from_scan(
            &scanner,
            &scan,
            code,
            address,
            address,
            (invalid.rx + 256) as u64,
        )
        .unwrap();
        assert!(matches!(
            unsafe { SyncJumpPatch::bind(plan, (invalid.rw + 32) as *mut u8, capability) },
            Err(SyncPatchError::UnsupportedInstruction)
        ));
        invalid.assert_bytes(&before);
    }
    10
}

fn deny_membarrier() {
    // BPF checks x86-64 architecture, denies only SYS_membarrier with EPERM,
    // and allows the signal-mask/route queries and ownership checks afterward.
    let mut filters = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 0xc000003e,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x80000000,
        },
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
            k: libc::SYS_membarrier as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        },
    ];
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    // SAFETY: dedicated fresh process, valid finite filter retained for prctl.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
        0
    );
}

fn poisoned_barrier(capability: SyncCore, barrier: usize) {
    assert!((1..=3).contains(&barrier));
    let map = Mapping::new();
    fixture(&map, 63, 256, NOPS[0]);
    let original = map.snapshot();
    let patch = map.bind(63, 11, 256, capability);
    let refs = [&patch];
    let mut batch = unsafe { SynchronizedBatch::prepare(&refs, Direction::Apply).unwrap() };
    for _ in 0..(barrier * 2 - 1) {
        unsafe {
            batch.advance().unwrap();
        }
    }
    let phase = [
        Phase::GuardsPublished,
        Phase::BacksPublished,
        Phase::FrontsPublished,
    ][barrier - 1];
    assert_eq!(batch.receipt().phase, phase);
    let exact = phase_image(&original, &[(&patch, 63)], Direction::Apply, phase);
    map.assert_bytes(&exact);
    deny_membarrier();
    let failure = unsafe { batch.advance().unwrap_err() };
    assert_eq!(
        failure.error,
        SyncPatchError::Synchronize(liteinst2::sync_core::SyncCoreError::SystemCall {
            operation: liteinst2::sync_core::SyncCoreOperation::Synchronize,
            errno: libc::EPERM
        })
    );
    assert_eq!(failure.receipt.phase, phase);
    assert_eq!(failure.receipt.synchronizations, barrier - 1);
    assert!(failure.receipt.mutated && failure.receipt.writer_ownership_retained);
    assert_eq!(failure.receipt.failure, Some(failure.error));
    map.assert_bytes(&exact);
    // Failure stays terminal, even though phase three already exposed final bytes.
    assert_eq!(unsafe { batch.advance().unwrap_err() }, failure);
    map.assert_bytes(&exact);
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&refs, Direction::Apply) },
        Err(SyncPatchError::Patch(PatchError::Contended))
    ));
    drop(batch);
    assert!(matches!(
        unsafe { SynchronizedBatch::prepare(&refs, Direction::Apply) },
        Err(SyncPatchError::Patch(PatchError::Contended))
    ));
    map.assert_bytes(&exact);
    assert_eq!(patch.handled_guard_traps(), 0);
    // Never execute, rollback, unmap or unlock the poisoned source. Process exit
    // is the only resource release in these explicitly isolated negative modes.
    println!(
        "word-sync: denied_barrier={barrier} terminal=true retained_writers=1 executed_poisoned_source=0"
    );
}

fn main() {
    const {
        assert!(cfg!(all(target_os = "linux", target_arch = "x86_64")));
    }
    assert_eq!(
        std::fs::read_dir("/proc/self/task").unwrap().count(),
        1,
        "fresh main thread required"
    );
    // Geometry is a required positive host prerequisite, never a silent skip.
    assert_eq!(
        unsafe { libc::sysconf(libc::_SC_LEVEL1_DCACHE_LINESIZE) },
        64
    );
    assert_eq!(
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) },
        PAGE as libc::c_long
    );
    assert_eq!(
        unsafe { libc::sysconf(libc::_SC_LEVEL1_ICACHE_LINESIZE) },
        64
    );
    let capability = SyncCore::prepare().expect("required sync-core capability");
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() == 1 && arguments[0].starts_with("deny-") {
        let barrier: usize = arguments[0][5..].parse().unwrap();
        poisoned_barrier(capability, barrier);
        return;
    }
    assert!(
        arguments.is_empty(),
        "only fixed deny-1, deny-2, deny-3 modes are admitted"
    );
    let (cases, calls, traps) = all_splits(capability);
    let atomic_calls = atomic_cycles(capability);
    let (batch_calls, batch_traps) = two_member_batch(capability, false);
    let (mixed_calls, mixed_traps) = two_member_batch(capability, true);
    let saved_calls = saved_head(capability);
    let refusals = refusal_cases(capability);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    assert_eq!(
        (
            cases,
            calls + atomic_calls + batch_calls + mixed_calls + saved_calls,
            traps + batch_traps + mixed_traps,
            refusals
        ),
        (28, 263, 68, 10)
    );
    println!(
        "word-sync: split_cycles=28 atomic_cycles=4 batch_cycles=2 saved_head_cycles=1 calls=263 guard_deliveries=68 saved_signal_returns=3 prewrite_refusals=10"
    );
}
