#![cfg(all(target_arch = "aarch64", target_os = "linux"))]
//! Stopped-thread flip proofs: a worker thread repeatedly calls an
//! SVC stub; the patcher flips the site to a near island (and back)
//! while the worker is cooperatively parked under the publication
//! lease, with an explicit `isb` rendezvous acknowledgement. Plus the
//! self-thread BRK fallback flip against an owned SIGTRAP handler.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use liteinst_aarch64::emit::Strategy;
use liteinst_aarch64::{BtiTarget, Insn, bti, decode, movz, svc};
use liteinst_aarch64_patch::flip::FlipRequest;
use liteinst_aarch64_patch::island::Island;
use liteinst_aarch64_patch::site::{
    FallbackPermission, ResumeState, Site, SiteState, StopControl, StrategyPreference, TrapRoute,
};
use liteinst_aarch64_patch::{PatchError, Patcher};

const RET: u32 = 0xd65f_03c0;
const ENOSYS: u64 = (-38i64) as u64;
const L_MFD_EXEC: libc::c_uint = 0x0010;

struct SiteMap {
    fd: libc::c_int,
    rw: *mut u8,
    rx: *mut u8,
    len: usize,
}

impl SiteMap {
    fn new(words: &[u32]) -> Self {
        let page = liteinst_aarch64_patch::page_size().unwrap() as usize;
        let name = std::ffi::CString::new("liteinst-flip-site").unwrap();
        let fd = unsafe {
            libc::memfd_create(
                name.as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | L_MFD_EXEC,
            )
        };
        assert!(fd >= 0, "memfd: {}", std::io::Error::last_os_error());
        assert_eq!(unsafe { libc::ftruncate(fd, page as libc::off_t) }, 0);
        let map =
            |prot| unsafe { libc::mmap(std::ptr::null_mut(), page, prot, libc::MAP_SHARED, fd, 0) };
        let rw = map(libc::PROT_READ | libc::PROT_WRITE);
        let rx = map(libc::PROT_READ | libc::PROT_EXEC);
        assert_ne!(rw, libc::MAP_FAILED);
        assert_ne!(rx, libc::MAP_FAILED);
        let m = Self {
            fd,
            rw: rw as *mut u8,
            rx: rx as *mut u8,
            len: page,
        };
        for (i, w) in words.iter().enumerate() {
            unsafe { (m.rw.add(i * 4) as *mut u32).write_volatile(*w) };
        }
        m
    }
    fn call(&self) -> u64 {
        let f: extern "C" fn() -> u64 = unsafe { std::mem::transmute(self.rx as *const ()) };
        f()
    }
}

impl Drop for SiteMap {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.rw as *mut libc::c_void, self.len);
            libc::munmap(self.rx as *mut libc::c_void, self.len);
            libc::close(self.fd);
        }
    }
}

#[derive(Default)]
struct CoopShared {
    quit: AtomicBool,
    park_req: AtomicBool,
    parked: AtomicBool,
    release: AtomicBool,
    acked: AtomicBool,
    last: AtomicU64,
    calls: AtomicU64,
}

struct CoopStop {
    shared: Arc<CoopShared>,
    held: bool,
}

fn spin_until(mut cond: impl FnMut() -> bool, what: &str) {
    let start = std::time::Instant::now();
    while !cond() {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "timeout: {what}"
        );
        std::hint::spin_loop();
    }
}

// SAFETY (test): the only executor besides the test thread is the one
// worker, whose park/rendezvous flags this type drives; the flipping
// thread never executes the stub while holding the lease.
unsafe impl StopControl for CoopStop {
    fn acquire(&mut self) -> Result<(), PatchError> {
        if self.held {
            assert!(self.shared.parked.load(Ordering::SeqCst));
            return Ok(());
        }
        self.shared.release.store(false, Ordering::SeqCst);
        self.shared.acked.store(false, Ordering::SeqCst);
        self.shared.park_req.store(true, Ordering::SeqCst);
        spin_until(|| self.shared.parked.load(Ordering::SeqCst), "worker park");
        self.held = true;
        Ok(())
    }
    fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
        self.shared.release.store(true, Ordering::SeqCst);
        spin_until(|| self.shared.acked.load(Ordering::SeqCst), "worker ack");
        self.shared.park_req.store(false, Ordering::SeqCst);
        spin_until(
            || !self.shared.parked.load(Ordering::SeqCst),
            "worker leave",
        );
        self.held = false;
        Ok(vec![ResumeState::Released])
    }
}

fn stub_words() -> [u32; 3] {
    [movz(true, 8, 0xffff), svc(0), RET]
}

#[test]
fn stopped_thread_flip_and_rollback_change_live_behavior() {
    let map = SiteMap::new(&stub_words());
    map.sync_self();
    let shared = Arc::new(CoopShared::default());
    let worker_shared = Arc::clone(&shared);
    let rx_entry = map.rx as u64;
    let worker = std::thread::spawn(move || {
        let f: extern "C" fn() -> u64 = unsafe { std::mem::transmute(rx_entry as *const ()) };
        while !worker_shared.quit.load(Ordering::SeqCst) {
            if worker_shared.park_req.load(Ordering::SeqCst) {
                worker_shared.parked.store(true, Ordering::SeqCst);
                while !worker_shared.release.load(Ordering::SeqCst)
                    && !worker_shared.quit.load(Ordering::SeqCst)
                {
                    std::hint::spin_loop();
                }
                // Rendezvous: synchronize context, then acknowledge.
                unsafe { std::arch::asm!("isb", options(nostack)) };
                worker_shared.acked.store(true, Ordering::SeqCst);
                while worker_shared.park_req.load(Ordering::SeqCst)
                    && !worker_shared.quit.load(Ordering::SeqCst)
                {
                    std::hint::spin_loop();
                }
                worker_shared.parked.store(false, Ordering::SeqCst);
                continue;
            }
            let r = f();
            worker_shared.last.store(r, Ordering::SeqCst);
            worker_shared.calls.fetch_add(1, Ordering::SeqCst);
        }
    });
    spin_until(
        || shared.last.load(Ordering::SeqCst) == ENOSYS && shared.calls.load(Ordering::SeqCst) > 10,
        "pre-flip ENOSYS calls",
    );

    let mut patcher = Patcher::attested().unwrap();
    let island = Island::build(&[bti(BtiTarget::JumpCall), movz(true, 0, 42), RET]).unwrap();
    let mut site =
        unsafe { Site::from_aliases(map.rx as u64 + 4, map.rw.add(4) as *mut u32, svc(0), 1) };
    let mut stop = CoopStop {
        shared: Arc::clone(&shared),
        held: false,
    };
    let strategy = patcher
        .flip(
            &mut site,
            FlipRequest {
                island: Some(island),
                strategy: StrategyPreference::BranchOnly,
                fallback: FallbackPermission::RefuseTrap,
                trap_route: None,
            },
            &mut stop,
        )
        .unwrap();
    assert_eq!(strategy, Strategy::Branch);
    assert_eq!(site.state(), SiteState::Flipped);
    assert!(matches!(
        decode(unsafe { (map.rx.add(4) as *const u32).read_volatile() }),
        Insn::Branch { link: false, .. }
    ));
    spin_until(
        || shared.last.load(Ordering::SeqCst) == 42,
        "post-flip island calls",
    );

    patcher.rollback(&mut site, &mut stop).unwrap();
    assert_eq!(site.state(), SiteState::Unpatched);
    spin_until(
        || shared.last.load(Ordering::SeqCst) == ENOSYS,
        "post-rollback ENOSYS calls",
    );
    shared.quit.store(true, Ordering::SeqCst);
    shared.release.store(true, Ordering::SeqCst);
    shared.park_req.store(false, Ordering::SeqCst);
    worker.join().unwrap();
}

impl SiteMap {
    fn sync_self(&self) {
        // Stub written before first execution; sync it once here.
        // (Patcher::attested separately probes per its own contract.)
        unsafe { liteinst_aarch64_patch::cache::sync_icache(self.rw, self.rx, self.len).unwrap() };
    }
}

static BRK_HITS: AtomicU32 = AtomicU32::new(0);
static BRK_IMM: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn on_trap(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    let ctx = unsafe { &mut *(ctx as *mut libc::ucontext_t) };
    let pc = ctx.uc_mcontext.pc;
    let word = unsafe { (pc as *const u32).read_volatile() };
    BRK_IMM.store((word >> 5) & 0xffff, Ordering::SeqCst);
    ctx.uc_mcontext.regs[0] = 42;
    ctx.uc_mcontext.pc = pc + 4;
    BRK_HITS.fetch_add(1, Ordering::SeqCst);
}

struct SelfStop;
// SAFETY (test): single-threaded test; the flipping thread is the
// only executor and never inside the stub while flipping.
unsafe impl StopControl for SelfStop {
    fn acquire(&mut self) -> Result<(), PatchError> {
        Ok(())
    }
    fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
        unsafe { std::arch::asm!("isb", options(nostack)) };
        Ok(vec![ResumeState::SyncAcked])
    }
}

#[test]
fn brk_fallback_flip_reaches_owned_handler() {
    let map = SiteMap::new(&stub_words());
    map.sync_self();
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_trap as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGTRAP, &action, &mut old) },
        0
    );

    let mut patcher = Patcher::attested().unwrap();
    let mut site =
        unsafe { Site::from_aliases(map.rx as u64 + 4, map.rw.add(4) as *mut u32, svc(0), 3) };
    let strategy = patcher
        .flip(
            &mut site,
            FlipRequest {
                island: None,
                strategy: StrategyPreference::TrapOnly,
                fallback: FallbackPermission::RefuseTrap,
                trap_route: Some(TrapRoute {
                    brk_imm: 0x4c01,
                    generation: 3,
                }),
            },
            &mut SelfStop,
        )
        .unwrap();
    assert_eq!(strategy, Strategy::Trap);
    let result = map.call();
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGTRAP, &old, std::ptr::null_mut()) },
        0
    );
    assert_eq!(result, 42);
    assert_eq!(BRK_HITS.load(Ordering::SeqCst), 1);
    assert_eq!(BRK_IMM.load(Ordering::SeqCst), 0x4c01);
}
