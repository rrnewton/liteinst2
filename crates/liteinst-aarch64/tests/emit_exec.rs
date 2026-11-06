#![cfg(target_arch = "aarch64")]
//! Positive execution tests for the emitter: a real SVC site in a dual
//! RW/RX memfd mapping is flipped to `B` (near island) or `BRK` (trap
//! fallback) and then called. These run only on AArch64 hosts (64 KiB
//! metal and 4 KiB guests alike; the page size is queried with
//! `sysconf`, never assumed). The library stays fact-only: all mapping,
//! writing and cache maintenance in this file is test harness code.

use std::ffi::CString;
use std::sync::atomic::{AtomicU32, Ordering};

use liteinst_aarch64::emit::{page_span, svc_fallback_word, svc_patch_word};
use liteinst_aarch64::{BtiTarget, Insn, branch, bti, decode, movz, svc};

const RET: u32 = 0xd65f_03c0;
const MAGIC: u64 = 42;
const ISLAND_OFF: usize = 256;
/// `MFD_EXEC` (kernel 6.3+); defined locally so the locked libc version
/// need not carry the constant.
const L_MFD_EXEC: libc::c_uint = 0x0010;

fn page_size() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(value > 0, "sysconf(_SC_PAGESIZE) failed: {value}");
    value as u64
}

/// Architected clear-cache sequence over `[base, base + len)`: clean
/// data lines to the point of unification, invalidate instruction
/// lines, then synchronise. Line sizes come from CTR_EL0 at runtime.
fn clear_cache(base: *mut u8, len: usize) {
    use std::arch::asm;
    let ctr: u64;
    unsafe { asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let dline = 4usize << ((ctr >> 16) & 0xf);
    let iline = 4usize << (ctr & 0xf);
    let start = base as usize;
    let end = start + len;
    let mut addr = start & !(dline - 1);
    while addr < end {
        unsafe { asm!("dc cvau, {0}", in(reg) addr, options(nostack)) };
        addr += dline;
    }
    unsafe { asm!("dsb ish", options(nostack)) };
    let mut addr = start & !(iline - 1);
    while addr < end {
        unsafe { asm!("ic ivau, {0}", in(reg) addr, options(nostack)) };
        addr += iline;
    }
    unsafe {
        asm!("dsb ish", options(nostack));
        asm!("isb", options(nostack));
    }
}

struct DualMap {
    fd: libc::c_int,
    rw: *mut u8,
    rx: *mut u8,
    len: usize,
}

impl DualMap {
    fn new(payload_bytes: usize) -> Self {
        let page = page_size();
        let len = page_span(page, payload_bytes as u64).expect("page span") as usize;
        let name = CString::new("liteinst-emit-exec").unwrap();
        let fd = unsafe {
            libc::memfd_create(
                name.as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | L_MFD_EXEC,
            )
        };
        assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
        let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
        assert_eq!(rc, 0, "ftruncate: {}", std::io::Error::last_os_error());
        let rw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(
            rw,
            libc::MAP_FAILED,
            "mmap rw: {}",
            std::io::Error::last_os_error()
        );
        let rx = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(
            rx,
            libc::MAP_FAILED,
            "mmap rx: {}",
            std::io::Error::last_os_error()
        );
        Self {
            fd,
            rw: rw as *mut u8,
            rx: rx as *mut u8,
            len,
        }
    }

    fn write_word(&self, byte_off: usize, word: u32) {
        assert_eq!(byte_off % 4, 0);
        unsafe { (self.rw.add(byte_off) as *mut u32).write_volatile(word) };
    }

    fn rx_word(&self, byte_off: usize) -> u32 {
        unsafe { (self.rx.add(byte_off) as *const u32).read_volatile() }
    }

    fn sync(&self) {
        clear_cache(self.rx, self.len);
    }

    fn rx_addr(&self, byte_off: usize) -> u64 {
        self.rx as u64 + byte_off as u64
    }

    /// Layout: `svc #0; ret` at 0, island at ISLAND_OFF:
    /// `bti jc; mov x0, #42; b .+4's resume (the ret)`.
    fn build_stub(&self) {
        self.write_word(0, svc(0));
        self.write_word(4, RET);
        let back = branch(false, 4 - (ISLAND_OFF as i64 + 8)).unwrap();
        self.write_word(ISLAND_OFF, bti(BtiTarget::JumpCall));
        self.write_word(ISLAND_OFF + 4, movz(true, 0, MAGIC as u32));
        self.write_word(ISLAND_OFF + 8, back);
        self.sync();
    }

    fn call(&self) -> u64 {
        let f: extern "C" fn() -> u64 = unsafe { std::mem::transmute(self.rx as *const ()) };
        f()
    }
}

impl Drop for DualMap {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.rw as *mut libc::c_void, self.len);
            libc::munmap(self.rx as *mut libc::c_void, self.len);
            libc::close(self.fd);
        }
    }
}

#[test]
fn svc_to_b_executes_the_island() {
    let page = page_size();
    eprintln!("svc_to_b page_size={page}");
    assert!(page.is_power_of_two());
    let map = DualMap::new(ISLAND_OFF + 16);
    map.build_stub();
    assert_eq!(
        decode(RET),
        Insn::BranchReg {
            kind: liteinst_aarch64::BranchRegKind::Return,
            rn: 30
        }
    );
    let patch = svc_patch_word(svc(0), map.rx_addr(0), map.rx_addr(ISLAND_OFF))
        .expect("island in branch range");
    // The single aligned word store that publishes the patch.
    map.write_word(0, patch);
    map.sync();
    assert_eq!(
        decode(map.rx_word(0)),
        Insn::Branch {
            link: false,
            offset: ISLAND_OFF as i64
        }
    );
    assert_eq!(map.call(), MAGIC);
}

static TRAP_HITS: AtomicU32 = AtomicU32::new(0);
static TRAP_IMM: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn on_trap(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    let ctx = unsafe { &mut *(ctx as *mut libc::ucontext_t) };
    let pc = ctx.uc_mcontext.pc;
    let word = unsafe { (pc as *const u32).read_volatile() };
    TRAP_IMM.store((word >> 5) & 0xffff, Ordering::SeqCst);
    ctx.uc_mcontext.regs[0] = MAGIC;
    ctx.uc_mcontext.pc = pc + 4;
    TRAP_HITS.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn svc_to_brk_reaches_the_trap_handler() {
    let page = page_size();
    eprintln!("svc_to_brk page_size={page}");
    let map = DualMap::new(ISLAND_OFF + 16);
    map.build_stub();
    let patch = svc_fallback_word(svc(0), 0x4c01).expect("svc site");
    map.write_word(0, patch);
    map.sync();

    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_trap as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::sigaction(libc::SIGTRAP, &action, &mut old) };
    assert_eq!(rc, 0, "sigaction: {}", std::io::Error::last_os_error());
    let result = map.call();
    let rc = unsafe { libc::sigaction(libc::SIGTRAP, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "restore sigaction");
    assert_eq!(result, MAGIC);
    assert_eq!(TRAP_HITS.load(Ordering::SeqCst), 1);
    assert_eq!(TRAP_IMM.load(Ordering::SeqCst), 0x4c01);
}
