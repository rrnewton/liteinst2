//! Executable cache allocation, the entry bridge, dispatcher loop,
//! and fault recovery through the PC map.
//!
//! Execution model (P1a): in-process. The dispatcher loads full guest
//! state, enters the cache, and the cache returns only at exit stubs
//! (return / indirect / syscall / nondet) or via the fault handler.
//! A synchronous fault inside copied code is reported at the precise
//! source PC recovered through the PC map; it is never delivered as
//! a cache PC.

use std::sync::atomic::{AtomicPtr, Ordering};

use crate::cache::{CacheIndex, CacheRecord};
use crate::refuse::Refuse;
use crate::state::{
    GuestState, JitData, OFF_HOST_R12, OFF_HOST_R13, OFF_HOST_R14, OFF_HOST_R15, OFF_HOST_RBP,
    OFF_HOST_RBX, OFF_HOST_RSP, OFF_STATE, OFF_TMP_ENTRY, ST_R8, ST_R9, ST_R10, ST_R11, ST_R12,
    ST_R13, ST_R14, ST_R15, ST_RAX, ST_RBP, ST_RBX, ST_RCX, ST_RDI, ST_RDX, ST_RFLAGS, ST_RSI,
    ST_RSP, exit_kind,
};
use crate::translate::{Translation, translate};
use crate::types::{CacheKey, CountProfile, Generation, RegionFacts, byte_hash};

pub const CODE_CAP: usize = 1 << 18;
const PAGE: usize = 4096;

core::arch::global_asm!(
    ".global liteinst_jit_enter",
    "liteinst_jit_enter:",
    "mov [rdi + {host_rsp}], rsp",
    "mov [rdi + {host_rbx}], rbx",
    "mov [rdi + {host_rbp}], rbp",
    "mov [rdi + {host_r12}], r12",
    "mov [rdi + {host_r13}], r13",
    "mov [rdi + {host_r14}], r14",
    "mov [rdi + {host_r15}], r15",
    "mov [rdi + {tmp}], rsi",
    "push qword ptr [rdi + {flags}]",
    "popfq",
    "mov rsp, [rdi + {rsp}]",
    "mov rax, [rdi + {tmp}]",
    "lea rsp, [rsp - 8]",
    "mov [rsp], rax",
    "mov rax, [rdi + {rax}]",
    "mov rbx, [rdi + {rbx}]",
    "mov rcx, [rdi + {rcx}]",
    "mov rdx, [rdi + {rdx}]",
    "mov rsi, [rdi + {rsi}]",
    "mov rbp, [rdi + {rbp}]",
    "mov r8, [rdi + {r8}]",
    "mov r9, [rdi + {r9}]",
    "mov r10, [rdi + {r10}]",
    "mov r11, [rdi + {r11}]",
    "mov r12, [rdi + {r12}]",
    "mov r13, [rdi + {r13}]",
    "mov r14, [rdi + {r14}]",
    "mov r15, [rdi + {r15}]",
    "mov rdi, [rdi + {rdi}]",
    "ret",
    host_rsp = const OFF_HOST_RSP,
    host_rbx = const OFF_HOST_RBX,
    host_rbp = const OFF_HOST_RBP,
    host_r12 = const OFF_HOST_R12,
    host_r13 = const OFF_HOST_R13,
    host_r14 = const OFF_HOST_R14,
    host_r15 = const OFF_HOST_R15,
    tmp = const OFF_TMP_ENTRY,
    flags = const OFF_STATE + ST_RFLAGS,
    rsp = const OFF_STATE + ST_RSP,
    rax = const OFF_STATE + ST_RAX,
    rbx = const OFF_STATE + ST_RBX,
    rcx = const OFF_STATE + ST_RCX,
    rdx = const OFF_STATE + ST_RDX,
    rsi = const OFF_STATE + ST_RSI,
    rdi = const OFF_STATE + ST_RDI,
    rbp = const OFF_STATE + ST_RBP,
    r8 = const OFF_STATE + ST_R8,
    r9 = const OFF_STATE + ST_R9,
    r10 = const OFF_STATE + ST_R10,
    r11 = const OFF_STATE + ST_R11,
    r12 = const OFF_STATE + ST_R12,
    r13 = const OFF_STATE + ST_R13,
    r14 = const OFF_STATE + ST_R14,
    r15 = const OFF_STATE + ST_R15,
);

unsafe extern "C" {
    fn liteinst_jit_enter(data: *mut JitData, entry: *const u8);
}

/// What a handler asks the dispatcher to do after an exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resume {
    At(u64),
    Done,
}

/// Serves instructions that exit their block. Implementors must leave
/// `state` exactly as native execution of the instruction would
/// (including the `RCX`/`R11` syscall clobbers when they emulate a
/// syscall) and name the resume PC.
pub trait Handler {
    fn syscall(
        &mut self,
        state: &mut GuestState,
        insn_pc: u64,
        next_pc: u64,
    ) -> Result<Resume, Refuse>;
    fn nondet(
        &mut self,
        _state: &mut GuestState,
        insn_pc: u64,
        _next_pc: u64,
    ) -> Result<Resume, Refuse> {
        Err(Refuse::NoHandler { src_pc: insn_pc })
    }
}

/// Guest memory reads the dispatcher needs (return targets).
pub trait GuestMemory {
    fn read_u64(&self, addr: u64) -> Option<u64>;
}

/// In-process guest memory via `process_vm_readv` on this process, so
/// a bad guest address fails cleanly instead of faulting the
/// dispatcher.
pub struct ProcessMemory;

impl GuestMemory for ProcessMemory {
    fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut buf = [0u8; 8];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: 8,
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut libc::c_void,
            iov_len: 8,
        };
        // SAFETY: both iovecs describe live 8-byte buffers for the
        // duration of the call; failure is reported, never faults.
        let n = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
        (n == 8).then(|| u64::from_ne_bytes(buf))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub state: GuestState,
    pub branches: u64,
    pub instructions: u64,
    pub exits: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fault {
    pub src_pc: u64,
    pub addr: u64,
    pub signum: i32,
    pub state: GuestState,
    pub branches: u64,
    pub instructions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunError {
    Refuse(Refuse),
    Fault(Box<Fault>),
}

impl From<Refuse> for RunError {
    fn from(r: Refuse) -> RunError {
        RunError::Refuse(r)
    }
}
impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "liteinst-jit run: {self:?}")
    }
}
impl std::error::Error for RunError {}

struct Arena {
    base: *mut u8,
    total: usize,
}

impl Arena {
    fn new() -> Result<Arena, Refuse> {
        let total = CODE_CAP + PAGE;
        // SAFETY: anonymous private mapping of `total` bytes.
        let p = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(Refuse::MappingPolicy {
                operation: "mmap cache",
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        Ok(Arena {
            base: p.cast(),
            total,
        })
    }
    fn data_addr(&self) -> u64 {
        self.base as u64 + CODE_CAP as u64
    }
    fn install_code(&mut self, code: &[u8]) -> Result<(), Refuse> {
        if code.len() > CODE_CAP {
            return Err(Refuse::BudgetExceeded { what: "code cache" });
        }
        // SAFETY: the mapping is RW and at least CODE_CAP bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), self.base, code.len());
            if libc::mprotect(
                self.base.cast(),
                CODE_CAP,
                libc::PROT_READ | libc::PROT_EXEC,
            ) != 0
            {
                return Err(Refuse::MappingPolicy {
                    operation: "mprotect cache RX",
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                });
            }
        }
        Ok(())
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: owned mapping from `new`.
        unsafe {
            libc::munmap(self.base.cast(), self.total);
        }
    }
}

struct ActiveRun {
    gen_lo: u64,
    gen_hi: u64,
    data: *mut JitData,
    fault_gen_pc: u64,
    fault_addr: u64,
    fault_sig: i32,
}

// SAFETY discipline: `ACTIVE` is set only by the single-threaded P1a
// dispatcher around cache entry, and cleared before any other code
// runs guest state. The handler treats it as read-only except for
// the fault record fields of the pointee.
static ACTIVE: AtomicPtr<ActiveRun> = AtomicPtr::new(core::ptr::null_mut());
// glibc sigjmp_buf is opaque (jmp_buf + saved mask); 512 bytes is
// comfortably larger than the x86-64 layout. Bound directly because
// the libc crate does not export the sigjmp family.
static mut JMP_BUF: [u64; 64] = [0; 64];

unsafe extern "C" {
    #[link_name = "__sigsetjmp"]
    fn sigsetjmp_raw(env: *mut u8, savemask: i32) -> i32;
    fn siglongjmp(env: *mut u8, val: i32) -> !;
}

/// Previous dispositions, chained for faults outside the cache
/// (notably the Rust runtime's stack-overflow SIGSEGV handler).
/// Entries are `(handler, flags)` per signal in `FAULT_SIGNALS`.
static mut PREV_HANDLERS: [(usize, i32); 3] = [(usize::MAX, 0); 3];
const FAULT_SIGNALS: [i32; 3] = [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL];

fn chain_previous(sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let idx = FAULT_SIGNALS.iter().position(|&s| s == sig).unwrap_or(0);
    // SAFETY: PREV_HANDLERS is written once at install time before
    // any guest code runs, single-threaded dispatcher discipline.
    let (handler, flags) = unsafe { PREV_HANDLERS[idx] };
    if handler == usize::MAX || handler == libc::SIG_DFL || handler == libc::SIG_IGN {
        // SAFETY: default disposition and re-raise reproduces the
        // kernel-visible fault exactly.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return;
    }
    if flags & libc::SA_SIGINFO != 0 {
        // SAFETY: the previous action was installed with SA_SIGINFO,
        // so its handler has the three-argument signature.
        let f: extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) =
            unsafe { core::mem::transmute(handler) };
        f(sig, info, ctx);
    } else {
        // SAFETY: classic one-argument signal handler.
        let f: extern "C" fn(i32) = unsafe { core::mem::transmute(handler) };
        f(sig);
    }
}

extern "C" fn fault_handler(sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let active = ACTIVE.load(Ordering::SeqCst);
    if active.is_null() || ctx.is_null() {
        chain_previous(sig, info, ctx);
        return;
    }
    // SAFETY: ctx is the kernel-provided ucontext for this signal.
    let gregs = unsafe { (*(ctx as *const libc::ucontext_t)).uc_mcontext.gregs };
    let rip = gregs[libc::REG_RIP as usize] as u64;
    // SAFETY: `active` is live for the whole cache-entry window.
    let run = unsafe { &mut *active };
    if rip < run.gen_lo || rip >= run.gen_hi {
        chain_previous(sig, info, ctx);
        return;
    }
    run.fault_gen_pc = rip;
    run.fault_sig = sig;
    run.fault_addr = if info.is_null() {
        0
    } else {
        // SAFETY: info is kernel-provided for this signal.
        unsafe { (*info).si_addr() as usize as u64 }
    };
    // SAFETY: `data` points at the allocation-resident JitData.
    let st = unsafe { &mut (*run.data).state };
    st.rax = gregs[libc::REG_RAX as usize] as u64;
    st.rbx = gregs[libc::REG_RBX as usize] as u64;
    st.rcx = gregs[libc::REG_RCX as usize] as u64;
    st.rdx = gregs[libc::REG_RDX as usize] as u64;
    st.rsi = gregs[libc::REG_RSI as usize] as u64;
    st.rdi = gregs[libc::REG_RDI as usize] as u64;
    st.rbp = gregs[libc::REG_RBP as usize] as u64;
    st.rsp = gregs[libc::REG_RSP as usize] as u64;
    st.r8 = gregs[libc::REG_R8 as usize] as u64;
    st.r9 = gregs[libc::REG_R9 as usize] as u64;
    st.r10 = gregs[libc::REG_R10 as usize] as u64;
    st.r11 = gregs[libc::REG_R11 as usize] as u64;
    st.r12 = gregs[libc::REG_R12 as usize] as u64;
    st.r13 = gregs[libc::REG_R13 as usize] as u64;
    st.r14 = gregs[libc::REG_R14 as usize] as u64;
    st.r15 = gregs[libc::REG_R15 as usize] as u64;
    st.rflags = gregs[libc::REG_EFL as usize] as u64;
    // SAFETY: JMP_BUF was armed by sigsetjmp in the dispatcher for
    // exactly this cache-entry window.
    unsafe {
        siglongjmp(core::ptr::addr_of_mut!(JMP_BUF).cast(), 1);
    }
}

fn install_fault_handlers() -> Result<(), Refuse> {
    for (idx, sig) in FAULT_SIGNALS.into_iter().enumerate() {
        let mut old: libc::sigaction = unsafe { core::mem::zeroed() };
        // SAFETY: query-only sigaction with a null new action.
        if unsafe { libc::sigaction(sig, core::ptr::null(), &mut old) } != 0 {
            return Err(Refuse::SignalOwnership { signum: sig });
        }
        if old.sa_sigaction == fault_handler as *const () as usize {
            continue;
        }
        // Record whatever was there (including the Rust runtime's
        // stack-overflow handler) for chaining; P1a intercepts only
        // cache-range PCs, everything else forwards untouched.
        // SAFETY: written before guest execution, read by the
        // handler under the same single-threaded discipline.
        unsafe {
            if PREV_HANDLERS[idx].0 == usize::MAX {
                PREV_HANDLERS[idx] = (old.sa_sigaction, old.sa_flags);
            }
        }
        let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
        act.sa_sigaction = fault_handler as *const () as usize;
        act.sa_flags = libc::SA_SIGINFO;
        // SAFETY: previous disposition recorded above for chaining.
        if unsafe { libc::sigaction(sig, &act, core::ptr::null_mut()) } != 0 {
            return Err(Refuse::SignalOwnership { signum: sig });
        }
    }
    Ok(())
}

fn lahf_available() -> bool {
    let r = core::arch::x86_64::__cpuid_count(0x8000_0001, 0);
    r.ecx & 1 != 0
}

/// A prepared executable translation plus its cache index.
pub struct Executable {
    // Kept alive for the mapping's lifetime; dropped last.
    #[allow(dead_code)]
    arena: Arena,
    translation: Translation,
    index: CacheIndex,
    data: *mut JitData,
    profile: CountProfile,
    valid: bool,
}

impl Executable {
    pub fn prepare(
        region: &RegionFacts,
        entry: u64,
        profile: CountProfile,
    ) -> Result<Executable, Refuse> {
        if !lahf_available() {
            return Err(Refuse::Arch {
                what: "LAHF/SAHF unavailable in 64-bit mode",
            });
        }
        let mut arena = Arena::new()?;
        let base = arena.base as u64;
        let data_addr = arena.data_addr();
        let translation = translate(region, entry, profile, base, data_addr)?;
        arena.install_code(&translation.code)?;
        let mut index = CacheIndex::new(region.generation);
        for block in translation.blocks.values() {
            let end = block
                .insns
                .last()
                .map(|i| i.pc + i.len as u64)
                .unwrap_or(block.start)
                .max(
                    block
                        .term
                        .as_ref()
                        .map_or(block.start, |t| t.pc + t.len as u64),
                );
            let bytes = region
                .slice_from(block.start)
                .map(|s| &s[..(end - block.start) as usize])
                .unwrap_or(&[]);
            index.insert(CacheRecord {
                key: CacheKey {
                    src_pc: block.start,
                    byte_hash: byte_hash(bytes),
                    generation: region.generation,
                    profile,
                },
                src_start: block.start,
                src_end: end,
                gen_entry: translation.block_gen[&block.start],
            })?;
        }
        Ok(Executable {
            arena,
            translation,
            index,
            data: data_addr as *mut JitData,
            profile,
            valid: true,
        })
    }

    pub fn translation(&self) -> &Translation {
        &self.translation
    }

    /// Invalidate overlapping entries and advance the generation.
    /// After any invalidation the executable refuses to run: P1a
    /// eviction is flush-and-reprepare, never patch-in-place.
    pub fn invalidate(
        &mut self,
        src_start: u64,
        src_end: u64,
        new_generation: Generation,
    ) -> Result<usize, Refuse> {
        let n = self.index.invalidate(src_start, src_end, new_generation)?;
        self.valid = false;
        Ok(n)
    }

    /// Run from `state.rip` until a return pops `return_sentinel`, a
    /// handler says `Done`, a named refusal, or a fault.
    pub fn run(
        &mut self,
        mut state: GuestState,
        handler: &mut dyn Handler,
        mem: &dyn GuestMemory,
        return_sentinel: u64,
    ) -> Result<Outcome, RunError> {
        if !self.valid {
            return Err(Refuse::StaleGeneration {
                expected: self.index.generation().0,
                found: self.index.generation().0,
            }
            .into());
        }
        install_fault_handlers()?;
        let mut exits: u64 = 0;
        // Counters accumulate across dispatcher re-entries: each
        // entry seeds JitData with the running totals.
        let (mut tot_branches, mut tot_instructions) = (0u64, 0u64);
        loop {
            let Some(&gen_entry) = self.translation.block_gen.get(&state.rip) else {
                return Err(Refuse::IndirectUnresolved { src_pc: state.rip }.into());
            };
            // SAFETY: `data` is the RW data page of the live arena.
            unsafe {
                let mut fresh = JitData::new(state);
                fresh.branch_count = tot_branches;
                fresh.instruction_count = tot_instructions;
                core::ptr::write(self.data, fresh);
            }
            let mut active = ActiveRun {
                gen_lo: self.translation.gen_base,
                gen_hi: self
                    .translation
                    .gen_base
                    .wrapping_add(self.translation.code.len() as u64),
                data: self.data,
                fault_gen_pc: 0,
                fault_addr: 0,
                fault_sig: 0,
            };
            ACTIVE.store(&mut active, Ordering::SeqCst);
            // SAFETY: sigsetjmp arms the fault return; liteinst_jit_enter
            // transfers full state to generated code which returns only
            // through the common exit or the fault handler.
            let jumped = unsafe { sigsetjmp_raw(core::ptr::addr_of_mut!(JMP_BUF).cast(), 1) };
            if jumped == 0 {
                unsafe {
                    liteinst_jit_enter(self.data, gen_entry as *const u8);
                }
            }
            ACTIVE.store(core::ptr::null_mut(), Ordering::SeqCst);
            // SAFETY: reading the data page after exit/fault.
            let data = unsafe { core::ptr::read(self.data) };
            state = data.state;
            if jumped != 0 {
                let src_pc = self
                    .translation
                    .pcmap
                    .lookup(active.fault_gen_pc)
                    .map(|e| e.src_pc)
                    .unwrap_or(0);
                state.rip = src_pc;
                let mut instructions = data.instruction_count;
                if self.profile == CountProfile::BranchesAndInstructions {
                    for block in self.translation.blocks.values() {
                        let pcs = block.insn_pcs();
                        if let Some(pos) = pcs.iter().position(|&p| p == src_pc) {
                            instructions -= block.instruction_total() - pos as u64;
                            break;
                        }
                    }
                }
                return Err(RunError::Fault(Box::new(Fault {
                    src_pc,
                    addr: active.fault_addr,
                    signum: active.fault_sig,
                    state,
                    branches: data.branch_count,
                    instructions,
                })));
            }
            exits += 1;
            tot_branches = data.branch_count;
            tot_instructions = data.instruction_count;
            let done = Outcome {
                state,
                branches: tot_branches,
                instructions: tot_instructions,
                exits,
            };
            match data.exit_kind {
                exit_kind::RETURN => {
                    let Some(target) = mem.read_u64(state.rsp) else {
                        return Err(RunError::Fault(Box::new(Fault {
                            src_pc: data.exit_src,
                            addr: state.rsp,
                            signum: libc::SIGSEGV,
                            state,
                            branches: data.branch_count,
                            instructions: data.instruction_count,
                        })));
                    };
                    state.rsp = state.rsp.wrapping_add(8);
                    state.rip = target;
                    if target == return_sentinel {
                        let mut out = done;
                        out.state = state;
                        return Ok(out);
                    }
                    // Loop: the block_gen lookup above resolves the
                    // return target or refuses it by name.
                }
                exit_kind::INDIRECT => {
                    return Err(Refuse::IndirectUnresolved {
                        src_pc: data.exit_src,
                    }
                    .into());
                }
                exit_kind::SYSCALL => {
                    state.rip = data.exit_src;
                    let resume = handler.syscall(&mut state, data.exit_src, data.exit_next)?;
                    tot_instructions += 1;
                    match resume {
                        Resume::Done => {
                            let mut out = done;
                            out.state = state;
                            out.instructions = tot_instructions;
                            return Ok(out);
                        }
                        Resume::At(pc) => {
                            state.rip = pc;
                        }
                    }
                }
                exit_kind::NONDET => {
                    state.rip = data.exit_src;
                    let resume = handler.nondet(&mut state, data.exit_src, data.exit_next)?;
                    tot_instructions += 1;
                    match resume {
                        Resume::Done => {
                            let mut out = done;
                            out.state = state;
                            out.instructions = tot_instructions;
                            return Ok(out);
                        }
                        Resume::At(pc) => {
                            state.rip = pc;
                        }
                    }
                }
                other => {
                    return Err(Refuse::Unrelocatable {
                        src_pc: data.exit_src,
                        reason: if other == 0 {
                            "cache returned without exit kind"
                        } else {
                            "unknown exit kind"
                        },
                    }
                    .into());
                }
            }
        }
    }
}
