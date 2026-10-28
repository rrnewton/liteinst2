//! Fixed optional-profile oracle; no frontend accounting or performance claim.
//! Child module deliberately reuses private wire/step/cleanup helpers. Its frame
//! and whole gate bytes are distinct from the enclosing mandatory adapter.
use super::*;
use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::ControlIdentity;
use liteinst2::planner::HookSemantics;
use liteinst2::precontext::{CallScratch, PreContextAction, PreContextRole, PreContextSelector};
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy,
    plan_precontext_coalesced_detailed_after,
};
use liteinst2::trampoline::HookContext;
use std::os::fd::{AsRawFd, OwnedFd};

// Linux UAPI asm-generic/siginfo.h: illegal-operand si_code (libc does not export it).
const ILL_ILLOPN: i32 = 2;
const LEAF: [u8; 28] = [
    0x0f, 0xb6, 0x07, 0x8d, 0x4e, 0x01, 0x83, 0xfe, 0x00, 0x74, 0x0a, 0x0f, 0xb6, 0x4f, 0x01, 0x01,
    0xc8, 0x83, 0xc0, 0x07, 0xc3, 0x8d, 0x40, 0x09, 0x8d, 0x49, 0x05, 0xc3,
];
const HEADS: [u64; 11] = [0, 3, 6, 9, 11, 15, 17, 20, 21, 24, 27];
const PATH0: [u64; 7] = [0, 3, 6, 9, 21, 24, 27];
const PATH1: [u64; 8] = [0, 3, 6, 9, 11, 15, 17, 20];
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const OPTIONAL_GATE: [u8; 31] = [
    0x53, 0x48, 0x89, 0xfb, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x4c, 0x8b, 0x5b, 0x48, 0x4c, 0x89,
    0x5b, 0x50, 0x48, 0x89, 0x63, 0x58, 0x41, 0xff, 0xd3, 0x48, 0x89, 0x63, 0x60, 0x5b, 0xc3,
];
#[repr(C)]
struct Frame {
    scratch: CallScratch,
    target: u64,
    observed: u64,
    pre: u64,
    resumed: u64,
    sequence: u64,
    pid: u64,
    tid: u64,
}
const _: () = {
    assert!(core::mem::size_of::<CallScratch>() == 72);
    assert!(core::mem::size_of::<Frame>() == 128);
    assert!(core::mem::align_of::<CallScratch>() == 8);
    assert!(core::mem::align_of::<Frame>() == 8);
    assert!(core::mem::offset_of!(Frame, scratch) == 0);
    assert!(core::mem::offset_of!(Frame, target) == 72);
    assert!(core::mem::offset_of!(Frame, observed) == 80);
    assert!(core::mem::offset_of!(Frame, pre) == 88);
    assert!(core::mem::offset_of!(Frame, resumed) == 96);
    assert!(core::mem::offset_of!(Frame, sequence) == 104);
    assert!(core::mem::offset_of!(Frame, pid) == 112);
    assert!(core::mem::offset_of!(Frame, tid) == 120);
};
// Used both by the actual gate reads and the focused wrong-layout controls.
const FRAME_LAYOUT: [usize; 12] = [
    core::mem::size_of::<CallScratch>(),
    core::mem::size_of::<Frame>(),
    core::mem::offset_of!(Frame, scratch),
    core::mem::offset_of!(Frame, target),
    core::mem::offset_of!(Frame, observed),
    core::mem::offset_of!(Frame, pre),
    core::mem::offset_of!(Frame, resumed),
    core::mem::offset_of!(Frame, sequence),
    core::mem::offset_of!(Frame, pid),
    core::mem::offset_of!(Frame, tid),
    core::mem::align_of::<CallScratch>(),
    core::mem::align_of::<Frame>(),
];
fn gate_layout(bytes: &[u8], layout: [usize; 12]) -> Result<(), &'static str> {
    if layout != [72, 128, 0, 72, 80, 88, 96, 104, 112, 120, 8, 8] {
        return Err("scratch layout");
    }
    if bytes != OPTIONAL_GATE {
        return Err("gate bytes");
    }
    Ok(())
}
core::arch::global_asm!(
    r#"
.pushsection .text.li2_optional_oracle,"ax",@progbits
.global __li2_optional_oracle_call
.hidden __li2_optional_oracle_call
.type __li2_optional_oracle_call,@function
__li2_optional_oracle_call:
 push rbx
 mov rbx,rdi
 mov rdi,rsi
 mov rsi,rdx
 mov r11,[rbx+72]
 mov [rbx+80],r11
 mov [rbx+88],rsp
 call r11
 mov [rbx+96],rsp
 pop rbx
 ret
.size __li2_optional_oracle_call,.-__li2_optional_oracle_call
.popsection
"#
);
unsafe extern "C" {
    fn __li2_optional_oracle_call(frame: *mut Frame, data: *const u8, mode: usize) -> u64;
}
fn gate() -> u64 {
    __li2_optional_oracle_call as *const () as usize as u64
}
fn pid() -> u64 {
    unsafe { libc::getpid() as u64 }
}
fn tid() -> u64 {
    unsafe { libc::syscall(libc::SYS_gettid) as u64 }
}
fn single_main() {
    assert_eq!(pid(), tid());
    let names: Vec<_> = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, [std::ffi::OsString::from(pid().to_string())]);
}
fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}

thread_local! {
    // Executor-only, initialized before tracing; never points into scratch.
    static LOG: Cell<(*const PreContextAction,*mut u64)> = const { Cell::new((core::ptr::null(),core::ptr::null_mut())) };
}
unsafe extern "C" fn observer(_: *mut HookContext, identity: ControlIdentity<'_>) {
    LOG.with(|slot| {
        let (actions, log) = slot.get();
        if actions.is_null() || log.is_null() {
            unsafe { libc::_exit(122) };
        }
        // SAFETY: three immutable retained controls and a private executor-only page.
        unsafe {
            let controls = std::slice::from_raw_parts(actions, 3);
            let role = controls
                .iter()
                .position(|a| a.control().has_identity(identity));
            let Some(role) = role else {
                libc::_exit(122);
            };
            let n = log.read_volatile() as usize;
            if n >= 2 {
                libc::_exit(122);
            }
            log.add(1 + 2 * n).write_volatile(role as u64);
            log.add(2 + 2 * n)
                .write_volatile(controls[role].logical_pc());
            log.write_volatile((n + 1) as u64);
        }
    });
    // Deliberate C-ABI scratch clobbers, never edits to HookContext/application memory.
    unsafe {
        core::arch::asm!("add rax,1","pxor xmm0,xmm0","fninit",
        out("rax") _,out("xmm0") _,options(nostack));
    }
}
unsafe extern "C" fn unused_hook(_: *mut HookContext) {
    unsafe { libc::_exit(122) };
}

struct Fixture {
    oracle: OrdinaryOracle,
    code: Mapping,
    frame: Mapping,
    log: Mapping,
}
impl Fixture {
    fn new(seed: u64) -> Self {
        let f = Self {
            oracle: OrdinaryOracle::new(seed),
            code: Mapping::new(PAGE),
            frame: Mapping::new(PAGE),
            log: Mapping::new(PAGE),
        };
        f.code.initialize(0, &[0xcc; PAGE]);
        f.code.initialize(128, &LEAF);
        f.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        f.frame.initialize(0, &[0xa5; PAGE]);
        f.log.initialize(0, &[0; PAGE]);
        f
    }
    fn entry(&self) -> u64 {
        self.code.address() + 128
    }
    fn result(&self, mode: usize) -> u64 {
        let b = self.oracle.data.bytes();
        u64::from(b[128]) + if mode == 0 { 9 } else { u64::from(b[129]) + 7 }
    }
    fn snapshot(&self, child: &Tracee, ready: &Ready, pc: u64) -> Snapshot {
        gate_layout(&child.memory(ready.gate, OPTIONAL_GATE.len()), FRAME_LAYOUT).unwrap();
        for (a, b) in &ready.immutable {
            assert_eq!(child.memory(*a, b.len()), *b);
        }
        let start = self.oracle.gate_rsp() - 16 - 128;
        Snapshot {
            logical_pc: pc,
            registers: child.registers(),
            xstate: canonical_xstate(&child.xstate()),
            data: child.memory(self.oracle.data.address(), PAGE),
            application_stack: child.memory(
                start,
                (self.oracle.stack.address() + STACK_BYTES as u64 - start) as usize,
            ),
        }
    }
    fn seed(&self, child: &Tracee, actual: libc::user_regs_struct, mode: usize) {
        assert_eq!(
            (actual.rdi, actual.rsi, actual.rdx),
            (
                self.frame.address(),
                self.oracle.data.address() + 128,
                mode as u64
            )
        );
        assert_eq!(actual.rsp % 16, 8);
        let mut r = actual;
        let mut s = self.oracle.seed;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        r.rax = next();
        let _ = next();
        r.rbx = self.frame.address();
        r.rcx = next();
        r.rbp = next();
        r.r8 = next();
        r.r9 = next();
        r.r10 = next();
        r.r11 = next();
        r.r12 = next();
        r.r13 = next();
        r.r14 = next();
        r.r15 = next();
        r.rsp = self.oracle.gate_rsp();
        r.orig_rax = u64::MAX;
        r.eflags = 0xad7 | ((self.oracle.seed & 1) << 10);
        child.set_registers(&r);
        child.set_xstate(&seeded_xstate(child.xstate(), self.oracle.seed));
    }
}

fn exclude(ranges: &mut Vec<AddressRange>, owner: AddressRange) {
    let mut next = Vec::new();
    for &r in ranges.iter() {
        if !r.overlaps(owner) {
            next.push(r);
            continue;
        }
        if r.start() < owner.start() {
            next.push(range(r.start(), (owner.start() - r.start()) as usize));
        }
        if owner.end() < r.end() {
            next.push(range(owner.end(), (r.end() - owner.end()) as usize));
        }
    }
    *ranges = next;
}
// Child-only setup before its helper exists. Returns full typed image metadata,
// not an admission. Published owners deliberately survive to process exit.
fn prepare(f: &Fixture, candidate: bool, selector: &PreContextSelector) -> (Ready, [u64; 12]) {
    single_main();
    let entry = f.entry();
    let identity = CodeIdentity {
        source: SourceIdentity([0x71; 32]),
        mapping: entry,
        generation: 1,
    };
    let originals = vec![ExpectedBytes {
        address: f.code.address(),
        bytes: f.code.bytes().to_vec(),
    }];
    let actions = Box::new([
        PreContextAction::new(entry, PreContextRole::Entry, selector, observer),
        PreContextAction::new(entry + 20, PreContextRole::Return, selector, observer),
        PreContextAction::new(entry + 27, PreContextRole::Return, selector, observer),
    ]);
    for a in actions.iter() {
        assert!(a.control().is_enabled());
        assert!(a.control().try_set_enabled(false).is_err());
    }
    let actions = Box::leak(actions);
    LOG.set((actions.as_ptr(), f.log.writable().cast()));
    let entries = LegalEntrySet {
        identity,
        scope: range(entry, LEAF.len()),
        provenance: EntryProvenance::Declared(
            "literal optional oracle entry/direct branch targets".into(),
        ),
        completeness: EntryCompleteness::Complete,
        entries: [0, 11, 21]
            .map(|o| LegalEntry {
                address: entry + o,
                requires_endbr: false,
            })
            .to_vec(),
        resumes: ResumeObligation::NoneExist,
    };
    let mut composition = Composition::new(identity, originals.clone()).unwrap();
    let mut members = Vec::new();
    let mut owned = vec![range(f.code.address(), PAGE)];
    let mut details = [0; 12];
    for (i, (lo, hi)) in [(0, 11), (11, 21), (21, 28)].into_iter().enumerate() {
        let mut allocation = AllocationPolicy::near(actions[i].logical_pc()).unwrap();
        for &r in &owned {
            exclude(&mut allocation.ranges, r);
        }
        let req = InstallRequest {
            identity,
            code: &LEAF,
            base_address: entry,
            function: range(entry, LEAF.len()),
            block: range(entry + lo, (hi - lo) as usize),
            logical_pc: actions[i].logical_pc(),
            entries: &entries,
            hook: unused_hook,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                ..SearchPolicy::default()
            },
        };
        // SAFETY: literal whole leaf, all RETs, private frame and preserving controls.
        let p = unsafe {
            plan_precontext_coalesced_detailed_after(&req, &actions[i..i + 1], &composition)
        }
        .unwrap();
        assert_eq!(p.image().precontext_selector(), Some(selector));
        assert_eq!(p.image().precontext_gates().len(), 1);
        let g = p.image().precontext_gates()[0];
        assert_eq!(
            (g.logical_pc, g.role),
            (actions[i].logical_pc(), actions[i].role())
        );
        details[4 * i..4 * i + 4].copy_from_slice(&[
            g.entry,
            g.observing_entry,
            g.original_body,
            g.fault,
        ]);
        assert!(p.image().entry_routes().contains(&(g.logical_pc, g.entry)));
        assert!(
            !p.image()
                .entry_routes()
                .iter()
                .any(|&(pc, _)| pc == g.fault)
        );
        composition.append(p.plan()).unwrap();
        owned.extend(p.plan().parts().allocations.iter().map(|a| a.range));
        members.push(p);
    }
    let bundle =
        PlannedBundle::compose(originals.clone(), members, BundleBudget::default()).unwrap();
    assert_eq!(bundle.plan().final_bytes(), composition.final_bytes());
    assert_eq!(bundle.images().len(), 3);
    let mut ready = Ready {
        entry,
        gate: gate(),
        continuation: gate() + 25,
        heads: HEADS.map(|o| entry + o).to_vec(),
        returns: vec![entry + 20, entry + 27],
        boundaries: HEADS.map(|o| (entry + o, entry + o)).to_vec(),
        immutable: vec![(f.code.address(), originals[0].bytes.clone())],
        original_source: originals[0].bytes.clone(),
    };
    if candidate {
        ready.immutable[0].1 = bundle.plan().final_bytes()[0].bytes.clone();
        for image in bundle.images() {
            ready
                .immutable
                .push((image.address(), image.bytes().to_vec()));
            for &(logical, physical) in image.instruction_boundaries() {
                let row = ready
                    .boundaries
                    .iter_mut()
                    .find(|r| r.0 == logical)
                    .unwrap();
                assert_eq!(row.1, logical);
                row.1 = physical;
            }
        }
        let source = range(f.code.address(), PAGE);
        let mut exclusive = &bundle;
        f.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        // SAFETY: sole child before helper/entry; entire source and all allocations held.
        let alias = unsafe { WritableAlias::new(source, f.code.writable()) }.unwrap();
        let mut lease = unsafe { QuiescenceLease::new(&mut exclusive, identity, owned) };
        let installed = unsafe {
            bundle.publish_with(&[alias], &mut lease, || {
                f.code.protect(libc::PROT_READ | libc::PROT_EXEC);
                Ok(())
            })
        };
        let (installed, receipt) = match installed {
            Ok(x) => x,
            Err(e) => {
                eprintln!("optional publication failed: {e:?}");
                std::process::abort();
            }
        };
        assert!(!lease.is_poisoned());
        assert_eq!(receipt.plan().final_bytes(), bundle.plan().final_bytes());
        assert_eq!(installed.plan().final_bytes(), receipt.plan().final_bytes());
        assert_eq!(installed.trampolines().len(), 3);
        assert_eq!(installed.routed_entries(), 0);
        std::mem::forget(installed);
    }
    assert_eq!(f.code.bytes(), ready.immutable[0].1);
    std::mem::forget(bundle);
    (ready, details)
}

struct Channels {
    ready: Pipe,
    request: Pipe,
    ack: Pipe,
}
impl Channels {
    fn new() -> Self {
        let c = Self {
            ready: Pipe::new(),
            request: Pipe::new(),
            ack: Pipe::new(),
        };
        for fd in c.fds() {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
        c
    }
    fn fds(&self) -> [i32; 6] {
        [
            self.ready.0[0],
            self.ready.0[1],
            self.request.0[0],
            self.request.0[1],
            self.ack.0[0],
            self.ack.0[1],
        ]
    }
    fn parent(&mut self) {
        for fd in [
            &mut self.ready.0[1],
            &mut self.request.0[0],
            &mut self.ack.0[1],
        ] {
            assert_eq!(unsafe { libc::close(*fd) }, 0);
            *fd = -1;
        }
    }
}
pub(super) fn wait_io(fd: i32, events: i16, deadline: Instant) {
    loop {
        assert!(Instant::now() < deadline, "optional pipe deadline");
        let mut p = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let n = unsafe { libc::poll(&raw mut p, 1, 1) };
        if n < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
            continue;
        }
        if n == 0 {
            continue;
        }
        assert_eq!(p.revents & (libc::POLLERR | libc::POLLNVAL), 0);
        if p.revents & (events | libc::POLLHUP) != 0 {
            return;
        }
    }
}
pub(super) fn write_all(fd: i32, mut bytes: &[u8], deadline: Instant) {
    while !bytes.is_empty() {
        wait_io(fd, libc::POLLOUT, deadline);
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            assert!(matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN)
            ));
            continue;
        }
        assert!(n > 0);
        bytes = &bytes[n as usize..];
    }
}
pub(super) fn read_exact(fd: i32, bytes: &mut [u8], deadline: Instant) {
    let mut done = 0;
    while done < bytes.len() {
        wait_io(fd, libc::POLLIN, deadline);
        let n = unsafe { libc::read(fd, bytes[done..].as_mut_ptr().cast(), bytes.len() - done) };
        if n < 0 {
            assert!(matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN)
            ));
            continue;
        }
        assert!(n > 0, "optional pipe disconnected before complete message");
        done += n as usize;
    }
}
pub(super) fn words<const N: usize>(fd: i32, deadline: Instant) -> [u64; N] {
    let mut result = [0; N];
    for word in &mut result {
        let mut bytes = [0; 8];
        read_exact(fd, &mut bytes, deadline);
        *word = u64::from_le_bytes(bytes);
    }
    result
}
pub(super) fn send_words(fd: i32, words: &[u64], deadline: Instant) {
    for word in words {
        write_all(fd, &word.to_le_bytes(), deadline);
    }
}
pub(super) fn eof(fd: i32, deadline: Instant) {
    loop {
        wait_io(fd, libc::POLLIN, deadline);
        let mut b = 0_u8;
        let n = unsafe { libc::read(fd, (&raw mut b).cast(), 1) };
        if n < 0 {
            assert!(matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN)
            ));
            continue;
        }
        assert_eq!(n, 0, "no extra mailbox bytes");
        return;
    }
}
// READY has one unknown but positive non-executor helper TID. FLIPPED must
// authenticate that exact previously observed TID, all four words and EOF.
pub(super) fn helper_ack(
    bytes: &[u8],
    stage: u64,
    process: u64,
    helper: Option<u64>,
    value: bool,
) -> Result<u64, &'static str> {
    if bytes.len() != 32 {
        return Err("ack length");
    }
    let mut a = [0; 4];
    for (w, b) in a.iter_mut().zip(bytes.chunks_exact(8)) {
        *w = u64::from_le_bytes(b.try_into().unwrap());
    }
    if !matches!(stage, 1 | 2)
        || a[0] != stage
        || process == 0
        || a[1] != process
        || a[2] == 0
        || a[2] == process
        || helper.is_some_and(|expected| expected != a[2])
        || a[3] != u64::from(value)
    {
        return Err("ack fields");
    }
    Ok(a[2])
}
pub(super) fn final_ack(fd: i32, deadline: Instant, process: u64, helper: u64, value: bool) {
    // Fixed-size exact frame plus one-byte overrun probe: no unbounded collection.
    let mut bytes = [0; 33];
    read_exact(fd, &mut bytes[..32], deadline);
    loop {
        wait_io(fd, libc::POLLIN, deadline);
        let n = unsafe { libc::read(fd, bytes[32..].as_mut_ptr().cast(), 1) };
        if n < 0 {
            assert!(matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN)
            ));
            continue;
        }
        assert!(n <= 1);
        assert_eq!(
            helper_ack(&bytes[..32 + n as usize], 2, process, Some(helper), value).unwrap(),
            helper
        );
        return;
    }
}
fn close_fd(fd: &mut i32) {
    assert!(*fd >= 0);
    assert_eq!(unsafe { libc::close(*fd) }, 0);
    *fd = -1;
}
fn child(
    f: &Fixture,
    mode: usize,
    initial: bool,
    malformed: u64,
    channels: &[Channels],
    index: usize,
    deadline: Instant,
) {
    single_main();
    let candidate = malformed != 0 || index == 1;
    let keep = [
        channels[index].ready.0[1],
        channels[index].request.0[0],
        channels[index].ack.0[1],
    ];
    for c in channels {
        for fd in c.fds() {
            if !keep.contains(&fd) {
                assert_eq!(unsafe { libc::close(fd) }, 0);
            }
        }
    }
    // SAFETY: exactly these endpoints remain owned by this fork child.
    let (ready_fd, request_fd, ack_fd) = unsafe {
        (
            OwnedFd::from_raw_fd(keep[0]),
            OwnedFd::from_raw_fd(keep[1]),
            OwnedFd::from_raw_fd(keep[2]),
        )
    };
    let (selector, mut writer) = PreContextSelector::new(initial);
    let (ready, details) = prepare(f, candidate, &selector);
    let frame = f.frame.writable().cast::<Frame>();
    // SAFETY: exclusive aligned private page; no reference survives execution.
    unsafe {
        frame.write(Frame {
            scratch: CallScratch::armed(),
            target: f.entry(),
            observed: 0,
            pre: 0,
            resumed: 0,
            sequence: 1,
            pid: pid(),
            tid: tid(),
        });
    }
    if malformed != 0 {
        assert!(candidate && (malformed == 1 || malformed == 2));
        // Deliberately readable malformed tags, never invalid pointer storage.
        unsafe {
            frame
                .cast::<u64>()
                .add(if malformed == 1 { 1 } else { 2 })
                .write(if malformed == 1 { 0 } else { 3 });
        }
    }
    send_words(ack_fd.as_raw_fd(), &details, deadline);
    let executor = tid();
    let process = pid();
    let helper = std::thread::spawn(move || {
        assert_eq!(pid(), process);
        assert_ne!(tid(), executor);
        assert_eq!(selector.is_enabled(), initial);
        send_words(
            ack_fd.as_raw_fd(),
            &[1, pid(), tid(), u64::from(initial)],
            deadline,
        );
        assert_eq!(words::<1>(request_fd.as_raw_fd(), deadline), [1]);
        eof(request_fd.as_raw_fd(), deadline);
        writer.set_enabled(!initial);
        assert_eq!(selector.is_enabled(), !initial);
        send_words(
            ack_fd.as_raw_fd(),
            &[2, pid(), tid(), u64::from(!initial)],
            deadline,
        );
        !initial
    });
    write_all(ready_fd.as_raw_fd(), &ready.encode(), deadline);
    drop(ready_fd);
    // Executor-only readiness. Helper predates TRACEME and is never traced.
    unsafe {
        let mut mask: libc::sigset_t = core::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut mask),
            0
        );
        assert_eq!(libc::sigismember(&mask, libc::SIGTRAP), 0);
        assert_eq!(libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize), 0);
        assert_eq!(
            libc::syscall(
                libc::SYS_tgkill,
                process as libc::pid_t,
                executor as libc::pid_t,
                libc::SIGTRAP
            ),
            0
        );
    }
    // SAFETY: real private call, literal RBX-free leaf, full stack/input owners;
    // tracer seeds at gate entry and restores only its own already-compared harness.
    let value =
        unsafe { __li2_optional_oracle_call(frame, f.oracle.data.writable().add(128), mode) };
    assert_eq!(malformed, 0, "malformed entry returned");
    assert_eq!(value, f.result(mode));
    let snapshot = unsafe { (*frame).scratch.snapshot() }.unwrap();
    use liteinst2::precontext::{Disposition, ScratchPhase};
    assert_eq!(
        snapshot.phase,
        if candidate {
            ScratchPhase::ReturnObserved
        } else {
            ScratchPhase::Armed
        }
    );
    assert_eq!(
        snapshot.disposition,
        if candidate {
            Some(if initial {
                Disposition::Slow
            } else {
                Disposition::FastBypass
            })
        } else {
            None
        }
    );
    if candidate {
        assert_eq!(
            (snapshot.entry_pc, snapshot.return_pc),
            (f.entry(), f.entry() + if mode == 0 { 27 } else { 20 })
        );
        assert_eq!(snapshot.entry_rsp, f.oracle.gate_rsp() - 16);
        assert_eq!(snapshot.return_rsp, snapshot.entry_rsp);
        assert_eq!(snapshot.entry_word, gate() + 25);
        assert_eq!(snapshot.return_word, snapshot.entry_word);
    }
    assert_eq!(unsafe { (*frame).observed }, f.entry());
    assert_eq!(unsafe { (*frame).pre }, f.oracle.gate_rsp() - 8);
    assert_eq!(unsafe { (*frame).resumed }, f.oracle.gate_rsp() - 8);
    while !helper.is_finished() {
        assert!(Instant::now() < deadline, "helper join deadline");
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(helper.join().unwrap(), !initial);
    assert!(Instant::now() < deadline);
    // No instantaneous task-census inference from join; normal group exit/reap is required.
}

struct Children {
    first: Tracee,
    second: Option<Tracee>,
}
impl std::ops::Index<usize> for Children {
    type Output = Tracee;
    fn index(&self, i: usize) -> &Tracee {
        match i {
            0 => &self.first,
            1 => self.second.as_ref().unwrap(),
            _ => panic!("child index"),
        }
    }
}
fn start(
    f: &Fixture,
    mode: usize,
    initial: bool,
    malformed: u64,
    deadline: Instant,
) -> (Children, Vec<Channels>) {
    single_main();
    let n = if malformed == 0 { 2 } else { 1 };
    let mut channels: Vec<_> = (0..n).map(|_| Channels::new()).collect();
    let mut ids = [0; 2];
    assert!(Instant::now() < deadline, "parent channel/setup deadline");
    for i in 0..n {
        let process = unsafe { libc::fork() };
        if process == 0 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                child(f, mode, initial, malformed, &channels, i, deadline)
            }));
            unsafe {
                libc::_exit(if result.is_ok() { 0 } else { 122 });
            }
        }
        if process < 0 {
            for &id in &ids[..i] {
                drop(Tracee {
                    pid: id,
                    deadline,
                    reaped: Cell::new(false),
                });
            }
            panic!("optional fork failed");
        }
        ids[i] = process;
    }
    // No parent allocations/reads/validation between the sibling forks.
    let children = Children {
        first: Tracee {
            pid: ids[0],
            deadline,
            reaped: Cell::new(false),
        },
        second: if n == 2 {
            Some(Tracee {
                pid: ids[1],
                deadline,
                reaped: Cell::new(false),
            })
        } else {
            None
        },
    };
    for c in &mut channels {
        c.parent();
    }
    assert!(Instant::now() < deadline, "owned sibling/setup deadline");
    (children, channels)
}
fn ready(child: &Tracee, c: &Channels, initial: bool) -> (Ready, [u64; 12], u64) {
    let r = c.ready.read(child);
    let details = words::<12>(c.ack.0[0], child.deadline);
    let mut ack = [0; 32];
    read_exact(c.ack.0[0], &mut ack, child.deadline);
    let helper = helper_ack(&ack, 1, child.pid as u64, None, initial).unwrap();
    let status = child.wait();
    assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP);
    let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
    child.request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
    assert_eq!(
        (info.si_signo, info.si_code),
        (libc::SIGTRAP, libc::SI_TKILL)
    );
    assert_eq!(unsafe { info.si_pid() }, child.pid);
    child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
    assert_eq!(r.gate, gate());
    assert_eq!(r.continuation, gate() + 25);
    assert_eq!(r.heads, HEADS.map(|o| r.entry + o));
    assert_eq!(r.returns, [r.entry + 20, r.entry + 27]);
    (r, details, helper)
}
fn details(r: &Ready, d: &[u64; 12]) {
    let mut all = BTreeSet::new();
    for (i, role) in [r.entry, r.entry + 20, r.entry + 27]
        .into_iter()
        .enumerate()
    {
        let q = &d[4 * i..4 * i + 4];
        assert_eq!(
            r.boundaries.iter().find(|(pc, _)| *pc == role).unwrap().1,
            q[2]
        );
        assert!(
            q.iter().all(|a| all.insert(*a)),
            "distinct role entry/observer/body/fault"
        );
        let (start, bytes) = r.immutable[1..]
            .iter()
            .find(|(start, bytes)| {
                q.iter()
                    .all(|a| *a >= *start && *a < *start + bytes.len() as u64)
            })
            .expect("whole role in retained image");
        let fault = usize::try_from(q[3] - *start).unwrap();
        assert_eq!(&bytes[fault..fault.checked_add(2).unwrap()], &[0x0f, 0x0b]);
    }
}
fn flip(child: &Tracee, c: &mut Channels, helper: u64, initial: bool) {
    send_words(c.request.0[1], &[1], child.deadline);
    close_fd(&mut c.request.0[1]);
    final_ack(
        c.ack.0[0],
        child.deadline,
        child.pid as u64,
        helper,
        !initial,
    );
}
fn reach(
    f: &Fixture,
    walk: &mut Walk<'_>,
    r: &Ready,
    mode: usize,
) -> (libc::user_regs_struct, Vec<u8>, Vec<u8>) {
    while walk.child.registers().rip != r.gate {
        walk.step("optional_reach_gate");
    }
    gate_layout(
        &walk.child.memory(r.gate, OPTIONAL_GATE.len()),
        FRAME_LAYOUT,
    )
    .unwrap();
    let actual = walk.child.registers();
    let x = walk.child.xstate();
    let word = walk.child.memory(actual.rsp, 8);
    f.seed(walk.child, actual, mode);
    (actual, x, word)
}

struct Records {
    header: [u64; 16],
    events: Vec<(u64, u64)>,
}
impl Records {
    fn new(f: &Fixture, child: &Tracee) -> Self {
        Self {
            header: [
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                f.entry(),
                0,
                0,
                0,
                1,
                child.pid as u64,
                child.pid as u64,
            ],
            events: Vec::new(),
        }
    }
    fn check(
        &mut self,
        f: &Fixture,
        child: &Tracee,
        point: &Snapshot,
        candidate: bool,
        initial: bool,
    ) {
        let pc = point.logical_pc;
        assert_eq!(
            point.registers.rbx,
            f.frame.address(),
            "same valid scratch in every application state"
        );
        if pc == gate() + 18 {
            self.header[10] = f.entry();
        }
        if pc == gate() + 22 {
            self.header[11] = f.oracle.gate_rsp() - 8;
        }
        if pc == gate() + 29 {
            self.header[12] = f.oracle.gate_rsp() - 8;
        }
        if pc == f.entry() || pc == f.entry() + 20 || pc == f.entry() + 27 {
            assert_eq!(point.registers.rsp, f.oracle.gate_rsp() - 16);
            assert_eq!(
                child.memory(point.registers.rsp, 8),
                (gate() + 25).to_le_bytes()
            );
        }
        if candidate && pc == f.entry() {
            self.header[..6].copy_from_slice(&[
                point.registers.rcx,
                2,
                if initial { 2 } else { 1 },
                pc,
                f.oracle.gate_rsp() - 16,
                gate() + 25,
            ]);
            if initial {
                self.events.push((0, pc));
            }
        }
        if candidate && (pc == f.entry() + 20 || pc == f.entry() + 27) {
            self.header[0] = point.registers.rcx;
            self.header[1] = 3;
            self.header[6..9].copy_from_slice(&[pc, f.oracle.gate_rsp() - 16, gate() + 25]);
            if initial {
                self.events
                    .push((if pc == f.entry() + 20 { 1 } else { 2 }, pc));
            }
        }
        self.compare(f, child);
    }
    fn expected_pages(&self) -> ([u8; PAGE], [u8; PAGE]) {
        let mut frame = [0xa5; PAGE];
        for (i, w) in self.header.iter().enumerate() {
            frame[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        let mut log = [0_u8; PAGE];
        log[..8].copy_from_slice(&(self.events.len() as u64).to_le_bytes());
        assert!(self.events.len() <= 2);
        for (i, (role, pc)) in self.events.iter().enumerate() {
            log[8 + 16 * i..16 + 16 * i].copy_from_slice(&role.to_le_bytes());
            log[16 + 16 * i..24 + 16 * i].copy_from_slice(&pc.to_le_bytes());
        }
        (frame, log)
    }
    fn validate_pages(&self, frame: &[u8], log: &[u8]) -> Result<(), &'static str> {
        let (expected_frame, expected_log) = self.expected_pages();
        if frame != expected_frame {
            return Err("whole private scratch/frame/canaries");
        }
        if log != expected_log {
            return Err("exact callback identities and zero tail");
        }
        Ok(())
    }
    fn compare(&self, f: &Fixture, child: &Tracee) {
        self.validate_pages(
            &child.memory(f.frame.address(), PAGE),
            &child.memory(f.log.address(), PAGE),
        )
        .unwrap();
    }
}
fn reaped(child: &Tracee) {
    assert!(child.reaped.get());
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(child.pid, &raw mut status, libc::WNOHANG | libc::__WALL) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
fn outer_return(
    f: &Fixture,
    walk: &mut Walk<'_>,
    r: &Ready,
    saved: libc::user_regs_struct,
    x: &[u8],
    word: &[u8],
    value: u64,
) {
    let actual = walk.child.registers();
    assert_eq!(
        (actual.rip, actual.rsp, actual.rax),
        (r.gate + OUTER_RET, f.oracle.gate_rsp(), value)
    );
    assert_eq!(
        walk.child.memory(f.oracle.data.address(), PAGE),
        f.oracle.data.bytes()
    );
    assert_eq!(
        walk.child.memory(saved.rsp, 8),
        word,
        "own real harness return word"
    );
    let continuation = u64::from_le_bytes(word.try_into().unwrap());
    // Same existing harness boundary: never repair application state, RAX or a return PC.
    let mut restored = saved;
    restored.rax = actual.rax;
    restored.rip = actual.rip;
    walk.child.set_registers(&restored);
    walk.child.set_xstate(x);
    walk.step("optional_outer_return");
    let after = walk.child.registers();
    assert_eq!(
        (after.rip, after.rsp, after.rax),
        (continuation, saved.rsp.checked_add(8).unwrap(), value)
    );
    assert_eq!(walk.child.memory(saved.rsp, 8), word);
    let mut resume = after;
    resume.eflags = harness_resume_flags(saved.eflags, after.eflags);
    walk.child.set_registers(&resume);
    walk.child.request(libc::PTRACE_CONT, 0, 0);
    let status = walk.child.wait();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "optional real invoke/helper join failed: {status:#x}"
    );
    reaped(walk.child);
    assert!(Instant::now() < walk.child.deadline, "normal reap deadline");
}
fn pair(seed: u64, mode: usize, initial: bool) -> (String, usize) {
    let deadline = Instant::now() + CHILD_BUDGET;
    let f = Fixture::new(seed);
    assert!(Instant::now() < deadline, "parent fixture deadline");
    let (children, mut channels) = start(&f, mode, initial, 0, deadline);
    let (a_ready, _, a_helper) = ready(&children[0], &channels[0], initial);
    let (b_ready, b_details, b_helper) = ready(&children[1], &channels[1], initial);
    // Only the shared geometry is reused; exact optional gate bytes are checked separately.
    assert_eq!(OPTIONAL_GATE.len(), GATE_BYTES.len());
    assert_eq!((AFTER_CALL, OUTER_RET), (25, 30));
    let am = a_ready.validate(false);
    let bm = b_ready.validate(true);
    same_ready(&a_ready, &b_ready);
    details(&b_ready, &b_details);
    assert_eq!(a_ready.entry, f.entry());
    assert_eq!(&a_ready.original_source[128..156], &LEAF);
    let mut a = Walk {
        child: &children[0],
        steps: 0,
    };
    let mut b = Walk {
        child: &children[1],
        steps: 0,
    };
    let (ar, ax, aw) = reach(&f, &mut a, &a_ready, mode);
    let (br, bx, bw) = reach(&f, &mut b, &b_ready, mode);
    same_arguments(&ar, &br);
    assert_eq!(ax.len(), bx.len());
    let path: &[u64] = if mode == 0 { &PATH0 } else { &PATH1 };
    let expected_visits: Vec<_> = path.iter().map(|o| f.entry() + o).collect();
    let expected_points: Vec<_> = GATE_HEADS[..8]
        .iter()
        .map(|o| gate() + o)
        .chain(expected_visits.iter().copied())
        .chain(GATE_HEADS[8..].iter().map(|o| gate() + o))
        .collect();
    assert_eq!(expected_points.len(), if mode == 0 { 18 } else { 19 });
    let mut points = Vec::new();
    let mut a_records = Records::new(&f, a.child);
    let mut a_flipped = false;
    loop {
        let pc = a.child.registers().rip;
        let logical = if GATE_HEADS.iter().any(|o| gate() + o == pc) {
            pc
        } else {
            *am.get(&pc).expect("original escaped declared heads")
        };
        assert_eq!(Some(&logical), expected_points.get(points.len()));
        let point = f.snapshot(a.child, &a_ready, logical);
        a_records.check(&f, a.child, &point, false, initial);
        if logical == f.entry() {
            assert!(!a_flipped);
            flip(a.child, &mut channels[0], a_helper, initial);
            a_flipped = true;
        }
        points.push(point);
        if pc == gate() + OUTER_RET {
            break;
        }
        a.step("optional_original_body");
    }
    assert!(a_flipped);
    assert_eq!(points.len(), expected_points.len());
    let mut next = 0;
    let mut b_records = Records::new(&f, b.child);
    let mut b_flipped = false;
    let mut observers = Vec::new();
    let mut callbacks = 0;
    loop {
        let pc = b.child.registers().rip;
        for i in 0..3 {
            if pc == b_details[4 * i + 1] {
                assert!(initial);
                observers.push(i);
                assert!(observers.len() <= 2);
            }
        }
        if pc == observer as *const () as usize as u64 {
            callbacks += 1;
            assert!(callbacks <= 2);
        }
        let logical = if GATE_HEADS.iter().any(|o| gate() + o == pc) {
            Some(pc)
        } else {
            bm.get(&pc).copied()
        };
        if let Some(logical) = logical {
            let expected = points.get(next).expect("extra candidate restored boundary");
            assert_eq!(logical, expected.logical_pc);
            assert_state(expected, &f.snapshot(b.child, &b_ready, logical));
            b_records.check(&f, b.child, expected, true, initial);
            if logical == f.entry() {
                assert!(!b_flipped);
                flip(b.child, &mut channels[1], b_helper, initial);
                b_flipped = true;
            }
            next += 1;
            if pc == gate() + OUTER_RET {
                break;
            }
        }
        b.step("optional_candidate_body");
    }
    assert!(b_flipped);
    assert_eq!(next, points.len());
    let ret_role = if mode == 0 { 2 } else { 1 };
    assert_eq!(observers, if initial { vec![0, ret_role] } else { vec![] });
    assert_eq!(callbacks, if initial { 2 } else { 0 });
    assert_eq!(b_records.events.len(), callbacks);
    let value = f.result(mode);
    outer_return(&f, &mut a, &a_ready, ar, &ax, &aw, value);
    outer_return(&f, &mut b, &b_ready, br, &bx, &bw, value);
    let row = format!(
        "{{\"mode\":{mode},\"seed\":{seed},\"initial_selector\":{initial},\"ret_offset\":{},\"comparisons\":{next},\"original_steps\":{},\"candidate_steps\":{},\"callback_events\":{callbacks},\"observer_entries\":{},\"subject_returns\":2,\"outer_returns\":2,\"flip_acknowledgements\":2,\"helper_joins\":2}}",
        if mode == 0 { 27 } else { 20 },
        a.steps,
        b.steps,
        observers.len()
    );
    assert!(Instant::now() < deadline, "complete pair deadline");
    (row, next)
}
fn malformed(tag: u64) -> String {
    let deadline = Instant::now() + CHILD_BUDGET;
    let f = Fixture::new(SEEDS[0]);
    assert!(Instant::now() < deadline, "parent fixture deadline");
    let (children, channels) = start(&f, 0, false, tag, deadline);
    let (r, gate_details, _) = ready(&children[0], &channels[0], false);
    let map = r.validate(true);
    details(&r, &gate_details);
    let mut walk = Walk {
        child: &children[0],
        steps: 0,
    };
    let _ = reach(&f, &mut walk, &r, 0);
    let initial_rcx = walk.child.registers().rcx;
    let mut original_heads = 0;
    let mut callbacks = 0;
    let mut observers = 0;
    loop {
        let pc = walk.child.registers().rip;
        if map.contains_key(&pc) {
            original_heads += 1;
        }
        if pc == observer as *const () as usize as u64 {
            callbacks += 1;
        }
        if (0..3).any(|i| pc == gate_details[4 * i + 1]) {
            observers += 1;
        }
        assert_eq!((original_heads, callbacks, observers), (0, 0, 0));
        assert!(walk.steps < MAX_STEPS);
        assert!(Instant::now() < walk.child.deadline);
        walk.steps += 1;
        walk.child.request(libc::PTRACE_SINGLESTEP, 0, 0);
        let status = walk.child.wait();
        assert!(libc::WIFSTOPPED(status));
        if libc::WSTOPSIG(status) == libc::SIGILL {
            let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
            walk.child
                .request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
            assert_eq!((info.si_signo, info.si_code), (libc::SIGILL, ILL_ILLOPN));
            assert_eq!(walk.child.registers().rip, gate_details[3]);
            assert_eq!(unsafe { info.si_addr() } as usize as u64, gate_details[3]);
            assert_eq!(walk.child.memory(gate_details[3], 2), [0x0f, 0x0b]);
            break;
        }
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
    }
    // No SIGILL delivery to the entry router, no original or return execution.
    let _ = f.snapshot(walk.child, &r, gate_details[3]);
    assert_eq!(
        walk.child.memory(f.oracle.data.address(), PAGE),
        f.oracle.data.bytes()
    );
    let mut records = Records::new(&f, walk.child);
    records.header[0] = initial_rcx;
    records.header[if tag == 1 { 1 } else { 2 }] = if tag == 1 { 0 } else { 3 };
    records.header[10] = f.entry();
    records.header[11] = f.oracle.gate_rsp() - 8;
    records.compare(&f, walk.child);
    assert_eq!(unsafe { libc::kill(walk.child.pid, libc::SIGKILL) }, 0);
    let status = walk.child.wait();
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
    reaped(walk.child);
    assert!(Instant::now() < deadline, "malformed reap deadline");
    let row = format!(
        "{{\"tag\":\"{}\",\"sigill\":true,\"local_ud2\":true,\"original_heads\":0,\"callback_events\":0,\"observer_entries\":0,\"subject_returns\":0,\"outer_returns\":0,\"cleanup\":\"SIGKILL_REAP_ECHILD\",\"steps\":{}}}",
        if tag == 1 { "phase" } else { "choice" },
        walk.steps
    );
    assert!(Instant::now() < deadline, "complete malformed deadline");
    row
}

// Invoked by this custom-harness main, not cfg(test) declarations. These
// exercise the same validators as the live gate/mailbox/page observations.
fn protocol_controls() -> [&'static str; 5] {
    gate_layout(&OPTIONAL_GATE, FRAME_LAYOUT).unwrap();
    assert_eq!(gate_layout(GATE_BYTES, FRAME_LAYOUT), Err("gate bytes"));
    for offset in [13, 17, 21, 28] {
        let mut wrong = OPTIONAL_GATE;
        wrong[offset] ^= 8;
        assert_eq!(gate_layout(&wrong, FRAME_LAYOUT), Err("gate bytes"));
    }
    for index in 0..FRAME_LAYOUT.len() {
        let mut wrong = FRAME_LAYOUT;
        wrong[index] ^= 8;
        assert_eq!(gate_layout(&OPTIONAL_GATE, wrong), Err("scratch layout"));
    }
    let encode = |a: [u64; 4]| {
        let mut b = [0; 32];
        for (w, out) in a.iter().zip(b.chunks_exact_mut(8)) {
            out.copy_from_slice(&w.to_le_bytes());
        }
        b
    };
    assert_eq!(
        helper_ack(&encode([1, 41, 42, 0]), 1, 41, None, false),
        Ok(42)
    );
    let good = [2, 41, 42, 1];
    let bytes = encode(good);
    assert_eq!(helper_ack(&bytes, 2, 41, Some(42), true), Ok(42));
    for index in 0..4 {
        let mut wrong = good;
        wrong[index] ^= 1;
        assert_eq!(
            helper_ack(&encode(wrong), 2, 41, Some(42), true),
            Err("ack fields")
        );
    }
    for helper in [0, 41] {
        assert_eq!(
            helper_ack(&encode([1, 41, helper, 0]), 1, 41, None, false),
            Err("ack fields")
        );
    }
    let mut duplicate = [0; 33];
    duplicate[..32].copy_from_slice(&bytes);
    duplicate[32] = bytes[0];
    assert_eq!(
        helper_ack(&duplicate, 2, 41, Some(42), true),
        Err("ack length")
    );
    assert_eq!(
        helper_ack(&bytes[..31], 2, 41, Some(42), true),
        Err("ack length")
    );
    let records = Records {
        header: [7; 16],
        events: vec![(0, 0x2000), (1, 0x2014)],
    };
    let (frame, log) = records.expected_pages();
    assert_eq!(records.validate_pages(&frame, &log), Ok(()));
    let mut omitted = log;
    omitted[..8].copy_from_slice(&1_u64.to_le_bytes());
    omitted[24..40].fill(0);
    assert_eq!(
        records.validate_pages(&frame, &omitted),
        Err("exact callback identities and zero tail")
    );
    [
        "gate_displacement",
        "scratch_layout",
        "ack_fields",
        "duplicate_ack_tail",
        "slow_ret_log",
    ]
}

pub fn run() {
    single_main();
    // No source/owner creation in a multithreaded libtest process.
    gate_layout(
        unsafe { std::slice::from_raw_parts(gate() as usize as *const u8, OPTIONAL_GATE.len()) },
        FRAME_LAYOUT,
    )
    .unwrap();
    let pure_controls = protocol_controls();
    let mut rows = Vec::with_capacity(8);
    let mut comparisons = 0;
    for seed in SEEDS {
        for mode in [0, 1] {
            for initial in [false, true] {
                let (row, n) = pair(seed, mode, initial);
                rows.push(row);
                comparisons += n;
            }
        }
    }
    assert_eq!(rows.len(), 8);
    assert_eq!(comparisons, 148);
    let controls = [malformed(1), malformed(2)];
    single_main();
    // This is the only success output, after all physical returns, joins and reaps.
    println!(
        "{{\"schema\":1,\"profile\":\"precontext-v1\",\"status\":\"PASS\",\"pure_controls\":{:?},\"pairs\":[{}],\"malformed\":[{}],\"totals\":{{\"pairs\":8,\"positive_children\":16,\"malformed_children\":2,\"comparisons\":148,\"callback_events\":8,\"subject_returns\":16,\"outer_returns\":16,\"helper_joins\":16}},\"scope\":\"fixed-core-no-frontend-or-performance\"}}",
        pure_controls,
        rows.join(","),
        controls.join(",")
    );
}
