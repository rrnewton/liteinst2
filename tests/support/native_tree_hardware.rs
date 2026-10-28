//! Private fixed-tree execution breakpoints. No waiter, step or cleanup owner.
//! The caller propagates every refusal; this helper never searches or retries.
use super::{GATE_BYTES, Profile, Ready, Tracee, call_tree};
use std::time::Instant;

const ENABLES: u64 = 0xff;
const GD: u64 = 1 << 13;
const SLOT0_MODE: u64 = 0xf << 16;
const CAUSES: u64 = 0xf | (1 << 13) | (1 << 14) | (1 << 15);
const TF: u64 = 1 << 8;
const RF: u64 = 1 << 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Layout,
    InitialDebugOwner,
    Ptrace(i32),
    Readback,
    Deadline,
    Target,
    Instruction,
    Event,
    Flags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Role {
    GateEntry,
    OuterCall,
    TreeCall,
    ChildRet,
    RootRet,
    OuterRet,
}

#[derive(Clone, Copy)]
pub(super) struct Target {
    address: u64,
    bytes: &'static [u8],
    save_harness: bool,
}
impl Target {
    /// Existing Ready validation runs before any debug-register mutation.
    pub(super) fn ready(ready: &Ready, candidate: bool, role: Role) -> Result<Self, Error> {
        if ready.profile != Profile::Legacy {
            return Err(Error::Target);
        }
        let _ = ready.validate(candidate);
        let base = ready.immutable[0].0;
        let offset = usize::try_from(ready.entry.checked_sub(base).ok_or(Error::Target)?)
            .map_err(|_| Error::Target)?;
        let end = offset.checked_add(71).ok_or(Error::Target)?;
        let source = ready
            .original_source
            .get(offset..end)
            .ok_or(Error::Target)?;
        let add = |n| ready.entry.checked_add(n).ok_or(Error::Target);
        let heads = call_tree::truth::ROOT_HEADS
            .iter()
            .map(|&n| add(u64::from(n)))
            .chain(
                call_tree::truth::CHILD_HEADS
                    .iter()
                    .map(|&n| add(32 + u64::from(n))),
            )
            .collect::<Result<Vec<_>, _>>()?;
        let call = add(9)?;
        if source[..23] != call_tree::truth::ROOT_BYTES
            || source[23..32] != call_tree::truth::GAP_BYTES
            || source[32..] != call_tree::truth::CHILD_BYTES
            || ready.heads != heads
            || ready.returns != [add(22)?, add(70)?]
            || ready.boundaries.iter().find(|(p, _)| *p == call) != Some(&(call, call))
        {
            return Err(Error::Target);
        }
        let physical = |logical| {
            ready
                .boundaries
                .iter()
                .find(|(p, _)| *p == logical)
                .map(|(_, p)| *p)
                .ok_or(Error::Target)
        };
        let (address, bytes): (u64, &'static [u8]) = match role {
            Role::GateEntry => (ready.gate, GATE_BYTES),
            Role::OuterCall => (
                ready.gate.checked_add(22).ok_or(Error::Target)?,
                &[0x41, 0xff, 0xd3],
            ),
            Role::TreeCall => (add(9)?, &[0xe8, 0x12, 0, 0, 0]),
            Role::ChildRet => (physical(add(70)?)?, &[0xc3]),
            Role::RootRet => (physical(add(22)?)?, &[0xc3]),
            Role::OuterRet => (ready.gate.checked_add(30).ok_or(Error::Target)?, &[0xc3]),
        };
        Ok(Self {
            address,
            bytes,
            save_harness: role == Role::GateEntry,
        })
    }

    // Only this module and its separately reviewed native control child can
    // select a probe NOP. There is no public arbitrary-address constructor.
    fn probe(address: u64) -> Self {
        Self {
            address,
            bytes: &[0x90],
            save_harness: true,
        }
    }

    fn instruction(self, actual: &[u8]) -> Result<(), Error> {
        if actual == self.bytes {
            Ok(())
        } else {
            Err(Error::Instruction)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reg {
    Address,
    Status,
    Control,
}
impl Reg {
    fn index(self) -> usize {
        match self {
            Self::Address => 0,
            Self::Status => 6,
            Self::Control => 7,
        }
    }
}

fn debug_offset(index: usize) -> Result<usize, Error> {
    // This fixture is deliberately the Linux x86-64 user ABI, not a guessed
    // numeric offset or an exported cross-architecture register interface.
    const _: fn(&libc::user) -> &[u64; 8] = |user| &user.u_debugreg;
    if !cfg!(all(target_os = "linux", target_arch = "x86_64"))
        || core::mem::size_of::<libc::c_long>() != 8
        || !matches!(index, 0 | 6 | 7)
    {
        return Err(Error::Layout);
    }
    let base = core::mem::offset_of!(libc::user, u_debugreg);
    let word = core::mem::size_of::<u64>();
    let offset = index
        .checked_mul(word)
        .and_then(|n| base.checked_add(n))
        .ok_or(Error::Layout)?;
    if base % word != 0
        || offset.checked_add(word).ok_or(Error::Layout)? > core::mem::size_of::<libc::user>()
    {
        return Err(Error::Layout);
    }
    Ok(offset)
}

fn peek_result(value: libc::c_long, errno: i32) -> Result<u64, Error> {
    if value == -1 && errno != 0 {
        Err(Error::Ptrace(errno))
    } else {
        Ok(value as u64)
    }
}
fn initial_control(dr7: u64) -> Result<(), Error> {
    if dr7 & (ENABLES | GD) == 0 {
        Ok(())
    } else {
        Err(Error::InitialDebugOwner)
    }
}

// The small seam exists only to exercise the real restoration algorithm under
// individual I/O failures. It does not simulate native execution or reaping.
trait DebugAccess {
    fn read(&self, reg: Reg) -> Result<u64, Error>;
    fn write(&self, reg: Reg, value: u64) -> Result<(), Error>;
}
struct PtraceDebug<'a>(&'a Tracee);
impl DebugAccess for PtraceDebug<'_> {
    fn read(&self, reg: Reg) -> Result<u64, Error> {
        let offset = debug_offset(reg.index())?;
        // SAFETY: exact owned, stopped child; errno is this caller's TLS slot.
        let (value, errno) = unsafe {
            *libc::__errno_location() = 0;
            let value = libc::ptrace(libc::PTRACE_PEEKUSER, self.0.pid, offset, 0_usize);
            let errno = *libc::__errno_location();
            (value, errno)
        };
        peek_result(value, errno)
    }
    fn write(&self, reg: Reg, value: u64) -> Result<(), Error> {
        let offset = debug_offset(reg.index())?;
        // SAFETY: only typed DR0/DR6/DR7 offsets for this stopped owned child.
        let (result, errno) = unsafe {
            *libc::__errno_location() = 0;
            let result = libc::ptrace(libc::PTRACE_POKEUSER, self.0.pid, offset, value as usize);
            let errno = *libc::__errno_location();
            (result, errno)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Ptrace(errno))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Stopped,
    Running,
    Terminal,
    Restored,
}
struct Owner<'a, I: DebugAccess> {
    io: &'a I,
    saved: [u64; 3],
    state: State,
    dirty: bool,
}
impl<'a, I: DebugAccess> Owner<'a, I> {
    fn save(io: &'a I) -> Result<Self, Error> {
        let saved = [
            io.read(Reg::Address)?,
            io.read(Reg::Status)?,
            io.read(Reg::Control)?,
        ];
        initial_control(saved[2])?;
        Ok(Self {
            io,
            saved,
            state: State::Stopped,
            dirty: false,
        })
    }
    fn verify(&self, expected: [u64; 3]) -> Result<(), Error> {
        let actual = [
            self.io.read(Reg::Address)?,
            self.io.read(Reg::Status)?,
            self.io.read(Reg::Control)?,
        ];
        if actual == expected {
            Ok(())
        } else {
            Err(Error::Readback)
        }
    }
    fn install(&mut self, address: u64) -> Result<(), Error> {
        self.dirty = true; // Restoration custody precedes the first write.
        let status = self.saved[1] & !CAUSES;
        let control = (self.saved[2] & !(ENABLES | SLOT0_MODE)) | 1;
        self.io.write(Reg::Control, self.saved[2] & !ENABLES)?;
        self.io.write(Reg::Address, address)?;
        self.io.write(Reg::Status, status)?;
        self.io.write(Reg::Control, control)?;
        self.verify([address, status, control])
    }
    fn restore(&mut self) -> Result<(), Error> {
        self.io.write(Reg::Control, self.saved[2] & !ENABLES)?;
        self.io.write(Reg::Address, self.saved[0])?;
        self.io.write(Reg::Status, self.saved[1])?;
        self.io.write(Reg::Control, self.saved[2])?;
        self.verify(self.saved)?;
        self.dirty = false;
        self.state = State::Restored;
        Ok(())
    }
}
impl<I: DebugAccess> Drop for Owner<'_, I> {
    fn drop(&mut self) {
        if self.dirty && self.state == State::Stopped {
            // One non-panicking best-effort sequence, never a waiter/CONT or
            // successful-restoration claim. Tracee retains failure kill/reap.
            let _ = self.io.write(Reg::Control, self.saved[2] & !ENABLES);
            let _ = self.io.write(Reg::Address, self.saved[0]);
            let _ = self.io.write(Reg::Status, self.saved[1]);
            let _ = self.io.write(Reg::Control, self.saved[2]);
        }
    }
}

#[derive(Clone, Copy)]
struct Event {
    status: i32,
    signo: i32,
    code: i32,
    dr6: u64,
}
fn event_valid(event: Event, rip: u64, target: u64) -> bool {
    event.status == ((libc::SIGTRAP << 8) | 0x7f)
        && event.signo == libc::SIGTRAP
        && event.code == libc::TRAP_HWBKPT
        && event.dr6 & CAUSES == 1
        && rip == target
}

pub(super) struct HardwareStop {
    target: Target,
    raw: libc::user_regs_struct,
    dr6: u64,
}
impl HardwareStop {
    pub(super) fn raw(&self) -> &libc::user_regs_struct {
        &self.raw
    }
    pub(super) fn dr6(&self) -> u64 {
        self.dr6
    }
    pub(super) fn harness(&self) -> Result<libc::user_regs_struct, Error> {
        if !self.target.save_harness || self.raw.eflags & TF != 0 {
            return Err(Error::Flags);
        }
        let mut saved = self.raw;
        saved.eflags &= !RF;
        Ok(saved)
    }
}
fn authenticate(
    target: Target,
    event: Event,
    raw: libc::user_regs_struct,
) -> Result<HardwareStop, Error> {
    if !event_valid(event, raw.rip, target.address) {
        return Err(Error::Event);
    }
    Ok(HardwareStop {
        target,
        raw,
        dr6: event.dr6,
    })
}

/// Caller must be at its owned stop and propagate any refusal. Targets contain
/// only closed literal roles. Existing Tracee remains the sole waiter/cleanup.
pub(super) fn stop_at(child: &Tracee, target: Target) -> Result<HardwareStop, Error> {
    if Instant::now() >= child.deadline {
        return Err(Error::Deadline);
    }
    target.instruction(&child.memory(target.address, target.bytes.len()))?;
    let io = PtraceDebug(child);
    let mut owner = Owner::save(&io)?;
    owner.install(target.address)?;
    if Instant::now() >= child.deadline {
        return Err(Error::Deadline);
    }
    child.request(libc::PTRACE_CONT, 0, 0);
    owner.state = State::Running;
    let status = child.wait();
    owner.state = if libc::WIFSTOPPED(status) {
        State::Stopped
    } else {
        State::Terminal
    };
    if owner.state != State::Stopped {
        return Err(Error::Event);
    }
    let within_deadline = Instant::now() < child.deadline;
    // Capture DR6, siginfo and registers before restoration can erase causes.
    let captured: Result<(Event, libc::user_regs_struct), Error> = (|| {
        let dr6 = io.read(Reg::Status)?;
        // SAFETY: fully initialized C output storage for this stopped child.
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        child.request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
        Ok((
            Event {
                status,
                signo: info.si_signo,
                code: info.si_code,
                dr6,
            },
            child.registers(),
        ))
    })();
    owner.restore()?;
    if !within_deadline || Instant::now() >= child.deadline {
        return Err(Error::Deadline);
    }
    let (event, raw) = captured?;
    target.instruction(&child.memory(target.address, target.bytes.len()))?;
    if Instant::now() >= child.deadline {
        return Err(Error::Deadline);
    }
    authenticate(target, event, raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    // Stale B0/B2/BD/BS/BT and disabled slot-zero configuration must survive
    // restoration, while none may contaminate the installed breakpoint.
    const ORIGINAL: [u64; 3] = [0x1234, 0xffff_eff5, 0xabcd_0400];
    fn event() -> Event {
        Event {
            status: (libc::SIGTRAP << 8) | 0x7f,
            signo: libc::SIGTRAP,
            code: libc::TRAP_HWBKPT,
            dr6: 0xffff_0ff1,
        }
    }
    fn registers() -> libc::user_regs_struct {
        libc::user_regs_struct {
            r15: 1,
            r14: 2,
            r13: 3,
            r12: 4,
            rbp: 5,
            rbx: 6,
            r11: 7,
            r10: 8,
            r9: 9,
            r8: 10,
            rax: 11,
            rcx: 12,
            rdx: 13,
            rsi: 14,
            rdi: 15,
            orig_rax: 16,
            rip: 0x4000,
            cs: 18,
            eflags: 0x202,
            rsp: 20,
            ss: 21,
            fs_base: 22,
            gs_base: 23,
            ds: 24,
            es: 25,
            fs: 26,
            gs: 27,
        }
    }
    fn words(r: libc::user_regs_struct) -> [u64; 27] {
        [
            r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx,
            r.rdx, r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base,
            r.gs_base, r.ds, r.es, r.fs, r.gs,
        ]
    }
    #[test]
    fn hardware_event_requires_exact_owned_trap() {
        assert!(event_valid(event(), 0x4000, 0x4000));
        for status in [
            0,
            libc::SIGTRAP,
            (libc::SIGSTOP << 8) | 0x7f,
            event().status | (1 << 16),
        ] {
            assert!(!event_valid(Event { status, ..event() }, 0x4000, 0x4000));
        }
        for bit in [1, 2, 3, 13, 14, 15] {
            assert!(!event_valid(
                Event {
                    dr6: event().dr6 | (1 << bit),
                    ..event()
                },
                0x4000,
                0x4000
            ));
        }
        assert!(!event_valid(
            Event {
                dr6: event().dr6 & !1,
                ..event()
            },
            0x4000,
            0x4000
        ));
        assert!(!event_valid(
            Event {
                signo: libc::SIGSTOP,
                ..event()
            },
            0x4000,
            0x4000
        ));
        for code in [0, libc::TRAP_BRKPT, libc::TRAP_TRACE, libc::SI_USER] {
            assert!(!event_valid(Event { code, ..event() }, 0x4000, 0x4000));
        }
        assert!(!event_valid(event(), 0x4001, 0x4000));
    }
    #[test]
    fn hardware_initial_owner_and_offsets_are_closed() {
        assert_eq!(initial_control(ORIGINAL[2]), Ok(()));
        for bit in (0..8).chain([13]) {
            assert_eq!(
                initial_control(ORIGINAL[2] | (1 << bit)),
                Err(Error::InitialDebugOwner)
            );
        }
        let base = core::mem::offset_of!(libc::user, u_debugreg);
        assert_eq!(debug_offset(0), Ok(base));
        assert_eq!(debug_offset(6), Ok(base + 48));
        assert_eq!(debug_offset(7), Ok(base + 56));
        for index in [1, 2, 3, 4, 5, 8, usize::MAX] {
            assert_eq!(debug_offset(index), Err(Error::Layout));
        }
    }
    #[test]
    fn hardware_peek_preserves_valid_minus_one() {
        assert_eq!(peek_result(-1, 0), Ok(u64::MAX));
        assert_eq!(peek_result(-1, libc::EIO), Err(Error::Ptrace(libc::EIO)));
        assert_eq!(peek_result(0, libc::EIO), Ok(0));
        assert_eq!(peek_result(-2, 0), Ok(u64::MAX - 1));
    }
    #[test]
    fn hardware_harness_only_removes_authenticated_rf() {
        let expected = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x4000, 18, 0x202, 20, 21, 22,
            23, 24, 25, 26, 27,
        ];
        for rf in [0, RF] {
            let mut raw = registers();
            raw.eflags |= rf;
            let stop = authenticate(Target::probe(raw.rip), event(), raw).unwrap();
            assert_eq!(words(stop.harness().unwrap()), expected);
            assert_eq!(words(*stop.raw()), words(raw));
            assert_eq!(stop.dr6(), event().dr6);
            assert_eq!(raw.eflags ^ stop.harness().unwrap().eflags, rf);
        }
        let mut raw = registers();
        raw.eflags |= TF;
        assert!(
            authenticate(Target::probe(raw.rip), event(), raw)
                .unwrap()
                .harness()
                .is_err()
        );
        assert!(authenticate(Target::probe(raw.rip), Event { code: 0, ..event() }, raw).is_err());
        let mut raw = registers();
        raw.rax ^= 1;
        raw.eflags ^= 1;
        let saved = authenticate(Target::probe(raw.rip), event(), raw)
            .unwrap()
            .harness()
            .unwrap();
        assert_eq!(words(saved), words(raw)); // No repair of non-RF changes.
        let transfer = Target {
            address: raw.rip,
            bytes: &[0xc3],
            save_harness: false,
        };
        assert!(
            authenticate(transfer, event(), raw)
                .unwrap()
                .harness()
                .is_err()
        );
    }

    struct Script {
        words: RefCell<[u64; 3]>,
        writes: RefCell<Vec<(Reg, u64)>>,
        count: Cell<usize>,
        fail: Cell<Option<usize>>,
        mismatch: Cell<bool>,
    }
    impl Script {
        fn new() -> Self {
            Self {
                words: RefCell::new(ORIGINAL),
                writes: RefCell::new(Vec::new()),
                count: Cell::new(0),
                fail: Cell::new(None),
                mismatch: Cell::new(false),
            }
        }
        fn operation(&self) -> Result<(), Error> {
            let n = self.count.get() + 1;
            self.count.set(n);
            if self.fail.get() == Some(n) {
                Err(Error::Ptrace(libc::EIO))
            } else {
                Ok(())
            }
        }
        fn index(reg: Reg) -> usize {
            match reg {
                Reg::Address => 0,
                Reg::Status => 1,
                Reg::Control => 2,
            }
        }
        fn restored(&self) {
            assert_eq!(*self.words.borrow(), ORIGINAL);
            assert!(self.writes.borrow().ends_with(&[
                (Reg::Control, ORIGINAL[2]),
                (Reg::Address, ORIGINAL[0]),
                (Reg::Status, ORIGINAL[1]),
                (Reg::Control, ORIGINAL[2]),
            ]));
        }
    }
    impl DebugAccess for Script {
        fn read(&self, reg: Reg) -> Result<u64, Error> {
            self.operation()?;
            Ok(self.words.borrow()[Self::index(reg)] ^ u64::from(self.mismatch.replace(false)))
        }
        fn write(&self, reg: Reg, value: u64) -> Result<(), Error> {
            self.operation()?;
            self.writes.borrow_mut().push((reg, value));
            self.words.borrow_mut()[Self::index(reg)] = value;
            Ok(())
        }
    }
    #[test]
    fn hardware_partial_install_and_restore_keep_custody() {
        for failing in 1..=3 {
            let io = Script::new();
            io.fail.set(Some(failing));
            assert!(Owner::save(&io).is_err());
            assert!(io.writes.borrow().is_empty());
        }
        for failing in 1..=7 {
            let io = Script::new();
            let mut owner = Owner::save(&io).unwrap();
            io.fail.set(Some(io.count.get() + failing));
            assert!(owner.install(0x4000).is_err());
            drop(owner);
            io.restored();
        }
        for failing in 1..=7 {
            let io = Script::new();
            let mut owner = Owner::save(&io).unwrap();
            owner.install(0x4000).unwrap();
            io.fail.set(Some(io.count.get() + failing));
            assert!(owner.restore().is_err());
            drop(owner);
            io.restored();
        }
    }
    #[test]
    fn hardware_readback_and_exact_restoration() {
        let io = Script::new();
        let mut owner = Owner::save(&io).unwrap();
        owner.install(0x4000).unwrap();
        assert_eq!(*io.words.borrow(), [0x4000, 0xffff_0ff0, 0xabc0_0401]);
        owner.restore().unwrap();
        assert_eq!(owner.state, State::Restored);
        let count = io.count.get();
        drop(owner);
        assert_eq!(io.count.get(), count);
        io.restored();
        for restoring in [false, true] {
            let io = Script::new();
            let mut owner = Owner::save(&io).unwrap();
            if restoring {
                owner.install(0x4000).unwrap();
            }
            io.mismatch.set(true);
            let result = if restoring {
                owner.restore()
            } else {
                owner.install(0x4000)
            };
            assert_eq!(result, Err(Error::Readback));
            drop(owner);
            io.restored();
        }
    }
    #[test]
    fn hardware_cleanup_does_not_touch_running_or_terminal_child() {
        for state in [State::Running, State::Terminal] {
            let io = Script::new();
            let mut owner = Owner::save(&io).unwrap();
            owner.install(0x4000).unwrap();
            owner.state = state;
            let count = io.count.get();
            drop(owner);
            assert_eq!(io.count.get(), count);
            assert_ne!(*io.words.borrow(), ORIGINAL);
        }
    }
    #[test]
    fn hardware_targets_authenticate_closed_tree_and_literal_bytes() {
        fn ready() -> Ready {
            let root = 0x1100;
            let mut source = vec![0; 4096];
            source[0x100..0x117].copy_from_slice(&call_tree::truth::ROOT_BYTES);
            source[0x117..0x120].copy_from_slice(&call_tree::truth::GAP_BYTES);
            source[0x120..0x147].copy_from_slice(&call_tree::truth::CHILD_BYTES);
            let heads: Vec<_> = call_tree::truth::ROOT_HEADS
                .iter()
                .map(|&n| root + u64::from(n))
                .chain(
                    call_tree::truth::CHILD_HEADS
                        .iter()
                        .map(|&n| root + 32 + u64::from(n)),
                )
                .collect();
            Ready {
                profile: Profile::Legacy,
                entry: root,
                gate: 0x3000,
                continuation: 0x3019,
                boundaries: heads.iter().map(|&p| (p, p)).collect(),
                heads,
                returns: vec![root + 22, root + 70],
                original_source: source.clone(),
                immutable: vec![(0x1000, source)],
            }
        }
        for (role, address) in [
            (Role::GateEntry, 0x3000),
            (Role::OuterCall, 0x3016),
            (Role::TreeCall, 0x1109),
            (Role::ChildRet, 0x1146),
            (Role::RootRet, 0x1116),
            (Role::OuterRet, 0x301e),
        ] {
            let target = Target::ready(&ready(), false, role).unwrap();
            assert_eq!(target.address, address);
            assert_eq!(target.instruction(target.bytes), Ok(()));
            for i in 0..target.bytes.len() {
                let mut changed = target.bytes.to_vec();
                changed[i] ^= 1;
                assert_eq!(target.instruction(&changed), Err(Error::Instruction));
            }
        }
        let mut wrong = ready();
        wrong.profile = Profile::NativeCall;
        assert!(Target::ready(&wrong, false, Role::GateEntry).is_err());
        let mut wrong = ready();
        wrong.original_source[0x109] ^= 1;
        wrong.immutable[0].1 = wrong.original_source.clone();
        assert!(Target::ready(&wrong, false, Role::TreeCall).is_err());
        let mut wrong = ready();
        wrong.immutable.push((0x4000, vec![0xe8; 4096]));
        wrong
            .boundaries
            .iter_mut()
            .find(|(p, _)| *p == 0x1109)
            .unwrap()
            .1 = 0x4000;
        assert!(Target::ready(&wrong, true, Role::TreeCall).is_err());
    }
}

#[cfg(test)]
#[path = "native_tree_hardware_control.rs"]
mod control;
