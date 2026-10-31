//! Private premises for one fresh, sole-main-thread indexed-DSO witness.
//! No native call, loader authority, handler, supervisor or stack switch is supplied.
//! Numeric range checks never establish pointer validity or lifetime.

use li2core::trampoline::SavedExtendedStateLayout;
use std::{fs::OpenOptions, io::Read, marker::PhantomData, os::unix::fs::OpenOptionsExt, rc::Rc};

pub const CHAIN_STACK_BYTES: u64 = 128 * 1024;
const STATE_OVERHEAD: u64 = 4096;
const MAP_BYTES: usize = 2 * 1024 * 1024;
const MAP_ROWS: usize = 65536;
const RANGE_COUNT: usize = 64;
// The raw kernel ABI includes glibc's reserved realtime signals, unlike
// pthread_sigmask. SIGKILL/SIGSTOP remain unmaskable; faults still fail the run.
const BLOCKED: u64 = !(1 << (libc::SIGKILL - 1) | 1 << (libc::SIGSTOP - 1));

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Io(std::io::ErrorKind),
    Os(&'static str, i32),
    Environment,
    Tasks,
    Affinity,
    Identity,
    CpuChanged,
    IbtAdvertised,
    ShadowStack,
    Xstate,
    SignalMask,
    Stack,
    Mapping,
    Bounds,
    Overlap(usize, usize),
}
type Result<T> = std::result::Result<T, Error>;
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}
fn require(ok: bool, error: Error) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}
fn last(operation: &'static str) -> Error {
    Error::Os(
        operation,
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    )
}

/// A nonempty numeric user-address range, without a dereference capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    start: u64,
    end: u64,
}
impl Range {
    pub fn new(start: u64, length: u64) -> Result<Self> {
        let end = start.checked_add(length).ok_or(Error::Bounds)?;
        require(
            start != 0 && length != 0 && end <= isize::MAX as u64,
            Error::Bounds,
        )?;
        Ok(Self { start, end })
    }
    pub const fn start(self) -> u64 {
        self.start
    }
    pub const fn end(self) -> u64 {
        self.end
    }
    pub const fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// Supply distinct leaf objects (records/control/observations/input/code/CFI/
/// context/globals), not their overlapping containing allocations. The owner
/// separately proves their permissions, full sizes, lifetimes and provenance.
pub fn require_disjoint(ranges: &[Range]) -> Result<()> {
    require(
        !ranges.is_empty() && ranges.len() <= RANGE_COUNT,
        Error::Bounds,
    )?;
    for (i, a) in ranges.iter().enumerate() {
        for (j, b) in ranges[..i].iter().enumerate() {
            if a.start < b.end && b.start < a.end {
                return Err(Error::Overlap(j, i));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cpu {
    pub basic: [u32; 4],
    pub features: [u32; 4],
    pub structured: [u32; 4],
}
fn ibt_absent(cpu: Cpu) -> Result<()> {
    require(cpu.basic[0] >= 1, Error::CpuChanged)?;
    require(
        cpu.basic[0] >= 7 || cpu.structured == [0; 4],
        Error::CpuChanged,
    )?;
    require(cpu.structured[3] & (1 << 20) == 0, Error::IbtAdvertised)
}
#[allow(unused_unsafe)] // CPUID intrinsic safety changed across supported Rust versions.
fn cpu() -> Result<Cpu> {
    use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};
    let words = |r: CpuidResult| [r.eax, r.ebx, r.ecx, r.edx];
    // SAFETY: this module is for Linux x86-64; CPUID is architectural here.
    let basic = words(unsafe { __cpuid(0) });
    require(basic[0] >= 1, Error::CpuChanged)?;
    let value = Cpu {
        basic,
        features: words(unsafe { __cpuid(1) }),
        structured: if basic[0] >= 7 {
            words(unsafe { __cpuid_count(7, 0) })
        } else {
            [0; 4]
        },
    };
    ibt_absent(value)?;
    Ok(value)
}

/// Unsupported is recorded distinctly, not labelled a successful status query.
/// It requires the caller's trusted-Linux/no-alternate-userspace-CET-ABI premise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowStack {
    Disabled,
    Unsupported(i32),
}
fn classify_shadow(rc: i64, value: u64, errno: i32) -> Result<ShadowStack> {
    match (rc, value, errno) {
        (0, 0, _) => Ok(ShadowStack::Disabled),
        (-1, _, libc::EINVAL | libc::ENOSYS) => Ok(ShadowStack::Unsupported(errno)),
        _ => Err(Error::ShadowStack),
    }
}
fn shadow_stack() -> Result<ShadowStack> {
    let mut value = 0_u64;
    // SAFETY: read-only ARCH_SHSTK_STATUS and owned unsigned-long output.
    let rc = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut value) };
    let errno = if rc == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    classify_shadow(rc, value, errno)
}
fn signal_mask(set: Option<&u64>) -> Result<u64> {
    let mut old = 0_u64;
    let requested = set.map_or(std::ptr::null(), std::ptr::from_ref);
    // SAFETY: Linux x86-64 rt_sigprocmask uses exactly one kernel u64. The
    // optional input and output are live storage; no handler is installed.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            requested,
            &mut old,
            8_usize,
        )
    };
    if rc != 0 {
        return Err(last("rt_sigprocmask"));
    }
    Ok(old)
}
fn environment() -> Result<()> {
    require(
        ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"]
            .iter()
            .all(|name| std::env::var_os(name).is_none()),
        Error::Environment,
    )
}
fn sole_main_thread() -> Result<u32> {
    let pid = std::process::id();
    // SAFETY: read-only kernel identity query.
    require(
        unsafe { libc::syscall(libc::SYS_gettid) } == i64::from(pid),
        Error::Tasks,
    )?;
    let mut tasks = std::fs::read_dir("/proc/self/task")?;
    let first = tasks.next().transpose()?.ok_or(Error::Tasks)?;
    require(first.file_name() == pid.to_string().as_str(), Error::Tasks)?;
    // At most two entries are requested: a second entry already disproves the
    // exact-one premise. This is not an unbounded process inventory.
    require(tasks.next().transpose()?.is_none(), Error::Tasks)?;
    Ok(pid)
}
fn sole_cpu() -> Result<usize> {
    // SAFETY: zero initialization and the exact fixed libc affinity structure.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) } != 0 {
        return Err(last("sched_getaffinity"));
    }
    require(unsafe { libc::CPU_COUNT(&set) } == 1, Error::Affinity)?;
    let current = unsafe { libc::sched_getcpu() };
    require(
        current >= 0 && (current as usize) < libc::CPU_SETSIZE as usize,
        Error::Affinity,
    )?;
    require(
        unsafe { libc::CPU_ISSET(current as usize, &set) },
        Error::Affinity,
    )?;
    Ok(current as usize)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stack {
    pub allocation: Range,
    pub mapped: Range,
    /// Bytes both attributed to this pthread stack and actually mapped RW.
    pub usable: Range,
    pub rsp: u64,
    pub required_below: u64,
}
impl Stack {
    /// Retain both raw identities: equal intersections cannot hide VMA growth
    /// or a changed pthread allocation.
    fn verify_extents(self, current: Self) -> Result<()> {
        require(
            current.allocation == self.allocation && current.mapped == self.mapped,
            Error::Stack,
        )
    }
    pub fn exclude_object(self, object: Range) -> Result<()> {
        require_disjoint(&[object, self.allocation])?;
        require_disjoint(&[object, self.mapped])
    }
}
fn stack_allocation() -> Result<Range> {
    let mut attributes = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    // SAFETY: querying the current, still-owned main thread into valid storage.
    let rc = unsafe { libc::pthread_getattr_np(libc::pthread_self(), attributes.as_mut_ptr()) };
    if rc != 0 {
        return Err(Error::Os("pthread_getattr_np", rc));
    }
    let mut attributes = unsafe { attributes.assume_init() };
    let (mut address, mut bytes) = (std::ptr::null_mut(), 0_usize);
    let rc = unsafe { libc::pthread_attr_getstack(&attributes, &mut address, &mut bytes) };
    // Destroy even if the query refused; no stack ownership is released here.
    let destroyed = unsafe { libc::pthread_attr_destroy(&mut attributes) };
    if rc != 0 {
        return Err(Error::Os("pthread_attr_getstack", rc));
    }
    if destroyed != 0 {
        return Err(Error::Os("pthread_attr_destroy", destroyed));
    }
    Range::new(address as usize as u64, bytes as u64)
}

const PRETOUCH_BYTES: usize = 256 * 1024;
const PRETOUCH_FRAME_ALLOWANCE: u64 = 64 * 1024;
fn pretouch_capacity(allocation: Range, rsp: u64) -> Result<()> {
    require(
        allocation.contains(Range::new(rsp, 8)?)
            && rsp
                .checked_sub(allocation.start())
                .is_some_and(|available| {
                    available >= PRETOUCH_BYTES as u64 + PRETOUCH_FRAME_ALLOWANCE
                }),
        Error::Stack,
    )
}

#[inline(never)]
fn touch_owned_stack_array() {
    // A real local allocation; never derive or dereference a pointer below RSP.
    // MaybeUninit avoids a second initialization temporary in debug builds.
    let mut bytes = std::mem::MaybeUninit::<[u8; PRETOUCH_BYTES]>::uninit();
    let pointer = bytes.as_mut_ptr().cast::<u8>();
    for offset in 0..PRETOUCH_BYTES {
        // SAFETY: every byte belongs to this live local array. Write each byte
        // before allowing the opaque consumer to observe the allocation.
        unsafe { pointer.add(offset).write_volatile(0) };
    }
    std::hint::black_box(&mut bytes);
}

/// One fixed preparation step before admission, not a response to a failed
/// reserve check. The separate helper cannot reserve its array before this
/// outer capacity check. Runtime::enter/verify still require the full mapped
/// reserve and reject any later extent change. Compiler stack layout and Linux
/// main-stack growth remain part of the trusted experiment's host contract.
pub fn prepare_stack() -> Result<()> {
    sole_main_thread()?;
    let allocation = stack_allocation()?;
    let rsp: u64;
    // SAFETY: read only the current stack pointer.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    pretouch_capacity(allocation, rsp)?;
    touch_owned_stack_array();
    Ok(())
}
fn maps() -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/proc/self/maps")?;
    require(file.metadata()?.is_file(), Error::Mapping)?;
    let mut bytes = Vec::new();
    file.take((MAP_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    require(bytes.len() <= MAP_BYTES, Error::Bounds)?;
    String::from_utf8(bytes).map_err(|_| Error::Mapping)
}
fn number(text: &str, radix: u32) -> Result<u64> {
    require(
        !text.is_empty()
            && text.bytes().all(|b| {
                if radix == 16 {
                    b.is_ascii_hexdigit()
                } else {
                    b.is_ascii_digit()
                }
            }),
        Error::Mapping,
    )?;
    u64::from_str_radix(text, radix).map_err(|_| Error::Mapping)
}
fn stack_mapping(text: &str) -> Result<Range> {
    require(
        !text.is_empty() && text.len() <= MAP_BYTES && text.ends_with('\n'),
        Error::Mapping,
    )?;
    let (mut previous, mut stack) = (0, None);
    for (index, line) in text.lines().enumerate() {
        require(index < MAP_ROWS, Error::Bounds)?;
        let mut fields = line.split_ascii_whitespace();
        let mut next = || fields.next().ok_or(Error::Mapping);
        let (start, end) = next()?.split_once('-').ok_or(Error::Mapping)?;
        let (start, end) = (number(start, 16)?, number(end, 16)?);
        require(
            start != 0 && start < end && start >= previous,
            Error::Mapping,
        )?;
        previous = end;
        let permissions = next()?;
        let p = permissions.as_bytes();
        require(
            p.len() == 4
                && matches!(p[0], b'r' | b'-')
                && matches!(p[1], b'w' | b'-')
                && matches!(p[2], b'x' | b'-')
                && matches!(p[3], b'p' | b's'),
            Error::Mapping,
        )?;
        let offset = number(next()?, 16)?;
        let (major, minor) = next()?.split_once(':').ok_or(Error::Mapping)?;
        let device = (number(major, 16)?, number(minor, 16)?);
        let inode = number(next()?, 10)?;
        if fields.next() == Some("[stack]") {
            require(
                stack.is_none()
                    && fields.next().is_none()
                    && permissions == "rw-p"
                    && offset == 0
                    && device == (0, 0)
                    && inode == 0,
                Error::Mapping,
            )?;
            stack = Some(Range::new(start, end - start)?);
        }
    }
    stack.ok_or(Error::Mapping)
}
fn stack_extent(
    allocation: Range,
    mapped: Range,
    rsp: u64,
    marker: u64,
    xstate_bytes: u64,
) -> Result<Stack> {
    let required_below = CHAIN_STACK_BYTES
        .checked_add(xstate_bytes)
        .and_then(|n| n.checked_add(STATE_OVERHEAD))
        .ok_or(Error::Bounds)?;
    // glibc's main-thread allocation can end below the [stack] VMA's argv,
    // environment and auxv pages. Neither observation alone defines usable
    // call-stack memory: require ownership AND actual mapping for every byte.
    let start = allocation.start.max(mapped.start);
    let end = allocation.end.min(mapped.end);
    require(xstate_bytes != 0 && start < end, Error::Stack)?;
    let usable = Range::new(start, end - start)?;
    require(
        usable.contains(Range::new(rsp, 8)?) && usable.contains(Range::new(marker, 1)?),
        Error::Stack,
    )?;
    require(
        rsp.checked_sub(usable.start)
            .is_some_and(|n| n >= required_below),
        Error::Stack,
    )?;
    Ok(Stack {
        allocation,
        mapped,
        usable,
        rsp,
        required_below,
    })
}
fn stack(layout: SavedExtendedStateLayout) -> Result<Stack> {
    let allocation = stack_allocation()?;
    let marker = 0_u8;
    let address = std::hint::black_box(&marker) as *const u8 as usize as u64;
    let rsp: u64;
    // SAFETY: read the real current RSP; no memory access or stack modification.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    let mapped = stack_mapping(&maps()?)?;
    std::hint::black_box(&marker);
    let result = stack_extent(allocation, mapped, rsp, address, layout.len());
    if result.is_err() {
        eprintln!(
            "stack_extent_refused allocation={allocation:?} mapped={mapped:?} rsp={rsp:#x} marker={address:#x} xstate_bytes={}",
            layout.len()
        );
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub pid: u32,
    pub cpu: usize,
    pub features: Cpu,
    pub xstate: SavedExtendedStateLayout,
    pub shadow_stack: ShadowStack,
    pub prior_mask: u64,
    pub blocked_mask: u64,
    pub stack: Stack,
}
pub struct Runtime {
    evidence: Evidence,
    _local: PhantomData<Rc<()>>,
}
impl Runtime {
    /// Establish finite observations, then keep all signals blocked until exit.
    ///
    /// # Safety
    /// This must be a fresh process on a trusted Linux x86-64 kernel with
    /// faithful CPUID/proc/pthread/syscall interfaces (no errno-forcing filter)
    /// and no alternate legacy CET ABI enabling SHSTK when ARCH_SHSTK_STATUS
    /// is unsupported. The caller owns
    /// all compiler/CRT/loader/consumer dependencies and the actual tiny chain's
    /// stack-depth proof within CHAIN_STACK_BYTES. Boundary observations do not
    /// prove continuous facts: no thread creation, affinity/XCR0/CET changes,
    /// signal-mask changes, handlers entering the fixture, reentry, concurrent
    /// writers, unload, stack switch, mapping/protection changes or foreign
    /// saved context may occur through complete postflight. The owner retains
    /// every input/output/context/code/CFI/global pointer with valid permission,
    /// size and lifetime. Existing runtime handlers are not approved to run;
    /// synchronous faults, SIGKILL and SIGSTOP are not converted into success.
    /// This helper does not disable CET, install handlers or invoke any DSO.
    pub unsafe fn enter() -> Result<Self> {
        environment()?;
        let pid = sole_main_thread()?;
        let cpu_number = sole_cpu()?;
        let prior_mask = signal_mask(Some(&BLOCKED))?;
        require(signal_mask(None)? == BLOCKED, Error::SignalMask)?;
        let features = cpu()?;
        let xstate = SavedExtendedStateLayout::detect().map_err(|_| Error::Xstate)?;
        let shadow_stack = shadow_stack()?;
        let stack = stack(xstate)?;
        let runtime = Self {
            evidence: Evidence {
                pid,
                cpu: cpu_number,
                features,
                xstate,
                shadow_stack,
                prior_mask,
                blocked_mask: BLOCKED,
                stack,
            },
            _local: PhantomData,
        };
        runtime.verify()?;
        Ok(runtime)
    }
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    /// Recheck before/after loading and every native invocation, on this thread.
    /// A failure is terminal; this never repairs changed state or retries work.
    pub fn verify(&self) -> Result<Stack> {
        require(sole_main_thread()? == self.evidence.pid, Error::Identity)?;
        environment()?;
        require(sole_cpu()? == self.evidence.cpu, Error::Affinity)?;
        require(cpu()? == self.evidence.features, Error::CpuChanged)?;
        require(
            SavedExtendedStateLayout::detect().map_err(|_| Error::Xstate)? == self.evidence.xstate,
            Error::Xstate,
        )?;
        require(
            shadow_stack()? == self.evidence.shadow_stack,
            Error::ShadowStack,
        )?;
        require(signal_mask(None)? == BLOCKED, Error::SignalMask)?;
        let current = stack(self.evidence.xstate)?;
        if current.allocation != self.evidence.stack.allocation
            || current.mapped != self.evidence.stack.mapped
        {
            eprintln!(
                "stack_identity_refused initial={:?} current={current:?}",
                self.evidence.stack
            );
        }
        self.evidence.stack.verify_extents(current)?;
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn range(a: u64, b: u64) -> Range {
        Range::new(a, b - a).unwrap()
    }
    #[test]
    fn preparation_refuses_insufficient_owned_stack_before_entering_large_frame() {
        let allocation = range(0x100000, 0x200000);
        let threshold = allocation.start() + PRETOUCH_BYTES as u64 + PRETOUCH_FRAME_ALLOWANCE;
        pretouch_capacity(allocation, threshold).unwrap();
        assert_eq!(
            pretouch_capacity(allocation, threshold - 1),
            Err(Error::Stack)
        );
        assert_eq!(
            pretouch_capacity(allocation, allocation.end()),
            Err(Error::Stack)
        );
    }
    #[test]
    fn numeric_objects_refuse_aliases_overflow_and_excess_count() {
        let a = range(0x1000, 0x2000);
        let b = range(0x2000, 0x2008);
        require_disjoint(&[a, b]).unwrap();
        assert!(a.contains(range(0x1008, 0x1010)));
        assert_eq!(
            require_disjoint(&[a, range(0x1fff, 0x2001)]),
            Err(Error::Overlap(0, 1))
        );
        for (start, len) in [(0, 1), (1, 0), (u64::MAX, 2), (isize::MAX as u64, 1)] {
            assert_eq!(Range::new(start, len), Err(Error::Bounds));
        }
        let full: Vec<_> = (1..=64).map(|n| Range::new(n * 16, 8).unwrap()).collect();
        require_disjoint(&full).unwrap();
        let mut excess = full;
        excess.push(Range::new(0x10000, 8).unwrap());
        assert_eq!(require_disjoint(&excess), Err(Error::Bounds));
    }
    #[test]
    fn ibt_advertisement_never_becomes_an_inactive_assumption() {
        let mut value = Cpu {
            basic: [7, 0, 0, 0],
            features: [0; 4],
            structured: [0; 4],
        };
        ibt_absent(value).unwrap();
        value.structured[3] = 1 << 20;
        assert_eq!(ibt_absent(value), Err(Error::IbtAdvertised));
        value.basic[0] = 1;
        assert_eq!(ibt_absent(value), Err(Error::CpuChanged));
        value.structured = [0; 4];
        ibt_absent(value).unwrap();
    }
    #[test]
    fn shadow_status_distinguishes_unsupported_and_rejects_active_or_unknown() {
        assert_eq!(classify_shadow(0, 0, 0), Ok(ShadowStack::Disabled));
        for errno in [libc::EINVAL, libc::ENOSYS] {
            assert_eq!(
                classify_shadow(-1, 0, errno),
                Ok(ShadowStack::Unsupported(errno))
            );
        }
        for value in [1, 2, u64::MAX] {
            assert_eq!(classify_shadow(0, value, 0), Err(Error::ShadowStack));
        }
        assert_eq!(classify_shadow(-1, 0, libc::EPERM), Err(Error::ShadowStack));
    }
    #[test]
    fn raw_signal_mask_includes_reserved_realtime_signals() {
        for signal in 1..=64 {
            assert_eq!(
                BLOCKED & (1 << (signal - 1)) != 0,
                !matches!(signal, 9 | 19)
            );
        }
    }
    #[test]
    fn stack_requires_actual_rw_private_anonymous_unique_mapping() {
        const VALID: &str = "1000-2000 r-xp 00000000 00:01 10 /fixture\n100000-200000 rw-p 00000000 00:00 0 [stack]\n";
        assert_eq!(stack_mapping(VALID).unwrap(), range(0x100000, 0x200000));
        for (from, to) in [
            ("rw-p", "r--p"),
            ("rw-p", "rwxp"),
            ("rw-p", "rw-s"),
            ("00:00 0", "00:01 0"),
            ("00:00 0", "00:00 9"),
            ("[stack]", "[stack:7]"),
            ("100000-200000", "1800-200000"),
        ] {
            assert!(stack_mapping(&VALID.replace(from, to)).is_err());
        }
        assert!(stack_mapping(&format!("{VALID}200000-210000 rw-p 0 00:00 0 [stack]\n")).is_err());
        assert!(stack_mapping(VALID.trim_end()).is_err());
    }
    #[test]
    fn stack_reserve_charges_actual_xstate_and_never_reads_a_guessed_address() {
        let allocation = range(0x100000, 0x400000);
        let mapped = range(0x200000, 0x300000);
        let needed = CHAIN_STACK_BYTES + STATE_OVERHEAD + 576;
        let rsp = mapped.start + needed;
        assert_eq!(
            stack_extent(allocation, mapped, rsp, rsp + 8, 576)
                .unwrap()
                .required_below,
            needed
        );
        assert_eq!(
            stack_extent(allocation, mapped, rsp - 1, rsp + 8, 576),
            Err(Error::Stack)
        );
        assert_eq!(
            stack_extent(allocation, mapped, rsp, rsp + 8, 577),
            Err(Error::Stack)
        );
        assert_eq!(
            stack_extent(allocation, mapped, rsp, mapped.end, 576),
            Err(Error::Stack)
        );
        assert_eq!(
            stack_extent(range(0x280000, 0x400000), mapped, rsp, rsp + 8, 576),
            Err(Error::Stack)
        );
        assert_eq!(
            stack_extent(allocation, mapped, rsp, rsp + 8, u64::MAX),
            Err(Error::Bounds)
        );
    }
    #[test]
    fn main_stack_excludes_upper_argument_pages_without_losing_reserve() {
        let allocation = range(0x100000, 0x300000);
        let mapped = range(0x200000, 0x302000);
        let needed = CHAIN_STACK_BYTES + STATE_OVERHEAD + 2496;
        let rsp = mapped.start + needed;
        let stack = stack_extent(allocation, mapped, rsp, rsp + 8, 2496).unwrap();
        assert_eq!(stack.usable, range(0x200000, 0x300000));
        assert_eq!(stack.allocation, allocation);
        assert_eq!(stack.mapped, mapped);
        assert_eq!(stack.required_below, needed);
        assert_eq!(
            stack_extent(allocation, mapped, rsp - 1, rsp + 8, 2496),
            Err(Error::Stack)
        );
        assert_eq!(
            stack_extent(
                range(mapped.start + 1, allocation.end),
                mapped,
                rsp,
                rsp + 8,
                2496
            ),
            Err(Error::Stack)
        );
        // A pointer inside the VMA but above pthread's end is never usable.
        for (sample, marker) in [
            (allocation.end, rsp + 8),
            (allocation.end - 7, rsp + 8),
            (rsp, allocation.end),
        ] {
            assert_eq!(
                stack_extent(allocation, mapped, sample, marker, 2496),
                Err(Error::Stack)
            );
        }
        for other in [range(0x302000, 0x400000), range(0x400000, 0x500000)] {
            assert_eq!(
                stack_extent(other, mapped, rsp, rsp + 8, 2496),
                Err(Error::Stack)
            );
        }
    }
    #[test]
    fn stack_identity_retains_raw_ranges_even_when_intersection_is_unchanged() {
        let allocation = range(0x100000, 0x300000);
        let mapped = range(0x200000, 0x302000);
        let rsp = 0x280000;
        let original = stack_extent(allocation, mapped, rsp, rsp + 8, 2496).unwrap();
        let deeper = stack_extent(allocation, mapped, rsp - 16, rsp - 8, 2496).unwrap();
        original.verify_extents(deeper).unwrap();
        for (allocation, mapped) in [
            (range(0x0f0000, allocation.end), mapped),
            (allocation, range(mapped.start, 0x303000)),
        ] {
            let current = stack_extent(allocation, mapped, rsp, rsp + 8, 2496).unwrap();
            assert_eq!(current.usable, original.usable);
            assert_eq!(original.verify_extents(current), Err(Error::Stack));
        }
    }
    #[test]
    fn object_exclusion_covers_pthread_reservation_and_mapped_argument_tail() {
        let stack = stack_extent(
            range(0x100000, 0x300000),
            range(0x200000, 0x302000),
            0x280000,
            0x280008,
            2496,
        )
        .unwrap();
        for object in [range(0x180000, 0x180008), range(0x300000, 0x300008)] {
            assert_eq!(stack.exclude_object(object), Err(Error::Overlap(0, 1)));
        }
        stack.exclude_object(range(0x302000, 0x302008)).unwrap();
    }
}
