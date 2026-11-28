//! The attach-mode stretch driver (test seams only).
//!
//! It drives a budget stretch in a process the caller already traces
//! and whose arena the caller placed: no remote child, no mailbox, no
//! setup report and no signal-action dump. The caller (the test
//! harness) spawns the host, which stops itself under ptrace, then
//! places the arena with [`inject_syscall`] (one `mmap`, then one
//! `mprotect` of the code part to RX) and builds an
//! [`AttachedExecutable`]. That queries the host's 64 signal actions
//! through [`inject_syscall`] and wraps a `RemoteExecutable` built
//! over the attached tracee, so the stretch engine is the remote
//! engine's own code, unchanged.
//!
//! `AttachedExecutable` is concrete over the in-crate tracee (through
//! [`AttachTracee`]), not generic over any [`Tracee`]; a later change, with other
//! tracees, would revisit that. It never kills, reaps or detaches the
//! host: the caller owns its lifetime.

use crate::exec::{BudgetStop, CODE_CAP, Outcome, RunError};
use crate::o1::ChildInfo;
use crate::refuse::Refuse;
use crate::remote::{GuestAction, RemoteChildInfo, RemoteExecutable, SignalRegistry};
use crate::state::{GuestState, JitData};
use crate::tracee::{AttachTracee, Errno, Tracee};
use crate::types::{CountProfile, RegionFacts};

/// `syscall; int3`: the injected instruction pair.
const SYSCALL_INT3: [u8; 3] = [0x0f, 0x05, 0xcc];

/// The host's injection site: its stop RIP, the 3 original bytes
/// there, and the full register set at the stop. Every
/// [`inject_syscall`] starts from these saved registers and restores
/// both the bytes and the registers.
#[derive(Clone, Copy)]
pub struct PatchSite {
    pub rip: u64,
    pub orig: [u8; 3],
    pub regs: libc::user_regs_struct,
}

impl PatchSite {
    /// Capture the site at the host's current stop: its registers,
    /// then the 3 bytes at its RIP.
    pub fn capture<T: Tracee>(tracee: &T) -> Result<PatchSite, Refuse> {
        let regs = tracee
            .get_regs()
            .map_err(seam("attach: PTRACE_GETREGS at the patch site"))?;
        let mut orig = [0u8; 3];
        tracee
            .read_mem(regs.rip, &mut orig)
            .map_err(seam("attach: read the patch site bytes"))?;
        Ok(PatchSite {
            rip: regs.rip,
            orig,
            regs,
        })
    }
}

/// What the caller mapped in the host: the code region (RX) and,
/// directly after it, the data region (RW) that holds `JitData`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArenaPlacement {
    pub code_base: u64,
    pub code_len: usize,
    pub data_addr: u64,
    pub data_len: usize,
}

impl ArenaPlacement {
    /// The remote layout the translation assumes: code in the first
    /// `CODE_CAP` bytes, `JitData` directly after, all of it inside
    /// the mapping. Anything else refuses by name.
    fn check(&self) -> Result<(), Refuse> {
        if self.code_len < CODE_CAP {
            return Err(Refuse::Arch {
                what: "attach arena: code region shorter than CODE_CAP",
            });
        }
        if self.data_addr != self.code_base + CODE_CAP as u64 {
            return Err(Refuse::Arch {
                what: "attach arena: data region does not follow the code at CODE_CAP",
            });
        }
        if self.data_len < core::mem::size_of::<JitData>() {
            return Err(Refuse::Arch {
                what: "attach arena: data region shorter than JitData",
            });
        }
        Ok(())
    }
}

fn seam(operation: &'static str) -> impl FnOnce(Errno) -> Refuse {
    move |Errno(errno)| Refuse::RemoteSubstrate { operation, errno }
}

/// The errno an injected syscall returned, if its RAX is -1..=-4095.
pub fn syscall_errno(rax: u64) -> Option<i32> {
    let v = rax as i64;
    (-4095..=-1).contains(&v).then(|| (-v) as i32)
}

/// A FOLL_FORCE write of all of `bytes` into the host at `addr`
/// through `/proc/<pid>/mem` (it can write an RX mapping, which
/// `process_vm_writev` cannot). A short write is a failure.
fn proc_mem_write(pid: i32, addr: u64, bytes: &[u8]) -> Result<(), i32> {
    use std::os::unix::fs::FileExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/{pid}/mem"))
        .map_err(|e| e.raw_os_error().unwrap_or(0))?;
    match file.write_at(bytes, addr) {
        Ok(n) if n == bytes.len() => Ok(()),
        Ok(_) => Err(libc::EIO),
        Err(e) => Err(e.raw_os_error().unwrap_or(0)),
    }
}

/// The ONE route for every syscall the attach path injects. Each call
/// is self-contained:
/// - registers start from the SAVED set; RAX = `nr`, RDI, RSI, RDX,
///   R10, R8 and R9 = `args`, RIP = the site, and `orig_rax` = -1
///   (a signal-delivery stop, no syscall in progress);
/// - `syscall; int3` is written at the site through `/proc/<pid>/mem`;
/// - the host resumes with signal 0 (its stop is a SIGTRAP delivery
///   stop, which must not be delivered);
/// - the expected stop is SIGTRAP with RIP = site + 3; anything else
///   refuses by name (the caller then kills the host);
/// - RAX at that stop is the result, returned raw: the caller decodes
///   -errno ([`syscall_errno`]) and checks the call's own success
///   value;
/// - the 3 saved bytes are written back and read back, a mismatch
///   refuses by name, and then the saved registers are restored.
pub fn inject_syscall<T: Tracee>(
    tracee: &T,
    site: &PatchSite,
    nr: u64,
    args: [u64; 6],
) -> Result<u64, Refuse> {
    let pid = tracee.pid();
    let mut regs = site.regs;
    regs.rax = nr;
    regs.rdi = args[0];
    regs.rsi = args[1];
    regs.rdx = args[2];
    regs.r10 = args[3];
    regs.r8 = args[4];
    regs.r9 = args[5];
    regs.rip = site.rip;
    regs.orig_rax = u64::MAX;
    proc_mem_write(pid, site.rip, &SYSCALL_INT3).map_err(|errno| Refuse::RemoteSubstrate {
        operation: "attach inject: write syscall; int3",
        errno,
    })?;
    tracee
        .set_regs(&regs)
        .map_err(seam("attach inject: PTRACE_SETREGS"))?;
    tracee.cont(0).map_err(seam("attach inject: PTRACE_CONT"))?;
    let status = tracee
        .wait_stop()
        .map_err(seam("attach inject: waitpid"))?;
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP {
        return Err(Refuse::RemoteSubstrate {
            operation: "attach inject: the stop after the syscall is not SIGTRAP",
            errno: 0,
        });
    }
    let after = tracee
        .get_regs()
        .map_err(seam("attach inject: PTRACE_GETREGS after the syscall"))?;
    if after.rip != site.rip + SYSCALL_INT3.len() as u64 {
        return Err(Refuse::RemoteSubstrate {
            operation: "attach inject: the stop RIP is not the site + 3",
            errno: 0,
        });
    }
    let result = after.rax;
    proc_mem_write(pid, site.rip, &site.orig).map_err(|errno| Refuse::RemoteSubstrate {
        operation: "attach inject: restore the site bytes",
        errno,
    })?;
    let mut back = [0u8; 3];
    tracee
        .read_mem(site.rip, &mut back)
        .map_err(seam("attach inject: read back the site bytes"))?;
    if back != site.orig {
        return Err(Refuse::RemoteSubstrate {
            operation: "attach inject: the restored site bytes differ",
            errno: 0,
        });
    }
    tracee
        .set_regs(&site.regs)
        .map_err(seam("attach inject: restore the saved registers"))?;
    Ok(result)
}

/// A budgeted (or plain) direct-block executable over an attached
/// host: the remote engine, run in a process the caller traces and
/// owns, with an arena the caller placed.
pub struct AttachedExecutable {
    inner: RemoteExecutable,
    arena: ArenaPlacement,
    region: RegionFacts,
    entry: u64,
    profile: CountProfile,
}

impl AttachedExecutable {
    /// Build the executable AFTER the arena exists. It refuses by name
    /// on a bad placement or if `region.base` is not the host's
    /// `base`. It reads the signal-action mirror itself: for each
    /// signal 1..=64, `rt_sigaction(sig, NULL, scratch, 8)` through
    /// [`inject_syscall`], with `scratch` the JitData scratch in the
    /// placed data region, then the four words handler, flags,
    /// restorer and mask read back. No action is assumed default.
    pub fn new(
        tracee: AttachTracee,
        site: &PatchSite,
        arena: ArenaPlacement,
        host: &ChildInfo,
        region: RegionFacts,
        entry: u64,
        profile: CountProfile,
    ) -> Result<Self, Refuse> {
        arena.check()?;
        if region.base != host.base {
            return Err(Refuse::Unrelocatable {
                src_pc: entry,
                reason: "attach region base does not match the host's fixture mapping",
            });
        }
        let scratch = arena.data_addr + core::mem::offset_of!(JitData, scratch) as u64;
        let mut actions = [GuestAction::default(); 65];
        for (sig, slot) in actions.iter_mut().enumerate().skip(1) {
            let rax = inject_syscall(
                &tracee,
                site,
                libc::SYS_rt_sigaction as u64,
                [sig as u64, 0, scratch, 8, 0, 0],
            )?;
            if rax != 0 {
                return Err(Refuse::RemoteSubstrate {
                    operation: "attach: rt_sigaction query",
                    errno: syscall_errno(rax).unwrap_or(0),
                });
            }
            let mut words = [0u8; 32];
            tracee
                .read_mem(scratch, &mut words)
                .map_err(seam("attach: read an rt_sigaction answer"))?;
            let w = |i: usize| u64::from_le_bytes(words[i * 8..i * 8 + 8].try_into().unwrap());
            *slot = GuestAction {
                handler: w(0),
                flags: w(1),
                restorer: w(2),
                sa_mask: w(3),
            };
        }
        let info = RemoteChildInfo {
            base: host.base,
            stack_top: host.stack_top,
            data: host.data,
            dst: host.dst,
            src: host.src,
            arena_base: arena.code_base,
            mailbox: 0,
        };
        let inner = RemoteExecutable::attach_inner(tracee.0, info, actions)?;
        Ok(AttachedExecutable {
            inner,
            arena,
            region,
            entry,
            profile,
        })
    }

    /// The placement this executable runs in.
    pub fn arena(&self) -> ArenaPlacement {
        self.arena
    }

    /// Translate for the placed arena and install it, UNBUDGETED (the
    /// W2 positive control): `prepare_attached` with `rcb_budget`
    /// false. One-shot.
    pub fn prepare(&mut self) -> Result<(), Refuse> {
        self.inner
            .prepare_attached(&self.region, self.entry, self.profile, false)
    }

    /// As [`AttachedExecutable::prepare`], with the remaining-RCB
    /// budget check in every branch credit stub; such an executable
    /// runs only through [`AttachedExecutable::run_budgeted`].
    pub fn prepare_budgeted(&mut self) -> Result<(), Refuse> {
        self.inner
            .prepare_attached(&self.region, self.entry, self.profile, true)
    }

    /// The initial state as the remote engine builds it: RSP = the
    /// host's stack top, RFLAGS = 0x202, RIP = the host's base.
    pub fn initial_state(&self) -> GuestState {
        self.inner.initial_state()
    }

    /// The remote engine's unbudgeted run, unchanged.
    pub fn run(&mut self, state: GuestState, return_sentinel: u64) -> Result<Outcome, RunError> {
        self.inner.run(state, return_sentinel)
    }

    /// The remote engine's budgeted run, unchanged.
    pub fn run_budgeted(
        &mut self,
        state: GuestState,
        return_sentinel: u64,
        target: u64,
    ) -> Result<BudgetStop, RunError> {
        self.inner.run_budgeted(state, return_sentinel, target)
    }

    /// `PTRACE_SINGLESTEP` requests since the last budget run started
    /// (the W2 witness), from the remote engine's own counter.
    pub fn single_steps_for_test(&self) -> u64 {
        self.inner.single_steps_for_test()
    }

    /// Read host memory (the harness's read-back).
    pub fn read_mem(&self, addr: u64, buf: &mut [u8]) -> bool {
        self.inner.read_mem(addr, buf)
    }

    /// The queried signal-action mirror, for the harness's comparison
    /// with the host's `/proc` `SigCgt` and `SigIgn` before any
    /// stretch.
    pub fn registry(&self) -> &SignalRegistry {
        self.inner.registry()
    }
}

#[cfg(test)]
mod tests {
    //! Refusing cases for the attach driver's own guards: each
    //! `ArenaPlacement::check` refusal by its exact name and the exact
    //! layout accepted, `syscall_errno` at its boundaries, and the two
    //! refusals `AttachedExecutable::new` makes before any ptrace
    //! request. No host is spawned or traced.

    use super::*;

    use crate::tracee::PtraceTracee;
    use crate::types::Generation;

    /// A pid no process can have (Linux caps pid_max at 2^22). If a
    /// guard in `AttachedExecutable::new` is removed, the call reaches
    /// `inject_syscall`, whose first act, opening
    /// `/proc/2147483647/mem`, fails with ENOENT and touches no
    /// process.
    const NO_PID: i32 = i32::MAX;

    const CODE: u64 = 0x7000_0000_0000;
    const DATA: u64 = CODE + CODE_CAP as u64;
    const JD: usize = core::mem::size_of::<JitData>();

    const SHORT_CODE: Refuse = Refuse::Arch {
        what: "attach arena: code region shorter than CODE_CAP",
    };
    const NOT_AT_CAP: Refuse = Refuse::Arch {
        what: "attach arena: data region does not follow the code at CODE_CAP",
    };
    const SHORT_DATA: Refuse = Refuse::Arch {
        what: "attach arena: data region shorter than JitData",
    };

    fn placement(code_len: usize, data_addr: u64, data_len: usize) -> ArenaPlacement {
        ArenaPlacement {
            code_base: CODE,
            code_len,
            data_addr,
            data_len,
        }
    }

    #[test]
    fn check_accepts_the_exact_placement() {
        assert_eq!(placement(CODE_CAP, DATA, JD).check(), Ok(()));
    }

    #[test]
    fn check_refuses_short_code() {
        assert_eq!(placement(CODE_CAP - 1, DATA, JD).check(), Err(SHORT_CODE));
    }

    #[test]
    fn check_refuses_data_not_at_code_cap() {
        assert_eq!(placement(CODE_CAP, DATA - 1, JD).check(), Err(NOT_AT_CAP));
        assert_eq!(placement(CODE_CAP, DATA + 1, JD).check(), Err(NOT_AT_CAP));
    }

    #[test]
    fn check_refuses_short_data() {
        assert_eq!(placement(CODE_CAP, DATA, JD - 1).check(), Err(SHORT_DATA));
    }

    #[test]
    fn errno_zero_is_success() {
        assert_eq!(syscall_errno(0), None);
    }

    #[test]
    fn errno_minus_one_is_eperm() {
        assert_eq!(syscall_errno(-1_i64 as u64), Some(1));
    }

    #[test]
    fn errno_minus_4095_is_the_last_errno() {
        assert_eq!(syscall_errno(-4095_i64 as u64), Some(4095));
    }

    #[test]
    fn errno_minus_4096_is_not_an_errno() {
        assert_eq!(syscall_errno(-4096_i64 as u64), None);
    }

    #[test]
    fn errno_large_pointer_is_not_an_errno() {
        assert_eq!(syscall_errno(0x7fff_ffff_f000), None);
        assert_eq!(syscall_errno(0x7f12_3456_7000), None);
    }

    fn site() -> PatchSite {
        PatchSite {
            rip: 0,
            orig: [0; 3],
            // SAFETY: user_regs_struct holds only integers, so all-zero is valid.
            regs: unsafe { core::mem::zeroed() },
        }
    }

    fn new_with(arena: ArenaPlacement, region_base: u64) -> Option<Refuse> {
        let host = ChildInfo {
            base: 0x0010_0000,
            ..ChildInfo::default()
        };
        let region = RegionFacts {
            base: region_base,
            bytes: vec![0x90],
            generation: Generation(1),
            immutable_private: true,
        };
        AttachedExecutable::new(
            AttachTracee(PtraceTracee::new(NO_PID)),
            &site(),
            arena,
            &host,
            region,
            region_base,
            CountProfile::Branches,
        )
        .err()
    }

    #[test]
    fn new_refuses_a_bad_arena_before_any_ptrace() {
        let bad = placement(CODE_CAP - 1, DATA, JD);
        assert_eq!(new_with(bad, 0x0010_0000), Some(SHORT_CODE));
    }

    #[test]
    fn new_refuses_a_region_base_mismatch_before_any_ptrace() {
        let mismatch = Refuse::Unrelocatable {
            src_pc: 0x0020_0000,
            reason: "attach region base does not match the host's fixture mapping",
        };
        let exact = placement(CODE_CAP, DATA, JD);
        assert_eq!(new_with(exact, 0x0020_0000), Some(mismatch));
    }
}
