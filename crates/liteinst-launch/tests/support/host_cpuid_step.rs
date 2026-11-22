//! Host calibration for tests that single-step a native CPUID.
//!
//! Some hosted virtual machines emulate CPUID without delivering the pending
//! single-step trap, so the next instruction also retires before the trace
//! stop (issues 112 and 115). A native CPUID completion cannot be verified
//! on such a host. Each test that single-steps a native CPUID calls
//! [`require_calibrated`] as its first line, whether it steps the CPUID
//! through a validated selected completion (the static and dynamic selected
//! gates), through the reference page gate, or directly. On a calibrated
//! host it returns and the test runs unchanged; on an uncalibrated host the
//! test FAILS by name. No environment variable or feature changes either
//! outcome, and a probe that cannot run is a hard failure, never
//! "uncalibrated".

use std::io;
use std::sync::{Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant};

/// Single-steps the probe makes, once per test binary.
pub const PROBE_STEPS: usize = 64;
/// Offset of a delivered trace stop: just past `cpuid` (0f a2).
pub const DELIVERED_OFFSET: u64 = 2;
const STOP_DEADLINE: Duration = Duration::from_secs(10);
// Pointer-width variadic ptrace arguments; a bare 0 would pass as i32.
const NULL: *mut libc::c_void = std::ptr::null_mut();

// cpuid; eight nops; int3. A delivered trap stops at +2; a lost one stops
// after the next nop, at +3. The int3 bounds a run that loses every trap.
std::arch::global_asm!(
    ".pushsection .text.liteinst_cpuid_step_probe,\"ax\",@progbits",
    ".globl liteinst_cpuid_step_probe",
    ".hidden liteinst_cpuid_step_probe",
    ".type liteinst_cpuid_step_probe,@function",
    "liteinst_cpuid_step_probe:",
    "cpuid",
    "nop",
    "nop",
    "nop",
    "nop",
    "nop",
    "nop",
    "nop",
    "nop",
    "int3",
    ".size liteinst_cpuid_step_probe, . - liteinst_cpuid_step_probe",
    ".popsection",
);

unsafe extern "C" {
    // Never called here: only its address is used, as a traced child's rip.
    fn liteinst_cpuid_step_probe();
}

/// One single-step over the probe's CPUID, as the tracer observed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepStop {
    /// A SIGTRAP stop with si_code TRAP_TRACE, at this byte offset from the
    /// probe's CPUID.
    Trace {
        /// rip at the stop, minus the probe's address.
        offset: u64,
    },
    /// Anything else: no stop, another signal or si_code, or a failed fork,
    /// ptrace or wait call. Never a statement about the host.
    Failed(String),
}

/// The probe's verdict on this host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeResult {
    /// Every trace stop came exactly after the CPUID.
    Calibrated {
        /// Single-steps made.
        steps: usize,
    },
    /// `lost` of `steps` trace stops came after a later instruction.
    Uncalibrated {
        /// Trace stops anywhere but the delivered offset.
        lost: usize,
        /// Single-steps made.
        steps: usize,
        /// Offset of the first such stop.
        first_observed_offset: u64,
    },
}

impl std::fmt::Display for ProbeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Calibrated { steps } => write!(f, "calibrated 0/{steps}"),
            Self::Uncalibrated {
                lost,
                steps,
                first_observed_offset,
            } => write!(
                f,
                "uncalibrated {lost}/{steps} (first stop at +{first_observed_offset}, \
                 expected +{DELIVERED_OFFSET})"
            ),
        }
    }
}

/// The pure verdict over a recorded stop sequence.
///
/// Only a trace stop at exactly [`DELIVERED_OFFSET`] counts as delivered.
/// A `Failed` entry, or an empty record, panics as "host probe failed".
pub fn classify(stops: &[StepStop]) -> ProbeResult {
    if stops.is_empty() {
        panic!("host probe failed: no single-step was recorded");
    }
    let mut lost = 0;
    let mut first_observed_offset = None;
    for stop in stops {
        match stop {
            StepStop::Failed(reason) => panic!("host probe failed: {reason}"),
            StepStop::Trace { offset } if *offset == DELIVERED_OFFSET => {}
            StepStop::Trace { offset } => {
                lost += 1;
                first_observed_offset.get_or_insert(*offset);
            }
        }
    }
    match first_observed_offset {
        None => ProbeResult::Calibrated { steps: stops.len() },
        Some(first_observed_offset) => ProbeResult::Uncalibrated {
            lost,
            steps: stops.len(),
            first_observed_offset,
        },
    }
}

/// A test binary's own fork lock, held only while the probe forks, so the
/// child inherits no concurrent fixture's writable executable descriptor.
pub trait ForkLock {
    /// Holds the lock in the mode the binary's own forks use.
    fn hold_for_fork(&self) -> Box<dyn Held + '_>;
}

/// Any lock guard; dropping it releases the lock.
pub trait Held {}
impl<T> Held for T {}

impl ForkLock for Mutex<()> {
    fn hold_for_fork(&self) -> Box<dyn Held + '_> {
        Box::new(self.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

// Launches share the lock and fixture writers hold it exclusively, so a
// fork holds it shared, as the binary's own launches do.
impl ForkLock for RwLock<()> {
    fn hold_for_fork(&self) -> Box<dyn Held + '_> {
        Box::new(self.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// This binary's probe verdict. The probe runs at most once per binary; a
/// probe that panics caches nothing, so every later gated test fails too.
pub fn host_result(fork: &impl ForkLock) -> ProbeResult {
    static RESULT: OnceLock<ProbeResult> = OnceLock::new();
    *RESULT.get_or_init(|| classify(&record_steps(fork, 0, PROBE_STEPS)))
}

/// The first line of every test that single-steps a native CPUID. `fork` is
/// the binary's own fork lock; `name` is `<binary>::<test path>`.
pub fn require_calibrated(fork: &impl ForkLock, name: &str) {
    require_calibrated_with(host_result(fork), name);
}

/// The gate's decision for one probe result: return, or FAIL by name.
pub fn require_calibrated_with(result: ProbeResult, name: &str) {
    if let ProbeResult::Uncalibrated {
        lost,
        steps,
        first_observed_offset,
    } = result
    {
        panic!(
            "UNCALIBRATED HOST: {name}: single-step trap lost after CPUID in \
             {lost}/{steps} probe steps (first stop at +{first_observed_offset}, \
             expected +{DELIVERED_OFFSET}); native CPUID completion cannot be \
             verified on this host (issues 112, 115). Not a liteinst result."
        );
    }
}

/// The probe's child. It is signalled only while still unreaped: once a wait
/// has consumed its exit, or reports it is no longer this process's child,
/// its pid may already belong to another process.
struct Traced {
    pid: libc::pid_t,
    reaped: bool,
}

impl Drop for Traced {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: this probe's own child, not yet reaped, so the pid is ours.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(self.pid, &raw mut status, libc::__WALL) };
            if waited == self.pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                self.reaped = true;
                return;
            }
            if waited < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                self.reaped = true;
                return;
            }
        }
    }
}

/// Single-steps a fresh traced child `steps` times, each from the probe's
/// address plus `start_offset`, and records every stop as an offset from
/// the probe's address. It never panics: a failure is recorded as
/// [`StepStop::Failed`] and ends the record. The child is killed and reaped
/// on every path, and never signalled once reaped.
pub fn record_steps(fork: &impl ForkLock, start_offset: u64, steps: usize) -> Vec<StepStop> {
    // The binary's fork lock keeps writable executable descriptors of
    // concurrent fixtures out of the child, as for every other fork here.
    let guard = fork.hold_for_fork();
    // SAFETY: the child calls only async-signal-safe functions and never
    // returns into Rust code.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, NULL, NULL) == 0 {
                libc::raise(libc::SIGSTOP);
            }
            libc::_exit(127);
        }
    }
    drop(guard);
    if pid < 0 {
        return vec![StepStop::Failed(format!(
            "fork: {}",
            io::Error::last_os_error()
        ))];
    }
    let mut child = Traced { pid, reaped: false };
    let mut stops = Vec::with_capacity(steps);
    match wait_stop(&mut child) {
        Ok(libc::SIGSTOP) => {}
        Ok(signal) => stops.push(StepStop::Failed(format!(
            "initial stop by signal {signal}, not SIGSTOP"
        ))),
        Err(reason) => stops.push(StepStop::Failed(reason)),
    }
    if stops.is_empty() {
        let base = liteinst_cpuid_step_probe as *const () as u64;
        match get_registers(pid) {
            Ok(initial) => {
                for _ in 0..steps {
                    let stop = step_once(&mut child, &initial, base, start_offset)
                        .map_or_else(StepStop::Failed, |offset| StepStop::Trace { offset });
                    let failed = matches!(stop, StepStop::Failed(_));
                    stops.push(stop);
                    if failed {
                        break;
                    }
                }
            }
            Err(reason) => stops.push(StepStop::Failed(reason)),
        }
    }
    drop(child);
    stops
}

fn step_once(
    child: &mut Traced,
    initial: &libc::user_regs_struct,
    base: u64,
    start_offset: u64,
) -> Result<u64, String> {
    let pid = child.pid;
    let mut registers = *initial;
    registers.rip = base + start_offset;
    registers.rax = 0;
    registers.rcx = 0;
    // No syscall-restart adjustment may move the new rip.
    registers.orig_rax = u64::MAX;
    // SAFETY: ptrace requests on this probe's own stopped tracee.
    if unsafe { libc::ptrace(libc::PTRACE_SETREGS, pid, NULL, &raw const registers) } != 0 {
        return Err(format!("PTRACE_SETREGS: {}", io::Error::last_os_error()));
    }
    if unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, pid, NULL, NULL) } != 0 {
        return Err(format!("PTRACE_SINGLESTEP: {}", io::Error::last_os_error()));
    }
    let signal = wait_stop(child)?;
    if signal != libc::SIGTRAP {
        return Err(format!(
            "single-step stopped by signal {signal}, not SIGTRAP"
        ));
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, pid, NULL, &raw mut info) } != 0 {
        return Err(format!("PTRACE_GETSIGINFO: {}", io::Error::last_os_error()));
    }
    if info.si_code != libc::TRAP_TRACE {
        return Err(format!("SIGTRAP si_code {}, not TRAP_TRACE", info.si_code));
    }
    Ok(get_registers(pid)?.rip.wrapping_sub(base))
}

fn get_registers(pid: libc::pid_t) -> Result<libc::user_regs_struct, String> {
    let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: ptrace request on this probe's own stopped tracee.
    if unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, NULL, &raw mut registers) } != 0 {
        return Err(format!("PTRACE_GETREGS: {}", io::Error::last_os_error()));
    }
    Ok(registers)
}

/// The stopping signal of the child's next stop, within a bounded wait. A
/// wait that consumes the child's exit, or finds it is no longer this
/// process's child, marks it reaped so it is never signalled.
fn wait_stop(child: &mut Traced) -> Result<i32, String> {
    let pid = child.pid;
    let until = Instant::now() + STOP_DEADLINE;
    loop {
        let mut status = 0;
        // SAFETY: nonblocking wait for this probe's own child only.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG | libc::__WALL) };
        if waited == pid {
            if libc::WIFSTOPPED(status) {
                return Ok(libc::WSTOPSIG(status));
            }
            child.reaped = true;
            return Err(format!(
                "child left without a stop: wait status {status:#x}"
            ));
        }
        if waited < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                child.reaped = true;
            }
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(format!("waitpid: {error}"));
            }
        }
        if Instant::now() >= until {
            return Err(format!("no stop within {STOP_DEADLINE:?}"));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
