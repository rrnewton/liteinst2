//! Host calibration for tests that single-step a native CPUID.
//!
//! Some hosted virtual machines emulate CPUID without delivering the pending
//! single-step trap, so the next instruction also retires before the trace
//! stop (issues 112 and 115). A native CPUID completion cannot be verified
//! on such a host. Every test that single-steps a native CPUID calls
//! [`require_calibrated`] as its first line. On a calibrated host it returns
//! and the test runs unchanged; on an uncalibrated host the test FAILS by
//! name. No environment variable or feature changes either outcome, and a
//! probe that cannot run is a hard failure, never "uncalibrated".

use std::io;
use std::sync::{Mutex, OnceLock, PoisonError};
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

/// This binary's probe verdict. The probe runs at most once per binary; a
/// probe that panics caches nothing, so every later gated test fails too.
pub fn host_result(fork: &Mutex<()>) -> ProbeResult {
    static RESULT: OnceLock<ProbeResult> = OnceLock::new();
    *RESULT.get_or_init(|| classify(&run_probe(fork)))
}

/// The first line of every test that single-steps a native CPUID. `fork` is
/// the binary's own fork lock; `name` is `<binary>::<test path>`.
pub fn require_calibrated(fork: &Mutex<()>, name: &str) {
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

/// Kills and reaps the probe child on every path.
struct Traced(libc::pid_t);

impl Drop for Traced {
    fn drop(&mut self) {
        // SAFETY: plain syscalls on this probe's own unreaped child.
        unsafe { libc::kill(self.0, libc::SIGKILL) };
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(self.0, &raw mut status, libc::__WALL) };
            if waited == self.0 && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                return;
            }
            if waited < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
        }
    }
}

fn run_probe(fork: &Mutex<()>) -> Vec<StepStop> {
    // The binary's fork lock keeps writable executable descriptors of
    // concurrent fixtures out of the child, as for every other fork here.
    let guard = fork.lock().unwrap_or_else(PoisonError::into_inner);
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
    let child = Traced(pid);
    let mut stops = Vec::with_capacity(PROBE_STEPS);
    match wait_stop(pid) {
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
                for _ in 0..PROBE_STEPS {
                    let stop = step_once(pid, &initial, base)
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

fn step_once(pid: libc::pid_t, initial: &libc::user_regs_struct, base: u64) -> Result<u64, String> {
    let mut registers = *initial;
    registers.rip = base;
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
    let signal = wait_stop(pid)?;
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

/// The stopping signal of the child's next stop, within a bounded wait.
fn wait_stop(pid: libc::pid_t) -> Result<i32, String> {
    let until = Instant::now() + STOP_DEADLINE;
    loop {
        let mut status = 0;
        // SAFETY: nonblocking wait for this probe's own child only.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG | libc::__WALL) };
        if waited == pid {
            if libc::WIFSTOPPED(status) {
                return Ok(libc::WSTOPSIG(status));
            }
            return Err(format!(
                "child left without a stop: wait status {status:#x}"
            ));
        }
        if waited < 0 {
            let error = io::Error::last_os_error();
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
