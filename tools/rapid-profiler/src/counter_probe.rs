//! One fresh, disabled, pinned raw event around one whole Rust operation.
//!
//! This requests Linux's AMD Zen 5 event 0x64/umask 0x09. The Linux event table
//! maps family 26 broadly; the available AMD 58550 manual covers models 00h–0Fh,
//! not model 11h. Neither a successful read nor this module certifies exact-model
//! event semantics, errata, cache-model equality, body-only cost or accuracy.
//! The counting window includes dispatch and all work inside `invoke`, including
//! public API checks, callbacks and postflight. It is bounded by enable/disable
//! ioctls, not synchronized to any TSC endpoints. No scaling or reset occurs.

use crate::counter_reading::{Arithmetic, CounterDelta, CounterReading, CounterRecord};
use perf_event_open_sys::{bindings as perf, ioctls, perf_event_open};

pub const RAW_CONFIG: u64 = 0x0964;
const ATTR_BYTES: usize = core::mem::size_of::<perf::perf_event_attr>();
const READ_BYTES: usize = 32;
const FLAGS: u64 = (1 << 0) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 20);
const READ_FORMAT: u64 = (perf::PERF_FORMAT_TOTAL_TIME_ENABLED
    | perf::PERF_FORMAT_TOTAL_TIME_RUNNING
    | perf::PERF_FORMAT_ID) as u64;

/// Complete zero-filled request bytes, with only the named fields set. Encoding
/// the ABI avoids exposing uninitialized Rust padding as reproducible evidence.
#[repr(C, align(8))]
struct Request([u8; ATTR_BYTES]);
const _: () = {
    assert!(core::mem::align_of::<perf::perf_event_attr>() == 8);
    assert!(core::mem::offset_of!(perf::perf_event_attr, type_) == 0);
    assert!(core::mem::offset_of!(perf::perf_event_attr, size) == 4);
    assert!(core::mem::offset_of!(perf::perf_event_attr, config) == 8);
    assert!(core::mem::offset_of!(perf::perf_event_attr, read_format) == 32);
    assert!(core::mem::offset_of!(perf::perf_event_attr, _bitfield_1) == 40);
};
fn request() -> Request {
    let mut a = Request([0; ATTR_BYTES]);
    a.0[..4].copy_from_slice(&perf::PERF_TYPE_RAW.to_le_bytes());
    a.0[4..8].copy_from_slice(&(ATTR_BYTES as u32).to_le_bytes());
    a.0[8..16].copy_from_slice(&RAW_CONFIG.to_le_bytes());
    a.0[32..40].copy_from_slice(&READ_FORMAT.to_le_bytes());
    a.0[40..48].copy_from_slice(&FLAGS.to_le_bytes());
    a
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Open,
    Id,
    ReadDisabledStart,
    Enable,
    Disable,
    ReadDisabledEnd,
    Close,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Syscall {
    pub result: i64,
    /// Captured immediately on a negative result; never stale success errno.
    pub errno: Option<i32>,
}
impl Syscall {
    fn capture(result: i64) -> Self {
        Self {
            result,
            errno: (result < 0).then(|| unsafe { *libc::__errno_location() }),
        }
    }
    fn zero(self) -> bool {
        self.result == 0 && self.errno.is_none()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationResult {
    pub operation: Operation,
    pub syscall: Syscall,
    /// Actual returned prefix only: 8 for successful ID, 0..=32 for reads.
    /// Remaining bytes are initialized storage, not observed counter words.
    pub data_len: usize,
    pub data: [u8; READ_BYTES],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuIdentity {
    pub cpu: u32,
    pub pid: u32,
    pub tid: i64,
    pub vendor: [u8; 12],
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuFailure {
    Affinity(Syscall),
    NotSingleton,
    CurrentCpu(Syscall),
    Identity(Syscall),
    UnsupportedVendorOrFamily,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Issue {
    ExternalId,
    CpuBefore(CpuFailure),
    CpuAfter(CpuFailure),
    CpuChanged,
    Operation(Operation),
    ReadSize(Operation),
    EventId(Operation),
    NotFresh,
    Arithmetic,
}

/// Raw evidence survives every ordinary failure, including partial reads and
/// cleanup failures. `issues` retains the first and subsequent observed failures.
#[derive(Debug)]
pub struct ProbeReceipt {
    pub external_id: u64,
    pub requested_attributes: Vec<u8>,
    pub attributes_after_open: Vec<u8>,
    pub cpu_before: Option<CpuIdentity>,
    pub cpu_after: Option<CpuIdentity>,
    pub event_id: Option<u64>,
    pub operations: Vec<OperationResult>,
    pub counters: CounterRecord,
    pub issues: Vec<Issue>,
    /// Positive enabled == running, matching IDs, monotonic words and successful
    /// cleanup only. This is an observed read property, not accuracy certification.
    pub full_running_delta: Option<CounterDelta>,
}
/// `None` means no invocation occurred. `Some(Err(..))`, when T is a Result,
/// preserves a real invocation failure independently of the counter status.
#[derive(Debug)]
pub struct ProbeObservation<T> {
    pub invocation: Option<T>,
    pub receipt: ProbeReceipt,
}

trait System {
    fn cpu(&mut self) -> Result<CpuIdentity, CpuFailure>;
    fn open(&mut self, request: &mut Request) -> Syscall;
    fn operate(&mut self, fd: i32, op: Operation, bytes: &mut [u8; READ_BYTES]) -> Syscall;
}
struct Linux;
impl System for Linux {
    fn cpu(&mut self) -> Result<CpuIdentity, CpuFailure> {
        let mut affinity = [0_u8; core::mem::size_of::<libc::cpu_set_t>()];
        let result = Syscall::capture(i64::from(unsafe {
            libc::sched_getaffinity(0, affinity.len(), affinity.as_mut_ptr().cast())
        }));
        if !result.zero() {
            return Err(CpuFailure::Affinity(result));
        }
        if affinity.iter().map(|b| b.count_ones()).sum::<u32>() != 1 {
            return Err(CpuFailure::NotSingleton);
        }
        let cpu = Syscall::capture(i64::from(unsafe { libc::sched_getcpu() }));
        if cpu.result < 0 {
            return Err(CpuFailure::CurrentCpu(cpu));
        }
        let index = cpu.result as usize;
        if affinity
            .get(index / 8)
            .is_none_or(|b| b & (1 << (index % 8)) == 0)
        {
            return Err(CpuFailure::NotSingleton);
        }
        let tid = Syscall::capture(unsafe { libc::syscall(libc::SYS_gettid) });
        if tid.result <= 0 || tid.result > i64::from(i32::MAX) {
            return Err(CpuFailure::Identity(tid));
        }
        let zero = std::arch::x86_64::__cpuid(0);
        let mut vendor = [0; 12];
        vendor[..4].copy_from_slice(&zero.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&zero.edx.to_le_bytes());
        vendor[8..].copy_from_slice(&zero.ecx.to_le_bytes());
        let signature = std::arch::x86_64::__cpuid(1).eax;
        let base_family = (signature >> 8) & 15;
        let family = base_family
            + if base_family == 15 {
                (signature >> 20) & 255
            } else {
                0
            };
        let model = ((signature >> 4) & 15)
            | if matches!(base_family, 6 | 15) {
                (signature >> 12) & 240
            } else {
                0
            };
        if vendor != *b"AuthenticAMD" || family != 26 {
            return Err(CpuFailure::UnsupportedVendorOrFamily);
        }
        Ok(CpuIdentity {
            cpu: index as u32,
            pid: std::process::id(),
            tid: tid.result,
            vendor,
            family,
            model,
            stepping: signature & 15,
        })
    }
    fn open(&mut self, request: &mut Request) -> Syscall {
        // SAFETY: aligned complete native ABI, zeroed counting-only fields. This
        // requests one current-thread event, no group/inheritance, close-on-exec.
        Syscall::capture(i64::from(unsafe {
            perf_event_open(
                request.0.as_mut_ptr().cast(),
                0,
                -1,
                -1,
                perf::PERF_FLAG_FD_CLOEXEC as libc::c_ulong,
            )
        }))
    }
    fn operate(&mut self, fd: i32, op: Operation, bytes: &mut [u8; READ_BYTES]) -> Syscall {
        // SAFETY: the private Flight owns fd. All output buffers are initialized,
        // correctly sized, and live through the syscall. No operation is retried.
        let result = unsafe {
            match op {
                Operation::Id => {
                    let mut id = 0;
                    let result = Syscall::capture(i64::from(ioctls::ID(fd, &mut id)));
                    bytes[..8].copy_from_slice(&id.to_le_bytes());
                    return result;
                }
                Operation::Enable => i64::from(ioctls::ENABLE(fd, 0)),
                Operation::Disable => i64::from(ioctls::DISABLE(fd, 0)),
                Operation::ReadDisabledStart | Operation::ReadDisabledEnd => {
                    libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) as i64
                }
                Operation::Close => i64::from(libc::close(fd)),
                Operation::Open => unreachable!("open has a separate request"),
            }
        };
        Syscall::capture(result)
    }
}

// Owns the fd immediately after open. An unwind disables/closes once and emits
// no success record. Explicit close clears custody BEFORE close; EINTR cannot
// trigger a retry on a numeric fd that the kernel may already have reused.
struct Flight<'a, S: System> {
    system: &'a mut S,
    fd: Option<i32>,
    enabled: bool,
}
impl<S: System> Flight<'_, S> {
    fn operation(&mut self, op: Operation, receipt: &mut ProbeReceipt) -> OperationResult {
        let fd = if op == Operation::Close {
            self.fd.take().expect("one close")
        } else {
            self.fd.expect("live fd")
        };
        let mut data = [0; READ_BYTES];
        let syscall = self.system.operate(fd, op, &mut data);
        let data_len = match op {
            Operation::Id if syscall.zero() => 8,
            Operation::ReadDisabledStart | Operation::ReadDisabledEnd if syscall.result >= 0 => {
                usize::try_from(syscall.result)
                    .unwrap_or(usize::MAX)
                    .min(READ_BYTES)
            }
            _ => 0,
        };
        let result = OperationResult {
            operation: op,
            syscall,
            data_len,
            data,
        };
        receipt.operations.push(result);
        let success = match op {
            Operation::ReadDisabledStart | Operation::ReadDisabledEnd => {
                if syscall.result >= 0 && syscall.result != READ_BYTES as i64 {
                    receipt.issues.push(Issue::ReadSize(op));
                }
                syscall.result == READ_BYTES as i64 && syscall.errno.is_none()
            }
            _ => syscall.zero(),
        };
        if !success && !receipt.issues.contains(&Issue::ReadSize(op)) {
            receipt.issues.push(Issue::Operation(op));
        }
        result
    }
}
impl<S: System> Drop for Flight<'_, S> {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            if self.enabled {
                self.system
                    .operate(fd, Operation::Disable, &mut [0; READ_BYTES]);
            }
            self.system
                .operate(fd, Operation::Close, &mut [0; READ_BYTES]);
        }
    }
}
fn endpoint(row: OperationResult, receipt: &mut ProbeReceipt) -> Option<CounterReading> {
    if row.syscall.result != READ_BYTES as i64 || row.syscall.errno.is_some() {
        return None;
    }
    let words: [u64; 4] =
        std::array::from_fn(|n| u64::from_ne_bytes(row.data[n * 8..n * 8 + 8].try_into().unwrap()));
    if Some(words[3]) != receipt.event_id {
        receipt.issues.push(Issue::EventId(row.operation));
    }
    Some(CounterReading {
        value: words[0],
        time_enabled: words[1],
        time_running: words[2],
    })
}

/// Request exactly one raw event and call `invoke` at most once. The current
/// thread must already have singleton CPU affinity on AMD family 26. Affinity
/// is observed, never changed. A failed open/read/enable does not invoke work.
///
/// The caller supplies a nonzero population label and keeps the thread, affinity
/// and process stable through the operation. The operation's own memory/source,
/// signal/unwind and termination contracts still apply. Normal closure errors
/// remain in `invocation`; unwind cleanup emits no observation. This function
/// cannot make an arbitrary closure finite or prevent it changing system state.
pub fn probe_current_thread_once<T>(
    external_id: u64,
    invoke: impl FnOnce() -> T,
) -> ProbeObservation<T> {
    run(&mut Linux, external_id, invoke)
}
fn run<T, S: System>(
    system: &mut S,
    external_id: u64,
    invoke: impl FnOnce() -> T,
) -> ProbeObservation<T> {
    let mut attributes = request();
    let mut receipt = ProbeReceipt {
        external_id,
        requested_attributes: attributes.0.to_vec(),
        attributes_after_open: Vec::new(),
        cpu_before: None,
        cpu_after: None,
        event_id: None,
        operations: Vec::with_capacity(7),
        counters: CounterRecord::new(None, None),
        issues: Vec::with_capacity(12),
        full_running_delta: None,
    };
    if external_id == 0 {
        receipt.issues.push(Issue::ExternalId);
        return ProbeObservation {
            invocation: None,
            receipt,
        };
    }
    match system.cpu() {
        Ok(cpu) => receipt.cpu_before = Some(cpu),
        Err(e) => {
            receipt.issues.push(Issue::CpuBefore(e));
            return ProbeObservation {
                invocation: None,
                receipt,
            };
        }
    }
    let open = system.open(&mut attributes);
    // Establish cleanup custody before recording/copying any successful result.
    let mut flight = Flight {
        system,
        fd: (open.result >= 0).then_some(open.result as i32),
        enabled: false,
    };
    receipt.attributes_after_open = attributes.0.to_vec();
    receipt.operations.push(OperationResult {
        operation: Operation::Open,
        syscall: open,
        data_len: 0,
        data: [0; READ_BYTES],
    });
    if open.result < 0 {
        receipt.issues.push(Issue::Operation(Operation::Open));
        return ProbeObservation {
            invocation: None,
            receipt,
        };
    }
    let mut invocation = None;
    let mut start = None;
    let mut end = None;
    let id = flight.operation(Operation::Id, &mut receipt);
    if id.syscall.zero() {
        receipt.event_id = Some(u64::from_ne_bytes(id.data[..8].try_into().unwrap()));
        let row = flight.operation(Operation::ReadDisabledStart, &mut receipt);
        start = endpoint(row, &mut receipt);
        if start.is_some_and(|s| s.value != 0 || s.time_enabled != 0 || s.time_running != 0) {
            receipt.issues.push(Issue::NotFresh);
        }
        if receipt.issues.is_empty() {
            let enabled = flight.operation(Operation::Enable, &mut receipt);
            if enabled.syscall.zero() {
                flight.enabled = true;
                invocation = Some(invoke());
                flight.operation(Operation::Disable, &mut receipt);
                // A failed disable remains in issues; close below ends custody.
                // No second disable or close is attempted on the normal path.
                flight.enabled = false;
                let row = flight.operation(Operation::ReadDisabledEnd, &mut receipt);
                end = endpoint(row, &mut receipt);
                match flight.system.cpu() {
                    Ok(cpu) => {
                        receipt.cpu_after = Some(cpu);
                        if receipt.cpu_before != Some(cpu) {
                            receipt.issues.push(Issue::CpuChanged);
                        }
                    }
                    Err(e) => receipt.issues.push(Issue::CpuAfter(e)),
                }
            }
        }
    }
    flight.operation(Operation::Close, &mut receipt);
    receipt.counters = CounterRecord::new(start, end);
    if invocation.is_some() {
        match receipt.counters.arithmetic() {
            Arithmetic::FullRunning { delta, .. } if receipt.issues.is_empty() => {
                receipt.full_running_delta = Some(delta)
            }
            Arithmetic::FullRunning { .. } => {}
            _ => receipt.issues.push(Issue::Arithmetic),
        }
    }
    ProbeObservation {
        invocation,
        receipt,
    }
}

#[cfg(test)]
mod tests;
