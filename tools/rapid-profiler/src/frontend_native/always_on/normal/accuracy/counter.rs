//! Current-thread instructions:u evidence. This does not qualify PMU semantics.
use super::*;
use crate::counter_reading::CounterReading;
use perf_event_open_sys::{bindings as perf, ioctls, perf_event_open};
const ATTR_BYTES: usize = core::mem::size_of::<perf::perf_event_attr>();
const READ_BYTES: usize = 32;
const FLAGS: u64 = (1 << 0) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 20);
const READ_FORMAT: u64 = (perf::PERF_FORMAT_TOTAL_TIME_ENABLED
    | perf::PERF_FORMAT_TOTAL_TIME_RUNNING
    | perf::PERF_FORMAT_ID) as u64;
#[repr(C, align(8))]
pub(super) struct Request(pub(super) [u8; ATTR_BYTES]);
const _: () = {
    assert!(ATTR_BYTES == 128);
    assert!(core::mem::align_of::<perf::perf_event_attr>() == 8);
    assert!(core::mem::offset_of!(perf::perf_event_attr, type_) == 0);
    assert!(core::mem::offset_of!(perf::perf_event_attr, size) == 4);
    assert!(core::mem::offset_of!(perf::perf_event_attr, config) == 8);
    assert!(core::mem::offset_of!(perf::perf_event_attr, read_format) == 32);
    assert!(core::mem::offset_of!(perf::perf_event_attr, _bitfield_1) == 40);
};
fn request() -> Request {
    let mut a = Request([0; ATTR_BYTES]);
    a.0[..4].copy_from_slice(&perf::PERF_TYPE_HARDWARE.to_le_bytes());
    a.0[4..8].copy_from_slice(&(ATTR_BYTES as u32).to_le_bytes());
    a.0[8..16].copy_from_slice(&u64::from(perf::PERF_COUNT_HW_INSTRUCTIONS).to_le_bytes());
    a.0[32..40].copy_from_slice(&READ_FORMAT.to_le_bytes());
    a.0[40..48].copy_from_slice(&FLAGS.to_le_bytes());
    a
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCounterIdentity {
    pub pid: u32,
    pub tid: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCounterSyscall {
    pub result: i64,
    pub errno: Option<i32>,
}
impl NormalCounterSyscall {
    fn capture(result: i64) -> Self {
        Self {
            result,
            errno: (result < 0).then(|| unsafe { *libc::__errno_location() }),
        }
    }
    pub fn succeeded(self) -> bool {
        self.result >= 0 && self.errno.is_none()
    }
    fn zero(self) -> bool {
        self.result == 0 && self.errno.is_none()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalCounterOperation {
    Id,
    Enable,
    Read,
    Disable,
    Close,
}
/// The initialized buffer is retained even on an error. Only data_len bytes are
/// claimed returned: ID success = 8; reads retain the actual 0..32-byte prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCounterRead {
    pub operation: NormalCounterOperation,
    pub syscall: NormalCounterSyscall,
    pub data_len: usize,
    pub data: [u8; READ_BYTES],
}
impl NormalCounterRead {
    pub fn reading(self) -> Option<CounterReading> {
        if self.operation != NormalCounterOperation::Read
            || self.syscall.result != 32
            || self.syscall.errno.is_some()
            || self.data_len != 32
        {
            return None;
        }
        Some(CounterReading {
            value: self.word(0),
            time_enabled: self.word(1),
            time_running: self.word(2),
        })
    }
    pub fn event_id(self) -> Option<u64> {
        match self.operation {
            NormalCounterOperation::Id if self.syscall.zero() && self.data_len == 8 => {
                Some(self.word(0))
            }
            NormalCounterOperation::Read if self.reading().is_some() => Some(self.word(3)),
            _ => None,
        }
    }
    fn word(self, i: usize) -> u64 {
        u64::from_le_bytes(
            self.data[i * 8..i * 8 + 8]
                .try_into()
                .expect("fixed counter word"),
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCounterAcquisition {
    pub owner: NormalCounterIdentity,
    pub requested_attributes: [u8; ATTR_BYTES],
    pub attributes_after_open: [u8; ATTR_BYTES],
    pub open: NormalCounterSyscall,
    pub id: Option<NormalCounterRead>,
    pub enable: Option<NormalCounterRead>,
}
impl NormalCounterAcquisition {
    pub fn event_id(self) -> Option<u64> {
        self.id.and_then(NormalCounterRead::event_id)
    }
}
/// Read brackets are deliberately distinct from NormalRecord's earlier callback
/// stamps. AUX differences and reader overhead remain visible, without correction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCounterEndpoint {
    pub observer: NormalCounterIdentity,
    pub before: RawTimestamp,
    pub read: Option<NormalCounterRead>,
    pub after: RawTimestamp,
    /// None means no complete ID pair, never an inferred match.
    pub event_id_matches: Option<bool>,
    pub owner_matches: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCounterClose {
    pub acquisition: NormalCounterAcquisition,
    pub observer: NormalCounterIdentity,
    pub disable: Option<NormalCounterRead>,
    pub close: Option<NormalCounterRead>,
}
pub(super) trait System {
    fn identity(&mut self) -> NormalCounterIdentity;
    fn stamp(&mut self) -> RawTimestamp;
    fn open(&mut self, a: &mut Request) -> NormalCounterSyscall;
    fn operate(
        &mut self,
        fd: i32,
        op: NormalCounterOperation,
        data: &mut [u8; READ_BYTES],
    ) -> NormalCounterSyscall;
}
struct Linux;
impl System for Linux {
    fn identity(&mut self) -> NormalCounterIdentity {
        NormalCounterIdentity {
            pid: std::process::id(),
            tid: tid(),
        }
    }
    fn stamp(&mut self) -> RawTimestamp {
        // SAFETY: accuracy attachment admitted the strict AMD reference clock;
        // its unsafe lifetime contract preserves that actual-thread policy.
        unsafe { timing::read() }
    }
    fn open(&mut self, a: &mut Request) -> NormalCounterSyscall {
        // SAFETY: complete aligned initialized ABI; current thread, any CPU,
        // no group, non-inherited, pinned, disabled initially, close-on-exec.
        NormalCounterSyscall::capture(i64::from(unsafe {
            perf_event_open(
                a.0.as_mut_ptr().cast(),
                0,
                -1,
                -1,
                perf::PERF_FLAG_FD_CLOEXEC as libc::c_ulong,
            )
        }))
    }
    fn operate(
        &mut self,
        fd: i32,
        op: NormalCounterOperation,
        data: &mut [u8; READ_BYTES],
    ) -> NormalCounterSyscall {
        // Preserve application errno across callback reads, including failures.
        // SAFETY: this actual thread owns errno and Counter owns the live fd.
        let saved = unsafe { *libc::__errno_location() };
        let result = unsafe {
            match op {
                NormalCounterOperation::Id => {
                    let mut id = 0;
                    let r = ioctls::ID(fd, &mut id);
                    data[..8].copy_from_slice(&id.to_le_bytes());
                    i64::from(r)
                }
                NormalCounterOperation::Enable => i64::from(ioctls::ENABLE(fd, 0)),
                NormalCounterOperation::Disable => i64::from(ioctls::DISABLE(fd, 0)),
                NormalCounterOperation::Read => {
                    libc::syscall(libc::SYS_read, fd, data.as_mut_ptr(), data.len())
                }
                NormalCounterOperation::Close => i64::from(libc::close(fd)),
            }
        };
        let observed = NormalCounterSyscall::capture(result);
        // SAFETY: restore only this thread's original errno, after recording it.
        unsafe { *libc::__errno_location() = saved };
        observed
    }
}
pub(super) struct Counter {
    system: Box<dyn System>,
    fd: Option<i32>,
    acquisition: NormalCounterAcquisition,
}
impl Counter {
    pub(super) fn open() -> Self {
        Self::with_system(Box::new(Linux))
    }
    pub(super) fn with_system(mut system: Box<dyn System>) -> Self {
        let owner = system.identity();
        let mut a = request();
        let requested_attributes = a.0;
        let open = system.open(&mut a);
        let fd = if open.succeeded() {
            i32::try_from(open.result).ok()
        } else {
            None
        };
        let mut this = Self {
            system,
            fd,
            acquisition: NormalCounterAcquisition {
                owner,
                requested_attributes,
                attributes_after_open: a.0,
                open,
                id: None,
                enable: None,
            },
        };
        if this.fd.is_some() {
            this.acquisition.id = Some(this.operation(NormalCounterOperation::Id));
            // An ID/enable failure never suppresses later work or raw reads.
            this.acquisition.enable = Some(this.operation(NormalCounterOperation::Enable));
        }
        this
    }
    pub(super) fn acquisition(&self) -> NormalCounterAcquisition {
        self.acquisition
    }
    fn operation(&mut self, op: NormalCounterOperation) -> NormalCounterRead {
        // Remove custody before close: never retry EINTR on a possibly reused fd.
        let fd = if op == NormalCounterOperation::Close {
            self.fd.take().expect("owned counter")
        } else {
            self.fd.expect("owned counter")
        };
        let mut data = [0; READ_BYTES];
        let syscall = self.system.operate(fd, op, &mut data);
        let data_len = match op {
            NormalCounterOperation::Id if syscall.zero() => 8,
            NormalCounterOperation::Read if syscall.succeeded() => {
                (syscall.result as usize).min(READ_BYTES)
            }
            _ => 0,
        };
        NormalCounterRead {
            operation: op,
            syscall,
            data_len,
            data,
        }
    }
    pub(super) fn endpoint(&mut self) -> NormalCounterEndpoint {
        let observer = self.system.identity();
        let owner_matches = observer == self.acquisition.owner;
        let before = self.system.stamp();
        let read = if owner_matches && self.fd.is_some() {
            Some(self.operation(NormalCounterOperation::Read))
        } else {
            None
        };
        let after = self.system.stamp();
        let event_id_matches = self
            .acquisition
            .event_id()
            .zip(read.and_then(NormalCounterRead::event_id))
            .map(|(a, b)| a == b);
        NormalCounterEndpoint {
            observer,
            before,
            read,
            after,
            event_id_matches,
            owner_matches,
        }
    }
    pub(super) fn close(&mut self) -> NormalCounterClose {
        let observer = self.system.identity();
        let (disable, close) = if observer == self.acquisition.owner && self.fd.is_some() {
            (
                Some(self.operation(NormalCounterOperation::Disable)),
                Some(self.operation(NormalCounterOperation::Close)),
            )
        } else {
            (None, None)
        };
        NormalCounterClose {
            acquisition: self.acquisition,
            observer,
            disable,
            close,
        }
    }
}
impl Drop for Counter {
    fn drop(&mut self) {
        if self.fd.is_some() {
            let _ = self.close();
        }
    }
}
