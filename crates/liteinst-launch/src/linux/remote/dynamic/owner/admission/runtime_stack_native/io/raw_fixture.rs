//! Actual raw-fixture custody, compiled only for native controls. This context
//! cannot become a current registry stop, stack operand or completion seal.
use super::*;
use crate::linux::remote::dynamic::owner::bootstrap::StateSlot;
use crate::linux::remote::dynamic::owner::{PinKind, broker};
use std::cell::{Cell, RefCell};
use std::os::fd::AsRawFd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum RawIoFault {
    MissingBasename,
    InvalidStatfs,
    NullRead,
    NullPread,
    InvalidCloseProbe,
    ExpireAfterPositiveRead,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum RawIoRecord {
    BasenameMissing,
    Statfs {
        fd: i32,
        request: Request,
    },
    Read {
        pread: bool,
        record: ReadRecord,
    },
    CloseProbe {
        fd: i32,
        request: Request,
    },
    Getregs {
        tid: i32,
        output: usize,
        request: Request,
    },
}

/// Borrows the actual Owner's original pidfds and consumed stopped waits.
/// The private fixed task set excludes running, terminal, unpinned, extra or
/// stale tasks. Only the raw fixture's actual wait domain can satisfy it.
pub(in crate::linux::remote::dynamic::owner::admission) struct RawStoppedIo<'a> {
    owner: &'a Owner,
    target: i32,
    held: [(i32, i32); 2],
    count: usize,
    until: Instant,
    fault: Option<RawIoFault>,
    fired: Cell<bool>,
    expire: Cell<bool>,
    records: RefCell<[Option<RawIoRecord>; 8]>,
    recorded: Cell<usize>,
}
impl<'a> RawStoppedIo<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn acquire(
        owner: &'a Owner,
        target: i32,
        waits: &[(i32, i32)],
        until: Instant,
        fault: Option<RawIoFault>,
    ) -> Result<Self, LaunchError> {
        if !(1..=2).contains(&waits.len())
            || !waits.iter().any(|(tid, _)| *tid == target)
            || (waits.len() == 2 && waits[0].0 == waits[1].0)
        {
            return Err(invalid("raw stack fixture task set differs"));
        }
        let mut held = [(0, 0); 2];
        held[..waits.len()].copy_from_slice(waits);
        let result = Self {
            owner,
            target,
            held,
            count: waits.len(),
            until,
            fault,
            fired: Cell::new(false),
            expire: Cell::new(false),
            records: RefCell::new([None; 8]),
            recorded: Cell::new(0),
        };
        result.require(until)?;
        Ok(result)
    }
    fn record(&self, record: RawIoRecord) {
        let index = self.recorded.get();
        assert!(index < 8, "raw stack argument receipt exceeds fixed bound");
        self.records.borrow_mut()[index] = Some(record);
        self.recorded.set(index + 1);
    }
    fn take(&self, fault: RawIoFault) -> bool {
        self.fault == Some(fault) && !self.fired.replace(true)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn records(
        &self,
    ) -> [Option<RawIoRecord>; 8] {
        *self.records.borrow()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_held(
        &self,
    ) -> Result<(), LaunchError> {
        self.require(self.until)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn capture_file(
        &self,
        name: &CStr,
        bytes: &mut [u8],
        capture: &mut FileCapture,
        eof: &mut u8,
    ) -> Result<(), LaunchError> {
        capture_file_with(self, self.until, name, bytes, capture, eof)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn capture_pagemap(
        &self,
        geometry: &OperandGeometry,
        word: &mut WordObservation,
        access: &mut PagemapAccess,
    ) -> Result<(), LaunchError> {
        capture_pagemap_with(self, self.until, geometry, word, access)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn capture_word(
        &self,
        geometry: &OperandGeometry,
        word: &mut WordObservation,
        access: &PagemapAccess,
    ) -> Result<(), LaunchError> {
        capture_word_with(self, self.until, geometry, word, access)
    }
    /// A separate actual failed raw request followed by the unchanged complete
    /// StateSlot reader. This does not claim a failed production state group.
    pub(in crate::linux::remote::dynamic::owner::admission) fn null_getregs_then_state(
        &self,
        state: &mut StateSlot,
    ) -> Result<Request, LaunchError> {
        self.require(self.until)?;
        let request =
            outcome(
                unsafe { libc::ptrace(libc::PTRACE_GETREGS, self.target, 0_usize, 0_usize) } as i64,
            );
        self.record(RawIoRecord::Getregs {
            tid: self.target,
            output: 0,
            request,
        });
        self.require(self.until)?;
        state.capture_tid(self.target)?;
        self.require(self.until)?;
        Ok(request)
    }
}
impl IoContext for RawStoppedIo<'_> {
    fn tid(&self) -> i32 {
        self.target
    }
    fn require(&self, until: Instant) -> Result<(), LaunchError> {
        if until != self.until {
            return Err(invalid("raw stack original deadline differs"));
        }
        if self.expire.get() {
            while Instant::now() < self.until {
                std::thread::sleep(
                    std::time::Duration::from_millis(1)
                        .min(self.until.saturating_duration_since(Instant::now())),
                );
            }
        }
        self.owner.time_left(until, "raw stack fixture held read")?;
        if self.owner.owned.len() != self.count || self.owner.lost_wait || self.owner.missing_pin {
            return Err(invalid("raw stack fixture physical task set differs"));
        }
        for &(tid, status) in &self.held[..self.count] {
            if tid <= 0
                || !self.owner.owned.contains(&tid)
                || self.owner.stopped.get(&tid) != Some(&status)
                || !libc::WIFSTOPPED(status)
                || self.owner.reaped.contains(&tid)
                || self.owner.tracer_terminal.contains_key(&tid)
                || self.owner.pin_kinds.get(&tid) != Some(&PinKind::Process)
            {
                return Err(invalid("raw stack fixture consumed wait differs"));
            }
            let pin = self
                .owner
                .handles
                .get(&tid)
                .ok_or_else(|| invalid("raw stack fixture original pin absent"))?;
            if broker::hup(pin) {
                return Err(invalid("raw stack fixture original pin is terminal"));
            }
            let mut event = libc::pollfd {
                fd: pin.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            let request = outcome(i64::from(unsafe { libc::poll(&raw mut event, 1, 0) }));
            checked(request, "raw stack fixture pidfd poll")?;
            if request.result != 0 || event.revents != 0 {
                return Err(invalid("raw stack fixture pin is not live"));
            }
        }
        self.owner
            .time_left(until, "raw stack fixture held read complete")?;
        Ok(())
    }
    fn basename<'a>(&self, name: &'a CStr) -> &'a CStr {
        if self.take(RawIoFault::MissingBasename) {
            self.record(RawIoRecord::BasenameMissing);
            c"liteinst-stack-missing-proc-entry"
        } else {
            name
        }
    }
    fn statfs_fd(&self, fd: i32) -> i32 {
        if self.take(RawIoFault::InvalidStatfs) {
            -1
        } else {
            fd
        }
    }
    fn observed_statfs(&self, fd: i32, request: Request) {
        if fd == -1 {
            self.record(RawIoRecord::Statfs { fd, request });
        }
    }
    fn output(&self, pread: bool, pointer: *mut u8, _count: usize) -> *mut u8 {
        let fault = if pread {
            RawIoFault::NullPread
        } else {
            RawIoFault::NullRead
        };
        if self.take(fault) {
            std::ptr::null_mut()
        } else {
            pointer
        }
    }
    fn observed_read(&self, pread: bool, record: ReadRecord) {
        // Retain the configured request only. Ordinary successful metadata can
        // require many positive reads; its complete first/last/count prefix is
        // already retained by FileCapture, not truncated to this fault array.
        if self.fired.get() && record.destination == 0 {
            self.record(RawIoRecord::Read { pread, record });
        }
        if !pread && record.request.result > 0 && self.take(RawIoFault::ExpireAfterPositiveRead) {
            self.record(RawIoRecord::Read { pread, record });
            self.expire.set(true);
        }
    }
    fn close_probe(&self) -> Result<(), LaunchError> {
        if self.take(RawIoFault::InvalidCloseProbe) {
            // This never closes/retries a live numeric descriptor. The actual
            // owned guards still close their own fds once. It qualifies only
            // raw EBADF evidence, not guarded-close-failure handling.
            let request = outcome(i64::from(unsafe { libc::close(-1) }));
            self.record(RawIoRecord::CloseProbe { fd: -1, request });
            checked(request, "raw stack invalid close probe")?;
        }
        Ok(())
    }
}
