//! Per-owner test seams. No environment/global hook, client callback, synthetic
//! kernel event or replacement state participates in the production path.
use super::*;
use std::ops::Range;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum JournalFaultPoint {
    AfterRawEntry,
    AfterValidatedEntry,
    AfterRawNewborn,
    AfterValidatedExit,
    AfterParentBridge,
    AfterChildBridge,
    AfterTransport,
    BeforeRebind,
    AfterRebind,
}
pub(in crate::linux::remote::dynamic::owner) enum JournalFaultAction {
    AwaitRelease {
        ready: SyncSender<JournalFaultWitness>,
        release: Receiver<JournalFaultRelease>,
    },
}
#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) enum JournalFaultRelease {
    Error,
    Panic,
}
pub(in crate::linux::remote::dynamic::owner) struct JournalFault {
    pub(in crate::linux::remote::dynamic::owner) point: JournalFaultPoint,
    pub(in crate::linux::remote::dynamic::owner) memory: Vec<Range<u64>>,
    pub(in crate::linux::remote::dynamic::owner) action: JournalFaultAction,
}
/// These are independently reread native states, not a journal projection.
/// Running tasks are listed as owned but never given an invented held snapshot.
pub(in crate::linux::remote::dynamic::owner) struct JournalFaultWitness {
    pub(in crate::linux::remote::dynamic::owner) point: JournalFaultPoint,
    pub(in crate::linux::remote::dynamic::owner) until: Instant,
    pub(in crate::linux::remote::dynamic::owner) owned: Vec<(i32, OwnedFd)>,
    pub(in crate::linux::remote::dynamic::owner) held: Vec<JournalHeldWitness>,
}
pub(in crate::linux::remote::dynamic::owner) struct JournalHeldWitness {
    pub(in crate::linux::remote::dynamic::owner) tid: i32,
    pub(in crate::linux::remote::dynamic::owner) raw_status: i32,
    pub(in crate::linux::remote::dynamic::owner) state: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic::owner) memory: Vec<(Range<u64>, Vec<u8>)>,
}

impl Owner {
    pub(in crate::linux::remote::dynamic::owner) fn journal_fault_at(
        &mut self,
        point: JournalFaultPoint,
    ) -> Result<(), LaunchError> {
        if self
            .journal_fault
            .as_ref()
            .is_none_or(|fault| fault.point != point)
        {
            return Ok(());
        }
        let fault = self
            .journal_fault
            .take()
            .expect("matching per-owner journal fault");
        let result = self.run_journal_fault(fault);
        if let Err(error) = &result {
            self.kernel_journal.fail_active(failure_kind(error));
        }
        result
    }
    fn run_journal_fault(&mut self, fault: JournalFault) -> Result<(), LaunchError> {
        let until = {
            let mut archive = self.kernel_journal.lock();
            let handle = self
                .kernel_journal
                .active
                .ok_or(invalid("journal fault has no active invocation"))?;
            KernelJournalWriter::attempt_mut(&mut archive, handle)?
                .binding
                .until
        };
        let JournalFaultAction::AwaitRelease { ready, release } = fault.action;
        self.time_left(until, "kernel journal fault latch")?;
        let mut total = 0_usize;
        if fault.memory.len() > 8 || self.owned.len() > 2 {
            return Err(invalid("journal fault witness exceeds finite layout"));
        }
        for range in &fault.memory {
            let len = usize::try_from(
                range
                    .end
                    .checked_sub(range.start)
                    .ok_or(invalid("journal fault witness range reversed"))?,
            )
            .map_err(|_| invalid("journal fault witness range overflows"))?;
            total = total
                .checked_add(len)
                .ok_or(invalid("journal fault witness size overflows"))?;
        }
        if total > 64 * 1024 {
            return Err(invalid("journal fault witness memory exceeds bound"));
        }
        let mut owned = Vec::new();
        for &tid in &self.owned {
            let pin = self
                .handles
                .get(&tid)
                .ok_or(invalid("journal fault task lacks original pidfd"))?;
            // SAFETY: duplicate only a descriptor already retained by
            // the real owner. No numeric PID is reopened by a reader.
            let fd = unsafe { libc::fcntl(pin.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(system("journal fault duplicate pidfd"));
            }
            owned.push((tid, unsafe { OwnedFd::from_raw_fd(fd) }));
        }
        let mut held = Vec::new();
        for (&tid, &raw_status) in &self.stopped {
            if !self.owned.contains(&tid) || self.handles.get(&tid).is_none_or(broker::hup) {
                return Err(invalid("journal fault witness lacks held ownership"));
            }
            let mut memory = Vec::new();
            for range in &fault.memory {
                memory.push((
                    range.clone(),
                    read_memory(tid, range.start, (range.end - range.start) as usize)?,
                ));
            }
            held.push(JournalHeldWitness {
                tid,
                raw_status,
                state: TaskStateSnapshot::read(tid)?,
                memory,
            });
        }
        self.time_left(until, "kernel journal fault latch")?;
        ready
            .try_send(JournalFaultWitness {
                point: fault.point,
                until,
                owned,
                held,
            })
            .map_err(|_| invalid("journal fault witness receiver is unavailable"))?;
        loop {
            self.time_left(until, "kernel journal fault latch")?;
            let left = until.saturating_duration_since(Instant::now());
            match release.recv_timeout(left.min(Duration::from_millis(1))) {
                Ok(JournalFaultRelease::Error) => {
                    self.kernel_journal.fail_active(KernelFailureKind::Injected);
                    return Err(invalid("injected kernel journal failure"));
                }
                Ok(JournalFaultRelease::Panic) => {
                    std::panic::panic_any("injected kernel journal panic")
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(invalid("journal fault release disconnected"));
                }
            }
        }
    }
}
