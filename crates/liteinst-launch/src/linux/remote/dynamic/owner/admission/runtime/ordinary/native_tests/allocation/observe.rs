//! Independent read-only native diagnostics, bracketed by the original deadline/pin.
use super::*;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Held {
    pid: i32,
    pin: i32,
    status: i32,
    closing: bool,
    cancelled: bool,
}
fn held(owner: &Owner, until: Instant) -> Held {
    assert!(
        Instant::now() < until,
        "ordinary diagnostic original deadline"
    );
    assert!(owner.pid > 0 && owner.attached);
    assert!(!owner.lost_wait && !owner.missing_pin);
    assert!(owner.owned.contains(&owner.pid));
    assert!(!owner.reaped.contains(&owner.pid));
    assert!(!owner.tracer_terminal.contains_key(&owner.pid));
    let status = *owner.stopped.get(&owner.pid).unwrap();
    assert!(libc::WIFSTOPPED(status));
    assert_ne!(status >> 16, libc::PTRACE_EVENT_EXIT);
    let pin = owner.handles.get(&owner.pid).unwrap();
    let mut event = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    // SAFETY: initialized record and the actual Owner's original live pidfd.
    assert_eq!(unsafe { libc::poll(&raw mut event, 1, 0) }, 0);
    assert_eq!(event.revents, 0);
    assert!(
        Instant::now() < until,
        "ordinary diagnostic original deadline"
    );
    Held {
        pid: owner.pid,
        pin: pin.as_raw_fd(),
        status,
        closing: owner.closing,
        cancelled: owner.cancel.load(Ordering::Acquire),
    }
}
#[derive(Debug)]
struct ReadRecord {
    offset: u64,
    requested: usize,
    result: Result<usize, Option<i32>>,
}
#[derive(Default)]
struct ReadEvidence {
    bytes: Vec<u8>,
    copied: usize,
    opened: Option<Result<(), Option<i32>>>,
    reads: Vec<ReadRecord>,
    complete: bool,
}
impl ReadEvidence {
    fn with_size(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            ..Self::default()
        }
    }
    fn read_memory(&mut self, file: &File, address: u64) {
        assert!(!self.complete && self.reads.is_empty());
        let result = file
            .read_at(&mut self.bytes, address)
            .map_err(|e| e.raw_os_error());
        if let Ok(copied) = result {
            self.copied = copied;
        }
        self.reads.push(ReadRecord {
            offset: address,
            requested: self.bytes.len(),
            result,
        });
        assert_eq!(result, Ok(self.bytes.len()));
        self.complete = true;
    }
    fn read_maps(&mut self, pid: i32, owner: &Owner, until: Instant) {
        assert!(!self.complete && self.reads.is_empty() && self.opened.is_none());
        let file = File::open(format!("/proc/{pid}/maps"));
        self.opened = Some(file.as_ref().map(|_| ()).map_err(|e| e.raw_os_error()));
        let mut file = file.unwrap();
        loop {
            let before = held(owner, until);
            assert!(self.copied < self.bytes.len());
            let requested = self.bytes.len() - self.copied;
            let offset = self.copied as u64;
            let result = file
                .read(&mut self.bytes[self.copied..])
                .map_err(|e| e.raw_os_error());
            if let Ok(copied) = result {
                self.copied += copied;
            }
            self.reads.push(ReadRecord {
                offset,
                requested,
                result,
            });
            assert_eq!(held(owner, until), before);
            let copied = result.unwrap();
            assert!(self.copied <= 64 * 1024);
            if copied == 0 {
                break;
            }
        }
        assert!(self.copied > 0 && self.bytes[self.copied - 1] == b'\n');
        self.complete = true;
    }
    fn require_complete(&self, maps: bool) {
        assert!(self.complete);
        if maps {
            assert_eq!(self.opened, Some(Ok(())));
        } else {
            assert_eq!(self.opened, None);
        }
        assert!(!self.reads.is_empty());
        let mut copied = 0;
        for (i, r) in self.reads.iter().enumerate() {
            let n = r.result.unwrap();
            assert!(n <= r.requested);
            if maps {
                assert_eq!(r.offset, copied as u64);
                assert_eq!(r.requested, self.bytes.len() - copied);
            }
            if n == 0 {
                assert!(maps && i + 1 == self.reads.len());
            }
            copied += n;
        }
        assert_eq!(copied, self.copied);
        if maps {
            assert_eq!(self.reads.last().unwrap().result, Ok(0));
        } else {
            assert_eq!(self.reads.len(), 1);
            assert_eq!(copied, self.bytes.len());
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.copied]
    }
}

pub(super) struct Diagnostic {
    state: StateSlot,
    maps: ReadEvidence,
    source: ReadEvidence,
    stack: ReadEvidence,
    before: Option<Held>,
    after: Option<Held>,
    complete: bool,
}
impl Diagnostic {
    pub(super) fn allocate(original: &support::Before) -> Self {
        let (_, _, stack) = original.diagnostic_stack();
        Self {
            state: StateSlot::allocate().unwrap(),
            maps: ReadEvidence::with_size(64 * 1024 + 1),
            source: ReadEvidence::with_size(8192),
            stack: ReadEvidence::with_size(stack.len()),
            before: None,
            after: None,
            complete: false,
        }
    }
    pub(super) fn capture(&mut self, owner: &Owner, until: Instant, original: &support::Before) {
        assert!(!self.complete && self.before.is_none());
        self.before = Some(held(owner, until));
        let stamp = held(owner, until);
        let result = self.state.capture_tid(owner.pid);
        assert_eq!(held(owner, until), stamp);
        result.unwrap();
        let stamp = held(owner, until);
        self.maps.read_maps(owner.pid, owner, until);
        assert_eq!(held(owner, until), stamp);
        let (memory, stack_start, _) = original.diagnostic_stack();
        let stamp = held(owner, until);
        self.source.read_memory(memory, BASE);
        assert_eq!(held(owner, until), stamp);
        let stamp = held(owner, until);
        self.stack.read_memory(memory, stack_start);
        assert_eq!(held(owner, until), stamp);
        self.after = Some(held(owner, until));
        assert_eq!(self.before, self.after);
        self.complete = true;
    }
    pub(super) fn require_complete(&self) {
        assert!(self.complete && self.state.complete);
        assert!(self.before.is_some());
        assert_eq!(self.before, self.after);
        assert_eq!(
            [
                self.state.registers_request,
                self.state.xstate_request,
                self.state.mask_request
            ],
            [Some(NativeRequest {
                result: 0,
                errno: None
            }); 3]
        );
        assert_eq!(
            self.state.requested_pointer,
            self.state.state.xstate.as_ptr() as usize
        );
        assert_eq!(self.state.returned_pointer, self.state.requested_pointer);
        assert_eq!(self.state.returned_length, self.state.state.xstate.len());
        assert_eq!(self.state.state.xstate.capacity(), MAX_XSTATE);
        assert!((512..MAX_XSTATE).contains(&self.state.returned_length));
        self.maps.require_complete(true);
        self.source.require_complete(false);
        self.stack.require_complete(false);
    }
    pub(super) fn require_baseline(
        &self,
        owner: &Owner,
        original: &support::Before,
        expected: &TaskStateSnapshot,
    ) {
        self.require_complete();
        assert_eq!(self.state.state, *expected);
        assert_eq!(self.source.bytes(), original.source);
        let (_, stack_start, stack) = original.diagnostic_stack();
        assert_eq!(self.stack.bytes(), stack);
        assert_eq!(self.source.reads[0].offset, BASE);
        assert_eq!(self.stack.reads[0].offset, stack_start);
        let runtime = owner.runtime.as_ref().unwrap();
        assert_eq!(
            self.maps.bytes(),
            runtime.sources.runtime_baseline_maps().unwrap()
        );
        let origin = runtime.initial_origin.unwrap();
        let current = runtime
            .census
            .as_ref()
            .unwrap()
            .current_observation(origin)
            .unwrap();
        assert_eq!(current.registers, self.state.state.registers);
        assert_eq!(current.xstate, self.state.state.xstate);
        assert_eq!(current.signal_mask, self.state.state.mask);
        assert_eq!(
            runtime
                .native
                .as_ref()
                .unwrap()
                .admission_current(current.task.task)
                .unwrap()
                .token,
            current.token
        );
    }
    pub(super) fn require_unchanged(&self, before: &Self) {
        self.require_complete();
        before.require_complete();
        assert_eq!(self.state.state, before.state.state);
        assert_eq!(self.maps.bytes(), before.maps.bytes());
        assert_eq!(self.source.bytes(), before.source.bytes());
        assert_eq!(self.stack.bytes(), before.stack.bytes());
        assert_eq!(self.source.reads[0].offset, before.source.reads[0].offset);
        assert_eq!(self.stack.reads[0].offset, before.stack.reads[0].offset);
        let a = self.before.unwrap();
        let b = before.before.unwrap();
        assert_eq!((a.pid, a.pin, a.status), (b.pid, b.pin, b.status));
    }
}

pub(super) fn invoke(owner: &mut Owner, until: Instant) -> Result<AdmissionReply, GateError> {
    match owner
        .execute(
            DynamicRequest::Admission(Box::new(AdmissionRequest::Advance)),
            until,
        )
        .map_err(GateError::Control)?
    {
        Response::Admission(value) => *value,
        _ => panic!("ordinary allocation response namespace differs"),
    }
}
pub(super) fn invoke_unwind(
    owner: &mut Owner,
    original: &support::Before,
    until: Instant,
    secondary: &mut Option<PanicPayload>,
) -> ! {
    held(owner, until);
    assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
    assert_eq!(original.initial.tid, owner.pid);
    let (commands, receiver) = std::sync::mpsc::channel();
    let (_done_sender, done) = std::sync::mpsc::channel();
    let mut session = crate::linux::remote::dynamic::DynamicSession {
        pid: owner.pid,
        initial: original.initial.clone(),
        commands,
        cancel: Arc::clone(&owner.cancel),
        done,
        operation_timeout: Duration::from_secs(3),
    };
    let (outcome, client) = std::thread::scope(|scope| {
        let client = scope.spawn(move || {
            let reply =
                session.admission_call_for_journal_test(AdmissionRequest::Advance, until, until);
            let cancelled_before_drop = session.cancel.load(Ordering::Acquire);
            (reply, cancelled_before_drop)
        });
        let outcome = catch_unwind(AssertUnwindSafe(|| owner.serve(receiver)));
        (outcome, client.join())
    });
    // Validation cannot replace the original serve panic. Keep its exact Box
    // while recording a distinct transport diagnostic for after cleanup.
    let checked = catch_unwind(AssertUnwindSafe(|| {
        let (reply, cancelled_before_drop) = match client {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        };
        assert!(matches!(
            reply,
            Err(GateError::Control(LaunchError::Invalid(
                "dynamic tracer is closed"
            )))
        ));
        assert!(cancelled_before_drop && owner.cancel.load(Ordering::Acquire));
        assert!(!owner.closing);
    }));
    *secondary = checked.err();
    match outcome {
        Err(payload) => resume_unwind(payload),
        Ok(_) => panic!("expected actual ordinary owner serve unwind"),
    }
}
