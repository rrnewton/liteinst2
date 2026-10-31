//! Opt-in first-release and CALL/store/return enclosures on the Schedule clock.
//! These observations establish neither phase realization nor PMU accuracy.
use rapid_profiler::frontend_native::backoff::Policy;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub(in crate::normal) mod prepared;

type Result<T> = std::result::Result<T, &'static str>;
pub(in crate::normal) const COMMAND: &str = "normal-selected-accuracy-phase-session";
pub(in crate::normal) const WIRE: &str = "selected-accuracy-phase-session-v1";
pub(in crate::normal) const CALLS: usize = 2048;
pub(in crate::normal) const FUNCTION: u64 = 41;
const BODY: [u8; 37] = [
    0x31, 0xc0, 0x4c, 0x8d, 0x04, 0x37, 0x0f, 0xb6, 0x0f, 0x83, 0xf1, 0x5a, 0x48, 0x01, 0xc8, 0x48,
    0xff, 0xc7, 0x4c, 0x39, 0xc7, 0x72, 0xef, 0x48, 0xba, 0x15, 0x7c, 0x4a, 0x7f, 0xb9, 0x79, 0x37,
    0x9e, 0x48, 0x31, 0xd0, 0xc3,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) struct Request {
    policy: Policy,
    kind: &'static str,
    delay: u64,
    fence: u64,
}
impl Request {
    pub(in crate::normal) fn new(kind: &str, delay: u64, policy: Policy) -> Result<Self> {
        let kind = match kind {
            "locked" if delay == 0 => "locked",
            "random" if u128::from(delay) < policy.period().as_nanos() => "random",
            _ => return Err("closed phase request"),
        };
        if !policy.is_accuracy()
            || !(1..=520).contains(&policy.epoch_limit())
            || policy.call_limit() != 4096
            || policy.worker_backpressure()
            || policy.sink_backpressure()
        {
            return Err("phase requires unchanged accuracy policy");
        }
        let fence = ns(policy
            .period()
            .checked_mul(policy.epoch_limit())
            .and_then(|end| end.checked_add(policy.shutdown()))
            .ok_or("phase original safety fence overflow")?)?;
        Ok(Self {
            policy,
            kind,
            delay,
            fence,
        })
    }
    pub(in crate::normal) fn policy(self) -> Policy {
        self.policy
    }
    pub(in crate::normal) fn header(self) -> String {
        format!("PHASE,{},{}\n", self.kind, self.delay)
    }
    pub(in crate::normal) fn ready(self) -> String {
        format!(
            "READY,{WIRE},{},{},{},2,64,",
            self.policy.retained(),
            self.policy.epoch_limit(),
            self.policy.period().as_millis()
        )
    }
}
fn ns(value: Duration) -> Result<u64> {
    u64::try_from(value.as_nanos()).map_err(|_| "phase nanosecond overflow")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) struct Release {
    enter: u64,
    released: u64,
}
impl Release {
    pub(in crate::normal) fn line(self) -> String {
        format!("RELEASE,1,{FUNCTION},{},{}\n", self.enter, self.released)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) struct Timing {
    ordinal: u64,
    before: u64,
    after: u64,
}
impl Timing {
    pub(in crate::normal) fn line(self) -> String {
        format!(
            "CALLTIME,{},{},{FUNCTION},{},{}\n",
            self.ordinal, self.ordinal, self.before, self.after
        )
    }
}

/// Created before READY, shared only by this controller and its actual worker.
/// OnceLock publication does not imply the queued wire has been durably written.
#[derive(Debug)]
pub(in crate::normal) struct Shared {
    request: Request,
    origin: OnceLock<Instant>,
    first_arm: OnceLock<u64>,
    release: OnceLock<Release>,
    rows: Box<[OnceLock<Timing>]>,
}
impl Shared {
    pub(in crate::normal) fn new(request: Request) -> Arc<Self> {
        Arc::new(Self {
            request,
            origin: OnceLock::new(),
            first_arm: OnceLock::new(),
            release: OnceLock::new(),
            rows: (0..CALLS).map(|_| OnceLock::new()).collect(),
        })
    }
    pub(in crate::normal) fn request(&self) -> Request {
        self.request
    }
    pub(in crate::normal) fn start(&self, origin: Instant, policy: Policy) -> Result<()> {
        if policy != self.request.policy {
            return Err("phase Schedule policy mismatch");
        }
        origin
            .checked_add(Duration::from_nanos(self.request.fence))
            .ok_or("phase original safety fence unavailable")?;
        self.origin
            .set(origin)
            .map_err(|_| "phase origin already published")
    }
    pub(in crate::normal) fn first_arm(&self, completed: Duration) -> Result<()> {
        if self.origin.get().is_none() || completed > self.request.policy.lateness() {
            return Err("phase first arm not acknowledged on original clock");
        }
        self.first_arm
            .set(ns(completed)?)
            .map_err(|_| "phase first arm already retained")
    }
    pub(in crate::normal) fn release(&self) -> Result<Release> {
        self.release
            .get()
            .copied()
            .ok_or("phase release unavailable")
    }
    /// Join the actual complete call and its unmodified NORMAL/PMU ordinal.
    pub(in crate::normal) fn row(&self, ordinal: u64, id: u64, function: u64) -> Result<Timing> {
        if ordinal != id || function != FUNCTION || !(1..=CALLS as u64).contains(&ordinal) {
            return Err("phase call identity mismatch");
        }
        let row = self.rows[ordinal as usize - 1]
            .get()
            .copied()
            .ok_or("phase returned timing unavailable")?;
        if row.ordinal != ordinal {
            return Err("phase retained ordinal mismatch");
        }
        Ok(row)
    }
    pub(in crate::normal) fn complete(&self, emitted: usize) -> Result<()> {
        if emitted != CALLS
            || self.release.get().is_none()
            || self.rows.iter().any(|row| row.get().is_none())
        {
            return Err("phase requires every returned timing and one release");
        }
        Ok(())
    }
}

pub(in crate::normal) struct Worker {
    shared: Arc<Shared>,
    next: u64,
    last: u64,
    pending: Option<u64>,
    failed: bool,
}
impl Worker {
    pub(in crate::normal) fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            next: 1,
            last: 0,
            pending: None,
            failed: false,
        }
    }
    fn refuse<T>(&mut self, why: &'static str) -> Result<T> {
        self.failed = true;
        Err(why)
    }
    fn observe(&mut self, now: Instant) -> Result<u64> {
        if self.failed {
            return Err("phase clock already refused");
        }
        let value = self
            .shared
            .origin
            .get()
            .and_then(|start| now.checked_duration_since(*start))
            .ok_or("phase origin absent or clock regressed")
            .and_then(ns);
        let value = match value {
            Ok(value) => value,
            Err(why) => return self.refuse(why),
        };
        if value < self.last || value >= self.shared.request.fence {
            return self.refuse("phase clock regressed or original safety fence reached");
        }
        self.last = value;
        Ok(value)
    }
    pub(in crate::normal) fn before(&mut self, id: u64, function: usize) -> Result<()> {
        self.before_with(id, function, now)
    }
    fn before_with(
        &mut self,
        id: u64,
        function: usize,
        mut clock: impl FnMut() -> Instant,
    ) -> Result<()> {
        if self.failed
            || self.pending.is_some()
            || id != self.next
            || self.next > CALLS as u64
            || function != 0
        {
            return self.refuse("phase call sequence mismatch");
        }
        if self.next == 1 {
            let entered = self.observe(clock())?;
            let Some(&arm) = self.shared.first_arm.get() else {
                return self.refuse("phase first arm unavailable");
            };
            if entered < arm {
                return self.refuse("phase gate precedes first arm");
            }
            let mut released = entered;
            while released < self.shared.request.delay {
                std::hint::spin_loop();
                released = self.observe(clock())?;
            }
            // Retain the once-only actual release before entering native code.
            if self
                .shared
                .release
                .set(Release {
                    enter: entered,
                    released,
                })
                .is_err()
            {
                return self.refuse("phase release already retained");
            }
        }
        self.pending = Some(self.observe(clock())?);
        Ok(())
    }
    /// The caller MUST retain the actual returned Call before this fallible join.
    pub(in crate::normal) fn returned(&mut self, observed: Instant) -> Result<()> {
        let Some(before) = self.pending.take() else {
            return self.refuse("phase returned without an owned invocation");
        };
        let after = self.observe(observed)?;
        let row = Timing {
            ordinal: self.next,
            before,
            after,
        };
        if self.shared.rows[self.next as usize - 1].set(row).is_err() {
            return self.refuse("phase timing already retained");
        }
        self.next += 1;
        Ok(())
    }
}

/// Capture/restore the actual calling thread's errno around each Instant read.
/// In particular the first operation after csv::invoke captures post-call errno.
pub(in crate::normal) fn now() -> Instant {
    with_errno(Instant::now)
}
fn with_errno<T>(read: impl FnOnce() -> T) -> T {
    // SAFETY: Linux thread-local errno pointer is valid on this actual thread.
    let errno = unsafe { libc::__errno_location() };
    let saved = unsafe { *errno };
    let value = read();
    unsafe { *errno = saved };
    value
}

/// Additional closed body check over the loader's already authenticated pages.
/// This is not a replacement for complete ELF/caller/ABI/lifetime authority.
pub(in crate::normal) fn exact37(
    entry: u64,
    returns: &[u64],
    pages: &[(u64, Vec<u8>)],
) -> Result<()> {
    let end = entry
        .checked_add(BODY.len() as u64)
        .ok_or("Exact37 range overflow")?;
    if returns != [end - 1] {
        return Err("Exact37 complete RET roster mismatch");
    }
    let mut found = 0;
    for (base, bytes) in pages {
        if *base % 4096 != 0 || bytes.len() != 4096 {
            return Err("Exact37 complete source page shape");
        }
        let limit = base.checked_add(4096).ok_or("Exact37 page overflow")?;
        if *base <= entry && end <= limit {
            found += 1;
            if bytes[(entry - base) as usize..(end - base) as usize] != BODY {
                return Err("Exact37 complete body mismatch");
            }
        }
    }
    if found != 1 {
        return Err("Exact37 unique whole source page required");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup(kind: &str, delay: u64) -> (Instant, Arc<Shared>, Worker) {
        let policy = Policy::accuracy(10, 10, 520, 4096).unwrap();
        let shared = Shared::new(Request::new(kind, delay, policy).unwrap());
        let start = Instant::now();
        shared.start(start, policy).unwrap();
        shared.first_arm(Duration::from_nanos(10)).unwrap();
        let worker = Worker::new(Arc::clone(&shared));
        (start, shared, worker)
    }
    #[test]
    fn request_is_separate_and_never_changes_the_accuracy_policy() {
        for k in [1, 10, 100, 1000] {
            for ms in [1, 10, 100] {
                let policy = Policy::accuracy(k, ms, 520, 4096).unwrap();
                for (kind, delay) in [
                    ("locked", 0),
                    ("random", 0),
                    ("random", u64::from(ms) * 1_000_000 - 1),
                ] {
                    assert_eq!(Request::new(kind, delay, policy).unwrap().policy(), policy);
                }
                for (kind, delay) in [
                    ("locked", 1),
                    ("random", u64::from(ms) * 1_000_000),
                    ("other", 0),
                ] {
                    assert!(Request::new(kind, delay, policy).is_err());
                }
                assert!(Request::new("locked", 0, policy.with_worker_backpressure()).is_err());
                assert!(Request::new("locked", 0, policy.with_sink_backpressure()).is_err());
            }
        }
        assert!(Request::new("locked", 0, Policy::ten_ms(10, 520, 4096).unwrap()).is_err());
        assert!(Request::new("locked", 0, Policy::accuracy(10, 10, 520, 2048).unwrap()).is_err());
        assert!(ns(Duration::from_secs(u64::MAX)).is_err());
    }
    #[test]
    fn origin_first_arm_and_clock_failures_are_terminal() {
        let policy = Policy::accuracy(10, 10, 520, 4096).unwrap();
        let shared = Shared::new(Request::new("locked", 0, policy).unwrap());
        let start = Instant::now();
        let mut worker = Worker::new(Arc::clone(&shared));
        assert!(worker.before_with(1, 0, || start).is_err());
        shared.start(start, policy).unwrap();
        assert!(shared.start(start, policy).is_err());
        assert!(
            shared
                .start(start, Policy::accuracy(1, 10, 520, 4096).unwrap())
                .is_err()
        );
        assert!(
            shared
                .first_arm(policy.lateness() + Duration::from_nanos(1))
                .is_err()
        );
        shared.first_arm(policy.lateness()).unwrap();
        assert!(shared.first_arm(Duration::ZERO).is_err());
        assert!(
            worker
                .before_with(1, 0, || start + policy.lateness())
                .is_err()
        );
        for elapsed in [None, Some(shared.request.fence)] {
            let (_, _, mut worker) = setup("locked", 0);
            let origin = *worker.shared.origin.get().unwrap();
            let observed = elapsed.map_or(origin - Duration::from_nanos(1), |n| {
                origin + Duration::from_nanos(n)
            });
            assert!(worker.observe(observed).is_err());
            assert!(worker.observe(origin + Duration::from_nanos(20)).is_err());
        }
        let (start, _, mut worker) = setup("locked", 0);
        assert!(
            worker
                .before_with(1, 0, || start + Duration::from_nanos(9))
                .is_err()
        );
    }
    #[test]
    fn zero_and_random_gate_are_once_only_and_keep_whole_period_lateness() {
        for delay in [0, 500] {
            let (start, shared, mut worker) = setup("random", delay);
            let mut samples = [20, 499, 500, 501].into_iter();
            worker
                .before_with(1, 0, || {
                    start + Duration::from_nanos(samples.next().unwrap())
                })
                .unwrap();
            let release = shared.release().unwrap();
            assert_eq!(release.enter, 20);
            assert_eq!(release.released, if delay == 0 { 20 } else { 500 });
            worker.returned(start + Duration::from_nanos(600)).unwrap();
            worker
                .before_with(2, 0, || start + Duration::from_nanos(20_000_020))
                .unwrap();
            worker
                .returned(start + Duration::from_nanos(20_000_030))
                .unwrap();
            assert_eq!(shared.release().unwrap(), release);
            assert_eq!(shared.row(2, 2, FUNCTION).unwrap().before, 20_000_020);
        }
        let (start, shared, mut worker) = setup("locked", 0);
        worker
            .before_with(1, 0, || start + Duration::from_nanos(20_000_020))
            .unwrap();
        assert_eq!(shared.release().unwrap().released, 20_000_020);
        assert_eq!(shared.release().unwrap().released / 10_000_000, 2);
        assert_eq!(shared.release().unwrap().released % 10_000_000, 20);
        let mut duplicate = Worker::new(Arc::clone(&shared));
        assert!(
            duplicate
                .before_with(1, 0, || start + Duration::from_nanos(20_000_021))
                .is_err()
        );
        assert_eq!(shared.release().unwrap().released, 20_000_020);
    }
    #[test]
    fn return_clock_refusal_keeps_release_and_never_invents_timing() {
        let (start, shared, mut worker) = setup("locked", 0);
        worker
            .before_with(1, 0, || start + Duration::from_nanos(20))
            .unwrap();
        assert!(worker.returned(start + Duration::from_nanos(19)).is_err());
        assert!(shared.release().is_ok());
        assert!(shared.row(1, 1, FUNCTION).is_err());
        assert!(
            worker
                .before_with(1, 0, || start + Duration::from_nanos(30))
                .is_err()
        );
        assert!(shared.complete(0).is_err());
        let (_, shared, _) = setup("locked", 0);
        assert!(shared.release().is_err()); // EOF/no invocation emits no release.
        assert!(shared.complete(0).is_err());
    }
    #[test]
    fn all_2048_rows_join_exact_identity_without_duplicate_or_missing_credit() {
        let (start, shared, mut worker) = setup("locked", 0);
        for ordinal in 1..=CALLS as u64 {
            let t = start + Duration::from_nanos(ordinal * 100);
            worker.before_with(ordinal, 0, || t).unwrap();
            worker.returned(t + Duration::from_nanos(10)).unwrap();
            assert_eq!(
                shared.row(ordinal, ordinal, FUNCTION).unwrap().ordinal,
                ordinal
            );
        }
        shared.complete(CALLS).unwrap();
        assert!(shared.complete(CALLS - 1).is_err());
        for (ordinal, id, function) in [
            (0, 0, FUNCTION),
            (1, 2, FUNCTION),
            (1, 1, 42),
            (2049, 2049, FUNCTION),
        ] {
            assert!(shared.row(ordinal, id, function).is_err());
        }
        assert!(worker.before_with(2049, 0, || start).is_err());
        for (id, function) in [(2, 0), (1, 1)] {
            let (start, _, mut worker) = setup("locked", 0);
            assert!(worker.before_with(id, function, || start).is_err());
        }
        let (start, _, mut worker) = setup("locked", 0);
        worker
            .before_with(1, 0, || start + Duration::from_nanos(20))
            .unwrap();
        assert!(
            worker
                .before_with(1, 0, || start + Duration::from_nanos(21))
                .is_err()
        );
    }
    #[test]
    fn observations_preserve_actual_thread_errno() {
        let ptr = unsafe { libc::__errno_location() };
        let original = unsafe { *ptr };
        for sentinel in [0, libc::EINTR, libc::ERANGE] {
            unsafe { *ptr = sentinel };
            assert_eq!(
                with_errno(|| {
                    unsafe { *ptr = libc::EINVAL };
                    19
                }),
                19
            );
            assert_eq!(unsafe { *ptr }, sentinel);
            let _ = now();
            assert_eq!(unsafe { *ptr }, sentinel);
        }
        unsafe { *ptr = original };
    }
    #[test]
    fn phase_wire_fits_old_8mib_and_exact_geometry_rejects_every_changed_byte() {
        let request = Request::new(
            "random",
            99_999_999,
            Policy::accuracy(1000, 100, 520, 4096).unwrap(),
        )
        .unwrap();
        assert_eq!(request.header(), "PHASE,random,99999999\n");
        assert_eq!(
            request.ready(),
            "READY,selected-accuracy-phase-session-v1,1000,520,100,2,64,"
        );
        assert_eq!(
            Release {
                enter: 7,
                released: 9
            }
            .line(),
            "RELEASE,1,41,7,9\n"
        );
        assert_eq!(
            Timing {
                ordinal: 2048,
                before: 7,
                after: 9
            }
            .line(),
            "CALLTIME,2048,2048,41,7,9\n"
        );
        for line in [
            request.header(),
            Release {
                enter: u64::MAX,
                released: u64::MAX,
            }
            .line(),
            Timing {
                ordinal: 2048,
                before: u64::MAX,
                after: u64::MAX,
            }
            .line(),
        ] {
            assert!(line.is_ascii() && line.len() <= 350 && line.ends_with('\n'));
        }
        assert_eq!(6 * CALLS + 3 * 520 + 22, 13_870);
        const {
            assert!((6 * CALLS + 3 * 520 + 22) * 350 < 8 * 1024 * 1024);
        }
        let entry = 0x1020;
        let mut pages = vec![(0x1000, vec![0; 4096])];
        pages[0].1[32..69].copy_from_slice(&BODY);
        exact37(entry, &[entry + 36], &pages).unwrap();
        for at in 32..69 {
            pages[0].1[at] ^= 1;
            assert!(exact37(entry, &[entry + 36], &pages).is_err());
            pages[0].1[at] ^= 1;
        }
        assert!(exact37(entry, &[entry + 35], &pages).is_err());
        assert!(exact37(entry, &[entry + 36, entry + 36], &pages).is_err());
        assert!(exact37(entry, &[entry + 36], &[]).is_err());
        pages.push(pages[0].clone());
        assert!(exact37(entry, &[entry + 36], &pages).is_err());
        pages.pop();
        pages[0].1.pop();
        assert!(exact37(entry, &[entry + 36], &pages).is_err());
    }
}
