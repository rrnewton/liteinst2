//! Native join and procfs task retirement are separate observations.
//!
//! After native join, require census omission and a direct NotFound before
//! releasing held results. This is a procfs observation, not unconditional
//! proof of kernel task unlink: procfs can also return ENOENT when allocating
//! an inode fails. Callers retain their original final singleton checks.
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::Instant;

#[derive(Debug)]
pub(super) enum Error {
    Identity,
    Census,
    UnexpectedTask(u32),
    Deadline,
    Clock(String),
    Read(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity => write!(f, "joined task identity"),
            Self::Census => write!(f, "incomplete or malformed task census"),
            Self::UnexpectedTask(tid) => write!(f, "unexpected task {tid}"),
            Self::Deadline => write!(f, "joined task retirement deadline"),
            Self::Clock(error) => write!(f, "{error}"),
            Self::Read(error) => write!(f, "task census: {error}"),
        }
    }
}

#[derive(Debug)]
pub(super) struct Failure {
    cause: Error,
    joined: Vec<u32>,
    observed: Option<Vec<u32>>,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; captured_tids={:?} last_complete_tasks={:?}",
            self.cause, self.joined, self.observed
        )
    }
}

pub(super) struct Handle<T> {
    handle: thread::JoinHandle<T>,
    pid: u32,
    tid: Arc<AtomicU32>,
}

pub(super) fn spawn<F, T>(body: F) -> Handle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let pid = std::process::id();
    let tid = Arc::new(AtomicU32::new(0));
    let captured = Arc::clone(&tid);
    let handle = thread::spawn(move || {
        let actual = unsafe { libc::syscall(libc::SYS_gettid) };
        assert!((1..=i64::from(i32::MAX)).contains(&actual));
        assert_ne!(actual, i64::from(pid));
        captured.store(actual as u32, Ordering::Release);
        body()
    });
    Handle { handle, pid, tid }
}

impl<T> Handle<T> {
    pub(super) fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    pub(super) fn join(self) -> Joined<T> {
        // Capture is independent of T: a panicking closure still has a TID.
        let result = self.handle.join();
        Joined {
            result,
            pid: self.pid,
            tid: self.tid.load(Ordering::Acquire),
            retired: false,
            observed: None,
        }
    }
}

pub(super) struct Joined<T> {
    result: thread::Result<T>,
    pid: u32,
    tid: u32,
    retired: bool,
    observed: Option<Vec<u32>>,
}

struct Census {
    pid: u32,
    tids: BTreeSet<u32>,
    absent: BTreeSet<u32>,
}

fn lookup_absent(result: std::io::Result<bool>) -> Result<bool, Error> {
    match result {
        Ok(true) => Ok(false), // The exact task directory still exists.
        Ok(false) => Err(Error::Census),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(Error::Read(error)),
    }
}

impl Census {
    fn parse(pid: u32, entries: impl IntoIterator<Item = OsString>) -> Result<Self, Error> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(Error::Identity);
        }
        let mut tids = BTreeSet::new();
        for entry in entries {
            let bytes = entry.as_bytes();
            let tid: u32 = std::str::from_utf8(bytes)
                .map_err(|_| Error::Census)?
                .parse()
                .map_err(|_| Error::Census)?;
            if tid == 0
                || tid > i32::MAX as u32
                || tid.to_string().as_bytes() != bytes
                || !tids.insert(tid)
            {
                return Err(Error::Census);
            }
        }
        if !tids.contains(&pid) {
            return Err(Error::Census);
        }
        Ok(Self {
            pid,
            tids,
            absent: BTreeSet::new(),
        })
    }

    fn read(
        joined: &[u32],
        observed: &mut Option<Vec<u32>>,
        mut check_time: impl FnMut() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        check_time()?;
        let pid = std::process::id();
        if unsafe { libc::syscall(libc::SYS_gettid) } != i64::from(pid) {
            return Err(Error::Identity);
        }
        let entries = std::fs::read_dir("/proc/self/task")
            .map_err(Error::Read)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::Read)?;
        let mut census = Self::parse(pid, entries)?;
        *observed = Some(census.tids.iter().copied().collect());
        check_time()?;
        for &tid in joined {
            if tid == 0 || tid > i32::MAX as u32 || tid == pid {
                return Err(Error::Identity);
            }
            // Directory iteration is not an atomic membership snapshot. An
            // omission alone does not satisfy our task-absence observation.
            check_time()?;
            if lookup_absent(
                std::fs::symlink_metadata(format!("/proc/self/task/{tid}"))
                    .map(|metadata| metadata.is_dir()),
            )? {
                census.absent.insert(tid);
            }
            check_time()?;
        }
        Ok(census)
    }
}

// Validate the complete observation before changing any retirement state.
fn observe<T>(
    census: &Census,
    joined: &mut [&mut Joined<T>],
    exclusive: bool,
) -> Result<bool, Error> {
    if joined.is_empty() {
        return Err(Error::Identity);
    }
    let mut identities = BTreeSet::from([census.pid]);
    let mut expected = BTreeSet::from([census.pid]);
    for task in joined.iter() {
        if task.pid != census.pid
            || task.tid == 0
            || task.tid > i32::MAX as u32
            || !identities.insert(task.tid)
        {
            return Err(Error::Identity);
        }
        if task.retired && (census.tids.contains(&task.tid) || !census.absent.contains(&task.tid)) {
            return Err(Error::UnexpectedTask(task.tid));
        }
        if !task.retired {
            expected.insert(task.tid);
        }
    }
    if exclusive && let Some(tid) = census.tids.difference(&expected).next() {
        return Err(Error::UnexpectedTask(*tid));
    }
    for task in joined.iter_mut() {
        task.retired = !census.tids.contains(&task.tid) && census.absent.contains(&task.tid);
    }
    Ok(joined.iter().all(|task| task.retired))
}

fn wait_until(
    until: Instant,
    mut now: impl FnMut() -> Instant,
    mut observe: impl FnMut() -> Result<bool, Error>,
    mut yield_now: impl FnMut(),
) -> Result<(), Error> {
    loop {
        if now() >= until {
            return Err(Error::Deadline);
        }
        let retired = observe()?;
        if now() >= until {
            return Err(Error::Deadline);
        }
        if retired {
            return Ok(());
        }
        yield_now();
    }
}

impl<T> Joined<T> {
    pub(super) fn tid(&self) -> u32 {
        self.tid
    }

    pub(super) fn diagnostic(&self) -> String {
        format!(
            "captured_tid={} last_complete_tasks={:?}",
            self.tid, self.observed
        )
    }

    pub(super) fn result(&self) -> &thread::Result<T> {
        assert!(
            self.retired,
            "task retirement required before reading result"
        );
        &self.result
    }

    pub(super) fn wait_until(&mut self, until: Instant) -> Result<(), Failure> {
        let tid = self.tid;
        let mut observed = None;
        let outcome = wait_until(
            until,
            Instant::now,
            || {
                // Other owned workers can still be live. This certifies only this
                // joined task; the caller's final single_main remains unchanged.
                let census = Census::read(&[tid], &mut observed, || {
                    if Instant::now() >= until {
                        Err(Error::Deadline)
                    } else {
                        Ok(())
                    }
                })?;
                observe(&census, &mut [self], false)
            },
            thread::yield_now,
        );
        outcome.map_err(|cause| Failure {
            cause,
            joined: vec![tid],
            observed,
        })
    }

    pub(super) fn into_result(self) -> thread::Result<T> {
        assert!(
            self.retired,
            "task retirement required before releasing result"
        );
        self.result
    }
}

// Session shutdown polls this once per existing event-loop iteration. Its
// existing Schedule owns time; this adds no sleep or replacement deadline.
pub(super) fn poll_exclusive<T>(
    joined: &mut [&mut Joined<T>],
    check_time: impl FnMut() -> Result<(), Error>,
) -> Result<bool, Failure> {
    let tids = joined.iter().map(|task| task.tid).collect::<Vec<_>>();
    let mut observed = None;
    let census = Census::read(&tids, &mut observed, check_time);
    if let Some(ids) = &observed {
        for task in joined.iter_mut() {
            task.observed = Some(ids.clone());
        }
    }
    let census = census.map_err(|cause| Failure {
        cause,
        joined: tids.clone(),
        observed,
    })?;
    observe(&census, joined, true).map_err(|cause| Failure {
        cause,
        joined: tids,
        observed: Some(census.tids.iter().copied().collect()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    fn census(entries: &[&str]) -> Census {
        let mut census =
            Census::parse(7, entries.iter().map(|entry| OsString::from(*entry))).unwrap();
        // Fabricated direct-lookup outcomes, not an observation of native tasks.
        census.absent = [8, 9, 10]
            .into_iter()
            .filter(|tid| !census.tids.contains(tid))
            .collect();
        census
    }
    fn joined(tid: u32) -> Joined<u64> {
        Joined {
            result: Ok(42),
            pid: 7,
            tid,
            retired: false,
            observed: None,
        }
    }

    #[test]
    fn captured_kernel_tid_survives_success_and_panic() {
        let task = spawn(|| unsafe { libc::syscall(libc::SYS_gettid) } as u32).join();
        assert_eq!(task.result.as_ref().copied().unwrap(), task.tid());
        assert_ne!(task.tid(), std::process::id());
        assert!(!task.retired);
        let task = spawn::<_, ()>(|| panic!("captured identity survives")).join();
        assert!(task.result.is_err());
        assert!(task.tid() > 0 && task.tid() != std::process::id());
        assert!(!task.retired);
    }

    #[test]
    fn complete_census_refuses_malformed_duplicate_or_missing_main() {
        for names in [
            vec![],
            vec!["8"],
            vec!["7", "7"],
            vec!["7", "0"],
            vec!["7", "+8"],
            vec!["7", "08"],
            vec!["7", "8\n"],
            vec!["7", "2147483648"],
            vec!["7", "no-task"],
        ] {
            assert!(Census::parse(7, names.into_iter().map(OsString::from)).is_err());
        }
        assert_eq!(census(&["9", "7", "8"]).tids, BTreeSet::from([7, 8, 9]));
        assert!(Census::parse(0, [OsString::from("0")]).is_err());
    }

    #[test]
    fn retirement_preserves_result_until_exact_tid_absence() {
        assert!(std::panic::catch_unwind(|| joined(8).into_result()).is_err());
        assert!(!lookup_absent(Ok(true)).unwrap());
        assert!(lookup_absent(Err(std::io::ErrorKind::NotFound.into())).unwrap());
        assert!(matches!(lookup_absent(Ok(false)), Err(Error::Census)));
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Interrupted,
        ] {
            assert!(matches!(
                lookup_absent(Err(kind.into())),
                Err(Error::Read(_))
            ));
        }
        let mut task = joined(8);
        let omitted_but_present = Census::parse(7, [OsString::from("7")]).unwrap();
        assert!(!observe(&omitted_but_present, &mut [&mut task], true).unwrap());
        assert!(!observe(&census(&["7", "8", "9"]), &mut [&mut task], false).unwrap());
        assert_eq!(task.result.as_ref().copied().unwrap(), 42);
        assert!(!task.retired);
        assert!(observe(&census(&["7", "9"]), &mut [&mut task], false).unwrap());
        assert_eq!(task.into_result().unwrap(), 42);
        let mut reused = joined(8);
        assert!(observe(&census(&["7"]), &mut [&mut reused], false).unwrap());
        assert!(matches!(
            observe(&census(&["7", "8"]), &mut [&mut reused], false),
            Err(Error::UnexpectedTask(8))
        ));
        let mut panic = Joined::<()> {
            result: Err(Box::new(123_u32)),
            pid: 7,
            tid: 8,
            retired: false,
            observed: None,
        };
        assert!(!observe(&census(&["7", "8"]), &mut [&mut panic], true).unwrap());
        assert!(observe(&census(&["7"]), &mut [&mut panic], true).unwrap());
        assert_eq!(
            *panic.into_result().unwrap_err().downcast::<u32>().unwrap(),
            123
        );
    }

    #[test]
    fn exclusive_retirement_refuses_unknown_tasks_and_waits_for_both() {
        let (mut a, mut b) = (joined(8), joined(9));
        assert!(matches!(
            observe(&census(&["7", "9", "10"]), &mut [&mut a, &mut b], true),
            Err(Error::UnexpectedTask(10))
        ));
        assert!(!a.retired && !b.retired);
        assert!(!observe(&census(&["7", "9"]), &mut [&mut a, &mut b], true).unwrap());
        assert!(a.retired && !b.retired);
        assert!(observe(&census(&["7"]), &mut [&mut a, &mut b], true).unwrap());
        let mut duplicate = joined(8);
        assert!(matches!(
            observe(&census(&["7"]), &mut [&mut a, &mut duplicate], true),
            Err(Error::Identity)
        ));
        let mut foreign = joined(10);
        foreign.pid = 6;
        assert!(matches!(
            observe(&census(&["7"]), &mut [&mut foreign], true),
            Err(Error::Identity)
        ));
        let mut main = joined(7);
        assert!(matches!(
            observe(&census(&["7"]), &mut [&mut main], true),
            Err(Error::Identity)
        ));
        let mut zero = joined(0);
        assert!(matches!(
            observe(&census(&["7"]), &mut [&mut zero], true),
            Err(Error::Identity)
        ));
        let mut empty: [&mut Joined<u64>; 0] = [];
        assert!(matches!(
            observe(&census(&["7"]), &mut empty, true),
            Err(Error::Identity)
        ));
    }

    #[test]
    fn retirement_uses_one_absolute_deadline_and_checks_after_observation() {
        let start = Instant::now();
        let until = start + Duration::from_secs(2);
        let now = Cell::new(start);
        let probes = Cell::new(0);
        assert!(matches!(
            wait_until(
                until,
                || now.get(),
                || {
                    probes.set(probes.get() + 1);
                    Ok(false)
                },
                || now.set(now.get() + Duration::from_secs(1))
            ),
            Err(Error::Deadline)
        ));
        assert_eq!(probes.get(), 2);
        assert!(matches!(
            wait_until(until, || until, || panic!("expired must not probe"), || {}),
            Err(Error::Deadline)
        ));
        now.set(start);
        assert!(matches!(
            wait_until(
                until,
                || now.get(),
                || {
                    now.set(until);
                    Ok(true)
                },
                || {}
            ),
            Err(Error::Deadline)
        ));
        assert!(
            wait_until(
                until,
                || start,
                || Ok(true),
                || panic!("already retired must not wait")
            )
            .is_ok()
        );
        assert!(matches!(
            wait_until(
                until,
                || start,
                || Err(Error::Census),
                || panic!("error must not retry")
            ),
            Err(Error::Census)
        ));
    }
}
