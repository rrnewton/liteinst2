//! Fresh-exec isolation for fixed native test campaigns.
//!
//! Callers bind their exact libtest name, private selector, and unchanged body.
//! Only the selected child invokes the body; normal return must produce the
//! sentinel after every assertion and local destructor has completed.

#[path = "bounded_proc_stat.rs"]
mod bounded_proc_stat;

pub(super) fn run(name: &str, selector: &str, body: fn()) {
    use self::bounded_proc_stat::read_bounded_stat;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const BODY_RETURNED: i32 = 102;

    if let Some(selected) = std::env::var_os(selector) {
        assert_eq!(
            selected,
            std::ffi::OsStr::new(name),
            "wrong isolated test selector"
        );
        body();
        // SAFETY: the complete body and its local destructors have returned.
        // Zero-test harness success cannot produce this completion status.
        unsafe { libc::_exit(BODY_RETURNED) };
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Exit {
        code: i32,
        status: i32,
    }

    // WNOWAIT leaves the direct child waitable: its PID/PGID cannot be recycled
    // until the final exact-PID reap, after every group signal and peer wait.
    fn peek(pid: i32) -> Result<Option<Exit>, String> {
        // SAFETY: initialized output and exact still-owned child PID.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: successful waitid initialized the child-status union fields.
        let found = unsafe { info.si_pid() };
        if found == 0 {
            return Ok(None);
        }
        if found != pid {
            return Err("waitid returned a different owned child".into());
        }
        Ok(Some(Exit {
            code: info.si_code,
            status: unsafe { info.si_status() },
        }))
    }

    // Same finite nonrecursive /proc grammar used by the approved parked v5
    // helper: <=65536 entries, <=4096 bytes per stat, deadline on every read.
    // The optional /proc/PID/task/TID/children interface is not available here.
    fn owned_group(group: i32, deadline: Instant) -> Result<Vec<i32>, String> {
        let mut result = Vec::new();
        let entries = std::fs::read_dir("/proc").map_err(|e| e.to_string())?;
        for (index, entry) in entries.enumerate() {
            if index >= 65536 || Instant::now() >= deadline {
                return Err("bounded process inventory exhausted".into());
            }
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let pid: i32 = name.parse().map_err(|_| "invalid numeric process ID")?;
            let file = match std::fs::File::open(entry.path().join("stat")) {
                Ok(file) => file,
                Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            let Some(bytes) = read_bounded_stat(file)
                .map_err(|error| format!("read /proc/{pid}/stat: {error}"))?
            else {
                continue;
            };
            if bytes.len() > 4096 || Instant::now() >= deadline {
                return Err("bounded process stat read exhausted".into());
            }
            if !bytes.starts_with(format!("{pid} (").as_bytes()) {
                return Err("process stat identity mismatch".into());
            }
            // comm may contain arbitrary non-UTF8 bytes and parentheses. Only
            // the numeric fields after its final delimiter are ASCII-parsed.
            let close = bytes
                .windows(2)
                .rposition(|pair| pair == b") ")
                .ok_or("malformed process stat")?;
            let suffix = std::str::from_utf8(&bytes[close + 2..])
                .map_err(|_| "non-ASCII numeric process fields")?;
            let fields: Vec<_> = suffix.split_whitespace().collect();
            if fields.len() < 3 {
                return Err("short process stat".into());
            }
            let parent: u32 = fields[1].parse().map_err(|_| "invalid parent PID")?;
            let pgrp: i32 = fields[2].parse().map_err(|_| "invalid process group")?;
            if parent == std::process::id() && pgrp == group {
                result.push(pid);
            }
        }
        if Instant::now() >= deadline {
            return Err("bounded process inventory deadline".into());
        }
        result.sort_unstable();
        Ok(result)
    }

    struct Group {
        _child: Child,
        pid: libc::pid_t,
        cleanup_attempted: bool,
        leader_status: Option<i32>,
        peers: Vec<libc::pid_t>,
    }
    impl Group {
        fn cleanup(&mut self) -> Result<(), String> {
            assert!(!self.cleanup_attempted, "owned group cleanup repeated");
            self.cleanup_attempted = true;
            // SAFETY: the unreaped leader pins the exact new process group.
            // Kill nested ptrace children too, including on worker abort. The
            // leader is reaped last, after all peer signals and waits.
            if unsafe { libc::kill(-self.pid, libc::SIGKILL) } != 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err("owned process group kill failed".into());
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if Instant::now() >= deadline {
                    return Err("owned process group cleanup exceeded two seconds".into());
                }
                // The leader's exit notification follows orphan adoption. Keep
                // that leader waitable while finding and reaping its tracees.
                if peek(self.pid)?.is_none() {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                let children = owned_group(self.pid, deadline)?;
                if !children.contains(&self.pid) {
                    return Err("owned unreaped leader absent from inventory".into());
                }
                let peers: Vec<_> = children
                    .into_iter()
                    .filter(|&pid| pid != self.pid)
                    .collect();
                if peers.is_empty() {
                    let mut status = 0;
                    // SAFETY: reap the exact pinned leader last. No group
                    // operation or wait follows this ownership release.
                    if unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL) }
                        != self.pid
                    {
                        return Err("exact final leader reap failed".into());
                    }
                    self.leader_status = Some(status);
                    return Ok(());
                }
                for pid in peers {
                    if Instant::now() >= deadline {
                        return Err("owned peer cleanup deadline".into());
                    }
                    if !self.peers.contains(&pid) {
                        self.peers.push(pid);
                    }
                    // Prove direct-child ownership without releasing the PID.
                    let _ = peek(pid)?;
                    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                    {
                        return Err("owned peer kill failed".into());
                    }
                    let mut status = 0;
                    // SAFETY: only the exact still-owned same-group child.
                    let reaped =
                        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
                    if reaped == -1 {
                        return Err("exact owned peer reap failed".into());
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    impl Drop for Group {
        fn drop(&mut self) {
            if self.cleanup_attempted {
                return;
            }
            if let Err(error) = self.cleanup() {
                eprintln!("native cleanup during unwind failed: {error}");
            }
        }
    }

    // SAFETY: the existing chain-isolation pattern uses this idempotent flag.
    // It is process-wide; cleanup still waits/signals only our new owned group.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(selector, name)
        .stdin(Stdio::null())
        // Exact exit receipts below authenticate body completion; keep its
        // diagnostics on stderr without unfinished child libtest progress.
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0);
    // SAFETY: only async-signal-safe syscalls are used before exec.
    unsafe {
        command.pre_exec(|| {
            for (resource, seconds) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_CPU, 20)] {
                let limit = libc::rlimit {
                    rlim_cur: seconds,
                    rlim_max: seconds,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn().expect("launch isolated native test");
    let pid = i32::try_from(child.id()).unwrap();
    let mut group = Group {
        _child: child,
        pid,
        cleanup_attempted: false,
        leader_status: None,
        peers: Vec::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let outcome = loop {
        if let Some(outcome) = peek(group.pid).expect("poll isolated native test") {
            break Some(outcome);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    group
        .cleanup()
        .expect("clean up isolated native process group");
    assert_eq!(
        outcome,
        Some(Exit {
            code: libc::CLD_EXITED,
            status: BODY_RETURNED,
        }),
        "isolated body failed or timed out"
    );
    let status = group.leader_status.expect("isolated leader was not reaped");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), BODY_RETURNED);
    assert!(
        group.peers.is_empty(),
        "successful body left ptrace children: {:?}",
        group.peers
    );
}
