//! Test-only process boundary, not a production qualifier or oracle exemption.

const COHORTS: [&str; 5] = [
    "native_state_covers_successor_eviction_into_b2_and_t1_puns",
    "native_successor_eviction_preserves_seven_byte_victim_fault",
    "native_successor_eviction_preserves_bounded_victim_backedge",
    "native_successor_eviction_preserves_victim_rip_relative_data",
    "occupied_successor_page_refuses_without_mutation",
];
const CPU_SECONDS: libc::rlim_t = 20;
const WALL_SECONDS: u64 = 30;

// This cfg builds only process-launch support. Every original assertion lives
// in an unconditionally compiled run_* body in the shared fixture module.
#[cfg(test)]
pub fn run_parent(cohort: &str) {
    launcher::run(cohort);
}

pub fn main_thread_driver() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(args.len(), 5);
    assert_eq!(args[1], "--cohort");
    assert_eq!(args[3], "--captures");
    let cohort = args[2].to_str().expect("literal cohort name");
    assert!(COHORTS.contains(&cohort));
    let capture = std::path::PathBuf::from(&args[4]);
    assert!(capture.is_dir());
    // Record the wrapper bounds in both build modes; no limits or trace state
    // are changed by the native fixture module.
    std::fs::write(
        capture.join("declared-bounds.txt"),
        format!("cpu={CPU_SECONDS}\nwall={WALL_SECONDS}\ntrace_wall=15\ntrace_steps=20000\n"),
    )
    .unwrap();
    record_single_main_thread(&capture, "before");
    match cohort {
        "native_state_covers_successor_eviction_into_b2_and_t1_puns" => {
            super::run_native_state_covers_successor_eviction_into_b2_and_t1_puns()
        }
        "native_successor_eviction_preserves_seven_byte_victim_fault" => {
            super::run_native_successor_eviction_preserves_seven_byte_victim_fault()
        }
        "native_successor_eviction_preserves_bounded_victim_backedge" => {
            super::run_native_successor_eviction_preserves_bounded_victim_backedge()
        }
        "native_successor_eviction_preserves_victim_rip_relative_data" => {
            super::run_native_successor_eviction_preserves_victim_rip_relative_data()
        }
        "occupied_successor_page_refuses_without_mutation" => occupied_victim_refusal(&capture),
        _ => unreachable!(),
    }
    record_single_main_thread(&capture, "after");
    std::fs::write(
        capture.join("complete.txt"),
        format!("completed-cohort:{cohort}\n"),
    )
    .unwrap();
}

fn record_single_main_thread(capture: &std::path::Path, phase: &str) {
    let pid = std::process::id();
    // SAFETY: gettid only reads the current kernel thread identity.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    assert_eq!(tid, libc::c_long::from(pid));
    let mut tasks: Vec<_> = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    tasks.sort();
    assert_eq!(tasks, vec![pid.to_string()]);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    std::fs::write(capture.join(format!("{phase}.maps")), maps).unwrap();
    std::fs::write(
        capture.join(format!("{phase}.threads.txt")),
        format!(
            "pid={pid}\ntid={tid}\ncount={}\ntasks={tasks:?}\n",
            tasks.len()
        ),
    )
    .unwrap();
}

fn occupied_victim_refusal(capture: &std::path::Path) {
    use liteinst2::contracts::*;
    use liteinst2::planner::HookSemantics;
    use liteinst2::quiescent::{AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy};
    // Separate pure-planner negative: no native execution and no skipped old
    // case. The held page is deliberately occupied for the entire request.
    let code = [0x89, 0xc0, 0xb8, 0x11, 0x22, 0x33, 0x44, 0xc3];
    let native = super::oracle::NativeOracle::new(&code);
    let owner = super::oracle::Mapping::new(4096);
    // SAFETY: the dedicated private page is writable and exclusively held.
    unsafe {
        std::ptr::write_bytes(owner.writable(), 0xa5, 4096);
    }
    let source = AddressRange::new(native.code.address(), code.len()).unwrap();
    let target = owner.address() + 128;
    assert!(i32::try_from(i128::from(target) - i128::from(source.start() + 7)).is_ok());
    let identity = CodeIdentity {
        source: SourceIdentity([0xe3; 32]),
        mapping: source.start(),
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared("deliberately occupied auxiliary image page".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: vec![],
        resumes: ResumeObligation::NoneExist,
    };
    let selected = AllocationPolicy::near(source.start()).unwrap();
    let victim = AllocationPolicy {
        ranges: vec![AddressRange::new(owner.address(), 4096).unwrap()],
        preferred_address: Some(target),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let request = InstallRequest {
        identity,
        code: &code,
        base_address: source.start(),
        function: source,
        block: AddressRange::new(source.start(), 2).unwrap(),
        logical_pc: source.start(),
        entries: &entries,
        hook: super::observe,
        semantics: HookSemantics::Observe,
        allocation: &selected,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            max_upstream_bytes: 0,
            max_sites: 1,
            ..SearchPolicy::default()
        },
    };
    // SAFETY: both owned readable pages remain mapped through this comparison.
    let source_before =
        unsafe { std::slice::from_raw_parts(native.code.writable(), 4096) }.to_vec();
    let owner_before = unsafe { std::slice::from_raw_parts(owner.writable(), 4096) }.to_vec();
    let before = std::fs::read_to_string("/proc/self/maps").unwrap();
    let failure = liteinst2::eviction::plan_successor_detailed(
        &request,
        &victim,
        liteinst2::bundle::BundleBudget::default(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(failure.attempts[0].victim, source.start() + 2);
    assert_eq!(failure.attempts[0].victim_target, target);
    assert_eq!(failure.attempts[0].prefix_count, None);
    assert_eq!(
        failure.attempts[0].refusal,
        Some(Refusal::AllocationUnavailable)
    );
    assert!(!failure.search.accepted);
    assert_eq!(failure.search.runs.len(), 1);
    assert_eq!(
        failure.search.runs[0].domain,
        liteinst2::search::SearchDomain::VictimImages
    );
    assert_eq!(failure.search.runs[0].examined, 1);
    native.assert_publication(&[]);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(native.code.writable(), 4096) },
        source_before
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owner.writable(), 4096) },
        owner_before
    );
    std::fs::write(capture.join("occupied-before.maps"), before).unwrap();
    std::fs::write(
        capture.join("occupied-after.maps"),
        std::fs::read_to_string("/proc/self/maps").unwrap(),
    )
    .unwrap();
    std::fs::write(capture.join("occupied-result.txt"), format!("source={source:?}\nowner={:#x}\ntarget={target:#x}\n{failure:#?}\nsource_unchanged=true\nowner_unchanged=true\n", owner.address())).unwrap();
}

#[cfg(test)]
#[path = "bounded_proc_stat.rs"]
mod bounded_proc_stat;

#[cfg(test)]
mod launcher {
    use super::bounded_proc_stat::read_bounded_stat;
    use super::{COHORTS, CPU_SECONDS, WALL_SECONDS};
    use std::collections::BTreeSet;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug)]
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

    struct Guard {
        _child: Child,
        pid: i32,
        seen_peers: BTreeSet<i32>,
        peer_reaps: Vec<(i32, i32)>,
        direct_reap: Option<i32>,
        cleanup_attempted: bool,
        cleanup_error: Option<String>,
    }
    impl Guard {
        fn cleanup(&mut self) {
            if self.cleanup_attempted {
                return;
            }
            self.cleanup_attempted = true;
            self.cleanup_error = self.cleanup_inner().err();
        }
        fn cleanup_inner(&mut self) -> Result<(), String> {
            // SAFETY: the unreaped leader still pins this exact owned group.
            let killed = unsafe { libc::kill(-self.pid, libc::SIGKILL) };
            if killed == -1 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err("owned group kill failed".into());
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if Instant::now() >= deadline {
                    return Err("owned cleanup exceeded two seconds".into());
                }
                // Exit notification follows reparenting: once the direct child
                // is waitable, its same-group descendants are ours, or still
                // descend from another same-group child in this inventory.
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
                    // SAFETY: reap ONLY the exact pinned leader, last. No
                    // process-group operation follows this ownership release.
                    let reaped = unsafe {
                        libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL)
                    };
                    if reaped != self.pid {
                        return Err("exact final leader reap failed".into());
                    }
                    self.direct_reap = Some(status);
                    return Ok(());
                }
                for pid in peers {
                    if Instant::now() >= deadline {
                        return Err("peer cleanup deadline".into());
                    }
                    self.seen_peers.insert(pid);
                    // waitid proves parent-child ownership without releasing
                    // the PID before an individual signal or exact reap.
                    let _ = peek(pid)?;
                    let killed = unsafe { libc::kill(pid, libc::SIGKILL) };
                    if killed == -1
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                    {
                        return Err("owned peer kill failed".into());
                    }
                    let mut status = 0;
                    let reaped =
                        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
                    if reaped == pid {
                        self.peer_reaps.push((pid, status));
                    } else if reaped == -1 {
                        return Err("exact owned peer reap failed".into());
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            self.cleanup();
        }
    }

    pub(super) fn run(cohort: &str) {
        assert!(COHORTS.contains(&cohort));
        let driver = std::env::var_os("LITEINST_T2_MAIN_THREAD_DRIVER")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                option_env!("CARGO_BIN_EXE_successor-eviction-oracle-driver").map(Into::into)
            })
            .expect("main-thread T2 fixture binary must be built; never skip a cohort");
        assert!(driver.is_absolute());
        let root = std::env::var_os("LITEINST_T2_MAIN_THREAD_CAPTURES")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("liteinst2-t2-main-thread"));
        std::fs::create_dir_all(&root).unwrap();
        let capture = root.join(format!("{}-{cohort}", std::process::id()));
        std::fs::create_dir(&capture).unwrap();
        let stdout = std::fs::File::create(capture.join("stdout.txt")).unwrap();
        let stderr = std::fs::File::create(capture.join("stderr.txt")).unwrap();
        // SAFETY: idempotent flag; other test groups remain separately owned.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
        let mut command = Command::new(&driver);
        command
            .args(["--cohort", cohort, "--captures"])
            .arg(&capture)
            .process_group(0)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // SAFETY: only async-signal-safe syscalls before exec.
        unsafe {
            command.pre_exec(|| {
                for (kind, value) in [
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_CPU, CPU_SECONDS),
                    (libc::RLIMIT_FSIZE, 16 * 1024 * 1024),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(kind, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let pid = child.id() as i32;
        let mut guard = Guard {
            _child: child,
            pid,
            seen_peers: BTreeSet::new(),
            peer_reaps: Vec::new(),
            direct_reap: None,
            cleanup_attempted: false,
            cleanup_error: None,
        };
        let deadline = Instant::now() + Duration::from_secs(WALL_SECONDS);
        let outcome = loop {
            if let Some(outcome) = peek(pid).expect("owned direct-child waitid failed") {
                break Some(outcome);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        guard.cleanup();
        std::fs::write(capture.join("parent-result.txt"), format!(
            "cohort={cohort}\ndriver={}\ncpu_seconds={CPU_SECONDS}\nwall_seconds={WALL_SECONDS}\npeek={outcome:?}\nseen_peers={:?}\npeer_reaps={:?}\ndirect_reap={:?}\ncleanup_error={:?}\nleader_reaped_last={}\n",
            driver.display(), guard.seen_peers, guard.peer_reaps, guard.direct_reap, guard.cleanup_error, guard.direct_reap.is_some() && guard.cleanup_error.is_none(),
        )).unwrap();
        eprintln!("T2 main-thread {cohort}: {}", capture.display());
        eprint!(
            "{}",
            std::fs::read_to_string(capture.join("stderr.txt")).unwrap()
        );
        assert!(guard.cleanup_error.is_none(), "owned child cleanup failed");
        let reaped = guard
            .direct_reap
            .expect("direct child was not reaped exactly");
        assert!(
            outcome.is_some(),
            "required T2 cohort exceeded {WALL_SECONDS}s wall bound"
        );
        let outcome = outcome.unwrap();
        assert_eq!(
            outcome.code,
            libc::CLD_EXITED,
            "required T2 child did not exit normally"
        );
        assert_eq!(outcome.status, 0, "required T2 child failed; logs retained");
        assert!(libc::WIFEXITED(reaped));
        assert_eq!(libc::WEXITSTATUS(reaped), 0);
        assert!(
            guard.seen_peers.is_empty() && guard.peer_reaps.is_empty(),
            "successful cohort left descendants behind"
        );
        assert_eq!(
            std::fs::read_to_string(capture.join("complete.txt")).unwrap(),
            format!("completed-cohort:{cohort}\n")
        );
    }
}
