#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Required native state comparisons for all six T1 prefix geometries.
//! Handwritten streams and frozen rel32 words determine placement independently
//! of the decoder and planner. Every original head executes with both seeds.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

#[path = "support/bounded_proc_stat.rs"]
mod bounded_proc_stat;

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, LegalEntry,
    LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, TraceMap};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const PROBE_ID: u64 = 0x701;

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the emitter supplies a live frame and assert_trace activates the
    // child's bounded private log. Only caller-saved scratch state is destroyed.
    unsafe {
        oracle::record_hook_event(PROBE_ID, (*context).instruction_pointer);
        core::arch::asm!(
            "add rax, 1",
            "pxor xmm0, xmm0",
            "fninit",
            out("rax") _,
            out("xmm0") _,
            options(nostack),
        );
    }
}

fn permissions(pointer: *mut u8, protection: i32) -> Result<(), Refusal> {
    // SAFETY: callers retain the complete private source page under their lease.
    if unsafe { libc::mprotect(pointer.cast(), 4096, protection) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

struct Puzzle {
    length: usize,
    prefixes: usize,
    code: &'static [u8],
    heads: [usize; 3],
    frozen: u32,
}

fn window(base: u64, length: usize, prefixes: usize, code: &[u8]) -> AddressRange {
    let free = length - prefixes - 1;
    let mut displacement = [0_u8; 4];
    displacement[free..].copy_from_slice(&code[length..5 + prefixes]);
    let start = u64::try_from(
        i128::from(base) + (5 + prefixes) as i128 + i128::from(i32::from_le_bytes(displacement)),
    )
    .unwrap();
    AddressRange::new(start, 1_usize << (8 * free)).unwrap()
}

#[test]
fn native_state_covers_every_prefixed_pun_and_original_successor() {
    isolated_prefixed_pun();
}

// Fresh exec excludes the support module's other mapping tests. The original
// body below, all 26 support tests, and each trace's bounds remain unchanged.
fn isolated_prefixed_pun() {
    use bounded_proc_stat::read_bounded_stat;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const NAME: &str = "native_state_covers_every_prefixed_pun_and_original_successor";
    const SELECTOR: &str = "LITEINST2_PREFIXED_PUN_CHILD";
    const BODY_RETURNED: i32 = 102;

    if let Some(selected) = std::env::var_os(SELECTOR) {
        assert_eq!(
            selected,
            std::ffi::OsStr::new(NAME),
            "wrong isolated test selector"
        );
        native_state_covers_every_prefixed_pun_and_original_successor_body();
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
                eprintln!("prefixed-PUN cleanup during unwind failed: {error}");
            }
        }
    }

    // SAFETY: the existing chain-isolation pattern uses this idempotent flag.
    // It is process-wide; cleanup still waits/signals only our new owned group.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
        .env(SELECTOR, NAME)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
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
    let child = command.spawn().expect("launch isolated prefixed-PUN test");
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
        if let Some(outcome) = peek(group.pid).expect("poll isolated prefixed-PUN test") {
            break Some(outcome);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    group
        .cleanup()
        .expect("clean up isolated prefixed-PUN process group");
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

fn native_state_covers_every_prefixed_pun_and_original_successor_body() {
    // L2 MOV EAX,EAX; LEA RCX,[RDI+8]; RET.
    const L2: &[u8] = &[0x89, 0xc0, 0x48, 0x8d, 0x4f, 0x08, 0xc3];
    // L3 LEA RAX,[RDI]; MOV [RDI],RAX; RET.
    const L3: &[u8] = &[0x48, 0x8d, 0x07, 0x48, 0x89, 0x07, 0xc3];
    // L4 LEA RCX,[RDI+8]; MOV [RDI],RCX; RET.
    const L4: &[u8] = &[0x48, 0x8d, 0x4f, 0x08, 0x48, 0x89, 0x0f, 0xc3];
    let puzzles = [
        Puzzle {
            length: 2,
            prefixes: 1,
            code: L2,
            heads: [0, 2, 6],
            frozen: 0x084f_8d48,
        },
        Puzzle {
            length: 3,
            prefixes: 1,
            code: L3,
            heads: [0, 3, 6],
            frozen: 0x0789_4800,
        },
        Puzzle {
            length: 3,
            prefixes: 2,
            code: L3,
            heads: [0, 3, 6],
            frozen: 0xc307_8948,
        },
        Puzzle {
            length: 4,
            prefixes: 1,
            code: L4,
            heads: [0, 4, 7],
            frozen: 0x8948_0000,
        },
        Puzzle {
            length: 4,
            prefixes: 2,
            code: L4,
            heads: [0, 4, 7],
            frozen: 0x0f89_4800,
        },
        Puzzle {
            length: 4,
            prefixes: 3,
            code: L4,
            heads: [0, 4, 7],
            frozen: 0xc30f_8948,
        },
    ];
    let mut installed_comparisons = 0;
    let mut retired_comparisons = 0;
    let mut negative_displacements = 0;
    let mut retained = Vec::new();
    for (index, puzzle) in puzzles.iter().enumerate() {
        let mut oracle = NativeOracle::new(puzzle.code);
        let base = oracle.code.address();
        let heads = puzzle.heads.map(|offset| base + offset as u64);
        let source = AddressRange::new(base, puzzle.code.len()).unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity([0xc0 + index as u8; 32]),
            mapping: base,
            generation: 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope: source,
            provenance: EntryProvenance::Declared(format!(
                "native T1 L{} P{} all three original heads",
                puzzle.length, puzzle.prefixes
            )),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: heads
                .iter()
                .map(|&address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let free = puzzle.length - puzzle.prefixes - 1;
        let width = 1_usize << (8 * free);
        assert_eq!(
            &puzzle.frozen.to_le_bytes()[free..],
            &puzzle.code[puzzle.length..5 + puzzle.prefixes],
            "handwritten bytes must supply the declared fixed displacement"
        );
        assert!(
            puzzle.frozen.to_le_bytes()[..free]
                .iter()
                .all(|&byte| byte == 0)
        );
        let next = base + (5 + puzzle.prefixes) as u64;
        let low = u64::try_from(i128::from(next) + i128::from(puzzle.frozen as i32)).unwrap();
        let expected_window = AddressRange::new(low, width).unwrap();
        assert_eq!(
            expected_window,
            window(base, puzzle.length, puzzle.prefixes, puzzle.code)
        );
        let target = low + width as u64 / 2;
        let permitted = AddressRange::new(target & !4095, 8192).unwrap();
        for other_prefixes in 0..puzzle.length {
            if other_prefixes != puzzle.prefixes {
                assert!(
                    !permitted.overlaps(window(base, puzzle.length, other_prefixes, puzzle.code)),
                    "allocation must exclude B2 and every other prefix count"
                );
            }
        }
        let mut allocation = AllocationPolicy::near(base).unwrap();
        allocation.ranges = vec![permitted];
        allocation.preferred_address = Some(target);
        let mut request = InstallRequest {
            identity,
            code: puzzle.code,
            base_address: base,
            function: source,
            block: source,
            logical_pc: base,
            entries: &entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::GeneralizedPunOnly,
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        };
        assert_eq!(
            plan_install(&request).unwrap_err(),
            Refusal::AllocationUnavailable
        );
        request.search.tactics = TacticPolicy::PrefixPunOnly;
        let prepared = plan_install(&request).unwrap_or_else(|error| {
            panic!(
                "required T1 L{} P{} refused: {error:?}",
                puzzle.length, puzzle.prefixes
            )
        });
        if puzzle.length == 2 {
            // This permitted page fixes displacement byte 1 to 0x7f..=0x9f,
            // none of which is an approved illegal opcode for successor head 2.
            // Ordinary relocation therefore cannot preserve that required entry.
            request.search.tactics = TacticPolicy::RelocationOnly;
            assert_eq!(
                plan_install(&request).unwrap_err(),
                Refusal::AllocationUnavailable
            );
            request.search.tactics = TacticPolicy::PreferGeneralizedPun;
            let default = plan_install(&request).expect("default must admit the T1 fallback");
            assert_eq!(
                default.plan(),
                prepared.plan(),
                "required T1 fallback changed geometry"
            );
        } else if puzzle.length == 3 && puzzle.prefixes == 2 {
            // This separate page permits the original relocation tactic: the
            // byte at successor head 3 is the approved illegal opcode 0x07.
            // Default ordering must retain that feasible tactic ahead of T1.
            request.search.tactics = TacticPolicy::RelocationOnly;
            let relocation =
                plan_install(&request).expect("required relocation alternative refused");
            assert!(matches!(
                relocation.plan().parts().kind,
                PlanKind::Relocation
            ));
            request.search.tactics = TacticPolicy::PreferGeneralizedPun;
            let default = plan_install(&request).expect("default must admit feasible relocation");
            assert_eq!(default.plan(), relocation.plan());
        }
        let parts = prepared.plan().parts();
        let PlanKind::PrefixedPun(pun) = &parts.kind else {
            panic!("required T1 became another tactic: {:?}", parts.kind);
        };
        assert_eq!(pun.instruction_len as usize, puzzle.length);
        assert_eq!(pun.prefix_count as usize, puzzle.prefixes);
        assert_eq!(parts.physical_pc, base);
        assert_eq!(parts.logical_pc, base);
        assert_eq!(
            parts.displaced,
            AddressRange::new(base, puzzle.length).unwrap()
        );
        assert_eq!(
            pun.consumed,
            AddressRange::new(base, 5 + puzzle.prefixes).unwrap()
        );
        assert_eq!(pun.target_window, expected_window);
        assert_eq!(pun.target_window.len(), width as u64);
        assert_eq!(
            prepared.image().address(),
            target,
            "preferred exact target must be used"
        );
        assert_eq!(parts.writes.len(), 1);
        let edit = &parts.writes[0];
        assert_eq!(edit.address, base);
        assert_eq!(edit.bytes.len(), puzzle.length);
        assert_eq!(&edit.bytes[..puzzle.prefixes], vec![0x2e; puzzle.prefixes]);
        assert_eq!(edit.bytes[puzzle.prefixes], 0xe9);
        assert_eq!(pun.store.address, base);
        assert_eq!(pun.store.bytes.len(), puzzle.length.next_power_of_two());
        assert_eq!(&pun.store.bytes[..puzzle.length], edit.bytes);
        assert_eq!(
            &pun.store.bytes[puzzle.length..],
            &puzzle.code[puzzle.length..pun.store.bytes.len()],
            "the wider three-byte store must preserve its successor pad"
        );
        let mut consumed = puzzle.code[..5 + puzzle.prefixes].to_vec();
        consumed[..puzzle.length].copy_from_slice(&edit.bytes);
        assert_eq!(
            &consumed[puzzle.length..],
            &puzzle.code[puzzle.length..5 + puzzle.prefixes]
        );
        let displacement = i32::from_le_bytes(consumed[puzzle.prefixes + 1..].try_into().unwrap());
        assert_eq!(
            i128::from(next) + i128::from(displacement),
            i128::from(target)
        );
        negative_displacements += usize::from(displacement < 0);
        assert!(
            parts
                .obligations
                .iter()
                .all(|entry| matches!(entry, EntryObligation::Preserved(_)))
        );
        assert!(!parts.requirements.sigill_router);
        assert_eq!(prepared.image().instruction_boundaries().len(), 1);
        assert_eq!(prepared.image().instruction_boundaries()[0].0, base);
        let mut boundaries = prepared.image().instruction_boundaries().to_vec();
        boundaries.extend(heads[1..].iter().map(|&pc| (pc, pc)));
        boundaries.push((oracle.return_pc(), oracle.return_pc()));
        let map = TraceMap {
            boundaries,
            gateways: vec![base],
            generated_ranges: std::iter::once(
                target..target + prepared.image().bytes().len() as u64,
            )
            .collect(),
        };
        let mut originals = Vec::new();
        for seed in SEEDS {
            for (entry_index, &entry) in heads.iter().enumerate() {
                let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
                assert_eq!(
                    trace.visits(),
                    heads[entry_index..]
                        .iter()
                        .copied()
                        .chain([oracle.return_pc()])
                        .collect::<Vec<_>>()
                );
                originals.push((entry, trace));
            }
        }
        let writable = oracle.code.writable();
        let (mut installed, receipt) = {
            // SAFETY: this exclusive fixture owner has reaped every original
            // child and excludes all executors, aliases and saved continuations.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source]) };
            permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: the exact source/store padding/fetch bytes are held; RX
            // is established before sync-core and successful receipt issuance.
            let result = unsafe {
                prepared.publish_with(writable, &mut lease, || {
                    permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .expect("required T1 publication failed");
            assert!(!lease.is_poisoned());
            result
        };
        assert_eq!(receipt.plan(), prepared.plan());
        oracle.assert_publication(&[(base, edit.bytes.clone())]);
        let log = HookEventLog::new();
        let enabled = [HookEvent {
            probe_id: PROBE_ID,
            logical_pc: base,
        }];
        for (entry, trace) in &originals {
            oracle.assert_trace(
                trace,
                *entry,
                &map,
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &enabled,
                }),
            );
            installed_comparisons += 1;
        }
        assert_eq!(installed.routed_entries(), 0);
        {
            let mut ranges = vec![source];
            ranges.extend(parts.allocations.iter().map(|allocation| allocation.range));
            // SAFETY: all installed children have been reaped, draining source,
            // generated code and saved continuations before restoration.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
            permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: the complete source/generated lease and exact alias remain
            // held; finalization changes permissions only and cannot unwind.
            unsafe {
                installed.retire_with(&mut lease, || {
                    permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .expect("required T1 retirement failed");
            assert!(!lease.is_poisoned());
        }
        assert!(installed.is_retired());
        oracle.assert_publication(&[]);
        let original_map = TraceMap {
            boundaries: heads
                .iter()
                .copied()
                .chain([oracle.return_pc()])
                .map(|pc| (pc, pc))
                .collect(),
            ..TraceMap::default()
        };
        for (entry, trace) in &originals {
            oracle.assert_trace(
                trace,
                *entry,
                &original_map,
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &[],
                }),
            );
            retired_comparisons += 1;
        }
        retained.push(oracle);
    }
    assert_eq!(installed_comparisons, 36);
    assert_eq!(retired_comparisons, 36);
    assert_eq!(negative_displacements, 3);
    eprintln!(
        "native T1 oracle: six required prefix geometries; 18 original heads; 36 installed and 36 retired comparisons; three negative rel32 cases; no successor changes or state mismatches"
    );
}
