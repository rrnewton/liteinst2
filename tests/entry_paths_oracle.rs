//! Native state comparisons for original instruction entry paths.

#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, LegalEntry,
    LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, SignalResume, TraceMap};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const BODY_HEADS: [usize; 7] = [0, 1, 2, 3, 4, 5, 10];
const BODY_LEN: usize = 11;
const TABLE: usize = 0x500;
const DISPATCH: usize = 0x180;
const DISPATCH_HEADS: [usize; 5] = [0x180, 0x187, 0x18b, 0x192, 0x195];
const ID: u64 = 0xe001;
const CHILD: &str = "LITEINST_ENTRY_PATH_CHILD";

unsafe extern "C" fn observe(context: *mut HookContext) {
    unsafe { oracle::record_hook_event(ID, (*context).instruction_pointer) };
}

fn e9(from: usize, to: usize) -> [u8; 5] {
    let mut bytes = [0xe9; 5];
    let displacement = i32::try_from(to as i64 - (from + 5) as i64).unwrap();
    bytes[1..].copy_from_slice(&displacement.to_le_bytes());
    bytes
}

fn fixture() -> (Vec<u8>, Vec<usize>) {
    let mut bytes = vec![0xcc; TABLE + BODY_HEADS.len() * 8];
    bytes[..BODY_LEN].copy_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0xb8, 0x2a, 0, 0, 0, 0xc3]);
    let mut heads = BODY_HEADS.to_vec();
    for (index, &target) in BODY_HEADS.iter().enumerate() {
        let selector = 0x100 + index * 16;
        bytes[selector] = 0xba; // MOV EDX,case; every table case executes.
        bytes[selector + 1..selector + 5].copy_from_slice(&(index as u32).to_le_bytes());
        bytes[selector + 5..selector + 10].copy_from_slice(&e9(selector + 5, DISPATCH));
        heads.extend([selector, selector + 5]);
        let direct = 0x200 + index * 16;
        bytes[direct..direct + 5].copy_from_slice(&e9(direct, target));
        heads.push(direct);
        // Relative-address table entries are literal data, never decoder heads.
        bytes[TABLE + index * 8..TABLE + index * 8 + 8]
            .copy_from_slice(&(target as u64).to_le_bytes());
    }
    bytes[0x180..0x187].copy_from_slice(&[0x48, 0x8d, 0x05, 0x79, 0x03, 0, 0]); // LEA RAX,[RIP+TABLE]
    bytes[0x187..0x18b].copy_from_slice(&[0x48, 0x8b, 0x04, 0xd0]); // MOV RAX,[RAX+RDX*8]
    bytes[0x18b..0x192].copy_from_slice(&[0x48, 0x8d, 0x0d, 0x6e, 0xfe, 0xff, 0xff]); // LEA RCX,[RIP+base]
    bytes[0x192..0x195].copy_from_slice(&[0x48, 0x01, 0xc8]); // ADD RAX,RCX
    bytes[0x195..0x197].copy_from_slice(&[0xff, 0xe0]); // JMP RAX
    heads.extend(DISPATCH_HEADS);
    heads.sort_unstable();
    assert_eq!(heads.len(), 33);
    let table_displacement = i32::from_le_bytes(bytes[0x183..0x187].try_into().unwrap());
    let base_displacement = i32::from_le_bytes(bytes[0x18e..0x192].try_into().unwrap());
    assert_eq!(0x187_i64 + i64::from(table_displacement), TABLE as i64);
    assert_eq!(0x192_i64 + i64::from(base_displacement), 0);
    (bytes, heads)
}

fn permissions(pointer: *mut u8, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(pointer.cast(), 4096, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn request<'a>(
    bytes: &'a [u8],
    base: u64,
    identity: CodeIdentity,
    body: AddressRange,
    entries: &'a LegalEntrySet,
    allocation: &'a AllocationPolicy,
) -> InstallRequest<'a> {
    InstallRequest {
        identity,
        code: &bytes[..BODY_LEN],
        base_address: base,
        function: body,
        block: body,
        logical_pc: base,
        entries,
        hook: observe,
        semantics: HookSemantics::Observe,
        allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0,
            max_sites: 1,
            max_displaced_bytes: 5,
        },
    }
}

fn cycle(saved_resume: bool) {
    let (bytes, offsets) = fixture();
    let mut native = NativeOracle::new(&bytes);
    let base = native.code.address();
    let identity = CodeIdentity {
        source: SourceIdentity([0xe1 + u8::from(saved_resume); 32]),
        mapping: u64::from(saved_resume) + 1,
        generation: 1,
    };
    let body = AddressRange::new(base, BODY_LEN).unwrap();
    let source = AddressRange::new(base, 4096).unwrap();
    let body_heads: Vec<_> = BODY_HEADS
        .iter()
        .map(|offset| base + *offset as u64)
        .collect();
    let entries = LegalEntrySet {
        identity,
        scope: body,
        provenance: EntryProvenance::Declared(
            "literal body heads; external direct/table paths and real signal resumes".into(),
        ),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: body_heads
            .iter()
            .map(|&address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: if saved_resume {
            ResumeObligation::Enumerated(body_heads.clone())
        } else {
            ResumeObligation::NoneExist
        },
    };
    let mut allocation = AllocationPolicy::near(base).unwrap();
    allocation.preferred_address = Some(base + 64 * 1024 * 1024);
    if !saved_resume {
        // Four required refusals do not substitute for any execution below.
        for case in 0..4 {
            let mut invalid = entries.clone();
            let expected = match case {
                0 => {
                    invalid.entries.push(LegalEntry {
                        address: base + 6,
                        requires_endbr: false,
                    });
                    Refusal::NotInstructionHead
                }
                1 => {
                    invalid.resumes = ResumeObligation::Enumerated(vec![base + 6]);
                    Refusal::NotInstructionHead
                }
                2 => {
                    invalid.resumes = ResumeObligation::Unresolved;
                    Refusal::UnresolvedEntry
                }
                3 => {
                    invalid.completeness = EntryCompleteness::Incomplete;
                    Refusal::UnresolvedEntry
                }
                _ => unreachable!(),
            };
            assert!(
                matches!(plan_install(&request(&bytes, base, identity, body, &invalid, &allocation)), Err(ref error) if *error == expected)
            );
            native.assert_publication(&[]);
        }
    }
    let plan = plan_install(&request(
        &bytes,
        base,
        identity,
        body,
        &entries,
        &allocation,
    ))
    .expect("required B1 entry fixture must install");
    assert_eq!(plan.plan().parts().kind, PlanKind::Relocation);
    assert_eq!(plan.plan().parts().physical_pc, base);
    assert_eq!(
        plan.plan().parts().displaced,
        AddressRange::new(base, 5).unwrap()
    );
    assert_eq!(plan.plan().parts().entries.resumes, entries.resumes);
    let routed: Vec<_> = plan
        .plan()
        .parts()
        .obligations
        .iter()
        .filter_map(|item| match item {
            EntryObligation::Routed(route) => Some(route.original),
            _ => None,
        })
        .collect();
    assert_eq!(
        routed,
        (1..5).map(|offset| base + offset).collect::<Vec<_>>()
    );
    let heads: Vec<_> = offsets.iter().map(|&offset| base + offset as u64).collect();
    let all: Vec<_> = heads.iter().copied().chain([native.return_pc()]).collect();
    let direct_map = TraceMap {
        boundaries: all.iter().map(|&pc| (pc, pc)).collect(),
        gateways: Vec::new(),
        generated_ranges: Vec::new(),
    };
    let image = plan.image();
    let mut installed_map = TraceMap {
        boundaries: Vec::new(),
        gateways: Vec::new(),
        generated_ranges: std::iter::once(
            image.address()..image.address() + image.bytes().len() as u64,
        )
        .collect(),
    };
    for &pc in &all {
        if plan.plan().parts().displaced.contains(pc) {
            let (_, relocated) = image
                .instruction_boundaries()
                .iter()
                .find(|(original, _)| *original == pc)
                .unwrap();
            installed_map.boundaries.push((pc, *relocated));
            installed_map.gateways.push(pc);
        } else {
            installed_map.boundaries.push((pc, pc));
        }
    }
    let signal = if saved_resume {
        Some(unsafe { SignalResume::new() })
    } else {
        None
    };
    let mut traces = Vec::new();
    for seed in SEEDS {
        for (index, &offset) in BODY_HEADS.iter().enumerate() {
            let tail: Vec<_> = BODY_HEADS[index..]
                .iter()
                .map(|&head| base + head as u64)
                .chain([native.return_pc()])
                .collect();
            let cases: Vec<(u64, Vec<u64>)> = if saved_resume {
                vec![(base + offset as u64, tail)]
            } else {
                let direct = base + (0x200 + index * 16) as u64;
                let table = base + (0x100 + index * 16) as u64;
                vec![
                    (base + offset as u64, tail.clone()),
                    (
                        direct,
                        std::iter::once(direct).chain(tail.clone()).collect(),
                    ),
                    (
                        table,
                        [table, table + 5]
                            .into_iter()
                            .chain(DISPATCH_HEADS.map(|pc| base + pc as u64))
                            .chain(tail)
                            .collect(),
                    ),
                ]
            };
            for (entry, expected) in cases {
                let trace = match &signal {
                    Some(signal) => native.trace_original_after_signal(
                        entry,
                        &heads,
                        &[native.return_pc()],
                        seed,
                        signal,
                    ),
                    None => native.trace_original(entry, &heads, &[native.return_pc()], seed),
                };
                assert_eq!(
                    trace.visits(),
                    expected,
                    "required incoming edge did not execute"
                );
                traces.push((entry, trace));
            }
        }
    }
    assert_eq!(traces.len(), if saved_resume { 14 } else { 42 });
    let expected_events: usize = traces
        .iter()
        .map(|(_, trace)| trace.visits().iter().filter(|&&pc| pc == base).count())
        .sum();
    assert_eq!(expected_events, if saved_resume { 2 } else { 6 });
    let pointer = native.code.writable();
    let (mut installed, receipt) = {
        let mut lease = unsafe { QuiescenceLease::new(&mut native, identity, vec![source]) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            plan.publish_with(pointer, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap()
    };
    assert_eq!(receipt.plan().parts().identity, identity);
    let edits = plan
        .plan()
        .parts()
        .writes
        .iter()
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect::<Vec<_>>();
    native.assert_publication(&edits);
    let events = [HookEvent {
        probe_id: ID,
        logical_pc: base,
    }];
    let log = HookEventLog::new();
    for (entry, trace) in &traces {
        let hooks = Some(HookExpectation {
            log: &log,
            enabled: &events,
        });
        match &signal {
            Some(signal) => native.assert_trace_after_signal(
                trace,
                *entry,
                &installed_map,
                &routed,
                hooks,
                signal,
            ),
            None => native.assert_trace(trace, *entry, &installed_map, &routed, hooks),
        }
    }
    {
        let mut ranges = vec![source];
        ranges.extend(
            plan.plan()
                .parts()
                .allocations
                .iter()
                .map(|item| item.range),
        );
        let mut lease = unsafe { QuiescenceLease::new(&mut native, identity, ranges) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap();
    }
    native.assert_publication(&[]);
    for (entry, trace) in &traces {
        match &signal {
            Some(signal) => {
                native.assert_trace_after_signal(trace, *entry, &direct_map, &[], None, signal)
            }
            None => native.assert_trace(trace, *entry, &direct_map, &[], None),
        }
    }
    if let Some(signal) = signal {
        assert_eq!(signal.completed_roundtrips(), 42);
    }
    println!(
        "entry_paths mode={} original={} installed={} retired={} hooks={} planning_refusals={} prepublication_saved_context_lifecycle=false",
        if saved_resume {
            "real-signal-resume"
        } else {
            "direct-and-all-table-cases"
        },
        traces.len(),
        traces.len(),
        traces.len(),
        if saved_resume { 2 } else { 6 },
        if saved_resume { 0 } else { 4 }
    );
}

#[test]
fn entry_paths_required_native_puzzles() {
    if let Ok(mode) = std::env::var(CHILD) {
        cycle(mode == "resume");
        return;
    }
    for mode in ["edges", "resume"] {
        let directory = std::env::temp_dir().join(format!(
            "liteinst-entry-paths-{}-{mode}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let output = |name| std::fs::File::create(directory.join(name)).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "entry_paths_required_native_puzzles",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, mode)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(output("stdout"))
            .stderr(output("stderr"));
        unsafe {
            command.pre_exec(|| {
                for (resource, value) in [
                    (libc::RLIMIT_CPU, 20),
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_FSIZE, 128 * 1024),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() >= Duration::from_secs(30) {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.wait();
                panic!(
                    "entry puzzle {mode} exceeded its 30-second wall budget; evidence {}",
                    directory.display()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = std::fs::read_to_string(directory.join("stdout")).unwrap();
        let stderr = std::fs::read_to_string(directory.join("stderr")).unwrap();
        assert!(
            status.success(),
            "entry puzzle {mode} failed: {status}; evidence {}\n{stdout}\n{stderr}",
            directory.display()
        );
        print!("{stdout}");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
