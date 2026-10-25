#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, LegalEntry,
    LegalEntrySet, PlanKind, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, ParkedPublication, TraceMap};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BODY: [u8; 11] = [0x90, 0x90, 0x90, 0x90, 0x90, 0xb8, 0x2a, 0, 0, 0, 0xc3];
const HEADS: [u64; 7] = [0, 1, 2, 3, 4, 5, 10];
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const ID: u64 = 0xe002;
const CHILD: &str = "LITEINST_PARKED_CONTEXT_CHILD";

unsafe extern "C" fn observe(context: *mut HookContext) {
    unsafe { oracle::record_hook_event(ID, (*context).instruction_pointer) };
}

fn cohort() {
    let native = NativeOracle::new(&BODY);
    let base = native.code.address();
    let heads: Vec<_> = HEADS.into_iter().map(|offset| base + offset).collect();
    let mut originals = 0;
    let mut publications = 0;
    let mut roundtrips = 0;
    let mut hooks = 0;
    let mut routed_resumes = 0;
    for seed in SEEDS {
        for (index, &entry) in heads.iter().enumerate() {
            let identity = CodeIdentity {
                source: SourceIdentity([0xe2; 32]),
                mapping: publications + 1,
                generation: 1,
            };
            let body = AddressRange::new(base, BODY.len()).unwrap();
            let entries = LegalEntrySet {
                identity,
                scope: body,
                provenance: EntryProvenance::Declared(
                    "fixture-owned full body; one live prepublication signal frame".into(),
                ),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: heads
                    .iter()
                    .map(|&address| LegalEntry {
                        address,
                        requires_endbr: false,
                    })
                    .collect(),
                resumes: ResumeObligation::Enumerated(heads.clone()),
            };
            let mut allocation = AllocationPolicy::near(base).unwrap();
            allocation.preferred_address = Some(base + 64 * 1024 * 1024);
            assert_eq!(
                (
                    allocation.max_candidates,
                    allocation.max_mappings,
                    allocation.max_mapped_bytes
                ),
                (256, 1, 8192)
            );
            let plan = plan_install(&InstallRequest {
                identity,
                code: &BODY,
                base_address: base,
                function: body,
                block: body,
                logical_pc: base,
                entries: &entries,
                hook: observe,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_sites: 1,
                    max_displaced_bytes: 5,
                },
            })
            .expect("every parked-context case must plan and publish");
            assert_eq!(plan.plan().parts().kind, PlanKind::Relocation);
            assert_eq!(plan.plan().parts().physical_pc, base);
            assert_eq!(
                plan.plan().parts().displaced,
                AddressRange::new(base, 5).unwrap()
            );
            assert_eq!(
                plan.plan().parts().entries.resumes,
                ResumeObligation::Enumerated(heads.clone())
            );
            let routed: Vec<_> = plan
                .plan()
                .parts()
                .obligations
                .iter()
                .filter_map(|obligation| {
                    if let EntryObligation::Routed(route) = obligation {
                        Some(route.original)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(
                routed,
                (1..5).map(|offset| base + offset).collect::<Vec<_>>()
            );

            let original = native.trace_original(entry, &heads, &[native.return_pc()], seed);
            let expected: Vec<_> = heads[index..]
                .iter()
                .copied()
                .chain([native.return_pc()])
                .collect();
            assert_eq!(
                original.visits(),
                expected,
                "original itinerary must not skip a declared head"
            );
            originals += 1;
            let image = plan.image();
            let mut map = TraceMap {
                boundaries: Vec::new(),
                gateways: Vec::new(),
                generated_ranges: std::iter::once(
                    image.address()..image.address() + image.bytes().len() as u64,
                )
                .collect(),
            };
            for pc in heads.iter().copied().chain([native.return_pc()]) {
                if plan.plan().parts().displaced.contains(pc) {
                    let (_, relocated) = image
                        .instruction_boundaries()
                        .iter()
                        .find(|(original, _)| *original == pc)
                        .unwrap();
                    map.boundaries.push((pc, *relocated));
                    map.gateways.push(pc);
                } else {
                    map.boundaries.push((pc, pc));
                }
            }
            let events = [HookEvent {
                probe_id: ID,
                logical_pc: base,
            }];
            let log = HookEventLog::new();
            // The parent retains the immutable plan/control through the trace.
            // Only its single-threaded fork child publishes while its real
            // signal frame is gated. The parent's source stays original.
            let parked = unsafe { ParkedPublication::new(&plan, &native.code) };
            native.assert_trace_parked_publication(
                &original,
                entry,
                &map,
                &routed,
                Some(HookExpectation {
                    log: &log,
                    enabled: &events,
                }),
                &parked,
            );
            assert_eq!(parked.completed_roundtrips(), 1);
            publications += 1;
            roundtrips += parked.completed_roundtrips();
            hooks += usize::from(entry == base);
            routed_resumes += usize::from(routed.contains(&entry));
            native.assert_publication(&[]);
        }
    }
    assert_eq!(
        (originals, publications, roundtrips, hooks, routed_resumes),
        (14, 14, 14, 2, 8)
    );
    println!(
        "parked_context originals=14 child_publications=14 unchanged_frames=14 real_rt_sigreturns=14 installed_traces=14 hook_events=2 routed_resumes=8 retirement_claim=false"
    );
}

#[test]
fn prepublication_parked_context_required_native_puzzles() {
    if let Ok(mode) = std::env::var(CHILD) {
        assert_eq!(mode, "cohort");
        cohort();
        return;
    }
    let directory =
        std::env::temp_dir().join(format!("liteinst-parked-context-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let output = |name| std::fs::File::create(directory.join(name)).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "prepublication_parked_context_required_native_puzzles",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "cohort")
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
                "parked-context cohort exceeded 30 seconds; evidence {}",
                directory.display()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = std::fs::read_to_string(directory.join("stdout")).unwrap();
    let stderr = std::fs::read_to_string(directory.join("stderr")).unwrap();
    assert!(
        status.success(),
        "parked-context cohort failed: {status}; evidence {}\n{stdout}\n{stderr}",
        directory.display()
    );
    print!("{stdout}");
    std::fs::remove_dir_all(directory).unwrap();
}
