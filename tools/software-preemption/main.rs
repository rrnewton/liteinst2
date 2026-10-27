//! Standalone finite-corpus software preemption; no Hermit or PMU dependency.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]
mod corpus;
mod counter;

use corpus::{CASES, Case, Site};
use counter::{Mode, ResultRow, Run};
use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, InstalledOnce, SearchPolicy, TacticPolicy,
    plan_coalesced_detailed,
};
use std::path::Path;

// Mappings are process-lived even on failure. An unjoined worker can never
// observe Rust unwinding freeing its source/images. Normal retirement occurs
// explicitly only after run() has joined its worker and callback state.
struct Mapping {
    address: u64,
    original: Vec<u8>,
}
impl Mapping {
    fn new(bytes: &[u8]) -> Self {
        assert!(!bytes.is_empty() && bytes.len() <= 4096);
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "source mapping");
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), p.cast(), bytes.len()) };
        let result = Self {
            address: p as usize as u64,
            original: bytes.to_vec(),
        };
        result.protect(libc::PROT_READ | libc::PROT_EXEC).unwrap();
        result
    }
    fn protect(&self, flags: i32) -> Result<(), Refusal> {
        if unsafe { libc::mprotect(self.address as usize as *mut libc::c_void, 4096, flags) } != 0 {
            return Err(Refusal::Backend(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(())
    }
    fn bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.address as usize as *const u8, self.original.len())
        }
    }
}
struct Program {
    native: Mapping,
    candidate: Mapping,
    site: Site,
    identity: CodeIdentity,
    control: ProbeControl,
    installed: Option<InstalledOnce>,
    ranges: Vec<AddressRange>,
}
impl Drop for Program {
    fn drop(&mut self) {
        // This is retention, not a drain or successful cleanup claim.
        if let Some(installed) = self.installed.take() {
            std::mem::forget(installed);
        }
    }
}
fn single_main() {
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(std::process::id())
    );
    assert_eq!(
        std::fs::read_dir("/proc/self/task").unwrap().count(),
        1,
        "publication only before worker creation or after exact join"
    );
}
impl Program {
    fn new(case: Case) -> Self {
        single_main();
        let bytes = case.bytes();
        let native = Mapping::new(&bytes);
        let candidate = Mapping::new(&bytes);
        assert_eq!(native.bytes(), candidate.bytes());
        let base = candidate.address;
        let site = corpus::admit(&bytes, base).expect("whole authored function admission");
        let identity = CodeIdentity {
            source: SourceIdentity([case as u8 + 1; 32]),
            mapping: base,
            generation: 1,
        };
        let scope = AddressRange::new(base, bytes.len()).unwrap();
        let entries = LegalEntrySet { identity,scope,provenance:EntryProvenance::Declared("complete decoded heads of private authored call-free function; no external entry or saved resume".into()),completeness:EntryCompleteness::Complete,
            entries:site.heads.iter().map(|&address| LegalEntry { address,requires_endbr:false }).collect(),resumes:ResumeObligation::NoneExist };
        let (control, writer) = ProbeControl::new_managed_bound(counter::hook, true);
        drop(writer); // This admitted branch is never silently disabled.
        let pc = base + site.offset as u64;
        let allocation = AllocationPolicy::near(pc).unwrap();
        assert_eq!(
            (
                allocation.max_candidates,
                allocation.max_mappings,
                allocation.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        let planned = plan_coalesced_detailed(
            &InstallRequest {
                identity,
                code: &bytes,
                base_address: base,
                function: scope,
                block: AddressRange::new(pc, site.length).unwrap(),
                logical_pc: pc,
                entries: &entries,
                hook: unused_hook,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 15,
                    max_sites: 1,
                },
            },
            &[ControlledAction {
                logical_pc: pc,
                control: control.clone(),
            }],
        )
        .expect("required real branch instrumentation refused");
        assert_eq!(planned.plan().parts().kind, PlanKind::Relocation);
        assert_eq!(planned.plan().parts().physical_pc, pc);
        assert_eq!(
            planned.plan().parts().displaced,
            AddressRange::new(pc, site.length).unwrap()
        );
        assert!(!planned.plan().parts().requirements.sigill_router);
        assert!(
            planned
                .plan()
                .parts()
                .obligations
                .iter()
                .all(|o| matches!(o, EntryObligation::Preserved(_)))
        );
        assert_eq!(planned.image().controls(), std::slice::from_ref(&control));
        let ranges: Vec<_> = planned
            .plan()
            .parts()
            .dependencies
            .iter()
            .copied()
            .chain(planned.plan().parts().allocations.iter().map(|a| a.range))
            .collect();
        candidate
            .protect(libc::PROT_READ | libc::PROT_WRITE)
            .unwrap();
        let mut result = Self {
            native,
            candidate,
            site,
            identity,
            control,
            installed: None,
            ranges,
        };
        let (installed, receipt) = {
            // SAFETY: this exclusive program owns the entire private source,
            // complete heads and no resumes; only the current main thread exists.
            // No callable pointer is handed to a worker until the final RX store,
            // exact publisher checks and this lease have completed.
            let address = result.candidate.address;
            let mut lease =
                unsafe { QuiescenceLease::new(&mut result, identity, result_ranges(&planned)) };
            let publication = unsafe {
                planned.publish_with(address as usize as *mut u8, &mut lease, || {
                    if libc::mprotect(
                        address as usize as *mut libc::c_void,
                        4096,
                        libc::PROT_READ | libc::PROT_EXEC,
                    ) != 0
                    {
                        return Err(Refusal::Backend(
                            std::io::Error::last_os_error().to_string(),
                        ));
                    }
                    Ok(())
                })
            }
            .expect("publication failure is fatal, never native eligibility");
            assert!(!lease.is_poisoned());
            publication
        };
        assert_eq!(receipt.plan(), planned.plan());
        assert_eq!(installed.plan(), planned.plan());
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    planned.image().address() as usize as *const u8,
                    planned.image().bytes().len(),
                )
            },
            planned.image().bytes()
        );
        let mut expected = bytes;
        for edit in &planned.plan().parts().writes {
            let offset = usize::try_from(edit.address - base).unwrap();
            expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        assert_eq!(result.candidate.bytes(), expected);
        assert_eq!(result.native.bytes(), result.native.original);
        result.installed = Some(installed);
        result
    }
    fn run(&self, mode: Mode, n: u64, rounds: u64, quantum: u64, hold: bool) -> ResultRow {
        counter::run(Run {
            entry: if mode == Mode::Native {
                self.native.address
            } else {
                self.candidate.address
            },
            site: self.candidate.address + self.site.offset as u64,
            offset: self.site.offset as u64,
            condition: self.site.condition,
            control: &self.control,
            mode,
            quantum,
            n,
            rounds,
            check_parked: hold,
        })
    }
    fn retire(&mut self) {
        single_main();
        let mut installed = self.installed.take().unwrap();
        self.candidate
            .protect(libc::PROT_READ | libc::PROT_WRITE)
            .unwrap();
        let page = self.candidate.address;
        let ranges = self.ranges.clone();
        let identity = self.identity;
        let outcome = {
            // SAFETY: every worker is joined and main is again the only thread;
            // no source/generated invocation or saved application context exists.
            let mut lease = unsafe { QuiescenceLease::new(self, identity, ranges) };
            let outcome = unsafe {
                installed.retire_with(&mut lease, || {
                    if libc::mprotect(
                        page as usize as *mut libc::c_void,
                        4096,
                        libc::PROT_READ | libc::PROT_EXEC,
                    ) != 0
                    {
                        return Err(Refusal::Backend("retirement RX".into()));
                    }
                    Ok(())
                })
            };
            if outcome.is_ok() {
                assert!(!lease.is_poisoned());
            }
            outcome
        };
        if outcome.is_err() {
            std::mem::forget(installed);
            panic!("retirement failed; no successful result");
        }
        assert!(installed.is_retired());
        assert_eq!(self.candidate.bytes(), self.candidate.original);
        assert_eq!(self.native.bytes(), self.native.original);
        // Retain all executable/control owners through process exit after proof.
        std::mem::forget(installed);
    }
}
fn result_ranges(p: &liteinst2::quiescent::PlannedInstall) -> Vec<AddressRange> {
    p.plan()
        .parts()
        .dependencies
        .iter()
        .copied()
        .chain(p.plan().parts().allocations.iter().map(|a| a.range))
        .collect()
}
unsafe extern "C" fn unused_hook(_: *mut liteinst2::trampoline::HookContext) {
    unsafe { libc::_exit(123) }
}

fn validate(case: Case, mode: Mode, n: u64, rounds: u64, quantum: u64, r: &ResultRow) {
    let (value, words, edges, encounters) = case.expected(n);
    assert_eq!(r.checksum, value * rounds);
    let mut expected = [0x5a5a_5a5a_5a5a_5a5a; 512];
    expected[..3].copy_from_slice(&words);
    assert_eq!(r.memory, expected, "complete native result page/canaries");
    assert_eq!(
        r.counted,
        if mode == Mode::Native {
            0
        } else {
            edges * rounds
        }
    );
    assert_eq!(
        r.encounters,
        if mode == Mode::Native {
            0
        } else {
            encounters * rounds
        }
    );
    assert_eq!(
        r.stops.len() as u64,
        if mode == Mode::Stop {
            edges * rounds / quantum
        } else {
            0
        }
    );
    for stop in &r.stops {
        assert_eq!(stop.count % quantum, 0);
        assert_eq!(
            stop.encounters,
            stop.count
                + if case == Case::Direct {
                    0
                } else {
                    (stop.count - 1) / edges
                },
            "untaken terminal branches are encounters, never clock edges"
        );
        let iteration = (stop.count - 1) % edges + 1;
        let acc = if case == Case::Unsigned {
            3 * iteration
        } else {
            iteration * (2 * n - iteration + 1) / 2
        };
        let remaining = if case == Case::Unsigned {
            iteration
        } else {
            n - iteration
        };
        assert_eq!(
            stop.words,
            [acc, remaining, iteration],
            "independent BEFORE-edge arithmetic"
        );
        assert_eq!(
            [stop.registers[16], stop.registers[15], stop.registers[14]],
            stop.words,
            "actual saved RAX/RCX/RDX"
        );
        assert!(corpus::taken(
            match case {
                Case::Countdown => Some(5),
                Case::Signed => Some(15),
                Case::Unsigned => Some(2),
                Case::Direct => None,
            },
            stop.registers[17]
        ));
    }
}
fn stop_keys(r: &ResultRow) -> Vec<(u64, u64, u64, [u64; 3], u64)> {
    r.stops
        .iter()
        .map(|s| {
            (
                s.site,
                s.count,
                s.encounters,
                s.words,
                s.registers[17] & 0x8d5,
            )
        })
        .collect()
}
fn condition_controls() -> usize {
    // Independent hardware SETcc, not the software predicate's truth table.
    // POPFQ changes only the five arithmetic flags tested; no TF/DF/AC bits.
    let mut count = 0;
    for cc in 0u8..16 {
        let code = [0x57, 0x9d, 0x0f, 0x90 | cc, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3];
        let map = Mapping::new(&code);
        let f: unsafe extern "C" fn(u64) -> u64 =
            unsafe { std::mem::transmute(map.address as usize) };
        for bits in 0u64..32 {
            let flags = 2
                | (bits & 1)
                | ((bits >> 1 & 1) << 2)
                | ((bits >> 2 & 1) << 6)
                | ((bits >> 3 & 1) << 7)
                | ((bits >> 4 & 1) << 11);
            assert_eq!(
                unsafe { f(flags) },
                u64::from(corpus::taken(Some(cc), flags)),
                "SETcc {cc}/{bits}"
            );
            count += 1;
        }
    }
    assert_eq!(count, 512);
    count
}
fn qualify(output: &Path) {
    let conditions = condition_controls();
    let mut rows = String::from(
        "case,n,quantum,repeat,taken_edges,branch_encounters,stops,parked_checks,checksum\n",
    );
    let mut events = String::from(
        "case,n,quantum,repeat,logical_site_offset,counted_taken_edges,branch_encounters,rax,rcx,rdx,arithmetic_flags\n",
    );
    let mut cells = 0;
    let mut parked = 0;
    for case in CASES {
        let mut program = Program::new(case);
        for n in [1, 2, 7, 17] {
            let native = program.run(Mode::Native, n, 1, 1, false);
            validate(case, Mode::Native, n, 1, 1, &native);
            let counted = program.run(Mode::Counter, n, 1, 1, false);
            validate(case, Mode::Counter, n, 1, 1, &counted);
            assert_eq!(
                (native.checksum, native.memory),
                (counted.checksum, counted.memory)
            );
            for quantum in [1, 3, 7] {
                let mut previous = None;
                for repeat in 0..2 {
                    let actual = program.run(Mode::Stop, n, 1, quantum, true);
                    validate(case, Mode::Stop, n, 1, quantum, &actual);
                    assert_eq!(
                        (native.checksum, native.memory),
                        (actual.checksum, actual.memory)
                    );
                    let keys = stop_keys(&actual);
                    if let Some(ref old) = previous {
                        assert_eq!(&keys, old, "complete repeated deterministic stop sequence");
                    }
                    previous = Some(keys);
                    assert_eq!(actual.parked_checks, actual.stops.len());
                    parked += actual.parked_checks;
                    for event in &actual.stops {
                        events.push_str(&format!(
                            "{},{n},{quantum},{repeat},{},{},{},{},{},{},{}\n",
                            case.name(),
                            event.site,
                            event.count,
                            event.encounters,
                            event.words[0],
                            event.words[1],
                            event.words[2],
                            event.registers[17] & 0x8d5
                        ));
                    }
                    rows.push_str(&format!(
                        "{},{n},{quantum},{repeat},{},{},{},{},{}\n",
                        case.name(),
                        actual.counted,
                        actual.encounters,
                        actual.stops.len(),
                        actual.parked_checks,
                        actual.checksum
                    ));
                    cells += 1;
                }
            }
        }
        program.retire();
    }
    assert_eq!(cells, 96);
    assert_eq!(parked, 256);
    std::fs::write(output.join("qualification.csv"), rows).unwrap();
    std::fs::write(output.join("stops.csv"), events).unwrap();
    std::fs::write(output.join("summary.json"),format!("{{\"scope\":\"finite-before-taken-backedge\",\"stop_cells\":96,\"native_cells\":16,\"counter_cells\":16,\"condition_controls\":{conditions},\"parked_checks\":{parked},\"deterministic_repeats\":48,\"status\":\"PASS\"}}\n")).unwrap();
    println!("preemption:qualify:96-stop-cells:16-native:16-counter:512-setcc:48-exact-repeats");
}
fn benchmark(case: Case, output: &Path) {
    let mut program = Program::new(case);
    let mut csv = String::from(
        "case,mode,phase,repetition,n,rounds,work_units,elapsed_ns,checksum,taken_edges,branch_encounters,stops\n",
    );
    for mode in [Mode::Native, Mode::Counter, Mode::Stop] {
        for repetition in 0..9 {
            let actual = program.run(mode, 256, 128, 64, false);
            validate(case, mode, 256, 128, 64, &actual);
            assert_eq!(
                actual.parked_checks, 0,
                "no deliberate pause in throughput measurement"
            );
            let phase = if repetition < 2 { "warmup" } else { "measured" };
            csv.push_str(&format!(
                "{},{},{phase},{repetition},256,128,32768,{},{},{},{},{}\n",
                case.name(),
                mode.name(),
                actual.elapsed_ns,
                actual.checksum,
                actual.counted,
                actual.encounters,
                actual.stops.len()
            ));
        }
    }
    program.retire();
    std::fs::write(output.join("measurements.csv"), csv).unwrap();
    println!(
        "preemption:benchmark:{}:27-rows:2-warmups:7-measured:equal-work",
        case.name()
    );
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(args.len() == 3 || args.len() == 4);
    single_main();
    let output = std::path::PathBuf::from(args.last().unwrap());
    assert!(output.is_absolute() && !output.exists());
    std::fs::create_dir(&output).unwrap();
    assert_eq!(output.canonicalize().unwrap(), output);
    match args[1].as_str() {
        "qualify" if args.len() == 3 => qualify(&output),
        "bench" if args.len() == 4 => benchmark(Case::parse(&args[2]), &output),
        _ => panic!("usage: liteinst-preempt qualify NEW_OUTPUT | bench CASE NEW_OUTPUT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn whole_authored_corpus_has_one_exact_near_backward_site() {
        for case in CASES {
            let bytes = case.bytes();
            let s = corpus::admit(&bytes, 0x10000).unwrap();
            assert_eq!(s.length, if case == Case::Direct { 5 } else { 6 });
            assert!(s.heads.contains(&(0x10000 + s.offset as u64)));
        }
    }
    #[test]
    fn unsupported_backedge_and_call_are_refused_before_publication() {
        assert!(corpus::admit(&[0xeb, 0xfe, 0xc3], 0x10000).is_err());
        assert!(corpus::admit(&[0xe8, 0, 0, 0, 0, 0xc3], 0x10000).is_err());
        assert!(corpus::admit(&[0xff, 0xe0], 0x10000).is_err());
        assert!(corpus::admit(&[0x90, 0xc3], 0x10000).is_err());
    }
}
