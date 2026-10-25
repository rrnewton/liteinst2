#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Forced and preferred engine outcomes, exercised through its returned bundle.

use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
use liteinst2::contracts::*;
use liteinst2::engine::{
    self, CandidateEvidence, EnginePlan, EnginePolicy, SelectedMetrics, Tactic,
};
use liteinst2::eviction;
use liteinst2::neighbor::{self, NeighborSearch};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{self, AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy};
use liteinst2::trampoline::HookContext;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const PAD: usize = 16;
const SELECTED_OFFSET: usize = 128;
const VALUE: u64 = 42;
const ENV: &str = "LITEINST_TACTIC_ENGINE_CHILD";
const TEST: &str = "tactic_engine_required_puzzles";
static CALLBACKS: AtomicU64 = AtomicU64::new(0);
static LAST_PC: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the emitter passes its initialized live frame.
    LAST_PC.store(unsafe { (*context).instruction_pointer }, Ordering::Relaxed);
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
enum Shape {
    Long,
    Generalized,
    Prefixed,
    Successor,
    Neighbor,
}

struct Fixture {
    write: *mut u8,
    execute: *mut u8,
    original: Vec<u8>,
    mapping: Vec<u8>,
    body_len: usize,
    block_len: usize,
    heads: Vec<usize>,
    identity: CodeIdentity,
    shape: Shape,
}

impl Fixture {
    fn new(case: u64, shape: Shape) -> Self {
        let (mut body, block_len, heads) = match shape {
            Shape::Long => (vec![0xb8, 42, 0, 0, 0, 0xc3], 6, vec![0, 5]),
            Shape::Generalized => (
                vec![0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3],
                9,
                vec![0, 3, 8],
            ),
            Shape::Prefixed => (vec![0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3], 8, vec![0, 2, 7]),
            Shape::Successor => (
                vec![
                    0x0f, 0x1f, 0, // selected three-byte NOP
                    0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, // whole eight-byte victim
                    0xb8, 42, 0, 0, 0, 0xc3,
                ],
                17,
                vec![0, 3, 11, 16, 64, 74],
            ),
            Shape::Neighbor => (
                // Natural two-byte conditional block; both successors reach RET.
                // Immediate successor is one NOP, too short for T2.
                vec![0x75, 1, 0x90, 0xc3],
                2,
                vec![0, 2, 3, 64, 74],
            ),
        };
        if matches!(shape, Shape::Successor | Shape::Neighbor) {
            body.resize(64, 0x90);
            body.extend_from_slice(&[0x48, 0xb8]);
            body.extend_from_slice(&VALUE.to_le_bytes());
            body.push(0xc3);
        }
        let body_len = body.len();
        let mut original = vec![0x90; PAD];
        original.extend_from_slice(&body);
        let mut mapping = vec![0xa5; 2 * PAGE];
        mapping[SELECTED_OFFSET - PAD..SELECTED_OFFSET - PAD + original.len()]
            .copy_from_slice(&original);
        let address = 0x4200_0000_0000_u64 + case * 0x2_0000_0000;
        // SAFETY: each bounded child exclusively owns both new exact aliases.
        let (write, execute) = unsafe {
            let fd = libc::memfd_create(c"tactic-engine-contract".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, (2 * PAGE) as libc::off_t), 0);
            let write = libc::mmap(
                std::ptr::null_mut(),
                2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            let execute = libc::mmap(
                address as *mut _,
                2 * PAGE,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                fd,
                0,
            );
            assert_ne!(write, libc::MAP_FAILED);
            assert_eq!(execute as usize as u64, address);
            assert_eq!(libc::close(fd), 0);
            std::ptr::copy_nonoverlapping(mapping.as_ptr(), write.cast(), 2 * PAGE);
            (write.cast(), execute.cast())
        };
        Self {
            write,
            execute,
            original,
            mapping,
            body_len,
            block_len,
            heads,
            identity: CodeIdentity {
                source: SourceIdentity([case as u8; 32]),
                mapping: case + 1,
                generation: 1,
            },
            shape,
        }
    }

    fn selected(&self) -> u64 {
        self.execute as usize as u64 + SELECTED_OFFSET as u64
    }

    fn base(&self) -> u64 {
        self.selected() - PAD as u64
    }

    fn source(&self) -> AddressRange {
        AddressRange::new(self.base(), self.original.len()).unwrap()
    }

    fn entries(&self) -> LegalEntrySet {
        LegalEntrySet {
            identity: self.identity,
            scope: AddressRange::new(self.selected(), self.body_len).unwrap(),
            provenance: EntryProvenance::Declared("private engine puzzle entries".into()),
            // Filler after the original RETs has no permitted external entry.
            // These engine tests do not claim the leaf oracle's all-head corpus.
            completeness: EntryCompleteness::Complete,
            entries: self
                .heads
                .iter()
                .map(|offset| LegalEntry {
                    address: self.selected() + *offset as u64,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        }
    }

    fn selected_allocation(&self) -> AllocationPolicy {
        let s = self.selected();
        let target = match self.shape {
            Shape::Long | Shape::Neighbor => s + 0x400_0000,
            // Original successor bytes B8,2A fix the high displacement bytes.
            Shape::Generalized => s + 5 + 0x2ab8_0000 + 0x8000,
            // One CS prefix consumes B8,2A,00,00 as the complete displacement.
            Shape::Prefixed => s + 6 + 0x2ab8,
            // Victim E9 followed by 56 fixes the selected B2 high bytes.
            Shape::Successor => s + 5 + 0x56e9_0000 + 0x8000,
        };
        let mut policy = AllocationPolicy::near(s).unwrap();
        policy.preferred_address = Some(target);
        if !matches!(self.shape, Shape::Generalized) {
            policy.ranges = vec![AddressRange::new(target & !4095, 8192).unwrap()];
        }
        policy
    }

    fn victim_allocation(&self) -> AllocationPolicy {
        let target = match self.shape {
            Shape::Successor => self.selected() + 3 + 5 + 0x0012_3456,
            _ => self.selected() + 0x600_0000,
        };
        let mut policy = AllocationPolicy::near(self.selected()).unwrap();
        policy.preferred_address = Some(target);
        policy.ranges = vec![AddressRange::new(target & !4095, 8192).unwrap()];
        policy
    }

    fn request<'a>(
        &'a self,
        entries: &'a LegalEntrySet,
        allocation: &'a AllocationPolicy,
    ) -> InstallRequest<'a> {
        InstallRequest {
            identity: self.identity,
            code: &self.original,
            base_address: self.base(),
            function: entries.scope,
            block: AddressRange::new(self.selected(), self.block_len).unwrap(),
            logical_pc: self.selected(),
            entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation,
            search: SearchPolicy {
                // The engine must override this for every forced single leaf.
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        }
    }

    fn policy(&self, forced: Option<Tactic>) -> EnginePolicy {
        EnginePolicy {
            forced,
            neighbor: NeighborSearch {
                forced_victim: Some(self.selected() + 64),
                ..NeighborSearch::default()
            },
            ..EnginePolicy::default()
        }
    }

    fn plan(&self, policy: EnginePolicy) -> Result<EnginePlan, engine::EngineFailure> {
        engine::plan(
            &self.request(&self.entries(), &self.selected_allocation()),
            &self.victim_allocation(),
            policy,
        )
    }

    fn leaf(&self, tactic: Tactic) -> Result<PlannedBundle, Refusal> {
        let entries = self.entries();
        let allocation = self.selected_allocation();
        let mut request = self.request(&entries, &allocation);
        match tactic {
            Tactic::GeneralizedPun | Tactic::Relocation | Tactic::PrefixedPun => {
                request.search.tactics = match tactic {
                    Tactic::GeneralizedPun => TacticPolicy::GeneralizedPunOnly,
                    Tactic::Relocation => TacticPolicy::RelocationOnly,
                    Tactic::PrefixedPun => TacticPolicy::PrefixPunOnly,
                    _ => unreachable!(),
                };
                let member = quiescent::plan_install(&request)?;
                PlannedBundle::compose(
                    vec![ExpectedBytes {
                        address: self.base(),
                        bytes: self.original.clone(),
                    }],
                    vec![member],
                    BundleBudget::default(),
                )
            }
            Tactic::SuccessorEviction => {
                request.search.tactics = TacticPolicy::PreferGeneralizedPun;
                eviction::plan_successor(
                    &request,
                    &self.victim_allocation(),
                    BundleBudget::default(),
                )
                .map(|plan| plan.bundle().clone())
            }
            Tactic::NeighborEviction => neighbor::plan_neighbor(
                &request,
                &self.victim_allocation(),
                self.policy(None).neighbor,
                BundleBudget::default(),
            )
            .map(|plan| plan.bundle().clone()),
        }
    }

    fn observed(&self) -> Vec<u8> {
        // SAFETY: no application execution or other writer runs during checks.
        unsafe { std::slice::from_raw_parts(self.write, 2 * PAGE) }.to_vec()
    }

    fn permissions(&self, executable: bool) -> Result<(), Refusal> {
        let protection = libc::PROT_READ | if executable { libc::PROT_EXEC } else { 0 };
        // SAFETY: this fixture exclusively owns the complete executable alias.
        if unsafe { libc::mprotect(self.execute.cast(), 2 * PAGE, protection) } == 0 {
            Ok(())
        } else {
            Err(Refusal::Backend(
                std::io::Error::last_os_error().to_string(),
            ))
        }
    }

    fn calls(&self, installed: bool) {
        let before = CALLBACKS.load(Ordering::Relaxed);
        for offset in &self.heads {
            let actual: u64;
            // SAFETY: each declared head terminates at a genuine RET. RAX is
            // initialized for bare RET and no live lease admits these calls.
            unsafe {
                core::arch::asm!("call r11", in("r11") self.selected() + *offset as u64,
                    inlateout("rax") VALUE => actual, clobber_abi("C"));
            }
            assert_eq!(actual, VALUE);
            assert_eq!(
                CALLBACKS.load(Ordering::Relaxed),
                before + u64::from(installed)
            );
            if installed {
                assert_eq!(LAST_PC.load(Ordering::Relaxed), self.selected());
            }
        }
    }

    fn execute(&self, plan: &EnginePlan) {
        let bundle = plan.bundle();
        self.permissions(true).unwrap();
        self.calls(false);
        self.permissions(false).unwrap();
        // SAFETY: both aliases have the same backing and stay owned until after
        // retirement. Neither mapping is simultaneously writable and executable.
        let alias = unsafe {
            WritableAlias::new(
                AddressRange::new(self.execute as usize as u64, 2 * PAGE).unwrap(),
                self.write,
            )
        }
        .unwrap();
        let mut installed = {
            let mut guard = ();
            // SAFETY: this private child is the sole owner of source execution,
            // saved continuations, writable aliases and the complete generation.
            let mut lease =
                unsafe { QuiescenceLease::new(&mut guard, self.identity, vec![self.source()]) };
            let (installed, receipt) =
                unsafe { bundle.publish_with(&[alias], &mut lease, || self.permissions(true)) }
                    .expect("required engine-bundle publication refused");
            assert_eq!(receipt.plan().steps(), bundle.plan().steps());
            assert!(!lease.is_poisoned());
            installed
        };
        let mut expected = self.mapping.clone();
        for snapshot in bundle.plan().final_bytes() {
            let offset = (snapshot.address - self.execute as usize as u64) as usize;
            expected[offset..offset + snapshot.bytes.len()].copy_from_slice(&snapshot.bytes);
        }
        assert_eq!(self.observed(), expected);
        self.calls(true);
        self.permissions(false).unwrap();
        {
            let mut ranges = vec![self.source()];
            ranges.extend(bundle.plan().steps().iter().flat_map(|step| {
                step.parts()
                    .allocations
                    .iter()
                    .map(|allocation| allocation.range)
            }));
            let mut guard = ();
            // SAFETY: the fresh gate drains every original/generated execution
            // and saved reference before reverse-store retirement.
            let mut lease = unsafe { QuiescenceLease::new(&mut guard, self.identity, ranges) };
            unsafe { installed.retire_with(&mut lease, || self.permissions(true)) }.unwrap();
            assert!(!lease.is_poisoned());
        }
        assert!(installed.is_retired());
        assert_eq!(self.observed(), self.mapping);
        self.calls(false);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: every installed bundle is retired before fixture destruction.
        unsafe {
            assert_eq!(libc::munmap(self.write.cast(), 2 * PAGE), 0);
            assert_eq!(libc::munmap(self.execute.cast(), 2 * PAGE), 0);
        }
    }
}

fn assert_leaf_equal(engine: &EnginePlan, leaf: &PlannedBundle) {
    let bundle = engine.bundle();
    assert_eq!(bundle.plan().identity(), leaf.plan().identity());
    assert_eq!(bundle.plan().originals(), leaf.plan().originals());
    assert_eq!(bundle.plan().final_bytes(), leaf.plan().final_bytes());
    assert_eq!(bundle.plan().steps(), leaf.plan().steps());
    assert_eq!(bundle.plan().locks(), leaf.plan().locks());
    assert_eq!(bundle.plan().memory(), leaf.plan().memory());
    assert_eq!(bundle.images().len(), leaf.images().len());
    for (actual, expected) in bundle.images().iter().zip(leaf.images()) {
        assert_eq!(actual.address(), expected.address());
        assert_eq!(actual.bytes(), expected.bytes());
        assert_eq!(actual.entry_routes(), expected.entry_routes());
        assert_eq!(
            actual.instruction_boundaries(),
            expected.instruction_boundaries()
        );
        assert_eq!(
            actual.program_counter_mappings(),
            expected.program_counter_mappings()
        );
    }
    match (engine.tactic(), engine.metrics()) {
        (Tactic::SuccessorEviction, SelectedMetrics::Successor(metrics)) => {
            assert_eq!(metrics.victim_fallthrough_redirects, 2);
        }
        (Tactic::NeighborEviction, SelectedMetrics::Neighbor(geometry, metrics)) => {
            assert_eq!(geometry.relay, geometry.victim + 5);
            assert_eq!(metrics.selected_fallthrough_redirects, 3);
            assert_eq!(metrics.victim_fallthrough_redirects, 2);
        }
        (
            Tactic::GeneralizedPun | Tactic::Relocation | Tactic::PrefixedPun,
            SelectedMetrics::Single(metrics),
        ) => assert_eq!(metrics.attempts.last().unwrap().refusal, None),
        other => panic!("winning metric kind disagrees with tactic: {other:?}"),
    }
}

fn forced() {
    let cases = [
        (Shape::Generalized, Tactic::GeneralizedPun),
        (Shape::Long, Tactic::Relocation),
        (Shape::Prefixed, Tactic::PrefixedPun),
        (Shape::Successor, Tactic::SuccessorEviction),
        (Shape::Neighbor, Tactic::NeighborEviction),
    ];
    let mut calls = 0;
    for (case, (shape, tactic)) in cases.into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, shape);
        let leaf = fixture.leaf(tactic).expect("required forced leaf refused");
        let planned = fixture
            .plan(fixture.policy(Some(tactic)))
            .expect("required forced engine tactic refused");
        assert_eq!(planned.tactic(), tactic);
        assert_eq!(planned.attempts().len(), 1);
        assert_eq!(planned.attempts()[0].tactic, tactic);
        assert_eq!(planned.attempts()[0].refusal, None);
        assert_leaf_equal(&planned, &leaf);
        assert_eq!(fixture.observed(), fixture.mapping);
        calls += fixture.heads.len() * 3;
        fixture.execute(&planned);
    }
    assert_eq!(calls, 57);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 5);
    println!("engine_forced_winners=5; required_cycles=5; calls=57; callbacks=5");
}

fn ranking() {
    let cases = [
        (
            Shape::Generalized,
            Tactic::GeneralizedPun,
            Tactic::Relocation,
        ),
        (Shape::Prefixed, Tactic::Relocation, Tactic::PrefixedPun),
        (
            Shape::Successor,
            Tactic::SuccessorEviction,
            Tactic::NeighborEviction,
        ),
    ];
    let order = [
        Tactic::GeneralizedPun,
        Tactic::Relocation,
        Tactic::PrefixedPun,
        Tactic::SuccessorEviction,
        Tactic::NeighborEviction,
    ];
    let mut calls = 0;
    for (case, (shape, winner, later)) in cases.into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, shape);
        let leaf = fixture
            .leaf(winner)
            .expect("required earlier tactic refused");
        fixture
            .leaf(later)
            .expect("later tactic must independently be feasible");
        let planned = fixture.plan(fixture.policy(None)).unwrap();
        assert_eq!(planned.tactic(), winner);
        let index = order.iter().position(|tactic| *tactic == winner).unwrap();
        assert_eq!(planned.attempts().len(), index + 1);
        for (actual, expected) in planned.attempts().iter().zip(&order) {
            assert_eq!(actual.tactic, *expected);
            if actual.tactic != winner {
                assert_eq!(actual.refusal, Some(fixture.leaf(*expected).unwrap_err()));
            } else {
                assert_eq!(actual.refusal, None);
            }
        }
        assert_leaf_equal(&planned, &leaf);
        calls += fixture.heads.len() * 3;
        fixture.execute(&planned);
    }
    assert_eq!(calls, 36);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 3);
    println!("engine_preferred_multi_feasible=3; required_cycles=3; calls=36; callbacks=3");
}

fn neighbor_fallback() {
    let fixture = Fixture::new(0, Shape::Neighbor);
    assert_eq!(&fixture.original[PAD..PAD + 4], &[0x75, 1, 0x90, 0xc3]);
    assert_eq!(fixture.block_len, 2, "original conditional ends its block");
    let allocation = fixture.selected_allocation();
    let s = fixture.selected();
    for (next, frozen, width) in [(s + 5, 0x90c3_9000_u32, 256), (s + 6, 0x9090_c390, 1)] {
        let low = u64::try_from(i128::from(next) + i128::from(frozen as i32)).unwrap();
        let unavailable = AddressRange::new(low, width).unwrap();
        assert!(
            allocation
                .ranges
                .iter()
                .all(|range| !range.overlaps(unavailable))
        );
    }
    let expected = [
        (Tactic::GeneralizedPun, Refusal::AllocationUnavailable),
        (Tactic::Relocation, Refusal::NoPatchWindow),
        (Tactic::PrefixedPun, Refusal::AllocationUnavailable),
        (Tactic::SuccessorEviction, Refusal::NoPatchWindow),
    ];
    for (tactic, reason) in &expected {
        assert_eq!(fixture.leaf(*tactic).unwrap_err(), *reason);
    }
    let leaf = fixture.leaf(Tactic::NeighborEviction).unwrap();
    let planned = fixture.plan(fixture.policy(None)).unwrap();
    assert_eq!(planned.tactic(), Tactic::NeighborEviction);
    assert_eq!(planned.attempts().len(), 5);
    for (attempt, (tactic, reason)) in planned.attempts().iter().zip(&expected) {
        assert_eq!(attempt.tactic, *tactic);
        assert_eq!(attempt.refusal.as_ref(), Some(reason));
    }
    assert_eq!(planned.attempts()[4].refusal, None);
    assert_leaf_equal(&planned, &leaf);
    fixture.execute(&planned);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
    println!("engine_genuine_t3_fallback=1; earlier_exact_refusals=4; calls=15; callbacks=1");
}

fn refusals() {
    let fixture = Fixture::new(0, Shape::Long);
    fixture.leaf(Tactic::Relocation).unwrap();
    let failure = fixture
        .plan(fixture.policy(Some(Tactic::GeneralizedPun)))
        .unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(failure.attempts[0].tactic, Tactic::GeneralizedPun);
    assert_eq!(failure.attempts[0].refusal, Some(Refusal::NoPatchWindow));
    assert_eq!(fixture.observed(), fixture.mapping);

    let fixture = Fixture::new(1, Shape::Generalized);
    fixture.leaf(Tactic::GeneralizedPun).unwrap();
    let mut policy = fixture.policy(Some(Tactic::GeneralizedPun));
    policy.bundle.max_mappings = 0;
    let failure = fixture.plan(policy).unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(failure.attempts[0].tactic, Tactic::GeneralizedPun);
    assert_eq!(
        failure.attempts[0].refusal,
        Some(Refusal::AllocationUnavailable)
    );
    let CandidateEvidence::Single(candidates) = &failure.attempts[0].candidates else {
        panic!("aggregate refusal must retain successful leaf evidence");
    };
    assert_eq!(candidates.last().unwrap().refusal, None);
    assert_eq!(fixture.observed(), fixture.mapping);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);
    println!(
        "engine_forced_no_substitution=1; aggregate_budget_after_leaf_success=1; source_changes=0"
    );
}

#[test]
fn tactic_engine_required_puzzles() {
    if let Ok(mode) = std::env::var(ENV) {
        match mode.as_str() {
            "forced" => forced(),
            "ranking" => ranking(),
            "neighbor-fallback" => neighbor_fallback(),
            "refusals" => refusals(),
            _ => panic!("unknown engine child {mode}"),
        }
        println!("tactic-engine-complete:{mode}");
        return;
    }
    for mode in ["forced", "ranking", "neighbor-fallback", "refusals"] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(ENV, mode)
            .env("RUST_BACKTRACE", "0")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: only async-signal-safe limit calls run before exec.
        unsafe {
            command.pre_exec(|| {
                for (resource, value) in [
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_CPU, 20),
                    (libc::RLIMIT_FSIZE, 65536),
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
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                panic!(
                    "engine child {mode} exceeded its fixed deadline: {:?}",
                    child.wait_with_output().unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{mode}: {:?}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains(&format!("tactic-engine-complete:{mode}")));
        print!("{stdout}");
    }
}
