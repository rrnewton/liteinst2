#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Bounded native two-image publication and transactional-failure fixtures.
use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
use liteinst2::contracts::*;
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, PlannedInstall, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static HOOKS: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" fn observe(_: *mut HookContext) {
    HOOKS.fetch_add(1, Ordering::Relaxed);
}
const ADDRESS: u64 = 0x2600_0000_0000;
const ENV: &str = "LITEINST_BUNDLE_CONTRACT_CHILD";

struct Fixture {
    write: *mut u8,
    execute: *mut u8,
    originals: Vec<ExpectedBytes>,
    identity: CodeIdentity,
}
impl Fixture {
    fn new(routed: bool) -> Self {
        // SAFETY: child exclusively owns fresh aliases, with no executable users yet.
        let (write, execute) = unsafe {
            let fd = libc::memfd_create(c"bundle-contract".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, 4096), 0);
            let w = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            let x = libc::mmap(
                ADDRESS as *mut _,
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                fd,
                0,
            );
            assert_ne!(w, libc::MAP_FAILED);
            assert_ne!(x, libc::MAP_FAILED);
            assert_eq!(libc::close(fd), 0);
            (w.cast::<u8>(), x.cast::<u8>())
        };
        let originals = vec![
            ExpectedBytes {
                address: ADDRESS + 0x100,
                bytes: if routed {
                    vec![0x90, 0xb8, 0x21, 0x43, 0x65, 0x07, 0xc3]
                } else {
                    vec![0xb8, 0x21, 0x43, 0x65, 0x07, 0xc3]
                },
            },
            ExpectedBytes {
                address: ADDRESS + 0x180,
                bytes: vec![0x66, 0x90, 0xb8, 0x03, 0x02, 0x10, 0x00, 0xc3],
            },
        ];
        for read in &originals {
            // SAFETY: exact checked offsets in the private writable page.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    read.bytes.as_ptr(),
                    write.add((read.address - ADDRESS) as usize),
                    read.bytes.len(),
                )
            };
        }
        Self {
            write,
            execute,
            originals,
            identity: CodeIdentity {
                source: SourceIdentity([41; 32]),
                mapping: 41,
                generation: 1,
            },
        }
    }
    fn members(&self) -> Vec<PlannedInstall> {
        let mut members = Vec::new();
        for (index, source) in self.originals.iter().enumerate() {
            let scope = AddressRange::new(source.address, source.bytes.len()).unwrap();
            let entries = LegalEntrySet {
                identity: self.identity,
                scope,
                provenance: EntryProvenance::Declared("two-image private fixture".into()),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: vec![],
                resumes: ResumeObligation::NoneExist,
            };
            let mut allocation = AllocationPolicy::near(source.address).unwrap();
            if index == 0 {
                allocation.preferred_address = Some(ADDRESS + 0x10_0000);
            }
            let member = plan_install(&InstallRequest {
                identity: self.identity,
                code: &source.bytes,
                base_address: source.address,
                function: scope,
                block: scope,
                logical_pc: source.address,
                entries: &entries,
                hook: observe,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: if index == 0 {
                        TacticPolicy::RelocationOnly
                    } else {
                        TacticPolicy::GeneralizedPunOnly
                    },
                    ..SearchPolicy::default()
                },
            })
            .unwrap();
            assert_eq!(
                matches!(member.plan().parts().kind, PlanKind::GeneralizedPun(_)),
                index == 1
            );
            members.push(member);
        }
        members
    }
    fn bundle(&self) -> PlannedBundle {
        PlannedBundle::compose(
            self.originals.clone(),
            self.members(),
            BundleBudget::default(),
        )
        .unwrap()
    }
    fn alias(&self) -> WritableAlias {
        // SAFETY: both aliases share this child's exclusively owned original page.
        unsafe { WritableAlias::new(AddressRange::new(ADDRESS, 4096).unwrap(), self.write) }
            .unwrap()
    }
    fn held(&self) -> Vec<AddressRange> {
        self.originals
            .iter()
            .map(|s| AddressRange::new(s.address, s.bytes.len()).unwrap())
            .collect()
    }
    fn check(&self, bytes: &[ExpectedBytes]) {
        for expected in bytes {
            // SAFETY: private mapping with no concurrent executor/writer.
            assert_eq!(
                unsafe {
                    std::slice::from_raw_parts(
                        self.write.add((expected.address - ADDRESS) as usize),
                        expected.bytes.len(),
                    )
                },
                expected.bytes
            );
        }
    }
    fn calls(&self, expected_hooks: usize) {
        let before = HOOKS.load(Ordering::Relaxed);
        let mut entries = vec![
            (ADDRESS + 0x100, 0x0765_4321_u32),
            (ADDRESS + 0x180, 0x0010_0203),
            (ADDRESS + 0x182, 0x0010_0203),
        ];
        if self.originals[0].bytes[0] == 0x90 {
            entries.push((ADDRESS + 0x101, 0x0765_4321));
        }
        for (address, expected) in entries {
            // SAFETY: these private verified fixtures have u32(void) ABI and no active mutation.
            let call: unsafe extern "C" fn() -> u32 =
                unsafe { std::mem::transmute(address as usize) };
            assert_eq!(unsafe { call() }, expected);
        }
        assert_eq!(HOOKS.load(Ordering::Relaxed) - before, expected_hooks);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: each scenario drains all calls before dropping the fixture.
        unsafe {
            assert_eq!(libc::munmap(self.write.cast(), 4096), 0);
            assert_eq!(libc::munmap(self.execute.cast(), 4096), 0);
        }
    }
}
fn child(mode: &str) {
    let fixture = Fixture::new(mode == "router");
    fixture.calls(0);
    let bundle = fixture.bundle();
    assert_eq!(bundle.plan().memory().mappings, 2);
    assert_eq!(
        bundle.plan().memory().backing_bytes,
        bundle.plan().memory().virtual_bytes
    );
    let mut guard = ();
    // SAFETY: child alone owns/executes all mappings and is parked in this test.
    let mut lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
    let aliases = [fixture.alias()];
    match mode {
        "success" | "router" | "retire-postwrite" => {
            let (mut installed, receipt) = unsafe { bundle.publish(&aliases, &mut lease) }.unwrap();
            assert_eq!(receipt.plan().steps(), bundle.plan().steps());
            assert!(!lease.is_poisoned());
            drop(lease);
            fixture.check(bundle.plan().final_bytes());
            fixture.calls(2);
            if mode == "router" {
                assert!(installed.routed_entries() > 0);
            }
            let mut lease =
                unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
            let failure = unsafe { installed.retire(&mut lease) }.unwrap_err();
            assert_eq!(failure.reason, Refusal::DependencyNotHeld);
            assert_eq!(failure.stage, FailureStage::BeforeWrite);
            drop(lease);
            fixture.check(bundle.plan().final_bytes());
            fixture.calls(2);
            let mut held = fixture.held();
            held.extend(
                bundle
                    .plan()
                    .steps()
                    .iter()
                    .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
            );
            let mut lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, held) };
            if mode == "retire-postwrite" {
                let error =
                    unsafe { installed.retire_with(&mut lease, || Err(Refusal::Synchronization)) }
                        .unwrap_err();
                assert_eq!(error.stage, FailureStage::KeepGated);
                assert!(lease.is_poisoned());
                assert!(!installed.is_retired());
                fixture.check(&fixture.originals);
                let retry = unsafe { installed.retire(&mut lease) }.unwrap_err();
                assert_eq!(retry.reason, Refusal::LeasePoisoned);
                // Restored bytes alone do not authorize execution after failed synchronization.
                std::mem::forget(fixture);
                println!("bundle scenario {mode}: complete");
                return;
            }
            unsafe { installed.retire(&mut lease) }.unwrap();
            assert!(installed.is_retired());
            assert!(!lease.is_poisoned());
            drop(lease);
            fixture.check(&fixture.originals);
            fixture.calls(0);
        }
        "collision" => {
            let collision = bundle.plan().steps()[1].parts().allocations[0].range;
            let mapping = unsafe {
                libc::mmap(
                    collision.start() as *mut _,
                    collision.len() as usize,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            let error = unsafe { bundle.publish(&aliases, &mut lease) }
                .err()
                .unwrap();
            assert_eq!(error.stage, FailureStage::BeforeWrite);
            assert!(!lease.is_poisoned());
            drop(lease);
            fixture.check(&fixture.originals);
            fixture.calls(0);
            assert_eq!(
                unsafe { libc::munmap(mapping, collision.len() as usize) },
                0
            );
            // Retry proves both the first staged mapping and every reservation were released.
            let mut lease =
                unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
            let (_installed, _) = unsafe { bundle.publish(&aliases, &mut lease) }.unwrap();
            drop(lease);
            fixture.check(bundle.plan().final_bytes());
            fixture.calls(2);
            // Active handles intentionally retain ownership; child exit reclaims everything.
            std::mem::forget(fixture);
        }
        "stale" => {
            unsafe {
                *fixture.write.add(0x183) ^= 1;
            }
            let error = unsafe { bundle.publish(&aliases, &mut lease) }
                .err()
                .unwrap();
            assert_eq!(error.reason, Refusal::ExpectedBytesChanged);
            assert_eq!(error.stage, FailureStage::BeforeWrite);
            assert!(!lease.is_poisoned());
            unsafe {
                *fixture.write.add(0x183) ^= 1;
            }
            fixture.check(&fixture.originals);
            let (_installed, _) = unsafe { bundle.publish(&aliases, &mut lease) }.unwrap();
            drop(lease);
            fixture.calls(2);
            std::mem::forget(fixture);
        }
        "postwrite" => {
            let error = unsafe {
                bundle.publish_with(&aliases, &mut lease, || Err(Refusal::Synchronization))
            }
            .err()
            .unwrap();
            assert_eq!(error.stage, FailureStage::KeepGated);
            assert!(lease.is_poisoned());
            fixture.check(bundle.plan().final_bytes());
            let retry = unsafe { bundle.publish(&aliases, &mut lease) }
                .err()
                .unwrap();
            assert_eq!(retry.reason, Refusal::LeasePoisoned);
            // No application execution after a failed synchronization/finalization.
            std::mem::forget(fixture);
        }
        "budgets" => {
            drop(lease);
            for budget in [
                BundleBudget {
                    max_steps: 1,
                    ..BundleBudget::default()
                },
                BundleBudget {
                    max_mappings: 1,
                    ..BundleBudget::default()
                },
                BundleBudget {
                    max_virtual_bytes: 0,
                    ..BundleBudget::default()
                },
                BundleBudget {
                    max_backing_bytes: 0,
                    ..BundleBudget::default()
                },
                BundleBudget {
                    max_virtual_span: 0,
                    ..BundleBudget::default()
                },
            ] {
                let error =
                    PlannedBundle::compose(fixture.originals.clone(), fixture.members(), budget)
                        .unwrap_err();
                assert_eq!(error, Refusal::AllocationUnavailable);
                fixture.check(&fixture.originals);
            }
            fixture.calls(0);
        }
        _ => panic!("unknown scenario"),
    }
    println!("bundle scenario {mode}: complete");
}
#[test]
fn bundle_transactions() {
    if let Ok(mode) = std::env::var(ENV) {
        child(&mode);
        return;
    }
    for mode in [
        "success",
        "router",
        "collision",
        "stale",
        "postwrite",
        "retire-postwrite",
        "budgets",
    ] {
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "bundle_transactions", "--nocapture"])
            .env(ENV, mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if process.try_wait().unwrap().is_some() {
                break;
            }
            if start.elapsed() > Duration::from_secs(15) {
                process.kill().unwrap();
                panic!(
                    "bundle child {mode} timed out: {:?}",
                    process.wait_with_output().unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = process.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "scenario {mode}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("bundle scenario {mode}: complete"))
        );
    }
}
