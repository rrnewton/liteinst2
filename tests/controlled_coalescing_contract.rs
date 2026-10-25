#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Required observing-control publication and retirement contracts.
//! Predeclared inventory: seven child modes; five completed bundle cycles,
//! seven images in those cycles, 1,148 native calls and 822 controlled callbacks.
//! One additional B2 setup transaction is separate. Negative inventory:
//! fourteen planner refusals, two allocation-collision and one ownership
//! BeforeWrite refusal, two KeepGated failures and two poisoned retries.
//! Every fixture body head is exercised; no internal CFG is certified as a block.

use liteinst2::bundle::{BundleBudget, BundlePlan, InstalledBundle, PlannedBundle, WritableAlias};
use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::grouping::GroupingBudget;
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, PlannedInstall, SearchPolicy, TacticPolicy, plan_coalesced,
    plan_install,
};
use liteinst2::trampoline::{HookCallback, HookContext, translate_program_counter};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const BODY: [u8; 16] = [0xb8, 1, 0, 0, 0, 0x05, 2, 0, 0, 0, 0x05, 4, 0, 0, 0, 0xc3];
const HEADS: [usize; 4] = [0, 5, 10, 15];
const ENV: &str = "LITEINST_CONTROLLED_COALESCING_CHILD";
const TEST: &str = "controlled_coalescing_required_contracts";
static COUNTS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
static EVENT_COUNT: AtomicUsize = AtomicUsize::new(0);
static EVENT_IDS: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];
static EVENT_PCS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
static OVERFLOW: AtomicBool = AtomicBool::new(false);
static UNEXPECTED: AtomicU64 = AtomicU64::new(0);

unsafe fn record(id: usize, frame: *mut HookContext) {
    COUNTS[id].fetch_add(1, Ordering::Relaxed);
    let index = EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    if index >= EVENT_IDS.len() {
        OVERFLOW.store(true, Ordering::Relaxed);
        return;
    }
    EVENT_IDS[index].store(id, Ordering::Relaxed);
    // SAFETY: the controlled dispatcher supplies its preserved application frame.
    EVENT_PCS[index].store(unsafe { (*frame).instruction_pointer }, Ordering::Relaxed);
}
unsafe extern "C" fn callback0(frame: *mut HookContext) {
    unsafe { record(0, frame) };
}
unsafe extern "C" fn callback1(frame: *mut HookContext) {
    unsafe { record(1, frame) };
}
unsafe extern "C" fn callback2(frame: *mut HookContext) {
    unsafe { record(2, frame) };
}
unsafe extern "C" fn callback3(frame: *mut HookContext) {
    unsafe { record(3, frame) };
}
unsafe extern "C" fn callback4(frame: *mut HookContext) {
    unsafe { record(4, frame) };
}
unsafe extern "C" fn callback5(frame: *mut HookContext) {
    unsafe { record(5, frame) };
}
unsafe extern "C" fn unexpected(_: *mut HookContext) {
    UNEXPECTED.fetch_add(1, Ordering::Relaxed);
}

fn controls() -> Vec<ProbeControl> {
    [
        callback0 as HookCallback,
        callback1,
        callback2,
        callback3,
        callback4,
        callback5,
    ]
    .into_iter()
    .map(|callback| ProbeControl::new(callback, false))
    .collect()
}

struct Fixture {
    write: *mut u8,
    execute: *mut u8,
    original: Vec<u8>,
    identity: CodeIdentity,
    bodies: usize,
}
impl Fixture {
    fn new(case: u64, bodies: usize) -> Self {
        assert!((1..=2).contains(&bodies));
        let address = 0x4600_0000_0000_u64 + case * 0x2_0000_0000;
        let mut original = vec![0xa5; PAGE];
        for body in 0..bodies {
            let offset = Self::offset(body);
            original[offset - 2..offset].copy_from_slice(&[0x89, 0xc0]);
            original[offset..offset + BODY.len()].copy_from_slice(&BODY);
        }
        // SAFETY: this bounded child exclusively owns both aliases. There is
        // no writable executable mapping and no MAP_FIXED replacement.
        let (write, execute) = unsafe {
            let fd = libc::memfd_create(c"controlled-coalescing".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, PAGE as libc::off_t), 0);
            let write = libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            let execute = libc::mmap(
                address as *mut _,
                PAGE,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                fd,
                0,
            );
            assert_ne!(write, libc::MAP_FAILED);
            assert_eq!(execute as usize as u64, address);
            assert_eq!(libc::close(fd), 0);
            std::ptr::copy_nonoverlapping(original.as_ptr(), write.cast(), PAGE);
            (write.cast(), execute.cast())
        };
        Self {
            write,
            execute,
            original,
            bodies,
            identity: CodeIdentity {
                source: SourceIdentity([case as u8; 32]),
                mapping: case + 1,
                generation: 1,
            },
        }
    }
    fn offset(body: usize) -> usize {
        128 + body * 512
    }
    fn pc(&self, body: usize) -> u64 {
        self.execute as usize as u64 + Self::offset(body) as u64
    }
    fn page(&self) -> AddressRange {
        AddressRange::new(self.execute as usize as u64, PAGE).unwrap()
    }
    fn range(&self, body: usize) -> AddressRange {
        AddressRange::new(self.pc(body), BODY.len()).unwrap()
    }
    fn allocation(&self, body: usize) -> AllocationPolicy {
        let target = self.execute as usize as u64
            + 0x0400_0000
            + body as u64 * 0x10_0000
            + if body == 0 { 0x100 } else { 0x900 };
        let mut allocation = AllocationPolicy::near(self.pc(body)).unwrap();
        allocation.preferred_address = Some(target);
        allocation.ranges = vec![AddressRange::new(target & !4095, PAGE).unwrap()];
        allocation.max_candidates = 1;
        allocation.max_mapped_bytes = PAGE;
        allocation
    }
    fn entries(&self, body: usize) -> LegalEntrySet {
        LegalEntrySet {
            identity: self.identity,
            scope: self.range(body),
            provenance: EntryProvenance::Declared(
                "three adjacent five-byte arithmetic instructions and RET; every body head".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: HEADS
                .into_iter()
                .map(|offset| LegalEntry {
                    address: self.pc(body) + offset as u64,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        }
    }
    fn actions(&self, body: usize, controls: &[ProbeControl]) -> Vec<ControlledAction> {
        (0..3)
            .map(|index| ControlledAction {
                logical_pc: self.pc(body) + HEADS[index] as u64,
                control: controls[body * 3 + index].clone(),
            })
            .collect()
    }
    fn request<'a>(
        &self,
        body: usize,
        entries: &'a LegalEntrySet,
        allocation: &'a AllocationPolicy,
    ) -> InstallRequest<'a> {
        InstallRequest {
            identity: self.identity,
            code: &BODY,
            base_address: self.pc(body),
            function: self.range(body),
            block: self.range(body),
            logical_pc: self.pc(body),
            entries,
            hook: unexpected,
            semantics: HookSemantics::Observe,
            allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_sites: 1,
                max_upstream_bytes: 0,
                max_displaced_bytes: 15,
            },
        }
    }
    fn member(&self, body: usize, controls: &[ProbeControl]) -> PlannedInstall {
        let member = plan_coalesced(
            &self.request(body, &self.entries(body), &self.allocation(body)),
            &self.actions(body, controls),
        )
        .expect("required three-action coalesced block refused");
        assert_eq!(member.plan().parts().kind, PlanKind::Relocation);
        assert_eq!(
            member.plan().parts().displaced,
            AddressRange::new(self.pc(body), 15).unwrap()
        );
        assert_eq!(
            member.image().address(),
            self.allocation(body).preferred_address.unwrap()
        );
        assert_eq!(member.image().instruction_boundaries().len(), 3);
        assert_eq!(member.image().entry_routes().len(), 3);
        for (original, _) in member.image().instruction_boundaries() {
            assert!([self.pc(body), self.pc(body) + 5, self.pc(body) + 10].contains(original));
        }
        member
    }
    fn bundle(&self, controls: &[ProbeControl], grouped: bool) -> PlannedBundle {
        let originals = (0..self.bodies)
            .map(|body| ExpectedBytes {
                address: self.pc(body),
                bytes: BODY.to_vec(),
            })
            .collect();
        let members = (0..self.bodies)
            .map(|body| self.member(body, controls))
            .collect();
        if grouped {
            let bundle = PlannedBundle::compose_grouped(
                originals,
                members,
                BundleBudget::default(),
                GroupingBudget::default(),
            )
            .expect("required grouped coalesced images refused");
            assert_eq!(bundle.images().len(), 2);
            assert_eq!(bundle.images()[0].address() % PAGE as u64, 0x100);
            assert_eq!(bundle.images()[1].address() % PAGE as u64, 0x900);
            assert!(bundle.images()[0].bytes().len() <= 0x800);
            assert!(bundle.images()[1].bytes().len() <= 0x700);
            let memory = bundle.plan().memory();
            assert_eq!(memory.mappings, 2);
            assert_eq!(memory.virtual_pages, 2);
            assert_eq!(memory.virtual_bytes, 8192);
            assert_eq!(memory.backing_pages, 1);
            assert_eq!(memory.backing_bytes, 4096);
            assert!(bundle.grouping().is_some());
            bundle
        } else {
            PlannedBundle::compose(originals, members, BundleBudget::default()).unwrap()
        }
    }
    fn observed(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.write, PAGE) }.to_vec()
    }
    fn permissions(&self, executable: bool) {
        assert_eq!(
            unsafe {
                libc::mprotect(
                    self.execute.cast(),
                    PAGE,
                    libc::PROT_READ | if executable { libc::PROT_EXEC } else { 0 },
                )
            },
            0
        );
    }
    fn finalize(&self) -> Result<(), Refusal> {
        if unsafe { libc::mprotect(self.execute.cast(), PAGE, libc::PROT_READ | libc::PROT_EXEC) }
            == 0
        {
            Ok(())
        } else {
            Err(Refusal::Backend(
                std::io::Error::last_os_error().to_string(),
            ))
        }
    }
    fn alias(&self) -> WritableAlias {
        unsafe { WritableAlias::new(self.page(), self.write) }.unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe {
            assert_eq!(libc::munmap(self.write.cast(), PAGE), 0);
            assert_eq!(libc::munmap(self.execute.cast(), PAGE), 0);
        }
    }
}
fn expected_source(fixture: &Fixture, plan: &BundlePlan) -> Vec<u8> {
    let mut expected = fixture.original.clone();
    for snapshot in plan.final_bytes() {
        let offset = (snapshot.address - fixture.page().start()) as usize;
        expected[offset..offset + snapshot.bytes.len()].copy_from_slice(&snapshot.bytes);
    }
    expected
}
fn held(fixture: &Fixture, plan: &BundlePlan) -> Vec<AddressRange> {
    let mut held = vec![fixture.page()];
    held.extend(plan.steps().iter().flat_map(|step| {
        step.parts()
            .allocations
            .iter()
            .map(|allocation| allocation.range)
    }));
    held
}
fn publish(fixture: &Fixture, bundle: &PlannedBundle) -> InstalledBundle {
    let mut guard = ();
    let mut lease =
        unsafe { QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.page()]) };
    let (installed, receipt) =
        unsafe { bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize()) }
            .unwrap();
    assert_eq!(receipt.plan().steps(), bundle.plan().steps());
    assert!(!lease.is_poisoned());
    installed
}
fn retire(fixture: &Fixture, installed: &mut InstalledBundle) {
    fixture.permissions(false);
    let mut guard = ();
    let mut lease = unsafe {
        QuiescenceLease::new(
            &mut guard,
            fixture.identity,
            held(fixture, installed.plan()),
        )
    };
    unsafe { installed.retire_with(&mut lease, || fixture.finalize()) }.unwrap();
    assert!(!lease.is_poisoned());
    assert!(installed.is_retired());
    assert_eq!(fixture.observed(), fixture.original);
}
fn generated_snapshot(plan: &BundlePlan) -> Vec<(AddressRange, Vec<u8>)> {
    plan.steps()
        .iter()
        .flat_map(|step| step.parts().allocations.iter())
        .map(|allocation| {
            let range = allocation.range;
            (
                range,
                unsafe {
                    std::slice::from_raw_parts(range.start() as *const u8, range.len() as usize)
                }
                .to_vec(),
            )
        })
        .collect()
}
fn unchanged_generated(snapshots: &[(AddressRange, Vec<u8>)]) {
    for (range, original) in snapshots {
        assert_eq!(
            unsafe { std::slice::from_raw_parts(range.start() as *const u8, range.len() as usize) },
            original
        );
    }
}
fn verify_images(bundle: &PlannedBundle) {
    for image in bundle.images() {
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(image.address() as *const u8, image.bytes().len())
            },
            image.bytes()
        );
    }
}
fn call_all(fixture: &Fixture, body: usize, mask: usize, installed: bool) -> usize {
    for (entry, offset) in HEADS.into_iter().enumerate() {
        EVENT_COUNT.store(0, Ordering::Relaxed);
        OVERFLOW.store(false, Ordering::Relaxed);
        let before: Vec<_> = COUNTS
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect();
        let actual: u64;
        unsafe {
            core::arch::asm!("call r11", in("r11") fixture.pc(body) + offset as u64, inlateout("rax") 42_u64 => actual, clobber_abi("C"));
        }
        assert_eq!(actual, [7, 48, 46, 42][entry]);
        let expected: Vec<_> = (entry..3)
            .filter(|index| installed && mask & (1 << index) != 0)
            .map(|index| (body * 3 + index, fixture.pc(body) + HEADS[index] as u64))
            .collect();
        assert!(!OVERFLOW.load(Ordering::Relaxed));
        assert_eq!(EVENT_COUNT.load(Ordering::Relaxed), expected.len());
        for (index, (id, pc)) in expected.iter().enumerate() {
            assert_eq!(EVENT_IDS[index].load(Ordering::Relaxed), *id);
            assert_eq!(EVENT_PCS[index].load(Ordering::Relaxed), *pc);
        }
        for (id, count) in COUNTS.iter().enumerate() {
            assert_eq!(
                count.load(Ordering::Relaxed),
                before[id] + u64::from(expected.iter().any(|event| event.0 == id))
            );
        }
        assert_eq!(UNEXPECTED.load(Ordering::Relaxed), 0);
    }
    4
}
fn set_mask(controls: &[ProbeControl], body: usize, mask: usize) {
    for index in 0..3 {
        let control = &controls[body * 3 + index];
        let enabled = mask & (1 << index) != 0;
        let before: Vec<_> = controls.iter().map(ProbeControl::is_enabled).collect();
        // Toggle through a clone, proving stable shared identity for this action.
        let clone = control.clone();
        clone.set_enabled(enabled);
        assert_eq!(control, &clone);
        assert_eq!(control.is_enabled(), enabled);
        for (other, other_control) in controls.iter().enumerate() {
            if other != body * 3 + index {
                assert_ne!(control, other_control);
                assert_eq!(
                    other_control.is_enabled(),
                    before[other],
                    "one control store changed another action"
                );
            }
        }
    }
}
fn run_subsets(fixture: &Fixture, controls: &[ProbeControl], bundle: &PlannedBundle) -> usize {
    fixture.permissions(true);
    let mut calls = 0;
    for body in 0..fixture.bodies {
        calls += call_all(fixture, body, 0, false);
    }
    fixture.permissions(false);
    let mut installed = publish(fixture, bundle);
    verify_images(bundle);
    let source = expected_source(fixture, bundle.plan());
    assert_eq!(fixture.observed(), source);
    let generated = generated_snapshot(installed.plan());
    let masks = if fixture.bodies == 1 { 8 } else { 64 };
    for combined in 0..masks {
        for body in 0..fixture.bodies {
            set_mask(controls, body, (combined >> (body * 3)) & 7);
        }
        for body in 0..fixture.bodies {
            calls += call_all(fixture, body, (combined >> (body * 3)) & 7, true);
        }
        assert_eq!(
            fixture.observed(),
            source,
            "toggle changed source instructions"
        );
        unchanged_generated(&generated);
    }
    retire(fixture, &mut installed);
    for body in 0..fixture.bodies {
        calls += call_all(fixture, body, 0, false);
    }
    unchanged_generated(&generated);
    calls
}
fn assert_counts(expected: [u64; 6]) {
    for (count, expected) in COUNTS.iter().zip(expected) {
        assert_eq!(count.load(Ordering::Relaxed), expected);
    }
}
fn subsets(grouped: bool) {
    let fixture = Fixture::new(0, if grouped { 2 } else { 1 });
    let controls = controls();
    let bundle = fixture.bundle(&controls, grouped);
    let calls = run_subsets(&fixture, &controls, &bundle);
    assert_eq!(calls, if grouped { 528 } else { 40 });
    assert_counts(if grouped {
        [32, 64, 96, 32, 64, 96]
    } else {
        [4, 8, 12, 0, 0, 0]
    });
    println!(
        "required_cycles=1; images={}; runtime_subsets={}; calls={calls}; callbacks={}; immutable_code=proved",
        fixture.bodies,
        if grouped { 64 } else { 8 },
        if grouped { 384 } else { 24 }
    );
}
fn lifetime() {
    let fixture = Fixture::new(0, 1);
    let controls = controls();
    set_mask(&controls, 0, 7);
    let bundle = fixture.bundle(&controls, false);
    fixture.permissions(true);
    let mut calls = call_all(&fixture, 0, 0, false);
    fixture.permissions(false);
    let mut installed = publish(&fixture, &bundle);
    let source = expected_source(&fixture, bundle.plan());
    let generated = generated_snapshot(installed.plan());
    drop(bundle);
    drop(controls);
    calls += call_all(&fixture, 0, 7, true);
    assert_eq!(fixture.observed(), source);
    unchanged_generated(&generated);
    retire(&fixture, &mut installed);
    calls += call_all(&fixture, 0, 0, false);
    assert_eq!(calls, 12);
    assert_counts([1, 2, 3, 0, 0, 0]);
    println!(
        "required_cycles=1; external_controls_and_pure_plan_dropped=proved; calls=12; callbacks=6"
    );
}
fn prewrite() {
    let fixture = Fixture::new(0, 2);
    let controls = controls();
    let bundle = fixture.bundle(&controls, true);
    let allocations: Vec<_> = bundle
        .plan()
        .steps()
        .iter()
        .flat_map(|step| {
            step.parts()
                .allocations
                .iter()
                .map(|allocation| allocation.range)
        })
        .collect();
    assert_eq!(allocations.len(), 2);
    for blocked in 0..2 {
        let range = allocations[blocked];
        let mapping = unsafe {
            libc::mmap(
                range.start() as *mut _,
                range.len() as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_eq!(mapping as usize as u64, range.start());
        {
            let mut guard = ();
            let mut lease =
                unsafe { QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.page()]) };
            let failure = unsafe {
                bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize())
            }
            .err()
            .unwrap();
            assert_eq!(failure.stage, FailureStage::BeforeWrite);
            assert_eq!(failure.reason, Refusal::AllocationUnavailable);
            assert!(!lease.is_poisoned());
        }
        assert_eq!(fixture.observed(), fixture.original);
        let other = allocations[1 - blocked];
        let mut residency = vec![0; other.len() as usize / PAGE];
        assert_eq!(
            unsafe {
                libc::mincore(
                    other.start() as *mut _,
                    other.len() as usize,
                    residency.as_mut_ptr(),
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM)
        );
        for image in bundle.images() {
            for mapping in image.program_counter_mappings() {
                assert_eq!(translate_program_counter(mapping.generated_start()), None);
            }
        }
        assert_eq!(unsafe { libc::munmap(mapping, range.len() as usize) }, 0);
    }
    assert_eq!(run_subsets(&fixture, &controls, &bundle), 528);
    assert_counts([32, 64, 96, 32, 64, 96]);
    println!(
        "collision_beforewrite=2; required_same_plan_retry_cycles=1; calls=528; callbacks=384; both_grouped_alias_cleanup_orders=proved"
    );
}
fn ownership() {
    let fixture = Fixture::new(0, 1);
    let controls = controls();
    let blocked = fixture.bundle(&controls, false);
    let pc = fixture.pc(0) - 2;
    let code = &fixture.original[Fixture::offset(0) - 2..Fixture::offset(0) + 5];
    let range = AddressRange::new(pc, code.len()).unwrap();
    let entries = LegalEntrySet {
        identity: fixture.identity,
        scope: range,
        provenance: EntryProvenance::Declared(
            "prior B2 owns coalesced instruction fetch bytes".into(),
        ),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: vec![],
        resumes: ResumeObligation::NoneExist,
    };
    let target = pc + 5 + u32::from_le_bytes([128, BODY[0], BODY[1], BODY[2]]) as u64;
    let mut allocation = AllocationPolicy::near(pc).unwrap();
    allocation.preferred_address = Some(target);
    allocation.ranges = vec![AddressRange::new(target & !4095, 8192).unwrap()];
    let prior = plan_install(&InstallRequest {
        identity: fixture.identity,
        code,
        base_address: pc,
        function: range,
        block: AddressRange::new(pc, 2).unwrap(),
        logical_pc: pc,
        entries: &entries,
        hook: unexpected,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            max_sites: 1,
            max_upstream_bytes: 0,
            max_displaced_bytes: 2,
        },
    })
    .expect("required B2 setup refused");
    assert!(matches!(
        prior.plan().parts().kind,
        PlanKind::GeneralizedPun(_)
    ));
    let prior = PlannedBundle::compose(
        vec![ExpectedBytes {
            address: pc,
            bytes: code.to_vec(),
        }],
        vec![prior],
        BundleBudget::default(),
    )
    .unwrap();
    let mut installed = publish(&fixture, &prior);
    fixture.permissions(false);
    let before = fixture.observed();
    for source in blocked.plan().originals() {
        let offset = (source.address - fixture.page().start()) as usize;
        assert_eq!(&before[offset..offset + source.bytes.len()], source.bytes);
    }
    {
        let mut guard = ();
        let mut lease =
            unsafe { QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.page()]) };
        let failure =
            unsafe { blocked.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize()) }
                .err()
                .unwrap();
        assert_eq!(failure.reason, Refusal::OwnershipConflict);
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert!(!lease.is_poisoned());
    }
    assert_eq!(fixture.observed(), before);
    retire(&fixture, &mut installed);
    drop(blocked);
    let rebuilt = fixture.bundle(&controls, false);
    assert_eq!(run_subsets(&fixture, &controls, &rebuilt), 40);
    assert_counts([4, 8, 12, 0, 0, 0]);
    println!(
        "matching_snapshot_ownership_beforewrite=1; b2_setup_transactions=1; full_replan_cycles=1; calls=40; callbacks=24"
    );
}
fn refusals() {
    let fixture = Fixture::new(0, 1);
    let controls = controls();
    let entries = fixture.entries(0);
    let allocation = fixture.allocation(0);
    let actions = fixture.actions(0, &controls);
    let mut count = 0;
    for case in 0..14 {
        let mut entries = entries.clone();
        let mut allocation = allocation.clone();
        let mut actions = actions.clone();
        let expected = match case {
            0 => {
                actions.clear();
                Refusal::InvalidPlan
            }
            1 => {
                actions.remove(0);
                Refusal::InvalidPlan
            }
            2 => {
                actions.swap(1, 2);
                Refusal::InvalidPlan
            }
            3 => {
                actions[1].logical_pc = actions[0].logical_pc;
                Refusal::InvalidPlan
            }
            4 => {
                actions[1].control = actions[0].control.clone();
                Refusal::InvalidPlan
            }
            5 => {
                actions[1].logical_pc += 1;
                Refusal::NotInstructionHead
            }
            6 => {
                actions[2].logical_pc = fixture.pc(0) + 16;
                Refusal::InvalidRange
            }
            7 | 13 => Refusal::UnsupportedSemantics(String::new()),
            8 | 9 => Refusal::NoPatchWindow,
            10 => {
                allocation.max_candidates = 0;
                Refusal::AllocationUnavailable
            }
            11 => {
                entries.completeness = EntryCompleteness::Incomplete;
                Refusal::UnresolvedEntry
            }
            12 => {
                entries.resumes = ResumeObligation::Unresolved;
                Refusal::UnresolvedEntry
            }
            _ => unreachable!(),
        };
        if case == 13 {
            entries.entries[1].requires_endbr = true;
        }
        let mut request = fixture.request(0, &entries, &allocation);
        match case {
            7 => request.semantics = HookSemantics::ReplaceFirst,
            8 => request.search.max_displaced_bytes = 14,
            9 => request.search.max_sites = 0,
            _ => {}
        }
        let reason = plan_coalesced(&request, &actions).unwrap_err();
        if matches!(expected, Refusal::UnsupportedSemantics(_)) {
            assert!(matches!(reason, Refusal::UnsupportedSemantics(_)));
        } else {
            assert_eq!(reason, expected);
        }
        assert_eq!(fixture.observed(), fixture.original);
        count += 1;
    }
    assert_eq!(count, 14);
    assert_counts([0; 6]);
    println!(
        "planner_refusals=14; source_changes=0; duplicate_controls_and_conditional_replacement_refused=proved"
    );
}
fn retained(plan: &BundlePlan) {
    for range in plan.steps().iter().flat_map(|step| {
        step.parts()
            .allocations
            .iter()
            .map(|allocation| allocation.range)
    }) {
        let mut residency = vec![0; range.len() as usize / PAGE];
        assert_eq!(
            unsafe {
                libc::mincore(
                    range.start() as *mut _,
                    range.len() as usize,
                    residency.as_mut_ptr(),
                )
            },
            0
        );
    }
    for generated in plan.steps().iter().flat_map(|step| &step.parts().generated) {
        for mapping in &generated.program_counters {
            assert!(translate_program_counter(mapping.generated_start()).is_some());
        }
    }
}
fn poison() {
    for (case, retiring) in [false, true].into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, 1);
        let controls = controls();
        set_mask(&controls, 0, 7);
        let bundle = fixture.bundle(&controls, false);
        let plan = bundle.plan().clone();
        if retiring {
            let mut installed = publish(&fixture, &bundle);
            fixture.permissions(false);
            drop(bundle);
            drop(controls);
            let mut guard = ();
            let mut lease = unsafe {
                QuiescenceLease::new(&mut guard, fixture.identity, held(&fixture, &plan))
            };
            let failure = unsafe {
                installed.retire_with(&mut lease, || {
                    Err(Refusal::Backend(
                        "forced controlled retirement failure".into(),
                    ))
                })
            }
            .unwrap_err();
            assert_eq!(failure.stage, FailureStage::KeepGated);
            assert!(lease.is_poisoned());
            assert!(!installed.is_retired());
            assert_eq!(fixture.observed(), fixture.original);
            retained(&plan);
            let retry = unsafe { installed.retire(&mut lease) }.unwrap_err();
            assert_eq!(retry.reason, Refusal::LeasePoisoned);
            assert_eq!(retry.stage, FailureStage::BeforeWrite);
            std::mem::forget(installed);
        } else {
            let mut guard = ();
            let mut lease =
                unsafe { QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.page()]) };
            let failure = unsafe {
                bundle.publish_with(&[fixture.alias()], &mut lease, || {
                    Err(Refusal::Backend(
                        "forced controlled publication failure".into(),
                    ))
                })
            }
            .err()
            .unwrap();
            assert_eq!(failure.stage, FailureStage::KeepGated);
            assert!(lease.is_poisoned());
            assert_eq!(fixture.observed(), expected_source(&fixture, &plan));
            let retry = unsafe {
                bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize())
            }
            .err()
            .unwrap();
            assert_eq!(retry.reason, Refusal::LeasePoisoned);
            assert_eq!(retry.stage, FailureStage::BeforeWrite);
            drop(bundle);
            drop(controls);
            retained(&plan);
        }
        std::mem::forget(fixture);
    }
    assert_counts([0; 6]);
    println!(
        "keep_gated=2; poisoned_retry_beforewrite=2; code_and_maps_retained_after_pure_control_handles_drop=proved; calls_after_poison=0"
    );
}

#[test]
fn controlled_coalescing_required_contracts() {
    if let Ok(mode) = std::env::var(ENV) {
        match mode.as_str() {
            "subsets" => subsets(false),
            "grouped" => subsets(true),
            "lifetime" => lifetime(),
            "prewrite" => prewrite(),
            "ownership" => ownership(),
            "refusals" => refusals(),
            "poison" => poison(),
            _ => panic!("unknown child mode {mode}"),
        }
        println!("controlled-coalescing-complete:{mode}");
        return;
    }
    for mode in [
        "subsets",
        "grouped",
        "lifetime",
        "prewrite",
        "ownership",
        "refusals",
        "poison",
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(ENV, mode)
            .env("RUST_BACKTRACE", "0")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
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
                    "controlled coalescing child {mode} timed out: {:?}",
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
        assert!(stdout.contains(&format!("controlled-coalescing-complete:{mode}")));
        print!("{stdout}");
    }
}
