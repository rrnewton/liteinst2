#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Required T2 successor-eviction puzzles. No arbitrary victim tail is an entry.

use liteinst2::bundle::{BundleBudget, InstalledBundle, PlannedBundle, WritableAlias};
use liteinst2::contracts::*;
use liteinst2::eviction::{EvictionKind, PlannedEviction, plan_successor, plan_successor_detailed};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy};
use liteinst2::trampoline::{HookContext, translate_program_counter};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const PAD: usize = 16;
const RESULT: u64 = 0x1937_5a82;
const VICTIM_DISPLACEMENT: i32 = 0x0012_3456;
const ENV: &str = "LITEINST_SUCCESSOR_EVICTION_CONTRACT_CHILD";
const TEST: &str = "successor_eviction_contract_puzzles";
const GEOMETRIES: [(usize, usize); 10] = [
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (2, 1),
    (3, 1),
    (3, 2),
    (4, 1),
    (4, 2),
    (4, 3),
];
static CALLBACKS: AtomicU64 = AtomicU64::new(0);
static LAST_PC: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the selected hook receives an initialized frame from its emitter.
    LAST_PC.store(unsafe { (*context).instruction_pointer }, Ordering::Relaxed);
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

fn nop(len: usize) -> Vec<u8> {
    match len {
        1 => vec![0x90],
        2 => vec![0x66, 0x90],
        3 => vec![0x0f, 0x1f, 0],
        4 => vec![0x0f, 0x1f, 0x40, 0],
        5 => vec![0x0f, 0x1f, 0x44, 0, 0],
        6 => vec![0x66, 0x0f, 0x1f, 0x44, 0, 0],
        7 => vec![0x0f, 0x1f, 0x80, 0, 0, 0, 0],
        8..=15 => {
            let mut bytes = vec![0x66; len - 8];
            bytes.extend_from_slice(&[0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]);
            bytes
        }
        _ => panic!("unsupported NOP length"),
    }
}

struct Fixture {
    write: *mut u8,
    execute: *mut u8,
    offset: usize,
    len: usize,
    prefixes: usize,
    victim_len: usize,
    original: Vec<u8>,
    original_mapping: Vec<u8>,
    identity: CodeIdentity,
}

impl Fixture {
    fn new(case: u64, offset: usize, len: usize, prefixes: usize, victim_len: usize) -> Self {
        let mut original = vec![0x90; PAD];
        original.extend(nop(len));
        original.extend(nop(victim_len));
        original.push(0xb8);
        original.extend_from_slice(&(RESULT as u32).to_le_bytes());
        original.push(0xc3);
        assert!(offset >= PAD && offset - PAD + original.len() <= 2 * PAGE);
        let mut original_mapping = vec![0xa5; 2 * PAGE];
        original_mapping[offset - PAD..offset - PAD + original.len()].copy_from_slice(&original);
        let address = 0x3800_0000_0000_u64 + case * 0x2_0000_0000;
        // SAFETY: this bounded child exclusively owns both new aliases. Exact
        // fixed placements do not overwrite any existing mapping.
        let (write, execute) = unsafe {
            let fd = libc::memfd_create(c"successor-eviction-contract".as_ptr(), libc::MFD_CLOEXEC);
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
            std::ptr::copy_nonoverlapping(original_mapping.as_ptr(), write.cast(), 2 * PAGE);
            (write.cast(), execute.cast())
        };
        Self {
            write,
            execute,
            offset,
            len,
            prefixes,
            victim_len,
            original,
            original_mapping,
            identity: CodeIdentity {
                source: SourceIdentity([case as u8; 32]),
                mapping: case + 1,
                generation: 1,
            },
        }
    }

    fn pc(&self) -> u64 {
        self.execute as usize as u64 + self.offset as u64
    }
    fn victim(&self) -> u64 {
        self.pc() + self.len as u64
    }
    fn base(&self) -> u64 {
        self.pc() - PAD as u64
    }
    fn source(&self) -> AddressRange {
        AddressRange::new(self.base(), self.original.len()).unwrap()
    }
    fn function(&self) -> AddressRange {
        AddressRange::new(self.pc(), self.len + self.victim_len + 6).unwrap()
    }
    fn observed(&self) -> Vec<u8> {
        // SAFETY: no other execution or writer knows this fixture's addresses.
        unsafe { std::slice::from_raw_parts(self.write, 2 * PAGE) }.to_vec()
    }
    fn permissions(&self, execute: bool) {
        let protection = libc::PROT_READ | if execute { libc::PROT_EXEC } else { 0 };
        // SAFETY: exclusive ownership is the gate; both pages cover all fetches.
        assert_eq!(
            unsafe { libc::mprotect(self.execute.cast(), 2 * PAGE, protection) },
            0
        );
    }
    fn finalize(&self) -> Result<(), Refusal> {
        // SAFETY: the owner remains parked until the receipt and lease drop.
        if unsafe {
            libc::mprotect(
                self.execute.cast(),
                2 * PAGE,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(Refusal::Backend(
                std::io::Error::last_os_error().to_string(),
            ))
        }
    }
    fn alias(&self) -> WritableAlias {
        // SAFETY: this backing and its two aliases remain owned through retirement.
        unsafe {
            WritableAlias::new(
                AddressRange::new(self.execute as usize as u64, 2 * PAGE).unwrap(),
                self.write,
            )
        }
        .unwrap()
    }
    fn entries(&self) -> LegalEntrySet {
        LegalEntrySet {
            identity: self.identity,
            scope: self.function(),
            provenance: EntryProvenance::Declared("whole successor NOP fixture".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        }
    }
    fn tactic(&self) -> TacticPolicy {
        if self.prefixes == 0 {
            TacticPolicy::GeneralizedPunOnly
        } else {
            TacticPolicy::PrefixPunOnly
        }
    }
    fn victim_target(&self) -> u64 {
        self.victim() + 5 + VICTIM_DISPLACEMENT as u64
    }
    fn victim_jump(&self) -> Vec<u8> {
        let mut bytes = vec![0xe9];
        bytes.extend_from_slice(&VICTIM_DISPLACEMENT.to_le_bytes());
        bytes
    }
    fn first_overlay(&self) -> Vec<u8> {
        let mut bytes = self.original.clone();
        bytes[PAD + self.len..PAD + self.len + 5].copy_from_slice(&self.victim_jump());
        bytes
    }
    fn window(&self, prefixes: usize) -> AddressRange {
        let free = self.len - prefixes - 1;
        let mut displacement = [0; 4];
        displacement[free..]
            .copy_from_slice(&self.first_overlay()[PAD + self.len..PAD + 5 + prefixes]);
        let low = i128::from(self.pc() + 5 + prefixes as u64)
            + i128::from(i32::from_le_bytes(displacement));
        AddressRange::new(u64::try_from(low).unwrap(), 1 << (8 * free)).unwrap()
    }
    fn selected_allocation(&self) -> AllocationPolicy {
        let window = self.window(self.prefixes);
        let preferred = window.start() + window.len() / 2;
        let range = AddressRange::new(preferred & !4095, 8192).unwrap();
        for other in 0..self.len {
            if other != self.prefixes {
                assert!(!range.overlaps(self.window(other)));
            }
        }
        let mut allocation = AllocationPolicy::near(self.pc()).unwrap();
        allocation.preferred_address = Some(preferred);
        allocation.ranges = vec![range];
        allocation
    }
    fn victim_allocation(&self) -> AllocationPolicy {
        let mut allocation = AllocationPolicy::near(self.victim()).unwrap();
        allocation.preferred_address = Some(self.victim_target());
        allocation.ranges = vec![AddressRange::new(self.victim_target() & !4095, 8192).unwrap()];
        allocation
    }
    fn request<'a>(
        &'a self,
        entries: &'a LegalEntrySet,
        selected: &'a AllocationPolicy,
    ) -> InstallRequest<'a> {
        InstallRequest {
            identity: self.identity,
            code: &self.original,
            base_address: self.base(),
            function: self.function(),
            block: AddressRange::new(self.pc(), self.len).unwrap(),
            logical_pc: self.pc(),
            entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation: selected,
            search: SearchPolicy {
                tactics: self.tactic(),
                max_sites: 1,
                max_upstream_bytes: 0,
                max_displaced_bytes: self.len.max(self.victim_len),
            },
        }
    }
    fn plan(&self) -> PlannedEviction {
        plan_successor(
            &self.request(&self.entries(), &self.selected_allocation()),
            &self.victim_allocation(),
            BundleBudget::default(),
        )
        .unwrap_or_else(|reason| {
            panic!(
                "required L{} P{} victim{} at {:#x}: {reason:?}",
                self.len,
                self.prefixes,
                self.victim_len,
                self.pc()
            )
        })
    }
    fn calls(&self, patched: bool) {
        let before = CALLBACKS.load(Ordering::Relaxed);
        for offset in [
            0,
            self.len,
            self.len + self.victim_len,
            self.len + self.victim_len + 5,
        ] {
            let actual: u64;
            // SAFETY: these are exactly the four original body heads. The final
            // bare RET receives a defined RAX; no lease or mutation is active.
            unsafe {
                core::arch::asm!("call r11", in("r11") self.pc() + offset as u64,
                inlateout("rax") RESULT => actual, clobber_abi("C"));
            }
            assert_eq!(actual, RESULT);
            assert_eq!(
                CALLBACKS.load(Ordering::Relaxed),
                before + u64::from(patched)
            );
            if patched {
                assert_eq!(LAST_PC.load(Ordering::Relaxed), self.pc());
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: installed sources are retired, or the whole fixture is retained.
        unsafe {
            assert_eq!(libc::munmap(self.write.cast(), 2 * PAGE), 0);
            assert_eq!(libc::munmap(self.execute.cast(), 2 * PAGE), 0);
        }
    }
}

fn assert_plan(fixture: &Fixture, planned: &PlannedEviction) {
    assert_eq!(
        planned.kind(),
        EvictionKind::Successor {
            victim: fixture.victim()
        }
    );
    let selected_attempt = planned.metrics().attempts.last().unwrap();
    assert_eq!(selected_attempt.prefix_count, Some(fixture.prefixes as u8));
    assert_eq!(selected_attempt.refusal, None);
    assert_eq!(selected_attempt.victim, fixture.victim());
    assert_eq!(selected_attempt.victim_target, fixture.victim_target());
    let bundle = planned.bundle();
    assert_eq!(bundle.plan().steps().len(), 2);
    assert_eq!(bundle.images().len(), 2);
    assert_eq!(bundle.plan().memory().mappings, 2);
    let victim = bundle.plan().steps()[0].parts();
    assert_eq!(victim.physical_pc, fixture.victim());
    assert_eq!(
        victim.displaced,
        AddressRange::new(fixture.victim(), fixture.victim_len).unwrap()
    );
    assert_eq!(
        victim.writes,
        vec![ByteEdit {
            address: fixture.victim(),
            bytes: fixture.victim_jump()
        }]
    );
    assert_eq!(bundle.images()[0].address(), fixture.victim_target());
    assert_eq!(bundle.images()[0].layout().instrumentation_len, 0);
    assert_eq!(bundle.images()[0].layout().restore_len, 0);
    assert_eq!(bundle.images()[0].instruction_boundaries().len(), 1);
    assert_eq!(
        bundle.images()[0].instruction_boundaries()[0].0,
        fixture.victim()
    );
    let selected = bundle.plan().steps()[1].parts();
    let (consumed, window, store) = match &selected.kind {
        PlanKind::GeneralizedPun(pun) => {
            assert_eq!(fixture.prefixes, 0);
            assert_eq!(usize::from(pun.instruction_len), fixture.len);
            (pun.consumed, pun.target_window, &pun.store)
        }
        PlanKind::PrefixedPun(pun) => {
            assert_ne!(fixture.prefixes, 0);
            assert_eq!(usize::from(pun.instruction_len), fixture.len);
            assert_eq!(usize::from(pun.prefix_count), fixture.prefixes);
            (pun.consumed, pun.target_window, &pun.store)
        }
        other => panic!("T2 selected kind silently changed: {other:?}"),
    };
    assert_eq!(selected.physical_pc, fixture.pc());
    assert_eq!(selected.logical_pc, fixture.pc());
    assert_eq!(
        selected.displaced,
        AddressRange::new(fixture.pc(), fixture.len).unwrap()
    );
    assert_eq!(
        consumed,
        AddressRange::new(fixture.pc(), 5 + fixture.prefixes).unwrap()
    );
    assert_eq!(window, fixture.window(fixture.prefixes));
    assert_eq!(
        bundle.images()[1].address(),
        fixture.selected_allocation().preferred_address.unwrap()
    );
    assert_eq!(selected.writes.len(), 1);
    assert_eq!(selected.writes[0].address, fixture.pc());
    assert_eq!(selected.writes[0].bytes.len(), fixture.len);
    assert_eq!(
        &selected.writes[0].bytes[..fixture.prefixes],
        vec![0x2e; fixture.prefixes]
    );
    assert_eq!(selected.writes[0].bytes[fixture.prefixes], 0xe9);
    let store_address = fixture.pc() - u64::from(fixture.len == 3 && fixture.pc() % 64 == 61);
    assert_eq!(store.address, store_address);
    assert_eq!(store.bytes.len(), fixture.len.next_power_of_two());
    let before_selected = fixture.first_overlay();
    let offset = (store_address - fixture.base()) as usize;
    let mut expected_store = before_selected[offset..offset + store.bytes.len()].to_vec();
    let changed = (fixture.pc() - store_address) as usize;
    expected_store[changed..changed + fixture.len].copy_from_slice(&selected.writes[0].bytes);
    assert_eq!(store.bytes, expected_store);
    let mut fetch = before_selected[PAD..PAD + 5 + fixture.prefixes].to_vec();
    fetch[..fixture.len].copy_from_slice(&selected.writes[0].bytes);
    let displacement = i32::from_le_bytes(fetch[fixture.prefixes + 1..].try_into().unwrap());
    assert_eq!(
        i128::from(fixture.pc() + fetch.len() as u64) + i128::from(displacement),
        i128::from(bundle.images()[1].address())
    );
    let mut overlay = fixture.original.clone();
    for step in bundle.plan().steps() {
        for read in &step.parts().reads {
            let offset = (read.address - fixture.base()) as usize;
            assert_eq!(read.bytes, overlay[offset..offset + read.bytes.len()]);
        }
        for edit in &step.parts().writes {
            let offset = (edit.address - fixture.base()) as usize;
            overlay[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
    }
    assert_eq!(
        bundle.plan().originals(),
        &[ExpectedBytes {
            address: fixture.base(),
            bytes: fixture.original.clone()
        }]
    );
    assert_eq!(
        bundle.plan().final_bytes(),
        &[ExpectedBytes {
            address: fixture.base(),
            bytes: overlay.clone()
        }]
    );
    for range in [
        victim.displaced,
        consumed,
        AddressRange::new(store.address, store.bytes.len()).unwrap(),
    ] {
        assert!(bundle.plan().locks().iter().any(|lock| lock.covers(range)));
    }
    assert_eq!(
        &overlay[PAD + fixture.len + 5..],
        &fixture.original[PAD + fixture.len + 5..],
        "victim tail or later successor changed"
    );
    assert!(!victim.requirements.sigill_router && !selected.requirements.sigill_router);
}

fn expected_mapping(fixture: &Fixture, bundle: &PlannedBundle) -> Vec<u8> {
    let mut bytes = fixture.original_mapping.clone();
    for snapshot in bundle.plan().final_bytes() {
        let offset = (snapshot.address - fixture.execute as usize as u64) as usize;
        bytes[offset..offset + snapshot.bytes.len()].copy_from_slice(&snapshot.bytes);
    }
    bytes
}

fn publish(fixture: &Fixture, bundle: &PlannedBundle) -> InstalledBundle {
    let mut guard = ();
    // SAFETY: exclusive private-child ownership supplies real exclusion, with
    // every source read and continuation drained throughout this borrow.
    let mut lease =
        unsafe { QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.source()]) };
    let (installed, receipt) =
        unsafe { bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize()) }
            .unwrap();
    assert_eq!(receipt.plan().steps(), bundle.plan().steps());
    assert!(!lease.is_poisoned());
    installed // lease and gate borrow end before caller admits application execution.
}

fn retire(fixture: &Fixture, bundle: &PlannedBundle, installed: &mut InstalledBundle) {
    fixture.permissions(false);
    let mut held = vec![fixture.source()];
    held.extend(
        bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    let mut guard = ();
    // SAFETY: this fresh gate drains original and both generated images.
    let mut lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, held) };
    unsafe { installed.retire_with(&mut lease, || fixture.finalize()) }.unwrap();
    assert!(installed.is_retired());
    assert!(!lease.is_poisoned());
    assert_eq!(fixture.observed(), fixture.original_mapping);
}

fn execute(fixture: &Fixture, planned: &PlannedEviction) {
    assert_plan(fixture, planned);
    fixture.permissions(true);
    fixture.calls(false);
    fixture.permissions(false);
    let bundle = planned.bundle();
    let mut installed = publish(fixture, bundle);
    assert_eq!(fixture.observed(), expected_mapping(fixture, bundle));
    fixture.calls(true);
    assert_eq!(installed.routed_entries(), 0);
    retire(fixture, bundle, &mut installed);
    fixture.calls(false);
}

fn lengths() {
    let mut count = 0;
    for victim_len in 5..=15 {
        for (len, prefixes) in GEOMETRIES {
            let fixture = Fixture::new(count, 128, len, prefixes, victim_len);
            let planned = fixture.plan();
            execute(&fixture, &planned);
            count += 1;
        }
    }
    assert_eq!(count, 110);
    println!(
        "victim_lengths=11; selected_geometries=10; required_cycles=110; calls=1320; callbacks=110"
    );
}

fn lines() {
    let (mut positives, mut refusals) = (0, 0);
    for (geometry, (len, prefixes)) in GEOMETRIES.into_iter().enumerate() {
        for offset in 0..64 {
            let fixture = Fixture::new(
                (geometry * 64 + offset) as u64,
                128 + offset,
                len,
                prefixes,
                8,
            );
            if offset + len > 64 {
                assert_eq!(
                    plan_successor(
                        &fixture.request(&fixture.entries(), &fixture.selected_allocation()),
                        &fixture.victim_allocation(),
                        BundleBudget::default()
                    )
                    .unwrap_err(),
                    Refusal::NoPatchWindow
                );
                assert_eq!(fixture.observed(), fixture.original_mapping);
                refusals += 1;
            } else {
                let planned = fixture.plan();
                execute(&fixture, &planned);
                positives += 1;
            }
        }
    }
    assert_eq!((positives, refusals), (620, 20));
    println!(
        "offsets_each=64; required_cycles=620; crossing_refusals=20; calls=7440; callbacks=620"
    );
}

fn pages() {
    let mut count = 0;
    for (len, prefixes) in GEOMETRIES {
        let fixture = Fixture::new(count, PAGE - len, len, prefixes, 15);
        let planned = fixture.plan();
        execute(&fixture, &planned);
        count += 1;
    }
    for victim_len in 5..=15 {
        let fixture = Fixture::new(count, PAGE - 3 - 4, 3, 1, victim_len);
        assert_eq!(fixture.victim() % PAGE as u64, PAGE as u64 - 4);
        let planned = fixture.plan();
        execute(&fixture, &planned);
        count += 1;
    }
    assert_eq!(count, 21);
    println!(
        "selected_fetch_page_crossings=10; whole_victim_page_crossings=11; required_cycles=21; calls=252; callbacks=21"
    );
}

fn prerequisites() {
    let short = Fixture::new(0, 128, 2, 0, 4);
    assert_eq!(
        plan_successor(
            &short.request(&short.entries(), &short.selected_allocation()),
            &short.victim_allocation(),
            BundleBudget::default()
        )
        .unwrap_err(),
        Refusal::NoPatchWindow
    );
    let fixture = Fixture::new(1, 128, 3, 1, 15);
    let selected = fixture.selected_allocation();
    let victim = fixture.victim_allocation();
    let entries = fixture.entries();
    let mut request = fixture.request(&entries, &selected);
    request.function =
        AddressRange::new(fixture.pc(), fixture.len + fixture.victim_len - 1).unwrap();
    assert_eq!(
        plan_successor(&request, &victim, BundleBudget::default()).unwrap_err(),
        Refusal::NoPatchWindow
    );
    let mut limited = fixture.entries();
    limited.scope = AddressRange::new(fixture.pc(), fixture.len).unwrap();
    assert_eq!(
        plan_successor(
            &fixture.request(&limited, &selected),
            &victim,
            BundleBudget::default()
        )
        .unwrap_err(),
        Refusal::UnresolvedEntry
    );
    let mut interior = fixture.entries();
    interior.entries.push(LegalEntry {
        address: fixture.victim() + 1,
        requires_endbr: false,
    });
    assert_eq!(
        plan_successor(
            &fixture.request(&interior, &selected),
            &victim,
            BundleBudget::default()
        )
        .unwrap_err(),
        Refusal::NotInstructionHead
    );
    let mut request = fixture.request(&entries, &selected);
    request.code = &fixture.original[..PAD + fixture.len + fixture.victim_len - 1];
    request.function = AddressRange::new(fixture.pc(), fixture.len).unwrap();
    assert!(
        matches!(
            plan_successor(&request, &victim, BundleBudget::default()),
            Err(Refusal::Backend(_))
        ),
        "incomplete original decode cannot be silently scanned partially"
    );
    let mut request = fixture.request(&entries, &selected);
    request.search.tactics = TacticPolicy::RelocationOnly;
    assert!(matches!(
        plan_successor(&request, &victim, BundleBudget::default()),
        Err(Refusal::UnsupportedSemantics(_))
    ));
    let mut request = fixture.request(&entries, &selected);
    request.code = &fixture.original[..PAD + fixture.len];
    request.function = AddressRange::new(fixture.pc(), fixture.len).unwrap();
    assert_eq!(
        plan_successor(&request, &victim, BundleBudget::default()).unwrap_err(),
        Refusal::NoPatchWindow
    );
    let mut request = fixture.request(&entries, &selected);
    request.search.max_displaced_bytes = fixture.victim_len - 1;
    assert_eq!(
        plan_successor(&request, &victim, BundleBudget::default()).unwrap_err(),
        Refusal::NoPatchWindow
    );
    let one = Fixture::new(2, 128, 1, 0, 8);
    let entries = one.entries();
    let selected = one.selected_allocation();
    let mut request = one.request(&entries, &selected);
    request.search.tactics = TacticPolicy::PrefixPunOnly;
    assert_eq!(
        plan_successor(&request, &one.victim_allocation(), BundleBudget::default()).unwrap_err(),
        Refusal::NoPatchWindow
    );
    assert_eq!(fixture.observed(), fixture.original_mapping);
    assert_eq!(short.observed(), short.original_mapping);
    assert_eq!(one.observed(), one.original_mapping);
    println!("required_prerequisite_refusals=9; source_changes=0");
}

fn collision() {
    let fixture = Fixture::new(0, 128, 3, 1, 15);
    let planned = fixture.plan();
    assert_plan(&fixture, &planned);
    let bundle = planned.bundle();
    let first = bundle.plan().steps()[0].parts().allocations[0].range;
    let second = bundle.plan().steps()[1].parts().allocations[0].range;
    let mapping = unsafe {
        libc::mmap(
            second.start() as *mut _,
            second.len() as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_eq!(mapping as usize as u64, second.start());
    {
        let mut guard = ();
        let mut lease =
            unsafe { QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.source()]) };
        let failure =
            unsafe { bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize()) }
                .err()
                .unwrap();
        assert!(matches!(failure.reason, Refusal::Backend(_)));
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert!(!lease.is_poisoned());
    }
    assert_eq!(fixture.observed(), fixture.original_mapping);
    let mut residency = vec![0; first.len() as usize / PAGE];
    assert_eq!(
        unsafe {
            libc::mincore(
                first.start() as *mut _,
                first.len() as usize,
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
        for pc in image.program_counter_mappings() {
            assert_eq!(translate_program_counter(pc.generated_start()), None);
        }
    }
    assert_eq!(unsafe { libc::munmap(mapping, second.len() as usize) }, 0);
    execute(&fixture, &planned);
    println!("second_mapping_collision_beforewrite=1; cleanup_and_same_plan_retry=passed");
}

fn stale_and_leases() {
    for (case, (len, prefixes, line, stale_offset)) in
        [(2, 0, 128, 2 + 10), (3, 1, 128, 3), (3, 2, 128 + 61, -1)]
            .into_iter()
            .enumerate()
    {
        let fixture = Fixture::new(case as u64, line, len, prefixes, 15);
        let planned = fixture.plan();
        let address = (fixture.pc() as i128 + stale_offset as i128) as u64;
        let index = (address - fixture.execute as usize as u64) as usize;
        unsafe {
            *fixture.write.add(index) ^= 1;
        }
        let changed = fixture.observed();
        {
            let mut guard = ();
            let mut lease = unsafe {
                QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.source()])
            };
            let failure = unsafe {
                planned
                    .bundle()
                    .publish_with(&[fixture.alias()], &mut lease, || fixture.finalize())
            }
            .err()
            .unwrap();
            assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
            assert_eq!(failure.stage, FailureStage::BeforeWrite);
            assert!(!lease.is_poisoned());
        }
        assert_eq!(fixture.observed(), changed);
        unsafe {
            *fixture.write.add(index) ^= 1;
        }
        execute(&fixture, &planned);
    }
    let fixture = Fixture::new(10, 128, 4, 2, 8);
    let planned = fixture.plan();
    let bundle = planned.bundle();
    for stale in [false, true] {
        let mut guard = ();
        let mut identity = fixture.identity;
        let held = if stale {
            identity.generation += 1;
            vec![fixture.source()]
        } else {
            vec![AddressRange::new(fixture.pc(), fixture.len).unwrap()]
        };
        let mut lease = unsafe { QuiescenceLease::new(&mut guard, identity, held) };
        let failure =
            unsafe { bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize()) }
                .err()
                .unwrap();
        assert_eq!(
            failure.reason,
            if stale {
                Refusal::StaleGeneration
            } else {
                Refusal::DependencyNotHeld
            }
        );
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert!(!lease.is_poisoned());
        assert_eq!(fixture.observed(), fixture.original_mapping);
    }
    fixture.permissions(true);
    fixture.calls(false);
    fixture.permissions(false);
    let mut installed = publish(&fixture, bundle);
    fixture.calls(true);
    for missing in 0..2 {
        let mut held = vec![fixture.source()];
        held.extend(
            bundle.plan().steps()[1 - missing]
                .parts()
                .allocations
                .iter()
                .map(|a| a.range),
        );
        let mut guard = ();
        let mut lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, held) };
        let failure = unsafe { installed.retire(&mut lease) }.unwrap_err();
        assert_eq!(failure.reason, Refusal::DependencyNotHeld);
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert!(!lease.is_poisoned());
        assert_eq!(fixture.observed(), expected_mapping(&fixture, bundle));
    }
    retire(&fixture, bundle, &mut installed);
    fixture.calls(false);
    println!(
        "stale_bytes_beforewrite=3; publish_lease_beforewrite=2; retirement_missing_image_beforewrite=2; required_retries=4"
    );
}

fn budgets() {
    let fixture = Fixture::new(0, 128, 3, 1, 8);
    let entries = fixture.entries();
    let selected = fixture.selected_allocation();
    let victim = fixture.victim_allocation();
    let planned = fixture.plan();
    let memory = planned.bundle().plan().memory();
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
            max_virtual_bytes: memory.virtual_bytes - 1,
            ..BundleBudget::default()
        },
        BundleBudget {
            max_backing_bytes: memory.backing_bytes - 1,
            ..BundleBudget::default()
        },
        BundleBudget {
            max_virtual_span: memory.virtual_span - 1,
            ..BundleBudget::default()
        },
    ] {
        assert_eq!(
            plan_successor(&fixture.request(&entries, &selected), &victim, budget).unwrap_err(),
            Refusal::AllocationUnavailable
        );
    }
    for side in 0..2 {
        for zero in 0..3 {
            let mut selected = selected.clone();
            let mut victim = victim.clone();
            let limits = if side == 0 {
                &mut selected
            } else {
                &mut victim
            };
            match zero {
                0 => limits.max_candidates = 0,
                1 => limits.max_mappings = 0,
                2 => limits.max_mapped_bytes = 0,
                _ => unreachable!(),
            }
            assert_eq!(
                plan_successor(
                    &fixture.request(&entries, &selected),
                    &victim,
                    BundleBudget::default()
                )
                .unwrap_err(),
                Refusal::AllocationUnavailable
            );
        }
    }
    assert_eq!(fixture.observed(), fixture.original_mapping);
    execute(&fixture, &planned);
    println!("aggregate_refusals=5; per_image_allocation_refusals=6; required_retry=1");
}

fn failure_inventory() {
    let fixture = Fixture::new(0, 128, 2, 1, 8);
    let planned = fixture.plan();
    assert_plan(&fixture, &planned);
    let selected = fixture.selected_allocation();
    let entries = fixture.entries();
    let mut victim = fixture.victim_allocation();
    victim.max_candidates = 1;
    victim.ranges =
        vec![AddressRange::new((fixture.victim_target() & !4095) + 0x2_0000, 8192).unwrap()];
    let failure = plan_successor_detailed(
        &fixture.request(&entries, &selected),
        &victim,
        BundleBudget::default(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(failure.attempts[0].prefix_count, None);
    assert_eq!(failure.attempts[0].victim, fixture.victim());
    assert_eq!(failure.attempts[0].victim_target, fixture.victim_target());
    assert_eq!(
        failure.attempts[0].refusal,
        Some(Refusal::AllocationUnavailable)
    );
    assert_eq!(fixture.observed(), fixture.original_mapping);

    let crossing = Fixture::new(1, 128 + 63, 2, 1, 8);
    let mut victim = crossing.victim_allocation();
    victim.max_candidates = 2;
    let failure = plan_successor_detailed(
        &crossing.request(&crossing.entries(), &crossing.selected_allocation()),
        &victim,
        BundleBudget::default(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert_eq!(failure.attempts.len(), 2);
    assert_eq!(failure.attempts[0].prefix_count, Some(1));
    assert_eq!(failure.attempts[0].refusal, Some(Refusal::NoPatchWindow));
    assert_eq!(failure.attempts[0].victim_target, crossing.victim_target());
    assert_eq!(failure.attempts[1].prefix_count, None);
    assert_eq!(
        failure.attempts[1].refusal,
        Some(Refusal::AllocationUnavailable)
    );
    assert_eq!(
        failure.attempts[1].victim_target,
        crossing.victim_target() + 0x1_0000
    );
    assert_eq!(crossing.observed(), crossing.original_mapping);
    println!(
        "inventory_planning_refusals=2; victim_only_is_not_b2=proved; selected_refusal_preserved=proved"
    );
}

unsafe extern "C" fn replace_selected(context: *mut HookContext) {
    // SAFETY: the selected replacement receives the emitter's initialized frame.
    unsafe {
        (*context).rax = 99;
        LAST_PC.store((*context).instruction_pointer, Ordering::Relaxed);
    }
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

fn replacement() {
    let mut fixture = Fixture::new(0, 128, 3, 0, 15);
    // This separate fixture has exactly INC RAX; whole NOP; RET in its body.
    // In particular, no later MOV can conceal execution of the replaced INC.
    fixture.original[PAD..PAD + 3].copy_from_slice(&[0x48, 0xff, 0xc0]);
    fixture
        .original
        .truncate(PAD + fixture.len + fixture.victim_len);
    fixture.original.push(0xc3);
    fixture.original_mapping.fill(0xa5);
    fixture.original_mapping[fixture.offset - PAD..fixture.offset - PAD + fixture.original.len()]
        .copy_from_slice(&fixture.original);
    // SAFETY: the source is gated, never executed yet, and owned by this child.
    unsafe {
        std::ptr::copy_nonoverlapping(fixture.original_mapping.as_ptr(), fixture.write, 2 * PAGE);
    }
    let function = AddressRange::new(fixture.pc(), fixture.len + fixture.victim_len + 1).unwrap();
    let heads = [fixture.pc(), fixture.victim(), fixture.victim() + 15];
    let entries = LegalEntrySet {
        identity: fixture.identity,
        scope: function,
        provenance: EntryProvenance::Declared("INC replacement and whole successor NOP".into()),
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
    let selected = fixture.selected_allocation();
    let request = InstallRequest {
        identity: fixture.identity,
        code: &fixture.original,
        base_address: fixture.base(),
        function,
        block: AddressRange::new(fixture.pc(), fixture.len).unwrap(),
        logical_pc: fixture.pc(),
        entries: &entries,
        hook: replace_selected,
        semantics: HookSemantics::ReplaceFirst,
        allocation: &selected,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            max_sites: 1,
            max_upstream_bytes: 0,
            max_displaced_bytes: fixture.victim_len,
        },
    };
    let planned = plan_successor(
        &request,
        &fixture.victim_allocation(),
        BundleBudget::default(),
    )
    .expect("required selected-only replacement after successor eviction refused");
    assert_plan(&fixture, &planned);
    let call_heads = |patched: bool| {
        let before = CALLBACKS.load(Ordering::Relaxed);
        for (index, head) in heads.into_iter().enumerate() {
            let actual: u64;
            // SAFETY: these are the three original body heads; all source and
            // generated execution is admitted only after the live lease ends.
            unsafe {
                core::arch::asm!("call r11", in("r11") head,
                    inlateout("rax") 42_u64 => actual, clobber_abi("C"));
            }
            assert_eq!(
                actual,
                if index == 0 {
                    if patched { 99 } else { 43 }
                } else {
                    42
                },
                "selected INC must be replaced alone; direct victim/RET preserve RAX"
            );
            assert_eq!(
                CALLBACKS.load(Ordering::Relaxed),
                before + u64::from(patched),
                "only the selected entry invokes the replacement callback"
            );
            if patched {
                assert_eq!(LAST_PC.load(Ordering::Relaxed), fixture.pc());
            }
        }
    };
    fixture.permissions(true);
    call_heads(false);
    fixture.permissions(false);
    let bundle = planned.bundle();
    let mut installed = publish(&fixture, bundle);
    assert_eq!(fixture.observed(), expected_mapping(&fixture, bundle));
    call_heads(true);
    assert_eq!(installed.routed_entries(), 0);
    retire(&fixture, bundle, &mut installed);
    call_heads(false);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
    println!(
        "replacement_required_cycles=1; calls=9; callbacks=1; selected_original=43; selected_installed=99; selected_retired=43; direct_victim_and_ret=42"
    );
}

#[test]
fn successor_eviction_contract_puzzles() {
    if let Ok(mode) = std::env::var(ENV) {
        match mode.as_str() {
            "lengths" => lengths(),
            "lines" => lines(),
            "pages" => pages(),
            "prerequisites" => prerequisites(),
            "collision" => collision(),
            "stale-leases" => stale_and_leases(),
            "budgets" => budgets(),
            "inventory" => failure_inventory(),
            "replacement" => replacement(),
            _ => panic!("unknown child mode {mode}"),
        }
        println!("successor-eviction-complete:{mode}");
        return;
    }
    for mode in [
        "lengths",
        "lines",
        "pages",
        "prerequisites",
        "collision",
        "stale-leases",
        "budgets",
        "inventory",
        "replacement",
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
        // SAFETY: only async-signal-safe resource-limit calls precede exec.
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
                let output = child.wait_with_output().unwrap();
                panic!("T2 child {mode} timed out: {output:?}");
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
        assert!(stdout.contains(&format!("successor-eviction-complete:{mode}")));
        print!("{stdout}");
    }
}
