#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Draft required T3 contracts. No native result is claimed until this runs.
//! Four explicit body heads are exercised; filler NOP heads are not counted.

use liteinst2::bundle::{BundleBudget, InstalledBundle, PlannedBundle, WritableAlias};
use liteinst2::contracts::*;
use liteinst2::neighbor::{
    NeighborAttemptStage, NeighborSearch, PlannedNeighbor, plan_neighbor, plan_neighbor_detailed,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::{HookContext, translate_program_counter};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const PAD: usize = 16;
const SEED: u64 = 42;
const VICTIM_VALUE: u64 = 0x1937_5a82_4b6c_d0e1;
const ENV: &str = "LITEINST_NEIGHBOR_EVICTION_CONTRACT_CHILD";
const TEST: &str = "neighbor_eviction_contract_puzzles";
static CALLBACKS: AtomicU64 = AtomicU64::new(0);
static LAST_PC: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the emitter supplies its initialized selected-site frame.
    LAST_PC.store(unsafe { (*context).instruction_pointer }, Ordering::Relaxed);
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn replace(context: *mut HookContext) {
    // SAFETY: replacing only the selected instruction may modify saved RAX.
    unsafe {
        (*context).rax = 99;
        LAST_PC.store((*context).instruction_pointer, Ordering::Relaxed);
    }
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

fn selected_bytes(len: usize) -> Vec<u8> {
    match len {
        1 => vec![0x90], // Required short-length refusal, never a positive.
        2 => vec![0xff, 0xc0],
        3 => vec![0x48, 0xff, 0xc0],
        4 => vec![0x48, 0x83, 0xc0, 1],
        5 => vec![0xb8, 0, 0, 0, 0], // Required long-length refusal.
        _ => panic!("unsupported selected fixture length"),
    }
}

fn victim_bytes(len: usize) -> Vec<u8> {
    if len == 9 {
        return vec![0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0];
    }
    assert!((10..=15).contains(&len));
    let mut bytes = vec![0x2e; len - 10];
    bytes.extend_from_slice(&[0x48, 0xb8]);
    bytes.extend_from_slice(&VICTIM_VALUE.to_le_bytes());
    bytes
}

struct Fixture {
    write: *mut u8,
    execute: *mut u8,
    selected_offset: usize,
    victim_offset: usize,
    len: usize,
    victim_len: usize,
    source_offset: usize,
    original: Vec<u8>,
    original_mapping: Vec<u8>,
    identity: CodeIdentity,
}

impl Fixture {
    fn new(case: u64, selected: usize, delta: i64, len: usize, victim_len: usize) -> Self {
        let victim = usize::try_from(selected as i64 + delta).unwrap();
        let low = selected.min(victim);
        let high = (selected + len + 1).max(victim + victim_len + 1);
        assert!(low >= PAD && high <= 2 * PAGE);
        assert!(selected + len < victim || victim + victim_len < selected);
        let source_offset = low - PAD;
        let mut original = vec![0x90; high - source_offset];
        let selected_index = selected - source_offset;
        let victim_index = victim - source_offset;
        original[selected_index..selected_index + len].copy_from_slice(&selected_bytes(len));
        original[selected_index + len] = 0xc3;
        original[victim_index..victim_index + victim_len]
            .copy_from_slice(&victim_bytes(victim_len));
        original[victim_index + victim_len] = 0xc3;
        let mut original_mapping = vec![0xa5; 2 * PAGE];
        original_mapping[source_offset..high].copy_from_slice(&original);
        let address = 0x3800_0000_0000_u64 + case * 0x2_0000_0000;
        // SAFETY: this bounded child exclusively owns both aliases, using
        // MAP_FIXED_NOREPLACE so no unrelated source is displaced.
        let (write, execute) = unsafe {
            let fd = libc::memfd_create(c"neighbor-eviction-contract".as_ptr(), libc::MFD_CLOEXEC);
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
            selected_offset: selected,
            victim_offset: victim,
            len,
            victim_len,
            source_offset,
            original,
            original_mapping,
            identity: CodeIdentity {
                source: SourceIdentity([case as u8; 32]),
                mapping: case + 1,
                generation: 1,
            },
        }
    }
    fn selected(&self) -> u64 {
        self.execute as usize as u64 + self.selected_offset as u64
    }
    fn victim(&self) -> u64 {
        self.execute as usize as u64 + self.victim_offset as u64
    }
    fn relay(&self) -> u64 {
        self.victim() + 5
    }
    fn source(&self) -> AddressRange {
        AddressRange::new(
            self.execute as usize as u64 + self.source_offset as u64,
            self.original.len(),
        )
        .unwrap()
    }
    fn function(&self) -> AddressRange {
        let start = self.selected().min(self.victim());
        let end =
            (self.selected() + self.len as u64 + 1).max(self.victim() + self.victim_len as u64 + 1);
        AddressRange::new(start, (end - start) as usize).unwrap()
    }
    fn heads(&self) -> [u64; 4] {
        [
            self.selected(),
            self.victim(),
            self.selected() + self.len as u64,
            self.victim() + self.victim_len as u64,
        ]
    }
    fn selected_target(&self) -> u64 {
        self.selected() + 0x0400_0017
    }
    fn victim_target(&self) -> u64 {
        self.victim() + 0x0600_0043
    }
    fn allocation(&self, selected: bool) -> AllocationPolicy {
        let target = if selected {
            self.selected_target()
        } else {
            self.victim_target()
        };
        let mut allocation = AllocationPolicy::near(if selected {
            self.relay()
        } else {
            self.victim()
        })
        .unwrap();
        allocation.preferred_address = Some(target);
        allocation.ranges = vec![AddressRange::new(target & !4095, 8192).unwrap()];
        allocation.max_candidates = 4;
        allocation
    }
    fn entries(&self) -> LegalEntrySet {
        LegalEntrySet {
            identity: self.identity,
            scope: self.function(),
            provenance: EntryProvenance::Declared(
                "two independent INC/MOVABS/RET streams with NOP filler".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: self
                .heads()
                .into_iter()
                .map(|address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        }
    }
    fn request<'a>(
        &'a self,
        entries: &'a LegalEntrySet,
        allocation: &'a AllocationPolicy,
        replacement: bool,
    ) -> InstallRequest<'a> {
        InstallRequest {
            identity: self.identity,
            code: &self.original,
            base_address: self.source().start(),
            function: self.function(),
            block: AddressRange::new(self.selected(), self.len).unwrap(),
            logical_pc: self.selected(),
            entries,
            hook: if replacement { replace } else { observe },
            semantics: if replacement {
                HookSemantics::ReplaceFirst
            } else {
                HookSemantics::Observe
            },
            allocation,
            search: SearchPolicy {
                max_sites: 1,
                max_upstream_bytes: 0,
                max_displaced_bytes: self.len.max(self.victim_len),
                ..SearchPolicy::default()
            },
        }
    }
    fn search(&self) -> NeighborSearch {
        NeighborSearch {
            forced_victim: Some(self.victim()),
            max_victims: 1,
            max_pairs: 16,
        }
    }
    fn plan(&self, replacement: bool) -> PlannedNeighbor {
        plan_neighbor(
            &self.request(&self.entries(), &self.allocation(true), replacement),
            &self.allocation(false),
            self.search(),
            BundleBudget::default(),
        )
        .unwrap_or_else(|reason| {
            panic!(
                "required L{} M{} delta{}: {reason:?}",
                self.len,
                self.victim_len,
                self.victim() as i128 - self.selected() as i128
            )
        })
    }
    fn observed(&self) -> Vec<u8> {
        // SAFETY: the backing is live and owned exclusively in this child.
        unsafe { std::slice::from_raw_parts(self.write, 2 * PAGE) }.to_vec()
    }
    fn permissions(&self, execute: bool) {
        let protection = libc::PROT_READ | if execute { libc::PROT_EXEC } else { 0 };
        // SAFETY: every application executor/continuation is excluded here.
        assert_eq!(
            unsafe { libc::mprotect(self.execute.cast(), 2 * PAGE, protection) },
            0
        );
    }
    fn finalize(&self) -> Result<(), Refusal> {
        // SAFETY: both fetch pages belong to this fixture and remain gated.
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
        // SAFETY: exact alias of owned source backing, retained through retirement.
        unsafe {
            WritableAlias::new(
                AddressRange::new(self.execute as usize as u64, 2 * PAGE).unwrap(),
                self.write,
            )
        }
        .unwrap()
    }
    fn calls(&self, patched: bool, replacement: bool) {
        let before = CALLBACKS.load(Ordering::Relaxed);
        for (index, head) in self.heads().into_iter().enumerate() {
            let actual: u64;
            // SAFETY: exactly the four declared original body heads, with no
            // live lease, concurrent execution or pending publication.
            unsafe {
                core::arch::asm!("call r11", in("r11") head, inlateout("rax") SEED => actual, clobber_abi("C"));
            }
            let expected = match index {
                0 if patched && replacement => 99,
                0 => SEED + 1,
                1 => VICTIM_VALUE,
                _ => SEED,
            };
            assert_eq!(
                actual, expected,
                "incorrect value at original entry {head:#x}"
            );
            assert_eq!(
                CALLBACKS.load(Ordering::Relaxed),
                before + u64::from(patched),
                "victim and successor entries must not add the selected hook"
            );
            if patched {
                assert_eq!(LAST_PC.load(Ordering::Relaxed), self.selected());
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: successful installs are retired. KeepGated fixtures are forgotten.
        unsafe {
            assert_eq!(libc::munmap(self.write.cast(), 2 * PAGE), 0);
            assert_eq!(libc::munmap(self.execute.cast(), 2 * PAGE), 0);
        }
    }
}

fn near_jump(head: u64, target: u64) -> Vec<u8> {
    let displacement = i32::try_from(i128::from(target) - i128::from(head) - 5).unwrap();
    let mut bytes = vec![0xe9];
    bytes.extend_from_slice(&displacement.to_le_bytes());
    bytes
}

fn assert_plan(fixture: &Fixture, planned: &PlannedNeighbor) {
    let geometry = planned.geometry();
    assert_eq!(geometry.selected, fixture.selected());
    assert_eq!(geometry.selected_len, fixture.len);
    assert_eq!(geometry.victim, fixture.victim());
    assert_eq!(geometry.victim_len, fixture.victim_len);
    assert_eq!(geometry.relay, fixture.relay());
    let signed =
        i8::try_from(i128::from(fixture.relay()) - i128::from(fixture.selected()) - 2).unwrap();
    assert_eq!(geometry.rel8, signed);
    assert_eq!(geometry.selected_target, fixture.selected_target());
    assert_eq!(geometry.victim_target, fixture.victim_target());
    assert_eq!(planned.metrics().selected_fallthrough_redirects, 3);
    assert_eq!(planned.metrics().victim_fallthrough_redirects, 2);
    assert_eq!(planned.metrics().victims_examined, 1);
    assert!(
        planned.metrics().pairs_examined > 0
            && planned.metrics().pairs_examined <= fixture.search().max_pairs
    );
    assert!(!planned.metrics().attempts.is_empty());
    assert_eq!(planned.metrics().attempts.last().unwrap().refusal, None);
    let success = planned.metrics().attempts.last().unwrap();
    assert_eq!(success.stage, NeighborAttemptStage::Composition);
    assert_eq!(success.victim, fixture.victim());
    assert_eq!(success.victim_target, Some(fixture.victim_target()));
    assert_eq!(success.selected_target, Some(fixture.selected_target()));
    let bundle = planned.bundle();
    let steps = bundle.plan().steps();
    assert_eq!(steps.len(), 2);
    assert_eq!(bundle.images().len(), 2);
    assert!(
        steps[0].parts().physical_pc > steps[1].parts().physical_pc,
        "composition must be descending in both directions"
    );
    let selected = steps
        .iter()
        .find(|step| step.parts().physical_pc == fixture.selected())
        .unwrap()
        .parts();
    let victim = steps
        .iter()
        .find(|step| step.parts().physical_pc == fixture.victim())
        .unwrap()
        .parts();
    assert_eq!(
        selected.displaced,
        AddressRange::new(fixture.selected(), fixture.len).unwrap()
    );
    assert_eq!(
        victim.displaced,
        AddressRange::new(fixture.victim(), fixture.victim_len).unwrap()
    );
    assert_eq!(
        selected.writes,
        vec![ByteEdit {
            address: fixture.selected(),
            bytes: vec![0xeb, signed as u8]
        }]
    );
    let mut victim_edits = vec![
        near_jump(fixture.victim(), fixture.victim_target()),
        near_jump(fixture.relay(), fixture.selected_target()),
    ];
    let victim_patch: Vec<u8> = victim_edits.drain(..).flatten().collect();
    let mut actual_victim_patch = Vec::new();
    let mut next = fixture.victim();
    for edit in &victim.writes {
        assert_eq!(edit.address, next);
        actual_victim_patch.extend_from_slice(&edit.bytes);
        next += edit.bytes.len() as u64;
    }
    assert_eq!(actual_victim_patch, victim_patch);
    assert_eq!(next, fixture.victim() + 10);
    for (head, target) in [
        (fixture.victim(), fixture.victim_target()),
        (fixture.relay(), fixture.selected_target()),
    ] {
        let offset = (head - fixture.victim()) as usize;
        let actual = i32::from_le_bytes(
            actual_victim_patch[offset + 1..offset + 5]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            i128::from(head + 5) + i128::from(actual),
            i128::from(target)
        );
    }
    assert_ne!(fixture.victim_target(), fixture.selected_target());
    let victim_image = bundle
        .images()
        .iter()
        .find(|image| image.address() == fixture.victim_target())
        .unwrap();
    assert_eq!(victim_image.layout().instrumentation_len, 0);
    assert_eq!(victim_image.layout().restore_len, 0);
    assert_eq!(victim_image.instruction_boundaries().len(), 1);
    assert_eq!(victim_image.instruction_boundaries()[0].0, fixture.victim());
    assert!(
        bundle
            .images()
            .iter()
            .any(|image| image.address() == fixture.selected_target())
    );
    let mut overlay = fixture.original.clone();
    for step in steps {
        let parts = step.parts();
        assert_eq!(parts.identity, fixture.identity);
        assert!(!parts.requirements.sigill_router);
        assert!(parts.requirements.quiescent && parts.requirements.sync_core);
        assert_eq!(
            parts.reads,
            vec![ExpectedBytes {
                address: fixture.source().start(),
                bytes: overlay.clone()
            }]
        );
        for edit in &parts.writes {
            let start = (edit.address - fixture.source().start()) as usize;
            overlay[start..start + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
    }
    assert_eq!(
        bundle.plan().originals(),
        &[ExpectedBytes {
            address: fixture.source().start(),
            bytes: fixture.original.clone()
        }]
    );
    assert_eq!(
        bundle.plan().final_bytes(),
        &[ExpectedBytes {
            address: fixture.source().start(),
            bytes: overlay.clone()
        }]
    );
    for range in [selected.displaced, victim.displaced] {
        assert!(
            bundle.plan().locks().iter().any(|lock| lock.covers(range)),
            "whole original instruction including unchanged tail must remain locked"
        );
    }
    let selected_index = (fixture.selected() - fixture.source().start()) as usize;
    let victim_index = (fixture.victim() - fixture.source().start()) as usize;
    assert_eq!(
        &overlay[selected_index + 2..selected_index + fixture.len],
        &fixture.original[selected_index + 2..selected_index + fixture.len]
    );
    assert_eq!(
        &overlay[victim_index + 10..victim_index + fixture.victim_len],
        &fixture.original[victim_index + 10..victim_index + fixture.victim_len]
    );
    let mut independent = fixture.original.clone();
    independent[selected_index..selected_index + 2].copy_from_slice(&[0xeb, signed as u8]);
    independent[victim_index..victim_index + 10].copy_from_slice(&victim_patch);
    assert_eq!(overlay, independent, "no additional source byte may change");
    assert_eq!(bundle.plan().memory().mappings, 2);
    let mut mapped_bytes = 0;
    let mut first = u64::MAX;
    let mut last = 0;
    for (step, image) in steps.iter().zip(bundle.images()) {
        let start = image.address() & !4095;
        let end = (image.address() + image.bytes().len() as u64 + 4095) & !4095;
        let range = AddressRange::new(start, (end - start) as usize).unwrap();
        assert_eq!(
            step.parts().allocations,
            vec![AllocationRequest {
                range,
                alignment: 4096
            }]
        );
        mapped_bytes += end - start;
        first = first.min(start);
        last = last.max(end);
    }
    let memory = bundle.plan().memory();
    assert_eq!(memory.virtual_bytes, mapped_bytes);
    assert_eq!(memory.backing_bytes, mapped_bytes);
    assert_eq!(memory.virtual_pages, (mapped_bytes / PAGE as u64) as usize);
    assert_eq!(memory.backing_pages, memory.virtual_pages);
    assert_eq!(memory.virtual_span, last - first);
}

fn expected_mapping(fixture: &Fixture, bundle: &PlannedBundle) -> Vec<u8> {
    let mut mapping = fixture.original_mapping.clone();
    for snapshot in bundle.plan().final_bytes() {
        let start = (snapshot.address - fixture.execute as usize as u64) as usize;
        mapping[start..start + snapshot.bytes.len()].copy_from_slice(&snapshot.bytes);
    }
    mapping
}

fn all_ranges(fixture: &Fixture, bundle: &PlannedBundle) -> Vec<AddressRange> {
    let mut held = vec![fixture.source()];
    held.extend(
        bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|step| step.parts().allocations.iter().map(|a| a.range)),
    );
    held
}

fn publish(fixture: &Fixture, bundle: &PlannedBundle) -> InstalledBundle {
    let mut guard = ();
    // SAFETY: exclusive child ownership drains all source executions and continuations.
    let mut lease =
        unsafe { QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.source()]) };
    let (installed, receipt) =
        unsafe { bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize()) }
            .unwrap();
    assert_eq!(receipt.plan().steps(), bundle.plan().steps());
    assert!(!lease.is_poisoned());
    installed // The lease ends before the caller executes any original head.
}

fn retire(fixture: &Fixture, bundle: &PlannedBundle, installed: &mut InstalledBundle) {
    fixture.permissions(false);
    let mut guard = ();
    // SAFETY: fresh exclusion covers the source and both generated allocations.
    let mut lease =
        unsafe { QuiescenceLease::new(&mut guard, fixture.identity, all_ranges(fixture, bundle)) };
    unsafe { installed.retire_with(&mut lease, || fixture.finalize()) }.unwrap();
    assert!(!lease.is_poisoned());
    assert!(installed.is_retired());
    assert_eq!(fixture.observed(), fixture.original_mapping);
}

fn execute(fixture: &Fixture, planned: &PlannedNeighbor, replacement: bool) {
    assert_plan(fixture, planned);
    fixture.permissions(true);
    fixture.calls(false, replacement);
    fixture.permissions(false);
    let bundle = planned.bundle();
    let mut installed = publish(fixture, bundle);
    assert_eq!(fixture.observed(), expected_mapping(fixture, bundle));
    assert_eq!(installed.routed_entries(), 0);
    fixture.calls(true, replacement);
    retire(fixture, bundle, &mut installed);
    fixture.calls(false, replacement);
}

fn endpoints() {
    let mut cases = 0;
    for len in 2..=4 {
        for victim_len in 10..=15 {
            for (delta, rel8) in [(-131, -128_i8), (124, 127_i8)] {
                let fixture = Fixture::new(cases, 256, delta, len, victim_len);
                let planned = fixture.plan(false);
                assert_eq!(planned.geometry().rel8, rel8);
                execute(&fixture, &planned, false);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 36);
    println!(
        "endpoint_required_cycles=36; explicit_entries_per_cycle=4; calls=432; callbacks=36; signed_limits=-128,+127"
    );
}

fn outside() {
    let mut cases = 0;
    for len in 2..=4 {
        for victim_len in 10..=15 {
            for delta in [-132, 125] {
                let fixture = Fixture::new(cases, 256, delta, len, victim_len);
                let failure = plan_neighbor_detailed(
                    &fixture.request(&fixture.entries(), &fixture.allocation(true), false),
                    &fixture.allocation(false),
                    fixture.search(),
                    BundleBudget::default(),
                )
                .unwrap_err();
                assert_eq!(failure.reason, Refusal::NoPatchWindow);
                assert_eq!(fixture.observed(), fixture.original_mapping);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 36);
    println!("outside_rel8_required_refusals=36; source_changes=0; forced_victim_substitutions=0");
}

fn boundaries() {
    let mut cases = 0;
    let mut multi_page_images = 0;
    for len in 2..=4 {
        for victim_len in 10..=15 {
            for delta in [-64_i64, 64] {
                for boundary in [320, PAGE] {
                    // Both EB bytes, as well as the original selected instruction,
                    // cross the line/page boundary. Full quiescence is required.
                    let selected = boundary - 1;
                    let fixture = Fixture::new(cases, selected, delta, len, victim_len);
                    let planned = fixture.plan(false);
                    assert_eq!(planned.bundle().plan().memory().virtual_pages, 2);
                    execute(&fixture, &planned, false);
                    cases += 1;
                    // The ten rewritten victim bytes cross the same boundary.
                    let victim = boundary - 4;
                    let selected = usize::try_from(victim as i64 - delta).unwrap();
                    let fixture = Fixture::new(cases, selected, delta, len, victim_len);
                    let planned = fixture.plan(false);
                    let crosses_generated_page = boundary == PAGE && delta == 64;
                    assert_eq!(
                        planned.bundle().plan().memory().virtual_pages,
                        if crosses_generated_page { 3 } else { 2 }
                    );
                    if crosses_generated_page {
                        let image = planned
                            .bundle()
                            .images()
                            .iter()
                            .find(|image| image.address() == fixture.selected_target())
                            .unwrap();
                        assert_eq!(image.address() % PAGE as u64, PAGE as u64 - 45);
                        assert!(image.bytes().len() > 45);
                        assert!(image.bytes().len() <= PAGE + 45);
                        multi_page_images += 1;
                    }
                    execute(&fixture, &planned, false);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 144);
    assert_eq!(multi_page_images, 18);
    println!(
        "selected_and_victim_cache_page_crossings=144; required_cycles=144; calls=1728; callbacks=144; required_two_page_images=18"
    );
}

fn replacement() {
    for (case, delta) in [-64, 64].into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, 256, delta, 3, 15);
        let planned = fixture.plan(true);
        execute(&fixture, &planned, true);
    }
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 2);
    println!(
        "replacement_required_cycles=2; calls=24; callbacks=2; selected_original=43; selected_installed=99; selected_retired=43; victim_unchanged=proved"
    );
}

fn every_cache_offset() {
    let mut cases = 0;
    for len in 2..=4 {
        for delta in [-64, 64] {
            for offset in 0..64 {
                let fixture = Fixture::new(cases, 256 + offset, delta, len, 10);
                assert_eq!(fixture.selected() % 64, offset as u64);
                assert_eq!(fixture.victim() % 64, offset as u64);
                let planned = fixture.plan(false);
                execute(&fixture, &planned, false);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 384);
    println!(
        "all_cache_offsets=64; selected_lengths=3; directions=2; victim_len=10; required_cycles=384; calls=4608; callbacks=384; boundary_exemptions=0"
    );
}

fn assert_refusal(fixture: &Fixture, request: &InstallRequest<'_>, expected: Refusal) {
    assert_eq!(
        plan_neighbor(
            request,
            &fixture.allocation(false),
            fixture.search(),
            BundleBudget::default()
        )
        .unwrap_err(),
        expected
    );
    assert_eq!(fixture.observed(), fixture.original_mapping);
}

fn prerequisites() {
    let mut count = 0;
    for (direction, delta) in [-64, 64].into_iter().enumerate() {
        let first_case = direction as u64 * 100;
        for (index, (len, victim_len)) in [(1, 15), (5, 15), (3, 9)].into_iter().enumerate() {
            let fixture = Fixture::new(first_case + index as u64, 256, delta, len, victim_len);
            assert_refusal(
                &fixture,
                &fixture.request(&fixture.entries(), &fixture.allocation(true), false),
                Refusal::NoPatchWindow,
            );
            count += 1;
        }
        let fixture = Fixture::new(first_case + 10, 256, delta, 4, 15);
        let entries = fixture.entries();
        let allocation = fixture.allocation(true);
        let mut request = fixture.request(&entries, &allocation, false);
        request.function = AddressRange::new(fixture.selected(), fixture.len + 1).unwrap();
        assert_refusal(&fixture, &request, Refusal::NoPatchWindow);
        count += 1;
        let mut limited = fixture.entries();
        limited.scope = AddressRange::new(fixture.selected(), fixture.len + 1).unwrap();
        limited
            .entries
            .retain(|entry| limited.scope.contains(entry.address));
        assert_refusal(
            &fixture,
            &fixture.request(&limited, &allocation, false),
            Refusal::UnresolvedEntry,
        );
        count += 1;
        for address in [
            fixture.selected() + 1,
            fixture.relay(),
            fixture.victim() + 14,
        ] {
            let mut interior = fixture.entries();
            interior.entries.push(LegalEntry {
                address,
                requires_endbr: false,
            });
            assert_refusal(
                &fixture,
                &fixture.request(&interior, &allocation, false),
                Refusal::NotInstructionHead,
            );
            count += 1;
            let mut resumes = fixture.entries();
            resumes.resumes = ResumeObligation::Enumerated(vec![address]);
            assert_refusal(
                &fixture,
                &fixture.request(&resumes, &allocation, false),
                Refusal::NotInstructionHead,
            );
            count += 1;
        }
        let mut incomplete = fixture.entries();
        incomplete.completeness = EntryCompleteness::Incomplete;
        assert_refusal(
            &fixture,
            &fixture.request(&incomplete, &allocation, false),
            Refusal::UnresolvedEntry,
        );
        count += 1;
        let mut unresolved = fixture.entries();
        unresolved.resumes = ResumeObligation::Unresolved;
        assert_refusal(
            &fixture,
            &fixture.request(&unresolved, &allocation, false),
            Refusal::UnresolvedEntry,
        );
        count += 1;
        for address in [fixture.selected(), fixture.victim()] {
            let mut cet = fixture.entries();
            cet.entries
                .iter_mut()
                .find(|entry| entry.address == address)
                .unwrap()
                .requires_endbr = true;
            assert!(matches!(
                plan_neighbor(
                    &fixture.request(&cet, &allocation, false),
                    &fixture.allocation(false),
                    fixture.search(),
                    BundleBudget::default()
                ),
                Err(Refusal::UnsupportedSemantics(_))
            ));
            count += 1;
        }
        // Each alternative is one complete fifteen-byte original instruction.
        // These are pure input snapshots: no source or executable mapping changes.
        for suffix in [
            vec![0xe8, 0, 0, 0, 0],
            vec![0xd9, 0xee],
            vec![0x8e, 0xe0],
            vec![0xf4],
        ] {
            let mut code = fixture.original.clone();
            let mut instruction = vec![0x2e; 15 - suffix.len()];
            instruction.extend_from_slice(&suffix);
            let offset = (fixture.victim() - fixture.source().start()) as usize;
            code[offset..offset + 15].copy_from_slice(&instruction);
            let mut request = fixture.request(&entries, &allocation, false);
            request.code = &code;
            assert!(matches!(
                plan_neighbor(
                    &request,
                    &fixture.allocation(false),
                    fixture.search(),
                    BundleBudget::default()
                ),
                Err(Refusal::UnsupportedSemantics(_))
            ));
            count += 1;
        }
        for target in [fixture.selected() + 1, fixture.relay()] {
            let mut code = fixture.original.clone();
            code[0] = 0xeb;
            code[1] = i8::try_from(i128::from(target) - i128::from(fixture.source().start()) - 2)
                .unwrap() as u8;
            let mut request = fixture.request(&entries, &allocation, false);
            request.code = &code;
            assert_refusal(&fixture, &request, Refusal::NotInstructionHead);
            count += 1;
        }
        let mut request = fixture.request(&entries, &allocation, false);
        request.search.max_sites = 0;
        assert_refusal(&fixture, &request, Refusal::NoPatchWindow);
        count += 1;
        let mut request = fixture.request(&entries, &allocation, false);
        request.search.max_displaced_bytes = 14;
        assert_refusal(&fixture, &request, Refusal::NoPatchWindow);
        count += 1;
        assert_eq!(fixture.observed(), fixture.original_mapping);

        let selected = Fixture::new(first_case + 11, 256, delta, 2, 15);
        let mut code = selected.original.clone();
        let offset = (selected.selected() - selected.source().start()) as usize;
        code[offset..offset + 2].copy_from_slice(&[0x0f, 0x05]); // SYSCALL
        let entries = selected.entries();
        let allocation = selected.allocation(true);
        let mut request = selected.request(&entries, &allocation, false);
        request.code = &code;
        assert!(matches!(
            plan_neighbor(
                &request,
                &selected.allocation(false),
                selected.search(),
                BundleBudget::default()
            ),
            Err(Refusal::UnsupportedSemantics(_))
        ));
        assert_eq!(selected.observed(), selected.original_mapping);
        count += 1;
    }
    let fixture = Fixture::new(300, PAGE - 32, 64, 2, 15);
    let entries = fixture.entries();
    let allocation = fixture.allocation(true);
    let mut request = fixture.request(&entries, &allocation, false);
    let end = (fixture.victim() - fixture.source().start()) as usize + fixture.victim_len - 1;
    request.code = &fixture.original[..end];
    request.function = AddressRange::new(fixture.selected(), fixture.len).unwrap();
    assert!(
        matches!(
            plan_neighbor(
                &request,
                &fixture.allocation(false),
                fixture.search(),
                BundleBudget::default()
            ),
            Err(Refusal::Backend(_))
        ),
        "an incomplete supplied original instruction cannot be partially scanned"
    );
    assert_eq!(fixture.observed(), fixture.original_mapping);
    count += 1;
    assert_eq!(count, 49);
    println!("prerequisite_refusals=49; both_directions=required; source_changes=0");
}

fn budgets() {
    let mut refusals = 0;
    for (case, delta) in [-64, 64].into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, 256, delta, 4, 15);
        let selected = fixture.allocation(true);
        let victim = fixture.allocation(false);
        let entries = fixture.entries();
        let planned = fixture.plan(false);
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
                plan_neighbor(
                    &fixture.request(&entries, &selected, false),
                    &victim,
                    fixture.search(),
                    budget
                )
                .unwrap_err(),
                Refusal::AllocationUnavailable
            );
            refusals += 1;
        }
        for side in 0..2 {
            for zero in 0..3 {
                let mut selected = selected.clone();
                let mut victim = victim.clone();
                let allocation = if side == 0 {
                    &mut selected
                } else {
                    &mut victim
                };
                match zero {
                    0 => allocation.max_candidates = 0,
                    1 => allocation.max_mappings = 0,
                    2 => allocation.max_mapped_bytes = 0,
                    _ => unreachable!(),
                }
                assert_eq!(
                    plan_neighbor(
                        &fixture.request(&entries, &selected, false),
                        &victim,
                        fixture.search(),
                        BundleBudget::default()
                    )
                    .unwrap_err(),
                    Refusal::AllocationUnavailable
                );
                refusals += 1;
            }
        }
        for zero_victims in [true, false] {
            let mut search = fixture.search();
            if zero_victims {
                search.max_victims = 0;
            } else {
                search.max_pairs = 0;
            }
            assert_eq!(
                plan_neighbor(
                    &fixture.request(&entries, &selected, false),
                    &victim,
                    search,
                    BundleBudget::default()
                )
                .unwrap_err(),
                Refusal::AllocationUnavailable
            );
            refusals += 1;
        }
        assert_eq!(fixture.observed(), fixture.original_mapping);
        execute(&fixture, &planned, false);
    }
    assert_eq!(refusals, 26);
    println!("budget_planning_refusals=26; successful_corrected_cycles=2; calls=24; callbacks=2");
}

fn collisions() {
    let mut cases = 0;
    for delta in [-64, 64] {
        for blocked_image in 0..2 {
            let fixture = Fixture::new(cases, 256, delta, 4, 15);
            let planned = fixture.plan(false);
            assert_plan(&fixture, &planned);
            let bundle = planned.bundle();
            let allocations: Vec<_> = bundle
                .plan()
                .steps()
                .iter()
                .flat_map(|step| step.parts().allocations.iter().map(|a| a.range))
                .collect();
            let blocked = allocations[blocked_image];
            // SAFETY: reserve only an unoccupied, planned image extent.
            let mapping = unsafe {
                libc::mmap(
                    blocked.start() as *mut _,
                    blocked.len() as usize,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_eq!(mapping as usize as u64, blocked.start());
            {
                let mut guard = ();
                let mut lease = unsafe {
                    QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.source()])
                };
                let failure = unsafe {
                    bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize())
                }
                .err()
                .unwrap();
                assert!(matches!(failure.reason, Refusal::Backend(_)));
                assert_eq!(failure.stage, FailureStage::BeforeWrite);
                assert!(!lease.is_poisoned());
            }
            assert_eq!(fixture.observed(), fixture.original_mapping);
            let other = allocations[1 - blocked_image];
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
            assert_eq!(unsafe { libc::munmap(mapping, blocked.len() as usize) }, 0);
            execute(&fixture, &planned, false); // Same immutable plan, fresh lease.
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
    println!(
        "collision_beforewrite=4; required_same_plan_retry_cycles=4; calls=48; callbacks=4; both_image_orders=proved"
    );
}

fn stale_and_leases() {
    let mut case = 0;
    for delta in [-64, 64] {
        for stale in 0..3 {
            let fixture = Fixture::new(case, 256, delta, 4, 15);
            let planned = fixture.plan(false);
            let address = match stale {
                0 => fixture.selected() + 3,
                1 => fixture.victim() + 14,
                2 => fixture.relay(),
                _ => unreachable!(),
            };
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
            execute(&fixture, &planned, false);
            case += 1;
        }
        let fixture = Fixture::new(case, 256, delta, 3, 15);
        let planned = fixture.plan(false);
        assert_plan(&fixture, &planned);
        let bundle = planned.bundle();
        for stale in [false, true] {
            let mut identity = fixture.identity;
            let held = if stale {
                identity.generation += 1;
                vec![fixture.source()]
            } else {
                vec![AddressRange::new(fixture.selected(), fixture.len).unwrap()]
            };
            let mut guard = ();
            let mut lease = unsafe { QuiescenceLease::new(&mut guard, identity, held) };
            let failure = unsafe {
                bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize())
            }
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
        fixture.calls(false, false);
        fixture.permissions(false);
        let mut installed = publish(&fixture, bundle);
        assert_eq!(fixture.observed(), expected_mapping(&fixture, bundle));
        fixture.calls(true, false);
        fixture.permissions(false);
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
        fixture.calls(false, false);
        case += 1;
    }
    assert_eq!(case, 8);
    println!(
        "stale_beforewrite=6; publish_lease_beforewrite=4; retirement_lease_beforewrite=4; required_retry_cycles=8; calls=96; callbacks=8"
    );
}

fn inventory() {
    let mut count = 0;
    for (case, delta) in [-64, 64].into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, 256, delta, 3, 15);
        let entries = fixture.entries();
        let selected = fixture.allocation(true);
        let victim = fixture.allocation(false);
        let mut search = fixture.search();
        search.forced_victim = Some(fixture.relay());
        let failure = plan_neighbor_detailed(
            &fixture.request(&entries, &selected, false),
            &victim,
            search,
            BundleBudget::default(),
        )
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::NotInstructionHead);
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(
            failure.attempts[0].stage,
            NeighborAttemptStage::Qualification
        );
        assert_eq!(failure.attempts[0].victim, fixture.relay());
        assert_eq!(failure.attempts[0].victim_target, None);
        assert_eq!(failure.attempts[0].selected_target, None);
        count += 1;
        let mut unavailable = victim.clone();
        unavailable.max_candidates = 1;
        unavailable.ranges =
            vec![AddressRange::new((fixture.victim_target() & !4095) + 0x2_0000, PAGE).unwrap()];
        let failure = plan_neighbor_detailed(
            &fixture.request(&entries, &selected, false),
            &unavailable,
            fixture.search(),
            BundleBudget::default(),
        )
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(
            failure.attempts[0].stage,
            NeighborAttemptStage::VictimPlacement
        );
        assert_eq!(
            failure.attempts[0].victim_target,
            Some(fixture.victim_target())
        );
        assert_eq!(failure.attempts[0].selected_target, None);
        count += 1;
        let mut one_victim = victim.clone();
        one_victim.max_candidates = 1;
        let mut overlapping = selected.clone();
        overlapping.max_candidates = 1;
        overlapping.preferred_address = Some(fixture.victim_target());
        overlapping.ranges = victim.ranges.clone();
        let failure = plan_neighbor_detailed(
            &fixture.request(&entries, &overlapping, false),
            &one_victim,
            fixture.search(),
            BundleBudget::default(),
        )
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(
            failure.attempts[0].stage,
            NeighborAttemptStage::SelectedPlacement
        );
        assert_eq!(
            failure.attempts[0].victim_target,
            Some(fixture.victim_target())
        );
        assert_eq!(
            failure.attempts[0].selected_target,
            Some(fixture.victim_target())
        );
        count += 1;
        let mut one_selected = selected.clone();
        one_selected.max_candidates = 1;
        let failure = plan_neighbor_detailed(
            &fixture.request(&entries, &one_selected, false),
            &one_victim,
            fixture.search(),
            BundleBudget {
                max_virtual_span: 1,
                ..BundleBudget::default()
            },
        )
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(failure.attempts[0].stage, NeighborAttemptStage::Composition);
        assert_eq!(
            failure.attempts[0].victim_target,
            Some(fixture.victim_target())
        );
        assert_eq!(
            failure.attempts[0].selected_target,
            Some(fixture.selected_target())
        );
        assert_eq!(fixture.observed(), fixture.original_mapping);
        count += 1;
    }
    assert_eq!(count, 8);
    println!(
        "inventory_planning_refusals=8; qualification_placement_composition_distinguished=proved; source_changes=0"
    );
}

fn retained_images(bundle: &PlannedBundle) {
    for allocation in bundle
        .plan()
        .steps()
        .iter()
        .flat_map(|step| &step.parts().allocations)
    {
        let mut residency = vec![0; allocation.range.len() as usize / PAGE];
        assert_eq!(
            unsafe {
                libc::mincore(
                    allocation.range.start() as *mut _,
                    allocation.range.len() as usize,
                    residency.as_mut_ptr(),
                )
            },
            0
        );
    }
    for image in bundle.images() {
        for mapping in image.program_counter_mappings() {
            assert!(translate_program_counter(mapping.generated_start()).is_some());
        }
    }
}

fn poison() {
    let mut cases = 0;
    for delta in [-64, 64] {
        for retiring in [false, true] {
            let fixture = Fixture::new(cases, 256, delta, 4, 15);
            let planned = fixture.plan(false);
            assert_plan(&fixture, &planned);
            let bundle = planned.bundle();
            if retiring {
                let mut installed = publish(&fixture, bundle);
                assert_eq!(fixture.observed(), expected_mapping(&fixture, bundle));
                fixture.permissions(false);
                {
                    let mut guard = ();
                    // SAFETY: all source and generated execution remains excluded,
                    // including after deliberately failing final permission setup.
                    let mut lease = unsafe {
                        QuiescenceLease::new(
                            &mut guard,
                            fixture.identity,
                            all_ranges(&fixture, bundle),
                        )
                    };
                    let failure = unsafe {
                        installed.retire_with(&mut lease, || {
                            Err(Refusal::Backend(
                                "forced retirement finalizer failure".into(),
                            ))
                        })
                    }
                    .unwrap_err();
                    assert_eq!(failure.stage, FailureStage::KeepGated);
                    assert!(lease.is_poisoned());
                    assert!(!installed.is_retired());
                    assert_eq!(fixture.observed(), fixture.original_mapping);
                    retained_images(bundle);
                    let retry = unsafe { installed.retire(&mut lease) }.unwrap_err();
                    assert_eq!(retry.reason, Refusal::LeasePoisoned);
                    assert_eq!(retry.stage, FailureStage::BeforeWrite);
                }
                std::mem::forget(installed);
            } else {
                let mut guard = ();
                let mut lease = unsafe {
                    QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.source()])
                };
                let failure = unsafe {
                    bundle.publish_with(&[fixture.alias()], &mut lease, || {
                        Err(Refusal::Backend(
                            "forced publication finalizer failure".into(),
                        ))
                    })
                }
                .err()
                .unwrap();
                assert_eq!(failure.stage, FailureStage::KeepGated);
                assert!(lease.is_poisoned());
                assert_eq!(fixture.observed(), expected_mapping(&fixture, bundle));
                retained_images(bundle);
                let retry = unsafe {
                    bundle.publish_with(&[fixture.alias()], &mut lease, || fixture.finalize())
                }
                .err()
                .unwrap();
                assert_eq!(retry.reason, Refusal::LeasePoisoned);
                assert_eq!(retry.stage, FailureStage::BeforeWrite);
            }
            // No execution or mapping teardown is allowed after KeepGated.
            std::mem::forget(fixture);
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
    println!(
        "keep_gated_failures=4; poisoned_retry_beforewrite=4; application_calls_after_poison=0; retained_source_and_images=proved"
    );
}

fn write_original(fixture: &mut Fixture) {
    fixture.original_mapping.fill(0xa5);
    fixture.original_mapping[fixture.source_offset..fixture.source_offset + fixture.original.len()]
        .copy_from_slice(&fixture.original);
    // SAFETY: custom fixture construction precedes planning and execution.
    unsafe {
        std::ptr::copy_nonoverlapping(fixture.original_mapping.as_ptr(), fixture.write, 2 * PAGE);
    }
}

fn automatic_budget() {
    let mut fixture = Fixture::new(0, PAGE - 128, -131, 3, 10);
    let upper = fixture.selected() + 124;
    let upper_index = (upper - fixture.source().start()) as usize;
    fixture.original.resize(upper_index + 11, 0x90);
    fixture.original[upper_index..upper_index + 10].copy_from_slice(&victim_bytes(10));
    fixture.original[upper_index + 10] = 0xc3;
    write_original(&mut fixture);
    let function =
        AddressRange::new(fixture.victim(), (upper + 11 - fixture.victim()) as usize).unwrap();
    let mut entries = fixture.entries();
    entries.scope = function;
    entries
        .entries
        .extend([upper, upper + 10].map(|address| LegalEntry {
            address,
            requires_endbr: false,
        }));
    let first_target = upper + 5 + 0x1_0000;
    let second_target = fixture.victim() + 5 + 0x1_0000;
    assert_ne!(first_target & !4095, second_target & !4095);
    let mut selected = fixture.allocation(true);
    selected.preferred_address = Some(first_target);
    selected.ranges = vec![AddressRange::new(first_target & !4095, PAGE).unwrap()];
    selected.max_candidates = 1;
    let mut victim = fixture.allocation(false);
    victim.preferred_address = None;
    victim.ranges = vec![AddressRange::new(second_target & !4095, 2 * PAGE).unwrap()];
    victim.max_candidates = 1;
    let mut request = fixture.request(&entries, &selected, false);
    request.function = function;
    let mut search = NeighborSearch {
        forced_victim: None,
        max_victims: 2,
        max_pairs: 1,
    };
    let failure =
        plan_neighbor_detailed(&request, &victim, search, BundleBudget::default()).unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(
        failure.attempts[0].stage,
        NeighborAttemptStage::SelectedPlacement
    );
    assert_eq!(failure.attempts[0].victim, upper);
    assert_eq!(failure.attempts[0].victim_target, Some(first_target));
    assert_eq!(failure.attempts[0].selected_target, Some(first_target));
    assert_eq!(fixture.observed(), fixture.original_mapping);
    search.max_pairs = 2;
    let planned = plan_neighbor(&request, &victim, search, BundleBudget::default())
        .expect("second original victim must succeed when the second pair is admitted");
    assert_eq!(planned.metrics().victims_examined, 2);
    assert_eq!(planned.metrics().pairs_examined, 2);
    assert_eq!(planned.metrics().attempts.len(), 2);
    assert_eq!(planned.metrics().attempts[0], failure.attempts[0]);
    let success = &planned.metrics().attempts[1];
    assert_eq!(success.stage, NeighborAttemptStage::Composition);
    assert_eq!(success.victim, fixture.victim());
    assert_eq!(success.refusal, None);
    assert_eq!(success.victim_target, Some(second_target));
    assert_eq!(success.selected_target, Some(first_target));
    assert_eq!(planned.geometry().victim, fixture.victim());
    assert_eq!(planned.geometry().selected, fixture.selected());
    assert_eq!(planned.geometry().rel8, -128);
    assert_eq!(planned.geometry().relay, fixture.relay());
    assert_eq!(planned.geometry().victim_target, second_target);
    assert_eq!(planned.geometry().selected_target, first_target);
    let bundle = planned.bundle();
    assert_eq!(bundle.plan().steps().len(), 2);
    assert_eq!(
        bundle.plan().steps()[0].parts().physical_pc,
        fixture.selected()
    );
    assert_eq!(
        bundle.plan().steps()[1].parts().physical_pc,
        fixture.victim()
    );
    let mut expected = fixture.original.clone();
    for step in bundle.plan().steps() {
        assert_eq!(
            step.parts().reads,
            vec![ExpectedBytes {
                address: fixture.source().start(),
                bytes: expected.clone()
            }]
        );
        for edit in &step.parts().writes {
            let index = (edit.address - fixture.source().start()) as usize;
            expected[index..index + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
    }
    let mut independent = fixture.original.clone();
    let selected_index = (fixture.selected() - fixture.source().start()) as usize;
    independent[selected_index..selected_index + 2].copy_from_slice(&[0xeb, 0x80]);
    let victim_index = (fixture.victim() - fixture.source().start()) as usize;
    independent[victim_index..victim_index + 5]
        .copy_from_slice(&near_jump(fixture.victim(), second_target));
    independent[victim_index + 5..victim_index + 10]
        .copy_from_slice(&near_jump(fixture.relay(), first_target));
    assert_eq!(expected, independent);
    assert_eq!(
        &expected[upper_index..upper_index + 11],
        &fixture.original[upper_index..upper_index + 11]
    );
    assert_eq!(
        bundle.plan().final_bytes(),
        &[ExpectedBytes {
            address: fixture.source().start(),
            bytes: independent
        }]
    );
    for range in [
        AddressRange::new(fixture.selected(), 3).unwrap(),
        AddressRange::new(fixture.victim(), 10).unwrap(),
    ] {
        assert!(bundle.plan().locks().iter().any(|lock| lock.covers(range)));
    }
    let heads = [
        fixture.selected(),
        fixture.victim(),
        fixture.selected() + 3,
        fixture.victim() + 10,
        upper,
        upper + 10,
    ];
    let mut calls = 0;
    let mut call_all = |patched: bool| {
        let before = CALLBACKS.load(Ordering::Relaxed);
        for (index, head) in heads.into_iter().enumerate() {
            let actual: u64;
            // SAFETY: the six explicit body heads are original and leases have ended.
            unsafe {
                core::arch::asm!("call r11", in("r11") head, inlateout("rax") SEED => actual, clobber_abi("C"));
            }
            assert_eq!(
                actual,
                match index {
                    0 => 43,
                    1 | 4 => VICTIM_VALUE,
                    _ => SEED,
                }
            );
            assert_eq!(
                CALLBACKS.load(Ordering::Relaxed),
                before + u64::from(patched)
            );
            if patched {
                assert_eq!(LAST_PC.load(Ordering::Relaxed), fixture.selected());
            }
            calls += 1;
        }
    };
    fixture.permissions(true);
    call_all(false);
    fixture.permissions(false);
    let mut installed = publish(&fixture, bundle);
    assert_eq!(fixture.observed(), expected_mapping(&fixture, bundle));
    call_all(true);
    retire(&fixture, bundle, &mut installed);
    call_all(false);
    assert_eq!(calls, 18);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
    println!(
        "automatic_descending_victims=2; total_pair_budget_refusals=1; required_cycles=1; explicit_entries=6; calls=18; callbacks=1"
    );
}

fn prior_byte_locks() {
    for (case, delta) in [-64, 64].into_iter().enumerate() {
        let mut fixture = Fixture::new(case as u64, 256, delta, 4, 15);
        // A preceding B2 consumes three bytes of the lower T3 instruction,
        // while leaving T3's separately supplied source snapshot unchanged.
        fixture.original[PAD - 2..PAD].copy_from_slice(&[0x89, 0xc0]);
        write_original(&mut fixture);
        let lower = fixture.selected().min(fixture.victim());
        let lower_len = if lower == fixture.selected() {
            fixture.len
        } else {
            fixture.victim_len
        };
        let prior_pc = lower - 2;
        let prior_code = &fixture.original[PAD - 2..PAD + lower_len + 1];
        let prior_source = AddressRange::new(prior_pc, prior_code.len()).unwrap();
        let entries = LegalEntrySet {
            identity: fixture.identity,
            scope: prior_source,
            provenance: EntryProvenance::Declared(
                "preceding B2 consumes an unchanged T3 instruction head".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        };
        let frozen = i32::from_le_bytes([
            0,
            fixture.original[PAD],
            fixture.original[PAD + 1],
            fixture.original[PAD + 2],
        ]);
        let target = u64::try_from(i128::from(prior_pc + 5) + i128::from(frozen) + 128).unwrap();
        let mut allocation = AllocationPolicy::near(prior_pc).unwrap();
        allocation.preferred_address = Some(target);
        allocation.ranges = vec![AddressRange::new(target & !4095, 8192).unwrap()];
        let prior = plan_install(&InstallRequest {
            identity: fixture.identity,
            code: prior_code,
            base_address: prior_pc,
            function: prior_source,
            block: AddressRange::new(prior_pc, 2).unwrap(),
            logical_pc: prior_pc,
            entries: &entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::GeneralizedPunOnly,
                max_sites: 1,
                max_upstream_bytes: 0,
                max_displaced_bytes: 2,
            },
        })
        .expect("required preceding B2 dependency fixture refused");
        let PlanKind::GeneralizedPun(pun) = &prior.plan().parts().kind else {
            panic!("prior fixture silently changed tactic");
        };
        assert_eq!(pun.consumed, AddressRange::new(prior_pc, 5).unwrap());
        let prior_bundle = PlannedBundle::compose(
            vec![ExpectedBytes {
                address: prior_pc,
                bytes: prior_code.to_vec(),
            }],
            vec![prior],
            BundleBudget::default(),
        )
        .unwrap();
        let t3_entries = fixture.entries();
        let t3_allocation = fixture.allocation(true);
        let mut request = fixture.request(&t3_entries, &t3_allocation, false);
        request.code = &fixture.original[PAD..];
        request.base_address = lower;
        let blocked = plan_neighbor(
            &request,
            &fixture.allocation(false),
            fixture.search(),
            BundleBudget::default(),
        )
        .unwrap();
        let mut installed = publish(&fixture, &prior_bundle);
        fixture.permissions(false);
        let before = fixture.observed();
        for snapshot in blocked.bundle().plan().originals() {
            let start = (snapshot.address - fixture.execute as usize as u64) as usize;
            assert_eq!(
                &before[start..start + snapshot.bytes.len()],
                snapshot.bytes,
                "ownership refusal must not be explained by stale expected bytes"
            );
        }
        {
            let mut guard = ();
            let mut lease = unsafe {
                QuiescenceLease::new(&mut guard, fixture.identity, vec![fixture.source()])
            };
            let failure = unsafe {
                blocked
                    .bundle()
                    .publish_with(&[fixture.alias()], &mut lease, || fixture.finalize())
            }
            .err()
            .unwrap();
            assert_eq!(failure.reason, Refusal::OwnershipConflict);
            assert_eq!(failure.stage, FailureStage::BeforeWrite);
            assert!(!lease.is_poisoned());
        }
        assert_eq!(fixture.observed(), before);
        retire(&fixture, &prior_bundle, &mut installed);
        let corrected = fixture.plan(false);
        execute(&fixture, &corrected, false);
    }
    println!(
        "prior_consumed_lock_beforewrite=2; prerequisite_b2_setup_transactions=2; required_t3_retry_cycles=2; calls=24; callbacks=2"
    );
}

#[test]
fn neighbor_eviction_contract_puzzles() {
    if let Ok(mode) = std::env::var(ENV) {
        match mode.as_str() {
            "endpoints" => endpoints(),
            "outside" => outside(),
            "boundaries" => boundaries(),
            "replacement" => replacement(),
            "all-offsets" => every_cache_offset(),
            "prerequisites" => prerequisites(),
            "budgets" => budgets(),
            "collisions" => collisions(),
            "stale-leases" => stale_and_leases(),
            "inventory" => inventory(),
            "poison" => poison(),
            "automatic-budget" => automatic_budget(),
            "prior-locks" => prior_byte_locks(),
            _ => panic!("unknown child mode {mode}"),
        }
        println!("neighbor-eviction-complete:{mode}");
        return;
    }
    for mode in [
        "endpoints",
        "outside",
        "boundaries",
        "replacement",
        "all-offsets",
        "prerequisites",
        "budgets",
        "collisions",
        "stale-leases",
        "inventory",
        "poison",
        "automatic-budget",
        "prior-locks",
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
        // SAFETY: only async-signal-safe resource limits precede exec.
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
                panic!("T3 child {mode} timed out: {output:?}");
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
        assert!(stdout.contains(&format!("neighbor-eviction-complete:{mode}")));
        print!("{stdout}");
    }
}
