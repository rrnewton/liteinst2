#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Required install-once prefixed-pun placement and publication puzzles.
//!
//! These bounded children exclusively own every source alias and executor.
//! The tests inspect exact semantic edits and hardware-store padding, then
//! execute every declared body head before installation, after publication,
//! and after retirement. Architectural state is checked separately by the
//! independent native oracle; these tests do not claim concurrent atomicity.

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, FailureStage, LegalEntry,
    LegalEntrySet, PatchPlan, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, InstalledOnce, PatchTactic, PlannedInstall, SearchPolicy,
    TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const HEADROOM: usize = 16;
const RESULT: u64 = 0x1937_5a82;
const CHILD_ENV: &str = "LITEINST_PREFIXED_PUN_CONTRACT_CHILD";
const CHILD_TEST: &str = "prefixed_pun_contract_puzzles";
static CALLBACKS: AtomicU64 = AtomicU64::new(0);
static LAST_PC: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the trampoline supplies an initialized callback frame.
    let context = unsafe { &*context };
    LAST_PC.store(context.instruction_pointer, Ordering::Relaxed);
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

struct Fixture {
    writable: *mut u8,
    executable: *mut u8,
    source_offset: usize,
    instruction_len: usize,
    prefix_count: usize,
    original: Vec<u8>,
    original_mapping: Vec<u8>,
    identity: CodeIdentity,
}

impl Fixture {
    fn new(case: u64, physical_offset: usize, instruction_len: usize, prefix_count: usize) -> Self {
        let instruction: &[u8] = match instruction_len {
            1 => &[0x90],
            2 => &[0x66, 0x90],
            3 => &[0x0f, 0x1f, 0x00],
            4 => &[0x0f, 0x1f, 0x40, 0x00],
            _ => panic!("unsupported required puzzle length"),
        };
        let mut original = vec![0x90; HEADROOM];
        original.extend_from_slice(instruction);
        original.push(0xb8); // MOV EAX,RESULT; RET.
        original.extend_from_slice(&(RESULT as u32).to_le_bytes());
        original.push(0xc3);
        let source_offset = physical_offset.checked_sub(HEADROOM).unwrap();
        assert!(source_offset + original.len() <= 2 * PAGE);
        // Each source and its entire signed-rel32 neighborhood are disjoint
        // from previous fixtures, whose generated images live until exit.
        let address = 0x3400_0000_0000_u64 + case * 0x2_0000_0000;
        let mut original_mapping = vec![0xa5; 2 * PAGE];
        original_mapping[source_offset..source_offset + original.len()].copy_from_slice(&original);
        // SAFETY: these mappings and their backing file belong only to this
        // isolated child. NOREPLACE never overwrites a preexisting mapping.
        let (writable, executable) = unsafe {
            let fd = libc::memfd_create(c"liteinst-prefixed-pun".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
            assert_eq!(libc::ftruncate(fd, (2 * PAGE) as libc::off_t), 0);
            let writable = libc::mmap(
                ptr::null_mut(),
                2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            let executable = libc::mmap(
                address as usize as *mut libc::c_void,
                2 * PAGE,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                fd,
                0,
            );
            assert_ne!(writable, libc::MAP_FAILED);
            assert_ne!(executable, libc::MAP_FAILED);
            assert_eq!(executable as usize as u64, address);
            assert_eq!(libc::close(fd), 0);
            ptr::copy_nonoverlapping(
                original_mapping.as_ptr(),
                writable.cast::<u8>(),
                original_mapping.len(),
            );
            (writable.cast(), executable.cast())
        };
        Self {
            writable,
            executable,
            source_offset,
            instruction_len,
            prefix_count,
            original,
            original_mapping,
            identity: CodeIdentity {
                source: SourceIdentity([case as u8; 32]),
                mapping: case + 1,
                generation: 1,
            },
        }
    }

    fn base(&self) -> u64 {
        self.executable as usize as u64 + self.source_offset as u64
    }

    fn physical(&self) -> u64 {
        self.base() + HEADROOM as u64
    }

    fn source(&self) -> AddressRange {
        AddressRange::new(self.base(), self.original.len()).unwrap()
    }

    fn writable_source(&self) -> *mut u8 {
        // SAFETY: construction checked the entire source within this mapping.
        unsafe { self.writable.add(self.source_offset) }
    }

    fn observed(&self) -> Vec<u8> {
        // SAFETY: the isolated fixture has no concurrent writer.
        unsafe { std::slice::from_raw_parts(self.writable, 2 * PAGE) }.to_vec()
    }

    fn executable(&self, enabled: bool) {
        let protection = libc::PROT_READ | if enabled { libc::PROT_EXEC } else { 0 };
        // SAFETY: exclusive ownership drains every executor and continuation
        // before changing both pages, including the complete consumed fetch span.
        assert_eq!(
            unsafe { libc::mprotect(self.executable.cast(), 2 * PAGE, protection) },
            0
        );
    }

    fn finalize_executable(&self) -> Result<(), Refusal> {
        // SAFETY: the exclusive owner still gates execution. Both pages become
        // RX before the publication receipt and sync-core completion.
        if unsafe {
            libc::mprotect(
                self.executable.cast(),
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

    fn window(&self, prefixes: usize) -> AddressRange {
        // Independent E9 rel32 arithmetic: the prefix bytes move its opcode
        // and next PC while successors fix every high displacement byte.
        let consumed = 5 + prefixes;
        let free = self.instruction_len - prefixes - 1;
        let mut displacement = [0_u8; 4];
        displacement[free..]
            .copy_from_slice(&self.original[HEADROOM + self.instruction_len..HEADROOM + consumed]);
        let low = i128::from(self.physical() + consumed as u64)
            + i128::from(i32::from_le_bytes(displacement));
        AddressRange::new(u64::try_from(low).unwrap(), 1_usize << (8 * free)).unwrap()
    }

    fn target_window(&self) -> AddressRange {
        self.window(self.prefix_count)
    }

    fn allocation(&self) -> AllocationPolicy {
        let window = self.target_window();
        let preferred = window.start() + window.len() / 2;
        let range = AddressRange::new(preferred & !(PAGE as u64 - 1), 2 * PAGE).unwrap();
        for prefixes in 0..self.instruction_len {
            if prefixes != self.prefix_count {
                assert!(
                    !range.overlaps(self.window(prefixes)),
                    "fixture does not force its prefix count"
                );
            }
        }
        let mut allocation = AllocationPolicy::near(self.physical()).unwrap();
        allocation.preferred_address = Some(preferred);
        allocation.ranges = vec![range];
        allocation
    }

    fn entries(&self) -> LegalEntrySet {
        LegalEntrySet {
            identity: self.identity,
            scope: self.source(),
            provenance: EntryProvenance::Declared("bounded prefixed-pun puzzle".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        }
    }

    fn request<'a>(
        &'a self,
        entries: &'a LegalEntrySet,
        allocation: &'a AllocationPolicy,
        tactics: TacticPolicy,
    ) -> InstallRequest<'a> {
        InstallRequest {
            identity: self.identity,
            code: &self.original,
            base_address: self.base(),
            function: self.source(),
            block: AddressRange::new(self.physical(), self.instruction_len + 6).unwrap(),
            logical_pc: self.physical(),
            entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation,
            search: SearchPolicy {
                max_upstream_bytes: 0,
                max_sites: 1,
                max_displaced_bytes: self.instruction_len + 6,
                tactics,
            },
        }
    }

    fn plan(&self, tactics: TacticPolicy) -> PlannedInstall {
        plan_install(&self.request(&self.entries(), &self.allocation(), tactics)).unwrap_or_else(
            |reason| panic!("required positive at {:#x}: {reason}", self.physical()),
        )
    }

    fn call(&self, offset: usize) -> u64 {
        let result: u64;
        // SAFETY: the three body heads contain NOP/MOV EAX,constant/RET only.
        // The generated observer preserves the seeded RAX for bare RET entry.
        unsafe {
            core::arch::asm!(
                "call r11",
                in("r11") self.physical() + offset as u64,
                inlateout("rax") RESULT => result,
                clobber_abi("C"),
            );
        }
        result
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: every installed source reference was retired before Drop.
        unsafe {
            assert_eq!(libc::munmap(self.writable.cast(), 2 * PAGE), 0);
            assert_eq!(libc::munmap(self.executable.cast(), 2 * PAGE), 0);
        }
    }
}

/// Exclusive ownership supplies quiescence; NX alone is not the gate.
struct HeldFixture<'a>(&'a Fixture);

impl HeldFixture<'_> {
    fn lease(&mut self, ranges: Vec<AddressRange>) -> QuiescenceLease<'_> {
        assert!(!self.0.writable_source().is_null());
        let identity = self.0.identity;
        // SAFETY: no other thread, handler, writer or saved context knows any
        // fixture address. The borrow retains this gate through publication.
        unsafe { QuiescenceLease::new(self, identity, ranges) }
    }
}

fn assert_pun(fixture: &Fixture, planned: &PlannedInstall) {
    let parts = planned.plan().parts();
    let PlanKind::PrefixedPun(pun) = &parts.kind else {
        panic!("required prefixed pun became {:?}", parts.kind);
    };
    let len = fixture.instruction_len;
    let prefixes = fixture.prefix_count;
    let consumed = 5 + prefixes;
    let physical = fixture.physical();
    assert_eq!(parts.physical_pc, physical);
    assert_eq!(parts.logical_pc, physical);
    assert_eq!(parts.displaced, AddressRange::new(physical, len).unwrap());
    assert_eq!(usize::from(pun.instruction_len), len);
    assert_eq!(usize::from(pun.prefix_count), prefixes);
    assert_eq!(pun.consumed, AddressRange::new(physical, consumed).unwrap());
    assert_eq!(pun.target_window, fixture.target_window());
    assert_eq!(pun.target_window.len(), 1_u64 << (8 * (len - prefixes - 1)));
    assert!(pun.target_window.contains(planned.image().address()));
    assert_eq!(
        planned.image().address(),
        fixture.allocation().preferred_address.unwrap()
    );
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.writes[0].address, physical);
    assert_eq!(parts.writes[0].bytes.len(), len);
    assert_eq!(&parts.writes[0].bytes[..prefixes], vec![0x2e; prefixes]);
    assert_eq!(parts.writes[0].bytes[prefixes], 0xe9);
    let mut jump = fixture.original[HEADROOM..HEADROOM + consumed].to_vec();
    jump[..len].copy_from_slice(&parts.writes[0].bytes);
    let target = i128::from(physical + consumed as u64)
        + i128::from(i32::from_le_bytes(jump[prefixes + 1..].try_into().unwrap()));
    assert_eq!(target, i128::from(planned.image().address()));
    assert!(!parts.requirements.sigill_router);
    assert!(
        planned
            .metrics()
            .attempts
            .iter()
            .any(|attempt| attempt.tactic == PatchTactic::PrefixPun && attempt.refusal.is_none())
    );
    let store_address = physical - u64::from(len == 3 && physical % 64 == 61);
    let store_len = len.next_power_of_two();
    assert_eq!(pun.store.address, store_address);
    assert_eq!(pun.store.bytes.len(), store_len);
    assert_eq!(
        store_address / 64,
        (store_address + store_len as u64 - 1) / 64
    );
    let offset = usize::try_from(store_address - fixture.base()).unwrap();
    let mut expected = fixture.original[offset..offset + store_len].to_vec();
    let changed = usize::try_from(physical - store_address).unwrap();
    expected[changed..changed + len].copy_from_slice(&parts.writes[0].bytes);
    assert_eq!(pun.store.bytes, expected, "hardware store padding changed");
    for required in [
        pun.consumed,
        AddressRange::new(store_address, store_len).unwrap(),
    ] {
        assert!(
            parts
                .dependencies
                .iter()
                .any(|range| range.covers(required))
        );
        assert!(parts.reads.iter().any(|read| {
            AddressRange::new(read.address, read.bytes.len())
                .unwrap()
                .covers(required)
        }));
    }
}

fn patched_mapping(fixture: &Fixture, planned: &PlannedInstall) -> Vec<u8> {
    let mut expected = fixture.original_mapping.clone();
    for edit in &planned.plan().parts().writes {
        let offset = (edit.address - fixture.executable as usize as u64) as usize;
        expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
    }
    expected
}

fn publish(fixture: &Fixture, planned: &PlannedInstall) -> InstalledOnce {
    let mut held = HeldFixture(fixture);
    let mut lease = held.lease(planned.plan().parts().dependencies.clone());
    // SAFETY: both source aliases and the complete consumed fetch span are owned. Every
    // executor/continuation is drained and the finalizer establishes RX before
    // sync-core while the exclusive ownership gate remains held.
    let (installed, receipt) = unsafe {
        planned.publish_with(fixture.writable_source(), &mut lease, || {
            fixture.finalize_executable()
        })
    }
    .unwrap_or_else(|error| panic!("required publication: {error:?}"));
    assert_eq!(receipt.plan(), planned.plan());
    assert!(!lease.is_poisoned());
    installed
}

fn retire(fixture: &Fixture, installed: &mut InstalledOnce) {
    fixture.executable(false);
    let mut ranges = installed.plan().parts().dependencies.clone();
    ranges.extend(installed.plan().parts().allocations.iter().map(|a| a.range));
    let mut held = HeldFixture(fixture);
    let mut lease = held.lease(ranges);
    // SAFETY: the fresh lease drains source and all generated code, and the
    // finalizer does not admit execution or unwind while restoring RX.
    unsafe { installed.retire_with(&mut lease, || fixture.finalize_executable()) }.unwrap();
    assert!(!lease.is_poisoned());
    assert!(installed.is_retired());
    assert_eq!(fixture.observed(), fixture.original_mapping);
}

fn execute_plan(fixture: &Fixture, planned: &PlannedInstall) {
    let heads = [0, fixture.instruction_len, fixture.instruction_len + 5];
    let initial_callbacks = CALLBACKS.load(Ordering::Relaxed);
    assert_eq!(fixture.observed(), fixture.original_mapping);
    fixture.executable(true);
    for head in heads {
        assert_eq!(fixture.call(head), RESULT, "native entry {head}");
    }
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks);
    fixture.executable(false);
    let mut installed = publish(fixture, planned);
    assert_eq!(fixture.observed(), patched_mapping(fixture, planned));
    {
        let observed = fixture.observed();
        let successor = fixture.source_offset + HEADROOM + fixture.instruction_len;
        assert_eq!(
            observed[successor..],
            fixture.original_mapping[successor..],
            "pun changed a successor byte"
        );
    }
    for head in heads {
        assert_eq!(fixture.call(head), RESULT, "patched entry {head}");
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks + 1);
        assert_eq!(LAST_PC.load(Ordering::Relaxed), fixture.physical());
        assert_eq!(installed.routed_entries(), 0);
    }
    retire(fixture, &mut installed);
    for head in heads {
        assert_eq!(fixture.call(head), RESULT, "retired entry {head}");
    }
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks + 1);
}

const PAIRS: [(usize, usize); 6] = [(2, 1), (3, 1), (3, 2), (4, 1), (4, 2), (4, 3)];

fn line_puzzles() {
    let mut positives = 0;
    let mut crossing_refusals = 0;
    for (pair, (len, prefixes)) in PAIRS.into_iter().enumerate() {
        for offset in 0..64 {
            let fixture = Fixture::new((pair * 64 + offset) as u64, 128 + offset, len, prefixes);
            let entries = fixture.entries();
            let allocation = fixture.allocation();
            if offset + len > 64 {
                assert_eq!(
                    plan_install(&fixture.request(
                        &entries,
                        &allocation,
                        TacticPolicy::PrefixPunOnly
                    ))
                    .unwrap_err(),
                    Refusal::NoPatchWindow
                );
                assert_eq!(fixture.observed(), fixture.original_mapping);
                crossing_refusals += 1;
                continue;
            }
            let planned = fixture.plan(TacticPolicy::PrefixPunOnly);
            assert_pun(&fixture, &planned);
            if offset == 0 {
                // The narrow placement forces T1 without redefining B2's window.
                assert_eq!(
                    plan_install(&fixture.request(
                        &entries,
                        &allocation,
                        TacticPolicy::GeneralizedPunOnly
                    ))
                    .unwrap_err(),
                    Refusal::AllocationUnavailable
                );
                let broad = AllocationPolicy::near(fixture.physical()).unwrap();
                let preferred = plan_install(&fixture.request(
                    &entries,
                    &broad,
                    TacticPolicy::PreferGeneralizedPun,
                ))
                .unwrap();
                assert!(
                    matches!(preferred.plan().parts().kind, PlanKind::GeneralizedPun(_)),
                    "B2 lost default priority"
                );
            }
            execute_plan(&fixture, &planned);
            positives += 1;
        }
    }
    assert_eq!(positives, 370);
    assert_eq!(crossing_refusals, 14);
    println!(
        "length_prefix_pairs=6; offsets_each=64; required_prefixed_puns=370; crossing_refusals=14; entry_cases=1110; native_calls=3330; callbacks=370; mismatches=0"
    );
}

fn page_puzzles() {
    for (case, (len, prefixes)) in PAIRS.into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, PAGE - len, len, prefixes);
        let planned = fixture.plan(TacticPolicy::PrefixPunOnly);
        assert_pun(&fixture, &planned);
        let PlanKind::PrefixedPun(pun) = &planned.plan().parts().kind else {
            unreachable!()
        };
        assert_eq!(
            fixture.physical() + len as u64,
            fixture.executable as u64 + PAGE as u64
        );
        assert!(pun.consumed.start() / (PAGE as u64) < (pun.consumed.end() - 1) / PAGE as u64);
        execute_plan(&fixture, &planned);
    }
    println!(
        "two_executable_page_prefixed_puns=6; entry_cases=18; native_calls=54; callbacks=6; mismatches=0"
    );
}

fn prerequisite_refusals() {
    let fixture = Fixture::new(0, 128, 1, 1);
    let entries = fixture.entries();
    let allocation = AllocationPolicy::near(fixture.physical()).unwrap();
    assert_eq!(
        plan_install(&fixture.request(&entries, &allocation, TacticPolicy::PrefixPunOnly))
            .unwrap_err(),
        Refusal::NoPatchWindow
    );
    assert_eq!(fixture.observed(), fixture.original_mapping);
    for (case, (len, prefixes)) in PAIRS.into_iter().enumerate() {
        let fixture = Fixture::new((case + 1) as u64, 128, len, prefixes);
        let entries = fixture.entries();
        let allocation = fixture.allocation();
        let mut request = fixture.request(&entries, &allocation, TacticPolicy::PrefixPunOnly);
        request.code = &fixture.original[..HEADROOM + len];
        request.function = AddressRange::new(fixture.base(), request.code.len()).unwrap();
        request.block = AddressRange::new(fixture.physical(), len).unwrap();
        assert_eq!(plan_install(&request).unwrap_err(), Refusal::NoPatchWindow);
        assert_eq!(fixture.observed(), fixture.original_mapping);
    }
    for prefixes in 1..=2 {
        let fixture = Fixture::new((10 + prefixes) as u64, 128 + 61, 3, prefixes);
        let entries = fixture.entries();
        let allocation = fixture.allocation();
        let mut request = fixture.request(&entries, &allocation, TacticPolicy::PrefixPunOnly);
        request.code = &fixture.original[HEADROOM..];
        request.base_address = fixture.physical();
        request.function = AddressRange::new(request.base_address, request.code.len()).unwrap();
        assert_eq!(plan_install(&request).unwrap_err(), Refusal::NoPatchWindow);
        assert_eq!(fixture.observed(), fixture.original_mapping);
    }
    println!(
        "one_byte_refusals=1; missing_consumed_refusals=6; missing_left_pad_refusals=2; source_changes=0"
    );
}

fn assert_stale_byte(fixture: &Fixture, planned: &PlannedInstall, address: u64) {
    let offset = (address - fixture.base()) as usize;
    let original = fixture.original[offset];
    // SAFETY: the isolated fixture owns the writable alias; no execution is admitted.
    unsafe { fixture.writable_source().add(offset).write(original ^ 1) };
    let changed = fixture.observed();
    {
        let mut held = HeldFixture(fixture);
        let mut lease = held.lease(planned.plan().parts().dependencies.clone());
        // SAFETY: aliases and all execution stay held even for deliberately stale bytes.
        let failure = unsafe {
            planned.publish_with(fixture.writable_source(), &mut lease, || {
                fixture.finalize_executable()
            })
        }
        .err()
        .expect("stale byte must refuse");
        assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert!(!lease.is_poisoned());
    }
    assert_eq!(
        fixture.observed(),
        changed,
        "staleness refusal wrote source bytes"
    );
    // SAFETY: the same exclusive owner restores the authenticated original byte.
    unsafe { fixture.writable_source().add(offset).write(original) };
    execute_plan(fixture, planned);
}

fn stale_bytes() {
    for (case, (len, prefixes)) in PAIRS.into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, 128, len, prefixes);
        let planned = fixture.plan(TacticPolicy::PrefixPunOnly);
        assert_pun(&fixture, &planned);
        assert_stale_byte(
            &fixture,
            &planned,
            fixture.physical() + (4 + prefixes) as u64,
        );
    }
    for prefixes in 1..=2 {
        for (side, offset) in [128, 128 + 61].into_iter().enumerate() {
            let fixture = Fixture::new((10 + prefixes * 2 + side) as u64, offset, 3, prefixes);
            let planned = fixture.plan(TacticPolicy::PrefixPunOnly);
            assert_pun(&fixture, &planned);
            let padding = if side == 0 {
                fixture.physical() + 3
            } else {
                fixture.physical() - 1
            };
            assert_stale_byte(&fixture, &planned, padding);
        }
    }
    println!(
        "stale_consumed_beforewrite=6; stale_store_padding_beforewrite=4; successful_same_plan_retries=10; native_calls=90; callbacks=10; mismatches=0"
    );
}

fn admission_refusals() {
    let fixture = Fixture::new(0, 128, 3, 1);
    let planned = fixture.plan(TacticPolicy::PrefixPunOnly);
    assert_pun(&fixture, &planned);
    for stale in [false, true] {
        let mut held = HeldFixture(&fixture);
        let mut identity = fixture.identity;
        let ranges = if stale {
            identity.generation += 1;
            planned.plan().parts().dependencies.clone()
        } else {
            vec![planned.plan().parts().displaced]
        };
        // SAFETY: exclusive ownership is real. Deliberately stale/incomplete
        // identity/range evidence must be rejected before it can authorize writes.
        let mut lease = unsafe { QuiescenceLease::new(&mut held, identity, ranges) };
        let failure = unsafe {
            planned.publish_with(fixture.writable_source(), &mut lease, || {
                fixture.finalize_executable()
            })
        }
        .err()
        .expect("invalid lease must refuse");
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
    let allocation = fixture.allocation();
    let mut entries = fixture.entries();
    entries.entries.push(LegalEntry {
        address: fixture.physical(),
        requires_endbr: true,
    });
    assert!(matches!(
        plan_install(&fixture.request(&entries, &allocation, TacticPolicy::PrefixPunOnly)),
        Err(Refusal::UnsupportedSemantics(_))
    ));
    for incomplete in [false, true] {
        let mut entries = fixture.entries();
        if incomplete {
            entries.completeness = EntryCompleteness::Incomplete;
        } else {
            entries.resumes = ResumeObligation::Unresolved;
        }
        assert_eq!(
            plan_install(&fixture.request(&entries, &allocation, TacticPolicy::PrefixPunOnly))
                .unwrap_err(),
            Refusal::UnresolvedEntry
        );
    }
    for zero in 0..3 {
        let mut allocation = fixture.allocation();
        match zero {
            0 => allocation.max_candidates = 0,
            1 => allocation.max_mappings = 0,
            2 => allocation.max_mapped_bytes = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            plan_install(&fixture.request(
                &fixture.entries(),
                &allocation,
                TacticPolicy::PrefixPunOnly
            ))
            .unwrap_err(),
            Refusal::AllocationUnavailable
        );
    }
    assert_eq!(fixture.observed(), fixture.original_mapping);
    execute_plan(&fixture, &planned);
    println!(
        "lease_beforewrite_refusals=2; cet_refusals=1; unresolved_entry_refusals=2; zero_budget_refusals=3; successful_retry=1; native_calls=9; callbacks=1; mismatches=0"
    );
}

fn malformed_contracts() {
    let fixture = Fixture::new(0, 128, 3, 1);
    let planned = fixture.plan(TacticPolicy::PrefixPunOnly);
    assert_pun(&fixture, &planned);
    for mutation in 0..10 {
        let mut parts = planned.plan().parts().clone();
        let PlanKind::PrefixedPun(pun) = &mut parts.kind else {
            unreachable!()
        };
        match mutation {
            0 => pun.prefix_count = 0,
            1 => pun.prefix_count = pun.instruction_len,
            2 => pun.instruction_len = 1,
            3 => pun.consumed = AddressRange::new(pun.consumed.start(), 5).unwrap(),
            4 => {
                pun.target_window = AddressRange::new(
                    pun.target_window.start() + 1,
                    pun.target_window.len() as usize,
                )
                .unwrap()
            }
            5 => {
                parts.writes[0].bytes[0] = 0x3e;
                pun.store.bytes[0] = 0x3e;
            }
            6 => {
                parts.writes[0].bytes[1] = 0xeb;
                pun.store.bytes[1] = 0xeb;
            }
            7 => pun.store.bytes[3] ^= 1,
            8 => parts.generated[0].address += 1,
            9 => {
                pun.store.bytes.pop().unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            PatchPlan::checked(parts),
            Err(Refusal::InvalidPlan),
            "malformed prefixed contract {mutation}"
        );
    }
    assert_eq!(fixture.observed(), fixture.original_mapping);
    println!("malformed_prefix_count_window_opcode_store_target_refusals=10; source_changes=0");
}

fn default_fallback() {
    let fixture = Fixture::new(0, 128, 2, 1);
    let entries = fixture.entries();
    let allocation = fixture.allocation();
    for tactic in [
        TacticPolicy::GeneralizedPunOnly,
        TacticPolicy::RelocationOnly,
    ] {
        assert_eq!(
            plan_install(&fixture.request(&entries, &allocation, tactic)).unwrap_err(),
            Refusal::AllocationUnavailable
        );
    }
    let planned = fixture.plan(TacticPolicy::PreferGeneralizedPun);
    assert_pun(&fixture, &planned);
    let attempts = &planned.metrics().attempts;
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0].tactic, PatchTactic::GeneralizedPun);
    assert_eq!(attempts[0].refusal, Some(Refusal::AllocationUnavailable));
    assert_eq!(attempts[1].tactic, PatchTactic::Relocation);
    assert_eq!(attempts[1].refusal, Some(Refusal::AllocationUnavailable));
    assert_eq!(attempts[2].tactic, PatchTactic::PrefixPun);
    assert_eq!(attempts[2].refusal, None);
    execute_plan(&fixture, &planned);
    println!(
        "b2_and_relocation_unavailable=proved; default_prefixed_fallback=executed; native_calls=9; callbacks=1; mismatches=0"
    );
}
fn run_child(mode: &str) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, mode)
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: only async-signal-safe setrlimit runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            for (resource, value) in [
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_FSIZE, 65536),
                (libc::RLIMIT_CPU, 20),
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
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() >= Duration::from_secs(30) {
            // SAFETY: the owned child started its own process group.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let output = child.wait_with_output().unwrap();
            panic!("prefixed-pun child {mode} timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn prefixed_pun_contract_puzzles() {
    if let Some(mode) = std::env::var_os(CHILD_ENV) {
        let mode = mode.to_str().unwrap();
        match mode {
            "lines" => line_puzzles(),
            "pages" => page_puzzles(),
            "prerequisites" => prerequisite_refusals(),
            "stale" => stale_bytes(),
            "admission" => admission_refusals(),
            "malformed" => malformed_contracts(),
            "fallback" => default_fallback(),
            _ => panic!("unknown child mode {mode}"),
        }
        println!("prefixed-pun-contract-complete:{mode}");
        return;
    }
    for mode in [
        "lines",
        "pages",
        "prerequisites",
        "stale",
        "admission",
        "malformed",
        "fallback",
    ] {
        let output = run_child(mode);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{mode}: {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
        assert!(
            stdout.contains(&format!("prefixed-pun-contract-complete:{mode}")),
            "child filter did not execute {mode}: {stdout}"
        );
        print!("{stdout}");
    }
}
