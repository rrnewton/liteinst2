#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Forced native placement, entry-routing, and transaction puzzles.
//!
//! Each child owns private fixture mappings and is the only executor or writer
//! that can access them. The parent bounds execution and authenticates that the
//! selected child completed every required row. This is additional native
//! evidence, not a replacement for the independent architectural-state oracle.

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, FailureStage,
    LegalEntry, LegalEntrySet, PublicationFailure, QuiescenceLease, Refusal, ResumeObligation,
    SourceIdentity,
};
use liteinst2::patcher::{JumpPatchPlan, LiveJumpPatch, StalenessBudget};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, InstalledOnce, PlannedInstall, SearchPolicy, plan_install,
};
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::HookContext;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const CHILD_ENV: &str = "LITEINST_QUIESCENT_CONTRACT_CHILD";
const CHILD_TEST: &str = "quiescent_contract_puzzles";
const RESULT: u64 = 0x1937_5a2b;
const ILLEGAL: [u8; 14] = [
    0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
];
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
    offset: usize,
    original: Vec<u8>,
    identity: CodeIdentity,
}

impl Fixture {
    fn new(case: u64, offset: usize, original: Vec<u8>) -> Self {
        assert!(offset + original.len() <= 2 * PAGE);
        // Sparse, private addresses keep every constrained-rel32 puzzle away
        // from the process loader. NOREPLACE makes a collision a test failure,
        // never permission to overwrite another mapping.
        let address = 0x3000_0000_0000_u64 + case * 0x1000_0000;
        // SAFETY: these syscalls create mappings owned only by this child.
        let (writable, executable) = unsafe {
            let fd = libc::memfd_create(c"liteinst-quiescent-contract".as_ptr(), libc::MFD_CLOEXEC);
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
                original.as_ptr(),
                writable.cast::<u8>().add(offset),
                original.len(),
            );
            (writable.cast(), executable.cast())
        };
        Self {
            writable,
            executable,
            offset,
            original,
            identity: CodeIdentity {
                source: SourceIdentity([case as u8; 32]),
                mapping: case + 1,
                generation: 1,
            },
        }
    }

    fn base(&self) -> u64 {
        self.executable as usize as u64 + self.offset as u64
    }

    fn writable_source(&self) -> *mut u8 {
        // SAFETY: construction checked this offset within the owned mapping.
        unsafe { self.writable.add(self.offset) }
    }

    fn source(&self) -> AddressRange {
        AddressRange::new(self.base(), self.original.len()).unwrap()
    }

    fn observed(&self) -> Vec<u8> {
        // SAFETY: no concurrent writer exists in this isolated fixture.
        unsafe { std::slice::from_raw_parts(self.writable_source(), self.original.len()) }.to_vec()
    }

    fn executable(&self, enabled: bool) {
        let protections = libc::PROT_READ | if enabled { libc::PROT_EXEC } else { 0 };
        // SAFETY: the child owns the complete executable alias and has no
        // in-flight application call or saved continuation when changing it.
        assert_eq!(
            unsafe { libc::mprotect(self.executable.cast(), 2 * PAGE, protections) },
            0
        );
    }

    fn finalize_executable(&self) -> Result<(), Refusal> {
        // SAFETY: exclusive ownership continues to gate actual execution while
        // the publisher establishes final RX permissions before sync-core.
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

    fn allocation(&self) -> AllocationPolicy {
        let mut allocation = AllocationPolicy::near(self.base()).unwrap();
        allocation.preferred_address =
            Some(self.base() + 64 * 1024 * 1024 + (self.identity.mapping - 1) * 1024 * 1024);
        allocation
    }

    fn entries(&self) -> LegalEntrySet {
        LegalEntrySet {
            identity: self.identity,
            scope: self.source(),
            provenance: EntryProvenance::Declared("bounded native contract puzzle".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        }
    }

    fn request<'a>(
        &'a self,
        entries: &'a LegalEntrySet,
        allocation: &'a AllocationPolicy,
        block_len: usize,
    ) -> InstallRequest<'a> {
        InstallRequest {
            identity: self.identity,
            code: &self.original,
            base_address: self.base(),
            function: self.source(),
            block: AddressRange::new(self.base(), block_len).unwrap(),
            logical_pc: self.base(),
            entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation,
            search: SearchPolicy {
                max_upstream_bytes: 0,
                max_sites: 1,
                max_displaced_bytes: block_len,
            },
        }
    }

    fn plan(&self, block_len: usize) -> PlannedInstall {
        plan_install(&self.request(&self.entries(), &self.allocation(), block_len)).unwrap_or_else(
            |reason| panic!("required positive fixture at {:#x}: {reason}", self.base()),
        )
    }

    fn call(&self, offset: usize) -> u64 {
        // SAFETY: positive fixtures are NOPs followed by MOV EAX,constant; RET.
        // Only verified instruction heads are passed, and the alias is RX.
        let function: extern "C" fn() -> u64 =
            unsafe { std::mem::transmute((self.base() + offset as u64) as usize) };
        function()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: ordinary child paths retire all references before this drop.
        // The intentionally retained legacy/failure paths terminate without it.
        unsafe {
            assert_eq!(libc::munmap(self.writable.cast(), 2 * PAGE), 0);
            assert_eq!(libc::munmap(self.executable.cast(), 2 * PAGE), 0);
        }
    }
}

/// Exclusive ownership, not NX alone, establishes this fixture's quiescence.
/// No other thread, handler, writer, or saved context knows its code addresses.
struct HeldFixture<'a>(&'a Fixture);

impl HeldFixture<'_> {
    fn lease(&mut self, identity: CodeIdentity, ranges: Vec<AddressRange>) -> QuiescenceLease<'_> {
        assert!(!ranges.is_empty());
        // Read the ownership binding so this guard cannot become a free token.
        assert!(!self.0.writable_source().is_null());
        // SAFETY: the isolated child owns all aliases and accesses. Callers
        // keep execution stopped through the borrow and pass only held ranges.
        unsafe { QuiescenceLease::new(self, identity, ranges) }
    }
}

fn nop(len: usize) -> &'static [u8] {
    match len {
        1 => &[0x90],
        2 => &[0x66, 0x90],
        3 => &[0x0f, 0x1f, 0x00],
        4 => &[0x0f, 0x1f, 0x40, 0x00],
        5 => &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        _ => panic!("invalid puzzle NOP length"),
    }
}

fn image(mut prefix: Vec<u8>) -> Vec<u8> {
    prefix.push(0xb8);
    prefix.extend_from_slice(&(RESULT as u32).to_le_bytes());
    prefix.push(0xc3);
    prefix
}

fn patched_snapshot(fixture: &Fixture, planned: &PlannedInstall) -> Vec<u8> {
    let mut expected = fixture.original.clone();
    for edit in &planned.plan().parts().writes {
        let offset = (edit.address - fixture.base()) as usize;
        expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
    }
    expected
}

fn retire(fixture: &Fixture, installed: &mut InstalledOnce) {
    fixture.executable(false);
    let mut ranges = installed.plan().parts().dependencies.clone();
    ranges.extend(installed.plan().parts().allocations.iter().map(|a| a.range));
    let mut held = HeldFixture(fixture);
    let mut lease = held.lease(fixture.identity, ranges);
    // SAFETY: this fresh lease drains both original and generated execution;
    // the finalizer changes permissions without admitting execution or unwinding.
    unsafe { installed.retire_with(&mut lease, || fixture.finalize_executable()) }.unwrap();
    assert!(!lease.is_poisoned());
    assert!(installed.is_retired());
    assert_eq!(fixture.observed(), fixture.original);
}

fn positive(case: u64, offset: usize, prefix: Vec<u8>, heads: &[usize]) -> (usize, u128) {
    assert_eq!(prefix.len(), 5);
    let fixture = Fixture::new(case, offset, image(prefix));
    fixture.executable(true);
    let initial_callbacks = CALLBACKS.load(Ordering::Relaxed);
    for &head in heads {
        assert_eq!(fixture.call(head), RESULT, "native head {head}");
    }
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks);
    fixture.executable(false);
    let planned = fixture.plan(5);
    let parts = planned.plan().parts();
    assert_eq!(parts.physical_pc, fixture.base());
    assert_eq!(parts.logical_pc, fixture.base());
    assert_eq!(parts.displaced.len(), 5);
    assert_eq!(parts.writes.len(), 1);
    let replacement = &parts.writes[0].bytes;
    assert_eq!(replacement[0], 0xe9);
    let encoded_target = i128::from(fixture.base() + 5)
        + i128::from(i32::from_le_bytes(replacement[1..5].try_into().unwrap()));
    assert_eq!(encoded_target, i128::from(planned.image().address()));
    let routes: Vec<_> = parts
        .obligations
        .iter()
        .filter_map(|entry| match entry {
            EntryObligation::Routed(route) => Some(route),
            _ => None,
        })
        .collect();
    assert_eq!(routes.len(), heads.len() - 1);
    for &head in &heads[1..] {
        assert!(
            ILLEGAL.contains(&replacement[head]),
            "unqualified byte at {head}"
        );
        let route = routes
            .iter()
            .find(|route| route.original == fixture.base() + head as u64)
            .unwrap();
        assert!(
            planned
                .image()
                .entry_routes()
                .contains(&(route.original, route.generated))
        );
    }
    assert_eq!(
        fixture.observed(),
        fixture.original,
        "planning changed source"
    );
    let (mut installed, publication_ns) = {
        let mut held = HeldFixture(&fixture);
        let mut lease = held.lease(fixture.identity, parts.dependencies.clone());
        // SAFETY: all source aliases are owned, executable fetch is gated, and
        // the caller has drained every fixture call before constructing lease.
        let start = Instant::now();
        let (installed, receipt) = unsafe {
            planned.publish_with(fixture.writable_source(), &mut lease, || {
                fixture.finalize_executable()
            })
        }
        .unwrap_or_else(|error| panic!("required publication at {:#x}: {error:?}", fixture.base()));
        let publication_ns = start.elapsed().as_nanos();
        assert_eq!(receipt.plan(), planned.plan());
        assert!(!lease.is_poisoned());
        (installed, publication_ns)
    };
    assert_eq!(fixture.observed(), patched_snapshot(&fixture, &planned));
    for (index, &head) in heads.iter().enumerate() {
        assert_eq!(fixture.call(head), RESULT, "patched head {head}");
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks + 1);
        assert_eq!(LAST_PC.load(Ordering::Relaxed), fixture.base());
        assert_eq!(installed.routed_entries(), index as u64);
    }
    retire(&fixture, &mut installed);
    for &head in heads {
        assert_eq!(fixture.call(head), RESULT, "retired head {head}");
    }
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks + 1);
    (heads.len(), publication_ns)
}

fn layout_puzzles() {
    let mut executed = 0;
    let mut publication_ns = Vec::new();
    for mask in 0_u8..16 {
        let mut heads = vec![0];
        heads.extend((1..5).filter(|&offset| mask & (1 << (offset - 1)) != 0));
        let mut prefix = Vec::new();
        for (index, &start) in heads.iter().enumerate() {
            let end = heads.get(index + 1).copied().unwrap_or(5);
            prefix.extend_from_slice(nop(end - start));
        }
        let (entries, elapsed) = positive(u64::from(mask), 128, prefix, &heads);
        executed += entries;
        publication_ns.push(elapsed);
    }
    assert_eq!(
        executed, 48,
        "every permitted head in all 16 layouts must execute"
    );
    println!("layouts=16; native_and_patched_and_retired_entries={executed}; mismatches=0");
    println!("layout_publication_ns={publication_ns:?}");
}

fn boundary_puzzles() {
    let mut publication_ns = Vec::new();
    for offset in 0..64 {
        let (entries, elapsed) = positive(offset as u64, 128 + offset, nop(5).to_vec(), &[0]);
        assert_eq!(entries, 1);
        publication_ns.push(elapsed);
    }
    for crossing in 1..5 {
        let (entries, elapsed) =
            positive(64 + crossing as u64, PAGE - crossing, nop(5).to_vec(), &[0]);
        assert_eq!(entries, 1);
        publication_ns.push(elapsed);
    }
    println!("cache_line_offsets=64; word_alignments=8; crossing_page_offsets=4; mismatches=0");
    println!("boundary_publication_ns={publication_ns:?}");
}

fn page_tail_puzzle() {
    // LEA RAX,[RIP]; MOV EAX,EAX; RET ends exactly at the executable page.
    // Entering MOV or RET is originally valid even though the next page cannot
    // be fetched. A longer invalid EVEX encoding must not introduce #PF there.
    let fixture = Fixture::new(
        0,
        PAGE - 10,
        vec![0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x89, 0xc0, 0xc3],
    );
    assert_eq!(
        fixture.base() + 10,
        fixture.executable as usize as u64 + PAGE as u64
    );
    // SAFETY: this child exclusively owns both aliases. Every later permission
    // change covers only the first page, retaining this guard through retirement.
    assert_eq!(
        unsafe { libc::mprotect(fixture.executable.add(PAGE).cast(), PAGE, libc::PROT_NONE,) },
        0
    );
    let permissions = |executable: bool| -> Result<(), Refusal> {
        let protections = libc::PROT_READ | if executable { libc::PROT_EXEC } else { 0 };
        // SAFETY: all calls are drained and exclusive ownership remains held;
        // this operation never admits an executor and never touches the guard.
        if unsafe { libc::mprotect(fixture.executable.cast(), PAGE, protections) } == 0 {
            Ok(())
        } else {
            Err(Refusal::Backend(
                std::io::Error::last_os_error().to_string(),
            ))
        }
    };
    let seed = 0xfeed_abcd_7654_3210_u64;
    let call = |offset: u64| -> u64 {
        let result: u64;
        // SAFETY: these three verified heads contain LEA/MOV/RET only. The
        // generated hook follows System V and preserves the seeded application
        // state, including RAX for the bare RET entry.
        unsafe {
            core::arch::asm!(
                "call r11",
                in("r11") fixture.base() + offset,
                inlateout("rax") seed => result,
                clobber_abi("C"),
            );
        }
        result
    };
    let expected = [
        (0, (fixture.base() + 7) as u32 as u64),
        (7, seed as u32 as u64),
        (9, seed),
    ];
    let initial_callbacks = CALLBACKS.load(Ordering::Relaxed);
    permissions(true).unwrap();
    for &(head, result) in &expected {
        assert_eq!(call(head), result, "native page-tail entry {head}");
    }
    permissions(false).unwrap();
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks);
    let entries = fixture.entries();
    let allocation = fixture.allocation();
    let mut request = fixture.request(&entries, &allocation, 10);
    request.logical_pc = fixture.base() + 7;
    request.search.max_upstream_bytes = 7;
    request.search.max_sites = 2;
    let planned = plan_install(&request).expect("required positive page-tail placement");
    assert_eq!(planned.plan().parts().physical_pc, fixture.base());
    assert_eq!(planned.plan().parts().logical_pc, fixture.base() + 7);
    assert_eq!(planned.plan().parts().displaced.len(), 9);
    assert_eq!(patched_snapshot(&fixture, &planned)[7], 0x60);
    assert_eq!(fixture.observed(), fixture.original);
    let (mut installed, publication_ns) = {
        let mut held = HeldFixture(&fixture);
        let mut lease = held.lease(
            fixture.identity,
            planned.plan().parts().dependencies.clone(),
        );
        let start = Instant::now();
        // SAFETY: the exclusive fixture gate remains held through the final RX
        // transition, receipt, and sync-core. The guard page stays PROT_NONE.
        let (installed, receipt) = unsafe {
            planned.publish_with(fixture.writable_source(), &mut lease, || permissions(true))
        }
        .unwrap();
        assert_eq!(receipt.plan(), planned.plan());
        assert!(!lease.is_poisoned());
        (installed, start.elapsed().as_nanos())
    };
    assert_eq!(fixture.observed(), patched_snapshot(&fixture, &planned));
    for (index, &(head, result)) in expected.iter().enumerate() {
        assert_eq!(call(head), result, "patched page-tail entry {head}");
        assert_eq!(
            CALLBACKS.load(Ordering::Relaxed),
            initial_callbacks + if index == 0 { 1 } else { 2 }
        );
        assert_eq!(LAST_PC.load(Ordering::Relaxed), fixture.base() + 7);
        assert_eq!(installed.routed_entries(), u64::from(index != 0));
    }
    permissions(false).unwrap();
    {
        let mut ranges = planned.plan().parts().dependencies.clone();
        ranges.extend(planned.plan().parts().allocations.iter().map(|a| a.range));
        let mut held = HeldFixture(&fixture);
        let mut lease = held.lease(fixture.identity, ranges);
        // SAFETY: original and generated execution are drained under the fresh
        // lease; only the source page returns to RX before completion.
        unsafe { installed.retire_with(&mut lease, || permissions(true)) }.unwrap();
        assert!(!lease.is_poisoned());
    }
    assert!(installed.is_retired());
    assert_eq!(fixture.observed(), fixture.original);
    for &(head, result) in &expected {
        assert_eq!(call(head), result, "retired page-tail entry {head}");
    }
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks + 2);
    println!(
        "guarded_page_tail=passed; marker=0x60; native_and_patched_and_retired_entries=3; mismatches=0; publication_ns={publication_ns}"
    );
}

fn publication_failure(
    fixture: &Fixture,
    planned: &PlannedInstall,
    identity: CodeIdentity,
    ranges: Vec<AddressRange>,
) -> PublicationFailure {
    let before = fixture.observed();
    let mut held = HeldFixture(fixture);
    let mut lease = held.lease(identity, ranges);
    // SAFETY: source ownership/exclusion holds even when the supplied plan or
    // lease identity/range evidence is deliberately stale or incomplete.
    let failure = match unsafe { planned.publish(fixture.writable_source(), &mut lease) } {
        Ok(_) => panic!("negative publication unexpectedly succeeded"),
        Err(failure) => failure,
    };
    assert_eq!(failure.stage, FailureStage::BeforeWrite);
    assert!(!lease.is_poisoned());
    assert_eq!(
        fixture.observed(),
        before,
        "prepublication failure changed bytes"
    );
    failure
}

fn planning_negatives() {
    let fixture = Fixture::new(0, 128, image(nop(5).to_vec()));
    let allocation = fixture.allocation();
    let original = fixture.observed();
    let mut entries = fixture.entries();
    entries.identity.generation += 1;
    assert_eq!(
        plan_install(&fixture.request(&entries, &allocation, 5)).unwrap_err(),
        Refusal::StaleGeneration
    );
    entries = fixture.entries();
    entries.completeness = EntryCompleteness::Incomplete;
    assert_eq!(
        plan_install(&fixture.request(&entries, &allocation, 5)).unwrap_err(),
        Refusal::UnresolvedEntry
    );
    entries = fixture.entries();
    entries.resumes = ResumeObligation::Unresolved;
    assert_eq!(
        plan_install(&fixture.request(&entries, &allocation, 5)).unwrap_err(),
        Refusal::UnresolvedEntry
    );
    entries = fixture.entries();
    entries.entries.push(LegalEntry {
        address: fixture.base() + 1,
        requires_endbr: false,
    });
    assert_eq!(
        plan_install(&fixture.request(&entries, &allocation, 5)).unwrap_err(),
        Refusal::NotInstructionHead
    );
    entries = fixture.entries();
    entries.entries.push(LegalEntry {
        address: fixture.base(),
        requires_endbr: true,
    });
    assert!(matches!(
        plan_install(&fixture.request(&entries, &allocation, 5)),
        Err(Refusal::UnsupportedSemantics(_))
    ));
    let mut exhausted = allocation.clone();
    exhausted.max_mappings = 0;
    assert_eq!(
        plan_install(&fixture.request(&fixture.entries(), &exhausted, 5)).unwrap_err(),
        Refusal::AllocationUnavailable
    );
    assert_eq!(fixture.observed(), original);

    for (case, (name, prefix)) in [
        ("CALL", vec![0xe8, 0, 0, 0, 0]),
        ("x87 FLDZ", vec![0xd9, 0xee, 0x0f, 0x1f, 0x00]),
        ("MOV SS,AX", vec![0x8e, 0xd0, 0x0f, 0x1f, 0x00]),
        ("far indirect JMP", vec![0x48, 0xff, 0x28, 0x66, 0x90]),
        ("POPFQ", vec![0x9d, 0x0f, 0x1f, 0x40, 0]),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(case as u64 + 1, 128, image(prefix));
        let refused = plan_install(&fixture.request(&fixture.entries(), &fixture.allocation(), 5));
        assert!(
            matches!(refused, Err(Refusal::UnsupportedSemantics(_))),
            "{name}: {refused:?}"
        );
        assert_eq!(fixture.observed(), fixture.original, "{name} modified code");
    }
    println!("planning_refusals=11; source_changes=0");
}

fn transaction_negatives() {
    let fixture = Fixture::new(0, 128, image(nop(5).to_vec()));
    let planned = fixture.plan(5);
    let dependencies = planned.plan().parts().dependencies.clone();
    let mut advanced = fixture.identity;
    advanced.generation += 1;
    assert_eq!(
        publication_failure(&fixture, &planned, advanced, dependencies.clone()).reason,
        Refusal::StaleGeneration
    );
    assert_eq!(
        publication_failure(
            &fixture,
            &planned,
            fixture.identity,
            vec![AddressRange::new(fixture.base() + 1, fixture.original.len() - 1).unwrap()]
        )
        .reason,
        Refusal::DependencyNotHeld
    );
    // The mapping owner changes an immediate after planning. Failure must
    // retain that complete current snapshot, not overwrite it with old bytes.
    unsafe { fixture.writable_source().add(6).write(0xa5) };
    assert_eq!(
        publication_failure(&fixture, &planned, fixture.identity, dependencies.clone()).reason,
        Refusal::ExpectedBytesChanged
    );
    unsafe { fixture.writable_source().add(6).write(fixture.original[6]) };

    let allocation = planned.plan().parts().allocations[0].range;
    // SAFETY: planning has not reserved this target. NOREPLACE independently
    // claims it after planning, forcing the real publisher allocation failure.
    let collision = unsafe {
        libc::mmap(
            allocation.start() as usize as *mut libc::c_void,
            allocation.len() as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_eq!(collision as usize as u64, allocation.start());
    unsafe { ptr::write_bytes(collision.cast::<u8>(), 0xa5, allocation.len() as usize) };
    assert!(matches!(
        publication_failure(&fixture, &planned, fixture.identity, dependencies.clone()).reason,
        Refusal::Backend(_)
    ));
    assert!(
        unsafe { std::slice::from_raw_parts(collision.cast::<u8>(), allocation.len() as usize) }
            .iter()
            .all(|&byte| byte == 0xa5)
    );
    assert_eq!(
        unsafe { libc::munmap(collision, allocation.len() as usize) },
        0
    );
    // A failed allocation must release both pending byte ownership and storage
    // so the same immutable plan can subsequently publish successfully.
    let mut installed = {
        let mut held = HeldFixture(&fixture);
        let mut lease = held.lease(fixture.identity, dependencies);
        unsafe {
            planned.publish_with(fixture.writable_source(), &mut lease, || {
                fixture.finalize_executable()
            })
        }
        .unwrap()
        .0
    };
    assert_eq!(fixture.call(0), RESULT);
    fixture.executable(false);
    let retained = fixture.observed();
    {
        let mut held = HeldFixture(&fixture);
        let mut lease = held.lease(
            fixture.identity,
            planned.plan().parts().dependencies.clone(),
        );
        // SAFETY: the fixture owns and drains generated code as well. The
        // deliberately incomplete range evidence must be refused before writes.
        let failure = unsafe { installed.retire(&mut lease) }.unwrap_err();
        assert_eq!(failure.reason, Refusal::DependencyNotHeld);
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert!(!lease.is_poisoned());
        assert_eq!(fixture.observed(), retained);
    }
    retire(&fixture, &mut installed);
    println!(
        "prepublication_refusals=4; failed_allocation_retry=passed; incomplete_retirement_lease=refused; source_changes=0"
    );
}

fn legacy_overlap() {
    let fixture = Fixture::new(0, 128, image(nop(5).to_vec()));
    fixture.executable(true);
    let planned = fixture.plan(5);
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&fixture.original, fixture.base()).unwrap();
    let legacy = JumpPatchPlan::from_scan(
        &scanner,
        &scan,
        &fixture.original,
        fixture.base(),
        fixture.base(),
        planned.image().address(),
    )
    .unwrap();
    // SAFETY: this never publishes or executes a legacy redirect. Its aliases
    // remain mapped and executable until the child exits; no concurrent writer
    // or executor can access this fixture, including during the refused call.
    let _binding = unsafe {
        LiveJumpPatch::bind(
            legacy,
            fixture.writable_source(),
            StalenessBudget::new(1).unwrap(),
        )
    }
    .unwrap();
    assert_eq!(
        publication_failure(
            &fixture,
            &planned,
            fixture.identity,
            planned.plan().parts().dependencies.clone()
        )
        .reason,
        Refusal::OwnershipConflict
    );
    println!("legacy_overlap=refused; source_changes=0");
    std::mem::forget(fixture);
}

fn synchronization_failure() {
    let fixture = Fixture::new(0, 128, image(nop(5).to_vec()));
    let planned = fixture.plan(5);
    // This child denies only membarrier after planning. It therefore exercises
    // the real kernel capability failure before allocation or source writes.
    let mut instructions = [
        libc::sock_filter {
            code: 0x20, // BPF_LD | BPF_W | BPF_ABS, seccomp_data.nr
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
            jt: 0,
            jf: 1,
            k: libc::SYS_membarrier as u32,
        },
        libc::sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    // SAFETY: the kernel copies this valid program; its irreversible filter is
    // confined to the dedicated child and preserves every other system call.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
                0,
                0,
            ),
            0
        );
    }
    assert_eq!(
        publication_failure(
            &fixture,
            &planned,
            fixture.identity,
            planned.plan().parts().dependencies.clone()
        )
        .reason,
        Refusal::Synchronization
    );
    println!("sync_core_unavailable=refused; source_changes=0");
}

fn postwrite_failure() -> ! {
    let fixture = Fixture::new(0, 128, image(vec![0x90; 5]));
    let planned = fixture.plan(5);
    let mut held = HeldFixture(&fixture);
    let mut lease = held.lease(
        fixture.identity,
        planned.plan().parts().dependencies.clone(),
    );
    let mut finalized = false;
    // SAFETY: the deliberate failure keeps execute permission revoked. Neither
    // this closure nor this child releases the gate after the source edit.
    let failure = match unsafe {
        planned.publish_with(fixture.writable_source(), &mut lease, || {
            finalized = true;
            Err(Refusal::Backend("forced final-permissions failure".into()))
        })
    } {
        Ok(_) => panic!("postwrite fault injection unexpectedly succeeded"),
        Err(failure) => failure,
    };
    assert!(finalized);
    assert_eq!(failure.stage, FailureStage::KeepGated);
    assert_eq!(
        failure.reason,
        Refusal::Backend("forced final-permissions failure".into())
    );
    assert!(lease.is_poisoned());
    assert_eq!(fixture.observed(), patched_snapshot(&fixture, &planned));
    assert_eq!(lease.check(planned.plan()), Err(Refusal::LeasePoisoned));
    let repeated = match unsafe { planned.publish(fixture.writable_source(), &mut lease) } {
        Ok(_) => panic!("poisoned lease was reused"),
        Err(failure) => failure,
    };
    assert_eq!(repeated.stage, FailureStage::BeforeWrite);
    assert_eq!(repeated.reason, Refusal::LeasePoisoned);
    assert_eq!(fixture.observed(), patched_snapshot(&fixture, &planned));
    println!("postwrite_fault=KeepGated; poisoned_retry=refused; execute_gate=held");
    println!("quiescent-contract-complete:postwrite");
    std::io::stdout().flush().unwrap();
    // Terminate while the borrowed gate and all possibly reachable resources
    // remain held. The parent independently requires this completion marker.
    std::process::exit(0)
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
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let output = child.wait_with_output().unwrap();
            panic!("quiescent contract child {mode} timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn quiescent_contract_puzzles() {
    if let Some(mode) = std::env::var_os(CHILD_ENV) {
        let mode = mode.to_str().unwrap();
        match mode {
            "layouts" => layout_puzzles(),
            "boundaries" => boundary_puzzles(),
            "page-tail" => page_tail_puzzle(),
            "planning-negative" => planning_negatives(),
            "transaction-negative" => transaction_negatives(),
            "legacy-overlap" => legacy_overlap(),
            "synchronization-negative" => synchronization_failure(),
            "postwrite" => postwrite_failure(),
            _ => panic!("unknown child mode {mode}"),
        }
        println!("quiescent-contract-complete:{mode}");
        return;
    }
    for mode in [
        "layouts",
        "boundaries",
        "page-tail",
        "planning-negative",
        "transaction-negative",
        "legacy-overlap",
        "synchronization-negative",
        "postwrite",
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
            stdout.contains(&format!("quiescent-contract-complete:{mode}")),
            "child filter did not run {mode}: {stdout}"
        );
        print!("{stdout}");
    }
}
