#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Required install-once generalized-pun placement and publication puzzles.
//!
//! These bounded children exclusively own every source alias and executor.
//! The tests inspect exact semantic edits and hardware-store padding, then
//! execute every declared body head before installation, after publication,
//! and after retirement. Architectural state is checked separately by the
//! independent native oracle; these tests do not claim concurrent atomicity.

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, FailureStage, LegalEntrySet,
    PlanKind, PublicationFailure, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, InstalledOnce, PlannedInstall, SearchPolicy, TacticPolicy,
    plan_install,
};
use liteinst2::trampoline::HookContext;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const PREFIX: usize = 16;
const RESULT: u64 = 0x1937_5a2b;
const CHILD_ENV: &str = "LITEINST_GENERALIZED_PUN_CONTRACT_CHILD";
const CHILD_TEST: &str = "generalized_pun_contract_puzzles";
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
    original: Vec<u8>,
    original_mapping: Vec<u8>,
    identity: CodeIdentity,
}

impl Fixture {
    fn new(case: u64, physical_offset: usize, instruction_len: usize) -> Self {
        let instruction: &[u8] = match instruction_len {
            1 => &[0x90],
            2 => &[0x66, 0x90],
            3 => &[0x0f, 0x1f, 0x00],
            4 => &[0x0f, 0x1f, 0x40, 0x00],
            _ => panic!("unsupported required puzzle length"),
        };
        let mut original = vec![0x90; PREFIX];
        original.extend_from_slice(instruction);
        original.push(0xb8); // MOV EAX,RESULT; RET.
        original.extend_from_slice(&(RESULT as u32).to_le_bytes());
        original.push(0xc3);
        let source_offset = physical_offset.checked_sub(PREFIX).unwrap();
        assert!(source_offset + original.len() <= 2 * PAGE);
        // Each source and its entire signed-rel32 neighborhood are disjoint
        // from previous fixtures, whose generated images live until exit.
        let address = 0x3200_0000_0000_u64 + case * 0x2_0000_0000;
        let mut original_mapping = vec![0xa5; 2 * PAGE];
        original_mapping[source_offset..source_offset + original.len()].copy_from_slice(&original);
        // SAFETY: these mappings and their backing file belong only to this
        // isolated child. NOREPLACE never overwrites a preexisting mapping.
        let (writable, executable) = unsafe {
            let fd = libc::memfd_create(c"liteinst-generalized-pun".as_ptr(), libc::MFD_CLOEXEC);
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
        self.base() + PREFIX as u64
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
        // before changing both pages, including all five consumed fetch bytes.
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

    fn target_window(&self) -> AddressRange {
        // The unchanged source suffix fixes the high 5-L displacement bytes;
        // only L-1 low bytes vary. This arithmetic does not use planner output.
        let mut displacement = [0_u8; 4];
        displacement[self.instruction_len - 1..]
            .copy_from_slice(&self.original[PREFIX + self.instruction_len..PREFIX + 5]);
        let low = i128::from(self.physical() + 5) + i128::from(i32::from_le_bytes(displacement));
        let width = 1_usize << (8 * (self.instruction_len - 1));
        AddressRange::new(u64::try_from(low).unwrap(), width).unwrap()
    }

    fn allocation(&self) -> AllocationPolicy {
        let mut allocation = AllocationPolicy::near(self.physical()).unwrap();
        allocation.preferred_address = Some(self.target_window().start());
        allocation
    }

    fn entries(&self) -> LegalEntrySet {
        LegalEntrySet {
            identity: self.identity,
            scope: self.source(),
            provenance: EntryProvenance::Declared("bounded generalized-pun puzzle".into()),
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
    let PlanKind::GeneralizedPun(pun) = &parts.kind else {
        panic!("required generalized pun became {:?}", parts.kind);
    };
    let len = fixture.instruction_len;
    let physical = fixture.physical();
    assert_eq!(parts.physical_pc, physical);
    assert_eq!(parts.logical_pc, physical);
    assert_eq!(parts.displaced, AddressRange::new(physical, len).unwrap());
    assert_eq!(usize::from(pun.instruction_len), len);
    assert_eq!(pun.consumed, AddressRange::new(physical, 5).unwrap());
    assert_eq!(pun.target_window, fixture.target_window());
    assert_eq!(pun.target_window.len(), [0, 1, 256, 65536, 16777216][len]);
    assert!(pun.target_window.contains(planned.image().address()));
    if len == 4 {
        assert!(pun.target_window.end() < physical, "signed rel32 window");
    } else {
        assert!(
            pun.target_window.start() > physical,
            "positive rel32 window"
        );
    }
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.writes[0].address, physical);
    assert_eq!(parts.writes[0].bytes.len(), len);
    assert_eq!(parts.writes[0].bytes[0], 0xe9);
    let mut jump = fixture.original[PREFIX..PREFIX + 5].to_vec();
    jump[..len].copy_from_slice(&parts.writes[0].bytes);
    let target =
        i128::from(physical + 5) + i128::from(i32::from_le_bytes(jump[1..5].try_into().unwrap()));
    assert_eq!(target, i128::from(planned.image().address()));
    assert!(!parts.requirements.sigill_router);
    let store_address = physical - u64::from(len == 3 && physical % 64 == 61);
    let store_len = if len == 3 { 4 } else { len };
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
    // SAFETY: both source aliases and all five fetch bytes are owned. Every
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

fn execute_plan(fixture: &Fixture, planned: &PlannedInstall, pun: bool) {
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
    if pun {
        let observed = fixture.observed();
        let successor = fixture.source_offset + PREFIX + fixture.instruction_len;
        assert_eq!(
            observed[successor..],
            fixture.original_mapping[successor..],
            "pun changed a successor byte"
        );
    }
    for (index, head) in heads.into_iter().enumerate() {
        assert_eq!(fixture.call(head), RESULT, "patched entry {head}");
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks + 1);
        assert_eq!(LAST_PC.load(Ordering::Relaxed), fixture.physical());
        assert_eq!(installed.routed_entries(), u64::from(!pun && index > 0));
    }
    retire(fixture, &mut installed);
    for head in heads {
        assert_eq!(fixture.call(head), RESULT, "retired entry {head}");
    }
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), initial_callbacks + 1);
}

fn line_puzzles() {
    let mut pun_count = 0;
    let mut fallback_count = 0;
    for len in 2..=4 {
        for offset in 0..64 {
            let fixture = Fixture::new((len * 64 + offset) as u64, 128 + offset, len);
            if offset + len <= 64 {
                let planned = fixture.plan(TacticPolicy::GeneralizedPunOnly);
                assert_pun(&fixture, &planned);
                if offset == 0 {
                    let preferred = fixture.plan(TacticPolicy::PreferGeneralizedPun);
                    assert_pun(&fixture, &preferred);
                    assert_eq!(
                        preferred.plan(),
                        planned.plan(),
                        "pun lost first preference"
                    );
                }
                execute_plan(&fixture, &planned, true);
                pun_count += 1;
            } else {
                let entries = fixture.entries();
                let allocation = fixture.allocation();
                assert_eq!(
                    plan_install(&fixture.request(
                        &entries,
                        &allocation,
                        TacticPolicy::GeneralizedPunOnly,
                    ))
                    .unwrap_err(),
                    Refusal::NoPatchWindow,
                    "cross-line pun was not refused"
                );
                assert_eq!(fixture.observed(), fixture.original_mapping);
                let planned = fixture.plan(TacticPolicy::PreferGeneralizedPun);
                assert!(matches!(planned.plan().parts().kind, PlanKind::Relocation));
                execute_plan(&fixture, &planned, false);
                fallback_count += 1;
            }
        }
    }
    assert_eq!(pun_count, 186);
    assert_eq!(fallback_count, 6);
    println!(
        "cache_line_offsets=64; lengths=3; required_puns={pun_count}; required_relocation_fallbacks={fallback_count}; native_patched_retired_entries=576; mismatches=0"
    );
}

fn page_puzzles() {
    for len in 2..=4 {
        let fixture = Fixture::new(len as u64, PAGE - len, len);
        let planned = fixture.plan(TacticPolicy::GeneralizedPunOnly);
        assert_pun(&fixture, &planned);
        assert_eq!(
            fixture.physical() + len as u64,
            fixture.executable as usize as u64 + PAGE as u64
        );
        execute_plan(&fixture, &planned, true);
    }
    println!("two_executable_page_puns=3; native_patched_retired_entries=9; mismatches=0");
}

fn one_byte_puzzle() {
    let fixture = Fixture::new(0, 128, 1);
    let planned = fixture.plan(TacticPolicy::GeneralizedPunOnly);
    assert_pun(&fixture, &planned);
    assert_eq!(planned.image().address(), fixture.target_window().start());
    execute_plan(&fixture, &planned, true);
    println!(
        "one_byte_puns=1; target_window_bytes=1; native_patched_retired_entries=3; mismatches=0"
    );
}

fn prerequisite_refusals() {
    let fixture = Fixture::new(0, 128 + 61, 3);
    let entries = fixture.entries();
    let allocation = fixture.allocation();
    let mut request = fixture.request(&entries, &allocation, TacticPolicy::GeneralizedPunOnly);
    request.code = &fixture.original[PREFIX..];
    request.base_address = fixture.physical();
    request.function = AddressRange::new(request.base_address, request.code.len()).unwrap();
    assert_eq!(plan_install(&request).unwrap_err(), Refusal::NoPatchWindow);
    assert_eq!(fixture.observed(), fixture.original_mapping);
    for len in 2..=4 {
        let fixture = Fixture::new(len as u64, 128, len);
        let entries = fixture.entries();
        let allocation = fixture.allocation();
        let mut request = fixture.request(&entries, &allocation, TacticPolicy::GeneralizedPunOnly);
        request.code = &fixture.original[..PREFIX + len];
        request.function = AddressRange::new(fixture.base(), request.code.len()).unwrap();
        request.block = AddressRange::new(fixture.physical(), len).unwrap();
        assert_eq!(plan_install(&request).unwrap_err(), Refusal::NoPatchWindow);
        assert_eq!(fixture.observed(), fixture.original_mapping);
    }
    println!("missing_left_padding=refused; truncated_consumed_bytes=3_refused; source_changes=0");
}

fn padding_authentication() {
    for (case, offset) in [128, 128 + 61].into_iter().enumerate() {
        let fixture = Fixture::new(case as u64, offset, 3);
        let planned = fixture.plan(TacticPolicy::GeneralizedPunOnly);
        assert_pun(&fixture, &planned);
        let PlanKind::GeneralizedPun(pun) = &planned.plan().parts().kind else {
            unreachable!("assert_pun requires this variant");
        };
        let padding = if pun.store.address < fixture.physical() {
            pun.store.address
        } else {
            fixture.physical() + 3
        };
        let byte_offset = (padding - fixture.base()) as usize;
        let original = fixture.original[byte_offset];
        // SAFETY: only the held fixture owner writes this authenticated padding
        // byte. No executor is admitted; the deliberate staleness must refuse.
        unsafe {
            fixture
                .writable_source()
                .add(byte_offset)
                .write(original ^ 1)
        };
        let changed = fixture.observed();
        {
            let mut held = HeldFixture(&fixture);
            let mut lease = held.lease(planned.plan().parts().dependencies.clone());
            // SAFETY: all aliases and execution remain held. Testing stale
            // bytes does not waive any lifetime or exclusion requirement.
            let failure = match unsafe {
                planned.publish_with(fixture.writable_source(), &mut lease, || {
                    fixture.finalize_executable()
                })
            } {
                Ok(_) => panic!("publication accepted changed hardware-store padding"),
                Err(failure) => failure,
            };
            assert_eq!(failure.stage, FailureStage::BeforeWrite);
            assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
            assert!(!lease.is_poisoned());
        }
        assert_eq!(fixture.observed(), changed, "refusal wrote source bytes");
        // SAFETY: the same owner restores the original byte before retry.
        unsafe { fixture.writable_source().add(byte_offset).write(original) };
        execute_plan(&fixture, &planned, true);
    }
    println!(
        "right_padding_staleness=refused; left_padding_staleness=refused; same_plan_retries=2_executed; mismatches=0"
    );
}

struct Collision {
    address: *mut u8,
    len: usize,
}

impl Collision {
    fn new(range: AddressRange) -> Self {
        assert_eq!(range.start() as usize % PAGE, 0);
        assert_eq!(range.len() as usize % PAGE, 0);
        // SAFETY: NOREPLACE refuses any preexisting mapping. Only this child
        // owns the requested sparse fixture target region.
        let address = unsafe {
            libc::mmap(
                range.start() as usize as *mut libc::c_void,
                range.len() as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        assert_eq!(address as usize as u64, range.start());
        // SAFETY: the newly allocated range is writable and nonempty.
        unsafe { ptr::write_bytes(address.cast::<u8>(), 0xa5, range.len() as usize) };
        Self {
            address: address.cast(),
            len: range.len() as usize,
        }
    }

    fn assert_unchanged(&self) {
        // SAFETY: this owned mapping remains live and has no concurrent writer.
        assert!(
            unsafe { std::slice::from_raw_parts(self.address, self.len) }
                .iter()
                .all(|byte| *byte == 0xa5)
        );
    }
}

impl Drop for Collision {
    fn drop(&mut self) {
        // SAFETY: the reservation was never made executable or published.
        assert_eq!(unsafe { libc::munmap(self.address.cast(), self.len) }, 0);
    }
}

fn collision_puzzles() {
    let fixture = Fixture::new(0, 128, 2);
    let entries = fixture.entries();
    let allocation = fixture.allocation();
    let window = fixture.target_window();
    let blocked_start = window.start() & !(PAGE as u64 - 1);
    let blocked_end = (window.end() + PAGE as u64 - 1) & !(PAGE as u64 - 1);
    let blocker = Collision::new(
        AddressRange::new(blocked_start, (blocked_end - blocked_start) as usize).unwrap(),
    );
    assert_eq!(
        plan_install(&fixture.request(&entries, &allocation, TacticPolicy::GeneralizedPunOnly))
            .unwrap_err(),
        Refusal::AllocationUnavailable
    );
    assert_eq!(fixture.observed(), fixture.original_mapping);
    blocker.assert_unchanged();
    let fallback = fixture.plan(TacticPolicy::PreferGeneralizedPun);
    assert!(matches!(fallback.plan().parts().kind, PlanKind::Relocation));
    execute_plan(&fixture, &fallback, false);
    blocker.assert_unchanged();
    drop(blocker);
    let planned = fixture.plan(TacticPolicy::GeneralizedPunOnly);
    assert_pun(&fixture, &planned);
    fixture.executable(false);
    let blocker = Collision::new(planned.plan().parts().allocations[0].range);
    {
        let mut held = HeldFixture(&fixture);
        let mut lease = held.lease(planned.plan().parts().dependencies.clone());
        // SAFETY: the same owned aliases and held gate cover this deliberate
        // allocation failure; no execution is admitted on the failed path.
        let failure = match unsafe {
            planned.publish_with(fixture.writable_source(), &mut lease, || {
                fixture.finalize_executable()
            })
        } {
            Ok(_) => panic!("publication overwrote an occupied allocation"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure,
            PublicationFailure {
                stage: FailureStage::BeforeWrite,
                ..
            }
        ));
        assert!(matches!(failure.reason, Refusal::Backend(_)));
        assert!(!lease.is_poisoned());
    }
    assert_eq!(fixture.observed(), fixture.original_mapping);
    blocker.assert_unchanged();
    drop(blocker);
    execute_plan(&fixture, &planned, true);

    let fixture = Fixture::new(1, 128, 3);
    let entries = fixture.entries();
    let mut allocation = fixture.allocation();
    allocation.max_candidates = 0;
    assert_eq!(
        plan_install(&fixture.request(&entries, &allocation, TacticPolicy::GeneralizedPunOnly))
            .unwrap_err(),
        Refusal::AllocationUnavailable
    );
    assert_eq!(fixture.observed(), fixture.original_mapping);
    println!(
        "occupied_target_window=refused; collision_fallback=executed; zero_candidate_budget=refused; publication_collision=BeforeWrite; same_plan_retry=executed; mismatches=0"
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
            panic!("generalized-pun child {mode} timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn generalized_pun_contract_puzzles() {
    if let Some(mode) = std::env::var_os(CHILD_ENV) {
        let mode = mode.to_str().unwrap();
        match mode {
            "one-byte" => one_byte_puzzle(),
            "lines" => line_puzzles(),
            "pages" => page_puzzles(),
            "prerequisites" => prerequisite_refusals(),
            "padding" => padding_authentication(),
            "collisions" => collision_puzzles(),
            _ => panic!("unknown child mode {mode}"),
        }
        println!("generalized-pun-contract-complete:{mode}");
        return;
    }
    for mode in [
        "one-byte",
        "lines",
        "pages",
        "prerequisites",
        "padding",
        "collisions",
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
            stdout.contains(&format!("generalized-pun-contract-complete:{mode}")),
            "child filter did not execute {mode}: {stdout}"
        );
        print!("{stdout}");
    }
}
