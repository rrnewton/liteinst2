#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[allow(dead_code)]
#[path = "../../../tests/support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, FailureStage, LegalEntry,
    LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use oracle::process_text::ProcessTextOracle;
use oracle::{HookEvent, HookEventLog, HookExpectation, TraceMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const VALUES: [i32; 2] = [37, -23];
const ID: u64 = 0xe301;
const NOP5: [u8; 5] = [0x0f, 0x1f, 0x44, 0, 0];
static PREFIX_TRACE: AtomicBool = AtomicBool::new(false);
static OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static OBSERVED_PC: AtomicU64 = AtomicU64::new(0);
static OBSERVED_RAX: AtomicU64 = AtomicU64::new(0);
static OBSERVED_RDX: AtomicU64 = AtomicU64::new(0);

unsafe extern "C-unwind" {
    fn liteinst_exception_function(value: i32) -> i32;
}
unsafe extern "C" {
    fn liteinst_exception_personality();
    static liteinst_exception_function_end: u8;
    static liteinst_exception_page_end: u8;
    static liteinst_exception_call_begin: u8;
    static liteinst_exception_call_end: u8;
    static liteinst_exception_landing: u8;
    static liteinst_exception_prefix_end: u8;
    static liteinst_exception_block_end: u8;
    static liteinst_exception_lsda: u8;
    static liteinst_exception_lsda_end: u8;
    static liteinst_exception_callsites: u8;
    static liteinst_exception_callsites_end: u8;
    static liteinst_exception_type_entry: u8;
    static liteinst_exception_type_base: u8;
    static liteinst_exception_type_ref: usize;
    static liteinst_exception_personality_ref: usize;
    #[link_name = "_ZTIi"]
    static INT_TYPEINFO: u8;
    static mut liteinst_exception_pad_visits: u64;
    static mut liteinst_exception_pad_rax: u64;
    static mut liteinst_exception_pad_rdx: u64;
    static mut liteinst_exception_search: u64;
    static mut liteinst_exception_cleanup: u64;
    static mut liteinst_exception_handler: u64;
    static mut liteinst_exception_other: u64;
    static mut liteinst_exception_personality_calls: u64;
}

macro_rules! symbol {
    ($name:ident) => {{ (&raw const $name) as u64 }};
}

unsafe extern "C" fn observe(context: *mut HookContext) {
    let context = unsafe { &*context };
    OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
    OBSERVED_PC.store(context.instruction_pointer, Ordering::Relaxed);
    OBSERVED_RAX.store(context.rax, Ordering::Relaxed);
    OBSERVED_RDX.store(context.rdx, Ordering::Relaxed);
    if PREFIX_TRACE.load(Ordering::Relaxed) {
        unsafe { oracle::record_hook_event(ID, context.instruction_pointer) };
    }
    // Exercise permitted caller-clobbered state without changing HookContext.
    // DF remains ABI-clear; the generated restore must preserve the saved DF.
    unsafe {
        core::arch::asm!(
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx",
            "pxor xmm0, xmm0", "pxor xmm1, xmm1", "stc",
            out("rax") _, out("rcx") _, out("rdx") _,
            out("xmm0") _, out("xmm1") _, options(nostack)
        );
    }
}

fn bytes(address: u64, length: usize) -> Vec<u8> {
    // All callers use explicit, bounded symbols in this linked fixture.
    unsafe { std::slice::from_raw_parts(address as usize as *const u8, length).to_vec() }
}

fn uleb(data: &[u8], at: &mut usize) -> u64 {
    let mut result = 0_u64;
    for shift in (0..=63).step_by(7) {
        let byte = *data.get(*at).expect("truncated fixture LSDA ULEB");
        *at += 1;
        if shift == 63 {
            assert!(byte <= 1, "overflowing fixture LSDA ULEB");
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return result;
        }
    }
    panic!("unterminated fixture LSDA ULEB")
}

fn verify_lsda(function: u64, landing: u64) -> Vec<u8> {
    let start = symbol!(liteinst_exception_lsda);
    let end = symbol!(liteinst_exception_lsda_end);
    assert!(start < end && end - start <= 128);
    let data = bytes(start, (end - start) as usize);
    assert_eq!(&data[..2], &[0xff, 0x9b]);
    let mut at = 2;
    let type_offset = uleb(&data, &mut at);
    assert_eq!(
        start + at as u64 + type_offset,
        symbol!(liteinst_exception_type_base)
    );
    assert_eq!(data[at], 1);
    at += 1;
    let callsite_bytes = uleb(&data, &mut at);
    assert_eq!(start + at as u64, symbol!(liteinst_exception_callsites));
    assert_eq!(
        start + at as u64 + callsite_bytes,
        symbol!(liteinst_exception_callsites_end)
    );
    assert_eq!(
        uleb(&data, &mut at),
        symbol!(liteinst_exception_call_begin) - function
    );
    assert_eq!(
        uleb(&data, &mut at),
        symbol!(liteinst_exception_call_end) - symbol!(liteinst_exception_call_begin)
    );
    assert_eq!(uleb(&data, &mut at), landing - function);
    assert_eq!(uleb(&data, &mut at), 1);
    assert_eq!(start + at as u64, symbol!(liteinst_exception_callsites_end));
    assert_eq!(&data[at..at + 2], &[1, 0]);
    at += 2;
    let type_entry = symbol!(liteinst_exception_type_entry);
    assert!(
        data[at..(type_entry - start) as usize]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(type_entry + 4, symbol!(liteinst_exception_type_base));
    assert_eq!(type_entry + 4, end);
    let displacement =
        i32::from_le_bytes(data[(type_entry - start) as usize..].try_into().unwrap());
    assert_eq!(
        i128::from(type_entry) + i128::from(displacement),
        i128::from(symbol!(liteinst_exception_type_ref))
    );
    assert_eq!(
        unsafe { std::ptr::read_volatile(&raw const liteinst_exception_type_ref) },
        symbol!(INT_TYPEINFO) as usize
    );
    assert_eq!(
        unsafe { std::ptr::read_volatile(&raw const liteinst_exception_personality_ref) },
        liteinst_exception_personality as *const () as usize
    );
    data
}

fn native_catches(landing: u64, installed: bool) {
    assert!(!PREFIX_TRACE.load(Ordering::Relaxed));
    for expected in VALUES {
        macro_rules! zero {
            ($name:ident) => {
                unsafe { std::ptr::write_volatile(&raw mut $name, 0) }
            };
        }
        zero!(liteinst_exception_pad_visits);
        zero!(liteinst_exception_pad_rax);
        zero!(liteinst_exception_pad_rdx);
        zero!(liteinst_exception_search);
        zero!(liteinst_exception_cleanup);
        zero!(liteinst_exception_handler);
        zero!(liteinst_exception_other);
        zero!(liteinst_exception_personality_calls);
        for value in [&OBSERVATIONS, &OBSERVED_PC, &OBSERVED_RAX, &OBSERVED_RDX] {
            value.store(0, Ordering::Relaxed);
        }
        // The C++ exception is caught inside the assembly frame. No exception
        // passes through generated code or crosses a Rust callback frame.
        assert_eq!(unsafe { liteinst_exception_function(expected) }, expected);
        macro_rules! read {
            ($name:ident) => {
                unsafe { std::ptr::read_volatile(&raw const $name) }
            };
        }
        assert_eq!(read!(liteinst_exception_pad_visits), 1);
        assert_ne!(read!(liteinst_exception_pad_rax), 0);
        assert_eq!(read!(liteinst_exception_pad_rdx), 1);
        assert_eq!(read!(liteinst_exception_search), 1);
        assert_eq!(read!(liteinst_exception_cleanup), 1);
        assert_eq!(read!(liteinst_exception_handler), 1);
        assert_eq!(read!(liteinst_exception_other), 0);
        assert_eq!(read!(liteinst_exception_personality_calls), 2);
        assert_eq!(OBSERVATIONS.load(Ordering::Relaxed), u64::from(installed));
        if installed {
            assert_eq!(OBSERVED_PC.load(Ordering::Relaxed), landing);
            assert_eq!(
                OBSERVED_RAX.load(Ordering::Relaxed),
                read!(liteinst_exception_pad_rax)
            );
            assert_eq!(
                OBSERVED_RDX.load(Ordering::Relaxed),
                read!(liteinst_exception_pad_rdx)
            );
        } else {
            assert_eq!(OBSERVED_PC.load(Ordering::Relaxed), 0);
            assert_eq!(OBSERVED_RAX.load(Ordering::Relaxed), 0);
            assert_eq!(OBSERVED_RDX.load(Ordering::Relaxed), 0);
        }
    }
}

fn permissions(pointer: *mut u8, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(pointer.cast(), 4096, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn request<'a>(
    original: &'a [u8],
    identity: CodeIdentity,
    function: AddressRange,
    block: AddressRange,
    entries: &'a LegalEntrySet,
    allocation: &'a AllocationPolicy,
) -> InstallRequest<'a> {
    InstallRequest {
        identity,
        code: original,
        base_address: function.start(),
        function,
        block,
        logical_pc: block.start(),
        entries,
        hook: observe,
        semantics: HookSemantics::Observe,
        allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0,
            max_sites: 1,
            max_displaced_bytes: 5,
        },
    }
}

#[test]
fn exception_landing_actual_unwind_and_exact_prefix_state() {
    let function = liteinst_exception_function as *const () as u64;
    let end = symbol!(liteinst_exception_function_end);
    let landing = symbol!(liteinst_exception_landing);
    let continuation = symbol!(liteinst_exception_prefix_end);
    assert_eq!(function % 4096, 0);
    assert_eq!(symbol!(liteinst_exception_page_end), function + 4096);
    assert!(function < landing && landing < end && end < function + 2048);
    assert_eq!(continuation, landing + 5);
    assert_eq!(bytes(landing, 5), NOP5);
    let metadata = verify_lsda(function, landing);
    let original = bytes(function, (end - function) as usize);
    let source = AddressRange::new(function, 4096).unwrap();
    let scope = AddressRange::new(function, original.len()).unwrap();
    let block = AddressRange::new(
        landing,
        (symbol!(liteinst_exception_block_end) - landing) as usize,
    )
    .unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0xe3; 32]),
        mapping: 1,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity, scope: block,
        provenance: EntryProvenance::Declared("literal LSDA landing entry; complete authored basic block; no active unwind/saved contexts at publication".into()),
        completeness: EntryCompleteness::Complete,
        entries: vec![LegalEntry { address: landing, requires_endbr: false }],
        resumes: ResumeObligation::NoneExist,
    };
    let mut allocation = AllocationPolicy::near(landing).unwrap();
    allocation.preferred_address = Some(function + 64 * 1024 * 1024);
    let native = unsafe { ProcessTextOracle::new(function) };
    native.assert_publication(&[]);
    for case in 0..3 {
        let mut invalid = entries.clone();
        let expected = match case {
            0 => {
                invalid.entries.push(LegalEntry {
                    address: landing + 1,
                    requires_endbr: false,
                });
                Refusal::NotInstructionHead
            }
            1 => {
                invalid.completeness = EntryCompleteness::Incomplete;
                Refusal::UnresolvedEntry
            }
            2 => {
                invalid.resumes = ResumeObligation::Unresolved;
                Refusal::UnresolvedEntry
            }
            _ => unreachable!(),
        };
        assert!(
            matches!(plan_install(&request(&original, identity, scope, block, &invalid, &allocation)), Err(ref reason) if *reason == expected)
        );
        native.assert_publication(&[]);
    }
    let plan = plan_install(&request(
        &original,
        identity,
        scope,
        block,
        &entries,
        &allocation,
    ))
    .expect("required literal LSDA NOP5 landing must install");
    assert_eq!(plan.plan().parts().kind, PlanKind::Relocation);
    assert_eq!(plan.plan().parts().physical_pc, landing);
    assert_eq!(
        plan.plan().parts().displaced,
        AddressRange::new(landing, 5).unwrap()
    );
    assert_eq!(plan.plan().parts().writes.len(), 1);
    assert_eq!(plan.plan().parts().writes[0].address, landing);
    assert_eq!(plan.plan().parts().writes[0].bytes.len(), 5);
    assert_eq!(plan.plan().parts().writes[0].bytes[0], 0xe9);
    assert_eq!(
        plan.image().entry_routes(),
        &[(landing, plan.image().address())]
    );
    assert_eq!(plan.image().instruction_boundaries().len(), 1);
    let restored = plan.image().instruction_boundaries()[0];
    assert_eq!(restored.0, landing);
    assert_eq!(
        &plan.image().bytes()[(restored.1 - plan.image().address()) as usize..][..5],
        &NOP5
    );
    assert!(
        !plan
            .plan()
            .parts()
            .obligations
            .iter()
            .any(|item| matches!(item, liteinst2::contracts::EntryObligation::Routed(_)))
    );
    let pointer = function as usize as *mut u8;
    let mut owner = ();
    // Both failures are pre-write and preserve the exact full source page.
    {
        let stale = CodeIdentity {
            generation: 2,
            ..identity
        };
        let mut lease = unsafe { QuiescenceLease::new(&mut owner, stale, vec![source]) };
        let failure = match unsafe {
            plan.publish_with(pointer, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        } {
            Err(error) => error,
            Ok(_) => panic!("stale lease unexpectedly published"),
        };
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert_eq!(failure.reason, Refusal::StaleGeneration);
        assert!(!lease.is_poisoned());
    }
    native.assert_publication(&[]);
    {
        let mut lease = unsafe { QuiescenceLease::new(&mut owner, identity, vec![source]) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe { std::ptr::write_volatile((landing + 4) as usize as *mut u8, 1) };
        let failure = match unsafe {
            plan.publish_with(pointer, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        } {
            Err(error) => error,
            Ok(_) => panic!("stale source unexpectedly published"),
        };
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
        assert!(!lease.is_poisoned());
        // Authenticate the still-stale page before the fixture restores it.
        native.assert_publication(&[(landing + 4, vec![1])]);
        unsafe { std::ptr::write_volatile((landing + 4) as usize as *mut u8, 0) };
        permissions(pointer, libc::PROT_READ | libc::PROT_EXEC).unwrap();
    }
    native.assert_publication(&[]);
    native_catches(landing, false);
    assert_eq!(verify_lsda(function, landing), metadata);
    let originals = SEEDS.map(|seed| {
        let trace = native.trace_original(landing, &[landing], &[continuation], seed);
        assert_eq!(trace.visits(), vec![landing, continuation]);
        trace
    });
    let (mut installed, receipt) = {
        // Every prior exception and trace child has completed. Other fixture
        // threads cannot call this private assembly symbol. No aliases exist.
        let mut lease = unsafe { QuiescenceLease::new(&mut owner, identity, vec![source]) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            plan.publish_with(pointer, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap()
    };
    assert_eq!(receipt.plan(), plan.plan());
    let edits = plan
        .plan()
        .parts()
        .writes
        .iter()
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect::<Vec<_>>();
    native.assert_publication(&edits);
    assert_eq!(
        bytes(plan.image().address(), plan.image().bytes().len()),
        plan.image().bytes()
    );
    native_catches(landing, true);
    assert_eq!(verify_lsda(function, landing), metadata);
    let map = TraceMap {
        boundaries: vec![restored, (continuation, continuation)],
        gateways: vec![landing],
        generated_ranges: std::iter::once(
            plan.image().address()..plan.image().address() + plan.image().bytes().len() as u64,
        )
        .collect(),
    };
    let events = [HookEvent {
        probe_id: ID,
        logical_pc: landing,
    }];
    let log = HookEventLog::new();
    PREFIX_TRACE.store(true, Ordering::Relaxed);
    for original in &originals {
        native.assert_trace(
            original,
            landing,
            &map,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &events,
            }),
        );
    }
    PREFIX_TRACE.store(false, Ordering::Relaxed);
    {
        let mut ranges = vec![source];
        ranges.extend(
            plan.plan()
                .parts()
                .allocations
                .iter()
                .map(|allocation| allocation.range),
        );
        let mut lease = unsafe { QuiescenceLease::new(&mut owner, identity, ranges) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap();
    }
    native.assert_publication(&[]);
    native_catches(landing, false);
    assert_eq!(verify_lsda(function, landing), metadata);
    let retired_map = TraceMap {
        boundaries: vec![(landing, landing), (continuation, continuation)],
        ..TraceMap::default()
    };
    for original in &originals {
        native.assert_trace(original, landing, &retired_map, &[], None);
    }
    native.assert_publication(&[]);
    println!(
        "exception_landing actual_catches=6 original=2 installed=2 retired=2 literal_pad_visits=6 search_personality_calls=6 handler_personality_calls=6 native_hooks=2 prefix_original=2 prefix_installed=2 prefix_retired=2 prefix_hook_events=2 planning_refusals=3 before_write_refusals=2 generated_unwind_qualified=false"
    );
}
