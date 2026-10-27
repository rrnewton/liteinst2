//! A genuine caller-defined CPUID replacement, separate from native CPUID.
use super::{
    machine::Machine,
    program::{Region, permissions, search},
};
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use liteinst_inprocess::selected::SelectedKind;
use liteinst2::contracts::{AddressRange, PlanKind, QuiescenceLease};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, InstallRequest, plan_install};
use liteinst2::trampoline::HookContext;
use std::mem::ManuallyDrop;
static CALLS: AtomicU64 = AtomicU64::new(0);
static LAST_PC: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn masked_cpuid(context: *mut HookContext) {
    let c = unsafe { &mut *context };
    let leaf = c.rax as u32;
    let subleaf = c.rcx as u32;
    let mut eax = leaf;
    let mut ecx = subleaf;
    let ebx: u64;
    let edx: u32;
    unsafe {
        asm!("mov {saved}, rbx","cpuid","xchg {saved}, rbx",saved=out(reg)ebx,inout("eax")eax,inout("ecx")ecx,out("edx")edx,options(nostack,preserves_flags));
    }
    let mut values = [eax, ebx as u32, ecx, edx];
    match (leaf, subleaf) {
        (1, 0) => values[2] &= !(1 << 30),
        (7, 0) => {
            values[1] &= !(1 << 18);
            values[2] &= !(1 << 22);
        }
        (0x80000001, 0) => values[3] &= !(1 << 27),
        _ => {}
    }
    c.rax = u64::from(values[0]);
    c.rbx = u64::from(values[1]);
    c.rcx = u64::from(values[2]);
    c.rdx = u64::from(values[3]);
    LAST_PC.store(c.instruction_pointer, Ordering::Relaxed);
    CALLS.fetch_add(1, Ordering::Relaxed);
}

pub struct Observation {
    pub leaf: u32,
    pub subleaf: u32,
    pub outputs: [u64; 4],
    pub calls: u64,
}
// A complete original hardware CPUID read is the independent expected policy
// input. Only the explicitly selected returned feature bits are changed.
#[allow(unused_unsafe)] // Rust1.85 intrinsic signature.
fn hardware(leaf: u32, subleaf: u32) -> [u32; 4] {
    let c = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
    [c.eax, c.ebx, c.ecx, c.edx]
}
pub fn observe(kind: SelectedKind) -> Observation {
    let (leaf, index, bit) = match kind {
        SelectedKind::Rdrand => (1, 2, 30),
        SelectedKind::Rdseed => (7, 1, 18),
        SelectedKind::Rdpid => (7, 2, 22),
        SelectedKind::Rdtscp => (0x80000001, 3, 27),
        _ => unreachable!(),
    };
    let native = hardware(leaf, 0);
    assert_ne!(
        native[index] & (1 << bit),
        0,
        "this masking control requires an actual advertised bit"
    );
    let mut expected = native;
    match leaf {
        1 => expected[2] &= !(1 << 30),
        7 => {
            expected[1] &= !(1 << 18);
            expected[2] &= !(1 << 22);
        }
        0x80000001 => expected[3] &= !(1 << 27),
        _ => unreachable!(),
    }
    // Entirely disjoint certified source/function interval from the random site.
    let mut region = ManuallyDrop::new(Region::new(&[0x0f, 0xa2], false));
    let entries = region.entries();
    let allocation = AllocationPolicy::near(region.entry()).unwrap();
    let prepared = plan_install(&InstallRequest {
        identity: region.identity(),
        code: &region.original[region.offset..=region.end],
        base_address: region.entry(),
        function: entries.scope,
        block: entries.scope,
        logical_pc: region.entry(),
        entries: &entries,
        hook: masked_cpuid,
        semantics: HookSemantics::ReplaceFirst,
        allocation: &allocation,
        search: search(),
    })
    .unwrap();
    assert_eq!(prepared.plan().parts().kind, PlanKind::Relocation);
    assert_eq!(prepared.plan().parts().physical_pc, region.entry());
    let mut expected_source = region.original.clone();
    for edit in &prepared.plan().parts().writes {
        let start = usize::try_from(edit.address - region.address.as_ptr() as u64).unwrap();
        expected_source[start..start + edit.bytes.len()].copy_from_slice(&edit.bytes);
    }
    let address = region.address.as_ptr();
    let len = region.original.len();
    let offset = region.offset;
    let identity = region.identity();
    let entry = region.entry();
    let (installed, receipt) = {
        let mut lease = unsafe {
            QuiescenceLease::new(
                &mut *region,
                identity,
                vec![AddressRange::new(address as u64, len).unwrap()],
            )
        };
        permissions(address, len, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        let result = unsafe {
            prepared.publish_with(address.add(offset), &mut lease, || {
                permissions(address, len, libc::PROT_READ | libc::PROT_EXEC)
            })
        };
        let result = match result {
            Ok(value) => value,
            Err(error) => {
                eprintln!("CPUID policy publication refused: {error:?}");
                std::process::abort();
            }
        };
        assert!(!lease.is_poisoned());
        result
    };
    let owner = ManuallyDrop::new((region, installed, receipt));
    assert_eq!(owner.1.plan(), prepared.plan());
    assert_eq!(owner.2.plan(), prepared.plan());
    assert_eq!(owner.0.bytes(), expected_source);
    assert_eq!(owner.0.bytes()[offset], 0xe9);
    let generated = unsafe {
        std::slice::from_raw_parts(
            owner.1.trampoline().address() as *const u8,
            owner.1.trampoline().code_len(),
        )
    };
    assert_eq!(generated, prepared.image().bytes());
    let mut machine = Machine::new();
    machine.initial[0] = u64::from(leaf);
    machine.initial[2] = 0;
    let mut actual = machine.empty_snapshot();
    let before = CALLS.load(Ordering::Relaxed);
    machine.capture_into(entry as usize, &mut actual);
    let calls = CALLS.load(Ordering::Relaxed).checked_sub(before).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(LAST_PC.load(Ordering::Relaxed), entry);
    let mut expected_state = machine.initial;
    expected_state[7] += 8;
    for (destination, value) in [
        (0, expected[0]),
        (1, expected[1]),
        (2, expected[2]),
        (3, expected[3]),
    ] {
        expected_state[destination] = u64::from(value);
    }
    assert_eq!(actual.registers, expected_state);
    let outputs = [
        actual.registers[0],
        actual.registers[1],
        actual.registers[2],
        actual.registers[3],
    ];
    assert_eq!(
        outputs[index] & (1 << bit),
        0,
        "the actual returned CPUID bit must be clear"
    );
    Observation {
        leaf,
        subleaf: 0,
        outputs,
        calls,
    }
}
