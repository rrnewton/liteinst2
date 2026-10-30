//! Private finite component adapter. It does not publish source patches or grant
//! arbitrary entry, exception, rseq, alias, mapping or application authority.
#![deny(unsafe_op_in_unsafe_fn)]
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    ResumeObligation, SourceIdentity,
};
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::quiescent::{AllocationPolicy, PlannedInstall};
use liteinst2::quiescent::{WholeFunctionRequest, plan_whole_function_controlled_detailed};
use liteinst2::trampoline::{HookContext, ObservationStackProfile};
use std::sync::atomic::{AtomicU64, Ordering};
static CALLBACKS: AtomicU64 = AtomicU64::new(0);
unsafe extern "C" fn forbidden_callback(_: *mut HookContext) {
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Boundary {
    original: u64,
    generated: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcRange {
    start: u64,
    end: u64,
    original: u64,
}
#[repr(C)]
pub struct Description {
    abi: u64,
    source: u64,
    source_bytes: u64,
    allocation: u64,
    allocation_bytes: u64,
    image: u64,
    image_bytes: u64,
    entry: u64,
    heads: u64,
    ranges: u64,
    saved_state_bytes: u64,
    saved_state_mask: u64,
    bytes: *const u8,
    source_identity: [u8; 32],
    body: [Boundary; 80],
    pc: [PcRange; 160],
}
struct Retained {
    _plan: PlannedInstall,
}
/// # Safety
/// All of plan.h's lifetime/exclusion premises and the core whole-function
/// contract apply. Every input/output allocation is valid, aligned and disjoint.
/// `ret` and `leaders` are exact source coordinates, not synthesized permits.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn region_plan_create(
    base: u64,
    code: *const u8,
    bytes: usize,
    leaders: *const u64,
    leader_count: usize,
    ret: u64,
    object: u64,
    generation: u64,
    identity_bytes: *const u8,
    out: *mut Description,
) -> *mut std::ffi::c_void {
    if base == 0
        || !(5..=80).contains(&bytes)
        || !(1..=80).contains(&leader_count)
        || code.is_null()
        || leaders.is_null()
        || identity_bytes.is_null()
        || out.is_null()
        || object == 0
        || generation == 0
    {
        return std::ptr::null_mut();
    }
    let code = unsafe { std::slice::from_raw_parts(code, bytes) };
    let leaders = unsafe { std::slice::from_raw_parts(leaders, leader_count) };
    let Some(end) = base.checked_add(bytes as u64) else {
        return std::ptr::null_mut();
    };
    if ret < base
        || ret >= end
        || leaders.iter().any(|&x| x < base || x >= end)
        || leaders.windows(2).any(|w| w[0] >= w[1])
    {
        return std::ptr::null_mut();
    }
    let Ok(scope) = AddressRange::new(base, bytes) else {
        return std::ptr::null_mut();
    };
    let mut source_identity = [0; 32];
    source_identity.copy_from_slice(unsafe { std::slice::from_raw_parts(identity_bytes, 32) });
    let identity = CodeIdentity {
        source: SourceIdentity(source_identity),
        mapping: object,
        generation,
    };
    let entries = LegalEntrySet {
        identity,
        scope,
        provenance: EntryProvenance::Declared("owned closed region; exact caller CFG".into()),
        completeness: EntryCompleteness::Complete,
        entries: leaders
            .iter()
            .map(|&address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    };
    let Ok(allocation) = AllocationPolicy::near(base) else {
        return std::ptr::null_mut();
    };
    // Managed controls are immutable to the emitted image's caller. Dropping the
    // unique writers leaves them disabled; the retained plan owns both blocks.
    let actions: [ControlledAction; 2] = [base, ret].map(|logical_pc| {
        let (control, writer) = ProbeControl::new_managed(forbidden_callback, false);
        drop(writer);
        ControlledAction {
            logical_pc,
            control,
        }
    });
    let request = WholeFunctionRequest {
        identity,
        code,
        base_address: base,
        entries: &entries,
        allocation: &allocation,
    };
    let Ok(plan) = (unsafe { plan_whole_function_controlled_detailed(&request, &actions) }) else {
        return std::ptr::null_mut();
    };
    let image = plan.image();
    let parts = plan.plan().parts();
    if parts.allocations.len() != 1
        || parts.generated.len() != 1
        || image.bytes().is_empty()
        || image.instruction_boundaries().len() > 80
        || image.program_counter_mappings().len() > 160
        || image.layout().observation_stack_profile != ObservationStackProfile::Legacy128
        || image.controls().len() != 2
        || image.controls().iter().any(|c| c.is_enabled())
        || image.clock().is_some()
        || image.precontext_selector().is_some()
    {
        return std::ptr::null_mut();
    }
    let alloc = parts.allocations[0].range;
    let Some(entry) = image
        .entry_routes()
        .iter()
        .find(|x| x.0 == base)
        .map(|x| x.1)
    else {
        return std::ptr::null_mut();
    };
    let mut desc = Description {
        abi: 1,
        source: base,
        source_bytes: bytes as u64,
        allocation: alloc.start(),
        allocation_bytes: alloc.len() as u64,
        image: image.address(),
        image_bytes: image.bytes().len() as u64,
        entry,
        heads: image.instruction_boundaries().len() as u64,
        ranges: image.program_counter_mappings().len() as u64,
        saved_state_bytes: image.layout().saved_extended_state.len() as u64,
        saved_state_mask: image.layout().saved_extended_state.mask(),
        bytes: image.bytes().as_ptr(),
        source_identity,
        body: [Boundary::default(); 80],
        pc: [PcRange::default(); 160],
    };
    for (out, &(original, generated)) in desc.body.iter_mut().zip(image.instruction_boundaries()) {
        *out = Boundary {
            original,
            generated,
        };
    }
    for (out, p) in desc.pc.iter_mut().zip(image.program_counter_mappings()) {
        *out = PcRange {
            start: p.generated_start(),
            end: p.generated_end(),
            original: p.logical_address(),
        };
    }
    unsafe { out.write(desc) };
    Box::into_raw(Box::new(Retained { _plan: plan })).cast()
}
#[unsafe(no_mangle)]
pub extern "C" fn region_callback_count() -> u64 {
    CALLBACKS.load(Ordering::Relaxed)
}
/// # Safety
/// Only once, after complete revoke/sync/unmap and no outstanding use (plan.h).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn region_plan_destroy(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle.cast::<Retained>()) });
    }
}
