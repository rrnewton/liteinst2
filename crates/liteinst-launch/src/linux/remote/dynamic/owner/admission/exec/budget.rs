//! Pre-effect bounds for one replacement, separate from later demand plans.
//! Source/head sizes are maxima from the public profile, never fixture counts.
use super::*;
use crate::gate::domain::Image;

#[cfg(test)]
mod tests;

const MAP_BYTES: usize = 64 * 1024;
const MAP_ROWS: usize = 512;
const EXECUTABLE_ROWS: usize = 64;
const ORIGINAL_PAGES: usize = 16 * 1024;

pub(super) fn add(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_add(b)
        .ok_or_else(|| refused("exec evidence size overflows"))
}
fn mul(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_mul(b)
        .ok_or_else(|| refused("exec evidence size overflows"))
}
fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize, GateError> {
    values.into_iter().try_fold(0, add)
}

pub(super) fn combine(a: BudgetCharge, b: BudgetCharge) -> Result<BudgetCharge, GateError> {
    Ok(BudgetCharge {
        epochs: add(a.epochs, b.epochs)?,
        source_fact_bytes: add(a.source_fact_bytes, b.source_fact_bytes)?,
        reports: add(a.reports, b.reports)?,
        origins: add(a.origins, b.origins)?,
        witnesses: add(a.witnesses, b.witnesses)?,
        plan_history: add(a.plan_history, b.plan_history)?,
    })
}

pub(super) fn bytes(bytes: usize) -> BudgetCharge {
    BudgetCharge {
        source_fact_bytes: bytes,
        ..BudgetCharge::default()
    }
}

/// The existing maps reader's vector growth is bounded independently of its
/// string payload. Raw tables must fit 512 rows/64 KiB before new bootstrap.
fn mapping_bound(rows: usize) -> Result<usize, GateError> {
    sum([
        mul(2 * rows, size_of::<MemoryMapping>())?,
        MAP_BYTES,
        4 * rows,
    ])
}

pub(super) fn mapping_bytes(maps: &Vec<MemoryMapping>) -> Result<usize, GateError> {
    maps.iter().try_fold(
        mul(maps.capacity(), size_of::<MemoryMapping>())?,
        |total, map| {
            sum([
                total,
                map.permissions.capacity(),
                map.pathname.as_ref().map_or(0, String::capacity),
            ])
        },
    )
}

/// Immutable source bytes and every possible byte as a complete head. The
/// entry charge follows the existing initial-domain logical evidence formula;
/// it is not an RSS or allocator-private-overhead measurement.
fn domain_bound(profile: &DynamicExecProfile) -> Result<usize, GateError> {
    sum([
        size_of::<Domain>(),
        mul(profile.max_total_capture_bytes, 2 + 512)?,
        mul(profile.max_capture_images, 2 * size_of::<Image>() + 1024)?,
        mul(ORIGINAL_PAGES, 64)?,
        mul(2, mapping_bound(EXECUTABLE_ROWS)?)?,
        4096,
    ])
}

pub(super) fn future(profile: &DynamicExecProfile) -> Result<BudgetCharge, GateError> {
    // Native proof keeps one ENTRY and four bootstrap XSTATE buffers. The
    // extra maximum covers the owned new checkpoint; the sealed copies have
    // already been allocated and separately debited before original release.
    let native = sum([
        mul(6, MAX_XSTATE)?,
        mapping_bound(MAP_ROWS)?,
        mapping_bound(EXECUTABLE_ROWS)?,
        MAP_BYTES,
        size_of::<ExecBootstrapReady>(),
        size_of::<ObservedStop>(),
    ])?;
    let response = sum([
        size_of::<DynamicImageReplacement>(),
        2 * MAX_XSTATE,
        15,
        size_of::<DynamicSourceRequest>(),
        ExecSourceBinding::allocated_bytes()?,
        size_of::<DynamicSourceFacts>(),
        mul(profile.max_capture_images, size_of::<DynamicSourceHeads>())?,
        mul(profile.max_total_capture_bytes, 64)?,
    ])?;
    // Source scratch is preallocated/debited independently. Reserving the full
    // capture envelope here also retains conversion peaks and any abandoned
    // staging capacity without a refund. These unused bytes are charged, not
    // falsely reported as an actual retained source allocation.
    let storage = sum([
        native,
        response,
        domain_bound(profile)?,
        PreparedExecSources::reservation_bytes(profile)?,
    ])?;
    combine(
        census::exec_initial_charge(MAX_XSTATE).map_err(census_error)?,
        bytes(storage),
    )
}

pub(super) fn initial_attempt_bytes(
    inputs: &ExecInputs,
    seal: &PreparedExecSeal,
    scratch: &PreparedExecSources,
    forbidden: &Vec<Range<u64>>,
    maps: &Vec<MemoryMapping>,
    journal_increment: usize,
) -> Result<usize, GateError> {
    // Each embedded header is included by ExecAttempt exactly once. Moved
    // PendingInvocation payloads were already debited by their original owner.
    let payload = |total: usize, header: usize| {
        total
            .checked_sub(header)
            .ok_or_else(|| refused("exec embedded evidence header differs"))
    };
    sum([
        size_of::<ExecAttempt>(),
        payload(inputs.allocated_bytes()?, size_of::<ExecInputs>())?,
        payload(seal.retained_bytes()?, size_of::<PreparedExecSeal>())?,
        payload(scratch.allocated_bytes()?, size_of::<PreparedExecSources>())?,
        mul(forbidden.capacity(), size_of::<Range<u64>>())?,
        mapping_bytes(maps)?,
        journal_increment,
    ])
}

pub(super) fn initial_bound(
    profile: &DynamicExecProfile,
    forbidden_count: usize,
    maps: &Vec<MemoryMapping>,
    journal_increment: usize,
) -> Result<usize, GateError> {
    sum([
        size_of::<ExecAttempt>(),
        ExecInputs::reservation_bytes(profile)?,
        size_of::<PreparedExecSeal>(),
        2 * MAX_XSTATE,
        PreparedExecSources::reservation_bytes(profile)?,
        mul(forbidden_count, size_of::<Range<u64>>())?,
        mapping_bytes(maps)?,
        journal_increment,
    ])
}

pub(super) fn domain_bytes(domain: &Domain) -> Result<usize, GateError> {
    let images = domain.images.iter().try_fold(
        mul(domain.images.capacity(), size_of::<Image>())?,
        |total, image| {
            sum([
                total,
                image.snapshot.bytes().len(),
                mul(image.entries.heads().len(), 256)?,
                image.mapping.permissions.capacity(),
                image.mapping.pathname.as_ref().map_or(0, String::capacity),
            ])
        },
    )?;
    sum([
        size_of::<Domain>(),
        images,
        domain.resource_payload_bytes()?,
        mapping_bytes(&domain.original_executables)?,
        mul(domain.pages.len(), 64)?,
    ])
}

pub(super) fn native_payload(ready: &ExecBootstrapReady) -> Result<usize, GateError> {
    ready
        .retained_bytes()?
        .checked_sub(size_of::<ExecBootstrapReady>())
        .ok_or_else(|| refused("exec native evidence header differs"))
}

pub(super) fn source_payload(captured: &CapturedExecSources) -> Result<usize, GateError> {
    captured.newly_retained_bytes()
}

pub(super) fn reply_payload(facts: &DynamicSourceFacts) -> Result<usize, GateError> {
    facts.images.iter().try_fold(
        mul(facts.images.capacity(), size_of::<DynamicSourceHeads>())?,
        |total, image| add(total, mul(image.heads.len(), 64)?),
    )
}
