//! Retained native and acquisition evidence. These checks perform no query and
//! cannot construct a stop, completion seal, stack identity or release permit.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_native::{
    InstructionEffect, InstructionEffectRecord,
};
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::{
    PreparedStackNative, StackPhase,
    acquire::{StackCaptureProgress, StackCaptureStage},
};
use crate::linux::remote::dynamic::owner::bootstrap::{self, Request, StateSlot};
use std::mem::size_of;

const MAX: usize = 65536;

fn require(value: bool, message: &'static str) -> Result<(), OracleError> {
    if value {
        Ok(())
    } else {
        Err(OracleError::Invalid(message))
    }
}
fn progress(value: &StackCaptureProgress) -> Result<(), OracleError> {
    require(
        value.started
            && value.complete
            && value.first_failure.is_none()
            && value.stage == StackCaptureStage::Complete,
        "native acquisition did not complete",
    )
}
fn zero() -> Option<Request> {
    Some(Request {
        result: 0,
        errno: None,
    })
}
fn allocation(bytes: &Vec<u8>) -> (usize, usize, usize) {
    (bytes.as_ptr() as usize, bytes.len(), bytes.capacity())
}
fn state(value: &StateSlot) -> Result<(), OracleError> {
    require(
        value.complete
            && value.registers_request == zero()
            && value.xstate_request == zero()
            && value.mask_request == zero()
            && value.requested_pointer == value.state.xstate.as_ptr() as usize
            && value.returned_pointer == value.requested_pointer
            && value.returned_length == value.state.xstate.len()
            && (512..MAX).contains(&value.returned_length)
            && value.state.xstate.capacity() == MAX,
        "native retained full state or request association differs",
    )
}

/// Exact actual effect grammar. XSTATE/mask restoration are optional only
/// where the unchanged producer conditionally emits them; each recorded effect
/// must still have its own successful request and chronological position.
fn effects(rows: &[Option<InstructionEffectRecord>; 32], length: usize) -> Result<(), OracleError> {
    require(
        length <= rows.len() && rows[length..].iter().all(Option::is_none),
        "native effect initialized suffix differs",
    )?;
    let mut cursor = 0;
    for wait in 0..7 {
        let mut expect = |effect: InstructionEffect, original: bool| -> Result<(), OracleError> {
            let row = rows
                .get(cursor)
                .and_then(Option::as_ref)
                .ok_or(OracleError::Invalid("native effect prefix is short"))?;
            require(
                row.effect == effect
                    && row.complete
                    && row.result == if original { None } else { zero() },
                "native effect order or actual request differs",
            )?;
            cursor += 1;
            Ok(())
        };
        if wait == 3 {
            expect(InstructionEffect::OriginalRelease, true)?;
            continue;
        }
        expect(InstructionEffect::SetRegisters { wait }, false)?;
        expect(InstructionEffect::PrivateRelease { wait }, false)?;
        // End this closure loan before observing the actual next row.
        let next = rows
            .get(cursor)
            .and_then(Option::as_ref)
            .map(|row| row.effect);
        if next == Some(InstructionEffect::RestoreXstate { wait }) {
            let row = rows[cursor].as_ref().expect("observed actual effect");
            require(
                row.complete && row.result == zero(),
                "native XSTATE restoration failed",
            )?;
            cursor += 1;
        }
        let row = rows
            .get(cursor)
            .and_then(Option::as_ref)
            .ok_or(OracleError::Invalid("native register restoration absent"))?;
        require(
            row.effect == InstructionEffect::RestoreRegisters { wait }
                && row.complete
                && row.result == zero(),
            "native register restoration failed",
        )?;
        cursor += 1;
        if rows
            .get(cursor)
            .and_then(Option::as_ref)
            .map(|row| row.effect)
            == Some(InstructionEffect::RestoreMask { wait })
        {
            let row = rows[cursor].as_ref().expect("observed actual effect");
            require(
                row.complete && row.result == zero(),
                "native mask restoration failed",
            )?;
            cursor += 1;
        }
    }
    require(
        cursor == length,
        "native effect chain has extra or missing rows",
    )
}

pub(super) fn require_complete(experiment: &Experiment) -> Result<(), OracleError> {
    let owner = experiment.admitted_owner.owner_ref()?;
    let runtime = owner
        .runtime
        .as_ref()
        .ok_or(OracleError::Invalid("native runtime absent"))?;
    let stack = runtime
        .stack
        .as_ref()
        .ok_or(OracleError::Invalid("native stack owner absent"))?;
    let plan = experiment
        .plan
        .as_ref()
        .ok_or(OracleError::Invalid("native plan absent"))?;
    require(
        stack.startup_complete
            && stack.count == 2
            && stack.pending.is_none()
            && stack.failure.is_none()
            && stack.settlement_failure.is_none(),
        "native retained stack attempts incomplete",
    )?;
    let profile = stack.profile.consumer_view();
    progress(profile.progress)?;
    require(
        profile.provenance
            && profile.eof == &[0; 2]
            && profile.diagnostic.first_failure().is_none(),
        "native startup acquisition failed",
    )?;
    let initial = stack.profile.identity()?;
    let description = initial.description();
    let (original, original_read) = runtime.sources.original_maps();
    require(
        original_read.complete && original_read.failure.is_none(),
        "native original map source incomplete",
    )?;
    let original = original
        .get(..original_read.copied_bytes)
        .ok_or(OracleError::Invalid("native original map prefix invalid"))?;
    initial.require_original(original)?;
    let association = profile
        .association
        .as_ref()
        .ok_or(OracleError::Invalid("native startup association absent"))?;
    require(
        association.stop == initial.stop()
            && association.stop == &description.restored
            && association.original_pointer == original.as_ptr() as usize
            && association.original_length == original.len()
            && association.until == initial.until()
            && Some(association.until) == experiment.admitted_until
            && description.initial_rsp
                == experiment.admitted.lane.metadata.state.state.registers.rsp,
        "native original startup association differs",
    )?;
    state(&profile.diagnostic.observation.state)?;
    require(
        profile.diagnostic.observation.state.state == experiment.admitted.lane.metadata.state.state,
        "native initial full state differs from independent admitted observation",
    )?;
    for (index, ordinal) in [plan.call, plan.ret].into_iter().enumerate() {
        let attempt = stack
            .attempts
            .get(index)
            .and_then(Option::as_deref)
            .ok_or(OracleError::Invalid("native actual stack attempt absent"))?;
        let native = attempt.native.consumer_view();
        let identity = native
            .identity
            .ok_or(OracleError::Invalid("native genuine identity absent"))?;
        let operand = attempt.operand.consumer_view();
        let operand_description = operand
            .diagnostic
            .description()
            .ok_or(OracleError::Invalid("native operand description absent"))?;
        let before = experiment.admitted.lane.frame(ordinal, false)?;
        let after = experiment.admitted.lane.frame(ordinal, true)?;
        let pages = attempt.geometry.pages();
        require(
            native.shape == Some((pages.start(), pages.end()))
                && native.until == Some(attempt.until)
                && before.until == native.until
                && after.until == native.until
                && identity.until() == attempt.until
                && native.initial == Some(&attempt.stop)
                && identity.stop() == &attempt.stop
                && native.source == Some(identity.source_id())
                && native.origin == Some(identity.origin())
                && identity.origin() == attempt.origin
                && native.execution == Some(identity.execution())
                && native.encoding.get(..native.encoding_len)
                    == Some(plan.instruction(ordinal)?.bytes())
                && native.claimed
                && native.progress.phase == StackPhase::Closed
                && native.progress.instruction_completed
                && native.progress.nx_closed
                && native.progress.first_failure.is_none()
                && !native.progress.failed_held_attempted
                && native.progress.failed_held_failure.is_none()
                && attempt.native.allocated_bytes()? == PreparedStackNative::reservation_bytes()?
                && native.native_payload_bytes == 15 * MAX
                && native.membership.len() == MAX
                && native.membership.capacity() == MAX,
            "native stack association or installed capacity differs",
        )?;
        require(
            native.states[0].state == before.state.state
                && native.states[4].state == after.state.state
                && native.states[8].state == after.state.state,
            "native canonical states differ from independent observations",
        )?;
        for slot in native.states {
            state(slot)?;
        }
        let own_profile = before.profile.as_ref().ok_or(OracleError::Invalid(
            "native independent control observation absent",
        ))?;
        native.profile.require(own_profile.debug.values[4])?;
        require(
            native.profile.debug.values == own_profile.debug.values
                && native.profile.rseq == own_profile.rseq,
            "native original control profile differs",
        )?;
        effects(native.effects, native.effects_len)?;
        for wait in 0..7 {
            let raw = native.progress.waits[wait]
                .ok_or(OracleError::Invalid("native raw stack wait absent"))?;
            let stop = native.stops[wait]
                .as_ref()
                .ok_or(OracleError::Invalid("native stack checkpoint absent"))?;
            require(
                raw.0 == owner.pid
                    && libc::WIFSTOPPED(raw.1)
                    && libc::WSTOPSIG(raw.1) == libc::SIGTRAP
                    && raw.1 >> 16 == 0
                    && native.progress.queries_started[wait]
                    && native.signals[wait].request == zero()
                    && stop.token.tid == raw.0
                    && stop.token.session == owner.anchor_session()
                    && native.debug[wait]
                        .requests
                        .iter()
                        .zip(native.debug[wait].values)
                        .all(|(request, value)| {
                            request.is_some_and(|r| r.errno.is_none() && r.result as u64 == value)
                        }),
                "native actual wait/query association differs",
            )?;
            if wait == 3 {
                let trace = native
                    .trace
                    .ok_or(OracleError::Invalid("native original trace absent"))?;
                require(
                    trace.ordinal == wait
                        && trace.tid == raw.0
                        && trace.status == raw.1
                        && trace.signal == native.signals[wait].bytes
                        && trace.dr6 == native.debug[wait].values[4],
                    "native original trace projection differs",
                )?;
                native.debug[wait].require(0xffff_4ff0)?;
            } else {
                native.signals[wait].validate()?;
            }
        }
        let baseline = native.maps[0]
            .ok_or(OracleError::Invalid("native baseline map absent"))?
            .bytes();
        require(
            baseline == before.maps.prefix() && baseline == after.maps.prefix(),
            "native closed maps differ from independent observations",
        )?;
        for index in [1, 2] {
            let maps = native.maps[index].ok_or(OracleError::Invalid("native open map absent"))?;
            attempt
                .geometry
                .verify_open(baseline, maps.bytes())
                .map_err(|_| OracleError::Invalid("native full admitted fetch geometry differs"))?;
        }
        for index in [3, 4] {
            require(
                native.maps[index]
                    .ok_or(OracleError::Invalid("native final map absent"))?
                    .bytes()
                    == baseline,
                "native final full NX maps differ",
            )?;
        }
        // The final ready() retains the actual entire immutable island read.
        let island = bootstrap::island_code_fixed();
        require(
            native.memory.complete
                && native.memory.address == description.island.start
                && native.memory.requested == island.len()
                && native.memory.copied == island.len()
                && native.memory.bytes[..island.len()] == island
                && native.memory.last_request.is_some_and(|r| {
                    r.errno.is_none() && (r.result as u64).to_ne_bytes() == native.memory.last_word
                }),
            "native final island memory verification differs",
        )?;
        progress(operand.progress)?;
        require(
            operand.eof == &[0; 2]
                && operand.association == attempt.operand.view().association
                && operand_description == identity.operand_description()
                && operand.diagnostic.word == *attempt.operand.view().word
                && operand.diagnostic.first_failure().is_none(),
            "native actual operand capture differs",
        )?;
        operand
            .pagemap_access
            .validate_for(&operand.diagnostic.word.pagemap)
            .map_err(|_| OracleError::Invalid("native operand pagemap access differs"))?;
        let provenance = operand
            .provenance
            .as_ref()
            .ok_or(OracleError::Invalid("native operand provenance absent"))?;
        let source = &profile.diagnostic.observation;
        require(
            provenance.origin == identity.origin()
                && provenance.execution == identity.execution()
                && provenance.profile.payloads
                    == [
                        allocation(&source.smaps),
                        allocation(&source.maps),
                        allocation(&source.state.state.xstate),
                    ]
                && provenance.profile.original == (original.as_ptr() as usize, original.len())
                && provenance.profile.stop == initial.stop()
                && provenance.profile.until == initial.until()
                && *provenance.profile.stack == description.stack
                && *provenance.profile.metadata == description.metadata
                && *provenance.profile.layout == description.layout
                && *provenance.profile.raw_layout == profile.diagnostic.layout_evidence
                && provenance.profile.initial_rsp == description.initial_rsp
                && provenance.profile.island == &description.island,
            "native immutable startup/operand provenance differs",
        )?;
        for word in &native.words {
            progress(word.progress)?;
            require(
                word.eof == &[0; 2]
                    && word.capture.complete
                    && word.capture.first_failure.is_none(),
                "native word capture did not complete",
            )?;
            word.capture
                .pagemap_access
                .validate_for(&word.capture.word.pagemap)
                .map_err(|_| OracleError::Invalid("native word pagemap access differs"))?;
        }
    }
    Ok(())
}

pub(super) fn temporary_bytes() -> Result<usize, OracleError> {
    // New observer locals only; retained native payloads stay production-owned.
    // Projection constructors separately account their own complete view values.
    [
        crate::linux::remote::dynamic::owner::admission::runtime_stack_native::consumer_oracle::temporary_bytes()?,
        2 * size_of::<crate::linux::remote::dynamic::owner::admission::runtime_stack_native::consumer_oracle::StackNativeConsumerView<'static>>(),
        size_of::<[u8; 68]>(), 2 * size_of::<InstructionEffectRecord>(),
        4 * size_of::<InstructionEffect>(), 2 * size_of::<Option<Request>>(),
        6 * size_of::<(usize, usize, usize)>(), 2 * size_of::<(usize, usize)>(),
        3 * size_of::<&[u8]>(), 32 * size_of::<&Owner>(),
        24 * size_of::<usize>(), 12 * size_of::<bool>(),
        4 * size_of::<Result<(), OracleError>>(),
        4 * size_of::<std::ops::Range<usize>>(),
        size_of::<[usize; 15]>() + size_of::<std::array::IntoIter<usize, 15>>(),
        map_parser_temporary_bytes()?,
        size_of::<[usize; 17]>() + size_of::<std::array::IntoIter<usize, 17>>(),
    ].into_iter().try_fold(0_usize, |total, value| total.checked_add(value)
        .ok_or(OracleError::Invalid("native observer temporary charge overflows")))
}

/// Concrete borrowed parser/control families reached by require_original and
/// verify_open. Both call chains are summed conservatively, independently of
/// the lanes' own parser charges. This is source-managed storage, not an
/// observed compiler frame size. The unchanged map parser has scalar columns
/// and borrowed fields; initial_coalescence::rows::Columns is not on this path.
fn map_parser_temporary_bytes() -> Result<usize, OracleError> {
    use crate::linux::remote::dynamic::owner::admission::mapping::maps::{
        MapEntries, MapEntry, MapParseError, MapPermissions, ParsedMaps,
    };
    use crate::linux::remote::dynamic::owner::admission::runtime_stack::StackError;
    [
        4 * size_of::<ParsedMaps<'static>>(),
        6 * size_of::<MapEntries<'static>>(),
        4 * size_of::<std::iter::Enumerate<MapEntries<'static>>>(),
        10 * size_of::<MapEntry<'static>>(),
        4 * size_of::<Option<MapEntry<'static>>>(),
        4 * size_of::<Result<ParsedMaps<'static>, MapParseError>>(),
        4 * size_of::<Result<MapEntry<'static>, MapParseError>>(),
        4 * size_of::<Result<ParsedMaps<'static>, GateError>>(),
        4 * size_of::<Result<ParsedMaps<'static>, StackError>>(),
        4 * size_of::<Result<usize, StackError>>(),
        4 * size_of::<Result<usize, GateError>>(),
        4 * size_of::<Result<(), GateError>>(),
        4 * size_of::<Result<(), MapParseError>>(),
        4 * size_of::<Result<&'static [u8], MapParseError>>(),
        4 * size_of::<Result<(&'static [u8], &'static [u8]), MapParseError>>(),
        4 * size_of::<Result<u64, MapParseError>>(),
        4 * size_of::<Result<u32, MapParseError>>(),
        4 * size_of::<Option<u64>>(),
        8 * size_of::<Option<usize>>(),
        4 * size_of::<MapPermissions>(),
        4 * size_of::<[u8; 4]>(),
        3 * size_of::<std::slice::Split<'static, u8, fn(&u8) -> bool>>(),
        4 * size_of::<std::slice::Iter<'static, u8>>(),
        4 * size_of::<std::ops::Range<u64>>(),
        4 * size_of::<std::ops::Range<usize>>(),
        24 * size_of::<&'static [u8]>(),
        32 * size_of::<u64>(),
        24 * size_of::<usize>(),
        16 * size_of::<bool>(),
        size_of::<[usize; 30]>() + size_of::<std::array::IntoIter<usize, 30>>(),
    ]
    .into_iter()
    .try_fold(0_usize, |total, value| {
        total.checked_add(value).ok_or(OracleError::Invalid(
            "native observer map parser temporary charge overflows",
        ))
    })
}
