//! Test-only complete CALL-row/ledger snapshots; no record or seal constructor.
use super::super::runtime_stack::binding::{ProfileRecord, SourceRecord};
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct CallLedgerRowSnapshot {
    address: usize,
    binding: Option<Binding>,
    before: Option<ObservedStop>,
    before_allocation: Option<(usize, usize, usize)>,
    buffer: Vec<u8>,
    buffer_allocation: (usize, usize, usize),
    allocation: PayloadProgress,
    settled_bytes: usize,
    id: Option<PotentialCallId>,
    header_bytes: usize,
    allocated_bytes: usize,
    fault: (Option<usize>, Option<usize>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct CallLedgerSnapshot {
    slots_address: Option<usize>,
    slots_length: Option<usize>,
    rows: Option<Vec<Option<CallLedgerRowSnapshot>>>,
    allocation: PayloadProgress,
    count: usize,
    identity: Option<(u64, u64)>,
    header_bytes: usize,
    allocated_bytes: usize,
}
impl PreparedCallRecord {
    /// Configures the existing single-payload callbacks while Empty.
    /// After-install panic payload is exactly 0x5343414c_u32 (SCAL).
    pub(in crate::linux::remote::dynamic::owner::admission) fn set_allocation_fault(
        &mut self,
        fail_before: Option<usize>,
        panic_after: Option<usize>,
    ) {
        assert!(!self.allocation.started && self.allocation.failure.is_none());
        assert!(self.binding.is_none() && self.before.is_none() && self.id.is_none());
        assert!(self.buffer.is_empty() && self.buffer.capacity() == 0);
        assert_eq!(self.settled_bytes, 0);
        assert!(fail_before.is_none_or(|index| index < 1));
        assert!(panic_after.is_none_or(|index| index < 1));
        self.allocation_fail_before = fail_before;
        self.allocation_panic_after = panic_after;
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_snapshot(
        &self,
    ) -> CallLedgerRowSnapshot {
        CallLedgerRowSnapshot {
            address: std::ptr::from_ref(self) as usize,
            binding: self.binding.clone(),
            before: self.before.clone(),
            before_allocation: self.before.as_ref().map(|v| {
                (
                    v.xstate.as_ptr() as usize,
                    v.xstate.len(),
                    v.xstate.capacity(),
                )
            }),
            buffer: self.buffer.clone(),
            buffer_allocation: (
                self.buffer.as_ptr() as usize,
                self.buffer.len(),
                self.buffer.capacity(),
            ),
            allocation: self.allocation,
            settled_bytes: self.settled_bytes,
            id: self.id,
            header_bytes: size_of::<Self>(),
            allocated_bytes: self.allocated_bytes().unwrap(),
            fault: (self.allocation_fail_before, self.allocation_panic_after),
        }
    }
}
impl RecordedCall<'_> {
    /// Called with the actual binding in the pre-opening native oracle hook.
    /// Every stored value is compared before the immutable diagnostic copy.
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_stack_call(
        &self,
        actual: &RuntimeStackBinding<'_, '_>,
    ) -> CallLedgerRowSnapshot {
        let row = self.row;
        let binding = row.binding.as_ref().unwrap();
        let before = row.before.as_ref().unwrap();
        let id = row.id.unwrap();
        assert_eq!(self.id(), id);
        assert_eq!(id.census, binding.census);
        assert_eq!(id.session, before.token.session);
        assert_eq!(id.session, actual.execution().session);
        assert_ne!(id.ledger, 0);
        assert_ne!(id.serial, 0);
        assert_eq!(binding.origin, actual.origin());
        assert_eq!(binding.execution, actual.execution());
        assert_eq!(binding.source.id, actual.source_id());
        assert_eq!(&binding.operand, actual.operand_description());
        assert_eq!(
            binding.profile,
            ProfileRecord::from(actual.profile_description())
        );
        assert_eq!(binding.until, actual.until());
        assert_eq!(&binding.fetch, actual.geometry());
        assert_eq!(before, actual.before());
        assert_eq!(before.token, actual.stop().token);
        assert_eq!(before.task, actual.stop().identity);
        assert_eq!(before.logical_pc, before.registers.rip);
        assert_eq!(before.phase, StopPhase::UserCheckpoint);
        assert!(before.signal.is_none() && actual.stop().signal.is_none());
        assert_eq!(before.task.generation, 0);
        assert_eq!(before.token.task, Some(before.task.task));
        assert_eq!(before.xstate.capacity(), MAX_XSTATE_BYTES);
        assert!((576..MAX_XSTATE_BYTES).contains(&before.xstate.len()));
        assert!(row.buffer.is_empty());
        assert_eq!(row.buffer.capacity(), 0);
        assert!(
            row.allocation.started && row.allocation.complete && row.allocation.failure.is_none()
        );
        assert_eq!(row.allocation.payload, MAX_XSTATE_BYTES);
        assert_eq!(
            row.settled_bytes,
            size_of::<PreparedCallRecord>() + MAX_XSTATE_BYTES
        );
        assert_eq!(row.allocated_bytes().unwrap(), row.settled_bytes);
        assert_eq!(row.allocation_fail_before, None);
        assert_eq!(row.allocation_panic_after, None);
        let window = actual.window();
        assert_eq!(binding.source, SourceRecord::capture(window));
        assert_eq!(binding.source.initial, window.initial_source());
        assert_eq!(binding.source.range, window.snapshot.range());
        assert_eq!(binding.source.target, window.target);
        assert!(std::ptr::eq(actual.candidate().snapshot(), window.snapshot));
        assert_eq!(actual.candidate().registers(), &actual.before().registers);
        let geometry = &binding.operand.geometry;
        assert_eq!(geometry.operation, StackOperation::DirectCall);
        assert_eq!(geometry.length, 5);
        assert_eq!(geometry.encoding[0], 0xe8);
        assert_eq!(&geometry.encoding[..5], actual.candidate().bytes());
        assert_eq!(geometry.pc, before.logical_pc);
        assert_eq!(geometry.next_pc, geometry.pc.checked_add(5).unwrap());
        assert_eq!(geometry.next_pc, actual.candidate().next_pc());
        assert_eq!(geometry.original_rsp, before.registers.rsp);
        assert_eq!(
            geometry.slot.start,
            before.registers.rsp.checked_sub(8).unwrap()
        );
        assert_eq!(geometry.slot.end, before.registers.rsp);
        assert_eq!(geometry.stack, binding.profile.stack.range());
        assert_eq!(geometry.island, actual.island().range);
        let displacement = i32::from_le_bytes(geometry.encoding[1..5].try_into().unwrap());
        let target = geometry
            .next_pc
            .checked_add_signed(i64::from(displacement))
            .unwrap();
        assert_eq!(geometry.call_target, Some(target));
        assert_eq!(binding.operand.target, target);
        assert_eq!(binding.operand.stop, *actual.stop());
        assert_eq!(binding.operand.until, actual.until());
        assert!(!geometry.island.contains(&target));
        assert!(!geometry.island.contains(&geometry.next_pc));
        let offset = usize::try_from(geometry.pc - window.snapshot.range().start()).unwrap();
        assert_eq!(
            &window.snapshot.bytes()[offset..offset + 5],
            actual.candidate().bytes()
        );
        assert_eq!(binding.fetch.instruction(), actual.candidate().range());
        assert_eq!(binding.fetch.pages().start(), geometry.pc & !4095);
        assert_eq!(
            binding.fetch.pages().end(),
            ((geometry.next_pc - 1) & !4095) + 4096
        );
        // In particular, when next_pc is page-aligned this exclusive return
        // page is not included in the CALL instruction's opened fetch range.
        if geometry.next_pc % 4096 == 0 {
            assert_eq!(binding.fetch.pages().end(), geometry.next_pc);
            assert!(!binding.fetch.pages().contains(geometry.next_pc));
        }
        let a = actual.operand().view();
        assert!(a.complete && a.first_failure.is_none());
        assert_eq!(&a.observation.state.state, actual.operand().before());
        assert_eq!(a.observation.state.state.registers, before.registers);
        assert_eq!(a.observation.state.state.xstate, before.xstate);
        assert_eq!(a.observation.state.state.mask, before.signal_mask);
        let word_offset = usize::try_from(geometry.slot.start - geometry.envelope.start).unwrap();
        assert_eq!(
            binding.operand.value,
            u64::from_le_bytes(
                a.word.bytes[word_offset..word_offset + 8]
                    .try_into()
                    .unwrap()
            )
        );
        row.test_snapshot()
    }
}
impl RuntimeCallLedger {
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_row(
        &self,
        id: PotentialCallId,
    ) -> CallLedgerRowSnapshot {
        let slots = self.slots.as_deref().unwrap();
        let index = id.serial.checked_sub(1).unwrap();
        assert!(index < self.count);
        assert_eq!(id.ledger, slots.as_ptr() as usize);
        assert_eq!(Some((id.census, id.session)), self.identity);
        let record = slots[index].as_deref().unwrap();
        assert_eq!(record.id, Some(id));
        record.test_snapshot()
    }
    /// Complete installed rows, including unused slots and allocation markers.
    /// No deadline or live native proof is needed to retain historical custody.
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_snapshot(
        &self,
    ) -> CallLedgerSnapshot {
        if let Some(slots) = &self.slots {
            assert_eq!(
                self.allocation.payload,
                slots.len() * size_of::<Option<Box<PreparedCallRecord>>>()
            );
            assert!(self.count <= slots.len());
            assert!(slots[..self.count].iter().all(Option::is_some));
            assert!(slots[self.count..].iter().all(Option::is_none));
            for (index, row) in slots[..self.count].iter().enumerate() {
                let row = row.as_deref().unwrap();
                let id = row.id.unwrap();
                assert_eq!(id.ledger, slots.as_ptr() as usize);
                assert_eq!(id.serial, index + 1);
                assert_eq!(Some((id.census, id.session)), self.identity);
            }
        }
        CallLedgerSnapshot {
            slots_address: self.slots.as_ref().map(|v| v.as_ptr() as usize),
            slots_length: self.slots.as_ref().map(|v| v.len()),
            rows: self.slots.as_ref().map(|v| {
                v.iter()
                    .map(|r| r.as_deref().map(PreparedCallRecord::test_snapshot))
                    .collect()
            }),
            allocation: self.allocation,
            count: self.count,
            identity: self.identity,
            header_bytes: size_of::<Self>(),
            allocated_bytes: self.allocated_bytes().unwrap(),
        }
    }
}

impl RuntimeCallLedger {
    /// Sensitivity of the same typed Eq comparator used after later operations
    /// and cleanup. Mutations are isolated copies of an actual appended row.
    /// No copied description is passed to a producer, validator or constructor
    /// of native authority, and the live ledger is checked unchanged each time.
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_row_sensitivity(
        &self,
        id: PotentialCallId,
    ) {
        let original = self.test_row(id);
        let ledger = self.test_snapshot();
        assert!(original.binding.is_some() && original.before.is_some());
        assert_eq!(original.id, Some(id));
        assert_eq!(
            original
                .binding
                .as_ref()
                .unwrap()
                .operand
                .geometry
                .operation,
            StackOperation::DirectCall
        );
        macro_rules! reject_copy {
            ($label:literal, $row:ident => $body:block) => {{
                let mut $row = original.clone();
                $body
                assert_ne!($row, original, $label);
                assert_eq!(self.test_row(id), original);
                assert_eq!(self.test_snapshot(), ledger);
            }};
        }
        reject_copy!("call id census", row => { row.id.as_mut().unwrap().census ^= 1; });
        reject_copy!("call id session", row => { row.id.as_mut().unwrap().session ^= 1; });
        reject_copy!("call id ledger address", row => { row.id.as_mut().unwrap().ledger ^= 1; });
        reject_copy!("call id serial", row => { row.id.as_mut().unwrap().serial ^= 1; });
        reject_copy!("binding census", row => { row.binding.as_mut().unwrap().census ^= 1; });
        reject_copy!("binding candidate serial", row => { row.binding.as_mut().unwrap().candidate_serial ^= 1; });
        reject_copy!("reservation census", row => { row.binding.as_mut().unwrap().reservation.census ^= 1; });
        reject_copy!("reservation serial", row => { row.binding.as_mut().unwrap().reservation.serial ^= 1; });
        reject_copy!("origin census", row => { row.binding.as_mut().unwrap().origin.census ^= 1; });
        reject_copy!("origin serial", row => { row.binding.as_mut().unwrap().origin.serial ^= 1; });
        reject_copy!("execution session", row => { row.binding.as_mut().unwrap().execution.session ^= 1; });
        reject_copy!("execution serial", row => { row.binding.as_mut().unwrap().execution.serial ^= 1; });
        reject_copy!("source content identity", row => {
            let source = &mut row.binding.as_mut().unwrap().source;
            let mut identity = source.id.identity(); identity.source.0[0] ^= 1;
            source.id = super::super::super::runtime_capture::SourceWindowId::synthetic_for_test(identity, source.id.index());
        });
        reject_copy!("source mapping identity", row => {
            let source = &mut row.binding.as_mut().unwrap().source;
            let mut identity = source.id.identity(); identity.mapping ^= 1;
            source.id = super::super::super::runtime_capture::SourceWindowId::synthetic_for_test(identity, source.id.index());
        });
        reject_copy!("source generation identity", row => {
            let source = &mut row.binding.as_mut().unwrap().source;
            let mut identity = source.id.identity(); identity.generation ^= 1;
            source.id = super::super::super::runtime_capture::SourceWindowId::synthetic_for_test(identity, source.id.index());
        });
        reject_copy!("source window index", row => {
            let source = &mut row.binding.as_mut().unwrap().source;
            source.id = super::super::super::runtime_capture::SourceWindowId::synthetic_for_test(source.id.identity(), source.id.index() ^ 1);
        });
        reject_copy!("source range", row => {
            let source = &mut row.binding.as_mut().unwrap().source;
            source.range = AddressRange::new(source.range.start(), source.range.end().checked_add(1).unwrap()).unwrap();
        });
        reject_copy!("source target range", row => {
            let source = &mut row.binding.as_mut().unwrap().source;
            source.target = AddressRange::new(source.target.start(), source.target.end().checked_add(1).unwrap()).unwrap();
        });
        reject_copy!("original pc", row => { row.binding.as_mut().unwrap().operand.geometry.pc ^= 1; });
        reject_copy!("exclusive next pc", row => { row.binding.as_mut().unwrap().operand.geometry.next_pc ^= 1; });
        reject_copy!("relative CALL target", row => { *row.binding.as_mut().unwrap().operand.geometry.call_target.as_mut().unwrap() ^= 1; });
        reject_copy!("bound target", row => { row.binding.as_mut().unwrap().operand.target ^= 1; });
        reject_copy!("original stack pointer", row => { row.binding.as_mut().unwrap().operand.geometry.original_rsp ^= 1; });
        reject_copy!("frozen slot start", row => { row.binding.as_mut().unwrap().operand.geometry.slot.start ^= 1; });
        reject_copy!("frozen slot end", row => { row.binding.as_mut().unwrap().operand.geometry.slot.end ^= 1; });
        reject_copy!("frozen word", row => { row.binding.as_mut().unwrap().operand.value ^= 1; });
        reject_copy!("read envelope start", row => { row.binding.as_mut().unwrap().operand.geometry.envelope.start ^= 1; });
        reject_copy!("read envelope end", row => { row.binding.as_mut().unwrap().operand.geometry.envelope.end ^= 1; });
        reject_copy!("encoding length", row => { row.binding.as_mut().unwrap().operand.geometry.length ^= 1; });
        for index in 0..5 {
            reject_copy!("each original CALL byte", row => {
                row.binding.as_mut().unwrap().operand.geometry.encoding[index] ^= 1;
            });
        }
        reject_copy!("before session", row => { row.before.as_mut().unwrap().token.session ^= 1; });
        reject_copy!("before sequence", row => { row.before.as_mut().unwrap().token.sequence ^= 1; });
        reject_copy!("before tid", row => { row.before.as_mut().unwrap().token.tid ^= 1; });
        reject_copy!("before task association", row => { row.before.as_mut().unwrap().token.task = None; });
        reject_copy!("before task generation", row => { row.before.as_mut().unwrap().task.generation ^= 1; });
        reject_copy!("before original pc", row => { row.before.as_mut().unwrap().registers.rip ^= 1; });
        reject_copy!("before stack pointer", row => { row.before.as_mut().unwrap().registers.rsp ^= 1; });
        reject_copy!("before signal mask", row => { row.before.as_mut().unwrap().signal_mask ^= 1; });
        reject_copy!("before complete xstate", row => { row.before.as_mut().unwrap().xstate[0] ^= 1; });
        reject_copy!("retained source capacity", row => { row.before_allocation.as_mut().unwrap().2 ^= 1; });
        reject_copy!("settled bytes", row => { row.settled_bytes ^= 1; });
        reject_copy!("allocated bytes", row => { row.allocated_bytes ^= 1; });
    }
}
