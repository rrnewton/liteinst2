//! Pure allocation/model controls plus explicitly requested test-only native
//! intervention plumbing. No pure fixture constructs a completion seal.
use super::super::runtime_instruction::{DebugDisposition, classify};
use super::super::runtime_stack::{access::PkuLayoutEvidence, operand::OperandGeometry};
use super::super::source_identity::{FileIdentity, ImageRole, SourceVma};
use super::*;
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};
use liteinst_admission::{AddressRange, Generation, MappingId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum InterventionPoint {
    AfterA,
    AfterB,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum InterventionKind {
    Ac,
    PkruKeyZeroDeny,
}
#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic::owner::admission) struct InterventionReadback {
    pub(in crate::linux::remote::dynamic::owner::admission) registers: RegisterSnapshot,
    pub(in crate::linux::remote::dynamic::owner::admission) mask: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) requests: [Option<Request>; 3],
    pub(in crate::linux::remote::dynamic::owner::admission) requested_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) returned_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) returned_length: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
}
impl InterventionReadback {
    fn from_slot(slot: &StateSlot) -> Self {
        Self {
            registers: slot.state.registers,
            mask: slot.state.mask,
            requests: [
                slot.registers_request,
                slot.xstate_request,
                slot.mask_request,
            ],
            requested_pointer: slot.requested_pointer,
            returned_pointer: slot.returned_pointer,
            returned_length: slot.returned_length,
            complete: slot.complete,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic::owner::admission) struct Intervention {
    pub(in crate::linux::remote::dynamic::owner::admission) point: InterventionPoint,
    pub(in crate::linux::remote::dynamic::owner::admission) kind: InterventionKind,
    pub(in crate::linux::remote::dynamic::owner::admission) started: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) setter: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) before: Option<InterventionReadback>,
    pub(in crate::linux::remote::dynamic::owner::admission) after: Option<InterventionReadback>,
    pub(in crate::linux::remote::dynamic::owner::admission) pkru_offset: Option<usize>,
    pub(in crate::linux::remote::dynamic::owner::admission) old_pkru: Option<u32>,
    pub(in crate::linux::remote::dynamic::owner::admission) changed_pkru: Option<u32>,
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
}
impl PreparedStackNative {
    /// Configure only the existing test allocation hooks before any payload.
    pub(in crate::linux::remote::dynamic::owner::admission) fn set_allocation_fault(
        &mut self,
        fail_before: Option<usize>,
        panic_after: Option<usize>,
    ) {
        assert_eq!(self.progress.phase, StackPhase::Empty);
        assert!(fail_before.is_none_or(|ordinal| ordinal < 18));
        assert!(panic_after.is_none_or(|ordinal| ordinal < 18));
        self.allocation_fault.before = fail_before;
        self.allocation_fault.after = panic_after;
    }
    /// Configure one retained word owner's existing three-slot allocator.
    pub(in crate::linux::remote::dynamic::owner::admission) fn set_word_allocation_fault(
        &mut self,
        index: usize,
        fail_before: Option<usize>,
        panic_after: Option<usize>,
    ) {
        assert_eq!(self.progress.phase, StackPhase::Empty);
        assert!(index < 3);
        assert!(fail_before.is_none_or(|ordinal| ordinal < 3));
        assert!(panic_after.is_none_or(|ordinal| ordinal < 3));
        self.words[index].set_allocation_fault(fail_before, panic_after);
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn set_intervention(
        &mut self,
        point: InterventionPoint,
        kind: InterventionKind,
    ) -> Result<(), LaunchError> {
        if self.progress.phase != StackPhase::Allocated
            || self.intervention.is_some()
            || self.progress.first_failure.is_some()
        {
            return Err(LaunchError::Invalid("owned stack test intervention reused"));
        }
        self.intervention = Some(Intervention {
            point,
            kind,
            started: false,
            setter: None,
            before: None,
            after: None,
            pkru_offset: None,
            old_pkru: None,
            changed_pkru: None,
            complete: false,
        });
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn intervention(
        &self,
    ) -> Option<&Intervention> {
        self.intervention.as_ref()
    }
}
pub(super) fn pkru_offset(layout: &PkuLayoutEvidence) -> Result<usize, LaunchError> {
    layout.validate().map_err(stack_error)?;
    let offset = layout.records[4]
        .ok_or(LaunchError::Invalid("test PKRU layout absent"))?
        .registers[1];
    usize::try_from(offset).map_err(|_| LaunchError::Invalid("test PKRU offset overflows"))
}
pub(super) fn intervene(
    owner: &Owner,
    native: &NativeLifecycle,
    p: &mut PreparedStackNative,
    stop: &AdmissionStop,
    offset: usize,
    point: InterventionPoint,
) -> Result<(), LaunchError> {
    let Some(config) = p.intervention.as_ref() else {
        return Ok(());
    };
    if config.point != point {
        return Ok(());
    }
    if config.started {
        return Err(LaunchError::Invalid("test stack intervention repeated"));
    }
    let kind = config.kind;
    p.intervention
        .as_mut()
        .expect("configured intervention")
        .started = true;
    let until = p.deadline();
    native.require_admission_stop(stop)?;
    bootstrap::physical(owner, until)?;
    let before_result = p.states[WORK].capture(owner, until);
    p.intervention
        .as_mut()
        .expect("configured intervention")
        .before = Some(InterventionReadback::from_slot(&p.states[WORK]));
    before_result?;
    if p.states[WORK].state != p.states[BEFORE].state {
        return Err(LaunchError::Invalid(
            "test intervention original state differs",
        ));
    }
    let mut changed_registers = p.states[BEFORE].state.registers;
    let result = match kind {
        InterventionKind::Ac => {
            changed_registers.eflags |= 1 << 18;
            let raw = libc::user_regs_struct::from(changed_registers);
            request(
                libc::PTRACE_SETREGS,
                owner.pid,
                0,
                (&raw const raw) as usize,
            )
        }
        InterventionKind::PkruKeyZeroDeny => {
            let end = offset
                .checked_add(4)
                .ok_or(LaunchError::Invalid("test PKRU extent overflows"))?;
            let bytes = p.states[WORK]
                .state
                .xstate
                .get_mut(offset..end)
                .ok_or(LaunchError::Invalid("test PKRU component absent"))?;
            let old = u32::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| LaunchError::Invalid("test PKRU width differs"))?,
            );
            let changed = old | 3;
            bytes.copy_from_slice(&changed.to_le_bytes());
            let record = p.intervention.as_mut().expect("configured intervention");
            record.pkru_offset = Some(offset);
            record.old_pkru = Some(old);
            record.changed_pkru = Some(changed);
            let mut vector = libc::iovec {
                iov_base: p.states[WORK].state.xstate.as_mut_ptr().cast(),
                iov_len: p.states[WORK].state.xstate.len(),
            };
            request(
                libc::PTRACE_SETREGSET,
                owner.pid,
                NT_X86_XSTATE,
                (&raw mut vector) as usize,
            )
        }
    };
    p.intervention
        .as_mut()
        .expect("configured intervention")
        .setter = Some(result);
    // Retain an actual readback even after a failed setter while held custody
    // remains valid. Its complete initialized WORK payload remains native-owned.
    bootstrap::physical(owner, until)?;
    let after_result = p.states[WORK].capture(owner, until);
    p.intervention
        .as_mut()
        .expect("configured intervention")
        .after = Some(InterventionReadback::from_slot(&p.states[WORK]));
    checked(result, "test owned stack intervention")?;
    after_result?;
    if p.states[WORK].state.registers != changed_registers
        || p.states[WORK].state.mask != p.states[BEFORE].state.mask
        || p.states[WORK].state.xstate.len() != p.states[BEFORE].state.xstate.len()
    {
        return Err(LaunchError::Invalid(
            "test owned stack intervention readback differs",
        ));
    }
    for (index, (actual, before)) in p.states[WORK]
        .state
        .xstate
        .iter()
        .zip(&p.states[BEFORE].state.xstate)
        .enumerate()
    {
        let expected =
            if kind == InterventionKind::PkruKeyZeroDeny && (offset..offset + 4).contains(&index) {
                p.intervention
                    .as_ref()
                    .expect("configured intervention")
                    .changed_pkru
                    .expect("actual changed PKRU")
                    .to_le_bytes()[index - offset]
            } else {
                *before
            };
        if *actual != expected {
            return Err(LaunchError::Invalid(
                "test intervention changed unrelated XSTATE",
            ));
        }
    }
    native.require_admission_stop(stop)?;
    bootstrap::physical(owner, until)?;
    p.intervention
        .as_mut()
        .expect("configured intervention")
        .complete = true;
    Ok(())
}

fn geometry(crossing: bool) -> FetchGeometry {
    let source = SourceVma {
        original_index: 0,
        current_index: 0,
        original_span: (0, 0),
        current_span: (0, 0),
        start: 0x400000,
        end: 0x403000,
        offset: 0,
        file: FileIdentity {
            major: 8,
            minor: 1,
            inode: 7,
        },
        role: ImageRole::Executable,
    };
    let pc = if crossing { 0x400ffd } else { 0x400ffb };
    FetchGeometry::for_instruction(source, AddressRange::new(pc, pc + 5).unwrap()).unwrap()
}
fn capacities(p: &PreparedStackNative) -> Vec<(usize, usize)> {
    let mut out: Vec<_> = p
        .states
        .iter()
        .map(|s| (s.state.xstate.as_ptr() as usize, s.state.xstate.capacity()))
        .collect();
    out.push((p.membership.as_ptr() as usize, p.membership.capacity()));
    for map in &p.maps {
        out.push((
            map.retained().map_or(0, |m| m.bytes().as_ptr() as usize),
            map.payload_bytes(),
        ));
    }
    for word in &p.words {
        let view = word.view();
        out.push((
            view.observation.state.state.xstate.as_ptr() as usize,
            view.observation.state.state.xstate.capacity(),
        ));
        out.push((
            view.observation.maps.as_ptr() as usize,
            view.observation.maps.capacity(),
        ));
        out.push((
            view.observation.smaps.as_ptr() as usize,
            view.observation.smaps.capacity(),
        ));
    }
    out
}
fn state(pc: u64) -> TaskStateSnapshot {
    let mut raw: RegisterSnapshot = unsafe { std::mem::zeroed::<libc::user_regs_struct>() }.into();
    raw.rip = pc;
    raw.rsp = 0x800008;
    raw.cs = 0x33;
    raw.ss = 0x2b;
    raw.orig_rax = u64::MAX;
    raw.eflags = 0x202;
    TaskStateSnapshot {
        registers: raw,
        xstate: vec![0x5a; 832],
        mask: 0x200,
    }
}
fn capability(bytes: &[u8]) -> Result<StackOperation, LaunchError> {
    let snapshot = Snapshot::new(
        MappingId(7),
        Generation(0),
        0x400000,
        bytes.to_vec(),
        Boundary::Unknown,
        Boundary::Unknown,
        WriteControl::Owned,
    )
    .unwrap();
    let actual = state(0x400000);
    let candidate = classify(
        &snapshot,
        &actual.registers,
        DebugDisposition::Absent,
        &crate::selected::SyscallAliases::new(),
    )
    .map_err(|_| LaunchError::Invalid("model classifier refusal"))?;
    runner::stack_encoding(&candidate)
}
fn signal(pc: u64) -> [u8; 128] {
    let mut raw = [0; 128];
    raw[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
    raw[8..12].copy_from_slice(&libc::TRAP_TRACE.to_ne_bytes());
    raw[16..24].copy_from_slice(&pc.to_ne_bytes());
    raw
}
fn debug() -> DebugRead {
    let values = [0, 0, 0, 0, DR_TRACE, 0];
    DebugRead {
        values,
        requests: std::array::from_fn(|i| {
            Some(Request {
                result: values[i] as i64,
                errno: None,
            })
        }),
    }
}

#[test]
fn owned_stack_native_empty_and_fixed_allocation_have_exact_owners() {
    let mut p = PreparedStackNative::empty();
    assert_eq!(
        p.allocated_bytes().unwrap(),
        size_of::<PreparedStackNative>()
    );
    assert!(capacities(&p).iter().all(|(_, capacity)| *capacity == 0));
    let until = Instant::now();
    p.allocate_payloads(&geometry(false), until).unwrap();
    assert_eq!(
        p.allocated_bytes().unwrap(),
        PreparedStackNative::reservation_bytes().unwrap()
    );
    assert_eq!(
        p.allocated_bytes().unwrap(),
        size_of::<PreparedStackNative>() + 24 * MAP_BYTES
    );
    assert!(
        capacities(&p)
            .iter()
            .all(|(_, capacity)| *capacity == MAP_BYTES)
    );
    assert_eq!(p.progress.phase, StackPhase::Allocated);
    p.require_allocated().unwrap();
    assert!(p.progress.effects().is_empty());
    assert_eq!(p.progress.waits, [None; WAITS]);
    assert!(!p.claimed);
    assert!(p.identity.is_none());
    assert!(p.trace.is_none());
}
#[test]
fn owned_stack_native_allocation_errors_retain_every_installed_prefix() {
    for fail in 0..18 {
        let mut p = PreparedStackNative::empty();
        p.allocation_fault.before = Some(fail);
        let until = Instant::now();
        assert!(p.allocate_payloads(&geometry(false), until).is_err());
        let count = if fail < 15 {
            fail
        } else {
            15 + (fail - 15) * 3
        };
        assert_eq!(
            p.allocated_bytes().unwrap(),
            size_of::<PreparedStackNative>() + count * MAP_BYTES
        );
        assert_eq!(
            capacities(&p)
                .iter()
                .filter(|(_, c)| *c == MAP_BYTES)
                .count(),
            count
        );
        let before = capacities(&p);
        let error = p.progress.first_failure;
        assert!(p.allocate_payloads(&geometry(true), until).is_err());
        assert_eq!(capacities(&p), before);
        assert_eq!(p.progress.first_failure, error);
        assert_eq!(p.progress.phase, StackPhase::Allocating);
        assert!(p.require_allocated().is_err());
        assert!(p.progress.effects().is_empty());
        assert_eq!(p.progress.waits, [None; WAITS]);
    }
}
#[test]
fn owned_stack_native_allocation_unwinds_retain_exact_prefix_and_payload() {
    for point in 0..18 {
        let mut p = PreparedStackNative::empty();
        p.allocation_fault.after = Some(point);
        let until = Instant::now();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p.allocate_payloads(&geometry(false), until)
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"owned stack native allocation model unwind")
        );
        p.mark_aborted();
        let count = if point < 15 {
            point + 1
        } else {
            15 + (point - 14) * 3
        };
        assert_eq!(
            p.allocated_bytes().unwrap(),
            size_of::<PreparedStackNative>() + count * MAP_BYTES
        );
        assert_eq!(
            p.progress.first_failure,
            Some((StackPhase::Allocating, InstructionFailure::Unwound))
        );
        let before = capacities(&p);
        assert!(p.allocate_payloads(&geometry(false), until).is_err());
        assert_eq!(capacities(&p), before);
        assert!(p.progress.effects().is_empty());
    }
}
#[test]
fn owned_stack_native_page_boundary_keeps_fixed_charge_and_original_geometry() {
    let one = geometry(false);
    let two = geometry(true);
    assert_eq!(one.pages(), AddressRange::new(0x400000, 0x401000).unwrap());
    assert_eq!(two.pages(), AddressRange::new(0x400000, 0x402000).unwrap());
    assert_eq!(one.instruction().end(), 0x401000);
    for geometry in [one, two] {
        let mut p = PreparedStackNative::empty();
        p.allocate_payloads(&geometry, Instant::now()).unwrap();
        assert_eq!(
            p.shape.unwrap(),
            StackNativeShape::from_geometry(&geometry).unwrap()
        );
        assert_eq!(
            p.allocated_bytes().unwrap(),
            PreparedStackNative::reservation_bytes().unwrap()
        );
    }
}
#[test]
fn owned_stack_native_closed_encoding_gate_rejects_selected_prefixes_and_indirect() {
    assert_eq!(
        capability(&[0xe8, 0, 0, 0, 0]).unwrap(),
        StackOperation::DirectCall
    );
    assert_eq!(capability(&[0xc3]).unwrap(), StackOperation::Return);
    for bytes in [
        &[0x66, 0xe8, 0, 0, 0, 0][..],
        &[0x48, 0xc3],
        &[0xc2, 0, 0],
        &[0xff, 0xd0],
        &[0xff, 0x10],
        &[0x50],
        &[0x58],
        &[0x0f, 0xa2],
        &[0x0f, 0x05],
        &[0xeb, 0xfe],
        &[0x90],
    ] {
        assert!(capability(bytes).is_err());
    }
}
#[test]
fn owned_stack_native_trace_model_requires_full_raw_identity_and_debug() {
    let state = state(0x400005);
    let signal = signal(state.registers.rip);
    let status = (libc::SIGTRAP << 8) | 0x7f;
    let trace = runner::validate_trace(42, 42, status, signal, &state, &debug()).unwrap();
    assert_eq!(trace.ordinal, 3);
    assert_eq!(trace.tid, 42);
    assert_eq!(trace.status, status);
    assert_eq!(trace.signal, signal);
    for (tid, status) in [
        (43, status),
        (42, 0),
        (42, libc::SIGKILL),
        (42, status | (libc::PTRACE_EVENT_EXEC << 16)),
        (42, (libc::SIGSEGV << 8) | 0x7f),
    ] {
        assert!(runner::validate_trace(tid, 42, status, signal, &state, &debug()).is_err());
    }
    for (offset, value) in [
        (0, libc::SIGSEGV),
        (4, libc::EIO),
        (8, libc::SI_USER),
        (8, libc::TRAP_BRKPT),
    ] {
        let mut changed = signal;
        changed[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        assert!(runner::validate_trace(42, 42, status, changed, &state, &debug()).is_err());
    }
    let mut changed = signal;
    changed[16] ^= 1;
    assert!(runner::validate_trace(42, 42, status, changed, &state, &debug()).is_err());
    for index in 0..6 {
        let mut changed = debug();
        changed.requests[index] = None;
        assert!(runner::validate_trace(42, 42, status, signal, &state, &changed).is_err());
    }
}
#[test]
fn owned_stack_native_expected_word_changes_only_exact_call_slot() {
    for rsp in [0x800008, 0x800009, 0x801001] {
        for bytes in [&[0xe8, 0, 0, 0, 0][..], &[0xc3]] {
            let geometry = OperandGeometry::derive(
                0x400ffb,
                bytes,
                rsp,
                &(0x800000..0x802000),
                &(0x900000..0x901000),
            )
            .unwrap();
            let mut before = [0; 16];
            let length = geometry.envelope_length();
            before[..length].fill(0x5a);
            let offset = (geometry.slot.start - geometry.envelope.start) as usize;
            before[offset..offset + 8].copy_from_slice(&0x400100_u64.to_le_bytes());
            let description = OperandDescription {
                target: geometry.call_target.unwrap_or(0x400100),
                geometry,
                value: 0x400100,
                pkru: 0,
                stop: model_stop(),
                until: Instant::now(),
            };
            let after = runner::after_word(&description, &before).unwrap();
            for index in 0..16 {
                let expected = if description.geometry.operation == StackOperation::DirectCall
                    && (offset..offset + 8).contains(&index)
                {
                    description.geometry.next_pc.to_le_bytes()[index - offset]
                } else {
                    before[index]
                };
                assert_eq!(after[index], expected);
            }
        }
    }
}
#[test]
fn owned_stack_native_first_error_and_unattempted_diagnostics_never_become_success() {
    let mut p = PreparedStackNative::empty();
    p.allocate_payloads(&geometry(false), Instant::now())
        .unwrap();
    p.progress.phase = StackPhase::Original;
    p.progress
        .fail(Some(&LaunchError::Invalid("first actual refusal")));
    let first = p.progress.first_failure;
    p.mark_aborted();
    p.progress.fail(Some(&LaunchError::Timeout("later")));
    assert_eq!(p.progress.first_failure, first);
    assert!(!p.progress.nx_closed);
    assert!(!p.progress.instruction_completed);
    assert!(
        p.words
            .iter()
            .all(|word| word.view().association.is_none() && !word.view().complete)
    );
    assert_eq!(p.progress.waits, [None; 7]);
    assert!(p.progress.effects().is_empty());
    assert!(p.trace.is_none());
}
fn model_stop() -> AdmissionStop {
    let registry = crate::lifecycle::LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 1,
        },
        42,
        0x400ffb,
    )
    .unwrap();
    let task = registry.root_task();
    let row = registry.task(task).unwrap();
    AdmissionStop {
        token: DynamicStop {
            session: 7,
            tid: 42,
            task: Some(task),
            sequence: 1,
        },
        identity: DynamicTask {
            task,
            process: row.process,
            address_space: row.address_space,
            generation: 0,
        },
        phase: AdmissionPhase::Restored,
        signal: None,
    }
}
