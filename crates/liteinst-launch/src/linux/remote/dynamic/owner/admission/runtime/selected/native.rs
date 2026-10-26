//! Bounded scripted CPU state application and a genuine private INT3 bridge.
//! Application pages remain NX. No original instruction or syscall executes.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_native::{
    ControlLineage, ControlProfile,
};
use crate::linux::remote::dynamic::owner::bootstrap::{
    self, MapBuffer, MemoryObservation, Request, SignalObservation, StateSlot,
};
use crate::linux::remote::dynamic::owner::trusted;

const BEFORE: usize = 4; // distinct pre-apply read; never overwritten after an effect
const APPLIED: usize = 0;
const INJECTED: usize = 1;
const TRAP: usize = 2;
const RESTORED: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeEffect {
    Apply,
    Inject,
    Release,
    Restore,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NativeEffectRecord {
    pub(super) effect: NativeEffect,
    pub(super) result: Option<Request>,
}

pub(super) struct PreparedNativeSelected {
    states: [StateSlot; 5],
    profiles: [ControlProfile; 3],
    maps: [MapBuffer; 2],
    membership: Vec<u8>,
    peek: [MemoryObservation; 2],
    signal: SignalObservation,
    effects: [Option<NativeEffectRecord>; 4],
    pub(super) wait: Option<(i32, i32)>,
    pub(super) queries_started: bool,
    restored: Option<AdmissionStop>,
}

/// The constructor is confined to this module, after all actual native phases.
/// This descriptive receipt cannot perform a native request. ControlLineage
/// may consume it only after exact before/after profile authentication.
pub(in crate::linux::remote::dynamic::owner::admission) struct NativeSelectedProof {
    before: AdmissionStop,
    after: AdmissionStop,
    before_orig_rax: u64,
    after_orig_rax: u64,
}
impl NativeSelectedProof {
    pub(in crate::linux::remote::dynamic::owner::admission) fn before_orig_rax(&self) -> u64 {
        self.before_orig_rax
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn after_orig_rax(&self) -> u64 {
        self.after_orig_rax
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn before(&self) -> &AdmissionStop {
        &self.before
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn after(&self) -> &AdmissionStop {
        &self.after
    }
}

impl PreparedNativeSelected {
    pub(super) fn payload_bound() -> usize {
        5 * MAX_XSTATE + 3 * MAP_BYTES
    }
    pub(super) fn allocate() -> Result<Self, GateError> {
        Ok(Self {
            states: [
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
            ],
            profiles: [
                ControlProfile::default(),
                ControlProfile::default(),
                ControlProfile::default(),
            ],
            maps: [MapBuffer::allocate()?, MapBuffer::allocate()?],
            membership: bytes(MAP_BYTES)?,
            peek: [MemoryObservation::default(); 2],
            signal: SignalObservation::default(),
            effects: [None; 4],
            wait: None,
            queries_started: false,
            restored: None,
        })
    }
    pub(super) fn payload_bytes(&self) -> Result<usize, GateError> {
        let states = self.states.iter().try_fold(0usize, |sum, state| {
            add(sum, state.allocated_bytes() - size_of::<StateSlot>())
        })?;
        // MapBuffer is an exact-layout Box<[u8; 65536]> in the shared bootstrap.
        add(add(states, 2 * MAP_BYTES)?, self.membership.capacity())
    }
    pub(super) fn before_provider(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        stop: &AdmissionStop,
        lineage: &ControlLineage,
        until: Instant,
    ) -> Result<(), GateError> {
        native.require_initial_source_mm(owner, stop, until, &mut self.membership)?;
        self.profiles[0].capture(owner, until)?;
        lineage.authenticate(stop, &self.profiles[0])?;
        Ok(())
    }
    pub(super) fn final_state(&self) -> Result<&TaskStateSnapshot, GateError> {
        if self.restored.is_none() || !self.states[RESTORED].complete {
            return Err(refused("runtime selected native restoration is incomplete"));
        }
        Ok(self.states[RESTORED].initialized_state())
    }
    pub(super) fn final_stop(&self) -> Result<&AdmissionStop, GateError> {
        self.restored
            .as_ref()
            .ok_or_else(|| refused("runtime selected native stop is absent"))
    }
    pub(super) fn control_profiles(&self) -> (&ControlProfile, &ControlProfile) {
        (&self.profiles[1], &self.profiles[2])
    }

    pub(super) fn execute(
        &mut self,
        owner: &mut Owner,
        native: &mut NativeLifecycle,
        binding: NativeSelectedBinding<'_>,
    ) -> Result<NativeSelectedProof, GateError> {
        let NativeSelectedBinding {
            stop,
            before,
            input,
            completed,
            result,
            island,
            baseline,
            lineage,
            until,
        } = binding;
        // Independently bind the sealed native receipt to the exact selected
        // semantics before any effect. This <=15-byte temporary is reserved.
        // It is never labeled an observed kernel completion.
        let expected = model_with_lineage(input, result, lineage, stop)?;
        if input.registers() != &before.registers
            || expected != *completed
            || expected.instruction.retained_capacity() > 15
        {
            return Err(refused("runtime selected native model binding differs"));
        }
        drop(expected);
        let after = &completed.after;
        if self.effects.iter().any(Option::is_some)
            || self.wait.is_some()
            || self.queries_started
            || before.token != stop.token
            || before.task != stop.identity
            || before.logical_pc != before.registers.rip
            || before.signal.is_some()
            || before.phase != StopPhase::UserCheckpoint
            || before.registers.cs != 0x33
            || after.cs != 0x33
            || stop.signal.is_some()
            || !matches!(
                stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || island.address_space != stop.identity.address_space
            || island.generation != 0
            || stop.identity.generation != 0
            || island.page_size != 4096
            || island.range.start % 4096 != 0
            || island.range.end.checked_sub(island.range.start) != Some(4096)
        {
            return Err(refused("runtime selected native binding differs"));
        }
        native.require_initial_source_mm(owner, stop, until, &mut self.membership)?;
        if native.admission_interrupt_credit(owner.pid)? != 0 {
            return Err(refused("runtime selected has interruption credit"));
        }
        self.maps[0].capture(owner, until)?;
        if self.maps[0].bytes() != baseline {
            return Err(refused("runtime selected baseline map inventory differs"));
        }
        bootstrap::verify_memory(
            owner,
            island.range.start,
            &bootstrap::island_code_fixed(),
            &mut self.peek[0],
            until,
        )?;
        self.profiles[1].capture(owner, until)?;
        lineage.authenticate(stop, &self.profiles[1])?;
        // Independent actual full-state read immediately before the first
        // mutation. Its initialized request prefixes and MAX storage remain
        // retained even if validation fails; APPLIED is never reused for it.
        self.states[BEFORE].capture(owner, until)?;
        require_state(
            self.states[BEFORE].initialized_state(),
            input.registers(),
            before,
        )?;
        lineage.require_orig_rax(
            stop,
            self.states[BEFORE].initialized_state().registers.orig_rax,
        )?;
        native.require_admission_stop(stop)?;
        bootstrap::physical(owner, until)?;
        self.write_registers(owner, NativeEffect::Apply, 0, after, until)?;
        self.states[APPLIED].capture(owner, until)?;
        require_state(self.states[APPLIED].initialized_state(), after, before)?;

        let injected = trusted::temporary(after, island.trap());
        if injected.cs != 0x33
            || injected.orig_rax != u64::MAX
            || injected.eflags & (0x100 | 0x10000 | 0x40000) != 0
        {
            return Err(refused("runtime selected private setup differs"));
        }
        self.write_registers(owner, NativeEffect::Inject, 1, &injected, until)?;
        self.states[INJECTED].capture(owner, until)?;
        require_state(self.states[INJECTED].initialized_state(), &injected, before)?;
        native.require_admission_stop(stop)?;
        owner.time_left(until, "runtime selected private release")?;
        native.begin_admission_execution(stop)?;
        self.effects[2] = Some(NativeEffectRecord {
            effect: NativeEffect::Release,
            result: None,
        });
        owner.time_left(until, "runtime selected private release")?;
        let release = request(libc::PTRACE_CONT, owner.pid, 0, 0);
        self.effects[2].as_mut().expect("record installed").result = Some(release);
        request_ok(release, "PTRACE_CONT runtime selected")?;
        owner.released(owner.pid);
        let (tid, status) = owner.wait_raw(until, "runtime selected private trap")?;
        self.wait = Some((tid, status));
        // A terminal or unowned wait remains diagnostic and is never queried.
        bootstrap::raw_held(owner, tid, status, until)?;
        self.queries_started = true;
        let signal = self.signal.capture(tid);
        let state = self.states[TRAP].capture_tid(tid);
        signal?;
        state?;
        owner.time_left(until, "runtime selected private trap")?;
        if tid != owner.pid
            || native.consume_admission_interrupt(tid)?
            || !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != libc::SIGTRAP
            || status >> 16 != 0
        {
            return Err(refused(
                "runtime selected reached an unexpected native stop",
            ));
        }
        self.signal.validate()?;
        let mut expected_trap = injected;
        expected_trap.rip = island
            .trap()
            .checked_add(1)
            .ok_or_else(|| refused("runtime selected trap PC overflows"))?;
        require_state(
            self.states[TRAP].initialized_state(),
            &expected_trap,
            before,
        )?;
        bootstrap::verify_memory(
            owner,
            island.range.start,
            &bootstrap::island_code_fixed(),
            &mut self.peek[1],
            until,
        )?;
        self.write_registers(owner, NativeEffect::Restore, 3, after, until)?;
        self.states[RESTORED].capture(owner, until)?;
        require_state(self.states[RESTORED].initialized_state(), after, before)?;
        let restored =
            native.finish_admission_execution(tid, after.rip, AdmissionPhase::Restored)?;
        // Retain the real new token before any subsequent fallible read.
        self.restored = Some(restored);
        let restored = self.restored.as_ref().expect("actual stop retained");
        native.require_initial_source_mm(owner, restored, until, &mut self.membership)?;
        self.maps[1].capture(owner, until)?;
        if self.maps[1].bytes() != baseline {
            return Err(refused("runtime selected changed the closed map inventory"));
        }
        self.profiles[2].capture(owner, until)?;
        bootstrap::physical(owner, until)?;
        for (record, expected) in self.effects.iter().zip([
            NativeEffect::Apply,
            NativeEffect::Inject,
            NativeEffect::Release,
            NativeEffect::Restore,
        ]) {
            if record
                != &Some(NativeEffectRecord {
                    effect: expected,
                    result: Some(Request {
                        result: 0,
                        errno: None,
                    }),
                })
            {
                return Err(refused("runtime selected native effect receipt differs"));
            }
        }
        Ok(NativeSelectedProof {
            before: stop.clone(),
            after: restored.clone(),
            before_orig_rax: self.states[BEFORE].initialized_state().registers.orig_rax,
            after_orig_rax: self.states[RESTORED].initialized_state().registers.orig_rax,
        })
    }
    fn write_registers(
        &mut self,
        owner: &Owner,
        effect: NativeEffect,
        index: usize,
        registers: &RegisterSnapshot,
        until: Instant,
    ) -> Result<(), GateError> {
        bootstrap::physical(owner, until)?;
        self.effects[index] = Some(NativeEffectRecord {
            effect,
            result: None,
        });
        owner.time_left(until, "runtime selected register write")?;
        let raw = libc::user_regs_struct::from(*registers);
        let result = request(
            libc::PTRACE_SETREGS,
            owner.pid,
            0,
            (&raw const raw) as usize,
        );
        self.effects[index]
            .as_mut()
            .expect("record installed")
            .result = Some(result);
        request_ok(result, "PTRACE_SETREGS runtime selected")?;
        Ok(())
    }
}

pub(super) struct NativeSelectedBinding<'a> {
    pub(super) stop: &'a AdmissionStop,
    pub(super) before: &'a ObservedStop,
    pub(super) input: &'a SelectedInput,
    pub(super) completed: &'a CompletedInstruction,
    pub(super) result: SelectedResult,
    pub(super) island: &'a TrustedIsland,
    pub(super) baseline: &'a [u8],
    pub(super) lineage: &'a ControlLineage,
    pub(super) until: Instant,
}
fn require_state(
    state: &TaskStateSnapshot,
    registers: &RegisterSnapshot,
    before: &ObservedStop,
) -> Result<(), GateError> {
    if state.registers != *registers
        || state.xstate != before.xstate
        || state.mask != before.signal_mask
    {
        return Err(refused("runtime selected complete native state differs"));
    }
    Ok(())
}
fn request(operation: u32, tid: i32, address: usize, data: usize) -> Request {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let result = unsafe {
        libc::ptrace(
            operation,
            tid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    let errno = if result == -1 {
        let value = unsafe { *libc::__errno_location() };
        (value != 0).then_some(value)
    } else {
        None
    };
    Request { result, errno }
}
fn request_ok(result: Request, operation: &'static str) -> Result<(), LaunchError> {
    if let Some(errno) = result.errno {
        return Err(io_error(
            operation,
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    if result.result != 0 {
        return Err(LaunchError::Invalid(
            "runtime selected ptrace result differs",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission::runtime) mod native_tests;

#[cfg(test)]
mod control_tests;
