//! Explicit trap-coverage publication, separate from the strict/A1 paths.

use super::*;
use crate::trap_coverage::{TrapGuard, TrapGuardRole};

impl SingleThreadPageGate {
    /// Reconstructs the exact expected instruction image, including guards in
    /// the operand/prefix bytes. The immutable original snapshot stays separate.
    pub(super) fn armed_instruction(&self, pc: u64, original: &[u8]) -> Vec<u8> {
        domain::armed_instruction(pc, original, &self.sites, &self.covered_guards)
    }

    pub(super) fn admit_covered(
        &mut self,
        signal: &SignalStop,
        deadline: Instant,
    ) -> Result<(), GateError> {
        let started = Instant::now();
        let budget = self
            .coverage_budget
            .ok_or(GateError::Refused("missing coverage budget"))?;
        if budget.page_size != PAGE || self.core.is_some() || self.selected_aliases.is_none() {
            return Err(GateError::Refused("coverage backend configuration differs"));
        }
        let page = signal
            .address
            .ok_or(GateError::Refused("missing fetch address"))?
            & !(PAGE - 1);
        let image = self
            .images
            .iter()
            .find(|image| image.snapshot.range().contains(page))
            .ok_or(GateError::Refused("missing image facts"))?;
        let plan = domain::prepare_covered_admission(
            (image, &self.oracle),
            page,
            &self.policy,
            &self.returns,
            (
                self.selected_aliases.as_ref().expect("checked aliases"),
                &self.covered_guards,
                budget,
            ),
            deadline,
        )?;
        for &next in plan.pages() {
            self.returns
                .record_independent_streams_before_admission(
                    &image.snapshot,
                    AddressRange::new(next, next + PAGE).unwrap(),
                    &image.entries,
                )
                .map_err(|_| GateError::Refused("independent CALL-return census is unresolved"))?;
        }

        let expected = self.armed_instruction(image.mapping.start, image.snapshot.bytes());
        let mut stop = self.process.hold()?;
        stop.acknowledge_owned_signal(signal)?;
        if stop.read_memory(image.mapping.start, expected.len())? != expected {
            return Err(GateError::Refused(
                "source changed before covered publication",
            ));
        }
        #[cfg(test)]
        failure::capture(
            &mut self.coverage_failure,
            failure::Scope::Publication,
            &stop,
        )?;
        for guard in plan.guards().values() {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                self.covered_guards.entry(guard.address())
            {
                stop.write_memory_checked(guard.address(), &guard.original_bytes()[..1], &[0xcc])?;
                entry.insert(guard.clone());
                match guard.role() {
                    TrapGuardRole::Selected(site) => {
                        self.sites.insert(site.address, site);
                        self.metrics.covered_candidates += 1;
                    }
                    TrapGuardRole::Collateral => self.metrics.collateral_guards += 1,
                }
                #[cfg(test)]
                failure::hit(
                    &mut self.coverage_failure,
                    failure::Phase::GuardWritten,
                    &stop,
                )?;
            }
        }
        let protection = libc::PROT_EXEC
            | if image.mapping.permissions.as_bytes()[0] == b'r' {
                libc::PROT_READ
            } else {
                0
            };
        for &next in plan.pages() {
            stop.mprotect(next, PAGE as usize, protection, remaining(deadline)?)?;
            #[cfg(test)]
            failure::hit(
                &mut self.coverage_failure,
                failure::Phase::PageExecutable,
                &stop,
            )?;
        }
        stop.sync_core(remaining(deadline)?)?;
        for &next in plan.pages() {
            if self.pages.insert(next, true) == Some(false) {
                self.metrics.admitted_pages += 1;
                self.metrics.untouched_pages -= 1;
            }
        }
        self.metrics.first_touch.push(started.elapsed());
        Ok(())
    }

    pub(super) fn execute_collateral(
        &mut self,
        guard: &TrapGuard,
        signal: &SignalStop,
        deadline: Instant,
    ) -> Result<Option<GateEvent>, GateError> {
        qualify_collateral(guard)?;
        let pc = guard.address();
        let original = guard.original_bytes();
        let armed = self.armed_instruction(pc, original);
        let mut stop = self.process.hold()?;
        if stop.read_memory(pc, armed.len())? != armed {
            return Err(GateError::Refused("collateral guard bytes changed"));
        }
        stop.acknowledge_owned_signal(signal)?;
        let mut before = stop.read_registers()?;
        if before.eflags & ((1 << 8) | (1 << 16)) != 0 {
            return Err(GateError::Refused(
                "collateral entry requires clear TF and RF",
            ));
        }
        before.rip = pc;
        stop.write_registers(&before)?;
        let before_xstate = stop.read_xstate()?;
        #[cfg(test)]
        failure::capture(
            &mut self.coverage_failure,
            failure::Scope::Collateral,
            &stop,
        )?;
        stop.write_memory_checked(pc, &armed, original)?;
        stop.sync_core(remaining(deadline)?)?;
        #[cfg(test)]
        failure::hit(
            &mut self.coverage_failure,
            failure::Phase::CollateralRestored,
            &stop,
        )?;
        match stop.single_step_until_event(remaining(deadline)?)? {
            ProcessEvent::Signal(signal)
                if signal.signal == libc::SIGTRAP && signal.code == libc::TRAP_TRACE =>
            {
                let mut stop = self.process.hold()?;
                stop.acknowledge_owned_signal(&signal)?;
                let after = stop.read_registers()?;
                let xstate = stop.read_xstate()?;
                if after.rip != pc + original.len() as u64 || xstate != before_xstate {
                    return Err(GateError::Refused(
                        "collateral step did not complete exactly",
                    ));
                }
                #[cfg(test)]
                failure::hit(
                    &mut self.coverage_failure,
                    failure::Phase::CollateralCompleted,
                    &stop,
                )?;
                stop.write_memory_checked(pc, original, &armed)?;
                stop.sync_core(remaining(deadline)?)?;
                if stop.read_registers()? != after || stop.read_xstate()? != xstate {
                    return Err(GateError::Refused(
                        "collateral rearming changed completed state",
                    ));
                }
                self.metrics.collateral_completions += 1;
                Ok(None)
            }
            ProcessEvent::Signal(signal) => self.application_signal(signal).map(Some),
            _ => Err(GateError::Refused(
                "collateral step has no original completion",
            )),
        }
    }
}

// No hook, selector, environment variable or public API exists in a production
// build. Each unit fixture injects an error only after a real child operation;
// ordinary gate error handling remains responsible for exclusion and cleanup.
#[cfg(test)]
pub(super) mod failure {
    use super::GateError;
    use crate::{RegisterSnapshot, SingleThreadStop};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(in crate::gate) enum Phase {
        GuardWritten,
        PageExecutable,
        SelectedRestored,
        SelectedCompleted,
        CollateralRestored,
        CollateralCompleted,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(in crate::gate) enum Scope {
        Publication,
        Selected,
        Collateral,
    }

    impl Phase {
        fn scope(self) -> Scope {
            match self {
                Self::GuardWritten | Self::PageExecutable => Scope::Publication,
                Self::SelectedRestored | Self::SelectedCompleted => Scope::Selected,
                Self::CollateralRestored | Self::CollateralCompleted => Scope::Collateral,
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(in crate::gate) struct State {
        pub(in crate::gate) registers: RegisterSnapshot,
        pub(in crate::gate) xstate: Vec<u8>,
    }

    impl State {
        fn read(stop: &SingleThreadStop<'_>) -> Result<Self, GateError> {
            Ok(Self {
                registers: stop.read_registers()?,
                xstate: stop.read_xstate()?,
            })
        }
    }

    #[derive(Clone, Debug)]
    pub(in crate::gate) struct Injection {
        pub(in crate::gate) phase: Phase,
        pub(in crate::gate) before: Option<State>,
        pub(in crate::gate) at_failure: Option<State>,
    }

    impl Injection {
        pub(in crate::gate) fn new(phase: Phase) -> Self {
            Self {
                phase,
                before: None,
                at_failure: None,
            }
        }
    }

    pub(in crate::gate) fn capture(
        injection: &mut Option<Injection>,
        scope: Scope,
        stop: &SingleThreadStop<'_>,
    ) -> Result<(), GateError> {
        if let Some(injection) = injection
            .as_mut()
            .filter(|item| item.phase.scope() == scope)
        {
            assert!(
                injection.before.is_none(),
                "failure scope must be entered once"
            );
            injection.before = Some(State::read(stop)?);
        }
        Ok(())
    }

    pub(in crate::gate) fn hit(
        injection: &mut Option<Injection>,
        phase: Phase,
        stop: &SingleThreadStop<'_>,
    ) -> Result<(), GateError> {
        if let Some(injection) = injection.as_mut().filter(|item| item.phase == phase) {
            assert!(injection.before.is_some());
            assert!(injection.at_failure.is_none());
            injection.at_failure = Some(State::read(stop)?);
            return Err(GateError::Refused("injected coverage operation failure"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "coverage_failure_tests.rs"]
mod failure_tests;
