//! One observer reservation, installed allocation and actual prefix settlement.
//! Finishing never refunds charged lifetime capacity or permits execution.
use super::admitted::{AdmittedShape, PreparedAdmitted};
use super::artifact::PinnedArtifact;
use super::owner::ArtifactOwner;
use super::protocol::Input;
use super::raw::PreparedRawLane;
use super::*;
use crate::linux::remote::dynamic::owner::admission::census::{CensusError, Reservation};
use std::mem::size_of;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BudgetObservation {
    pub(super) charged: BudgetCharge,
    pub(super) used: BudgetCharge,
}

impl BudgetObservation {
    fn of(census: &ResumeCensus) -> Self {
        Self {
            charged: census.charged(),
            used: census.used(),
        }
    }
}

/// Each secondary outcome is retained independently of the original allocation
/// Err/panic. None is backfilled when an earlier action did not occur.
pub(super) struct ObserverReservation {
    pub(super) started: bool,
    pub(super) shape: Option<AdmittedShape>,
    pub(super) before: Option<BudgetObservation>,
    pub(super) after: Option<BudgetObservation>,
    pub(super) reservation_bytes: Option<usize>,
    pub(super) retained_bound: Option<usize>,
    pub(super) temporary_bound: Option<usize>,
    pub(super) reserve: Option<Result<Reservation, CensusError>>,
    pub(super) token: Option<Reservation>,
    pub(super) allocation_complete: bool,
    pub(super) allocation_unwound: bool,
    pub(super) measured: Option<Result<usize, OracleError>>,
    pub(super) measurement_failed: bool,
    pub(super) measurement_error_transferred: bool,
    pub(super) measurement_unwound: bool,
    pub(super) measurement_panic: Option<Box<dyn std::any::Any + Send>>,
    pub(super) settlement_started: bool,
    pub(super) settlement_reused: bool,
    pub(super) debit: Option<Result<(), CensusError>>,
    pub(super) debit_unwound: bool,
    pub(super) debit_panic: Option<Box<dyn std::any::Any + Send>>,
    pub(super) finish: Option<Result<(), CensusError>>,
    pub(super) finish_unwound: bool,
    pub(super) finish_panic: Option<Box<dyn std::any::Any + Send>>,
    pub(super) settlement_access: Option<OracleError>,
    pub(super) formula_checked: Option<bool>,
}

impl ObserverReservation {
    pub(super) const fn empty() -> Self {
        Self {
            started: false,
            shape: None,
            before: None,
            after: None,
            reservation_bytes: None,
            retained_bound: None,
            temporary_bound: None,
            reserve: None,
            token: None,
            allocation_complete: false,
            allocation_unwound: false,
            measured: None,
            measurement_failed: false,
            measurement_error_transferred: false,
            measurement_unwound: false,
            measurement_panic: None,
            settlement_started: false,
            settlement_reused: false,
            debit: None,
            debit_unwound: false,
            debit_panic: None,
            finish: None,
            finish_unwound: false,
            finish_panic: None,
            settlement_access: None,
            formula_checked: None,
        }
    }

    pub(super) fn require_finished(&self) -> Result<(), OracleError> {
        if !self.started
            || self.token.is_none()
            || self.reserve != self.token.map(Ok)
            || !self.allocation_complete
            || self.allocation_unwound
            || !matches!(self.measured, Some(Ok(_)))
            || self.measurement_failed
            || self.measurement_error_transferred
            || self.measurement_unwound
            || self.debit_unwound
            || self.finish_unwound
            || !self.settlement_started
            || self.settlement_reused
            || self.debit != Some(Ok(()))
            || self.finish != Some(Ok(()))
            || self.settlement_access.is_some()
            || self.formula_checked != Some(true)
            || !self.formula_matches()
        {
            return Err(OracleError::Invalid(
                "oracle observer reservation is incomplete",
            ));
        }
        Ok(())
    }
}

fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize, OracleError> {
    values.into_iter().try_fold(0_usize, |total, value| {
        total
            .checked_add(value)
            .ok_or(OracleError::Invalid("oracle observer byte count overflows"))
    })
}

fn subtract(total: usize, embedded: usize) -> Result<usize, OracleError> {
    total.checked_sub(embedded).ok_or(OracleError::Invalid(
        "oracle embedded header accounting differs",
    ))
}

impl Experiment {
    /// Count each new owning slot once. The physical Owner is unchanged launch
    /// infrastructure; its native/runtime/journal payload remains in the
    /// production ownership/accounting domain. Only the two oracle wrappers'
    /// own Options, pin records and cleanup outcomes are new observer storage.
    fn remaining_header_bytes() -> Result<usize, OracleError> {
        subtract(
            size_of::<Self>(),
            sum([
                size_of::<Input>(),
                size_of::<PinnedArtifact>(),
                size_of::<PreparedRawLane>(),
                size_of::<PreparedAdmitted>(),
                size_of::<PreparedKernelObservation>(),
                size_of::<PrefixMirrors>(),
                2 * size_of::<Owner>(),
                // The genuine Ready inline state was already debited by startup.
                // Only that exact moved value is excluded, never a new snapshot.
                PreparedAdmitted::producer_inline_bytes(),
            ])?,
        )
    }

    pub(super) fn observer_allocated_bytes(&self) -> Result<usize, OracleError> {
        sum([
            Self::remaining_header_bytes()?,
            self.input.allocated_bytes()?,
            self.file.allocated_bytes()?,
            self.raw.allocated_bytes()?,
            self.admitted.allocated_bytes()?,
            self.journal.allocated_bytes()?,
            self.prefix.allocated_bytes()?,
        ])
    }

    fn observer_retained_bound(&self, shape: AdmittedShape) -> Result<usize, OracleError> {
        // The raw lane has already finished and stays installed unchanged.
        // Its full actual retained payload participates in Q; it has no census
        // authority and does not acquire one by being counted here.
        sum([
            Self::remaining_header_bytes()?,
            self.input.allocated_bytes()?,
            self.file.allocated_bytes()?,
            self.raw.allocated_bytes()?,
            PreparedAdmitted::reservation_bytes(shape)?,
            PreparedKernelObservation::reservation_bytes()?,
            PrefixMirrors::reservation_bytes(shape.window_bytes)?,
        ])
    }

    fn observer_temporary_bound(&self, shape: AdmittedShape) -> Result<usize, OracleError> {
        let plan = self
            .plan
            .as_ref()
            .ok_or(OracleError::Invalid("oracle plan is absent"))?;
        let raw_shape = self.raw.lane.observed_shape(plan)?;
        sum([
            PinnedArtifact::temporary_bytes()?,
            // The file helper bounds one exact 32-byte command allocation.
            // Both real launches need an allowance, even after raw cleanup.
            32,
            PreparedRawLane::temporary_bytes(raw_shape)?,
            PreparedAdmitted::temporary_bytes(shape)?,
            2 * ArtifactOwner::temporary_bytes(),
            protocol::temporary_bytes()?,
            PreparedKernelObservation::temporary_bytes()?,
            journal::temporary_bytes()?,
            native_checks::temporary_bytes()?,
            output::temporary_bytes()?,
            PrefixMirrors::temporary_bytes()?,
            root_temporary_bytes()?,
        ])
    }

    pub(super) fn prepare_observer(&mut self, until: Instant) -> Result<(), OracleError> {
        if self.reservation.started {
            return Err(OracleError::Invalid("oracle observer reservation reused"));
        }
        self.reservation.started = true;
        let owner = self.admitted_owner.owner_ref()?;
        owner.time_left(until, "oracle observer shape")?;
        let runtime = owner
            .runtime
            .as_ref()
            .ok_or(OracleError::Invalid("oracle runtime is absent"))?;
        let plan = self
            .plan
            .as_ref()
            .ok_or(OracleError::Invalid("oracle plan is absent"))?;
        let shape = PreparedAdmitted::shape(runtime, plan)?;
        self.reservation.shape = Some(shape);
        let retained = self.observer_retained_bound(shape)?;
        self.reservation.retained_bound = Some(retained);
        let temporary = self.observer_temporary_bound(shape)?;
        self.reservation.temporary_bound = Some(temporary);
        let reserved = sum([retained, temporary])?;
        self.reservation.reservation_bytes = Some(reserved);
        let census = self
            .admitted_owner
            .owner()?
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.census.as_mut())
            .ok_or(OracleError::Invalid("oracle actual census is absent"))?;
        self.reservation.before = Some(BudgetObservation::of(census));
        let reserve = census.reserve(BudgetCharge {
            source_fact_bytes: reserved,
            ..BudgetCharge::default()
        });
        self.reservation.reserve = Some(reserve);
        let token = reserve.map_err(|error| OracleError::Gate(census_error(error)))?;
        // No fallible action between reserve and installation of its real token.
        self.reservation.token = Some(token);
        let allocation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let owner = self.admitted_owner.owner_ref()?;
            owner.time_left(until, "oracle observer allocation")?;
            self.prefix.allocate_payloads(shape.window_bytes)?;
            // Catch only this observer's allocation. An unrelated admitted
            // failure must not poison a fresh journal history capture.
            let journal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.journal.allocate_payloads()
            }));
            match journal {
                Ok(result) => result?,
                Err(payload) => {
                    self.journal.mark_aborted();
                    std::panic::resume_unwind(payload);
                }
            }
            self.admitted.allocate_payloads(
                shape,
                self.plan
                    .as_ref()
                    .ok_or(OracleError::Invalid("oracle plan is absent"))?,
                owner,
            )?;
            self.reservation.allocation_complete = true;
            Ok::<(), OracleError>(())
        }));
        self.reservation.allocation_unwound = allocation.is_err();
        // A measurement refusal is itself retained. Finish is still attempted
        // below; no retry, replacement allocation or partial-prefix discard.
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.observer_allocated_bytes()
        })) {
            Ok(measured) => {
                self.reservation.measurement_failed = measured.is_err();
                self.reservation.measured = Some(measured);
            }
            Err(payload) => {
                self.reservation.measurement_unwound = true;
                self.reservation.measurement_panic = Some(payload);
            }
        }
        let settlement = self.settle_observer();
        self.reservation.propagate(allocation, settlement)?;
        self.admitted_owner
            .owner_ref()?
            .time_left(until, "oracle observer prepared")?;
        Ok(())
    }

    fn settle_observer(&mut self) -> Result<(), OracleError> {
        let census = match self.admitted_owner.owner().and_then(|owner| {
            owner
                .runtime
                .as_mut()
                .and_then(|runtime| runtime.census.as_mut())
                .ok_or(OracleError::Invalid("oracle settlement lost actual census"))
        }) {
            Ok(census) => census,
            Err(error) => {
                self.reservation.settlement_access = Some(error);
                return Err(OracleError::Invalid(
                    "oracle observer settlement lost custody",
                ));
            }
        };
        self.reservation.settle(census)
    }
}

impl ObserverReservation {
    fn propagate(
        &mut self,
        allocation: custody::Observed,
        settlement: Result<(), OracleError>,
    ) -> Result<(), OracleError> {
        match allocation {
            Ok(Err(error)) => Err(error),
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Ok(())) => {
                // Only after the earlier allocation succeeded can a secondary
                // unwind become the primary failure. All finish attempts have
                // already occurred; rethrow the exact original payload.
                if let Some(payload) = self.measurement_panic.take() {
                    std::panic::resume_unwind(payload);
                }
                if self.measurement_failed {
                    if let Some(Err(error)) = self.measured.take() {
                        // The exact original error moves into the outer body
                        // outcome. The flag distinguishes this from no read.
                        self.measurement_error_transferred = true;
                        return Err(error);
                    }
                    return Err(OracleError::Invalid(
                        "oracle original measurement error is absent",
                    ));
                }
                if let Some(payload) = self.debit_panic.take() {
                    std::panic::resume_unwind(payload);
                }
                if let Some(Err(error)) = self.debit {
                    return Err(OracleError::Gate(census_error(error)));
                }
                if let Some(payload) = self.finish_panic.take() {
                    std::panic::resume_unwind(payload);
                }
                if let Some(Err(error)) = self.finish {
                    return Err(OracleError::Gate(census_error(error)));
                }
                settlement?;
                self.require_finished()?;
                Ok(())
            }
        }
    }

    fn settle(&mut self, census: &mut ResumeCensus) -> Result<(), OracleError> {
        if self.settlement_started {
            self.settlement_reused = true;
            return Err(OracleError::Invalid("oracle observer settlement repeated"));
        }
        self.settlement_started = true;
        let token = self
            .token
            .ok_or(OracleError::Invalid("oracle settlement token missing"))?;
        if self.reserve != Some(Ok(token)) {
            return Err(OracleError::Invalid(
                "oracle settlement token differs from actual reserve",
            ));
        }
        if let Some(Ok(bytes)) = &self.measured {
            let debit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                census.account_external(
                    token,
                    BudgetCharge {
                        source_fact_bytes: *bytes,
                        ..BudgetCharge::default()
                    },
                )
            }));
            match debit {
                Ok(result) => self.debit = Some(result),
                Err(payload) => {
                    self.debit_unwound = true;
                    self.debit_panic = Some(payload);
                }
            }
        }
        // Always finish the same actual token even if measurement/debit failed.
        // A failure is recorded and blocks dispatch; finish never refunds Q.
        let finish = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            census.finish_reservation(token)
        }));
        match finish {
            Ok(result) => self.finish = Some(result),
            Err(payload) => {
                self.finish_unwound = true;
                self.finish_panic = Some(payload);
            }
        }
        self.after = Some(BudgetObservation::of(census));
        let valid = self.formula_matches();
        self.formula_checked = Some(valid);
        if self.debit != Some(Ok(())) || self.finish != Some(Ok(())) || !valid {
            return Err(OracleError::Invalid(
                "oracle observer actual settlement differs",
            ));
        }
        Ok(())
    }

    fn formula_matches(&self) -> bool {
        match (
            self.before,
            self.after,
            self.reservation_bytes,
            self.retained_bound,
            self.measured.as_ref(),
        ) {
            (Some(before), Some(after), Some(reserved), Some(bound), Some(Ok(actual))) => {
                let mut expected_charged = before.charged;
                let mut expected_used = before.used;
                match (
                    before.charged.source_fact_bytes.checked_add(reserved),
                    before.used.source_fact_bytes.checked_add(*actual),
                ) {
                    (Some(charged), Some(used)) => {
                        expected_charged.source_fact_bytes = charged;
                        expected_used.source_fact_bytes = used;
                        after.charged == expected_charged
                            && after.used == expected_used
                            && *actual <= bound
                            && bound <= reserved
                            && self
                                .temporary_bound
                                .and_then(|temporary| bound.checked_add(temporary))
                                == Some(reserved)
                            && (!self.allocation_complete || *actual == bound)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

// Concrete source arrays and IntoIter values from the six root calculators:
// remaining header (8), actual capacity (7), retained bound (7), temporary
// bound (12), retained-plus-temporary (2), and this root allowance (33).
// Each checked fold also gets its total/item/operands, iterator/add outcomes,
// and result/error header; the header subtraction has its own outcome. This
// type is used only for its size: no scratch allocation or extra effect occurs.
// It bounds these source values, not an optimized compiler stack frame.
type RootCalculatorScratch = (
    [usize; 8],
    std::array::IntoIter<usize, 8>,
    [usize; 7],
    std::array::IntoIter<usize, 7>,
    [usize; 7],
    std::array::IntoIter<usize, 7>,
    [usize; 12],
    std::array::IntoIter<usize, 12>,
    [usize; 2],
    std::array::IntoIter<usize, 2>,
    [usize; 33],
    std::array::IntoIter<usize, 33>,
    [[usize; 4]; 6],
    [Option<usize>; 12],
    [Result<usize, OracleError>; 6],
    Option<usize>,
    Result<usize, OracleError>,
);

// Complete new diagnostic source values: decimal buffer; seven-vector array
// and helper result; projection return/destructure; borrowed error/outcome and
// static string/slice arguments; ASCII/length iterator controls; decimal and
// checked-length scalar/Option controls; and the writev return. This is a
// conservative source-value allowance, not an observed compiler frame size.
type FailureDiagnosticScratch = (
    [u8; 12],
    [libc::iovec; 7],
    libc::iovec,
    [(&'static str, &'static str, Option<i32>); 2],
    [&'static OracleError; 2],
    &'static LaunchError,
    &'static GateError,
    &'static std::io::Error,
    Option<&'static custody::Outcome>,
    &'static custody::Outcome,
    [&'static str; 4],
    [&'static [u8]; 10],
    std::str::Bytes<'static>,
    std::slice::Iter<'static, libc::iovec>,
    &'static libc::iovec,
    [usize; 10],
    [u32; 3],
    [i32; 3],
    [u8; 3],
    [bool; 4],
    Option<u8>,
    Option<&'static u8>,
    std::ops::ControlFlow<(), ()>,
    [Option<i32>; 2],
    [Option<usize>; 2],
    *const libc::iovec,
    *const u8,
    *mut libc::c_void,
    libc::ssize_t,
);

fn root_temporary_bytes() -> Result<usize, OracleError> {
    // Source-level allowances for the direct wrapper, classifier and outer
    // catches. These are bounds, not an assertion about a compiler stack frame.
    sum([
        size_of::<RuntimeOwner>(),
        size_of::<crate::linux::remote::dynamic::owner::kernel_journal::JournalUnwind>(),
        size_of::<Option<crate::linux::remote::dynamic::owner::exec_journal::ExecJournalUnwind>>(),
        size_of::<crate::linux::remote::dynamic::owner::admission::runtime_instruction::InstructionCandidate<'static>>(),
        size_of::<AdmissionRequest>(), size_of::<AdmissionReply>(),
        size_of::<RuntimeStartOptions>(),
        size_of::<AdmittedShape>(), size_of::<Reservation>(),
        2 * size_of::<BudgetObservation>(), 2 * size_of::<BudgetCharge>(),
        2 * size_of::<GateError>(), 2 * size_of::<OracleError>(),
        size_of::<Result<Result<(), OracleError>, Box<dyn std::any::Any + Send>>>(),
        2 * size_of::<std::panic::AssertUnwindSafe<&mut Experiment>>(),
        size_of::<[usize; 8]>(),
        // New outer literal construction/moves and nested catch/result slots.
        // Retained owners are separate; this conservative value allowance does
        // not assert that the compiler materializes another whole stack copy.
        size_of::<Experiment>(), size_of::<custody::Custody>(),
        4 * size_of::<custody::Observed>(),
        size_of::<Result<Result<(), LaunchError>, Box<dyn std::any::Any + Send>>>(),
        2 * size_of::<JournalWriterTransition>(),
        size_of::<DynamicRuntimeOptions>(),
        2 * size_of::<Option<Instant>>(),
        2 * size_of::<Option<raw::RawBoundary>>(),
        2 * size_of::<Option<admitted::AdmittedBoundary>>(),
        16 * size_of::<&Owner>(), 24 * size_of::<usize>(),
        8 * size_of::<bool>(),
        // The two genuinely observed original pidfd proofs use these fixed
        // new query values. Native/launch-owner internals retain their existing
        // accounting domain; these observer-owned request buffers are extra.
        2 * size_of::<libc::pollfd>(), 2 * size_of::<libc::siginfo_t>(),
        4 * size_of::<owner::RequestResult>(),
        size_of::<std::sync::atomic::AtomicU64>(),
        size_of::<(RootCalculatorScratch, FailureDiagnosticScratch)>(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{LifecycleRegistry, Limits as LifecycleLimits};
    use crate::linux::remote::dynamic::owner::admission::census::Limits;

    // Supplied bookkeeping identities only. No native owner/stop/seal, child,
    // ptrace request or execution capability is constructed by these controls.
    fn census() -> ResumeCensus {
        let registry = LifecycleRegistry::new(LifecycleLimits::default(), 23, 0x401000).unwrap();
        let space = registry.task(registry.root_task()).unwrap().address_space;
        ResumeCensus::new(
            17,
            space,
            0,
            Limits {
                epochs: 8,
                source_fact_bytes: 4096,
                reports: 8,
                origins: 8,
                witnesses: 8,
                plan_history: 8,
            },
        )
        .unwrap()
    }
    fn charge(bytes: usize) -> BudgetCharge {
        BudgetCharge {
            source_fact_bytes: bytes,
            ..BudgetCharge::default()
        }
    }
    fn reserved(census: &mut ResumeCensus, bound: usize, actual: usize) -> ObserverReservation {
        let mut q = ObserverReservation::empty();
        q.started = true;
        q.before = Some(BudgetObservation::of(census));
        q.reservation_bytes = Some(40);
        q.retained_bound = Some(bound);
        q.temporary_bound = Some(40 - bound.min(40));
        let token = census.reserve(charge(40)).unwrap();
        q.reserve = Some(Ok(token));
        q.token = Some(token);
        q.allocation_complete = bound == actual;
        q.measured = Some(Ok(actual));
        q
    }
    fn change(value: &mut BudgetCharge, axis: usize) {
        let field = match axis {
            0 => &mut value.epochs,
            1 => &mut value.source_fact_bytes,
            2 => &mut value.reports,
            3 => &mut value.origins,
            4 => &mut value.witnesses,
            _ => &mut value.plan_history,
        };
        *field += 1;
    }

    #[test]
    fn consumer_oracle_q_finishes_actual_token_before_next_reservation_without_refund() {
        let mut census = census();
        let mut q = reserved(&mut census, 23, 23);
        let token = q.token.unwrap();
        assert_eq!(
            census.reserve(charge(1)),
            Err(CensusError::OutstandingReservation)
        );
        assert!(q.require_finished().is_err());
        q.settle(&mut census).unwrap();
        q.require_finished().unwrap();
        assert_eq!(census.charged().source_fact_bytes, 40);
        assert_eq!(census.used().source_fact_bytes, 23);
        let next = census.reserve(charge(10)).unwrap();
        assert_ne!(next, token);
        census.finish_reservation(next).unwrap();
        assert_eq!(census.charged().source_fact_bytes, 50);
        assert_eq!(census.used().source_fact_bytes, 23);
        assert_eq!(
            census.finish_reservation(token),
            Err(CensusError::StaleReservation)
        );
        let before_repeat = (q.debit, q.finish, q.after, census.charged(), census.used());
        assert!(q.settle(&mut census).is_err());
        assert_eq!(
            (q.debit, q.finish, q.after, census.charged(), census.used()),
            before_repeat
        );
        assert!(q.require_finished().is_err());
    }

    #[test]
    fn consumer_oracle_q_checks_all_six_axes_actual_bytes_and_token_identity() {
        let mut census = census();
        let mut q = reserved(&mut census, 23, 23);
        q.settle(&mut census).unwrap();
        let after = q.after.unwrap();
        for axis in 0..6 {
            change(&mut q.after.as_mut().unwrap().charged, axis);
            assert!(q.require_finished().is_err(), "charged axis {axis}");
            q.after = Some(after);
            change(&mut q.after.as_mut().unwrap().used, axis);
            assert!(q.require_finished().is_err(), "used axis {axis}");
            q.after = Some(after);
        }
        q.measured = Some(Ok(22));
        assert!(q.require_finished().is_err());
        q.measured = Some(Ok(23));
        let original = q.reserve;
        let mut foreign = self::census();
        q.reserve = Some(Ok(foreign.reserve(charge(40)).unwrap()));
        assert!(q.require_finished().is_err());
        q.reserve = original;
        q.before.as_mut().unwrap().charged.source_fact_bytes = usize::MAX;
        assert!(!q.formula_matches());
    }

    #[test]
    fn consumer_oracle_q_settles_every_supplied_installed_prefix_without_completing_it() {
        // These are supplied small exact allocations; component-specific2/16
        // fault controls separately cover the actual observer allocation sites.
        for prefix in 0..=3 {
            let mut buffers: [Vec<u8>; 3] = std::array::from_fn(|_| Vec::new());
            for index in 0..prefix {
                buffers[index] = exact_storage::empty_bytes([3, 5, 9][index]).unwrap();
                buffers[index].extend_from_slice(&[0x5a; 9][..[3, 5, 9][index]]);
            }
            let actual: usize = buffers.iter().map(Vec::capacity).sum();
            let pointers = buffers.each_ref().map(|buffer| buffer.as_ptr());
            let mut census = census();
            let mut q = reserved(&mut census, 17, actual);
            q.allocation_complete = false;
            let settlement = q.settle(&mut census);
            assert!(settlement.is_ok());
            let result = q.propagate(
                Ok(Err(OracleError::Invalid("original allocation"))),
                settlement,
            );
            assert!(matches!(
                result,
                Err(OracleError::Invalid("original allocation"))
            ));
            assert!(q.require_finished().is_err());
            assert_eq!(q.finish, Some(Ok(())));
            assert_eq!(census.charged().source_fact_bytes, 40);
            assert_eq!(census.used().source_fact_bytes, actual);
            assert_eq!(buffers.each_ref().map(|buffer| buffer.as_ptr()), pointers);
            assert!(
                buffers
                    .iter()
                    .all(|buffer| buffer.iter().all(|byte| *byte == 0x5a))
            );
            let next = census.reserve(charge(1)).unwrap();
            census.finish_reservation(next).unwrap();
        }
    }

    #[test]
    fn consumer_oracle_q_preserves_primary_unwind_through_measurement_failure_and_finish() {
        let mut census = census();
        let mut q = reserved(&mut census, 23, 0);
        q.allocation_unwound = true;
        q.measurement_failed = true;
        q.measured = Some(Err(OracleError::Invalid("secondary measurement")));
        let settlement = q.settle(&mut census);
        assert!(settlement.is_err());
        assert_eq!(q.debit, None);
        assert_eq!(q.finish, Some(Ok(())));
        let payload: custody::Unwind = Box::new([0x72_u8; 11]);
        let pointer = (&*payload as *const dyn std::any::Any).cast::<()>();
        let actual = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            q.propagate(Err(payload), settlement)
        }))
        .expect_err("original unwind must propagate");
        assert_eq!((&*actual as *const dyn std::any::Any).cast::<()>(), pointer);
        assert_eq!(actual.downcast_ref::<[u8; 11]>(), Some(&[0x72; 11]));
        assert!(matches!(
            q.measured,
            Some(Err(OracleError::Invalid("secondary measurement")))
        ));
        assert_eq!(census.charged().source_fact_bytes, 40);
        assert_eq!(census.used().source_fact_bytes, 0);
        let next = census.reserve(charge(1)).unwrap();
        census.finish_reservation(next).unwrap();
    }

    #[test]
    fn consumer_oracle_q_finishes_even_when_actual_debit_exceeds_reserved_capacity() {
        let mut census = census();
        let mut q = reserved(&mut census, 41, 41);
        let settlement = q.settle(&mut census);
        assert!(settlement.is_err());
        assert_eq!(q.debit, Some(Err(CensusError::ReservationExhausted)));
        assert_eq!(q.finish, Some(Ok(())));
        assert_eq!(q.formula_checked, Some(false));
        assert!(q.propagate(Ok(Ok(())), settlement).is_err());
        assert_eq!(census.charged().source_fact_bytes, 40);
        assert_eq!(census.used().source_fact_bytes, 0);
        let next = census.reserve(charge(1)).unwrap();
        census.finish_reservation(next).unwrap();
    }
}
