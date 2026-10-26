//! Pre-effect initial reservations before the actual kernel task/mm identity
//! exists. These are resource records, never native or publication authority.
use super::super::super::trusted::{AdmissionPhase, AdmissionStop};
use super::*;

/// Non-Clone startup account. Every reservation survives failures and the
/// successful binding transfers the complete charge into the one live census.
/// Existing control infrastructure is outside source_fact_bytes; retained
/// source, state, copied stop/history and all new evidence buffers remain in it.
pub(in super::super) struct InitialRuntimeReservation {
    limits: Limits,
    charged: BudgetCharge,
    bound: bool,
}

impl InitialRuntimeReservation {
    pub(in super::super) fn new(limits: Limits) -> Result<Self, CensusError> {
        let limits = limits.validate()?;
        let charged = BudgetCharge {
            epochs: 1,
            ..BudgetCharge::default()
        };
        if !charged.fits(limits) {
            return Err(CensusError::Capacity);
        }
        Ok(Self {
            limits,
            charged,
            bound: false,
        })
    }

    /// Reserve before allocating/capturing/mutating the corresponding payload.
    /// This never returns unused capacity to the account, even after refusal.
    pub(in super::super) fn reserve(&mut self, charge: BudgetCharge) -> Result<(), CensusError> {
        if self.bound {
            return Err(CensusError::StaleReservation);
        }
        let next = self.charged.add(charge)?;
        if !next.fits(self.limits) {
            return Err(CensusError::Capacity);
        }
        self.charged = next;
        Ok(())
    }

    #[cfg(test)]
    pub(in super::super) fn charged(&self) -> BudgetCharge {
        self.charged
    }

    /// The caller independently authenticates this current owner-held stop.
    /// These identity comparisons cannot prove a kernel stop or mm exclusion.
    /// No old EXEC token, proposed task identity or replacement-exec seal is
    /// accepted as an initial runtime binding.
    pub(in super::super) fn bind(
        &mut self,
        session: u64,
        stop: &AdmissionStop,
    ) -> Result<(ResumeCensus, Reservation), CensusError> {
        if self.bound {
            return Err(CensusError::StaleReservation);
        }
        if session == 0
            || stop.token.session != session
            || stop.token.task != Some(stop.identity.task)
            || stop.identity.generation != 0
            || stop.signal.is_some()
            || !matches!(
                stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
        {
            return Err(CensusError::IdentityMismatch);
        }
        let mut census = ResumeCensus::new(session, stop.identity.address_space, 0, self.limits)?;
        // ResumeCensus::new already debits the initial epoch. Every other
        // reservation, including unused bytes and any later epoch, transfers
        // unchanged. No whole-object copy is billed a second time on this move.
        let remaining = self.charged.subtract(BudgetCharge {
            epochs: 1,
            ..BudgetCharge::default()
        })?;
        let reservation = census.reserve(remaining)?;
        if census.charged() != self.charged {
            return Err(CensusError::ReservationExhausted);
        }
        self.bound = true;
        Ok((census, reservation))
    }
}

/// Same logical retained-payload formula as insert(CurrentHeldPc). This adds
/// neither an exec witness nor an archived census. Use MAX before first effects.
pub(in super::super) fn initial_runtime_origin_charge(
    xstate_bytes: usize,
) -> Result<BudgetCharge, CensusError> {
    if xstate_bytes == 0 || xstate_bytes > MAX_XSTATE_BYTES {
        return Err(CensusError::InvalidObservation);
    }
    let bytes = std::mem::size_of::<ObservedStop>()
        .checked_add(xstate_bytes)
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StoredOrigin>()))
        .ok_or(CensusError::Capacity)?;
    Ok(BudgetCharge {
        source_fact_bytes: bytes,
        origins: 1,
        ..BudgetCharge::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::LifecycleRegistry;

    fn limits() -> Limits {
        Limits {
            epochs: 8,
            source_fact_bytes: 4 * MAX_XSTATE_BYTES,
            reports: 4,
            origins: 4,
            witnesses: 4,
            plan_history: 4,
        }
    }
    fn model_stop() -> AdmissionStop {
        let registry = LifecycleRegistry::new_after_exec_syscall_exit(
            crate::lifecycle::Limits::default(),
            101,
            0x401000,
        )
        .unwrap();
        let record = registry.task(registry.root_task()).unwrap();
        // Pure descriptive fixture only; no native owner sees this value.
        AdmissionStop {
            token: DynamicStop {
                session: 7,
                sequence: 5,
                tid: 101,
                task: Some(record.id),
            },
            identity: DynamicTask {
                task: record.id,
                process: record.process,
                address_space: record.address_space,
                generation: 0,
            },
            phase: AdmissionPhase::EntryReady,
            signal: None,
        }
    }
    #[test]
    fn initial_runtime_reservation_keeps_all_six_ceilings_and_atomic_refusal() {
        let limit = limits();
        let mut account = InitialRuntimeReservation::new(limit).unwrap();
        let all = BudgetCharge {
            epochs: limit.epochs - 1,
            source_fact_bytes: limit.source_fact_bytes,
            reports: limit.reports,
            origins: limit.origins,
            witnesses: limit.witnesses,
            plan_history: limit.plan_history,
        };
        account.reserve(all).unwrap();
        let full = account.charged();
        for extra in [
            BudgetCharge {
                epochs: 1,
                ..BudgetCharge::default()
            },
            BudgetCharge {
                source_fact_bytes: 1,
                ..BudgetCharge::default()
            },
            BudgetCharge {
                reports: 1,
                ..BudgetCharge::default()
            },
            BudgetCharge {
                origins: 1,
                ..BudgetCharge::default()
            },
            BudgetCharge {
                witnesses: 1,
                ..BudgetCharge::default()
            },
            BudgetCharge {
                plan_history: 1,
                ..BudgetCharge::default()
            },
        ] {
            assert_eq!(account.reserve(extra), Err(CensusError::Capacity));
            assert_eq!(account.charged(), full);
        }
    }
    #[test]
    fn initial_runtime_binding_transfers_unused_charge_once_without_refund() {
        let mut account = InitialRuntimeReservation::new(limits()).unwrap();
        account
            .reserve(BudgetCharge {
                source_fact_bytes: 4096,
                reports: 1,
                origins: 1,
                witnesses: 1,
                plan_history: 1,
                ..BudgetCharge::default()
            })
            .unwrap();
        let before = account.charged();
        let stop = model_stop();
        let (mut census, reservation) = account.bind(7, &stop).unwrap();
        assert_eq!(census.charged(), before);
        assert_eq!(
            census.used(),
            BudgetCharge {
                epochs: 1,
                ..BudgetCharge::default()
            }
        );
        census.finish_reservation(reservation).unwrap();
        assert_eq!(census.charged(), before);
        assert_eq!(account.charged(), before);
        assert!(matches!(
            account.bind(7, &stop),
            Err(CensusError::StaleReservation)
        ));
        assert_eq!(
            account.reserve(BudgetCharge::default()),
            Err(CensusError::StaleReservation)
        );
    }
    #[test]
    fn initial_runtime_binding_rejects_changed_descriptive_identity_without_spending() {
        let mut account = InitialRuntimeReservation::new(limits()).unwrap();
        let stop = model_stop();
        let before = account.charged();
        for change in 0..4 {
            let mut changed = stop.clone();
            match change {
                0 => changed.token.session += 1,
                1 => changed.token.task = None,
                2 => changed.identity.generation += 1,
                3 => changed.phase = AdmissionPhase::Guard,
                _ => unreachable!(),
            }
            assert!(matches!(
                account.bind(7, &changed),
                Err(CensusError::IdentityMismatch)
            ));
            assert_eq!(account.charged(), before);
            assert!(!account.bound);
        }
        assert!(account.bind(7, &stop).is_ok());
    }
    #[test]
    fn initial_runtime_origin_charge_has_no_fake_exec_epoch_or_witness() {
        for n in [512, 832, MAX_XSTATE_BYTES] {
            let expected =
                2 * (std::mem::size_of::<ObservedStop>() + n) + std::mem::size_of::<StoredOrigin>();
            assert_eq!(
                initial_runtime_origin_charge(n).unwrap(),
                BudgetCharge {
                    source_fact_bytes: expected,
                    origins: 1,
                    ..BudgetCharge::default()
                }
            );
        }
        assert_eq!(
            initial_runtime_origin_charge(0),
            Err(CensusError::InvalidObservation)
        );
        assert_eq!(
            initial_runtime_origin_charge(MAX_XSTATE_BYTES + 1),
            Err(CensusError::InvalidObservation)
        );
    }
}
