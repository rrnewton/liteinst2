//! Test-only exact old-row retention and one-account replacement inspection.
use super::super::super::exec::oracle::{InspectionField, inspect};
use super::*;
pub(in crate::linux::remote::dynamic::owner::admission) type RetirementCheck =
    Box<dyn Fn(&RetiredCensus, &ResumeCensus, &ObservedStop)>;

impl ResumeCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn exec_oracle_check(
        &self,
    ) -> RetirementCheck {
        let identity = self.identity;
        let session = self.session;
        let space = self.space;
        let limits = self.limits;
        let state = self.state.clone();
        let history = self.history_snapshot().unwrap();
        let allocations = (
            self.state.origins.as_ptr() as usize,
            self.state.origins.capacity(),
            self.state.history.as_ptr() as usize,
            self.state.history.capacity(),
        );
        Box::new(move |retired, live, initial| {
            let retired_history = retired.history_snapshot().unwrap();
            assert_eq!(retired_history, history);
            assert_eq!(retired.retirement.binding.census, identity);
            assert_eq!(
                (
                    retired.retirement.binding.session,
                    retired.retirement.binding.space,
                    retired.retirement.binding.generation
                ),
                (session, space, state.generation)
            );
            inspect(
                InspectionField::CensusOrigins,
                &state.origins,
                &retired.origins,
            )
            .unwrap();
            inspect(
                InspectionField::CensusHistory,
                &state.history,
                &retired.history,
            )
            .unwrap();
            assert!(!retired.origins.is_empty() && !retired.history.is_empty());
            for field in 0..3 {
                let mut changed = retired.origins.clone();
                match field {
                    0 => changed[0].active = !changed[0].active,
                    1 => changed[0].current.registers.eflags ^= 1,
                    2 => changed[0].current.xstate[0] ^= 1,
                    _ => unreachable!(),
                }
                assert_eq!(
                    inspect(InspectionField::CensusOrigins, &state.origins, &changed),
                    Err(InspectionField::CensusOrigins)
                );
            }
            let mut changed = retired_history.rows().to_vec();
            changed.pop();
            assert_eq!(
                inspect(
                    InspectionField::CensusHistory,
                    history.rows(),
                    changed.as_slice()
                ),
                Err(InspectionField::CensusHistory)
            );
            let mut changed = retired_history.rows().to_vec();
            let after = changed
                .iter_mut()
                .find_map(|row| match row {
                    HistoryRecord::Refreshed { after, .. } => Some(after),
                    _ => None,
                })
                .expect("actual native refresh history");
            after.registers.rax ^= 1;
            assert_eq!(
                inspect(
                    InspectionField::CensusHistory,
                    history.rows(),
                    changed.as_slice()
                ),
                Err(InspectionField::CensusHistory)
            );
            assert_eq!(
                (
                    retired.origins.as_ptr() as usize,
                    retired.origins.capacity(),
                    retired.history.as_ptr() as usize,
                    retired.history.capacity()
                ),
                allocations
            );
            budget(
                InspectionField::Charged,
                state.charged,
                retired.charged_at_retirement,
            );
            budget(
                InspectionField::Used,
                state.used,
                retired.used_at_retirement,
            );
            assert_eq!(retired.retirement.new_stop, initial.token);
            assert_eq!(retired.retirement.new_task, initial.task);
            let old = state
                .origins
                .iter()
                .find(|origin| origin.row.id == retired.retirement.binding.origin)
                .unwrap();
            assert!(old.active);
            assert_eq!(retired.retirement.old_stop, old.current.token);
            let (reservation, remaining) = state.reservation.unwrap();
            assert_eq!(retired.retirement.binding.reservation, reservation);
            assert_ne!(live.identity, identity);
            assert_eq!(live.session, session);
            assert_eq!(live.space, initial.task.address_space);
            assert_ne!(live.space, space);
            assert_eq!(live.limits, limits);
            assert_eq!(live.state.generation, 0);
            assert_eq!(live.state.next_serial, 3);
            budget(InspectionField::Charged, state.charged, live.state.charged);
            let charge = exec_initial_charge(initial.xstate.len()).unwrap();
            budget(
                InspectionField::Used,
                state.used.add(charge).unwrap(),
                live.state.used,
            );
            let (current, left) = live.state.reservation.unwrap();
            assert_eq!(
                current,
                Reservation {
                    census: live.identity,
                    serial: 1
                }
            );
            assert_eq!(left, remaining.subtract(charge).unwrap());
            assert_eq!(live.state.origins.len(), 1);
            assert!(live.state.history.is_empty());
            let added = &live.state.origins[0];
            assert_eq!(
                added.row.id,
                OriginId {
                    census: live.identity,
                    serial: 2
                }
            );
            assert_eq!(added.row.kind, OriginKind::CurrentHeldPc);
            assert_eq!(
                (added.row.pc, added.row.created_generation),
                (initial.logical_pc, 0)
            );
            assert_eq!(&added.row.initial, initial);
            assert_eq!(&added.current, initial);
            assert!(added.active);
            assert!(added.frame.is_none());
            let unchanged = live.state.clone();
            assert_eq!(
                live.check_reserved(reservation, BudgetCharge::default()),
                Err(CensusError::StaleReservation)
            );
            assert_eq!(
                live.check_current_origin(old.row.id, &old.current),
                Err(CensusError::UnknownOrigin)
            );
            assert_eq!(live.state, unchanged);
        })
    }
}

fn budget(field: InspectionField, expected: BudgetCharge, actual: BudgetCharge) {
    inspect(field, &expected, &actual).unwrap();
    // These are plain copied counts, never a second census or reservation.
    for index in 0..6 {
        let mut changed = actual;
        let value = match index {
            0 => &mut changed.epochs,
            1 => &mut changed.source_fact_bytes,
            2 => &mut changed.reports,
            3 => &mut changed.origins,
            4 => &mut changed.witnesses,
            5 => &mut changed.plan_history,
            _ => unreachable!(),
        };
        *value = value.checked_add(1).unwrap();
        assert_eq!(inspect(field, &expected, &changed), Err(field));
    }
}
