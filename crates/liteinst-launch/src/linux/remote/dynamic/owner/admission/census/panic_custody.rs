//! Read-only test descriptions. No census/account/permit is cloned or rebuilt.
use super::*;
type Check = Box<dyn Fn(&ResumeCensus)>;
impl ResumeCensus {
    pub(in super::super) fn panic_prefix_check(&self) -> Check {
        let identity = (self.identity, self.session, self.space, self.limits);
        let state = self.state.clone();
        let history = self.history_snapshot().unwrap();
        assert!(state.reservation.is_none());
        Box::new(move |actual| {
            assert_eq!(
                (actual.identity, actual.session, actual.space, actual.limits),
                identity
            );
            assert_eq!(actual.state.generation, state.generation);
            assert_eq!(
                actual.state.next_serial,
                state.next_serial.checked_add(1).unwrap()
            );
            let (reservation, _) = actual
                .state
                .reservation
                .expect("original unfinished reservation");
            assert_eq!(
                reservation,
                Reservation {
                    census: identity.0,
                    serial: state.next_serial
                }
            );
            assert!(actual.state.history.len() >= state.history.len());
            assert_eq!(&actual.state.history[..state.history.len()], state.history);
            assert_eq!(
                actual.history_snapshot_prefix(history.len()).unwrap(),
                history
            );
            let mut expected = state.origins.clone();
            let added = &actual.state.history[state.history.len()..];
            assert!(
                !added.is_empty(),
                "actual source restoration refresh was retained"
            );
            for row in added {
                actual.history_view(row).unwrap();
                let HistoryRecord::Refreshed {
                    origin,
                    before,
                    after,
                } = row
                else {
                    panic!("unbridged EXIT must not consume an origin or rebind an epoch")
                };
                let retained = expected
                    .iter_mut()
                    .find(|item| item.row.id == *origin)
                    .unwrap();
                assert!(retained.active);
                assert!(retained.frame.is_none());
                assert_eq!(&retained.current, before);
                assert_eq!(
                    (
                        after.task,
                        after.logical_pc,
                        after.registers,
                        &after.xstate,
                        after.signal_mask
                    ),
                    (
                        before.task,
                        before.logical_pc,
                        before.registers,
                        &before.xstate,
                        before.signal_mask
                    )
                );
                assert_eq!(
                    (after.token.session, after.token.tid, after.phase),
                    (before.token.session, before.token.tid, before.phase)
                );
                assert!(after.token.sequence > before.token.sequence);
                assert_eq!(after.token.task, before.token.task);
                assert_eq!(after.signal, before.signal);
                assert!(exact_refresh(before, after));
                // Detached data-only corruptions use the same full comparator;
                // neither altered description can reach a native/census owner.
                assert_eq!(after.token.task, Some(after.task.task));
                assert!(after.signal.is_none());
                let mut changed = after.clone();
                changed.token.task = None;
                assert!(!exact_refresh(before, &changed));
                let mut changed = after.clone();
                changed.signal = Some(DynamicSignalInfo { raw: [0; 128] });
                assert!(!exact_refresh(before, &changed));
                retained.current = after.clone();
            }
            assert_eq!(actual.state.origins, expected);
            assert_eq!(
                actual.state.used.witnesses,
                state.used.witnesses.checked_add(added.len()).unwrap()
            );
            for (before, after) in [
                (state.charged, actual.state.charged),
                (state.used, actual.state.used),
            ] {
                assert!(
                    after.epochs >= before.epochs
                        && after.source_fact_bytes >= before.source_fact_bytes
                        && after.reports >= before.reports
                        && after.origins >= before.origins
                        && after.witnesses >= before.witnesses
                        && after.plan_history >= before.plan_history
                );
            }
            assert_eq!(
                (
                    actual.state.used.epochs,
                    actual.state.used.reports,
                    actual.state.used.origins,
                    actual.state.used.plan_history
                ),
                (
                    state.used.epochs,
                    state.used.reports,
                    state.used.origins,
                    state.used.plan_history
                )
            );
            assert!(actual.state.used.source_fact_bytes > state.used.source_fact_bytes);
        })
    }
    pub(in super::super) fn panic_exact_check(&self) -> Check {
        let identity = (self.identity, self.session, self.space, self.limits);
        let state = self.state.clone();
        let history = self.history_snapshot().unwrap();
        let allocations = (
            self.state.origins.as_ptr() as usize,
            self.state.origins.capacity(),
            self.state.history.as_ptr() as usize,
            self.state.history.capacity(),
        );
        Box::new(move |actual| {
            assert_eq!(
                (actual.identity, actual.session, actual.space, actual.limits),
                identity
            );
            assert_eq!(actual.state, state);
            assert_eq!(actual.history_snapshot().unwrap(), history);
            assert_eq!(
                (
                    actual.state.origins.as_ptr() as usize,
                    actual.state.origins.capacity(),
                    actual.state.history.as_ptr() as usize,
                    actual.state.history.capacity()
                ),
                allocations
            );
        })
    }
}

// This finite private restoration changes only the actual stop sequence.
// Full Eq also binds token.task and every byte of optional signal metadata.
fn exact_refresh(before: &ObservedStop, after: &ObservedStop) -> bool {
    let mut expected = before.clone();
    expected.token.sequence = after.token.sequence;
    after.token.sequence > before.token.sequence && expected == *after
}
