//! Read-only test descriptions. No census/account/permit is cloned or rebuilt.
use super::*;
type Check = Box<dyn Fn(&ResumeCensus)>;
impl ResumeCensus {
    pub(in super::super) fn panic_prefix_check(&self) -> Check {
        let identity = (self.identity, self.session, self.space, self.limits);
        let state = self.state.clone();
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
            let mut expected = state.origins.clone();
            let added = &actual.state.history[state.history.len()..];
            assert!(
                !added.is_empty(),
                "actual source restoration refresh was retained"
            );
            for row in added {
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
