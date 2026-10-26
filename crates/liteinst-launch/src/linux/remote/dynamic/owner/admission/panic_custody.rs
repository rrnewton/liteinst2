//! Existing getpid-panic fixture: retained ownership, never new release proof.
use super::*;
type Check = Box<dyn Fn(&AdmissionOwner)>;
type UnwindCheck = Box<dyn Fn(&AdmissionOwner) -> Check>;
impl AdmissionOwner {
    pub(in super::super) fn panic_custody_check(&self) -> UnwindCheck {
        let domain = self.domain.panic_custody_check();
        let census = self.census.panic_prefix_check();
        let stable = self.panic_stable_check();
        assert!(self.pending.is_some());
        Box::new(move |actual| {
            domain(&actual.domain);
            census(&actual.census);
            stable(actual);
            // The in-flight local is consumed, but its journal retains the
            // exact input. It must not become a second resumable provider slot.
            assert!(actual.pending.is_none());
            let domain = actual.domain.panic_custody_check();
            let census = actual.census.panic_exact_check();
            let stable = actual.panic_stable_check();
            let native = actual.native.admission_snapshot();
            let closed = actual.closed;
            Box::new(move |after_cleanup| {
                domain(&after_cleanup.domain);
                census(&after_cleanup.census);
                stable(after_cleanup);
                assert_eq!(after_cleanup.native.admission_snapshot(), native);
                assert!(after_cleanup.pending.is_none());
                assert_eq!(after_cleanup.closed, closed);
            })
        })
    }
    fn panic_stable_check(&self) -> Check {
        assert!(self.signals.is_none() && self.mapping.is_none() && self.exec.is_none());
        assert!(self.completion_history.is_empty() && self.running.is_empty());
        let island = (
            self.island.address_space,
            self.island.generation,
            self.island.range.clone(),
            self.island.page_size,
        );
        let bootstrap = (
            self.bootstrap.exec_event.clone(),
            self.bootstrap.exec_exit.clone(),
            self.bootstrap.entry_trap.clone(),
            self.bootstrap.restored_entry.clone(),
        );
        let origins = self.origins.clone();
        let ready = self.ready.clone();
        let work = self.work.iter().map(work_key).collect::<Vec<_>>();
        let diagnostics = self.diagnostics.clone();
        let lifecycle = self.lifecycle_history.clone();
        let serial = self.next_execution;
        let creation = self.creation;
        let metrics = self.metrics.clone();
        Box::new(move |actual| {
            assert!(actual.signals.is_none() && actual.mapping.is_none() && actual.exec.is_none());
            assert!(actual.completion_history.is_empty() && actual.running.is_empty());
            assert_eq!(
                (
                    actual.island.address_space,
                    actual.island.generation,
                    actual.island.range.clone(),
                    actual.island.page_size
                ),
                island
            );
            assert_eq!(
                (
                    &actual.bootstrap.exec_event,
                    &actual.bootstrap.exec_exit,
                    &actual.bootstrap.entry_trap,
                    &actual.bootstrap.restored_entry
                ),
                (&bootstrap.0, &bootstrap.1, &bootstrap.2, &bootstrap.3)
            );
            assert_eq!(actual.origins, origins);
            assert_eq!(actual.ready, ready);
            assert_eq!(actual.work.iter().map(work_key).collect::<Vec<_>>(), work);
            assert_eq!(actual.diagnostics, diagnostics);
            assert_eq!(actual.lifecycle_history, lifecycle);
            assert_eq!(actual.next_execution, serial);
            assert_eq!(actual.creation, creation);
            metrics_equal(&actual.metrics, &metrics);
        })
    }
}
fn work_key(work: &PendingWork) -> (bool, TaskId, u64) {
    match *work {
        PendingWork::Fetch { task, page } => (false, task, page),
        PendingWork::Guard { task, pc } => (true, task, pc),
    }
}

fn metrics_equal(actual: &DynamicAdmissionMetrics, expected: &DynamicAdmissionMetrics) {
    let a = &actual.pages;
    let e = &expected.pages;
    assert_eq!(
        (
            a.startup,
            &a.first_touch,
            a.admitted_pages,
            a.untouched_pages,
            a.observations,
            a.covered_candidates,
            a.collateral_guards,
            a.collateral_completions
        ),
        (
            e.startup,
            &e.first_touch,
            e.admitted_pages,
            e.untouched_pages,
            e.observations,
            e.covered_candidates,
            e.collateral_guards,
            e.collateral_completions
        )
    );
    let a = &actual.selected;
    let e = &expected.selected;
    assert_eq!(
        (
            &a.callbacks,
            a.native_completions,
            a.scripted_completions,
            a.provider_faults,
            a.native_signals,
            a.refusals
        ),
        (
            &e.callbacks,
            e.native_completions,
            e.scripted_completions,
            e.provider_faults,
            e.native_signals,
            e.refusals
        )
    );
    for (a, e) in [
        (&actual.oracle.preparation, &expected.oracle.preparation),
        (&actual.oracle.demand, &expected.oracle.demand),
    ] {
        assert_eq!(
            (
                a.inspections,
                a.hits,
                a.runtime_scans,
                a.no_entry,
                a.stale,
                a.corrupt,
                a.refused,
                a.decoded_starts
            ),
            (
                e.inspections,
                e.hits,
                e.runtime_scans,
                e.no_entry,
                e.stale,
                e.corrupt,
                e.refused,
                e.decoded_starts
            )
        );
        assert_eq!(
            (
                a.lookup_elapsed,
                a.fresh_scan_elapsed,
                a.store_elapsed,
                a.saturated
            ),
            (
                e.lookup_elapsed,
                e.fresh_scan_elapsed,
                e.store_elapsed,
                e.saturated
            )
        );
    }
    assert_eq!(
        (
            actual.resource_scan_decoded_starts,
            actual.retained_origins,
            actual.continuation_history_records,
            actual.retained_call_obligations,
            actual.oldest_call_generation,
            actual.charged_source_bytes,
            actual.retained_source_bytes
        ),
        (
            expected.resource_scan_decoded_starts,
            expected.retained_origins,
            expected.continuation_history_records,
            expected.retained_call_obligations,
            expected.oldest_call_generation,
            expected.charged_source_bytes,
            expected.retained_source_bytes
        )
    );
    assert_eq!(
        (
            actual.bootstrap_xstate_bytes,
            actual.fetch_faults,
            actual.guard_stops,
            actual.generation_changes
        ),
        (
            expected.bootstrap_xstate_bytes,
            expected.fetch_faults,
            expected.guard_stops,
            expected.generation_changes
        )
    );
}
