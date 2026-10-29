//! Closed lifecycle adapter. Both modes use the same loader, caller and Walk.
use super::*;
use rapid_profiler::frontend_native::{
    IntervalEpoch, IntervalEpochStorage, NormalModuleBatch, NormalModuleClient,
    NormalModuleController, NormalModuleHistoryBatch, NormalModuleHistoryStream,
    NormalModuleSessionController, PreparedNormalModuleSessionController,
};

enum Controller {
    Finite(NormalModuleController),
    Session(NormalModuleSessionController),
}
pub(super) struct Candidate {
    controller: Controller,
    banks: Vec<IntervalEpochStorage>,
    published: Option<NormalModuleHistoryBatch>,
    removed: Option<NormalModuleHistoryBatch>,
}
pub(super) fn ready(context: NormalContext<'_>, ready: &Ready) {
    if ready.case.is_session() {
        context.ready_module_session(ready);
    } else {
        context.ready_module(ready);
    }
}
impl Candidate {
    pub(super) fn prepare(
        site: InstalledNormalModuleSite,
        case: native_module::Case,
    ) -> (Self, NormalModuleClient, IntervalEpoch) {
        if case.is_session() {
            assert_eq!(
                case,
                native_module::Case::new_session(
                    case.csv.id() - 1,
                    case.k,
                    case.extents[0],
                    case.extents[1],
                    case.order[0]
                )
            );
            let mut prepared =
                PreparedNormalModuleSessionController::new(site, INSTALL, FUNCTIONS, case.k)
                    .unwrap();
            let mut banks = prepared.prepare_epoch_storage().unwrap();
            assert_eq!(banks.len(), 3);
            // SAFETY: dedicated pristine child, one sequential caller; all module,
            // callback and code owners remain live through final postflight.
            let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
            // On Result refusal restore custody before the fail-stop assertion.
            let epoch = match controller.stage_prepared(banks.pop().unwrap()) {
                Ok(epoch) => epoch,
                Err((error, bank)) => {
                    banks.push(bank);
                    panic!("session stage: {error:?}")
                }
            };
            assert_eq!(banks.len(), 2);
            (
                Self {
                    controller: Controller::Session(controller),
                    banks,
                    published: None,
                    removed: None,
                },
                client,
                epoch,
            )
        } else {
            let mut prepared = PreparedNormalModuleController::new(
                site,
                INSTALL,
                FUNCTIONS,
                Limits {
                    epochs: 1,
                    threads: 1,
                    depth: 1,
                    records_per_epoch: 32,
                    actions: 2,
                },
            )
            .unwrap();
            let epoch = prepared
                .stage(Config {
                    retained_per_function: case.k,
                    max_inflight: 1,
                    max_invocations: 32,
                })
                .unwrap();
            // SAFETY: same actual child, continuous union-wide sequential contract.
            let (controller, client) = unsafe { prepared.activate() }.unwrap();

            (
                Self {
                    controller: Controller::Finite(controller),
                    banks: Vec::new(),
                    published: None,
                    removed: None,
                },
                client,
                epoch,
            )
        }
    }
    pub(super) fn arm(&mut self, epoch: &IntervalEpoch, ready: &Ready) {
        match &mut self.controller {
            Controller::Finite(c) => c.arm(epoch).unwrap(),
            Controller::Session(c) => {
                c.arm(epoch).unwrap();
                let chunk = c
                    .drain_history()
                    .unwrap()
                    .expect("session Published transfer");
                check::session::stream(ready, std::process::id(), &stream(chunk.stream()));
                check::session::chunk(epoch.generation(), true, &facts(&chunk));
                assert_eq!(
                    chunk.binding_at(0),
                    Some(rapid_profiler::frontend::HistoryBinding::Initial)
                );
                assert_eq!(chunk.binding_at(1), Some(chunk.after()));
                assert!(c.drain_history().unwrap().is_none());
                self.published = Some(chunk);
            }
        }
    }
    pub(super) fn batch(&self, ready: &Ready, batch: &NormalModuleBatch) {
        match &self.controller {
            Controller::Finite(_) => {
                assert_eq!(batch.history_stream(), None);
                assert_eq!(batch.history_high_water(), None);
            }
            Controller::Session(_) => {
                let published = self.published.as_ref().unwrap();
                assert_eq!(batch.history_stream(), Some(published.stream()));
                check::session::stream(
                    ready,
                    std::process::id(),
                    &stream(batch.history_stream().unwrap()),
                );
                check::session::watermark(ready, batch.history_high_water());
            }
        }
    }
    pub(super) fn disarm(&mut self, epoch: &IntervalEpoch, ready: &Ready) {
        match &mut self.controller {
            Controller::Finite(c) => c.disarm(epoch).unwrap(),
            Controller::Session(c) => {
                c.disarm(epoch).unwrap();
                let chunk = c
                    .drain_history()
                    .unwrap()
                    .expect("session Removed transfer");
                assert!(chunk.follows(self.published.as_ref().unwrap()));
                check::session::stream(ready, std::process::id(), &stream(chunk.stream()));
                check::session::chunk(epoch.generation(), false, &facts(&chunk));
                assert_eq!(chunk.binding_at(1), Some(chunk.before()));
                assert_eq!(chunk.binding_at(2), Some(chunk.after()));
                assert!(c.drain_history().unwrap().is_none());
                self.removed = Some(chunk);
            }
        }
    }
    pub(super) fn report(&self, epoch: &IntervalEpoch) -> Report {
        match &self.controller {
            Controller::Finite(c) => c.report(epoch),
            Controller::Session(c) => c.report(epoch),
        }
        .unwrap()
        .expect("closed zero-reservation module Report")
    }
    pub(super) fn history(&self, ready: &Ready) {
        let generation = ready.journal.as_ref().unwrap().a_generation;
        match &self.controller {
            Controller::Finite(c) => history(&c.history().unwrap(), &[generation], true),
            Controller::Session(c) => {
                let removed = self.removed.as_ref().unwrap();
                let window = c.history_window().unwrap();
                assert_eq!(window.stream(), removed.stream());
                check::session::stream(ready, std::process::id(), &stream(window.stream()));
                check::session::closed(
                    removed.after(),
                    &check::session::Window {
                        number: window.last_batch_number(),
                        range: window.range(),
                        before: window.before(),
                        after: window.after(),
                        actions: window.actions().to_vec(),
                        status: window.status(),
                        current: window.current(),
                        enabled: window.enabled().to_vec(),
                        failed: window.retained_failed_generation(),
                    },
                );
            }
        }
    }
    pub(super) fn reclaim(&mut self, epoch: IntervalEpoch, ready: &Ready) {
        match &mut self.controller {
            Controller::Finite(_) => drop(epoch),
            Controller::Session(c) => {
                check::session::banks(self.banks.len(), false);
                // Report was fully copied/checked and dropped by the caller; no
                // pending owner remains after its actual final-return checkpoint.
                let bank = match c.reclaim_storage(epoch) {
                    Ok(bank) => bank,
                    Err((error, token)) => {
                        let _retained = token;
                        panic!("session reclaim: {error:?}")
                    }
                };
                self.banks.push(bank);
                check::session::banks(self.banks.len(), true);
                self.history(ready);
            }
        }
    }
}
fn stream(s: &NormalModuleHistoryStream) -> check::session::Stream {
    check::session::Stream {
        pid: s.pid(),
        install: s.install(),
        identity: s.identity(),
        functions: *s.functions(),
        entries: *s.entries(),
        format: s.format(),
    }
}
fn facts(c: &NormalModuleHistoryBatch) -> check::session::Chunk {
    check::session::Chunk {
        number: c.number(),
        range: c.range(),
        before: c.before(),
        after: c.after(),
        actions: c.actions().to_vec(),
    }
}

#[derive(Clone, Copy)]
pub(super) enum Run {
    Finite(Arguments),
    Session(native_module::SessionArguments),
}
impl Run {
    pub(super) fn is_session(self) -> bool {
        matches!(self, Self::Session(_))
    }
    pub(super) fn fields(
        self,
    ) -> (
        usize,
        native::csv::Arguments,
        oracle::native_ordinary::strnlen::Arguments,
    ) {
        match self {
            Self::Finite(a) => (a.k, a.csv, a.length),
            Self::Session(a) => (a.k, a.csv, a.length),
        }
    }
    pub(super) fn case(self, index: usize) -> native_module::Case {
        match self {
            Self::Finite(a) => a.case(index),
            Self::Session(a) => a.case(index),
        }
    }
    pub(super) fn oracle(
        self,
        seed: u64,
        case: native_module::Case,
        deadline: Deadline,
    ) -> NormalOracle {
        match self {
            Self::Finite(_) => NormalOracle::new_module(seed, case, deadline),
            Self::Session(_) => NormalOracle::new_module_session(seed, case, deadline),
        }
    }
    pub(super) fn pair<F>(
        self,
        oracle: &NormalOracle,
        setup: F,
    ) -> (native::NormalPairResult<4>, native_module::Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        match self {
            Self::Finite(_) => oracle.pair_module(setup),
            Self::Session(_) => oracle.pair_module_session(setup),
        }
    }
    pub(super) fn population(self) -> Accumulator {
        match self {
            Self::Finite(_) => Accumulator::Finite(ModulePopulation::default()),
            Self::Session(_) => Accumulator::Session(native_module::SessionPopulation::default()),
        }
    }
    pub(super) fn files(self) -> (&'static str, &'static str) {
        match self {
            Self::Finite(_) => ("normal-module-pairs.csv", "normal-module-coverage.csv"),
            Self::Session(_) => (
                "normal-module-session-pairs.csv",
                "normal-module-session-coverage.csv",
            ),
        }
    }
}
pub(super) enum Accumulator {
    Finite(ModulePopulation),
    Session(native_module::SessionPopulation),
}
impl Accumulator {
    pub(super) fn record(
        &mut self,
        seed: u64,
        case: native_module::Case,
        pair: &native::NormalPairResult<4>,
        trace: &native_module::Trace,
    ) -> Option<native_module::Coverage> {
        match self {
            Self::Finite(p) => p.record(seed, case, pair, trace),
            Self::Session(p) => p.record(seed, case, pair, trace),
        }
    }
    pub(super) fn finish(self) -> usize {
        match self {
            Self::Finite(p) => p.finish(),
            Self::Session(p) => p.finish(),
        }
    }
}
pub(crate) fn run(
    subject: &Path,
    expected: &Path,
    arguments: native_module::SessionArguments,
    caller_path: &Path,
    caller_expected: &Path,
    output: &Path,
    deadline: Deadline,
) {
    super::run_profile(
        subject,
        expected,
        Run::Session(arguments),
        caller_path,
        caller_expected,
        output,
        deadline,
    )
}
