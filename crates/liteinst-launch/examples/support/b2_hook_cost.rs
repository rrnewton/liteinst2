//! Validation-interleaved finite measurements. No new production execution backend.
use liteinst_admission::scan::{Policy, SiteClass};
use liteinst_launch::gate::{
    GateMetrics, GateOracleMetrics, ImageFacts, OraclePhaseMetrics, SelectedCompletion,
    SelectedEvent, SelectedExecution, SelectedMetrics, SelectedPageGate,
};
use liteinst_launch::selected::{
    InstructionProvider, ProviderDecision, SelectedInput, SelectedResult, SemanticsError,
    SyscallAliases, SyscallResult,
};
use liteinst_launch::{
    DynamicAdmissionBackend, DynamicAdmissionCompletion, DynamicAdmissionEvent,
    DynamicAdmissionMetrics, DynamicAdmissionOptions, DynamicAdmissionSession, ExecCheckpoint,
    LaunchCommand, RegisterSnapshot,
};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::os::fd::OwnedFd;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
const TIMEOUT: Duration = Duration::from_secs(3);
const STEP_BUDGET: usize = 128;
static FILE_FORK: Mutex<()> = Mutex::new(());
const PREFIX: &str = "LITEINST_EVALUATION_B2_HOOK_COST:";
#[path = "../../tests/support/b2_reference/cases.rs"]
mod cases;
#[path = "../../tests/support/b2_reference/checks.rs"]
mod checks;
#[path = "../../tests/support/b2_reference/image.rs"]
mod image;
#[path = "../../tests/support/b2_reference/model.rs"]
mod model;
#[path = "../../tests/support/b2_reference/raw.rs"]
mod raw;
use checks::{Replay, check_completion, check_metrics, rethrow};
use image::{BASE, Builder, DATA, DATA_LEN, FLAGS, Fixture, MASK, PAGE, STACK};
use model::{Reply, Row, State, Trace};

fn ns(value: Duration) -> u64 {
    u64::try_from(value.as_nanos()).expect("bounded duration must fit u64 nanoseconds")
}
fn classes() -> [SiteClass; 7] {
    [
        SiteClass::Cpuid,
        SiteClass::Rdrand,
        SiteClass::Rdseed,
        SiteClass::Rdpid,
        SiteClass::Rdtsc,
        SiteClass::Rdtscp,
        SiteClass::Syscall,
    ]
}
fn class_name(class: SiteClass) -> &'static str {
    match class {
        SiteClass::Cpuid => "cpuid",
        SiteClass::Rdrand => "rdrand",
        SiteClass::Rdseed => "rdseed",
        SiteClass::Rdpid => "rdpid",
        SiteClass::Rdtsc => "rdtsc",
        SiteClass::Rdtscp => "rdtscp",
        SiteClass::Syscall => "syscall",
    }
}
#[derive(Clone, Copy)]
enum Lane {
    Static,
    Dynamic,
}
impl Lane {
    fn name(self) -> &'static str {
        match self {
            Self::Static => "static_trap",
            Self::Dynamic => "dynamic_page",
        }
    }
}
#[derive(Clone, Copy)]
struct Identity {
    fixture: &'static str,
    phase: &'static str,
    pair_index: usize,
    round: usize,
    order_index: usize,
    lane: Lane,
}
impl Identity {
    fn fields(self, out: &mut String) {
        write!(out, "\"fixture\":\"{}\",\"phase\":\"{}\",\"pair_index\":{},\"round\":{},\"order_index\":{},\"lane\":\"{}\"",
            self.fixture, self.phase, self.pair_index, self.round, self.order_index, self.lane.name()).unwrap();
    }
}
#[derive(Default)]
struct Timing {
    start: Cell<Option<Instant>>,
    provider_entry: Cell<Option<Instant>>,
    provider_exit: Cell<Option<Instant>>,
    end: Cell<Option<Instant>>,
    calls: Cell<usize>,
}
impl Timing {
    fn reset(&self) {
        self.start.set(None);
        self.provider_entry.set(None);
        self.provider_exit.set(None);
        self.end.set(None);
        self.calls.set(0);
    }
    fn complete(&self) -> Span {
        assert_eq!(self.calls.get(), 1);
        let t0 = self.start.get().unwrap();
        let t1 = self.provider_entry.get().unwrap();
        let t2 = self.provider_exit.get().unwrap();
        let t3 = self.end.get().unwrap();
        assert!(t0 <= t1 && t1 <= t2 && t2 <= t3);
        let span = Span {
            completion: ns(t3.duration_since(t0)),
            before: ns(t1.duration_since(t0)),
            provider: ns(t2.duration_since(t1)),
            after: ns(t3.duration_since(t2)),
        };
        assert_eq!(
            span.completion,
            span.before
                .checked_add(span.provider)
                .unwrap()
                .checked_add(span.after)
                .unwrap()
        );
        span
    }
}
struct TimedReplay {
    inner: Replay,
    timing: Rc<Timing>,
}
impl InstructionProvider for TimedReplay {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        let entered = Instant::now();
        assert_eq!(
            self.timing.calls.get(),
            0,
            "one provider per completion interval"
        );
        self.timing.provider_entry.set(Some(entered));
        self.timing.calls.set(1);
        let decision = self.inner.decide(input);
        self.timing.provider_exit.set(Some(Instant::now()));
        decision
    }
}
#[derive(Clone, Copy)]
struct Span {
    completion: u64,
    before: u64,
    provider: u64,
    after: u64,
}
struct Snapshot {
    pages: GateMetrics,
    selected: SelectedMetrics,
    oracle: GateOracleMetrics,
    dynamic: Option<DynamicAdmissionMetrics>,
}
enum Gate {
    Static(Box<SelectedPageGate<TimedReplay>>),
    Dynamic(Box<DynamicAdmissionSession<TimedReplay>>),
}
enum Completion {
    Static(Box<SelectedCompletion>),
    Dynamic(Box<DynamicAdmissionCompletion>),
}
impl Gate {
    fn launch(lane: Lane, case: &cases::Case, provider: TimedReplay) -> Self {
        let fixture = &case.fixture;
        match lane {
            Lane::Static => {
                let checkpoint = {
                    let _fork = FILE_FORK.lock().unwrap();
                    let _mask = raw::MaskGuard::new();
                    ExecCheckpoint::launch(&LaunchCommand::new(&fixture.path), TIMEOUT).unwrap()
                };
                // SAFETY: exact same fixed immutable ELF, complete head census,
                // private source/data, scripted-only selected effects and sole
                // owner as the shared correctness fixture. No handler/writer,
                // alias, competing waiter or private island entry exists.
                let gate = unsafe {
                    if case.covered {
                        SelectedPageGate::new_with_coverage(
                            checkpoint,
                            vec![fixture.facts()],
                            Policy::default(),
                            SyscallAliases::new(),
                            provider,
                            TIMEOUT,
                            Default::default(),
                        )
                    } else {
                        SelectedPageGate::new(
                            checkpoint,
                            vec![fixture.facts()],
                            Policy::default(),
                            SyscallAliases::new(),
                            provider,
                            TIMEOUT,
                        )
                    }
                }
                .unwrap();
                Self::Static(Box::new(gate))
            }
            Lane::Dynamic => {
                let options = DynamicAdmissionOptions {
                    backend: if case.covered {
                        DynamicAdmissionBackend::CoverageTrap(Default::default())
                    } else {
                        DynamicAdmissionBackend::StrictTrap
                    },
                    ..Default::default()
                };
                let _fork = FILE_FORK.lock().unwrap();
                let _mask = raw::MaskGuard::new();
                // SAFETY: same finite source/head and memory facts as above.
                // All original selected effects are scripted. The actual owner
                // retains CALL obligations, generations and publication checks.
                let gate = unsafe {
                    DynamicAdmissionSession::launch(
                        &LaunchCommand::new(&fixture.path),
                        vec![fixture.facts()],
                        options,
                        provider,
                        TIMEOUT,
                    )
                }
                .unwrap();
                Self::Dynamic(Box::new(gate))
            }
        }
    }
    fn pid(&self) -> i32 {
        match self {
            Self::Static(g) => g.pid(),
            Self::Dynamic(g) => g.pid(),
        }
    }
    fn initial_source(&mut self, fixture: &Fixture) -> Vec<u8> {
        match self {
            Self::Static(g) => g.read_memory(BASE, fixture.bytes.len()).unwrap(),
            Self::Dynamic(g) => g
                .read_memory(g.initial_state().task.task, BASE, fixture.bytes.len())
                .unwrap(),
        }
    }
    fn next(&mut self) -> Completion {
        match self {
            Self::Static(g) => {
                let SelectedEvent::Completed(done) = g.next_event().unwrap() else {
                    panic!("static lane did not complete the exact scripted invocation");
                };
                Completion::Static(done)
            }
            Self::Dynamic(g) => {
                let DynamicAdmissionEvent::Completed(done) = g.next_event().unwrap() else {
                    panic!("dynamic lane did not complete the exact scripted invocation");
                };
                Completion::Dynamic(done)
            }
        }
    }
    fn check_and_state(&mut self, done: &Completion, expected: &Row, pin: &OwnedFd) -> State {
        match (self, done) {
            (Self::Static(g), Completion::Static(done)) => {
                check_completion(done, expected);
                State {
                    registers: g.read_registers().unwrap(),
                    xstate: g.read_xstate().unwrap(),
                    mask: raw::held_mask(g.pid(), pin),
                    data: g.read_memory(DATA, DATA_LEN).unwrap(),
                }
            }
            (Self::Dynamic(g), Completion::Dynamic(done)) => {
                check_completion(&done.selected, expected);
                assert_eq!(done.before_signal_mask, expected.before.mask);
                assert_eq!(done.signal_mask, expected.after.mask);
                let held = g.state(done.after_task.task).unwrap();
                State {
                    registers: held.registers,
                    xstate: held.xstate,
                    mask: held.signal_mask,
                    data: g.read_memory(done.after_task.task, DATA, DATA_LEN).unwrap(),
                }
            }
            _ => panic!("completion belongs to another lane"),
        }
    }
    fn metrics(&mut self) -> Snapshot {
        match self {
            Self::Static(g) => Snapshot {
                pages: g.gate_metrics().clone(),
                selected: g.metrics().clone(),
                oracle: g.oracle_metrics(),
                dynamic: None,
            },
            Self::Dynamic(g) => {
                let m = g.metrics().unwrap();
                Snapshot {
                    pages: m.pages.clone(),
                    selected: m.selected.clone(),
                    oracle: m.oracle.clone(),
                    dynamic: Some(m),
                }
            }
        }
    }
    fn calls(&self) -> usize {
        match self {
            Self::Static(g) => g.provider().inner.calls,
            Self::Dynamic(g) => g.provider().inner.calls,
        }
    }
    fn finish(self, pin: &OwnedFd) {
        match self {
            Self::Static(g) => {
                drop(g);
                raw::reaped(pin);
            }
            Self::Dynamic(g) => {
                let pid = g.pid();
                let cleaned = (*g).terminate(TIMEOUT);
                raw::reaped(pin);
                assert_eq!(cleaned.unwrap().reaped, [pid]);
            }
        }
    }
}
struct RowRecord {
    ordinal: usize,
    class: SiteClass,
    site_offset: u64,
    encoding: String,
    script_id: String,
    span: Span,
    validation_ns: u64,
    before: Snapshot,
    after: Snapshot,
}
struct SessionRecord {
    identity: Identity,
    covered: bool,
    collateral: usize,
    launch_total_ns: u64,
    validation_ns: u64,
    cleanup_ns: u64,
    rows: Vec<RowRecord>,
    states: Vec<State>,
}
struct PendingSession {
    covered: bool,
    launch_total_ns: u64,
    validation_ns: u64,
    cleanup_ns: Option<u64>,
    rows: Vec<RowRecord>,
}
struct Progress {
    identity: Option<Identity>,
    ordinal: Option<usize>,
    stage: &'static str,
    timing: Rc<Timing>,
    pending: Option<PendingSession>,
    cleanup: bool,
    emitted_sessions: usize,
    emitted_completions: usize,
}
impl Progress {
    fn new() -> Self {
        Self {
            identity: None,
            ordinal: None,
            stage: "arguments",
            timing: Rc::new(Timing::default()),
            pending: None,
            cleanup: false,
            emitted_sessions: 0,
            emitted_completions: 0,
        }
    }
}
fn reference(case: &cases::Case, progress: &mut Progress) -> Trace {
    progress.stage = "raw_reference";
    progress.cleanup = false;
    progress.ordinal = None;
    progress.timing.reset();
    let mut native = raw::Raw::launch(&case.fixture);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let initial = native.state();
        let expected =
            model::interpret(&case.fixture, initial, &case.replies, STEP_BUDGET).unwrap();
        let observed = native
            .run(&case.fixture, &case.replies, STEP_BUDGET)
            .unwrap();
        assert_eq!(
            observed, expected,
            "ordinary block execution and interception order"
        );
        case.check_trace(&expected);
        expected
    }));
    native.finish();
    progress.cleanup = true;
    rethrow(result)
}
fn session(
    case: &cases::Case,
    expected: &Trace,
    identity: Identity,
    progress: &mut Progress,
) -> SessionRecord {
    assert!(expected.rows.len() <= 4);
    progress.identity = Some(identity);
    progress.ordinal = None;
    progress.stage = "launch";
    progress.cleanup = false;
    progress.timing = Rc::new(Timing::default());
    let timing = Rc::clone(&progress.timing);
    let provider = TimedReplay {
        inner: Replay::new(&expected.rows),
        timing: Rc::clone(&timing),
    };
    let rows = Vec::with_capacity(4);
    let mut states = Vec::with_capacity(4);
    let launch_start = Instant::now();
    let mut gate = Gate::launch(identity.lane, case, provider);
    let launch_total_ns = ns(launch_start.elapsed());
    progress.pending = Some(PendingSession {
        covered: case.covered,
        launch_total_ns,
        validation_ns: 0,
        cleanup_ns: None,
        rows,
    });
    let pin = raw::pin(gate.pid());
    let mut validation_ns = 0_u64;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        progress.stage = "validation";
        let started = Instant::now();
        assert_eq!(gate.initial_source(&case.fixture), case.fixture.bytes);
        raw::nx(gate.pid(), &pin, BASE + PAGE as u64);
        validation_ns = validation_ns.checked_add(ns(started.elapsed())).unwrap();
        for (ordinal, expected_row) in expected.rows.iter().enumerate() {
            progress.ordinal = Some(ordinal);
            progress.stage = "validation";
            timing.reset();
            let validation_start = Instant::now();
            let before = gate.metrics();
            assert_eq!(gate.calls(), ordinal);
            let precheck_ns = ns(validation_start.elapsed());
            progress.stage = "completion";
            timing.start.set(Some(Instant::now()));
            let done = gate.next();
            timing.end.set(Some(Instant::now()));
            // No serialization, output, metrics or validation memory read occurs
            // between these four timestamps. The inner provider is unchanged.
            progress.stage = "validation";
            let validation_start = Instant::now();
            let span = timing.complete();
            let observed = gate.check_and_state(&done, expected_row, &pin);
            assert_eq!(observed, expected_row.after);
            assert_eq!(gate.calls(), ordinal + 1);
            let after = gate.metrics();
            check_metrics(&after.selected, &expected.rows[..=ordinal]);
            assert!(!before.oracle.preparation.saturated && !before.oracle.demand.saturated);
            assert!(!after.oracle.preparation.saturated && !after.oracle.demand.saturated);
            assert_eq!(after.oracle.preparation.inspections, 0);
            assert_eq!(after.oracle.demand.hits, 0);
            assert_eq!(
                after.selected.scripted_completions,
                before.selected.scripted_completions + 1
            );
            assert!(
                after
                    .pages
                    .first_touch
                    .starts_with(&before.pages.first_touch)
            );
            let site_offset = expected_row.before.registers.rip.checked_sub(BASE).unwrap();
            assert!(site_offset < case.fixture.bytes.len() as u64);
            let mut encoding = String::with_capacity(30);
            for byte in &expected_row.bytes {
                write!(&mut encoding, "{byte:02x}").unwrap();
            }
            let script_id = format!("{}.row{ordinal}", case.id);
            let row_validation_ns = precheck_ns
                .checked_add(ns(validation_start.elapsed()))
                .unwrap();
            validation_ns = validation_ns.checked_add(row_validation_ns).unwrap();
            states.push(observed);
            progress.pending.as_mut().unwrap().rows.push(RowRecord {
                ordinal,
                class: expected_row.selected.class(),
                site_offset,
                encoding,
                script_id,
                span,
                validation_ns: row_validation_ns,
                before,
                after,
            });
            progress.pending.as_mut().unwrap().validation_ns = validation_ns;
        }
        timing.reset();
        let started = Instant::now();
        assert_eq!(gate.calls(), case.replies.len());
        let metrics = gate.metrics();
        check_metrics(&metrics.selected, &expected.rows);
        assert_eq!(metrics.pages.collateral_completions, case.collateral);
        assert_eq!(
            states,
            expected
                .rows
                .iter()
                .map(|r| r.after.clone())
                .collect::<Vec<_>>()
        );
        validation_ns = validation_ns.checked_add(ns(started.elapsed())).unwrap();
    }));
    progress.pending.as_mut().unwrap().validation_ns = validation_ns;
    if result.is_ok() {
        progress.stage = "cleanup";
    }
    let cleanup_start = Instant::now();
    gate.finish(&pin);
    let cleanup_ns = ns(cleanup_start.elapsed());
    progress.cleanup = true;
    progress.pending.as_mut().unwrap().cleanup_ns = Some(cleanup_ns);
    rethrow(result);
    let pending = progress.pending.take().unwrap();
    SessionRecord {
        identity,
        covered: case.covered,
        collateral: case.collateral,
        launch_total_ns,
        validation_ns,
        cleanup_ns,
        rows: pending.rows,
        states,
    }
}
fn numbers(out: &mut String, values: impl IntoIterator<Item = u64>) {
    out.push('[');
    for (i, value) in values.into_iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        write!(out, "{value}").unwrap();
    }
    out.push(']');
}
fn optional_number(out: &mut String, value: Option<u64>) {
    match value {
        Some(n) => write!(out, "{n}").unwrap(),
        None => out.push_str("null"),
    }
}
fn phase_metrics(out: &mut String, m: &OraclePhaseMetrics) {
    write!(out, "{{\"inspections\":{},\"hits\":{},\"runtime_scans\":{},\"no_entry\":{},\"stale\":{},\"corrupt\":{},\"refused\":{},\"decoded_starts\":{},\"lookup_elapsed_ns\":{},\"fresh_scan_elapsed_ns\":{},\"store_elapsed_ns\":{},\"saturated\":{}}}",
        m.inspections, m.hits, m.runtime_scans, m.no_entry, m.stale, m.corrupt, m.refused,
        m.decoded_starts, ns(m.lookup_elapsed), ns(m.fresh_scan_elapsed), ns(m.store_elapsed), m.saturated).unwrap();
}
fn snapshot(out: &mut String, m: &Snapshot) {
    let p = &m.pages;
    write!(
        out,
        "{{\"pages\":{{\"startup_ns\":{},\"first_touch_ns\":",
        ns(p.startup)
    )
    .unwrap();
    numbers(out, p.first_touch.iter().map(|d| ns(*d)));
    write!(out, ",\"admitted_pages\":{},\"untouched_pages\":{},\"observations\":{},\"covered_candidates\":{},\"collateral_guards\":{},\"collateral_completions\":{}}},\"selected\":{{\"callbacks\":",
        p.admitted_pages, p.untouched_pages, p.observations, p.covered_candidates,
        p.collateral_guards, p.collateral_completions).unwrap();
    numbers(
        out,
        classes()
            .iter()
            .map(|class| *m.selected.callbacks.get(class).unwrap_or(&0) as u64),
    );
    let s = &m.selected;
    write!(out, ",\"native_completions\":{},\"scripted_completions\":{},\"provider_faults\":{},\"native_signals\":{},\"refusals\":{}}},\"oracle\":{{\"preparation\":",
        s.native_completions, s.scripted_completions, s.provider_faults, s.native_signals, s.refusals).unwrap();
    phase_metrics(out, &m.oracle.preparation);
    out.push_str(",\"demand\":");
    phase_metrics(out, &m.oracle.demand);
    out.push_str("},\"dynamic\":");
    if let Some(d) = &m.dynamic {
        write!(out, "{{\"resource_scan_decoded_starts\":{},\"retained_origins\":{},\"continuation_history_records\":{},\"retained_call_obligations\":{},\"oldest_call_generation\":",
            d.resource_scan_decoded_starts, d.retained_origins, d.continuation_history_records, d.retained_call_obligations).unwrap();
        optional_number(out, d.oldest_call_generation);
        write!(out, ",\"charged_source_bytes\":{},\"retained_source_bytes\":{},\"bootstrap_xstate_bytes\":{},\"fetch_faults\":{},\"guard_stops\":{},\"generation_changes\":{}}}",
            d.charged_source_bytes, d.retained_source_bytes, d.bootstrap_xstate_bytes,
            d.fetch_faults, d.guard_stops, d.generation_changes).unwrap();
    } else {
        out.push_str("null");
    }
    out.push('}');
}
fn row_fields(out: &mut String, row: &RowRecord) {
    write!(out, "\"ordinal\":{},\"class\":\"{}\",\"site_offset\":{},\"encoding_hex\":\"{}\",\"script_id\":\"{}\",\"completion_ns\":{},\"before_provider_ns\":{},\"checked_provider_ns\":{},\"after_provider_ns\":{},\"validation_ns\":{},\"metrics_before\":",
        row.ordinal, class_name(row.class), row.site_offset, row.encoding, row.script_id,
        row.span.completion, row.span.before, row.span.provider, row.span.after, row.validation_ns).unwrap();
    snapshot(out, &row.before);
    out.push_str(",\"metrics_after\":");
    snapshot(out, &row.after);
}
fn emit_session(record: &SessionRecord, progress: &mut Progress) {
    // This lane passed full state checks and physical cleanup. Pair equality
    // and the whole-run gates still qualify these retained observations later.
    let mut line = String::with_capacity(1024);
    line.push_str("{\"schema_version\":1,\"kind\":\"session\",");
    record.identity.fields(&mut line);
    write!(&mut line, ",\"covered\":{},\"raw_reference_completed\":true,\"callbacks\":{},\"collateral_completions\":{},\"launch_total_ns\":{},\"validation_ns\":{},\"cleanup_ns\":{},\"completed\":true,\"cleanup\":true}}",
        record.covered, record.rows.len(), record.collateral, record.launch_total_ns,
        record.validation_ns, record.cleanup_ns).unwrap();
    println!("{PREFIX}{line}");
    progress.emitted_sessions += 1;
    for row in &record.rows {
        line.clear();
        line.push_str("{\"schema_version\":1,\"kind\":\"completion\",");
        record.identity.fields(&mut line);
        line.push(',');
        row_fields(&mut line, row);
        line.push_str(",\"completed\":1,\"cleanup\":true}");
        println!("{PREFIX}{line}");
        progress.emitted_completions += 1;
    }
}
fn emit_failure(progress: &Progress) {
    let mut line = String::with_capacity(1024);
    line.push_str("{\"schema_version\":1,\"kind\":\"failure\",");
    if let Some(id) = progress.identity {
        id.fields(&mut line);
    } else {
        line.push_str("\"fixture\":null,\"phase\":null,\"pair_index\":null,\"round\":null,\"order_index\":null,\"lane\":null");
    }
    write!(&mut line, ",\"stage\":\"{}\",\"ordinal\":", progress.stage).unwrap();
    optional_number(&mut line, progress.ordinal.map(|n| n as u64));
    let timing = &progress.timing;
    for (name, begin, end) in [
        ("completion_ns", timing.start.get(), timing.end.get()),
        (
            "before_provider_ns",
            timing.start.get(),
            timing.provider_entry.get(),
        ),
        (
            "checked_provider_ns",
            timing.provider_entry.get(),
            timing.provider_exit.get(),
        ),
        (
            "after_provider_ns",
            timing.provider_exit.get(),
            timing.end.get(),
        ),
    ] {
        write!(&mut line, ",\"{name}\":").unwrap();
        optional_number(
            &mut line,
            begin.zip(end).map(|(a, b)| ns(b.duration_since(a))),
        );
    }
    line.push_str(",\"partial_session\":");
    if let Some(pending) = &progress.pending {
        write!(
            &mut line,
            "{{\"covered\":{},\"launch_total_ns\":{},\"validation_ns\":{},\"cleanup_ns\":",
            pending.covered, pending.launch_total_ns, pending.validation_ns
        )
        .unwrap();
        optional_number(&mut line, pending.cleanup_ns);
        line.push('}');
    } else {
        line.push_str("null");
    }
    line.push_str(",\"partial_rows\":[");
    if let Some(pending) = &progress.pending {
        for (i, row) in pending.rows.iter().enumerate() {
            if i != 0 {
                line.push(',');
            }
            line.push('{');
            row_fields(&mut line, row);
            line.push('}');
        }
    }
    line.push(']');
    write!(
        &mut line,
        ",\"cleanup\":{},\"emitted_sessions\":{},\"emitted_completions\":{},\"qualified\":false}}",
        progress.cleanup, progress.emitted_sessions, progress.emitted_completions
    )
    .unwrap();
    println!("{PREFIX}{line}");
}
fn calibration() {
    let mut samples = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let begin = Instant::now();
        let end = Instant::now();
        samples.push(ns(end.duration_since(begin)));
    }
    let mut resolution: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC, &raw mut resolution) },
        0
    );
    assert!(resolution.tv_sec >= 0 && (0..1_000_000_000).contains(&resolution.tv_nsec));
    let resolution_ns = (resolution.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .unwrap()
        .checked_add(resolution.tv_nsec as u64)
        .unwrap();
    assert!(resolution_ns > 0);
    let mut line = String::with_capacity(8192);
    write!(&mut line, "{{\"schema_version\":1,\"kind\":\"calibration\",\"clock\":\"std_instant\",\"monotonic_resolution_ns\":{resolution_ns},\"subtracted\":false,\"samples_ns\":").unwrap();
    numbers(&mut line, samples);
    line.push('}');
    println!("{PREFIX}{line}");
}
fn xorshift(state: &mut u64) -> bool {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state & 1 != 0
}
fn run_all(progress: &mut Progress) {
    if cfg!(debug_assertions) {
        panic!("release profile required");
    }
    assert_eq!(
        std::env::args().skip(1).collect::<Vec<_>>(),
        [
            "--warmup-pairs",
            "3",
            "--measured-pairs",
            "10",
            "--order-seed",
            "1"
        ]
    );
    progress.stage = "calibration";
    calibration();
    let constructors: [fn() -> cases::Case; 5] = [
        cases::masked,
        cases::timestamps,
        cases::prefixed,
        cases::embedded,
        cases::cross_page,
    ];
    let mut random = 1_u64;
    let mut pair_index = 0_usize;
    let mut raw_references = 0_usize;
    let mut callbacks = [0_u64; 7];
    let mut measured = [0_u64; 7];
    let mut collateral = 0_usize;
    for construct in constructors {
        progress.stage = "fixture";
        progress.identity = None;
        progress.ordinal = None;
        progress.timing.reset();
        progress.cleanup = false;
        let case = construct();
        for (phase, rounds) in [("warmup", 3_usize), ("measured", 10_usize)] {
            let mut first_static = false;
            for round in 0..rounds {
                // Each phase uses seeded ABBA/BAAB blocks. Its even round takes
                // one PRNG bit; the next odd round reverses the pair. Warmup's
                // third pair is the explicit unpaired final seed-selected row.
                if round % 2 == 0 {
                    first_static = xorshift(&mut random);
                } else {
                    first_static = !first_static;
                }
                let lanes = if first_static {
                    [Lane::Static, Lane::Dynamic]
                } else {
                    [Lane::Dynamic, Lane::Static]
                };
                let first_id = Identity {
                    fixture: case.id,
                    phase,
                    pair_index,
                    round,
                    order_index: 0,
                    lane: lanes[0],
                };
                progress.identity = Some(first_id);
                let expected = reference(&case, progress);
                raw_references += 1;
                let first = session(&case, &expected, first_id, progress);
                progress.stage = "output";
                emit_session(&first, progress);
                let second = session(
                    &case,
                    &expected,
                    Identity {
                        order_index: 1,
                        lane: lanes[1],
                        ..first_id
                    },
                    progress,
                );
                progress.stage = "output";
                emit_session(&second, progress);
                progress.stage = "agreement";
                assert_eq!(first.states, second.states);
                assert_eq!(
                    first.states,
                    expected
                        .rows
                        .iter()
                        .map(|r| r.after.clone())
                        .collect::<Vec<_>>()
                );
                assert_eq!(first.rows.len(), case.replies.len());
                assert_eq!(second.rows.len(), case.replies.len());
                for record in [&first, &second] {
                    collateral += record.collateral;
                    for row in &record.rows {
                        let index = classes().iter().position(|c| *c == row.class).unwrap();
                        callbacks[index] += 1;
                        if phase == "measured" {
                            measured[index] += 1;
                        }
                    }
                }
                pair_index += 1;
            }
        }
    }
    progress.stage = "run_validation";
    assert_eq!(pair_index, 65);
    assert_eq!(raw_references, 65);
    assert_eq!(progress.emitted_sessions, 130);
    assert_eq!(progress.emitted_completions, 442);
    assert_eq!(callbacks, [52, 52, 104, 78, 104, 26, 26]);
    assert_eq!(measured, [40, 40, 80, 60, 80, 20, 20]);
    assert_eq!(callbacks.iter().sum::<u64>(), 442);
    assert_eq!(measured.iter().sum::<u64>(), 340);
    assert_eq!(collateral, 26);
    progress.stage = "output";
    println!(
        "{PREFIX}{{\"schema_version\":1,\"kind\":\"run_complete\",\"pairs\":65,\"raw_references\":65,\"production_sessions\":130,\"selected_completions\":442,\"warmup_completions\":102,\"measured_completions\":340,\"collateral_completions\":26,\"semantic_mismatches\":0,\"refusals\":0,\"fallbacks\":0,\"cleanup\":true}}"
    );
}
pub(super) fn run() {
    let mut progress = Progress::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_all(&mut progress)));
    if result.is_err() {
        // No panic text, addresses, native state or process identity enters the
        // structured record. Previous complete rows stay recorded but the whole
        // command fails; no retry or missing-sample replacement is performed.
        emit_failure(&progress);
        std::process::exit(1);
    }
}
