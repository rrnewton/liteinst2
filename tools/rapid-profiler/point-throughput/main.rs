//! Stable disabled managed points: one worker, one control, two real images.
//! Direct generated-entry calls, not source publication or interval conversion.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

use liteinst::contracts::{Epoch, ToggleProbe, Visibility};
use liteinst::controls::{PointObservationAction, ProbeControl};
use liteinst::scanner::InstructionScanner;
use liteinst::trampoline::{ExecutableTrampoline, HookContext, TrampolinePlan};
use rapid_profiler::data_flag::{
    AdmissionBoundary, DataFlagSession, PointOutcome, PointSpec, PointThread,
};
use rapid_profiler::frontend::{Limits, Observation, PayloadOutcome, RecordObservation};
use rapid_profiler::generation::{Config, Disposition, FunctionId, Terminal};
use std::cell::Cell;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

const PAGE: usize = 4096;
const CODE: [u8; 7] = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
const CALLS: u64 = 2048;
const CHECKSUM: u64 = 6_296_576;
const FUNCTION: FunctionId = FunctionId(11);
const HEADER: &str = "pid,worker_tid,worker_cpu,arm,phase,batch,status,calls,elapsed_ns,checksum,callbacks,records,refusals\n";
type Function = unsafe extern "C" fn(u64, u64) -> u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Arm {
    Native,
    Ordinary,
    Early,
}
impl Arm {
    const ALL: [Self; 3] = [Self::Native, Self::Ordinary, Self::Early];
    fn name(self, enabled: bool) -> &'static str {
        match (self, enabled) {
            (Self::Native, false) => "native",
            (Self::Ordinary, false) => "ordinary-disabled",
            (Self::Early, false) => "early-disabled",
            (Self::Ordinary, true) => "ordinary-enabled",
            (Self::Early, true) => "early-enabled",
            (Self::Native, true) => unreachable!("native has no callback control"),
        }
    }
}
fn order(text: &str) -> [Arm; 3] {
    use Arm::{Early as E, Native as N, Ordinary as O};
    match text {
        "native,ordinary-disabled,early-disabled" => [N, O, E],
        "native,early-disabled,ordinary-disabled" => [N, E, O],
        "ordinary-disabled,native,early-disabled" => [O, N, E],
        "ordinary-disabled,early-disabled,native" => [O, E, N],
        "early-disabled,native,ordinary-disabled" => [E, N, O],
        "early-disabled,ordinary-disabled,native" => [E, O, N],
        _ => panic!("required exact native/ordinary-disabled/early-disabled permutation"),
    }
}
fn inputs(index: u64) -> (u64, u64) {
    (index + 1, 2 * index + 3)
}
fn cpu() -> usize {
    // SAFETY: initialized owned cpu_set_t and its exact byte extent.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
        0
    );
    let found: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        .filter(|&n| unsafe { libc::CPU_ISSET(n, &set) })
        .collect();
    assert_eq!(found.len(), 1, "one externally reserved worker CPU");
    found[0]
}
fn single_main() {
    let threads: Vec<_> = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse::<u32>()
                .unwrap()
        })
        .collect();
    assert_eq!(threads, [std::process::id()]);
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        i64::from(std::process::id())
    );
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Witness {
    source: u64,
    allowed: bool,
    count: u64,
    pc: u64,
    a: u64,
    b: u64,
}
thread_local! { static WITNESS: Cell<Witness> = const { Cell::new(Witness { source: 0, allowed: false, count: 0, pc: 0, a: 0, b: 0 }) }; }
fn fatal() -> ! {
    unsafe { libc::_exit(123) }
}
unsafe extern "C" fn observe(context: *mut HookContext) {
    if context.is_null() {
        fatal();
    }
    // SAFETY: the real managed dispatcher supplies its live saved frame. This
    // witness never reenters the borrowed point attachment or unwinds across C.
    let c = unsafe { &*context };
    let accepted = WITNESS
        .try_with(|slot| {
            let mut w = slot.get();
            if !w.allowed
                || w.count != 0
                || w.source != c.instruction_pointer
                || (c.rdi, c.rsi) != (7, 11)
            {
                return false;
            }
            w.count = 1;
            w.pc = c.instruction_pointer;
            w.a = c.rdi;
            w.b = c.rsi;
            slot.set(w);
            true
        })
        .unwrap_or(false);
    if !accepted {
        fatal();
    }
}

struct Program {
    source: u64,
    images: [ExecutableTrampoline; 2],
    snapshots: [(u64, Vec<u8>); 3],
    session: DataFlagSession,
    attachment: PointThread,
    control: ProbeControl,
    closed_epochs: Vec<(Epoch, Vec<RecordObservation>)>,
}
impl Program {
    fn new() -> Self {
        single_main();
        assert_eq!(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }, PAGE as i64);
        // One exclusive anonymous source page. It and executable-image owners
        // are deliberately process-lived: generated return jumps still use it.
        // No executable page is overwritten, temporarily unmapped or retired.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        unsafe { std::ptr::copy_nonoverlapping(CODE.as_ptr(), raw.cast::<u8>(), CODE.len()) };
        assert_eq!(
            unsafe { libc::mprotect(raw, PAGE, libc::PROT_READ | libc::PROT_EXEC) },
            0
        );
        let source = raw as usize as u64;
        let session = DataFlagSession::new(
            0x504f_494e_5402,
            &[PointSpec {
                pc: source,
                group: 0,
                function: Some(FUNCTION),
                callback: observe,
            }],
            Limits {
                epochs: 2,
                threads: 1,
                depth: 1,
                records_per_epoch: 1,
                actions: 32,
            },
        )
        .unwrap();
        let attachment = session.attach_current_thread().unwrap();
        let actions = session.actions();
        assert_eq!(actions.len(), 1);
        let control = actions[0].control.clone();
        assert!(!control.is_enabled() && control.try_set_enabled(true).is_err());
        let early = session.point_observation_actions();
        assert!(matches!(
            &early[0],
            PointObservationAction::EarlyIfEnabled(_)
        ));
        assert_eq!(early[0].controlled_action(), &actions[0]);
        let scan = InstructionScanner::default().scan(&CODE, source).unwrap();
        assert_eq!(
            scan.instructions()
                .iter()
                .map(|i| i.address() - source)
                .collect::<Vec<_>>(),
            [0, 3, 6]
        );
        let plans = [
            TrampolinePlan::from_controlled_actions(&scan, source, source + 6, &actions).unwrap(),
            TrampolinePlan::from_point_observation_actions(&scan, source, source + 6, &early)
                .unwrap(),
        ];
        let images = plans
            .each_ref()
            .map(|plan| ExecutableTrampoline::allocate(plan).unwrap());
        let mut snapshots = vec![(
            source,
            unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), PAGE) }.to_vec(),
        )];
        for (index, (plan, image)) in plans.iter().zip(&images).enumerate() {
            assert_eq!(image.address() % PAGE as u64, source % PAGE as u64);
            assert!(image.allocation_len() <= 2 * PAGE && image.code_len() > 0);
            let emitted = plan.emit_at(image.address()).unwrap();
            assert_eq!(emitted.early_control_gates().len(), index);
            if index == 1 {
                let gate = emitted.early_control_gates()[0];
                assert_eq!((gate.logical_pc, gate.entry), (source, image.address()));
                assert!(
                    gate.entry < gate.post_load
                        && gate.post_load < gate.observing_entry
                        && gate.observing_entry < gate.original_body
                );
            }
            assert_eq!(emitted.entry_routes().len(), 2);
            assert_eq!(emitted.instruction_boundaries().len(), 2);
            let bytes = unsafe {
                std::slice::from_raw_parts(image.address() as *const u8, image.code_len())
            }
            .to_vec();
            assert_eq!(bytes, emitted.bytes());
            snapshots.push((image.address(), bytes));
        }
        WITNESS.set(Witness {
            source,
            ..Witness::default()
        });
        // Drop scan/plans/action clones; both executable images retain the same
        // real control. Session/attachment and the source page stay live.
        Self {
            source,
            images,
            snapshots: snapshots.try_into().unwrap(),
            session,
            attachment,
            control,
            closed_epochs: Vec::new(),
        }
    }
    fn function(&self, arm: Arm) -> Function {
        let entry = match arm {
            Arm::Native => self.source,
            Arm::Ordinary => self.images[0].address(),
            Arm::Early => self.images[1].address(),
        };
        // SAFETY of invocation is stated at call sites; construction alone does
        // not call foreign code. These exact bytes implement the two-u64 ABI.
        unsafe { std::mem::transmute(entry as usize) }
    }
    fn unchanged(&self) {
        for (address, expected) in &self.snapshots {
            // SAFETY: original RX page and initialized image extents are retained
            // for this process; no writer or retirement exists in this fixture.
            assert_eq!(
                unsafe { std::slice::from_raw_parts(*address as *const u8, expected.len()) },
                expected
            );
        }
        for (epoch, expected) in &self.closed_epochs {
            assert_eq!(
                self.session
                    .report(*epoch)
                    .unwrap()
                    .unwrap()
                    .records()
                    .collect::<Vec<_>>(),
                *expected
            );
        }
    }
    fn enabled(&mut self, arm: Arm) -> ResultRow {
        assert_ne!(arm, Arm::Native);
        self.unchanged();
        let before = self.attachment.diagnostics().unwrap();
        assert_eq!(before.refusals, 0);
        let epoch = self
            .session
            .stage(Config {
                retained_per_function: 1,
                max_inflight: 1,
                max_invocations: 1,
            })
            .unwrap();
        let on = self.session.arm(epoch).unwrap();
        assert_eq!(self.session.complete(&on), Ok(Visibility::Eventual));
        assert_eq!(
            self.session.admission_boundary(&on),
            Ok(AdmissionBoundary::Current(epoch))
        );
        assert!(self.control.is_enabled());
        WITNESS.set(Witness {
            source: self.source,
            allowed: true,
            ..Witness::default()
        });
        let function = self.function(arm);
        // SAFETY: single worker, sole base entry, fixed scalar normal call/return,
        // Linux x86-64 SysV/no-CET; ordinary save-stack/red-zone requirements stay
        // valid in both states. Callback is independently optional, non-unwinding
        // and non-reentrant. All code, control, TLS and source owners are live.
        let result = unsafe { function(7, 11) };
        assert_eq!(result, 18);
        assert_eq!(
            WITNESS.get(),
            Witness {
                source: self.source,
                allowed: true,
                count: 1,
                pc: self.source,
                a: 7,
                b: 11
            }
        );
        let diagnostics = self.attachment.diagnostics().unwrap();
        assert_eq!(diagnostics.refusals, before.refusals);
        assert_eq!(diagnostics.last_refusal, before.last_refusal);
        let Some(PointOutcome::Completed {
            completion,
            payload,
        }) = diagnostics.last
        else {
            panic!("required actual point completion")
        };
        assert_eq!(completion.admission.generation.get(), epoch.0);
        assert_eq!(
            (
                completion.admission.invocation,
                completion.admission.function,
                completion.admission.entry_value
            ),
            (0, FUNCTION, self.source)
        );
        assert_eq!(completion.disposition, Disposition::Retained { rank: 0 });
        assert_eq!(completion.other_reservations_after_close, Some(0));
        let deactivate = completion.deactivate.expect("K=1 closure request");
        assert_eq!(
            (deactivate.generation.get(), deactivate.function),
            (epoch.0, FUNCTION)
        );
        assert_eq!(payload.admission, completion.admission);
        assert!(payload.thread > 0);
        assert_eq!(payload.start_sequence, self.closed_epochs.len() as u64);
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end: Observation::Value(self.source),
                completed_children: 0
            }
        );
        // K alone is not disarm. Complete the actual removal ticket, then close
        // and inspect the retained epoch. Drop is never completion evidence.
        let off = self.session.disarm(epoch).unwrap();
        assert_eq!(self.session.complete(&off), Ok(Visibility::Eventual));
        assert_eq!(
            self.session.admission_boundary(&off),
            Ok(AdmissionBoundary::Closed(epoch))
        );
        self.session.close_and_drain(epoch).unwrap();
        assert!(!self.control.is_enabled());
        let rows: Vec<_> = self
            .session
            .report(epoch)
            .unwrap()
            .unwrap()
            .records()
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record.admission, completion.admission);
        assert_eq!(
            rows[0].record.terminal,
            Some(Terminal::Completed {
                value: 0,
                disposition: Disposition::Retained { rank: 0 }
            })
        );
        assert_eq!(rows[0].payload, Some(payload));
        self.closed_epochs.push((epoch, rows));
        WITNESS.set(Witness {
            allowed: false,
            ..WITNESS.get()
        });
        self.unchanged();
        ResultRow {
            elapsed: None,
            checksum: result,
            callbacks: 1,
            records: 1,
            refusals: 0,
        }
    }
    fn disabled(&self, arm: Arm, timed: bool) -> ResultRow {
        self.unchanged();
        assert_eq!(self.closed_epochs.len(), 2);
        assert!(!self.control.is_enabled());
        let witness = WITNESS.get();
        assert!(!witness.allowed);
        let diagnostics = self.attachment.diagnostics().unwrap();
        assert_eq!(diagnostics.refusals, 0);
        let function = black_box(self.function(arm));
        let mut checksum = 0_u64;
        let start = timed.then(Instant::now);
        for index in 0..CALLS {
            let (a, b) = inputs(index);
            // SAFETY: same complete obligations as enabled(); false is no waiver
            // of stack/code/owner validity. No control writes occur in this loop.
            let returned = unsafe { function(black_box(a), black_box(b)) };
            if !timed {
                assert_eq!(returned, 3 * index + 4);
            }
            checksum = checksum.wrapping_add(black_box(returned));
        }
        let elapsed = start.map(|t| t.elapsed().as_nanos());
        assert_eq!(checksum, CHECKSUM);
        assert_eq!(WITNESS.get(), witness);
        assert_eq!(self.attachment.diagnostics().unwrap(), diagnostics);
        assert!(!self.control.is_enabled());
        self.unchanged();
        ResultRow {
            elapsed,
            checksum,
            callbacks: 0,
            records: 0,
            refusals: 0,
        }
    }
}

struct ResultRow {
    elapsed: Option<u128>,
    checksum: u64,
    callbacks: u64,
    records: u64,
    refusals: u64,
}
struct Row {
    arm: Arm,
    phase: &'static str,
    index: usize,
    status: &'static str,
    result: Option<ResultRow>,
}
fn roster(ordered: [Arm; 3]) -> Vec<Row> {
    let mut rows: Vec<_> = [Arm::Ordinary, Arm::Early]
        .into_iter()
        .map(|arm| Row {
            arm,
            phase: "enabled-control",
            index: 0,
            status: "UNOBSERVED",
            result: None,
        })
        .collect();
    rows.extend(Arm::ALL.into_iter().map(|arm| Row {
        arm,
        phase: "qualification",
        index: 0,
        status: "UNOBSERVED",
        result: None,
    }));
    rows.extend(ordered.into_iter().flat_map(|arm| {
        (0..67).map(move |index| Row {
            arm,
            phase: if index < 3 { "warmup" } else { "measured" },
            index: if index < 3 { index } else { index - 3 },
            status: "UNOBSERVED",
            result: None,
        })
    }));
    rows
}
fn render(rows: &[Row], worker: usize) -> String {
    use std::fmt::Write;
    let mut text = String::from(HEADER);
    for row in rows {
        let enabled = row.phase == "enabled-control";
        let result = row
            .result
            .as_ref()
            .map(|r| {
                format!(
                    "{},{},{},{},{}",
                    r.elapsed.map(|n| n.to_string()).unwrap_or_default(),
                    r.checksum,
                    r.callbacks,
                    r.records,
                    r.refusals
                )
            })
            .unwrap_or_else(|| ",,,,".into());
        writeln!(
            text,
            "{},{},{worker},{},{},{},{},{},{}",
            std::process::id(),
            std::process::id(),
            row.arm.name(enabled),
            row.phase,
            row.index,
            row.status,
            if enabled { 1 } else { CALLS },
            result
        )
        .unwrap();
    }
    text
}
fn save(output: &Path, rows: &[Row], worker: usize) {
    std::fs::write(output.join("measurements.next"), render(rows, worker)).unwrap();
    std::fs::rename(
        output.join("measurements.next"),
        output.join("measurements.csv"),
    )
    .unwrap();
}
fn run(text: &str, output: &Path) {
    let ordered = order(text);
    assert!(!output.exists());
    std::fs::create_dir(output).unwrap();
    let worker = cpu();
    let mut rows = roster(ordered);
    save(output, &rows, worker);
    std::fs::write(
        output.join("summary.json"),
        "{\"status\":\"INCOMPLETE\",\"profile\":\"early-point-throughput-v1\"}\n",
    )
    .unwrap();
    let mut active = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        single_main();
        let mut program = Program::new();
        for index in 0..rows.len() {
            active = Some(index);
            rows[index].status = "DISPATCHED";
            save(output, &rows, worker);
            assert_eq!(cpu(), worker);
            let row = &rows[index];
            let result = if row.phase == "enabled-control" {
                program.enabled(row.arm)
            } else {
                program.disabled(row.arm, row.phase != "qualification")
            };
            assert_eq!(
                result.elapsed.is_some(),
                matches!(row.phase, "warmup" | "measured")
            );
            assert_eq!(cpu(), worker);
            rows[index].result = Some(result);
            rows[index].status = "PASS";
            active = None;
            save(output, &rows, worker);
        }
        assert_eq!(rows.len(), 206);
        assert_eq!(program.closed_epochs.len(), 2);
        program.unchanged();
    }));
    if let Err(error) = outcome {
        if let Some(index) = active {
            rows[index].status = "FAILED";
        }
        save(output, &rows, worker);
        std::fs::write(
            output.join("summary.json"),
            "{\"status\":\"FAILED\",\"profile\":\"early-point-throughput-v1\"}\n",
        )
        .unwrap();
        std::panic::resume_unwind(error);
    }
    std::fs::write(output.join("summary.json"), format!("{{\"status\":\"PASS\",\"profile\":\"early-point-throughput-v1\",\"order\":\"{text}\",\"pid\":{},\"worker_tid\":{},\"worker_cpu\":{worker},\"source_bytes\":7,\"enabled_controls\":2,\"qualification_rows\":3,\"warmup_rows\":9,\"measured_rows\":192,\"calls_per_batch\":2048,\"checksum_per_batch\":6296576,\"total_calls\":417794,\"enabled_callbacks\":2,\"retained_records\":2,\"timed_callbacks\":0,\"publication\":\"direct-generated-entry\",\"performance_threshold\":false}}\n", std::process::id(), std::process::id())).unwrap();
    println!("early-point:2-enabled:3-qualified:9-warmups:192-measured:no-outlier-filter");
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "point-throughput ORDER FRESH_OUTPUT");
    run(&args[1], Path::new(&args[2]));
}

#[cfg(test)]
mod tests;
