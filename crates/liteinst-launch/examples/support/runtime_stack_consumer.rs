//! No private native authority or cfg(test) support is used by this example.
use liteinst_launch::gate::SelectedExecution;
use liteinst_launch::lifecycle::ExitStatus;
use liteinst_launch::selected::{
    InstructionProvider, Operation, ProviderDecision, SelectedArguments, SelectedInput,
    SemanticsError, SyscallAbi,
};
use liteinst_launch::{
    DynamicAdmissionEvent, DynamicAdmissionMetrics, DynamicAdmissionSession, DynamicAdmissionState,
    DynamicRuntimeCleanupStatus, DynamicRuntimeOptions, KernelFailureKind, KernelProgressSnapshot,
    KernelWriterStatus, LaunchCommand, RuntimeKernelFact, RuntimeKernelProfile,
    RuntimeStackProfile,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::thread::ThreadId;
use std::time::Duration;

#[path = "runtime_stack_consumer/archive.rs"]
mod archive;

const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ARTIFACT: u64 = 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;
type Observation<T> = std::thread::Result<Result<T>>;

fn observed_error<T>(value: &Observation<T>) -> Option<&'static str> {
    match value {
        Ok(Ok(_)) => None,
        Ok(Err(code)) => Some(*code),
        Err(_) => Some("caught_panic"),
    }
}

fn require(value: bool, code: &'static str) -> Result<()> {
    if value { Ok(()) } else { Err(code) }
}
fn diagnostic<T, E: std::fmt::Debug>(
    value: std::result::Result<T, E>,
    code: &'static str,
) -> Result<T> {
    value.map_err(|error| {
        eprintln!("{code}: {error:?}");
        code
    })
}

struct Provider {
    thread: ThreadId,
    inputs: Vec<SelectedInput>,
}
impl InstructionProvider for Provider {
    fn decide(
        &mut self,
        input: &SelectedInput,
    ) -> std::result::Result<ProviderDecision, SemanticsError> {
        let index = self.inputs.len();
        let expected = [39, 186, 231].get(index).copied();
        if std::thread::current().id() != self.thread
            || input.instruction().bytes() != [0x0f, 0x05]
            || input.instruction().operation()
                != (Operation::Syscall {
                    abi: SyscallAbi::LinuxX64,
                })
        {
            return Err(SemanticsError::ScriptMismatch);
        }
        let SelectedArguments::Syscall {
            abi: SyscallAbi::LinuxX64,
            number,
            arguments,
        } = input.arguments()
        else {
            return Err(SemanticsError::ScriptMismatch);
        };
        if Some(number) != expected || (index == 2 && arguments[0] != 7) {
            return Err(SemanticsError::ScriptMismatch);
        }
        self.inputs.push(input.clone());
        Ok(ProviderDecision::Native)
    }
}

#[derive(Clone, Copy)]
struct Metric {
    charged: usize,
    retained: usize,
    origins: usize,
    history: usize,
    generations: usize,
}
impl Metric {
    fn capture(value: DynamicAdmissionMetrics) -> Result<Self> {
        require(
            value.charged_source_bytes <= 64 * 1024 * 1024
                && value.retained_source_bytes <= value.charged_source_bytes
                && value.retained_origins <= 4096
                && value.generation_changes == 0,
            "metric_bounds",
        )?;
        Ok(Self {
            charged: value.charged_source_bytes,
            retained: value.retained_source_bytes,
            origins: value.retained_origins,
            history: value.continuation_history_records,
            generations: value.generation_changes,
        })
    }
    fn json(self) -> String {
        format!(
            "{{\"charged_source_bytes\":{},\"retained_source_bytes\":{},\"retained_origins\":{},\"history_records\":{},\"generation_changes\":{}}}",
            self.charged, self.retained, self.origins, self.history, self.generations
        )
    }
}

#[derive(Default)]
struct Report {
    provider_calls: usize,
    returned: Vec<u64>,
    terminal: bool,
    terminal_argument: Option<u64>,
    state_checks: usize,
    attempts: usize,
    waits: usize,
    states: usize,
    facts: Vec<usize>,
    failures: usize,
    metrics: Vec<Metric>,
    identities: bool,
    cleanup: bool,
    writer_cleaned: bool,
    archive_preserved: bool,
    artifact_unchanged: bool,
}
impl Report {
    fn archive(&mut self, snapshot: &KernelProgressSnapshot) {
        self.attempts = snapshot.runtime_attempts.len();
        self.waits = snapshot
            .runtime_attempts
            .iter()
            .map(|a| a.raw.iter().flatten().count())
            .sum();
        self.states = snapshot
            .runtime_attempts
            .iter()
            .map(|a| a.states.iter().filter(|s| s.captured).count())
            .sum();
        self.facts = snapshot
            .runtime_attempts
            .iter()
            .map(|a| a.facts.len())
            .collect();
        self.failures = snapshot
            .runtime_attempts
            .iter()
            .filter(|a| a.failure.is_some())
            .count();
    }
    fn observe_provider(&mut self, provider: &Provider) {
        self.provider_calls = provider.inputs.len();
        self.terminal_argument = provider
            .inputs
            .get(2)
            .and_then(|input| match input.arguments() {
                SelectedArguments::Syscall {
                    abi: SyscallAbi::LinuxX64,
                    number: 231,
                    arguments,
                } => Some(arguments[0]),
                _ => None,
            });
    }
    fn print(&self, error: Option<&'static str>) {
        let numbers = |values: &[u64]| {
            values
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let facts = self
            .facts
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let metrics = self
            .metrics
            .iter()
            .map(|m| m.json())
            .collect::<Vec<_>>()
            .join(",");
        let error = error.map_or_else(|| "null".into(), |e| format!("\"{e}\""));
        let terminal_argument = self
            .terminal_argument
            .map_or_else(|| "null".into(), |value| value.to_string());
        println!(
            "{{\"schema_version\":1,\"experiment\":\"runtime-stack-consumer\",\"role\":\"public_consumer\",\"stack_history_scope\":\"not_publicly_observed\",\"status\":\"{}\",\"error\":{},\"provider_calls\":{},\"returned_syscalls\":[{}],\"terminal_syscall\":{},\"terminal_code\":{},\"terminal_argument\":{},\"full_state_checks\":{},\"journal_attempts\":{},\"journal_raw_waits\":{},\"journal_state_copies\":{},\"journal_fact_counts\":[{}],\"journal_failures\":{},\"identity_chain_exact\":{},\"cleanup_complete\":{},\"writer_cleaned\":{},\"archive_preserved\":{},\"artifact_unchanged\":{},\"observed_metrics\":[{}],\"limits\":{{\"epochs\":256,\"source_fact_bytes\":67108864,\"reports\":4096,\"origins\":4096,\"witnesses\":4096,\"plan_history\":4096}},\"invocation_seconds\":3,\"cleanup_seconds\":3}}",
            if error == "null" { "passed" } else { "failed" },
            error,
            self.provider_calls,
            numbers(&self.returned),
            if self.terminal { "231" } else { "null" },
            if self.terminal { "7" } else { "null" },
            terminal_argument,
            self.state_checks,
            self.attempts,
            self.waits,
            self.states,
            facts,
            self.failures,
            self.identities,
            self.cleanup,
            self.writer_cleaned,
            self.archive_preserved,
            self.artifact_unchanged,
            metrics
        );
    }
}

struct Artifact {
    file: File,
    path: PathBuf,
    bytes: Vec<u8>,
    identity: (u64, u64, u64, u32, u64, i64, i64),
}
impl Artifact {
    fn open(path: PathBuf) -> Result<Self> {
        require(
            !path.is_absolute()
                && path.starts_with("target/evaluation/admission")
                && path.components().all(|c| matches!(c, Component::Normal(_))),
            "artifact_path",
        )?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| "artifact_open")?;
        let metadata = file.metadata().map_err(|_| "artifact_metadata")?;
        require(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.len() <= MAX_ARTIFACT
                && metadata.len() >= 64
                && metadata.mode() & 0o222 == 0
                && metadata.mode() & 0o111 != 0,
            "artifact_metadata",
        )?;
        let identity = (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mode(),
            metadata.nlink(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        );
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_ARTIFACT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "artifact_read")?;
        require(bytes.len() as u64 == metadata.len(), "artifact_length")?;
        let result = Self {
            file,
            path,
            bytes,
            identity,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        use std::os::unix::fs::FileExt;
        let m = self.file.metadata().map_err(|_| "artifact_metadata")?;
        require(
            self.identity
                == (
                    m.dev(),
                    m.ino(),
                    m.len(),
                    m.mode(),
                    m.nlink(),
                    m.ctime(),
                    m.ctime_nsec(),
                ),
            "artifact_changed",
        )?;
        let other = std::fs::symlink_metadata(&self.path).map_err(|_| "artifact_metadata")?;
        require(
            other.is_file()
                && self.identity
                    == (
                        other.dev(),
                        other.ino(),
                        other.len(),
                        other.mode(),
                        other.nlink(),
                        other.ctime(),
                        other.ctime_nsec(),
                    ),
            "artifact_changed",
        )?;
        let mut bytes = vec![0; self.bytes.len()];
        let mut offset = 0;
        while offset < bytes.len() {
            let n = self
                .file
                .read_at(&mut bytes[offset..], offset as u64)
                .map_err(|_| "artifact_read")?;
            require(n > 0, "artifact_read")?;
            offset += n;
        }
        require(bytes == self.bytes, "artifact_changed")
    }
}

fn metric(session: &mut DynamicAdmissionSession<Provider>, report: &mut Report) -> Result<()> {
    let value = Metric::capture(session.metrics().map_err(|_| "metrics_read")?)?;
    if let Some(old) = report.metrics.last() {
        require(
            value.charged >= old.charged
                && value.retained >= old.retained
                && value.origins >= old.origins
                && value.history >= old.history,
            "metric_regression",
        )?;
    }
    report.metrics.push(value);
    Ok(())
}

fn drive(session: &mut DynamicAdmissionSession<Provider>, report: &mut Report) -> Result<()> {
    let initial = session.initial_state().clone();
    let pid = session.pid();
    require(pid > 0 && initial.task.generation == 0, "initial_identity")?;
    // This public boundary observation does not expose the intervening CALL/RET.
    // The separately inspected artifact must make no other explicit RSP writes.
    require(initial.registers.rsp % 16 == 0, "initial_stack_alignment")?;
    require(
        session
            .state(initial.task.task)
            .map_err(|_| "initial_state")?
            == initial,
        "initial_state",
    )?;
    metric(session, report)?;
    let reader = session.kernel_progress();
    let empty = reader.snapshot();
    require(
        empty.attempts.is_empty() && empty.runtime_attempts.is_empty() && !empty.archive_poisoned,
        "initial_archive",
    )?;
    let mut previous = None;
    for (index, number) in [39_u64, 186].into_iter().enumerate() {
        let event = diagnostic(session.next_event(), "runtime_return")?;
        let DynamicAdmissionEvent::Completed(event) = event else {
            return Err("returned_event");
        };
        report.observe_provider(session.provider());
        let input = session
            .provider()
            .inputs
            .get(index)
            .ok_or("missing_provider_input")?
            .clone();
        require(
            event.selected.input == input
                && input.registers().rax == number
                && event.selected.execution == SelectedExecution::Native
                && event.before_task == initial.task
                && event.after_task == initial.task,
            "completion_binding",
        )?;
        require(
            input.registers().rsp == initial.registers.rsp
                && event.selected.after.rsp == initial.registers.rsp,
            "selected_stack_restoration",
        )?;
        let mut expected = *input.registers();
        expected.rax = pid as u64;
        expected.orig_rax = number;
        expected.rip = input.instruction().next_pc();
        expected.rcx = expected.rip;
        expected.r11 = input.registers().eflags & !0x10000;
        expected.eflags &= !0x10000;
        require(
            event.selected.after == expected
                && event.selected.before_xstate == event.selected.xstate
                && event.before_signal_mask == event.signal_mask,
            "full_syscall_state",
        )?;
        let after = DynamicAdmissionState {
            task: initial.task,
            registers: expected,
            xstate: event.selected.xstate.clone(),
            signal_mask: event.signal_mask,
        };
        require(
            session
                .state(initial.task.task)
                .map_err(|_| "returned_state")?
                == after,
            "returned_state",
        )?;
        let snapshot = reader.snapshot();
        report.archive(&snapshot);
        require(
            snapshot.runtime_attempts.len() == index + 1
                && snapshot.attempts.is_empty()
                && !snapshot.archive_poisoned,
            "archive_inventory",
        )?;
        if let Some(old) = &previous {
            require(&snapshot.runtime_attempts[..index] == old, "archive_prefix")?;
        }
        archive::check(
            &snapshot.runtime_attempts[index],
            &input,
            &event.selected.before_xstate,
            event.before_signal_mask,
            Some(&after),
            &initial.task,
            pid,
        )?;
        previous = Some(snapshot.runtime_attempts);
        report.returned.push(number);
        report.state_checks += 1;
        metric(session, report)?;
    }
    let event = diagnostic(session.next_event(), "runtime_terminal")?;
    report.observe_provider(session.provider());
    require(report.provider_calls == 3, "provider_count")?;
    let DynamicAdmissionEvent::TaskTerminal {
        task,
        status,
        all_terminal,
    } = event
    else {
        return Err("terminal_event");
    };
    require(
        task == initial.task
            && status == ExitStatus::Code(7)
            && all_terminal
            && session.is_closed(),
        "terminal_event",
    )?;
    let snapshot = reader.snapshot();
    report.archive(&snapshot);
    require(
        snapshot.runtime_attempts.len() == 3
            && snapshot.attempts.is_empty()
            && !snapshot.archive_poisoned
            && snapshot.runtime_attempts[..2] == previous.ok_or("archive_prefix")?,
        "terminal_archive",
    )?;
    let input = &session.provider().inputs[2];
    require(
        report.terminal_argument == Some(7) && input.registers().rsp == initial.registers.rsp,
        "terminal_argument_and_stack",
    )?;
    archive::check(
        &snapshot.runtime_attempts[2],
        input,
        &initial.xstate,
        initial.signal_mask,
        None,
        &initial.task,
        pid,
    )?;
    archive::chain(&snapshot.runtime_attempts)?;
    report.terminal = true;
    report.identities = true;
    Ok(())
}

fn execute(path: PathBuf, report: &mut Report) -> Result<()> {
    let artifact = Artifact::open(path)?;
    let command = LaunchCommand {
        program: artifact.path.clone(),
        args: Vec::new(),
    };
    let provider = Provider {
        thread: std::thread::current().id(),
        inputs: Vec::with_capacity(3),
    };
    // SAFETY: this example accepts the recorder's immutable, private, freestanding
    // static artifact only. No external writer/tracer, signals, mapping/lifecycle
    // composition or opaque saved contexts are allowed. Unknown effects refuse.
    // OriginalResidentWord also requires exclusive original-stack writer/alias
    // custody, no external pager/userfaultfd, and the same supported component-9
    // XSAVE layout on every allowed CPU. The fixed recorder owns this envelope;
    // affinity alone is not a layout or custody proof. No stack is read/touched
    // here to establish residency: the actual runtime may honestly refuse it.
    // The separate inspector/evaluator authenticates the exact emitted helper,
    // dataflow, short initialized ELF extents and the fixed source. This example
    // asserts no full-page file-to-memory tail equality or private CALL history.
    let mut session = match unsafe {
        DynamicAdmissionSession::launch_runtime_with_cleanup(
            &command,
            DynamicRuntimeOptions {
                kernel: RuntimeKernelProfile::IdentityAndTermination,
                stack: RuntimeStackProfile::OriginalResidentWord,
                ..Default::default()
            },
            provider,
            TIMEOUT,
        )
    } {
        Ok(session) => session,
        Err(mut failure) => {
            // Preserve the original error before observing separate cleanup.
            // No provider/source/native success is inferred from cleanup.
            eprintln!("runtime_launch: {:?}", failure.error());
            // TIMEOUT bounds this public cleanup observation, not the owner's
            // physical drain. A timeout retains its receiver; this host aborts
            // rather than claim completion or continue with unknown custody.
            match failure.wait_cleanup(TIMEOUT) {
                Ok(DynamicRuntimeCleanupStatus::NotStarted) => {}
                Ok(DynamicRuntimeCleanupStatus::Complete(_)) => report.cleanup = true,
                observation => {
                    eprintln!("runtime_launch_cleanup: {observation:?}");
                    report.print(Some("runtime_launch"));
                    std::process::abort();
                }
            }
            return Err("runtime_launch");
        }
    };
    let pid = session.pid();
    let reader = session.kernel_progress();
    let result = catch_unwind(AssertUnwindSafe(|| drive(&mut session, report)));
    // Keep the exact body result/panic payload alive through all observations.
    // Later failures have their own records and cannot replace this primary.
    let body_error = observed_error(&result);
    let mut before = None;
    let before_observation: Observation<()> = catch_unwind(AssertUnwindSafe(|| {
        report.observe_provider(session.provider());
        let snapshot = before.insert(reader.snapshot());
        report.archive(snapshot);
        Ok(())
    }));
    let before_error = observed_error(&before_observation);
    let primary = body_error.or(before_error);
    for (phase, error) in [("body", body_error), ("before_cleanup", before_error)] {
        if let Some(error) = error {
            let _ = writeln!(
                std::io::stderr().lock(),
                "runtime_stack_consumer {phase}: {error}"
            );
        }
    }
    let cleanup = catch_unwind(AssertUnwindSafe(|| session.terminate(TIMEOUT)));
    match &cleanup {
        Ok(Ok(value)) if value.reaped == [pid] => report.cleanup = true,
        observation => {
            match observation {
                Ok(value) => {
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "runtime_stack_consumer physical_cleanup: {value:?}"
                    );
                }
                Err(_) => {
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "runtime_stack_consumer physical_cleanup: caught_panic"
                    );
                }
            }
            // A failed output write must not unwind past unknown custody.
            let _summary = catch_unwind(AssertUnwindSafe(|| {
                report.print(Some(primary.unwrap_or("physical_cleanup")));
            }));
            std::process::abort();
        }
    }
    let success = result.as_ref().is_ok_and(|value| value.is_ok());
    let mut after = None;
    let archive_observation: Observation<()> = catch_unwind(AssertUnwindSafe(|| {
        let after = after.insert(reader.snapshot());
        report.writer_cleaned =
            after.writer == KernelWriterStatus::Cleaned && !after.archive_poisoned;
        report.archive_preserved = before.as_ref().is_some_and(|before| {
            before.attempts == after.attempts
                && before.runtime_attempts.len() == after.runtime_attempts.len()
                && before
                    .runtime_attempts
                    .iter()
                    .zip(&after.runtime_attempts)
                    .all(|(old, new)| {
                        let mut expected = old.clone();
                        // An existing first failure and all payloads remain exact. Only
                        // incomplete failed attempts may gain cleanup's first Cancelled.
                        if !success
                            && old.failure.is_none()
                            && !old.facts.iter().any(|fact| {
                                matches!(
                                    fact,
                                    RuntimeKernelFact::ReturnCommitted { .. }
                                        | RuntimeKernelFact::TerminalCommitted { .. }
                                )
                            })
                            && new
                                .failure
                                .is_some_and(|f| f.kind == KernelFailureKind::Cancelled)
                        {
                            expected.failure = new.failure;
                        }
                        expected == *new
                    })
        });
        report.archive(after);
        require(
            report.writer_cleaned && report.archive_preserved,
            "cleanup_archive",
        )
    }));
    // This is independent of archive success, and keeps the actual outcome.
    let artifact_observation = catch_unwind(AssertUnwindSafe(|| artifact.check()));
    report.artifact_unchanged = matches!(&artifact_observation, Ok(Ok(())));
    let archive_error = observed_error(&archive_observation);
    let artifact_error = observed_error(&artifact_observation);
    for (phase, error) in [
        ("cleanup_archive", archive_error),
        ("artifact", artifact_error),
    ] {
        if let Some(error) = error {
            let _ = writeln!(
                std::io::stderr().lock(),
                "runtime_stack_consumer {phase}: {error}"
            );
        }
    }
    match primary.or(archive_error).or(artifact_error) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub(super) fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args == [std::ffi::OsString::from("--protocol-version")] {
        println!(
            "{{\"protocol\":\"liteinst-runtime-stack-consumer\",\"version\":1,\"role\":\"public_consumer\"}}"
        );
        return ExitCode::SUCCESS;
    }
    let mut report = Report::default();
    let result = if args.len() == 2 && args[0] == "--artifact" {
        execute(Path::new(&args[1]).to_path_buf(), &mut report)
    } else {
        Err("arguments")
    };
    report.print(result.err());
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
