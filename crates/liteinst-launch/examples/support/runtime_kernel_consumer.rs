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
};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::thread::ThreadId;
use std::time::Duration;

#[path = "runtime_kernel_consumer/archive.rs"]
mod archive;

const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ARTIFACT: u64 = 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

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
        println!(
            "{{\"schema_version\":1,\"experiment\":\"runtime-kernel-consumer\",\"status\":\"{}\",\"error\":{},\"provider_calls\":{},\"returned_syscalls\":[{}],\"terminal_syscall\":{},\"terminal_code\":{},\"full_state_checks\":{},\"journal_attempts\":{},\"journal_raw_waits\":{},\"journal_state_copies\":{},\"journal_fact_counts\":[{}],\"journal_failures\":{},\"identity_chain_exact\":{},\"cleanup_complete\":{},\"writer_cleaned\":{},\"archive_preserved\":{},\"artifact_unchanged\":{},\"observed_metrics\":[{}],\"limits\":{{\"epochs\":256,\"source_fact_bytes\":67108864,\"reports\":4096,\"origins\":4096,\"witnesses\":4096,\"plan_history\":4096}},\"invocation_seconds\":3,\"cleanup_seconds\":3}}",
            if error == "null" { "passed" } else { "failed" },
            error,
            self.provider_calls,
            numbers(&self.returned),
            if self.terminal { "231" } else { "null" },
            if self.terminal { "7" } else { "null" },
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
        report.provider_calls = session.provider().inputs.len();
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
    report.provider_calls = session.provider().inputs.len();
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
    // The separate recorder authenticates ELF geometry and the fixed source.
    let mut session = match unsafe {
        DynamicAdmissionSession::launch_runtime_with_cleanup(
            &command,
            DynamicRuntimeOptions {
                kernel: RuntimeKernelProfile::IdentityAndTermination,
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
    report.provider_calls = session.provider().inputs.len();
    let before = reader.snapshot();
    report.archive(&before);
    let cleanup = session.terminate(TIMEOUT);
    match cleanup {
        Ok(value) if value.reaped == [pid] => report.cleanup = true,
        _ => {
            report.print(Some("physical_cleanup"));
            std::process::abort();
        }
    }
    let after = reader.snapshot();
    report.writer_cleaned = after.writer == KernelWriterStatus::Cleaned && !after.archive_poisoned;
    let success = result.as_ref().is_ok_and(|value| value.is_ok());
    report.archive_preserved = before.attempts == after.attempts
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
            });
    report.archive(&after);
    require(
        report.writer_cleaned && report.archive_preserved,
        "cleanup_archive",
    )?;
    artifact.check()?;
    report.artifact_unchanged = true;
    match result {
        Ok(value) => value,
        Err(_) => Err("caught_panic"),
    }
}

pub(super) fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args == [std::ffi::OsString::from("--protocol-version")] {
        println!("{{\"protocol\":\"liteinst-runtime-kernel-consumer\",\"version\":1}}");
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
