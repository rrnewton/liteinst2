//! Unsafe checked-launcher entry point. Seals are NOT caller authentication.
use li2_kernel_exec_observer::{
    Error, Evidence, Observation, admit_from_checked_launcher, observe_with_evidence, wire,
};

fn error(value: Option<&Error>) -> String {
    value.map_or_else(|| "null".into(), |e| format!("\"{e:?}\""))
}
fn boolean(value: Option<bool>) -> &'static str {
    match value {
        None => "null",
        Some(true) => "true",
        Some(false) => "false",
    }
}
fn receipt(
    hash: Option<&str>,
    transport: bool,
    evidence: &Evidence,
    observation: Option<&Observation>,
) -> String {
    let stops = evidence
        .stops
        .iter()
        .map(|s| {
            format!(
                "{{\"kind\":\"{}\",\"status\":{},\"siginfo\":\"{}\"}}",
                s.kind,
                s.status,
                wire::hex(&s.siginfo)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let observed = observation.map_or_else(|| "null".into(), |o| format!(
        "{{\"completion\":{},\"main_entry\":{},\"bootstrap_bias\":{},\"stopped_before_main_execution\":{},\"observer_killed_child\":{},\"absence_echild\":{},\"route_coverage_complete\":false}}",
        o.completion,o.main_entry,o.bootstrap_bias,o.stopped_before_main_execution,o.observer_killed_child,o.absence_echild));
    format!(
        concat!(
            "{{\"schema\":\"LI2-OBSERVER-RECEIPT-1\",\"request_sha256\":{},\"transport_accepted\":{},",
            "\"child_started\":{},\"stops\":[{}],\"exec_auxv\":\"{}\",\"entry_auxv\":\"{}\",\"exec_maps\":\"{}\",\"entry_maps\":\"{}\",",
            "\"exec_status\":\"{}\",\"entry_status\":\"{}\",\"entry_registers\":\"{}\",\"entry_xstate\":\"{}\",",
            "\"debug_restored\":{},\"primary_error\":{},\"restore_error\":{},\"cleanup_error\":{},\"absence_echild\":{},",
            "\"observation\":{},\"route_coverage_complete\":false,\"native_correctness_complete\":false}}"
        ),
        hash.map_or_else(|| "null".into(), |h| format!("\"{h}\"")),
        transport,
        evidence.child_started,
        stops,
        wire::hex(&evidence.exec_auxv),
        wire::hex(&evidence.entry_auxv),
        wire::hex(&evidence.exec_maps),
        wire::hex(&evidence.entry_maps),
        wire::hex(&evidence.exec_status),
        wire::hex(&evidence.entry_status),
        wire::hex(&evidence.entry_registers),
        wire::hex(&evidence.entry_xstate),
        boolean(evidence.debug_restored),
        error(evidence.primary_error.as_ref()),
        error(evidence.restore_error.as_ref()),
        error(evidence.cleanup_error.as_ref()),
        evidence.absence_echild,
        observed
    )
}

fn run(
    evidence: &mut Evidence,
    digest: &mut Option<String>,
    transport: &mut bool,
) -> Result<Observation, Error> {
    let raw = std::env::args_os().collect::<Vec<_>>();
    let args = raw
        .iter()
        .map(|a| a.to_str().ok_or(Error::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    if args.len() != 5
        || args[1] != "--checked-launcher-request-fd"
        || args[3] != "--request-sha256"
        || std::env::vars_os().next().is_some()
    {
        return Err(Error::Shape);
    }
    let expected = wire::digest(args[4])?;
    *digest = Some(args[4].to_owned());
    let fd = args[2].parse::<i32>().map_err(|_| Error::Shape)?;
    if !(3..=1024).contains(&fd)
        || args[2] != fd.to_string()
        || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0
    {
        return Err(Error::Shape);
    }
    // Dedicated process, sole inherited request owner; read_owned_fd closes it.
    let request = unsafe { wire::read_owned_fd(fd, expected) }?;
    *transport = true;
    // SAFETY: this binary is called only through the pinned checked launcher
    // specified by the explicitly accepted final profile. This is a documented
    // unsafe API/CLI boundary, not a claim that the fd/digest authenticates it.
    let admitted = unsafe { admit_from_checked_launcher(&request) }?;
    observe_with_evidence(&request, &admitted, evidence)
}

fn main() {
    let mut evidence = Evidence::default();
    let mut digest = None;
    let mut transport = false;
    let result = run(&mut evidence, &mut digest, &mut transport);
    if evidence.primary_error.is_none() {
        evidence.primary_error = result.as_ref().err().cloned();
    }
    println!(
        "{}",
        receipt(
            digest.as_deref(),
            transport,
            &evidence,
            result.as_ref().ok()
        )
    );
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}
