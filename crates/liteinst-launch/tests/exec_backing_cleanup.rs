//! Fixed backing-resource controls on ordinary process main threads.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "support/host_cpuid_step.rs"]
mod host_cpuid_step;

// The probe runs on the parent's only thread before any control or fixture
// exists, so its child can inherit no writable executable descriptor. Nothing
// else takes this lock; it only satisfies the probe's interface.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static PROBE_FORK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> std::process::ExitCode {
    // Five of the six trajectories natively complete the fixture's first
    // CPUID through owner_body(Case::Complete), as the gated lib test
    // admitted_exec_native_first_user_and_retired_history_are_exact does.
    // Each control re-enters this binary as `--cleanup-child <role>`; only
    // the parent probes.
    if std::env::args().nth(1).as_deref() != Some("--cleanup-child") {
        host_cpuid_step::require_calibrated(&PROBE_FORK, "exec_backing_cleanup::main");
    }
    liteinst_launch::__run_exec_backing_cleanup()
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
