//! Fixed backing-resource controls on ordinary process main threads.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> std::process::ExitCode {
    liteinst_launch::__run_exec_backing_cleanup()
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
