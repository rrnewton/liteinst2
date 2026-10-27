//! The private feature entry owns all arguments, custody and bounded output.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> std::process::ExitCode {
    liteinst_launch::__run_owned_stack_consumer_oracle()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
