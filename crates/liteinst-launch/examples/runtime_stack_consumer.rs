//! Finite public-API consumer; generated inputs belong to the separate recorder.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "support/runtime_stack_consumer.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> std::process::ExitCode {
    platform::main()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() -> std::process::ExitCode {
    eprintln!("runtime_stack_consumer requires Linux x86-64");
    std::process::ExitCode::from(2)
}
