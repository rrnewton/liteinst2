//! Fixed finite scripted selected-completion latency cohort; see the source manifest.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "support/b2_hook_cost.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    platform::run();
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("b2_hook_cost requires Linux x86-64");
    std::process::exit(2);
}
