//! Explicit required physical probe; ordinary cargo test does not execute it.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    // SAFETY: this is a fresh dedicated program with no application workers or
    // handler users. The external gate owns CPU/memory/PID/wall/stream bounds.
    unsafe { liteinst2::trampoline::run_saved_pkru_physical_probe() };
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("PKRU_UNSUPPORTED platform; no protected positive is claimed");
    std::process::exit(2);
}
