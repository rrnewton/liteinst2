//! Explicit standalone native campaign; ordinary Cargo tests never run it.
#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[allow(dead_code)]
#[path = "quiescent_oracle.rs"]
mod oracle;

fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("run-tactics")) {
        oracle::elf_exec_oracle::tactics::main();
        return;
    }
    oracle::elf_exec_oracle::main();
}
