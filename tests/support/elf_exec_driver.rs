//! Explicit standalone native campaign; ordinary Cargo tests never run it.
#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[allow(dead_code)]
#[path = "quiescent_oracle.rs"]
mod oracle;

fn main() {
    oracle::elf_exec_oracle::main();
}
