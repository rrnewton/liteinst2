//! Explicit standalone native campaign; ordinary Cargo tests never run it.
#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[allow(dead_code)]
#[path = "quiescent_oracle.rs"]
mod oracle;

fn main() {
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("common-core-router-controls"))
    {
        oracle::elf_exec_oracle::common_image::core_pair::router_controls_main();
        return;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("replay-common-e9")) {
        oracle::elf_exec_oracle::common_image::e9_pair::main();
        return;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("replay-common-core")) {
        oracle::elf_exec_oracle::common_image::core_pair::main();
        return;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("replay-common-original"))
    {
        oracle::elf_exec_oracle::common_image::main();
        return;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("observe-common-app")) {
        oracle::elf_exec_oracle::common_app::main();
        return;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("run-tactics")) {
        oracle::elf_exec_oracle::tactics::main();
        return;
    }
    oracle::elf_exec_oracle::main();
}
