//! Auto-compile the profiler's punning fixture so `cargo run -p rapid-profiler`
//! Just Works with no manual clang step.
//!
//! The fixture must be laid out exactly as the liteinst2 rapid-probe punning
//! requires: a 5-byte NOP patch slot at each function entry
//! (`-fpatchable-function-entry=5,0`) and 4 KiB-aligned functions so each gets
//! its own trampoline page (`-falign-functions=4096`). It is linked as a
//! freestanding, non-PIE ELF entered at `workload` so the profiler can load and
//! drive it directly.
//!
//! If clang is unavailable the build still succeeds (so plain `cargo build`
//! works everywhere); it just skips emitting the default-fixture env, and the
//! binary then requires an explicit ELF argument.

use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let fixture_src = manifest_dir.join("fixtures/simple.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let fixture_out = out_dir.join("rapid-profiler-fixture");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", fixture_src.display());
    println!("cargo:rerun-if-env-changed=CLANG");

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_owned());

    // Keep these flags identical to tests/e2e.rs::compile_fixture.
    let status = Command::new(&clang)
        .args([
            "-O2",
            "-fpatchable-function-entry=5,0",
            "-falign-functions=4096",
            "-fno-pie",
            "-no-pie",
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-Wl,-e,workload",
            "-Wl,--build-id=none",
            "-Wl,-z,noexecstack",
        ])
        .arg(&fixture_src)
        .arg("-o")
        .arg(&fixture_out)
        .status();

    match status {
        Ok(status) if status.success() && Path::new(&fixture_out).exists() => {
            // main.rs reads this via option_env! to default the profiled image.
            println!(
                "cargo:rustc-env=RAPID_PROFILER_DEFAULT_FIXTURE={}",
                fixture_out.display()
            );
        }
        Ok(status) => {
            println!(
                "cargo:warning=rapid-profiler: {clang} exited {status} building the default \
                 fixture; `cargo run` will require an explicit ELF argument."
            );
        }
        Err(error) => {
            println!(
                "cargo:warning=rapid-profiler: could not run {clang} ({error}); the default \
                 fixture was not built, so `cargo run` will require an explicit ELF argument."
            );
        }
    }
}
