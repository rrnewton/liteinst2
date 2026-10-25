#![deny(warnings)]

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=fixtures/fixture.cpp");
    println!("cargo:rerun-if-changed=fixtures/fixture.S");
    println!("cargo:rerun-if-env-changed=CXX");
    assert_eq!(env::var("CARGO_CFG_TARGET_OS").unwrap(), "linux");
    assert_eq!(env::var("CARGO_CFG_TARGET_ARCH").unwrap(), "x86_64");
    let compiler = env::var_os("CXX").unwrap_or_else(|| "g++".into());
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    for (source, object, flags) in [
        (
            "fixture.cpp",
            "exception-cpp.o",
            &[
                "-std=c++17",
                "-O2",
                "-fPIC",
                "-fexceptions",
                "-fno-omit-frame-pointer",
                "-fcf-protection=none",
                "-fno-lto",
                "-Wall",
                "-Wextra",
                "-Werror",
            ][..],
        ),
        (
            "fixture.S",
            "exception-asm.o",
            &["-fPIC", "-fcf-protection=none"][..],
        ),
    ] {
        let object = output.join(object);
        let status = Command::new(&compiler)
            .args(flags)
            .arg("-c")
            .arg(root.join("fixtures").join(source))
            .arg("-o")
            .arg(&object)
            .status()
            .expect("C++ compiler is required for the exception oracle");
        assert!(
            status.success(),
            "exception fixture {source} failed to build"
        );
        assert!(object.is_file());
        println!("cargo:rustc-link-arg-tests={}", object.display());
    }
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=gcc_s");
}
