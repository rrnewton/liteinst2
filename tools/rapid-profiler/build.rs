#![deny(warnings)]
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

    native_interval_subject(&manifest_dir, &out_dir);
    native_branch_subject(&manifest_dir, &out_dir);
}

// This fixture is mandatory for the unconditionally registered native target.
// It has its own producer record; the legacy Clang fixture above is unchanged.
fn native_interval_subject(manifest_dir: &Path, out_dir: &Path) {
    let source = manifest_dir.join("native-interval/subject.S");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=NATIVE_INTERVAL_DSO");
    println!("cargo:rerun-if-env-changed=CC");
    let record = out_dir.join("native-interval-producer.txt");
    native_output_file(&record);
    let subject = if let Some(path) = env::var_os("NATIVE_INTERVAL_DSO") {
        let path = PathBuf::from(path);
        native_subject_file(&path);
        println!("cargo:rerun-if-changed={}", path.display());
        std::fs::write(
            &record,
            format!("producer=external-admitted-override\nsubject={path:?}\nsource={source:?}\n"),
        )
        .expect("record explicit native subject override");
        path
    } else {
        let directory = out_dir.join("native-interval");
        std::fs::create_dir_all(&directory).expect("create native subject output directory");
        assert_eq!(
            directory.canonicalize().unwrap(),
            directory,
            "owned OUT_DIR directory"
        );
        let temporary = directory.join("tmp");
        std::fs::create_dir_all(&temporary).expect("create native subject temporary directory");
        assert_eq!(
            temporary.canonicalize().unwrap(),
            temporary,
            "owned native temporary directory"
        );
        let object = directory.join("subject.o");
        let depfile = directory.join("subject.d");
        let subject = directory.join("subject.so");
        for path in [&object, &depfile, &subject] {
            native_output_file(path);
        }
        let compiler = env::var_os("CC").unwrap_or_else(|| "gcc".into());
        let assemble = [
            "-fPIC".into(),
            "-c".into(),
            "-Wa,--fatal-warnings".into(),
            "-MD".into(),
            "-MF".into(),
            depfile.as_os_str().to_owned(),
            source.as_os_str().to_owned(),
            "-o".into(),
            object.as_os_str().to_owned(),
        ];
        let link = [
            "-shared".into(),
            "-nostdlib".into(),
            "-Wl,-Bsymbolic,--no-undefined,--build-id=none,-z,relro,-z,now,-z,noexecstack".into(),
            object.as_os_str().to_owned(),
            "-o".into(),
            subject.as_os_str().to_owned(),
        ];
        let workspace = manifest_dir.parent().unwrap().parent().unwrap();
        for arguments in [&assemble[..], &link[..]] {
            let status = Command::new(&compiler)
                .args(arguments)
                .current_dir(workspace)
                .env_clear()
                .env("LC_ALL", "C")
                .env("PATH", "/usr/bin:/bin")
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .env("TMPDIR", &temporary)
                .status()
                .expect("run mandatory native subject compiler");
            assert!(status.success(), "native subject compiler failed: {status}");
        }
        native_subject_file(&subject);
        assert!(
            depfile.is_file() && object.is_file(),
            "native producer outputs required"
        );
        std::fs::write(
            &record,
            format!("producer=out-dir-fallback\nsubject={subject:?}\nsource={source:?}\ncompiler_lookup={compiler:?}\ncwd={workspace:?}\nassemble_argv={assemble:?}\nlink_argv={link:?}\nLC_ALL=C\nPATH=/usr/bin:/bin\nPYTHONDONTWRITEBYTECODE=1\nTMPDIR={temporary:?}\n"),
        )
        .expect("record actual native subject producer");
        subject
    };
    let value = subject.to_str().expect("native subject path is UTF-8");
    assert!(
        !value.contains('\n') && !value.contains('\r'),
        "single-line native subject path"
    );
    println!("cargo:rustc-env=NATIVE_INTERVAL_DSO={value}");
}

// Independent producer for the additive, exact two-return fixture.
fn native_branch_subject(manifest_dir: &Path, out_dir: &Path) {
    let source = manifest_dir.join("native-interval/branch-subject.S");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=NATIVE_BRANCH_DSO");
    println!("cargo:rerun-if-env-changed=CC");
    let record = out_dir.join("native-branch-producer.txt");
    native_output_file(&record);
    let subject = if let Some(path) = env::var_os("NATIVE_BRANCH_DSO") {
        let path = PathBuf::from(path);
        native_subject_file(&path);
        println!("cargo:rerun-if-changed={}", path.display());
        std::fs::write(
            &record,
            format!("producer=external-admitted-override\nsubject={path:?}\nsource={source:?}\n"),
        )
        .expect("record explicit native subject override");
        path
    } else {
        let directory = out_dir.join("native-branch");
        std::fs::create_dir_all(&directory).expect("create native subject output directory");
        assert_eq!(
            directory.canonicalize().unwrap(),
            directory,
            "owned OUT_DIR directory"
        );
        let temporary = directory.join("tmp");
        std::fs::create_dir_all(&temporary).expect("create native subject temporary directory");
        assert_eq!(
            temporary.canonicalize().unwrap(),
            temporary,
            "owned native temporary directory"
        );
        let object = directory.join("subject.o");
        let depfile = directory.join("subject.d");
        let subject = directory.join("subject.so");
        for path in [&object, &depfile, &subject] {
            native_output_file(path);
        }
        let compiler = env::var_os("CC").unwrap_or_else(|| "gcc".into());
        let assemble = [
            "-fPIC".into(),
            "-c".into(),
            "-Wa,--fatal-warnings".into(),
            "-MD".into(),
            "-MF".into(),
            depfile.as_os_str().to_owned(),
            source.as_os_str().to_owned(),
            "-o".into(),
            object.as_os_str().to_owned(),
        ];
        let link = [
            "-shared".into(),
            "-nostdlib".into(),
            "-Wl,-Bsymbolic,--no-undefined,--build-id=none,-z,relro,-z,now,-z,noexecstack".into(),
            object.as_os_str().to_owned(),
            "-o".into(),
            subject.as_os_str().to_owned(),
        ];
        let workspace = manifest_dir.parent().unwrap().parent().unwrap();
        for arguments in [&assemble[..], &link[..]] {
            let status = Command::new(&compiler)
                .args(arguments)
                .current_dir(workspace)
                .env_clear()
                .env("LC_ALL", "C")
                .env("PATH", "/usr/bin:/bin")
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .env("TMPDIR", &temporary)
                .status()
                .expect("run mandatory native subject compiler");
            assert!(status.success(), "native subject compiler failed: {status}");
        }
        native_subject_file(&subject);
        assert!(
            depfile.is_file() && object.is_file(),
            "native producer outputs required"
        );
        std::fs::write(
            &record,
            format!("producer=out-dir-fallback\nsubject={subject:?}\nsource={source:?}\ncompiler_lookup={compiler:?}\ncwd={workspace:?}\nassemble_argv={assemble:?}\nlink_argv={link:?}\nLC_ALL=C\nPATH=/usr/bin:/bin\nPYTHONDONTWRITEBYTECODE=1\nTMPDIR={temporary:?}\n"),
        )
        .expect("record actual native subject producer");
        subject
    };
    let value = subject.to_str().expect("native subject path is UTF-8");
    assert!(
        !value.contains('\n') && !value.contains('\r'),
        "single-line native subject path"
    );
    println!("cargo:rustc-env=NATIVE_BRANCH_DSO={value}");
}

fn native_output_file(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => assert!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "ordinary owned output"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("cannot inspect native output: {error}"),
    }
}

fn native_subject_file(path: &Path) {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let text = path.to_str().expect("native subject path is UTF-8");
    assert!(
        !text.contains('\n') && !text.contains('\r'),
        "single-line native subject owner"
    );
    assert!(path.is_absolute(), "explicit absolute native subject owner");
    assert_eq!(
        path.canonicalize().expect("native subject exists"),
        path,
        "canonical native subject owner"
    );
    let metadata = std::fs::symlink_metadata(path).expect("native subject metadata");
    assert!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && (64..=1024 * 1024).contains(&metadata.len()),
        "bounded regular native subject required"
    );
    let file = std::fs::File::open(path).expect("readable native subject required");
    let opened = file.metadata().expect("opened native subject metadata");
    assert_eq!(
        (opened.dev(), opened.ino(), opened.len()),
        (metadata.dev(), metadata.ino(), metadata.len()),
        "opened subject owner"
    );
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .expect("read bounded native subject");
    assert_eq!(
        bytes.len() as u64,
        metadata.len(),
        "complete bounded subject read"
    );
    assert!(
        bytes.get(..7) == Some(b"\x7fELF\x02\x01\x01") && bytes.get(16..20) == Some(&[3, 0, 62, 0]),
        "x86-64 little-endian ELF shared object required"
    );
    let after = std::fs::symlink_metadata(path).expect("native subject remains owned");
    assert_eq!(
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        ),
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec()
        ),
        "subject owner stable across read"
    );
    assert_eq!(
        path.canonicalize().unwrap(),
        path,
        "canonical owner remains exact"
    );
}
