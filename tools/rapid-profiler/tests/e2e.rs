#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use rapid_profiler::RapidProfiler;

fn compile_fixture(output: &PathBuf) {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/simple.c");
    let result = Command::new("clang")
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
        .arg(fixture)
        .arg("-o")
        .arg(output)
        .output()
        .expect("clang must be installed for the rapid-profiler end-to-end test");
    assert!(
        result.status.success(),
        "clang failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn parse_epochs(output: &str) -> Vec<BTreeMap<String, u64>> {
    let mut epochs = Vec::new();
    for line in output.lines() {
        let mut fields = line.split('\t');
        let name = fields.next().unwrap();
        let value = fields.next().unwrap();
        if name == "epoch" {
            epochs.push(BTreeMap::new());
            continue;
        }
        epochs
            .last_mut()
            .expect("function row must follow an epoch header")
            .insert(name.to_owned(), value.parse().unwrap());
    }
    epochs
}

#[test]
fn profiles_every_function_saturates_and_rearms() {
    let output = std::env::temp_dir().join(format!(
        "liteinst2-rapid-profiler-fixture-{}",
        std::process::id()
    ));
    compile_fixture(&output);
    let profiler = RapidProfiler::load(&output, "workload", 1_000).unwrap();
    let reports = profiler
        .run_epochs(2, 2_500, std::time::Duration::from_millis(1))
        .unwrap();
    assert_eq!(reports.len(), 2);
    for report in reports {
        let functions = report
            .functions
            .into_iter()
            .map(|function| (function.function, (function.count, function.self_disabled)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(functions.len(), 4, "{functions:?}");
        assert_eq!(functions["workload"], (1, false));
        assert_eq!(functions["branch"], (1_000, true));
        assert_eq!(functions["leaf_even"], (1_000, true));
        assert_eq!(functions["leaf_odd"], (1_000, true));
    }

    let result = Command::new(env!("CARGO_BIN_EXE_rapid-profiler"))
        .arg(&output)
        .args([
            "--iterations",
            "2500",
            "--limit",
            "1000",
            "--epochs",
            "2",
            "--epoch-ms",
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "profiler failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    let epochs = parse_epochs(&stdout);
    assert_eq!(epochs.len(), 2, "{stdout}");
    for counts in epochs {
        assert_eq!(counts.len(), 4, "{counts:?}");
        assert_eq!(counts["workload"], 1);
        assert_eq!(counts["branch"], 1_000);
        assert_eq!(counts["leaf_even"], 1_000);
        assert_eq!(counts["leaf_odd"], 1_000);
    }
    let _ = std::fs::remove_file(output);
}

#[test]
fn rejects_functions_with_colliding_trampoline_pages() {
    let output = std::env::temp_dir().join(format!(
        "liteinst2-rapid-profiler-collision-{}",
        std::process::id()
    ));
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/simple.c");
    let compile = Command::new("clang")
        .args([
            "-O2",
            "-fpatchable-function-entry=5,0",
            "-fno-pie",
            "-no-pie",
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-Wl,-e,workload",
            "-Wl,--build-id=none",
        ])
        .arg(fixture)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(compile.status.success());
    let result = Command::new(env!("CARGO_BIN_EXE_rapid-profiler"))
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(
        stderr.contains("imply the same trampoline page"),
        "{stderr}"
    );
    let _ = std::fs::remove_file(output);
}
