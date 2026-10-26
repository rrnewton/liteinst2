#!/usr/bin/env python3
"""Finite reproduction of the two-return fixture using the existing helper."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time


def main():
    if sys.flags.optimize:
        raise SystemExit("Assertions required")
    parser = argparse.ArgumentParser()
    for name in ("raw", "toolchain", "user-home", "cargo-home"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    raw = args.raw
    assert raw.is_absolute() and raw.parent.resolve() == raw.parent
    assert raw.is_relative_to(repo / "ignored") and not raw.exists()
    for path in (args.toolchain, args.user_home, args.cargo_home):
        assert path.is_absolute() and path.resolve() == path and path.is_dir()
    git = lambda *argv: subprocess.check_output(["git", "-C", str(repo), *argv], timeout=15)
    revision = git("rev-parse", "HEAD").decode().strip()
    assert not git("diff", "HEAD", "--"), "clean tracked source required"
    sources = {
        name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
        for name in git("ls-files", "-z").decode().split("\0") if name
    }
    raw.mkdir()
    def save(name, data):
        with (raw / name).open("x") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
    cpu = Path("/proc/cpuinfo").read_text()
    model = next(row.split(":", 1)[1].strip() for row in cpu.splitlines() if row.startswith("model name"))
    save("source.json", {"revision": revision, "files": sources})
    save("hardware.json", {"cpu_model": model, "architecture": platform.machine(),
         "logical_cpus": os.cpu_count(), "kernel_release": platform.release(),
         "libc": platform.libc_ver()})
    toolchain = args.toolchain / "bin"
    cargo = str(toolchain / "cargo")
    environment = {
        "CARGO_BUILD_JOBS": "4", "CARGO_HOME": str(args.cargo_home),
        "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
        "CARGO_PROFILE_DEV_CODEGEN_UNITS": "1", "CARGO_PROFILE_TEST_CODEGEN_UNITS": "1",
        "CARGO_TARGET_DIR": str(repo / "target"), "HOME": str(args.user_home),
        "LC_ALL": "C", "PATH": str(toolchain) + ":/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1", "RUSTC": str(toolchain / "rustc"),
        "RUSTC_WORKSPACE_WRAPPER": "", "RUSTC_WRAPPER": "",
        "RUSTDOC": str(toolchain / "rustdoc"), "RUSTDOCFLAGS": "-Dwarnings",
        "RUSTFLAGS": "-Dwarnings -Funsafe-op-in-unsafe-fn -Ccodegen-units=1",
        "RUST_TEST_THREADS": "1",
    }
    save("tools.json", {name: subprocess.check_output(argv, env=environment, text=True, timeout=15)
         for name, argv in (("rustc", [str(toolchain / "rustc"), "-vV"]),
                            ("cargo", [cargo, "-V"]), ("gcc", ["/usr/bin/gcc", "--version"]))})
    results = []
    required = [("fmt", ["fmt", "--check"]),
                ("clippy", ["clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]),
                ("test", ["test", "--workspace"]),
                ("check", ["check", "--workspace", "--all-features", "--all-targets"])]
    modes = ("straight", "budget", "generation", "refusals", "two-returns-paths",
             "two-returns-budget", "two-returns-generation", "two-returns-refusals")
    expected_stdout = {
        "straight": "native-leaf:straight:calls_per_phase=2:phases=3:visits_per_phase=10:events=4:completed=2:refused=0\n",
        "budget": "native-leaf:budget:calls_per_phase=6:phases=3:visits_per_phase=30:events=12:completed=2:refused=4\n",
        "generation": "native-leaf:generation:calls_per_phase=4:phases=3:visits_per_phase=20:events=8:completed=4:refused=0\n",
        "refusals": "native-leaf:refusals:required=6:beforewrite=6:source-page-unchanged\nnative-leaf:permissions:required=2:beforewrite=2:header-page-restored\n",
        "two-returns-paths": "native-two-returns:paths:calls_per_phase=4:phases=3:visits_per_phase=32:events=8:completed=4:refused=0\n",
        "two-returns-budget": "native-two-returns:budget:calls_per_phase=4:phases=3:visits_per_phase=32:events=8:completed=2:refused=2\n",
        "two-returns-generation": "native-two-returns:generation:calls_per_phase=4:phases=3:visits_per_phase=32:events=8:completed=4:refused=0\n",
        "two-returns-refusals": "native-two-returns:refusals:required=4:beforewrite=4:source-page-unchanged\n",
    }
    save("inventory.json", [name for name, _ in required] + ["native-compile"] + list(modes))
    expected_files = json.loads((repo / "evaluation/frontend-native-gate-clock/expected/expected-native-files.json").read_text())
    root_files = ["loader-before.maps", "loader-after.maps", "loader.json", "source-page.bin"]
    branch_files = list(root_files)
    for case in range(2):
        base = "case-" + str(case) + "/"
        branch_files.extend(base + name for name in ("plan.json", "truth.json", "expected-events.json"))
        branch_files.extend(base + kind + "-" + str(index) + ".bin" for kind in ("generated", "source-edit") for index in range(3))
        for phase in ("original", "installed", "retired"):
            branch_files.append(base + phase + "-reports.json")
            phase_base = base + phase + "/"
            branch_files.extend(phase_base + name for name in ("child.json", "journal.bin"))
            for call in range(2):
                stem = phase_base + "call-" + str(call)
                branch_files.append(stem + ".json")
                branch_files.extend(stem + "-" + point + "." + suffix
                    for point in ["before", "after"] + ["point-" + str(index) for index in range(9)]
                    for suffix in ("regs", "xstate", "data", "stack"))
    assert len(branch_files) == len(set(branch_files)) == 580
    for mode in modes[4:7]:
        expected_files[mode] = sorted(branch_files)
    expected_files["two-returns-refusals"] = sorted(root_files + ["refusals.json"])
    assert {key: len(expected_files[key]) for key in modes[:4]} == {"straight": 213, "budget": 620, "generation": 422, "refusals": 13}
    save("expected-native-files.json", expected_files)

    def execute(name, argv, env, native=False):
        directory = raw / name
        directory.mkdir()
        (directory / "tmp").mkdir()
        env = dict(env, TMPDIR=str(directory / "tmp"))
        row = {"name": name, "argv": argv, "cwd": str(repo), "env": env}
        started = time.monotonic()
        if native:
            compiler = name == "native-compile"
            request = dict(argv=argv, cwd=str(repo), env=env,
                           stdout=str(directory / "stdout.txt"), stderr=str(directory / "stderr.txt"),
                           cpu_seconds=60 if compiler else 20,
                           wall_seconds=90 if compiler else 30,
                           file_bytes=(128 if compiler else 16) * 1024 * 1024)
            with (directory / "request.json").open("x") as stream:
                json.dump(request, stream, indent=2)
                stream.write("\n")
            actual = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
                      "100s" if compiler else "40s", "/usr/bin/python3.9", "-B",
                      str(repo / "tools/unwind-oracle/bounded_command.py"),
                      "--request", str(directory / "request.json"),
                      "--receipt", str(directory / "receipt.json")]
            outer_env = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
            stdout, stderr, deadline = "helper.stdout", "helper.stderr", 115 if compiler else 55
            row["request"] = request
        else:
            # The unchanged required-gates.py owns the original per-command
            # 180/180/360/180 limits and four test threads.
            actual = argv
            outer_env = env
            stdout, stderr, deadline = "stdout.txt", "stderr.txt", 1000
        row.update(outer_argv=actual, outer_env=outer_env, parent_timeout_seconds=deadline)
        with (directory / stdout).open("xb") as out, (directory / stderr).open("xb") as err:
            process = subprocess.Popen(actual, cwd=repo, env=outer_env, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True)
            try:
                result = process.wait(timeout=deadline)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                result = process.wait()
                row["parent_timeout"] = True
        row.update(exit=result, elapsed_seconds=time.monotonic() - started)
        results.append(row)
        save("result-" + name + ".json", row)
        print(name, result, flush=True)
        assert result == 0, "failed phase retained; later phases unrun"
        if native:
            receipt = json.loads((directory / "receipt.json").read_text())
            assert set(receipt) == {"request_sha256", "helper_sha256", "exit", "wall_timeout",
                    "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256",
                    "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
            assert type(receipt["exit"]) is int and receipt["exit"] == 0
            assert type(receipt["wall_timeout"]) is bool and not receipt["wall_timeout"]
            assert type(receipt["inputs_unchanged"]) is bool
            assert type(receipt["elapsed_seconds"]) in (float, int) and math.isfinite(receipt["elapsed_seconds"]) and receipt["elapsed_seconds"] >= 0
            assert receipt["request_sha256"] == hashlib.sha256((directory / "request.json").read_bytes()).hexdigest()
            assert receipt["helper_sha256"] == hashlib.sha256((repo / "tools/unwind-oracle/bounded_command.py").read_bytes()).hexdigest()
            helper_output = {"exit": 0, "wall_timeout": False, "absence_proof": "ECHILD", "descendants": 0, "success": True}
            assert (directory / "helper.stdout").read_text() == json.dumps(helper_output) + "\n"
            assert receipt["absence_proof"] == "ECHILD" and receipt["inputs_unchanged"]
            assert type(receipt["unexpected_descendants"]) is list and receipt["unexpected_descendants"] == []
            assert type(receipt["cleanup_events"]) is list and receipt["cleanup_events"] == []
            assert receipt["cleanup_error"] is None and receipt["aborted"] is None
            assert not (directory / "helper.stderr").read_bytes()
            for key in ("stdout", "stderr"):
                assert receipt[key + "_sha256"] == hashlib.sha256((directory / (key + ".txt")).read_bytes()).hexdigest()
            if name in expected_stdout:
                assert (directory / "stdout.txt").read_text() == expected_stdout[name]
                assert not (directory / "stderr.txt").read_bytes()
                capture_root = directory / "captures"
                captures = list(capture_root.rglob("*"))
                assert all(not path.is_symlink() and (path.is_dir() or path.is_file()) for path in captures)
                assert sorted(str(path.relative_to(capture_root)) for path in captures if path.is_file()) == expected_files[name]
                # Exact filename inventory complements the in-binary assertions;
                # independent whole-capture review is a separate evidence step.
        return directory

    try:
        required_env = {key: value for key, value in environment.items()
                        if key not in ("RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_PROFILE_DEV_CODEGEN_UNITS", "CARGO_PROFILE_TEST_CODEGEN_UNITS")}
        required_env["RUST_TEST_THREADS"] = "4"
        required_dir = execute("required", ["/usr/bin/python3.9", "-B", str(repo / "evaluation/required-gates.py"),
                               "--repo", str(repo), "--output", str(raw / "required/gates")], required_env)
        gate_records = json.loads((required_dir / "gates/commands.json").read_text())
        assert gate_records["head"] == revision
        assert [(row["name"], row["argv"]) for row in gate_records["records"]] == [(name, ["cargo", *argv]) for name, argv in required]
        assert all(row["exit"] == 0 for row in gate_records["records"])
        compiled = execute("native-compile", [cargo, "build", "--manifest-path", str(repo / "Cargo.toml"),
                           "-p", "rapid-profiler", "--bin", "frontend-native-oracle", "--offline",
                           "--locked", "--message-format=json"], environment, True)
        messages = [json.loads(row) for row in (compiled / "stdout.txt").read_text().splitlines()]
        assert 1 <= len(messages) <= 256
        assert messages[-1] == {"reason": "build-finished", "success": True}
        assert sum(row.get("reason") == "build-finished" for row in messages) == 1
        assert all(row.get("reason") in ("compiler-artifact", "build-script-executed", "build-finished") for row in messages)
        assert not any(row.startswith(("warning:", "error:")) for row in (compiled / "stderr.txt").read_text().splitlines())
        artifacts = [row for row in messages if row.get("reason") == "compiler-artifact"
                     and row["target"]["name"] == "frontend-native-oracle"]
        assert len(artifacts) == 1 and artifacts[0]["executable"]
        artifact = artifacts[0]
        native_package = "path+" + (repo / "tools/rapid-profiler").as_uri() + "#0.1.0"
        assert artifact["package_id"] == native_package
        assert artifact["manifest_path"] == str(repo / "tools/rapid-profiler/Cargo.toml")
        assert artifact["target"] == {
            "kind": ["bin"], "crate_types": ["bin"], "name": "frontend-native-oracle",
            "src_path": str(repo / "tools/rapid-profiler/native-interval/main.rs"),
            "edition": "2024", "doc": True, "doctest": False, "test": False,
        }
        assert artifact["profile"] == {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                                       "overflow_checks": True, "test": False}
        assert artifact["features"] == [] and type(artifact["fresh"]) is bool
        assert artifact["filenames"] == [str(repo / "target/debug/frontend-native-oracle")]
        assert artifact["executable"] == artifact["filenames"][0]
        producers = [row for row in messages if row.get("reason") == "build-script-executed"
                     and any(key == "NATIVE_BRANCH_DSO" for key, _ in row.get("env", []))]
        assert len(producers) == 1
        assert producers[0]["package_id"] == native_package
        producer_env = dict(producers[0]["env"])
        assert len(producer_env) == len(producers[0]["env"])
        artifact_dir = raw / "artifacts"
        artifact_dir.mkdir()
        binary = artifact_dir / "native-oracle"
        shutil.copy2(artifacts[0]["executable"], binary)
        subjects = {key: Path(producer_env[key]) for key in ("NATIVE_INTERVAL_DSO", "NATIVE_BRANCH_DSO")}
        binding = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                   "artifact": artifacts[0], "producer": producers[0],
                   "subjects": {key: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                for key, path in subjects.items()}}
        save("artifacts.json", binding)
        runtime_env = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
        for mode in modes:
            subject = subjects["NATIVE_BRANCH_DSO" if mode.startswith("two-returns-") else "NATIVE_INTERVAL_DSO"]
            execute(mode, [str(binary), mode, str(subject), str(raw / mode / "captures")], runtime_env, True)
    finally:
        save("results.json", results)
        save("source-after.json", {"revision": git("rev-parse", "HEAD").decode().strip(),
             "files": {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in sources}})
    assert git("rev-parse", "HEAD").decode().strip() == revision
    assert not git("diff", "HEAD", "--")
    assert all(hashlib.sha256((repo / name).read_bytes()).hexdigest() == digest for name, digest in sources.items())


if __name__ == "__main__":
    main()
