#!/usr/bin/env python3
"""Qualify the offline frontend and its normally loaded fixed ET_EXEC fixture."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
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
    git = lambda *a: subprocess.check_output(["/usr/bin/git", "-C", str(repo), *a], timeout=15)
    digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    revision = git("rev-parse", "HEAD").decode().strip()
    assert not git("diff", "HEAD", "--"), "clean tracked source required"
    sources = {name: digest(repo / name)
               for name in git("ls-files", "-z").decode().split("\0") if name}
    assert "BRIEF-li2core.md" not in sources
    assert str(Path(__file__).resolve().relative_to(repo)) in sources
    raw.mkdir()

    def save(name, value):
        with (raw / name).open("x") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")

    save("source.json", {"revision": revision, "files": sources})
    cpu = Path("/proc/cpuinfo").read_text()
    save("hardware.json", {
        "cpu_model": next(row.split(":", 1)[1].strip() for row in cpu.splitlines()
                          if row.startswith("model name")),
        "architecture": platform.machine(), "logical_cpus": os.cpu_count(),
        "kernel_release": platform.release(), "libc": platform.libc_ver(),
    })
    tool = args.toolchain / "bin"
    env = {
        "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(repo / "target"),
        "CARGO_HOME": str(args.cargo_home), "HOME": str(args.user_home),
        "RUSTC": str(tool / "rustc"), "RUSTDOC": str(tool / "rustdoc"),
        "RUSTC_WORKSPACE_WRAPPER": "", "RUSTC_WRAPPER": "",
        "RUST_TEST_THREADS": "4", "LC_ALL": "C",
        "PATH": str(tool) + ":/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
    }
    runtime_env = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    tools = {}
    for name, executable, option in (
        ("rustc", tool / "rustc", "-vV"), ("cargo", tool / "cargo", "-V"),
        ("gcc", Path("/usr/bin/gcc"), "--version"),
        ("ld", Path("/usr/bin/ld"), "--version"),
        ("strip", Path("/usr/bin/strip"), "--version"),
    ):
        tools[name] = {"argv": [str(executable), option], "sha256": digest(executable.resolve()),
                       "output": subprocess.check_output([str(executable), option], env=env,
                                                         text=True, timeout=15)}
    save("tools.json", tools)
    stage_names = ["required", "comparison", "native-compile", "codec-compile", "target",
                   "assemble", "link", "strip"]
    for strip_state in ("unstripped", "stripped"):
        for hook in ("null", "journal"):
            stage_names.extend(prefix + strip_state + "-" + hook
                               for prefix in ("select-", "prepare-", "verify-"))
    stage_names += ["native", "ordinary-original-unstripped", "ordinary-original-stripped"]
    stage_names += ["ordinary-candidate-" + str(index) for index in range(4)]
    assert len(stage_names) == 27
    save("stage-inventory.json", stage_names)
    results = []
    helper = repo / "tools/unwind-oracle/bounded_command.py"

    def execute(name, argv, environment, compiler=False, required=False):
        assert name == stage_names[len(results)], "finite stage inventory and order"
        directory = raw / name
        directory.mkdir()
        (directory / "tmp").mkdir()
        environment = dict(environment, TMPDIR=str(directory / "tmp"))
        row = {"name": name, "argv": argv, "cwd": str(repo), "env": environment,
               "start_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        if required:
            actual, outer_env, timeout = argv, environment, 1000
            stdout, stderr = "stdout.txt", "stderr.txt"
        else:
            request = dict(argv=argv, cwd=str(repo), env=environment,
                           stdout=str(directory / "stdout.txt"), stderr=str(directory / "stderr.txt"),
                           cpu_seconds=60 if compiler else 20,
                           wall_seconds=90 if compiler else 30,
                           file_bytes=(128 if compiler else 16) * 1024 * 1024)
            save(name + "/request.json", request)
            actual = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
                      "100s" if compiler else "40s", "/usr/bin/python3.9", "-B", str(helper),
                      "--request", str(directory / "request.json"),
                      "--receipt", str(directory / "receipt.json")]
            outer_env = runtime_env
            timeout = 115 if compiler else 55
            stdout, stderr = "helper.stdout", "helper.stderr"
            row["request"] = request
        row.update(outer_argv=actual, outer_env=outer_env, parent_timeout_seconds=timeout)
        save(name + "/command.json", row)
        started = time.monotonic()
        with (directory / stdout).open("xb") as out, (directory / stderr).open("xb") as err:
            process = subprocess.Popen(actual, cwd=repo, env=outer_env, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
                row["parent_timeout"] = True
        row.update(exit=code, elapsed_seconds=time.monotonic() - started)
        results.append(row)
        save(name + "/result.json", row)
        print(name, code, flush=True)
        assert code == 0, "failed phase retained; later phases unrun"
        if not required:
            receipt = json.loads((directory / "receipt.json").read_text())
            assert set(receipt) == {"request_sha256", "helper_sha256", "exit", "wall_timeout",
                    "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256",
                    "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
            assert type(receipt["exit"]) is int and receipt["exit"] == 0
            assert receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True
            assert type(receipt["elapsed_seconds"]) in (int, float)
            assert math.isfinite(receipt["elapsed_seconds"]) and receipt["elapsed_seconds"] >= 0
            assert receipt["request_sha256"] == digest(directory / "request.json")
            assert receipt["helper_sha256"] == digest(helper)
            assert receipt["absence_proof"] == "ECHILD"
            assert receipt["unexpected_descendants"] == [] and receipt["cleanup_events"] == []
            assert receipt["cleanup_error"] is None and receipt["aborted"] is None
            expected = {"exit": 0, "wall_timeout": False, "absence_proof": "ECHILD", "descendants": 0, "success": True}
            assert (directory / "helper.stdout").read_text() == json.dumps(expected) + "\n"
            assert not (directory / "helper.stderr").read_bytes()
            for key in ("stdout", "stderr"):
                assert receipt[key + "_sha256"] == digest(directory / (key + ".txt"))
        return directory

    def authenticate(directory, original, selection):
        expected = {"COMPLETE", "bundle-index.tsv", "candidate.elf", "image-0000.bin",
                    "ledger.tsv", "metadata.li2meta", "plan-ledger.tsv", "report.tsv",
                    "selection.txt", "site-1.diagnostics.txt", "source.li2sparse", "target.tsv"}
        paths = list(directory.iterdir())
        assert {p.name for p in paths} == expected
        assert all(stat.S_ISREG(p.lstat().st_mode) and p.stat().st_size <= 1024 * 1024
                   and stat.S_IMODE(p.stat().st_mode) == 0o600 for p in paths)
        index = directory / "bundle-index.tsv"
        assert (directory / "COMPLETE").read_text() == (
            "LI2TOOL-DIRECTORY 1\nindex_sha256 " + digest(index)
            + "\ncandidate_complete true\nqualification_complete false\n")
        rows = index.read_text().splitlines()
        assert rows[:4] == ["LI2BUNDLE\t1", "original_sha256\t" + digest(original),
                           "qualification_complete\tfalse",
                           "consumer_action\tRuntimeScan-while-gated-until-qualified"]
        wanted = sorted(expected - {"COMPLETE", "bundle-index.tsv"})
        assert rows[4:] == ["file\t" + name + "\t" + str((directory / name).stat().st_size)
                            + "\t" + digest(directory / name) for name in wanted]
        assert (directory / "selection.txt").read_bytes() == selection.read_bytes()
        return {name: digest(directory / name) for name in sorted(expected)}

    try:
        gates = execute("required", ["/usr/bin/python3.9", "-B", str(repo / "evaluation/required-gates.py"),
                         "--repo", str(repo), "--output", str(raw / "required/gates")], env, required=True)
        records = json.loads((gates / "gates/commands.json").read_text())
        assert records["head"] == revision and records["source_sha256"] == sources
        assert [(r["name"], r["exit"]) for r in records["records"]] == [
            ("fmt", 0), ("clippy", 0), ("test", 0), ("check", 0)]
        calibration = execute("comparison", ["/usr/bin/python3.9", "-B",
                              str(repo / "tools/elf-rewrite/tests/compare_sites.py")], runtime_env)
        assert not (calibration / "stderr.txt").read_bytes()
        assert (calibration / "stdout.txt").read_text() == (
            "comparison calibrations: one exact loss/trap inventory and five required refusals\n"
            "comparison calibrations: original one/five retained; total three positives and 24 required refusals\n")
        compiled = execute("native-compile", [str(tool / "cargo"), "build", "-p", "liteinst2",
                           "-p", "liteinst-rewrite", "--bin", "elf-exec-oracle", "--bin", "liteinst-rewrite",
                           "--offline", "--locked", "--message-format=json"], env, compiler=True)
        codec = execute("codec-compile", [str(tool / "cargo"), "build", "-p", "liteinst-rewrite",
                        "--example", "verify_elf_exec", "--offline", "--locked", "--message-format=json"],
                        env, compiler=True)
        artifacts = raw / "artifacts"
        artifacts.mkdir()
        binaries = {}
        for name, package_path, compilation, kind in (
            ("elf-exec-oracle", repo, compiled, "bin"),
            ("liteinst-rewrite", repo / "tools/elf-rewrite", compiled, "bin"),
            ("verify_elf_exec", repo / "tools/elf-rewrite", codec, "example"),
        ):
            messages = [json.loads(line) for line in (compilation / "stdout.txt").read_text().splitlines()]
            assert 1 <= len(messages) <= 256
            assert messages[-1] == {"reason": "build-finished", "success": True}
            assert sum(row.get("reason") == "build-finished" for row in messages) == 1
            assert all(row.get("reason") in ("compiler-artifact", "build-script-executed", "build-finished") for row in messages)
            assert not any(line.startswith(("warning:", "error:")) for line in (compilation / "stderr.txt").read_text().splitlines())
            selected = [row for row in messages if row.get("reason") == "compiler-artifact"
                        and row["target"]["name"] == name and row.get("executable")]
            assert len(selected) == 1
            item = selected[0]
            assert item["manifest_path"] == str(package_path / "Cargo.toml")
            assert item["target"]["kind"] == [kind] and item["target"]["crate_types"] == ["bin"]
            assert item["profile"] == {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                                       "overflow_checks": True, "test": False}
            assert item["features"] == [] and type(item["fresh"]) is bool
            binary_parent = repo / "target/debug"
            if kind == "example":
                binary_parent /= "examples"
            assert item["filenames"] == [str(binary_parent / name)]
            assert item["executable"] == item["filenames"][0]
            binary = artifacts / name
            shutil.copy2(item["executable"], binary)
            binaries[name] = {"artifact": item, "sha256": digest(binary)}
        save("artifacts.json", binaries)
        driver, frontend = artifacts / "elf-exec-oracle", artifacts / "liteinst-rewrite"
        profile = execute("target", [str(driver), "target"], runtime_env)
        assert not (profile / "stderr.txt").read_bytes()
        target_record = profile / "stdout.txt"
        fixture = repo / "tests/fixtures/elf-exec"
        subjects = raw / "subjects"
        subjects.mkdir()
        object_file = subjects / "subject.o"
        original = subjects / "original-unstripped"
        stripped = subjects / "original-stripped"
        execute("assemble", ["/usr/bin/gcc", "-c", "-nostdlib", "-fno-pie", "-Wa,--fatal-warnings",
                              str(fixture / "subject.S"), "-o", str(object_file)], runtime_env)
        execute("link", ["/usr/bin/ld", "-m", "elf_x86_64", "-nostdlib", "--build-id=none", "-z", "noexecstack",
                          "-T", str(fixture / "subject.ld"), str(object_file), "-o", str(original)], runtime_env)
        execute("strip", ["/usr/bin/strip", "--strip-all", "-o", str(stripped), str(original)], runtime_env)
        originals = {"unstripped": original, "stripped": stripped}
        before = {name: digest(path) for name, path in originals.items()}
        candidates = []
        authenticated = {}
        for strip_state, subject in originals.items():
            for hook in ("null", "journal"):
                name = strip_state + "-" + hook
                selection = subjects / (name + ".selection")
                selected = execute("select-" + name, ["/usr/bin/python3.9", "-B", str(repo / "evaluation/elf-exec/render_selection.py"),
                        str(subject), str(target_record), hook, str(selection)], runtime_env)
                assert (selected / "stdout.txt").read_text() == (
                    "selection prepared: sites=1 heads=2 hook=" + hook + " qualification_complete=false\n")
                assert not (selected / "stderr.txt").read_bytes()
                output = raw / (name + "-candidate")
                produced = execute("prepare-" + name, [str(frontend), "prepare", str(subject),
                                   str(selection), str(output)], runtime_env)
                assert (produced / "stdout.txt").read_text() == "candidate_complete=true qualification_complete=false sites=1\n"
                assert not (produced / "stderr.txt").read_bytes()
                authenticated[name] = authenticate(output, subject, selection)
                verified = execute("verify-" + name, [str(artifacts / "verify_elf_exec"), str(subject),
                                   str(selection), str(output)], runtime_env)
                assert (verified / "stdout.txt").read_text() == (
                    "elf exec artifact verified: metadata=1 sparse_pages=1 images=1 qualification_complete=false\n")
                assert not (verified / "stderr.txt").read_bytes()
                candidates.append(output)
        save("originals.json", before)
        save("candidate-files-before.json", authenticated)
        # The driver authenticates all source/image/LOAD bytes and comparisons;
        # it follows startup to the authored CALL without redirecting RIP.
        captures = raw / "captures"
        native = execute("native", [str(driver), "run", str(original), str(stripped),
                          *map(str, candidates), str(captures)], runtime_env)
        assert (native / "stdout.txt").read_text() == (
            "PASS kernel-exec MOV5/RET: 8 original + 16 rewritten traces; 72 full-state comparisons; "
            "24 subject CALL/RETs; 8 hook CALL/RETs; 4 journal rows\n")
        assert not (native / "stderr.txt").read_bytes()
        assert (captures / "complete.tsv").read_text() == (
            "status\tpassed\noriginal_traces\t8\nrewritten_traces\t16\nfull_state_comparisons\t72\n"
            "subject_call_ret_witnesses\t24\nhook_call_return_witnesses\t8\nrecording_hook_rows\t4\n"
            "manual_load_mappings\t0\npost_seed_state_repairs\t0\n")
        copies = [("original-unstripped", original), ("original-stripped", stripped)]
        copies += [("candidate-" + str(index), path / "candidate.elf") for index, path in enumerate(candidates)]
        for name, source in copies:
            copy = captures / name
            assert copy.read_bytes() == source.read_bytes(), "exact executed file identity"
            assert stat.S_IMODE(copy.stat().st_mode) == 0o500
            ordinary = execute("ordinary-" + name, [str(copy)], runtime_env)
            assert (ordinary / "stdout.txt").read_text() == "elf exec ok\n"
            assert not (ordinary / "stderr.txt").read_bytes()
            assert copy.read_bytes() == source.read_bytes()
        after = {}
        for name, output in zip(authenticated, candidates):
            strip_state, hook = name.rsplit("-", 1)
            after[name] = authenticate(output, originals[strip_state], subjects / (name + ".selection"))
        assert after == authenticated
        save("candidate-files-after.json", after)
        capture_files = {"original-unstripped", "original-stripped", "runtime-target.tsv", "complete.tsv"}
        capture_files.update("candidate-" + str(index) for index in range(4))
        capture_files.update(name + ".provider" for name, _ in copies)
        loaded_pages = [0x400000, 0x401000, 0x403000, 0x404000] + list(range(0x406000, 0x416000, 4096))
        trace_directories = set()
        for strip_state in range(2):
            for head in range(2):
                for seed in range(2):
                    for variant in ("original", "hook-0", "hook-1"):
                        directory = f"strip-{strip_state}-head-{head}-seed-{seed}-{variant}"
                        trace_directories.add(directory)
                        names = {"exec.auxv", "exec.maps", "terminal.auxv", "terminal.maps",
                                 "exec.map-files", "terminal.map-files",
                                 "startup-pcs.bin", "before-seed.tsv", "journal.bin", "complete.tsv"}
                        pages = loaded_pages + ([] if variant == "original" else [0x418000, 0x420000])
                        names.update(f"loaded-{address:x}.bin" for address in pages)
                        for stem in ["before-call", "after-call"] + ["point-" + str(i) for i in range(3 - head)]:
                            names.update(stem + suffix for suffix in (".regs", ".xstate", ".data", ".stack"))
                        if variant != "original" and head == 0:
                            names.update(("hook-call.tsv", "hook-ret.tsv", "hook-context.bin", "hook-saved-xstate.bin"))
                        capture_files.update(directory + "/" + name for name in names)
        assert len(trace_directories) == 24 and len(capture_files) == 1230
        captures_list = list(captures.rglob("*"))
        assert all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in captures_list)
        assert {str(p.relative_to(captures)) for p in captures_list if p.is_dir()} == trace_directories
        assert {str(p.relative_to(captures)) for p in captures_list if p.is_file()} == capture_files
        save("capture-files.json", {str(p.relative_to(captures)): digest(p)
                                   for p in sorted(captures_list) if p.is_file()})
        assert [row["name"] for row in results] == stage_names
    finally:
        save("results.json", results)
        save("source-after.json", {"revision": git("rev-parse", "HEAD").decode().strip(),
             "files": {name: digest(repo / name) for name in sources}})
    assert before == {name: digest(path) for name, path in originals.items()}
    assert all(record["sha256"] == digest(artifacts / name) for name, record in binaries.items())
    assert git("rev-parse", "HEAD").decode().strip() == revision
    assert not git("diff", "HEAD", "--")
    assert all(digest(repo / name) == value for name, value in sources.items())


if __name__ == "__main__":
    main()
