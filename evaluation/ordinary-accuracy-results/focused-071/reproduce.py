#!/usr/bin/env python3
"""Fixed focused census. Raw output stays in the source checkout's target/ tree."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys


HERE = Path(__file__).resolve().parent
REVISION = "071783b9a3c27ae26c439c7c5b7ac599cfeb7245"
LIMIT = 8 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": sha(raw)}


def save(path, value):
    temporary = path.with_suffix(".next")
    temporary.write_bytes(canonical(value) + b"\n")
    temporary.replace(path)


def commands(cargo, python):
    common = ["--locked", "--offline", "--jobs", "4", "-p", "rapid-profiler"]
    stages = [
        ("fmt", "command", [cargo, "fmt", "--all", "--", "--check"]),
        ("ordinary-check", "command", [cargo, "check"] + common + ["--all-targets", "--all-features"]),
        ("ordinary-clippy", "command", [cargo, "clippy"] + common + ["--all-targets", "--all-features", "--", "-D", "warnings"]),
    ]
    for n, prefix in enumerate(("normal::leaf_set::selected::phase_tests::", "normal::session::phase::tests::"), 1):
        argv = [cargo, "test"] + common + ["--bin", "ordinary-interval", "--all-features", prefix, "--"]
        stages += [(f"rust-phase-{n}-list", "rust_listing", argv + ["--list"]),
                   (f"rust-phase-{n}-run", "rust_tests", argv + ["--test-threads=316"])]
    suites = [
        "ordinary-accuracy/phase_controls.py",
        "ordinary-selected-session/phase_functional_controls.py",
        "ordinary-accuracy/reader_controls.py",
        "ordinary-selected-session/accuracy_functional_controls.py",
        "ordinary-accuracy/test_truth.py",
        "ordinary-leaf-set-session/runner_controls.py",
        "ordinary-selected-session/driver_controls.py",
        "ordinary-call-pair-session/runner_controls.py",
        "ordinary-leaf-set-session/controls.py",
        "ordinary-selected-session/wire_controls.py",
        "ordinary-leaf-set-session/original_controls.py",
        "ordinary-call-pair-session/original_controls.py",
        "ordinary-call-pair-session/owner_controls.py",
        "ordinary-selected-session/build_controls.py",
        "ordinary-selected-session/profile_controls.py",
        "ordinary-selected-session/sdk_state_controls.py",
        "ordinary-selected-session/accuracy_state_controls.py",
    ]
    for n, suite in enumerate(suites, 1):
        path = Path("evaluation") / suite
        tail = (["-m", "unittest", "discover", "-s", str(path.parent), "-p", path.name, "-v"]
                if suite.startswith("ordinary-accuracy/") else [str(path), "-v"])
        stages.append((f"python-{n:02}", "python_tests", [python, "-I", "-B"] + tail))
    return stages


def identity(names, expected):
    assert len(names) == expected["count"] and len(names) == len(set(names))
    assert sha(canonical(sorted(names))) == expected["identities_sha256"]


def census(raw, kind, expected):
    text = raw.decode("utf-8")
    if kind == "rust_listing":
        identity(re.findall(r"^(\S+): test$", text, re.M), expected)
        assert re.findall(r"^(\d+) tests, (\d+) benchmarks$", text, re.M) == [(str(expected["count"]), "0")]
        return 0
    if kind == "rust_tests":
        rows = re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)(?:[ \t][^\r\n]*)?$", text, re.M)
        identity([name for name, _ in rows], expected)
        assert all(status == "ok" for _, status in rows)
        assert re.findall(r"^running (\d+) tests?$", text, re.M) == [str(expected["count"])]
        summaries = re.findall(r"^test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; (\d+) filtered out; finished in ([0-9.]+)s$", text, re.M)
        assert len(summaries) == len(re.findall(r"^test result:", text, re.M)) == 1
        assert summaries[0][:2] == (str(expected["count"]), str(expected["filtered"]))
        assert math.isfinite(float(summaries[0][2]))
    elif kind == "python_tests":
        rows = re.findall(r"^(test_\w+) \(([\w.]+)\) \.\.\. (ok|FAIL|ERROR|skipped[^\n]*|expected failure|unexpected success)$", text, re.M)
        identity([owner + "." + name for name, owner, _ in rows], expected)
        assert all(status == "ok" for _, _, status in rows)
        summaries = re.findall(r"^Ran (\d+) tests? in ([0-9.]+)s$", text, re.M)
        assert len(summaries) == 1 and summaries[0][0] == str(expected["count"])
        assert math.isfinite(float(summaries[0][1]))
        assert re.findall(r"^(OK|FAILED)(?: \([^\n]*\))?$", text, re.M) == ["OK"]
        assert text.rstrip().splitlines()[-1] == "OK"
    else:
        assert kind == "command"
        return 0
    return expected["count"]


def normal(closed, seconds):
    return (closed["cleanup_complete"] is True and closed["exit_code"] == 0
            and closed["termination"] is None and closed["reaped_descendants"] == 0
            and 0 <= closed["seconds"] <= seconds + 3)


def main():
    if sys.flags.optimize:
        raise SystemExit("Assertions must remain enabled")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--cargo", type=Path, required=True, help="Real pinned toolchain binary, not a rustup proxy")
    p.add_argument("--cpus", required=True, help="Four CPUs held by the caller's disjoint reservation")
    p.add_argument("--name", default="focused-071-reproduction")
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    a = p.parse_args()
    root, cargo = a.root.resolve(), a.cargo.resolve()
    assert re.fullmatch(r"[a-zA-Z0-9_-]+", a.name)
    cpus = [int(x) for x in a.cpus.split(",")]
    assert len(cpus) == 4 and cpus == sorted(set(cpus))
    assert set(cpus) <= os.sched_getaffinity(0)
    os.sched_setaffinity(0, cpus)
    receipt = json.loads((HERE / "receipt.json").read_bytes())
    stages = commands(str(cargo), sys.executable)
    assert sha(canonical(commands("$CARGO", "$PYTHON"))) == receipt["commands_sha256"]
    tools = {name: cargo.parent / name for name in receipt["tools"] if name != "python3.9"}
    tools["python3.9"] = Path(sys.executable)

    def unchanged():
        assert os.sched_getaffinity(0) == set(cpus)
        def git(*args):
            return subprocess.check_output(["git", "-C", str(root), *args], timeout=10)
        assert git("rev-parse", "HEAD").decode().strip() == REVISION
        assert not git("diff", "--name-only", "HEAD", "--")
        assert not git("diff", "--cached", "--name-only", "--")
        new = git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
        assert set(new) <= {b"", b"BRIEF-li2core.md"}
        overlay = receipt["source_overlay"]
        paths = git("diff", "--name-only", "-z", overlay["execution_base"], REVISION, "--").decode().split("\0")[:-1]
        assert len(paths) == overlay["files"] == 35
        assert sha(canonical({name: pin(root / name) for name in paths})) == overlay["manifest_sha256"]
        for name, expected in receipt["sources"].items():
            assert pin(root / name) == expected, name
        for name, expected in receipt["tools"].items():
            assert pin(tools[name]) == expected, name

    unchanged()
    helper = root / "evaluation/admission/processes.py"
    spec = importlib.util.spec_from_file_location("focused_owner", helper)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    out = root / "target/evaluation" / a.name
    if not a.worker:
        out.mkdir(parents=True, exist_ok=False)
        (out / "tmp").mkdir()
    assert out.is_dir()
    env = {key: value for key, value in receipt["environment"].items() if not value.startswith("$")}
    env.update(HOME=os.environ["HOME"], CARGO_HOME=os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
               PATH=str(cargo.parent) + ":/usr/bin:/bin", RUSTC=str(tools["rustc"]), RUSTDOC=str(tools["rustdoc"]),
               CARGO_TARGET_DIR=str(root / "target"), TMPDIR=str(out / "tmp"), TMP=str(out / "tmp"), TEMP=str(out / "tmp"))
    rows = [{"name": name, "kind": kind, "status": "UNRUN", "attempts": 0, "passed_executions": 0}
            for name, kind, _ in stages]

    def checkpoint(complete=False):
        counts = {"stages_passed": sum(r["status"] == "PASS" for r in rows),
                  "rust_passed": sum(r.get("passed_executions", 0) for r in rows if r["kind"] == "rust_tests"),
                  "python_passed": sum(r.get("passed_executions", 0) for r in rows if r["kind"] == "python_tests")}
        passed = complete and len(rows) == 24 and all(r["status"] == "PASS" for r in rows)
        if passed:
            assert counts == {"stages_passed": 24, "rust_passed": 9, "python_passed": 198}
        save(out / "child.json", {"all_pass": passed, "counts": counts, "rows": rows,
                                  "qualification": "PENDING_OUTER_CLOSURE; NO_NATIVE_OR_PERFORMANCE_CREDIT"})
        return passed

    checkpoint()
    if not a.worker:
        load_before = os.getloadavg()
        argv = [sys.executable, "-B", str(Path(__file__).resolve()), "--root", str(root), "--cargo", str(cargo),
                "--cpus", a.cpus, "--name", a.name, "--worker"]
        closed = owner.run_command(argv, env, out / "outer.log", 1200, LIMIT)
        result = {"status": "FAILED", "revision": REVISION, "cpus": cpus, "reservation": "caller-held",
                  "load_before": load_before, "outer": closed}
        save(out / "result.json", result)
        result["load_after"] = os.getloadavg()
        # Closure precedes every child-output read, including failed attempts.
        if closed["cleanup_complete"] is True:
            child = json.loads((out / "child.json").read_bytes()) if (out / "child.json").exists() else None
            result["child"] = child
            if normal(closed, 1200) and child is not None and child["all_pass"]:
                unchanged()
                result["status"] = "PASS"
        save(out / "result.json", result)
        print(json.dumps({"status": result["status"], "census": result.get("child", {}).get("counts") if result.get("child") else None}))
        return 0 if result["status"] == "PASS" else 1
    accepted = set()
    for (name, kind, argv), row in zip(stages, rows):
        if kind == "rust_tests" and name.replace("-run", "-list") not in accepted:
            row["reason"] = "required exact listing did not pass"
            checkpoint()
            continue
        unchanged()
        seconds = 60 if kind == "python_tests" else 180
        log = out / (name + ".log")
        # Dispatch intent is not proof of execution or a closed outcome.
        row.update(status="DISPATCHED_UNRESOLVED", attempts=1, load_before=os.getloadavg())
        checkpoint()
        closed = owner.run_command(argv, env, log, seconds, LIMIT)
        row.update(status="CLOSED_UNRESOLVED", closed=closed)
        checkpoint()
        if closed["cleanup_complete"] is not True:
            row["status"] = "CLEANUP_INCOMPLETE"
            checkpoint()
            break
        row["load_after"] = os.getloadavg()
        unchanged()
        raw = log.read_bytes()
        assert len(raw) <= LIMIT and sha(raw) == closed["private_log_sha256"]
        row["status"] = "FAILED"
        try:
            count = census(raw, kind, receipt["census_by_stage"].get(name.replace("-list", "-run")))
            if normal(closed, seconds):
                row.update(status="PASS", passed_executions=count)
                if kind == "rust_listing":
                    accepted.add(name)
        except (AssertionError, UnicodeError, ValueError):
            row["census_refused"] = True
        checkpoint()
    passed = checkpoint(complete=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
