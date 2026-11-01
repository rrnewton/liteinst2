#!/usr/bin/env python3
"""Run one fixed correctness cohort; private captures stay under ignored/."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
if len(sys.argv) != 4:
    raise SystemExit("reproduce.py EXACT_REVISION NEW_PRIVATE_OUTPUT ALLOCATOR_TAG")
root = Path(__file__).resolve().parents[2]
assert Path.cwd().resolve() == root
revision, output, tag = sys.argv[1:]
assert len(revision) == 40 and all(c in "0123456789abcdef" for c in revision)
assert tag and all(c.isalnum() or c in "-_." for c in tag)
scope = ["src", "tests", "crates", "examples", "tools", "Cargo.toml", "Cargo.lock",
         "build.rs", ".cargo", "rust-toolchain", "rust-toolchain.toml",
         "evaluation/early-controlled-point", "evaluation/admission/processes.py"]


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*args):
    return subprocess.check_output(["/usr/bin/git", "-c", "index.threads=1", "-c",
        "core.preloadIndex=false", *args], timeout=10).decode().strip()


def source_unchanged():
    assert git("rev-parse", "HEAD") == revision
    assert not git("diff", revision, "--", *scope)
    assert not git("ls-files", "--others", "--exclude-standard", "--", *scope)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


source_unchanged()
out = Path(output).resolve()
assert out.is_relative_to(root / "ignored") and not out.exists()
out.mkdir()
logs = root / "target/evaluation" / out.name
logs.mkdir(parents=True, exist_ok=False)
helper = root / "evaluation/admission/processes.py"
assert digest(helper) == "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
spec = importlib.util.spec_from_file_location("early_point_owner", helper)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
env = {key: value for key, value in os.environ.items() if not key.startswith(("CARGO", "RUST"))}
env.update(CARGO_BUILD_JOBS="12", RUST_TEST_THREADS="12", CARGO_INCREMENTAL="0",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_NET_OFFLINE="true",
           CARGO_TARGET_DIR=str(root / "target"))
tools = {name: Path(shutil.which(name, path=env["PATH"])).resolve()
         for name in ("cargo", "rustc", "rustdoc")}
assert all(path.name == name for name, path in tools.items()), "Use direct toolchain binaries"
env.update(RUSTC=str(tools["rustc"]), RUSTDOC=str(tools["rustdoc"]))
commands = [
    ("core", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "liteinst2",
              "--lib", "early_control", "--", "--nocapture"], 180),
    ("planning", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "liteinst2",
                  "--test", "early_control_planning", "--", "--nocapture"], 180),
    ("static-oracle", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "liteinst2",
                       "--test", "early_control_oracle", "--", "--nocapture"], 240),
    ("race-oracle", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "liteinst2",
                     "--test", "early_control_race_oracle", "--", "--nocapture"], 120),
    ("profiler", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "rapid-profiler",
                  "--lib", "data_flag::tests::", "--", "--nocapture"], 180),
]
# Source-declared inventory. The native wrappers' exact exec children produce
# additional one-test summaries; they remain separately visible, never added
# to the top-level scientific or harness population.
expected_passes = {
    "core": [9], "planning": [2], "static-oracle": [1, 1, 1, 1, 37],
    "race-oracle": [1, 1, 1, 1, 36], "profiler": [2],
}
frozen = {str(path): digest(path) for path in [Path(__file__), helper, Path(sys.executable),
                                             Path("/usr/bin/git"), *tools.values()]}
planned = dict(revision=revision, source_tree=git("rev-parse", "HEAD^{tree}"),
    hardware=dict(label="AMD EPYC Zen 5 dev host", architecture=os.uname().machine,
                  logical_cpus=os.cpu_count(), cpu_model=next(
                      line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                      if line.startswith("model name"))), commands=commands, attempts=1,
    cpus=sorted(os.sched_getaffinity(0)), jobs=12, test_threads=12,
    load_average=list(os.getloadavg()), capture_limit=2 * 1024 * 1024,
    reservation=dict(allocator="cpuset-alloc", caller_reported_tag=tag, cores=12,
                     authority="Caller reservation; runner independently observes affinity only."),
    toolchain={name: subprocess.check_output([str(tools[name]), "--version"], env=env,
                                            timeout=10).decode().strip() for name in ("cargo", "rustc")},
    script_sha256=digest(Path(__file__)),
    scope="Finite point-observer correctness only; no performance, drainage or complete A4 qualification.")
planned["expected_harness_passes"] = expected_passes
assert len(planned["cpus"]) == 12
save(out / "planned.json", dict(planned=planned, frozen=frozen, source_scope=scope))
rows = []
failed = True
error = None
try:
    for name, command, wall in commands:
        source_unchanged()
        assert all(digest(Path(path)) == value for path, value in frozen.items())
        log = logs / (name + ".log")
        assert not log.exists()
        argv = [str(tools["cargo"]), *command[1:]]
        result = owner.run_command(argv, env, log, wall, planned["capture_limit"])
        row = dict(name=name, result=result, load_after=list(os.getloadavg()))
        rows.append(row)
        save(out / (name + "-result.json"), row)
        print(json.dumps(row), flush=True)
        assert result["cleanup_complete"], "Unresolved owner; do not consume capture"
        raw = log.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
        (out / log.name).write_bytes(raw)
        # Preserve every harness summary; controlled child summaries are not
        # silently subtracted or called additional top-level tests.
        row["harness_summaries"] = [dict(zip(("outcome", "passed", "failed", "ignored", "measured", "filtered"),
            [match[0], *map(int, match[1:])])) for match in re.findall(
            r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
            raw.decode())]
        source_unchanged()
        assert all(digest(Path(path)) == value for path, value in frozen.items())
        if (result["exit_code"] != 0 or result["termination"] is not None
                or result["reaped_descendants"] != 0):
            break
        assert row["harness_summaries"], "No harness result was recorded"
        assert all(item["outcome"] == "ok" and item["failed"] == 0 for item in row["harness_summaries"])
        assert sorted(item["passed"] for item in row["harness_summaries"]) == expected_passes[name]
        assert all(item["ignored"] == 0 and item["measured"] == 0 for item in row["harness_summaries"])
    failed = len(rows) != len(commands) or any(
        row["result"]["exit_code"] != 0 or row["result"]["termination"] is not None
        or not row["result"]["cleanup_complete"] or row["result"]["reaped_descendants"] != 0
        for row in rows)
except BaseException as exception:
    error = type(exception).__name__
    raise
finally:
    save(out / "closed.json", dict(planned=planned, results=rows, error=error,
        status="FAIL" if failed or error else "PASS",
        undispatched=[command[0] for command in commands[len(rows):]]))
raise SystemExit(int(failed))
