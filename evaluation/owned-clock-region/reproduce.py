#!/usr/bin/env python3
"""One fixed release-build region correctness cohort; raw output stays private."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
if len(sys.argv) != 3:
    raise SystemExit("reproduce.py EXACT_REVISION NEW_PRIVATE_OUTPUT")
root = Path(__file__).resolve().parents[2]
assert Path.cwd().resolve() == root
revision = sys.argv[1]
scope = ["src", "tools", "crates", "Cargo.toml", "Cargo.lock"]


def check_source():
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], timeout=10).decode().strip() == revision
    assert not subprocess.check_output(["git", "diff", revision, "--", *scope], timeout=10)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    with path.open("rb") as source:
        result = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


check_source()
out = Path(sys.argv[2]).resolve()
assert out.is_relative_to(root / "ignored") and not out.exists()
out.mkdir()
logs = root / "target/evaluation" / out.name
logs.mkdir(parents=True)
helper = root / "evaluation/admission/processes.py"
assert digest(helper) == "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
spec = importlib.util.spec_from_file_location("region_command_owner", helper)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
# Do not inherit target-directory, compiler-wrapper, or Rust-flag overrides.
env = {key: value for key, value in os.environ.items() if not key.startswith(("CARGO", "RUST"))}
env.update(CARGO_BUILD_JOBS="12", RUST_TEST_THREADS="12", CARGO_INCREMENTAL="0",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_NET_OFFLINE="true")
binary = root / "target/release/liteinst-preempt"
commands = [
    ("release-build", ["cargo", "build", "--release", "--locked", "--offline", "-j", "12",
                       "--target-dir", str(root / "target"), "--bin", "liteinst-preempt",
                       "--message-format=json-render-diagnostics"], 600),
    ("native-oracle", [str(binary), "region-oracle", str(out / "oracle")], 180),
]
hardware = dict(architecture=os.uname().machine, logical_cpus=os.cpu_count(),
                cpu_model=next(line.split(":", 1)[1].strip()
                               for line in Path("/proc/cpuinfo").read_text().splitlines()
                               if line.startswith("model name")))
planned = dict(revision=revision, hardware=hardware, commands=commands,
               attempts=1, cpus=sorted(os.sched_getaffinity(0)), load=os.getloadavg(),
               jobs=12, test_threads=12, log_cap=2 * 1024 * 1024,
               scope="Correctness only; no performance or live-publication qualification.",
               toolchain={name: subprocess.check_output([name, "--version"], env=env, timeout=10).decode().strip()
                          for name in ("cargo", "rustc")},
               script_sha256=digest(Path(__file__)))
assert len(planned["cpus"]) == 12
save(out / "planned.json", planned)
results = []
binary_hash = None
error = None
failed = True
try:
    for name, command, wall in commands:
        check_source()
        if name == "native-oracle":
            assert binary_hash is not None and digest(binary) == binary_hash
        log = logs / (name + ".log")
        assert not log.exists()
        result = owner.run_command(command, env, log, wall, planned["log_cap"])
        row = dict(name=name, result=result, load_after=os.getloadavg())
        results.append(row)
        # Persist the owner result before processing or copying its capture.
        save(out / (name + "-result.json"), row)
        print(json.dumps(row), flush=True)
        raw = log.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
        (out / log.name).write_bytes(raw)
        check_source()
        if (result["exit_code"] != 0 or result["termination"] is not None
                or not result["cleanup_complete"] or result["reaped_descendants"] != 0):
            break
        if name == "release-build":
            messages = [json.loads(line) for line in raw.decode().splitlines() if line.startswith("{")]
            artifacts = [item for item in messages if item.get("reason") == "compiler-artifact"
                         and item.get("target", {}).get("name") == "liteinst-preempt"
                         and item.get("executable")]
            assert len(artifacts) == 1 and Path(artifacts[0]["executable"]).resolve() == binary.resolve()
            binary_hash = digest(binary)
        else:
            assert digest(binary) == binary_hash
    failed = len(results) != len(commands) or any(
        row["result"]["exit_code"] != 0 or row["result"]["termination"] is not None
        or not row["result"]["cleanup_complete"] or row["result"]["reaped_descendants"] != 0
        for row in results)
except BaseException as exception:
    error = type(exception).__name__
    raise
finally:
    save(out / "closed.json", dict(planned=planned, results=results, error=error,
         binary_sha256=binary_hash, status="FAIL" if failed or error else "PASS",
         undispatched=[command[0] for command in commands[len(results):]]))
raise SystemExit(int(failed))
