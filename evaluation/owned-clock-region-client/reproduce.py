#!/usr/bin/env python3
"""One release build and a fixed, bounded published-region client cohort."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
if len(sys.argv) != 3:
    raise SystemExit("reproduce.py EXACT_REVISION NEW_PRIVATE_OUTPUT")
root = Path(__file__).resolve().parents[2]
assert Path.cwd().resolve() == root
revision = sys.argv[1]
scope = ["src", "crates", "tools", "examples", "Cargo.toml", "Cargo.lock",
         "evaluation/owned-clock-region-client", "evaluation/admission/processes.py"]


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def check_source():
    git = ["/usr/bin/git", "-c", "index.threads=1", "-c", "core.preloadIndex=false"]
    assert subprocess.check_output(git + ["rev-parse", "HEAD"], timeout=10).decode().strip() == revision
    assert not subprocess.check_output(git + ["diff", revision, "--", *scope], timeout=10)
    assert not subprocess.check_output(git + ["ls-files", "--others", "--exclude-standard", "--", *scope], timeout=10)


check_source()
out = Path(sys.argv[2]).resolve()
assert out.is_relative_to(root / "ignored") and not out.exists()
out.mkdir()
logs = root / "target/evaluation" / out.name
logs.mkdir(parents=True)
helper = root / "evaluation/admission/processes.py"
assert digest(helper) == "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
spec = importlib.util.spec_from_file_location("region_client_owner", helper)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
env = {key: value for key, value in os.environ.items() if not key.startswith(("CARGO", "RUST"))}
env.update(CARGO_BUILD_JOBS="12", RUST_TEST_THREADS="12", CARGO_INCREMENTAL="0",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_NET_OFFLINE="true")
tools = {name: Path(shutil.which(name, path=env["PATH"])).resolve()
         for name in ("cargo", "rustc", "rustdoc")}
assert all(path.name == name for name, path in tools.items()), "Use direct toolchain binaries, not rustup shims"
env.update(RUSTC=str(tools["rustc"]), RUSTDOC=str(tools["rustdoc"]))
tool_hashes = {name: digest(path) for name, path in tools.items()}
script_hash = digest(Path(__file__))
binary = root / "target/release/examples/owned_region_clock"
positive = [(1, 1, 1), (1, 4, 2), (3, 1, 1), (3, 4, 2), (4, 3, 11), (32, 32, 1023)]
negative = [["0", "4", "2"], ["3", "0", "2"], ["33", "4", "2"], ["3", "33", "2"],
            ["3", "4", "0"], ["3", "4", "32769"], ["x", "4", "2"], ["3", "4"]]
refusal = b"invalid arguments: expected outer inner quantum; outer and inner in 1..=32, quantum in 1..=32768\n"
commands = [dict(name="release-build", kind="build", argv=[str(tools["cargo"]), "build", "--release",
            "--locked", "--offline", "-j", "12", "--target-dir", str(root / "target"),
            "--example", "owned_region_clock", "--message-format=json-render-diagnostics"], wall=600)]
for index, arguments in enumerate(positive):
    commands.append(dict(name=f"positive-{index:02}", kind="positive", arguments=list(arguments),
                         argv=["/usr/bin/prlimit", "--cpu=10", "--fsize=65536", "--core=0", "--",
                               str(binary), *map(str, arguments)], wall=20))
for index, arguments in enumerate(negative):
    commands.append(dict(name=f"negative-{index:02}", kind="negative", arguments=arguments,
                         argv=["/usr/bin/prlimit", "--cpu=2", "--fsize=65536", "--core=0", "--",
                               str(binary), *arguments], wall=5))
planned = dict(revision=revision, attempts=1, commands=commands,
               hardware=dict(architecture=os.uname().machine, logical_cpus=os.cpu_count(),
                             cpu_model=next(line.split(":", 1)[1].strip()
                                            for line in Path("/proc/cpuinfo").read_text().splitlines()
                                            if line.startswith("model name"))),
               cpus=sorted(os.sched_getaffinity(0)), load=os.getloadavg(), jobs=12, test_threads=12,
               capture_cap=2 * 1024 * 1024, native_capture_cap=65536, cleanup_seconds=3,
               script_sha256=script_hash, helper_sha256=digest(helper), tool_sha256=tool_hashes,
               source_tree=subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD^{tree}"], timeout=10).decode().strip(),
               python=sys.version, python_sha256=digest(Path(sys.executable).resolve()),
               environment={key: value for key, value in env.items()
                            if key.startswith(("CARGO", "RUST")) or key in ("PATH", "LANG", "LC_ALL", "LD_PRELOAD", "LD_LIBRARY_PATH")},
               tool_versions={name: subprocess.check_output([str(path), "--version"], env=env, timeout=10).decode().strip()
                              for name, path in tools.items()},
               scope="Finite positive publication/client integration and input refusal; no performance, retirement, or full-state-after-callback claim.")
assert len(planned["cpus"]) == 12
save(out / "planned.json", planned)
rows = [dict(name=item["name"], status="UNOBSERVED") for item in commands]
save(out / "outcomes.json", rows)
binary_hash = None
error = None
failed = True
try:
    for index, command in enumerate(commands):
        check_source()
        assert digest(Path(__file__)) == script_hash and digest(helper) == planned["helper_sha256"]
        assert all(digest(tools[name]) == pin for name, pin in tool_hashes.items())
        if command["kind"] != "build":
            assert binary_hash is not None and digest(binary) == binary_hash
        row = rows[index]
        row.update(status="DISPATCHED", load_before=os.getloadavg())
        save(out / "outcomes.json", rows)
        log = logs / (command["name"] + ".log")
        assert not log.exists()
        cap = planned["capture_cap"] if command["kind"] == "build" else planned["native_capture_cap"]
        row["owner"] = owner.run_command(command["argv"], env, log, command["wall"], cap)
        row["load_after"] = os.getloadavg()
        save(out / "outcomes.json", rows)
        result = row["owner"]
        assert result["cleanup_complete"], "command ownership is unresolved; do not consume its capture"
        raw = log.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row["owner"]["private_log_sha256"]
        (out / log.name).write_bytes(raw)
        assert result["reaped_descendants"] == 0 and result["termination"] is None
        check_source()
        if command["kind"] == "build":
            assert result["exit_code"] == 0
            messages = [json.loads(line) for line in raw.decode().splitlines() if line.startswith("{")]
            artifacts = [item for item in messages if item.get("reason") == "compiler-artifact"
                         and item.get("target", {}).get("name") == "owned_region_clock"
                         and item.get("executable")]
            assert len(artifacts) == 1 and Path(artifacts[0]["executable"]).resolve() == binary
            row["compiled_profile"] = artifacts[0]["profile"]
            binary_hash = digest(binary)
        elif command["kind"] == "negative":
            assert result["exit_code"] == 2 and raw == refusal
            row["observed"] = dict(exit_code=2, refusal="argument admission before publication")
        else:
            assert result["exit_code"] == 0
            n, m, q = command["arguments"]
            # Independent scalar loop enumerates decisions; the client uses closed forms.
            taken = encounters = inner_stops = outer_stops = answer = 0
            for outer_remaining in range(n, 0, -1):
                for inner_remaining in range(m, 0, -1):
                    answer += inner_remaining
                    encounters += 1
                    if inner_remaining > 1:
                        taken += 1
                        inner_stops += int(taken % q == 0)
                encounters += 1
                if outer_remaining > 1:
                    taken += 1
                    outer_stops += int(taken % q == 0)
            expected = dict(status="PASS", profile="owned-region-publisher-v1", outer=n, inner=m, quantum=q,
                            result=answer, encounters=encounters, taken=taken, stops=inner_stops + outer_stops,
                            inner_stops=inner_stops, outer_stops=outer_stops, parked=inner_stops + outer_stops,
                            joined=True, publication="publish_with", handled_routes=0)
            row["observed"] = json.loads(raw)
            assert row["observed"] == expected
            assert all(type(row["observed"][key]) is type(value) for key, value in expected.items())
        if binary_hash is not None:
            assert digest(binary) == binary_hash
        assert digest(Path(__file__)) == script_hash and digest(helper) == planned["helper_sha256"]
        assert all(digest(tools[name]) == pin for name, pin in tool_hashes.items())
        row["status"] = "PASS"
        save(out / "outcomes.json", rows)
        print(json.dumps(dict(name=row["name"], status=row["status"], owner=row["owner"])), flush=True)
    failed = any(row["status"] != "PASS" for row in rows)
except BaseException as exception:
    error = type(exception).__name__
    for row in rows:
        if row["status"] == "DISPATCHED":
            row["status"] = "FAIL"
    save(out / "outcomes.json", rows)
    raise
finally:
    save(out / "closed.json", dict(planned=planned, outcomes=rows, error=error,
         binary_sha256=binary_hash, status="FAIL" if failed or error else "PASS"))
raise SystemExit(int(failed))
