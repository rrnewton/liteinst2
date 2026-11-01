#!/usr/bin/env python3
"""One release build and two fixed, untimed owned-clock correctness commands."""
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
if len(sys.argv) != 4:
    raise SystemExit("reproduce.py EXACT_REVISION NEW_PRIVATE_OUTPUT ALLOCATOR_TAG")
root = Path(__file__).resolve().parents[2]  # Install at evaluation/owned-clock-batch/.
assert Path.cwd().resolve() == root
revision, output, tag = sys.argv[1:]
assert tag and all(c.isalnum() or c in "-_." for c in tag)
scope = ["src", "tests", "crates", "examples", "tools/software-preemption", "Cargo.toml",
         "Cargo.lock", "evaluation/owned-clock-batch", "evaluation/admission/processes.py"]
MIB = 1048576


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def git(*arguments):
    return subprocess.check_output(["/usr/bin/git", "-c", "index.threads=1", "-c",
        "core.preloadIndex=false", *arguments], timeout=10).decode().strip()


def check_source():
    assert git("rev-parse", "HEAD") == revision
    assert not git("diff", revision, "--", *scope)
    assert not git("ls-files", "--others", "--exclude-standard", "--", *scope)


def small(path):
    assert path.is_file() and not path.is_symlink() and path.stat().st_size <= MIB
    return path.read_bytes()


def table(folder, name, header):
    rows = list(csv.reader(io.StringIO(small(folder / name).decode(), newline="")))
    assert rows and rows[0] == header.split(",")
    assert all(len(row) == len(rows[0]) for row in rows[1:])
    return rows[1:]


def positive_integer(text):
    value = int(text)
    assert value > 0 and str(value) == text
    return value


def rejections(folder, batch, main_pid=None):
    prefix = "" if batch else "region-"
    rows = table(folder, prefix + "rejections.csv",
                 "fault,pid,tid,site,count,reply_site,reply_count,exit,result")
    assert len(rows) == 2
    count, rcx, encounters, r8, rax = (64, 3, 86, 1, 9) if batch else (2, 2, 2, 3, 2)
    for cause, row in enumerate(rows, 1):
        fault = str(cause) if batch else ("wrong-site" if cause == 1 else "wrong-count")
        pid, tid = map(positive_integer, row[1:3])
        assert pid != tid and pid != main_pid
        reply = (21, count) if cause == 1 else (20, count + 1)
        assert row == [fault, str(pid), str(tid), "20", str(count), *map(str, reply), "123", "PASS"]
        raw = small(folder / (prefix + "rejection-" + fault + ".bin"))
        assert len(raw) == 248 and raw[:8] == (b"LI2RBQ64" if batch else b"LI2RGN01")
        words = struct.unpack("<30Q", raw[8:])
        assert words[:3] == (cause, pid, tid) and words[3] > 0
        assert words[4:12] == (20, count, *reply, rcx, encounters, count, 0)
        assert words[12] == words[3] + 20 and words[13] > 0
        assert (words[21], words[27], words[28]) == (r8, rcx, rax) and words[29] & 64 == 0


def artifacts(folder, batch, capture):
    names = {"summary.json", "region-gates.csv"}
    names.update(("measurements.csv", "rejections.csv", "rejection-1.bin", "rejection-2.bin",
                  "fork-entry.csv", "fork-entry.bin") if batch else
                 ("region-stops.csv", "region-events.csv", "region-rejections.csv",
                  "region-rejection-wrong-site.bin", "region-rejection-wrong-count.bin"))
    assert {p.name for p in folder.iterdir()} == names
    pins = {name: {"bytes": len(small(folder / name)), "sha256": digest(folder / name)} for name in sorted(names)}
    gates = table(folder, "region-gates.csv", "mode,quantum,seed,full_state_comparisons,status")
    assert gates == [[mode, str(q), str(seed), str(n), "PASS"] for seed in (7, 42)
                     for mode, q, n in (("counter-whole-trace", 2, 63),
                     ("inner-zero-before-save", 2, 11), ("outer-zero-before-save", 4, 22))]
    expected = dict(status="PASS", profile="owned-region-batch-oracle-v1" if batch else
        "owned-two-backedge-region-oracle-v1", gate_pairs=6, gate_children=12,
        full_state_comparisons=192, rejection_children=2, rejection_witnesses=2,
        publisher_validation=False, full_state_after_callback=False, performance_qualification=False)
    markers = ["preemption:region-gates:6-pairs:12-children:192-full-state-comparisons"]
    if batch:
        expected.update(qualification_rows=3, calls_per_arm=2048, encounters_per_lease=30720,
            taken_per_instrumented_arm=22528, quantum=64, stops=352, inner_stops=288,
            outer_stops=64, fork_entry_children=1, fork_entry_witnesses=1)
        rows = table(folder, "measurements.csv", "pid,worker_tid,arm,phase,batch,status,calls,expected_encounters,expected_taken,elapsed_ns,checksum,clock_encounters,clock_taken,stops,remaining")
        assert len(rows) == 3
        main_pid = positive_integer(rows[0][0])
        for row, arm in zip(rows, ("native", "counter", "stop")):
            assert positive_integer(row[0]) == main_pid and positive_integer(row[1]) != main_pid
            clock = ["", "", "0", ""] if arm == "native" else ["30720", "22528", "352" if arm == "stop" else "0", "64"]
            assert row[2:] == [arm, "qualification", "0", "PASS", "2048", "30720", "22528", "", "24576", *clock]
        rejections(folder, True, main_pid)
        fork = table(folder, "fork-entry.csv", "pid,parent_pid,batch_owner_refused,ordinary_owner_refused,clock_unchanged,exit,status")
        assert len(fork) == 1
        pid = positive_integer(fork[0][0])
        assert pid != main_pid and fork[0] == [str(pid), str(main_pid), "true", "true", "true", "0", "PASS"]
        raw = small(folder / "fork-entry.bin")
        assert len(raw) == 48 and raw[:8] == b"LI2BFORK"
        assert struct.unpack("<5Q", raw[8:]) == (pid, main_pid, 1, 1, 1)
        markers += ["preemption:region-bench-rejections:2-children:2-before-refill-witnesses:2-exit123-echild",
                    "preemption:region-batch:3-qualified:352-exact-handoffs:no-timing"]
    else:
        expected.update(stop_quanta=[2, 11, 12], stops=6, parked_checks=6)
        stops = table(folder, "region-stops.csv", "quantum,encounters,taken,stops,parked_checks,remaining,result")
        assert stops == [[str(q), "15", "11", str(n), str(n), str(left), "PASS"]
                         for q, n, left in ((2, 5, 1), (11, 1, 11), (12, 0, 1))]
        events = table(folder, "region-events.csv", "quantum,site,count,encounters,rax,rcx,r8")
        assert events == [list(map(str, row)) for row in ((2,20,2,2,2,2,3), (2,29,4,5,4,0,2),
            (2,20,6,7,6,2,2), (2,29,8,10,8,0,1), (2,20,10,12,10,2,1), (11,20,11,13,11,1,1))]
        rejections(folder, False)
        markers += ["preemption:region-rejections:2-children:2-first-stop-witnesses:2-exit123-echild",
                    "preemption:region-stops:3-quanta:15-encounters:11-taken:6-stops:6-parked-checks"]
    summary = json.loads(small(folder / "summary.json"))
    assert json.dumps(summary, sort_keys=True) == json.dumps(expected, sort_keys=True)
    assert all(capture.decode().splitlines().count(marker) == 1 for marker in markers)
    assert pins == {name: {"bytes": len(small(folder / name)), "sha256": digest(folder / name)} for name in sorted(names)}
    return dict(summary=summary, files=pins)


check_source()
out = Path(output).resolve()
assert out.is_relative_to(root / "ignored") and not out.exists()
out.mkdir()
logs = root / "target/evaluation" / out.name
logs.mkdir(parents=True)
helper = root / "evaluation/admission/processes.py"
assert digest(helper) == "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
spec = importlib.util.spec_from_file_location("region_batch_owner", helper)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
env = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO", "RUST"))}
env.update(CARGO_BUILD_JOBS="12", RUST_TEST_THREADS="12", CARGO_INCREMENTAL="0",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_NET_OFFLINE="true")
tools = {name: Path(shutil.which(name, path=env["PATH"])).resolve() for name in ("cargo", "rustc", "rustdoc")}
assert all(path.name == name for name, path in tools.items()), "Use direct toolchain binaries"
env.update(RUSTC=str(tools["rustc"]), RUSTDOC=str(tools["rustdoc"]), CARGO_TARGET_DIR=str(root / "target"))
frozen_paths = [Path(__file__).resolve(), helper, Path(sys.executable).resolve(), *tools.values(),
                Path("/usr/bin/git"), Path("/usr/bin/taskset"), Path("/usr/bin/prlimit")]
frozen = {str(path): digest(path) for path in frozen_paths}
cpus = sorted(os.sched_getaffinity(0))
assert len(cpus) == 12
pair = ",".join(map(str, cpus[:2]))
binary = root / "target/release/liteinst-preempt"
commands = [dict(name="release-build", argv=[str(tools["cargo"]), "build", "--release", "--locked",
    "--offline", "-j", "12", "--target-dir", str(root / "target"), "--bin", "liteinst-preempt",
    "--message-format=json-render-diagnostics"], wall=600, capture=2*MIB)]
for name in ("region-oracle", "region-batch-oracle"):
    commands.append(dict(name=name, argv=["/usr/bin/taskset", "-c", pair, "/usr/bin/prlimit",
        "--cpu=60", "--fsize=1048576", "--core=0", "--", str(binary), name, str(out / name)],
        wall=90, capture=MIB))
planned = dict(revision=revision, source_tree=git("rev-parse", "HEAD^{tree}"), attempts=1,
    commands=commands, scope=scope, frozen=frozen, cpus=cpus, native_cpus=cpus[:2], load=os.getloadavg(),
    reservation=dict(allocator="cpuset-alloc", cores=12, caller_reported_tag=tag,
                     authority="External caller reserves CPUs; runner records affinity, not an independent live witness."),
    jobs=12, test_threads=12, cleanup_seconds=3, performance_qualification=False,
    hardware=dict(architecture=os.uname().machine, logical_cpus=os.cpu_count(), cpu_model=next(
        line.split(":",1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name"))),
    python=sys.version, environment={k:v for k,v in env.items() if k.startswith(("CARGO","RUST"))
        or k in ("PATH","LANG","LC_ALL","LD_PRELOAD","LD_LIBRARY_PATH")},
    tool_versions={name:subprocess.check_output([str(path),"--version"],env=env,timeout=10).decode().strip() for name,path in tools.items()})
rows = [dict(name=c["name"], status="UNOBSERVED") for c in commands]
save(out / "planned.json", planned)
save(out / "outcomes.json", rows)
binary_hash, error, failed = None, None, True
try:
    for row, command in zip(rows, commands):
        check_source()
        assert sorted(os.sched_getaffinity(0)) == cpus
        assert all(digest(Path(path)) == sha for path, sha in frozen.items())
        if binary_hash is not None:
            assert digest(binary) == binary_hash
        row.update(status="DISPATCHED", load_before=os.getloadavg())
        save(out / "outcomes.json", rows)
        log = logs / (command["name"] + ".log")
        assert not log.exists()
        row["owner"] = owner.run_command(command["argv"], env, log, command["wall"], command["capture"])
        row["load_after"] = os.getloadavg()
        save(out / "outcomes.json", rows)
        result = row["owner"]
        assert result["cleanup_complete"], "ownership unresolved: capture must not be consumed"
        raw = log.read_bytes()
        assert len(raw) <= command["capture"] and hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
        (out / log.name).write_bytes(raw)
        assert result["exit_code"] == 0 and result["termination"] is None and result["reaped_descendants"] == 0
        check_source()
        if command["name"] == "release-build":
            messages = [json.loads(line) for line in raw.decode().splitlines() if line.startswith("{")]
            found = [m for m in messages if m.get("reason") == "compiler-artifact"
                     and m.get("target", {}).get("name") == "liteinst-preempt" and m.get("executable")]
            assert len(found) == 1 and Path(found[0]["executable"]).resolve() == binary
            assert found[0]["target"]["src_path"] == str(root / "tools/software-preemption/main.rs") and found[0]["filenames"] == [str(binary)]
            assert found[0]["target"]["kind"] == ["bin"] and found[0]["profile"]["opt_level"] == "3" and found[0]["profile"]["test"] is False
            row["compiled_profile"] = found[0]["profile"]
            binary_hash = digest(binary)
        else:
            row["artifacts"] = artifacts(out / command["name"], command["name"] == "region-batch-oracle", raw)
        assert digest(binary) == binary_hash
        assert all(digest(Path(path)) == sha for path, sha in frozen.items())
        check_source()
        row["source_after"] = True
        row["status"] = "PASS"
        save(out / "outcomes.json", rows)
        print(json.dumps(dict(name=row["name"], status=row["status"], owner=result)), flush=True)
    failed = any(row["status"] != "PASS" for row in rows)
except BaseException as exception:
    error = dict(type=type(exception).__name__, message=str(exception))
    for row in rows:
        if row["status"] == "DISPATCHED":
            row["status"] = "FAIL"
    save(out / "outcomes.json", rows)
    raise
finally:
    save(out / "closed.json", dict(planned=planned, outcomes=rows, error=error,
        binary_sha256=binary_hash, status="FAIL" if failed or error else "PASS"))
raise SystemExit(int(failed))
