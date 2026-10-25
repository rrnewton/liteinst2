#!/usr/bin/env python3
"""Reproduce admission validation; publish strict summaries, keep logs private."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
from parsing import InvalidEvidence, parse_harnesses, native_receipts, native_block
from processes import run_command

ENV = {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "4",
       "CARGO_NET_OFFLINE": "true", "RUST_TEST_THREADS": "4",
       "CARGO_TERM_COLOR": "never", "PYTHONDONTWRITEBYTECODE": "1",
       "RUSTFLAGS": "", "RUSTDOCFLAGS": "", "RUSTC_WRAPPER": "",
       "RUSTC_WORKSPACE_WRAPPER": ""}
COMMANDS = [
    ("recorder_tests", ["python3", "-m", "unittest", "discover", "-s",
                        "evaluation/admission", "-p", "test_*.py"], 180),
    ("fmt", ["cargo", "fmt", "--check"], 180),
    ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--all-features",
                "--", "-D", "warnings"], 180),
    ("workspace_tests", ["cargo", "test", "--workspace"], 360),
    ("workspace_check", ["cargo", "check", "--workspace", "--all-features",
                         "--all-targets"], 180),
    ("serial_launch", ["cargo", "test", "-p", "liteinst-launch", "--tests", "--",
                       "--test-threads=1", "--nocapture"], 180),
]
def require(condition, code):
    if not condition:
        raise InvalidEvidence(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    # Repository selectors/config injection inherited from the invoking shell
    # must not authenticate a different checkout. HEAD replacement is disabled.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(ROOT), "--work-tree=" + str(ROOT),
         "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
        cwd=ROOT, env=env, stderr=subprocess.DEVNULL)


def source_state():
    entries = git("ls-tree", "-rz", "HEAD").split(b"\0")
    sources = {}
    matches = True
    algorithm = git("rev-parse", "--show-object-format").decode().strip()
    require(algorithm in ("sha1", "sha256"), "unsupported_git_object_format")
    for entry in entries:
        if not entry:
            continue
        descriptor, raw_name = entry.split(b"\t", 1)
        mode, kind, object_id = descriptor.decode().split()
        name = raw_name.decode()
        if name.startswith("evaluation/admission/results/"):
            continue
        require(not name.startswith("/") and ".." not in Path(name).parts,
                "invalid_source_path")
        require(kind == "blob" and mode in ("100644", "100755", "120000"),
                "unsupported_source_mode")
        path = ROOT / name
        if mode == "120000":
            data = os.fsencode(os.readlink(path))
            actual_mode = "120000"
        else:
            require(path.is_file() and not path.is_symlink(), "missing_or_changed_source_type")
            data = path.read_bytes()
            actual_mode = "100755" if path.stat().st_mode & 0o111 else "100644"
        digest = hashlib.new(algorithm, b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        matches &= digest == object_id and actual_mode == mode
        sources[name] = sha(data)
    encoded = json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()
    return {"revision": git("rev-parse", "HEAD").decode().strip(),
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "tracked_diff_sha256": sha(git("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD")),
            "head_sources_match": matches,
            "tracked_clean": matches and not git("status", "--porcelain", "--untracked-files=no"),
            "source_manifest_sha256": sha(encoded), "source_sha256": sources}


def hardware():
    cpu = {}
    for line in Path("/proc/cpuinfo").read_text().split("\n\n", 1)[0].splitlines():
        key, _, value = line.partition(":")
        cpu[key.strip()] = value.strip()
    fields = {}
    for key in ("vendor_id", "model name", "cpu family", "model", "stepping", "microcode"):
        value = cpu.get(key)
        require(value is not None and re.fullmatch(r"[A-Za-z0-9 ()_.+-]{1,160}", value),
                "unsupported_cpu_metadata")
        fields[key.replace(" ", "_")] = value
    flags = cpu.get("flags", "").split()
    require(all(re.fullmatch(r"[a-z0-9_]+", flag) for flag in flags), "invalid_isa_flags")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    caps = int(status["CapEff"].strip(), 16)
    release = os.uname().release
    upstream = re.match(r"\d+\.\d+(?:\.\d+)?", release)
    require(upstream is not None, "unsupported_kernel_version")
    try:
        ptrace_scope = int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text())
        ptrace_scope_status = "observed"
    except FileNotFoundError:
        ptrace_scope, ptrace_scope_status = None, "interface_absent"
    except PermissionError:
        ptrace_scope, ptrace_scope_status = None, "unreadable"
    fields.update({"architecture": "x86_64", "isa_flags": sorted(flags),
                   "logical_cpus_visible": os.cpu_count(),
                   "affinity_cpu_count": len(os.sched_getaffinity(0)),
                   "kernel_upstream_version": upstream[0],
                   "kernel_release_sha256": sha(release.encode()),
                   "effective_uid_is_root": os.geteuid() == 0,
                   "cap_sys_ptrace": bool(caps & (1 << 19)),
                   "cap_sys_admin": bool(caps & (1 << 21)),
                   "ptrace_scope": ptrace_scope, "ptrace_scope_status": ptrace_scope_status})
    return fields


def tool_version(program, env):
    value = subprocess.check_output([program, "--version"], cwd=ROOT,
                                    stderr=subprocess.DEVNULL, timeout=10, env=env).decode().strip()
    require(re.fullmatch(r"[a-zA-Z0-9 .()+-]{1,120}", value), "unsupported_tool_version")
    return value


def write_result(path, record):
    # No captured free-form output is passed here. Creation is append-only by
    # run ID; subsequent writes update only this still-running record atomically.
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


# Inherited campaign, compiler and libtest overrides are intentionally excluded.
# These location variables locate the installed toolchain/dependency cache only;
# their values stay private. Cargo configuration is inspected separately.
LOCATION_VARIABLES = ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME")


def controlled_environment(inherited, temporary):
    env = {key: inherited[key] for key in LOCATION_VARIABLES if key in inherited}
    # Relative locations would mean different files to the caller and child cwd.
    for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME"):
        if key in env:
            require(Path(env[key]).is_absolute(), "relative_location_environment")
    require("PATH" in env and all(item and Path(item).is_absolute()
            for item in env["PATH"].split(os.pathsep)), "relative_executable_search_path")
    env.update(ENV, CARGO_TARGET_DIR=str(ROOT / "target"), TMPDIR=str(temporary),
               LANG="C.UTF-8", LC_ALL="C.UTF-8")
    return env


def cargo_configuration(env):
    """Hash known config files without publishing locations or contents."""
    candidates = [(f"ancestor_{index}", parent / ".cargo")
                  for index, parent in enumerate((ROOT, *ROOT.parents))]
    cargo_home = Path(env.get("CARGO_HOME", str(Path(env["HOME"]) / ".cargo")))
    candidates.append(("cargo_home", cargo_home))
    records = []
    for label, directory in candidates:
        for filename in ("config", "config.toml"):
            try:
                data = (directory / filename).read_bytes()
            except FileNotFoundError:
                continue
            except PermissionError:
                records.append({"location": label, "format": filename, "status": "unreadable"})
                continue
            parsed = tomllib.loads(data.decode())
            # Network settings cannot select code or test cases in an offline run.
            require(set(parsed) <= {"http", "net"}, "unsupported_cargo_configuration")
            records.append({"location": label, "format": filename, "status": "transport_only",
                            "sha256": sha(data)})
    return records


def command_evidence(command, output, corpus):
    """Retain failure status and sanitized partial observations independently."""
    if command["id"] == "recorder_tests" and command["status"] == "passed":
        counts = re.findall(r"^Ran (\d+) tests in [\d.]+s$", output, re.MULTILINE)
        if counts != [str(corpus["recorder_tests"])] or output.rstrip().splitlines()[-1:] != ["OK"]:
            command.update(parse_error="changed_recorder_test_cohort", status="invalid_evidence")
        else:
            command["tests_passed"] = corpus["recorder_tests"]
    if command["id"] not in corpus["harness_test_counts"]:
        return
    command["evidence_status"] = "complete"
    try:
        command["harnesses"] = parse_harnesses(
            output, corpus["harness_test_counts"][command["id"]], command["exit_code"])
    except InvalidEvidence as error:
        command["harnesses"] = error.partial or []
        command["parse_error"] = str(error)
        command["evidence_status"] = "incomplete"
    if command["id"] == "serial_launch":
        try:
            command["native_cases"] = native_receipts(
                native_block(output), corpus["native_cases"], command["status"] == "passed")
        except InvalidEvidence as error:
            command["native_cases"] = error.partial or []
            command["native_parse_error"] = str(error)
            command["evidence_status"] = "incomplete"
    if command["evidence_status"] != "complete" and command["status"] == "passed":
        command["status"] = "invalid_evidence"


def qualify(record):
    """Only the completed, unchanged experiment can qualify observations."""
    passed = (record["source_unchanged"] is True and record["configuration_unchanged"] is True
              and all(c["status"] == "passed" for c in record["commands"]))
    record["status"] = "passed" if passed else "failed"
    for command in record["commands"]:
        for row in command.get("native_cases", []):
            row["qualified_run"] = passed and row.get("command_succeeded", False)


def preflight(source, expected, untracked):
    require(source["revision"] == expected, "revision_differs")
    require(source["tracked_clean"], "dirty_tracked_source")
    for name in untracked:
        require(name == "BRIEF-li2adm.md" or name.startswith("evaluation/admission/results/"),
                "untracked_input")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-revision", required=True, help="exact 40-hex checkout revision")
    args = parser.parse_args()
    require(re.fullmatch(r"[a-f0-9]{40}", args.expect_revision), "invalid_expected_revision")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_id = stamp + "-" + args.expect_revision[:12]
    private = ROOT / "target/evaluation/admission" / run_id
    private.mkdir(parents=True, exist_ok=False)
    temporary = private / "tmp"
    temporary.mkdir()
    public = HERE / "results" / (run_id + ".json")
    public.parent.mkdir(parents=True, exist_ok=True)
    require(not public.exists(), "duplicate_run_id")
    record = {"schema_version": 1, "experiment": "admission-validation", "run_id": run_id,
              "source": None, "runner_sha256": sha(Path(__file__).read_bytes()),
              "corpus_sha256": None,
              "reproduce": ["python3", "evaluation/admission/run.py", "--expect-revision",
                            args.expect_revision], "hardware": None, "toolchain": None,
              "environment": ENV | {"CARGO_TARGET_DIR": "target", "TMPDIR": "private_run/tmp",
                                     "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "RLIMIT_CORE": 0},
              "inherited_location_variables": list(LOCATION_VARIABLES),
              "configuration": None, "configuration_unchanged": None,
              "log_limit_bytes_per_command": 8 * 1024 * 1024,
              "claim_targets": [1, 2, 4], "complete_claims_established": [],
              "preemption_clock": "not_evaluated", "performance_claim": None,
              "status": "preflight", "commands": [], "source_unchanged": None}
    for name, argv, timeout in COMMANDS:
        record["commands"].append({"id": name, "argv": argv, "timeout_seconds": timeout,
                                   "environment_delta": {"LITEINST_EVALUATION": "1"}
                                   if name == "serial_launch" else {}, "status": "not_run"})
    write_result(public, record)
    print(public.relative_to(ROOT), flush=True)
    try:
        env = controlled_environment(os.environ, temporary)
        require(sys.platform == "linux" and os.uname().machine == "x86_64", "unsupported_platform")
        source = source_state()
        record["source"] = source
        preflight(source, args.expect_revision,
                  git("ls-files", "--others", "--exclude-standard").decode().splitlines())
        corpus_data = (HERE / "corpus.json").read_bytes()
        record["corpus_sha256"] = sha(corpus_data)
        corpus = json.loads(corpus_data)
        require(corpus["schema_version"] == 1, "unknown_corpus_schema")
        record["configuration"] = cargo_configuration(env)
        record["hardware"] = hardware()
        record["toolchain"] = {name: {"version": tool_version(name, env),
                                      "launcher_sha256": sha(Path(shutil.which(name, path=env.get("PATH"))).read_bytes())}
                               for name in ("rustc", "cargo")}
        record["toolchain"]["python"] = {"version": sys.version.split()[0],
                                          "executable_sha256": sha(Path(sys.executable).read_bytes())}
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        record["status"] = "running"
        write_result(public, record)
        for command in record["commands"]:
            log = private / (command["id"] + ".log")
            command["status"] = "running"
            write_result(public, record)
            command.update(run_command(command["argv"], env | command["environment_delta"],
                                       log, command["timeout_seconds"]))
            passed = (command["exit_code"] == 0 and command["termination"] is None
                      and command["cleanup_complete"])
            command["status"] = "passed" if passed else "failed"
            command_evidence(command, log.read_text(errors="replace"), corpus)
            write_result(public, record)
            print(json.dumps({key: command[key] for key in ("id", "status", "exit_code", "seconds")}),
                  flush=True)
            if command["status"] != "passed":
                break
        after = source_state()
        record["source_unchanged"] = source == after
        preflight(after, args.expect_revision,
                  git("ls-files", "--others", "--exclude-standard").decode().splitlines())
        record["configuration_unchanged"] = record["configuration"] == cargo_configuration(env)
        qualify(record)
    except (Exception, KeyboardInterrupt) as error:
        # Never publish exception messages, which may contain paths or captured output.
        if isinstance(error, InvalidEvidence):
            record["error_code"] = str(error)
        else:
            record["error_type"] = type(error).__name__
        record["status"] = ("refused" if record["status"] == "preflight" else
                            "interrupted" if isinstance(error, KeyboardInterrupt) else "recorder_error")
        for command in record["commands"]:
            for row in command.get("native_cases", []):
                row["qualified_run"] = False
    finally:
        write_result(public, record)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except InvalidEvidence as failure:
        print("evaluation refused: " + str(failure), file=sys.stderr)
        sys.exit(2)
