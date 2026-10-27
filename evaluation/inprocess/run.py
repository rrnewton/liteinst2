#!/usr/bin/env python3
"""Release-only owned-region native and NX page-gate measurements.

Run from the committed repository root. Complete raw process output stays under
target/; public receipts retain bounded typed rows and capture hashes. This
runner kills a timed-out process group and waits for its direct child; it does
not claim custody of descendants that escape that group.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time
from datetime import datetime, timezone

CASES = ("cpuid", "rdtsc", "getpid", "gettid", "read", "write", "read_ebadf",
         "cross_instruction", "cross_redirect", "boundary_call")
TIMES = ("fixture_preparation_ns", "selected_preparation_ns", "publication_ns",
         "gate_preparation_ns", "arm_ns", "native_capture_ns", "first_call_ns",
         "handler_first_touch_ns", "handler_max_first_touch_ns")
ROW_KEYS = {"schema_version", "case", "status", "iterations", "batches",
            "register_words", "xstate_mask", "xstate_compared_bytes",
            "red_zone_bytes", "comparisons", "pushed_return_ok",
            "return_page_pending", "faults", "admitted_pages",
            "native_steady_ns", "gated_steady_ns", *TIMES}


class Refusal(Exception):
    """A fixed public failure category, never captured process text."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            result.update(block)
    return result.hexdigest()


def output(argv):
    return subprocess.check_output(argv, text=True, timeout=20).strip()


def hardware(cpu):
    fields = None
    for block in Path("/proc/cpuinfo").read_text().split("\n\n"):
        row = dict((key.strip(), value.strip()) for line in block.splitlines()
                   for key, sep, value in [line.partition(":")] if sep)
        if row.get("processor") == str(cpu):
            fields = row
            break
    require(fields is not None, "selected_cpu_not_observed")
    status = dict((key, value.strip()) for line in
                  Path("/proc/self/status").read_text().splitlines()
                  for key, sep, value in [line.partition(":")] if sep)
    require(re.fullmatch(r"[0-9a-fA-F]{16}", status.get("CapEff", "")) is not None
            and status.get("Seccomp") in ("0", "1", "2"), "process_status_invalid")
    release = platform.release()
    version = re.match(r"[0-9.]+", release)
    require(version is not None, "kernel_version_invalid")
    return {key: fields.get(key) for key in
            ("vendor_id", "model name", "cpu family", "model", "stepping", "microcode")} | {
        "architecture": platform.machine(), "kernel_version": version[0],
        "kernel_release_sha256": digest(release.encode()),
        "isa_flags": fields.get("flags", "").split(), "probe_cpu": cpu,
        "affinity_cpu_count": len(os.sched_getaffinity(0)),
        "runner_euid": os.geteuid(), "runner_is_root": os.geteuid() == 0,
        "runner_cap_eff": status["CapEff"].lower(),
        "runner_seccomp_mode": int(status["Seccomp"]),
    }


def invoke(argv, environment, directory, label, timeout, cpu=None):
    stdout, stderr = (directory / (label + suffix) for suffix in (".stdout", ".stderr"))
    started = time.monotonic_ns()
    row = {"label": label, "argv": argv, "timeout_seconds": timeout,
           "affinity_cpu": cpu, "exit_code": None, "timed_out": False,
           "leader_reaped": False, "killpg_requested": False,
           "killpg_errno": None, "error": None, "error_errno": None, "capture_errors": {}}
    process = None

    def stop_and_reap():
        # Popen.wait records returncode before the caller can record its row.
        # An interrupt in that gap must not signal a now-reusable numeric PID.
        if process.returncode is not None:
            row["exit_code"] = process.returncode
            row["leader_reaped"] = True
            return
        row["killpg_requested"] = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError as error:
            # ESRCH can be an exit race; still wait for the actual child.
            row["killpg_errno"] = error.errno
        try:
            row["exit_code"] = process.wait(timeout=5)
            row["leader_reaped"] = True
        except subprocess.TimeoutExpired:
            row["error"] = row["error"] or "leader_reap_timeout"
        except OSError as error:
            row["error"] = row["error"] or "leader_reap_failed"
            row["error_errno"] = error.errno

    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(argv, env=environment, stdout=out, stderr=err,
                                       start_new_session=True,
                                       preexec_fn=(lambda: os.sched_setaffinity(0, {cpu}))
                                       if cpu is not None else None)
            try:
                row["exit_code"] = process.wait(timeout=timeout)
                row["leader_reaped"] = True
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                stop_and_reap()
    except (OSError, subprocess.SubprocessError) as error:
        row["error"] = "spawn_or_capture_failed" if process is None else "process_wait_failed"
        row["error_errno"] = getattr(error, "errno", None)
        if process is not None and not row["leader_reaped"]:
            stop_and_reap()
    except KeyboardInterrupt:
        row["error"] = "interrupted"
        if process is not None and not row["leader_reaped"]:
            stop_and_reap()
    row["elapsed_ns"] = time.monotonic_ns() - started
    for name, path in (("stdout", stdout), ("stderr", stderr)):
        try:
            row[name + "_sha256"] = file_digest(path)
            row[name + "_bytes"] = path.stat().st_size
        except OSError as error:
            row[name + "_sha256"] = None
            row[name + "_bytes"] = None
            row["capture_errors"][name] = error.errno
            if row["error"] is None:
                row["error"] = "capture_read_failed"
                row["error_errno"] = error.errno
    return row, stdout


def completed(command):
    return (command["exit_code"] == 0 and not command["timed_out"]
            and command["leader_reaped"] and command["error"] is None)


def pairs(items):
    row = {}
    for key, value in items:
        require(key not in row, "duplicate_native_json_key")
        row[key] = value
    return row


def invalid_constant(_):
    raise Refusal("nonfinite_native_json")


def native_row(data, case, iterations):
    row = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    require(type(row) is dict and set(row) == ROW_KEYS, "native_row_keys")
    require(row["case"] == case and row["status"] == "passed", "native_row_status")
    for key, value in (("schema_version", 1), ("iterations", iterations),
                       ("batches", 17), ("comparisons", 2)):
        require(type(row[key]) is int and row[key] == value, "native_row_identity")
    for key in TIMES:
        require(type(row[key]) is int and 0 <= row[key] <= 2**64 - 1, "native_row_time")
    for key in ("native_steady_ns", "gated_steady_ns"):
        require(type(row[key]) is list and len(row[key]) == 17
                and all(type(n) is int and 0 <= n <= 2**64 - 1 for n in row[key]),
                "native_row_batches")
    boundary = case == "boundary_call"
    for key in ("register_words", "xstate_mask", "xstate_compared_bytes", "red_zone_bytes"):
        require(row[key] is None if boundary else type(row[key]) is int,
                "native_row_state_type")
    if not boundary:
        require(row["register_words"] == 17 and row["red_zone_bytes"] == 128
                and 0 <= row["xstate_mask"] <= 2**64 - 1
                and 0 < row["xstate_compared_bytes"] <= 2**64 - 1,
                "native_row_state_extent")
    for key in ("pushed_return_ok", "return_page_pending"):
        require(row[key] is True if boundary else row[key] is None, "native_row_boundary")
    expected = (2, 2) if boundary else (1, 2 if case.startswith("cross_") else 1)
    require(all(type(row[key]) is int for key in ("faults", "admitted_pages"))
            and (row["faults"], row["admitted_pages"]) == expected,
            "native_row_faults")
    for key in ("selected_preparation_ns", "publication_ns"):
        require(row[key] == 0 if case in ("cross_instruction", "boundary_call")
                else row[key] > 0, "native_row_publication")
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100000:
        parser.error("iterations must be in 1..100000")
    revision = output(["git", "rev-parse", "HEAD"])
    if output(["git", "status", "--porcelain", "--untracked-files=no"]):
        parser.error("tracked source must be committed before measurement")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    private = Path("target/evaluation/inprocess") / (stamp + "-" + revision[:12])
    private.mkdir(parents=True, exist_ok=False)
    destination = args.output or (Path("evaluation/inprocess/results") /
                                  (stamp + "-" + revision[:12] + ".json"))
    if destination.exists():
        parser.error("output already exists")
    environment = os.environ.copy()
    settings = {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "4",
                "CARGO_TARGET_DIR": "target", "CARGO_NET_OFFLINE": "true"}
    environment.update(settings)
    cpu = min(os.sched_getaffinity(0))
    record = {"schema_version": 1, "revision": revision,
              "tree": output(["git", "rev-parse", "HEAD^{tree}"]),
              "started_utc": stamp, "build_profile": "release", "environment": settings,
              "runner_sha256": file_digest(Path(__file__)), "source_unchanged": None,
              "reproduce": ["python3", "evaluation/inprocess/run.py", "--iterations",
                            str(args.iterations)],
              "scope": "Owned immutable regions, eager publication, singleton in-process NX admission; no whole-program or lazy-patching claim.",
              "commands": [], "rows": [], "status": "failed"}
    try:
        record["hardware"] = hardware(cpu)
        record["rustc"] = output(["rustc", "--version"])
        record["cargo"] = output(["cargo", "--version"])
        command, _ = invoke(["cargo", "build", "--release", "--locked", "--offline",
                             "-p", "liteinst-inprocess", "--example", "native_probe"],
                            environment, private, "build", 600)
        record["commands"].append(command)
        require(completed(command), "release_build_failed")
        executable = Path("target/release/examples/native_probe")
        executable_hash = file_digest(executable)
        record["executable_sha256"] = executable_hash
        for case in CASES:
            require(file_digest(executable) == executable_hash, "executable_changed")
            command, stdout = invoke([str(executable), case, str(args.iterations)],
                                     environment, private, case, 60, cpu)
            record["commands"].append(command)
            require(completed(command), case + "_execution_failed")
            require(command["stdout_bytes"] <= 65536, "oversized_native_output")
            record["rows"].append(native_row(stdout.read_bytes(), case, args.iterations))
        require(file_digest(executable) == executable_hash, "executable_changed")
        record["status"] = "passed"
    except Refusal as error:
        record["error"] = str(error)
    except (ValueError, KeyError, TypeError, UnicodeError):
        record["error"] = "invalid_native_json"
    except (OSError, subprocess.SubprocessError) as error:
        record["error"] = "metadata_or_capture_failed"
        record["error_errno"] = getattr(error, "errno", None)
    finally:
        try:
            record["source_unchanged"] = (
                output(["git", "rev-parse", "HEAD"]) == revision
                and not output(["git", "status", "--porcelain", "--untracked-files=no"]))
        except (OSError, subprocess.SubprocessError):
            record["source_unchanged"] = None
        if record["source_unchanged"] is not True:
            record["status"] = "failed"
            record.setdefault("error", "source_changed_or_unobserved")
        attempted = {command["label"] for command in record["commands"]}
        record["not_run_cases"] = [case for case in CASES if case not in attempted]
        text = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + "\n"
        private_locations = (str(Path.home()), str(Path.cwd()), platform.node())
        if any(len(value) > 1 and value in text for value in private_locations):
            raise RuntimeError("public receipt contains private location data")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x") as result:
            result.write(text)
        print(destination)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
