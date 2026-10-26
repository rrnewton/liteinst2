#!/usr/bin/env python3
"""Four bounded default-parallel launch-unit runs; not the six-command protocol."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import resource
import shutil
import sys

from parsing import InvalidEvidence, parse_harnesses
from processes import run_command
from run import (ROOT, HERE, GIT, ENV, LOCATION_VARIABLES, cargo_configuration,
                 controlled_environment, git, hardware, preflight, require,
                 sha, source_state, tool_version, write_result)

UNIT = "unit/liteinst_launch/lib"
ARGV = ("cargo", "test", "-p", "liteinst-launch", "--lib")
IDS = ("default_parallel_1", "default_parallel_2", "default_parallel_3", "default_parallel_4")
TIMEOUT = 180
LOG_LIMIT = 8 * 1024 * 1024


def default_environment(inherited, temporary):
    env = controlled_environment(inherited, temporary)
    del env["RUST_TEST_THREADS"]
    require("RUST_TEST_THREADS" not in env, "unexpected_test_thread_override")
    return env


def affinity_witness(cpus):
    require(isinstance(cpus, (set, frozenset))
            and len(cpus) == 8
            and all(type(cpu) is int and cpu >= 0 for cpu in cpus),
            "default_parallel_requires_eight_cpus")
    return frozenset(cpus)


def expected_unit(corpus):
    require(type(corpus.get("schema_version")) is int and corpus["schema_version"] == 1,
            "unknown_corpus_schema")
    values = corpus["harness_test_counts"]
    expected = values["workspace_tests"][UNIT]
    require(expected == values["serial_launch"][UNIT], "launch_unit_corpus_differs")
    require(isinstance(expected, dict) and set(expected) == {"tests", "ignored"}
            and all(type(value) is int for value in expected.values())
            and expected["tests"] > 0 and 0 <= expected["ignored"] <= expected["tests"],
            "invalid_launch_unit_corpus")
    return {UNIT: dict(expected)}


def authenticated_corpus(data, source):
    require(sha(data) == source["source_sha256"].get("evaluation/admission/corpus.json"),
            "default_parallel_corpus_source_mismatch")
    return expected_unit(json.loads(data))


def commands():
    return [{"id": name, "argv": list(ARGV), "timeout_seconds": TIMEOUT,
             "environment_delta": {}, "status": "not_run"} for name in IDS]


def observe(command, output, expected):
    passed = (command["exit_code"] == 0 and command["termination"] is None
              and command["cleanup_complete"] is True and command["reaped_descendants"] == 0)
    command["status"] = "passed" if passed else "failed"
    command["evidence_status"] = "complete"
    try:
        command["harnesses"] = parse_harnesses(output, expected, command["exit_code"])
    except InvalidEvidence as error:
        command["harnesses"] = error.partial or []
        command["evidence_status"] = "incomplete"
        command["parse_error"] = str(error)
        if command["status"] == "passed":
            command["status"] = "invalid_evidence"
    for row in command["harnesses"]:
        row["qualified_run"] = False


def qualify(record):
    complete = (record.get("source_unchanged") is True
                and record.get("configuration_unchanged") is True
                and record.get("toolchain_unchanged") is True
                and record.get("hardware_unchanged") is True
                and record.get("affinity_unchanged") is True
                and record.get("affinity_cpu_count") == 8
                and record.get("environment", {}).get("RUST_TEST_THREADS") is None
                and "RUST_TEST_THREADS" not in record.get("environment", {})
                and "error_code" not in record and "error_type" not in record)
    runs = record["commands"]
    complete &= len(runs) == len(IDS)
    for index, command in enumerate(runs):
        complete &= (index < len(IDS) and command.get("id") == IDS[index]
                     and command.get("argv") == list(ARGV)
                     and command.get("timeout_seconds") == TIMEOUT
                     and command.get("environment_delta") == {}
                     and command.get("status") == "passed"
                     and command.get("exit_code") == 0
                     and command.get("termination") is None
                     and command.get("cleanup_complete") is True
                     and command.get("reaped_descendants") == 0
                     and command.get("evidence_status") == "complete"
                     and len(command.get("harnesses", [])) == 1)
        for row in command.get("harnesses", []):
            outer = row.get("outer") or {}
            complete &= (row.get("id") == UNIT and row.get("status") == "complete"
                         and outer.get("result") == "ok" and outer.get("failed") == 0
                         and outer.get("filtered") == 0 and outer.get("measured") == 0
                         and outer.get("ignored") == row.get("expected_ignored")
                         and outer.get("passed", -1) + outer.get("ignored", -1)
                         == row.get("expected_tests"))
    record["status"] = "passed" if complete else "failed"
    for command in runs:
        for row in command.get("harnesses", []):
            row["qualified_run"] = bool(complete)


def toolchain(env):
    result = {name: {"version": tool_version(name, env),
                     "launcher_sha256": sha(Path(shutil.which(name, path=env["PATH"])).read_bytes())}
              for name in ("rustc", "cargo")}
    result["git"] = {"argv0": GIT, "version": tool_version(GIT, env),
                     "executable_sha256": sha(Path(GIT).read_bytes())}
    result["python"] = {"version": sys.version.split()[0],
        "executable_sha256": sha(Path(sys.executable).read_bytes()),
        "launcher_sha256": sha(Path(shutil.which("python3", path=env["PATH"])).read_bytes())}
    return result


def audit_current(record, env, cpus, revision):
    # Keep exact selected IDs private. A changed set with the same count refuses.
    record["affinity_unchanged"] = cpus == affinity_witness(os.sched_getaffinity(0))
    record["source_unchanged"] = record["source"] == source_state()
    record["configuration_unchanged"] = record["configuration"] == cargo_configuration(env)
    record["toolchain_unchanged"] = record["toolchain"] == toolchain(env)
    record["hardware_unchanged"] = record["hardware"] == hardware()
    require(record["affinity_unchanged"], "default_parallel_affinity_changed")
    require(record["source_unchanged"], "default_parallel_source_changed")
    require(record["configuration_unchanged"], "default_parallel_configuration_changed")
    require(record["toolchain_unchanged"], "default_parallel_toolchain_changed")
    require(record["hardware_unchanged"], "default_parallel_hardware_changed")
    preflight(record["source"], revision,
              git("ls-files", "--others", "--exclude-standard").decode().splitlines())


def execute(record, env, private, expected, publish, stable):
    for command in record["commands"]:
        stable()
        command["status"] = "running"
        publish()
        log = private / (command["id"] + ".log")
        command.update(run_command(command["argv"], env, log, TIMEOUT, LOG_LIMIT))
        # Harvest typed observations before a post-command source/config failure.
        observe(command, log.read_text(errors="replace"), expected)
        publish()
        stable()
        if command["status"] != "passed":
            break


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-revision", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[a-f0-9]{40}", args.expect_revision), "invalid_expected_revision")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_id = stamp + "-default-parallel-" + args.expect_revision[:12]
    private = ROOT / "target/evaluation/admission" / run_id
    private.mkdir(parents=True, exist_ok=False)
    temporary = private / "tmp"
    temporary.mkdir()
    public = HERE / "results" / (run_id + ".json")
    public.parent.mkdir(parents=True, exist_ok=True)
    require(not public.exists(), "duplicate_run_id")
    public_env = {key: value for key, value in ENV.items() if key != "RUST_TEST_THREADS"}
    public_env.update(CARGO_TARGET_DIR="target", TMPDIR="private_run/tmp",
                      LANG="C.UTF-8", LC_ALL="C.UTF-8", RLIMIT_CORE=0)
    record = {"schema_version": 1, "experiment": "admission-default-parallel",
        "run_id": run_id, "qualification_protocol": False,
        "claim_targets": [4], "complete_claims_established": [],
        "source": None, "source_unchanged": None, "configuration": None,
        "configuration_unchanged": None, "toolchain": None, "toolchain_unchanged": None,
        "hardware": None, "hardware_unchanged": None,
        "affinity_cpu_count": None, "affinity_unchanged": None,
        "test_parallelism": "libtest_default_without_thread_override",
        "runner_sha256": sha(Path(__file__).read_bytes()), "corpus_sha256": None,
        "reproduce": ["python3", "evaluation/admission/default_parallel.py",
                      "--expect-revision", args.expect_revision],
        "reproduction_requires_inherited_affinity_cpus": 8,
        "environment": public_env, "inherited_location_variables": list(LOCATION_VARIABLES),
        "log_limit_bytes_per_command": LOG_LIMIT, "performance_claim": None,
        "preemption_clock": "not_evaluated", "status": "preflight", "commands": commands()}
    write_result(public, record)
    print(public.relative_to(ROOT), flush=True)
    try:
        env = default_environment(os.environ, temporary)
        require(sys.platform == "linux" and os.uname().machine == "x86_64", "unsupported_platform")
        selected = os.sched_getaffinity(0)
        record["affinity_cpu_count"] = len(selected)
        cpus = affinity_witness(selected)
        record["source"] = source_state()
        preflight(record["source"], args.expect_revision,
                  git("ls-files", "--others", "--exclude-standard").decode().splitlines())
        corpus_data = (HERE / "corpus.json").read_bytes()
        record["corpus_sha256"] = sha(corpus_data)
        expected = authenticated_corpus(corpus_data, record["source"])
        record["configuration"] = cargo_configuration(env)
        record["hardware"] = hardware()
        require(record["hardware"]["affinity_cpu_count"] == 8, "default_parallel_hardware_affinity_differs")
        record["toolchain"] = toolchain(env)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        record["status"] = "running"
        execute(record, env, private, expected,
                lambda: write_result(public, record),
                lambda: audit_current(record, env, cpus, args.expect_revision))
        audit_current(record, env, cpus, args.expect_revision)
        qualify(record)
    except (Exception, KeyboardInterrupt) as error:
        record["error_code" if isinstance(error, InvalidEvidence) else "error_type"] = (
            str(error) if isinstance(error, InvalidEvidence) else type(error).__name__)
        record["status"] = ("refused" if record["status"] == "preflight" else
                            "interrupted" if isinstance(error, KeyboardInterrupt) else "recorder_error")
        for command in record["commands"]:
            for row in command.get("harnesses", []):
                row["qualified_run"] = False
    finally:
        write_result(public, record)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except InvalidEvidence as error:
        print("default parallel validation refused: " + str(error), file=sys.stderr)
        sys.exit(2)
