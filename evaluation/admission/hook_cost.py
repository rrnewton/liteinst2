#!/usr/bin/env python3
"""Inner cost collection inside an already reserved, enforced CPU scope.

Writes an unqualified private staging receipt. The bounded outer invocation is
the only publisher: it must also prove allocator and supervisor cleanup.
"""

import argparse
import os
from pathlib import Path
import re
import resource
import sys

import run
from processes import run_command
from hook_cost_proof import (LOG_LIMIT, PUBLIC_ENV, clock_metadata, correctness_prerequisite,
    executable_identity, placement, require, sha, source_identity, strict_json, toolchain)
from hook_cost_schema import load_inventory, parse_capture
from parsing import InvalidEvidence

ROOT, HERE = run.ROOT, run.HERE
BINARY = "target/release/examples/b2_hook_cost"
BUILD = ["cargo", "build", "--offline", "--release", "-p", "liteinst-launch", "--example", "b2_hook_cost"]
BUILD_TIMEOUT, MEASURE_TIMEOUT = 180, 300
RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{12}-hook-cost")


def clean_command(command):
    return (type(command.get("exit_code")) is int and command["exit_code"] == 0
            and command.get("termination") is None and command.get("cleanup_complete") is True
            and type(command.get("reaped_descendants")) is int and command["reaped_descendants"] == 0)


def command_spec(name, argv, timeout):
    return {"id": name, "argv": argv, "timeout_seconds": timeout, "environment_delta": {}, "status": "not_run"}


def public_error(error):
    # Never persist OS exceptions, paths, native panic text or arbitrary output.
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    if isinstance(error, InvalidEvidence) and re.fullmatch(r"[a-z0-9_]{1,100}", str(error)):
        return str(error)
    return {OSError: "operating_system_error", ValueError: "invalid_metadata", KeyError: "missing_metadata"}.get(type(error),
                                                                                                             "recorder_exception")


def collect(args):
    require(RUN_ID.fullmatch(args.run_id), "invalid_run_id")
    private = ROOT / "target/evaluation/admission" / args.run_id
    require(private.is_dir() and not private.is_symlink(), "outer_private_directory_missing")
    output = private / "inner.json"
    require(not output.exists(), "duplicate_inner_receipt")
    temporary = private / "inner-tmp"
    temporary.mkdir()
    record = {"schema_version": 1, "experiment": "b2-hook-cost", "run_id": args.run_id,
              "status": "preflight", "qualified": False, "source": None, "source_unchanged": False,
              "configuration_unchanged": False, "placement_unchanged": False, "hardware_unchanged": False,
              "toolchain_unchanged": False, "executable_unchanged": False, "environment": PUBLIC_ENV,
              "inherited_location_variables": list(run.LOCATION_VARIABLES), "log_limit_bytes_per_command": LOG_LIMIT,
              "runner_sha256": sha(Path(__file__).read_bytes()), "commands": [], "evidence": None,
              "performance_pass_threshold": None, "claim_scope": "finite_scripted_synchronous_completion_cost"}
    run.write_result(output, record)
    try:
        env = run.controlled_environment(os.environ, temporary)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        require(sys.platform == "linux" and os.uname().machine == "x86_64", "unsupported_platform")
        source = source_identity(args.expect_revision)
        record["source"] = source
        configuration = run.cargo_configuration(env)
        record["configuration"] = configuration
        hardware = run.hardware()
        record["hardware"] = hardware
        require(hardware["effective_uid_is_root"] is False
                and type(hardware["effective_capabilities"]) is int
                and hardware["effective_capabilities"] == 0, "unprivileged_measurement_required")
        record["placement"] = placement()
        record["clock"] = clock_metadata()
        tools = toolchain(env)
        record["toolchain"] = tools
        corpus = strict_json((HERE / "corpus.json").read_bytes())
        record["correctness"] = correctness_prerequisite(HERE / "results" / args.correctness_receipt,
            args.correctness_sha256, source, corpus, configuration, hardware, tools,
            scoped_placement=record["placement"])
        inventory_digest = source["source_sha256"]["evaluation/admission/hook_cost_inventory.json"]
        inventory = load_inventory(HERE / "hook_cost_inventory.json", expected_sha256=inventory_digest)
        record["inventory_sha256"] = inventory_digest
        record["wire_sha256"] = sha((HERE / "hook_cost_wire.json").read_bytes())
        record["evidence"] = parse_capture("", inventory)
        record["commands"] = [command_spec("release_build", BUILD, BUILD_TIMEOUT),
            command_spec("measurement", [BINARY] + inventory["argv"], MEASURE_TIMEOUT)]
        run.write_result(output, record)
        for command in record["commands"]:
            require(source_identity(args.expect_revision) == source, "source_changed_before_command")
            require(run.cargo_configuration(env) == configuration, "configuration_changed_before_command")
            require(placement() == record["placement"], "placement_changed_before_command")
            if command["id"] == "measurement":
                record["executable"] = executable_identity(ROOT / BINARY)
            record["status"] = "running"
            command["status"] = "running"
            run.write_result(output, record)
            log = private / (command["id"] + ".log")
            command.update(run_command(command["argv"], env, log, command["timeout_seconds"], LOG_LIMIT))
            command["status"] = "passed" if clean_command(command) else "failed"
            if command["id"] == "measurement":
                raw = log.read_bytes()
                require(len(raw) <= LOG_LIMIT and sha(raw) == command["private_log_sha256"], "capture_digest_differs")
                record["evidence"] = parse_capture(raw.decode("utf-8", errors="replace"), inventory)
            run.write_result(output, record)
            require(command["status"] == "passed", "cost_command_failed")
        record["source_unchanged"] = source_identity(args.expect_revision) == source
        record["configuration_unchanged"] = run.cargo_configuration(env) == configuration
        record["placement_unchanged"] = placement() == record["placement"]
        record["hardware_unchanged"] = run.hardware() == hardware
        record["toolchain_unchanged"] = toolchain(env) == tools
        record["executable_unchanged"] = executable_identity(ROOT / BINARY) == record["executable"]
        require(all(record[k] is True for k in ("source_unchanged", "configuration_unchanged", "placement_unchanged",
                "hardware_unchanged", "toolchain_unchanged", "executable_unchanged")), "measurement_identity_changed")
        require(record["evidence"]["status"] == "complete", "measurement_evidence_incomplete")
        record["status"] = "measured_pending_outer"
    except (Exception, KeyboardInterrupt) as error:
        record["status"] = "failed"
        record["error"] = public_error(error)
    run.write_result(output, record)
    return 0 if record["status"] == "measured_pending_outer" else 1


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-revision", required=True)
    parser.add_argument("--correctness-receipt", required=True)
    parser.add_argument("--correctness-sha256", required=True)
    parser.add_argument("--run-id", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(collect(arguments()))
