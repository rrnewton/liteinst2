#!/usr/bin/env python3
"""Observe one fixed CALL/RET C artifact after exact-source prerequisites."""

import argparse
import copy
import datetime as dt
import os
from pathlib import Path
import re
import resource
import shutil
import sys

import run
import runtime_kernel_consumer as kernel
import runtime_stack_consumer_schema as schema
from default_parallel import toolchain
from parsing import InvalidEvidence
from processes import run_command
from runtime_consumer_schema import version_metadata

ROOT, HERE = run.ROOT, run.HERE
LOG_LIMIT, MAX_TOOL = kernel.LOG_LIMIT, kernel.MAX_TOOL
MAX_ARTIFACT = schema.MAX_ARTIFACT
SOURCE = "evaluation/admission/consumers/runtime_stack_identity.c"
PUBLIC = "target/debug/examples/runtime_stack_consumer"
ORACLE = "target/debug/examples/runtime_stack_consumer_oracle"
FEATURE = "dev-owned-stack-consumer-oracle"
RUN_ID = r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-runtime-stack-consumer-[0-9a-f]{12}"
STABILITY = ("source_unchanged", "configuration_unchanged", "toolchain_unchanged",
             "hardware_unchanged", "files_unchanged")


def command_specs(relative, artifact_digest=None, plan_digest=None):
    run.require(type(relative) is str and re.fullmatch("target/evaluation/admission/" + RUN_ID, relative),
                "stack_run_path")
    run.require(artifact_digest is None or schema.hash_value(artifact_digest), "stack_artifact_digest")
    run.require(plan_digest is None or schema.hash_value(plan_digest), "stack_plan_digest")
    object_file = relative + "/runtime_stack_identity.o"
    executable = relative + "/runtime_stack_identity.elf"
    commands = [
        ("clang_version", ["clang", "--version"], 10, 0),
        ("linker_version", ["ld.lld", "--version"], 10, 0),
        ("compile_c", ["clang", "--no-default-config", "--target=x86_64-unknown-linux-gnu",
            "-O2", "-ffreestanding", "-fno-builtin", "-nostdinc", "-fno-stack-protector",
            "-fno-pic", "-fno-pie", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
            "-fno-vectorize", "-fno-slp-vectorize", "-fcf-protection=none", "-mno-red-zone",
            "-mstack-alignment=8", "-fomit-frame-pointer", "-fno-optimize-sibling-calls",
            "-fintegrated-as", "-c", SOURCE, "-o", object_file], 180, 0),
        ("link_c", ["ld.lld", "-static", "--build-id=none", "--entry=_start", "-z", "noexecstack",
            "-z", "separate-code", "-z", "max-page-size=4096", "-o", executable, object_file], 180, 0),
        ("build_public", ["cargo", "build", "--locked", "--offline", "-p", "liteinst-launch",
            "--example", "runtime_stack_consumer"], 180, 0),
        ("clippy_oracle", ["cargo", "clippy", "--locked", "--offline", "-p", "liteinst-launch",
            "--example", "runtime_stack_consumer_oracle", "--features", FEATURE, "--", "-D", "warnings"], 180, 0),
        ("build_oracle", ["cargo", "build", "--locked", "--offline", "-p", "liteinst-launch",
            "--example", "runtime_stack_consumer_oracle", "--features", FEATURE], 180, 0),
        ("public_protocol", [PUBLIC, "--protocol-version"], 10, 0),
        ("oracle_protocol", [ORACLE, "--protocol-version"], 10, 0),
        ("inspect_artifact", [ORACLE, "--inspect-artifact", executable,
            "--expect-sha256", artifact_digest], 10, 0),
        ("reference", [executable], 3, 7),
        ("public_consumer", [PUBLIC, "--artifact", executable], 60, 0),
        ("oracle", [ORACLE, "--artifact", executable, "--expect-sha256", artifact_digest,
            "--expect-plan-sha256", plan_digest], 60, 0),
    ]
    # None records an as-yet unobserved digest, never an executable argv value.
    return [{"id": name, "argv": argv, "timeout_seconds": deadline,
             "expected_exit_code": expected, "environment_delta": {"RUST_TEST_THREADS": None},
             "status": "not_run"} for name, argv, deadline, expected in commands]


def observe(command, data):
    passed = kernel.command_passed(command)
    command["status"] = "passed" if passed else "failed"
    try:
        if command["id"] in ("clang_version", "linker_version"):
            command["tool_observation"] = version_metadata(
                "clang" if command["id"] == "clang_version" else "ld.lld", data)
        elif command["id"] in ("public_protocol", "oracle_protocol"):
            command["protocol"] = schema.parse_protocol(data,
                "public_consumer" if command["id"] == "public_protocol" else "oracle")
        elif command["id"] == "reference":
            run.require(data == b"", "stack_reference_output")
        elif command["id"] in ("inspect_artifact", "public_consumer", "oracle"):
            role = "artifact_plan" if command["id"] == "inspect_artifact" else command["id"]
            command["observation"] = schema.parse_row(data, passed, role)
    except InvalidEvidence as error:
        command["evidence_error"] = str(error)
        if passed:
            command["status"] = "invalid_evidence"


def consumer_environment_record():
    return {key: value for key, value in run.ENV.items() if key != "RUST_TEST_THREADS"} | {
        "CARGO_TARGET_DIR": "target", "TMPDIR": "private_run/tmp", "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8", "RLIMIT_CORE": 0}


def kernel_prerequisite(record, source, configuration, hardware, tools, correctness):
    """Check the unchanged old consumer before replaying its authenticated logs."""
    run.require(type(record) is dict and type(record.get("schema_version")) is int
        and record["schema_version"] == 1 and record.get("experiment") == "runtime-kernel-c-consumer"
        and record.get("status") == "passed" and record.get("source") == source,
        "stack_kernel_prerequisite_source")
    run.require(record.get("runner_sha256") == source["source_sha256"]["evaluation/admission/runtime_kernel_consumer.py"]
        and record.get("schema_sha256") == source["source_sha256"]["evaluation/admission/runtime_consumer_schema.py"],
        "stack_kernel_prerequisite_recorder")
    run.require(all(record.get(key) is True for key in STABILITY)
        and record.get("environment") == consumer_environment_record()
        and record.get("inherited_location_variables") == list(run.LOCATION_VARIABLES)
        and record.get("configuration") == configuration and record.get("hardware") == hardware
        and record.get("toolchain") == tools, "stack_kernel_prerequisite_environment")
    run.require(record.get("prerequisite") == correctness, "stack_kernel_prerequisite_six_binding")
    for key, expected in (("log_limit_bytes_per_command", LOG_LIMIT), ("cleanup_seconds", 3),
            ("artifact_limit_bytes", MAX_ARTIFACT), ("tool_and_example_limit_bytes", MAX_TOOL)):
        run.require(type(record.get(key)) is int and record[key] == expected,
                    "stack_kernel_prerequisite_limits")
    identity = record.get("run_id")
    run.require(type(identity) is str and re.fullmatch(
        r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-runtime-consumer-[0-9a-f]{12}", identity)
        and identity.endswith(source["revision"][:12])
        and record.get("private_relative") == "target/evaluation/admission/" + identity,
        "stack_kernel_prerequisite_identity")
    replay = copy.deepcopy(record)
    kernel.qualify(replay)
    run.require(replay["status"] == "passed" and replay == record,
                "stack_kernel_prerequisite_qualification")
    return True


def replay_kernel(record):
    hashes = {}
    replay = copy.deepcopy(record)
    for original, fresh in zip(record["commands"], replay["commands"]):
        digest = original.get("private_log_sha256")
        run.require(schema.hash_value(digest), "stack_kernel_prerequisite_log_hash")
        data = kernel.bounded_read(ROOT / record["private_relative"] / (original["id"] + ".log"), LOG_LIMIT)
        run.require(run.sha(data) == digest, "stack_kernel_prerequisite_log")
        for key in ("evidence_error", "tool_observation", "protocol", "consumer_observation"):
            fresh.pop(key, None)
        kernel.observe(fresh, data)
        hashes[original["id"]] = digest
    kernel.qualify(replay)
    run.require(replay == record and replay["status"] == "passed", "stack_kernel_prerequisite_replay")
    return hashes


def require_blob(value, maximum):
    schema.fields(value, {"sha256", "bytes"}, "stack_artifact_fields")
    run.require(schema.hash_value(value["sha256"]) and schema.natural(value["bytes"], maximum)
                and value["bytes"] > 0, "stack_artifact_bounds")


def qualify(record):
    """Parent qualification cannot be supplied by a child checked boolean."""
    complete = False
    try:
        run.require(all(record.get(key) is True for key in STABILITY)
            and all(record.get(key, {}).get("qualified") is True
                    for key in ("prerequisite", "kernel_prerequisite", "feature_prerequisite"))
            and "error_code" not in record and "error_type" not in record
            and not record.get("secondary_failures"), "stack_experiment_incomplete")
        artifacts, tools = record.get("artifacts", {}), record.get("c_tools", {})
        schema.fields(artifacts, {"c_source", "object", "elf", "public", "oracle"}, "stack_artifact_inventory")
        schema.fields(tools, {"clang", "ld.lld"}, "stack_tool_inventory")
        for name, value in artifacts.items():
            require_blob(value, MAX_TOOL if name in ("public", "oracle") else MAX_ARTIFACT)
        elf = record.get("elf")
        schema.fields(elf, {"sha256", "bytes", "static_native64", "load_segments",
            "initialized_text_bytes", "executable_bytes_sha256", "head_completeness"}, "stack_elf_fields")
        run.require(elf["sha256"] == artifacts["elf"]["sha256"] and elf["bytes"] == artifacts["elf"]["bytes"]
            and elf["static_native64"] is True and type(elf["load_segments"]) is int and elf["load_segments"] == 2
            and schema.natural(elf["initialized_text_bytes"], 4096) and elf["initialized_text_bytes"] > 0
            and schema.hash_value(elf["executable_bytes_sha256"]) and elf["head_completeness"] is False,
            "stack_elf_binding")
        commands = record["commands"]
        run.require(type(commands) is list and len(commands) == 13, "stack_command_inventory")
        inspect = commands[9].get("observation", {}).get("summary")
        public = commands[11].get("observation", {}).get("summary")
        oracle = commands[12].get("observation", {}).get("summary")
        schema.validate_inspect(inspect, True)
        run.require(record.get("artifact_plan") == inspect, "stack_retained_plan_binding")
        schema.validate_public(public, True)
        schema.validate_oracle(oracle, True)
        for row in (inspect, oracle):
            run.require(row["artifact_sha256"] == artifacts["elf"]["sha256"]
                and row["artifact_bytes"] == artifacts["elf"]["bytes"], "stack_row_artifact_binding")
        run.require(oracle["plan_sha256"] == inspect["plan_sha256"] and oracle["path"] == inspect["path"],
                    "stack_row_plan_binding")
        specs = command_specs(record["private_relative"], artifacts["elf"]["sha256"], inspect["plan_sha256"])
        for command, spec in zip(commands, specs):
            run.require(all(command.get(key) == value for key, value in spec.items() if key != "status")
                and command.get("status") == "passed" and kernel.command_passed(command)
                and "evidence_error" not in command and schema.hash_value(command.get("private_log_sha256")),
                "stack_command_not_qualified")
        run.require(commands[7].get("protocol") == schema.PUBLIC_PROTOCOL
            and commands[8].get("protocol") == schema.ORACLE_PROTOCOL, "stack_protocol_binding")
        for index in (9, 11, 12):
            run.require(commands[index]["observation"]["command_succeeded"] is True, "stack_row_command_failed")
        for index, name in enumerate(("clang", "ld.lld")):
            value = tools[name]
            schema.fields(value, {"sha256", "bytes", "version", "version_output_sha256"}, "stack_tool_fields")
            require_blob({key: value[key] for key in ("sha256", "bytes")}, MAX_TOOL)
            run.require(schema.hash_value(value["version_output_sha256"])
                and type(value["version"]) is str and re.fullmatch(r"\d+\.\d+(?:\.\d+){0,2}", value["version"])
                and commands[index].get("tool_observation") == {key: value[key]
                    for key in ("version", "version_output_sha256")}, "stack_tool_version_binding")
        complete = True
    except (InvalidEvidence, KeyError, TypeError, IndexError):
        complete = False
    record["status"] = "passed" if complete else "failed"
    for command in record.get("commands", []):
        if type(command) is dict and "observation" in command:
            command["observation"]["qualified_run"] = complete


def receipt_argument(value, digest):
    path = Path(value)
    run.require(schema.hash_value(digest) and not path.is_absolute()
        and path.parent == Path("evaluation/admission/results")
        and not (ROOT / path).is_symlink(), "stack_receipt_argument")
    return path


def read_receipt(path, digest):
    data = kernel.bounded_read(ROOT / path, 16 * 1024 * 1024)
    run.require(run.sha(data) == digest, "stack_receipt_digest")
    result = schema.strict_json(data)
    run.require(type(result) is dict and result.get("run_id") == path.stem, "stack_receipt_identity")
    return result


def fail(record, phase, error):
    """Keep first attribution; later file/cleanup failures remain separate."""
    failure = {"phase": phase, "code": str(error)} if isinstance(error, InvalidEvidence) else {
        "phase": phase, "type": type(error).__name__}
    if "error_code" not in record and "error_type" not in record:
        record["error_phase"] = phase
        record["error_code" if "code" in failure else "error_type"] = failure.get("code", failure.get("type"))
    else:
        record["secondary_failures"].append(failure)
    record["status"] = "failed"
    for command in record["commands"]:
        if type(command) is dict and "observation" in command:
            command["observation"]["qualified_run"] = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("expect-revision", "correctness-receipt", "correctness-sha256",
                 "kernel-consumer-receipt", "kernel-consumer-sha256", "feature-receipt", "feature-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    run.require(re.fullmatch(r"[0-9a-f]{40}", args.expect_revision), "stack_revision_argument")
    correctness_path = receipt_argument(args.correctness_receipt, args.correctness_sha256)
    kernel_path = receipt_argument(args.kernel_consumer_receipt, args.kernel_consumer_sha256)
    feature_path = receipt_argument(args.feature_receipt, args.feature_sha256)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    identity = stamp + "-runtime-stack-consumer-" + args.expect_revision[:12]
    relative = "target/evaluation/admission/" + identity
    private = ROOT / relative
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = private / "tmp"
    temporary.mkdir(mode=0o700)
    output = HERE / "results" / (identity + ".json")
    run.require(not output.exists(), "stack_duplicate_run")
    record = {"schema_version": 1, "experiment": "runtime-stack-c-consumer", "run_id": identity,
        "private_relative": relative, "status": "preflight", "source": None,
        "runner_sha256": run.sha(Path(__file__).read_bytes()),
        "schema_sha256": run.sha((HERE / "runtime_stack_consumer_schema.py").read_bytes()),
        "reproduce": ["python3", "evaluation/admission/runtime_stack_consumer.py",
            "--expect-revision", args.expect_revision, "--correctness-receipt", str(correctness_path),
            "--correctness-sha256", args.correctness_sha256, "--kernel-consumer-receipt", str(kernel_path),
            "--kernel-consumer-sha256", args.kernel_consumer_sha256,
            "--feature-receipt", str(feature_path), "--feature-sha256", args.feature_sha256],
        "commands": command_specs(relative), "c_tools": {}, "artifacts": {}, "artifact_observations": {},
        **{key: False for key in STABILITY}, "secondary_failures": [],
        "log_limit_bytes_per_command": LOG_LIMIT, "cleanup_seconds": 3,
        "cleanup_scope": "outer_supervisor", "artifact_limit_bytes": MAX_ARTIFACT,
        "tool_and_example_limit_bytes": MAX_TOOL, "performance_claim": None,
        "complete_B3": False, "full_application_support": False,
        "claim_scope": "one_unmodified_compiler_produced_call_ret_artifact",
        "inherited_location_variables": list(run.LOCATION_VARIABLES)}
    pins = {}
    phase = "preflight"
    run.write_result(output, record)
    print(output.relative_to(ROOT), flush=True)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        base_env = run.controlled_environment(os.environ, temporary)
        source = run.source_state()
        run.preflight(source, args.expect_revision,
            run.git("ls-files", "--others", "--exclude-standard").decode().splitlines())
        record["source"] = source
        run.require(sys.platform == "linux" and os.uname().machine == "x86_64", "stack_platform")
        record["configuration"] = run.cargo_configuration(base_env)
        record["hardware"] = run.hardware()
        run.require(1 <= record["hardware"]["affinity_cpu_count"] <= 8, "stack_affinity_bound")
        cpus = frozenset(os.sched_getaffinity(0))
        record["toolchain"] = toolchain(base_env)
        corpus_data = kernel.bounded_read(HERE / "corpus.json", 16 * 1024 * 1024)
        run.require(run.sha(corpus_data) == source["source_sha256"]["evaluation/admission/corpus.json"],
                    "stack_corpus_source")
        record["corpus_sha256"] = run.sha(corpus_data)
        corpus = schema.strict_json(corpus_data)
        prior = read_receipt(correctness_path, args.correctness_sha256)
        kernel.prerequisite(prior, source, corpus, record["corpus_sha256"], record["configuration"],
                            record["hardware"], record["toolchain"])
        six_hashes = kernel.replay_prerequisite(prior, corpus)
        record["prerequisite"] = {"qualified": True, "receipt": correctness_path.name,
            "sha256": args.correctness_sha256, "revision": source["revision"],
            "private_log_sha256": six_hashes, "policy": "exact_revision_and_unchanged_six_command_replay"}
        # Root owns the separately reviewed exact-source pure-cohort runner.
        # Absence or a rejected inventory is preflight failure, never a skip.
        from runtime_stack_feature_controls import authenticate_prerequisite
        feature_record = read_receipt(feature_path, args.feature_sha256)
        feature = authenticate_prerequisite(feature_record, source=source,
            configuration=record["configuration"], hardware=record["hardware"],
            toolchain=record["toolchain"], corpus=corpus, corpus_digest=record["corpus_sha256"])
        schema.fields(feature, {"qualified", "revision", "private_log_sha256",
            "method_inventory_sha256", "pure_methods", "native_methods", "policy"}, "stack_feature_auth_fields")
        run.require(feature["qualified"] is True and feature["revision"] == source["revision"]
            and schema.hash_value(feature["private_log_sha256"])
            and schema.hash_value(feature["method_inventory_sha256"])
            and schema.natural(feature["pure_methods"], 4096) and feature["pure_methods"] > 0
            and type(feature["native_methods"]) is int and feature["native_methods"] == 0
            and feature["policy"] == "exact_source_closed_feature_pure_replay", "stack_feature_auth_projection")
        # The helper, not this upper-bound/type check, must prove the exact
        # source-derived method set and every actual non-ignored result.
        record["feature_prerequisite"] = feature | {"receipt": feature_path.name, "sha256": args.feature_sha256}
        old = read_receipt(kernel_path, args.kernel_consumer_sha256)
        kernel_prerequisite(old, source, record["configuration"], record["hardware"],
                            record["toolchain"], record["prerequisite"])
        old_hashes = replay_kernel(old)
        old_paths = {"c_source": ROOT / kernel.SOURCE, "object": ROOT / old["private_relative"] / "runtime_identity.o",
                     "elf": ROOT / old["private_relative"] / "runtime_identity.elf", "example": ROOT / kernel.EXAMPLE}
        for name, path in old_paths.items():
            pin = kernel.PinnedFile(path, MAX_TOOL if name == "example" else MAX_ARTIFACT,
                artifact=name in ("object", "elf"), executable=name in ("elf", "example"))
            pins["prior_" + name] = pin
            run.require(pin.public() == old["artifacts"][name], "stack_kernel_prerequisite_artifact")
        record["kernel_prerequisite"] = {"qualified": True, "receipt": kernel_path.name,
            "sha256": args.kernel_consumer_sha256, "revision": source["revision"],
            "private_log_sha256": old_hashes, "artifacts_authenticated": True,
            "policy": "exact_revision_and_unchanged_eight_command_replay"}
        # Authenticate the six-command ENV first; derive only the consumer ENV.
        env = kernel.consumer_environment(base_env)
        record["environment"] = consumer_environment_record()
        for role in ("clang", "ld.lld"):
            located = shutil.which(role, path=env["PATH"])
            run.require(located is not None, "stack_tool_missing")
            pins[role] = kernel.PinnedTool(located, role)
            record["c_tools"][role] = pins[role].public()
            run.require(pins[role].public() == {key: old["c_tools"][role][key]
                        for key in ("sha256", "bytes")}, "stack_kernel_prerequisite_tool")
        pins["c_source"] = kernel.PinnedFile(ROOT / SOURCE, MAX_ARTIFACT)
        run.require(pins["c_source"].digest == source["source_sha256"][SOURCE], "stack_c_source")
        record["artifacts"]["c_source"] = pins["c_source"].public()

        def stable():
            after = run.source_state()
            record["source_unchanged"] = source == after
            run.preflight(after, args.expect_revision,
                run.git("ls-files", "--others", "--exclude-standard").decode().splitlines())
            record["configuration_unchanged"] = record["configuration"] == run.cargo_configuration(base_env)
            record["toolchain_unchanged"] = record["toolchain"] == toolchain(base_env)
            record["hardware_unchanged"] = record["hardware"] == run.hardware()
            record["files_unchanged"] = False
            run.require(cpus == frozenset(os.sched_getaffinity(0)), "stack_affinity_changed")
            for pin in pins.values():
                pin.check()
            record["files_unchanged"] = True
            run.require(all(record[key] for key in STABILITY), "stack_environment_changed")

        record["status"] = "running"
        for index, command in enumerate(record["commands"]):
            phase = command["id"]
            stable()
            artifact_digest = pins["elf"].digest if "elf" in pins else None
            plan_digest = record.get("artifact_plan", {}).get("plan_sha256")
            command["argv"] = command_specs(relative, artifact_digest, plan_digest)[index]["argv"]
            run.require(all(type(arg) is str for arg in command["argv"]), "stack_unbound_command")
            created = {"compile_c": private / "runtime_stack_identity.o",
                       "link_c": private / "runtime_stack_identity.elf"}.get(phase)
            if created is not None:
                run.require(not created.exists() and not created.is_symlink(), "stack_preexisting_output")
            command["status"] = "running"
            run.write_result(output, record)
            actual = list(command["argv"])
            if actual[0] in ("clang", "ld.lld"):
                actual[0] = str(pins[actual[0]].launcher)
            elif actual[0] in (PUBLIC, ORACLE):
                actual[0] = str(pins["public" if actual[0] == PUBLIC else "oracle"].path)
            log = private / (phase + ".log")
            command.update(run_command(actual, env, log, command["timeout_seconds"], LOG_LIMIT))
            process_passed = kernel.command_passed(command)
            command["status"] = "passed" if process_passed else "failed"
            if not process_passed:
                fail(record, phase, InvalidEvidence("stack_command_failed"))
            # Retain the actual completed process result before any fallible
            # capture read/parser, so a secondary read cannot hide its failure.
            captured = kernel.bounded_read(log, LOG_LIMIT)
            run.require(run.sha(captured) == command["private_log_sha256"], "stack_capture_digest")
            observe(command, captured)
            if process_passed and command["status"] != "passed":
                fail(record, phase, InvalidEvidence("stack_command_failed"))
            if created is not None:
                record["artifact_observations"][phase] = kernel.artifact_prefix(created, command["status"] == "passed")
            run.write_result(output, record)
            stable()
            if command["status"] != "passed":
                break
            if phase in ("clang_version", "linker_version"):
                role = "clang" if phase == "clang_version" else "ld.lld"
                record["c_tools"][role].update(command["tool_observation"])
                run.require(record["c_tools"][role] == old["c_tools"][role], "stack_kernel_prerequisite_version")
            elif phase == "compile_c":
                pins["object"] = kernel.PinnedFile(created, MAX_ARTIFACT, artifact=True)
                record["artifacts"]["object"] = pins["object"].public()
            elif phase == "link_c":
                pins["elf"] = kernel.PinnedFile(created, MAX_ARTIFACT, artifact=True, executable=True)
                description = schema.compact_elf(pins["elf"].data())
                pins["elf"].make_readonly()
                record["artifacts"]["elf"] = pins["elf"].public()
                record["elf"] = description
            elif phase in ("build_public", "build_oracle"):
                role = "public" if phase == "build_public" else "oracle"
                pins[role] = kernel.PinnedFile(ROOT / (PUBLIC if role == "public" else ORACLE), MAX_TOOL, executable=True)
                record["artifacts"][role] = pins[role].public()
            elif phase == "inspect_artifact":
                row = command["observation"]["summary"]
                run.require(row["artifact_sha256"] == pins["elf"].digest
                    and row["artifact_bytes"] == pins["elf"].identity[4], "stack_inspect_artifact_binding")
                record["artifact_plan"] = copy.deepcopy(row)
            stable()
            run.write_result(output, record)
        qualify(record)
    except (Exception, KeyboardInterrupt) as error:
        fail(record, phase, error)
    finally:
        for name, pin in pins.items():
            try:
                pin.close()
            except OSError as error:
                fail(record, "pin_close_" + name, error)
        run.write_result(output, record)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
