#!/usr/bin/env python3
"""One bounded, source-bound feature-pure cohort; separate from default gates."""

import argparse
from collections import Counter
import datetime as dt
import math
import os
from pathlib import Path
import re
import resource
import sys

import run
from default_parallel import toolchain as inspect_toolchain
from parsing import InvalidEvidence, SUMMARY
from processes import run_command
from runtime_consumer_schema import strict_json
from runtime_kernel_consumer import bounded_read

ROOT, HERE = run.ROOT, run.HERE
RUNNER = "evaluation/admission/runtime_stack_feature_controls.py"
INVENTORY = "evaluation/admission/runtime_stack_feature_inventory.json"
LIBRARY = "crates/liteinst-launch/src/"
CARGO = "crates/liteinst-launch/Cargo.toml"
FEATURE = "dev-owned-stack-consumer-oracle"
FILTER = "consumer_oracle"
HARNESS = "unit/liteinst_launch/lib"
ARGV = ("cargo", "test", "--locked", "--offline", "-p", "liteinst-launch",
        "--features", FEATURE, "--lib", FILTER)
TIMEOUT, LOG_LIMIT, INVENTORY_LIMIT = 180, 8 * 1024 * 1024, 16 * 1024 * 1024
POLICY = "exact_source_closed_feature_pure_replay"
HEX = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+")
LEAF = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-runtime-stack-feature-[0-9a-f]{12}")
HEADER = re.compile(r"Running unittests src/lib\.rs \(target/debug/deps/liteinst_launch-[0-9a-f]{16}\)")
TEST = re.compile(r"test ([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+) \.\.\. (ok|FAILED|ignored)")
# This is a deliberately closed source-census check, not a Rust cfg/parser or
# a proof that an arbitrary test is pure. The finalized source review supplies
# module/cfg reachability and effect classification; actual libtest names and
# filtered count must then agree. Unknown declaration spelling refuses.
DECLARATION = re.compile(r"(?m)^\s*#\[test\]\s*(?:#\[[^\n]*\]\s*)*"
    r"(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
ATTRIBUTE = re.compile(r"(?m)^\s*#\[test\]\s*")
STABILITY = ("source_unchanged", "configuration_unchanged", "toolchain_unchanged",
             "hardware_unchanged", "affinity_unchanged")


def fields(value, expected, code):
    run.require(type(value) is dict and set(value) == set(expected), code)


def digest(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def natural(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def same_json(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(same_json(actual[key], value) for key, value in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(same_json(left, right) for left, right in zip(actual, expected))
    return actual == expected


def default_count(corpus):
    run.require(type(corpus) is dict and type(corpus.get("schema_version")) is int
        and corpus["schema_version"] == 1, "feature_corpus_schema")
    workspace = corpus["harness_test_counts"]["workspace_tests"][HARNESS]
    serial = corpus["harness_test_counts"]["serial_launch"][HARNESS]
    fields(workspace, {"tests", "ignored"}, "feature_corpus_fields")
    run.require(same_json(workspace, serial) and natural(workspace["tests"], 65536)
        and workspace["tests"] > 0 and type(workspace["ignored"]) is int
        and workspace["ignored"] == 0, "feature_corpus_count")
    return workspace["tests"]


def validate_inventory(value, source, corpus):
    fields(value, {"schema_version", "finalized", "feature", "filter", "harness",
        "classification", "cargo_sha256", "source_rows", "compiled_methods"}, "feature_inventory_fields")
    run.require(type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["finalized"] is True and value["feature"] == FEATURE and value["filter"] == FILTER
        and value["harness"] == HARNESS and value["classification"] == "source_reviewed_pure",
        "feature_inventory_scope")
    sources = source["source_sha256"]
    run.require(digest(value["cargo_sha256"]) and value["cargo_sha256"] == sources.get(CARGO),
        "feature_inventory_cargo")
    rows = value["source_rows"]
    run.require(type(rows) is list and 0 < len(rows) <= 16384, "feature_inventory_rows")
    expected_paths = {path for path in sources if path.startswith(LIBRARY) and path.endswith(".rs")}
    paths, declarations = [], Counter()
    for row in rows:
        fields(row, {"path", "sha256", "test_functions"}, "feature_source_row_fields")
        path, names = row["path"], row["test_functions"]
        run.require(type(path) is str and path in expected_paths and digest(row["sha256"])
            and row["sha256"] == sources[path], "feature_source_row_binding")
        run.require(type(names) is list and len(names) <= 65536
            and all(type(name) is str and LEAF.fullmatch(name) for name in names)
            and names == sorted(names), "feature_source_declarations")
        paths.append(path)
        declarations.update((path, name) for name in names)
    run.require(paths == sorted(expected_paths), "feature_source_inventory_complete")
    methods = value["compiled_methods"]
    run.require(type(methods) is list and 0 < len(methods) <= 65536, "feature_method_inventory")
    names, mapped, selected, defaults = [], Counter(), [], []
    for method in methods:
        fields(method, {"name", "path", "scope"}, "feature_method_fields")
        name, path, scope = method["name"], method["path"], method["scope"]
        run.require(type(name) is str and NAME.fullmatch(name) and type(path) is str
            and path in expected_paths and scope in ("default", "feature_pure"), "feature_method_identity")
        names.append(name)
        mapped[(path, name.rsplit("::", 1)[-1])] += 1
        if scope == "feature_pure":
            run.require(FILTER in name, "feature_method_filter")
            selected.append(name)
        else:
            run.require(FILTER not in name, "feature_default_filter_overlap")
            defaults.append(name)
    run.require(names == sorted(set(names)) and mapped == declarations, "feature_method_census")
    run.require(len(defaults) == default_count(corpus) and 0 < len(selected) <= 4096,
        "feature_method_counts")
    native = corpus["native_validation_fixtures"]
    run.require(type(native) is list and all(type(row) is dict and type(row.get("test")) is str
        and type(row.get("harness")) is str for row in native), "feature_native_catalog")
    # Necessary exclusion only: source review also checks all call graphs for
    # actual effects. A new native test absent from the catalog is not pure.
    run.require(not set(selected).intersection(row["test"] for row in native), "feature_native_intersection")
    run.require({row["test"] for row in native if row["harness"] == HARNESS}.issubset(defaults),
        "feature_default_native_inventory")
    return {"methods": selected, "filtered_out": len(defaults), "native_methods": 0}


def source_guard(value, source, read):
    for row in value["source_rows"]:
        data = read(ROOT / row["path"], INVENTORY_LIMIT)
        run.require(run.sha(data) == row["sha256"], "feature_source_bytes")
        try:
            text = data.decode("utf-8")
        except UnicodeError as error:
            raise InvalidEvidence("feature_source_encoding") from error
        names = DECLARATION.findall(text)
        run.require(len(names) == len(ATTRIBUTE.findall(text))
            and sorted(names) == row["test_functions"]
            and re.search(r"(?m)^\s*#\[ignore(?:\s|\]|=)", text) is None,
            "feature_source_test_census")
    run.require(run.sha(read(ROOT / CARGO, INVENTORY_LIMIT)) == source["source_sha256"][CARGO],
        "feature_cargo_bytes")


def load_inventory(source, corpus):
    data = bounded_read(ROOT / INVENTORY, INVENTORY_LIMIT)
    run.require(run.sha(data) == source["source_sha256"].get(INVENTORY), "feature_inventory_source")
    value = strict_json(data)
    selected = validate_inventory(value, source, corpus)
    source_guard(value, source, bounded_read)
    return selected, run.sha(data)


def parse_capture(data, inventory):
    row = {"harness": HARNESS, "expected_tests": len(inventory["methods"]),
        "expected_filtered": inventory["filtered_out"], "header": False, "started": None,
        "methods": [], "outer": None, "status": "incomplete"}
    try:
        run.require(type(data) is bytes and len(data) <= LOG_LIMIT, "feature_capture_size")
        try:
            text = data.decode("utf-8")
        except UnicodeError as error:
            raise InvalidEvidence("feature_capture_encoding") from error
        allowed, seen = set(inventory["methods"]), set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith(("Running ", "Doc-tests ")):
                run.require(not row["header"] and HEADER.fullmatch(line), "feature_capture_header")
                row["header"] = True
            elif line.startswith("running "):
                match = re.fullmatch(r"running ([0-9]+) tests?", line)
                run.require(row["header"] and row["started"] is None and row["outer"] is None
                    and match is not None, "feature_capture_start")
                row["started"] = int(match[1])
                run.require(row["started"] == row["expected_tests"], "feature_capture_start_count")
            elif line.startswith("test result:"):
                match = SUMMARY.fullmatch(line)
                run.require(row["started"] is not None and row["outer"] is None
                    and match is not None, "feature_capture_summary")
                result, *values = match.groups()
                counts = [int(value) for value in values[:5]]
                seconds = float(values[5])
                row["outer"] = dict(zip(("passed", "failed", "ignored", "measured", "filtered"), counts))
                row["outer"].update(result=result, seconds=seconds)
                run.require(math.isfinite(seconds) and sum(counts[:3]) == row["expected_tests"]
                    and counts[3] == 0 and counts[4] == row["expected_filtered"]
                    and (result == "FAILED") == (counts[1] > 0), "feature_capture_summary_counts")
                run.require(seen == allowed, "feature_capture_missing_method")
                actual = Counter(item["status"] for item in row["methods"])
                run.require(counts[:3] == [actual["ok"], actual["FAILED"], actual["ignored"]],
                    "feature_capture_method_counts")
                run.require(result == "ok" and counts[1] == counts[2] == 0, "feature_capture_not_all_passed")
            elif line.startswith("test "):
                match = TEST.fullmatch(line)
                run.require(row["started"] is not None and row["outer"] is None
                    and match is not None, "feature_capture_method_line")
                name, status = match.groups()
                run.require(name in allowed and name not in seen, "feature_capture_method_identity")
                seen.add(name)
                row["methods"].append({"test": name, "status": status})
            else:
                # Only Cargo's pre-harness build output may be opaque. Its
                # bytes remain private and hash-bound, never copied to JSON.
                run.require(not row["header"], "feature_capture_unexpected_output")
        run.require(row["header"] and row["outer"] is not None, "feature_capture_incomplete")
        row["status"] = "complete"
        return row
    except InvalidEvidence as error:
        raise InvalidEvidence(str(error), partial=row) from error


def command_spec():
    return {"id": "feature_pure", "argv": list(ARGV), "timeout_seconds": TIMEOUT,
            "environment_delta": {}, "status": "not_run"}


def command_passed(command):
    return (type(command.get("exit_code")) is int and command["exit_code"] == 0
        and command.get("termination") is None and command.get("cleanup_complete") is True
        and type(command.get("reaped_descendants")) is int and command["reaped_descendants"] == 0)


def observe(command, data, inventory):
    passed = command_passed(command)
    command["status"] = "passed" if passed else "failed"
    try:
        command["observation"] = parse_capture(data, inventory)
        command["evidence_status"] = "complete"
    except InvalidEvidence as error:
        command["observation"] = error.partial
        command["evidence_status"] = "incomplete"
        command["parse_error"] = str(error)
        if passed:
            command["status"] = "invalid_evidence"


def public_environment():
    return run.ENV | {"CARGO_TARGET_DIR": "target", "TMPDIR": "private_run/tmp",
                       "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "RLIMIT_CORE": 0}


def affinity(cpus):
    run.require(isinstance(cpus, (set, frozenset)) and 1 <= len(cpus) <= 8
        and all(type(cpu) is int and cpu >= 0 for cpu in cpus), "feature_affinity_bound")
    return frozenset(cpus)


def qualify(record):
    command = record["commands"][0] if len(record["commands"]) == 1 else {}
    spec = command_spec()
    observation = command.get("observation") or {}
    complete = (all(record.get(key) is True for key in STABILITY)
        and record.get("first_failure") is None and record.get("secondary_failures") == []
        and natural(record.get("affinity_cpu_count"), 8) and record["affinity_cpu_count"] > 0
        and same_json(record.get("environment"), public_environment())
        and type(record.get("log_limit_bytes_per_command")) is int and record["log_limit_bytes_per_command"] == LOG_LIMIT
        and type(record.get("cleanup_seconds")) is int and record["cleanup_seconds"] == 3
        and record.get("cleanup_scope") == "outer_supervisor"
        and natural(record.get("pure_methods"), 4096) and record["pure_methods"] > 0
        and type(record.get("native_methods")) is int and record["native_methods"] == 0
        and natural(record.get("filtered_out"), 65536) and digest(record.get("method_inventory_sha256"))
        and all(command.get(key) == value for key, value in spec.items() if key != "status")
        and command.get("status") == "passed" and command_passed(command)
        and command.get("evidence_status") == "complete"
        and observation.get("status") == "complete" and observation.get("harness") == HARNESS
        and observation.get("expected_tests") == record["pure_methods"]
        and observation.get("expected_filtered") == record["filtered_out"]
        and "parse_error" not in command)
    record["qualified"] = bool(complete)
    record["status"] = "passed" if complete else "failed"


def prerequisite_metadata(record, *, source, configuration, hardware, toolchain, corpus_digest, inventory, inventory_digest):
    # Closed public metadata: adding an unreviewed field cannot strengthen the
    # qualification or leak a captured path/diagnostic into an accepted row.
    fields(record, {"schema_version", "experiment", "run_id", "qualification_protocol",
        "claim_scope", "performance_claim", "qualified", "status", "source", "configuration",
        "hardware", "toolchain", "runner_sha256", "corpus_sha256", "method_inventory_sha256",
        "pure_methods", "native_methods", "filtered_out", "affinity_cpu_count", "environment",
        "inherited_location_variables", "log_limit_bytes_per_command", "cleanup_seconds",
        "cleanup_scope", "reproduce", "commands", "first_failure", "secondary_failures", *STABILITY},
        "feature_receipt_fields")
    run.require(type(record["schema_version"]) is int and record["schema_version"] == 1
        and record["experiment"] == "runtime-stack-feature-controls" and record["qualified"] is True
        and record["status"] == "passed" and record["qualification_protocol"] is False
        and record["claim_scope"] == "source_reviewed_feature_pure_controls"
        and record["performance_claim"] is None, "feature_receipt_scope")
    run.require(same_json(record["source"], source) and source.get("tracked_clean") is True
        and source.get("head_sources_match") is True and all(record[key] is True for key in STABILITY),
        "feature_receipt_source")
    identity = record["run_id"]
    run.require(type(identity) is str and RUN_ID.fullmatch(identity)
        and identity.endswith(source["revision"][:12]), "feature_receipt_identity")
    run.require(record["reproduce"] == ["python3", RUNNER, "--expect-revision", source["revision"]],
        "feature_receipt_reproduce")
    run.require(same_json(record["configuration"], configuration) and same_json(record["hardware"], hardware)
        and same_json(record["toolchain"], toolchain) and same_json(record["environment"], public_environment())
        and record["inherited_location_variables"] == list(run.LOCATION_VARIABLES)
        and natural(record["affinity_cpu_count"], 8) and record["affinity_cpu_count"] > 0
        and record["affinity_cpu_count"] == hardware.get("affinity_cpu_count"), "feature_receipt_environment")
    run.require(record["runner_sha256"] == source["source_sha256"].get(RUNNER)
        and digest(record["runner_sha256"]) and record["corpus_sha256"] == corpus_digest
        and corpus_digest == source["source_sha256"].get("evaluation/admission/corpus.json")
        and record["method_inventory_sha256"] == inventory_digest, "feature_receipt_bindings")
    run.require(type(record["pure_methods"]) is int and record["pure_methods"] == len(inventory["methods"])
        and type(record["native_methods"]) is int and record["native_methods"] == 0
        and type(record["filtered_out"]) is int and record["filtered_out"] == inventory["filtered_out"],
        "feature_receipt_inventory")
    run.require(type(record["log_limit_bytes_per_command"]) is int
        and record["log_limit_bytes_per_command"] == LOG_LIMIT and type(record["cleanup_seconds"]) is int
        and record["cleanup_seconds"] == 3 and record["cleanup_scope"] == "outer_supervisor"
        and record["first_failure"] is None and record["secondary_failures"] == [], "feature_receipt_bounds")
    run.require(type(record["commands"]) is list and len(record["commands"]) == 1, "feature_receipt_commands")
    command = record["commands"][0]
    fields(command, {*command_spec(), "start_utc", "exit_code", "termination", "seconds",
        "private_log_sha256", "cleanup_complete", "reaped_descendants", "child_discovery_strategy",
        "evidence_status", "observation"}, "feature_receipt_command_fields")
    run.require(all(command[key] == value for key, value in command_spec().items() if key != "status")
        and type(command["timeout_seconds"]) is int and command["status"] == "passed"
        and command_passed(command) and digest(command["private_log_sha256"])
        and command["evidence_status"] == "complete", "feature_receipt_command")
    run.require(type(command["seconds"]) in (int, float) and math.isfinite(command["seconds"])
        and command["seconds"] >= 0 and type(command["start_utc"]) is str
        and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00", command["start_utc"])
        and command["child_discovery_strategy"] in ("proc_children", "pidfd_authenticated_proc_candidates"),
        "feature_receipt_process")


def authenticate_prerequisite(record, *, source, configuration, hardware, toolchain, corpus, corpus_digest):
    corpus_data = bounded_read(ROOT / "evaluation/admission/corpus.json", INVENTORY_LIMIT)
    run.require(run.sha(corpus_data) == corpus_digest
        and corpus_digest == source["source_sha256"].get("evaluation/admission/corpus.json")
        and same_json(strict_json(corpus_data), corpus), "feature_receipt_corpus_bytes")
    inventory, inventory_digest = load_inventory(source, corpus)
    prerequisite_metadata(record, source=source, configuration=configuration, hardware=hardware,
        toolchain=toolchain, corpus_digest=corpus_digest, inventory=inventory, inventory_digest=inventory_digest)
    command = record["commands"][0]
    data = bounded_read(ROOT / "target/evaluation/admission" / record["run_id"] / "feature_pure.log", LOG_LIMIT)
    run.require(run.sha(data) == command["private_log_sha256"], "feature_receipt_capture_hash")
    fresh = command_spec() | {key: command[key] for key in ("exit_code", "termination",
        "cleanup_complete", "reaped_descendants")}
    observe(fresh, data, inventory)
    run.require(all(same_json(command.get(key), fresh[key]) for key in ("status", "evidence_status", "observation"))
        and fresh["status"] == "passed", "feature_receipt_replay")
    return {"qualified": True, "revision": source["revision"],
        "private_log_sha256": command["private_log_sha256"], "method_inventory_sha256": inventory_digest,
        "pure_methods": len(inventory["methods"]), "native_methods": 0, "policy": POLICY}


def remember(record, stage, error):
    failure = {"stage": stage, "code": str(error) if isinstance(error, InvalidEvidence) else
        "interrupted" if isinstance(error, KeyboardInterrupt) else "feature_recorder_exception"}
    if record["first_failure"] is None:
        record["first_failure"] = failure
    else:
        record["secondary_failures"].append(failure)


def audit_current(record, env, cpus, revision):
    record["affinity_unchanged"] = cpus == affinity(os.sched_getaffinity(0))
    record["source_unchanged"] = record["source"] == run.source_state()
    record["configuration_unchanged"] = record["configuration"] == run.cargo_configuration(env)
    record["toolchain_unchanged"] = record["toolchain"] == inspect_toolchain(env)
    record["hardware_unchanged"] = record["hardware"] == run.hardware()
    run.require(all(record[key] for key in STABILITY), "feature_environment_changed")
    run.preflight(record["source"], revision,
        run.git("ls-files", "--others", "--exclude-standard").decode().splitlines())


def execute(record, env, private, inventory, publish, stable):
    command = record["commands"][0]
    stable()
    command["status"] = "running"
    publish()
    log = private / "feature_pure.log"
    command.update(run_command(command["argv"], env, log, TIMEOUT, LOG_LIMIT))
    # Retain actual termination/cleanup before any fallible capture read or
    # post-command guard. A later failure must not replace this first outcome.
    command["status"] = "passed" if command_passed(command) else "failed"
    if command["status"] != "passed":
        remember(record, "command", InvalidEvidence("feature_command_failed"))
    publish()
    try:
        data = bounded_read(log, LOG_LIMIT)
        run.require(run.sha(data) == command["private_log_sha256"], "feature_capture_changed")
        observe(command, data, inventory)
        if command["status"] != "passed" and record["first_failure"] is None:
            remember(record, "capture", InvalidEvidence("feature_capture_unqualified"))
    except (Exception, KeyboardInterrupt) as error:
        command["evidence_status"] = "incomplete"
        remember(record, "capture", error)
    publish()
    try:
        stable()
    except (Exception, KeyboardInterrupt) as error:
        remember(record, "postflight", error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-revision", required=True)
    args = parser.parse_args()
    run.require(re.fullmatch(r"[0-9a-f]{40}", args.expect_revision), "feature_expected_revision")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    identity = stamp + "-runtime-stack-feature-" + args.expect_revision[:12]
    private = ROOT / "target/evaluation/admission" / identity
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = private / "tmp"
    temporary.mkdir(mode=0o700)
    public = HERE / "results" / (identity + ".json")
    public.parent.mkdir(parents=True, exist_ok=True)
    run.require(not public.exists(), "feature_duplicate_run")
    record = {"schema_version": 1, "experiment": "runtime-stack-feature-controls", "run_id": identity,
        "qualification_protocol": False, "claim_scope": "source_reviewed_feature_pure_controls",
        "performance_claim": None, "qualified": False, "status": "preflight",
        "source": None, "configuration": None, "hardware": None, "toolchain": None,
        "runner_sha256": run.sha(Path(__file__).read_bytes()), "corpus_sha256": None,
        "method_inventory_sha256": None, "pure_methods": None, "native_methods": None,
        "filtered_out": None, "affinity_cpu_count": None, "environment": public_environment(),
        "inherited_location_variables": list(run.LOCATION_VARIABLES),
        "log_limit_bytes_per_command": LOG_LIMIT, "cleanup_seconds": 3, "cleanup_scope": "outer_supervisor",
        "reproduce": ["python3", RUNNER, "--expect-revision", args.expect_revision],
        "commands": [command_spec()], "first_failure": None, "secondary_failures": [],
        **{key: False for key in STABILITY}}
    run.write_result(public, record)
    print(public.relative_to(ROOT), flush=True)
    phase = "preflight"
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        env = run.controlled_environment(os.environ, temporary)
        run.require(sys.platform == "linux" and os.uname().machine == "x86_64", "feature_platform")
        cpus = affinity(os.sched_getaffinity(0))
        record["affinity_cpu_count"] = len(cpus)
        record["source"] = run.source_state()
        run.preflight(record["source"], args.expect_revision,
            run.git("ls-files", "--others", "--exclude-standard").decode().splitlines())
        corpus_data = bounded_read(HERE / "corpus.json", INVENTORY_LIMIT)
        record["corpus_sha256"] = run.sha(corpus_data)
        run.require(record["corpus_sha256"] == record["source"]["source_sha256"].get("evaluation/admission/corpus.json"),
            "feature_corpus_source")
        corpus = strict_json(corpus_data)
        inventory, record["method_inventory_sha256"] = load_inventory(record["source"], corpus)
        record.update(pure_methods=len(inventory["methods"]), native_methods=0, filtered_out=inventory["filtered_out"])
        record["configuration"] = run.cargo_configuration(env)
        record["hardware"] = run.hardware()
        run.require(record["hardware"]["affinity_cpu_count"] == len(cpus), "feature_hardware_affinity")
        record["toolchain"] = inspect_toolchain(env)
        phase, record["status"] = "execution", "running"
        execute(record, env, private, inventory, lambda: run.write_result(public, record),
            lambda: audit_current(record, env, cpus, args.expect_revision))
        qualify(record)
    except (Exception, KeyboardInterrupt) as error:
        remember(record, phase, error)
        record["qualified"] = False
        record["status"] = "refused" if phase == "preflight" else "failed"
    finally:
        run.write_result(public, record)
    return 0 if record["qualified"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except InvalidEvidence as error:
        print("feature controls refused: " + str(error), file=sys.stderr)
        sys.exit(2)
