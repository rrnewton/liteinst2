"""Synthetic public-protocol inputs; no native or measurement qualification."""

import copy
import json

import run
from hook_cost_proof import PUBLIC_ENV
from hook_cost_schema import (CLASSES, DYNAMIC_FIELDS, PHASE_FIELDS, PREFIX, SELECTED_FIELDS,
                             TOTALS, load_inventory)


def snapshot(specs, count, lane):
    counts = [0] * 7
    for row in specs[:count]:
        counts[CLASSES.index(row["class"])] += 1
    value = {"pages": {"startup_ns": 12, "admitted_pages": 1, "untouched_pages": 1,
                      "observations": count, "covered_candidates": 4, "collateral_guards": 0,
                      "collateral_completions": 0, "first_touch_ns": [10]},
             "selected": dict.fromkeys(SELECTED_FIELDS, 0),
             "oracle": {phase: dict.fromkeys(PHASE_FIELDS, 0) for phase in ("preparation", "demand")},
             "dynamic": None}
    value["selected"].update(callbacks=counts, scripted_completions=count)
    for phase in value["oracle"].values():
        phase["saturated"] = False
    if lane == "dynamic_page":
        value["dynamic"] = dict.fromkeys(DYNAMIC_FIELDS, 0)
        value["dynamic"]["oldest_call_generation"] = None
    return value


def wire_records():
    catalog = load_inventory()
    fixtures = {f["fixture"]: f for f in catalog["fixtures"]}
    records = [{"schema_version": 1, "kind": "calibration", "clock": "std_instant",
                "monotonic_resolution_ns": 1, "subtracted": False, "samples_ns": [20] * 1000}]
    for pair in catalog["pairs"]:
        fixture = fixtures[pair["fixture"]]
        for order, lane in enumerate(pair["lanes"]):
            identity = {k: pair[k] for k in ("fixture", "phase", "pair_index", "round")}
            identity.update(order_index=order, lane=lane)
            records.append(identity | {"schema_version": 1, "kind": "session", "covered": fixture["covered"],
                "raw_reference_completed": True, "callbacks": len(fixture["rows"]),
                "collateral_completions": fixture["collateral_completions"], "launch_total_ns": 100,
                "validation_ns": 50, "cleanup_ns": 20, "completed": True, "cleanup": True})
            for spec in fixture["rows"]:
                n = spec["ordinal"]
                records.append(identity | spec | {"schema_version": 1, "kind": "completion", "completion_ns": 12,
                    "before_provider_ns": 3, "checked_provider_ns": 4, "after_provider_ns": 5, "validation_ns": 5,
                    "metrics_before": snapshot(fixture["rows"], n, lane),
                    "metrics_after": snapshot(fixture["rows"], n + 1, lane), "completed": 1, "cleanup": True})
    records.append(TOTALS | {"schema_version": 1, "kind": "run_complete", "cleanup": True})
    return catalog, records


def wire(records):
    return "".join(PREFIX + json.dumps(row, separators=(",", ":")) + "\n" for row in records)


def partial_failure(identity, rows):
    return identity | {"schema_version": 1, "kind": "failure", "stage": "completion", "ordinal": len(rows),
        "completion_ns": None, "before_provider_ns": None, "checked_provider_ns": None, "after_provider_ns": None,
        "partial_session": {"covered": False, "launch_total_ns": 100, "validation_ns": 10, "cleanup_ns": 20},
        "partial_rows": rows, "cleanup": True, "emitted_sessions": 0, "emitted_completions": 0, "qualified": False}


def correctness_input():
    """Small synthetic corpus exercises every contract branch, no real source claim."""
    source = {"revision": "a" * 40, "source_sha256": {"evaluation/admission/run.py": "1" * 64},
              "source_manifest_sha256": "2" * 64}
    corpus = {"recorder_tests": 2, "harness_test_counts": {
        "workspace_tests": {"one": {"tests": 5, "ignored": 4}},
        "serial_launch": {"one": {"tests": 1, "ignored": 0}}},
        "native_cases": [{"test": "raw"}], "dynamic_admission_fixtures": ["dynamic"],
        "dynamic_matrix_cases": [{"case_id": "matrix"}], "native_validation_fixtures": [{"test": "named"}]}
    hardware = {"affinity_cpu_count": 2, "effective_uid_is_root": False, "effective_capabilities": 0}
    tools = {"cargo": {"version": "cargo 1.85", "launcher_sha256": "3" * 64, "executable_sha256": "4" * 64},
             "rustc": {"version": "rustc 1.85", "launcher_sha256": "3" * 64, "executable_sha256": "5" * 64},
             "git": {"argv0": "/usr/bin/git", "version": "git version 2.0", "executable_sha256": "6" * 64},
             "python": {"version": "3.11.0", "executable_sha256": "7" * 64, "launcher_sha256": "7" * 64}}
    previous_tools = copy.deepcopy(tools)
    for name in ("cargo", "rustc"):
        del previous_tools[name]["executable_sha256"]
    record = {"schema_version": 1, "experiment": "admission-validation", "status": "passed",
        "source_unchanged": True, "configuration_unchanged": True,
        "source": source | {"tracked_clean": True, "head_sources_match": True},
        "corpus_sha256": "8" * 64, "runner_sha256": "1" * 64, "configuration": [],
        "hardware": hardware | {"affinity_cpu_count": 16}, "toolchain": previous_tools,
        "environment": PUBLIC_ENV, "inherited_location_variables": list(run.LOCATION_VARIABLES),
        "log_limit_bytes_per_command": 8 * 1024 * 1024, "commands": []}
    for name, argv, deadline in run.COMMANDS:
        command = {"id": name, "argv": argv[:], "timeout_seconds": deadline, "status": "passed", "exit_code": 0,
                   "termination": None, "cleanup_complete": True, "reaped_descendants": 0, "private_log_sha256": "9" * 64,
                   "environment_delta": {"LITEINST_EVALUATION": "1"} if name == "serial_launch" else {}}
        if name == "recorder_tests":
            command.update(tests_passed=2, recorder_observations={"tests_run": 2, "exact_ok_terminal": True})
        if name in corpus["harness_test_counts"]:
            spec = corpus["harness_test_counts"][name]["one"]
            command.update(evidence_status="complete", harnesses=[{"id": "one", "status": "complete",
                "declared_outer_tests": spec["tests"], "expected_tests": spec["tests"], "expected_ignored": spec["ignored"],
                "outer": {"result": "ok", "passed": spec["tests"] - spec["ignored"], "failed": 0,
                          "ignored": spec["ignored"], "measured": 0, "filtered": 0}, "unclassified_summaries": []}])
        record["commands"].append(command)
    for field, key, value in (("native_cases", "test", "raw"), ("dynamic_admission_fixtures", "test", "dynamic"),
                              ("dynamic_matrix_cases", "case_id", "matrix"), ("native_validation_fixtures", "test", "named")):
        record["commands"][-1][field] = [{key: value, "qualified_run": True, "command_succeeded": True,
                                         "status": "complete", "test_result": "ok"}]
    return record, source, corpus, "8" * 64, [], hardware, tools
