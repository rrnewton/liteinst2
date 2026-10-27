"""Closed finite owned-stack consumer records; descriptive checks, never authority."""

import re

import runtime_consumer_schema as legacy
from parsing import InvalidEvidence
from run import require

LIMITS, METRICS, FLAGS, COUNTS = legacy.LIMITS, legacy.METRICS, legacy.FLAGS, legacy.COUNTS
MAX_ARTIFACT, MAX_SUMMARY, MAX_CAPTURE = legacy.MAX_ARTIFACT, legacy.MAX_SUMMARY, legacy.MAX_CAPTURE
strict_json, natural = legacy.strict_json, legacy.natural
HEX = re.compile(r"[0-9a-f]{64}")
PUBLIC_FIELDS = legacy.FIELDS | {"role", "stack_history_scope", "terminal_argument"}
PUBLIC_ERRORS = legacy.ERRORS | {"initial_stack_alignment", "selected_stack_restoration",
                               "terminal_argument_and_stack"}
PUBLIC_PROTOCOL = {"protocol": "liteinst-runtime-stack-consumer", "version": 1,
                   "role": "public_consumer"}
ORACLE_PROTOCOL = {"protocol": "liteinst-runtime-stack-consumer-oracle", "version": 1,
                   "role": "oracle"}
ORACLE_ERRORS = frozenset("""arguments artifact plan allocation raw_launch raw_execution
raw_cleanup admitted_launch admitted_execution admitted_cleanup comparison output caught_panic""".split())
BASE_FIELDS = {"schema_version", "experiment", "role", "status", "error", "artifact_sha256",
               "artifact_bytes", "plan_sha256", "path"}
INSPECT_CHECKS = {"elf", "closed_path", "dataflow", "artifact_unchanged"}
LANE_CHECKS = {"identity", "artifact", "own_state", "whole_source", "whole_stack",
               "helper_dataflow", "stack_access", "syscall_architecture", "terminal"}
ADMITTED_CHECKS = LANE_CHECKS | {"call_before_opening", "call_retained", "stack_census",
                               "final_current", "history_after_cleanup"}
CLEANUP_CHECKS = {"receipt", "application_hup", "application_echild", "broker_hup",
                "broker_echild", "mask_restored", "retained_prefix"}
COMPARISON_CHECKS = {"artifact_plan", "own_lane_equations", "structural", "helper_dataflow", "terminal"}
COMMON_COUNTS = {"instructions": 35, "ordinary": 30, "calls": 1, "returns": 1,
                 "syscall_entries": 3, "syscall_returns": 2, "terminal_syscall": 2**64 - 1,
                 "terminal_argument": 2**64 - 1, "terminal_code": 255}
RAW_COUNTS = COMMON_COUNTS | {"raw_waits": 42, "requests": 64, "frames": 69,
    "separate_phase_states": 6, "namespace_records": 5, "state_read_groups": 76}
ADMITTED_COUNTS = COMMON_COUNTS | {"frames": 69, "own_lane_state_read_groups": 70,
    "stack_commits": 2, "stack_raw_waits": 14, "stack_private_calls": 12,
    "stack_original_steps": 2, "stack_word_captures": 8, "stack_census_checks": 2,
    "call_rows": 1, "kernel_attempts": 3, "kernel_raw_waits": 27,
    "kernel_state_copies": 24, "kernel_failures": 3}
ACCOUNT_NUMBERS = {"reservation_bytes", "allocated_bytes", "charged_before", "charged_after",
                   "retained_before", "retained_after"}
ACCOUNT_CHECKS = {"settled", "finished", "formula_checked"}


def validate_public(value, complete=False):
    require(type(value) is dict and set(value) == PUBLIC_FIELDS, "consumer_summary_fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["experiment"] == "runtime-stack-consumer", "consumer_summary_identity")
    require(value["status"] in ("passed", "failed")
            and (value["error"] is None if value["status"] == "passed"
                 else type(value["error"]) is str and value["error"] in PUBLIC_ERRORS),
            "consumer_summary_status")
    require(all(type(value[key]) is bool for key in FLAGS), "consumer_summary_flag")
    require(all(natural(value[key], {"provider_calls": 3, "full_state_checks": 2,
                "journal_attempts": 3, "journal_raw_waits": 27,
                "journal_state_copies": 24, "journal_failures": 3}[key]) for key in COUNTS),
            "consumer_summary_count")
    require(type(value["returned_syscalls"]) is list
            and all(type(n) is int for n in value["returned_syscalls"])
            and value["returned_syscalls"] in ([], [39], [39, 186])
            and value["full_state_checks"] == len(value["returned_syscalls"]),
            "consumer_return_order")
    require((value["terminal_syscall"] is None and value["terminal_code"] is None)
            or (type(value["terminal_syscall"]) is int and value["terminal_syscall"] == 231
                and type(value["terminal_code"]) is int and value["terminal_code"] == 7
                and value["returned_syscalls"] == [39, 186]), "consumer_terminal_kind")
    require(type(value["limits"]) is dict and value["limits"] == LIMITS
            and all(type(n) is int for n in value["limits"].values())
            and type(value["invocation_seconds"]) is int and value["invocation_seconds"] == 3
            and type(value["cleanup_seconds"]) is int and value["cleanup_seconds"] == 3,
            "consumer_limits_changed")
    attempts = value["journal_attempts"]
    facts = value["journal_fact_counts"]
    require(type(facts) is list and len(facts) == attempts
            and all(natural(n, 32) for n in facts)
            and value["journal_raw_waits"] <= attempts * 9
            and value["journal_state_copies"] <= attempts * 8
            and value["journal_failures"] <= attempts, "consumer_archive_shape")
    metrics = value["observed_metrics"]
    require(type(metrics) is list and len(metrics) <= 3, "consumer_metrics_shape")
    previous = None
    for row in metrics:
        require(type(row) is dict and set(row) == METRICS
                and all(natural(n, 2**63 - 1) for n in row.values())
                and row["retained_source_bytes"] <= row["charged_source_bytes"] <= LIMITS["source_fact_bytes"]
                and row["retained_origins"] <= LIMITS["origins"]
                and row["generation_changes"] == 0, "consumer_metrics_bounds")
        if previous is not None:
            require(all(row[key] >= previous[key] for key in METRICS), "consumer_metrics_refund")
        previous = row
    if complete or value["status"] == "passed":
        require(value["status"] == "passed" and value["provider_calls"] == 3
                and value["returned_syscalls"] == [39, 186] and value["terminal_syscall"] == 231
                and value["terminal_code"] == 7 and value["full_state_checks"] == 2
                and attempts == 3 and value["journal_raw_waits"] == 24
                and value["journal_state_copies"] == 15 and facts == [25, 25, 20]
                and value["journal_failures"] == 0 and len(metrics) == 3
                and all(value[key] for key in FLAGS), "consumer_incomplete_success")
    require(value["role"] == "public_consumer"
            and value["stack_history_scope"] == "not_publicly_observed",
            "stack_public_scope")
    require(value["terminal_argument"] is None
            or natural(value["terminal_argument"], 2**64 - 1), "stack_public_terminal_argument")
    if complete or value["status"] == "passed":
        require(value["terminal_argument"] == 7 and type(value["terminal_argument"]) is int,
                "stack_public_terminal_argument")
    return value


def fields(value, expected, code):
    require(type(value) is dict and set(value) == expected, code)


def hash_value(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def outcomes(value, names, complete):
    fields(value, names, "stack_outcome_fields")
    require(all(item is None or type(item) is bool for item in value.values()),
            "stack_outcome_type")
    if complete:
        require(all(item is True for item in value.values()), "stack_outcome_failed_or_missing")


def oracle_base(value, role, extra, complete):
    fields(value, BASE_FIELDS | extra, "stack_oracle_fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["experiment"] == "runtime-stack-consumer" and value["role"] == role,
            "stack_oracle_identity")
    require(value["status"] in ("passed", "failed")
            and (value["error"] is None if value["status"] == "passed"
                 else type(value["error"]) is str and value["error"] in ORACLE_ERRORS),
            "stack_oracle_status")
    require(not complete or value["status"] == "passed", "stack_oracle_failed_command")
    success = complete or value["status"] == "passed"
    for key in ("artifact_sha256", "plan_sha256"):
        require(hash_value(value[key]) or (not success and value[key] is None),
                "stack_oracle_digest")
    require((natural(value["artifact_bytes"], MAX_ARTIFACT) and value["artifact_bytes"] > 0)
            or (not success and value["artifact_bytes"] is None), "stack_oracle_artifact_size")
    path = value["path"]
    if path is None:
        require(not success, "stack_plan_missing")
    else:
        fields(path, {"instructions", "ordinary", "calls", "returns", "syscalls"}, "stack_path_fields")
        require(natural(path["ordinary"], 30) and type(path["calls"]) is int and path["calls"] == 1
                and type(path["returns"]) is int and path["returns"] == 1
                and type(path["syscalls"]) is list and path["syscalls"] == [39, 186, 231]
                and all(type(n) is int for n in path["syscalls"])
                and natural(path["instructions"], 35)
                and path["instructions"] == path["ordinary"] + 5, "stack_path_contract")
    return success


def validate_inspect(value, complete=False):
    success = oracle_base(value, "artifact_plan", {"checks"}, complete)
    outcomes(value["checks"], INSPECT_CHECKS, success)
    return value


def observations(value, bounds):
    fields(value, set(bounds), "stack_observation_fields")
    require(all(n is None or natural(n, bounds[key]) for key, n in value.items()),
            "stack_observation_type_or_bound")


def common_success(path):
    return {"instructions": path["instructions"], "ordinary": path["ordinary"],
            "calls": 1, "returns": 1, "syscall_entries": 3, "syscall_returns": 2,
            "terminal_syscall": 231, "terminal_argument": 7, "terminal_code": 7}


def validate_lane(value, path, kind, complete):
    if value is None:
        require(not complete, "stack_lane_missing")
        return
    fields(value, {"error", "observations", "checks", "cleanup"}, "stack_lane_fields")
    require(value["error"] is None or (type(value["error"]) is str
            and value["error"] in ORACLE_ERRORS), "stack_lane_error")
    require(not complete or value["error"] is None, "stack_lane_failed")
    counts = value["observations"]
    if kind == "raw":
        observations(counts, RAW_COUNTS)
        names = LANE_CHECKS
    else:
        fields(counts, set(ADMITTED_COUNTS) | {"kernel_fact_counts"}, "stack_observation_fields")
        observations({key: counts[key] for key in ADMITTED_COUNTS}, ADMITTED_COUNTS)
        facts = counts["kernel_fact_counts"]
        require(facts is None or (type(facts) is list and len(facts) <= 3
                and all(natural(n, 32) for n in facts)), "stack_kernel_fact_prefix")
        if facts is not None and counts["kernel_attempts"] is not None:
            require(len(facts) == counts["kernel_attempts"], "stack_kernel_attempt_facts")
        names = ADMITTED_CHECKS
    outcomes(value["checks"], names, complete)
    outcomes(value["cleanup"], CLEANUP_CHECKS, complete)
    if complete:
        n = path["instructions"]
        expected = common_success(path)
        if kind == "raw":
            expected |= {"raw_waits": n + 5, "requests": n + 11, "frames": 2 * n - 1,
                         "separate_phase_states": 6, "namespace_records": 5,
                         "state_read_groups": 2 * n + 6}
        else:
            # This is the own-lane diagnostic inventory, not production kernel
            # state reads or copies. The root producer must bind this schedule.
            expected |= {"frames": 2 * n - 1, "own_lane_state_read_groups": 2 * n,
                "stack_commits": 2, "stack_raw_waits": 14, "stack_private_calls": 12,
                "stack_original_steps": 2, "stack_word_captures": 8, "stack_census_checks": 2,
                "call_rows": 1, "kernel_attempts": 3, "kernel_raw_waits": 24,
                "kernel_state_copies": 15, "kernel_fact_counts": [25, 25, 20], "kernel_failures": 0}
        require(counts == expected, "stack_lane_schedule")


def validate_accounting(value, complete):
    if value is None:
        require(not complete, "stack_accounting_missing")
        return
    fields(value, ACCOUNT_NUMBERS | ACCOUNT_CHECKS, "stack_accounting_fields")
    require(all(value[key] is None or natural(value[key],
                2**64 - 1 if key in ("reservation_bytes", "allocated_bytes")
                else LIMITS["source_fact_bytes"]) for key in ACCOUNT_NUMBERS), "stack_accounting_bounds")
    outcomes({key: value[key] for key in ACCOUNT_CHECKS}, ACCOUNT_CHECKS, complete)
    if complete:
        require(all(value[key] is not None for key in ACCOUNT_NUMBERS), "stack_accounting_prefix")
        require(value["allocated_bytes"] <= value["reservation_bytes"]
                and value["charged_after"] - value["charged_before"] == value["reservation_bytes"]
                and value["retained_after"] - value["retained_before"] == value["allocated_bytes"]
                and value["retained_before"] <= value["charged_before"]
                and value["retained_after"] <= value["charged_after"], "stack_accounting_equation")
    else:
        # Finish may genuinely succeed after a failed measurement. Preserve
        # that outcome and null measurement, never invent an allocated count.
        for lower, upper in (("charged_before", "charged_after"),
                             ("retained_before", "retained_after"),
                             ("retained_before", "charged_before"),
                             ("retained_after", "charged_after")):
            if value[lower] is not None and value[upper] is not None:
                require(value[lower] <= value[upper], "stack_accounting_prefix_order")
        if value["settled"] is True:
            if value["allocated_bytes"] is not None and value["reservation_bytes"] is not None:
                require(value["allocated_bytes"] <= value["reservation_bytes"],
                        "stack_accounting_prefix_settlement")
            if all(value[key] is not None for key in
                   ("retained_before", "retained_after", "allocated_bytes")):
                require(value["retained_after"] - value["retained_before"] == value["allocated_bytes"],
                        "stack_accounting_prefix_settlement")
        if value["finished"] is True and all(value[key] is not None for key in
                ("charged_before", "charged_after", "reservation_bytes")):
            require(value["charged_after"] - value["charged_before"] == value["reservation_bytes"],
                    "stack_accounting_prefix_reservation")


def validate_oracle(value, complete=False):
    success = oracle_base(value, "oracle", {"raw", "admitted", "comparison", "accounting",
        "limits", "invocation_seconds", "cleanup_seconds", "cleanup_scope"}, complete)
    require(type(value["limits"]) is dict and value["limits"] == LIMITS
            and all(type(n) is int for n in value["limits"].values())
            and type(value["invocation_seconds"]) is int and value["invocation_seconds"] == 3
            and type(value["cleanup_seconds"]) is int and value["cleanup_seconds"] == 3
            and value["cleanup_scope"] == "outer_supervisor", "stack_limits_changed")
    validate_lane(value["raw"], value["path"], "raw", success)
    validate_lane(value["admitted"], value["path"], "admitted", success)
    if value["comparison"] is None:
        require(not success, "stack_comparison_missing")
    else:
        outcomes(value["comparison"], COMPARISON_CHECKS, success)
    validate_accounting(value["accounting"], success)
    return value


def parse_row(data, command_succeeded, role):
    require(type(command_succeeded) is bool and type(data) is bytes
            and len(data) <= (MAX_SUMMARY if command_succeeded else MAX_CAPTURE), "stack_row_size")
    lines = data.splitlines()
    candidates = [line for line in lines if line.startswith(b'{"schema_version":')]
    require(len(candidates) == 1 and len(candidates[0]) <= MAX_SUMMARY, "stack_row_missing_or_duplicate")
    require(not command_succeeded or lines == candidates, "stack_unclassified_output")
    validators = {"public_consumer": validate_public, "artifact_plan": validate_inspect, "oracle": validate_oracle}
    require(role in validators, "stack_unknown_row_role")
    value = validators[role](strict_json(candidates[0]), command_succeeded)
    return {"summary": value, "command_succeeded": command_succeeded, "qualified_run": False}


def parse_protocol(data, role):
    require(type(data) is bytes and len(data) <= 1024, "stack_protocol_size")
    require(role in ("public_consumer", "oracle"), "stack_protocol_role")
    value = strict_json(data)
    expected = PUBLIC_PROTOCOL if role == "public_consumer" else ORACLE_PROTOCOL
    require(type(value) is dict and value == expected and type(value["version"]) is int,
            "stack_protocol_differs")
    return value


def compact_elf(data):
    """Private addresses validate geometry; none are copied to this public row."""
    full = legacy.elf_metadata(data)
    loads = [row for row in full["program_headers"] if row["type"] == 1]
    require(len(loads) == 2, "stack_elf_two_loads")
    low, high = loads
    require(low["flags"] == 4 and high["flags"] == 5 and low["offset"] == 0
            and high["offset"] == 4096 and low["vaddr"] % 4096 == 0
            and high["vaddr"] == low["vaddr"] + 4096
            and low["align"] == high["align"] == 4096
            and 0 < low["filesz"] == low["memsz"] <= 4096
            and 0 < high["filesz"] == high["memsz"] <= 4096, "stack_elf_page_geometry")
    return {"sha256": full["sha256"], "bytes": full["bytes"], "static_native64": True,
            "load_segments": 2, "initialized_text_bytes": high["filesz"],
            "executable_bytes_sha256": full["executable_bytes_sha256"],
            "head_completeness": False}
