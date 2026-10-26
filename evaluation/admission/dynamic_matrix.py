"""Exact dynamic invocation receipts, separate from named tests and static samples.

The inventory is a source declaration, not an observation. Only validated rows
are retained as observations, and no row qualifies without the containing test,
the independent harness parser, command cleanup and the unchanged full run.
"""

import copy
import json
import re

from dynamic_admission import FIXTURE_NAME, HARNESS
from parsing import InvalidEvidence, harness_id, require


PREFIX = "LITEINST_EVALUATION_DYNAMIC_MATRIX "
FIELDS = {"schema_version", "case_id", "class", "width", "destination",
          "input_flags", "path", "actual_cf", "completed", "cleanup"}
DECLARED_FIELDS = {"case_id", "outer_test", "class", "width", "destination", "path",
                   "input_flags_expected", "input_flags_source", "actual_cf_allowed",
                   "completed", "cleanup"}
CLASSES = {"cpuid", "rdtsc", "rdtscp", "rdrand", "rdseed", "rdpid"}
RANDOM = {"rdrand", "rdseed"}
CASE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,159}")
UINT64_MAX = (1 << 64) - 1


def uint(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def flags(value):
    # The live selected-entry contract excludes TF/RF; bit1 is architectural.
    return uint(value, UINT64_MAX) and value & 2 != 0 and value & 0x10100 == 0


def inventory(cases, fixtures):
    """Validate the complete declared finite cohort without inventing samples.

    An explicitly empty inventory describes no matrix for legacy/synthetic
    cohorts. It accepts no matrix telemetry. The tracked real corpus separately
    pins every one of its 388 entries and all seven owning fixture names.
    """
    require(isinstance(fixtures, list) and fixtures
            and all(isinstance(name, str) and FIXTURE_NAME.fullmatch(name) for name in fixtures)
            and len(set(fixtures)) == len(fixtures), "invalid_matrix_fixture_corpus")
    require(isinstance(cases, list) and len(cases) <= 4096, "invalid_matrix_corpus")
    declared = {}
    for case in cases:
        require(type(case) is dict and set(case) == DECLARED_FIELDS, "invalid_matrix_corpus")
        name = case["case_id"]
        require(isinstance(name, str) and CASE_ID.fullmatch(name), "invalid_matrix_corpus")
        require(name not in declared, "duplicate_matrix_corpus")
        require(isinstance(case["outer_test"], str) and case["outer_test"] in fixtures,
                "invalid_matrix_fixture_corpus")
        kind = case["class"]
        require(isinstance(kind, str) and kind in CLASSES, "invalid_matrix_corpus")
        require(type(case["width"]) is int, "invalid_matrix_corpus")
        if kind in RANDOM:
            require(case["width"] in (16, 32, 64) and uint(case["destination"], 15),
                    "invalid_matrix_corpus")
        elif kind == "rdpid":
            require(case["width"] == 32 and uint(case["destination"], 15), "invalid_matrix_corpus")
        else:
            require(case["width"] == (32 if kind == "cpuid" else 64)
                    and case["destination"] is None, "invalid_matrix_corpus")
        require(type(case["path"]) is str and case["path"] in ("native", "scripted"),
                "invalid_matrix_corpus")
        expected = case["input_flags_expected"]
        if case["input_flags_source"] == "initial_checkpoint":
            require(expected is None and name.startswith("first-"), "invalid_matrix_corpus")
        else:
            require(case["input_flags_source"] == "independent_fixture_model" and flags(expected),
                    "invalid_matrix_corpus")
        carry = case["actual_cf_allowed"]
        require(type(carry) is list, "invalid_matrix_corpus")
        if kind in RANDOM:
            require(all(uint(value, 1) for value in carry), "invalid_matrix_corpus")
            require(carry == [0, 1] if case["path"] == "native" else carry in ([0], [1]),
                    "invalid_matrix_corpus")
        else:
            require(carry == [None], "invalid_matrix_corpus")
        require(type(case["completed"]) is int and case["completed"] == 1
                and case["cleanup"] is True, "invalid_matrix_corpus")
        declared[name] = case
    return declared


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_matrix_json_key")
        result[key] = value
    return result


def invalid_constant(_value):
    raise InvalidEvidence("invalid_matrix_json")


def decoded_receipt(text, declared, active):
    require(len(text) <= 2048, "invalid_matrix_json")
    try:
        row = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (ValueError, RecursionError) as error:
        raise InvalidEvidence("invalid_matrix_json") from error
    require(type(row) is dict and set(row) == FIELDS, "invalid_matrix_fields")
    require(type(row["schema_version"]) is int and row["schema_version"] == 1,
            "invalid_matrix_schema")
    name = row["case_id"]
    require(isinstance(name, str) and name in declared, "unknown_matrix_case")
    case = declared[name]
    require(active == case["outer_test"], "matrix_case_wrong_fixture")
    for key in ("class", "path"):
        require(type(row[key]) is str and row[key] == case[key], "matrix_identity_differs")
    require(type(row["width"]) is int and row["width"] == case["width"], "matrix_identity_differs")
    require(row["destination"] is None if case["destination"] is None else
            uint(row["destination"], 15) and row["destination"] == case["destination"],
            "matrix_identity_differs")
    require(flags(row["input_flags"]), "invalid_matrix_input_flags")
    require(case["input_flags_expected"] is None or
            row["input_flags"] == case["input_flags_expected"], "matrix_input_flags_differs")
    if case["class"] in RANDOM:
        require(uint(row["actual_cf"], 1) and row["actual_cf"] in case["actual_cf_allowed"],
                "invalid_matrix_carry")
    else:
        require(row["actual_cf"] is None, "invalid_matrix_carry")
    require(type(row["completed"]) is int and row["completed"] == 1,
            "matrix_completion_not_one")
    require(row["cleanup"] is True, "matrix_cleanup_not_proven")
    return row


def matrix_receipts(output, cases, fixtures, successful_command):
    """Require each declared receipt once under its exact successful fixture."""
    declared = inventory(cases, fixtures)
    require(type(successful_command) is bool, "invalid_matrix_command_status")
    observed = {}
    results = {}
    seen = False
    inside = False
    active = None

    def partial():
        return [copy.deepcopy(observed.get(name, {
            "case_id": name, "test": case["outer_test"], "status": "not_observed",
            "test_result": None, "command_succeeded": successful_command, "qualified_run": False,
        })) for name, case in declared.items()]

    try:
        for line in output.splitlines():
            identity = harness_id(line)
            if identity:
                require(not inside or active is None, "matrix_fixture_missing_terminal")
                inside = identity == HARNESS
                if inside:
                    require(not seen, "duplicate_matrix_harness")
                    seen = True
                continue
            if re.match(r"\s*(Running |Doc-tests )", line):
                raise InvalidEvidence("unrecognized_harness_header")
            start = re.fullmatch(r"test (" + FIXTURE_NAME.pattern + r") \.\.\. (.*)", line) if inside else None
            if start:
                require(active is None, "matrix_fixture_missing_terminal")
                require(start[1] in fixtures and start[1] not in results, "matrix_named_cohort_differs")
                active = start[1]
                results[active] = None
                line = start[2]
            elif inside and line.startswith("test ") and not line.startswith("test result:"):
                raise InvalidEvidence("invalid_matrix_fixture_name")
            if PREFIX in line:
                require(inside and active is not None, "matrix_receipt_outside_fixture")
                require(line.startswith(PREFIX), "malformed_matrix_prefix")
                row = decoded_receipt(line[len(PREFIX):], declared, active)
                name = row["case_id"]
                require(name not in observed, "duplicate_matrix_receipt")
                observed[name] = row | {
                    "test": active, "status": "incomplete", "test_result": None,
                    "command_succeeded": successful_command, "qualified_run": False,
                }
                continue
            if not inside:
                continue
            terminal = (line if line in ("ok", "FAILED", "ignored") else
                        "ignored" if line.startswith("ignored,") else None)
            if terminal:
                require(active is not None, "matrix_terminal_without_fixture")
                results[active] = terminal
                for row in observed.values():
                    if row["test"] == active:
                        row["test_result"] = terminal
                        row["status"] = "complete" if terminal == "ok" else "failed"
                active = None
        require(not declared or seen, "missing_matrix_harness")
        require(active is None, "matrix_fixture_missing_terminal")
        require(set(observed) == set(declared), "missing_matrix_receipt")
        require(all(row["test_result"] == "ok" for row in observed.values()), "matrix_fixture_not_passed")
        return partial()
    except InvalidEvidence as error:
        error.partial = partial()
        raise
