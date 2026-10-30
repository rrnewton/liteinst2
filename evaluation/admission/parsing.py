"""Strict parsers for reviewed Cargo/libtest output, never raw-log exporters.

The log is evidence from a reviewed program, not an authenticated protocol from
hostile test code. Unknown or contradictory protocol records fail closed. All
partial observations contain only validated identities and typed fields.
"""

import copy
import json
import re

PREFIX = "LITEINST_EVALUATION_NATIVE_SELECTED "
KEYS = ("class", "destination", "input_flags", "cpuid_leaf", "cpuid_subleaf",
        "encoding", "coverage_backend")
COUNTERS = ("raw_native_completed", "scripted_completed", "native_gate_completed",
            "raw_native_fault", "scripted_fault", "native_gate_signal")
CARRY = ("raw_native_random_cf", "native_gate_random_cf")
SUMMARY = re.compile(
    r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in (\d+(?:\.\d+)?)s")
IDENTITY = re.compile(r"(?:unit/[A-Za-z0-9_]+/[A-Za-z0-9_]+|"
                      r"test/[A-Za-z0-9_]+|doc/[A-Za-z0-9_-]+)")
NAME = re.compile(r"[A-Za-z0-9_]+")


class InvalidEvidence(Exception):
    """A stable error code and sanitized observations, never arbitrary output."""

    def __init__(self, code, partial=None):
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", code):
            code = "invalid_error_code"
        super().__init__(code)
        self.code = code
        self.partial = partial


def require(condition, code):
    if not condition:
        raise InvalidEvidence(code)


def harness_id(line):
    """Return a path-free cohort ID, distinguishing unit libraries and binaries."""
    doc = re.fullmatch(r"\s*Doc-tests ([A-Za-z0-9_-]+)", line)
    if doc:
        return "doc/" + doc[1]
    example = re.fullmatch(
        r"\s*Running unittests examples/common_sites\.rs "
        r"\(target/debug/examples/common_sites-[a-f0-9]+\)", line)
    if example:
        return "unit/common_sites/common_sites"
    # Exact new Cargo example target declared test=true; no generic examples grammar.
    example = re.fullmatch(
        r"\s*Running unittests examples/verify_common_core\.rs "
        r"\(target/debug/examples/verify_common_core-[a-f0-9]+\)", line)
    if example:
        return "unit/verify_common_core/verify_common_core"
    # This exact example is an additional test=true Cargo target.
    example = re.fullmatch(
        r"\s*Running unittests examples/disassembly_sites\.rs "
        r"\(target/debug/examples/disassembly_sites-[a-f0-9]+\)", line)
    if example:
        return "unit/disassembly_sites/disassembly_sites"
    # One additional exact test=true example; no generic example spelling.
    example = re.fullmatch(
        r"\s*Running unittests examples/adjacent_b2_disassembly_sites\.rs "
        r"\(target/debug/examples/adjacent_b2_disassembly_sites-[a-f0-9]+\)", line)
    if example:
        return "unit/adjacent_b2_disassembly_sites/adjacent_b2_disassembly_sites"
    match = re.fullmatch(r"\s*Running (unittests [^()]+|tests/[^()]+|native-interval/calibrations\.rs) \(([^()]+)\)", line)
    if not match:
        return None
    binary = re.fullmatch(r"target/debug/deps/([A-Za-z0-9_]+)-[a-f0-9]+", match[2])
    require(binary is not None, "invalid_harness_binary_path")
    label = match[1]
    # This reviewed example has one source/binary/output-directory identity.
    # The generic legacy unit matcher cannot provide an alternate spelling.
    require(label != "unittests examples/common_sites.rs" and binary[1] != "common_sites",
            "invalid_harness_source_label")
    require(label != "unittests examples/verify_common_core.rs" and binary[1] != "verify_common_core",
            "invalid_harness_source_label")
    require(label != "unittests examples/disassembly_sites.rs" and binary[1] != "disassembly_sites",
            "invalid_harness_source_label")
    require(label != "unittests examples/adjacent_b2_disassembly_sites.rs"
            and binary[1] != "adjacent_b2_disassembly_sites", "invalid_harness_source_label")
    if label == "unittests ordinary-interval/main.rs" or binary[1] == "ordinary_interval":
        require(label == "unittests ordinary-interval/main.rs" and binary[1] == "ordinary_interval",
                "invalid_harness_source_label")
    if label == "native-interval/calibrations.rs":
        require(binary[1] == "frontend_native_calibrations", "invalid_harness_source_label")
        return "test/frontend_native_calibrations"
    if label.startswith("unittests "):
        source = label[len("unittests "):]
        require(re.fullmatch(r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_]+\.rs", source),
                "invalid_harness_source_label")
        stem = source.rsplit("/", 1)[-1][:-3]
        return "unit/" + binary[1] + "/" + stem
    require(re.fullmatch(r"tests/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_]+\.rs", label),
            "invalid_harness_source_label")
    return "test/" + binary[1]


def _expected_harnesses(expected):
    require(isinstance(expected, dict) and expected, "invalid_harness_corpus")
    for identity, counts in expected.items():
        require(isinstance(identity, str) and IDENTITY.fullmatch(identity), "invalid_harness_corpus")
        require(isinstance(counts, dict) and set(counts) == {"tests", "ignored"},
                "invalid_harness_corpus")
        require(all(type(counts[k]) is int and counts[k] >= 0 for k in counts)
                and counts["ignored"] <= counts["tests"], "invalid_harness_corpus")


def parse_harnesses(output, expected, exit_code):
    """Bind summaries to announced runs; retain safe partial rows on any error.

    The reviewed core ptrace and isolated stress fixtures exit their one-test
    children without libtest summaries. Their parents verify the child results.
    Only those exact cohorts permit one unmatched child start. Equal-sized
    child/parent runs require separate starts and summaries.
    """
    _expected_harnesses(expected)
    records = {}
    current = None
    stack = []

    def partial():
        result = []
        for identity, counts in expected.items():
            row = records.get(identity)
            if row is None:
                row = {"id": identity, "expected_tests": counts["tests"],
                       "expected_ignored": counts["ignored"], "status": "not_observed",
                       "declared_outer_tests": None, "nested_starts": 0,
                       "unmatched_nested_starts": 0, "outer": None, "nested": [],
                       "unclassified_summaries": []}
            result.append(copy.deepcopy(row))
        return result

    def close_current():
        if current is not None:
            require(current["outer"] is not None and not stack, "missing_outer_summary")

    try:
        for line in output.splitlines():
            identity = harness_id(line)
            if identity:
                close_current()
                require(identity in expected and identity not in records,
                        "unexpected_or_duplicate_harness")
                counts = expected[identity]
                current = {"id": identity, "expected_tests": counts["tests"],
                           "expected_ignored": counts["ignored"], "status": "incomplete",
                           "declared_outer_tests": None, "nested_starts": 0,
                           "unmatched_nested_starts": 0, "outer": None, "nested": [],
                           "unclassified_summaries": []}
                records[identity] = current
                stack = []
                continue
            if re.match(r"\s*(Running |Doc-tests )", line):
                raise InvalidEvidence("unrecognized_harness_header")
            if current is not None and "partitions" in current and line.startswith("all doctests ran in "):
                require(re.fullmatch(r"all doctests ran in \d+(?:\.\d+)?s; "
                                     r"merged doctests compilation took \d+(?:\.\d+)?s", line)
                        and current["outer"] is None and not stack
                        and [p["declared_tests"] for p in current["partitions"]]
                        == {38: [2, 36], 45: [2, 43], 47: [2, 45]}[current["expected_tests"]]
                        and all(p["summary"] is not None for p in current["partitions"]),
                        "incomplete_doc_partitions")
                summaries = [p["summary"] for p in current["partitions"]]
                combined = {k: sum(s[k] for s in summaries) for k in
                            ("passed", "failed", "ignored", "measured", "filtered")}
                require(sum(combined[k] for k in ("passed", "failed", "ignored", "measured"))
                        == current["expected_tests"], "changed_outer_cohort")
                combined["result"] = "FAILED" if combined["failed"] else "ok"
                current["outer"] = combined
                current["status"] = "complete"
                continue
            start = re.fullmatch(r"running (\d+) tests?", line)
            if start:
                require(current is not None, "test_start_without_harness")
                require(current["outer"] is None, "start_after_outer_summary")
                count = int(start[1])
                if current["declared_outer_tests"] is None:
                    current["declared_outer_tests"] = count
                    if (current["id"], current["expected_tests"], current["expected_ignored"], count) in (
                            ("doc/rapid_profiler", 38, 0, 2),
                            ("doc/rapid_profiler", 45, 0, 2),
                            ("doc/rapid_profiler", 47, 0, 2)):
                        # Retain actual declarations/summaries; the outer counts
                        # are aggregated only after both and rustdoc's terminal.
                        current["partitions"] = [{"declared_tests": 2, "summary": None}]
                    else:
                        require(count == current["expected_tests"], "changed_outer_cohort")
                elif "partitions" in current:
                    require(not stack and len(current["partitions"]) == 1
                            and current["partitions"][0]["summary"] is not None
                            and count == {38: 36, 45: 43, 47: 45}[current["expected_tests"]],
                            "changed_doc_partition")
                    current["partitions"].append({"declared_tests": count, "summary": None})
                else:
                    current["nested_starts"] += 1
                stack.append(count)
                continue
            match = SUMMARY.fullmatch(line)
            if not match:
                require(not line.startswith("test result:"), "malformed_test_summary")
                continue
            require(current is not None, "summary_without_harness")
            summary = dict(zip(("passed", "failed", "ignored", "measured", "filtered"),
                               (int(match[i]) for i in range(2, 7))))
            summary["result"] = match[1]
            current["unclassified_summaries"].append(summary)
            require(current["outer"] is None and stack, "summary_without_start")
            count = sum(summary[k] for k in ("passed", "failed", "ignored", "measured"))
            if "partitions" in current:
                part = current["partitions"][-1]
                require(stack == [part["declared_tests"]] and part["summary"] is None
                        and count == part["declared_tests"], "summary_start_count_mismatch")
                require(summary["filtered"] == 0, "filtered_outer_summary")
                require(summary["measured"] == 0, "unexpected_measured_tests")
                require(summary["ignored"] == 0, "changed_ignore_cohort")
                require((summary["result"] == "FAILED") == (summary["failed"] > 0),
                        "contradictory_summary_result")
                if exit_code == 0:
                    require(summary["result"] == "ok" and summary["failed"] == 0,
                            "successful_exit_with_failed_summary")
                part["summary"] = summary
                current["unclassified_summaries"].pop()
                stack.pop()
                continue
            # The core ptrace child and stress::run_isolated use authenticated
            # process exits instead of returning through libtest. These are
            # observations of the existing fixtures, not successful child counts.
            if count != stack[-1]:
                known = (current["id"], current["declared_outer_tests"], current["expected_ignored"])
                # Retain the exact historical core cohorts for replay. The
                # merged core adds 24 tests to the same unchanged ptrace-child
                # fixture. The later five-test A3 addition retains that exact
                # child and requires 213; managed controls add six and require219.
                # Eight inline-clock tests require227 with the same child body.
                # The authenticated original child behavior is unchanged; all
                # historical tuples remain replayable.
                require(known in (("unit/liteinst2/lib", 176, 1),
                                  ("unit/liteinst2/lib", 184, 1),
                                  ("unit/liteinst2/lib", 208, 1),
                                  ("unit/liteinst2/lib", 213, 1),
                                  ("unit/liteinst2/lib", 219, 1),
                                  ("unit/liteinst2/lib", 227, 1),
                                  ("unit/liteinst2/lib", 242, 1),
                                  ("unit/liteinst2/lib", 248, 1),
                                  # e797 adds seven tests; the exact ptrace child
                                  # and its parent-authenticated exit41 are unchanged.
                                  ("unit/liteinst2/lib", 255, 1),
                                  # 0a8 adds seven whole-function tests; the child
                                  # body and exact nested stack remain unchanged.
                                  ("unit/liteinst2/lib", 262, 1),
                                  # b66 adds nine tests; the exact live ptrace
                                  # parent/child and authenticated exit41 are unchanged.
                                  ("unit/liteinst2/lib", 271, 1),
                                  # Seven explicit short-neighbor unit controls;
                                  # the existing ptrace child and stack stay exact.
                                  ("unit/liteinst2/lib", 278, 1),
                                  # Five explicit engine controls; the pinned
                                  # ptrace child still exits41 without a summary.
                                  ("unit/liteinst2/lib", 283, 1),
                                  # Eight inherited-ownership unit controls; the
                                  # complete pinned ptrace child is unchanged.
                                  ("unit/liteinst2/lib", 291, 1),
                                  # Eight pending-selected controls retain the
                                  # same pinned ptrace child and exact stack.
                                  ("unit/liteinst2/lib", 299, 1),
                                  # Ten adjacent-B2 tests; the entire old ptrace
                                  # child source and nested stack stay exact.
                                  ("unit/liteinst2/lib", 309, 1),
                                  # Twenty-one mixed-pair controls retain the
                                  # complete original ptrace child protocol.
                                  ("unit/liteinst2/lib", 330, 1),
                                  # Thirty-four routed native cases and thirty-five
                                  # inherited oracle tests; original child unchanged.
                                  ("unit/liteinst2/lib", 399, 1), ("test/stress", 7, 3))
                        and stack == [current["declared_outer_tests"], 1]
                        and count == current["declared_outer_tests"]
                        and summary["filtered"] == 0,
                        "summary_start_count_mismatch")
                stack.pop()
                current["unmatched_nested_starts"] += 1
            is_outer = len(stack) == 1
            if is_outer:
                require(summary["filtered"] == 0, "filtered_outer_summary")
                current["outer"] = summary
            else:
                require(count + summary["filtered"] == current["declared_outer_tests"],
                        "nested_summary_cohort_mismatch")
                current["nested"].append(summary)
            current["unclassified_summaries"].pop()
            stack.pop()
            require((summary["result"] == "FAILED") == (summary["failed"] > 0),
                    "contradictory_summary_result")
            require(summary["measured"] == 0, "unexpected_measured_tests")
            if is_outer:
                require(summary["ignored"] == current["expected_ignored"], "changed_ignore_cohort")
                current["status"] = "complete"
            else:
                require(summary["ignored"] == 0, "unexpected_nested_ignore")
            if exit_code == 0:
                require(summary["result"] == "ok" and summary["failed"] == 0,
                        "successful_exit_with_failed_summary")
        close_current()
        require(set(records) == set(expected), "missing_harness")
        return partial()
    except InvalidEvidence as error:
        if current is not None and error.code != "missing_harness":
            current["status"] = "invalid"
        error.partial = partial()
        raise


def _case_catalog(cases):
    require(isinstance(cases, list) and cases, "invalid_native_corpus")
    expected = {}
    names = set()
    for case in cases:
        require(isinstance(case, dict) and set(case) == {"test", *KEYS}, "invalid_native_corpus")
        require(isinstance(case["test"], str) and NAME.fullmatch(case["test"]),
                "invalid_native_corpus")
        require(case["class"] in ("cpuid", "rdrand", "rdseed", "rdpid", "rdtsc", "rdtscp")
                and isinstance(case["encoding"], str)
                and re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", case["encoding"])
                and type(case["coverage_backend"]) is bool
                and all(type(case[k]) is int and 0 <= case[k] < 2**64
                        for k in ("destination", "input_flags"))
                and all(case[k] is None or type(case[k]) is int and 0 <= case[k] < 2**32
                        for k in ("cpuid_leaf", "cpuid_subleaf")), "invalid_native_corpus")
        key = tuple(case[k] for k in KEYS)
        require(key not in expected and case["test"] not in names, "duplicate_native_corpus_case")
        expected[key] = case["test"]
        names.add(case["test"])
    return expected, names


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_native_json_field")
        result[key] = value
    return result


def _receipt(raw, expected):
    try:
        row = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, TypeError) as error:
        raise InvalidEvidence("invalid_native_json") from error
    require(isinstance(row, dict) and set(row) == {"schema_version", *KEYS, *COUNTERS, *CARRY},
            "unknown_native_fields")
    require(type(row["schema_version"]) is int and row["schema_version"] == 2,
            "unknown_native_schema")
    require(isinstance(row["class"], str) and isinstance(row["encoding"], str)
            and type(row["coverage_backend"]) is bool and all(type(row[k]) is int for k in
            ("destination", "input_flags")) and all(row[k] is None or type(row[k]) is int
            for k in ("cpuid_leaf", "cpuid_subleaf")), "invalid_native_identity_types")
    key = tuple(row[k] for k in KEYS)
    require(key in expected, "unknown_native_case")
    require(all(type(row[k]) is int and row[k] in (0, 1) for k in COUNTERS),
            "invalid_native_counter")
    outcome = tuple(row[k] for k in COUNTERS)
    require(outcome in ((1, 1, 1, 0, 0, 0), (0, 0, 0, 1, 1, 1)), "conflicting_native_outcomes")
    completed = outcome[0] == 1
    for field in CARRY:
        if row["class"] in ("rdrand", "rdseed") and completed:
            require(type(row[field]) is int and row[field] in (0, 1), "missing_random_carry")
        else:
            require(row[field] is None, "unexpected_random_carry")
    return row | {"test": expected[key], "outcome": "completed" if completed else "capability_fault"}


def native_receipts(output, cases, successful_command):
    """Require one receipt and an explicit terminal ok for every serial case."""
    expected, names = _case_catalog(cases)
    require(type(successful_command) is bool, "invalid_command_status")
    observed = {}
    active = None

    def partial():
        return [copy.deepcopy(observed.get(name, {"test": name, "status": "not_observed",
                "test_result": None, "command_succeeded": successful_command,
                "qualified_run": False})) for name in sorted(names)]

    try:
        for line in output.splitlines():
            start = re.fullmatch(r"test ([A-Za-z0-9_]+) \.\.\. (.*)", line)
            if start:
                require(active is None, "native_test_missing_terminal")
                name = start[1]
                require(name in names and name not in observed, "native_named_cohort_differs")
                active = name
                observed[name] = {"test": name, "status": "incomplete", "test_result": None,
                                  "command_succeeded": successful_command, "qualified_run": False}
                line = start[2]
            elif line.startswith("test ") and not line.startswith("test result:"):
                raise InvalidEvidence("invalid_native_test_name")
            if PREFIX in line:
                require(line.startswith(PREFIX), "invalid_native_record_prefix")
                require(active is not None, "native_receipt_without_active_test")
                row = _receipt(line[len(PREFIX):], expected)
                require(row["test"] == active, "native_receipt_test_mismatch")
                require("outcome" not in observed[active], "duplicate_native_receipt")
                observed[active].update(row)
                continue
            terminal = (line if line in ("ok", "FAILED", "ignored") else
                        "ignored" if line.startswith("ignored,") else None)
            if terminal:
                require(active is not None, "native_terminal_without_test")
                observed[active]["test_result"] = terminal
                observed[active]["status"] = "complete" if terminal == "ok" else "failed"
                active = None
        require(active is None, "native_test_missing_terminal")
        require(set(observed) == names, "native_named_cohort_differs")
        require(all(row["test_result"] == "ok" for row in observed.values()), "native_test_not_passed")
        require(all("outcome" in row for row in observed.values()), "missing_native_receipt")
        return partial()
    except InvalidEvidence as error:
        error.partial = partial()
        raise


def native_block(output):
    active = False
    seen = False
    lines = []
    for line in output.splitlines():
        identity = harness_id(line)
        if identity:
            active = identity == "test/native_selected"
            if active:
                require(not seen, "duplicate_native_harness")
                seen = True
        elif re.match(r"\s*(Running |Doc-tests )", line):
            raise InvalidEvidence("unrecognized_harness_header")
        if active:
            lines.append(line)
    require(seen, "missing_native_harness")
    return "\n".join(lines)
