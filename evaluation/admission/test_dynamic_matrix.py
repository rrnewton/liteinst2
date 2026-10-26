"""Synthetic exact-receipt regressions; no native commands are executed."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

import dynamic_admission
import dynamic_matrix as matrix
import parsing
import run
from test_dynamic_admission import FIXTURES as BASE_FIXTURES, header, native_block, summary


FIXTURES = ["baseline", "matrix::scripted", "matrix::native", "matrix::first",
            "call_boundary::retained"]
CASES = [
    {"case_id": "seeded-rdrand-w16-gpr00-scripted-cf0-flags0ed7",
     "outer_test": "matrix::scripted", "class": "rdrand", "width": 16, "destination": 0,
     "path": "scripted", "input_flags_expected": 0xed7,
     "input_flags_source": "independent_fixture_model", "actual_cf_allowed": [0],
     "completed": 1, "cleanup": True},
    {"case_id": "seeded-rdseed-w64-gpr04-scripted-cf1-flags0602",
     "outer_test": "matrix::scripted", "class": "rdseed", "width": 64, "destination": 4,
     "path": "scripted", "input_flags_expected": 0x602,
     "input_flags_source": "independent_fixture_model", "actual_cf_allowed": [1],
     "completed": 1, "cleanup": True},
    {"case_id": "seeded-rdrand-w32-gpr15-native-hardware-flags0ed7",
     "outer_test": "matrix::native", "class": "rdrand", "width": 32, "destination": 15,
     "path": "native", "input_flags_expected": 0xed7,
     "input_flags_source": "independent_fixture_model", "actual_cf_allowed": [0, 1],
     "completed": 1, "cleanup": True},
    {"case_id": "first-cpuid-leaf0-subleaf0-native-hardware",
     "outer_test": "matrix::first", "class": "cpuid", "width": 32, "destination": None,
     "path": "native", "input_flags_expected": None,
     "input_flags_source": "initial_checkpoint", "actual_cf_allowed": [None],
     "completed": 1, "cleanup": True},
]


def receipt(case):
    return {"schema_version": 1, **{key: case[key] for key in
            ("case_id", "class", "width", "destination", "path", "completed", "cleanup")},
            "input_flags": 0x202 if case["input_flags_expected"] is None else case["input_flags_expected"],
            "actual_cf": case["actual_cf_allowed"][-1]}


def block(cases=CASES, fixtures=FIXTURES, split=False):
    lines = [header(), f"running {len(fixtures)} tests"]
    for fixture in fixtures:
        rows = [matrix.PREFIX + json.dumps(receipt(case))
                for case in cases if case["outer_test"] == fixture]
        if rows and not split:
            lines.append(f"test {fixture} ... " + rows.pop(0))
        else:
            lines.append(f"test {fixture} ... ")
        lines.extend(rows)
        lines.append("ok")
    lines.append(summary(len(fixtures)))
    return "\n".join(lines) + "\n"


def changed_receipt(text, index, **changes):
    original = receipt(CASES[index])
    return text.replace(json.dumps(original), json.dumps(original | changes), 1)


def expected_corpus():
    real = json.loads(Path(__file__).with_name("corpus.json").read_text())
    return {"harness_test_counts": {"serial_launch": {
                "test/dynamic_admission": {"tests": len(FIXTURES), "ignored": 0},
                "test/native_selected": {"tests": 50, "ignored": 0}}},
            "native_cases": real["native_cases"], "dynamic_admission_fixtures": FIXTURES,
            "dynamic_matrix_cases": CASES, "native_validation_fixtures": []}


class MatrixParsingTests(unittest.TestCase):
    def refuse(self, text, code, cases=CASES, fixtures=FIXTURES):
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^" + code + "$") as caught:
            matrix.matrix_receipts(text, cases, fixtures, True)
        self.assertFalse(any(row["qualified_run"] for row in caught.exception.partial or []))
        return caught.exception.partial

    def test_exact_inline_and_split_rows_remain_separate_unqualified_observations(self):
        for split in (False, True):
            with self.subTest(split=split):
                rows = matrix.matrix_receipts(block(split=split), CASES, FIXTURES, True)
                self.assertEqual(rows, [receipt(case) | {
                    "test": case["outer_test"], "status": "complete", "test_result": "ok",
                    "command_succeeded": True, "qualified_run": False} for case in CASES])
                self.assertEqual([row["actual_cf"] for row in rows], [0, 1, 1, None])

    def test_namespaces_require_exact_segments_and_exact_declared_identity(self):
        rows = dynamic_admission.fixture_results(block(), FIXTURES, True)
        self.assertEqual([row["test"] for row in rows], FIXTURES)
        for name in ("matrix::", "::scripted", "matrix:::scripted", "matrix/scripted",
                     "matrix::scripted::", "matrix::scripted.extra"):
            with self.subTest(name=name), self.assertRaises(parsing.InvalidEvidence):
                dynamic_admission.fixture_results(block().replace("matrix::scripted", name), FIXTURES, True)
        for name in ("scripted", "other::scripted", "matrix::scripted_extra"):
            self.refuse(block().replace("matrix::scripted", name), "matrix_named_cohort_differs")

    def test_missing_duplicate_and_malformed_harnesses_refuse(self):
        self.refuse("compiler diagnostics", "missing_matrix_harness")
        self.refuse(block() + block(), "duplicate_matrix_harness")
        self.refuse(block().replace("target/debug/deps/", "/PRIVATE_SENTINEL/"),
                    "invalid_harness_binary_path")
        self.refuse(block().replace("Running tests/", "Running invalid/"), "unrecognized_harness_header")

    def test_wrong_harness_and_outside_active_fixture_cannot_supply_rows(self):
        row = matrix.PREFIX + json.dumps(receipt(CASES[0])) + "\n"
        for text in (row + block(), header() + "\n" + row + block(),
                     block().replace("tests/dynamic_admission.rs", "tests/other.rs")
                     .replace("dynamic_admission-123abc", "other-123abc"),
                     block() + row, block() + header("other") + "\n" + row):
            with self.subTest(text=text[:40]):
                self.refuse(text, "matrix_receipt_outside_fixture")

    def test_known_case_under_wrong_fixture_refuses_without_rebinding(self):
        original = matrix.PREFIX + json.dumps(receipt(CASES[0]))
        text = block(split=True).replace(original + "\n", "", 1)
        text = text.replace("test matrix::native ... \n", "test matrix::native ... \n" + original + "\n")
        self.refuse(text, "matrix_case_wrong_fixture")

    def test_unknown_case_never_exports_untrusted_identity_or_diagnostics(self):
        rows = self.refuse(changed_receipt(block(), 1, case_id="PRIVATE_SENTINEL"), "unknown_matrix_case")
        self.assertEqual(rows[0]["status"], "incomplete")
        self.assertEqual(rows[1]["status"], "not_observed")
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
        self.assertNotIn("actual_cf", rows[1])

    def test_duplicate_and_missing_rows_never_become_an_observed_zero_carry(self):
        row = matrix.PREFIX + json.dumps(receipt(CASES[0]))
        self.refuse(block(split=True).replace(row, row + "\n" + row), "duplicate_matrix_receipt")
        rows = self.refuse(block(split=True).replace(row + "\n", ""), "missing_matrix_receipt")
        self.assertEqual(rows[0]["status"], "not_observed")
        self.assertNotIn("actual_cf", rows[0])
        self.assertEqual(rows[2]["actual_cf"], 1)

    def test_duplicate_json_fields_are_rejected_before_observation(self):
        original = json.dumps(receipt(CASES[0]))
        duplicate = original[:-1] + ', "actual_cf": 0}'
        rows = self.refuse(block().replace(original, duplicate, 1), "duplicate_matrix_json_key")
        self.assertEqual(rows[0]["status"], "not_observed")

    def test_malformed_nonobject_nonfinite_and_overlong_json_refuse(self):
        original = json.dumps(receipt(CASES[0]))
        for replacement, code in (("{", "invalid_matrix_json"), ("[]", "invalid_matrix_fields"),
                                  ("null", "invalid_matrix_fields"), ("NaN", "invalid_matrix_json"),
                                  ("Infinity", "invalid_matrix_json"),
                                  ('{"x":"' + "x" * 2048 + '"}', "invalid_matrix_json")):
            with self.subTest(code=code):
                self.refuse(block().replace(original, replacement, 1), code)

    def test_closed_schema_rejects_extra_missing_and_boolean_version(self):
        for key in matrix.FIELDS:
            row = receipt(CASES[0]); del row[key]
            with self.subTest(missing=key):
                self.refuse(block().replace(json.dumps(receipt(CASES[0])), json.dumps(row), 1),
                            "invalid_matrix_fields")
        self.refuse(changed_receipt(block(), 0, host="PRIVATE_SENTINEL"), "invalid_matrix_fields")
        for value in (0, 2, True, "1", 1.0):
            self.refuse(changed_receipt(block(), 0, schema_version=value), "invalid_matrix_schema")

    def test_every_identity_component_requires_exact_type_and_value(self):
        for key, values in (("class", ("rdseed", True, None)), ("width", (32, True, "16", 16.0)),
                            ("destination", (1, False, "0", None)), ("path", ("native", False, None))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.refuse(changed_receipt(block(), 0, **{key: value}), "matrix_identity_differs")
        self.refuse(changed_receipt(block(), 3, destination=0), "matrix_identity_differs")

    def test_flags_are_exact_for_seeded_rows_and_numeric_for_literal_first(self):
        self.refuse(changed_receipt(block(), 0, input_flags=0x202), "matrix_input_flags_differs")
        for value in (None, True, "514", 514.0, -1, 1 << 64, 0, 0x302, 0x10202):
            with self.subTest(value=value):
                self.refuse(changed_receipt(block(), 3, input_flags=value), "invalid_matrix_input_flags")
        for value in (0x202, 0xed7):
            rows = matrix.matrix_receipts(changed_receipt(block(), 3, input_flags=value), CASES, FIXTURES, True)
            self.assertEqual(rows[3]["input_flags"], value)

    def test_carry_is_actual_and_class_specific_without_native_failure_invention(self):
        for index in (0, 1, 2):
            for value in (None, True, False, "0", 0.0, -1, 2):
                with self.subTest(index=index, value=value):
                    self.refuse(changed_receipt(block(), index, actual_cf=value), "invalid_matrix_carry")
        self.refuse(changed_receipt(block(), 0, actual_cf=1), "invalid_matrix_carry")
        self.refuse(changed_receipt(block(), 1, actual_cf=0), "invalid_matrix_carry")
        for value in (0, 1, False):
            self.refuse(changed_receipt(block(), 3, actual_cf=value), "invalid_matrix_carry")
        for value in (0, 1):
            rows = matrix.matrix_receipts(changed_receipt(block(), 2, actual_cf=value), CASES, FIXTURES, True)
            self.assertEqual(rows[2]["actual_cf"], value)

    def test_completion_and_cleanup_need_literal_success_values(self):
        for value in (0, 2, True, 1.0, "1", None):
            self.refuse(changed_receipt(block(), 0, completed=value), "matrix_completion_not_one")
        for value in (False, 1, "true", None):
            self.refuse(changed_receipt(block(), 0, cleanup=value), "matrix_cleanup_not_proven")

    def test_panic_diagnostics_never_replace_terminal_success(self):
        text = block().replace("test matrix::scripted ... ",
                               "test matrix::scripted ... \nthread panicked at PRIVATE_SENTINEL\n")
        rows = matrix.matrix_receipts(text, CASES, FIXTURES, True)
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
        incomplete = text[:text.index("\nok\n", text.index("test matrix::scripted"))]
        rows = self.refuse(incomplete, "matrix_fixture_missing_terminal")
        self.assertEqual(rows[0]["status"], "incomplete")
        self.assertIsNone(rows[0]["test_result"])

    def test_failed_or_ignored_terminal_retains_receipts_but_never_passes(self):
        marker = "\nok\ntest matrix::native"
        for terminal in ("FAILED", "ignored", "ignored, no capability"):
            with self.subTest(terminal=terminal):
                rows = self.refuse(block().replace(marker, "\n" + terminal + "\ntest matrix::native"),
                                   "matrix_fixture_not_passed")
                self.assertEqual(rows[0]["status"], "failed")
                self.assertEqual(rows[0]["test_result"], "FAILED" if terminal == "FAILED" else "ignored")
                self.assertEqual(rows[2]["status"], "complete")

    def test_detached_duplicate_and_missing_terminals_refuse(self):
        self.refuse(header() + "\nok\n", "matrix_terminal_without_fixture")
        self.refuse(block() + "ok\n", "matrix_terminal_without_fixture")
        self.refuse(block().replace("\nok\ntest matrix::native", "\ntest matrix::native"),
                    "matrix_fixture_missing_terminal")
        self.refuse(block().replace("\nok\ntest matrix::native", "\n" + header("other") + "\ntest matrix::native"),
                    "matrix_fixture_missing_terminal")

    def test_telemetry_prefix_must_be_exact_and_not_diagnostic_text(self):
        self.refuse(block().replace(matrix.PREFIX, "diagnostic " + matrix.PREFIX, 1), "malformed_matrix_prefix")
        self.refuse(block().replace(matrix.PREFIX, "LITEINST_EVALUATION_DYNAMIC_MATRI ", 1),
                    "missing_matrix_receipt")

    def test_inventory_refuses_invalid_shapes_and_ambiguous_expectations(self):
        changes = [("class", "syscall"), ("width", True), ("width", 8), ("destination", True),
                   ("path", "other"), ("outer_test", "foreign::fixture"),
                   ("input_flags_expected", None), ("input_flags_source", "unknown"),
                   ("actual_cf_allowed", [0, 1]), ("actual_cf_allowed", [False]),
                   ("completed", True), ("cleanup", 1)]
        for key, value in changes:
            cases = copy.deepcopy(CASES); cases[0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(parsing.InvalidEvidence):
                matrix.matrix_receipts(block(), cases, FIXTURES, True)
        for cases in (None, {}, [CASES[0], CASES[0]], [{}], [dict(CASES[0], extra=1)]):
            with self.assertRaises(parsing.InvalidEvidence):
                matrix.matrix_receipts(block(), cases, FIXTURES, True)
        for fixtures in ([], {}, ["matrix::"], ["a", "a"]):
            with self.assertRaises(parsing.InvalidEvidence):
                matrix.matrix_receipts(block(), CASES, fixtures, True)

    def test_explicit_empty_inventory_accepts_no_telemetry_and_no_implicit_omission(self):
        text = block(cases=[])
        self.assertEqual(matrix.matrix_receipts(text, [], FIXTURES, True), [])
        self.refuse(block(), "unknown_matrix_case", cases=[])
        for value in (0, 1, None, "passed"):
            with self.assertRaisesRegex(parsing.InvalidEvidence, "invalid_matrix_command_status"):
                matrix.matrix_receipts(text, [], FIXTURES, value)


class MatrixRecorderIntegrationTests(unittest.TestCase):
    def test_three_cohorts_are_independent_and_matrix_rows_are_not_test_counts(self):
        expected = expected_corpus()
        observed = {"id": "serial_launch", "status": "passed", "exit_code": 0}
        run.command_evidence(observed, block() + native_block(expected["native_cases"]), expected)
        self.assertEqual(observed["status"], "passed")
        self.assertEqual(observed["evidence_status"], "complete")
        self.assertEqual(len(observed["native_cases"]), 50)
        self.assertEqual(len(observed["dynamic_admission_fixtures"]), 5)
        self.assertEqual(len(observed["dynamic_matrix_cases"]), 4)
        self.assertEqual(sum(row["completed"] for row in observed["dynamic_matrix_cases"]), 4)
        self.assertTrue(all("completed" not in row for row in observed["dynamic_admission_fixtures"]))
        self.assertTrue(all("raw_native_completed" not in row for row in observed["dynamic_matrix_cases"]))
        self.assertFalse(any(row["qualified_run"] for field in
                             ("native_cases", "dynamic_admission_fixtures", "dynamic_matrix_cases")
                             for row in observed[field]))

    def test_matrix_failure_does_not_discard_other_observations_or_qualify_partial_rows(self):
        expected = expected_corpus()
        text = changed_receipt(block(), 2, actual_cf=None) + native_block(expected["native_cases"])
        observed = {"id": "serial_launch", "status": "passed", "exit_code": 0}
        run.command_evidence(observed, text, expected)
        self.assertEqual(observed["status"], "invalid_evidence")
        self.assertEqual(observed["dynamic_matrix_parse_error"], "invalid_matrix_carry")
        self.assertEqual(len(observed["native_cases"]), 50)
        self.assertTrue(all(row["status"] == "complete" for row in observed["dynamic_admission_fixtures"]))
        self.assertEqual([row["status"] for row in observed["dynamic_matrix_cases"]],
                         ["complete", "complete", "not_observed", "not_observed"])

    def test_valid_rows_cannot_clear_aggregate_named_or_static_parser_failures(self):
        expected = expected_corpus()
        original = block() + native_block(expected["native_cases"])
        for text, field in (
                (original.replace("running 5 tests", "running 6 tests"), "parse_error"),
                (original.replace("test baseline ... \nok", "test baseline ... \nFAILED"), "dynamic_parse_error"),
                (original.replace(parsing.PREFIX, "MISSING_STATIC ", 1), "native_parse_error")):
            with self.subTest(field=field):
                observed = {"id": "serial_launch", "status": "passed", "exit_code": 0}
                run.command_evidence(observed, text, expected)
                self.assertEqual(observed["status"], "invalid_evidence")
                self.assertIn(field, observed)
                self.assertEqual(observed["evidence_status"], "incomplete")
                self.assertTrue(all(row["status"] == "complete" for row in observed["dynamic_matrix_cases"]))

    def test_nonzero_limit_or_adopted_descendants_never_turn_valid_rows_into_passes(self):
        expected = expected_corpus()
        text = block() + native_block(expected["native_cases"])
        for exit_code, termination in ((101, None), (0, "timeout"), (0, "output_limit"),
                                       (0, "descendants_after_exit")):
            with self.subTest(termination=termination):
                observed = {"id": "serial_launch", "status": "failed", "exit_code": exit_code,
                            "termination": termination, "cleanup_complete": True}
                run.command_evidence(observed, text, expected)
                self.assertEqual(observed["status"], "failed")
                self.assertEqual(observed["termination"], termination)
                self.assertTrue(all(row["status"] == "complete" for row in observed["dynamic_matrix_cases"]))
                self.assertFalse(any(row["command_succeeded"] or row["qualified_run"]
                                     for row in observed["dynamic_matrix_cases"]))

    def test_full_protocol_source_configuration_and_later_command_gate_all_three_cohorts(self):
        for source, config, later, result in ((True, True, "passed", True), (False, True, "passed", False),
                (True, False, "passed", False), (None, True, "passed", False),
                (True, True, "not_run", False), (True, True, "failed", False),
                (True, True, "invalid_evidence", False)):
            with self.subTest(source=source, config=config, later=later):
                command = {"status": "passed"}
                for field in ("native_cases", "dynamic_admission_fixtures", "dynamic_matrix_cases"):
                    command[field] = [{"qualified_run": False, "command_succeeded": True},
                                      {"qualified_run": False, "command_succeeded": False}]
                record = {"source_unchanged": source, "configuration_unchanged": config,
                          "commands": [command, {"status": later}]}
                run.qualify(record)
                self.assertEqual(record["status"], "passed" if result else "failed")
                for field in ("native_cases", "dynamic_admission_fixtures", "dynamic_matrix_cases"):
                    self.assertEqual([row["qualified_run"] for row in command[field]], [result, False])

    def test_compile_failure_retains_unknown_matrix_rows_without_inventing_values(self):
        observed = {"id": "serial_launch", "status": "failed", "exit_code": 101}
        run.command_evidence(observed, "PRIVATE_SENTINEL compiler failure", expected_corpus())
        self.assertEqual(observed["status"], "failed")
        self.assertEqual(observed["dynamic_matrix_parse_error"], "missing_matrix_harness")
        self.assertEqual(len(observed["dynamic_matrix_cases"]), 4)
        self.assertTrue(all(row["status"] == "not_observed" and "actual_cf" not in row
                            and "completed" not in row for row in observed["dynamic_matrix_cases"]))
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(observed))

    def test_real_inventory_is_exact_source_declared_rows_not_generated_class_counts(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        cases = declared["dynamic_matrix_cases"]
        encoded = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), "81c9212c05cdabd531629248aec53b48bd9a1517367b067c5a03340a1d39abbe")
        self.assertEqual(len(matrix.inventory(cases, declared["dynamic_admission_fixtures"])), 388)
        self.assertEqual(len(set(case["outer_test"] for case in cases)), 7)
        self.assertEqual(sum(case["path"] == "native" for case in cases), 144)
        self.assertEqual(sum(case["path"] == "scripted" for case in cases), 244)
        self.assertEqual(sum(case["input_flags_expected"] is None for case in cases), 12)
        self.assertEqual(declared["dynamic_admission_fixtures"], BASE_FIXTURES
                         + list(dict.fromkeys(case["outer_test"] for case in cases))
                         + ["call_boundary::native_call_return_into_never_executed_nx_page_keeps_old_generation_obligation"])
        self.assertEqual(len(declared["dynamic_admission_fixtures"]), 15)
        self.assertEqual(len(declared["native_cases"]), 50)
        for cohort in declared["harness_test_counts"].values():
            self.assertEqual(cohort["test/dynamic_admission"], {"tests": 15, "ignored": 0})


if __name__ == "__main__":
    unittest.main()
