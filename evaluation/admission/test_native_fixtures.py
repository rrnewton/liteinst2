"""Synthetic named-cohort protocol tests; no native command is executed."""

import copy
import json
import unittest

import native_fixtures as fixtures
from parsing import InvalidEvidence
import run
from test_dynamic_admission import corpus, fixture_block, native_block, summary


CASES = [
    {"cohort": "kernel_journal", "harness": fixtures.UNIT,
     "test": fixtures.PREFIXES[0] + "actual_entry"},
    {"cohort": "kernel_journal", "harness": fixtures.UNIT,
     "test": fixtures.PREFIXES[0] + "transport::actual_exit"},
    {"cohort": "kernel_journal", "harness": fixtures.UNIT,
     "test": fixtures.PREFIXES[1] + "dispatch_child_first"},
    {"cohort": "b2_reference", "harness": fixtures.REFERENCE, "test": "four_lanes"},
]


def header(identity):
    if identity == fixtures.UNIT:
        return "     Running unittests src/lib.rs (target/debug/deps/liteinst_launch-123abc)"
    name = identity.split("/")[-1]
    return f"     Running tests/{name}.rs (target/debug/deps/{name}-123abc)"


def block(split=False):
    lines = []
    for identity in (fixtures.UNIT, fixtures.REFERENCE):
        names = [row["test"] for row in CASES if row["harness"] == identity]
        if identity == fixtures.UNIT:
            names.insert(1, "ordinary::model_test")
        lines.extend([header(identity), f"running {len(names)} tests"])
        for name in names:
            if split:
                lines.extend([f"test {name} ... PRIVATE_SENTINEL diagnostics", "ok"])
            else:
                lines.append(f"test {name} ... ok")
        lines.append(summary(len(names)))
    return "\n".join(lines) + "\n"


def outcome(text, succeeded=True):
    return fixtures.fixture_outcomes(text, CASES, succeeded)


class NamedFixtureParsingTests(unittest.TestCase):
    def refuse(self, text, code):
        with self.assertRaisesRegex(InvalidEvidence, "^" + code + "$") as caught:
            outcome(text)
        rows = caught.exception.partial
        self.assertEqual(len(rows), len(CASES))
        self.assertFalse(any(row["qualified_run"] for row in rows))
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
        return rows

    def test_exact_inline_and_split_outcomes_have_no_native_sample_counts(self):
        for split in (False, True):
            with self.subTest(split=split):
                self.assertEqual(outcome(block(split)), [row | {
                    "status": "complete", "test_result": "ok", "command_succeeded": True,
                    "qualified_run": False} for row in CASES])

    def test_missing_duplicate_and_malformed_harnesses_refuse(self):
        self.refuse("PRIVATE_SENTINEL", "missing_native_fixture_harness")
        self.refuse(block() + block(), "duplicate_native_fixture_harness")
        self.refuse(block().replace("target/debug/deps/", "/PRIVATE_SENTINEL/", 1),
                    "invalid_harness_binary_path")
        self.refuse(block().replace("Running unittests", "Running invalid", 1),
                    "unrecognized_harness_header")

    def test_missing_duplicate_and_unknown_named_cases_refuse(self):
        first = f"test {CASES[0]['test']} ... ok\n"
        self.refuse(block().replace(first, ""), "native_fixture_cohort_differs")
        self.refuse(block().replace(first, first + first), "duplicate_native_fixture_test")
        self.refuse(block().replace(CASES[0]["test"], fixtures.PREFIXES[0] + "unknown"),
                    "native_fixture_cohort_differs")
        self.refuse(block().replace("test four_lanes ...", "test unknown ..."),
                    "native_fixture_cohort_differs")

    def test_exact_names_cannot_be_replaced_by_suffix_or_prefix_lookalikes(self):
        for name in (CASES[0]["test"] + "_extra", CASES[0]["test"].rsplit("::", 1)[-1],
                     CASES[0]["test"].replace("::native::", "::nativex::")):
            with self.subTest(name=name):
                self.refuse(block().replace(CASES[0]["test"], name), "native_fixture_cohort_differs")

    def test_known_case_in_another_harness_cannot_supply_an_outcome(self):
        first = f"test {CASES[0]['test']} ... ok\n"
        self.refuse(header("test/foreign") + "\n" + first + block(),
                    "native_fixture_wrong_harness")
        self.refuse(block().replace("test four_lanes ... ok", first.strip()),
                    "native_fixture_wrong_harness")

    def test_all_tests_in_monitored_unit_harness_have_exact_terminal_structure(self):
        ordinary = "test ordinary::model_test ... ok\n"
        self.refuse(block().replace(ordinary, ordinary + ordinary), "duplicate_native_fixture_test")
        self.refuse(block().replace(ordinary, "test ordinary::model_test ... \n"),
                    "native_fixture_missing_terminal")
        self.refuse(block().replace("ordinary::model_test", "bad/name"),
                    "invalid_native_fixture_name")

    def test_missing_terminal_at_summary_next_harness_or_eof_refuses(self):
        first = f"test {CASES[0]['test']} ... "
        for suffix in (summary(1), header(fixtures.REFERENCE), ""):
            with self.subTest(suffix=suffix):
                self.refuse(header(fixtures.UNIT) + "\nrunning 4 tests\n" + first + "\n" + suffix,
                            "native_fixture_missing_terminal")

    def test_terminal_without_test_and_test_after_summary_refuse(self):
        self.refuse(header(fixtures.UNIT) + "\nok\n", "native_fixture_terminal_without_test")
        self.refuse(block() + "ok\n", "native_fixture_terminal_without_test")
        self.refuse(block() + "test extra ... ok\n", "native_fixture_after_summary")

    def test_failed_and_ignored_cases_stay_typed_failures(self):
        for terminal in ("FAILED", "ignored", "ignored, reason"):
            with self.subTest(terminal=terminal):
                rows = self.refuse(block().replace("test four_lanes ... ok",
                                   "test four_lanes ... " + terminal), "native_fixture_not_passed")
                self.assertEqual(rows[-1]["status"], "failed")
                self.assertEqual(rows[-1]["test_result"], "FAILED" if terminal == "FAILED" else "ignored")
                self.assertEqual(rows[0]["test_result"], "ok")

    def test_partial_failure_exports_only_declared_identities_and_typed_fields(self):
        rows = self.refuse(block().replace("test four_lanes ... ok", "test PRIVATE_SENTINEL ... ok"),
                           "native_fixture_cohort_differs")
        self.assertEqual(rows[-1]["status"], "not_observed")
        self.assertIsNone(rows[-1]["test_result"])
        self.assertEqual(rows[0]["status"], "complete")
        self.assertTrue(all(set(row) == {"cohort", "harness", "test", "status", "test_result",
                                         "command_succeeded", "qualified_run"} for row in rows))

    def test_expected_panic_diagnostics_cannot_become_terminal_success(self):
        text = block().replace("test four_lanes ... ok",
                               "test four_lanes ... \nthread 'x' panicked at PRIVATE_SENTINEL\nok")
        self.assertEqual(outcome(text)[-1]["test_result"], "ok")
        self.refuse(text.replace("PRIVATE_SENTINEL\nok", "PRIVATE_SENTINEL"),
                    "native_fixture_missing_terminal")

    def test_catalog_has_closed_schema_exact_types_and_fixed_scope(self):
        invalid = [None, {}, "fixtures", [None], [CASES[0], CASES[0]]]
        for changes in ({"cohort": "foreign"}, {"harness": "test/foreign"}, {"test": True},
                        {"test": "bad/name"}, {"test": "ordinary::model"}, {"extra": "secret"}):
            invalid.append([CASES[0] | changes])
        invalid.append([{k: v for k, v in CASES[0].items() if k != "cohort"}])
        invalid.append([CASES[-1] | {"test": "module::four_lanes"}])
        for rows in invalid:
            with self.subTest(rows=rows), self.assertRaises(InvalidEvidence):
                fixtures.fixture_outcomes(block(), rows, True)

    def test_explicit_empty_historical_catalog_still_requires_exact_command_types(self):
        self.assertEqual(fixtures.fixture_outcomes("historical cohort", [], True), [])
        for status in (0, 1, None, "passed"):
            with self.subTest(status=status), self.assertRaisesRegex(
                    InvalidEvidence, "invalid_native_fixture_command_status"):
                fixtures.fixture_outcomes(block(), [], status)
        with self.assertRaisesRegex(InvalidEvidence, "invalid_native_fixture_output"):
            fixtures.fixture_outcomes(None, [], True)

    def test_named_results_must_follow_one_announced_run_start(self):
        first = f"test {CASES[0]['test']} ... ok\n"
        text = block().replace("running 4 tests\n" + first, first + "running 4 tests\n")
        self.refuse(text, "native_fixture_before_start")
        self.refuse(block().replace("running 4 tests", "running 4 tests\nrunning 4 tests"),
                    "duplicate_native_fixture_start")
        self.refuse(block() + "running 1 test\n", "duplicate_native_fixture_start")

    def test_native_budget_module_has_an_exact_declared_namespace(self):
        row = CASES[0] | {"test": fixtures.PREFIXES[2] + "capacity_refusal"}
        text = header(fixtures.UNIT) + f"\nrunning 1 test\ntest {row['test']} ... ok\n" + summary(1)
        self.assertEqual(fixtures.fixture_outcomes(text, [row], True), [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False}])
        for test in (row["test"].replace("journal_native_budget_tests::", "journal_native_budget_tests_extra::"),
                     "capacity_refusal"):
            with self.subTest(test=test), self.assertRaisesRegex(InvalidEvidence, "invalid_native_fixture_scope"):
                fixtures.fixture_outcomes(text, [row | {"test": test}], True)

    def test_failed_command_keeps_observations_without_qualification(self):
        rows = outcome(block(), False)
        self.assertTrue(all(row["test_result"] == "ok" for row in rows))
        self.assertFalse(any(row["command_succeeded"] or row["qualified_run"] for row in rows))


class NamedFixtureRecorderTests(unittest.TestCase):
    def evidence(self, suffix=None, status="passed", exit_code=0):
        expected = corpus()
        expected["native_validation_fixtures"] = CASES
        expected["harness_test_counts"]["serial_launch"].update({
            fixtures.UNIT: {"tests": 4, "ignored": 0},
            fixtures.REFERENCE: {"tests": 1, "ignored": 0},
        })
        text = fixture_block() + native_block(expected["native_cases"])
        text += block() if suffix is None else suffix
        command = {"id": "serial_launch", "status": status, "exit_code": exit_code}
        run.command_evidence(command, text, expected)
        return command

    def test_named_cohorts_remain_separate_from_samples_and_dynamic_fixtures(self):
        command = self.evidence()
        self.assertEqual(command["status"], "passed")
        self.assertEqual(command["evidence_status"], "complete")
        self.assertEqual(len(command["native_cases"]), 50)
        self.assertEqual(len(command["dynamic_admission_fixtures"]), 7)
        self.assertEqual(command["dynamic_matrix_cases"], [])
        self.assertEqual(len(command["native_validation_fixtures"]), 4)
        self.assertFalse(any(row["qualified_run"] for row in command["native_validation_fixtures"]))

    def test_named_failure_invalidates_command_without_erasing_other_evidence(self):
        command = self.evidence(block().replace("test four_lanes ... ok", "test unknown ... ok"))
        self.assertEqual(command["status"], "invalid_evidence")
        self.assertEqual(command["native_fixture_parse_error"], "native_fixture_cohort_differs")
        self.assertEqual(len(command["native_cases"]), 50)
        self.assertEqual(len(command["dynamic_admission_fixtures"]), 7)
        self.assertEqual(command["native_validation_fixtures"][-1]["status"], "not_observed")

    def test_named_success_never_resets_aggregate_failure(self):
        command = self.evidence(block().replace("running 4 tests", "running 5 tests"))
        self.assertEqual(command["status"], "invalid_evidence")
        self.assertEqual(command["parse_error"], "changed_outer_cohort")
        self.assertTrue(all(row["status"] == "complete" for row in command["native_validation_fixtures"]))

    def test_failed_command_with_complete_named_results_remains_failed(self):
        for exit_code in (0, 101):
            with self.subTest(exit_code=exit_code):
                command = self.evidence(status="failed", exit_code=exit_code)
                self.assertEqual(command["status"], "failed")
                self.assertFalse(any(row["command_succeeded"] or row["qualified_run"]
                                     for row in command["native_validation_fixtures"]))

    def test_whole_protocol_qualifies_only_unchanged_successful_named_cases(self):
        rows = outcome(block()) + outcome(block(), False)
        for source, config, status, passed in (
                (True, True, "passed", True), (False, True, "passed", False),
                (True, False, "passed", False), (None, True, "passed", False),
                (True, True, "not_run", False), (True, True, "failed", False),
                (True, True, "invalid_evidence", False)):
            with self.subTest(source=source, config=config, status=status):
                record = {"source_unchanged": source, "configuration_unchanged": config,
                          "commands": [{"status": "passed", "native_validation_fixtures": copy.deepcopy(rows)},
                                       {"status": status}]}
                run.qualify(record)
                self.assertEqual(record["status"], "passed" if passed else "failed")
                self.assertEqual([r["qualified_run"] for r in record["commands"][0]["native_validation_fixtures"]],
                                 [passed] * 4 + [False] * 4)


if __name__ == "__main__":
    unittest.main()
