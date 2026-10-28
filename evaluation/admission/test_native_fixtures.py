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


def exec_parser_block():
    rows = list(fixtures.EXEC_PARSER_ROWS)
    text = (header(fixtures.EXEC_REFERENCE) + "\nrunning 2 tests\n"
            + "".join(f"test {row['test']} ... PRIVATE_SENTINEL\nok\n" for row in rows)
            + summary(2))
    return text, rows


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

        text, expected = exec_parser_block()
        actual = fixtures.fixture_outcomes(text, expected, True)
        self.assertEqual(actual, [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in expected])
        self.assertEqual({row["cohort"] for row in actual}, {"b3_exec_parser_control"})
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(actual))

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

        text, expected = exec_parser_block()
        first = f"test {expected[0]['test']} ... PRIVATE_SENTINEL\nok\n"
        for changed, code in ((text.replace(first, ""), "native_fixture_cohort_differs"),
                              (text.replace(first, first + first), "duplicate_native_fixture_test"),
                              (text.replace(expected[0]["test"], fixtures.EXEC_PARSER_PREFIX + "unknown"),
                               "native_fixture_cohort_differs")):
            with self.subTest(parser_control=code), self.assertRaisesRegex(InvalidEvidence, "^" + code + "$") as caught:
                fixtures.fixture_outcomes(changed, expected, True)
            self.assertEqual(len(caught.exception.partial), 2)
            self.assertFalse(any(row["qualified_run"] for row in caught.exception.partial))

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

        text, expected = exec_parser_block()
        for foreign in (fixtures.UNIT, "test/foreign"):
            with self.subTest(parser_control_harness=foreign), self.assertRaisesRegex(
                    InvalidEvidence, "^native_fixture_wrong_harness$"):
                fixtures.fixture_outcomes(text.replace(header(fixtures.EXEC_REFERENCE), header(foreign)), expected, True)

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

        text, expected = exec_parser_block()
        for terminal in ("FAILED", "ignored", "ignored, reason"):
            changed = text.replace("PRIVATE_SENTINEL\nok\n", "PRIVATE_SENTINEL\n" + terminal + "\n", 1)
            with self.subTest(parser_control_terminal=terminal), self.assertRaisesRegex(
                    InvalidEvidence, "^native_fixture_not_passed$") as caught:
                fixtures.fixture_outcomes(changed, expected, True)
            self.assertEqual(caught.exception.partial[0]["status"], "failed")
            self.assertEqual(caught.exception.partial[0]["test_result"],
                             "FAILED" if terminal == "FAILED" else "ignored")
            self.assertFalse(any(row["qualified_run"] for row in caught.exception.partial))

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

        text, expected = exec_parser_block()
        for changes in ({"cohort": "b3_exec"}, {"cohort": "b3_exec_parser_control_extra"},
                        {"harness": fixtures.UNIT}, {"test": expected[0]["test"] + "_extra"}):
            with self.subTest(parser_control_scope=changes), self.assertRaisesRegex(
                    InvalidEvidence, "^invalid_native_fixture_scope$"):
                fixtures.fixture_outcomes(text, [expected[0] | changes], True)

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


class SignalFixtureParsingTests(unittest.TestCase):
    # Synthetic protocol examples only. The real corpus pins actual native
    # trajectories and comparator controls separately by their exact names.
    rows = [
        {"cohort": "b3_signal", "harness": fixtures.SIGNAL_REFERENCE,
         "test": "ordinary_stack_frame_matches_pristine_original"},
        {"cohort": "b3_signal", "harness": fixtures.SIGNAL_REFERENCE,
         "test": "pristine_comparator_rejects_metadata_and_unrelated_state_corruption"},
    ]

    def capture(self, terminal="ok"):
        return (header(fixtures.SIGNAL_REFERENCE) + "\nrunning 2 tests\n"
                + f"test {self.rows[0]['test']} ... PRIVATE_SENTINEL\nok\n"
                + f"test {self.rows[1]['test']} ... {terminal}\n" + summary(2))

    def test_signal_cohort_retains_exact_named_outcomes_without_sample_claims(self):
        actual = fixtures.fixture_outcomes(self.capture(), self.rows, True)
        self.assertEqual(actual, [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in self.rows])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(actual))
        self.assertTrue(all(set(row) == {"cohort", "harness", "test", "status", "test_result",
                                        "command_succeeded", "qualified_run"} for row in actual))

    def test_signal_scope_cannot_substitute_reference_or_unit_harnesses(self):
        for changes in ({"cohort": "b2_reference"}, {"harness": fixtures.REFERENCE},
                        {"harness": fixtures.UNIT}, {"test": "nested::ordinary"},
                        {"cohort": "b3_signal_extra"}):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                    InvalidEvidence, "invalid_native_fixture_scope"):
                fixtures.fixture_outcomes(self.capture(), [self.rows[0] | changes], True)
        foreign = self.capture().replace(header(fixtures.SIGNAL_REFERENCE), header("test/foreign"))
        with self.assertRaisesRegex(InvalidEvidence, "native_fixture_wrong_harness"):
            fixtures.fixture_outcomes(foreign, self.rows, True)

    def test_signal_failure_ignore_missing_and_unknown_keep_partial_evidence(self):
        cases = [(self.capture(terminal), "native_fixture_not_passed", "failed", result)
                 for terminal, result in (("FAILED", "FAILED"), ("ignored", "ignored"))]
        missing = self.capture().replace(f"test {self.rows[1]['test']} ... ok\n", "")
        cases.append((missing, "native_fixture_cohort_differs", "not_observed", None))
        cases.append((self.capture().replace(self.rows[1]["test"], "unknown_private_name"),
                      "native_fixture_cohort_differs", "not_observed", None))
        for output, error, status, result in cases:
            with self.subTest(error=error, result=result), self.assertRaisesRegex(
                    InvalidEvidence, error) as caught:
                fixtures.fixture_outcomes(output, self.rows, True)
            rows = caught.exception.partial
            self.assertEqual(rows[0]["status"], "complete")
            self.assertEqual(rows[1]["status"], status)
            self.assertEqual(rows[1]["test_result"], result)
            self.assertFalse(any(row["qualified_run"] for row in rows))
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
            self.assertNotIn("unknown_private_name", json.dumps(rows))

    def test_signal_observations_require_command_and_whole_protocol_success(self):
        for succeeded in (False, True):
            for source_ok in (False, True):
                for terminal in ("passed", "failed", "not_run"):
                    with self.subTest(command=succeeded, source=source_ok, terminal=terminal):
                        rows = fixtures.fixture_outcomes(self.capture(), self.rows, succeeded)
                        record = {"source_unchanged": source_ok, "configuration_unchanged": True,
                                  "commands": [{"status": "passed" if succeeded else "failed",
                                                "native_validation_fixtures": rows},
                                               {"status": terminal}]}
                        run.qualify(record)
                        expected = succeeded and source_ok and terminal == "passed"
                        self.assertEqual(record["status"], "passed" if expected else "failed")
                        self.assertEqual([row["qualified_run"] for row in rows], [expected] * 2)
                        self.assertTrue(all(row["test_result"] == "ok" for row in rows))


class ResetFixtureParsingTests(unittest.TestCase):
    # These synthetic protocol rows do not run any reset helper or certify an
    # actual failure injection. The tracked corpus supplies the native names.
    rows = [
        {"cohort": "b3_reset", "harness": fixtures.UNIT,
         "test": fixtures.RESET_PREFIX + "packet_send_failure_retains_real_reaper_cleanup"},
        {"cohort": "b3_reset", "harness": fixtures.UNIT,
         "test": fixtures.RESET_PREFIX + "absent_pid_publication_does_not_mean_no_reaper"},
    ]

    def capture(self, terminal="ok"):
        return (header(fixtures.UNIT) + "\nrunning 3 tests\n"
                + "test ordinary::model ... ok\n"
                + f"test {self.rows[0]['test']} ... PRIVATE_SENTINEL\nok\n"
                + f"test {self.rows[1]['test']} ... {terminal}\n" + summary(3))

    def test_reset_cohort_records_exact_outcomes_without_native_sample_counts(self):
        rows = fixtures.fixture_outcomes(self.capture(), self.rows, True)
        self.assertEqual(rows, [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in self.rows])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
        self.assertTrue(all(set(row) == {"cohort", "harness", "test", "status", "test_result",
                                        "command_succeeded", "qualified_run"} for row in rows))

    def test_reset_scope_cannot_be_relabelled_as_journal_signal_or_ordinary(self):
        for changes in ({"cohort": "kernel_journal"}, {"cohort": "b3_signal"},
                        {"cohort": "b3_reset_extra"}, {"harness": fixtures.SIGNAL_REFERENCE},
                        {"test": "ordinary::model"},
                        {"test": self.rows[0]["test"].replace("reset::tests::", "reset_extra::tests::")}):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                    InvalidEvidence, "invalid_native_fixture_scope"):
                fixtures.fixture_outcomes(self.capture(), [self.rows[0] | changes], True)

    def test_unlisted_reset_tests_and_wrong_harnesses_cannot_supply_evidence(self):
        unknown = self.capture().replace(self.rows[1]["test"], fixtures.RESET_PREFIX + "unlisted")
        duplicate = self.capture().replace(self.rows[1]["test"], self.rows[0]["test"])
        wrong = self.capture().replace(header(fixtures.UNIT), header("test/foreign"))
        for text, code in ((unknown, "native_fixture_cohort_differs"),
                           (duplicate, "duplicate_native_fixture_test"),
                           (wrong, "native_fixture_wrong_harness")):
            with self.subTest(code=code), self.assertRaisesRegex(InvalidEvidence, code) as caught:
                fixtures.fixture_outcomes(text, self.rows, True)
            self.assertEqual(len(caught.exception.partial), len(self.rows))
            self.assertFalse(any(row["qualified_run"] for row in caught.exception.partial))

    def test_reset_failures_missing_cases_and_failed_commands_stay_unqualified(self):
        missing = self.capture().replace(f"test {self.rows[1]['test']} ... ok\n", "")
        for text, code, status, result in (
                (self.capture("FAILED"), "native_fixture_not_passed", "failed", "FAILED"),
                (self.capture("ignored"), "native_fixture_not_passed", "failed", "ignored"),
                (missing, "native_fixture_cohort_differs", "not_observed", None)):
            with self.subTest(code=code, result=result), self.assertRaisesRegex(InvalidEvidence, code) as caught:
                fixtures.fixture_outcomes(text, self.rows, True)
            rows = caught.exception.partial
            self.assertEqual(rows[0]["status"], "complete")
            self.assertEqual((rows[1]["status"], rows[1]["test_result"]), (status, result))
            self.assertFalse(any(row["qualified_run"] for row in rows))
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
        rows = fixtures.fixture_outcomes(self.capture(), self.rows, False)
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
