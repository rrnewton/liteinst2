"""Synthetic runtime recorder controls; no Rust or native request is executed."""

import copy
import json
from pathlib import Path
import unittest

import native_fixtures as fixtures
from parsing import InvalidEvidence
import run
from test_dynamic_admission import corpus, fixture_block, native_block, summary
from test_native_fixtures import header
from test_source_census_fixtures import named_capture
from test_runtime_inventory import OLD_NATIVE72_SHA256, RUNTIME_ROWS, before_runtime, digest

ROWS = list(RUNTIME_ROWS)
NAMES = [row["test"] for row in ROWS]
FIELDS = {"cohort", "harness", "test", "status", "test_result",
          "command_succeeded", "qualified_run"}


def capture(split=False):
    lines = [header(fixtures.UNIT), "running 18 tests"]
    for name in NAMES:
        lines.extend([f"test {name} ... PRIVATE_SENTINEL pid=12345 raw_state=[99]",
                      "thread 'owner' panicked at /private/source:42:1",
                      "PRIVATE_SENTINEL pc=0x900000 source_bytes=[15,162]", "ok"] if split
                     else [f"test {name} ... ok"])
    return "\n".join(lines + [summary(18)]) + "\n"


def command_evidence(suffix=None, status="passed", exit_code=0):
    expected = corpus()
    expected["native_validation_fixtures"] = copy.deepcopy(ROWS)
    expected["harness_test_counts"]["serial_launch"][fixtures.UNIT] = {"tests": 18, "ignored": 0}
    text = fixture_block() + native_block(expected["native_cases"])
    text += capture() if suffix is None else suffix
    command = {"id": "serial_launch", "status": status, "exit_code": exit_code}
    run.command_evidence(command, text, expected)
    return command


class RuntimeFixtureTests(unittest.TestCase):
    def partial(self, output, code, succeeded=True):
        with self.assertRaisesRegex(InvalidEvidence, "^" + code + "$") as caught:
            fixtures.fixture_outcomes(output, ROWS, succeeded)
        rows = caught.exception.partial
        self.assertEqual(len(rows), 18)
        self.assertEqual([{key: row[key] for key in ("cohort", "harness", "test")} for row in rows], ROWS)
        self.assertTrue(all(set(row) == FIELDS for row in rows))
        self.assertTrue(all(row["command_succeeded"] is succeeded for row in rows))
        self.assertFalse(any(row["qualified_run"] for row in rows))
        for private in ("PRIVATE_SENTINEL", "/private/", "12345", "0x900000", "raw_state", "source_bytes"):
            self.assertNotIn(private, json.dumps(rows))
            self.assertNotIn(private, str(caught.exception))
        return rows

    def test_exact_three_cohorts_export_six_five_five_fixture_rows_only(self):
        self.assertEqual(fixtures.RUNTIME_ROWS, RUNTIME_ROWS)
        self.assertEqual([len(names) for _, _, names in fixtures.RUNTIME_COHORTS], [6, 5, 5])
        self.assertEqual([len(names) for _, _, names in fixtures.CROSS_PAGE_COHORTS], [1, 1])
        for split in (False, True):
            observed = fixtures.fixture_outcomes(capture(split), ROWS, True)
            self.assertEqual(observed, [row | {"status": "complete", "test_result": "ok",
                "command_succeeded": True, "qualified_run": False} for row in ROWS])
            self.assertTrue(all(set(row) == FIELDS for row in observed))
            for word in ("PRIVATE_SENTINEL", "/private/", "12345", "raw_state", "source_bytes", "samples", "corruptions"):
                self.assertNotIn(word, json.dumps(observed))

    def test_catalog_rejects_every_wrong_harness_cohort_and_known_name_relabelling(self):
        for row in ROWS:
            for change in ({"cohort": "kernel_journal"}, {"cohort": "b3_runtime"},
                           {"cohort": "b3_runtime_startup" if row["cohort"] != "b3_runtime_startup" else "b3_runtime_selected"},
                           {"harness": fixtures.EXEC_REFERENCE}, {"harness": fixtures.SIGNAL_REFERENCE},
                           {"harness": "unit/foreign/lib"}, {"test": row["test"] + "_extra"},
                           {"test": "module::" + row["test"]}, {"test": "unlisted_runtime_case"}):
                with self.subTest(row=row, change=change), self.assertRaisesRegex(
                        InvalidEvidence, "^invalid_native_fixture_scope$"):
                    fixtures.catalog([row | change])
        for change in ({"test": True}, {"test": "bad/name"}, {"extra": "PRIVATE_SENTINEL"}):
            with self.assertRaisesRegex(InvalidEvidence, "^invalid_native_fixture_catalog$"):
                fixtures.catalog([ROWS[0] | change])
        with self.assertRaisesRegex(InvalidEvidence, "^duplicate_native_fixture_catalog$"):
            fixtures.catalog(ROWS + [ROWS[0]])

    def test_wrong_harness_unknown_names_and_malformed_control_structure_refuse(self):
        for wrong in (fixtures.EXEC_REFERENCE, fixtures.SIGNAL_REFERENCE, "unit/foreign/lib", "test/foreign"):
            rows = self.partial(capture().replace(header(fixtures.UNIT), header(wrong)),
                                "native_fixture_wrong_harness")
            self.assertTrue(all(row["status"] == "not_observed" for row in rows))
        for cohort, prefix, names in fixtures.RUNTIME_COHORTS + fixtures.CROSS_PAGE_COHORTS:
            for unknown in (prefix + "unlisted", prefix + "nested::unlisted",
                            prefix.removesuffix("::") + "_extra::unlisted"):
                rows = self.partial(capture().replace(NAMES[-1], unknown), "native_fixture_cohort_differs")
                self.assertEqual([row["status"] for row in rows], ["complete"] * 17 + ["not_observed"])
        self.partial(capture().replace(NAMES[0], "bad/name"), "invalid_native_fixture_name")
        self.partial(capture().replace("target/debug/deps/", "/PRIVATE_SENTINEL/"), "invalid_harness_binary_path")
        self.partial(capture().replace("Running unittests", "Running invalid"), "unrecognized_harness_header")
        self.partial(capture() + capture(), "duplicate_native_fixture_harness")
        self.partial(capture().replace("running 18 tests\n", "running 18 tests\nrunning 18 tests\n"),
                     "duplicate_native_fixture_start")
        self.partial(capture() + "test unrelated ... ok\n", "native_fixture_after_summary")

    def test_each_missing_duplicate_and_unfinished_result_keeps_exact_failure_prefix(self):
        self.partial("PRIVATE_SENTINEL", "missing_native_fixture_harness")
        for index, name in enumerate(NAMES):
            line = f"test {name} ... ok\n"
            rows = self.partial(capture().replace(line, ""), "native_fixture_cohort_differs")
            self.assertEqual(rows[index]["status"], "not_observed")
            self.assertEqual(sum(row["status"] == "complete" for row in rows), 17)
            rows = self.partial(capture().replace(line, line + line), "duplicate_native_fixture_test")
            self.assertEqual(sum(row["status"] == "complete" for row in rows), index + 1)
            self.assertTrue(all(row["status"] == "not_observed" for row in rows[index + 1:]))
            prefix = capture().split(line, 1)[0] + f"test {name} ... PRIVATE_SENTINEL\n"
            for suffix in ("", summary(18), header("test/foreign")):
                rows = self.partial(prefix + suffix, "native_fixture_missing_terminal")
                self.assertEqual((rows[index]["status"], rows[index]["test_result"]), ("incomplete", None))
                self.assertEqual(sum(row["status"] == "complete" for row in rows), index)

    def test_failed_ignored_and_expected_panic_text_never_supply_success(self):
        for index, name in enumerate(NAMES):
            line = f"test {name} ... ok\n"
            for terminal in ("FAILED", "ignored", "ignored, PRIVATE_SENTINEL unsupported"):
                rows = self.partial(capture().replace(line, f"test {name} ... {terminal}\n"),
                                    "native_fixture_not_passed", False)
                self.assertEqual((rows[index]["status"], rows[index]["test_result"]),
                                 ("failed", "FAILED" if terminal == "FAILED" else "ignored"))
                self.assertEqual(sum(row["status"] == "complete" for row in rows), 17)
        last = f"test {NAMES[-1]} ... ok\n"
        self.partial(capture().replace(last, f"test {NAMES[-1]} ... \nthread 'owner' panicked at PRIVATE_SENTINEL\n"),
                     "native_fixture_missing_terminal", False)

    def test_unlisted_native_modules_cannot_hide_among_unrelated_pure_units(self):
        pure = "test linux::remote::dynamic::owner::admission::runtime::tests::pure_model ... ok\n"
        mixed = capture().replace("running 18 tests", "running 19 tests").replace(summary(18), pure + summary(19))
        self.assertEqual(fixtures.fixture_outcomes(mixed, ROWS, True), [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in ROWS])
        for _, prefix, _ in fixtures.RUNTIME_COHORTS + fixtures.CROSS_PAGE_COHORTS:
            for unknown in (prefix + "unlisted", prefix + "nested::unlisted", prefix.removesuffix("::") + "_extra::unlisted"):
                text = mixed.replace("running 19 tests", "running 20 tests").replace(
                    summary(19), f"test {unknown} ... ok\n" + summary(20))
                rows = self.partial(text, "native_fixture_cohort_differs")
                self.assertTrue(all(row["status"] == "complete" for row in rows))

    def test_named_ok_cannot_override_aggregate_source_config_command_or_cleanup_failure(self):
        clean = command_evidence()
        self.assertEqual((clean["status"], clean["evidence_status"]), ("passed", "complete"))
        self.assertEqual(len(clean["native_cases"]), 50)
        self.assertEqual(len(clean["dynamic_admission_fixtures"]), 7)
        self.assertEqual(clean["dynamic_matrix_cases"], [])
        aggregate = command_evidence(capture().replace("running 18 tests", "running 19 tests"))
        self.assertEqual((aggregate["status"], aggregate["parse_error"]), ("invalid_evidence", "changed_outer_cohort"))
        failed = command_evidence(status="failed", exit_code=101)
        # Existing execution infrastructure converts failed physical cleanup to
        # command failure before qualification; this row is synthetic evidence.
        cleanup_failed = copy.deepcopy(clean)
        cleanup_failed.update(status="failed", cleanup_complete=False)
        for value, source, config, other, wanted in ((clean, True, True, "passed", True),
                (aggregate, True, True, "passed", False), (failed, True, True, "passed", False),
                (cleanup_failed, True, True, "passed", False), (clean, False, True, "passed", False),
                (clean, True, False, "passed", False), (clean, None, True, "passed", False),
                (clean, True, True, "failed", False), (clean, True, True, "not_run", False)):
            commands = [{"id": name, "status": "passed"} for name, _, _ in run.COMMANDS]
            for index, command in enumerate(commands):
                if command["id"] == "serial_launch": commands[index] = copy.deepcopy(value)
                elif command["id"] == "workspace_check": command["status"] = other
            record = {"source_unchanged": source, "configuration_unchanged": config, "commands": commands}
            run.qualify(record)
            self.assertEqual(record["status"], "passed" if wanted else "failed")
            observed = next(row for row in commands if row["id"] == "serial_launch")["native_validation_fixtures"]
            self.assertEqual(len(observed), 18)
            self.assertTrue(all(row["qualified_run"] is wanted for row in observed))
        self.assertFalse(any(row["command_succeeded"] or row["qualified_run"]
                             for row in failed["native_validation_fixtures"]))

    def test_complete_old_and_new_catalog_keeps_all72_names_and_missing_old_refusals(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        before_runtime(declared)
        rows = declared["native_validation_fixtures"]
        self.assertEqual(rows[56:74], ROWS)
        # The original 72 identities remain an exact ordered prefix.
        self.assertEqual(digest(rows[:72]), OLD_NATIVE72_SHA256)
        output = named_capture(rows)
        self.assertEqual(fixtures.fixture_outcomes(output, rows, True), [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in rows])
        for index, missing in enumerate(rows):
            with self.subTest(test=missing["test"]), self.assertRaisesRegex(
                    InvalidEvidence, "^native_fixture_cohort_differs$") as caught:
                fixtures.fixture_outcomes(output.replace(f"test {missing['test']} ... ok\n", ""), rows, True)
            partial = caught.exception.partial
            self.assertEqual(len(partial), 75)
            self.assertEqual((partial[index]["status"], partial[index]["test_result"]), ("not_observed", None))
            self.assertEqual(sum(row["status"] == "complete" for row in partial), 74)
            self.assertFalse(any(row["qualified_run"] for row in partial))
