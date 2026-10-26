"""Closed wait-custody inventory and synthetic recorder controls; no native runs."""

import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

import native_fixtures as fixtures
from parsing import InvalidEvidence, require


PRE_WAIT_CORPUS_SHA256 = "1cc2de152567d2cc92e8efa9250f8112700ea335677ad7280d527ef69e6f3d49"
OLD_NATIVE74_SHA256 = "9732bf57d0638f3821e3ecfee8ef6f4fc3eb547553d5aa971a3e0a5ba7b55c4f"
WAIT_ROOT = "linux::remote::dynamic::owner::tests::wait_withdrawal"
WAIT_NAME = WAIT_ROOT + "::actual_listen_withdrawal_preserves_pinned_wait_and_cleanup"
WAIT_ROW = {"cohort": "b3_wait_custody", "harness": "unit/liteinst_launch/lib", "test": WAIT_NAME}
WAIT_SOURCE = "crates/liteinst-launch/src/linux/remote/dynamic/owner/tests/wait_withdrawal.rs"
FIELDS = {"cohort", "harness", "test", "status", "test_result", "command_succeeded", "qualified_run"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def before_wait_custody(declared):
    """Authenticate this complete addition before historical test projection.

    This is a test-only historical view, never a recorder acceptance fallback.
    The prior corpus digest binds every old count, row, helper and collection.
    """
    require(type(declared) is dict, "wait_custody_inventory_differs")
    require(type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 273, "wait_custody_inventory_differs")
    rows = declared.get("native_validation_fixtures")
    require(type(rows) is list and len(rows) == 75 and rows[74:] == [WAIT_ROW],
            "wait_custody_inventory_differs")
    fixtures.catalog(rows)
    require(digest(rows[:74]) == OLD_NATIVE74_SHA256, "wait_custody_inventory_differs")
    cohorts = declared.get("harness_test_counts")
    require(type(cohorts) is dict and set(cohorts) == {"workspace_tests", "serial_launch"},
            "wait_custody_inventory_differs")
    for name in ("workspace_tests", "serial_launch"):
        require(type(cohorts[name]) is dict
                and cohorts[name].get(fixtures.UNIT) == {"tests": 494, "ignored": 0},
                "wait_custody_inventory_differs")
        require(type(cohorts[name][fixtures.UNIT]["tests"]) is int
                and type(cohorts[name][fixtures.UNIT]["ignored"]) is int,
                "wait_custody_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["recorder_tests"] = 265
    previous["native_validation_fixtures"] = previous["native_validation_fixtures"][:74]
    for cohort in previous["harness_test_counts"].values():
        cohort[fixtures.UNIT] = {"tests": 493, "ignored": 0}
    require(digest(previous) == PRE_WAIT_CORPUS_SHA256, "wait_custody_inventory_differs")
    return previous


def capture(split=False):
    lines = ["     Running unittests src/lib.rs (target/debug/deps/liteinst_launch-123abc)",
             "running 1 test"]
    if split:
        lines.extend([f"test {WAIT_NAME} ... PRIVATE_SENTINEL pid=12345 raw_wait=127",
                      "thread 'owner' panicked at /private/source:42:1",
                      "PRIVATE_SENTINEL state=[99] pc=0x900000", "ok"])
    else:
        lines.append(f"test {WAIT_NAME} ... ok")
    lines.append("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s")
    return "\n".join(lines) + "\n"


class WaitCustodyFixtureTests(unittest.TestCase):
    def partial(self, output, code, succeeded=True):
        with self.assertRaisesRegex(InvalidEvidence, "^" + code + "$") as caught:
            fixtures.fixture_outcomes(output, [WAIT_ROW], succeeded)
        rows = caught.exception.partial
        self.assertEqual(len(rows), 1)
        self.assertEqual({key: rows[0][key] for key in ("cohort", "harness", "test")}, WAIT_ROW)
        self.assertEqual(set(rows[0]), FIELDS)
        self.assertIs(rows[0]["command_succeeded"], succeeded)
        self.assertFalse(rows[0]["qualified_run"])
        for private in ("PRIVATE_SENTINEL", "/private/", "12345", "0x900000", "raw_wait", "state="):
            self.assertNotIn(private, json.dumps(rows))
            self.assertNotIn(private, str(caught.exception))
        return rows[0]

    def test_wait_custody_source_is_one_separate_native_case_with_exact_additive_counts(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / WAIT_SOURCE).read_text()
        self.assertEqual(re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source),
                         ["actual_listen_withdrawal_preserves_pinned_wait_and_cleanup"])
        self.assertNotRegex(source, r"#\[ignore(?:\]|\()")
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        original = copy.deepcopy(declared)
        previous = before_wait_custody(declared)
        self.assertEqual(declared, original)
        self.assertEqual(digest(previous), PRE_WAIT_CORPUS_SHA256)
        self.assertEqual(digest(declared["native_validation_fixtures"][:74]), OLD_NATIVE74_SHA256)
        self.assertEqual(declared["native_validation_fixtures"][74:], [WAIT_ROW])
        self.assertEqual(list(fixtures.RUNTIME_ROWS), previous["native_validation_fixtures"][56:])
        self.assertEqual(len(fixtures.RUNTIME_ROWS), 18)
        self.assertNotIn(WAIT_ROW, fixtures.RUNTIME_ROWS)
        for name, harnesses, total, ignores in (("workspace_tests", 89, 1870, 4),
                                               ("serial_launch", 27, 786, 0)):
            current = declared["harness_test_counts"][name]
            self.assertEqual(len(current), harnesses)
            self.assertEqual(sum(row["tests"] for row in current.values()), total)
            self.assertEqual(sum(row["ignored"] for row in current.values()), ignores)
            self.assertEqual(current[fixtures.UNIT], {"tests": 494, "ignored": 0})
            self.assertEqual({key: value for key, value in current.items() if key != fixtures.UNIT},
                             {key: value for key, value in previous["harness_test_counts"][name].items()
                              if key != fixtures.UNIT})
        self.assertEqual(declared["recorder_tests"], 273)
        self.assertEqual(len(fixtures.catalog(declared["native_validation_fixtures"])), 75)
        for field, count in (("native_cases", 50), ("dynamic_admission_fixtures", 15),
                             ("dynamic_matrix_cases", 388)):
            self.assertEqual(declared[field], previous[field])
            self.assertEqual(len(declared[field]), count)
        self.assertEqual(declared["backing_cleanup_harnesses"], previous["backing_cleanup_harnesses"])

    def test_wait_custody_projection_rejects_every_changed_new_row_or_historical_inventory(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        for change in ("missing", "duplicate", "position", "cohort", "harness", "test", "extra"):
            changed = copy.deepcopy(declared)
            rows = changed["native_validation_fixtures"]
            if change == "missing": rows.pop()
            elif change == "duplicate": rows.append(copy.deepcopy(rows[-1]))
            elif change == "position": rows[-1], rows[-2] = rows[-2], rows[-1]
            elif change == "extra": rows[-1]["extra"] = "PRIVATE_SENTINEL"
            else: rows[-1][change] = "PRIVATE_SENTINEL"
            with self.subTest(change=change), self.assertRaises(InvalidEvidence) as caught:
                before_wait_custody(changed)
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for change in ("recorder", "unit", "unit_type", "ignored_type", "old_unit", "old_native",
                       "runtime", "static", "dynamic", "matrix", "helper", "baseline"):
            changed = copy.deepcopy(declared)
            if change == "recorder": changed["recorder_tests"] -= 1
            elif change == "unit": changed["harness_test_counts"]["workspace_tests"][fixtures.UNIT]["tests"] -= 1
            elif change == "unit_type": changed["harness_test_counts"]["serial_launch"][fixtures.UNIT]["tests"] = 494.0
            elif change == "ignored_type": changed["harness_test_counts"]["workspace_tests"][fixtures.UNIT]["ignored"] = False
            elif change == "old_unit": changed["harness_test_counts"]["serial_launch"]["test/dynamic_fork"]["tests"] -= 1
            elif change == "old_native": changed["native_validation_fixtures"][0]["test"] += "_extra"
            elif change == "runtime": changed["native_validation_fixtures"][56]["test"] += "_extra"
            elif change == "static": changed["native_cases"].pop()
            elif change == "dynamic": changed["dynamic_admission_fixtures"].pop()
            elif change == "matrix": changed["dynamic_matrix_cases"].pop()
            elif change == "helper": changed["backing_cleanup_harnesses"]["serial_launch"][0]["trajectories"].pop()
            else: changed["baseline_revision"] = "0" * 40
            with self.subTest(change=change), self.assertRaises(InvalidEvidence):
                before_wait_custody(changed)

    def test_wait_custody_catalog_requires_exact_closed_name_cohort_and_harness(self):
        self.assertEqual(fixtures.WAIT_CUSTODY_ROOT, WAIT_ROOT)
        self.assertEqual(fixtures.WAIT_CUSTODY_ROW, WAIT_ROW)
        self.assertEqual(fixtures.catalog([WAIT_ROW]), {(fixtures.UNIT, WAIT_NAME): WAIT_ROW})
        for change in ({"cohort": "kernel_journal"}, {"cohort": "b3_runtime_startup"},
                       {"cohort": "b3_wait"}, {"harness": fixtures.EXEC_REFERENCE},
                       {"harness": "unit/foreign/lib"}, {"test": WAIT_NAME + "_extra"},
                       {"test": WAIT_ROOT + "::nested::unlisted"},
                       {"test": WAIT_ROOT + "_extra::unlisted"},
                       {"test": WAIT_NAME.rsplit("::", 1)[-1]}, {"test": "module::" + WAIT_NAME}):
            with self.subTest(change=change), self.assertRaisesRegex(
                    InvalidEvidence, "^invalid_native_fixture_scope$"):
                fixtures.catalog([WAIT_ROW | change])
        for change in ({"test": True}, {"test": "bad/name"}, {"extra": "PRIVATE_SENTINEL"}):
            with self.assertRaisesRegex(InvalidEvidence, "^invalid_native_fixture_catalog$"):
                fixtures.catalog([WAIT_ROW | change])
        with self.assertRaisesRegex(InvalidEvidence, "^duplicate_native_fixture_catalog$"):
            fixtures.catalog([WAIT_ROW, WAIT_ROW])

    def test_wait_custody_inline_and_split_results_export_only_typed_public_fields(self):
        for split in (False, True):
            actual = fixtures.fixture_outcomes(capture(split), [WAIT_ROW], True)
            self.assertEqual(actual, [WAIT_ROW | {"status": "complete", "test_result": "ok",
                "command_succeeded": True, "qualified_run": False}])
            self.assertEqual(set(actual[0]), FIELDS)
            for private in ("PRIVATE_SENTINEL", "/private/", "12345", "raw_wait", "state=", "pc=",
                            "samples", "corruptions"):
                self.assertNotIn(private, json.dumps(actual))

    def test_wait_custody_missing_duplicate_and_unfinished_result_keep_exact_partial_status(self):
        line = f"test {WAIT_NAME} ... ok\n"
        absent = self.partial(capture().replace(line, ""), "native_fixture_cohort_differs")
        self.assertEqual((absent["status"], absent["test_result"]), ("not_observed", None))
        duplicate = self.partial(capture().replace(line, line + line), "duplicate_native_fixture_test")
        self.assertEqual((duplicate["status"], duplicate["test_result"]), ("complete", "ok"))
        prefix = capture().split(line, 1)[0] + f"test {WAIT_NAME} ... PRIVATE_SENTINEL\n"
        for suffix in ("", capture().splitlines()[-1],
                       "     Running tests/foreign.rs (target/debug/deps/foreign-123abc)\n"):
            unfinished = self.partial(prefix + suffix, "native_fixture_missing_terminal")
            self.assertEqual((unfinished["status"], unfinished["test_result"]), ("incomplete", None))
        self.partial("PRIVATE_SENTINEL", "missing_native_fixture_harness")
        self.partial(capture() + capture(), "duplicate_native_fixture_harness")
        self.partial(capture().replace("target/debug/deps/", "/PRIVATE_SENTINEL/"),
                     "invalid_harness_binary_path")

    def test_wait_custody_failed_ignored_or_failed_command_never_qualifies(self):
        for terminal in ("FAILED", "ignored", "ignored, PRIVATE_SENTINEL unsupported"):
            result = self.partial(capture().replace(f"test {WAIT_NAME} ... ok",
                f"test {WAIT_NAME} ... {terminal}"), "native_fixture_not_passed", False)
            self.assertEqual((result["status"], result["test_result"]),
                             ("failed", "FAILED" if terminal == "FAILED" else "ignored"))
        result = fixtures.fixture_outcomes(capture(), [WAIT_ROW], False)
        self.assertEqual(result, [WAIT_ROW | {"status": "complete", "test_result": "ok",
            "command_succeeded": False, "qualified_run": False}])
        text = capture().split(f"test {WAIT_NAME} ... ok", 1)[0]
        text += f"test {WAIT_NAME} ... \nthread 'owner' panicked at PRIVATE_SENTINEL\n"
        self.assertEqual(self.partial(text, "native_fixture_missing_terminal", False)["status"], "incomplete")

    def test_wait_custody_wrong_harness_and_unlisted_closed_root_cannot_hide_as_pure_units(self):
        original_header = capture().splitlines()[0]
        for name in ("foreign", "b3_exec_admission", "b3_signal_admission"):
            wrong_header = f"     Running tests/{name}.rs (target/debug/deps/{name}-123abc)"
            row = self.partial(capture().replace(original_header, wrong_header), "native_fixture_wrong_harness")
            self.assertEqual(row["status"], "not_observed")
        pure = "test linux::remote::dynamic::owner::tests::pure_model ... ok\n"
        mixed = capture().replace("running 1 test\n", "running 2 tests\n").replace(
            "test result: ok. 1 passed;", pure + "test result: ok. 2 passed;")
        self.assertEqual(fixtures.fixture_outcomes(mixed, [WAIT_ROW], True), [WAIT_ROW | {
            "status": "complete", "test_result": "ok", "command_succeeded": True, "qualified_run": False}])
        for name in (WAIT_NAME + "_extra", WAIT_ROOT + "::unlisted", WAIT_ROOT + "::nested::unlisted",
                     WAIT_ROOT + "_extra::unlisted"):
            row = self.partial(capture().replace(WAIT_NAME, name), "native_fixture_cohort_differs")
            self.assertEqual(row["status"], "not_observed")
            appended = mixed.replace("running 2 tests\n", "running 3 tests\n").replace(
                "test result: ok. 2 passed;", f"test {name} ... ok\ntest result: ok. 3 passed;")
            row = self.partial(appended, "native_fixture_cohort_differs")
            self.assertEqual((row["status"], row["test_result"]), ("complete", "ok"))

    def test_wait_custody_full_catalog_preserves_all74_names_and_requires_every_old_and_new_case(self):
        # Import after module initialization: historical controls themselves
        # import this module's strict projection helper.
        from test_source_census_fixtures import named_capture

        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        previous = before_wait_custody(declared)
        rows = declared["native_validation_fixtures"]
        self.assertEqual(rows[:74], previous["native_validation_fixtures"])
        self.assertEqual(rows[74:], [WAIT_ROW])
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
