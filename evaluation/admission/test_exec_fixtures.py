"""Synthetic exec recorder controls. These do not execute native fixtures."""

import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

import native_fixtures as fixtures
from parsing import InvalidEvidence
import run
from test_dynamic_admission import corpus, fixture_block, native_block, summary
from test_native_fixtures import header
from test_source_census_fixtures import named_capture


HARNESS = "test/b3_exec_admission"
NAMES = (
    "original_exec_replacement_matches_raw_replay_and_native_full_state",
    "stale_exec_source_reply_preserves_actual_replacement_without_commit",
    "resolver_panic_after_actual_exec_keeps_original_failure_and_cleanup",
    "blocked_exec_resolver_uses_original_deadline_and_owner_cleanup",
    "exec_full_comparator_rejects_each_state_input_map_and_identity_corruption",
)
ROWS = [{"cohort": "b3_exec", "harness": HARNESS, "test": name} for name in NAMES]
PRIVATE_NAMES = (
    "admitted_exec_native_first_user_and_retired_history_are_exact",
    "admitted_exec_native_source_reply_refusal_keeps_new_mm_held",
    "admitted_exec_native_errno_exit_never_mints_replacement",
)
PRIVATE_ROWS = [{"cohort": "b3_exec_private", "harness": fixtures.UNIT,
                 "test": fixtures.EXEC_PRIVATE_PREFIX + name} for name in PRIVATE_NAMES]
# Source-derived additive cohorts. Every count is bound to its exact file below.
UNIT_INCREMENT = 67
FIELDS = {"cohort", "harness", "test", "status", "test_result",
          "command_succeeded", "qualified_run"}


def capture(split=False):
    lines = [header(HARNESS), "running 5 tests"]
    for name in NAMES:
        lines.extend([f"test {name} ... PRIVATE_SENTINEL pid=12345 raw_state=[99]",
                      "PRIVATE_SENTINEL /private/source:42:1", "ok"] if split
                     else [f"test {name} ... ok"])
    return "\n".join(lines + [summary(5)]) + "\n"


def command_evidence(suffix=None, status="passed", exit_code=0):
    expected = corpus()
    expected["native_validation_fixtures"] = copy.deepcopy(ROWS)
    expected["harness_test_counts"]["serial_launch"][HARNESS] = {"tests": 5, "ignored": 0}
    text = fixture_block() + native_block(expected["native_cases"])
    text += capture() if suffix is None else suffix
    command = {"id": "serial_launch", "status": status, "exit_code": exit_code}
    run.command_evidence(command, text, expected)
    return command


class ExecFixtureTests(unittest.TestCase):
    def partial(self, text, reason, succeeded=True):
        with self.assertRaisesRegex(InvalidEvidence, "^" + reason + "$") as caught:
            fixtures.fixture_outcomes(text, ROWS, succeeded)
        rows = caught.exception.partial
        self.assertEqual(len(rows), 5)
        self.assertEqual([{key: row[key] for key in ("cohort", "harness", "test")}
                          for row in rows], ROWS)
        self.assertTrue(all(set(row) == FIELDS for row in rows))
        self.assertTrue(all(row["command_succeeded"] is succeeded for row in rows))
        self.assertFalse(any(row["qualified_run"] for row in rows))
        for secret in ("PRIVATE_SENTINEL", "/private/", "12345", "raw_state"):
            self.assertNotIn(secret, json.dumps(rows))
            self.assertNotIn(secret, str(caught.exception))
        return rows

    def test_exact_inline_split_outcomes_have_no_raw_state_or_sample_inference(self):
        self.assertEqual(fixtures.EXEC_REFERENCE, HARNESS)
        self.assertEqual(fixtures.EXEC_TESTS, frozenset(NAMES))
        for split in (False, True):
            rows = fixtures.fixture_outcomes(capture(split), ROWS, True)
            self.assertEqual(rows, [row | {"status": "complete", "test_result": "ok",
                             "command_succeeded": True, "qualified_run": False} for row in ROWS])
            self.assertTrue(all(set(row) == FIELDS for row in rows))

    def test_catalog_and_harness_reject_relabelled_or_unlisted_exec_names(self):
        for row in ROWS:
            for change in ({"cohort": "b3_exec_extra"}, {"cohort": "b3_mapping"},
                           {"harness": fixtures.UNIT}, {"harness": fixtures.MAPPING_REFERENCE},
                           {"test": row["test"] + "_extra"},
                           {"test": "module::" + row["test"]},
                           {"cohort": "b2_reference", "harness": fixtures.REFERENCE}):
                with self.subTest(change=change), self.assertRaisesRegex(
                        InvalidEvidence, "^invalid_native_fixture_scope$"):
                    fixtures.catalog([row | change])
        with self.assertRaisesRegex(InvalidEvidence, "^duplicate_native_fixture_catalog$"):
            fixtures.catalog(ROWS + [ROWS[0]])
        for name in (NAMES[0] + "_extra", "module::" + NAMES[0], "unlisted_exec_case"):
            self.partial(capture().replace(NAMES[-1], name), "native_fixture_cohort_differs")
        for wrong in (fixtures.UNIT, fixtures.REFERENCE, fixtures.MAPPING_REFERENCE, "test/foreign"):
            self.partial(capture().replace(header(HARNESS), header(wrong)), "native_fixture_wrong_harness")

    def test_every_missing_duplicate_failure_and_unfinished_case_retains_its_prefix(self):
        self.partial("PRIVATE_SENTINEL", "missing_native_fixture_harness")
        self.partial(capture() + capture(), "duplicate_native_fixture_harness")
        self.partial(capture().replace("running 5 tests\n", "running 5 tests\nrunning 5 tests\n"),
                     "duplicate_native_fixture_start")
        for index, name in enumerate(NAMES):
            line = f"test {name} ... ok\n"
            missing = self.partial(capture().replace(line, ""), "native_fixture_cohort_differs")
            self.assertEqual(missing[index]["status"], "not_observed")
            self.assertEqual(sum(row["status"] == "complete" for row in missing), 4)
            duplicate = self.partial(capture().replace(line, line + line), "duplicate_native_fixture_test")
            self.assertEqual(sum(row["status"] == "complete" for row in duplicate), index + 1)
            for terminal in ("FAILED", "ignored", "ignored, PRIVATE_SENTINEL"):
                rows = self.partial(capture().replace(line, f"test {name} ... {terminal}\n"),
                                    "native_fixture_not_passed", False)
                self.assertEqual((rows[index]["status"], rows[index]["test_result"]),
                                 ("failed", "FAILED" if terminal == "FAILED" else "ignored"))
            prefix = capture().split(line, 1)[0] + f"test {name} ... PRIVATE_SENTINEL\n"
            for suffix in ("", summary(5), header("test/foreign")):
                rows = self.partial(prefix + suffix, "native_fixture_missing_terminal")
                self.assertEqual((rows[index]["status"], rows[index]["test_result"]), ("incomplete", None))
                self.assertEqual(sum(row["status"] == "complete" for row in rows), index)

    def test_named_ok_cannot_override_aggregate_source_configuration_or_cleanup_failure(self):
        clean = command_evidence()
        self.assertEqual((clean["status"], clean["evidence_status"]), ("passed", "complete"))
        changed = command_evidence(capture().replace("running 5 tests", "running 6 tests"))
        self.assertEqual((changed["status"], changed["parse_error"]),
                         ("invalid_evidence", "changed_outer_cohort"))
        for source, config, failed_command, wanted in (
                (True, True, None, True), (False, True, None, False),
                (True, False, None, False), (None, True, None, False),
                (True, True, "serial_launch", False), (True, True, "workspace_check", False)):
            commands = [{"id": name, "status": "passed"} for name, _, _ in run.COMMANDS]
            for index, command in enumerate(commands):
                if command["id"] == "serial_launch":
                    commands[index] = copy.deepcopy(clean)
                if command["id"] == failed_command:
                    commands[index]["status"] = "failed"
            record = {"source_unchanged": source, "configuration_unchanged": config, "commands": commands}
            run.qualify(record)
            self.assertEqual(record["status"], "passed" if wanted else "failed")
            rows = next(command for command in commands if command["id"] == "serial_launch")["native_validation_fixtures"]
            self.assertTrue(all(row["qualified_run"] is wanted for row in rows))
        failed = command_evidence(status="failed", exit_code=101)
        self.assertFalse(any(row["command_succeeded"] or row["qualified_run"]
                             for row in failed["native_validation_fixtures"]))

    def test_five_declared_public_outcomes_match_exact_source_names_and_denominators(self):
        path = Path(__file__).with_name("corpus.json")
        declared = json.loads(path.read_text())
        self.assertEqual([row for row in declared["native_validation_fixtures"]
                          if row["cohort"] == "b3_exec"], ROWS)
        source = path.parents[2] / "crates/liteinst-launch/tests/b3_exec_admission.rs"
        names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source.read_text())
        self.assertEqual(names, list(NAMES))
        for command in ("workspace_tests", "serial_launch"):
            self.assertEqual(declared["harness_test_counts"][command][HARNESS], {"tests": 5, "ignored": 0})
        self.assertEqual(len(declared["native_cases"]), 50)
        self.assertEqual(len(declared["dynamic_admission_fixtures"]), 15)
        self.assertEqual(len(declared["dynamic_matrix_cases"]), 388)

    def test_private_native_scope_prefix_and_each_failure_remain_exact(self):
        self.assertEqual(fixtures.EXEC_PRIVATE_TESTS, frozenset(row["test"] for row in PRIVATE_ROWS))
        valid = named_capture(PRIVATE_ROWS)
        self.assertEqual(fixtures.fixture_outcomes(valid, PRIVATE_ROWS, True), [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in PRIVATE_ROWS])
        for row in PRIVATE_ROWS:
            for change in ({"cohort": "kernel_journal"}, {"cohort": "b3_exec"},
                           {"harness": HARNESS}, {"test": row["test"] + "_extra"}):
                with self.subTest(change=change), self.assertRaisesRegex(
                        InvalidEvidence, "^invalid_native_fixture_scope$"):
                    fixtures.catalog([row | change])
            line = f"test {row['test']} ... ok\n"
            for output, reason in (
                    (valid.replace(line, ""), "native_fixture_cohort_differs"),
                    (valid.replace(line, line + line), "duplicate_native_fixture_test"),
                    (valid.replace(line, line.replace("ok", "FAILED")), "native_fixture_not_passed"),
                    (valid.replace(line, line.replace("ok", "ignored")), "native_fixture_not_passed"),
                    (valid.replace(row["test"], fixtures.EXEC_PRIVATE_PREFIX + "unlisted"), "native_fixture_cohort_differs")):
                with self.subTest(reason=reason), self.assertRaisesRegex(InvalidEvidence, "^" + reason + "$") as caught:
                    fixtures.fixture_outcomes(output, PRIVATE_ROWS, False)
                self.assertEqual(len(caught.exception.partial), 3)
                self.assertFalse(any(item["qualified_run"] or item["command_succeeded"]
                                     for item in caught.exception.partial))

    def test_source_inventory_and_pre_exec_catalog_are_preserved_exactly(self):
        root = Path(__file__).resolve().parents[2]
        base = root / "crates/liteinst-launch/src/linux/remote/dynamic"
        files = {
            "admission/source/exec_tests.rs": 5,
            "admission/source_session/tests/exec.rs": 6,
            "owner/admission/census/exec/tests.rs": 11,
            "owner/admission/exec/inputs/tests.rs": 12,
            "owner/admission/exec/sources/tests.rs": 8,
            "owner/exec_journal/tests.rs": 13,
            "owner/selected/exec/tests.rs": 2,
            "owner/admission/exec/seal/tests.rs": 3,
            "owner/admission/exec/budget/tests.rs": 4,
            "owner/admission/exec/tests/native.rs": 3,
        }
        total = 0
        for name, count in files.items():
            source = (base / name).read_text()
            names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
            self.assertEqual(len(names), count, name)
            self.assertEqual(len(set(names)), count, name)
            self.assertNotRegex(source, r"#\[ignore(?:\]|\()")
            if name.endswith("exec/tests/native.rs"):
                self.assertEqual(names, list(PRIVATE_NAMES))
            total += count
        self.assertEqual(total, UNIT_INCREMENT)
        declared = json.loads((root / "evaluation/admission/corpus.json").read_text())
        self.assertEqual(declared["native_validation_fixtures"][42:], ROWS + PRIVATE_ROWS)
        old_rows = declared["native_validation_fixtures"][:42]
        digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest(old_rows), "93868f46ec716f2d1a6a770e8879ba28a28f160ea6182178dd819520d9b31307")
        old_cohorts = copy.deepcopy(declared["harness_test_counts"])
        for cohort in old_cohorts.values():
            self.assertEqual(cohort.pop(HARNESS), {"tests": 5, "ignored": 0})
            self.assertEqual(cohort[fixtures.UNIT], {"tests": 278 + UNIT_INCREMENT, "ignored": 0})
            cohort[fixtures.UNIT] = {"tests": 278, "ignored": 0}
        self.assertEqual(digest(old_cohorts), "26423ad36df0fc97ac2ed91687c80a251dddb5f10d1b430edbc4c60155b7e60e")
