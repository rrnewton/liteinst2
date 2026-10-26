"""Synthetic finite mapping evidence controls; no native command is executed."""

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


HARNESS = "test/b3_mapping_admission"
NAMES = (
    "original_rw_rx_rw_rx_unmap_matches_raw_full_state_and_two_runtime_sources",
    "stale_capture_reply_after_real_second_rx_preserves_partial_kernel_history",
    "resolver_panic_after_real_rx_keeps_failure_and_original_physical_cleanup",
    "blocked_resolver_expires_original_deadline_before_callback_is_released",
    "full_native_mapping_comparator_rejects_each_state_source_and_map_corruption",
)
ROWS = [{"cohort": "b3_mapping", "harness": HARNESS, "test": name} for name in NAMES]
FIELDS = {"cohort", "harness", "test", "status", "test_result",
          "command_succeeded", "qualified_run"}
# Canonical ordered original37 JSON at 049cc481d7e7cf92f0853f562227ffde3165d331.
OLD37_SHA256 = "e28eb2ed2457cc644f4f9f303e605df0e32577192596bd9ca12ae2d9003f762a"


def capture(split=False):
    lines = [header(HARNESS), "running 5 tests"]
    for index, name in enumerate(NAMES):
        if split:
            lines.extend([f"test {name} ... PRIVATE_SENTINEL pid=12345 address=0x900000",
                          "thread 'resolver' panicked at /private/source:99:1",
                          f"PRIVATE_SENTINEL raw_mapping_rows={index + 1} bytes=[0,15,162]", "ok"])
        else:
            lines.append(f"test {name} ... ok")
    lines.append(summary(5))
    return "\n".join(lines) + "\n"


def command_evidence(suffix=None, status="passed", exit_code=0):
    expected = corpus()
    expected["native_validation_fixtures"] = copy.deepcopy(ROWS)
    expected["harness_test_counts"]["serial_launch"][HARNESS] = {"tests": 5, "ignored": 0}
    text = fixture_block() + native_block(expected["native_cases"])
    text += capture() if suffix is None else suffix
    command = {"id": "serial_launch", "status": status, "exit_code": exit_code}
    run.command_evidence(command, text, expected)
    return command


class MappingFixtureTests(unittest.TestCase):
    def partial(self, output, code, succeeded=True):
        with self.assertRaisesRegex(InvalidEvidence, "^" + code + "$") as caught:
            fixtures.fixture_outcomes(output, ROWS, succeeded)
        rows = caught.exception.partial
        self.assertEqual(len(rows), 5)
        self.assertEqual([{key: row[key] for key in ("cohort", "harness", "test")} for row in rows], ROWS)
        self.assertTrue(all(set(row) == FIELDS for row in rows))
        self.assertTrue(all(row["command_succeeded"] is succeeded for row in rows))
        self.assertFalse(any(row["qualified_run"] for row in rows))
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
        self.assertNotIn("/private/", json.dumps(rows))
        return rows

    def test_exact_inline_split_outcomes_are_five_typed_fixtures_not_samples(self):
        self.assertEqual(fixtures.MAPPING_REFERENCE, HARNESS)
        self.assertEqual(fixtures.MAPPING_TESTS, frozenset(NAMES))
        for split in (False, True):
            with self.subTest(split=split):
                observed = fixtures.fixture_outcomes(capture(split), ROWS, True)
                self.assertEqual(observed, [row | {
                    "status": "complete", "test_result": "ok", "command_succeeded": True,
                    "qualified_run": False} for row in ROWS])
                self.assertTrue(all(set(row) == FIELDS for row in observed))
                public = json.dumps(observed)
                for forbidden in ("PRIVATE_SENTINEL", "/private/", "12345", "0x900000",
                                  "raw_mapping_rows", "bytes=", "samples", "corruptions"):
                    self.assertNotIn(forbidden, public)

    def test_catalog_rejects_wrong_scope_lookalikes_and_relabelled_known_names(self):
        for row in ROWS:
            changes = [
                {"cohort": "b3_mapping_extra"}, {"cohort": "b3_signal"},
                {"harness": fixtures.UNIT}, {"harness": fixtures.REFERENCE},
                {"harness": "test/b3_mapping_admission_extra"},
                {"test": row["test"] + "_extra"}, {"test": "module::" + row["test"]},
                {"test": "unlisted_future_mapping_case"},
                {"cohort": "b2_reference", "harness": fixtures.REFERENCE},
                {"cohort": "b3_signal", "harness": fixtures.SIGNAL_REFERENCE},
            ]
            for change in changes:
                with self.subTest(test=row["test"], change=change), self.assertRaisesRegex(
                        InvalidEvidence, "^invalid_native_fixture_scope$"):
                    fixtures.catalog([row | change])
        for change in ({"test": True}, {"test": "bad/name"}, {"extra": "PRIVATE_SENTINEL"}):
            with self.subTest(change=change), self.assertRaisesRegex(
                    InvalidEvidence, "^invalid_native_fixture_catalog$"):
                fixtures.catalog([ROWS[0] | change])
        with self.assertRaisesRegex(InvalidEvidence, "^duplicate_native_fixture_catalog$"):
            fixtures.catalog(ROWS + [ROWS[0]])

    def test_wrong_harness_unknown_case_and_malformed_control_structure_refuse(self):
        for wrong in (fixtures.UNIT, fixtures.REFERENCE, fixtures.SIGNAL_REFERENCE, "test/foreign"):
            with self.subTest(harness=wrong):
                rows = self.partial(capture().replace(header(HARNESS), header(wrong)),
                                    "native_fixture_wrong_harness")
                self.assertTrue(all(row["status"] == "not_observed" for row in rows))
        for name in ("unlisted_future_mapping_case", NAMES[0] + "_extra", "module::" + NAMES[0]):
            with self.subTest(name=name):
                rows = self.partial(capture().replace(NAMES[-1], name), "native_fixture_cohort_differs")
                self.assertEqual([row["status"] for row in rows], ["complete"] * 4 + ["not_observed"])
        self.partial(capture().replace(NAMES[0], "bad/name"), "invalid_native_fixture_name")
        self.partial(capture() + capture(), "duplicate_native_fixture_harness")
        self.partial(capture().replace("running 5 tests\n", "running 5 tests\nrunning 5 tests\n"),
                     "duplicate_native_fixture_start")
        self.partial(capture() + "test unlisted ... ok\n", "native_fixture_after_summary")

    def test_missing_duplicate_unfinished_failed_and_ignored_keep_exact_partial_prefix(self):
        rows = self.partial("PRIVATE_SENTINEL", "missing_native_fixture_harness")
        self.assertTrue(all(row["status"] == "not_observed" for row in rows))
        for index, name in enumerate(NAMES):
            line = f"test {name} ... ok\n"
            with self.subTest(missing=name):
                rows = self.partial(capture().replace(line, ""), "native_fixture_cohort_differs")
                self.assertEqual(rows[index]["status"], "not_observed")
                self.assertEqual(sum(row["status"] == "complete" for row in rows), 4)
            with self.subTest(duplicate=name):
                rows = self.partial(capture().replace(line, line + line), "duplicate_native_fixture_test")
                self.assertEqual(sum(row["status"] == "complete" for row in rows), index + 1)
                self.assertTrue(all(row["status"] == "not_observed" for row in rows[index + 1:]))
            for terminal in ("FAILED", "ignored", "ignored, PRIVATE_SENTINEL unsupported"):
                with self.subTest(name=name, terminal=terminal):
                    rows = self.partial(capture().replace(line, f"test {name} ... {terminal}\n"),
                                        "native_fixture_not_passed", succeeded=False)
                    self.assertEqual((rows[index]["status"], rows[index]["test_result"]),
                                     ("failed", "FAILED" if terminal == "FAILED" else "ignored"))
                    self.assertEqual(sum(row["status"] == "complete" for row in rows), 4)
            prefix = capture().split(line, 1)[0] + f"test {name} ... PRIVATE_SENTINEL\n"
            for tail in ("", summary(5), header("test/foreign")):
                with self.subTest(unfinished=name, tail=tail):
                    rows = self.partial(prefix + tail, "native_fixture_missing_terminal")
                    self.assertEqual(rows[index]["status"], "incomplete")
                    self.assertIsNone(rows[index]["test_result"])
                    self.assertEqual(sum(row["status"] == "complete" for row in rows), index)

    def test_named_ok_never_overrides_aggregate_command_source_or_whole_run_failure(self):
        clean = command_evidence()
        self.assertEqual((clean["status"], clean["evidence_status"]), ("passed", "complete"))
        self.assertEqual(len(clean["native_cases"]), 50)
        self.assertEqual(len(clean["dynamic_admission_fixtures"]), 7)
        self.assertEqual(clean["dynamic_matrix_cases"], [])
        aggregate = command_evidence(capture().replace("running 5 tests", "running 6 tests"))
        self.assertEqual((aggregate["status"], aggregate["parse_error"]),
                         ("invalid_evidence", "changed_outer_cohort"))
        failed = command_evidence(status="failed", exit_code=101)
        self.assertEqual(failed["status"], "failed")
        self.assertFalse(any(row["command_succeeded"] for row in failed["native_validation_fixtures"]))
        for command, source, config, other, qualifies in (
                (clean, True, True, "passed", True), (aggregate, True, True, "passed", False),
                (failed, True, True, "passed", False), (clean, False, True, "passed", False),
                (clean, True, False, "passed", False), (clean, None, True, "passed", False),
                (clean, True, True, "failed", False), (clean, True, True, "not_run", False),
                (clean, True, True, "invalid_evidence", False)):
            with self.subTest(status=command["status"], source=source, config=config, other=other):
                commands = [{"id": name, "status": "passed"} for name, _, _ in run.COMMANDS]
                changed = []
                for index, item in enumerate(commands):
                    if item["id"] == "serial_launch":
                        commands[index] = copy.deepcopy(command)
                    elif item["id"] == "workspace_check":
                        item["status"] = other
                        changed.append(item["id"])
                self.assertEqual(changed, ["workspace_check"])
                self.assertEqual(next(item for item in commands if item["id"] == "workspace_check")["status"], other)
                record = {"source_unchanged": source, "configuration_unchanged": config, "commands": commands}
                run.qualify(record)
                self.assertEqual(record["status"], "passed" if qualifies else "failed")
                result = next(item for item in commands if item["id"] == "serial_launch")["native_validation_fixtures"]
                self.assertEqual(len(result), 5)
                self.assertTrue(all(row["qualified_run"] is qualifies for row in result))
                self.assertTrue(all((row["status"], row["test_result"]) == ("complete", "ok") for row in result))

    def test_real_catalog_pins_old37_exact_five_source_names_and_both_harness_denominators(self):
        path = Path(__file__).with_name("corpus.json")
        declared = json.loads(path.read_text())
        rows = declared["native_validation_fixtures"]
        self.assertEqual(len(rows), 56)
        old = json.dumps(rows[:37], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.assertEqual(hashlib.sha256(old).hexdigest(), OLD37_SHA256)
        self.assertEqual(rows[37:42], ROWS)
        self.assertEqual(len(fixtures.catalog(rows)), 56)
        source = path.parents[2] / "crates/liteinst-launch/tests/b3_mapping_admission.rs"
        actual_names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source.read_text())
        self.assertEqual(actual_names, list(NAMES))
        for command in ("workspace_tests", "serial_launch"):
            self.assertEqual(declared["harness_test_counts"][command][HARNESS], {"tests": 5, "ignored": 0})
        self.assertEqual(len(declared["native_cases"]), 50)
        self.assertEqual(len(declared["dynamic_admission_fixtures"]), 15)
        self.assertEqual(len(declared["dynamic_matrix_cases"]), 388)
        output = named_capture(rows)
        self.assertEqual(fixtures.fixture_outcomes(output, rows, True), [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in rows])
        for index, missing in enumerate(rows):
            with self.subTest(missing=missing["test"]), self.assertRaisesRegex(
                    InvalidEvidence, "^native_fixture_cohort_differs$") as caught:
                fixtures.fixture_outcomes(output.replace(f"test {missing['test']} ... ok\n", ""), rows, True)
            partial = caught.exception.partial
            self.assertEqual(len(partial), 56)
            self.assertEqual((partial[index]["status"], partial[index]["test_result"]), ("not_observed", None))
            self.assertEqual(sum(row["status"] == "complete" for row in partial), 55)
            self.assertFalse(any(row["qualified_run"] for row in partial))


if __name__ == "__main__":
    unittest.main()
