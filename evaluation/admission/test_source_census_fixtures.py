"""Synthetic source-census evidence controls; no native command is executed."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

import native_fixtures as fixtures
from parsing import InvalidEvidence
import run
from test_dynamic_admission import corpus, fixture_block, native_block, summary
from test_native_fixtures import header


NATIVE_NAME = ("linux::remote::dynamic::owner::tests::source_census::"
               "changed_reserved_census_refuses_before_entry_patch_or_permission_change")
NATIVE_PREFIX = "linux::remote::dynamic::owner::tests::source_census::"
ROW = {"cohort": "b3_source_census", "harness": "unit/liteinst_launch/lib",
       "test": NATIVE_NAME}
FIELDS = {"cohort", "harness", "test", "status", "test_result",
          "command_succeeded", "qualified_run"}
# Canonical ordered JSON of the 36 native rows at source 7113048e1b96616f12724dfa75e1a63ea143d982.
# Computed once from that Git source, not from the current runtime catalog.
OLD36_SHA256 = "fc1a4e1a248c1ce9d9bfed2f66429ba95f956421b5274784866d20d2539a50f2"


def capture(split=False):
    diagnostics = ["PRIVATE_SENTINEL mutation=removed_mapping pid=1234 address=0x400000",
                   "PRIVATE_SENTINEL mutation=changed_offset source_bytes=8192",
                   "PRIVATE_SENTINEL mutation=changed_path path=/private/fixture"]
    lines = [header(fixtures.UNIT), "running 2 tests", "test ordinary::model ... ok"]
    if split:
        lines.extend([f"test {NATIVE_NAME} ... " + diagnostics[0],
                      *diagnostics[1:], "ok"])
    else:
        lines.extend([f"test {NATIVE_NAME} ... ok", *diagnostics])
    lines.append(summary(2))
    return "\n".join(lines) + "\n"


def named_capture(rows):
    groups = {}
    for row in rows:
        groups.setdefault(row["harness"], []).append(row["test"])
    lines = []
    for harness, names in groups.items():
        lines.extend([header(harness), f"running {len(names)} tests"])
        lines.extend(f"test {name} ... ok" for name in names)
        lines.append(summary(len(names)))
    return "\n".join(lines) + "\n"


def command_evidence(suffix=None, status="passed", exit_code=0):
    expected = corpus()
    expected["native_validation_fixtures"] = [ROW]
    expected["harness_test_counts"]["serial_launch"][fixtures.UNIT] = {"tests": 2, "ignored": 0}
    text = fixture_block() + native_block(expected["native_cases"])
    text += capture() if suffix is None else suffix
    command = {"id": "serial_launch", "status": status, "exit_code": exit_code}
    run.command_evidence(command, text, expected)
    return command


class SourceCensusFixtureTests(unittest.TestCase):
    def partial(self, output, code, succeeded=True):
        with self.assertRaisesRegex(InvalidEvidence, "^" + code + "$") as caught:
            fixtures.fixture_outcomes(output, [ROW], succeeded)
        rows = caught.exception.partial
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), FIELDS)
        self.assertFalse(rows[0]["qualified_run"])
        self.assertEqual(rows[0]["command_succeeded"], succeeded)
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
        self.assertNotIn("/private/", json.dumps(rows))
        return rows[0]

    def test_inline_and_split_native_refusal_is_one_typed_private_outcome(self):
        for split in (False, True):
            with self.subTest(split=split):
                rows = fixtures.fixture_outcomes(capture(split), [ROW], True)
                self.assertEqual(rows, [ROW | {
                    "status": "complete", "test_result": "ok", "command_succeeded": True,
                    "qualified_run": False}])
                self.assertEqual(set(rows[0]), FIELDS)
                self.assertEqual(len(rows), 1)  # three mutations are one named fixture
                public = json.dumps(rows)
                for private in ("PRIVATE_SENTINEL", "removed_mapping", "changed_offset",
                                "changed_path", "/private/", "0x400000", "1234", "8192"):
                    self.assertNotIn(private, public)
                self.assertNotIn("samples", rows[0])
                self.assertNotIn("mutations", rows[0])

    def test_scope_exact_name_and_monitored_namespace_reject_substitutes(self):
        self.assertEqual(fixtures.SOURCE_CENSUS_PREFIX, NATIVE_PREFIX)
        self.assertEqual(fixtures.SOURCE_CENSUS_TEST, NATIVE_NAME)
        changes = [
            {"cohort": name} for name in ("kernel_journal", "b3_reset", "b3_signal", "b3_source_census_extra")
        ] + [
            {"harness": harness} for harness in (fixtures.REFERENCE, fixtures.SIGNAL_REFERENCE, "test/foreign")
        ] + [
            {"test": name} for name in (
                NATIVE_NAME + "_extra", NATIVE_PREFIX + "future_native_case",
                NATIVE_PREFIX + "nested::changed_reserved_census_refuses_before_entry_patch_or_permission_change",
                NATIVE_NAME.replace("source_census::", "source_census_extra::"),
                NATIVE_NAME.rsplit("::", 1)[1])
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaisesRegex(
                    InvalidEvidence, "^invalid_native_fixture_scope$"):
                fixtures.catalog([ROW | change])
        for bad in (NATIVE_PREFIX + "bad/name", NATIVE_PREFIX + "", True):
            with self.subTest(name=bad), self.assertRaisesRegex(
                    InvalidEvidence, "^invalid_native_fixture_catalog$"):
                fixtures.catalog([ROW | {"test": bad}])
        wrong = capture().replace(header(fixtures.UNIT), header("test/foreign"))
        self.assertEqual(self.partial(wrong, "native_fixture_wrong_harness")["status"], "not_observed")
        for unknown in (NATIVE_PREFIX + "future_native_case", NATIVE_PREFIX + "nested::future_native_case"):
            text = capture().replace("running 2 tests", "running 3 tests")
            text = text.replace(summary(2), f"test {unknown} ... ok\n" + summary(3))
            row = self.partial(text, "native_fixture_cohort_differs")
            self.assertEqual((row["status"], row["test_result"]), ("complete", "ok"))
            self.assertNotIn("future_native_case", json.dumps(row))

    def test_missing_duplicate_unfinished_failed_ignored_keep_truthful_prefix(self):
        line = f"test {NATIVE_NAME} ... ok\n"
        cases = [
            ("PRIVATE_SENTINEL only", "missing_native_fixture_harness", "not_observed", None),
            (capture().replace(line, ""), "native_fixture_cohort_differs", "not_observed", None),
            (capture().replace(line, line + line), "duplicate_native_fixture_test", "complete", "ok"),
            (capture().replace(line, f"test {NATIVE_NAME} ... PRIVATE_SENTINEL\n"),
             "native_fixture_missing_terminal", "incomplete", None),
        ]
        for terminal, result in (("FAILED", "FAILED"), ("ignored", "ignored"),
                                 ("ignored, private capability reason", "ignored")):
            cases.append((capture().replace(line, f"test {NATIVE_NAME} ... {terminal}\n"),
                          "native_fixture_not_passed", "failed", result))
        for text, error, status, result in cases:
            with self.subTest(error=error, status=status, result=result):
                row = self.partial(text, error)
                self.assertEqual((row["status"], row["test_result"]), (status, result))
        row = self.partial(capture(True).replace("\nok\n", "\n"),
                           "native_fixture_missing_terminal", succeeded=False)
        self.assertEqual((row["status"], row["test_result"]), ("incomplete", None))

    def test_named_success_cannot_override_aggregate_command_or_whole_run_failure(self):
        clean = command_evidence()
        self.assertEqual((clean["status"], clean["evidence_status"]), ("passed", "complete"))
        self.assertEqual(len(clean["native_cases"]), 50)
        self.assertEqual(len(clean["dynamic_admission_fixtures"]), 7)
        self.assertEqual(clean["dynamic_matrix_cases"], [])
        self.assertEqual(len(clean["native_validation_fixtures"]), 1)
        aggregate = command_evidence(capture().replace("running 2 tests", "running 3 tests"))
        self.assertEqual(aggregate["status"], "invalid_evidence")
        self.assertEqual(aggregate["parse_error"], "changed_outer_cohort")
        self.assertEqual(aggregate["native_validation_fixtures"][0]["test_result"], "ok")
        failed = command_evidence(status="failed", exit_code=101)
        # The unchanged runner converts cleanup failure to command status=failed
        # before qualification; these synthetic rows make no cleanup observation.
        failed["cleanup_complete"] = False
        self.assertEqual(failed["status"], "failed")
        self.assertFalse(failed["native_validation_fixtures"][0]["command_succeeded"])
        for command, source, config, other_status, expected in (
                (clean, True, True, "passed", True),
                (aggregate, True, True, "passed", False),
                (failed, True, True, "passed", False),
                (clean, False, True, "passed", False),
                (clean, True, False, "passed", False),
                (clean, None, True, "passed", False),
                (clean, True, True, "failed", False),
                (clean, True, True, "not_run", False),
                (clean, True, True, "invalid_evidence", False)):
            with self.subTest(command=command["status"], source=source, config=config, other=other_status):
                commands = [{"id": name, "status": "passed"} for name, _, _ in run.COMMANDS]
                changed = []
                for index, item in enumerate(commands):
                    if item["id"] == "serial_launch":
                        commands[index] = copy.deepcopy(command)
                    elif item["id"] == "workspace_check":
                        item["status"] = other_status
                        changed.append(item["id"])
                self.assertEqual(changed, ["workspace_check"])
                self.assertEqual(next(item for item in commands if item["id"] == "workspace_check")["status"],
                                 other_status)
                record = {"source_unchanged": source, "configuration_unchanged": config,
                          "commands": commands}
                run.qualify(record)
                self.assertEqual(record["status"], "passed" if expected else "failed")
                observed = next(item for item in commands if item["id"] == "serial_launch")
                row = observed["native_validation_fixtures"][0]
                self.assertEqual(row["qualified_run"], expected)
                self.assertEqual((row["status"], row["test_result"]), ("complete", "ok"))

    def test_real_catalog_keeps_exact_old36_and_requires_single_new_native_identity(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        all_rows = declared["native_validation_fixtures"]
        self.assertEqual(len(all_rows), 50)
        rows = all_rows[:37]
        old37 = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.assertEqual(hashlib.sha256(old37).hexdigest(),
                         "e28eb2ed2457cc644f4f9f303e605df0e32577192596bd9ca12ae2d9003f762a")
        self.assertEqual(len(rows), 37)
        old = json.dumps(rows[:36], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.assertEqual(hashlib.sha256(old).hexdigest(), OLD36_SHA256)
        self.assertEqual(rows[36:], [ROW])
        identities = fixtures.catalog(rows)
        self.assertEqual(len(identities), 37)
        self.assertEqual(sum(row["cohort"] == "b3_source_census" for row in rows), 1)
        output = named_capture(rows)
        observed = fixtures.fixture_outcomes(output, rows, True)
        self.assertEqual(observed, [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in rows])
        for index, missing in enumerate(rows):
            with self.subTest(missing=missing["test"]), self.assertRaisesRegex(
                    InvalidEvidence, "^native_fixture_cohort_differs$") as caught:
                fixtures.fixture_outcomes(output.replace(f"test {missing['test']} ... ok\n", ""), rows, True)
            partial = caught.exception.partial
            self.assertEqual(len(partial), 37)
            self.assertEqual((partial[index]["status"], partial[index]["test_result"]), ("not_observed", None))
            self.assertEqual(sum(row["status"] == "complete" for row in partial), 36)
            self.assertFalse(any(row["qualified_run"] for row in partial))


if __name__ == "__main__":
    unittest.main()
