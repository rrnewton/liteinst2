"""Independent closed-protocol calibrations; no native cleanup qualification."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import backing_cleanup as cleanup
import parsing
import run


NAMES = ["admitted_exec_native_backing_probes_close_exact_owned_resources",
         "admitted_exec_native_backing_read_and_unwind_preserve_cleanup",
         "exec_backing_native_invalid_unmap_aborts_isolated_owner"]
IDS = ["complete", "read_error", "unwind", "invalid_unmap"]
HEADER = "     Running tests/exec_backing_cleanup.rs (target/debug/deps/exec_backing_cleanup-0123456789abcdef)\n"
PREFIX = "LITEINST_BACKING_CLEANUP_V1 "
OLD = ("     Running tests/example.rs (target/debug/deps/example-0123456789abcdef)\n"
       "\nrunning 2 tests\ntest first ... ok\ntest second ... ok\n"
       "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
EXPECTED = {"test/example": {"tests": 2, "ignored": 0}}


def specification():
    return {"id": "control/exec_backing_cleanup", "source": "tests/exec_backing_cleanup.rs",
            "binary": "exec_backing_cleanup", "protocol": "LITEINST_BACKING_CLEANUP_V1",
            "controls": list(NAMES), "trajectories": list(IDS)}


def records():
    result = [{"schema_version": 1, "kind": "begin", "controls": 3, "trajectories": 4}]
    for index, identity, control, outcome, probes, error, terminal, owner in (
            (0, "complete", NAMES[0], "complete", 6, 0, "exit0", True),
            (1, "read_error", NAMES[1], "native_read_error", 1, 14, "exit0", True),
            (2, "unwind", NAMES[1], "injected_unwind", 1, 0, "exit0", True),
            (3, "invalid_unmap", NAMES[2], "expected_fail_stop", 1, 22, "sigabrt", False)):
        result.append({"schema_version": 1, "kind": "trajectory", "index": index,
                       "id": identity, "control": control, "outcome": outcome,
                       "probes": probes, "errno": error, "terminal": terminal,
                       "owner_cleanup": owner, "physical_cleanup": True,
                       "receipt_authenticated": True})
    result.append({"schema_version": 1, "kind": "complete", "controls": 3,
                   "trajectories": 4, "physical_cleanup": True})
    return result


def transcript(rows=None):
    return HEADER + "".join(PREFIX + json.dumps(row) + "\n"
                            for row in (records() if rows is None else rows))


def corpus():
    return {"harness_test_counts": {"workspace_tests": copy.deepcopy(EXPECTED)},
            "backing_cleanup_harnesses": {
                name: [specification()] for name in ("workspace_tests", "serial_launch")}}


def observed(text, status="passed", exit_code=0):
    command = {"id": "workspace_tests", "status": status, "exit_code": exit_code}
    run.command_evidence(command, text, corpus())
    return command


class BackingCleanupTests(unittest.TestCase):
    def separate(self, text, succeeded=True):
        return cleanup.separate(text, [specification()], succeeded)

    def invalid(self, text, accepted, code=None):
        old, rows, error = self.separate(text)
        self.assertIsNotNone(error)
        if code is not None:
            self.assertEqual(error, code)
        self.assertEqual(rows[0]["observations"], records()[:accepted])
        self.assertFalse(rows[0]["qualified_run"])
        self.assertFalse(cleanup.is_complete(rows[0]))
        for secret in ("PRIVATE_SENTINEL", "/PRIVATE_PATH", "raw_state", "123456789"):
            self.assertNotIn(secret, json.dumps(rows))
            self.assertNotIn(secret, error)
        return old, rows[0]

    def test_exact_helper_is_separate_from_old_libtest_counts_and_abort_is_not_release(self):
        for text in (transcript() + OLD, OLD + transcript()):
            old, rows, error = self.separate(text)
            self.assertIsNone(error)
            self.assertEqual(old, OLD)
            self.assertEqual(parsing.parse_harnesses(old, EXPECTED, 0),
                             parsing.parse_harnesses(OLD, EXPECTED, 0))
            row = rows[0]
            self.assertEqual(row["observations"], records())
            self.assertEqual([control["id"] for control in row["controls"]], NAMES)
            self.assertEqual([control["status"] for control in row["controls"]], ["complete"] * 3)
            self.assertEqual(row["controls"][1]["trajectories"], ["read_error", "unwind"])
            self.assertFalse(row["observations"][4]["owner_cleanup"])
            self.assertEqual(row["observations"][4]["terminal"], "sigabrt")
            self.assertTrue(cleanup.is_complete(row))
            self.assertFalse(row["qualified_run"])
            self.assertNotIn("outer", row)
        command = observed(OLD + transcript())
        self.assertEqual(command["status"], "passed")
        self.assertEqual(len(command["harnesses"]), 1)
        self.assertEqual(command["harnesses"][0]["outer"]["passed"], 2)

    def test_real_inventory_preserves_old_denominators_and_named_collections(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        cleanup.require_inventory(declared)
        self.assertEqual(declared["backing_cleanup_harnesses"], corpus()["backing_cleanup_harnesses"])
        self.assertEqual(declared["recorder_tests"], 254)
        for name, harnesses, tests, ignored in (("workspace_tests", 89, 1731, 4),
                                               ("serial_launch", 27, 647, 0)):
            rows = declared["harness_test_counts"][name]
            self.assertEqual(len(rows), harnesses)
            self.assertEqual(sum(row["tests"] for row in rows.values()), tests)
            self.assertEqual(sum(row["ignored"] for row in rows.values()), ignored)
            self.assertNotIn("test/exec_backing_cleanup", rows)
        for field, count, digest in (
                ("native_validation_fixtures", 56, "faa3331583cc37593b7562ae294e30ea15c72a4de95337fed9aa9a5d851b71b9"),
                ("native_cases", 50, "b0c7e09f94583e2b5a920b61a472d2b599fc12223742cf0a3409cf4487e85c96"),
                ("dynamic_admission_fixtures", 15, "ec06cf57892acc437535a56ec8aad7c3c59cd8e6b9226e70fb034f7ca7ec8ea7"),
                ("dynamic_matrix_cases", 388, "81c9212c05cdabd531629248aec53b48bd9a1517367b067c5a03340a1d39abbe")):
            self.assertEqual(len(declared[field]), count)
            encoded = json.dumps(declared[field], sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)

    def test_missing_changed_or_disabled_real_inventory_refuses_before_commands(self):
        good = corpus()
        changes = [{}, {"backing_cleanup_harnesses": {}},
                   {"backing_cleanup_harnesses": {"workspace_tests": [], "serial_launch": []}},
                   {"backing_cleanup_harnesses": {"workspace_tests": [specification()]}}]
        for field in specification():
            changed = copy.deepcopy(good)
            changed["backing_cleanup_harnesses"]["serial_launch"][0][field] = None
            changes.append(changed)
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    parsing.InvalidEvidence, "^invalid_backing_cleanup_inventory$"):
                cleanup.require_inventory(changed)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "corpus.json").write_text('{"schema_version":1}')
            with patch.object(run, "ROOT", root), patch.object(run, "HERE", root), \
                 patch.object(run, "controlled_environment", return_value={}), \
                 patch.object(run, "source_state", return_value={"revision": "a" * 40,
                                                               "tracked_clean": True}), \
                 patch.object(run, "git", return_value=b""), \
                 patch.object(run, "run_command") as execute, \
                 patch.object(run, "hardware") as hardware, \
                 patch("sys.argv", ["run.py", "--expect-revision", "a" * 40]), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.main(), 1)
            execute.assert_not_called()
            hardware.assert_not_called()
            result = json.loads(next((root / "results").glob("*.json")).read_text())
            self.assertEqual(result["status"], "refused")
            self.assertEqual(result["error_code"], "invalid_backing_cleanup_inventory")
            self.assertTrue(all(command["status"] == "not_run" for command in result["commands"]))

    def test_only_exact_cargo_source_and_binary_pair_owns_a_removable_block(self):
        for wrong in (HEADER.replace("tests/exec_backing_cleanup.rs", "tests/foreign.rs"),
                      HEADER.replace("deps/exec_backing_cleanup-", "deps/foreign-"),
                      HEADER.replace("target/debug/deps", "/PRIVATE_PATH"),
                      HEADER.replace("0123456789abcdef", "xyz"),
                      HEADER.replace("0123456789abcdef", "0123456789abcde"),
                      HEADER.replace("Running tests/", "Running unittests tests/"),
                      "   Doc-tests exec_backing_cleanup\n"):
            text = OLD + transcript().replace(HEADER, wrong)
            remaining, _ = self.invalid(text, 0)
            self.assertEqual(remaining, text)
        remaining, _ = self.invalid(transcript() + OLD + transcript(), 6,
                                    "duplicate_backing_cleanup_harness")
        self.assertEqual(remaining, OLD)

    def test_malformed_duplicate_unknown_and_private_json_retains_only_valid_prefix(self):
        lines = transcript().splitlines(keepends=True)
        for payload in ('{', '[]', 'null', '{"schema_version":1,"schema_version":1}',
                        '{"kind":NaN}', '{"kind":Infinity}',
                        json.dumps(records()[2] | {"raw_state": "/PRIVATE_PATH/PRIVATE_SENTINEL"}),
                        json.dumps(records()[2] | {"errno": 123456789}),
                        json.dumps(records()[2] | {"id": {"PRIVATE_SENTINEL": True}})):
            text = "".join(lines[:3]) + PREFIX + payload + "\n" + "".join(lines[4:])
            self.invalid(text, 2)
        self.invalid("".join(lines[:3]) + PREFIX + '"' + 'x' * 1024 + '"\n', 2,
                     "oversized_backing_cleanup_record")

    def test_each_missing_record_and_terminal_preserves_the_exact_observed_prefix(self):
        original = records()
        for index in range(6):
            old, row = self.invalid(transcript(original[:index] + original[index + 1:]) + OLD,
                                    index)
            self.assertEqual(old, OLD)
            self.assertFalse(row["complete_observed"])
        _, row = self.invalid(OLD, 0, "missing_backing_cleanup_harness")
        self.assertEqual(row["status"], "invalid")
        _, row = self.invalid(transcript(original[:3]), 3, "incomplete_backing_cleanup_protocol")
        self.assertEqual([control["status"] for control in row["controls"]],
                         ["complete", "incomplete", "not_observed"])

    def test_duplicate_reordered_and_foreign_records_cannot_fill_missing_trajectories(self):
        original = records()
        for index in range(6):
            self.invalid(transcript(original[:index + 1] + [original[index]] + original[index + 1:]),
                         index + 1)
        for index in range(5):
            changed = copy.deepcopy(original)
            changed[index], changed[index + 1] = changed[index + 1], changed[index]
            self.invalid(transcript(changed), index)
        for index in range(1, 5):
            for field, value in (("id", "foreign"), ("control", NAMES[(index + 1) % 3]),
                                 ("index", index + 7)):
                changed = copy.deepcopy(original)
                changed[index][field] = value
                if changed != original:
                    self.invalid(transcript(changed), index)

    def test_every_fixed_field_and_boolean_type_is_required_without_errno_alternatives(self):
        original = records()
        for index, row in enumerate(original):
            for field, value in row.items():
                replacements = [not value, int(value)] if type(value) is bool else \
                               [value + 1, bool(value)] if type(value) is int else [value + "_foreign"]
                for replacement in replacements:
                    changed = copy.deepcopy(original)
                    changed[index][field] = replacement
                    with self.subTest(index=index, field=field, replacement=replacement):
                        self.invalid(transcript(changed), index, "backing_cleanup_record_differs")
                changed = copy.deepcopy(original)
                del changed[index][field]
                self.invalid(transcript(changed), index)

    def test_unscoped_protocol_and_forged_libtest_summaries_are_never_removed(self):
        line = PREFIX + json.dumps(records()[0]) + "\n"
        for text in (line + OLD + transcript(), OLD + line + transcript()):
            old, _ = self.invalid(text, 0, "backing_cleanup_record_outside_harness")
            self.assertIn(line, old)
        for injected in ("running 3 tests\n", "test forged ... ok\n", OLD.splitlines()[-1] + "\n",
                         "PRIVATE_SENTINEL\n", "LITEINST_BACKING_CLEANUP_V2 {}\n"):
            lines = transcript().splitlines(keepends=True)
            old, _ = self.invalid("".join(lines[:2]) + injected + "".join(lines[2:]) + OLD,
                                  1, "unexpected_backing_cleanup_output")
            self.assertEqual(old, OLD)

    def test_failed_command_retains_complete_helper_without_qualifying_expected_abort(self):
        for code in (101, -9, -6):
            command = observed(OLD + transcript(), "failed", code)
            self.assertEqual(command["status"], "failed")
            self.assertEqual(command["exit_code"], code)
            row = command["backing_cleanup_harnesses"][0]
            self.assertEqual(row["status"], "complete")
            self.assertEqual(row["observations"], records())
            self.assertFalse(row["command_succeeded"])
            self.assertFalse(row["qualified_run"])
        command = observed(OLD + transcript(records()[:4]), "failed", 101)
        self.assertEqual(command["backing_cleanup_harnesses"][0]["observations"], records()[:4])
        self.assertEqual(command["status"], "failed")

    def test_valid_helper_never_masks_old_failure_missing_filtered_or_ignored_harness(self):
        for text in ("", OLD.replace("running 2 tests", "running 3 tests"),
                     OLD.replace("2 passed; 0 failed", "1 passed; 1 failed").replace("result: ok", "result: FAILED"),
                     OLD.replace("2 passed; 0 failed; 0 ignored", "1 passed; 0 failed; 1 ignored"),
                     OLD.replace("0 filtered out", "1 filtered out"),
                     OLD.replace("tests/example.rs", "tests/foreign.rs").replace("deps/example-", "deps/foreign-")):
            command = observed(text + transcript())
            self.assertEqual(command["status"], "invalid_evidence")
            self.assertEqual(command["evidence_status"], "incomplete")
            self.assertEqual(command["backing_cleanup_harnesses"][0]["status"], "complete")
            self.assertFalse(command["backing_cleanup_harnesses"][0]["qualified_run"])

    def test_whole_protocol_source_configuration_and_both_helper_commands_gate_qualification(self):
        _, rows, error = self.separate(transcript())
        self.assertIsNone(error)
        clean = {"source_unchanged": True, "configuration_unchanged": True,
                 "backing_cleanup_required": True, "commands": [
                     {"id": name, "status": "passed", "backing_cleanup_harnesses": copy.deepcopy(rows)}
                     for name in ("workspace_tests", "serial_launch")]}
        passed = copy.deepcopy(clean)
        run.qualify(passed)
        run.qualify(passed)
        self.assertEqual(passed["status"], "passed")
        self.assertTrue(all(command["backing_cleanup_harnesses"][0]["qualified_run"]
                            for command in passed["commands"]))
        changes = []
        for field in ("source_unchanged", "configuration_unchanged"):
            changed = copy.deepcopy(clean)
            changed[field] = False
            changes.append(changed)
        for index in range(2):
            for field, value in (("status", "failed"), ("backing_cleanup_harnesses", [])):
                changed = copy.deepcopy(clean)
                changed["commands"][index][field] = value
                changes.append(changed)
            changed = copy.deepcopy(clean)
            changed["commands"][index]["backing_cleanup_harnesses"][0]["observations"][4]["terminal"] = "exit0"
            changes.append(changed)
        for changed in changes:
            run.qualify(changed)
            self.assertEqual(changed["status"], "failed")
            self.assertFalse(any(row["qualified_run"] for command in changed["commands"]
                                 for row in command.get("backing_cleanup_harnesses", [])))

    def test_first_error_freezes_prefix_and_later_valid_rows_cannot_repair_it(self):
        lines = transcript().splitlines(keepends=True)
        bad = PREFIX + '{"PRIVATE_SENTINEL":"/PRIVATE_PATH"}\n'
        old, row = self.invalid("".join(lines[:4]) + bad + "".join(lines[4:]) + OLD, 3,
                                "backing_cleanup_record_differs")
        self.assertEqual(old, OLD)
        self.assertEqual(row["controls"][0]["status"], "complete")
        self.assertEqual(row["controls"][1]["status"], "incomplete")
        _, rows, error = self.separate("".join(lines[:4]) + bad + "bad\n" + "".join(lines[4:]))
        self.assertEqual(error, "backing_cleanup_record_differs")
        self.assertEqual(rows[0]["observations"], records()[:3])

    def test_recorder_exception_disqualifies_retained_helper_without_exporting_failure_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "corpus.json").write_text(json.dumps({"schema_version": 1} | corpus()))
            source = {"revision": "a" * 40, "tracked_clean": True}
            def completed(argv, env, log, timeout):
                log.write_text("synthetic")
                return {"exit_code": 0, "termination": None, "cleanup_complete": True, "seconds": 0.01}
            def fail_after_rows(command, output, expected):
                command["backing_cleanup_harnesses"] = self.separate(transcript())[1]
                command["backing_cleanup_harnesses"][0]["qualified_run"] = True
                raise RuntimeError("PRIVATE_SENTINEL")
            with contextlib.ExitStack() as stack:
                for name, value in (("ROOT", root), ("HERE", root), ("GIT", sys.executable)):
                    stack.enter_context(patch.object(run, name, value))
                for name, value in (("source_state", source), ("git", b""), ("hardware", {}),
                                    ("cargo_configuration", []), ("tool_version", "synthetic"),
                                    ("controlled_environment", {"PATH": "/usr/bin"})):
                    stack.enter_context(patch.object(run, name, return_value=value))
                execute = stack.enter_context(patch.object(run, "run_command", side_effect=completed))
                stack.enter_context(patch.object(run, "command_evidence", side_effect=fail_after_rows))
                stack.enter_context(patch.object(run.shutil, "which", return_value=sys.executable))
                stack.enter_context(patch.object(run.resource, "setrlimit"))
                stack.enter_context(patch("sys.argv", ["run.py", "--expect-revision", "a" * 40]))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertEqual(run.main(), 1)
            self.assertEqual(execute.call_count, 1)
            record = json.loads(next((root / "results").glob("*.json")).read_text())
            self.assertEqual(record["status"], "recorder_error")
            self.assertEqual(record["error_type"], "RuntimeError")
            row = record["commands"][0]["backing_cleanup_harnesses"][0]
            self.assertEqual(row["observations"], records())
            self.assertFalse(row["qualified_run"])
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(record))
            self.assertTrue(all(command["status"] == "not_run" for command in record["commands"][1:]))
