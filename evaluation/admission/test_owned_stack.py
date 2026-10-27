"""Synthetic recorder/source controls; no test here launches a native task."""

import ast
import copy
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from core_a3_inventory import before_core_a3
from runtime_stack_consumer_inventory import (before_runtime_stack_consumer,
                                               before_runtime_stack_consumer_python)
import native_fixtures as fixtures
from core_719519_inventory import before_core_719519
from ordinary_shared_inventory import before_ordinary_shared
from ordinary_thirtytwo_inventory import before_ordinary_thirtytwo
from owned_stack_inventory import (
    NATIVE_NAMES, NATIVE_ROOT, OLD_NATIVE86_SHA256, OLD_PYTHON302_SHA256,
    PRE_OWNED_STACK_CORPUS_SHA256, PYTHON_METHODS, ROWS, RUST_METHODS,
    before_owned_stack, before_owned_stack_python, digest,
    validate_owned_stack_source,
)
from parsing import InvalidEvidence
from test_dynamic_admission import summary
from test_native_fixtures import header
from test_source_census_fixtures import named_capture

NAMES = [row["test"] for row in ROWS]
FIELDS = {"cohort", "harness", "test", "status", "test_result",
          "command_succeeded", "qualified_run"}


def capture(split=False):
    lines = [header(fixtures.UNIT), "running 17 tests"]
    for name in NAMES:
        lines.extend([f"test {name} ... PRIVATE_SENTINEL pid=12345 raw_state=[99]",
                      "thread 'owner' panicked at /private/source:42:1",
                      "PRIVATE_SENTINEL pc=0x900000", "ok"] if split
                     else [f"test {name} ... ok"])
    return "\n".join(lines + [summary(17)]) + "\n"


def python_identities():
    result = []
    for path in sorted(Path(__file__).parent.glob("test_*.py")):
        for cls in ast.parse(path.read_text()).body:
            if isinstance(cls, ast.ClassDef):
                result.extend(path.stem + "." + cls.name + "." + method.name
                              for method in cls.body
                              if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                              and method.name.startswith("test_"))
    return before_runtime_stack_consumer_python(result)


class OwnedStackTests(unittest.TestCase):
    def partial(self, output, code, succeeded=True):
        with self.assertRaisesRegex(InvalidEvidence, "^" + code + "$") as caught:
            fixtures.fixture_outcomes(output, list(ROWS), succeeded)
        rows = caught.exception.partial
        self.assertEqual(len(rows), 17)
        self.assertEqual([{key: row[key] for key in ("cohort", "harness", "test")}
                          for row in rows], list(ROWS))
        self.assertTrue(all(set(row) == FIELDS for row in rows))
        self.assertTrue(all(row["command_succeeded"] is succeeded for row in rows))
        self.assertFalse(any(row["qualified_run"] for row in rows))
        for private in ("PRIVATE_SENTINEL", "/private/", "12345", "0x900000", "raw_state"):
            self.assertNotIn(private, json.dumps(rows))
            self.assertNotIn(private, str(caught.exception))
        return rows

    def test_owned_stack_addition_preserves_exact_sources_corpus_and_history(self):
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(sum(map(len, RUST_METHODS.values())), 91)
        self.assertEqual(len(NATIVE_NAMES), 17)
        for path, expected in RUST_METHODS.items():
            source = (root / path).read_text()
            names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
            self.assertEqual(names, list(expected), path)
            self.assertEqual(len(names), len(set(names)), path)
            self.assertNotRegex(source, r"#\[ignore(?:\]|\()")
            validate_owned_stack_source(path, names)
        self.assertEqual(fixtures.OWNED_STACK_ROOT, NATIVE_ROOT)
        self.assertEqual(fixtures.OWNED_STACK_NAMES, NATIVE_NAMES)
        self.assertEqual(fixtures.OWNED_STACK_ROWS, ROWS)
        declared = before_core_a3(before_runtime_stack_consumer(before_core_719519(before_ordinary_shared(before_ordinary_thirtytwo(json.loads(Path(__file__).with_name("corpus.json").read_text()))))))
        original = copy.deepcopy(declared)
        previous = before_owned_stack(declared)
        self.assertEqual(declared, original)
        self.assertEqual(digest(previous), PRE_OWNED_STACK_CORPUS_SHA256)
        self.assertEqual(declared["native_validation_fixtures"][:86], previous["native_validation_fixtures"])
        self.assertEqual(digest(previous["native_validation_fixtures"]), OLD_NATIVE86_SHA256)
        self.assertEqual(declared["native_validation_fixtures"][86:], list(ROWS))
        self.assertEqual(len(fixtures.catalog(declared["native_validation_fixtures"])), 103)
        for name, harnesses, total, ignored in (("workspace_tests", 91, 2128, 4),
                                                ("serial_launch", 27, 995, 0)):
            current = declared["harness_test_counts"][name]
            self.assertEqual(len(current), harnesses)
            self.assertEqual(sum(row["tests"] for row in current.values()), total)
            self.assertEqual(sum(row["ignored"] for row in current.values()), ignored)
            self.assertEqual(current[fixtures.UNIT], {"tests": 703, "ignored": 0})
            self.assertEqual({key: value for key, value in current.items() if key != fixtures.UNIT},
                             {key: value for key, value in previous["harness_test_counts"][name].items()
                              if key != fixtures.UNIT})
        self.assertEqual(declared["recorder_tests"], 305)
        self.assertEqual(previous["recorder_tests"], 302)
        for field, count in (("native_cases", 50), ("dynamic_admission_fixtures", 15),
                             ("dynamic_matrix_cases", 388)):
            self.assertEqual(declared[field], previous[field])
            self.assertEqual(len(declared[field]), count)
        self.assertEqual(declared["backing_cleanup_harnesses"], previous["backing_cleanup_harnesses"])
        current_python = python_identities()
        old_python = before_owned_stack_python(current_python)
        self.assertEqual(len(current_python), 305)
        self.assertEqual(len(old_python), 302)
        self.assertEqual(digest(old_python), OLD_PYTHON302_SHA256)
        self.assertEqual([name for name in current_python if name not in old_python], list(PYTHON_METHODS))

    def test_owned_stack_projection_rejects_every_identity_count_and_source_mutation(self):
        declared = before_core_a3(before_runtime_stack_consumer(before_core_719519(before_ordinary_shared(before_ordinary_thirtytwo(json.loads(Path(__file__).with_name("corpus.json").read_text()))))))
        for index in range(103):
            for change in ("missing", "duplicate", "position", "cohort", "harness", "test", "extra"):
                changed = copy.deepcopy(declared)
                rows = changed["native_validation_fixtures"]
                if change == "missing": rows.pop(index)
                elif change == "duplicate": rows.append(copy.deepcopy(rows[index]))
                elif change == "position":
                    other = (index + 1) % len(rows)
                    rows[index], rows[other] = rows[other], rows[index]
                elif change == "extra": rows[index]["extra"] = "PRIVATE_SENTINEL"
                else: rows[index][change] = "PRIVATE_SENTINEL"
                with self.subTest(index=index, change=change), self.assertRaises(InvalidEvidence) as caught:
                    before_owned_stack(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for change in ("recorder", "recorder_type", "unit", "unit_type", "ignored_type", "old_unit",
                       "old_native", "runtime", "static", "dynamic", "matrix", "helper", "baseline", "extra"):
            changed = copy.deepcopy(declared)
            if change == "recorder": changed["recorder_tests"] -= 1
            elif change == "recorder_type": changed["recorder_tests"] = 305.0
            elif change == "unit": changed["harness_test_counts"]["workspace_tests"][fixtures.UNIT]["tests"] -= 1
            elif change == "unit_type": changed["harness_test_counts"]["serial_launch"][fixtures.UNIT]["tests"] = 703.0
            elif change == "ignored_type": changed["harness_test_counts"]["workspace_tests"][fixtures.UNIT]["ignored"] = False
            elif change == "old_unit": changed["harness_test_counts"]["serial_launch"]["test/dynamic_fork"]["tests"] -= 1
            elif change == "old_native": changed["native_validation_fixtures"][0]["test"] += "_extra"
            elif change == "runtime": changed["native_validation_fixtures"][56]["test"] += "_extra"
            elif change == "static": changed["native_cases"].pop()
            elif change == "dynamic": changed["dynamic_admission_fixtures"].pop()
            elif change == "matrix": changed["dynamic_matrix_cases"].pop()
            elif change == "helper": changed["backing_cleanup_harnesses"]["serial_launch"][0]["trajectories"].pop()
            elif change == "baseline": changed["baseline_revision"] = "0" * 40
            else: changed["extra"] = "PRIVATE_SENTINEL"
            with self.subTest(change=change), self.assertRaises(InvalidEvidence):
                before_owned_stack(changed)
        for path, expected in RUST_METHODS.items():
            names = list(expected)
            for changed in (names[:-1], names + [names[-1]],
                            ["PRIVATE_SENTINEL"] + names[1:]):
                with self.assertRaisesRegex(InvalidEvidence, "^owned_stack_source_inventory_differs$") as caught:
                    validate_owned_stack_source(path, changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
            # A singleton has no non-identity permutation; every multi-method
            # file additionally requires its exact original method order.
            if len(names) > 1:
                with self.assertRaisesRegex(InvalidEvidence, "^owned_stack_source_inventory_differs$"):
                    validate_owned_stack_source(path, list(reversed(names)))
        with self.assertRaisesRegex(InvalidEvidence, "^owned_stack_source_inventory_differs$"):
            validate_owned_stack_source("PRIVATE_SENTINEL", [])
        # A valid corpus cannot be peeled if any actual new source inventory
        # is absent, renamed or ignored. Keep the failure string path-free.
        read_text = Path.read_text
        for source_path, expected in RUST_METHODS.items():
            for mutation in ("missing", "rename", "ignore"):
                def changed_source(path, *args, **kwargs):
                    if path.as_posix().endswith(source_path):
                        if mutation == "missing":
                            raise OSError("PRIVATE_SENTINEL /private/source")
                        text = read_text(path, *args, **kwargs)
                        if mutation == "rename":
                            return text.replace(expected[0], "PRIVATE_SENTINEL", 1)
                        return text + "\n#[ignore]\n"
                    return read_text(path, *args, **kwargs)
                with self.subTest(source=source_path, mutation=mutation), patch(
                        "owned_stack_inventory.Path.read_text", changed_source):
                    with self.assertRaisesRegex(InvalidEvidence, "^owned_stack_source_inventory_differs$") as caught:
                        before_owned_stack(declared)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        identities = python_identities()
        for changed in (identities[:-1], identities + [identities[-1]], list(reversed(identities)),
                        ["PRIVATE_SENTINEL"] + identities[1:]):
            with self.assertRaisesRegex(InvalidEvidence, "^owned_stack_source_inventory_differs$"):
                before_owned_stack_python(changed)
        for name in PYTHON_METHODS:
            changed = list(identities)
            changed[changed.index(name)] += "_unlisted"
            with self.assertRaisesRegex(InvalidEvidence, "^owned_stack_source_inventory_differs$"):
                before_owned_stack_python(changed)

    def test_owned_stack_closed_outcomes_preserve_failure_prefix_and_privacy(self):
        for split in (False, True):
            for succeeded in (False, True):
                observed = fixtures.fixture_outcomes(capture(split), list(ROWS), succeeded)
                self.assertEqual(observed, [row | {"status": "complete", "test_result": "ok",
                    "command_succeeded": succeeded, "qualified_run": False} for row in ROWS])
                self.assertTrue(all(set(row) == FIELDS for row in observed))
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(observed))
        for row in ROWS:
            for change in ({"cohort": "b3_runtime_kernel"}, {"cohort": "kernel_journal"},
                           {"harness": fixtures.EXEC_REFERENCE}, {"harness": "unit/foreign/lib"},
                           {"test": row["test"] + "_extra"}, {"test": NATIVE_ROOT + "::nested::unlisted"},
                           {"test": "unlisted_runtime_case"}):
                with self.assertRaisesRegex(InvalidEvidence, "^invalid_native_fixture_scope$"):
                    fixtures.catalog([row | change])
        with self.assertRaisesRegex(InvalidEvidence, "^duplicate_native_fixture_catalog$"):
            fixtures.catalog(list(ROWS) + [ROWS[0]])
        self.partial("PRIVATE_SENTINEL", "missing_native_fixture_harness")
        for wrong in (fixtures.EXEC_REFERENCE, "unit/foreign/lib"):
            self.partial(capture().replace(header(fixtures.UNIT), header(wrong)), "native_fixture_wrong_harness")
        for unknown in (NATIVE_ROOT + "::unlisted", NATIVE_ROOT + "::nested::unlisted",
                        NATIVE_ROOT + "_extra::unlisted"):
            rows = self.partial(capture().replace(NAMES[-1], unknown), "native_fixture_cohort_differs")
            self.assertEqual([row["status"] for row in rows], ["complete"] * 16 + ["not_observed"])
        self.partial(capture().replace(NAMES[0], "bad/name"), "invalid_native_fixture_name")
        self.partial(capture().replace("target/debug/deps/", "/PRIVATE_SENTINEL/"), "invalid_harness_binary_path")
        self.partial(capture() + capture(), "duplicate_native_fixture_harness")
        for index, name in enumerate(NAMES):
            line = f"test {name} ... ok\n"
            rows = self.partial(capture().replace(line, ""), "native_fixture_cohort_differs")
            self.assertEqual(rows[index]["status"], "not_observed")
            self.assertEqual(sum(row["status"] == "complete" for row in rows), 16)
            rows = self.partial(capture().replace(line, line + line), "duplicate_native_fixture_test")
            self.assertEqual(sum(row["status"] == "complete" for row in rows), index + 1)
            prefix = capture().split(line, 1)[0] + f"test {name} ... PRIVATE_SENTINEL\n"
            rows = self.partial(prefix, "native_fixture_missing_terminal", False)
            self.assertEqual((rows[index]["status"], rows[index]["test_result"]), ("incomplete", None))
            for terminal in ("FAILED", "ignored", "ignored, PRIVATE_SENTINEL unsupported"):
                rows = self.partial(capture().replace(line, f"test {name} ... {terminal}\n"),
                                    "native_fixture_not_passed", False)
                self.assertEqual((rows[index]["status"], rows[index]["test_result"]),
                                 ("failed", "FAILED" if terminal == "FAILED" else "ignored"))
                self.assertEqual(sum(row["status"] == "complete" for row in rows), 16)
        declared = before_core_a3(before_runtime_stack_consumer(before_core_719519(before_ordinary_shared(before_ordinary_thirtytwo(json.loads(Path(__file__).with_name("corpus.json").read_text()))))))
        all_rows = declared["native_validation_fixtures"]
        before_owned_stack(declared)
        for row in all_rows:
            for mutation in ({"cohort": "PRIVATE_SENTINEL"}, {"harness": "unit/foreign/lib"}):
                with self.assertRaisesRegex(InvalidEvidence, "^invalid_native_fixture_scope$"):
                    fixtures.catalog([row | mutation])
            with self.assertRaisesRegex(InvalidEvidence, "^duplicate_native_fixture_catalog$"):
                fixtures.catalog(all_rows + [row])
        output = named_capture(all_rows)
        self.assertEqual(fixtures.fixture_outcomes(output, all_rows, True), [row | {
            "status": "complete", "test_result": "ok", "command_succeeded": True,
            "qualified_run": False} for row in all_rows])
        for index, missing in enumerate(all_rows):
            with self.subTest(test=missing["test"]), self.assertRaisesRegex(
                    InvalidEvidence, "^native_fixture_cohort_differs$") as caught:
                fixtures.fixture_outcomes(output.replace(f"test {missing['test']} ... ok\n", ""), all_rows, True)
            partial = caught.exception.partial
            self.assertEqual(len(partial), 103)
            self.assertEqual((partial[index]["status"], partial[index]["test_result"]), ("not_observed", None))
            self.assertEqual(sum(row["status"] == "complete" for row in partial), 102)
            self.assertFalse(any(row["qualified_run"] for row in partial))
            line = f"test {missing['test']} ... ok\n"
            for terminal in ("FAILED", "ignored", "ignored, PRIVATE_SENTINEL"):
                with self.subTest(test=missing["test"], terminal=terminal), self.assertRaisesRegex(
                        InvalidEvidence, "^native_fixture_not_passed$") as caught:
                    fixtures.fixture_outcomes(output.replace(line,
                        f"test {missing['test']} ... {terminal}\n"), all_rows, False)
                partial = caught.exception.partial
                self.assertEqual(len(partial), 103)
                self.assertEqual((partial[index]["status"], partial[index]["test_result"]),
                                 ("failed", "FAILED" if terminal == "FAILED" else "ignored"))
                self.assertEqual(sum(row["status"] == "complete" for row in partial), 102)
                self.assertTrue(all(set(row) == FIELDS for row in partial))
                self.assertFalse(any(row["qualified_run"] or row["command_succeeded"] for row in partial))
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(partial))
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
            prefix = output.split(line, 1)[0] + f"test {missing['test']} ... PRIVATE_SENTINEL /private/ raw_state\n"
            with self.subTest(test=missing["test"], prefix=True), self.assertRaisesRegex(
                    InvalidEvidence, "^native_fixture_missing_terminal$") as caught:
                fixtures.fixture_outcomes(prefix, all_rows, False)
            partial = caught.exception.partial
            self.assertEqual(len(partial), 103)
            self.assertEqual((partial[index]["status"], partial[index]["test_result"]), ("incomplete", None))
            # Harness grouping may differ from catalog order; compare exact set
            # of observed names from the retained output prefix, not an index.
            completed = set(re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. ok$", prefix, re.MULTILINE))
            self.assertEqual({row["test"] for row in partial if row["status"] == "complete"}, completed)
            self.assertFalse(any(row["qualified_run"] or row["command_succeeded"] for row in partial))
            self.assertTrue(all(set(row) == FIELDS for row in partial))
            for private in ("PRIVATE_SENTINEL", "/private/", "raw_state"):
                self.assertNotIn(private, json.dumps(partial))
                self.assertNotIn(private, str(caught.exception))
