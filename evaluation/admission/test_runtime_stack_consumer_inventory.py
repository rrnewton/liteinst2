"""Supplied-record/source controls; no child, compiler, feature test or native I/O."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from parsing import InvalidEvidence
import runtime_stack_consumer_inventory as inventory
from core_719519_inventory import before_core_719519
import ordinary_shared_inventory as shared
import native_fixtures as fixtures


class RuntimeStackConsumerInventoryTests(unittest.TestCase):
    def test_current_corpus_and_methods_reconstruct_exact_old_history(self):
        current = json.loads(Path(__file__).with_name("corpus.json").read_text())
        shared_previous = shared.before_ordinary_shared(current)
        declared = before_core_719519(shared_previous)
        unchanged = copy.deepcopy(declared)
        previous = inventory.before_runtime_stack_consumer(declared)
        self.assertEqual(declared, unchanged)
        self.assertEqual(declared["recorder_tests"], 330)
        self.assertEqual(inventory.digest(declared), inventory.CURRENT_RUNTIME_STACK_CONSUMER_CORPUS_SHA256)
        self.assertEqual(previous["recorder_tests"], 305)
        self.assertEqual(inventory.digest(previous), inventory.PRE_RUNTIME_STACK_CONSUMER_CORPUS_SHA256)
        self.assertEqual({key: value for key, value in declared.items() if key != "recorder_tests"},
                         {key: value for key, value in previous.items() if key != "recorder_tests"})
        for cohort, harnesses, total, ignored in (("workspace_tests", 93, 2148, 4),
                                                 ("serial_launch", 27, 995, 0)):
            rows = declared["harness_test_counts"][cohort]
            self.assertEqual(len(rows), harnesses)
            self.assertEqual(sum(row["tests"] for row in rows.values()), total)
            self.assertEqual(sum(row["ignored"] for row in rows.values()), ignored)
            self.assertEqual(rows["unit/liteinst_launch/lib"], {"tests": 703, "ignored": 0})
        self.assertEqual(len(declared["native_validation_fixtures"]), 103)
        self.assertEqual(declared["native_validation_fixtures"], previous["native_validation_fixtures"])
        identities = inventory.python_source_identities()
        original = list(identities)
        old = inventory.before_runtime_stack_consumer_python(identities)
        self.assertEqual(identities, original)
        self.assertEqual(len(identities), 330)
        self.assertEqual(len(old), 305)
        self.assertEqual(inventory.digest(old), inventory.OLD_PYTHON305_SHA256)
        self.assertEqual([name for name in identities if name not in old], list(inventory.PYTHON_METHODS))
        self.assertEqual([len(methods) for methods in inventory.PYTHON_MODULES.values()], [14, 3, 8])
        with self.assertRaisesRegex(InvalidEvidence, "^runtime_stack_consumer_inventory_differs$"):
            inventory.before_runtime_stack_consumer(previous)
        with self.assertRaisesRegex(InvalidEvidence, "^runtime_stack_consumer_source_inventory_differs$"):
            inventory.before_runtime_stack_consumer_python(old)

        # Preserve the exact core predecessor for the shared-layer inverse checks.
        declared = shared_previous
        # The new current corpus is authenticated before the old fixture is used.
        self.assertEqual(current, json.loads(Path(__file__).with_name("corpus.json").read_text()))
        self.assertEqual(shared.digest(current), shared.CURRENT_ORDINARY_SHARED_CORPUS_SHA256)
        self.assertEqual(shared.digest(declared), shared.PRE_ORDINARY_SHARED_CORPUS_SHA256)
        self.assertEqual(current["native_validation_fixtures"][:103], declared["native_validation_fixtures"])
        self.assertEqual(current["native_validation_fixtures"][103:], list(fixtures.ORDINARY_ALLOCATION_ROWS))
        self.assertEqual(len(fixtures.catalog(current["native_validation_fixtures"])), 107)
        self.assertEqual(sum(len(names) for names in shared.RUST_METHODS.values()), 33)
        for cohort, total in (("workspace_tests", 2199), ("serial_launch", 1028)):
            rows = current["harness_test_counts"][cohort]
            self.assertEqual(rows[fixtures.UNIT], {"tests": 736, "ignored": 0})
            self.assertEqual(sum(row["tests"] for row in rows.values()), total)
        with self.assertRaisesRegex(InvalidEvidence, "^ordinary_shared_inventory_differs$"):
            shared.before_ordinary_shared(declared)

    def test_projection_refuses_changed_fields_counts_and_identities(self):
        current = json.loads(Path(__file__).with_name("corpus.json").read_text())
        shared_previous = shared.before_ordinary_shared(current)
        declared = before_core_719519(shared_previous)
        for count in (305, 327, 329, 331, 330.0, True, None):
            changed = copy.deepcopy(declared)
            changed["recorder_tests"] = count
            with self.subTest(count=count), self.assertRaisesRegex(
                    InvalidEvidence, "^runtime_stack_consumer_inventory_differs$"):
                inventory.before_runtime_stack_consumer(changed)
        # Every unrelated complete-corpus field remains protected by the old
        # digest. No new field, omitted row, or private sentinel can be peeled.
        for key in declared:
            if key == "recorder_tests":
                continue
            for mode in ("missing", "changed"):
                changed = copy.deepcopy(declared)
                if mode == "missing":
                    del changed[key]
                else:
                    changed[key] = "PRIVATE_SENTINEL /private/source"
                with self.subTest(key=key, mode=mode), self.assertRaisesRegex(
                        InvalidEvidence, "^runtime_stack_consumer_inventory_differs$") as caught:
                    inventory.before_runtime_stack_consumer(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        changed = copy.deepcopy(declared)
        changed["extra"] = "PRIVATE_SENTINEL"
        with self.assertRaisesRegex(InvalidEvidence, "^runtime_stack_consumer_inventory_differs$"):
            inventory.before_runtime_stack_consumer(changed)
        for cohort in ("workspace_tests", "serial_launch"):
            for field, value in (("tests", 702), ("ignored", 1), ("tests", 703.0)):
                changed = copy.deepcopy(declared)
                changed["harness_test_counts"][cohort]["unit/liteinst_launch/lib"][field] = value
                with self.subTest(cohort=cohort, field=field, value=value), self.assertRaises(InvalidEvidence):
                    inventory.before_runtime_stack_consumer(changed)
        identities = inventory.python_source_identities()
        for index in range(len(identities)):
            for mode in ("missing", "duplicate", "rename", "order"):
                changed = list(identities)
                if mode == "missing":
                    changed.pop(index)
                elif mode == "duplicate":
                    changed.append(changed[index])
                elif mode == "rename":
                    changed[index] += "_PRIVATE_SENTINEL"
                else:
                    # Swap within the old/new projection so even a change that
                    # leaves both sets intact violates their exact source order.
                    same_group = [i for i, name in enumerate(changed)
                                  if (name.split(".", 1)[0] in inventory.PYTHON_MODULES)
                                  == (changed[index].split(".", 1)[0] in inventory.PYTHON_MODULES)]
                    other = same_group[(same_group.index(index) + 1) % len(same_group)]
                    changed[index], changed[other] = changed[other], changed[index]
                with self.subTest(index=index, mode=mode), self.assertRaisesRegex(
                        InvalidEvidence, "^runtime_stack_consumer_source_inventory_differs$") as caught:
                    inventory.before_runtime_stack_consumer_python(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        # Closed current-cohort controls are additive to every historical check.
        for index in (0, 103, 104, 105, 106):
            for mode in ("missing", "duplicate", "name", "cohort", "harness", "extra"):
                changed = copy.deepcopy(current)
                rows = changed["native_validation_fixtures"]
                if mode == "missing": rows.pop(index)
                elif mode == "duplicate": rows.append(copy.deepcopy(rows[index]))
                elif mode == "name": rows[index]["test"] += "_PRIVATE_SENTINEL"
                elif mode == "cohort": rows[index]["cohort"] = "PRIVATE_SENTINEL"
                elif mode == "harness": rows[index]["harness"] = "test/PRIVATE_SENTINEL"
                else: rows[index]["private"] = "/private/source"
                with self.subTest(shared_row=index, mode=mode), self.assertRaisesRegex(
                        InvalidEvidence, "^ordinary_shared_inventory_differs$") as caught:
                    shared.before_ordinary_shared(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
                self.assertNotIn("/private/", str(caught.exception))
        for cohort in ("workspace_tests", "serial_launch"):
            for field, value in (("tests", 735), ("tests", 737), ("tests", 736.0), ("ignored", 1)):
                changed = copy.deepcopy(current)
                changed["harness_test_counts"][cohort][fixtures.UNIT][field] = value
                with self.subTest(shared_count=cohort, field=field, value=value), self.assertRaisesRegex(
                        InvalidEvidence, "^ordinary_shared_inventory_differs$"):
                    shared.before_ordinary_shared(changed)
        changed = copy.deepcopy(current)
        changed["recorder_tests"] = 331
        with self.assertRaisesRegex(InvalidEvidence, "^ordinary_shared_inventory_differs$"):
            shared.before_ordinary_shared(changed)
        changed = copy.deepcopy(current)
        changed["extra"] = "PRIVATE_SENTINEL"
        with self.assertRaisesRegex(InvalidEvidence, "^ordinary_shared_inventory_differs$"):
            shared.before_ordinary_shared(changed)
        rows = list(fixtures.ORDINARY_ALLOCATION_ROWS)
        header = "     Running unittests src/lib.rs (target/debug/deps/liteinst_launch-0123456789abcdef)"
        lines = ["test " + row["test"] + " ... ok\n" for row in rows]
        log = header + "\nrunning 4 tests\n" + "".join(lines) + "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        for succeeded in (False, True):
            observed = fixtures.fixture_outcomes(log, rows, succeeded)
            self.assertEqual([row["test"] for row in observed], [row["test"] for row in rows])
            self.assertTrue(all(row["status"] == "complete" and row["test_result"] == "ok"
                                and row["command_succeeded"] is succeeded and row["qualified_run"] is False
                                for row in observed))
        for index, row in enumerate(rows):
            for field, value in (("cohort", "b3_runtime_ordinary"), ("harness", "test/foreign"),
                                 ("test", row["test"] + "_PRIVATE_SENTINEL")):
                changed = copy.deepcopy(rows)
                changed[index][field] = value
                with self.subTest(catalog=index, field=field), self.assertRaisesRegex(
                        InvalidEvidence, "^invalid_native_fixture_scope$"):
                    fixtures.catalog(changed)
            for altered in (log.replace(lines[index], ""), log.replace(lines[index], lines[index] * 2),
                            log.replace(row["test"], row["test"] + "_PRIVATE_SENTINEL"),
                            log.replace(lines[index], lines[index].replace(" ... ok", " ... FAILED")),
                            log.replace(lines[index], lines[index].replace(" ... ok", " ... ignored")),
                            log.replace(header, "     Running tests/foreign.rs (target/debug/deps/foreign-0123456789abcdef)")):
                with self.subTest(outcome=index), self.assertRaises(InvalidEvidence) as caught:
                    fixtures.fixture_outcomes(altered, rows, True)
                self.assertEqual(len(caught.exception.partial), 4)
                self.assertFalse(any(item["qualified_run"] for item in caught.exception.partial))
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(caught.exception.partial))
        private = log.replace("running 4 tests\n", "running 4 tests\nPRIVATE_SENTINEL /private/source pid=123\n")
        self.assertEqual(fixtures.fixture_outcomes(private, rows, True), fixtures.fixture_outcomes(log, rows, True))
        for prefix in ("unknown", rows[0]["test"].rsplit("::", 1)[-1]):
            with self.assertRaises(InvalidEvidence):
                fixtures.fixture_outcomes(log.replace(rows[0]["test"], prefix), rows, True)

    def test_source_census_refuses_missing_extra_or_renamed_methods(self):
        read_text = Path.read_text
        targets = [(module + ".py", methods[0].rsplit(".", 1)[1])
                   for module, methods in inventory.PYTHON_MODULES.items()]
        targets.append(("test_owned_stack.py", "test_owned_stack_addition_preserves_exact_sources_corpus_and_history"))
        for filename, method in targets:
            for mode in ("missing", "rename", "extra", "syntax"):
                def altered(path, *args, **kwargs):
                    if path.name == filename:
                        if mode == "missing":
                            raise OSError("PRIVATE_SENTINEL /private/source")
                        text = read_text(path, *args, **kwargs)
                        if mode == "rename":
                            return text.replace("def " + method + "(", "def test_PRIVATE_SENTINEL(", 1)
                        if mode == "extra":
                            return text + "\nclass Extra:\n    def test_PRIVATE_SENTINEL(self):\n        pass\n"
                        return text + "\nPRIVATE_SENTINEL (\n"
                    return read_text(path, *args, **kwargs)
                with self.subTest(filename=filename, mode=mode), patch(
                        "runtime_stack_consumer_inventory.Path.read_text", altered):
                    with self.assertRaisesRegex(
                            InvalidEvidence, "^runtime_stack_consumer_source_inventory_differs$") as caught:
                        inventory.require_current_runtime_stack_consumer_sources()
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
                self.assertNotIn("/private/", str(caught.exception))

        read_bytes = Path.read_bytes
        for target, methods in shared.RUST_METHODS.items():
            for mode in ("missing", "rename", "extra", "ignored"):
                def altered_shared(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        if mode == "missing": raise OSError("PRIVATE_SENTINEL /private/source")
                        data = read_bytes(path, *args, **kwargs)
                        if mode == "rename": return data.replace(methods[0].encode(), b"PRIVATE_SENTINEL", 1)
                        if mode == "extra": return data + b"\n#[test]\nfn PRIVATE_SENTINEL() {}\n"
                        return data.replace(b"#[test]", b"#[test]\n#[ignore]", 1)
                    return read_bytes(path, *args, **kwargs)
                with self.subTest(shared_source=target, mode=mode), patch(
                        "ordinary_shared_inventory.Path.read_bytes", altered_shared):
                    with self.assertRaisesRegex(
                            InvalidEvidence, "^ordinary_shared_source_inventory_differs$") as caught:
                        shared.require_current_ordinary_shared_sources()
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
                self.assertNotIn("/private/", str(caught.exception))



if __name__ == "__main__":
    unittest.main()
