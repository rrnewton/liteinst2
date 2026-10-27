"""Supplied-record/source controls; no child, compiler, feature test or native I/O."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from parsing import InvalidEvidence
import runtime_stack_consumer_inventory as inventory


class RuntimeStackConsumerInventoryTests(unittest.TestCase):
    def test_current_corpus_and_methods_reconstruct_exact_old_history(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
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

    def test_projection_refuses_changed_fields_counts_and_identities(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
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


if __name__ == "__main__":
    unittest.main()
