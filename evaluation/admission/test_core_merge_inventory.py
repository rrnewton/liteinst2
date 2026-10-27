"""Static merged-core catalog and strict Cargo header controls."""

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from core_main_inventory import (ADDED_HARNESSES, CHANGED_HARNESSES, RUST_METHODS,
                                 SOURCE_WIRING, PRE_CORE_MAIN_CORPUS_SHA256,
                                 before_core_main, validate_core_main_source)
from test_runtime_kernel_inventory import before_kernel

from test_runtime_inventory import before_runtime

import parsing
from test_parsing import counts, header, summary
from test_exec_fixtures import HARNESS as EXEC_HARNESS, ROWS as EXEC_ROWS, PRIVATE_ROWS, FAILURE_ROWS, UNIT_INCREMENT


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class CoreMergeInventoryTests(unittest.TestCase):
    def test_explicit_calibration_target_has_one_exact_source_and_binary_pair(self):
        expected = {"test/frontend_native_calibrations": counts(26)}
        first = "     Running native-interval/calibrations.rs (target/debug/deps/frontend_native_calibrations-123abc)"
        valid = "\n".join((first, "running 26 tests", summary(26)))
        row = parsing.parse_harnesses(valid, expected, 0)[0]
        self.assertEqual(row["outer"]["passed"], 26)
        self.assertEqual(row["nested"], [])
        for text in (valid.replace("calibrations.rs", "other.rs"),
                     valid.replace("native-interval/", "other/"),
                     valid.replace("frontend_native_calibrations-", "other-"),
                     valid.replace("target/debug/deps/", "/PRIVATE_SENTINEL/"),
                     valid.replace("native-interval/", "/PRIVATE_SENTINEL/"),
                     valid + "\n" + valid, first + "\nrunning 26 tests\n"):
            with self.subTest(text=text), self.assertRaises(parsing.InvalidEvidence) as caught:
                parsing.parse_harnesses(text, expected, 0)
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(caught.exception.partial))
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        # Source/binary/directory spelling authenticated from the saved core
        # workspace capture. This adds no general examples-directory grammar.
        example = "     Running unittests examples/common_sites.rs (target/debug/examples/common_sites-123abc)"
        expected = {"unit/common_sites/common_sites": counts(24)}
        valid = "\n".join((example, "running 24 tests", summary(24)))
        row = parsing.parse_harnesses(valid, expected, 0)[0]
        self.assertEqual(row["outer"]["passed"], 24)
        self.assertEqual(row["nested"], [])
        for text in (valid.replace("examples/common_sites.rs", "examples/other.rs"),
                     valid.replace("examples/common_sites.rs", "src/common_sites.rs"),
                     valid.replace("common_sites-", "other-"),
                     valid.replace("target/debug/examples/", "target/debug/deps/"),
                     valid.replace("target/debug/examples/", "target/release/examples/"),
                     valid.replace("target/debug/examples/", "/PRIVATE_SENTINEL/"),
                     valid.replace("examples/common_sites.rs", "/PRIVATE_SENTINEL/common_sites.rs"),
                     valid.replace("common_sites-123abc", "common_sites-NOTHEX"),
                     valid + "\n" + valid, example + "\nrunning 24 tests\n"):
            with self.subTest(example=text), self.assertRaises(parsing.InvalidEvidence) as caught:
                parsing.parse_harnesses(text, expected, 0)
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(caught.exception.partial))
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        seed = "     Running tests/e9_common_seed_contract.rs (target/debug/deps/e9_common_seed_contract-123abc)"
        row = parsing.parse_harnesses("\n".join((seed, "running 3 tests", summary(3))),
                                      {"test/e9_common_seed_contract": counts(3)}, 0)[0]
        self.assertEqual(row["outer"]["passed"], 3)

    def test_new_core_cohort_retains_exact_child_shape_without_generalizing_it(self):
        for total in (176, 184, 208):
            valid = "\n".join((header("liteinst2"), f"running {total} tests", "running 1 test",
                               summary(total - 1, ignored=1)))
            row = parsing.parse_harnesses(valid, {"unit/liteinst2/lib": counts(total, 1)}, 0)[0]
            self.assertEqual(row["outer"]["passed"], total - 1)
            self.assertEqual(row["unmatched_nested_starts"], 1)
            self.assertEqual(row["nested"], [])
        for name, total, child, ignored, filtered in (
                ("liteinst2", 207, 1, 1, 0), ("liteinst2", 209, 1, 1, 0),
                ("other", 208, 1, 1, 0), ("liteinst2", 208, 2, 1, 0),
                ("liteinst2", 208, 1, 0, 0), ("liteinst2", 208, 1, 1, 1)):
            text = "\n".join((header(name), f"running {total} tests", f"running {child} tests",
                              summary(total - ignored, ignored=ignored, filtered=filtered)))
            with self.subTest(name=name, total=total, child=child, ignored=ignored, filtered=filtered), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(text, {f"unit/{name}/lib": counts(total, ignored)}, 0)

    def test_catalog_preserves_all_old_harnesses_and_native_collection_identities(self):
        current = json.loads(Path(__file__).with_name("corpus.json").read_text())
        unchanged = copy.deepcopy(current)
        previous = before_core_main(current)
        self.assertEqual(current, unchanged)
        self.assertEqual(digest(previous), PRE_CORE_MAIN_CORPUS_SHA256)
        self.assertEqual(current["recorder_tests"], 302)
        self.assertEqual(len(current["native_validation_fixtures"]), 86)
        self.assertEqual(current["native_validation_fixtures"], previous["native_validation_fixtures"])
        self.assertEqual(current["harness_test_counts"]["serial_launch"],
                         previous["harness_test_counts"]["serial_launch"])
        workspace_now = current["harness_test_counts"]["workspace_tests"]
        self.assertEqual(len(workspace_now), 91)
        self.assertEqual(sum(row["tests"] for row in workspace_now.values()), 2037)
        self.assertEqual(sum(row["ignored"] for row in workspace_now.values()), 4)
        self.assertEqual(workspace_now["unit/liteinst_launch/lib"], counts(612))
        self.assertEqual(sum(map(len, RUST_METHODS.values())), 49)
        for identity in (*ADDED_HARNESSES, *CHANGED_HARNESSES):
            for change in ("missing", "count", "ignored", "type", "ignored_type", "rename", "extra"):
                altered = copy.deepcopy(current)
                group = altered["harness_test_counts"]["workspace_tests"]
                if change == "missing": del group[identity]
                elif change == "count": group[identity]["tests"] -= 1
                elif change == "ignored": group[identity]["ignored"] = 1
                elif change == "type": group[identity]["tests"] = float(group[identity]["tests"])
                elif change == "ignored_type": group[identity]["ignored"] = False
                elif change == "rename": group[identity + "_extra"] = group.pop(identity)
                else: group[identity]["extra"] = "PRIVATE_SENTINEL"
                with self.subTest(identity=identity, change=change), self.assertRaises(parsing.InvalidEvidence) as caught:
                    before_core_main(altered)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for change in ("recorder", "serial", "old_workspace", "native", "static", "dynamic", "matrix", "helper", "extra"):
            altered = copy.deepcopy(current)
            if change == "recorder": altered["recorder_tests"] -= 1
            elif change == "serial": altered["harness_test_counts"]["serial_launch"]["unit/liteinst_launch/lib"]["tests"] -= 1
            elif change == "old_workspace": altered["harness_test_counts"]["workspace_tests"]["unit/liteinst_launch/lib"]["tests"] -= 1
            elif change == "native": altered["native_validation_fixtures"].pop()
            elif change == "static": altered["native_cases"].pop()
            elif change == "dynamic": altered["dynamic_admission_fixtures"].pop()
            elif change == "matrix": altered["dynamic_matrix_cases"].pop()
            elif change == "helper": altered["backing_cleanup_harnesses"]["serial_launch"].pop()
            else: altered["extra"] = "PRIVATE_SENTINEL"
            with self.subTest(history=change), self.assertRaises(parsing.InvalidEvidence):
                before_core_main(altered)
        for path, names in RUST_METHODS.items():
            for bad in (list(names[:-1]), list(names) + [names[0]], list(reversed(names)),
                        ["PRIVATE_SENTINEL"] + list(names[1:])):
                with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_main_source_inventory_differs$"):
                    validate_core_main_source(path, bad)
        read_text = Path.read_text
        for target in (*RUST_METHODS, *SOURCE_WIRING):
            for mutation in ("missing", "changed"):
                def altered_source(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        if mutation == "missing": raise OSError("PRIVATE_SENTINEL /private/source")
                        text = read_text(path, *args, **kwargs)
                        needle = RUST_METHODS[target][0] if target in RUST_METHODS else SOURCE_WIRING[target]
                        return text.replace(needle, "PRIVATE_SENTINEL", 1)
                    return read_text(path, *args, **kwargs)
                with self.subTest(source=target, mutation=mutation), patch("core_main_inventory.Path.read_text", altered_source):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_main_source_inventory_differs$") as caught:
                        before_core_main(current)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        corpus = json.loads(Path(__file__).with_name("corpus.json").read_text())
        corpus = before_kernel(corpus)
        corpus = before_runtime(corpus)
        workspace = copy.deepcopy(corpus["harness_test_counts"]["workspace_tests"])
        # Remove only the separately pinned additive exec inventory before
        # checking the complete historical core-merge cohort and its digest.
        self.assertEqual(workspace.pop(EXEC_HARNESS), counts(5))
        self.assertEqual(workspace["unit/liteinst_launch/lib"], counts(278 + UNIT_INCREMENT))
        workspace["unit/liteinst_launch/lib"] = counts(278)
        added = {"unit/liteinst_artifact/lib": counts(20), "doc/liteinst_artifact": counts(0),
                 "unit/liteinst_rewrite/lib": counts(62), "unit/liteinst_rewrite/main": counts(0),
                 "doc/liteinst_rewrite": counts(0), "test/integration": counts(11),
                 "test/bounded_proc_stat": counts(7), "test/elf_exec_provider_contract": counts(8),
                 "test/eviction_chain_grouping_contract": counts(5),
                 "test/frontend_native_calibrations": counts(26)}
        self.assertEqual(len(workspace), 88)
        self.assertEqual(sum(row["tests"] for row in workspace.values()), 1649)
        self.assertEqual(sum(row["ignored"] for row in workspace.values()), 4)
        for name, value in added.items():
            self.assertEqual(workspace.pop(name), value)
        for name, new, old in (("unit/liteinst2/lib", counts(208, 1), counts(184, 1)),
                               ("unit/rapid_profiler/lib", counts(98), counts(24)),
                               ("doc/rapid_profiler", counts(10), counts(2)),
                               ("test/eviction_chain_oracle", counts(29), counts(28))):
            self.assertEqual(workspace[name], new)
            workspace[name] = old
        # Digests pinned from the pre-merge corpus at 3541a54, not generated from
        # the candidate catalog. A removed, renamed or relaxed old row fails.
        self.assertEqual(digest(workspace), "3e272269ffbb5854be993da867ab1f8f88f8513414aac93ca66e89825428283b")
        serial = copy.deepcopy(corpus["harness_test_counts"]["serial_launch"])
        self.assertEqual(serial.pop(EXEC_HARNESS), counts(5))
        self.assertEqual(serial["unit/liteinst_launch/lib"], counts(278 + UNIT_INCREMENT))
        serial["unit/liteinst_launch/lib"] = counts(278)
        self.assertEqual(len(serial), 26)
        self.assertEqual(sum(row["tests"] for row in serial.values()), 565)
        self.assertEqual(digest(serial), "701284ec0b5d8e593d6459a6d101deeb381de7430baa4683875f31d1c7027ea6")
        collections = {key: corpus[key] for key in ("native_cases", "dynamic_admission_fixtures",
                       "dynamic_matrix_cases", "native_validation_fixtures")}
        self.assertEqual(collections["native_validation_fixtures"][42:], EXEC_ROWS + PRIVATE_ROWS + FAILURE_ROWS)
        collections["native_validation_fixtures"] = collections["native_validation_fixtures"][:42]
        self.assertEqual(digest(collections), "a1d30223eafc695832627dae1a58a600d899bf8814c6182c5556ee1b117af365")
