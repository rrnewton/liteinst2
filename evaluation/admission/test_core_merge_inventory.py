"""Static merged-core catalog and strict Cargo header controls."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

import parsing
from test_parsing import counts, header, summary
from test_exec_fixtures import HARNESS as EXEC_HARNESS, ROWS as EXEC_ROWS, PRIVATE_ROWS, UNIT_INCREMENT


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
        corpus = json.loads(Path(__file__).with_name("corpus.json").read_text())
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
        self.assertEqual(collections["native_validation_fixtures"][42:], EXEC_ROWS + PRIVATE_ROWS)
        collections["native_validation_fixtures"] = collections["native_validation_fixtures"][:42]
        self.assertEqual(digest(collections), "a1d30223eafc695832627dae1a58a600d899bf8814c6182c5556ee1b117af365")
