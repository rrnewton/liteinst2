"""Static merged-core catalog and strict Cargo header controls."""

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from core_a3_inventory import (ADDED_HARNESSES as A3_ADDED, CHANGED_HARNESSES as A3_CHANGED,
                               RUST_METHODS as A3_METHODS, SOURCE_WIRING as A3_WIRING,
                               PRE_CORE_A3_CORPUS_SHA256, before_core_a3,
                               validate_core_a3_source)
import core_719519_inventory as core719
from core_719519_inventory import before_core_719519
from ordinary_shared_inventory import before_ordinary_shared
from ordinary_thirtytwo_inventory import before_ordinary_thirtytwo
from core_c73f159_inventory import before_core_c73f159
import core_c73f159_inventory as corec73
from core_ae149a9_inventory import before_core_ae149a9
import core_ae149a9_inventory as coreae
from core_041bd4a_inventory import before_core_041bd4a
from inprocess_inventory import before_inprocess
import core_041bd4a_inventory as core041
import inprocess_inventory as inprocess
from owned_stack_inventory import before_owned_stack
from runtime_stack_consumer_inventory import before_runtime_stack_consumer
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

        # Prospective exact Cargo contract from test=true source wiring, not a native capture.
        example = "     Running unittests examples/verify_common_core.rs (target/debug/examples/verify_common_core-123abc)"
        expected = {"unit/verify_common_core/verify_common_core": counts(3)}
        valid = "\n".join((example, "running 3 tests", summary(3)))
        row = parsing.parse_harnesses(valid, expected, 0)[0]
        self.assertEqual(row["outer"]["passed"], 3)
        self.assertEqual(row["nested"], [])
        for text in (valid.replace("examples/verify_common_core.rs", "examples/other.rs"),
                     valid.replace("examples/verify_common_core.rs", "src/verify_common_core.rs"),
                     valid.replace("examples/verify_common_core.rs", "examples/common_sites.rs"),
                     valid.replace("verify_common_core-", "common_sites-"),
                     valid.replace("verify_common_core-", "other-"),
                     valid.replace("target/debug/examples/", "target/debug/deps/"),
                     valid.replace("target/debug/examples/", "target/release/examples/"),
                     valid.replace("target/debug/examples/", "/PRIVATE_SENTINEL/"),
                     valid.replace("examples/verify_common_core.rs", "/PRIVATE_SENTINEL/verify_common_core.rs"),
                     valid.replace("verify_common_core-123abc", "verify_common_core-NOTHEX"),
                     valid + "\n" + valid, example + "\nrunning 3 tests\n"):
            with self.subTest(example=text), self.assertRaises(parsing.InvalidEvidence) as caught:
                parsing.parse_harnesses(text, expected, 0)
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(caught.exception.partial))
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        pages = "     Running tests/e9_common_core_pages_contract.rs (target/debug/deps/e9_common_core_pages_contract-123abc)"
        row = parsing.parse_harnesses("\n".join((pages, "running 9 tests", summary(9))),
                                      {"test/e9_common_core_pages_contract": counts(9)}, 0)[0]
        self.assertEqual(row["outer"]["passed"], 9)

        # The two new root integration targets use the unchanged Cargo grammar.
        for name in ("cross_function_neighbor", "foreign_neighbor_engine"):
            expected = {"test/" + name: counts(9)}
            first = header(name, unit=False)
            valid = "\n".join((first, "running 9 tests", summary(9)))
            row = parsing.parse_harnesses(valid, expected, 0)[0]
            self.assertEqual(row["id"], "test/" + name)
            self.assertEqual(row["outer"]["passed"], 9)
            self.assertEqual(row["nested"], [])
            for text in (valid + "\n" + valid, first + "\nrunning 9 tests\n",
                         valid.replace("running 9 tests", "running 8 tests"),
                         valid.replace("running 9 tests", "running 10 tests"),
                         valid.replace(summary(9), summary(8, failed=1)),
                         valid.replace(summary(9), summary(8, ignored=1)),
                         valid.replace(summary(9), summary(9, filtered=1)),
                         valid.replace(name + "-123abc", "unknown-123abc"),
                         valid.replace("target/debug/deps/", "/PRIVATE_SENTINEL/"),
                         valid.replace(name + "-123abc", name + "-NOTHEX")):
                with self.subTest(core719=name, text=text), self.assertRaises(parsing.InvalidEvidence) as caught:
                    parsing.parse_harnesses(text, expected, 0)
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(caught.exception.partial))
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        # c73 adds methods to existing harnesses; their exact old grammar remains.
        for identity, (_, current_count) in corec73.CHANGED_HARNESSES.items():
            total = current_count["tests"]
            if identity == "unit/verify_common_core/verify_common_core":
                first = "     Running unittests examples/verify_common_core.rs (target/debug/examples/verify_common_core-123abc)"
            elif identity == "unit/liteinst_rewrite/lib":
                first = header("liteinst_rewrite")
            else:
                first = header(identity.split("/", 1)[1], unit=False)
            valid = "\n".join((first, f"running {total} tests", summary(total)))
            row = parsing.parse_harnesses(valid, {identity: counts(total)}, 0)[0]
            self.assertEqual(row["id"], identity)
            self.assertEqual(row["outer"]["passed"], total)
            self.assertEqual(row["nested"], [])
            for text in (valid + "\n" + valid, first + f"\nrunning {total} tests\n",
                         valid.replace(f"running {total} tests", f"running {total - 1} tests"),
                         valid.replace(f"running {total} tests", f"running {total + 1} tests"),
                         valid.replace(summary(total), summary(total - 1, failed=1)),
                         valid.replace(summary(total), summary(total - 1, ignored=1)),
                         valid.replace(summary(total), summary(total, filtered=1)),
                         valid.replace(first, header("other", unit=False)),
                         valid.replace("target/debug/", "/PRIVATE_SENTINEL/"),
                         valid.replace("-123abc", "-NOTHEX")):
                with self.subTest(corec73_harness=identity, text=text), self.assertRaises(parsing.InvalidEvidence) as caught:
                    parsing.parse_harnesses(text, {identity: counts(total)}, 0)
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(caught.exception.partial))
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        # ae149a9 adds methods to existing harnesses; their exact old grammar remains.
        for identity, (_, current_count) in coreae.CHANGED_HARNESSES.items():
            total = current_count["tests"]
            if identity == "unit/verify_common_core/verify_common_core":
                first = "     Running unittests examples/verify_common_core.rs (target/debug/examples/verify_common_core-123abc)"
            elif identity == "unit/liteinst_rewrite/lib":
                first = header("liteinst_rewrite")
            else:
                first = header(identity.split("/", 1)[1], unit=False)
            valid = "\n".join((first, f"running {total} tests", summary(total)))
            row = parsing.parse_harnesses(valid, {identity: counts(total)}, 0)[0]
            self.assertEqual(row["id"], identity)
            self.assertEqual(row["outer"]["passed"], total)
            self.assertEqual(row["nested"], [])
            for text in (valid + "\n" + valid, first + f"\nrunning {total} tests\n",
                         valid.replace(f"running {total} tests", f"running {total - 1} tests"),
                         valid.replace(f"running {total} tests", f"running {total + 1} tests"),
                         valid.replace(summary(total), summary(total - 1, failed=1)),
                         valid.replace(summary(total), summary(total - 1, ignored=1)),
                         valid.replace(summary(total), summary(total, filtered=1)),
                         valid.replace(first, header("other", unit=False)),
                         valid.replace("target/debug/", "/PRIVATE_SENTINEL/"),
                         valid.replace("-123abc", "-NOTHEX")):
                with self.subTest(coreae_harness=identity, text=text), self.assertRaises(parsing.InvalidEvidence) as caught:
                    parsing.parse_harnesses(text, {identity: counts(total)}, 0)
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

        valid = "\n".join((header("liteinst2"), "running 213 tests", "running 1 test",
                           summary(212, ignored=1)))
        row = parsing.parse_harnesses(valid, {"unit/liteinst2/lib": counts(213, 1)}, 0)[0]
        self.assertEqual(row["outer"]["passed"], 212)
        self.assertEqual(row["unmatched_nested_starts"], 1)
        self.assertEqual(row["nested"], [])
        for name, total, child, ignored, filtered in (
                ("liteinst2", 212, 1, 1, 0), ("liteinst2", 214, 1, 1, 0),
                ("other", 213, 1, 1, 0), ("liteinst2", 213, 2, 1, 0),
                ("liteinst2", 213, 1, 0, 0), ("liteinst2", 213, 1, 1, 1)):
            text = "\n".join((header(name), f"running {total} tests", f"running {child} tests",
                              summary(total - ignored, ignored=ignored, filtered=filtered)))
            with self.subTest(name=name, total=total, child=child, ignored=ignored, filtered=filtered), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(text, {f"unit/{name}/lib": counts(total, ignored)}, 0)

        # Six source-derived managed unit controls preserve the same ptrace child.
        valid = "\n".join((header("liteinst2"), "running 219 tests", "running 1 test",
                           summary(218, ignored=1)))
        row = parsing.parse_harnesses(valid, {"unit/liteinst2/lib": counts(219, 1)}, 0)[0]
        self.assertEqual(row["outer"]["passed"], 218)
        self.assertEqual(row["unmatched_nested_starts"], 1)
        self.assertEqual(row["nested"], [])
        for name, total, child, ignored, filtered in (
                ("liteinst2", 218, 1, 1, 0), ("liteinst2", 220, 1, 1, 0),
                ("other", 219, 1, 1, 0), ("liteinst2", 219, 2, 1, 0),
                ("liteinst2", 219, 1, 0, 0), ("liteinst2", 219, 1, 1, 1)):
            text = "\n".join((header(name), f"running {total} tests", f"running {child} tests",
                              summary(total - ignored, ignored=ignored, filtered=filtered)))
            with self.subTest(core041=name, total=total, child=child, ignored=ignored, filtered=filtered), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(text, {f"unit/{name}/lib": counts(total, ignored)}, 0)
        for text in (valid.replace("running 1 test", "running 1 test\nrunning 1 test"),
                     valid.replace(summary(218, ignored=1), summary(217, failed=1, ignored=1)),
                     valid + "\n" + valid):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(text, {"unit/liteinst2/lib": counts(219, 1)}, 0)
        # Added profiler units and compile-fail doctests use ordinary complete summaries.
        for identity, total in (("unit/rapid_profiler/lib", 119),
                                ("doc/liteinst2", 3), ("doc/rapid_profiler", 11)):
            first = header("rapid_profiler") if identity.startswith("unit/") else "   Doc-tests " + identity[4:]
            expected = {identity: counts(total)}
            valid = "\n".join((first, f"running {total} tests", summary(total)))
            row = parsing.parse_harnesses(valid, expected, 0)[0]
            self.assertEqual(row["id"], identity)
            self.assertEqual(row["outer"]["passed"], total)
            self.assertEqual(row["nested"], [])
            for text in (valid + "\n" + valid, first + f"\nrunning {total} tests\n",
                         valid.replace(f"running {total} tests", f"running {total - 1} tests"),
                         valid.replace(summary(total), summary(total - 1, failed=1)),
                         valid.replace(summary(total), summary(total - 1, ignored=1)),
                         valid.replace(summary(total), summary(total, filtered=1)),
                         valid.replace("rapid_profiler", "PRIVATE_SENTINEL") if "rapid_profiler" in first else valid.replace("liteinst2", "PRIVATE_SENTINEL")):
                with self.subTest(core041_summary=identity), self.assertRaises(parsing.InvalidEvidence) as caught:
                    parsing.parse_harnesses(text, expected, 0)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        # New crate cohorts use complete ordinary summaries, including zero docs.
        for identity, total in (("unit/liteinst_inprocess/lib", 6), ("doc/liteinst_inprocess", 0)):
            first = header("liteinst_inprocess") if identity.startswith("unit/") else "   Doc-tests liteinst_inprocess"
            expected = {identity: counts(total)}
            valid = "\n".join((first, f"running {total} tests", summary(total)))
            row = parsing.parse_harnesses(valid, expected, 0)[0]
            self.assertEqual(row["id"], identity)
            self.assertEqual(row["outer"]["passed"], total)
            self.assertEqual(row["nested"], [])
            for text in (valid + "\n" + valid, first + f"\nrunning {total} tests\n",
                         valid.replace(f"running {total} tests", f"running {total + 1} tests"),
                         valid.replace(summary(total), summary(total, failed=1)),
                         valid.replace(summary(total), summary(total, ignored=1)),
                         valid.replace(summary(total), summary(total, filtered=1)),
                         valid.replace("liteinst_inprocess", "PRIVATE_SENTINEL")):
                with self.subTest(inprocess_summary=identity), self.assertRaises(parsing.InvalidEvidence) as caught:
                    parsing.parse_harnesses(text, expected, 0)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

    def test_catalog_preserves_all_old_harnesses_and_native_collection_identities(self):
        current041 = json.loads(Path(__file__).with_name("corpus.json").read_text())
        inprocess_current = copy.deepcopy(current041)
        current041 = before_inprocess(current041)
        self.assertEqual(inprocess_current, json.loads(Path(__file__).with_name("corpus.json").read_text()))
        self.assertEqual(inprocess.digest(inprocess_current), inprocess.CURRENT_INPROCESS_CORPUS_SHA256)
        self.assertEqual(inprocess.digest(current041), inprocess.PRE_INPROCESS_CORPUS_SHA256)
        self.assertEqual(inprocess.PRE_INPROCESS_CORPUS_SHA256, core041.CURRENT_CORE_041BD4A_CORPUS_SHA256)
        inprocess_rows = inprocess_current["harness_test_counts"]["workspace_tests"]
        self.assertEqual(len(inprocess_rows), 97)
        self.assertEqual(sum(row["tests"] for row in inprocess_rows.values()), 2296)
        self.assertEqual(sum(row["ignored"] for row in inprocess_rows.values()), 4)
        self.assertEqual(inprocess_current["harness_test_counts"]["serial_launch"], current041["harness_test_counts"]["serial_launch"])
        self.assertEqual({key: value for key, value in inprocess_current.items() if key != "harness_test_counts"},
                         {key: value for key, value in current041.items() if key != "harness_test_counts"})
        self.assertEqual(len(inprocess.RUST_METHODS), 6)
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^inprocess_inventory_differs$"):
            before_inprocess(current041)
        for identity, expected in inprocess.ADDED_HARNESSES.items():
            self.assertEqual(inprocess_rows[identity], expected)
            for mode in ("missing", "rename", "low", "high", "ignored", "float", "extra"):
                changed = copy.deepcopy(inprocess_current)
                rows = changed["harness_test_counts"]["workspace_tests"]
                if mode == "missing": del rows[identity]
                elif mode == "rename": rows[identity + "_PRIVATE_SENTINEL"] = rows.pop(identity)
                elif mode == "low": rows[identity]["tests"] -= 1
                elif mode == "high": rows[identity]["tests"] += 1
                elif mode == "ignored": rows[identity]["ignored"] += 1
                elif mode == "float": rows[identity]["tests"] = float(rows[identity]["tests"])
                else: rows[identity]["extra"] = "PRIVATE_SENTINEL"
                with self.subTest(inprocess=identity, mode=mode), self.assertRaisesRegex(
                        parsing.InvalidEvidence, "^inprocess_inventory_differs$"):
                    before_inprocess(changed)
        for key in inprocess_current:
            changed = copy.deepcopy(inprocess_current)
            del changed[key]
            with self.subTest(inprocess_missing=key), self.assertRaisesRegex(
                    parsing.InvalidEvidence, "^inprocess_inventory_differs$"):
                before_inprocess(changed)
        inprocess_read = Path.read_bytes
        for target in inprocess.NEW_SOURCE_SHA256:
            def changed_inprocess_source(path, *args, **kwargs):
                data = inprocess_read(path, *args, **kwargs)
                return data + b"\n// PRIVATE_SENTINEL\n" if path.as_posix().endswith(target) else data
            with self.subTest(inprocess_source=target), patch("inprocess_inventory.Path.read_bytes", changed_inprocess_source):
                with self.assertRaisesRegex(parsing.InvalidEvidence, "^inprocess_source_inventory_differs$"):
                    before_inprocess(inprocess_current)
        untouched041 = copy.deepcopy(current041)
        previous041 = before_core_041bd4a(current041)
        self.assertEqual(current041, untouched041)
        self.assertEqual(digest(current041), core041.CURRENT_CORE_041BD4A_CORPUS_SHA256)
        self.assertEqual(digest(previous041), core041.PRE_CORE_041BD4A_CORPUS_SHA256)
        self.assertEqual(digest(previous041), coreae.CURRENT_CORE_AE149A9_CORPUS_SHA256)
        self.assertEqual(sum(map(len, core041.ADDED_RUST_METHODS.values())), 19)
        self.assertEqual(len(core041.DOC_TESTS), 4)
        self.assertEqual(len(core041.COMPILED_METHODS), 23)
        self.assertEqual(len({(x["harness"], x["test"]) for x in core041.COMPILED_METHODS}), 23)
        workspace041 = current041["harness_test_counts"]["workspace_tests"]
        self.assertEqual(len(workspace041), 95)
        self.assertEqual(sum(row["tests"] for row in workspace041.values()), 2290)
        self.assertEqual(sum(row["ignored"] for row in workspace041.values()), 4)
        self.assertEqual(workspace041["unit/liteinst_launch/lib"], counts(737))
        self.assertEqual(current041["harness_test_counts"]["serial_launch"],
                         previous041["harness_test_counts"]["serial_launch"])
        self.assertEqual({key: value for key, value in current041.items() if key != "harness_test_counts"},
                         {key: value for key, value in previous041.items() if key != "harness_test_counts"})
        self.assertEqual(len(current041["native_validation_fixtures"]), 108)
        self.assertEqual(current041["recorder_tests"], 330)
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_041bd4a_inventory_differs$"):
            before_core_041bd4a(previous041)
        for identity, (prior, latest) in core041.CHANGED_HARNESSES.items():
            instances = [x for x in core041.COMPILED_METHODS if x["harness"] == identity]
            self.assertEqual(latest["tests"] - prior["tests"], len(instances))
            for mode in ("missing", "rename", "low", "high", "ignored", "float", "extra"):
                changed = copy.deepcopy(current041)
                rows = changed["harness_test_counts"]["workspace_tests"]
                if mode == "missing": del rows[identity]
                elif mode == "rename": rows[identity + "_PRIVATE_SENTINEL"] = rows.pop(identity)
                elif mode == "low": rows[identity]["tests"] -= 1
                elif mode == "high": rows[identity]["tests"] += 1
                elif mode == "ignored": rows[identity]["ignored"] += 1
                elif mode == "float": rows[identity]["tests"] = float(rows[identity]["tests"])
                else: rows[identity]["extra"] = "PRIVATE_SENTINEL"
                with self.subTest(core041=identity, mode=mode), self.assertRaisesRegex(
                        parsing.InvalidEvidence, "^core_041bd4a_inventory_differs$") as caught:
                    before_core_041bd4a(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for field in current041:
            changed = copy.deepcopy(current041)
            del changed[field]
            with self.subTest(core041_missing=field), self.assertRaisesRegex(
                    parsing.InvalidEvidence, "^core_041bd4a_inventory_differs$"):
                before_core_041bd4a(changed)
        for mutation in ("extra", "native", "serial", "recorder"):
            changed = copy.deepcopy(current041)
            if mutation == "extra": changed["extra"] = "PRIVATE_SENTINEL"
            elif mutation == "native": changed["native_validation_fixtures"].pop()
            elif mutation == "serial": changed["harness_test_counts"]["serial_launch"]["unit/liteinst_launch/lib"]["tests"] -= 1
            else: changed["recorder_tests"] -= 1
            with self.subTest(core041_full=mutation), self.assertRaisesRegex(
                    parsing.InvalidEvidence, "^core_041bd4a_inventory_differs$"):
                before_core_041bd4a(changed)
        read041 = Path.read_bytes
        for target in core041.SOURCE_SHA256:
            for mode in ("missing", "changed"):
                def altered041(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        if mode == "missing": raise OSError("PRIVATE_SENTINEL /private/source")
                        return read041(path, *args, **kwargs) + b"\n// PRIVATE_SENTINEL\n"
                    return read041(path, *args, **kwargs)
                with self.subTest(core041_source=target, mode=mode), patch(
                        "core_041bd4a_inventory.Path.read_bytes", altered041):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_041bd4a_source_inventory_differs$") as caught:
                        core041.require_current_core_041bd4a_sources()
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for target, names in core041.RUST_METHODS.items():
            for mode in ("rename", "extra", "ignored"):
                def altered041_method(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        source = read041(path, *args, **kwargs)
                        if mode == "rename": return source.replace(names[0].encode(), b"PRIVATE_SENTINEL", 1)
                        if mode == "extra": return source + b"\n#[test]\nfn PRIVATE_SENTINEL() {}\n"
                        return source.replace(b"#[test]", b"#[test]\n#[ignore]", 1)
                    return read041(path, *args, **kwargs)
                with self.subTest(core041_method=target, mode=mode), patch(
                        "core_041bd4a_inventory.Path.read_bytes", altered041_method):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_041bd4a_source_inventory_differs$"):
                        core041.require_current_core_041bd4a_sources()
        for target in {row["path"] for row in core041.DOC_TESTS}:
            def altered041_doc(path, *args, **kwargs):
                source = read041(path, *args, **kwargs)
                return source.replace(b"```compile_fail", b"```ignore", 1) if path.as_posix().endswith(target) else source
            with self.subTest(core041_doctest=target), patch("core_041bd4a_inventory.Path.read_bytes", altered041_doc):
                with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_041bd4a_source_inventory_differs$"):
                    core041.require_current_core_041bd4a_sources()

        current_ae = previous041
        untouched_ae = copy.deepcopy(current_ae)
        previous_ae = before_core_ae149a9(current_ae)
        self.assertEqual(current_ae, untouched_ae)
        self.assertEqual(coreae.digest(current_ae), coreae.CURRENT_CORE_AE149A9_CORPUS_SHA256)
        self.assertEqual(coreae.digest(previous_ae), coreae.PRE_CORE_AE149A9_CORPUS_SHA256)
        self.assertEqual(sum(map(len, coreae.RUST_METHODS.values())), 5)
        self.assertEqual(len(coreae.COMPILED_METHODS), 35)
        self.assertEqual(len({(row["harness"], row["test"]) for row in coreae.COMPILED_METHODS}), 35)
        workspace_ae = current_ae["harness_test_counts"]["workspace_tests"]
        self.assertEqual(len(workspace_ae), 95)
        self.assertEqual(sum(row["tests"] for row in workspace_ae.values()), 2267)
        self.assertEqual(sum(row["ignored"] for row in workspace_ae.values()), 4)
        self.assertEqual(workspace_ae["unit/liteinst_launch/lib"], counts(737))
        self.assertEqual(current_ae["harness_test_counts"]["serial_launch"],
                         previous_ae["harness_test_counts"]["serial_launch"])
        self.assertEqual(current_ae["native_validation_fixtures"], previous_ae["native_validation_fixtures"])
        self.assertEqual(len(current_ae["native_validation_fixtures"]), 108)
        self.assertEqual(current_ae["recorder_tests"], 330)
        self.assertEqual({key: value for key, value in current_ae.items() if key != "harness_test_counts"},
                         {key: value for key, value in previous_ae.items() if key != "harness_test_counts"})
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_ae149a9_inventory_differs$"):
            before_core_ae149a9(previous_ae)
        for identity, (prior, current_count) in coreae.CHANGED_HARNESSES.items():
            instances = [row for row in coreae.COMPILED_METHODS if row["harness"] == identity]
            self.assertEqual(current_count["tests"] - prior["tests"], len(instances))
            for mode in ("missing", "rename", "low", "high", "ignored", "float", "extra"):
                changed = copy.deepcopy(current_ae)
                group = changed["harness_test_counts"]["workspace_tests"]
                if mode == "missing": del group[identity]
                elif mode == "rename": group[identity + "_PRIVATE_SENTINEL"] = group.pop(identity)
                elif mode == "low": group[identity]["tests"] -= 1
                elif mode == "high": group[identity]["tests"] += 1
                elif mode == "ignored": group[identity]["ignored"] = 1
                elif mode == "float": group[identity]["tests"] = float(group[identity]["tests"])
                else: group[identity]["extra"] = "PRIVATE_SENTINEL"
                with self.subTest(coreae=identity, mode=mode), self.assertRaisesRegex(
                        parsing.InvalidEvidence, "^core_ae149a9_inventory_differs$") as caught:
                    before_core_ae149a9(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for field in current_ae:
            changed = copy.deepcopy(current_ae)
            del changed[field]
            with self.subTest(coreae_missing=field), self.assertRaisesRegex(
                    parsing.InvalidEvidence, "^core_ae149a9_inventory_differs$"):
                before_core_ae149a9(changed)
        changed = copy.deepcopy(current_ae)
        changed["extra"] = "PRIVATE_SENTINEL"
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_ae149a9_inventory_differs$"):
            before_core_ae149a9(changed)
        read_ae = Path.read_bytes
        for target in coreae.SOURCE_SHA256:
            for mode in ("missing", "changed"):
                def altered_ae(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        if mode == "missing": raise OSError("PRIVATE_SENTINEL /private/source")
                        return read_ae(path, *args, **kwargs) + b"\n// PRIVATE_SENTINEL\n"
                    return read_ae(path, *args, **kwargs)
                with self.subTest(coreae_source=target, mode=mode), patch(
                        "core_ae149a9_inventory.Path.read_bytes", altered_ae):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_ae149a9_source_inventory_differs$") as caught:
                        coreae.require_current_core_ae149a9_sources()
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for target, names in coreae.RUST_METHODS.items():
            for mode in ("rename", "extra", "ignored"):
                def altered_ae_method(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        raw_source = read_ae(path, *args, **kwargs)
                        if mode == "rename": return raw_source.replace(names[0].encode(), b"PRIVATE_SENTINEL", 1)
                        if mode == "extra": return raw_source + b"\n#[test]\nfn PRIVATE_SENTINEL() {}\n"
                        return raw_source.replace(b"#[test]", b"#[test]\n#[ignore]", 1)
                    return read_ae(path, *args, **kwargs)
                with self.subTest(coreae_method=target, mode=mode), patch(
                        "core_ae149a9_inventory.Path.read_bytes", altered_ae_method):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_ae149a9_source_inventory_differs$") as caught:
                        coreae.require_current_core_ae149a9_sources()
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        # Authenticate the complete merged core corpus before exposing the
        # exact old fixture to every historical assertion below.
        # Exact inverse bytes protect historical source predicates, without
        # accepting the old file at the current-source ingest boundary.
        root_ae = Path(__file__).resolve().parents[2]
        self.assertEqual(set(coreae.SOURCE_PROJECTIONS), {
            "tests/support/e9_common_core.rs",
            "tools/elf-rewrite/examples/verify_common_core.rs",
            "tools/exception-oracle/Cargo.toml"})
        for target, projection in coreae.SOURCE_PROJECTIONS.items():
            current_source = (root_ae / target).read_bytes()
            prior_source = coreae.source_before_core_ae149a9(target, current_source)
            self.assertEqual(hashlib.sha256(current_source).hexdigest(), projection["current_sha256"])
            self.assertEqual(hashlib.sha256(prior_source).hexdigest(), corec73.SOURCE_SHA256[target])
            self.assertNotEqual(current_source, prior_source)
            for bad_source in (prior_source, current_source + b"\n// PRIVATE_SENTINEL\n"):
                with self.subTest(ae_inverse=target), self.assertRaisesRegex(
                        parsing.InvalidEvidence, "^core_c73f159_source_inventory_differs$") as caught:
                    coreae.source_before_core_ae149a9(target, bad_source)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        current_c73 = previous_ae
        untouched_c73 = copy.deepcopy(current_c73)
        previous_c73 = before_core_c73f159(current_c73)
        self.assertEqual(current_c73, untouched_c73)
        self.assertEqual(corec73.digest(current_c73), corec73.CURRENT_CORE_C73F159_CORPUS_SHA256)
        self.assertEqual(corec73.digest(previous_c73), corec73.PRE_CORE_C73F159_CORPUS_SHA256)
        self.assertEqual(sum(map(len, corec73.RUST_METHODS.values())), 17)
        self.assertEqual(len(corec73.COMPILED_METHODS), 32)
        self.assertEqual(len({(row["harness"], row["test"]) for row in corec73.COMPILED_METHODS}), 32)
        workspace_c73 = current_c73["harness_test_counts"]["workspace_tests"]
        self.assertEqual(len(workspace_c73), 95)
        self.assertEqual(sum(row["tests"] for row in workspace_c73.values()), 2232)
        self.assertEqual(sum(row["ignored"] for row in workspace_c73.values()), 4)
        self.assertEqual(workspace_c73["unit/liteinst_launch/lib"], counts(737))
        self.assertEqual(current_c73["harness_test_counts"]["serial_launch"],
                         previous_c73["harness_test_counts"]["serial_launch"])
        self.assertEqual(current_c73["native_validation_fixtures"], previous_c73["native_validation_fixtures"])
        self.assertEqual(len(current_c73["native_validation_fixtures"]), 108)
        self.assertEqual(current_c73["recorder_tests"], 330)
        self.assertEqual({key: value for key, value in current_c73.items() if key != "harness_test_counts"},
                         {key: value for key, value in previous_c73.items() if key != "harness_test_counts"})
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_c73f159_inventory_differs$"):
            before_core_c73f159(previous_c73)
        for identity, (prior, current_count) in corec73.CHANGED_HARNESSES.items():
            instances = [row for row in corec73.COMPILED_METHODS if row["harness"] == identity]
            self.assertEqual(current_count["tests"] - prior["tests"], len(instances))
            for mode in ("missing", "rename", "low", "high", "ignored", "float", "extra"):
                changed = copy.deepcopy(current_c73)
                group = changed["harness_test_counts"]["workspace_tests"]
                if mode == "missing": del group[identity]
                elif mode == "rename": group[identity + "_PRIVATE_SENTINEL"] = group.pop(identity)
                elif mode == "low": group[identity]["tests"] -= 1
                elif mode == "high": group[identity]["tests"] += 1
                elif mode == "ignored": group[identity]["ignored"] = 1
                elif mode == "float": group[identity]["tests"] = float(group[identity]["tests"])
                else: group[identity]["extra"] = "PRIVATE_SENTINEL"
                with self.subTest(corec73=identity, mode=mode), self.assertRaisesRegex(
                        parsing.InvalidEvidence, "^core_c73f159_inventory_differs$") as caught:
                    before_core_c73f159(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for field in current_c73:
            changed = copy.deepcopy(current_c73)
            del changed[field]
            with self.subTest(corec73_missing=field), self.assertRaisesRegex(
                    parsing.InvalidEvidence, "^core_c73f159_inventory_differs$"):
                before_core_c73f159(changed)
        changed = copy.deepcopy(current_c73)
        changed["extra"] = "PRIVATE_SENTINEL"
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_c73f159_inventory_differs$"):
            before_core_c73f159(changed)
        read_c73 = Path.read_bytes
        for target in corec73.SOURCE_SHA256:
            for mode in ("missing", "changed"):
                def altered_c73(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        if mode == "missing": raise OSError("PRIVATE_SENTINEL /private/source")
                        return read_c73(path, *args, **kwargs) + b"\n// PRIVATE_SENTINEL\n"
                    return read_c73(path, *args, **kwargs)
                with self.subTest(corec73_source=target, mode=mode), patch(
                        "core_c73f159_inventory.Path.read_bytes", altered_c73):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_c73f159_source_inventory_differs$") as caught:
                        corec73.require_current_core_c73f159_sources()
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for target, names in corec73.RUST_METHODS.items():
            for mode in ("rename", "extra", "ignored"):
                def altered_c73_method(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        raw_source = read_c73(path, *args, **kwargs)
                        if mode == "rename": return raw_source.replace(names[0].encode(), b"PRIVATE_SENTINEL", 1)
                        if mode == "extra": return raw_source + b"\n#[test]\nfn PRIVATE_SENTINEL() {}\n"
                        return raw_source.replace(b"#[test]", b"#[test]\n#[ignore]", 1)
                    return read_c73(path, *args, **kwargs)
                with self.subTest(corec73_method=target, mode=mode), patch(
                        "core_c73f159_inventory.Path.read_bytes", altered_c73_method):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_c73f159_source_inventory_differs$") as caught:
                        corec73.require_current_core_c73f159_sources()
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        # Authenticate the complete merged core corpus before exposing the
        # exact old fixture to every historical assertion below.
        merged = before_ordinary_shared(before_ordinary_thirtytwo(before_core_c73f159(before_core_ae149a9(before_core_041bd4a(before_inprocess(json.loads(Path(__file__).with_name("corpus.json").read_text())))))))
        untouched = copy.deepcopy(merged)
        historical = before_core_719519(merged)
        self.assertEqual(merged, untouched)
        self.assertEqual(core719.digest(merged), core719.CURRENT_CORE_719519_CORPUS_SHA256)
        self.assertEqual(core719.digest(historical), core719.PRE_CORE_719519_CORPUS_SHA256)
        self.assertEqual(sum(map(len, core719.RUST_METHODS.values())), 18)
        workspace719 = merged["harness_test_counts"]["workspace_tests"]
        self.assertEqual(len(workspace719), 95)
        self.assertEqual(sum(row["tests"] for row in workspace719.values()), 2166)
        self.assertEqual(sum(row["ignored"] for row in workspace719.values()), 4)
        self.assertEqual(workspace719["unit/liteinst2/lib"], counts(213, 1))
        self.assertEqual(workspace719["unit/liteinst_launch/lib"], counts(703))
        self.assertEqual(merged["harness_test_counts"]["serial_launch"],
                         historical["harness_test_counts"]["serial_launch"])
        self.assertEqual(merged["native_validation_fixtures"], historical["native_validation_fixtures"])
        self.assertEqual(len(merged["native_validation_fixtures"]), 103)
        self.assertEqual(merged["recorder_tests"], 330)
        self.assertEqual({key: value for key, value in workspace719.items()
                          if key not in core719.ADDED_HARNESSES},
                         historical["harness_test_counts"]["workspace_tests"])
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_719519_inventory_differs$"):
            before_core_719519(historical)
        for identity in core719.ADDED_HARNESSES:
            for mode in ("missing", "rename", "count_low", "count_high", "ignored", "float", "extra"):
                changed = copy.deepcopy(merged)
                group = changed["harness_test_counts"]["workspace_tests"]
                if mode == "missing": del group[identity]
                elif mode == "rename": group[identity + "_PRIVATE_SENTINEL"] = group.pop(identity)
                elif mode == "count_low": group[identity]["tests"] = 8
                elif mode == "count_high": group[identity]["tests"] = 10
                elif mode == "ignored": group[identity]["ignored"] = 1
                elif mode == "float": group[identity]["tests"] = 9.0
                else: group[identity]["extra"] = "PRIVATE_SENTINEL"
                with self.subTest(core719=identity, mode=mode), self.assertRaisesRegex(
                        parsing.InvalidEvidence, "^core_719519_inventory_differs$") as caught:
                    before_core_719519(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for field in merged:
            for mode in ("missing", "changed"):
                changed = copy.deepcopy(merged)
                if mode == "missing": del changed[field]
                else: changed[field] = "PRIVATE_SENTINEL /private/source"
                with self.subTest(core719_field=field, mode=mode), self.assertRaisesRegex(
                        parsing.InvalidEvidence, "^core_719519_inventory_differs$") as caught:
                    before_core_719519(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        changed = copy.deepcopy(merged)
        changed["extra"] = "PRIVATE_SENTINEL"
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_719519_inventory_differs$"):
            before_core_719519(changed)
        read_bytes = Path.read_bytes
        for target in core719.SOURCE_SHA256:
            for mode in ("missing", "changed"):
                def altered719(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        if mode == "missing": raise OSError("PRIVATE_SENTINEL /private/source")
                        return read_bytes(path, *args, **kwargs) + b"\n// PRIVATE_SENTINEL\n"
                    return read_bytes(path, *args, **kwargs)
                with self.subTest(core719_source=target, mode=mode), patch(
                        "core_719519_inventory.Path.read_bytes", altered719):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_719519_source_inventory_differs$") as caught:
                        before_core_719519(merged)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for target, names in core719.RUST_METHODS.items():
            for mode in ("rename", "extra", "ignored"):
                def altered_method719(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        data = read_bytes(path, *args, **kwargs)
                        if mode == "rename": return data.replace(names[0].encode(), b"PRIVATE_SENTINEL", 1)
                        if mode == "extra": return data + b"\n#[test]\nfn PRIVATE_SENTINEL() {}\n"
                        return data.replace(b"#[test]", b"#[test]\n#[ignore]", 1)
                    return read_bytes(path, *args, **kwargs)
                with self.subTest(core719_method=target, mode=mode), patch(
                        "core_719519_inventory.Path.read_bytes", altered_method719):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_719519_source_inventory_differs$") as caught:
                        core719.require_current_core_719519_sources()
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

        actual = before_runtime_stack_consumer(before_core_719519(before_ordinary_shared(before_ordinary_thirtytwo(before_core_c73f159(before_core_ae149a9(before_core_041bd4a(before_inprocess(json.loads(Path(__file__).with_name("corpus.json").read_text())))))))))
        unchanged_actual = copy.deepcopy(actual)
        prior_a3 = before_core_a3(actual)
        self.assertEqual(actual, unchanged_actual)
        self.assertEqual(digest(prior_a3), PRE_CORE_A3_CORPUS_SHA256)
        self.assertEqual(actual["recorder_tests"], 305)
        self.assertEqual(len(actual["native_validation_fixtures"]), 103)
        self.assertEqual(actual["native_validation_fixtures"], prior_a3["native_validation_fixtures"])
        self.assertEqual(actual["harness_test_counts"]["serial_launch"],
                         prior_a3["harness_test_counts"]["serial_launch"])
        self.assertEqual(sum(row["tests"] for row in actual["harness_test_counts"]["serial_launch"].values()), 995)
        workspace_a3 = actual["harness_test_counts"]["workspace_tests"]
        self.assertEqual(len(workspace_a3), 93)
        self.assertEqual(sum(row["tests"] for row in workspace_a3.values()), 2148)
        self.assertEqual(sum(row["ignored"] for row in workspace_a3.values()), 4)
        self.assertEqual(workspace_a3["unit/liteinst_launch/lib"], counts(703))
        self.assertEqual(sum(map(len, A3_METHODS.values())), 20)
        with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_a3_inventory_differs$"):
            before_core_a3(prior_a3)
        for identity in (*A3_ADDED, *A3_CHANGED):
            for change in ("missing", "count", "ignored", "type", "ignored_type", "rename", "extra"):
                altered = copy.deepcopy(actual)
                group = altered["harness_test_counts"]["workspace_tests"]
                if change == "missing": del group[identity]
                elif change == "count": group[identity]["tests"] -= 1
                elif change == "ignored": group[identity]["ignored"] += 1
                elif change == "type": group[identity]["tests"] = float(group[identity]["tests"])
                elif change == "ignored_type": group[identity]["ignored"] = bool(group[identity]["ignored"])
                elif change == "rename": group[identity + "_extra"] = group.pop(identity)
                else: group[identity]["extra"] = "PRIVATE_SENTINEL"
                with self.subTest(a3_identity=identity, change=change), self.assertRaises(parsing.InvalidEvidence) as caught:
                    before_core_a3(altered)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for change in ("recorder", "serial", "old_workspace", "native", "static", "dynamic", "matrix", "helper", "baseline", "extra"):
            altered = copy.deepcopy(actual)
            if change == "recorder": altered["recorder_tests"] -= 1
            elif change == "serial": altered["harness_test_counts"]["serial_launch"]["unit/liteinst_launch/lib"]["tests"] -= 1
            elif change == "old_workspace": altered["harness_test_counts"]["workspace_tests"]["unit/liteinst_launch/lib"]["tests"] -= 1
            elif change == "native": altered["native_validation_fixtures"].pop()
            elif change == "static": altered["native_cases"].pop()
            elif change == "dynamic": altered["dynamic_admission_fixtures"].pop()
            elif change == "matrix": altered["dynamic_matrix_cases"].pop()
            elif change == "helper": altered["backing_cleanup_harnesses"]["serial_launch"].pop()
            elif change == "baseline": altered["baseline_revision"] = "0" * 40
            else: altered["extra"] = "PRIVATE_SENTINEL"
            with self.subTest(a3_history=change), self.assertRaises(parsing.InvalidEvidence):
                before_core_a3(altered)
        for path, names in A3_METHODS.items():
            for bad in (list(names[:-1]), list(names) + [names[0]], list(reversed(names)),
                        ["PRIVATE_SENTINEL"] + list(names[1:])):
                with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_a3_source_inventory_differs$"):
                    validate_core_a3_source(path, bad)
        read_a3 = Path.read_text
        for target in (*A3_METHODS, *A3_WIRING):
            for mutation in ("missing", "changed"):
                def altered_a3(path, *args, **kwargs):
                    if path.as_posix().endswith(target):
                        if mutation == "missing": raise OSError("PRIVATE_SENTINEL /private/source")
                        text = read_a3(path, *args, **kwargs)
                        needle = A3_METHODS[target][0] if target in A3_METHODS else A3_WIRING[target]
                        return text.replace(needle, "PRIVATE_SENTINEL", 1)
                    return read_a3(path, *args, **kwargs)
                with self.subTest(a3_source=target, mutation=mutation), patch("core_a3_inventory.Path.read_text", altered_a3):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, "^core_a3_source_inventory_differs$") as caught:
                        before_core_a3(actual)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        current = before_owned_stack(before_core_a3(before_runtime_stack_consumer(before_core_719519(before_ordinary_shared(before_ordinary_thirtytwo(before_core_c73f159(before_core_ae149a9(before_core_041bd4a(before_inprocess(json.loads(Path(__file__).with_name("corpus.json").read_text())))))))))))
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
