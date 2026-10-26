"""Portable evidence regressions using synthetic protocols and the fixed corpus."""

import json
from pathlib import Path
import unittest

import parsing


def header(name="example", source="src/lib.rs", unit=True):
    label = "unittests " + source if unit else "tests/" + name + ".rs"
    return f"     Running {label} (target/debug/deps/{name}-123abc)"


def summary(passed, ignored=0, failed=0, filtered=0, measured=0, result=None):
    result = result or ("FAILED" if failed else "ok")
    return (f"test result: {result}. {passed} passed; {failed} failed; {ignored} ignored; "
            f"{measured} measured; {filtered} filtered out; finished in 0.01s")


def counts(tests, ignored=0):
    return {"tests": tests, "ignored": ignored}


CASE = {"test": "rdrand_eax", "class": "rdrand", "destination": 0,
        "input_flags": 3799, "cpuid_leaf": None, "cpuid_subleaf": None,
        "encoding": "0fc7f0", "coverage_backend": False}
OTHER = CASE | {"test": "rdrand_ecx", "destination": 1, "encoding": "0fc7f1"}


def receipt(case=CASE, fault=False):
    random = case["class"] in ("rdrand", "rdseed") and not fault
    return {"schema_version": 2, **{k: case[k] for k in parsing.KEYS},
            **dict(zip(parsing.COUNTERS, (0, 0, 0, 1, 1, 1) if fault else (1, 1, 1, 0, 0, 0))),
            "raw_native_random_cf": 0 if random else None,
            "native_gate_random_cf": 1 if random else None}


def native_text(case=CASE, row=None, terminal="ok", split=False):
    row = receipt(case) if row is None else row
    prefix = f"test {case['test']} ... "
    if split:
        prefix += "native capability diagnostic\n"
    return prefix + parsing.PREFIX + json.dumps(row) + "\n" + terminal + "\n"


class HarnessParsingTests(unittest.TestCase):
    def test_library_and_binary_harnesses_keep_distinct_counts(self):
        text = "\n".join([header("rapid_profiler"), "running 7 tests", summary(7),
                           header("rapid_profiler", "src/main.rs"), "running 3 tests", summary(3)])
        rows = parsing.parse_harnesses(text, {"unit/rapid_profiler/lib": counts(7),
                                             "unit/rapid_profiler/main": counts(3)}, 0)
        self.assertEqual([row["outer"]["passed"] for row in rows], [7, 3])
        self.assertEqual(len({row["id"] for row in rows}), 2)

    def test_nested_summaries_and_reviewed_unmatched_child_are_not_outer_counts(self):
        for declared in (176, 184):
            with self.subTest(declared=declared):
                text = "\n".join([header("liteinst2"), f"running {declared} tests", "running 1 test",
                                   summary(1, filtered=declared - 1), "running 1 test",
                                   summary(1, filtered=declared - 1), "running 1 test",
                                   summary(declared - 1, ignored=1)])
                row = parsing.parse_harnesses(
                    text, {"unit/liteinst2/lib": counts(declared, 1)}, 0)[0]
                self.assertEqual(row["outer"]["passed"], declared - 1)
                self.assertEqual(row["outer"]["ignored"], 1)
                self.assertEqual(len(row["nested"]), 2)
                self.assertEqual(row["nested_starts"], 3)
                self.assertEqual(row["unmatched_nested_starts"], 1)

    def test_unmatched_child_exception_does_not_generalize(self):
        for name, child, declared in [("example", 1, 176), ("liteinst2", 2, 176),
                                      ("liteinst2", 1, 175), ("example", 1, 184),
                                      ("liteinst2", 2, 184), ("liteinst2", 1, 183),
                                      ("liteinst2", 1, 185)]:
            text = "\n".join([header(name), f"running {declared} tests", f"running {child} tests",
                               summary(declared - 1, ignored=1)])
            with self.subTest(name=name, child=child, declared=declared), self.assertRaises(
                    parsing.InvalidEvidence):
                parsing.parse_harnesses(text, {f"unit/{name}/lib": counts(declared, 1)}, 0)

    def test_authenticated_stress_child_exit_retains_only_outer_results(self):
        text = "\n".join([header("stress", unit=False), "running 7 tests", "running 1 test",
                           summary(4, ignored=3)])
        row = parsing.parse_harnesses(text, {"test/stress": counts(7, 3)}, 0)[0]
        self.assertEqual(row["outer"]["passed"], 4)
        self.assertEqual(row["outer"]["ignored"], 3)
        self.assertEqual(row["nested"], [])
        self.assertEqual(row["unmatched_nested_starts"], 1)
        for name, declared, child in [("other", 7, 1), ("stress", 8, 1), ("stress", 7, 2)]:
            text = "\n".join([header(name, unit=False), f"running {declared} tests",
                               f"running {child} tests", summary(declared - 3, ignored=3)])
            with self.subTest(name=name, declared=declared, child=child), self.assertRaises(
                    parsing.InvalidEvidence):
                parsing.parse_harnesses(text, {f"test/{name}": counts(declared, 3)}, 0)

    def test_child_and_parent_of_one_require_two_actual_starts_and_summaries(self):
        valid = "\n".join([header(), "running 1 test", "running 1 test", summary(1), summary(1)])
        row = parsing.parse_harnesses(valid, {"unit/example/lib": counts(1)}, 0)[0]
        self.assertEqual(row["outer"]["passed"], 1)
        self.assertEqual(len(row["nested"]), 1)
        for invalid in (valid.replace("running 1 test\n", "", 1), valid.rsplit("\n", 1)[0]):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(invalid, {"unit/example/lib": counts(1)}, 0)

    def test_summary_without_announced_child_cannot_be_removed_as_nested(self):
        text = "\n".join([header(), "running 2 tests", summary(1, filtered=1), summary(2)])
        with self.assertRaisesRegex(parsing.InvalidEvidence, "summary_start_count_mismatch"):
            parsing.parse_harnesses(text, {"unit/example/lib": counts(2)}, 0)

    def test_changed_skips_and_nested_skips_refuse(self):
        for ignored in (1, 2):
            text = "\n".join([header(), "running 2 tests", summary(2 - ignored, ignored=ignored)])
            with self.assertRaisesRegex(parsing.InvalidEvidence, "changed_ignore_cohort"):
                parsing.parse_harnesses(text, {"unit/example/lib": counts(2)}, 0)
        text = "\n".join([header(), "running 2 tests", "running 1 test",
                           summary(0, ignored=1, filtered=1), summary(2)])
        with self.assertRaisesRegex(parsing.InvalidEvidence, "unexpected_nested_ignore"):
            parsing.parse_harnesses(text, {"unit/example/lib": counts(2)}, 0)

    def test_partial_failure_keeps_completed_failed_and_missing_harnesses(self):
        expected = {"unit/first/lib": counts(1), "unit/second/lib": counts(2),
                    "unit/third/lib": counts(1)}
        text = "\n".join([header("first"), "running 1 test", summary(1), header("second"),
                           "running 2 tests", summary(1, failed=1)])
        with self.assertRaisesRegex(parsing.InvalidEvidence, "missing_harness") as caught:
            parsing.parse_harnesses(text, expected, 101)
        rows = caught.exception.partial
        self.assertEqual(rows[0]["outer"]["passed"], 1)
        self.assertEqual(rows[1]["outer"]["failed"], 1)
        self.assertEqual(rows[2]["status"], "not_observed")
        self.assertIsNone(rows[2]["outer"])

    def test_compile_failure_and_truncation_preserve_unknown_not_zero_success(self):
        expected = {"unit/example/lib": counts(2)}
        for text in ("compiler diagnostics omitted", header() + "\nrunning 2 tests\n"):
            with self.assertRaises(parsing.InvalidEvidence) as caught:
                parsing.parse_harnesses(text, expected, 101)
            self.assertIsNone(caught.exception.partial[0]["outer"])
            self.assertNotEqual(caught.exception.partial[0]["status"], "complete")

    def test_failed_summary_is_retained_but_zero_exit_is_contradictory(self):
        text = "\n".join([header(), "running 1 test", summary(0, failed=1)])
        self.assertEqual(parsing.parse_harnesses(text, {"unit/example/lib": counts(1)}, 101)
                         [0]["outer"]["failed"], 1)
        with self.assertRaisesRegex(parsing.InvalidEvidence, "successful_exit_with_failed_summary") as caught:
            parsing.parse_harnesses(text, {"unit/example/lib": counts(1)}, 0)
        self.assertEqual(caught.exception.partial[0]["outer"]["failed"], 1)

    def test_duplicate_headers_extra_summaries_and_cohort_changes_refuse(self):
        valid = "\n".join([header(), "running 1 test", summary(1)])
        for text in (valid + "\n" + valid, valid + "\n" + summary(1),
                     valid.replace("running 1 test", "running 2 tests"),
                     valid.replace("0 filtered out", "1 filtered out"),
                     valid.replace("test result: ok", "test result: FAILED")):
            with self.subTest(text=text), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(text, {"unit/example/lib": counts(1)}, 0)

    def test_private_like_labels_never_enter_partial_rows(self):
        marker = "PRIVATE_SENTINEL"
        for text in (header().replace("target/debug/deps/", "/" + marker + "/"),
                     header().replace("src/lib.rs", "/" + marker + "/lib.rs"),
                     header().replace("src/lib.rs", "../" + marker + "/lib.rs"),
                     header().replace("example-123abc", marker + "-123abc")):
            with self.assertRaises(parsing.InvalidEvidence) as caught:
                parsing.parse_harnesses(text, {"unit/example/lib": counts(1)}, 0)
            self.assertNotIn(marker, json.dumps(caught.exception.partial))
            self.assertNotIn(marker, str(caught.exception))


class NativeParsingTests(unittest.TestCase):
    def test_completed_receipts_bind_to_terminal_ok_without_final_run_qualification(self):
        for split in (False, True):
            row = parsing.native_receipts(native_text(split=split), [CASE], True)[0]
            self.assertEqual(row["test_result"], "ok")
            self.assertEqual(row["outcome"], "completed")
            self.assertEqual(row["raw_native_random_cf"], 0)
            self.assertEqual(row["native_gate_random_cf"], 1)
            self.assertTrue(row["command_succeeded"])
            self.assertFalse(row["qualified_run"])

    def test_capability_fault_stays_fault_with_no_native_completion(self):
        row = parsing.native_receipts(native_text(row=receipt(fault=True)), [CASE], True)[0]
        self.assertEqual(row["outcome"], "capability_fault")
        self.assertEqual(row["native_gate_completed"], 0)
        self.assertEqual(row["native_gate_signal"], 1)
        self.assertFalse(row["qualified_run"])

    def test_nonzero_command_preserves_observed_sample_without_qualifying_it(self):
        row = parsing.native_receipts(native_text(), [CASE], False)[0]
        self.assertFalse(row["command_succeeded"])
        self.assertFalse(row["qualified_run"])
        self.assertEqual(row["raw_native_completed"], 1)

    def test_missing_failed_or_ignored_terminal_never_qualifies(self):
        for terminal in ("", "FAILED", "ignored"):
            with self.subTest(terminal=terminal), self.assertRaises(parsing.InvalidEvidence) as caught:
                parsing.native_receipts(native_text(terminal=terminal), [CASE], True)
            row = caught.exception.partial[0]
            self.assertFalse(row["qualified_run"])
            self.assertEqual(row["raw_native_completed"], 1)

    def test_missing_receipt_and_receipt_after_terminal_refuse(self):
        for text in ("test rdrand_eax ... ok\n", "test rdrand_eax ... ok\n" + parsing.PREFIX
                     + json.dumps(receipt()) + "\n"):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.native_receipts(text, [CASE], True)

    def test_receipts_cannot_be_swapped_between_named_tests(self):
        text = native_text(CASE, receipt(OTHER)) + native_text(OTHER, receipt(CASE))
        with self.assertRaisesRegex(parsing.InvalidEvidence, "native_receipt_test_mismatch"):
            parsing.native_receipts(text, [CASE, OTHER], True)

    def test_missing_case_and_later_bad_record_preserve_earlier_evidence(self):
        for text in (native_text(), native_text() + native_text(OTHER, receipt(OTHER) | {"private": 1})):
            with self.assertRaises(parsing.InvalidEvidence) as caught:
                parsing.native_receipts(text, [CASE, OTHER], True)
            rows = {row["test"]: row for row in caught.exception.partial}
            self.assertEqual(rows[CASE["test"]]["test_result"], "ok")
            self.assertEqual(rows[CASE["test"]]["raw_native_completed"], 1)
            self.assertNotIn("private", json.dumps(rows))
            self.assertFalse(rows[CASE["test"]]["qualified_run"])

    def test_duplicate_names_records_and_json_keys_refuse(self):
        record = parsing.PREFIX + json.dumps(receipt()) + "\n"
        for text in (native_text() + native_text(),
                     native_text(terminal=record + "ok"),
                     native_text().replace('"schema_version": 2', '"schema_version": 1, "schema_version": 2')):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.native_receipts(text, [CASE], True)

    def test_closed_fields_types_identities_outcomes_and_carry(self):
        for patch in ({"raw_native_completed": True}, {"native_gate_signal": 1},
                      {"raw_native_random_cf": None}, {"native_gate_random_cf": 2},
                      {"schema_version": 1}, {"destination": 8}, {"host_path": "PRIVATE_SENTINEL"},
                      {"encoding": "480fc7f0"}, {"encoding": []}, {"coverage_backend": 0},
                      {"coverage_backend": True}):
            with self.subTest(patch=patch), self.assertRaises(parsing.InvalidEvidence) as caught:
                parsing.native_receipts(native_text(row=receipt() | patch), [CASE], True)
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(caught.exception.partial))
        with self.assertRaises(parsing.InvalidEvidence):
            parsing.native_receipts(native_text(row=receipt(fault=True) | {"raw_native_random_cf": 0}),
                                    [CASE], True)

    def test_block_boundaries_and_duplicate_blocks_are_checked(self):
        native = header("native_selected", unit=False) + "\n" + native_text()
        block = parsing.native_block(native + "\n" + header() + "\nprivate diagnostic")
        self.assertNotIn("private diagnostic", block)
        self.assertEqual(len(parsing.native_receipts(block, [CASE], True)), 1)
        for text in (header(), native + "\n" + native):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.native_block(text)


class DeclaredCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(Path(__file__).with_name("corpus.json").read_text())

    def test_fixed_workspace_and_launch_denominators(self):
        expected = self.corpus["harness_test_counts"]
        self.assertEqual(len(expected["workspace_tests"]), 66)
        self.assertEqual(len(expected["serial_launch"]), 14)
        self.assertEqual(sum(row["tests"] for row in expected["workspace_tests"].values()), 1048)
        self.assertEqual(sum(row["ignored"] for row in expected["workspace_tests"].values()), 4)
        self.assertEqual(sum(row["tests"] for row in expected["serial_launch"].values()), 210)
        self.assertEqual(sum(row["ignored"] for row in expected["serial_launch"].values()), 0)
        for cohort in expected.values():
            for identity, total in {
                "unit/liteinst_launch/lib": 15,
                "test/concurrent_gate": 10,
                "test/selected_gate": 24,
                "test/oracle_gate": 3,
                "test/dynamic_control": 8,
                "test/dynamic_signals": 4,
            }.items():
                self.assertEqual(cohort[identity], counts(total))
        self.assertEqual(expected["workspace_tests"]["unit/liteinst2/lib"], counts(184, 1))
        self.assertEqual(expected["workspace_tests"]["unit/rapid_profiler/lib"], counts(24))
        self.assertEqual(expected["workspace_tests"]["unit/rapid_profiler/main"], counts(3))
        self.assertEqual(expected["workspace_tests"]["doc/rapid_profiler"], counts(2))
        historical = "\n".join([header("liteinst2"), "running 176 tests", "running 1 test",
                                 summary(175, ignored=1)])
        with self.assertRaisesRegex(parsing.InvalidEvidence, "changed_outer_cohort"):
            parsing.parse_harnesses(historical, {
                "unit/liteinst2/lib": expected["workspace_tests"]["unit/liteinst2/lib"]}, 0)

    def test_all_50_native_case_records_and_exact_class_counts(self):
        cases = self.corpus["native_cases"]
        self.assertEqual(len(cases), 50)
        expected = {"cpuid": 3, "rdrand": 15, "rdseed": 15, "rdpid": 11, "rdtsc": 3, "rdtscp": 3}
        self.assertEqual({key: sum(case["class"] == key for case in cases) for key in expected}, expected)
        rows = parsing.native_receipts("".join(native_text(case) for case in cases), cases, True)
        self.assertEqual(len(rows), 50)
        self.assertEqual(sum(row["raw_native_completed"] for row in rows), 50)
        self.assertEqual(sum(row["scripted_completed"] for row in rows), 50)
        self.assertEqual(sum(row["native_gate_completed"] for row in rows), 50)
        self.assertEqual(sum(row["coverage_backend"] for row in rows), 17)
        self.assertFalse(any(row["qualified_run"] for row in rows))


if __name__ == "__main__":
    unittest.main()
