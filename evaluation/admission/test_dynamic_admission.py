"""Bounded synthetic protocol tests; no native fixture or command is executed."""

import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import dynamic_admission
import parsing
import run


FIXTURES = [
    "literal_first_cpuid_preserves_complete_state_and_native_memory",
    "interpreter_and_executable_literal_first_instructions_are_both_gated",
    "clone_return_at_page_boundary_gates_each_first_instruction_once",
    "default_rdpid_requires_explicit_coverage_and_keeps_all_registers",
    "forbidden_native_mapping_syscall_closes_before_any_kernel_effect",
    "provider_panic_cancels_actual_owner_and_physically_reaps",
    "blocked_provider_observes_owner_cleanup_before_returning_a_decision",
]


def header(name="dynamic_admission"):
    return f"     Running tests/{name}.rs (target/debug/deps/{name}-123abc)"


def summary(passed, failed=0, ignored=0):
    result = "FAILED" if failed else "ok"
    return (f"test result: {result}. {passed} passed; {failed} failed; {ignored} ignored; "
            "0 measured; 0 filtered out; finished in 0.01s")


def fixture_block(fixtures=FIXTURES, split=False):
    rows = [header(), f"running {len(fixtures)} tests"]
    for name in fixtures:
        if split:
            rows.extend([f"test {name} ... diagnostic text", "ok"])
        else:
            rows.append(f"test {name} ... ok")
    rows.append(summary(len(fixtures)))
    return "\n".join(rows) + "\n"


def native_block(cases):
    rows = [header("native_selected"), f"running {len(cases)} tests"]
    for case in cases:
        random = case["class"] in ("rdrand", "rdseed")
        receipt = {"schema_version": 2, **{key: case[key] for key in parsing.KEYS},
                   **dict(zip(parsing.COUNTERS, (1, 1, 1, 0, 0, 0))),
                   "raw_native_random_cf": 0 if random else None,
                   "native_gate_random_cf": 1 if random else None}
        rows.extend([f"test {case['test']} ... " + parsing.PREFIX + json.dumps(receipt), "ok"])
    rows.append(summary(len(cases)))
    return "\n".join(rows) + "\n"


def corpus():
    declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
    return {"harness_test_counts": {"serial_launch": {
                "test/dynamic_admission": {"tests": 7, "ignored": 0},
                "test/native_selected": {"tests": 50, "ignored": 0}}},
            "native_cases": declared["native_cases"], "dynamic_admission_fixtures": FIXTURES,
            "dynamic_matrix_cases": [], "native_validation_fixtures": []}


def command(status="passed", exit_code=0):
    return {"id": "serial_launch", "status": status, "exit_code": exit_code}


class DynamicFixtureParsingTests(unittest.TestCase):
    def test_all_named_inline_and_split_results_remain_unqualified(self):
        for split in (False, True):
            with self.subTest(split=split):
                rows = dynamic_admission.fixture_results(fixture_block(split=split), FIXTURES, True)
                self.assertEqual(rows, [
                    {"test": name, "status": "complete", "test_result": "ok",
                     "command_succeeded": True, "qualified_run": False} for name in FIXTURES])

    def test_expected_panic_text_never_substitutes_for_terminal_ok(self):
        name = FIXTURES[5]
        original = f"test {name} ... ok"
        panic = (f"test {name} ... \nthread 'fixture' panicked at PRIVATE_SENTINEL:\n"
                 "intentional provider panic\nok")
        text = fixture_block().replace(original, panic)
        rows = dynamic_admission.fixture_results(text, FIXTURES, True)
        self.assertEqual(rows[5]["test_result"], "ok")
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(rows))
        with self.assertRaisesRegex(parsing.InvalidEvidence, "dynamic_fixture_missing_terminal"):
            dynamic_admission.fixture_results(text.replace("intentional provider panic\nok",
                                                           "intentional provider panic"), FIXTURES, True)

    def test_absent_duplicate_and_malformed_harness_headers_refuse(self):
        for text, code in [
                ("compiler diagnostics", "missing_dynamic_fixture_harness"),
                (fixture_block() + fixture_block(), "duplicate_dynamic_fixture_harness"),
                (fixture_block().replace("target/debug/deps/", "/PRIVATE_SENTINEL/"),
                 "invalid_harness_binary_path"),
                (fixture_block().replace("Running tests/", "Running invalid/"),
                 "unrecognized_harness_header")]:
            with self.subTest(code=code), self.assertRaisesRegex(parsing.InvalidEvidence, code) as caught:
                dynamic_admission.fixture_results(text, FIXTURES, True)
            self.assertEqual(len(caught.exception.partial), 7)
            self.assertFalse(any(row["qualified_run"] for row in caught.exception.partial))

    def test_missing_duplicate_unknown_and_malformed_fixture_names_refuse(self):
        first = f"test {FIXTURES[0]} ... ok\n"
        last = f"test {FIXTURES[-1]} ... ok\n"
        for text, code in [
                (fixture_block().replace(last, ""), "dynamic_named_cohort_differs"),
                (fixture_block().replace(first, first + first), "dynamic_named_cohort_differs"),
                (fixture_block().replace(FIXTURES[0], "unknown_fixture"), "dynamic_named_cohort_differs"),
                (fixture_block().replace(FIXTURES[0], "bad::name"), "dynamic_named_cohort_differs")]:
            with self.subTest(code=code), self.assertRaisesRegex(parsing.InvalidEvidence, code):
                dynamic_admission.fixture_results(text, FIXTURES, True)

    def test_failed_ignored_and_incomplete_results_preserve_typed_observations(self):
        first = f"test {FIXTURES[0]} ... ok"
        for terminal in ("FAILED", "ignored", "ignored, requires capability"):
            with self.subTest(terminal=terminal), self.assertRaisesRegex(
                    parsing.InvalidEvidence, "dynamic_fixture_not_passed") as caught:
                dynamic_admission.fixture_results(
                    fixture_block().replace(first, f"test {FIXTURES[0]} ... {terminal}"), FIXTURES, False)
            rows = caught.exception.partial
            self.assertEqual(rows[0]["status"], "failed")
            self.assertEqual(rows[0]["test_result"], "FAILED" if terminal == "FAILED" else "ignored")
            self.assertEqual(rows[1]["status"], "complete")
            self.assertFalse(any(row["command_succeeded"] or row["qualified_run"] for row in rows))
        with self.assertRaisesRegex(parsing.InvalidEvidence, "dynamic_fixture_missing_terminal") as caught:
            dynamic_admission.fixture_results(header() + f"\ntest {FIXTURES[0]} ... \n", FIXTURES, False)
        self.assertEqual(caught.exception.partial[0]["status"], "incomplete")
        self.assertIsNone(caught.exception.partial[0]["test_result"])
        self.assertEqual(caught.exception.partial[1]["status"], "not_observed")

    def test_extra_terminal_without_active_fixture_is_not_a_result(self):
        for text in (header() + "\nok\n", fixture_block() + "ok\n"):
            with self.assertRaisesRegex(parsing.InvalidEvidence, "dynamic_terminal_without_fixture"):
                dynamic_admission.fixture_results(text, FIXTURES, True)

    def test_other_harness_cannot_supply_missing_fixture_or_terminal(self):
        last = f"test {FIXTURES[-1]} ... ok\n"
        text = fixture_block().replace(last, "") + header("other") + "\n" + last
        with self.assertRaisesRegex(parsing.InvalidEvidence, "dynamic_named_cohort_differs"):
            dynamic_admission.fixture_results(text, FIXTURES, True)
        text = header() + f"\ntest {FIXTURES[0]} ... \n" + header("other") + "\nok\n"
        with self.assertRaisesRegex(parsing.InvalidEvidence, "dynamic_fixture_missing_terminal"):
            dynamic_admission.fixture_results(text, FIXTURES, True)
        outside = header("other") + "\ntest foreign ... ok\n" + fixture_block()
        self.assertEqual(len(dynamic_admission.fixture_results(outside, FIXTURES, True)), 7)

    def test_catalog_and_command_status_require_exact_valid_types(self):
        for names in ([], {}, "fixture", [None], [True], ["bad/name"], ["a", "a"]):
            with self.subTest(names=names), self.assertRaises(parsing.InvalidEvidence):
                dynamic_admission.fixture_results(fixture_block(), names, True)
        for succeeded in (0, 1, None, "passed"):
            with self.subTest(succeeded=succeeded), self.assertRaisesRegex(
                    parsing.InvalidEvidence, "invalid_dynamic_command_status"):
                dynamic_admission.fixture_results(fixture_block(), FIXTURES, succeeded)

    def test_partial_records_never_export_untrusted_names_or_diagnostics(self):
        marker = "PRIVATE_SENTINEL"
        text = fixture_block().replace(f"test {FIXTURES[1]} ... ok", f"test {marker} ... ok")
        with self.assertRaises(parsing.InvalidEvidence) as caught:
            dynamic_admission.fixture_results(text, FIXTURES, False)
        serialized = json.dumps(caught.exception.partial)
        self.assertNotIn(marker, serialized)
        self.assertNotIn(marker, str(caught.exception))
        self.assertEqual(caught.exception.partial[0]["test_result"], "ok")
        self.assertEqual(caught.exception.partial[1]["status"], "not_observed")
        self.assertTrue(all(set(row) == {"test", "status", "test_result", "command_succeeded",
                                         "qualified_run"} for row in caught.exception.partial))


class DynamicRecorderIntegrationTests(unittest.TestCase):
    def test_static_fifty_and_dynamic_seven_are_separate_complete_observations(self):
        expected = corpus()
        text = fixture_block() + native_block(expected["native_cases"])
        observed = command()
        run.command_evidence(observed, text, expected)
        self.assertEqual(observed["status"], "passed")
        self.assertEqual(observed["evidence_status"], "complete")
        self.assertEqual(len(observed["native_cases"]), 50)
        self.assertEqual(len(observed["dynamic_admission_fixtures"]), 7)
        self.assertEqual(sum(row["raw_native_completed"] for row in observed["native_cases"]), 50)
        self.assertTrue(all("raw_native_completed" not in row
                            for row in observed["dynamic_admission_fixtures"]))
        self.assertFalse(any(row["qualified_run"] for field in
                             ("native_cases", "dynamic_admission_fixtures") for row in observed[field]))

    def test_dynamic_parser_failure_invalidates_without_discarding_static_receipts(self):
        expected = corpus()
        text = fixture_block().replace(FIXTURES[0], "wrong_fixture") + native_block(expected["native_cases"])
        observed = command()
        run.command_evidence(observed, text, expected)
        self.assertEqual(observed["status"], "invalid_evidence")
        self.assertEqual(observed["dynamic_parse_error"], "dynamic_named_cohort_differs")
        self.assertEqual(len(observed["native_cases"]), 50)
        self.assertEqual(len(observed["dynamic_admission_fixtures"]), 7)
        self.assertEqual(observed["dynamic_admission_fixtures"][0]["status"], "not_observed")

    def test_valid_dynamic_results_never_reset_existing_harness_or_native_failures(self):
        expected = corpus()
        original = fixture_block() + native_block(expected["native_cases"])
        for text, field, code in (
                (original.replace("running 7 tests", "running 8 tests"),
                 "parse_error", "changed_outer_cohort"),
                (original.replace(parsing.PREFIX, "MISSING_NATIVE_RECEIPT ", 1),
                 "native_parse_error", "missing_native_receipt")):
            with self.subTest(code=code):
                observed = command()
                run.command_evidence(observed, text, expected)
                self.assertEqual(observed["status"], "invalid_evidence")
                self.assertEqual(observed["evidence_status"], "incomplete")
                self.assertEqual(observed[field], code)
                self.assertTrue(all(row["status"] == "complete"
                                    for row in observed["dynamic_admission_fixtures"]))

    def test_failed_commands_keep_complete_observations_without_becoming_passes(self):
        expected = corpus()
        text = fixture_block() + native_block(expected["native_cases"])
        for exit_code, termination in ((101, None), (0, "timeout"), (0, "output_limit"),
                                       (0, "descendants_after_exit")):
            with self.subTest(exit_code=exit_code, termination=termination):
                observed = command("failed", exit_code)
                observed["termination"] = termination
                run.command_evidence(observed, text, expected)
                self.assertEqual(observed["status"], "failed")
                self.assertEqual(observed["exit_code"], exit_code)
                self.assertEqual(observed["termination"], termination)
                for field in ("native_cases", "dynamic_admission_fixtures"):
                    self.assertFalse(any(row["qualified_run"] or row["command_succeeded"]
                                         for row in observed[field]))

    def test_only_unchanged_complete_protocol_qualifies_both_cohorts(self):
        rows = [{"qualified_run": False, "command_succeeded": True},
                {"qualified_run": False, "command_succeeded": False}]
        for source, config, later, passed in (
                (True, True, "passed", True), (False, True, "passed", False),
                (True, False, "passed", False), (None, True, "passed", False),
                (True, True, "not_run", False), (True, True, "failed", False),
                (True, True, "invalid_evidence", False)):
            with self.subTest(source=source, config=config, later=later):
                record = {"source_unchanged": source, "configuration_unchanged": config,
                          "commands": [{"status": "passed", "native_cases": copy.deepcopy(rows),
                                        "dynamic_admission_fixtures": copy.deepcopy(rows)},
                                       {"status": later}]}
                run.qualify(record)
                self.assertEqual(record["status"], "passed" if passed else "failed")
                for field in ("native_cases", "dynamic_admission_fixtures"):
                    self.assertEqual([row["qualified_run"] for row in record["commands"][0][field]],
                                     [passed, False])

    def test_recorder_exception_clears_both_cohorts_and_keeps_message_private(self):
        # All commands, hardware queries and Git operations are mocked. This
        # exercises main's durable exception branch, not native supervision.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            here = root / "evaluation/admission"
            here.mkdir(parents=True)
            (here / "corpus.json").write_text(json.dumps({"schema_version": 1}))
            source = {"revision": "a" * 40, "tracked_clean": True}

            def completed(argv, env, log, timeout):
                log.write_text("synthetic evidence")
                return {"exit_code": 0, "termination": None, "cleanup_complete": True, "seconds": 0.01}

            def fail_after_rows(observed, output, expected):
                for field in ("native_cases", "dynamic_admission_fixtures", "dynamic_matrix_cases",
                              "native_validation_fixtures"):
                    observed[field] = [{"command_succeeded": True, "qualified_run": True}]
                raise RuntimeError("PRIVATE_SENTINEL")

            with contextlib.ExitStack() as stack:
                for name, value in (("ROOT", root), ("HERE", here), ("GIT", sys.executable)):
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
            files = list((here / "results").glob("*.json"))
            self.assertEqual(len(files), 1)
            record = json.loads(files[0].read_text())
            self.assertEqual(record["status"], "recorder_error")
            self.assertEqual(record["error_type"], "RuntimeError")
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(record))
            for field in ("native_cases", "dynamic_admission_fixtures", "dynamic_matrix_cases",
                              "native_validation_fixtures"):
                self.assertFalse(record["commands"][0][field][0]["qualified_run"])
            self.assertTrue(all(row["status"] == "not_run" for row in record["commands"][1:]))

    def test_exact_catalog_keeps_seven_fixtures_separate_from_fifty_samples(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        self.assertEqual(declared["dynamic_admission_fixtures"][:7], FIXTURES)
        self.assertEqual(len(declared["dynamic_admission_fixtures"]), 15)
        self.assertEqual(len(declared["native_cases"]), 50)
        for cohort in declared["harness_test_counts"].values():
            self.assertEqual(cohort["test/dynamic_admission"], {"tests": 15, "ignored": 0})
        self.assertEqual(declared["recorder_tests"], 219)

    def test_six_commands_and_existing_deadlines_are_not_extended(self):
        self.assertEqual(run.COMMANDS, [
            ("recorder_tests", ["python3", "-m", "unittest", "discover", "-s",
                                "evaluation/admission", "-p", "test_*.py"], 180),
            ("fmt", ["cargo", "fmt", "--check"], 180),
            ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--all-features",
                        "--", "-D", "warnings"], 180),
            ("workspace_tests", ["cargo", "test", "--workspace"], 360),
            ("workspace_check", ["cargo", "check", "--workspace", "--all-features",
                                 "--all-targets"], 180),
            ("serial_launch", ["cargo", "test", "-p", "liteinst-launch", "--tests", "--",
                               "--test-threads=1", "--nocapture"], 180),
        ])
        self.assertEqual(run.ENV, {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "4",
                                  "CARGO_NET_OFFLINE": "true", "RUST_TEST_THREADS": "4",
                                  "CARGO_TERM_COLOR": "never", "PYTHONDONTWRITEBYTECODE": "1",
                                  "RUSTFLAGS": "", "RUSTDOCFLAGS": "", "RUSTC_WRAPPER": "",
                                  "RUSTC_WORKSPACE_WRAPPER": ""})

    def test_compile_failure_retains_seven_unknown_rows_not_zero_successes(self):
        observed = command("failed", 101)
        run.command_evidence(observed, "PRIVATE_SENTINEL compiler error", corpus())
        self.assertEqual(observed["status"], "failed")
        self.assertEqual(observed["dynamic_parse_error"], "missing_dynamic_fixture_harness")
        rows = observed["dynamic_admission_fixtures"]
        self.assertEqual(len(rows), 7)
        self.assertTrue(all(row["status"] == "not_observed" and row["test_result"] is None for row in rows))
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(observed))


if __name__ == "__main__":
    unittest.main()
