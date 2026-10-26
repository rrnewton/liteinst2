"""Pure controls for the separate four-run default-libtest recorder."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import default_parallel as dp
from parsing import InvalidEvidence
from test_parsing import counts, header, summary


EXPECTED = {dp.UNIT: counts(278)}


def log(failed=0):
    return "\n".join((header("liteinst_launch"), "running 278 tests", summary(278 - failed, failed=failed)))


def result(exit_code=0):
    return {"exit_code": exit_code, "termination": None, "cleanup_complete": True,
            "reaped_descendants": 0, "seconds": 0.01, "private_log_sha256": "a" * 64}


def complete():
    record = {"source_unchanged": True, "configuration_unchanged": True,
              "toolchain_unchanged": True, "hardware_unchanged": True,
              "affinity_unchanged": True, "affinity_cpu_count": 8,
              "environment": {"CARGO_BUILD_JOBS": "4"}, "commands": dp.commands()}
    for command in record["commands"]:
        command.update(result())
        dp.observe(command, log(), EXPECTED)
    return record


class DefaultParallelTests(unittest.TestCase):
    def test_fork_cohort_authenticates_its_own_exact_corpus_and_commands(self):
        expected = {dp.FORK: counts(7)}
        corpus = {"schema_version": 1, "harness_test_counts": {
            "workspace_tests": EXPECTED | expected,
            "serial_launch": EXPECTED | expected}}
        data = json.dumps(corpus).encode()
        source = {"source_sha256": {"evaluation/admission/corpus.json": dp.sha(data)}}
        self.assertEqual(dp.authenticated_corpus(data, source, "fork"), expected)
        self.assertEqual(dp.authenticated_corpus(data, source), EXPECTED)
        self.assertEqual(dp.FORK_ARGV,
                         ("cargo", "test", "-p", "liteinst-launch", "--test", "dynamic_fork"))
        self.assertEqual([command["argv"] for command in dp.commands("fork")],
                         [list(dp.FORK_ARGV)] * 4)
        self.assertEqual([command["argv"] for command in dp.commands()], [list(dp.ARGV)] * 4)
        changed = copy.deepcopy(corpus)
        changed["harness_test_counts"]["serial_launch"][dp.FORK]["tests"] = 6
        with self.assertRaisesRegex(InvalidEvidence, "launch_unit_corpus_differs"):
            dp.expected_unit(changed, "fork")
        with self.assertRaisesRegex(InvalidEvidence, "default_parallel_corpus_source_mismatch"):
            dp.authenticated_corpus(data + b" ", source, "fork")
        for invalid in (None, "", "dynamic_fork", "unit --test-threads=1"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    InvalidEvidence, "invalid_default_parallel_cohort"):
                dp.commands(invalid)

    def test_fork_qualification_rejects_swapped_harness_commands_and_failed_repetitions(self):
        record = complete()
        record["cohort"] = "fork"
        record["commands"] = dp.commands("fork")
        text = "\n".join((header("dynamic_fork", unit=False), "running 7 tests", summary(7)))
        for command in record["commands"]:
            command.update(result())
            dp.observe(command, text, {dp.FORK: counts(7)})
        dp.qualify(record)
        self.assertEqual(record["status"], "passed")
        for index in range(4):
            for field, value in (("argv", list(dp.ARGV)), ("status", "failed"),
                                 ("exit_code", 101), ("reaped_descendants", 1)):
                changed = copy.deepcopy(record)
                changed["commands"][index][field] = value
                dp.qualify(changed)
                self.assertEqual(changed["status"], "failed")
                self.assertFalse(any(row["qualified_run"] for command in changed["commands"]
                                     for row in command["harnesses"]))
            changed = copy.deepcopy(record)
            changed["commands"][index]["harnesses"][0]["id"] = dp.UNIT
            dp.qualify(changed)
            self.assertEqual(changed["status"], "failed")
        changed = copy.deepcopy(record)
        changed["cohort"] = "unit"
        dp.qualify(changed)
        self.assertEqual(changed["status"], "failed")

    def test_fork_repetitions_keep_all_seven_cases_and_stop_on_first_failure(self):
        for failed_index in (None, 0, 3):
            record = {"commands": dp.commands("fork")}
            calls = []
            with tempfile.TemporaryDirectory() as temporary:
                def run(argv, env, path, timeout, limit):
                    index = len(calls)
                    calls.append(list(argv))
                    self.assertNotIn("RUST_TEST_THREADS", env)
                    self.assertEqual((timeout, limit), (180, 8 * 1024 * 1024))
                    failed = int(index == failed_index)
                    path.write_text("\n".join((header("dynamic_fork", unit=False),
                        "running 7 tests", summary(7 - failed, failed=failed))))
                    return result(101 if failed else 0)
                with patch.object(dp, "run_command", side_effect=run):
                    dp.execute(record, {}, Path(temporary), {dp.FORK: counts(7)},
                               lambda: None, lambda: None)
            attempts = 4 if failed_index is None else failed_index + 1
            self.assertEqual(calls, [list(dp.FORK_ARGV)] * attempts)
            self.assertEqual([command["status"] for command in record["commands"]],
                ["passed"] * 4 if failed_index is None else
                ["passed"] * failed_index + ["failed"] + ["not_run"] * (3 - failed_index))
            self.assertFalse(any(row["qualified_run"] for command in record["commands"]
                                 for row in command.get("harnesses", [])))

    def test_environment_removes_all_inherited_thread_overrides_and_keeps_build_bound(self):
        for threads in ("1", "64", "", "PRIVATE_SENTINEL"):
            env = dp.default_environment({"PATH": "/usr/bin:/bin", "HOME": "/CONFIG_HOME",
                    "RUST_TEST_THREADS": threads, "CARGO_BUILD_JOBS": "999",
                    "RUSTFLAGS": "PRIVATE_SENTINEL", "UNREVIEWED": "PRIVATE_SENTINEL"}, Path("/tmp/example"))
            self.assertNotIn("RUST_TEST_THREADS", env)
            self.assertEqual(env["CARGO_BUILD_JOBS"], "4")
            self.assertEqual(env["RUSTFLAGS"], "")
            self.assertNotIn("UNREVIEWED", env)
        self.assertEqual(dp.ARGV, ("cargo", "test", "-p", "liteinst-launch", "--lib"))
        self.assertTrue(all(command["argv"] == list(dp.ARGV) for command in dp.commands()))
        with self.assertRaisesRegex(InvalidEvidence, "relative_executable_search_path"):
            dp.default_environment({"PATH": "relative"}, Path("/tmp/example"))

    def test_affinity_is_exactly_eight_unique_typed_nonnegative_cpus(self):
        self.assertEqual(dp.affinity_witness({1, 3, 5, 7, 9, 11, 13, 15}),
                         frozenset((1, 3, 5, 7, 9, 11, 13, 15)))
        for value in (set(), set(range(7)), set(range(9)), list(range(8)),
                      {False, 1, 2, 3, 4, 5, 6, 7}, {-1, 1, 2, 3, 4, 5, 6, 7},
                      {"0", 1, 2, 3, 4, 5, 6, 7}):
            with self.subTest(value=value), self.assertRaisesRegex(InvalidEvidence, "default_parallel_requires_eight_cpus"):
                dp.affinity_witness(value)

    def test_unit_catalog_requires_matching_exact_unfiltered_denominator(self):
        corpus = {"schema_version": 1, "harness_test_counts":
                  {"workspace_tests": copy.deepcopy(EXPECTED), "serial_launch": copy.deepcopy(EXPECTED)}}
        self.assertEqual(dp.expected_unit(corpus), EXPECTED)
        data = json.dumps(corpus).encode()
        source = {"source_sha256": {"evaluation/admission/corpus.json": dp.sha(data)}}
        self.assertEqual(dp.authenticated_corpus(data, source), EXPECTED)
        for changed in (data + b" ", data.replace(b"278", b"277")):
            with self.assertRaisesRegex(InvalidEvidence, "default_parallel_corpus_source_mismatch"):
                dp.authenticated_corpus(changed, source)
        with self.assertRaisesRegex(InvalidEvidence, "default_parallel_corpus_source_mismatch"):
            dp.authenticated_corpus(data, {"source_sha256": {}})
        for schema in (True, 2, "1"):
            changed = copy.deepcopy(corpus)
            changed["schema_version"] = schema
            with self.assertRaisesRegex(InvalidEvidence, "unknown_corpus_schema"):
                dp.expected_unit(changed)
        changed = copy.deepcopy(corpus)
        changed["harness_test_counts"]["serial_launch"][dp.UNIT]["tests"] = 277
        with self.assertRaisesRegex(InvalidEvidence, "launch_unit_corpus_differs"):
            dp.expected_unit(changed)
        for invalid in ({"tests": True, "ignored": 0}, {"tests": 0, "ignored": 0},
                        {"tests": 278, "ignored": 279}, {"tests": 278, "ignored": -1},
                        {"tests": 278, "ignored": 0, "filtered": 1}):
            changed = copy.deepcopy(corpus)
            for cohort in changed["harness_test_counts"].values():
                cohort[dp.UNIT] = invalid
            with self.assertRaisesRegex(InvalidEvidence, "invalid_launch_unit_corpus"):
                dp.expected_unit(changed)

    def test_observation_preserves_failed_or_missing_evidence_without_qualification(self):
        command = dp.commands()[0] | result()
        dp.observe(command, log(), EXPECTED)
        self.assertEqual(command["status"], "passed")
        self.assertFalse(command["harnesses"][0]["qualified_run"])
        failed = dp.commands()[0] | result(101)
        dp.observe(failed, log(1), EXPECTED)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["harnesses"][0]["outer"]["failed"], 1)
        for text in (log() + "\n" + log(), log().replace("liteinst_launch-", "other-"),
                     log().replace("0 filtered out", "1 filtered out"),
                     log().split("test result:")[0], "PRIVATE_SENTINEL compiler failure",
                     log().replace("target/debug/deps/", "/PRIVATE_SENTINEL/")):
            command = dp.commands()[0] | result()
            dp.observe(command, text, EXPECTED)
            self.assertEqual(command["status"], "invalid_evidence")
            self.assertTrue(all(not row["qualified_run"] for row in command["harnesses"]))
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(command))

    def test_qualification_requires_all_four_exact_commands_and_physical_cleanup(self):
        record = complete()
        dp.qualify(record)
        self.assertEqual(record["status"], "passed")
        self.assertTrue(all(row["qualified_run"] for command in record["commands"] for row in command["harnesses"]))
        for index in range(4):
            for field, value in (("status", "failed"), ("exit_code", 101),
                    ("termination", "timeout"), ("cleanup_complete", False),
                    ("reaped_descendants", 1), ("evidence_status", "incomplete"),
                    ("argv", list(dp.ARGV) + ["--", "--test-threads=1"]),
                    ("timeout_seconds", 181), ("environment_delta", {"RUST_TEST_THREADS": "1"})):
                record = complete()
                record["commands"][index][field] = value
                dp.qualify(record)
                self.assertEqual(record["status"], "failed")
                self.assertTrue(all(not row["qualified_run"] for command in record["commands"] for row in command["harnesses"]))
        for count in (0, 3, 5):
            record = complete()
            record["commands"] = (record["commands"] + [copy.deepcopy(record["commands"][0])])[:count]
            dp.qualify(record)
            self.assertEqual(record["status"], "failed")

    def test_changed_source_configuration_tools_hardware_or_affinity_disqualifies_every_row(self):
        for field in ("source_unchanged", "configuration_unchanged", "toolchain_unchanged",
                      "hardware_unchanged", "affinity_unchanged"):
            for value in (False, None):
                record = complete()
                record[field] = value
                dp.qualify(record)
                self.assertEqual(record["status"], "failed")
                self.assertTrue(all(not row["qualified_run"] for command in record["commands"] for row in command["harnesses"]))
        for field, value in (("affinity_cpu_count", 7), ("error_code", "source_changed"),
                             ("error_type", "RuntimeError"), ("environment", {"RUST_TEST_THREADS": None})):
            record = complete()
            record[field] = value
            dp.qualify(record)
            self.assertEqual(record["status"], "failed")

    def test_fixed_sequential_repetitions_stop_after_first_failure_without_retry(self):
        for failure_index in (None, 1):
            record = {"commands": dp.commands()}
            calls = []
            stable = []
            published = []
            with tempfile.TemporaryDirectory() as temporary:
                def run(argv, env, path, timeout, limit):
                    index = len(calls)
                    calls.append((list(argv), dict(env), path.name, timeout, limit))
                    failed = index == failure_index
                    path.write_text(log(int(failed)))
                    return result(101 if failed else 0)
                with patch.object(dp, "run_command", side_effect=run):
                    dp.execute(record, {"CARGO_BUILD_JOBS": "4"}, Path(temporary), EXPECTED,
                               lambda: published.append(copy.deepcopy(record)), lambda: stable.append(True))
            attempted = 4 if failure_index is None else 2
            self.assertEqual(len(calls), attempted)
            self.assertEqual(len(stable), 2 * attempted)
            self.assertEqual(len(published), 2 * attempted)
            for index, (argv, env, name, timeout, limit) in enumerate(calls):
                self.assertEqual(argv, list(dp.ARGV))
                self.assertNotIn("RUST_TEST_THREADS", env)
                self.assertEqual(name, dp.IDS[index] + ".log")
                self.assertEqual((timeout, limit), (180, 8 * 1024 * 1024))
            self.assertEqual([command["status"] for command in record["commands"]],
                             ["passed"] * 4 if failure_index is None else ["passed", "failed", "not_run", "not_run"])
            self.assertTrue(all(not row["qualified_run"] for command in record["commands"] for row in command.get("harnesses", [])))

    def test_post_command_proof_failure_retains_the_captured_prefix_as_unqualified(self):
        record = {"commands": dp.commands()}
        calls = []
        published = []
        def stable():
            calls.append(True)
            if len(calls) == 2:
                raise InvalidEvidence("default_parallel_source_changed")
        with tempfile.TemporaryDirectory() as temporary:
            def run(argv, env, path, timeout, limit):
                path.write_text(log())
                return result()
            with patch.object(dp, "run_command", side_effect=run) as runner:
                with self.assertRaisesRegex(InvalidEvidence, "default_parallel_source_changed"):
                    dp.execute(record, {}, Path(temporary), EXPECTED,
                               lambda: published.append(copy.deepcopy(record)), stable)
                self.assertEqual(runner.call_count, 1)
        self.assertEqual(record["commands"][0]["harnesses"][0]["outer"]["passed"], 278)
        self.assertFalse(record["commands"][0]["harnesses"][0]["qualified_run"])
        self.assertEqual([command["status"] for command in record["commands"]], ["passed", "not_run", "not_run", "not_run"])
        self.assertEqual(published[-1], record)
