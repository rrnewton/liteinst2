import copy
from pathlib import Path
import tempfile
import unittest

from parsing import InvalidEvidence
from hook_cost_proof import cpu_list, strict_json, validate_correctness, replay_correctness, sha
from hook_cost_test_support import correctness_input


class HookCostPrerequisiteTests(unittest.TestCase):
    def check(self, mutate=None):
        args = list(copy.deepcopy(correctness_input()))
        if mutate:
            mutate(args[0])
        return validate_correctness(*args)

    def reject(self, mutate):
        with self.assertRaises(InvalidEvidence):
            self.check(mutate)

    def test_exact_prior_contract_allows_changed_reserved_affinity(self):
        self.assertEqual(self.check(), "a" * 40)

    def test_prior_actual_compiler_hash_is_not_invented(self):
        args = list(correctness_input())
        args[-1]["cargo"]["executable_sha256"] = "f" * 64
        self.assertEqual(validate_correctness(*args), "a" * 40)

    def test_boolean_schema_is_not_version_one(self):
        self.reject(lambda r: r.update(schema_version=True))

    def test_source_manifest_mismatch_refuses(self):
        self.reject(lambda r: r["source"].update(source_manifest_sha256="f" * 64))

    def test_missing_tool_fields_cannot_vacuously_match(self):
        for name in ("cargo", "rustc", "git", "python"):
            with self.subTest(name=name):
                self.reject(lambda r: r["toolchain"].update({name: {}}))

    def test_tool_digest_width_and_type_are_strict(self):
        for value in ("a", True, "X" * 64):
            self.reject(lambda r: r["toolchain"]["cargo"].update(launcher_sha256=value))

    def test_missing_zero_or_boolean_prior_affinity_refuses(self):
        self.reject(lambda r: r["hardware"].pop("affinity_cpu_count"))
        for value in (0, True):
            self.reject(lambda r: r["hardware"].update(affinity_cpu_count=value))

    def test_controlled_environment_and_location_contract_are_exact(self):
        self.reject(lambda r: r.update(environment={}))
        self.reject(lambda r: r.update(inherited_location_variables=["PATH"]))

    def test_serial_evaluation_flag_is_mandatory(self):
        self.reject(lambda r: r["commands"][-1].update(environment_delta={}))

    def test_unexpected_command_environment_is_rejected(self):
        self.reject(lambda r: r["commands"][0].update(environment_delta={"RUST_TEST_THREADS": "1"}))

    def test_capture_limit_cannot_be_widened(self):
        self.reject(lambda r: r.update(log_limit_bytes_per_command=16 * 1024 * 1024))

    def test_command_deadline_or_argv_cannot_change(self):
        self.reject(lambda r: r["commands"][3].update(timeout_seconds=361))
        self.reject(lambda r: r["commands"][3].update(argv=["cargo", "test", "--lib"]))

    def test_cargo_success_with_adoptee_or_incomplete_cleanup_refuses(self):
        self.reject(lambda r: r["commands"][3].update(reaped_descendants=1))
        self.reject(lambda r: r["commands"][3].update(cleanup_complete=False))

    def test_missing_named_class_cannot_hide_behind_test_total(self):
        self.reject(lambda r: r["commands"][-1].update(dynamic_matrix_cases=[]))

    def test_ignored_case_increase_is_not_a_pass(self):
        self.reject(lambda r: r["commands"][3]["harnesses"][0]["outer"].update(passed=0, ignored=5))

    def test_cpu_list_accepts_exact_numeric_topology(self):
        self.assertEqual(cpu_list("2,4-5"), [2, 4, 5])

    def test_cpu_list_rejects_overlap_unbounded_or_injected_text(self):
        for value in ("1,1", "1-3,2", "0-9999999", "", "1;2", "../private", "1-0"):
            with self.subTest(value=value), self.assertRaises(InvalidEvidence):
                cpu_list(value)

    def test_prior_json_duplicate_and_nonfinite_are_rejected(self):
        for value in ('{"status":"passed","status":"failed"}', '{"n":Infinity}'):
            with self.assertRaises(InvalidEvidence):
                strict_json(value)

    def test_prior_capture_hash_binds_actual_private_bytes(self):
        record, _, corpus, *_ = correctness_input()
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "recorder_tests.log").write_bytes(b"changed private capture")
            with self.assertRaisesRegex(InvalidEvidence, "correctness_capture_differs"):
                replay_correctness(record, corpus, Path(temporary))

    def test_missing_prior_capture_refuses_before_measurement(self):
        record, _, corpus, *_ = correctness_input()
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(FileNotFoundError):
            replay_correctness(record, corpus, Path(temporary))

    def test_claimed_pass_cannot_replace_missing_actual_harness(self):
        record, _, corpus, *_ = correctness_input()
        with tempfile.TemporaryDirectory() as temporary:
            for command in record["commands"]:
                data = b"Ran 2 tests in 0.01s\n\nOK\n" if command["id"] == "recorder_tests" else b""
                (Path(temporary) / (command["id"] + ".log")).write_bytes(data)
                command["private_log_sha256"] = sha(data)
            with self.assertRaisesRegex(InvalidEvidence, "correctness_capture_replay_failed"):
                replay_correctness(record, corpus, Path(temporary))


if __name__ == "__main__":
    unittest.main()
