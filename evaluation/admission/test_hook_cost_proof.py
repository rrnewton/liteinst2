import copy
from pathlib import Path
import tempfile
import unittest

from parsing import InvalidEvidence
from hook_cost_proof import cpu_list, hardware_relation, strict_json, validate_correctness, replay_correctness, sha
from hook_cost_test_support import correctness_input, placement_input


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
        args = list(correctness_input())
        args[5]["affinity_cpu_count"] = 2
        self.assertEqual(validate_correctness(*args, scoped_placement=placement_input()), "a" * 40)

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

    def test_unscoped_prior_counts_must_remain_exact(self):
        self.assertEqual(self.check(), "a" * 40)
        for key in ("affinity_cpu_count", "logical_cpus_visible"):
            args = list(correctness_input())
            args[5][key] = 2
            with self.subTest(key=key), self.assertRaisesRegex(InvalidEvidence, "unscoped_hardware_counts_differ"):
                validate_correctness(*args)

    def test_scoped_count_relations_retain_actual_observations(self):
        for logical, label in ((16, "unchanged"), (2, "equals_hard_placement")):
            args = list(correctness_input())
            args[5].update(affinity_cpu_count=2, logical_cpus_visible=logical)
            prior, observed, placed = args[0]["hardware"], args[5], placement_input()
            saved = copy.deepcopy((prior, observed, placed))
            self.assertEqual(validate_correctness(*args, scoped_placement=placed), "a" * 40)
            proof = hardware_relation(prior, observed, placed)
            self.assertEqual(proof, {"mode": "scoped_exact_placement", "logical_count_relation": label,
                "reference_counts": {"affinity_cpu_count": 16, "logical_cpus_visible": 16},
                "observed_counts": {"affinity_cpu_count": 2, "logical_cpus_visible": logical},
                "placement_cpu_count": 2})
            self.assertEqual((prior, observed, placed), saved)

    def test_invalid_or_unbound_count_observations_refuse(self):
        for side in ("prior", "observed"):
            for key in ("affinity_cpu_count", "logical_cpus_visible"):
                for value in (None, 0, True, -1):
                    args = list(correctness_input())
                    args[5].update(affinity_cpu_count=2, logical_cpus_visible=2)
                    target = args[0]["hardware"] if side == "prior" else args[5]
                    if value is None:
                        del target[key]
                    else:
                        target[key] = value
                    with self.subTest(side=side, key=key, value=value), \
                         self.assertRaisesRegex(InvalidEvidence, "hardware_count_missing_or_invalid"):
                        validate_correctness(*args, scoped_placement=placement_input())
        for key, error in (("affinity_cpu_count", "hardware_affinity_placement_differs"),
                           ("logical_cpus_visible", "hardware_visible_count_not_bound")):
            args = list(correctness_input())
            args[5].update(affinity_cpu_count=2, logical_cpus_visible=2)
            args[5][key] = 3
            with self.subTest(key=key), self.assertRaisesRegex(InvalidEvidence, error):
                validate_correctness(*args, scoped_placement=placement_input())

    def test_scoped_counts_require_complete_matching_placement(self):
        mutations = [lambda p: p.pop("effective_cpuset"),
                     lambda p: p.update(effective_cpuset=[2, 5]),
                     lambda p: p.update(affinity=[2, 2], effective_cpuset=[2, 2]),
                     lambda p: p.update(affinity=[2, 4, 6], effective_cpuset=[2, 4, 6]),
                     lambda p: p.update(hard_cpuset="affinity_only"),
                     lambda p: p.update(reserved_logical_cpus=True),
                     lambda p: p["topology"][1].update(core=2),
                     lambda p: p["topology"][1].update(cpu=5)]
        for mutate in mutations:
            args = list(correctness_input())
            args[5].update(affinity_cpu_count=2, logical_cpus_visible=2)
            placed = placement_input()
            mutate(placed)
            with self.assertRaises(InvalidEvidence):
                validate_correctness(*args, scoped_placement=placed)

    def test_scoped_count_relation_never_exempts_other_hardware_fields(self):
        for key, before, after in (("model_name", "CPU A", "CPU B"),
                ("isa_flags", ["sse"], ["sse", "avx"]), ("microcode", "0x1", "0x2"),
                ("kernel_release_sha256", "a" * 64, "b" * 64),
                ("effective_uid_is_root", False, True), ("effective_capabilities", 0, 1),
                ("ptrace_scope_status", "observed", "interface_absent"), ("ptrace_scope", 0, 1)):
            args = list(correctness_input())
            args[0]["hardware"][key] = before
            args[5].update(affinity_cpu_count=2, logical_cpus_visible=2)
            args[5][key] = after
            with self.subTest(key=key), self.assertRaisesRegex(InvalidEvidence, "correctness_hardware_differs"):
                validate_correctness(*args, scoped_placement=placement_input())

    def test_scoped_relation_cannot_expand_a_smaller_baseline(self):
        for key in ("affinity_cpu_count", "logical_cpus_visible"):
            args = list(correctness_input())
            args[0]["hardware"][key] = 1
            args[5].update(affinity_cpu_count=2, logical_cpus_visible=2)
            with self.subTest(key=key), self.assertRaisesRegex(InvalidEvidence, "hardware_count_scope_expands"):
                validate_correctness(*args, scoped_placement=placement_input())


if __name__ == "__main__":
    unittest.main()
