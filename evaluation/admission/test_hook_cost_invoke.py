import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import hook_cost_invoke as invoke
import run
from hook_cost_proof import PUBLIC_ENV, LOG_LIMIT, sha
from hook_cost import BINARY, BUILD, BUILD_TIMEOUT, MEASURE_TIMEOUT
from hook_cost_schema import parse_capture
from hook_cost_test_support import wire_records, wire
from parsing import InvalidEvidence


def completion_inputs():
    catalog, rows = wire_records()
    source = {"revision": "a" * 40}
    record = {"run_id": "test", "source": source, "configuration": [], "toolchain": {},
              "source_unchanged": True, "configuration_unchanged": True, "allocator_unchanged": True,
              "toolchain_unchanged": True, "qualified": False, "hardware": {"affinity_cpu_count": 16},
              "correctness": {"qualified_correctness": True}, "executed_binary": {"sha256": "b" * 64}}
    command = {"exit_code": 0, "termination": None, "cleanup_complete": True,
               "reaped_descendants": 0, "status": "passed", "seconds": 1.0, "start_utc": "2026-10-26T01:02:03.000000+00:00",
               "child_discovery_strategy": "proc_children", "private_log_sha256": "a" * 64}
    inner = {"schema_version": 1, "experiment": "b2-hook-cost", "run_id": "test", "status": "measured_pending_outer",
             "qualified": False, "source": source, "configuration": [], "toolchain": {}, "environment": PUBLIC_ENV,
             "log_limit_bytes_per_command": LOG_LIMIT, "source_unchanged": True, "configuration_unchanged": True,
             "placement_unchanged": True, "hardware_unchanged": True, "toolchain_unchanged": True,
             "executable_unchanged": True, "hardware": {"affinity_cpu_count": 2},
             "correctness": record["correctness"], "executable": record["executed_binary"],
             "inherited_location_variables": list(run.LOCATION_VARIABLES),
             "claim_scope": "finite_scripted_synchronous_completion_cost", "performance_pass_threshold": None,
             "clock": {"implementation": "clock_gettime(CLOCK_MONOTONIC)", "resolution_seconds": 1e-9,
                 "monotonic": True, "adjustable": False, "calibration_subtracted": False,
                 "clocksource": {"status": "observed", "value": "tsc"}},
             "placement": {"affinity": [2, 4], "effective_cpuset": [2, 4], "hard_cpuset": "cgroup_v2_effective",
                 "reserved_logical_cpus": 2, "selected_physical_cores": 2, "physical_core_exclusivity_claimed": False,
                 "topology": [{"cpu": n, "package": 0, "core": n, "thread_siblings": [n],
                               "governor": {"status": "interface_absent", "value": None}} for n in (2, 4)]},
             "commands": [command | {"id": "release_build", "argv": BUILD, "timeout_seconds": BUILD_TIMEOUT, "environment_delta": {}},
                          command | {"id": "measurement", "argv": [BINARY] + catalog["argv"],
                                     "timeout_seconds": MEASURE_TIMEOUT, "environment_delta": {}}],
             "evidence": parse_capture(wire(rows), catalog)}
    for field, filename in (("runner_sha256", "hook_cost.py"), ("inventory_sha256", "hook_cost_inventory.json"),
                            ("wire_sha256", "hook_cost_wire.json")):
        inner[field] = sha(Path(__file__).with_name(filename).read_bytes())
    record["capture_evidence"] = copy.deepcopy(inner["evidence"])
    record["inner_capture_matches"] = True
    record["inner_capture_authenticated"] = {"release_build": True, "measurement": True}
    record["collection"] = {"status": "observed_unqualified", "qualified": False,
                            "evidence": copy.deepcopy(inner["evidence"])}
    return record, inner, command, {"cpus": [2, 4]}, catalog


class HookCostOuterTests(unittest.TestCase):
    def test_allocator_assignment_is_exact_and_has_no_host_fields(self):
        text = 'cpuset-alloc: run: reserved {"cores":[4,2],"count":2}; running whole tree pinned via AllowedCPUs=2,4\n'
        row = invoke.assignment(text)
        self.assertEqual(row["cpus"], [2, 4])
        self.assertNotIn("pid", row)

    def test_missing_duplicate_or_mismatched_allocator_assignment_refuses(self):
        good = 'cpuset-alloc: run: reserved {"cores":[2,4],"count":2}; running whole tree pinned via AllowedCPUs=2,4\n'
        for text in ("", good + good, good.replace("count\":2", "count\":true"), good.replace("AllowedCPUs=2,4", "AllowedCPUs=2,5")):
            with self.assertRaises(InvalidEvidence):
                invoke.assignment(text)

    def test_all_outer_proofs_qualify_exact_observed_rows(self):
        record, inner, command, cpus, catalog = completion_inputs()
        invoke.finalize(record, inner, command, cpus, catalog)
        self.assertEqual(record["status"], "passed")
        self.assertTrue(all(r["qualified"] for r in record["collection"]["evidence"]["completions"]))
        self.assertFalse(any(r["qualified"] for r in inner["evidence"]["completions"]))

    def test_successful_inner_cannot_hide_outer_adoptee(self):
        record, inner, command, cpus, catalog = completion_inputs()
        command["reaped_descendants"] = 1
        with self.assertRaises(InvalidEvidence):
            invoke.finalize(record, inner, command, cpus, catalog)
        self.assertFalse(any(r["qualified"] for r in inner["evidence"]["completions"]))

    def test_source_tool_or_allocator_change_refuses(self):
        for key in ("source_unchanged", "configuration_unchanged", "allocator_unchanged", "toolchain_unchanged"):
            record, inner, command, cpus, catalog = completion_inputs()
            record[key] = False
            with self.assertRaises(InvalidEvidence):
                invoke.finalize(record, inner, command, cpus, catalog)

    def test_affinity_cannot_substitute_for_matching_hard_assignment(self):
        record, inner, command, cpus, catalog = completion_inputs()
        cpus["cpus"] = [2, 5]
        with self.assertRaises(InvalidEvidence):
            invoke.finalize(record, inner, command, cpus, catalog)

    def test_inner_failure_retains_rows_but_never_qualifies(self):
        record, inner, command, cpus, catalog = completion_inputs()
        inner["status"] = "failed"
        with self.assertRaises(InvalidEvidence):
            invoke.finalize(record, inner, command, cpus, catalog)
        self.assertIsNot(record["collection"], inner)
        self.assertEqual(record["collection"]["status"], "observed_unqualified")
        self.assertFalse(any(r["qualified"] for r in inner["evidence"]["completions"]))

    def test_empty_complete_collection_cannot_override_capture(self):
        record, inner, command, cpus, catalog = completion_inputs()
        inner["evidence"]["completions"] = []
        with self.assertRaisesRegex(InvalidEvidence, "inner_capture_evidence_differs"):
            invoke.finalize(record, inner, command, cpus, catalog)

    def test_wrong_inner_command_or_budget_cannot_qualify(self):
        for field, value in (("argv", ["cargo", "check"]), ("timeout_seconds", 181)):
            record, inner, command, cpus, catalog = completion_inputs()
            inner["commands"][0][field] = value
            with self.assertRaisesRegex(InvalidEvidence, "inner_commands_incomplete"):
                invoke.finalize(record, inner, command, cpus, catalog)

    def test_capture_recovery_retains_prefix_without_staging_receipt(self):
        catalog, rows = wire_records()
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            (private / "measurement.log").write_text(wire(rows[:6]))
            record = {"run_id": "test", "collection": None}
            invoke.harvest(private, record, catalog)
            self.assertEqual(record["inner_state"], "not_started_or_no_receipt")
            self.assertFalse(record["inner_capture_matches"])
            self.assertEqual(record["collection"]["evidence"]["completions"][0]["status"], "observed_unqualified")
            self.assertEqual(record["collection"]["evidence"]["completions"][4]["status"], "not_observed")

    def test_capture_mismatch_is_retained_but_never_authenticated(self):
        catalog, rows = wire_records()
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            (private / "measurement.log").write_text(wire(rows[:6]))
            (private / "inner.json").write_text(json.dumps({"run_id": "test", "commands": [
                {"id": "measurement", "private_log_sha256": "f" * 64}], "evidence": parse_capture("", catalog)}))
            record = {"run_id": "test", "collection": None}
            invoke.harvest(private, record, catalog)
            self.assertFalse(record["inner_capture_authenticated"]["measurement"])
            self.assertFalse(record["inner_capture_matches"])
            self.assertEqual(record["collection"]["evidence"]["completions"][0]["status"], "observed_unqualified")

    def test_untrusted_staging_paths_and_malformed_evidence_stay_private(self):
        catalog, rows = wire_records()
        for evidence in (None, {"status": "complete", "sessions": "/private/secret"}):
            with tempfile.TemporaryDirectory() as temporary:
                private = Path(temporary)
                (private / "measurement.log").write_text(wire(rows[:6]))
                raw = {"run_id": "test", "debug_path": "/private/secret", "evidence": evidence,
                       "commands": ["/private/secret"], "nested": {"path": "/private/secret"}}
                (private / "inner.json").write_text(json.dumps(raw))
                record = {"run_id": "test", "collection": None}
                observed_private = invoke.harvest(private, record, catalog)
                self.assertEqual(observed_private, raw)
                self.assertNotIn("/private", json.dumps(record))
                self.assertEqual(record["collection"]["evidence"]["completions"][0]["status"], "observed_unqualified")

    def test_success_projection_refuses_unknown_or_nested_private_fields(self):
        for mutate in (lambda inner: inner.update(debug_path="/private/secret"),
                       lambda inner: inner["placement"]["topology"][0]["governor"].update(value="/private/secret")):
            record, inner, command, cpus, catalog = completion_inputs()
            mutate(inner)
            with self.assertRaises(InvalidEvidence):
                invoke.finalize(record, inner, command, cpus, catalog)
            self.assertNotIn("/private", json.dumps(record))

    def test_portable_allocator_token_uses_only_controlled_path(self):
        with patch.object(invoke.shutil, "which", return_value="/approved/bin/cpuset-alloc") as lookup:
            self.assertEqual(invoke.resolve_allocator("cpuset-alloc", {"PATH": "/approved/bin"}), "/approved/bin/cpuset-alloc")
            lookup.assert_called_once_with("cpuset-alloc", path="/approved/bin")
        with self.assertRaises(InvalidEvidence):
            invoke.resolve_allocator("relative/tool", {"PATH": "/approved/bin"})

    def test_failed_commands_keep_exact_outcomes_without_qualification(self):
        _, inner, _, _, catalog = completion_inputs()
        inner["commands"][0].update(status="failed", exit_code=101, termination=None, seconds=2.5)
        inner["commands"][1] = {"id": "measurement", "argv": inner["commands"][1]["argv"],
            "timeout_seconds": MEASURE_TIMEOUT, "environment_delta": {}, "status": "not_run"}
        public = invoke.observed_commands(inner, catalog)
        self.assertEqual(public[0]["exit_code"], 101)
        self.assertEqual(public[0]["seconds"], 2.5)
        self.assertEqual(public[1]["status"], "not_run")
        self.assertTrue(all(not c["qualified"] for c in public))
        inner["commands"][1].update(status="failed", exit_code=-9, termination="timeout", cleanup_complete=True,
                                    reaped_descendants=1, seconds=300.1)
        public = invoke.observed_commands(inner, catalog)
        self.assertEqual((public[1]["exit_code"], public[1]["termination"], public[1]["reaped_descendants"]), (-9, "timeout", 1))
        inner["commands"][1]["termination"] = "/private/path"
        public = invoke.observed_commands(inner, catalog)
        self.assertEqual(public[1]["status"], "invalid_staging_metadata")
        self.assertNotIn("/private", json.dumps(public))

    def test_private_tmp_does_not_redirect_shared_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            private = base / "private"
            private.mkdir()
            inherited = {"PATH": "/usr/bin:/bin", "HOME": str(base)}
            with patch("hook_cost_invoke.tempfile.gettempdir", return_value=str(base)):
                env, proof = invoke.allocator_environment(inherited, private)
            self.assertEqual(env["DAGRUN_CORE_LEDGER"], str(base / f"dagrun-{os.getuid()}" / "core-reservations.json"))
            self.assertNotIn(str(private), env["DAGRUN_CORE_LEDGER"])
            self.assertTrue(proof["private_tmp_does_not_select_ledger"])
            self.assertNotIn("ledger_path", proof)

    def test_untrusted_engine_and_pythonpath_are_not_inherited(self):
        with tempfile.TemporaryDirectory() as temporary:
            env, _ = invoke.allocator_environment({"PATH": "/usr/bin", "HOME": temporary,
                "DAGRUN_ENGINE": "rust", "PYTHONPATH": "/private", "CI_HUB_PYTHON": "/private/python",
                "DAGRUN_CORE_LEDGER": temporary + "/shared.json"}, Path(temporary))
            self.assertEqual(env["DAGRUN_ENGINE"], "python")
            self.assertNotIn("PYTHONPATH", env)
            self.assertNotIn("CI_HUB_PYTHON", env)

    def test_invalid_published_argument_is_redacted_in_durable_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            here = root / "evaluation/admission"
            here.mkdir(parents=True)
            args = SimpleNamespace(expect_revision="a" * 40, correctness_receipt="/private/secret-receipt",
                correctness_sha256="b" * 64, allocator="/private/tool", allocator_sha256="c" * 64)
            with patch.object(invoke, "ROOT", root), patch.object(invoke, "HERE", here), \
                 patch.object(invoke, "run_command") as command:
                self.assertEqual(invoke.invoke(args), 1)
                command.assert_not_called()
            files = list((here / "results").glob("*.json"))
            self.assertEqual(len(files), 1)
            record = json.loads(files[0].read_text())
            self.assertEqual(record["status"], "failed")
            self.assertIsNone(record["reproduce"])
            self.assertNotIn("/private", files[0].read_text())


if __name__ == "__main__":
    unittest.main()
