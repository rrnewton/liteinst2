import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import hook_cost
import hook_cost_invoke
from hook_cost_proof import sha
from hook_cost_test_support import wire_records, wire
from parsing import InvalidEvidence


def source_with_catalog(here):
    data = Path(__file__).with_name("hook_cost_inventory.json").read_bytes()
    (here / "hook_cost_inventory.json").write_bytes(data)
    return {"revision": "a" * 40,
            "source_sha256": {"evaluation/admission/hook_cost_inventory.json": sha(data)}}


class HookCostCollectionTests(unittest.TestCase):
    def inner(self, command_results, prerequisite_error=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            here = root / "evaluation/admission"
            here.mkdir(parents=True)
            (here / "corpus.json").write_text("{}")
            source = source_with_catalog(here)
            for name in ("hook_cost_inventory.json", "hook_cost_wire.json"):
                (here / name).write_bytes(Path(__file__).with_name(name).read_bytes())
            run_id = "20261026T010203.000001Z-" + "a" * 12 + "-hook-cost"
            private = root / "target/evaluation/admission" / run_id
            private.mkdir(parents=True)
            args = SimpleNamespace(run_id=run_id, expect_revision="a" * 40,
                correctness_receipt="prior.json", correctness_sha256="b" * 64)
            calls = []
            def command(argv, env, log, timeout, limit):
                index = len(calls)
                calls.append((argv, timeout, limit))
                exit_code, text, adoptees = command_results[index]
                data = text.encode()
                log.write_bytes(data)
                return {"exit_code": exit_code, "termination": None, "cleanup_complete": True,
                        "reaped_descendants": adoptees, "private_log_sha256": sha(data)}
            with patch.object(hook_cost, "ROOT", root), patch.object(hook_cost, "HERE", here), \
                 patch.object(hook_cost, "source_identity", return_value=source), \
                 patch.object(hook_cost.run, "cargo_configuration", return_value=[]), \
                 patch.object(hook_cost.run, "hardware", return_value={"effective_uid_is_root": False, "effective_capabilities": 0}), \
                 patch.object(hook_cost, "placement", return_value={"affinity": [2, 4]}), \
                 patch.object(hook_cost, "clock_metadata", return_value={}), \
                 patch.object(hook_cost, "toolchain", return_value={}), \
                 patch.object(hook_cost, "executable_identity", return_value={"sha256": "c" * 64}), \
                 patch.object(hook_cost.resource, "setrlimit"), \
                 patch.object(hook_cost, "correctness_prerequisite", side_effect=InvalidEvidence("synthetic_prior_refusal") if prerequisite_error else None,
                              return_value={"qualified_correctness": True}), \
                 patch.object(hook_cost, "run_command", side_effect=command):
                code = hook_cost.collect(args)
            return code, json.loads((private / "inner.json").read_text()), calls

    def test_failed_correctness_precondition_starts_no_build(self):
        code, record, calls = self.inner([], prerequisite_error=True)
        self.assertEqual(code, 1)
        self.assertEqual(record["error"], "synthetic_prior_refusal")
        self.assertEqual(calls, [])

    def test_release_build_failure_prevents_measurement(self):
        code, record, calls = self.inner([(101, "private compiler failure", 0)])
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(record["commands"][1]["status"], "not_run")
        self.assertNotIn("private compiler failure", json.dumps(record))

    def test_measurement_exit_failure_preserves_valid_prefix(self):
        _, rows = wire_records()
        code, record, calls = self.inner([(0, "", 0), (1, wire(rows[:6]), 0)])
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(record["evidence"]["completions"][0]["status"], "observed_unqualified")
        self.assertFalse(record["qualified"])

    def test_successful_measurement_with_adoptee_is_failed(self):
        _, rows = wire_records()
        code, record, _ = self.inner([(0, "", 0), (0, wire(rows), 1)])
        self.assertEqual(code, 1)
        self.assertEqual(record["commands"][1]["status"], "failed")
        self.assertFalse(any(r["qualified"] for r in record["evidence"]["completions"]))

    def test_full_inner_success_still_awaits_outer_qualification(self):
        _, rows = wire_records()
        code, record, calls = self.inner([(0, "", 0), (0, wire(rows), 0)])
        self.assertEqual(code, 0)
        self.assertEqual(record["status"], "measured_pending_outer")
        self.assertFalse(record["qualified"])
        self.assertEqual([c[1] for c in calls], [180, 300])
        self.assertEqual([c[2] for c in calls], [8 * 1024 * 1024] * 2)

    def test_allocator_refusal_without_inner_is_public_terminal_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            here = root / "evaluation/admission"
            here.mkdir(parents=True)
            (here / "corpus.json").write_text("{}")
            source = source_with_catalog(here)
            args = SimpleNamespace(expect_revision="a" * 40,
                correctness_receipt="20261026T010203.000001Z-" + "a" * 12 + ".json",
                correctness_sha256="b" * 64, allocator="/private/bin/cpuset-alloc", allocator_sha256="c" * 64)
            calls = []
            def command(argv, env, log, timeout, limit):
                calls.append((argv, timeout, limit))
                data = b"private allocator refusal details\n"
                log.write_bytes(data)
                return {"exit_code": 3, "termination": None, "cleanup_complete": True,
                        "reaped_descendants": 0, "private_log_sha256": sha(data)}
            with patch.object(hook_cost_invoke, "ROOT", root), patch.object(hook_cost_invoke, "HERE", here), \
                 patch.object(hook_cost_invoke, "source_identity", return_value=source), \
                 patch.object(hook_cost_invoke, "allocator_environment", return_value=({"PATH": "/usr/bin"}, {})), \
                 patch.object(hook_cost_invoke.run, "cargo_configuration", return_value=[]), \
                 patch.object(hook_cost_invoke.run, "hardware", return_value={"effective_uid_is_root": False, "effective_capabilities": 0}), \
                 patch.object(hook_cost_invoke, "correctness_prerequisite", return_value={"qualified_correctness": True}), \
                 patch.object(hook_cost_invoke, "toolchain", return_value={}), \
                 patch.object(hook_cost_invoke, "scope_identity", return_value={}), \
                 patch.object(hook_cost_invoke.resource, "setrlimit"), \
                 patch.object(hook_cost_invoke, "allocator_identity", return_value={"entry_sha256": "c" * 64}), \
                 patch.object(hook_cost_invoke, "run_command", side_effect=command):
                self.assertEqual(hook_cost_invoke.invoke(args), 1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1:], (600, 8 * 1024 * 1024))
            output = next((here / "results").glob("*.json"))
            record = json.loads(output.read_text())
            self.assertEqual(record["command"]["exit_code"], 3)
            self.assertEqual(record["inner_state"], "not_started_or_no_receipt")
            self.assertFalse(record["whole_protocol_qualified"])
            self.assertEqual(len(record["collection"]["evidence"]["completions"]), 442)
            self.assertNotIn("/private", output.read_text())
            self.assertNotIn("private allocator refusal details", output.read_text())

    def test_outer_source_recheck_failure_preserves_capture_before_refusal(self):
        _, rows = wire_records()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            here = root / "evaluation/admission"
            here.mkdir(parents=True)
            (here / "corpus.json").write_text("{}")
            source = source_with_catalog(here)
            args = SimpleNamespace(expect_revision="a" * 40,
                correctness_receipt="20261026T010203.000001Z-" + "a" * 12 + ".json",
                correctness_sha256="b" * 64, allocator="/private/bin/cpuset-alloc", allocator_sha256="c" * 64)
            def command(argv, env, log, timeout, limit):
                data = wire(rows[:6]).encode()
                (log.parent / "measurement.log").write_bytes(data)
                (log.parent / "inner.json").write_text(json.dumps({"run_id": log.parent.name,
                    "status": "running", "commands": [], "evidence": None, "debug_path": "/private/hidden"}))
                log.write_bytes(b"")
                return {"exit_code": 0, "termination": None, "cleanup_complete": True,
                        "reaped_descendants": 0, "private_log_sha256": sha(b"")}
            with patch.object(hook_cost_invoke, "ROOT", root), patch.object(hook_cost_invoke, "HERE", here), \
                 patch.object(hook_cost_invoke, "source_identity", side_effect=[source, InvalidEvidence("dirty_tracked_source")]), \
                 patch.object(hook_cost_invoke, "allocator_environment", return_value=({"PATH": "/usr/bin"}, {})), \
                 patch.object(hook_cost_invoke.run, "cargo_configuration", return_value=[]), \
                 patch.object(hook_cost_invoke.run, "hardware", return_value={"effective_uid_is_root": False, "effective_capabilities": 0}), \
                 patch.object(hook_cost_invoke, "correctness_prerequisite", return_value={"qualified_correctness": True}), \
                 patch.object(hook_cost_invoke, "toolchain", return_value={}), \
                 patch.object(hook_cost_invoke, "scope_identity", return_value={}), \
                 patch.object(hook_cost_invoke.resource, "setrlimit"), \
                 patch.object(hook_cost_invoke, "allocator_identity", return_value={"entry_sha256": "c" * 64}), \
                 patch.object(hook_cost_invoke, "run_command", side_effect=command):
                self.assertEqual(hook_cost_invoke.invoke(args), 1)
            output = next((here / "results").glob("*.json"))
            record = json.loads(output.read_text())
            self.assertEqual(record["error"], "dirty_tracked_source")
            self.assertEqual(record["collection"]["evidence"]["completions"][0]["status"], "observed_unqualified")
            self.assertFalse(record["qualified"])
            self.assertNotIn("/private", output.read_text())

    def test_catalog_corruption_never_reloads_or_loses_captured_prefix(self):
        catalog, rows = wire_records()
        captured = wire(rows[:6]).encode()
        for when in ("before_command", "after_command"):
            with self.subTest(when=when), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                here = root / "evaluation/admission"
                here.mkdir(parents=True)
                (here / "corpus.json").write_text("{}")
                source = source_with_catalog(here)
                inventory_path = here / "hook_cost_inventory.json"
                if when == "before_command":
                    inventory_path.write_text("{invalid catalog")
                args = SimpleNamespace(expect_revision="a" * 40,
                    correctness_receipt="20261026T010203.000001Z-" + "a" * 12 + ".json",
                    correctness_sha256="b" * 64, allocator="/private/bin/cpuset-alloc", allocator_sha256="c" * 64)
                def command(argv, env, log, timeout, limit):
                    (log.parent / "measurement.log").write_bytes(captured)
                    inventory_path.write_text("{invalid catalog")
                    log.write_bytes(b"")
                    return {"exit_code": 0, "termination": None, "cleanup_complete": True,
                            "reaped_descendants": 0, "private_log_sha256": sha(b"")}
                with patch.object(hook_cost_invoke, "ROOT", root), patch.object(hook_cost_invoke, "HERE", here), \
                     patch.object(hook_cost_invoke, "source_identity",
                         side_effect=[source, InvalidEvidence("dirty_tracked_source")]), \
                     patch.object(hook_cost_invoke, "load_inventory", wraps=hook_cost_invoke.load_inventory) as load, \
                     patch.object(hook_cost_invoke, "allocator_environment", return_value=({"PATH": "/usr/bin"}, {})), \
                     patch.object(hook_cost_invoke.run, "cargo_configuration", return_value=[]), \
                     patch.object(hook_cost_invoke.run, "hardware", return_value={"effective_uid_is_root": False, "effective_capabilities": 0}), \
                     patch.object(hook_cost_invoke, "correctness_prerequisite", return_value={"qualified_correctness": True}), \
                     patch.object(hook_cost_invoke, "toolchain", return_value={}), \
                     patch.object(hook_cost_invoke, "scope_identity", return_value={}), \
                     patch.object(hook_cost_invoke.resource, "setrlimit"), \
                     patch.object(hook_cost_invoke, "allocator_identity", return_value={"entry_sha256": "c" * 64}), \
                     patch.object(hook_cost_invoke, "run_command", side_effect=command) as execute:
                    self.assertEqual(hook_cost_invoke.invoke(args), 1)
                    self.assertEqual(load.call_count, 1)
                    self.assertEqual(execute.call_count, int(when == "after_command"))
                output = next((here / "results").glob("*.json"))
                record = json.loads(output.read_text())
                self.assertEqual(record["status"], "failed")
                self.assertFalse(record["qualified"])
                self.assertFalse(record["source_unchanged"])
                self.assertFalse(record["whole_protocol_qualified"])
                self.assertNotIn("/private", output.read_text())
                if when == "before_command":
                    self.assertEqual(record["error"], "catalog_source_digest_differs")
                    self.assertIsNone(record["collection"])
                    self.assertNotIn("unobserved_inventory", record)
                    self.assertEqual(record["csv"], {})
                else:
                    self.assertEqual(record["error"], "dirty_tracked_source")
                    self.assertEqual(record["inner_capture_sha256"]["measurement"], sha(captured))
                    evidence = record["collection"]["evidence"]
                    self.assertEqual(evidence, hook_cost_invoke.parse_capture(captured.decode(), catalog))
                    self.assertEqual(sum(row["status"] == "observed_unqualified"
                                         for row in evidence["completions"]), 4)
                    self.assertFalse(any(row["qualified"] for row in evidence["completions"]))


if __name__ == "__main__":
    unittest.main()
