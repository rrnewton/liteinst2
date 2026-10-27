"""Pure, literal record controls; no compiler, process or native artifact runs."""

import copy
import json
import unittest

import run
import runtime_stack_consumer as driver
import runtime_stack_consumer_schema as schema
from parsing import InvalidEvidence

RELATIVE = "target/evaluation/admission/20261027T010203.123456Z-runtime-stack-consumer-" + "a" * 12
DIGEST, PLAN = "a" * 64, "b" * 64


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def public():
    return {"schema_version": 1, "experiment": "runtime-stack-consumer", "role": "public_consumer",
        "stack_history_scope": "not_publicly_observed", "status": "passed", "error": None,
        "provider_calls": 3, "returned_syscalls": [39, 186], "terminal_syscall": 231,
        "terminal_code": 7, "terminal_argument": 7, "full_state_checks": 2,
        "journal_attempts": 3, "journal_raw_waits": 24, "journal_state_copies": 15,
        "journal_fact_counts": [25, 25, 20], "journal_failures": 0,
        "identity_chain_exact": True, "cleanup_complete": True, "writer_cleaned": True,
        "archive_preserved": True, "artifact_unchanged": True, "limits": dict(schema.LIMITS),
        "invocation_seconds": 3, "cleanup_seconds": 3,
        "observed_metrics": [{"charged_source_bytes": n * 1024 * 1024,
            "retained_source_bytes": n * 512 * 1024, "retained_origins": n,
            "history_records": 2 * n, "generation_changes": 0} for n in (4, 12, 24)]}


def inspect():
    return {"schema_version": 1, "experiment": "runtime-stack-consumer", "role": "artifact_plan",
        "status": "passed", "error": None, "artifact_sha256": DIGEST, "artifact_bytes": 9000,
        "plan_sha256": PLAN, "path": {"instructions": 13, "ordinary": 8, "calls": 1,
            "returns": 1, "syscalls": [39, 186, 231]},
        "checks": {"elf": True, "closed_path": True, "dataflow": True, "artifact_unchanged": True}}


def cleanup():
    return {"receipt": True, "application_hup": True, "application_echild": True,
            "broker_hup": True, "broker_echild": True, "mask_restored": True, "retained_prefix": True}


def lane_checks():
    return {"identity": True, "artifact": True, "own_state": True, "whole_source": True,
            "whole_stack": True, "helper_dataflow": True, "stack_access": True,
            "syscall_architecture": True, "terminal": True}


def oracle():
    value = inspect()
    del value["checks"]
    value.update(role="oracle", limits=dict(schema.LIMITS), invocation_seconds=3,
                 cleanup_seconds=3, cleanup_scope="outer_supervisor")
    common = {"instructions": 13, "ordinary": 8, "calls": 1, "returns": 1,
              "syscall_entries": 3, "syscall_returns": 2, "terminal_syscall": 231,
              "terminal_argument": 7, "terminal_code": 7}
    value["raw"] = {"error": None, "observations": common | {"raw_waits": 18, "requests": 24,
        "frames": 25, "separate_phase_states": 6, "namespace_records": 5, "state_read_groups": 32},
        "checks": lane_checks(), "cleanup": cleanup()}
    value["admitted"] = {"error": None, "observations": common | {"frames": 25,
        "own_lane_state_read_groups": 26, "stack_commits": 2, "stack_raw_waits": 14,
        "stack_private_calls": 12, "stack_original_steps": 2, "stack_word_captures": 8,
        "stack_census_checks": 2, "call_rows": 1, "kernel_attempts": 3, "kernel_raw_waits": 24,
        "kernel_state_copies": 15, "kernel_fact_counts": [25, 25, 20], "kernel_failures": 0},
        "checks": lane_checks() | {"call_before_opening": True, "call_retained": True,
            "stack_census": True, "final_current": True, "history_after_cleanup": True}, "cleanup": cleanup()}
    value["comparison"] = {"artifact_plan": True, "own_lane_equations": True, "structural": True,
                           "helper_dataflow": True, "terminal": True}
    # Synthetic unequal reservation/installed capacities exercise equations,
    # not a fabricated source-derived native allocation amount.
    value["accounting"] = {"reservation_bytes": 8000, "allocated_bytes": 6000,
        "charged_before": 1000, "charged_after": 9000, "retained_before": 500,
        "retained_after": 6500, "settled": True, "finished": True, "formula_checked": True}
    return value


def completed(spec):
    return spec | {"status": "passed", "exit_code": spec["expected_exit_code"], "termination": None,
                  "cleanup_complete": True, "reaped_descendants": 0, "private_log_sha256": DIGEST}


def experiment():
    value = {"private_relative": RELATIVE, "prerequisite": {"qualified": True},
        "kernel_prerequisite": {"qualified": True}, "feature_prerequisite": {"qualified": True},
        **{key: True for key in driver.STABILITY}, "secondary_failures": [],
        "elf": {"sha256": DIGEST, "bytes": 9000, "static_native64": True, "load_segments": 2,
            "initialized_text_bytes": 61, "executable_bytes_sha256": PLAN, "head_completeness": False},
        "artifacts": {key: {"sha256": DIGEST, "bytes": 9000}
            for key in ("c_source", "object", "elf", "public", "oracle")},
        "c_tools": {key: {"sha256": DIGEST, "bytes": 9000, "version": "19.1.7",
            "version_output_sha256": PLAN} for key in ("clang", "ld.lld")},
        "artifact_plan": inspect(),
        "commands": [completed(spec) for spec in driver.command_specs(RELATIVE, DIGEST, PLAN)]}
    for command in value["commands"][:2]:
        command["tool_observation"] = {"version": "19.1.7", "version_output_sha256": PLAN}
    value["commands"][7]["protocol"] = dict(schema.PUBLIC_PROTOCOL)
    value["commands"][8]["protocol"] = dict(schema.ORACLE_PROTOCOL)
    for index, row, role in ((9, inspect(), "artifact_plan"), (11, public(), "public_consumer"),
                             (12, oracle(), "oracle")):
        value["commands"][index]["observation"] = schema.parse_row(encoded(row), True, role)
    return value


class RuntimeStackConsumerTests(unittest.TestCase):
    def test_public_summary_exact_kernel_contract(self):
        self.assertEqual(schema.validate_public(public(), True), public())
        for key, item in (("provider_calls", 2), ("journal_raw_waits", 23), ("journal_state_copies", 14),
                          ("journal_fact_counts", [25, 25, 19]), ("full_state_checks", 1), ("journal_failures", 1)):
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                schema.validate_public(public() | {key: item})
        for flag in schema.FLAGS:
            with self.subTest(flag=flag), self.assertRaises(InvalidEvidence):
                schema.validate_public(public() | {flag: False})

    def test_public_scope_and_terminal_argument(self):
        for update in ({"role": "oracle"}, {"stack_history_scope": "observed"},
                       {"terminal_argument": None}, {"terminal_argument": True}, {"terminal_argument": 263},
                       {"stack_commits": 2}):
            with self.assertRaises(InvalidEvidence):
                schema.validate_public(public() | update)
        failed = public() | {"status": "failed", "error": "terminal_argument_and_stack", "terminal_argument": 263}
        self.assertEqual(schema.validate_public(failed), failed)
        for name in ("initial_stack_alignment", "selected_stack_restoration"):
            self.assertEqual(schema.validate_public(failed | {"error": name})["error"], name)

    def test_oracle_protocol_roles(self):
        for role, value in (("public_consumer", schema.PUBLIC_PROTOCOL), ("oracle", schema.ORACLE_PROTOCOL)):
            self.assertEqual(schema.parse_protocol(encoded(value), role), value)
            for changed in (value | {"version": True}, value | {"extra": 1}, value | {"role": "artifact_plan"}):
                with self.assertRaises(InvalidEvidence):
                    schema.parse_protocol(encoded(changed), role)
        with self.assertRaises(InvalidEvidence):
            schema.parse_protocol(encoded(schema.PUBLIC_PROTOCOL), "oracle")
        with self.assertRaises(InvalidEvidence):
            schema.parse_protocol(encoded(schema.ORACLE_PROTOCOL), "public_consumer")

    def test_inspect_closed_path_and_identity(self):
        self.assertEqual(schema.validate_inspect(inspect(), True), inspect())
        for field, item in (("instructions", 12), ("instructions", 36), ("ordinary", 31),
                            ("calls", 0), ("returns", 2), ("syscalls", [39, 231, 186])):
            changed = inspect()
            changed["path"][field] = item
            with self.subTest(field=field), self.assertRaises(InvalidEvidence):
                schema.validate_inspect(changed)
        for update in ({"artifact_sha256": "A" * 64}, {"artifact_bytes": 0}, {"plan_sha256": None},
                       {"role": "public_consumer"}):
            with self.assertRaises(InvalidEvidence):
                schema.validate_inspect(inspect() | update)
        changed = inspect()
        changed["checks"]["dataflow"] = False
        with self.assertRaises(InvalidEvidence):
            schema.validate_inspect(changed)

    def test_oracle_raw_schedule(self):
        self.assertEqual(schema.validate_oracle(oracle(), True), oracle())
        for key in oracle()["raw"]["observations"]:
            changed = oracle()
            changed["raw"]["observations"][key] -= 1
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                schema.validate_oracle(changed)
        changed = oracle()
        changed["raw"]["observations"]["state_read_groups"] = 26
        with self.assertRaises(InvalidEvidence):
            schema.validate_oracle(changed)

    def test_oracle_admitted_separate_inventories(self):
        for key in oracle()["admitted"]["observations"]:
            changed = oracle()
            changed["admitted"]["observations"][key] = None
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                schema.validate_oracle(changed)
        for key, item in (("kernel_raw_waits", 38), ("own_lane_state_read_groups", 41),
                          ("stack_raw_waits", 13), ("call_rows", 0), ("kernel_fact_counts", [25, 25, 25])):
            changed = oracle()
            changed["admitted"]["observations"][key] = item
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                schema.validate_oracle(changed)

    def test_oracle_accounting_no_refund(self):
        for key, item in (("charged_after", 8999), ("retained_after", 6499), ("allocated_bytes", 8001),
                          ("charged_before", 10000), ("retained_before", 1001), ("reservation_bytes", 67108865),
                          ("settled", False), ("finished", None), ("formula_checked", False)):
            changed = oracle()
            changed["accounting"][key] = item
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                schema.validate_oracle(changed)
        refused = oracle() | {"status": "failed", "error": "allocation", "raw": None,
                              "admitted": None, "comparison": None}
        refused["accounting"] = {"reservation_bytes": 67108865, "allocated_bytes": 0,
            "charged_before": 1000, "charged_after": 1000, "retained_before": 500,
            "retained_after": 500, "settled": None, "finished": None, "formula_checked": True}
        self.assertEqual(schema.validate_oracle(refused), refused)
        measured = copy.deepcopy(refused)
        measured["accounting"] = {"reservation_bytes": 8000, "allocated_bytes": None,
            "charged_before": 1000, "charged_after": 9000, "retained_before": 500,
            "retained_after": 500, "settled": None, "finished": True, "formula_checked": False}
        self.assertEqual(schema.validate_oracle(measured), measured)
        self.assertFalse(schema.parse_row(encoded(measured), False, "oracle")["qualified_run"])
        with self.assertRaises(InvalidEvidence):
            schema.parse_row(encoded(measured), True, "oracle")
        for key, item in (("charged_after", 8999), ("retained_after", 499),
                          ("retained_before", 1001)):
            changed = copy.deepcopy(measured)
            changed["accounting"][key] = item
            with self.subTest(prefix=key), self.assertRaises(InvalidEvidence):
                schema.validate_oracle(changed)
        settled = copy.deepcopy(measured)
        settled["accounting"] |= {"allocated_bytes": 6000, "retained_after": 6500,
                                  "settled": True, "formula_checked": True}
        self.assertEqual(schema.validate_oracle(settled), settled)
        for key, item in (("retained_after", 6499), ("allocated_bytes", 8001)):
            changed = copy.deepcopy(settled)
            changed["accounting"][key] = item
            with self.subTest(settled=key), self.assertRaises(InvalidEvidence):
                schema.validate_oracle(changed)
        changed = oracle()
        changed["limits"]["source_fact_bytes"] += 1
        with self.assertRaises(InvalidEvidence):
            schema.validate_oracle(changed)

    def test_oracle_comparison_and_cleanup(self):
        for lane in ("raw", "admitted"):
            for group in ("checks", "cleanup"):
                for key in oracle()[lane][group]:
                    changed = oracle()
                    changed[lane][group][key] = False
                    with self.subTest(lane=lane, group=group, key=key), self.assertRaises(InvalidEvidence):
                        schema.validate_oracle(changed)
        for key in oracle()["comparison"]:
            changed = oracle()
            changed["comparison"][key] = None
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                schema.validate_oracle(changed)
        with self.assertRaises(InvalidEvidence):
            schema.validate_oracle(oracle() | {"cleanup_scope": "local_lane_timer"})

    def test_rows_duplicate_unknown_private_and_mistyped(self):
        for role, value in (("public_consumer", public()), ("artifact_plan", inspect()), ("oracle", oracle())):
            for key in value:
                changed = copy.deepcopy(value)
                del changed[key]
                with self.subTest(role=role, key=key), self.assertRaises(InvalidEvidence):
                    schema.parse_row(encoded(changed), True, role)
            for update in ({"private_path": "/PRIVATE_SENTINEL"}, {"schema_version": True}):
                with self.assertRaises(InvalidEvidence) as caught:
                    schema.parse_row(encoded(value | update), True, role)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
            row = encoded(value)
            for data in (row + row, b"private\n" + row, row + b"extra\n", row.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')):
                with self.assertRaises(InvalidEvidence):
                    schema.parse_row(data, True, role)
        with self.assertRaises(InvalidEvidence):
            schema.strict_json(b'{"x":NaN}')
        changed = oracle()
        changed["raw"]["observations"]["calls"] = True
        with self.assertRaises(InvalidEvidence):
            schema.validate_oracle(changed)

    def test_failed_prefix_never_qualifies(self):
        value = oracle() | {"status": "failed", "error": "raw_execution", "admitted": None,
                            "comparison": None}
        value["raw"]["error"] = "raw_execution"
        value["raw"]["observations"]["terminal_code"] = None
        value["raw"]["checks"]["terminal"] = None
        result = schema.parse_row(b"PRIVATE_SENTINEL\n" + encoded(value), False, "oracle")
        self.assertEqual(result["summary"], value)
        self.assertFalse(result["command_succeeded"] or result["qualified_run"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))
        with self.assertRaises(InvalidEvidence):
            schema.parse_row(encoded(value), True, "oracle")
        self.assertFalse(schema.parse_row(encoded(oracle()), False, "oracle")["qualified_run"])
        empty = inspect() | {"status": "failed", "error": "artifact", "artifact_sha256": None,
            "artifact_bytes": None, "plan_sha256": None, "path": None,
            "checks": {key: None for key in schema.INSPECT_CHECKS}}
        self.assertEqual(schema.validate_inspect(empty), empty)

    def test_thirteen_commands_and_late_digest_binding(self):
        specs = driver.command_specs(RELATIVE)
        self.assertEqual([row["id"] for row in specs], ["clang_version", "linker_version", "compile_c", "link_c",
            "build_public", "clippy_oracle", "build_oracle", "public_protocol", "oracle_protocol",
            "inspect_artifact", "reference", "public_consumer", "oracle"])
        self.assertEqual([row["timeout_seconds"] for row in specs], [10, 10, 180, 180, 180, 180, 180, 10, 10, 10, 3, 60, 60])
        self.assertEqual([row["expected_exit_code"] for row in specs], [0] * 10 + [7, 0, 0])
        self.assertIsNone(specs[9]["argv"][-1])
        self.assertEqual(specs[12]["argv"][-3:], [None, "--expect-plan-sha256", None])
        bound = driver.command_specs(RELATIVE, DIGEST, PLAN)
        self.assertEqual(bound[9]["argv"][-1], DIGEST)
        self.assertEqual(bound[12]["argv"][-3:], [DIGEST, "--expect-plan-sha256", PLAN])
        self.assertNotIn("--features", bound[4]["argv"])
        self.assertIn("dev-owned-stack-consumer-oracle", bound[5]["argv"])
        for flag in ("-mstack-alignment=8", "-fomit-frame-pointer", "-fno-optimize-sibling-calls"):
            self.assertEqual(bound[2]["argv"].count(flag), 1)
        self.assertNotIn("RUST_TEST_THREADS", driver.consumer_environment_record())
        for path in ("/tmp/run", RELATIVE + "/../x", RELATIVE.replace("runtime-stack-consumer", "runtime-consumer")):
            with self.assertRaises(InvalidEvidence):
                driver.command_specs(path)

    def test_reference_and_outer_cleanup(self):
        spec = driver.command_specs(RELATIVE)[10]
        actual = completed(spec)
        driver.observe(actual, b"")
        self.assertEqual(actual["status"], "passed")
        for update in ({"exit_code": 0}, {"exit_code": -9}, {"termination": "timeout"},
                       {"cleanup_complete": False}, {"reaped_descendants": 1}, {"exit_code": True}):
            changed = completed(spec) | update
            driver.observe(changed, b"")
            self.assertEqual(changed["status"], "failed")
        changed = completed(spec)
        driver.observe(changed, b"unexpected")
        self.assertEqual(changed["status"], "invalid_evidence")
        value = experiment()
        driver.fail(value, "oracle", InvalidEvidence("first_native_failure"))
        driver.fail(value, "pin_close_elf", OSError())
        self.assertEqual(value["error_code"], "first_native_failure")
        self.assertEqual(value["error_phase"], "oracle")
        self.assertEqual(value["secondary_failures"], [{"phase": "pin_close_elf", "type": "OSError"}])

    def test_both_prerequisites_require_exact_source_and_environment(self):
        # Reuse the unchanged old driver's *literal pure fixture*, then exercise
        # this new prerequisite's independent outer source/environment gates.
        from test_runtime_kernel_consumer import experiment as old_experiment
        source = {"revision": "a" * 40, "source_sha256": {
            "evaluation/admission/runtime_kernel_consumer.py": DIGEST,
            "evaluation/admission/runtime_consumer_schema.py": PLAN}}
        old = old_experiment()
        old.update(schema_version=1, experiment="runtime-kernel-c-consumer", status="passed", source=source,
            runner_sha256=DIGEST, schema_sha256=PLAN, environment=driver.consumer_environment_record(),
            inherited_location_variables=list(run.LOCATION_VARIABLES), configuration=[], hardware={}, toolchain={},
            run_id=old["private_relative"].split("/")[-1], log_limit_bytes_per_command=driver.LOG_LIMIT,
            cleanup_seconds=3, artifact_limit_bytes=schema.MAX_ARTIFACT, tool_and_example_limit_bytes=driver.MAX_TOOL)
        driver.kernel.qualify(old)
        self.assertTrue(driver.kernel_prerequisite(old, source, [], {}, {}, old["prerequisite"]))
        for key, item in (("status", "failed"), ("source", {}), ("runner_sha256", PLAN),
                          ("schema_sha256", DIGEST), ("prerequisite", {"qualified": False}),
                          ("environment", driver.consumer_environment_record() | {"RUST_TEST_THREADS": "4"}),
                          ("cleanup_seconds", 4), ("hardware", {"changed": True})):
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                driver.kernel_prerequisite(old | {key: item}, source, [], {}, {}, old["prerequisite"])
        for key in ("prerequisite", "kernel_prerequisite", "feature_prerequisite"):
            value = experiment()
            value[key]["qualified"] = False
            driver.qualify(value)
            self.assertEqual(value["status"], "failed")

    def test_experiment_requires_every_role_and_pin(self):
        value = experiment()
        driver.qualify(value)
        self.assertEqual(value["status"], "passed")
        for index in range(13):
            for update in ({"status": "not_run"}, {"exit_code": -9}, {"cleanup_complete": False},
                           {"reaped_descendants": 1}, {"private_log_sha256": None}):
                changed = experiment()
                changed["commands"][index].update(update)
                driver.qualify(changed)
                self.assertEqual(changed["status"], "failed")
                self.assertFalse(changed["commands"][12]["observation"]["qualified_run"])
        for key in driver.STABILITY:
            changed = experiment()
            changed[key] = False
            driver.qualify(changed)
            self.assertEqual(changed["status"], "failed")
        for index, key, item in ((9, "artifact_sha256", PLAN), (12, "plan_sha256", DIGEST),
                                 (12, "artifact_bytes", 8999)):
            changed = experiment()
            changed["commands"][index]["observation"]["summary"][key] = item
            driver.qualify(changed)
            self.assertEqual(changed["status"], "failed")
        changed = experiment()
        changed["artifact_plan"]["plan_sha256"] = DIGEST
        driver.qualify(changed)
        self.assertEqual(changed["status"], "failed")
        changed = experiment()
        changed["artifacts"]["public"]["sha256"] = "not-a-hash"
        driver.qualify(changed)
        self.assertEqual(changed["status"], "failed")


if __name__ == "__main__":
    unittest.main()
