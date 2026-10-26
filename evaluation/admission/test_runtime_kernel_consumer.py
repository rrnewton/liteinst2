"""Pure synthetic consumer controls; no compiler, process or artifact executes."""

import copy
import json
from pathlib import Path
import struct
import unittest

import run
import runtime_kernel_consumer as consumer
import runtime_consumer_schema as schema
from parsing import InvalidEvidence


RELATIVE = "target/evaluation/admission/20261026T010203.123456Z-runtime-consumer-" + "a" * 12


def summary():
    return {"schema_version": 1, "experiment": "runtime-kernel-consumer", "status": "passed",
        "error": None, "provider_calls": 3, "returned_syscalls": [39, 186], "terminal_syscall": 231,
        "terminal_code": 7, "full_state_checks": 2, "journal_attempts": 3, "journal_raw_waits": 24,
        "journal_state_copies": 15, "journal_fact_counts": [25, 25, 20], "journal_failures": 0,
        **{key: True for key in schema.FLAGS}, "limits": dict(schema.LIMITS),
        "invocation_seconds": 3, "cleanup_seconds": 3,
        "observed_metrics": [{"charged_source_bytes": n * 1024 * 1024,
            "retained_source_bytes": n * 512 * 1024, "retained_origins": n,
            "history_records": n * 2, "generation_changes": 0} for n in (4, 12, 24)]}


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def completed(spec):
    return spec | {"status": "passed", "exit_code": spec["expected_exit_code"], "termination": None,
        "cleanup_complete": True, "reaped_descendants": 0, "private_log_sha256": "a" * 64}


def experiment():
    record = {"private_relative": RELATIVE, "prerequisite": {"qualified": True},
        **{key: True for key in ("source_unchanged", "configuration_unchanged", "toolchain_unchanged",
            "hardware_unchanged", "files_unchanged")}, "elf": {"static_native64": True, "sha256": "a" * 64, "bytes": 768},
        "artifacts": {key: {"sha256": "a" * 64, "bytes": 768} for key in ("c_source", "object", "elf", "example")},
        "c_tools": {key: {"sha256": "a" * 64, "bytes": 768, "version": "19.1.7",
                          "version_output_sha256": "b" * 64} for key in ("clang", "ld.lld")},
        "commands": [completed(spec) for spec in consumer.command_specs(RELATIVE)]}
    for command in record["commands"][:2]:
        command["tool_observation"] = {"version": "19.1.7", "version_output_sha256": "b" * 64}
    record["commands"][5]["protocol"] = dict(schema.PROTOCOL)
    record["commands"][-1]["consumer_observation"] = schema.parse_summary(encoded(summary()), True)
    return record


def prerequisite():
    source = {"revision": "a" * 40, "tracked_clean": True, "head_sources_match": True,
              "source_sha256": {"evaluation/admission/run.py": "b" * 64}}
    corpus = {"schema_version": 1}
    environment = run.ENV | {"CARGO_TARGET_DIR": "target", "TMPDIR": "private_run/tmp",
                            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "RLIMIT_CORE": 0}
    record = {"schema_version": 1, "experiment": "admission-validation", "status": "passed",
        "source_unchanged": True, "configuration_unchanged": True, "source": source,
        "corpus_sha256": "c" * 64, "runner_sha256": "b" * 64, "environment": environment,
        "inherited_location_variables": list(run.LOCATION_VARIABLES), "configuration": [],
        "hardware": {"affinity_cpu_count": 4}, "toolchain": {"synthetic": "unchanged"},
        "log_limit_bytes_per_command": consumer.LOG_LIMIT, "backing_cleanup_required": True,
        "commands": [{"id": name, "argv": argv, "timeout_seconds": timeout,
            "environment_delta": {"LITEINST_EVALUATION": "1"} if name == "serial_launch" else {},
            "status": "passed", "exit_code": 0, "termination": None, "cleanup_complete": True,
            "reaped_descendants": 0, "private_log_sha256": "d" * 64}
            for name, argv, timeout in run.COMMANDS]}
    return record, source, corpus


def valid_elf():
    # Synthetic byte parser fixture only. One RX segment, GNU_STACK, a defined
    # _start symbol and its string table; none of these bytes is executed.
    data = bytearray(768)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x400100, 64, 512, 0, 64, 56, 2, 64, 3, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, 384, 384, 4096)
    struct.pack_into("<IIQQQQQQ", data, 120, 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    data[256:259] = b"\x90\x0f\x05"
    data[384:392] = b"\0_start\0"
    struct.pack_into("<IBBHQQ", data, 432, 1, 0x12, 0, 1, 0x400100, 3)
    struct.pack_into("<IIQQQQIIQQ", data, 576, 0, 2, 0, 0, 408, 48, 2, 0, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", data, 640, 0, 3, 0, 0, 384, 8, 0, 0, 1, 0)
    return bytes(data)


class RuntimeKernelConsumerTests(unittest.TestCase):
    def test_consumer_complete_summary_requires_all_exact_fields_and_counts(self):
        value = summary()
        self.assertEqual(schema.parse_summary(encoded(value), True), {
            "summary": value, "command_succeeded": True, "qualified_run": False})
        for field in schema.FLAGS:
            changed = copy.deepcopy(value)
            changed[field] = False
            with self.subTest(field=field), self.assertRaises(InvalidEvidence):
                schema.validate_summary(changed)
        for field, changed_value in (("journal_raw_waits", 23), ("journal_state_copies", 14),
            ("provider_calls", 2), ("terminal_syscall", 60), ("terminal_code", 0),
            ("journal_fact_counts", [25, 25, 25]), ("journal_failures", 1)):
            changed = copy.deepcopy(value)
            changed[field] = changed_value
            with self.subTest(field=field), self.assertRaises(InvalidEvidence):
                schema.validate_summary(changed)

    def test_consumer_schema_refuses_duplicate_unknown_mistyped_and_private_fields(self):
        value = summary()
        for field in value:
            changed = copy.deepcopy(value)
            del changed[field]
            with self.subTest(field=field), self.assertRaises(InvalidEvidence):
                schema.validate_summary(changed)
        for changed in (value | {"host_path": "/PRIVATE_SENTINEL"}, value | {"schema_version": True},
            value | {"provider_calls": True}, value | {"identity_chain_exact": 1},
            value | {"terminal_code": True}, value | {"returned_syscalls": [186, 39]},
            value | {"limits": dict(schema.LIMITS, epochs=True)}):
            with self.assertRaises(InvalidEvidence) as caught:
                schema.validate_summary(changed)
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        with self.assertRaisesRegex(InvalidEvidence, "duplicate_json"):
            schema.strict_json(b'{"value":1,"value":2}')
        with self.assertRaisesRegex(InvalidEvidence, "nonfinite_json"):
            schema.strict_json(b'{"value":NaN}')

    def test_consumer_summary_missing_duplicate_trailing_and_protocol_fail_closed(self):
        row = encoded(summary())
        for data in (b"", row + row, b"PRIVATE_SENTINEL\n" + row, row + b"trailing\n",
                     b"x" * (schema.MAX_SUMMARY + 1)):
            with self.subTest(data=data[:30]), self.assertRaises(InvalidEvidence):
                schema.parse_summary(data, True)
        self.assertEqual(schema.parse_protocol(encoded(schema.PROTOCOL)), schema.PROTOCOL)
        for data in (b"{}", encoded(schema.PROTOCOL | {"version": True}),
                     encoded(schema.PROTOCOL) + encoded(schema.PROTOCOL)):
            with self.assertRaises(InvalidEvidence):
                schema.parse_protocol(data)

    def test_consumer_failed_command_retains_only_typed_prefix_without_qualification(self):
        value = summary()
        value.update(status="failed", error="runtime_terminal", terminal_syscall=None, terminal_code=None,
                     identity_chain_exact=False, journal_failures=1)
        observed = schema.parse_summary(b"PRIVATE_SENTINEL /private/task\n" + encoded(value), False)
        self.assertEqual(observed["summary"], value)
        self.assertFalse(observed["command_succeeded"] or observed["qualified_run"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(observed))
        # A large private failure diagnostic still permits one bounded typed
        # row; neither the diagnostic nor its command becomes qualified.
        large = schema.parse_summary(b"x" * (schema.MAX_SUMMARY + 1) + b"\n" + encoded(value), False)
        self.assertEqual(large, observed)
        with self.assertRaises(InvalidEvidence):
            schema.parse_summary(b"x" * schema.MAX_CAPTURE + b"\n" + encoded(value), False)
        with self.assertRaises(InvalidEvidence):
            schema.parse_summary(encoded(value), 1)
        with self.assertRaises(InvalidEvidence):
            schema.parse_summary(encoded(value), True)
        # Even a complete row from a failed process is merely an observation.
        self.assertFalse(schema.parse_summary(encoded(summary()), False)["qualified_run"])

    def test_consumer_expected_reference_exit_and_cleanup_are_role_specific(self):
        specs = consumer.command_specs(RELATIVE)
        reference = completed(specs[-2])
        consumer.observe(reference, b"")
        self.assertEqual(reference["exit_code"], 7)
        self.assertEqual(reference["status"], "passed")
        for change in ({"exit_code": 0}, {"exit_code": -9}, {"termination": "timeout"},
                       {"cleanup_complete": False}, {"reaped_descendants": 1}, {"exit_code": True}):
            changed = completed(specs[-2]) | change
            consumer.observe(changed, b"")
            self.assertEqual(changed["status"], "failed")
        changed = completed(specs[-1]) | {"exit_code": 7}
        consumer.observe(changed, encoded(summary()))
        self.assertEqual(changed["status"], "failed")
        self.assertFalse(changed["consumer_observation"]["qualified_run"])

    def test_consumer_commands_are_fixed_and_default_test_environment_is_not_reused(self):
        specs = consumer.command_specs(RELATIVE)
        self.assertEqual([c["id"] for c in specs], ["clang_version", "linker_version", "compile_c",
            "link_c", "build_example", "example_protocol", "reference", "consumer"])
        self.assertEqual([c["timeout_seconds"] for c in specs], [10, 10, 180, 180, 180, 10, 3, 60])
        self.assertEqual([c["expected_exit_code"] for c in specs], [0, 0, 0, 0, 0, 0, 7, 0])
        self.assertIn("-fintegrated-as", specs[2]["argv"])
        self.assertEqual(specs[3]["argv"][0], "ld.lld")
        self.assertNotIn("--test-threads", " ".join(specs[-1]["argv"]))
        base = run.controlled_environment({"PATH": "/usr/bin", "HOME": "/CONFIG_HOME",
            "CC": "PRIVATE_SENTINEL", "CFLAGS": "PRIVATE_SENTINEL", "LD_PRELOAD": "PRIVATE_SENTINEL"}, Path("/private/tmp"))
        env = consumer.consumer_environment(base)
        self.assertEqual(base["RUST_TEST_THREADS"], run.ENV["RUST_TEST_THREADS"])
        self.assertNotIn("RUST_TEST_THREADS", env)
        self.assertFalse(any(key in env for key in ("CC", "CFLAGS", "LD_PRELOAD")))
        self.assertEqual(env["CARGO_BUILD_JOBS"], "4")
        for path in ("/tmp/consumer", RELATIVE + "/../other", "target/evaluation/admission/unbound"):
            with self.assertRaises(InvalidEvidence):
                consumer.command_specs(path)

    def test_consumer_elf_description_is_complete_static_and_not_head_authority(self):
        data = valid_elf()
        value = schema.elf_metadata(data)
        self.assertEqual(value["sha256"], run.sha(data))
        self.assertEqual(value["bytes"], len(data))
        self.assertEqual(value["entry"], 0x400100)
        self.assertEqual(len(value["program_headers"]), 2)
        self.assertEqual(value["executable_segments"], 1)
        self.assertTrue(value["static_native64"])
        self.assertFalse(value["head_completeness"])
        self.assertEqual(value["executable_bytes_sha256"], run.sha(data[:384]))

    def test_consumer_elf_rejects_malformed_dynamic_writable_and_out_of_range_inputs(self):
        source = valid_elf()
        edits = [(4, b"\x01"), (18, struct.pack("<H", 3)), (64, struct.pack("<I", 3)),
            (68, struct.pack("<I", 7)), (124, struct.pack("<I", 7)),
            (24, struct.pack("<Q", 0x500000)), (72, struct.pack("<Q", len(source))),
            (80, struct.pack("<Q", 2**64 - 1)), (96, struct.pack("<Q", 4096)),
            (56, struct.pack("<H", 65)), (62, struct.pack("<H", 3))]
        for at, replacement in edits:
            changed = bytearray(source)
            changed[at:at+len(replacement)] = replacement
            with self.subTest(at=at), self.assertRaises(InvalidEvidence):
                schema.elf_metadata(bytes(changed))
        for data in (source[:63], source[:700], bytes(schema.MAX_ARTIFACT + 1)):
            with self.assertRaises(InvalidEvidence):
                schema.elf_metadata(data)

    def test_consumer_elf_rejects_undefined_relocated_or_missing_start_symbol(self):
        source = valid_elf()
        for at, replacement in ((580, struct.pack("<I", 4)), (438, b"\0\0"),
            (440, struct.pack("<Q", 0x400101)), (436, b"\x11"), (432, struct.pack("<I", 99)),
            (616, struct.pack("<I", 3)), (632, struct.pack("<Q", 1))):
            changed = bytearray(source)
            changed[at:at+len(replacement)] = replacement
            with self.subTest(at=at), self.assertRaises(InvalidEvidence):
                schema.elf_metadata(bytes(changed))

    def test_consumer_prerequisite_requires_exact_source_original_environment_and_six_commands(self):
        original, source, corpus = prerequisite()
        def check(value):
            return consumer.prerequisite(value, source, corpus, "c" * 64, [],
                {"affinity_cpu_count": 4}, {"synthetic": "unchanged"})
        self.assertTrue(check(original))
        variants = []
        for key, value in (("status", "failed"), ("source_unchanged", False),
                           ("corpus_sha256", "e" * 64), ("runner_sha256", "e" * 64)):
            changed = copy.deepcopy(original)
            changed[key] = value
            variants.append(changed)
        changed = copy.deepcopy(original)
        del changed["environment"]["RUST_TEST_THREADS"]
        variants.append(changed)
        changed = copy.deepcopy(original)
        changed["source"]["revision"] = "f" * 40
        variants.append(changed)
        changed = copy.deepcopy(original)
        changed["commands"].pop()
        variants.append(changed)
        for index in range(6):
            for update in ({"status": "failed"}, {"exit_code": 7}, {"cleanup_complete": False},
                           {"reaped_descendants": 1}, {"argv": ["cargo", "check"]}):
                changed = copy.deepcopy(original)
                changed["commands"][index].update(update)
                variants.append(changed)
        for value in variants:
            with self.assertRaises(InvalidEvidence):
                check(value)

    def test_consumer_whole_experiment_never_qualifies_partial_failed_or_changed_run(self):
        record = experiment()
        consumer.qualify(record)
        self.assertEqual(record["status"], "passed")
        self.assertTrue(record["commands"][-1]["consumer_observation"]["qualified_run"])
        for key in ("source_unchanged", "configuration_unchanged", "toolchain_unchanged",
                    "hardware_unchanged", "files_unchanged"):
            changed = experiment()
            changed[key] = False
            consumer.qualify(changed)
            self.assertEqual(changed["status"], "failed")
            self.assertFalse(changed["commands"][-1]["consumer_observation"]["qualified_run"])
        for index in range(8):
            for update in ({"status": "not_run"}, {"exit_code": -9}, {"cleanup_complete": False},
                           {"reaped_descendants": 1}, {"expected_exit_code": 0 if index == 6 else 7}):
                changed = experiment()
                changed["commands"][index].update(update)
                consumer.qualify(changed)
                self.assertEqual(changed["status"], "failed")
        for kind in ("artifact", "tool", "elf", "summary"):
            changed = experiment()
            if kind == "artifact":
                changed["artifacts"]["elf"]["sha256"] = "c" * 64
            elif kind == "tool":
                changed["c_tools"]["clang"]["version_output_sha256"] = "c" * 64
            elif kind == "elf":
                changed["elf"]["bytes"] += 1
            else:
                changed["commands"][-1]["consumer_observation"]["summary"]["full_state_checks"] = 1
            consumer.qualify(changed)
            self.assertEqual(changed["status"], "failed")

    def test_consumer_version_metadata_retains_hash_without_host_path_or_freeform_output(self):
        for role, data, version in (("clang", b"clang version 19.1.7\nInstalledDir: /PRIVATE_SENTINEL\n", "19.1.7"),
                                   ("ld.lld", b"LLD 19.1.7 (compatible with GNU linkers)\n", "19.1.7")):
            result = schema.version_metadata(role, data)
            self.assertEqual(result, {"version": version, "version_output_sha256": run.sha(data)})
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))
        for role, data in (("cc", b"clang version 19.1.7"), ("clang", b""),
                           ("ld.lld", b"GNU ld 2.40"), ("clang", b"\xff"),
                           ("clang", b"x" * 65537)):
            with self.assertRaises(InvalidEvidence):
                schema.version_metadata(role, data)


if __name__ == "__main__":
    unittest.main()
