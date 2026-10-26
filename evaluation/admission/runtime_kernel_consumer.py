#!/usr/bin/env python3
"""Build and observe one finite C consumer after exact-source qualification."""

import argparse
import copy
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import sys

import run
from default_parallel import toolchain
from parsing import InvalidEvidence
from processes import run_command
from runtime_consumer_schema import (MAX_ARTIFACT, PROTOCOL, elf_metadata, parse_protocol,
                                     parse_summary, strict_json, validate_summary, version_metadata)

ROOT, HERE = run.ROOT, run.HERE
LOG_LIMIT = 8 * 1024 * 1024
MAX_TOOL = 256 * 1024 * 1024
SOURCE = "evaluation/admission/consumers/runtime_identity.c"
EXAMPLE = "target/debug/examples/runtime_kernel_consumer"
HEX = re.compile(r"[0-9a-f]{64}")


def command_specs(relative):
    run.require(type(relative) is str and re.fullmatch(
        r"target/evaluation/admission/[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-runtime-consumer-[0-9a-f]{12}", relative),
        "consumer_run_path")
    object_file, executable = relative + "/runtime_identity.o", relative + "/runtime_identity.elf"
    commands = [
        ("clang_version", ["clang", "--version"], 10, 0),
        ("linker_version", ["ld.lld", "--version"], 10, 0),
        ("compile_c", ["clang", "--no-default-config", "--target=x86_64-unknown-linux-gnu",
            "-O2", "-ffreestanding", "-fno-builtin", "-nostdinc", "-fno-stack-protector",
            "-fno-pic", "-fno-pie", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
            "-fno-vectorize", "-fno-slp-vectorize", "-fcf-protection=none", "-mno-red-zone",
            "-fintegrated-as", "-c", SOURCE, "-o", object_file], 180, 0),
        ("link_c", ["ld.lld", "-static", "--build-id=none", "--entry=_start", "-z", "noexecstack",
            "-z", "max-page-size=4096", "-o", executable, object_file], 180, 0),
        ("build_example", ["cargo", "build", "--locked", "--offline", "-p", "liteinst-launch",
            "--example", "runtime_kernel_consumer"], 180, 0),
        ("example_protocol", [EXAMPLE, "--protocol-version"], 10, 0),
        ("reference", [executable], 3, 7),
        ("consumer", [EXAMPLE, "--artifact", executable], 60, 0),
    ]
    return [{"id": name, "argv": argv, "timeout_seconds": deadline,
             "expected_exit_code": expected, "environment_delta": {"RUST_TEST_THREADS": None},
             "status": "not_run"} for name, argv, deadline, expected in commands]


def command_passed(command):
    return (type(command.get("exit_code")) is int
            and command["exit_code"] == command["expected_exit_code"]
            and command.get("termination") is None and command.get("cleanup_complete") is True
            and type(command.get("reaped_descendants")) is int and command["reaped_descendants"] == 0)


def observe(command, data):
    passed = command_passed(command)
    command["status"] = "passed" if passed else "failed"
    try:
        if command["id"] in ("clang_version", "linker_version"):
            command["tool_observation"] = version_metadata(
                "clang" if command["id"] == "clang_version" else "ld.lld", data)
        elif command["id"] == "example_protocol":
            command["protocol"] = parse_protocol(data)
        elif command["id"] == "reference":
            run.require(data == b"", "consumer_reference_output")
        elif command["id"] == "consumer":
            command["consumer_observation"] = parse_summary(data, passed)
    except InvalidEvidence as error:
        command["evidence_error"] = str(error)
        if passed:
            command["status"] = "invalid_evidence"


def bounded_read(path, limit):
    path = Path(path)
    run.require(not path.is_symlink(), "consumer_input_symlink")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    run.require(len(data) <= limit, "consumer_input_size")
    return data


def artifact_prefix(path, command_succeeded):
    """Retain a bounded failed compiler output without calling it an artifact."""
    if not path.exists() and not path.is_symlink():
        return {"status": "absent", "qualified": False}
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        run.require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
                    "consumer_artifact_type")
        data = os.pread(fd, MAX_ARTIFACT, 0)
        return {"status": "command_completed" if command_succeeded else "partial_unqualified",
                "file_bytes": value.st_size, "observed_prefix_bytes": len(data),
                "prefix_sha256": run.sha(data), "complete_read": len(data) == value.st_size,
                "qualified": False}
    finally:
        os.close(fd)


def prerequisite(record, source, corpus, corpus_digest, configuration, hardware, tools):
    """Validate the original six-command environment before consumer derivation."""
    run.require(type(record) is dict and type(record.get("schema_version")) is int
        and record["schema_version"] == 1 and record.get("experiment") == "admission-validation"
        and record.get("status") == "passed" and record.get("source_unchanged") is True
        and record.get("configuration_unchanged") is True, "consumer_prerequisite_unqualified")
    run.require(record.get("source") == source and source.get("tracked_clean") is True
                and source.get("head_sources_match") is True, "consumer_prerequisite_source")
    run.require(record.get("corpus_sha256") == corpus_digest
        and record.get("runner_sha256") == source["source_sha256"]["evaluation/admission/run.py"],
        "consumer_prerequisite_recorder")
    expected_env = run.ENV | {"CARGO_TARGET_DIR": "target", "TMPDIR": "private_run/tmp",
                             "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "RLIMIT_CORE": 0}
    run.require(record.get("environment") == expected_env
        and record.get("inherited_location_variables") == list(run.LOCATION_VARIABLES)
        and record.get("configuration") == configuration
        and record.get("hardware") == hardware and record.get("toolchain") == tools,
        "consumer_prerequisite_environment")
    run.require(type(record.get("log_limit_bytes_per_command")) is int
        and record["log_limit_bytes_per_command"] == LOG_LIMIT
        and record.get("backing_cleanup_required") is True, "consumer_prerequisite_bounds")
    commands = record.get("commands")
    run.require(type(commands) is list and len(commands) == len(run.COMMANDS),
        "consumer_prerequisite_commands")
    for command, (name, argv, timeout) in zip(commands, run.COMMANDS):
        run.require(type(command) is dict and command.get("id") == name and command.get("argv") == argv
            and command.get("timeout_seconds") == timeout
            and command.get("environment_delta") == ({"LITEINST_EVALUATION": "1"} if name == "serial_launch" else {})
            and command.get("status") == "passed" and type(command.get("exit_code")) is int
            and command["exit_code"] == 0 and command.get("termination") is None
            and command.get("cleanup_complete") is True and type(command.get("reaped_descendants")) is int
            and command["reaped_descendants"] == 0 and type(command.get("private_log_sha256")) is str
            and HEX.fullmatch(command["private_log_sha256"]), "consumer_prerequisite_command")
    # The actual exact inventories and all closed native cohorts are replayed
    # from authenticated capture bytes by replay_prerequisite below.
    run.require(type(corpus) is dict and type(corpus.get("schema_version")) is int
                and corpus["schema_version"] == 1,
                "consumer_prerequisite_corpus")
    return True


def replay_prerequisite(record, corpus):
    identity = record.get("run_id")
    run.require(type(identity) is str and re.fullmatch(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{12}", identity)
                and identity.endswith(record["source"]["revision"][:12]), "consumer_prerequisite_identity")
    private = ROOT / "target/evaluation/admission" / identity
    fresh = []
    hashes = {}
    for original in record["commands"]:
        data = bounded_read(private / (original["id"] + ".log"), LOG_LIMIT)
        run.require(run.sha(data) == original["private_log_sha256"], "consumer_prerequisite_log")
        command = {key: copy.deepcopy(original[key]) for key in ("id", "status", "exit_code")}
        run.command_evidence(command, data.decode("utf-8", errors="replace"), corpus)
        fresh.append(command)
        hashes[original["id"]] = run.sha(data)
    replay = {"commands": fresh, "source_unchanged": True, "configuration_unchanged": True,
              "backing_cleanup_required": True}
    run.qualify(replay)
    run.require(replay["status"] == "passed", "consumer_prerequisite_replay")
    for old, new in zip(record["commands"], fresh):
        run.require(all(old.get(key) == value for key, value in new.items()),
                    "consumer_prerequisite_replayed_fields")
    return hashes


class PinnedFile:
    """Read-only descriptor plus exact content/metadata; never native authority."""

    def __init__(self, path, limit, *, artifact=False, executable=False):
        self.path = Path(path)
        self.limit = limit
        self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            observed = os.fstat(self.fd)
            run.require(stat.S_ISREG(observed.st_mode) and 0 < observed.st_size <= limit
                        and (not artifact or observed.st_nlink == 1)
                        and (not executable or observed.st_mode & 0o111), "consumer_file_metadata")
            self.identity = self._identity(observed)
            self.digest = self._digest()
            self.check()
            if executable:
                run.require(os.pread(self.fd, 4, 0) == b"\x7fELF", "consumer_executable_kind")
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    @staticmethod
    def _identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    def _digest(self):
        digest = hashlib.sha256()
        offset = 0
        while offset <= self.limit:
            data = os.pread(self.fd, min(65536, self.limit + 1 - offset), offset)
            if not data:
                break
            digest.update(data)
            offset += len(data)
        run.require(offset == self.identity[4] and offset <= self.limit, "consumer_file_size_changed")
        return digest.hexdigest()

    def check(self):
        observed = os.stat(self.path, follow_symlinks=False)
        run.require(self.identity == self._identity(observed)
                    and self.identity == self._identity(os.fstat(self.fd))
                    and self.digest == self._digest(), "consumer_file_changed")

    def data(self):
        self.check()
        value = os.pread(self.fd, self.identity[4] + 1, 0)
        run.require(len(value) == self.identity[4] and run.sha(value) == self.digest,
                    "consumer_file_changed")
        return value

    def public(self):
        return {"sha256": self.digest, "bytes": self.identity[4]}

    def make_readonly(self):
        # Mutate only the already authenticated, held regular inode. A pathname
        # cannot redirect this operation to an unvalidated linker output.
        self.check()
        previous = self.identity
        run.require(previous[3] == 1, "consumer_artifact_type")
        os.fchmod(self.fd, 0o555)
        observed = self._identity(os.fstat(self.fd))
        run.require(observed[0:2] == previous[0:2]
                    and stat.S_IFMT(observed[2]) == stat.S_IFREG
                    and stat.S_IMODE(observed[2]) == 0o555
                    and observed[3:6] == previous[3:6], "consumer_artifact_mode")
        self.identity = observed
        self.check()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class PinnedTool(PinnedFile):
    """Preserve the fixed tool's argv0 flavor and authenticate its real file."""

    def __init__(self, launcher, role):
        self.launcher = Path(launcher).absolute()
        run.require(role in ("clang", "ld.lld") and self.launcher.name == role,
                    "consumer_tool_launcher")
        self.launcher_identity = self._identity(os.lstat(self.launcher))
        super().__init__(self.launcher.resolve(strict=True), MAX_TOOL, executable=True)

    def check(self):
        run.require(self.launcher_identity == self._identity(os.lstat(self.launcher))
                    and self.launcher.resolve(strict=True) == self.path,
                    "consumer_tool_resolution_changed")
        super().check()


def consumer_environment(base):
    run.require(base.get("RUST_TEST_THREADS") == run.ENV["RUST_TEST_THREADS"],
                "consumer_original_environment")
    env = dict(base)
    del env["RUST_TEST_THREADS"]
    return env


def qualify(record):
    specs = command_specs(record["private_relative"])
    commands = record["commands"]
    complete = (record.get("prerequisite", {}).get("qualified") is True
        and all(record.get(key) is True for key in ("source_unchanged", "configuration_unchanged",
            "toolchain_unchanged", "hardware_unchanged", "files_unchanged"))
        and "error_code" not in record and "error_type" not in record
        and len(commands) == len(specs) and record.get("elf", {}).get("static_native64") is True
        and set(record.get("artifacts", {})) == {"c_source", "object", "elf", "example"}
        and set(record.get("c_tools", {})) == {"clang", "ld.lld"})
    for command, spec in zip(commands, specs):
        complete &= all(command.get(key) == value for key, value in spec.items() if key != "status")
        complete &= (command.get("status") == "passed" and command_passed(command)
                     and "evidence_error" not in command)
    consumer = commands[-1].get("consumer_observation", {}) if commands else {}
    complete &= (consumer.get("command_succeeded") is True
                 and consumer.get("summary", {}).get("status") == "passed")
    try:
        validate_summary(consumer.get("summary"), True)
        run.require(len(commands) == 8 and commands[5].get("protocol") == PROTOCOL,
                    "consumer_final_protocol")
        for name, value in record.get("artifacts", {}).items():
            run.require(type(value) is dict and set(value) == {"sha256", "bytes"}
                and type(value["sha256"]) is str and HEX.fullmatch(value["sha256"])
                and type(value["bytes"]) is int and 0 < value["bytes"] <= (
                    MAX_TOOL if name == "example" else MAX_ARTIFACT), "consumer_final_artifact")
        for name, value in record.get("c_tools", {}).items():
            run.require(type(value) is dict and set(value) == {"sha256", "bytes", "version", "version_output_sha256"}
                and type(value["sha256"]) is str and HEX.fullmatch(value["sha256"])
                and type(value["version_output_sha256"]) is str and HEX.fullmatch(value["version_output_sha256"])
                and type(value["bytes"]) is int and 0 < value["bytes"] <= MAX_TOOL
                and type(value["version"]) is str and re.fullmatch(r"\d+\.\d+(?:\.\d+){0,2}", value["version"]),
                "consumer_final_tool")
            index = 0 if name == "clang" else 1
            run.require(commands[index].get("tool_observation") == {key: value[key]
                for key in ("version", "version_output_sha256")}, "consumer_final_version")
        run.require(record.get("elf", {}).get("sha256") == record.get("artifacts", {}).get("elf", {}).get("sha256")
            and record.get("elf", {}).get("bytes") == record.get("artifacts", {}).get("elf", {}).get("bytes"),
            "consumer_final_elf")
    except InvalidEvidence:
        complete = False
    record["status"] = "passed" if complete else "failed"
    if consumer:
        consumer["qualified_run"] = bool(complete)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-revision", required=True)
    parser.add_argument("--correctness-receipt", required=True)
    parser.add_argument("--correctness-sha256", required=True)
    args = parser.parse_args()
    run.require(re.fullmatch(r"[0-9a-f]{40}", args.expect_revision), "consumer_revision_argument")
    run.require(HEX.fullmatch(args.correctness_sha256), "consumer_receipt_argument")
    receipt = Path(args.correctness_receipt)
    run.require(not receipt.is_absolute() and receipt.parent == Path("evaluation/admission/results")
                and not (ROOT / receipt).is_symlink(), "consumer_receipt_path")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    identity = stamp + "-runtime-consumer-" + args.expect_revision[:12]
    relative = "target/evaluation/admission/" + identity
    private = ROOT / relative
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = private / "tmp"
    temporary.mkdir(mode=0o700)
    output = HERE / "results" / (identity + ".json")
    run.require(not output.exists(), "consumer_duplicate_run")
    record = {"schema_version": 1, "experiment": "runtime-kernel-c-consumer", "run_id": identity,
        "private_relative": relative, "status": "preflight", "source": None,
        "runner_sha256": run.sha(Path(__file__).read_bytes()),
        "schema_sha256": run.sha((HERE / "runtime_consumer_schema.py").read_bytes()),
        "reproduce": ["python3", "evaluation/admission/runtime_kernel_consumer.py",
            "--expect-revision", args.expect_revision, "--correctness-receipt", str(receipt),
            "--correctness-sha256", args.correctness_sha256],
        "commands": command_specs(relative), "c_tools": {}, "artifacts": {}, "artifact_observations": {},
        "source_unchanged": False, "configuration_unchanged": False,
        "toolchain_unchanged": False, "hardware_unchanged": False, "files_unchanged": False,
        "log_limit_bytes_per_command": LOG_LIMIT, "cleanup_seconds": 3,
        "artifact_limit_bytes": MAX_ARTIFACT, "tool_and_example_limit_bytes": MAX_TOOL,
        "performance_claim": None, "complete_B3": False, "full_application_support": False,
        "claim_scope": "one_freestanding_compiler_produced_static_native64_artifact",
        "inherited_location_variables": list(run.LOCATION_VARIABLES)}
    pins = {}
    run.write_result(output, record)
    print(output.relative_to(ROOT), flush=True)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        base_env = run.controlled_environment(os.environ, temporary)
        source = run.source_state()
        run.preflight(source, args.expect_revision,
            run.git("ls-files", "--others", "--exclude-standard").decode().splitlines())
        record["source"] = source
        run.require(sys.platform == "linux" and os.uname().machine == "x86_64",
                    "consumer_platform")
        record["configuration"] = run.cargo_configuration(base_env)
        record["hardware"] = run.hardware()
        run.require(1 <= record["hardware"]["affinity_cpu_count"] <= 8, "consumer_affinity_bound")
        cpus = frozenset(os.sched_getaffinity(0))
        record["toolchain"] = toolchain(base_env)
        corpus_data = bounded_read(HERE / "corpus.json", 16 * 1024 * 1024)
        run.require(run.sha(corpus_data) == source["source_sha256"]["evaluation/admission/corpus.json"],
                    "consumer_corpus_source")
        corpus = strict_json(corpus_data)
        data = bounded_read(ROOT / receipt, 16 * 1024 * 1024)
        run.require(run.sha(data) == args.correctness_sha256, "consumer_receipt_digest")
        prior = strict_json(data)
        run.require(prior.get("run_id") == receipt.stem, "consumer_receipt_identity")
        prerequisite(prior, source, corpus, run.sha(corpus_data), record["configuration"],
                     record["hardware"], record["toolchain"])
        hashes = replay_prerequisite(prior, corpus)
        record["prerequisite"] = {"qualified": True, "receipt": receipt.name,
            "sha256": args.correctness_sha256, "revision": source["revision"],
            "private_log_sha256": hashes, "policy": "exact_revision_and_unchanged_six_command_replay"}
        # Only now derive the separate consumer environment; prior ENV stays exact.
        env = consumer_environment(base_env)
        record["environment"] = {key: value for key, value in run.ENV.items() if key != "RUST_TEST_THREADS"} | {
            "CARGO_TARGET_DIR": "target", "TMPDIR": "private_run/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "RLIMIT_CORE": 0}
        for role in ("clang", "ld.lld"):
            located = shutil.which(role, path=env["PATH"])
            run.require(located is not None, "consumer_tool_missing")
            pins[role] = PinnedTool(located, role)
            record["c_tools"][role] = pins[role].public()
        pins["c_source"] = PinnedFile(ROOT / SOURCE, MAX_ARTIFACT)
        run.require(pins["c_source"].digest == source["source_sha256"][SOURCE], "consumer_c_source")
        record["artifacts"]["c_source"] = pins["c_source"].public()

        def stable():
            after = run.source_state()
            record["source_unchanged"] = source == after
            run.preflight(after, args.expect_revision,
                run.git("ls-files", "--others", "--exclude-standard").decode().splitlines())
            record["configuration_unchanged"] = record["configuration"] == run.cargo_configuration(base_env)
            record["toolchain_unchanged"] = record["toolchain"] == toolchain(base_env)
            record["hardware_unchanged"] = record["hardware"] == run.hardware()
            run.require(cpus == frozenset(os.sched_getaffinity(0)), "consumer_affinity_changed")
            for pin in pins.values():
                pin.check()
            record["files_unchanged"] = True
            run.require(all(record[key] for key in ("source_unchanged", "configuration_unchanged",
                "toolchain_unchanged", "hardware_unchanged", "files_unchanged")), "consumer_environment_changed")

        record["status"] = "running"
        for command in record["commands"]:
            stable()
            created = {"compile_c": private / "runtime_identity.o",
                       "link_c": private / "runtime_identity.elf"}.get(command["id"])
            if created is not None:
                run.require(not created.exists() and not created.is_symlink(),
                            "consumer_preexisting_output")
            command["status"] = "running"
            run.write_result(output, record)
            actual = list(command["argv"])
            if actual[0] in ("clang", "ld.lld"):
                actual[0] = str(pins[actual[0]].launcher)
            elif actual[0] == EXAMPLE:
                actual[0] = str(pins["example"].path)
            log = private / (command["id"] + ".log")
            command.update(run_command(actual, env, log, command["timeout_seconds"], LOG_LIMIT))
            observe(command, bounded_read(log, LOG_LIMIT))
            if created is not None:
                record["artifact_observations"][command["id"]] = artifact_prefix(
                    created, command["status"] == "passed")
            run.write_result(output, record)
            stable()
            if command["status"] != "passed":
                break
            if command["id"] in ("clang_version", "linker_version"):
                role = "clang" if command["id"] == "clang_version" else "ld.lld"
                record["c_tools"][role].update(command["tool_observation"])
            elif command["id"] == "compile_c":
                pins["object"] = PinnedFile(private / "runtime_identity.o", MAX_ARTIFACT, artifact=True)
                record["artifacts"]["object"] = pins["object"].public()
            elif command["id"] == "link_c":
                executable = private / "runtime_identity.elf"
                pins["elf"] = PinnedFile(executable, MAX_ARTIFACT, artifact=True, executable=True)
                description = elf_metadata(pins["elf"].data())
                pins["elf"].make_readonly()
                record["artifacts"]["elf"] = pins["elf"].public()
                record["elf"] = description
            elif command["id"] == "build_example":
                pins["example"] = PinnedFile(ROOT / EXAMPLE, MAX_TOOL, executable=True)
                record["artifacts"]["example"] = pins["example"].public()
            stable()
            run.write_result(output, record)
        qualify(record)
    except (Exception, KeyboardInterrupt) as error:
        if isinstance(error, InvalidEvidence):
            record["error_code"] = str(error)
        else:
            record["error_type"] = type(error).__name__
        record["status"] = "failed"
        for command in record["commands"]:
            if "consumer_observation" in command:
                command["consumer_observation"]["qualified_run"] = False
    finally:
        for pin in pins.values():
            try:
                pin.close()
            except OSError:
                record["status"] = "failed"
                record["error_code"] = "consumer_pin_close"
                for command in record["commands"]:
                    if "consumer_observation" in command:
                        command["consumer_observation"]["qualified_run"] = False
        run.write_result(output, record)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
