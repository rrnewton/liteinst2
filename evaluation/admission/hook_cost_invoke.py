#!/usr/bin/env python3
"""Record one bounded hard-reservation/build/measurement attempt, including refusal."""

import argparse
import copy
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tempfile

import run
from parsing import InvalidEvidence
from processes import run_command
from hook_cost import BINARY, BUILD, BUILD_TIMEOUT, MEASURE_TIMEOUT, clean_command, public_error
from hook_cost_proof import (HEX, LOG_LIMIT, PUBLIC_ENV, REVISION, correctness_prerequisite,
                             executable_identity, require, sha, source_identity,
                             strict_json, toolchain)
from hook_cost_schema import load_inventory, parse_capture, qualify
from hook_cost_summary import partial_csv, publish_csv

ROOT, HERE = run.ROOT, run.HERE
OUTER_TIMEOUT = 600
TAG = "li2adm-b2-hook-cost"
TERMINATIONS = {"output_limit", "capture_error", "spawn_error", "interrupted", "timeout", "ownership_refused",
                "setup_error", "cleanup_incomplete", "descendants_after_exit"}


def resolve_allocator(value, env):
    if value == "cpuset-alloc":
        value = shutil.which(value, path=env["PATH"])
        require(value is not None, "allocator_not_on_controlled_path")
    require(type(value) is str and Path(value).is_absolute() and Path(value).name == "cpuset-alloc",
            "allocator_entry_invalid")
    return value


def scope_identity(env):
    located = shutil.which("systemd-run", path=env["PATH"])
    require(located is not None, "systemd_run_missing")
    data = subprocess.check_output([located, "--version"], cwd=ROOT, env=env,
                                   stderr=subprocess.DEVNULL, timeout=10)
    require(len(data) <= 16384, "systemd_version_limit")
    first = data.decode("ascii").splitlines()[0]
    require(re.fullmatch(r"[A-Za-z0-9 .()+~:_-]{1,160}", first), "invalid_systemd_version")
    return {"tool": "systemd-run", "version": first, "version_output_sha256": sha(data),
            "executable_sha256": sha(Path(located).read_bytes()), "mode": "synchronous_scope"}


def allocator_identity(entry):
    """Hash the complete package source closure, not an asserted import trace."""
    entry = Path(entry)
    require(entry.is_absolute() and entry.name == "cpuset-alloc" and entry.is_file(), "allocator_entry_invalid")
    resolver = entry.resolve(strict=True)
    require(os.access(entry, os.X_OK), "allocator_not_executable")
    require(resolver.name == "engine-resolver" and resolver.parent.name == "bin"
            and resolver.parent.parent.name == "common", "unsupported_allocator_resolver_layout")
    root = resolver.parents[2]
    python_entry = root / "py/bin/cpuset-alloc"
    package = root / "py/dagrun"
    require(python_entry.is_file() and package.is_dir(), "allocator_package_missing")
    modules = {}
    for path in sorted(package.rglob("*.py")):
        require(path.is_file() and not path.is_symlink(), "allocator_package_symlink")
        modules[path.relative_to(root / "py").as_posix()] = sha(path.read_bytes())
    require("dagrun/__init__.py" in modules and "dagrun/reservation.py" in modules
            and len(modules) <= 256, "allocator_package_inventory")
    result = {"tool": "cpuset-alloc", "engine": "python", "entry_sha256": sha(entry.read_bytes()),
              "resolver_sha256": sha(resolver.read_bytes()), "python_entry_sha256": sha(python_entry.read_bytes()),
              "package_source_sha256": modules, "package_hash_scope": "all_package_python_sources_not_runtime_import_trace"}
    result["closure_sha256"] = sha(json.dumps(result, sort_keys=True, separators=(",", ":")).encode())
    return result


def allocator_environment(inherited, temporary):
    """Keep the preexisting shared ledger despite private capture/TMPDIR."""
    env = run.controlled_environment(inherited, temporary)
    roles = []
    runtime = inherited.get("XDG_RUNTIME_DIR")
    if runtime is not None:
        path = Path(runtime)
        require(path.is_absolute() and path.is_dir() and not path.is_symlink()
                and path.stat().st_uid == os.geteuid() and not path.stat().st_mode & 0o077,
                "invalid_allocator_runtime_directory")
        env["XDG_RUNTIME_DIR"] = runtime
        roles.append("XDG_RUNTIME_DIR")
    bus = inherited.get("DBUS_SESSION_BUS_ADDRESS")
    if bus is not None:
        require(type(bus) is str and len(bus) <= 4096 and "\0" not in bus and "\n" not in bus
                and re.fullmatch(r"unix:path=/[^,;\r\n]+(?:,guid=[0-9a-f]{32})?", bus), "invalid_allocator_bus")
        env["DBUS_SESSION_BUS_ADDRESS"] = bus
        roles.append("DBUS_SESSION_BUS_ADDRESS")
    explicit = inherited.get("DAGRUN_CORE_LEDGER")
    if explicit:
        ledger, policy = Path(explicit), "inherited_explicit_shared_ledger"
    elif runtime:
        ledger, policy = Path(runtime) / "dagrun/core-reservations.json", "original_runtime_default_shared_ledger"
    else:
        # tempfile consults the invoking environment, before the controlled
        # allocator environment replaces TMPDIR. Never choose a per-run ledger.
        ledger = Path(tempfile.gettempdir()) / f"dagrun-{os.getuid()}" / "core-reservations.json"
        policy = "original_temp_default_shared_ledger"
    require(ledger.is_absolute() and ".." not in ledger.parts and "\0" not in str(ledger), "invalid_allocator_ledger")
    env.update(DAGRUN_CORE_LEDGER=str(ledger), DAGRUN_ENGINE="python",
               PYTHONPYCACHEPREFIX=str(temporary / "fresh-python-cache"))
    require(not (temporary / "fresh-python-cache").exists(), "allocator_cache_not_fresh")
    return env, {"preserved_location_roles": roles, "ledger_policy": policy,
                 "private_tmp_does_not_select_ledger": True, "engine": "python",
                 "python_cache": "fresh_private_prefix_no_bytecode_writes"}


def assignment(output):
    found = []
    marker = "cpuset-alloc: run: reserved "
    for line in output.splitlines():
        if marker not in line:
            continue
        require(line.startswith(marker), "allocator_assignment_prefix")
        encoded, separator, suffix = line[len(marker):].partition("; running whole tree pinned via AllowedCPUs=")
        require(separator and len(encoded) < 256, "allocator_assignment_shape")
        row = strict_json(encoded)
        require(type(row) is dict and set(row) == {"cores", "count"} and type(row["count"]) is int
                and row["count"] == 2 and type(row["cores"]) is list and len(row["cores"]) == 2
                and all(type(cpu) is int and 0 <= cpu <= 1048575 for cpu in row["cores"])
                and len(set(row["cores"])) == 2, "allocator_assignment_cpus")
        require(suffix == ",".join(map(str, sorted(row["cores"]))), "allocator_assignment_suffix")
        found.append({"cpus": sorted(row["cores"]), "logical_cpu_count": 2,
                      "allocator_reported_mutation_verified_hard_pin": True})
    require(len(found) == 1, "allocator_assignment_count")
    return found[0]


def observed_commands(inner, inventory):
    """Closed projection retains failed command facts without endorsing them."""
    rows = (inner or {}).get("commands", [])
    specifications = [("release_build", BUILD, BUILD_TIMEOUT),
                      ("measurement", [BINARY] + inventory["argv"], MEASURE_TIMEOUT)]
    result = []
    for name, argv, deadline in specifications:
        public = {"id": name, "argv": argv, "timeout_seconds": deadline, "environment_delta": {},
                  "status": "not_observed", "qualified": False}
        matches = [r for r in rows if type(r) is dict and r.get("id") == name] if type(rows) is list else []
        if len(matches) == 1:
            row = matches[0]
            try:
                require(row.get("argv") == argv and type(row.get("timeout_seconds")) is int
                        and row["timeout_seconds"] == deadline and row.get("environment_delta") == {},
                        "invalid_reported_command_spec")
                require(row.get("status") in ("not_run", "running", "passed", "failed"), "invalid_reported_command_status")
                public["status"] = row["status"]
                for key in ("exit_code", "reaped_descendants", "seconds", "termination", "cleanup_complete",
                            "private_log_sha256", "start_utc", "child_discovery_strategy"):
                    if key not in row:
                        continue
                    value = row[key]
                    if key == "exit_code":
                        valid = value is None or type(value) is int and -255 <= value <= 255
                    elif key == "reaped_descendants":
                        valid = type(value) is int and 0 <= value <= (1 << 64) - 1
                    elif key == "seconds":
                        valid = value is None or type(value) in (int, float) and math.isfinite(value) and value >= 0
                    elif key == "termination":
                        valid = value is None or type(value) is str and value in TERMINATIONS
                    elif key == "cleanup_complete":
                        valid = type(value) is bool
                    elif key == "private_log_sha256":
                        valid = value is None or type(value) is str and HEX.fullmatch(value)
                    elif key == "start_utc":
                        valid = type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+\+00:00", value)
                    else:
                        valid = value in ("not_needed", "proc_children", "pidfd_authenticated_proc_candidates")
                    require(valid, "invalid_reported_command_field")
                    public[key] = value
            except (InvalidEvidence, TypeError):
                public["status"] = "invalid_staging_metadata"
                public["metadata_error"] = "invalid_reported_command"
        elif matches:
            public["status"] = "invalid_staging_metadata"
            public["metadata_error"] = "duplicate_reported_command"
        result.append(public)
    return result


def harvest(private, record, inventory):
    """Retain bounded observations before any post-run identity check can fail."""
    inner_path = private / "inner.json"
    inner = None
    if inner_path.exists():
        try:
            require(not inner_path.is_symlink(), "inner_receipt_symlink")
            with inner_path.open("rb") as stream:
                data = stream.read(LOG_LIMIT + 1)
            require(len(data) <= LOG_LIMIT, "inner_receipt_limit")
            record["inner_staging_sha256"] = sha(data)
            inner = strict_json(data)
            require(type(inner) is dict and inner.get("run_id") == record["run_id"], "inner_receipt_identity")
        except Exception as error:
            record["staging_error"] = public_error(error)
            inner = None
    else:
        record["inner_state"] = "not_started_or_no_receipt"
    record["collection"] = {"status": "observed_unqualified", "qualified": False,
        "commands": observed_commands(inner, inventory), "evidence": parse_capture("", inventory),
        "evidence_origin": "independently_reparsed_private_capture"}
    # A timeout can interrupt inner serialization. The exact bounded capture is
    # still evidence of its emitted prefix, independently of the staging file.
    for name in ("release_build", "measurement"):
        path = private / (name + ".log")
        if not path.exists():
            continue
        try:
            require(not path.is_symlink(), "inner_capture_symlink")
            with path.open("rb") as stream:
                payload = stream.read(LOG_LIMIT + 1)
            require(len(payload) <= LOG_LIMIT, "inner_capture_limit")
            digest = sha(payload)
            record.setdefault("inner_capture_sha256", {})[name] = digest
            commands = (inner or {}).get("commands", [])
            matches = ([c for c in commands if type(c) is dict and c.get("id") == name]
                       if type(commands) is list else [])
            matched = len(matches) == 1 and matches[0].get("private_log_sha256") == digest
            record.setdefault("inner_capture_authenticated", {})[name] = matched
            if name == "measurement":
                evidence = parse_capture(payload.decode("utf-8", errors="replace"), inventory)
                record["capture_evidence"] = evidence
                record["inner_capture_matches"] = type(inner) is dict and inner.get("evidence") == evidence
                record["collection"]["evidence"] = copy.deepcopy(evidence)
        except Exception as error:
            record.setdefault("harvest_errors", {})[name] = public_error(error)
    return inner


def atom_observation(value):
    require(type(value) is dict and set(value) == {"status", "value"}, "invalid_optional_observation")
    require(value["status"] in ("observed", "interface_absent", "unreadable"), "invalid_optional_status")
    if value["status"] == "observed":
        require(type(value["value"]) is str and re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", value["value"]),
                "invalid_optional_atom")
    else:
        require(value["value"] is None, "unexpected_optional_value")
    return copy.deepcopy(value)


def public_placement(value, cpus):
    keys = {"affinity", "effective_cpuset", "topology", "hard_cpuset", "reserved_logical_cpus",
            "selected_physical_cores", "physical_core_exclusivity_claimed"}
    require(type(value) is dict and set(value) == keys, "invalid_inner_placement")
    require(all(type(value[k]) is list and all(type(n) is int for n in value[k])
                for k in ("affinity", "effective_cpuset")), "invalid_inner_cpu_types")
    require(value["affinity"] == cpus and value["effective_cpuset"] == cpus
            and value["hard_cpuset"] == "cgroup_v2_effective"
            and type(value["reserved_logical_cpus"]) is int and value["reserved_logical_cpus"] == 2
            and type(value["selected_physical_cores"]) is int and value["selected_physical_cores"] == 2
            and value["physical_core_exclusivity_claimed"] is False, "invalid_inner_placement")
    require(type(value["topology"]) is list and len(value["topology"]) == 2, "invalid_inner_topology")
    for row, cpu in zip(value["topology"], cpus):
        require(type(row) is dict and set(row) == {"cpu", "package", "core", "thread_siblings", "governor"},
                "invalid_inner_topology")
        require(type(row["cpu"]) is int and row["cpu"] == cpu
                and all(type(row[k]) is int and 0 <= row[k] < 100000000 for k in ("package", "core")),
                "invalid_inner_topology")
        siblings = row["thread_siblings"]
        require(type(siblings) is list and 0 < len(siblings) <= 4096
                and all(type(n) is int and 0 <= n <= 1048575 for n in siblings)
                and siblings == sorted(set(siblings)) and cpu in siblings, "invalid_inner_siblings")
        atom_observation(row["governor"])
    require(len({(r["package"], r["core"]) for r in value["topology"]}) == 2, "inner_cpus_share_core")
    return copy.deepcopy(value)


def public_clock(value):
    require(type(value) is dict and set(value) == {"implementation", "resolution_seconds", "monotonic",
            "adjustable", "clocksource", "calibration_subtracted"}, "invalid_inner_clock")
    require(type(value["implementation"]) is str
            and re.fullmatch(r"[A-Za-z0-9_(). ]{1,100}", value["implementation"])
            and type(value["resolution_seconds"]) in (int, float)
            and math.isfinite(value["resolution_seconds"]) and value["resolution_seconds"] > 0
            and value["monotonic"] is True and value["adjustable"] is False
            and value["calibration_subtracted"] is False, "invalid_inner_clock")
    atom_observation(value["clocksource"])
    return copy.deepcopy(value)


def public_command(command, name, argv, deadline):
    require(clean_command(command) and command.get("status") == "passed"
            and command.get("id") == name and command.get("argv") == argv
            and type(command.get("timeout_seconds")) is int and command["timeout_seconds"] == deadline
            and command.get("environment_delta") == {}, "inner_commands_incomplete")
    require(type(command.get("seconds")) in (float, int) and math.isfinite(command["seconds"])
            and command["seconds"] >= 0 and type(command.get("start_utc")) is str
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+\+00:00", command["start_utc"])
            and command.get("child_discovery_strategy") in ("proc_children", "pidfd_authenticated_proc_candidates")
            and type(command.get("private_log_sha256")) is str and HEX.fullmatch(command["private_log_sha256"]),
            "invalid_inner_command_metadata")
    keys = {"id", "argv", "timeout_seconds", "environment_delta", "status", "exit_code", "termination",
            "cleanup_complete", "reaped_descendants", "seconds", "start_utc", "child_discovery_strategy", "private_log_sha256"}
    require(set(command) == keys, "inner_command_fields")
    return {key: copy.deepcopy(command[key]) for key in keys}


def finalize(record, inner, allocator_command, observed_assignment, inventory):
    """No rows qualify from an inner terminal alone; all outer proofs must hold."""
    require(type(inner) is dict and type(inner.get("schema_version")) is int and inner["schema_version"] == 1
            and inner.get("experiment") == "b2-hook-cost" and inner.get("run_id") == record["run_id"],
            "inner_receipt_identity")
    require(inner.get("status") == "measured_pending_outer" and inner.get("qualified") is False,
            "inner_collection_failed")
    require(clean_command(allocator_command), "allocator_or_outer_cleanup_failed")
    require(record["source_unchanged"] is True and record["configuration_unchanged"] is True
            and record["allocator_unchanged"] is True and record["toolchain_unchanged"] is True,
            "outer_identity_changed")
    require(inner.get("source") == record["source"] and inner.get("configuration") == record["configuration"],
            "inner_outer_source_or_config_differs")
    require(inner.get("toolchain") == record["toolchain"], "inner_outer_toolchain_differs")
    require(inner.get("environment") == PUBLIC_ENV and type(inner.get("log_limit_bytes_per_command")) is int
            and inner["log_limit_bytes_per_command"] == LOG_LIMIT
            and inner.get("inherited_location_variables") == list(run.LOCATION_VARIABLES),
            "inner_collection_contract_differs")
    for key in ("source_unchanged", "configuration_unchanged", "placement_unchanged", "hardware_unchanged",
                "toolchain_unchanged", "executable_unchanged"):
        require(inner.get(key) is True, "inner_identity_changed")
    placement = public_placement(inner.get("placement"), observed_assignment["cpus"])
    clock = public_clock(inner.get("clock"))
    require(inner.get("hardware") == record["hardware"] | {"affinity_cpu_count": 2}, "inner_hardware_differs")
    require(inner.get("correctness") == record["correctness"], "inner_correctness_differs")
    require(inner.get("executable") == record["executed_binary"], "outer_executable_changed")
    expected_commands = [("release_build", BUILD, BUILD_TIMEOUT),
                         ("measurement", [BINARY] + inventory["argv"], MEASURE_TIMEOUT)]
    require(len(inner.get("commands", [])) == 2, "inner_commands_incomplete")
    commands = [public_command(command, name, argv, deadline)
                for command, (name, argv, deadline) in zip(inner["commands"], expected_commands)]
    for field, filename in (("runner_sha256", "hook_cost.py"), ("inventory_sha256", "hook_cost_inventory.json"),
                            ("wire_sha256", "hook_cost_wire.json")):
        require(inner.get(field) == sha((HERE / filename).read_bytes()), "inner_implementation_digest_differs")
    require(inner.get("evidence", {}).get("status") == "complete", "inner_evidence_incomplete")
    # Authenticated staging must agree with an independent parse of the exact
    # hash-bound private capture. An empty/forged complete collection cannot pass.
    require(record.get("inner_capture_matches") is True
            and record.get("inner_capture_authenticated") == {"release_build": True, "measurement": True}
            and record.get("capture_evidence") == inner["evidence"], "inner_capture_evidence_differs")
    allowed = {"schema_version", "experiment", "run_id", "status", "qualified", "source", "source_unchanged",
        "configuration_unchanged", "placement_unchanged", "hardware_unchanged", "toolchain_unchanged",
        "executable_unchanged", "environment", "inherited_location_variables", "log_limit_bytes_per_command",
        "runner_sha256", "commands", "evidence", "performance_pass_threshold", "claim_scope", "configuration",
        "hardware", "placement", "clock", "toolchain", "correctness", "inventory_sha256", "wire_sha256", "executable"}
    require(set(inner) == allowed and inner["performance_pass_threshold"] is None
            and inner["claim_scope"] == "finite_scripted_synchronous_completion_cost", "inner_receipt_fields")
    public = {"schema_version": 1, "experiment": "b2-hook-cost", "run_id": record["run_id"],
        "status": "qualified_by_outer", "qualified": True, "evidence": copy.deepcopy(record["capture_evidence"]),
        "evidence_origin": "independently_reparsed_private_capture", "commands": commands,
        "placement": placement, "clock": clock, "hardware": record["hardware"] | {"affinity_cpu_count": 2},
        "source": record["source"], "configuration": record["configuration"], "toolchain": record["toolchain"],
        "correctness": record["correctness"], "executable": record["executed_binary"],
        "environment": PUBLIC_ENV, "inherited_location_variables": list(run.LOCATION_VARIABLES),
        "log_limit_bytes_per_command": LOG_LIMIT, "performance_pass_threshold": None,
        "claim_scope": "finite_scripted_synchronous_completion_cost"}
    for field in ("runner_sha256", "inventory_sha256", "wire_sha256", "source_unchanged", "configuration_unchanged",
                  "placement_unchanged", "hardware_unchanged", "toolchain_unchanged", "executable_unchanged"):
        public[field] = inner[field]
    qualify(public["evidence"], True)
    record["collection"] = public
    record["status"] = "passed"
    record["qualified"] = True


def invoke(args):
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    require(type(args.expect_revision) is str and REVISION.fullmatch(args.expect_revision), "invalid_expected_revision")
    run_id = stamp + "-" + args.expect_revision[:12] + "-hook-cost"
    private = ROOT / "target/evaluation/admission" / run_id
    private.mkdir(parents=True, exist_ok=False)
    temporary = private / "outer-tmp"
    temporary.mkdir()
    public = HERE / "results" / (run_id + ".json")
    public.parent.mkdir(parents=True, exist_ok=True)
    require(not public.exists(), "duplicate_result")
    record = {"schema_version": 1, "experiment": "b2-hook-cost-invocation", "run_id": run_id,
        "status": "preflight", "qualified": False, "source": None, "source_unchanged": False,
        "configuration_unchanged": False, "allocator_unchanged": False, "toolchain_unchanged": False,
        "allocator": None, "command": {"status": "not_run"}, "collection": None,
        "resource_plan": {"logical_cpus": 2, "distinct_physical_cores": 2,
                          "reserve_all_smt_siblings": False, "physical_core_exclusivity_claimed": False},
        "log_limit_bytes_per_command": LOG_LIMIT, "whole_protocol_qualified": False,
        "performance_pass_threshold": None, "csv": {},
        "reproduce": None}
    run.write_result(public, record)
    print(public.relative_to(ROOT), flush=True)
    inventory = None
    try:
        require(re.fullmatch(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{12}\.json", args.correctness_receipt),
                "invalid_correctness_receipt_name")
        require(HEX.fullmatch(args.correctness_sha256) and HEX.fullmatch(args.allocator_sha256), "invalid_input_digest")
        record["reproduce"] = ["python3", "evaluation/admission/hook_cost_invoke.py", "--expect-revision", args.expect_revision,
            "--correctness-receipt", args.correctness_receipt, "--correctness-sha256", args.correctness_sha256,
            "--allocator", "cpuset-alloc", "--allocator-sha256", args.allocator_sha256]
        env, allocation_env = allocator_environment(os.environ, temporary)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        record["allocator_environment"] = allocation_env
        record["source"] = source_identity(args.expect_revision)
        # Retain the exact authenticated catalog before starting any command.
        # Recovery must not reload possibly changed source after an effect.
        inventory = load_inventory(HERE / "hook_cost_inventory.json", expected_sha256=
            record["source"]["source_sha256"]["evaluation/admission/hook_cost_inventory.json"])
        record["configuration"] = run.cargo_configuration(env)
        record["hardware"] = run.hardware()
        require(record["hardware"]["effective_uid_is_root"] is False
                and type(record["hardware"]["effective_capabilities"]) is int
                and record["hardware"]["effective_capabilities"] == 0, "unprivileged_measurement_required")
        record["toolchain"] = toolchain(env)
        corpus = strict_json((HERE / "corpus.json").read_bytes())
        record["correctness"] = correctness_prerequisite(HERE / "results" / args.correctness_receipt,
            args.correctness_sha256, record["source"], corpus, record["configuration"], record["hardware"], record["toolchain"])
        allocator_path = resolve_allocator(args.allocator, env)
        allocator = allocator_identity(allocator_path)
        record["allocator"] = allocator
        record["scope_tool"] = scope_identity(env)
        require(allocator["entry_sha256"] == args.allocator_sha256, "allocator_expected_digest_differs")
        inner_argv = ["python3", "evaluation/admission/hook_cost.py", "--expect-revision", args.expect_revision,
            "--correctness-receipt", args.correctness_receipt, "--correctness-sha256", args.correctness_sha256,
            "--run-id", run_id]
        actual_argv = [allocator_path, "run", "--cores", "2", "--tag", TAG, "--"] + inner_argv
        record["command"] = {"id": "reserved_collection", "argv": ["cpuset-alloc"] + actual_argv[1:],
                             "timeout_seconds": OUTER_TIMEOUT, "status": "running"}
        record["status"] = "running"
        run.write_result(public, record)
        log = private / "allocation.log"
        record["command"].update(run_command(actual_argv, env, log, OUTER_TIMEOUT, LOG_LIMIT))
        record["command"]["status"] = "passed" if clean_command(record["command"]) else "failed"
        inner = harvest(private, record, inventory)
        record["source_unchanged"] = source_identity(args.expect_revision) == record["source"]
        record["configuration_unchanged"] = run.cargo_configuration(env) == record["configuration"]
        record["allocator_unchanged"] = (allocator_identity(allocator_path) == allocator
                                         and scope_identity(env) == record["scope_tool"])
        record["toolchain_unchanged"] = toolchain(env) == record["toolchain"]
        if type(inner) is dict and inner.get("status") == "measured_pending_outer":
            record["executed_binary"] = executable_identity(ROOT / BINARY)
            require(record["executed_binary"] == inner.get("executable"), "outer_executable_changed")
        raw = log.read_bytes()
        require(len(raw) <= LOG_LIMIT and sha(raw) == record["command"]["private_log_sha256"], "allocator_capture_digest_differs")
        record["assignment"] = assignment(raw.decode("utf-8", errors="replace"))
        require(inner is not None, "inner_receipt_missing")
        finalize(record, inner, record["command"], record["assignment"], inventory)
        record["whole_protocol_qualified"] = True
    except (Exception, KeyboardInterrupt) as error:
        if inventory is not None and "capture_evidence" not in record:
            harvest(private, record, inventory)
        record["status"], record["qualified"] = "failed", False
        record["whole_protocol_qualified"] = False
        record["error"] = public_error(error)
        inner = record.get("collection")
        if type(inner) is dict:
            inner["qualified"] = False
            if type(inner.get("evidence")) is dict:
                qualify(inner["evidence"], False)
            if inner.get("status") == "qualified_by_outer":
                inner["status"] = "outer_disqualified"
    # The independent parse is a promotion witness, not a duplicate public cohort.
    record.pop("capture_evidence", None)
    evidence = (record.get("collection") or {}).get("evidence")
    if evidence is None and inventory is not None:
        evidence = parse_capture("", inventory)
        record["unobserved_inventory"] = evidence
    try:
        # Failed preflight without an authenticated catalog has no inventory to
        # project. Preserve the terminal failure without invented observations.
        if evidence is not None:
            record["csv"] = publish_csv(public.parent, run_id, evidence)
    except (Exception, KeyboardInterrupt) as error:
        record["status"], record["qualified"], record["whole_protocol_qualified"] = "failed", False, False
        record["publication_error"] = public_error(error)
        record["csv"] = partial_csv(public.parent, run_id)
        qualify(evidence, False)
        if record.get("collection"):
            record["collection"]["qualified"] = False
            record["collection"]["status"] = "publication_failed"
    run.write_result(public, record)
    return 0 if record["qualified"] else 1


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-revision", required=True)
    parser.add_argument("--correctness-receipt", required=True)
    parser.add_argument("--correctness-sha256", required=True)
    parser.add_argument("--allocator", required=True)
    parser.add_argument("--allocator-sha256", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(invoke(arguments()))
