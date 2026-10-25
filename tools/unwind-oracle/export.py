#!/usr/bin/env python3
"""Export authenticated closed records using the shared evaluation schema.

This command never readmits or reruns a completed native cohort. Live loader
epochs may have changed since completion; closed receipts and captured mapping
proofs remain the evidence. An incomplete run is never exported as a pass.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import csv
import hashlib
import importlib.util
import json
import math
import re
from pathlib import Path


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(512 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def load(name, path, digest):
    assert name not in sys.modules
    path = Path(path)
    assert not path.is_symlink() and path.resolve(strict=True) == path
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.origin == str(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec", dont_inherit=True, optimize=0), vars(module))
    assert module.__file__ == str(path) and module.__spec__ is spec and sha(path) == digest
    return module


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def table(path, rows, fields):
    with path.open("x", newline="") as stream:
        out = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        out.writeheader()
        for row in rows:
            out.writerow({key: json.dumps(value, sort_keys=True, separators=(",", ":"))
                          if isinstance(value, (dict, list)) else value for key, value in row.items()})


def aggregate_receipt(path, digest, runtime, manifest_sha, inputs):
    """Read the closed qualification backstop without revalidating live tools."""
    assert path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink()
    assert path.name == "binding.json" and sha(path) == digest
    directory = path.parent
    expected_files = {"binding.json", "request.json", "receipt.json", "outer.stdout",
                      "outer.stderr", "helper.stdout", "helper.stderr"}
    assert {p.name for p in directory.iterdir()} == expected_files
    assert all(p.is_file() and not p.is_symlink() for p in directory.iterdir())
    value = read(path)
    assert value["status"] == "OUTER_REQUEST_REVIEW_REQUIRED_NO_EXECUTION"
    assert value["phase"] == "qualification" and value["no_retries"] is True
    assert value["root"] == inputs["root"]
    adapter = Path(inputs["public_adapter_directory"])
    sources = {str(Path(inputs["root"]) / n): h for n, h in inputs["source_selection"].items()
               if (Path(inputs["root"]) / n).is_relative_to(adapter)}
    assert value["sources"] == sources
    assert value["generator"]["path"] == str(adapter / "aggregate.py")
    assert value["generator"]["sha256"] == sources[value["generator"]["path"]]
    for role in ("python", "helper"):
        saved = value[role]
        recorded = inputs["tools"]["helper_python" if role == "python" else "helper"]
        assert saved == dict(path=recorded["path"], resolved=recorded["resolved_path"],
                             sha256=recorded["sha256"], stat=recorded["stat"])
    assert value["helper"]["sha256"] == "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
    assert value["request"] == str(directory / "request.json")
    assert sha(value["request"]) == value["request_sha256"]
    q = read(value["request"])
    assert set(q) == {"argv", "cwd", "env", "stdout", "stderr", "cpu_seconds", "wall_seconds", "file_bytes"}
    assert q["argv"] == [value["python"]["path"], "-B", str(runtime / "entry.py"), "run",
                         sha(runtime / "source-files.json"), "--manifest-sha256", manifest_sha]
    assert q["cwd"] == inputs["root"] and q["env"] == value["environment"]
    assert set(q["env"]) == {"PATH", "LC_ALL", "HOME", "PYTHONDONTWRITEBYTECODE"}
    assert q["env"]["PATH"] == "/usr/bin:/bin" and q["env"]["LC_ALL"] == "C"
    assert q["env"]["PYTHONDONTWRITEBYTECODE"] == "1" and Path(q["env"]["HOME"]).is_absolute()
    assert (q["cpu_seconds"], q["wall_seconds"], q["file_bytes"]) == (120, 180, 16 * 1024 * 1024)
    assert q["stdout"] == str(directory / "outer.stdout") and q["stderr"] == str(directory / "outer.stderr")
    for key, filename in (("receipt", "receipt.json"), ("helper_stdout", "helper.stdout"), ("helper_stderr", "helper.stderr")):
        assert value[key] == str(directory / filename)
    assert value["helper_argv"] == [value["python"]["path"], "-B", value["helper"]["path"],
                                    "--request", value["request"], "--receipt", value["receipt"]]
    frozen = read(runtime / "manifest.json")
    authenticated = value["authenticated_inputs"]
    required = {str(runtime / n): h for n, h in frozen["files"].items()}
    required[str(runtime / "manifest.json")] = manifest_sha
    required[str(runtime / "source-files.json")] = sha(runtime / "source-files.json")
    assert all(authenticated.get(p) == h for p, h in required.items())
    parameters = set(authenticated) - set(required)
    assert len(parameters) == 1
    parameter_path = Path(parameters.pop())
    assert not parameter_path.is_symlink() and sha(parameter_path) == authenticated[str(parameter_path)]
    assert read(parameter_path) == dict(phase="qualification", python=value["python"]["path"],
        home=q["env"]["HOME"], raw=str(runtime.parent), manifest_sha256=manifest_sha,
        source_index_sha256=sha(runtime / "source-files.json"))
    r = read(value["receipt"])
    assert r["request_sha256"] == value["request_sha256"] and r["helper_sha256"] == value["helper"]["sha256"]
    assert r["stdout_sha256"] == sha(q["stdout"]) and r["stderr_sha256"] == sha(q["stderr"])
    assert type(r["exit"]) is int or (r["exit"] is None and type(r["aborted"]) is str and len(r["aborted"]) > 0)
    assert type(r["elapsed_seconds"]) in (int, float)
    assert math.isfinite(r["elapsed_seconds"]) and r["elapsed_seconds"] >= 0
    assert type(r["wall_timeout"]) is bool and type(r["inputs_unchanged"]) is bool
    assert isinstance(r["unexpected_descendants"], list) and isinstance(r["cleanup_events"], list)
    helper_success = (r["exit"] == 0 and not r["wall_timeout"] and not r["unexpected_descendants"]
        and r["absence_proof"] == "ECHILD" and r["cleanup_error"] is None
        and r["aborted"] is None and r["inputs_unchanged"])
    summary = dict(exit=r["exit"], wall_timeout=r["wall_timeout"], absence_proof=r["absence_proof"],
                   descendants=len(r["unexpected_descendants"]), success=helper_success)
    assert Path(value["helper_stdout"]).read_bytes() == (json.dumps(summary) + "\n").encode()
    assert Path(value["helper_stderr"]).read_bytes() == b""
    passed = helper_success and r["cleanup_events"] == [] and r["elapsed_seconds"] < q["wall_seconds"]
    return dict(status="pass" if passed else "fail", binding_sha256=digest,
                files_sha256={p.name: sha(p) for p in sorted(directory.iterdir())},
                cpu_seconds=120, wall_seconds=180, file_bytes=16 * 1024 * 1024,
                elapsed_seconds=r["elapsed_seconds"], exit=r["exit"],
                cleanup="ECHILD_zero_descendants" if passed else "failed_or_incomplete",
                receipt_sha256=sha(value["receipt"]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--terminal", type=Path, required=True)
    parser.add_argument("--terminal-sha256", required=True)
    parser.add_argument("--aggregate-binding", type=Path, required=True)
    parser.add_argument("--aggregate-binding-sha256", required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--schema-sha256", required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--metadata-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    assert sys.pycache_prefix is None
    runtime = args.runtime.resolve(strict=True)
    assert sha(runtime / "manifest.json") == args.manifest_sha256
    manifest = read(runtime / "manifest.json")
    for name, checksum in manifest["files"].items():
        assert sha(runtime / name) == checksum
    assert args.terminal.parent.resolve(strict=True) == runtime / "control"
    assert args.terminal.resolve(strict=True) == args.terminal
    assert sha(args.terminal) == args.terminal_sha256
    terminal = read(args.terminal)
    complete = terminal["status"] == "TEN_FIXED_COMMANDS_AND_FINAL_AUDIT_PASS"
    assert complete or terminal["status"] == "FAILED_INCOMPLETE_NO_COHORT_PASS"
    assert args.terminal.name == ("complete.json" if complete else "failed-incomplete.json")
    if complete:
        assert terminal["manifest_sha256"] == args.manifest_sha256
    captured = {str(p.relative_to(runtime)): sha(p) for directory in ("run", "audit-output", "control")
                for p in (runtime / directory).rglob("*") if p.is_file() and p != args.terminal}
    assert captured == terminal["files"]
    assert not any(p.is_symlink() for directory in ("run", "audit-output", "control")
                   for p in (runtime / directory).rglob("*"))
    assert sha(args.metadata) == args.metadata_sha256
    metadata = read(args.metadata)
    inputs, plan, expected = (read(runtime / name) for name in ("inputs.json", "plan.json", "expected.json"))
    assert sha(Path(__file__)) == inputs["source_selection"]["tools/unwind-oracle/export.py"]
    frozen, build = runtime.parent, Path(inputs["build_directory"])
    freeze = read(frozen / "freeze.json")
    assert sha(frozen / "freeze.json") == manifest["references"][str(frozen / "freeze.json")]
    for name, checksum in freeze["source_files"].items():
        assert sha(frozen / "sources" / name) == checksum
    assert sha(build / "build-audit.json") == inputs["build_audit_sha256"]
    build_audit = read(build / "build-audit.json")
    assert {str(p.relative_to(build)): sha(p) for p in build.rglob("*") if p.is_file()} == dict(
        build_audit["files"], **{"build-audit.json": inputs["build_audit_sha256"]})
    names = ["guard", "mapping_identity", "backing_records", "audit"]
    assert all(name not in sys.modules for name in names)
    before_path = list(sys.path)
    try:
        source_index = read(runtime / "source-files.json")
        for name in names:
            load(name, runtime / (name + ".py"), source_index[name + ".py"])
        audit = sys.modules["audit"]
        assert sys.path == before_path
        assert sys.modules["guard"].verify_records() == inputs
        aggregate = aggregate_receipt(args.aggregate_binding, args.aggregate_binding_sha256,
                                      runtime, args.manifest_sha256, inputs)
        sources, maps = {}, {}
        for role, admission, checksum in (
            ("build-source", inputs["build_source_admission"], inputs["build_source_admission_sha256"]),
            ("runtime-source", inputs["source_admission"], inputs["source_admission_sha256"])):
            sources[role] = dict(kind=admission["source_kind"], tested_revision=admission["tested_revision"],
                base_revision=admission["base_revision"], git_tree=admission["git_tree"], source_manifest_sha256=checksum,
                source_tree_sha256=admission["source_tree_sha256"], tracked_diff_sha256=admission["tracked_diff_sha256"],
                clean_tracked=admission["clean_tracked"], file_count=len(admission["source_files"]))
            maps[role] = admission["source_files"]
        assert set(metadata) == {"hardware", "tools", "tool_version_evidence", "command_tools", "private_tokens", "path_substitutions"}
        assert metadata["hardware"]["label"] == "AMD EPYC Zen 5 dev host"
        assert set(metadata["hardware"]) == {"label", "architecture", "vendor", "family", "model", "stepping", "kernel_release", "observation_phase", "observation_sha256"}
        assert len({t["role"] for t in metadata["tools"]}) == len(metadata["tools"])
        for tool in metadata["tools"]:
            assert set(tool) == {"role", "sha256", "version", "version_basis", "version_capture_sha256"}
            assert re.fullmatch(r"[0-9a-f]{64}", tool["sha256"])
            evidence = metadata["tool_version_evidence"][tool["role"]]
            if evidence is None:
                assert tool["version"] is None and tool["version_capture_sha256"] is None
                assert tool["version_basis"] == "exact executable/source hash; version text not captured"
            else:
                assert sha(evidence["path"]) == evidence["sha256"] == tool["version_capture_sha256"]
                assert isinstance(tool["version"], str) and tool["version"]
                assert tool["version_basis"] == "captured version text"
        tools = {t["role"]: t for t in metadata["tools"]}
        expected_tools = {row["path"]: row["sha256"] for row in inputs["tools"].values()}
        expected_tools.update({row["path"]: row["sha256"] for row in inputs["binary"].values()})
        commands, cases, unexecuted, observations = [], [], [], {}
        rewrites = [(str(frozen) + "/", "${RAW}/")]
        rewrites += [(path, "${TOOLCHAIN}/" + role) for role, row in inputs["tools"].items()
                     for path in {row["path"], row["resolved_path"]}]
        rewrites += [(inputs["root"] + "/", "${REPO}/")]
        for old, new in metadata["path_substitutions"].items():
            assert Path(old).is_absolute() and re.fullmatch(r"\$\{[A-Z0-9_]+\}(?:/[A-Za-z0-9_./+-]*)?", new)
            rewrites.append((old, new))
        rewrites.sort(key=lambda pair: -len(pair[0]))

        def case(command, suffix, kind, expected_outcome, observed, status, evidence):
            cases.append(dict(ordinal=len(cases), command_id=command["id"], case_id=suffix,
                              kind=kind, expected=expected_outcome, observed=observed))

        def command(name, source_id, qp, rp, verified):
            q = read(qp)
            have = Path(rp).is_file()
            r = read(rp) if have else None
            if have:
                assert r["request_sha256"] == sha(qp)
                assert r["stdout_sha256"] == sha(q["stdout"]) and r["stderr_sha256"] == sha(q["stderr"])
                assert r["helper_sha256"] == inputs["helper"]["sha256"]
            if verified:
                assert have and r["exit"] == 0 and r["wall_timeout"] is False
                assert r["inputs_unchanged"] is True and r["aborted"] is None
                assert r["absence_proof"] == "ECHILD" and r["unexpected_descendants"] == r["cleanup_events"] == []
                assert r["cleanup_error"] is None
                assert math.isfinite(r["elapsed_seconds"]) and 0 <= r["elapsed_seconds"] < q["wall_seconds"]
            if not have:
                unexecuted.append(dict(id=name, source_id=source_id, request_sha256=sha(qp),
                                       observation="no bounded-command receipt; no execution or success inferred"))
                return dict(id=name, source_id=source_id, status="not_run", receipt_sha256=None, stdout_sha256=None)
            tool_id = metadata["command_tools"][name]
            assert tools[tool_id]["sha256"] == expected_tools[q["argv"][0]]
            public_argv = []
            for arg in q["argv"]:
                for old, new in rewrites:
                    arg = arg.replace(old, new)
                public_argv.append(arg)
            assert not any(re.search(r"(?:^|[=\s])/(?!/)", arg) for arg in public_argv), "undeclared command path"
            environment = {key: value for key, value in q["env"].items() if key in
                {"RUSTFLAGS", "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE", "RUST_TEST_THREADS", "LC_ALL", "LANG"}}
            for key, value in environment.items():
                for old, new in rewrites:
                    value = value.replace(old, new)
                assert not re.search(r"(?:^|[=\s])/(?!/)", value), "undeclared environment path"
                environment[key] = value
            assert math.isfinite(r["elapsed_seconds"]) and r["elapsed_seconds"] >= 0
            row = dict(id=name, source_id=source_id, environment=environment,
                status="pass" if verified else "fail", argv=public_argv,
                cpu_seconds=q["cpu_seconds"], wall_seconds=q["wall_seconds"], file_bytes=q["file_bytes"],
                elapsed_seconds=r["elapsed_seconds"], exit=r["exit"], receipt_sha256=sha(rp),
                stdout_sha256=r["stdout_sha256"], stderr_sha256=r["stderr_sha256"],
                cleanup="ECHILD_zero_descendants" if r["absence_proof"] == "ECHILD" and r["unexpected_descendants"] == r["cleanup_events"] == [] and r["cleanup_error"] is None else "incomplete")
            commands.append(row)
            return row

        for step in build_audit["steps"]:
            name = step["name"]
            rp, qp = build / (name + ".receipt.json"), build / (name + ".request.json")
            r = read(rp)
            assert r["exit"] == 0 and not r["wall_timeout"] and r["absence_proof"] == "ECHILD"
            assert r["unexpected_descendants"] == r["cleanup_events"] == [] and r["cleanup_error"] is None
            row = command("build." + name, "build-source", qp, rp, True)
            if name == "mapping-calibrations":
                values = read(read(qp)["stdout"])
                assert values == read(frozen / "sources/tools/unwind-oracle/mapping-expected.json")
                observations[row["id"]] = dict(positive=4, required_refusals=35)
                for label in ("identity.distinct_devices", "identity.same_device", "records.three_cohorts", "records.two_cohorts"):
                    case(row, label, "auditor_calibration", "success", "success", "pass", r["stdout_sha256"])
                for prefix, labels in (("identity.", values["legacy"]["names"]), ("records.", values["names"])):
                    for label in labels:
                        case(row, prefix + label, "auditor_calibration", "refusal", "refusal", "pass", r["stdout_sha256"])
            else:
                case(row, "compile", "metadata", "success", "success", "pass", sha(rp))
        for step in plan["steps"] + [plan["final_audit"]]:
            name = step["name"]
            audit_path = runtime / "control" / (name + ".audit.json")
            verified = audit_path.is_file()
            if verified:
                if name == "final-audit":
                    recorded = read(audit_path)
                    assert recorded["status"] == "ALL_FIXED_QUALIFICATION_RECORDS_PASS"
                    assert recorded == audit.audit_closed()
                    assert read(read(step["request"])["stdout"]) == recorded
                else:
                    actual = audit.one(step, inputs, expected)
                    assert read(audit_path)["rows"][-1] == actual
            row = command(name, "runtime-source", step["request"], step["receipt"], verified)
            status = row["status"]
            evidence = row["stdout_sha256"] if verified else row["receipt_sha256"]
            observed = "success" if verified else "failure" if status == "fail" else "not_run"
            if name == "launcher-list":
                labels = [(label, "metadata", "success") for label in expected["launcher"]]
                observations[row["id"]] = dict(declared_names=32)
            elif name == "consumer-models":
                labels = [(label, "model", "success") for label in expected["consumer_models"]]
                observations[row["id"]] = dict(expected_models=6)
            elif name == "shared-calibrations":
                labels = [(label, "calibration", "panic" if label in expected["should_panic"] else "success") for label in expected["shared_calibrations"]]
                observations[row["id"]] = dict(expected_calibrations=26)
            elif name == "full-library":
                labels = []
                for label, count in expected["full_library_name_counts"].items():
                    labels.append((label, "cargo_test", "preexisting_ignore" if label in expected["full_library_ignored"] else "success"))
                    labels += [(label + ".nested." + str(index), "nested_guard", "success") for index in range(1, count)]
                observations[row["id"]] = dict(top_level_expected=190, top_level_passed=189 if verified else 0,
                                     preexisting_ignores=1 if verified else 0, nested_invocations=3 if verified else 0)
            elif name == "final-audit":
                labels = [("complete_inventory", "metadata", "success")]
            else:
                expectation = {"positive": "success", "calibration": "missing_generated_frame",
                               "postwrite-negative": "retained_postwrite_failure"}[step["kind"]]
                labels = [(step["test"], "native" if step["kind"] == "positive" else "native_control", expectation)]
                if verified:
                    if step["kind"] == "postwrite-negative":
                        observations[row["id"]] = dict(original_subjects=2, original_backtraces=2, retained_postwrite_failures=1, installed_calls=0)
                    else:
                        observations[row["id"]] = dict(subjects=6, real_backtraces=8, strict_original=2, strict_installed=2, strict_retired=2,
                            generated_crossings=2 if step["kind"] == "positive" else 0,
                            required_missing_crossings=0 if step["kind"] == "positive" else 2,
                            prewrite_refusals=3 if step["kind"] == "positive" else 0)
            for label, kind, expectation in labels:
                if verified and expectation == "preexisting_ignore":
                    case(row, label, kind, expectation, "ignored", "ignored", evidence)
                else:
                    case(row, label, kind, expectation, expectation if verified else observed, status, evidence)
        planned = ["build." + step["name"] for step in build_audit["steps"]] + [step["name"] for step in plan["steps"]] + ["final-audit"]
        assert len(planned) == 19 and len(set(planned)) == 19
        assert set(metadata["command_tools"]) == set(planned)
        assert [row["id"] for row in commands] == planned[:len(commands)]
        assert [row["id"] for row in unexecuted] == planned[len(commands):]
        assert len(cases) == 310
        assert len({(row["command_id"], row["case_id"]) for row in cases}) == len(cases)
        if complete:
            assert len(commands) == 19 and not unexecuted and len(captured) == 121
            assert all(row["status"] == "pass" for row in commands)
        assert sha(args.schema) == args.schema_sha256
        schema = read(args.schema)
        assert schema["schema_version"] == 1
        command_fields = ["id", "source_id", "environment", "status", "argv", "cpu_seconds", "wall_seconds", "file_bytes", "elapsed_seconds", "exit", "cleanup", "receipt_sha256", "stdout_sha256", "stderr_sha256"]
        case_fields = ["ordinal", "command_id", "case_id", "kind", "expected", "observed"]
        assert schema["command_fields"] == command_fields and schema["case_fields"] == case_fields
        assert schema["command_statuses"] == ["pass", "fail"]
        assert schema["files"] == ["summary.json", "commands.csv", "cases.csv", "source-files.json", "files.json"]
        assert all(set(row) == set(command_fields) for row in commands)
        assert all(set(row) == set(case_fields) for row in cases)
        headings = ["page-admission cross-modification-free", "sound unprivileged cpuid/rdtsc/rdrand/rdseed/rdpid firstinstruction", "in-place preemption clock", "systematic everytactic"]
        report = dict(schema_version=1, suite="generated-unwind-backtrace", run_id=args.run_id,
            status="pass" if complete and aggregate["status"] == "pass" else "fail", sources=sources, hardware=metadata["hardware"], tools=metadata["tools"],
            commands=commands, cases=cases, planned_commands=planned, unexecuted_commands=unexecuted,
            observations=observations, claims=[dict(number=index + 1, heading=heading, status="unqualified") for index, heading in enumerate(headings)],
            scope="BacktraceOnly: two authored frame profiles; no full A2 or general unwind qualification",
            fresh_ordinary_parity_separate=True, private_capture_manifest_sha256=args.terminal_sha256,
            qualification_aggregate=aggregate,
            reporting_schema_sha256=args.schema_sha256, reporter_source_sha256=sha(Path(__file__)),
            timing_class="operational_diagnostics_not_performance_benchmarks")
        public = json.dumps(report, allow_nan=False) + json.dumps(maps)
        assert metadata["private_tokens"] and all(isinstance(s, str) and s for s in metadata["private_tokens"])
        for token in metadata["private_tokens"] + [inputs["root"], str(frozen)]:
            assert token not in public, "private token in public output"
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.run_id)
        assert sys.modules["guard"].verify_records() == inputs
        assert aggregate_receipt(args.aggregate_binding, args.aggregate_binding_sha256,
                                 runtime, args.manifest_sha256, inputs) == aggregate
        args.output.mkdir()
        write(args.output / "summary.json", report)
        write(args.output / "source-files.json", maps)
        table(args.output / "commands.csv", commands, command_fields)
        table(args.output / "cases.csv", cases, case_fields)
        write(args.output / "files.json", {p.name: sha(p) for p in sorted(args.output.iterdir())})
        assert sys.path == before_path
        print("EXPORTED_SANITIZED_CLOSED_RECORDS", flush=True)
    finally:
        for name in names:
            sys.modules.pop(name, None)
        assert sys.path == before_path


if __name__ == "__main__":
    main()
