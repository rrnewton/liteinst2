#!/usr/bin/env python3
"""Read-only Word receipt export. No compiler, native command or module import.

The reviewed private input inventory supplies paths and source-epoch metadata.
The public output contains only relative commands, hashes, counts and IDs.
This reporting adapter does not replace the original architectural auditor.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(512 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def table(path, rows, fields):
    with path.open("x", newline="") as stream:
        out = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        out.writeheader()
        for row in rows:
            out.writerow({key: json.dumps(value, separators=(",", ":"), sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})


def export(inputs, output):
    for path, expected in inputs["raw_files"].items():
        assert sha(path) == expected, "raw identity changed"
    commands, cases = [], []
    def add_case(command, name, kind, expected, observed=None):
        cases.append(dict(ordinal=len(cases), command_id=command, case_id=name, kind=kind, expected=expected, observed=expected if observed is None else observed))
    for spec in inputs["command_receipts"]:
        request, result = read(spec["request"]), read(spec["receipt"])
        assert result["request_sha256"] == sha(spec["request"])
        assert result["helper_sha256"] == "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
        assert sha(request["stdout"]) == result["stdout_sha256"] and sha(request["stderr"]) == result["stderr_sha256"]
        assert math.isfinite(result["elapsed_seconds"]) and result["elapsed_seconds"] >= 0
        clean = result["absence_proof"] == "ECHILD" and result["unexpected_descendants"] == [] and result["cleanup_error"] is None
        passed = clean and result["exit"] == 0 and result["wall_timeout"] is False and result["cleanup_events"] == [] and result["aborted"] is None and result["inputs_unchanged"] is True
        argv = request["argv"]
        for original, public in sorted(inputs["path_substitutions"].items(), key=lambda item: -len(item[0])):
            assert Path(original).is_absolute() and public.startswith("${")
            argv = [arg.replace(original, public) for arg in argv]
        assert not any(re.search(r"(?:^|[=\s])/(?!/)", arg) for arg in argv), "undeclared command path"
        environment = {key: value for key, value in request["env"].items() if key in {"RUSTFLAGS", "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE", "RUST_TEST_THREADS", "LC_ALL", "LANG"}}
        commands.append(dict(id=spec["id"], source_id=spec["source_id"], environment=environment, status="pass" if passed else "fail", argv=argv, cpu_seconds=request["cpu_seconds"], wall_seconds=request["wall_seconds"], file_bytes=request["file_bytes"], elapsed_seconds=result["elapsed_seconds"], exit=result["exit"], cleanup="ECHILD_zero_descendants" if clean else "incomplete", receipt_sha256=sha(spec["receipt"]), stdout_sha256=result["stdout_sha256"], stderr_sha256=result["stderr_sha256"]))
    if inputs.get("required"):
        required = read(inputs["required"])
        expected = [("fmt", ["cargo", "fmt", "--check"], 180), ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], 180), ("test", ["cargo", "test", "--workspace"], 360), ("check", ["cargo", "check", "--workspace", "--all-features", "--all-targets"], 180)]
        assert len(required["records"]) == 4
        assert required["head"] == inputs["metadata"]["tested_revision"]
        assert required["source_sha256"] == inputs["source_files"]["exact_revision"]
        for row, (name, argv, wall) in zip(required["records"], expected):
            assert (row["name"], row["argv"], row["timeout_seconds"], row["exit"]) == (name, argv, wall, 0)
            assert sha(Path(inputs["repository"]) / row["log"]) == row["sha256"]
            commands.append(dict(id="required-" + name, source_id="exact_revision", environment={"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "4", "RUST_TEST_THREADS": "4", "CARGO_NET_OFFLINE": "true"}, status="pass", argv=argv, cpu_seconds=None, wall_seconds=wall, file_bytes=None, elapsed_seconds=row["seconds"], exit=0, cleanup="process_group_runner_no_ECHILD_claim", receipt_sha256=sha(inputs["required"]), stdout_sha256=row["sha256"], stderr_sha256=None))
    if inputs.get("runtime"):
        runtime = Path(inputs["runtime"])
        inventory, plan = read(runtime / "inventory.json"), read(runtime / "plan.json")
        admission = read(inputs["native_admission"])
        assert admission["revision"] == inputs["metadata"]["tested_revision"]
        assert admission["source_files"] == inputs["source_files"]["exact_revision"]
        audit, complete = read(runtime / "run/audit.json"), read(runtime / "run/complete.json")
        assert sha(runtime / "run/audit.json") == complete["audit_sha256"]
        assert sha(runtime / "manifest.json") == complete["manifest_sha256"]
        assert complete["status"] == "COMPLETE_FIXED_COHORT_SCOPED" and complete["complete_A4"] is False
        assert audit["status"] == "FIXED_A4_STRICT_ORACLE_CASES_PASS_SCOPED" and audit["complete_A4"] is False and audit["prior_35_cycles_combined"] is False
        assert audit["totals"] == inventory["totals"] and audit["inventory_sha256"] == sha(runtime / "inventory.json")
        actual = {str(p.relative_to(runtime / "run")): sha(p) for p in (runtime / "run").rglob("*") if p.is_file()}
        assert len(actual) == 103 and actual == dict(complete["files"], **{"complete.json": sha(runtime / "run/complete.json")})
        order = ["baseline-" + x for x in ["positive", "deny-1", "deny-2", "deny-3"]] + ["auditor-calibrations", "calibration-list", "calibrations"] + [m["name"] for m in inventory["native_modes"]]
        assert plan["order"] == order and [r["name"] for r in audit["summaries"]] == order and len(order) == 20
        baseline = read(runtime / "baseline-expected.json")
        for name in order:
            row, = [row for row in commands if row["id"] == "word-" + name]
            assert row["status"] == "pass" and (row["cpu_seconds"], row["wall_seconds"], row["file_bytes"]) == (20, 30, 1048576)
            stdout, stderr = (runtime / "run" / (name + ".stdout")).read_bytes(), (runtime / "run" / (name + ".stderr")).read_bytes()
            assert stderr == b""
            if name.startswith("baseline-"):
                assert stdout == baseline[name.removeprefix("baseline-")].encode()
                add_case(row["id"], name, "baseline", "success" if name == "baseline-positive" else "terminal_barrier_refusal")
            elif name == "auditor-calibrations":
                assert stdout == b"auditor-calibrations accepted=3 rejected=12\n"
                for label in inputs["auditor_acceptances"]: add_case(row["id"], label, "auditor_calibration", "accept")
                for label in inputs["auditor_refusals"]: add_case(row["id"], label, "auditor_calibration", "refuse")
                assert len(inputs["auditor_acceptances"]) == 3 and len(inputs["auditor_refusals"]) == 12
            elif name == "calibration-list":
                names = [r["name"] for r in inventory["calibrations"]]
                assert stdout == ("".join(n + ": test\n" for n in names) + "\n26 tests, 0 benchmarks\n").encode()
            elif name == "calibrations":
                prefix = "\nrunning 26 tests\n"
                for test in inventory["calibrations"]:
                    prefix += "test " + test["name"] + (" - should panic" if test["should_panic"] else "") + " ... ok\n"
                    add_case(row["id"], test["name"], "strict_calibration", "panic" if test["should_panic"] else "success")
                prefix += "\ntest result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in "
                assert re.fullmatch(re.escape(prefix.encode()) + rb"[0-9]+\.[0-9]{2}s\n\n", stdout)
            else:
                mode, = [m for m in inventory["native_modes"] if m["name"] == name]
                assert stdout == ("".join("case " + case + "\n" for case in mode["case_ids"]) + mode["stdout_terminal"] + "\n").encode()
                for case in mode["case_ids"]: add_case(row["id"], case, "native", "exact_state_and_PC")
        assert len([r for r in cases if r["kind"] == "native"]) == 838
        assert len({r["case_id"] for r in cases}) == len(cases)
    report = dict(inputs["metadata"], schema_version=1, commands=commands, cases=cases, timing_class="operational_diagnostics_not_performance_benchmarks", private_capture_manifest_sha256=hashlib.sha256(json.dumps(inputs["raw_files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    public = json.dumps(report) + json.dumps(inputs["source_files"])
    for token in inputs["private_tokens"]: assert token not in public, "private token in output"
    output.mkdir()
    write(output / "summary.json", report)
    write(output / "source-files.json", inputs["source_files"])
    table(output / "commands.csv", commands, list(commands[0]))
    table(output / "cases.csv", cases, ["ordinal", "command_id", "case_id", "kind", "expected", "observed"])
    write(output / "files.json", {p.name: sha(p) for p in sorted(output.iterdir())})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert sha(args.inputs) == args.inputs_sha256
    export(read(args.inputs), args.output)
