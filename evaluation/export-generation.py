#!/usr/bin/env python3
"""Export the reviewed historical A5 snapshot receipts without running tools.

The input metadata must be independently reviewed. This reporting adapter does
not qualify source, toolchain, model semantics, or a future frontend by itself.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import sys

if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")

MATERIAL = Path(__file__).resolve().parent / "reproductions/generation-private"
MATERIAL_SHA256 = "4f07ff95576debeeb8879e4b869cd47b0c9b719c9ae17d549cedbe77100bb9a6"
HELPER_SHA256 = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(524288), b""):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def table(path, rows):
    with path.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, sort_keys=True, separators=(",", ":"))
                             if isinstance(value, (dict, list)) else value
                             for key, value in row.items()})


def exact_timed_output(actual, template):
    assert template.count("${ELAPSED}") == 1
    pattern = re.escape(template).replace(re.escape("${ELAPSED}"), r"[0-9]+\.[0-9]{2}")
    assert re.fullmatch(pattern, actual)


def export(inputs, output):
    assert sha(MATERIAL / "files.json") == MATERIAL_SHA256
    for name, expected in read(MATERIAL / "files.json").items():
        assert Path(name).name == name and sha(MATERIAL / name) == expected
    reconstruction, inventory = read(MATERIAL / "reconstruction.json"), read(MATERIAL / "inventory.json")
    assert inputs["source_files"] == {"preformat_snapshot": reconstruction["before_format"], "formatted_snapshot": reconstruction["formatted"]}
    for path, expected in inputs["raw_files"].items():
        assert sha(path) == expected
    order = ["format", "compile", "list", "models", "clippy", "docs", "msrv"]
    assert [row["id"] for row in inputs["command_receipts"]] == order
    commands, captures = [], {}
    for spec in inputs["command_receipts"]:
        name = spec["id"]
        request, result = read(spec["request"]), read(spec["receipt"])
        assert result["request_sha256"] == sha(spec["request"])
        assert result["helper_sha256"] == HELPER_SHA256
        assert result["exit"] == 0 and result["wall_timeout"] is False
        assert result["absence_proof"] == "ECHILD" and result["unexpected_descendants"] == []
        assert result["cleanup_events"] == [] and result["cleanup_error"] is None
        assert result["aborted"] is None and result["inputs_unchanged"] is True
        assert math.isfinite(result["elapsed_seconds"]) and result["elapsed_seconds"] >= 0
        for kind in ("stdout", "stderr"):
            assert sha(request[kind]) == result[kind + "_sha256"]
        captures[name] = {kind: Path(request[kind]).read_text() for kind in ("stdout", "stderr")}
        limits = (20, 30, 16777216) if name == "format" else (20, 30, 1048576) if name in ("list", "models") else (60, 90, 134217728)
        assert tuple(request[key] for key in ("cpu_seconds", "wall_seconds", "file_bytes")) == limits

        def substitute(value):
            if isinstance(value, dict):
                return {key: substitute(item) for key, item in value.items()}
            if isinstance(value, list):
                return [substitute(item) for item in value]
            if isinstance(value, str):
                for old, public in sorted(spec["path_substitutions"].items(), key=lambda item: -len(item[0])):
                    assert Path(old).is_absolute() and public.startswith("${")
                    value = value.replace(old, public)
            return value

        public = substitute(request)
        assert public == read(MATERIAL / "request-templates.json")[name]
        expected_source = "preformat_snapshot" if name == "format" else "formatted_snapshot"
        assert spec["source_id"] == expected_source
        if name in ("list", "models"):
            assert sha(request["argv"][0]) == inputs["expected_model_binary_sha256"]
        commands.append(dict(id=name, source_id=expected_source, environment=public["env"], status="pass",
                             argv=public["argv"], cpu_seconds=limits[0], wall_seconds=limits[1], file_bytes=limits[2],
                             elapsed_seconds=result["elapsed_seconds"], exit=0, cleanup="ECHILD_zero_descendants",
                             receipt_sha256=sha(spec["receipt"]), stdout_sha256=result["stdout_sha256"], stderr_sha256=result["stderr_sha256"]))
    assert captures["format"] == {"stdout": "", "stderr": ""}
    for name in ("list", "models"):
        assert captures[name]["stderr"] == ""
    assert captures["list"]["stdout"] == (MATERIAL / "list.stdout").read_text()
    exact_timed_output(captures["models"]["stdout"], (MATERIAL / "models.stdout-template").read_text())
    exact_timed_output(captures["docs"]["stdout"], (MATERIAL / "docs.stdout-template").read_text())
    for name in ("compile", "clippy", "msrv"):
        records = [json.loads(line) for line in captures[name]["stdout"].splitlines()]
        assert records and records[-1] == {"reason": "build-finished", "success": True}
        assert all(row["reason"] == "compiler-artifact" for row in records[:-1])
    cases = [dict(ordinal=i, command_id="models", case_id=name, kind="generation_model", expected="success", observed="success")
             for i, name in enumerate(inventory["model_names"])]
    assert len(cases) == 17
    for row in inventory["compile_fail"]:
        cases.append(dict(ordinal=len(cases), command_id="docs", case_id=row["id"], kind="ownership_compile_fail", expected=row["code"], observed=row["code"]))
    assert len(cases) == 19 and cases == inputs["expected_case_inventory"]
    metadata = inputs["metadata"]
    assert metadata["tested_revision"] is None and metadata["complete_A5"] is False
    assert metadata["preemption_clock_claim"] is False and metadata["frontend_activated"] is False
    assert [row["status"] for row in metadata["claims"]] == ["unqualified"] * 4
    assert metadata["totals"] == {"commands": 7, "model_tests_passed": 17, "model_tests_failed": 0,
                                 "model_tests_ignored": 0, "ownership_compile_fail_passed": 2,
                                 "ownership_compile_fail_failed": 0, "ownership_compile_fail_ignored": 0}
    report = dict(metadata, schema_version=1, commands=commands, cases=cases,
                  timing_class="operational_diagnostics_not_performance_benchmarks",
                  private_capture_manifest_sha256=hashlib.sha256(json.dumps(inputs["raw_files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    public = json.dumps(report) + json.dumps(inputs["source_files"])
    for token in inputs["private_tokens"]:
        assert token not in public
    assert not output.exists()
    output.mkdir()
    write(output / "summary.json", report)
    write(output / "source-files.json", inputs["source_files"])
    table(output / "commands.csv", commands)
    table(output / "cases.csv", cases)
    write(output / "files.json", {p.name: sha(p) for p in sorted(output.iterdir())})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert sha(args.inputs) == args.inputs_sha256
    export(read(args.inputs), args.output)
