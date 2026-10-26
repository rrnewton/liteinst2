#!/usr/bin/env python3
"""Summarize fixed, closed audit/collector records; execute no subprocesses."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

RUNS = [
    ("elf-exec-tactics-audit-run-v3", 1, 1,
     "806336d1d0e43087c6bfcd5eef17348372703bf10ced6ddf4216b3443f1c027c"),
    ("elf-exec-tactics-audit-run-v4", 0, 0,
     "15701346bc05e7e423b6df478ec16664367771b10f7d9a36e29708120c74c369"),
    ("elf-exec-tactics-history-run-v1", 0, 0,
     "559b54bbd2326c501cf45a08b0238beffebcd43083be3411250468d15087ce8c"),
    ("elf-exec-tactics-collect-run-v3", 0, 1,
     "b36f2ae7aa95034be5223d90377ad53ad3e16f5b32ca81de21c4b55401b77532"),
    ("elf-exec-tactics-collect-run-v3b", 0, 0,
     "b36f2ae7aa95034be5223d90377ad53ad3e16f5b32ca81de21c4b55401b77532"),
]
REVISION = "e6243a862fda2572304cccbcfe698ac9ea6212a6"


def main():
    assert not sys.flags.optimize
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo, output = args.repo, args.output
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert output.is_absolute() and output.parent.resolve(strict=True) == output.parent
    assert output.is_relative_to(repo / "ignored") and not output.exists()
    raw = repo / "ignored/a3"
    inputs = {}

    def read(path):
        assert path.resolve(strict=True) == path and path.is_file()
        assert path.is_relative_to(raw) and path.stat().st_size <= 16 * 1024 * 1024
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        key = str(path.relative_to(repo))
        assert inputs.get(key, digest) == digest
        inputs[key] = digest
        return data

    def js(path):
        return json.loads(read(path))

    rows = []
    recorded_repo = None
    for name, child_exit, wrapper_exit, source_hash in RUNS:
        directory = raw / name
        request = js(directory / "request.json")
        assert request["argv"][:2] == ["/usr/bin/python3", "-B"]
        assert request["timeout_seconds"] == 60
        assert request["env"] == dict(PATH="/usr/bin:/bin", LC_ALL="C", PYTHONDONTWRITEBYTECODE="1")
        owner = request["cwd"]
        assert recorded_repo in (None, owner)
        recorded_repo = owner
        script = Path(request["argv"][2]).relative_to(owner)
        assert hashlib.sha256(read(repo / script)).hexdigest() == source_hash
        wrapper_failure = name == "elf-exec-tactics-collect-run-v3"
        if wrapper_failure:
            assert not (directory / "result.json").exists()
            result = js(directory / "root-observation.json")
            assert result["collector_returncode"] == child_exit
            assert result["root_wrapper_exit"] == wrapper_exit
            assert result["closed_reaped"] is True
            elapsed = result["collector_elapsed_seconds"]
            assert elapsed is None
        else:
            result = js(directory / "result.json")
            assert result["returncode"] == child_exit
            assert result["subprocess_run_returned"] is True
            elapsed = result["elapsed_seconds"]
            assert type(elapsed) in (float, int) and 0 <= elapsed <= 60
        for stream in ("stdout", "stderr"):
            assert hashlib.sha256(read(directory / (stream + ".txt"))).hexdigest() == result[stream + "_sha256"]
        rows.append(dict(run=name, script_sha256=source_hash, script_tested_revision=None,
                         command=request, result=result, child_exit=child_exit,
                         root_wrapper_exit=wrapper_exit, operational_seconds=elapsed))

    # Replace only the recorded repository owner, retaining an exact inverse.
    def clean(value):
        if isinstance(value, str):
            assert "${RECORDED_REPO}" not in value
            public = value.replace(recorded_repo, "${RECORDED_REPO}")
            assert public.replace("${RECORDED_REPO}", recorded_repo) == value
            return public
        if isinstance(value, list):
            return [clean(x) for x in value]
        if isinstance(value, dict):
            return {clean(k): clean(v) for k, v in value.items()}
        return value

    audit_path = raw / "elf-exec-tactics-e6243a8-v1/runtime-audit-tactics-v1/audit.json"
    audit_bytes = read(audit_path)
    assert hashlib.sha256(audit_bytes).hexdigest() == "9c2fa534b86ec6bb4b300b121f3c879a913a5035ee51a452121e4b924739034e"
    audit = json.loads(audit_bytes)
    assert audit["source_revision"] == REVISION and audit["qualification_complete"] is False
    tests = raw / "elf-exec-e6243a8-v1/required/review-test-counts-baseline-v1"
    binding, groups, nested = [js(tests / n) for n in ("binding.json", "groups.json", "nested.json")]
    assert binding["tested_revision"] == REVISION and binding["outer"] == [70, 1175, 0, 4]
    assert len(groups) == 70
    assert [sum(g[k] for g in groups) for k in ("passed", "failed", "ignored")] == [1175, 0, 4]
    assert len(nested) == 7 and sum(n["passed"] == 1 for n in nested) == 5
    hardware = js(raw / "elf-exec-tactics-e6243a8-v1/hardware.json")
    summary = dict(schema=1, campaign_revision=REVISION, records=clean(rows),
                   audit_totals=audit["totals"], audit_sha256=hashlib.sha256(audit_bytes).hexdigest(),
                   required_test_counts=dict(outer_groups=70, passed=1175, failed=0, ignored=4,
                                             nested_completed=5, uncredited_guard_starts=2,
                                             groups=groups, nested=nested),
                   hardware=dict(hardware, host_label="AMD EPYC Zen 5 dev host"),
                   hardware_scope="Saved campaign context, not continuous hardware attestation for postprocessing",
                   root_outcome_authority="Root exec/write_stdin observations; no independent parent receipt is invented",
                   timing_scope="Operational diagnostics only; wrapper failure has no retained child duration",
                   collector_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   collector_tested_revision=None, qualification_complete=False)
    texts = {"postprocessing.json": json.dumps(summary, indent=2, sort_keys=True) + "\n"}
    stream = io.StringIO(newline="")
    columns = ["run", "script_sha256", "child_exit", "root_wrapper_exit", "operational_seconds"]
    writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows({k: row[k] for k in columns} for row in rows)
    texts["postprocessing.csv"] = stream.getvalue()
    for text in texts.values():
        assert not re.search(r"/home/|/Users/|(?:facebook|meta|fb)\.com|\.internal\b|\bdev(?:big|vm|box|gpu)[A-Za-z0-9_.-]+", text)
    for name, digest in list(inputs.items()):
        assert hashlib.sha256(read(repo / name)).hexdigest() == digest
    output.mkdir()
    for name, text in texts.items():
        with (output / name).open("x") as stream:
            stream.write(text)
    with (output / "private-binding.json").open("x") as stream:
        json.dump(dict(recorded_repo=recorded_repo, inputs=inputs), stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
