#!/usr/bin/env python3
"""Render four fixed historical attempts from saved records; execute no workloads."""
import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import re
import stat
import sys

INPUTS_SHA256 = "0d9e60441582ef88bfeb4e1796c1b870a31a9708cf104c7e6fac837abde90349"
GATES = [("fmt", ["cargo", "fmt", "--check"], 180),
         ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], 180),
         ("test", ["cargo", "test", "--workspace"], 360),
         ("check", ["cargo", "check", "--workspace", "--all-features", "--all-targets"], 180)]
EXPECTED = [(1, 0, 1, 26), (1, 0, 1, 26), (27, 27, 0, 0), (18, 17, 1, 75)]
FAILURES = ["Compiler could not resolve iced_x86 in the including test crate.",
            "Clippy rejected manual_is_multiple_of and collapsible_if in the shared helper.",
            None, "Native-B2 setup expected one generated-image record but found zero, before tracing."]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    assert not sys.flags.optimize, "Assertions required"
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "inputs", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    repo, output = args.repo, args.output
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert args.inputs.resolve(strict=True) == args.inputs and sha(args.inputs.read_bytes()) == INPUTS_SHA256
    spec = json.loads(args.inputs.read_bytes())
    assert output.is_absolute() and output.parent.resolve(strict=True) == output.parent
    assert output.is_relative_to(repo / "ignored") and not output.exists() and not output.is_symlink()
    files = spec["files"]

    def read(name):
        assert name in files and Path(name).parts[:1] == ("ignored",) and ".." not in Path(name).parts
        path = repo / name
        assert path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode)
        assert path.stat().st_size == files[name]["bytes"] <= 128 * 1024 * 1024
        data = path.read_bytes()
        assert sha(data) == files[name]["sha256"]
        return data

    def js(name):
        return json.loads(read(name))

    # Authenticate all frozen raw bytes, without copying logs, captures or ELF files.
    for name in files:
        read(name)
    parents = {x["run"]: x for x in js(spec["parent_observations"])["observations"]}
    assert list(parents) == spec["runs"] and len(parents) == 4
    roles, attempts, stages, commands = {}, [], [], []
    source_revisions = []
    for number, (run, expected) in enumerate(zip(spec["runs"], EXPECTED)):
        root = "ignored/a3/" + run
        assert not output.is_relative_to(repo / root) and not (repo / root).is_relative_to(output)
        launch = js(root + "-launch.json")
        parent = parents[run]
        source = js(root + "/source.json")
        assert source == js(root + "/source-after.json")
        revision = source["revision"]
        assert revision == launch["source_revision"] == parent["source_revision"]
        assert re.fullmatch("[0-9a-f]{40}", revision)
        source_revisions.append(revision)
        assert parent["closed_reaped"] is True and type(parent["parent_exit"]) is int
        assert parent["parent_exit"] == (0 if number == 2 else 1)
        assert parent["launch_log_sha256"] == sha(read(root + "-launch.log"))
        argv = launch["argv"]
        owner = launch["cwd"]
        assert argv[:2] == ["/usr/bin/python3.9", "-B"]
        recipe = "evaluation/elf-exec/" + ("reproduce_tactics.py" if number == 3 else "reproduce.py")
        assert argv[2] == owner + "/" + recipe and source["files"][recipe] == launch["source_sha256"]
        raw_owner = argv[argv.index("--raw") + 1]
        assert raw_owner == owner + "/" + root
        for token, value in (("REPO", owner), ("RAW_" + str(number), raw_owner),
                             ("RAW_REL_" + str(number), root)):
            assert roles.get("${" + token + "}", value) == value
            roles["${" + token + "}"] = value
        for option, token in (("--toolchain", "TOOLCHAIN"), ("--user-home", "USER_HOME"), ("--cargo-home", "CARGO_HOME")):
            value = argv[argv.index(option) + 1]
            assert roles.get("${" + token + "}", value) == value
            roles["${" + token + "}"] = value
        hardware = js(root + "/hardware.json")
        assert set(hardware) == {"cpu_model", "architecture", "logical_cpus", "kernel_release", "libc"}
        assert "AMD EPYC" in hardware["cpu_model"] and hardware["architecture"] == "x86_64"
        assert type(hardware["logical_cpus"]) is int and hardware["logical_cpus"] > 0
        inventory, results = js(root + "/stage-inventory.json"), js(root + "/results.json")
        assert len(set(inventory)) == len(inventory) == (93 if number == 3 else 27)
        assert [r["name"] for r in results] == inventory[:len(results)]
        assert (len(results), sum(r["exit"] == 0 for r in results), sum(r["exit"] != 0 for r in results), len(inventory) - len(results)) == expected
        assert all(type(r["exit"]) is int and r["exit"] == (1 if expected[2] and i == len(results)-1 else 0) for i, r in enumerate(results))
        receipts = {}
        for position, name in enumerate(inventory):
            row = results[position] if position < len(results) else None
            child, elapsed, receipt_digest = None, None, None
            if row is not None:
                command = js(root + "/" + name + "/command.json")
                assert row == js(root + "/" + name + "/result.json") == dict(command, exit=row["exit"], elapsed_seconds=row["elapsed_seconds"])
                elapsed = row["elapsed_seconds"]
                assert type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0
                if name != "required":
                    request_path = root + "/" + name + "/request.json"
                    receipt_path = root + "/" + name + "/receipt.json"
                    receipt = js(receipt_path)
                    assert set(receipt) == {"request_sha256", "helper_sha256", "exit", "wall_timeout", "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256", "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
                    assert receipt["request_sha256"] == sha(read(request_path)) and js(request_path) == row["request"]
                    assert receipt["helper_sha256"] == source["files"]["tools/unwind-oracle/bounded_command.py"]
                    assert receipt["absence_proof"] == "ECHILD" and receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True
                    assert receipt["cleanup_events"] == receipt["unexpected_descendants"] == [] and receipt["cleanup_error"] is None and receipt["aborted"] is None
                    child = receipt["exit"]
                    assert type(child) is int and child == (101 if row["exit"] else 0)
                    assert type(receipt["elapsed_seconds"]) in (int, float) and math.isfinite(receipt["elapsed_seconds"]) and receipt["elapsed_seconds"] >= 0
                    for stream in ("stdout", "stderr"):
                        assert receipt[stream + "_sha256"] == sha(read(root + "/" + name + "/" + stream + ".txt"))
                    helper_result = dict(exit=child, wall_timeout=False, absence_proof="ECHILD", descendants=0, success=child == 0)
                    assert read(root + "/" + name + "/helper.stdout") == (json.dumps(helper_result) + "\n").encode()
                    assert read(root + "/" + name + "/helper.stderr") == b""
                    receipt_digest = files[receipt_path]["sha256"]
                    receipts[name] = receipt_digest
            stages.append(dict(attempt=run, revision=revision, position=position+1, stage=name,
                status="UNRUN" if row is None else ("PASS" if row["exit"] == 0 else "FAILED"),
                recipe_stage_exit=None if row is None else row["exit"], strict_helper_child_exit=child,
                operational_seconds=elapsed, receipt_sha256=receipt_digest))
        commands.append(dict(attempt=run, kind="recipe-parent", status="PASS" if parent["parent_exit"] == 0 else "FAILED",
                             launch_record=launch, closed_parent_observation=parent))
        gate_status = []
        if number != 3:
            gates = js(root + "/required/gates/commands.json")
            assert gates["head"] == revision and gates["source_sha256"] == source["files"] and gates["tracked_diff_sha256"] == sha(b"")
            assert len(gates["records"]) == (4 if number == 2 else 2)
            required = js(root + "/required/command.json")
            for i, (name, argv, wall) in enumerate(GATES):
                actual = gates["records"][i] if i < len(gates["records"]) else None
                status = "UNRUN" if actual is None else ("PASS" if actual["exit"] == 0 else "FAILED")
                if actual:
                    assert (actual["name"], actual["argv"], actual["timeout_seconds"]) == (name, argv, wall)
                    assert actual["sha256"] == sha(read(root + "/required/gates/" + name + ".log"))
                    assert actual["exit"] == (101 if number < 2 and name == "clippy" else 0)
                commands.append(dict(attempt=run, kind="nested-required-gate", name=name, status=status,
                    argv=argv, cwd=owner, env=dict(required["env"], TMPDIR=owner + "/" + root + "/required/gates"),
                    timeout_seconds=wall, saved_result=actual, command_scope="Original fixed command; actual execution only when saved_result is present"))
                gate_status.append(dict(name=name, status=status, exit=None if actual is None else actual["exit"]))
        attempts.append(dict(attempt=run, tested_revision=revision, parent_exit=parent["parent_exit"],
            outcome="PASS_FIXED_B1_CAMPAIGN" if number == 2 else "FAILED", recipe_stages=len(inventory),
            observed_stages=expected[0], passed_stages=expected[1], failed_stages=expected[2], unrun_stages=expected[3],
            failure_stage=None if number == 2 else ("native-B2" if number == 3 else "required/clippy"),
            failure=FAILURES[number], nested_required_gates=gate_status, source_before_after_equal=True,
            source_files=len(source["files"]), source_record_sha256=files[root + "/source.json"]["sha256"],
            hardware=dict(hardware, host_label="AMD EPYC Zen 5 dev host"), strict_helper_receipts=receipts,
            native_original_traces=8 if number == 2 else 0, native_rewritten_traces=16 if number == 2 else 0,
            driver_full_state_comparisons=72 if number == 2 else 0, verified_candidate_artifacts=4 if number >= 2 else 0,
            adjacent_refusal_cases=4 if number == 3 else 0, ordinary_processes=6 if number == 2 else 0,
            artifact_qualification_complete=False, full_A3_complete=False))
    assert source_revisions[2] == source_revisions[3]
    b1 = "ignored/a3/" + spec["runs"][2]
    captures = js(b1 + "/capture-files.json")
    assert len(captures) == 1230 and all(files[b1 + "/captures/" + n]["sha256"] == h for n, h in captures.items())
    complete = dict(x.split("\t") for x in read(b1 + "/captures/complete.tsv").decode().splitlines())
    assert complete == dict(status="passed", original_traces="8", rewritten_traces="16", full_state_comparisons="72", subject_call_ret_witnesses="24", hook_call_return_witnesses="8", recording_hook_rows="4", manual_load_mappings="0", post_seed_state_repairs="0")
    tactic = "ignored/a3/" + spec["runs"][3]
    partial = sorted(n[len(tactic + "/captures-B2/"):] for n in files if n.startswith(tactic + "/captures-B2/"))
    assert partial == sorted(["runtime-target.tsv", "original-unstripped", "original-unstripped.provider", "original-stripped", "original-stripped.provider", "candidate-0", "candidate-0.provider"])
    assert len(js(tactic + "/candidate-files-before-B2.json")) == 4
    assert read(tactic + "/controls-B2/stdout.txt") == b"B2 unknown-entries Refused(7) no-artifact\nB2 source-byte-tamper original-identity\nB2 hook-byte-tamper-rebound-original hook-identity\nB2 selected-placement-unavailable Refused(11) no-artifact\nPASS adjacent tactic refusals: tactic=B2 cases=4 qualification_complete=false\n"
    attempts[2]["capture_files"] = 1230
    attempts[3]["capture_files"] = 7
    for attempt in attempts[:2]:
        attempt["capture_files"] = 0
    inverse = {value: key for key, value in roles.items()}
    pattern = re.compile("|".join(re.escape(v) for v in sorted(inverse, key=len, reverse=True)))
    tokens = re.compile("|".join(re.escape(v) for v in roles))

    def clean(value):
        if isinstance(value, str):
            assert not tokens.search(value)
            result = pattern.sub(lambda m: inverse[m[0]], value)
            assert tokens.sub(lambda m: roles[m[0]], result) == value
            return result
        if isinstance(value, list):
            return [clean(x) for x in value]
        if isinstance(value, dict):
            return {clean(k): clean(v) for k, v in value.items()}
        return value

    history = dict(schema=1, attempts=attempts, summary_scope="Historical saved-record summary; no new architectural capture audit or workload execution",
        parent_authority="Root's separately saved closed/reaped tool observations, not invented parent receipts; original launch pending fields stay unchanged",
        timing_scope="Per-stage operational diagnostics only; parent and nested durations overlap and are not aggregated",
        native_scope="B1's completed 72 driver comparisons belong only to its 377a649 run. Failed tactics has zero traces; verified artifacts and required refusals are not native positives.",
        inputs_sha256=INPUTS_SHA256, collector_tested_revision=None, artifact_qualification_complete=False, full_A3_complete=False)
    texts = {"history.json": json.dumps(clean(history), indent=2, sort_keys=True)+"\n",
             "commands.json": json.dumps(clean(commands), indent=2, sort_keys=True)+"\n"}
    columns = ["attempt", "tested_revision", "outcome", "parent_exit", "observed_stages", "passed_stages", "failed_stages", "unrun_stages", "failure_stage", "native_original_traces", "native_rewritten_traces", "driver_full_state_comparisons", "verified_candidate_artifacts", "adjacent_refusal_cases", "ordinary_processes", "capture_files"]
    for name, rows in (("attempts.csv", [{k:a[k] for k in columns} for a in attempts]), ("stages.csv", stages)):
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader(); writer.writerows(rows); texts[name] = stream.getvalue()
    for text in texts.values():
        assert not re.search(r"/home/|/Users/|(?:facebook|meta|fb)\.com|\.internal\b|\bdev(?:big|vm|box|gpu)[A-Za-z0-9_.-]+", text)
    for name in files:
        read(name)
    output.mkdir()
    for name, text in texts.items():
        with (output / name).open("x") as stream:
            stream.write(text)
    with (output / "files.json").open("x") as stream:
        json.dump({n:sha(t.encode()) for n,t in texts.items()}, stream, indent=2, sort_keys=True); stream.write("\n")
    with (output / "private-binding.json").open("x") as stream:
        json.dump(dict(coordinate_roles=roles, frozen_inputs_sha256=INPUTS_SHA256, raw_files=files,
                       source_sha256=sha(Path(__file__).read_bytes()), tested_revision=None), stream, indent=2, sort_keys=True); stream.write("\n")


if __name__ == "__main__":
    main()
