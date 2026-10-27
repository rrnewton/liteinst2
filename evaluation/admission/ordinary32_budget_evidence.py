#!/usr/bin/env python3
"""Extract one authenticated failed ordinary32 snapshot; never qualify a run."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys

CASE = ("linux::remote::dynamic::owner::admission::runtime::ordinary::"
        "native_tests::thirtytwo::"
        "runtime_ordinary_thirty_two_nops_fit_default_budget_and_retain_exact_history")
AXES = ("epochs", "source_fact_bytes", "reports", "origins", "witnesses", "plan_history")
COMMAND_IDS = ("recorder_tests", "fmt", "clippy", "workspace_tests", "workspace_check",
               "serial_launch")
HEX = r"[0-9a-f]{64}"
NUMBER = r"(?:0|[1-9][0-9]*)"
MAX_INPUT = 8 * 1024 * 1024


class InvalidEvidence(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise InvalidEvidence(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: require(False, "nonfinite_json_number"))


def read_bounded(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_INPUT + 1)
    require(len(data) <= MAX_INPUT, "input_too_large")
    return data


def counter(text):
    value = int(text)
    require(value <= (1 << 64) - 1, "counter_overflow")
    return value


def hardware_projection(value):
    text_fields = ("vendor_id", "model_name", "cpu_family", "model", "stepping", "microcode")
    bool_fields = ("effective_uid_is_root", "cap_sys_ptrace", "cap_sys_admin")
    int_fields = ("logical_cpus_visible", "affinity_cpu_count", "effective_capabilities")
    extra = ("architecture", "isa_flags", "kernel_upstream_version", "kernel_release_sha256",
             "ptrace_scope", "ptrace_scope_status")
    require(type(value) is dict and set(value) == set(text_fields + bool_fields + int_fields + extra),
            "hardware_shape")
    for name in text_fields:
        require(type(value[name]) is str and re.fullmatch(r"[A-Za-z0-9 ()_.+-]{1,160}", value[name]),
                "hardware_text")
    require(all(type(value[name]) is bool for name in bool_fields), "hardware_boolean")
    require(all(type(value[name]) is int and 0 <= value[name] < 1 << 64 for name in int_fields),
            "hardware_integer")
    require(1 <= value["affinity_cpu_count"] <= 8 and value["logical_cpus_visible"] >= 1,
            "hardware_affinity")
    require(value["architecture"] == "x86_64", "hardware_architecture")
    flags = value["isa_flags"]
    require(type(flags) is list and flags == sorted(set(flags))
            and all(type(flag) is str and re.fullmatch(r"[a-z0-9_]{1,80}", flag) for flag in flags),
            "hardware_flags")
    require(type(value["kernel_upstream_version"]) is str
            and re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", value["kernel_upstream_version"]),
            "hardware_kernel")
    require(type(value["kernel_release_sha256"]) is str
            and re.fullmatch(HEX, value["kernel_release_sha256"]), "hardware_kernel_hash")
    scope = value["ptrace_scope"]
    require((value["ptrace_scope_status"] == "observed" and type(scope) is int and 0 <= scope <= 3)
            or (value["ptrace_scope_status"] in ("interface_absent", "unreadable") and scope is None),
            "hardware_ptrace_scope")
    return value


def extract(receipt_bytes, capture_bytes, expected_receipt, revision):
    require(re.fullmatch(HEX, expected_receipt) and re.fullmatch(r"[0-9a-f]{40}", revision),
            "invalid_pin")
    require(digest(receipt_bytes) == expected_receipt, "receipt_digest")
    receipt = decode(receipt_bytes)
    require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
            and receipt["experiment"] == "admission-validation"
            and receipt["status"] == "failed" and receipt["complete_claims_established"] == []
            and receipt["performance_claim"] is None, "receipt_not_failed_validation")
    require(receipt["source_unchanged"] is True and receipt["configuration_unchanged"] is True,
            "changed_run_inputs")
    source = receipt["source"]
    require(source["revision"] == revision and source["tracked_clean"] is True
            and source["head_sources_match"] is True
            and source["tracked_diff_sha256"] == digest(b""), "source_identity")
    hashes = source["source_sha256"]
    require(type(hashes) is dict and hashes and all(
        type(path) is str and re.fullmatch(r"[A-Za-z0-9_./+-]+", path)
        and not path.startswith("/") and ".." not in path.split("/")
        and type(value) is str and re.fullmatch(HEX, value) for path, value in hashes.items()),
        "source_hashes")
    require(digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode())
            == source["source_manifest_sha256"], "source_manifest")
    require(re.fullmatch(r"[0-9a-f]{40}", source["tree"]), "source_tree")
    require(receipt["reproduce"] == ["python3", "evaluation/admission/run.py",
                                      "--expect-revision", revision], "original_driver")
    commands = receipt["commands"]
    require(type(commands) is list and [row["id"] for row in commands] == list(COMMAND_IDS),
            "command_identity_sequence")
    require([row["status"] for row in commands]
            == ["passed", "passed", "passed", "failed", "not_run", "not_run"], "failed_prefix")
    workspace = commands[3]
    require(workspace["argv"] == ["cargo", "test", "--workspace"]
            and workspace["timeout_seconds"] == 360 and workspace["exit_code"] == 101
            and workspace["termination"] is None and workspace["cleanup_complete"] is True
            and workspace["evidence_status"] == "incomplete"
            and workspace["parse_error"] == "missing_outer_summary", "workspace_failure")
    require(type(workspace["reaped_descendants"]) is int and workspace["reaped_descendants"] >= 0
            and type(workspace["seconds"]) in (float, int)
            and math.isfinite(workspace["seconds"]) and workspace["seconds"] >= 0,
            "workspace_measurements")
    require(receipt["log_limit_bytes_per_command"] == MAX_INPUT, "capture_limit")
    capture_hash = digest(capture_bytes)
    require(capture_hash == workspace["private_log_sha256"], "capture_digest")
    harnesses = [row for row in workspace["harnesses"] if row["id"] == "unit/liteinst_launch/lib"]
    require(len(harnesses) == 1 and harnesses[0]["status"] == "invalid"
            and harnesses[0]["outer"] is None
            and type(harnesses[0]["expected_tests"]) is int
            and harnesses[0]["expected_tests"] == harnesses[0]["declared_outer_tests"]
            and harnesses[0]["expected_ignored"] == 0, "owning_harness")
    text = capture_bytes.decode("utf-8")
    lines = text.splitlines()
    indices = [i for i, line in enumerate(lines) if line.startswith("runtime isolated case ")]
    require(len(indices) == 1, "isolated_failure_count")
    index = indices[0]
    require(lines[index] == 'runtime isolated case "' + CASE + '" failed: '
            'isolated child did not exit normally with zero: signal=17, code=1, status=101, '
            'expected_pid=true', "isolated_case_identity")
    require(sum(line.startswith("isolated stdout prefix: ") for line in lines) == 1
            and sum(line.startswith("isolated stderr prefix: ") for line in lines) == 1,
            "isolated_capture_count")
    require(lines[index + 1].startswith("isolated stdout prefix: ")
            and lines[index + 2].startswith("isolated stderr prefix: ")
            and lines[index + 3] == "runtime isolation failed closed; direct child reaped=true",
            "isolated_capture_association")
    stdout = decode(lines[index + 1].removeprefix("isolated stdout prefix: "))
    stderr = decode(lines[index + 2].removeprefix("isolated stderr prefix: "))
    require(type(stdout) is str and type(stderr) is str and stdout.isascii() and stderr.isascii()
            and len(stdout) < 8192 and len(stderr) < 8192, "isolated_capture_encoding")
    require(stdout.splitlines().count("running 1 test") == 1
            and stdout.splitlines().count("test " + CASE + " ... FAILED") == 1
            and stdout.count('called `Result::unwrap()` on an `Err` value: '
                             'Refused("dynamic continuation lifetime capacity exhausted")') == 1,
            "isolated_failure_outcome")
    summaries = re.findall(r"^test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; "
                           r"([0-9]+) filtered out; finished in [0-9]+\.[0-9]+s$", stdout, re.M)
    require(len(summaries) == 1 and counter(summaries[0]) + 1 == harnesses[0]["expected_tests"],
            "isolated_failure_summary")
    require(text.count("ordinary32 failure before cleanup:") == 1
            and text.count("ordinary32 census (limits,charged,used,remaining):") == 1,
            "diagnostic_count")
    diagnostic = stderr.splitlines(keepends=True)
    require(len(diagnostic) == 2 and all(line.endswith("\n") for line in diagnostic),
            "complete_diagnostic_lines")
    # This version accepts only the fully observed no-pending/last-complete prefix.
    # Other legitimate future failure shapes need their own reviewed extraction.
    first = re.fullmatch(
        r"ordinary32 failure before cleanup: instruction_1based=(" + NUMBER + r") "
        r"checked_prefix=(" + NUMBER + r") runtime_stage=Some\(Ready\) attempts=Some\((" + NUMBER
        + r")\) completed_attempts=Some\((" + NUMBER + r")\) pending_preparation=Some\(false\) "
        r"last_\(stage,failed,unwound,allocated,first_failure\)="
        r"Some\(\(Complete, false, false, true, None\)\)\n", diagnostic[0])
    require(first is not None, "diagnostic_runtime_shape")
    instruction, checked, attempts, complete = map(counter, first.groups())
    require(1 <= instruction <= 32 and checked + 1 == instruction
            and checked == attempts == complete, "diagnostic_prefix_consistency")
    body = ", ".join(re.escape(axis) + r": (" + NUMBER + r")" for axis in AXES)
    budget = re.fullmatch(
        r"ordinary32 census \(limits,charged,used,remaining\): Some\(\(Limits \{ " + body
        + r" \}, BudgetCharge \{ " + body + r" \}, BudgetCharge \{ " + body
        + r" \}, None\)\)\n", diagnostic[1])
    require(budget is not None, "diagnostic_budget_shape")
    values = list(map(counter, budget.groups()))
    limits, charged, used = [dict(zip(AXES, values[i:i + 6])) for i in (0, 6, 12)]
    require(limits == dict(zip(AXES, (256, 64 * 1024 * 1024, 4096, 4096, 4096, 4096))),
            "default_limits_differ")
    require(all(used[axis] <= charged[axis] <= limits[axis] for axis in AXES), "counter_order")
    return {
        "schema_version": 1, "experiment": "ordinary32-budget-failure-supplement",
        "status": "failed", "qualification": False, "fit_established": False,
        "observation_phase": "before_cleanup", "case": CASE,
        "receipt_sha256": expected_receipt, "private_capture_sha256": capture_hash,
        "source": {key: source[key] for key in ("revision", "tree", "source_manifest_sha256")},
        "hardware": hardware_projection(receipt["hardware"]),
        "original_driver": receipt["reproduce"],
        "command": {key: workspace[key] for key in (
            "id", "argv", "status", "exit_code", "termination", "timeout_seconds", "seconds",
            "cleanup_complete", "reaped_descendants", "evidence_status", "parse_error")},
        "following_commands": [{"id": row["id"], "status": row["status"]} for row in commands[4:]],
        "failure": {"kind": "lifetime_capacity_refused", "instruction_1based": instruction,
                    "checked_prefix": checked, "runtime_stage": "Ready", "attempts": attempts,
                    "completed_attempts": complete, "pending_preparation": False,
                    "last_attempt": {"stage": "Complete", "failed": False, "unwound": False,
                                     "allocated": True, "first_failure": None}},
        "budget": {"limits": limits, "charged": charged, "used": used, "remaining": None},
        "unobserved": ["attempted_reservation_charge", "exact_failure_site", "exhausted_axis"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--expect-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = extract(read_bounded(args.receipt), read_bounded(args.capture),
                         args.receipt_sha256, args.expect_revision)
        result["extractor_sha256"] = digest(Path(__file__).read_bytes())
        payload = (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
        # Create once; never overwrite a historical supplementary result.
        with args.output.open("xb") as stream:
            stream.write(payload)
    except (InvalidEvidence, OSError, ValueError, TypeError, KeyError, IndexError, RecursionError) as error:
        code = str(error) if isinstance(error, InvalidEvidence) else "invalid_input_or_output"
        print("ordinary32_evidence_error:" + code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
