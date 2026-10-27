#!/usr/bin/env python3
"""Compact numeric publication of existing selected-mode evaluator receipts.

This is a projection, not a validation gate. Run the original evaluators first;
their exact receipts remain hash-bound. Failed operations retain their labels.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read(path):
    data = path.read_bytes()
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    return data, value


def summarize(paths, revision):
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("exact revision required")
    tables = {name: [] for name in ("hardware", "environments", "tools", "bounds")}

    def intern(name, value):
        if value not in tables[name]:
            tables[name].append(value)
        return tables[name].index(value)

    source = None
    rows, identities = [], set()
    for path in paths:
        data, receipt = read(path)
        if receipt["expected_revision"] != revision or receipt["source"]["revision"] != revision:
            raise ValueError("mixed source revisions")
        if source is None:
            source = receipt["source"]
        if source != receipt["source"]:
            raise ValueError("mixed source manifests")
        identity = (receipt["profile"], receipt.get("group"))
        if identity in identities:
            raise ValueError("duplicate run profile/group")
        identities.add(identity)
        row = {key: receipt[key] for key in (
            "profile", "group", "status", "scope", "started_utc", "cpu", "reproduce",
            "source_unchanged", "configuration_unchanged", "failure_type", "final_error_count",
            "totals", "required_cases", "attempted_cases", "accepted_cases", "completed_cases",
            "expected_refusals", "required_finite_commands", "finite_command_count", "cohort_command_count",
            "ls_diagnostic", "failed_commands", "timing_scope", "build_status",
            "register_build_status", "required_cohort_commands") if key in receipt}
        row["receipt"] = {"name": path.name, "bytes": len(data), "sha256": digest(data)}
        environment = receipt.get("environment")
        if environment is None:
            if receipt["profile"] != "page-selected-register-real-v1":
                raise ValueError("missing receipt environment")
            environment = {"per_workload": {c["name"]: c["environment"] for c in receipt["cases"]}}
            if len(environment["per_workload"]) != len(receipt["cases"]):
                raise ValueError("duplicate workload environment")
        for table, value in (
            ("hardware", receipt["hardware"]), ("environments", environment),
            ("tools", receipt.get("tool_versions", receipt.get("toolchain"))),
            ("bounds", receipt.get("bounds"))):
            row[table + "_index"] = intern(table, value)
        commands = receipt.get("commands", [])
        if "command_count" in receipt:
            row["command_count"] = receipt["command_count"]
        elif isinstance(commands, list):
            row["command_count"] = len(commands)
        elif isinstance(commands, dict) and type(commands.get("attempted")) is int:
            row["command_count"] = commands["attempted"]
            row["command_summary"] = commands
        else:
            raise ValueError("unknown command inventory")
        if "native_commands" in receipt:
            row["native_commands"] = [{k: c[k] for k in (
                "name", "exit", "expected_exit", "timed_out", "reaped", "cleanup_error_count")
                if k in c} for c in receipt["native_commands"]]
        if "cases" in receipt:
            row["cases"] = [{k: c[k] for k in (
                "name", "accepted", "classification", "process_outcome", "actual_exit",
                "native_exit", "gated_exit", "operation_completed",
                "verified_memory_fault", "verified_native_fault", "verified_pre_open_refusal",
                "status", "environment", "counters", "outcome", "register", "cache_counts",
                "last_opcode", "repeat", "whole_process_ns", "first_touch_ns", "steady_state_ns")
                if k in c} for c in receipt["cases"]]
        if receipt["profile"] == "inprocess-required-checks-v1":
            row["commands"] = [{k: v for k, v in c.items() if k in (
                "id", "argv", "environment_delta", "seconds", "timeout_seconds", "status",
                "exit_code", "termination", "cleanup_complete", "reaped_descendants",
                "tests_passed", "harness_totals", "private_log_sha256") or k.endswith("_count")}
                for c in receipt["commands"]]
        rows.append(row)
    if not rows:
        raise ValueError("at least one receipt required")
    return {"schema_version": 1, "profile": "selected-milestone-summary-v1",
            "scope": "Numeric projection of original evaluator receipts; no new qualification or performance claim.",
            "source": source, "summary_script_sha256": digest(Path(__file__).read_bytes()),
            "tables": tables, "runs": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("receipts", nargs="+", type=Path)
    args = parser.parse_args()
    value = summarize(args.receipts, args.revision)
    data = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if re.search(r"/home/|devbig[0-9]+|internalfb\.com", data):
        raise ValueError("private-location marker in public summary")
    with args.output.open("x") as output:
        output.write(data)
    print(json.dumps({"runs": len(value["runs"]), "bytes": len(data.encode()),
                      "sha256": digest(data.encode())}))


if __name__ == "__main__":
    main()
