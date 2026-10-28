#!/usr/bin/env python3
"""Pure, hash-bound TRACE/VMOV publication; never runs a workload or a validator."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def selected(value, keys):
    return {key: value[key] for key in keys if key in value}


TOP = """profile group status scope started_utc cpu reproduce source_unchanged
configuration_unchanged failure_type final_error_count cleanup_complete totals
required_cases attempted_cases accepted_cases completed_cases expected_refusals
required_finite_commands finite_command_count cohort_command_count ls_diagnostic
failed_commands timing_scope build_status register_build_status finite_build_status
required_cohort_commands required_native_processes attempted_native_processes
command_count case_count catalogue old_negative_operations_completed
interval_scope whole_process_scope qualification programs workload selection
selected_configuration timing""".split()
CASE = """name accepted classification process_outcome actual_exit native_exit
gated_exit operation_completed verified_memory_fault verified_native_fault
verified_pre_open_refusal status environment environment_delta expected_operation
exit counters outcome register cache_counts chain last_opcode repeat whole_process_ns
first_touch_ns steady_state_ns header record""".split()
MAPS = """name accepted actual_exit operation_completed operation_failed mode events
actual_signals adapter_injections source_changes supplied_state_injections record""".split()
CHECK = """id argv environment_delta seconds timeout_seconds status exit_code
termination cleanup_complete reaped_descendants tests_passed harness_totals
private_log_sha256""".split()
COMMAND_COLUMNS = ["name", "profile", "exit", "expected_exit", "timed_out", "reaped",
                   "cleanup_error_count"]
PROFILES = {"page-selected-" + suffix for suffix in (
    "chain-oracle-v1", "chain-real-v1", "vmovdqu64-oracle-v1", "vpbroadcast-oracle-v1",
    "generic-oracle-v1", "maps-v1", "register-controls-v1", "register-connected-v1",
    "register-time-v1")} | {"inprocess-required-checks-v1"}


def project(input_path):
    raw = input_path.read_bytes()
    inputs = json.loads(raw)
    helper = Path("evaluation/inprocess/summarize_selected.py")
    if sha(helper.read_bytes()) != inputs["summary_reader_sha256"]:
        raise ValueError("summary reader changed")
    spec = importlib.util.spec_from_file_location("projection_reader", helper)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    inputs = json.loads(raw, object_pairs_hook=reader.unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite input")))
    tables = {key: [] for key in ("sources", "hardware", "environments", "tools", "tool_files", "bounds", "scopes",
                                  "observation_keys", "observations", "operation_commands")}

    def intern(key, value):
        if value not in tables[key]:
            tables[key].append(value)
        return tables[key].index(value)

    runs, preflights, seen = [], [], set()
    for supplied in inputs["receipts"]:
        name = supplied["name"]
        if Path(name).name != name or name in seen:
            raise ValueError("receipt basename/duplicate")
        seen.add(name)
        path = Path("evaluation/inprocess/results") / name
        data, receipt = reader.read(path)
        if len(data) != supplied["bytes"] or sha(data) != supplied["sha256"]:
            raise ValueError("receipt changed: " + name)
        if receipt["profile"] not in PROFILES:
            raise ValueError("unreviewed publication profile")
        actual = receipt["source"]["revision"]
        if not re.fullmatch("[0-9a-f]{40}", actual):
            raise ValueError("exact observed revision required")
        mismatch = receipt["expected_revision"] != actual
        if mismatch != (supplied["kind"] == "source_guard_failure"):
            raise ValueError("source-guard failure must be separate")
        if mismatch and (receipt["status"] != "failed" or receipt["command_count"] != 0
                         or receipt.get("cases")):
            raise ValueError("unexpected source-guard prefix")
        row = selected(receipt, TOP)
        if "scope" in row:
            row["scope_index"] = intern("scopes", row.pop("scope"))
        row["receipt"] = {"name": name, "bytes": len(data), "sha256": sha(data)}
        row["expected_revision"] = receipt["expected_revision"]
        row["source_index"] = intern("sources", receipt["source"])
        hw = dict(receipt["hardware"]) if receipt["hardware"] is not None else None
        if hw is not None and "probe_cpu" in hw:
            row["probe_cpu"] = hw.pop("probe_cpu")
        if hw is not None and "affinity_cpu_count" in hw:
            row["affinity_cpu_count"] = hw.pop("affinity_cpu_count")
        row["hardware_index"] = intern("hardware", hw)
        for key, table in (("environment", "environments"), ("bounds", "bounds")):
            if key in receipt:
                row[table + "_index"] = intern(table, receipt[key])
        tools = selected(receipt, ("tool_versions", "tool_hashes", "toolchain"))
        if "tool_hashes" in tools:
            hashes = tools.pop("tool_hashes")
            tools["tool_file_indices"] = {key: intern("tool_files", value) for key, value in hashes.items()}
            if {key: tables["tool_files"][index] for key, index in tools["tool_file_indices"].items()} != hashes:
                raise ValueError("tool interning changed bindings")
        row["tools_index"] = intern("tools", tools)
        row["evidence"] = selected(receipt, ("private_receipt", "commands_sha256",
                                             "command_rows_sha256"))
        for key in ("interpretation",):
            if key in receipt:
                row[key] = receipt[key]
        if "cases" in receipt:
            if receipt["profile"] in ("page-selected-chain-oracle-v1", "page-selected-vmovdqu64-oracle-v1"):
                row["cases"] = receipt["cases"]  # Complete new observations, including failures.
            else:
                row["cases"] = [selected(case, CASE) for case in receipt["cases"]]
        if "maps_cases" in receipt:
            row["maps_cases"] = [selected(case, MAPS) for case in receipt["maps_cases"]]
            row["old_negative_cases"] = receipt["old_negative_cases"]
        if "native_commands" in receipt:
            row["native_commands"] = [selected(command, (
                "name", "environment_delta", "exit", "expected_exit", "timed_out", "reaped",
                "cleanup_error_count", "duration_ns")) for command in receipt["native_commands"]]
        if receipt["profile"] == "inprocess-required-checks-v1":
            row["commands"] = [{key: value for key, value in command.items()
                                if key in CHECK or key.endswith("_count")}
                               for command in receipt["commands"]]
        elif "private_receipt" in receipt:
            private_path = Path("target/evaluation/inprocess") / path.stem / "receipt.json"
            private_data, private = reader.read(private_path)
            binding = receipt["private_receipt"]
            if len(private_data) != binding["bytes"] or sha(private_data) != binding["sha256"]:
                raise ValueError("private command receipt changed")
            if private["status"] != receipt["status"] or private["source"]["revision"] != actual:
                raise ValueError("private/public status/source mismatch")
            if private["expected_revision"] != receipt["expected_revision"]:
                raise ValueError("private/public requested revision mismatch")
            commands = private["commands"]
            if mismatch and commands:
                raise ValueError("source guard unexpectedly issued a command")
            outcomes = []
            for command in commands:
                if command["profile"] in ("native", "program") or command.get("exit") not in (0,):
                    values = selected(command, COMMAND_COLUMNS)
                    values["cleanup_error_count"] = len(command.get("cleanup_errors", []))
                    outcomes.append([values.get(key) for key in COMMAND_COLUMNS])
            row["operation_commands_index"] = intern("operation_commands", outcomes)
        # Lossless interning of repeated finite observations; keep each actual
        # record binding on its run. No values are recomputed or normalized.
        for field in ("cases", "maps_cases", "old_negative_cases"):
            if field in row:
                references = []
                for observation in row[field]:
                    common = {key: value for key, value in observation.items() if key != "record"}
                    keys = sorted(common)
                    packed = [intern("observation_keys", keys)] + [common[key] for key in keys]
                    ref = [intern("observations", packed)]
                    if "record" in observation:
                        record = observation["record"]
                        if record is None:
                            ref.append(None)
                        elif set(record) == {"bytes", "sha256"}:
                            ref.extend((record["bytes"], record["sha256"]))
                        else:
                            raise ValueError("unreviewed record binding fields")
                    stored = tables["observations"][ref[0]]
                    restored = dict(zip(tables["observation_keys"][stored[0]], stored[1:], strict=True))
                    if len(ref) == 2:
                        restored["record"] = None
                    elif len(ref) == 3:
                        restored["record"] = {"bytes": ref[1], "sha256": ref[2]}
                    if restored != observation:
                        raise ValueError("observation interning changed values")
                    references.append(ref)
                row[field] = references
        (preflights if mismatch else runs).append(row)
    return {"schema_version": 1, "profile": "trace-vmov-milestone-v1",
            "scope": "Projection of original evaluator receipts; no new validation or performance verdict.",
            "projection_script_sha256": sha(Path(__file__).read_bytes()),
            "input_manifest_sha256": sha(raw), "summary_reader_sha256": inputs["summary_reader_sha256"],
            "command_scope": "Exact evaluator reproduction argv retained; actual argv/captures bound by original command/private-receipt hashes. Operation rows retain native/program and every unsuccessful command.",
            "operation_command_columns": COMMAND_COLUMNS,
            "observation_layout": "Observation rows are [key_table_index,value...]. Case references are [observation_index], [index,null] for record:null, or [index,record_bytes,record_sha256]. Restore record only when present. Hardware probe_cpu/affinity_cpu_count are per-run.",
            "omitted_detail": "Earlier maps acquisition snapshots, remaining artifact manifests and full records remain in the hash-bound original receipts; operation labels/counts are retained here.",
            "tables": tables, "runs": runs, "source_guard_failures": preflights}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = project(args.inputs)
    data = (compact(value) + "\n").encode()
    if re.search(rb"/home/|devbig[0-9]+|internalfb\.com", data):
        raise ValueError("private-location marker")
    if len(data) > 90000:
        raise ValueError("projection exceeds 90,000-byte budget; do not silently omit observations")
    with args.output.open("xb") as output:
        output.write(data)
    print(compact({"runs": len(value["runs"]), "preflights": len(value["source_guard_failures"]),
                   "bytes": len(data), "sha256": sha(data)}))


if __name__ == "__main__":
    main()
