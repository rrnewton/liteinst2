"""Fixed emission/native joins using the unchanged bounded-command helper."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys
from bootstrap_validate import need, sha
from common import corrected, relocation_writes, structure
from frozen_profile import fixture_loader_contract
from old_audit import backend_stats, elf64, validate_rpc, validate_helper_receipt
from bounded_stage1 import FailureSignals, capture, helper_command, inventory, write_new
from guard import digest, epoch, identity, read, source

CALIBRATIONS = ("calibrate", "supervisor_calibrate", "calibrate_prerequisites", "calibrate-common", "calibrate-sparse", "calibrate-ledgers")


def bytes_at(row):
    raw = Path(row["path"]).read_bytes()
    need(sha(raw) == row["sha256"], "whole artifact identity")
    if "bytes" in row:
        need(len(raw) == row["bytes"], "whole artifact size")
    return raw


def prepare(here, expected):
    inputs = source(here, expected)
    out = here / "prepared-v1"
    out.mkdir()
    records = {name: identity(name) for name in inputs["runtime_hashes"]}
    need(all(row["sha256"] == inputs["runtime_hashes"][name] for name, row in records.items()), "known runtime bytes only")
    for name in inputs["absent"]:
        need(not Path(name).exists() and not Path(name).is_symlink(), "preload remains absent")
    for name, names in inputs["directory_names"].items():
        need(sorted(p.name for p in Path(name).iterdir()) == names, "known configuration directory inventory")
    write_new(out / "epoch.json", dict(status="PREPARED_REVIEW_REQUIRED_NO_WORKLOAD", source_manifest_sha256=expected,
              files=records, historical_runtime_epoch=inputs["historical_runtime_epoch"],
              identity_observation_only=True, no_automatic_refresh_after_review=True))
    (here / "calibration-run-v1").mkdir()
    requests = {}
    for name in CALIBRATIONS:
        q = dict(argv=[inputs["python"]["path"], "-B", str(here / "entry.py"), name, expected], cwd=str(here),
                 env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
                 stdout=str(here / "calibration-run-v1" / (name + ".stdout")),
                 stderr=str(here / "calibration-run-v1" / (name + ".stderr")),
                 cpu_seconds=20, wall_seconds=30, file_bytes=16777216)
        write_new(out / (name + ".request.json"), q)
        requests[name] = dict(path=str(out / (name + ".request.json")), sha256=digest(out / (name + ".request.json")),
                              receipt=str(here / "calibration-run-v1" / (name + ".receipt.json")))
    write_new(out / "complete.json", dict(status="PREPARED_ONLY_REVIEW_REQUIRED", source_manifest_sha256=expected,
              epoch_sha256=digest(out / "epoch.json"), calibration_requests=requests,
              emission_plan_sha256=digest(here / "emission-plan.json"), files=inventory(out), workload_count=0))
    need(source(here, expected) == inputs, "source stable after preparation")
    print("PREPARED_ONLY_REVIEW_REQUIRED", digest(out / "complete.json"), flush=True)


def admitted(here, expected, prepared_hash):
    prepared = here / "prepared-v1"
    need(digest(prepared / "complete.json") == prepared_hash, "reviewed preparation identity")
    terminal = read(prepared / "complete.json")
    need(terminal["source_manifest_sha256"] == expected and terminal["workload_count"] == 0, "prepared source identity")
    actual = inventory(prepared)
    need(actual == dict(terminal["files"], **{"complete.json": dict(bytes=(prepared / "complete.json").stat().st_size, sha256=prepared_hash)}), "exact prepared tree")
    inputs, observed = epoch(here, expected, prepared / "epoch.json", terminal["epoch_sha256"])
    return inputs, terminal, observed


def calibrations_passed(here, inputs, prepared):
    rows = prepared["calibration_requests"]
    need(list(rows) == sorted(CALIBRATIONS), "fixed five predecessor plus one additive ledger calibration records")
    results = {}
    for name in CALIBRATIONS:
        row = rows[name]
        need(digest(row["path"]) == row["sha256"], "exact actual calibration request")
        qraw = Path(row["path"]).read_bytes()
        q = json.loads(qraw)
        stdout, stderr = capture(Path(q["stdout"])), capture(Path(q["stderr"]))
        validate_helper_receipt(read(row["receipt"]), qraw, inputs["helper"]["sha256"], stdout, stderr)
        wanted = (here / "expected" / (name + ".stdout")).read_bytes()
        need(stdout == wanted and stderr == b"", "full fixed calibration output")
        results[name] = dict(request_sha256=sha(qraw), receipt_sha256=digest(row["receipt"]), stdout_sha256=sha(stdout))
    return results


def structural_case(here, inputs, case, output, rpc):
    return corrected(case, bytes_at(case["original"]), output, rpc, bytes_at(case["frozen_rpc"]),
                     bytes_at(inputs["corrected_loader_bin"]), bytes_at(inputs["corrected_loader_elf"]),
                     inputs["interpreter"], bytes_at(case["historical_original_backend_output"]),
                     bytes_at(inputs["old_loader_bin"]), bytes_at(inputs["old_loader_elf"]))


def native_inventory(target, matrix):
    """Exact finite 40-case structure; retains the old per-directory512 cap."""
    allowed = {row["id"] for row in matrix} | {"requests", "plan.json", "complete.json"}
    present = {p.name for p in target.iterdir()}
    need(present <= allowed and {row["id"] for row in matrix} | {"requests"} <= present, "exact native top-level inventory")
    result = {}
    for row in matrix:
        for name, value in inventory(target / row["id"]).items():
            result[row["id"] + "/" + name] = value
    for name, value in inventory(target / "requests").items():
        result["requests/" + name] = value
    for name in ("plan.json", "complete.json"):
        p = target / name
        if p.exists():
            result[name] = dict(bytes=p.stat().st_size, sha256=digest(p))
    return result


def emit(here, expected, prepared_hash):
    inputs, prepared, observed = admitted(here, expected, prepared_hash)
    calibration_receipts = calibrations_passed(here, inputs, prepared)
    plan = read(here / "emission-plan.json")
    cases = read(here / "cases.json")["cases"]
    target = here / "future-emission"
    target.mkdir()
    signals = FailureSignals()
    completed = []
    binding = inputs["helper"]
    def verify():
        now, then, current = admitted(here, expected, prepared_hash)
        need((now, then, current) == (inputs, prepared, observed), "fixed source/preparation/runtime identity")
    try:
        for index, case in enumerate(cases):
            directory = target / case["id"]
            directory.mkdir()
            items = []
            for item in plan["commands"][2 * index:2 * index + 2]:
                request_path = here / item["request"]
                need(digest(request_path) == item["request_sha256"] and item["case"] == case["id"], "frozen ordered tool command")
                items.append(dict(name=item["phase"], request=read(request_path)))
            front, back = items
            _, stderr = helper_command(front, inputs, binding, verify, signals)
            need(b"warning:" not in stderr and b"error:" not in stderr, "no frontend warning/error")
            rpc = capture(directory / "request.json")
            need(rpc == bytes_at(case["frozen_rpc"]), "byte-identical frontend RPC")
            validate_rpc(rpc, case, bytes_at(case["original"]), elf64(bytes_at(case["original"])))
            (directory / "request.json").chmod(0o444)
            need(not (directory / "a.out").exists(), "no stale output")
            stdout, stderr = helper_command(back, inputs, binding, verify, signals)
            need(capture(directory / "request.json") == rpc, "RPC unchanged by backend")
            output = capture(directory / "a.out")
            stats = backend_stats(stdout, stderr, case, bytes_at(case["original"]), output)
            verified = structural_case(here, inputs, case, output, rpc)
            write_new(directory / "structure.json", verified)
            write_new(directory / "backend-audit.json", stats)
            (directory / "a.out").chmod(0o500)
            verify()
            result = dict(id=case["id"], output=dict(path=str(directory / "a.out"), bytes=len(output), sha256=sha(output)),
                          rpc_sha256=sha(rpc), structure_sha256=digest(directory / "structure.json"),
                          statistics=stats, artifacts=inventory(directory), native_invocations=0)
            write_new(directory / "complete.json", result)
            completed.append(result)
        need(len(completed) == 6 and [x["id"] for x in completed] == [x["id"] for x in cases], "all six required artifacts")
        verify()
        write_new(target / "complete.json", dict(status="CORRECTED_COMMON_SIX_EMITTED_NATIVE_NOT_RUN", source_manifest_sha256=expected,
                  prepared_sha256=prepared_hash, calibration_receipts=calibration_receipts, cases=completed,
                  tool_commands=12, selected=6, B1=6, other_tactics=0, native_invocations=0,
                  qualification_complete=False, files=inventory(target)))
        print("CORRECTED_COMMON_SIX_EMITTED_NATIVE_NOT_RUN", digest(target / "complete.json"), flush=True)
    except BaseException as error:
        signals.ignore()
        write_new(target / "failed-incomplete.json", dict(status="FAILED_NO_RETRY_NO_PARTIAL_CREDIT", error=repr(error), completed_ids=[x["id"] for x in completed], files=inventory(target)))
        raise
    finally:
        signals.restore()


def emitted(here, inputs, expected, prepared_hash, checksum):
    target = here / "future-emission"
    need(digest(target / "complete.json") == checksum, "actual reviewed six-output terminal")
    terminal = read(target / "complete.json")
    need(terminal["status"] == "CORRECTED_COMMON_SIX_EMITTED_NATIVE_NOT_RUN" and
         terminal["source_manifest_sha256"] == expected and terminal["prepared_sha256"] == prepared_hash and
         terminal["tool_commands"] == 12 and terminal["B1"] == 6 and terminal["native_invocations"] == 0, "complete actual fresh emission required")
    need(inventory(target) == dict(terminal["files"], **{"complete.json": dict(bytes=(target / "complete.json").stat().st_size, sha256=checksum)}), "complete emission tree unchanged")
    cases = read(here / "cases.json")["cases"]
    need([x["id"] for x in terminal["cases"]] == [x["id"] for x in cases], "literal six-case order")
    result = {}
    for case, row in zip(cases, terminal["cases"]):
        output = bytes_at(row["output"])
        rpc = capture(target / case["id"] / "request.json")
        verified = structural_case(here, inputs, case, output, rpc)
        need(verified == read(target / case["id"] / "structure.json"), "independent fresh structural recomputation")
        result[case["id"]] = dict(case=case, output=row["output"], verified=verified)
    return result


def bind_native(here, expected, prepared_hash, emitted_hash):
    inputs, _, _ = admitted(here, expected, prepared_hash)
    cohort = emitted(here, inputs, expected, prepared_hash, emitted_hash)
    matrix = read(here / "native-inventory.json")
    target = here / "native-v1"
    target.mkdir()
    (target / "requests").mkdir()
    rows = []
    for row in matrix["runs"]:
        directory = target / row["id"]
        directory.mkdir()
        modules = {}
        for role in ("main", "dso"):
            item = cohort[row[role + "_case"]]
            case = item["case"]
            origin = row[role + "_origin"]
            need(origin in ("original", "E9-output"), "exact fixed origin")
            artifact = case["original"] if origin == "original" else item["output"]
            data = bytes_at(artifact)
            path = directory / case["name"]
            with path.open("xb") as stream: stream.write(data)
            path.chmod(0o500)
            modules[role] = dict(path=str(path), sha256=sha(data), origin=origin, case_id=case["id"])
        bound = dict(case=row, modules=modules, source_manifest_sha256=expected, prepared_sha256=prepared_hash,
                     emission_sha256=emitted_hash, environment=matrix["environment"])
        write_new(directory / "binding.json", bound)
        q = dict(argv=[inputs["python"]["path"], "-B", str(here / "entry.py"), "native", expected,
                       "--prepared-sha256", prepared_hash, "--emitted-sha256", emitted_hash,
                       "--case", row["id"], "--binding-sha256", digest(directory / "binding.json")],
                 cwd=str(here), env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
                 cpu_seconds=10, wall_seconds=30, file_bytes=16777216,
                 stdout=str(directory / "driver.stdout"), stderr=str(directory / "driver.stderr"))
        request_path = target / "requests" / (row["id"] + ".json")
        write_new(request_path, q)
        rows.append(dict(id=row["id"], binding_sha256=digest(directory / "binding.json"),
                         request=str(request_path), request_sha256=digest(request_path), receipt=str(directory / "driver.receipt.json")))
    need(len(rows) == 40, "all four baseline and thirty-six rewritten invocations")
    write_new(target / "plan.json", dict(status="FORTY_ACTUAL_REQUESTS_REVIEW_REQUIRED_NOT_EXECUTED", source_manifest_sha256=expected,
              prepared_sha256=prepared_hash, emitted_sha256=emitted_hash, rows=rows, files=native_inventory(target, matrix["runs"]),
              required_original=4, required_rewritten=36, per_trace_seconds=15, per_trace_stops=20000,
              required_bootstrap_modules=48, required_bootstrap_syscalls=336, required_fixed_mappings=96,
              required_exact_relocation_values=80, state_traces=0, generic_loader_admission=False))
    admitted(here, expected, prepared_hash)
    print("FORTY_ACTUAL_REQUESTS_REVIEW_REQUIRED_NOT_EXECUTED", digest(target / "plan.json"), flush=True)


def native_one(here, expected, args):
    from native import trace
    inputs, _, _ = admitted(here, expected, args.prepared_sha256)
    cohort = emitted(here, inputs, expected, args.prepared_sha256, args.emitted_sha256)
    matrix = read(here / "native-inventory.json")["runs"]
    wanted = [x for x in matrix if x["id"] == args.case]
    need(len(wanted) == 1, "one declared invocation, no substituted case")
    directory = here / "native-v1" / args.case
    need(digest(directory / "binding.json") == args.binding_sha256, "actual independently reviewed invocation binding")
    binding = read(directory / "binding.json")
    need(binding["case"] == wanted[0] and binding["source_manifest_sha256"] == expected and
         binding["prepared_sha256"] == args.prepared_sha256 and binding["emission_sha256"] == args.emitted_sha256,
         "same source, prepared epoch and actual artifact generation")
    modules = {}
    for role in ("main", "dso"):
        b = binding["modules"][role]
        item = cohort[wanted[0][role + "_case"]]
        case = item["case"]
        need(b["case_id"] == case["id"] and b["origin"] == wanted[0][role + "_origin"] and
             b["path"] == str(directory / case["name"]), "exact copied launch role")
        original = bytes_at(case["original"])
        blob = Path(b["path"]).read_bytes()
        want = original if b["origin"] == "original" else bytes_at(item["output"])
        need(blob == want and sha(blob) == b["sha256"], "actual launch bytes match original/emitted owner")
        modules[role] = dict(b, case=case, blob=blob, original_blob=original, verified=item["verified"])
    trace(wanted[0], modules, dict(path=inputs["interpreter"], sha256=inputs["runtime_hashes"][inputs["interpreter"]]), directory / "capture")
    admitted(here, expected, args.prepared_sha256)
    print("COMMON_LOADER_CASE_PASS", args.case, flush=True)


def audit_native(here, expected, args):
    inputs, _, _ = admitted(here, expected, args.prepared_sha256)
    emitted(here, inputs, expected, args.prepared_sha256, args.emitted_sha256)
    target = here / "native-v1"
    need(digest(target / "plan.json") == args.plan_sha256, "actual reviewed forty-request inventory")
    plan = read(target / "plan.json")
    matrix = read(here / "native-inventory.json")["runs"]
    need([row["id"] for row in plan["rows"]] == [row["id"] for row in matrix], "complete exact native case order")
    totals = dict(baseline=0, rewritten=0, bootstrap_modules=0, bootstrap_syscalls=0, fixed_mappings=0, exact_relocations=0)
    results = []
    for row, case in zip(plan["rows"], matrix):
        directory = target / case["id"]
        qraw = Path(row["request"]).read_bytes()
        need(sha(qraw) == row["request_sha256"], "unchanged request")
        q = json.loads(qraw)
        so, se = capture(Path(q["stdout"])), capture(Path(q["stderr"]))
        validate_helper_receipt(read(row["receipt"]), qraw, inputs["helper"]["sha256"], so, se)
        need(so == ("COMMON_LOADER_CASE_PASS " + case["id"] + "\n").encode() and se == b"", "exact complete driver output")
        need(digest(directory / "binding.json") == row["binding_sha256"], "launch binding retained")
        result = read(directory / "capture/complete.json")
        required = {"binding.json", "driver.stdout", "driver.stderr", "driver.receipt.json",
                    "capture/application.stdout", "capture/application.stderr", "capture/final-maps.txt", "capture/complete.json"}
        required.update(binding["path"].rsplit("/", 1)[-1] for binding in read(directory / "binding.json")["modules"].values())
        need(set(inventory(directory)) == required, "complete per-case raw file inventory, no hidden failure")
        need(result["case"] == case and result["status"] == "PASS_CLOSED_FIXTURE_LOADER_WITNESS", "required real loader completion")
        need(result["register_writes"] == result["memory_writes"] == 0 and result["single_thread_checks"] is True, "no reset/patch/peer escape")
        need((directory / "capture/application.stdout").read_bytes() == bytes.fromhex("63617272696572206d6978206f6b0a00") and
             (directory / "capture/application.stderr").read_bytes() == b"", "literal actual application stdout/stderr")
        events = result["bootstrap_syscalls"]
        expected_modules = sum(case[role + "_origin"] == "E9-output" for role in ("main", "dso"))
        need(result["expected_bootstrap_modules"] == expected_modules and len(events) == 7 * expected_modules, "per-launch baseline zero or complete module inventory")
        totals[case["phase"]] += 1
        totals["bootstrap_modules"] += expected_modules
        totals["bootstrap_syscalls"] += len(events)
        totals["fixed_mappings"] += sum(event["kind"] == "mmap" for event in events)
        totals["exact_relocations"] += sum(len(m["dynamic_writes"]) for m in result["modules"].values())
        results.append(dict(id=case["id"], receipt_sha256=digest(row["receipt"]), completion_sha256=digest(directory / "capture/complete.json")))
    need(totals == dict(baseline=4, rewritten=36, bootstrap_modules=48, bootstrap_syscalls=336, fixed_mappings=96, exact_relocations=80), "all predeclared loader witnesses required")
    write_new(target / "complete.json", dict(status="COMPLETE_FIXED_COMMON_LOADER_COHORT", source_manifest_sha256=expected,
              plan_sha256=args.plan_sha256, totals=totals, cases=results, architectural_state_traces=0,
              state_body_required=[48, 48, 48], qualification_complete=False, files=native_inventory(target, matrix)))
    print("COMPLETE_FIXED_COMMON_LOADER_COHORT", digest(target / "complete.json"), flush=True)


def main(here, expected, phase, argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepared-sha256")
    parser.add_argument("--emitted-sha256")
    parser.add_argument("--binding-sha256")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--case")
    parser.add_argument("--state-freeze-sha256")
    args = parser.parse_args(argv)
    if phase == "prepare":
        need(not argv, "fixed preparation takes no mutable overrides")
        prepare(here, expected)
    elif phase == "emit":
        emit(here, expected, args.prepared_sha256)
    elif phase == "bind-native":
        bind_native(here, expected, args.prepared_sha256, args.emitted_sha256)
    elif phase == "native":
        native_one(here, expected, args)
    elif phase == "audit-native":
        audit_native(here, expected, args)
    elif phase in {"bind-state", "bind-state-run", "audit-state"}:
        from state_join import bind_state, bind_state_run, audit_state
        {"bind-state": bind_state, "bind-state-run": bind_state_run, "audit-state": audit_state}[phase](here, expected, args)
    else:
        raise AssertionError("unknown fixed phase")
