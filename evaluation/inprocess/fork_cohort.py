#!/usr/bin/env python3
"""Raw-fork execution cohort; fork.py adds committed-source qualification."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from fork_supervise import Attempt, STATE_BYTES, error_record, need
import fork_controls as controls
import fork_continuation as compare_continuation

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "tools/page-entry"
BUILD = ROOT / "target/page-entry"
MODULES = Path(__file__).resolve().parent
CASES = ("basic", "cpuid", "rdtsc", "rdtscp", "cow", "efault_status", "efault_rusage", "high_wait", "wnohang")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("non-JSON number: " + value)


def decode(data):
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)


def report(data, role):
    need(data.startswith(b"LI2_FORK {") and data.endswith(b"}\n") and data.count(b"\n") == 1,
         "missing or malformed actual fork report")
    value = decode(data[len(b"LI2_FORK "):])
    fields = {"version", "scope", "source_patches", "status", "failure_code", "detail", "role", "self_pid",
              "before_pid", "child_pid", "attempted", "returned", "fork_result", "child_ready", "setup_started",
              "setup_complete", "gate_observed", "gate_results", "inherited", "current", "inherited_lifecycle",
              "current_lifecycle", "waits"}
    need(type(value) is dict and set(value) == fields, "closed fork report fields")
    need(value["scope"] == "sealed_namespace_raw_fork", "fork report scope")
    arrays = {"gate_results", "inherited", "current", "inherited_lifecycle", "current_lifecycle", "waits"}
    for name in fields - arrays - {"scope"}:
        need(type(value[name]) is int and -(1 << 63) <= value[name] < 1 << 63, "fork scalar type/range")
    need(value["version"] == 1 and value["role"] == role and value["source_patches"] == 0,
         "fork report identity")
    need(0 <= value["status"] <= 255 and value["failure_code"] >= 0 and value["self_pid"] > 0
         and value["before_pid"] > 0 and value["child_pid"] >= 0, "actual report status/PID bounds")
    need(all(value[key] in (0, 1) for key in ("attempted", "returned", "child_ready"))
         and 0 <= value["setup_complete"] <= value["setup_started"] <= 4
         and 0 <= value["gate_observed"] <= 8191, "report completion markers")
    for key, count in (("gate_results", 13), ("inherited", 15), ("current", 15),
                       ("inherited_lifecycle", 18), ("current_lifecycle", 18)):
        low, high = (-(1 << 63), 1 << 63) if key == "gate_results" else (0, 1 << 64)
        need(type(value[key]) is list and len(value[key]) == count and
             all(type(item) is int and low <= item < high for item in value[key]), "complete counter/result array")
    need(type(value["waits"]) is list and len(value["waits"]) <= 8, "bounded wait prefix")
    for wait in value["waits"]:
        need(type(wait) is list and len(wait) == 2 and type(wait[0]) is int and wait[0] in (0, 1)
             and type(wait[1]) is int and -(1 << 63) <= wait[1] < 1 << 63, "actual wait result")
    return value


def invoke(label, mode, case, args, rows, failure=0, continuation=None):
    attempt = Attempt(rows, args.output / label, label, mode, case, failure)
    def command(owner):
        writers = [entry["fd"] for entry in owner.row["fds"] if entry["name"].endswith("-write")]
        basename = ("continuation" + ("-" + continuation if continuation != "positive" else "")) if continuation else "fork"
        executable = BUILD / (basename + "-probe")
        if continuation:
            sinks = [entry["fd"] for entry in owner.row["fds"] if entry["name"] in ("state-0", "state-1")]
            target_args = [str(executable), *map(str, sinks)]
        else:
            extra = []
            if case == "wnohang":
                pipe = owner.pipe("wnohang")
                owner.passed.extend(pipe)
                extra = list(map(str, pipe))
            target_args = [str(executable), case, *extra]
        if mode == "native":
            return target_args
        result = [sys.executable, str(PRODUCT / "carrier.py"),
                  "exec-fork" if mode == "gated" else "exec-loader",
                  "--library-root", str(args.library_root), "--namespace", str(owner.folder / "namespace")]
        if mode == "gated":
            result += ["--report-parent", str(writers[0]), "--report-child", str(writers[1])]
            if failure:
                result += ["--child-failure", str(failure)]
        return result + [str(BUILD / (basename + "-carrier")), str(executable), "--", *target_args]

    def parse(owner):
        if mode == "gated":
            for index, data in enumerate(owner.report_bytes):
                owner.row["reports"].append(report(data, index))
            need(owner.row["reports"][0]["self_pid"] == owner.row["leader_pid"], "runtime parent differs from owned exec leader")
        else:
            need(owner.report_bytes == [b"", b""], "unexpected native/default fork reports")
        if continuation:
            need(len(owner.states) == 2 and all(type(value) is bytes and len(value) == STATE_BYTES for value in owner.states),
                 "complete original continuation files")
    attempt.result = attempt.run(command, state_count=2 if continuation else 0, postprocess=parse)
    need(attempt.row["cleanup_complete"], "physical cleanup incomplete; no further ordinary command")
    return attempt


def check_pair(native, gated, case, failure=0):
    n, ns, _ = native
    g, gs, _ = gated
    if n["failure"] or g["failure"] or not n["cleanup_complete"] or not g["cleanup_complete"]:
        raise ValueError("command failed or physical cleanup incomplete")
    if n["exit_code"] != 0 or g["exit_code"] != 0 or ns != gs:
        raise ValueError("actual native/gated exit or stdout mismatch")
    expected = b"PARENT_OK\n" if failure else b"CHILD_OK\nPARENT_OK\n"
    if gs != expected:
        raise ValueError("missing actual fork/wait marker")
    parent, child = g["reports"]
    if parent["failure_code"] or parent["status"] or parent["fork_result"] <= 0:
        raise ValueError("parent original successful fork missing")
    if parent["fork_result"] != child["self_pid"] or child["before_pid"] != parent["self_pid"] or child["fork_result"] != 0:
        raise ValueError("actual fork PID/result association")
    if parent["inherited"] != child["inherited"] or parent["inherited_lifecycle"] != child["inherited_lifecycle"]:
        raise ValueError("different inherited prefix")
    if not all(r["attempted"] == r["returned"] == 1 for r in (parent, child)):
        raise ValueError("fork call completion")
    if failure:
        if child["status"] != 125 or child["failure_code"] != 273 or child["detail"] != failure or child["child_ready"]:
            raise ValueError("child setup failure replaced or application resumed")
        if child["gate_observed"] != {1: 3, 2: 3, 3: 1023, 4: 4095}[failure]:
            raise ValueError("child gate observed prefix lost")
        if child["setup_started"] != failure or child["setup_complete"] != failure - 1:
            raise ValueError("incomplete child prefix lost")
    else:
        if child["status"] != 42 or child["failure_code"] or child["child_ready"] != 1 or child["setup_complete"] != 4:
            raise ValueError("child rearm incomplete")
        if child["gate_observed"] != 8191:
            raise ValueError("unobserved gate result presented as complete")
        gates = child["gate_results"]
        if len(gates) != 13 or gates[0:2] != [child["self_pid"]] * 2 or gates[2:11] != [0, 0, 0, 0, 2, 0, 0, 2, 0] or gates[11] < 0 or not gates[11] & 64 or gates[12]:
            raise ValueError("actual child gate returns differ from required states")
        if child["current"][4] <= child["inherited"][4]:
            raise ValueError("no actual post-fork SUD trap")
        selected = {"cpuid": 1, "rdtsc": 2, "rdtscp": 3}.get(case)
        if selected is not None and child["current"][selected] <= child["inherited"][selected]:
            raise ValueError("no actual child selected trap")
    waits = parent["waits"]
    expected_results = [-14, -10] if case in ("efault_status", "efault_rusage") else ([0, parent["fork_result"]] if case == "wnohang" else [parent["fork_result"]])
    if waits != [[1, value] for value in expected_results]:
        raise ValueError("original wait4 results changed")
    if case == "cow":
        base = child["inherited_lifecycle"]
        if child["current_lifecycle"][3] <= base[3] or child["current_lifecycle"][4] <= base[4]:
            raise ValueError("child mapping generation/retirement missing")
        if parent["current_lifecycle"][3] != parent["inherited_lifecycle"][3]:
            raise ValueError("child generation escaped its mm")



def bind_continuation(summary, native, gated):
    need(summary["native_pids"][0] == native.row["leader_pid"]
         and summary["gated_pids"][0] == gated.row["leader_pid"], "continuation parent differs from actual Popen owner")
    need(summary["gated_pids"] == [value["self_pid"] for value in gated.row["reports"]]
         and summary["gated_fork_result"] == gated.row["reports"][0]["fork_result"],
         "full-state records differ from actual runtime fork reports")


def source_digest():
    paths = sorted([*PRODUCT.glob("*"),
                    *[MODULES / name for name in ("fork_cohort.py", "fork_supervise.py", "fork_controls.py", "fork_continuation.py", "fork.py")]])
    rows = [(str(path.relative_to(ROOT)), digest(path)) for path in paths if path.is_file()]
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def main(argv=None, receipt_out=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    args.output.mkdir()
    rows = []
    receipt = {"scope": "working_tree_raw_fork_candidate_not_qualified", "passed": False,
               "cpus": sorted(os.sched_getaffinity(0)), "commands": rows,
               "planned_commands": 39, "original_commands": 24,
               "continuation_commands": 6, "supervisor_commands": 9,
               "failure": None, "secondary_errors": [], "source_unchanged": None}
    if receipt_out is not None:
        need(type(receipt_out) is dict and not receipt_out, "fresh external receipt owner")
        receipt_out.update(receipt)
        receipt = receipt_out
    binary_paths = [BUILD / name for name in (
        "bridge-loader.so", "fork-probe", "fork-carrier", "continuation-probe", "continuation-carrier",
        "continuation-gpr-probe", "continuation-gpr-carrier", "continuation-redzone-probe",
        "continuation-redzone-carrier", "supervisor-probe")]
    try:
        need(1 <= len(receipt["cpus"]) <= 2, "run only inside authorized <=2-CPU reservation")
        try:
            unknown = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            unknown = None
        need(unknown is None, "dedicated supervisor already has a child")
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
        subreaper = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(subreaper), 0, 0, 0):
            raise OSError(ctypes.get_errno(), "PR_GET_CHILD_SUBREAPER")
        need(subreaper.value == 1, "actual subreaper state absent")
        receipt["source_sha256"] = source_digest()
        receipt["binaries"] = {str(path.relative_to(ROOT)): digest(path) for path in binary_paths}
        for case in CASES:
            native = invoke("native-" + case, "native", case, args, rows)
            gated = invoke("gated-" + case, "gated", case, args, rows)
            check_pair(native.result, gated.result, case)
        native = invoke("native-child-failure", "native", "expect_child_failure", args, rows)
        for step in (1, 2, 3, 4):
            gated = invoke(f"gated-child-failure-{step}", "gated", "expect_child_failure", args, rows, step)
            check_pair(native.result, gated.result, "expect_child_failure", step)
        default = invoke("default-refusal", "default", "basic", args, rows).result
        if default[0]["failure"] or not default[0]["cleanup_complete"] or default[0]["exit_code"] != 125 or default[1]:
            raise ValueError("default fork refusal changed")
        records = [decode(line[len(b"LI2_LOADER "):]) for line in default[2].splitlines() if line.startswith(b"LI2_LOADER ")]
        if len(records) != 1 or records[0]["failure_code"] != 210 or records[0]["detail_abs"] != 57:
            raise ValueError("default refusal identity changed")
        receipt["continuation"] = []
        for kind in ("positive", "gpr", "redzone"):
            native = invoke("native-continuation-" + kind, "native", "continuation-" + kind, args, rows, continuation=kind)
            gated = invoke("gated-continuation-" + kind, "gated", "continuation-" + kind, args, rows, continuation=kind)
            check_pair(native.result, gated.result, "basic")
            basename = "continuation" + ("-" + kind if kind != "positive" else "")
            image = (BUILD / (basename + "-probe")).read_bytes()
            if kind == "positive":
                summary = compare_continuation.pair(tuple(native.states), tuple(gated.states), image)
                need(summary["complete"] is True, "full positive continuation incomplete")
                supplied = compare_continuation.corruption_controls(tuple(native.states), image)
                need(supplied == 30, "complete supplied mutation cohort")
                receipt["supplied_continuation_controls"] = supplied
            else:
                summary = compare_continuation.negative(tuple(native.states), tuple(gated.states), image, kind)
                need(summary["complete"] is False and summary["original_records_rejected"] is True
                     and summary["kind"] == kind and len(summary["expected_rejections"]) == 4,
                     "actual negative original records were relabelled passing")
            bind_continuation(summary, native, gated)
            receipt["continuation"].append(summary)
        receipt["supervisor_controls"] = controls.run(BUILD, args.output, rows)
        need(len(rows) == 39 and len(receipt["supervisor_controls"]) == 9, "complete original plus additive command cohort")
        receipt["source_unchanged"] = (source_digest() == receipt["source_sha256"] and
            {str(path.relative_to(ROOT)): digest(path) for path in binary_paths} == receipt["binaries"])
        need(receipt["source_unchanged"], "source or actual binaries changed during commands")
        receipt["passed"] = True
    except BaseException as error:
        receipt["failure"] = error_record("cohort", error)
    finally:
        try:
            if "source_sha256" in receipt:
                receipt["source_unchanged"] = (source_digest() == receipt["source_sha256"] and
                    {str(path.relative_to(ROOT)): digest(path) for path in binary_paths} == receipt["binaries"])
                if not receipt["source_unchanged"]:
                    raise ValueError("source or binary identity changed")
        except BaseException as error:
            receipt["passed"] = False
            failure = error_record("final_identity", error)
            if receipt["failure"] is None:
                receipt["failure"] = failure
            else:
                receipt["secondary_errors"].append(failure)
        # If this last durable write itself fails, the process must fail. All
        # attempted rows already have independent command.json write attempts.
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
