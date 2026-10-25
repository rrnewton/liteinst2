"""Exact fixed output/receipt audit, without native process execution."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import math
import re
from pathlib import Path
from guard import HERE, SUCCESS, files, read, receipt, sha, verify


def listed(inventory):
    names = [row["name"] for row in inventory["calibrations"]]
    assert names == sorted(set(names)) and len(names) == 26
    return ("".join(name + ": test\n" for name in names) + "\n26 tests, 0 benchmarks\n").encode()


def calibration_prefix(inventory):
    rows = inventory["calibrations"]
    assert len(rows) == 26
    lines = ["\nrunning 26 tests\n"]
    for row in rows:
        suffix = " - should panic" if row["should_panic"] else ""
        lines.append("test " + row["name"] + suffix + " ... ok\n")
    lines.append("\ntest result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in ")
    return "".join(lines).encode()


def native_output(mode):
    return ("".join("case " + case + "\n" for case in mode["case_ids"]) + mode["stdout_terminal"] + "\n").encode()


def output(name, stdout, stderr, inventory):
    assert stderr == b"", "unexpected child stderr"
    if name.startswith("baseline-"):
        expected = read(HERE / "baseline-expected.json")
        key = name.removeprefix("baseline-")
        assert key in expected and stdout == expected[key].encode(), "exact baseline output"
        return {"baseline_mode": key}
    if name == "auditor-calibrations":
        assert stdout == b"auditor-calibrations accepted=3 rejected=12\n"
        return {"pure_acceptances": 3, "pure_refusals": 12}
    if name == "calibration-list":
        assert stdout == listed(inventory), "exact calibration name inventory"
        return {"listed": 26}
    if name == "calibrations":
        match = re.fullmatch(re.escape(calibration_prefix(inventory)) + rb"([0-9]+\.[0-9]{2})s\n\n", stdout)
        assert match is not None, "exact unfiltered calibration output"
        elapsed = float(match.group(1))
        assert math.isfinite(elapsed) and elapsed >= 0
        return {"passed": 26, "failed": 0, "ignored": 0, "filtered": 0}
    modes = [mode for mode in inventory["native_modes"] if mode["name"] == name]
    assert len(modes) == 1, "unknown native mode"
    assert stdout == native_output(modes[0]), "exact ordered native case output"
    return {"case_ids": modes[0]["case_ids"], "terminal": modes[0]["stdout_terminal"]}


def step(name, inputs, plan):
    row = plan["requests"][name]
    request_path = HERE / row["request"]
    assert sha(request_path) == row["request_sha256"]
    request = read(request_path)
    assert request["env"] == plan["environment"] and request["cwd"] == plan["cwd"]
    assert [request[k] for k in ["cpu_seconds", "wall_seconds", "file_bytes"]] == [20, 30, 1048576]
    result = receipt(request_path, row["receipt"], inputs["tools"]["helper"]["sha256"])
    run = HERE / "run"
    assert (run / (name + ".helper.stdout")).read_bytes() == SUCCESS
    assert (run / (name + ".helper.stderr")).read_bytes() == b""
    summary = output(name, Path(request["stdout"]).read_bytes(), Path(request["stderr"]).read_bytes(), read(HERE / "inventory.json"))
    return dict(name=name, receipt_sha256=sha(row["receipt"]), stdout_sha256=result["stdout_sha256"], stderr_sha256=result["stderr_sha256"], summary=summary)


def complete():
    inputs = verify()
    plan = read(HERE / "plan.json")
    inventory = read(HERE / "inventory.json")
    expected_order = ["baseline-" + n for n in ["positive", "deny-1", "deny-2", "deny-3"]] + ["auditor-calibrations", "calibration-list", "calibrations"] + [m["name"] for m in inventory["native_modes"]]
    assert plan["order"] == expected_order and len(expected_order) == 20
    steps = read(HERE / "run/steps.json")
    assert [row["name"] for row in steps] == expected_order
    summaries = []
    for observed, name in zip(steps, expected_order):
        row = plan["requests"][name]
        request_path = HERE / row["request"]
        expected_argv = [inputs["tools"]["timeout"]["path"], "--signal=TERM", "--kill-after=10s", "40s", inputs["tools"]["helper_python"]["path"], "-B", inputs["tools"]["helper"]["path"], "--request", str(request_path), "--receipt", row["receipt"]]
        assert observed == {"name": name, "helper_argv": expected_argv, "helper_exit": 0, "request_sha256": sha(request_path), "receipt_sha256": sha(row["receipt"])}
        summaries.append(step(name, inputs, plan))
    ids = [case for mode in inventory["native_modes"] for case in mode["case_ids"]]
    assert len(ids) == len(set(ids)) == 838
    observed_ids = [case for row in summaries for case in row["summary"].get("case_ids", [])]
    assert observed_ids == ids
    expected_files = {"steps.json"}
    for name in expected_order:
        expected_files.update(name + suffix for suffix in [".stdout", ".stderr", ".receipt.json", ".helper.stdout", ".helper.stderr"])
    actual = files(HERE / "run")
    assert set(actual) == expected_files, "exact complete runtime receipt file inventory"
    assert verify() == inputs
    return {"status": "FIXED_A4_STRICT_ORACLE_CASES_PASS_SCOPED", "build_audit_sha256": inputs["build_audit_sha256"], "binary_binding_sha256": inputs["binary_binding_sha256"], "inventory_sha256": sha(HERE / "inventory.json"), "summaries": summaries, "totals": inventory["totals"], "files": actual, "prior_35_cycles_combined": False, "complete_A4": False}
