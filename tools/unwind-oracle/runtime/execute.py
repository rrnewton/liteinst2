#!/usr/bin/env python3
"""Once-only serial requests, using the existing bounded helper and timeout."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import json
import math
from pathlib import Path
import subprocess
from guard import HERE, files, read, sha, verify
from audit import HELPER_STDOUT, audit_through


def save(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    assert sha(HERE / "manifest.json") == args.manifest_sha256
    inputs = verify()
    plan = read(HERE / "plan.json")
    # Separate command captures, final audit output and terminal controller
    # records. Caller stdout/stderr must remain outside all three directories.
    for name in ("run", "audit-output", "control"):
        (HERE / name).mkdir()
    steps = []
    try:
        for command in plan["steps"] + [dict(plan["final_audit"], name="final-audit")]:
            assert sha(HERE / "manifest.json") == args.manifest_sha256
            assert verify() == inputs
            name = command["name"]
            qp, rp = Path(command["request"]), Path(command["receipt"])
            assert sha(qp) == command["request_sha256"]
            q = read(qp)
            wall = q["wall_seconds"]
            assert (q["cpu_seconds"], wall, q["file_bytes"]) in ((20, 30, 16777216), (30, 45, 16777216))
            for path in (q["stdout"], q["stderr"], str(rp), command["helper_stdout"], command["helper_stderr"]):
                assert not Path(path).exists(), path
            tools = inputs["tools"]
            argv = [tools["timeout"]["path"], "--signal=TERM", "--kill-after=10s", str(wall + 10) + "s",
                    tools["helper_python"]["path"], "-B", tools["helper"]["path"],
                    "--request", str(qp), "--receipt", str(rp)]
            with Path(command["helper_stdout"]).open("xb") as so, Path(command["helper_stderr"]).open("xb") as se:
                result = subprocess.run(argv, cwd=inputs["root"], env=q["env"], stdout=so, stderr=se, timeout=wall + 25)
            steps.append(dict(name=name, helper_argv=argv, helper_exit=result.returncode,
                              request_sha256=sha(qp), receipt_sha256=sha(rp) if rp.exists() else None))
            (HERE / "control/steps.json").write_text(json.dumps(steps, indent=2) + "\n")
            assert sha(HERE / "manifest.json") == args.manifest_sha256
            assert verify() == inputs
            assert result.returncode == 0, name
            r = read(rp)
            assert r["exit"] == 0 and r["wall_timeout"] is False
            assert r["unexpected_descendants"] == r["cleanup_events"] == []
            assert r["absence_proof"] == "ECHILD" and r["cleanup_error"] is None and r["aborted"] is None
            assert r["inputs_unchanged"] is True and r["request_sha256"] == sha(qp)
            assert math.isfinite(r["elapsed_seconds"]) and 0 <= r["elapsed_seconds"] < wall
            assert r["helper_sha256"] == tools["helper"]["sha256"]
            assert r["stdout_sha256"] == sha(q["stdout"]) and r["stderr_sha256"] == sha(q["stderr"])
            assert Path(command["helper_stdout"]).read_bytes() == HELPER_STDOUT
            assert Path(command["helper_stderr"]).read_bytes() == b""
            if name == "final-audit":
                assert Path(q["stderr"]).read_bytes() == b""
                checked = read(q["stdout"])
                assert checked == audit_through()
            else:
                checked = audit_through(name)
            save(HERE / "control" / (name + ".audit.json"), checked)
            print(name, "PASS", flush=True)
        assert len(steps) == 11
        assert verify() == inputs
        required_control = {"steps.json"} | {step["name"] + ".audit.json" for step in steps}
        assert set(files(HERE / "control")) == required_control
        assert set(files(HERE / "audit-output")) == {"final-audit" + suffix for suffix in
            (".stdout", ".stderr", ".receipt.json", ".helper.stdout", ".helper.stderr")}
        inventory = {str(p.relative_to(HERE)): sha(p) for folder in ("run", "audit-output", "control")
                     for p in sorted((HERE / folder).rglob("*")) if p.is_file()}
        assert len(inventory) == 121
        # Construct the inventory before opening this terminal file. Its own
        # digest is reported separately; it cannot authenticate itself.
        save(HERE / "control/complete.json", dict(status="TEN_FIXED_COMMANDS_AND_FINAL_AUDIT_PASS",
             manifest_sha256=args.manifest_sha256, steps=steps, files=inventory,
             fixed_native_modes=6, positive_totals=read(HERE / "expected.json")["inventory"]["positive_totals"],
             scope="BacktraceOnly: two authored frame profiles and two fixed seeds",
             fresh_ordinary_parity_separate=True, full_A2=False, general_unwind=False))
        print("TEN_FIXED_COMMANDS_AND_FINAL_AUDIT_PASS", sha(HERE / "control/complete.json"), flush=True)
    except BaseException as error:
        save(HERE / "control/failed-incomplete.json", dict(status="FAILED_INCOMPLETE_NO_COHORT_PASS",
             error=repr(error), steps=steps, cleanup_claimed=False,
             files={str(p.relative_to(HERE)): sha(p) for folder in ("run", "audit-output", "control")
                    for p in sorted((HERE / folder).rglob("*")) if p.is_file()}))
        raise


if __name__ == "__main__":
    main()
