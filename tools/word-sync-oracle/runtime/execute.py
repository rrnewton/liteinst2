#!/usr/bin/env python3
"""Root-only once-only serial execution using the existing bounded helper."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import json
import subprocess
from pathlib import Path
from guard import HERE, files, read, sha, verify
from audit import complete, step


def save(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    assert sha(HERE / "manifest.json") == args.manifest_sha256
    inputs = verify()
    plan = read(HERE / "plan.json")
    out = HERE / "run"
    out.mkdir()
    steps = []
    try:
        for name in plan["order"]:
            assert sha(HERE / "manifest.json") == args.manifest_sha256
            assert verify() == inputs
            row = plan["requests"][name]
            request_path = HERE / row["request"]
            assert sha(request_path) == row["request_sha256"]
            request = read(request_path)
            assert request["cwd"] == plan["cwd"] and request["env"] == plan["environment"]
            assert [request[k] for k in ["cpu_seconds", "wall_seconds", "file_bytes"]] == [20, 30, 1048576]
            for path in [request["stdout"], request["stderr"], row["receipt"]]:
                assert not Path(path).exists()
            argv = [inputs["tools"]["timeout"]["path"], "--signal=TERM", "--kill-after=10s", "40s", inputs["tools"]["helper_python"]["path"], "-B", inputs["tools"]["helper"]["path"], "--request", str(request_path), "--receipt", row["receipt"]]
            # Unchanged reviewed helper/timeout pattern. The helper owns all
            # descendants; this wrapper does not invent a second supervisor.
            with (out / (name + ".helper.stdout")).open("xb") as stdout, (out / (name + ".helper.stderr")).open("xb") as stderr:
                result = subprocess.run(argv, cwd=plan["cwd"], env=plan["environment"], stdout=stdout, stderr=stderr, timeout=55)
            steps.append(dict(name=name, helper_argv=argv, helper_exit=result.returncode, request_sha256=sha(request_path), receipt_sha256=sha(row["receipt"]) if Path(row["receipt"]).exists() else None))
            (out / "steps.json").write_text(json.dumps(steps, indent=2) + "\n")
            assert sha(HERE / "manifest.json") == args.manifest_sha256
            assert verify() == inputs
            assert result.returncode == 0, name
            step(name, inputs, plan)
            print(name, "PASS", flush=True)
        audit = complete()
        save(out / "audit.json", audit)
        terminal = dict(status="COMPLETE_FIXED_COHORT_SCOPED", manifest_sha256=args.manifest_sha256, audit_sha256=sha(out / "audit.json"), files=files(out), fixture_commands=19, native_modes=17, case_ids=838, pure_auditor_commands=1, complete_A4=False)
        save(out / "complete.json", terminal)
        print("COMPLETE_FIXED_COHORT_SCOPED", flush=True)
    except BaseException as error:
        # A missing helper receipt proves no cleanup. No retry, continuation,
        # inferred absence or partial-positive credit is authorized.
        save(out / "failed-incomplete.json", dict(status="FAILED_INCOMPLETE_NO_COHORT_PASS", error=repr(error), steps=steps, cleanup_claimed=False, files=files(out)))
        raise


if __name__ == "__main__":
    main()
