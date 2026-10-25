#!/usr/bin/env python3
"""Fixed lifecycle diagnostic; child details stay in bounded private storage."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess

import processes
import run


ROOT = run.ROOT
HERE = run.HERE
SYSTEM_GIT = "/usr/bin/git"
PRIVATE_LIMIT = 8 * 1024 * 1024
COMMANDS = (
    ("parser_tests", ["python3", "-m", "unittest", "discover", "-s",
                      "evaluation/admission", "-p", "test_parsing.py"]),
    ("process_tests", ["python3", "-m", "unittest", "discover", "-s",
                       "evaluation/admission", "-p", "test_processes.py"]),
    ("recorder_tests", ["python3", "-m", "unittest", "discover", "-s",
                        "evaluation/admission", "-p", "test_recorder.py"]),
    ("default_git", ["git", "--version"]),
    ("system_git", [SYSTEM_GIT, "--version"]),
)


def metadata_git(*args):
    """Use the explicit system Git for identity, outside the suspect probe."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.check_output(
        [SYSTEM_GIT, "--no-replace-objects", "-C", str(ROOT), "--work-tree=" + str(ROOT),
         "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
        cwd=ROOT, env=env, stderr=subprocess.DEVNULL, timeout=10)


def source_state():
    original = run.git
    try:
        run.git = metadata_git
        return run.source_state()
    finally:
        run.git = original


def tool_identity(program, env):
    resolved = shutil.which(program, path=env["PATH"])
    if resolved is None:
        raise run.InvalidEvidence("diagnostic_tool_missing")
    data = Path(resolved).read_bytes()
    return {"sha256": run.sha(data), "bytes": len(data)}


def observed_command(argv, env, output_log, child_log):
    """Observe only children authenticated by the unchanged real constructor."""
    original = processes._Child.__init__
    observations = 0
    distinct_pids = set()
    complete = True
    written = 0
    with child_log.open("wb") as output:
        def observed_init(child, pid):
            nonlocal observations, complete, written
            original(child, pid)
            # The real constructor already proved this stable pidfd is our
            # waitable child. No competing reaper can release its numeric PID
            # during these private, read-only proc observations.
            observations += 1
            distinct_pids.add(pid)
            try:
                base = Path("/proc") / str(pid)
                detail = {"pid": pid}
                for name in ("comm", "cmdline", "status"):
                    with (base / name).open("rb") as source:
                        data = source.read(65537)
                    if len(data) > 65536:
                        complete = False
                        detail[name + "_truncated"] = True
                    detail[name] = data[:65536].decode(errors="backslashreplace")
                encoded = (json.dumps(detail, sort_keys=True) + "\n").encode()
                available = PRIVATE_LIMIT - written
                if len(encoded) > available:
                    complete = False
                else:
                    output.write(encoded)
                    written += len(encoded)
            except OSError:
                complete = False

        try:
            processes._Child.__init__ = observed_init
            result = processes.run_command(argv, env, output_log, 30)
        finally:
            processes._Child.__init__ = original
    result.update(private_child_log_sha256=run.sha(child_log.read_bytes()),
                  authenticated_child_observations=observations,
                  authenticated_distinct_pids=len(distinct_pids),
                  private_child_observation_complete=complete)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-revision", required=True)
    args = parser.parse_args()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_id = "diagnostic-" + stamp
    public = HERE / "results" / (run_id + ".json")
    private = ROOT / "target/evaluation/admission" / run_id
    public.parent.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True)
    temporary = private / "tmp"
    temporary.mkdir()
    record = {"schema_version": 1, "kind": "subprocess_lifecycle_diagnostic",
              "run_id": run_id, "status": "running", "source_unchanged": None,
              "metadata_git_selection": "system_git", "commands": [
                  {"id": name, "argv": argv, "timeout_seconds": 30, "status": "not_run"}
                  for name, argv in COMMANDS]}
    run.write_result(public, record)
    try:
        before = source_state()
        record["source_before"] = before
        record["reproduce"] = ["python3", "evaluation/admission/diagnose.py",
                               "--expect-revision", before["revision"]]
        run.require(before["revision"] == args.expect_revision, "revision_differs")
        run.require(before["tracked_clean"], "dirty_tracked_source")
        untracked = metadata_git("ls-files", "--others", "--exclude-standard").decode().splitlines()
        run.require(all(path == "BRIEF-li2adm.md" or path.startswith("evaluation/admission/results/")
                        for path in untracked), "untracked_input")
        record["hardware"] = run.hardware()
        env = run.controlled_environment(os.environ, temporary)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        record["controlled_environment"] = run.ENV | {
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "CARGO_TARGET_DIR": "target",
            "TMPDIR": "private_run/tmp", "RLIMIT_CORE": 0}
        record["inherited_location_variables"] = list(run.LOCATION_VARIABLES)
        record["claim_targets"] = []
        record["qualified_run"] = False
        record["tool_identities"] = {
            "default_git": tool_identity("git", env),
            "system_git": tool_identity(SYSTEM_GIT, env),
            "python": tool_identity("python3", env),
        }
        for command in record["commands"]:
            output_log = private / (command["id"] + ".log")
            child_log = private / (command["id"] + "-children.log")
            command["status"] = "running"
            run.write_result(public, record)
            command.update(observed_command(command["argv"], env, output_log, child_log))
            command["status"] = ("passed" if command["exit_code"] == 0
                                 and command["termination"] is None
                                 and command["cleanup_complete"]
                                 and command["private_child_observation_complete"] else "failed")
            output = output_log.read_text(errors="replace")
            if command["id"].endswith("_tests"):
                counts = re.findall(r"^Ran (\d+) tests in [\d.]+s$", output, re.MULTILINE)
                command["reported_test_count"] = int(counts[0]) if len(counts) == 1 else None
                command["reported_unittest_ok"] = output.rstrip().splitlines()[-1:] == ["OK"]
            else:
                version = output.strip()
                if re.fullmatch(r"git version [a-zA-Z0-9 .()+-]{1,120}", version):
                    record["tool_identities"][command["id"]]["version"] = version
            run.write_result(public, record)
            if not command["cleanup_complete"]:
                break
        after = source_state()
        record["source_after"] = after
        record["source_unchanged"] = (before["revision"] == after["revision"]
                                      and before["source_sha256"] == after["source_sha256"]
                                      and after["tracked_clean"])
        record["status"] = ("passed" if record["source_unchanged"]
                            and all(command["status"] == "passed" for command in record["commands"])
                            else "failed")
    except (Exception, KeyboardInterrupt) as error:
        record["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        record["error_type"] = type(error).__name__
        if isinstance(error, run.InvalidEvidence):
            record["error_code"] = str(error)
    run.write_result(public, record)
    print(json.dumps({"result": str(public.relative_to(ROOT)), "status": record["status"]}))
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
