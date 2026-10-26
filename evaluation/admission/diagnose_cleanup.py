#!/usr/bin/env python3
"""Attribute two fork-cleanup failures; this is not the qualification protocol."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import resource
import shutil
import sys

from parsing import InvalidEvidence, SUMMARY, harness_id
from processes import run_command
from run import (ROOT, HERE, GIT, ENV, LOCATION_VARIABLES, cargo_configuration,
                 controlled_environment, git, hardware, preflight, require,
                 sha, source_state, tool_version, write_result)

CASES = (
    "unexpected_newborn_is_reaped_without_public_creation_support",
    "late_parent_payload_cannot_reacquire_a_reaped_child_identity",
)
PREFIX = "linux::remote::dynamic::owner::tests::"


def observations(output, case, total):
    lines = output.splitlines()
    headers = [harness_id(line) for line in lines
               if re.match(r"\s*(Running |Doc-tests )", line)]
    require(headers == ["unit/liteinst_launch/lib"], "changed_diagnostic_harness")
    require([line for line in lines if line.startswith("running ")] == ["running 1 test"],
            "changed_diagnostic_start")
    tests = [line for line in lines if line.startswith("test ") and not line.startswith("test result:")]
    require(tests in ([f"test {PREFIX}{case} ... ok"], [f"test {PREFIX}{case} ... FAILED"]),
            "changed_diagnostic_case")
    summaries = [SUMMARY.fullmatch(line) for line in lines if line.startswith("test result:")]
    require(len(summaries) == 1 and summaries[0] is not None, "changed_diagnostic_summary")
    match = summaries[0]
    counts = dict(zip(("passed", "failed", "ignored", "measured", "filtered"),
                      (int(match[index]) for index in range(2, 7))))
    require(counts in ({"passed": 1, "failed": 0, "ignored": 0, "measured": 0, "filtered": total - 1},
                       {"passed": 0, "failed": 1, "ignored": 0, "measured": 0, "filtered": total - 1}),
            "changed_diagnostic_counts")
    require((match[1] == "ok") == (counts["passed"] == 1)
            == tests[0].endswith(" ... ok"), "contradictory_diagnostic_result")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-revision", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[a-f0-9]{40}", args.expect_revision), "invalid_expected_revision")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_id = stamp + "-cleanup-" + args.expect_revision[:12]
    private = ROOT / "target/evaluation/admission" / run_id
    private.mkdir(parents=True, exist_ok=False)
    temporary = private / "tmp"
    temporary.mkdir()
    public = HERE / "results" / (run_id + ".json")
    require(not public.exists(), "duplicate_run_id")
    record = {"schema_version": 1, "experiment": "fork-cleanup-diagnostic", "run_id": run_id,
              "qualification_protocol": False, "complete_claims_established": [], "claim_targets": [4],
              "source": None, "source_unchanged": None, "configuration": None,
              "configuration_unchanged": None, "runner_sha256": sha(Path(__file__).read_bytes()),
              "reproduce": ["python3", "evaluation/admission/diagnose_cleanup.py",
                            "--expect-revision", args.expect_revision],
              "hardware": None, "toolchain": None, "corpus_sha256": None,
              "environment": ENV | {"CARGO_TARGET_DIR": "target", "TMPDIR": "private_run/tmp",
                                     "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "RLIMIT_CORE": 0},
              "inherited_location_variables": list(LOCATION_VARIABLES),
              "log_limit_bytes_per_command": 8 * 1024 * 1024,
              "performance_claim": None, "status": "preflight", "commands": []}
    for case in CASES:
        record["commands"].append({"id": case, "status": "not_run", "timeout_seconds": 180,
                                   "argv": ["cargo", "test", "-p", "liteinst-launch", "--lib",
                                            PREFIX + case, "--", "--exact", "--test-threads=1"]})
    write_result(public, record)
    print(public.relative_to(ROOT), flush=True)
    try:
        env = controlled_environment(os.environ, temporary)
        require(sys.platform == "linux" and os.uname().machine == "x86_64", "unsupported_platform")
        source = source_state()
        record["source"] = source
        preflight(source, args.expect_revision,
                  git("ls-files", "--others", "--exclude-standard").decode().splitlines())
        corpus_data = (HERE / "corpus.json").read_bytes()
        record["corpus_sha256"] = sha(corpus_data)
        corpus = json.loads(corpus_data)
        require(corpus["schema_version"] == 1, "unknown_corpus_schema")
        total = corpus["harness_test_counts"]["workspace_tests"]["unit/liteinst_launch/lib"]["tests"]
        record["configuration"] = cargo_configuration(env)
        record["hardware"] = hardware()
        record["toolchain"] = {name: {"version": tool_version(name, env),
                                      "launcher_sha256": sha(Path(shutil.which(name, path=env["PATH"])).read_bytes())}
                               for name in ("rustc", "cargo")}
        record["toolchain"]["git"] = {"argv0": GIT, "version": tool_version(GIT, env),
                                       "executable_sha256": sha(Path(GIT).read_bytes())}
        record["toolchain"]["python"] = {"version": sys.version.split()[0],
            "executable_sha256": sha(Path(sys.executable).read_bytes()),
            "launcher_sha256": sha(Path(shutil.which("python3", path=env["PATH"])).read_bytes())}
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        record["status"] = "running"
        for command in record["commands"]:
            log = private / (command["id"] + ".log")
            command["status"] = "running"
            write_result(public, record)
            command.update(run_command(command["argv"], env, log, command["timeout_seconds"]))
            passed = (command["exit_code"] == 0 and command["termination"] is None
                      and command["cleanup_complete"] and command["reaped_descendants"] == 0)
            command["status"] = "passed" if passed else "failed"
            command["evidence_status"] = "complete"
            try:
                command["observations"] = observations(log.read_text(errors="replace"), command["id"], total)
                if command["observations"]["failed"]:
                    command["status"] = "failed"
            except InvalidEvidence as error:
                command.update(evidence_status="incomplete", parse_error=str(error))
                if command["status"] == "passed":
                    command["status"] = "invalid_evidence"
            write_result(public, record)
            print(json.dumps({key: command[key] for key in
                              ("id", "status", "exit_code", "termination", "reaped_descendants", "seconds")}),
                  flush=True)
            # Each diagnostic is independent. An incomplete cleanup, however,
            # poisons the shared supervisor and forbids the second command.
            if not command["cleanup_complete"] or command["termination"] == "interrupted":
                break
        after = source_state()
        record["source_unchanged"] = source == after
        preflight(after, args.expect_revision,
                  git("ls-files", "--others", "--exclude-standard").decode().splitlines())
        record["configuration_unchanged"] = record["configuration"] == cargo_configuration(env)
        record["status"] = "passed" if (record["source_unchanged"] and record["configuration_unchanged"]
            and all(command["status"] == "passed" for command in record["commands"])) else "failed"
    except (Exception, KeyboardInterrupt) as error:
        record["error_code" if isinstance(error, InvalidEvidence) else "error_type"] = (
            str(error) if isinstance(error, InvalidEvidence) else type(error).__name__)
        record["status"] = ("refused" if record["status"] == "preflight" else
                            "interrupted" if isinstance(error, KeyboardInterrupt) else "recorder_error")
    finally:
        write_result(public, record)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except InvalidEvidence as error:
        print("diagnostic refused: " + str(error), file=sys.stderr)
        sys.exit(2)
