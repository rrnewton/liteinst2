#!/usr/bin/env python3
"""Reproduce the finite release JRCXZ control on one externally reserved CPU."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise SystemExit("Use assertions-enabled Python -I -B")
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument("--revision", required=True)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    root = Path.cwd().resolve()
    assert len(os.sched_getaffinity(0)) == 1
    def clean():
        assert subprocess.check_output(["git", "rev-parse", "HEAD"], timeout=10).decode().strip() == a.revision
        assert not subprocess.check_output(["git", "diff", "--binary", "HEAD"], timeout=10)
    clean()
    out = a.out.absolute()
    assert out == out.resolve() and out.parent == root / "target/evaluation" and not out.exists()
    helper = root / "evaluation/admission/processes.py"
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
    spec = importlib.util.spec_from_file_location("jrcxz_reproduction_owner", helper)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    out.mkdir()
    overrides = dict(CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="1", RUST_TEST_THREADS="1",
               CARGO_TARGET_DIR=str(root / "target"), CARGO_PROFILE_RELEASE_OPT_LEVEL="3",
               CARGO_PROFILE_RELEASE_DEBUG="0", CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS="true",
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS="true", CARGO_NET_OFFLINE="true",
               PYTHONDONTWRITEBYTECODE="1")
    env = dict(os.environ, **overrides)
    build = ["/usr/bin/prlimit", "--cpu=240", "--as=4294967296", "--fsize=134217728", "--core=0", "--",
             "cargo", "test", "--offline", "--locked", "--release", "-j1", "-p", "liteinst2",
             "--test", "neighbor_eviction_oracle", "--no-run", "--message-format=json"]
    record = dict(revision=a.revision, cpus=sorted(os.sched_getaffinity(0)), load_before=os.getloadavg(),
                  planned_native_attempts=1, qualification_complete=False,
                  build_command=build, build_wall_seconds=300, native_wall_seconds=60,
                  log_cap_bytes=8388608, build_environment=overrides, native_environment=dict(RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1'))
    (out / "intent.json").write_text(json.dumps(record, indent=2) + "\n")
    def run(command, name, wall, environment):
        result = owner.run_command(command, environment, out / (name + ".log"), wall, 8388608)
        record[name] = result
        (out / "closed-stages.json").write_text(json.dumps(record, indent=2) + "\n")
        assert result["cleanup_complete"], "unresolved ownership; do not inspect output"
        data = (out / (name + ".log")).read_bytes()
        assert hashlib.sha256(data).hexdigest() == result["private_log_sha256"]
        assert result["exit_code"] == 0 and result["termination"] is None and result["reaped_descendants"] == 0
        return data
    raw = run(build, "build", 300, env)
    artifacts = []
    for line in raw.decode().splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "neighbor_eviction_oracle" and item.get("executable"):
            artifacts.append(item)
    assert len(artifacts) == 1 and artifacts[0]["profile"]["test"] is True
    assert {k: artifacts[0]["profile"][k] for k in ("opt_level", "debuginfo", "debug_assertions", "overflow_checks")} == dict(
        opt_level="3", debuginfo=0, debug_assertions=True, overflow_checks=True)
    exe = Path(artifacts[0]["executable"])
    assert exe.parent == root / "target/release/deps"
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    native = ["/usr/bin/prlimit", "--cpu=45", "--as=4294967296", "--fsize=8388608", "--core=0", "--",
              str(exe), "--exact", "jrcxz_artifact_native::native_jrcxz_artifact_preserves_integer_flags_and_stack",
              "--nocapture", "--test-threads=1"]
    record.update(native_command=native, executable_sha256=digest)
    clean()
    native_env = dict(os.environ, RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1')
    output = run(native, "native", 60, native_env).decode()
    assert output.count("artifact JRCXZ: 4 RCX values x 2 seeds, 16 original/16 linked/16 restored traces, 8 observing callbacks; no qualification claim") == 1
    assert output.count("test result: ok. 1 passed; 0 failed; 0 ignored;") == 1
    clean()
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == digest
    record.update(source_unchanged=True, executable_unchanged=True, load_after=os.getloadavg())
    (out / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
