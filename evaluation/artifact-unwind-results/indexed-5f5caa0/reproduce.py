#!/usr/bin/env python3
"""Reproduce the fixed build and structural inspection; no native admission."""
import sys
if sys.flags.optimize:
    raise SystemExit("Assertions required")
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

REVISION = "5f5caa0af44ee8a56e99b2351cac8ed27bd8e3d7"
OWNER_SHA = "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
BUILD_SHA = "265089b24d3dc56afb87e5ba5bc9a232db948f0ca4c890f88e47ae61a618e3d7"
root = Path.cwd().resolve()


def clean():
    git = lambda *a: subprocess.check_output(["git", *a], cwd=root, timeout=10)
    assert git("rev-parse", "HEAD").decode().strip() == REVISION
    assert not git("status", "--porcelain", "--untracked-files=all"), "Clean checkout required"


def module(name, relative, digest):
    path = root / relative
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
for option in ("out", "toolchain", "source-review"):
    parser.add_argument("--" + option, type=Path, required=True)
args = parser.parse_args()
clean()
assert sys.version_info[:2] == (3, 9)
build = module("indexed_build", "tools/unwind-oracle/indexed_dso/build_fixture.py", BUILD_SHA)
owner = module("indexed_owner", "evaluation/admission/processes.py", OWNER_SHA)
out = args.out.absolute()
assert out.resolve() == out and out.is_relative_to(root / "ignored") and not out.exists()
out.mkdir(mode=0o700)
(out / "tmp").mkdir()
toolchain, review = args.toolchain.resolve(strict=True), args.source_review.resolve(strict=True)
source = {str(p.relative_to(root)): build.pin(p)["sha256"] for p in build.SOURCES}
assert len(source) == 8
admission = out / "source-admission.json"
build.save(admission, dict(schema="indexed-dso-build-source-v1", base_revision=REVISION,
    source_files=source, review=dict(path=str(review), sha256=build.pin(review)["sha256"])))
rust = Path(os.environ["RUST_TOOLCHAIN_BIN"]).resolve(strict=True)
env = dict(HOME=os.environ["HOME"], CARGO_HOME=os.environ["CARGO_HOME"],
    PATH=str(rust) + ":/usr/bin:/bin", RUSTC=str(rust / "rustc"), RUSTDOC=str(rust / "rustdoc"),
    CARGO_TARGET_DIR=str(root / "target"), CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="4",
    CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never", LANG="C.UTF-8", LC_ALL="C.UTF-8",
    PYTHONDONTWRITEBYTECODE="1", LITEINST_EVALUATION="1")
for profile in ("DEV", "TEST"):
    for key, value in (("DEBUG", "0"), ("OPT_LEVEL", "0"), ("DEBUG_ASSERTIONS", "true"), ("OVERFLOW_CHECKS", "true")):
        env["CARGO_PROFILE_" + profile + "_" + key] = value
env.update({key: str(out / "tmp") for key in ("TMPDIR", "TEMP", "TMP")})
affinity = sorted(os.sched_getaffinity(0))
assert len(affinity) == 4, "Run under the caller's four-CPU reservation"
rows = [dict(name=n, status="UNRUN", attempts=0) for n in ("build", "inspect")]
record = dict(revision=REVISION, status="INCOMPLETE", native_qualification=False,
    source_files=source, toolchain=build.pin(toolchain), source_review=build.pin(review),
    adapter=build.pin(Path(__file__).resolve()), rust_tools=[build.pin(rust / n) for n in ("cargo", "rustc", "rustdoc")],
    environment=env, affinity=affinity, load_before=Path("/proc/loadavg").read_text().split()[:3],
    stage_status_scope="Outer command closure only; final structural status requires all joins", stages=rows)
frozen = record["rust_tools"] + [record["toolchain"], record["source_review"], record["adapter"], build.pin(admission)]
build.save(out / "reproduction.json", record)


def run(index, command):
    clean()
    build.check(frozen)
    row = rows[index]
    row.update(status="DISPATCHED_UNRESOLVED", attempts=1, argv=command)
    build.save(out / "reproduction.json", record, True)
    logs = root / "target/evaluation" / ("indexed-reproduce-" + hashlib.sha256(str(out).encode()).hexdigest())
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / (row["name"] + ".log")
    assert not log.exists()
    closed = owner.run_command(command, env, log, 1200, 8 * 1024 * 1024)
    row.update(status="CLOSED", closed=closed)
    build.save(out / "reproduction.json", record, True)
    assert closed["cleanup_complete"] is True, "Unknown custody: do not read outputs or continue"
    data = build.raw(log)
    assert len(data) <= 8 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == closed["private_log_sha256"]
    with (out / (row["name"] + ".log")).open("xb") as stream:
        stream.write(data)
    assert closed["exit_code"] == 0 and closed["termination"] is None and closed["reaped_descendants"] == 0
    clean()
    build.check(frozen)
    row["status"] = "PASS"
    build.save(out / "reproduction.json", record, True)
    return data


python = str(Path(sys.executable).resolve())
run(0, [python, "-B", "tools/unwind-oracle/indexed_dso/build_fixture.py", "--out", str(out / "build"),
    "--toolchain", str(toolchain), "--toolchain-sha256", record["toolchain"]["sha256"],
    "--source-admission", str(admission), "--source-admission-sha256", build.pin(admission)["sha256"]])
manifest_pin = build.pin(out / "build/manifest.json")
manifest = build.load(out / "build/manifest.json")
build.check([manifest_pin])
assert manifest["status"] == "BUILD_ONLY_REVIEW_REQUIRED" and manifest["native_qualification"] is False
assert [(r["name"], r["status"], r["attempts"]) for r in manifest["stages"]] == [(n, "PASS", 1) for n in build.STAGES]
subject, caller = [out / "build" / ("libli2_uw_" + n + ".so") for n in ("subject", "caller")]
elf_pins = [build.pin(p) for p in (subject, caller)]
for name, pin in zip(("subject", "caller"), elf_pins):
    assert pin == manifest["links"][name]["elf"]
    assert pin == manifest["retained_files"]["libli2_uw_" + name + ".so"]
frozen.extend([manifest_pin] + elf_pins)
subject_sha, caller_sha = [pin["sha256"] for pin in elf_pins]
data = run(1, ["/usr/bin/timeout", "--signal=TERM", "--kill-after=3s", "180s", "cargo", "run",
    "--offline", "--locked", "-p", "liteinst-rewrite", "--example", "indexed_dso_inspect", "--",
    str(subject), subject_sha, str(caller), caller_sha])
values = [json.loads(line, object_pairs_hook=build.unique) for line in data.decode().splitlines()
          if line.startswith('{"schema":"li2-indexed-dso-inspection-v1"')]
assert len(values) == 1
value = values[0]
assert value["status"] == "STRUCTURAL_INSPECTION_ONLY" and value["native_qualification"] is False and value["caller_cfi_qualified"] is False
assert (value["subject_sha256"], value["caller_sha256"]) == (subject_sha, caller_sha)
record.update(status="STRUCTURAL_INSPECTION_ONLY", inspection=value, load_after=Path("/proc/loadavg").read_text().split()[:3])
build.save(out / "reproduction.json", record, True)
print(json.dumps(value, sort_keys=True))
