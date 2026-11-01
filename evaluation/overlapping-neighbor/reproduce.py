#!/usr/bin/env python3
"""One fresh focused or native campaign at the measured source revision."""
import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("assertions-enabled Python -I -B required")

REVISION = "392e4fbf82df434da0e782ff15556ad1a2b66812"
TREE = "00601c65059e17cb8a78bad0102d3c0e6839c923"
OWNER_SHA = "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
CAP = 8388608
TOOL_SHA = {
    "cargo": "828980723df339d62434390e9fb8ef8831036583343ae2316b7ab5646b5c1953",
    "rustc": "d3a664c970a9fd8361b64194861bebc1ae37b9054e5ee3400dc1c9e691797eea",
    "rustdoc": "3b0c7aef20e0dfdfe2dd19ddb0b40d3b744f76318a44031813f501e1912934df",
}
ROSTERS = {
    "core": (13, 475, "7b7617d6dcaf1564ea30189767b5220b0aacbe661e4eb1d76fad0a055943ed22"),
    "library": (195, 0, "967fb85e67b377379b78999fa9a064b1317ea511f58446fb61e6b04d0e63b74a"),
    "example": (17, 0, "4a2d7d25c3befb3c416b06f4b08f168f793733707d1dfffa35ee32eb02935a6b"),
    "native": (2, 104, "d544edd888d6e3d7c30ad4c0dcc3c132492f0acfdd3499fe2bab80c9db30a36b"),
}
FOCUSED_PREFIX = ["/usr/bin/prlimit", "--cpu=600", "--as=4294967296",
                  "--fsize=536870912", "--core=0", "--"]
COMMANDS = {
    "core": FOCUSED_PREFIX + ["cargo", "test", "--offline", "--locked", "-p",
        "liteinst2", "--lib", "-j", "12", "overlap::tests::", "--", "--test-threads=12"],
    "library": FOCUSED_PREFIX + ["cargo", "test", "--offline", "--locked", "-p",
        "liteinst-rewrite", "--lib", "-j", "12", "--", "--test-threads=12"],
    "example": FOCUSED_PREFIX + ["cargo", "test", "--offline", "--locked", "-p",
        "liteinst-rewrite", "--example", "disassembly_sites", "-j", "12", "--", "--test-threads=12"],
    "native": ["/usr/bin/prlimit", "--as=8589934592", "--core=0", "--", "cargo",
        "test", "--offline", "--locked", "-p", "liteinst2", "--test", "neighbor_eviction_oracle",
        "-j12", "overlapping_artifact_native::", "--", "--test-threads=12", "--nocapture"],
}
NATIVE_NAMES = ["overlapping_artifact_native::native_overlapping_artifact_selected_"
                + order + "_preserves_full_state" for order in ("before", "after")]
NATIVE_LINES = ["overlapping artifact: selected_before=" + value
    + ", 3 selected lengths x 4 victim lengths x 2 seeds, 48 heads, "
    + "96 original/96 linked/96 restored traces, 48 exact source-relay transitions "
    + "and 24 callbacks; no qualification claim" for value in ("false", "true")]


def pin(path):
    path = Path(path)
    before = path.stat()
    raw = path.read_bytes()
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert fields(before) == fields(path.stat()) and len(raw) == before.st_size
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def census(raw, name):
    text = raw.decode("utf-8")
    rows = re.findall(r"^test (\S+) \.\.\. (.*)$", text, re.M)
    names = sorted(n for n, status in rows)
    count, filtered, digest = ROSTERS[name]
    assert len(names) == len(set(names)) == count
    assert all(status == "ok" for _, status in rows)
    assert hashlib.sha256(("\n".join(names) + "\n").encode()).hexdigest() == digest
    assert re.findall(r"^running (\d+) tests?$", text, re.M) == [str(count)]
    summaries = re.findall(r"^test result:.*$", text, re.M)
    assert len(summaries) == 1
    expected = rf"test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in [0-9]+(?:\.[0-9]+)?s"
    assert re.fullmatch(expected, summaries[0])
    if name == "native":
        assert names == sorted(NATIVE_NAMES)
        assert sorted(line for line in text.splitlines() if "overlapping artifact:" in line) == sorted(NATIVE_LINES)
    return {"passed": count, "failed": 0, "ignored": 0, "filtered": filtered,
            "test_names_sha256": digest}


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument("--phase", choices=("focused", "native"), required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--toolchain-bin", type=Path, required=True)
    parser.add_argument("--name", required=True, help="fresh output basename under ignored/")
    args = parser.parse_args()
    assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", args.name)
    root, toolchain = args.root.resolve(strict=True), args.toolchain_bin.resolve(strict=True)
    os.chdir(root)
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) == 12, "reserve twelve exclusive CPUs and launch with that affinity"
    out, logs = root / "ignored" / args.name, root / "target/evaluation" / args.name
    assert not out.exists() and not logs.exists()
    assert out.resolve().is_relative_to(root / "ignored")
    assert logs.resolve().is_relative_to(root / "target/evaluation")
    out.mkdir(parents=True)
    rows, error, source_ok = [], None, False
    selected = ["core", "library", "example"] if args.phase == "focused" else ["native"]
    meta = dict(os.environ, PATH="/usr/bin:/bin", GIT_CONFIG_COUNT="2",
                GIT_CONFIG_KEY_0="index.threads", GIT_CONFIG_VALUE_0="1",
                GIT_CONFIG_KEY_1="core.preloadIndex", GIT_CONFIG_VALUE_1="false")
    git = lambda *a: subprocess.check_output(["/usr/bin/git", *a], env=meta, timeout=20, text=True).strip()
    helper = root / "evaluation/admission/processes.py"
    frozen = {}

    def unchanged():
        return (git("rev-parse", "HEAD") == REVISION and git("rev-parse", "HEAD^{tree}") == TREE
                and not git("status", "--porcelain", "--untracked-files=no")
                and sorted(os.sched_getaffinity(0)) == cpus
                and all(pin(path) == value for path, value in frozen.items()))

    def capacity(reserve):
        values = [int(subprocess.check_output(["/usr/bin/du", "-s", "-B1", *flags, str(root)],
                  timeout=60).split()[0]) for flags in ([], ["--apparent-size"])]
        assert max(values) + reserve < 20000000000, "storage cap/reserve exceeded"
        return values

    try:
        paths = [helper, Path(__file__).resolve(), Path(sys.executable), Path("/usr/bin/git"),
                 Path("/usr/bin/prlimit"), Path("/usr/bin/du")]
        paths += [toolchain / name for name in TOOL_SHA]
        frozen = {path: pin(path) for path in paths}
        assert pin(helper)["sha256"] == OWNER_SHA
        for name, digest in TOOL_SHA.items():
            assert pin(toolchain / name)["sha256"] == digest, "measured Rust toolchain required"
        assert unchanged()
        before_capacity = capacity(2214592512)
        env = {k: v for k, v in os.environ.items() if not (k.startswith("CARGO_") or k.startswith("RUST"))}
        env.update(PATH=str(toolchain) + ":/usr/bin:/bin", CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="12",
            CARGO_TARGET_DIR=str(root / "target"), CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
            CARGO_NET_OFFLINE="true", RUST_TEST_THREADS="12", PYTHONDONTWRITEBYTECODE="1")
        env.update(RUSTC=str(toolchain / "rustc"), RUSTDOC=str(toolchain / "rustdoc"))
        save(out / "planned.json", {"revision": REVISION, "tree": TREE, "phase": args.phase,
            "cpus": cpus, "commands": {n: COMMANDS[n] for n in selected}, "wall_seconds_each": 300,
            "log_bytes_each": CAP, "capacity_before": before_capacity, "attempts_each": 1,
            "tools": {p.name: value for p, value in frozen.items()},
            "independent_live_witness": False, "qualification": False})
        logs.mkdir(parents=True)
        spec = importlib.util.spec_from_file_location("overlap_public_owner", helper)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        for name in selected:
            assert unchanged()
            row = {"stage": name, "owner_call_requested": True, "load_before": list(os.getloadavg())}
            rows.append(row)
            result = owner.run_command(COMMANDS[name], env, logs / (name + ".log"), 300, CAP)
            row["owner"] = result
            save(out / (name + "-owner-closed.json"), result)
            assert result["cleanup_complete"] is True, "do not read an open capture"
            assert (logs / (name + ".log")).stat().st_size <= CAP
            raw = (logs / (name + ".log")).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
            row["load_after"] = list(os.getloadavg())
            assert result["exit_code"] == 0 and result["termination"] is None and result["reaped_descendants"] == 0
            row["census"] = census(raw, name)
            assert unchanged()
    except BaseException as failure:
        error = type(failure).__name__
    finally:
        try:
            source_ok = unchanged()
            capacity(0)
        except BaseException:
            source_ok = False
        passed = error is None and source_ok and len(rows) == len(selected)
        save(out / "closed.json", {"status": "PASS" if passed else "FAILED", "revision": REVISION,
            "phase": args.phase, "stages": rows, "error_type": error, "source_tools_unchanged": source_ok,
            "not_started": selected[len(rows):], "retry": False, "qualification": False,
            "independent_live_witness": False, "full_gate": "NOT_RUN_BY_THIS_SCRIPT"})
        with (out / "results.csv").open("x", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["stage", "exit_code", "seconds", "passed", "failed", "ignored", "filtered"])
            for row in rows:
                o, c = row.get("owner", {}), row.get("census", {})
                writer.writerow([row["stage"], o.get("exit_code"), o.get("seconds"),
                                 *[c.get(k) for k in ("passed", "failed", "ignored", "filtered")]])
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
