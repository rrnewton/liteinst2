#!/usr/bin/env python3
"""Prepare one fixed pure-control request for the existing bounded helper.

This program never launches a process. Historical receipts remain historical;
new local tool identities and output paths require review before execution.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

MATERIALS = {
    "calibrate.py": "a7187cb187f618e840e9685a00c166d880f67c30b9f867a7c99f717343af664c",
    "cases.json": "6308ed81ba035d1fb6586dc89f43cd5a506e9e08bc885189988795f8a298e95c",
    "expected.json": "14a039db5fdc3fb47795dd7f0a2ca1c15a1a6dabbc5881d63d9105b8c97cc9e5",
}
ADAPTER_SHA = "fd83e351ba6c13f18554f7103aeddf7547175cbfba273a7d89cf5df3e28e7d30"
HELPER_SHA = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"


def sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(512 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def coordinate(value):
    path = Path(value)
    assert path.is_absolute() and path.resolve() == path and not path.is_symlink()
    assert not any(c in str(path) for c in ("\0", "\n", "\r"))
    return path


def identity(path, expected, executable=False):
    path = Path(path)
    assert path.is_absolute() and path.is_file()
    assert re.fullmatch(r"[0-9a-f]{64}", expected)
    resolved = path.resolve(strict=True)
    before = path.stat()
    checksum = sha(path)
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    assert checksum == expected
    if executable:
        assert os.access(path, os.X_OK)
    return dict(path=str(path), resolved=str(resolved), sha256=checksum,
                stat=[before.st_dev, before.st_ino, before.st_size, before.st_mode & 0o777])


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    assert sys.pycache_prefix is None
    parser = argparse.ArgumentParser()
    for name in ("repo", "output", "python", "python-sha256", "timeout", "timeout-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    repo, output = coordinate(args.repo), coordinate(args.output)
    here = Path(__file__).resolve().parent
    assert here == repo / "evaluation/reproductions/unwind-consumer-env-dependency-v4"
    assert repo.is_dir() and output.parent.is_dir() and not output.exists()
    assert output.is_relative_to(repo / "ignored") and output != repo / "ignored"
    assert not output.is_relative_to(here) and not here.is_relative_to(output)
    python = identity(args.python, args.python_sha256, executable=True)
    timeout = identity(args.timeout, args.timeout_sha256, executable=True)
    assert Path(sys.executable).resolve(strict=True) == Path(python["resolved"])
    helper_path = coordinate(repo / "tools/unwind-oracle/bounded_command.py")
    adapter_path = coordinate(repo / "tools/unwind-oracle/adapter.py")
    helper = identity(helper_path, HELPER_SHA)
    assert sha(adapter_path) == ADAPTER_SHA
    sources = {str(Path(__file__).resolve()): sha(__file__), str(helper_path): HELPER_SHA,
               str(adapter_path): ADAPTER_SHA}
    for name, checksum in MATERIALS.items():
        path = coordinate(here / name)
        assert path.is_file() and sha(path) == checksum
        sources[str(path)] = checksum
    cases = json.loads((here / "cases.json").read_text())["cases"]
    expected = json.loads((here / "expected.json").read_text())
    assert len(cases) == 36 and len({row["name"] for row in cases}) == 36
    assert expected["accepted"] == [r["name"] for r in cases if r["expected"] == "accept"]
    assert expected["refused"] == [r["name"] for r in cases if r["expected"] == "refuse"]
    assert len(expected["accepted"]) == 4 and len(expected["refused"]) == 32
    argv = [python["path"], "-B", str(here / "calibrate.py"), "--adapter", str(adapter_path),
            "--adapter-sha256", ADAPTER_SHA, "--cases", str(here / "cases.json"),
            "--cases-sha256", MATERIALS["cases.json"], "--expected", str(here / "expected.json"),
            "--expected-sha256", MATERIALS["expected.json"], "--self-sha256", MATERIALS["calibrate.py"]]
    environment = dict(LC_ALL="C", PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
    request = dict(argv=argv, cwd=str(repo), env=environment, cpu_seconds=20,
                   wall_seconds=30, file_bytes=16 * 1024 * 1024,
                   stdout=str(output / "stdout"), stderr=str(output / "stderr"))
    output.mkdir()
    save(output / "request.json", request)
    helper_argv = [python["path"], "-B", str(helper_path), "--request", str(output / "request.json"),
                   "--receipt", str(output / "receipt.json")]
    binding = dict(status="PREPARED_REVIEW_REQUIRED_NO_EXECUTION", source_kind="exact_material_snapshot",
                   sources=sources, request_sha256=sha(output / "request.json"),
                   python=python, timeout=timeout, helper=helper, helper_argv=helper_argv,
                   outer_argv=[timeout["path"], "--signal=TERM", "--kill-after=10s", "40s"] + helper_argv,
                   parent_timeout_seconds=55, helper_stdout=str(output / "helper.stdout"),
                   helper_stderr=str(output / "helper.stderr"), receipt=str(output / "receipt.json"),
                   required_stdout=json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n",
                   required_stderr="", required_controls=dict(accepted=4, refused=32),
                   no_retries=True, launched_processes=0)
    for row in (python, timeout, helper):
        assert identity(row["path"], row["sha256"]) == row
    assert all(sha(path) == checksum for path, checksum in sources.items())
    save(output / "binding.json", binding)
    print("PREPARED_REVIEW_REQUIRED_NO_EXECUTION", sha(output / "binding.json"), flush=True)


if __name__ == "__main__":
    main()
