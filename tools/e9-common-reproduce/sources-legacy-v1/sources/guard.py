"""Finite source and explicitly reviewed runtime-epoch authentication."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from bootstrap_validate import need


def digest(path):
    p = Path(path)
    before = p.stat()
    need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= 256 * 1024 * 1024, "bounded regular input")
    h = hashlib.sha256()
    with p.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    after = p.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "input stable across whole read")
    return h.hexdigest()


def read(path):
    need(Path(path).stat().st_size <= 16 * 1024 * 1024, "finite JSON input")
    return json.loads(Path(path).read_text())


def source(here, expected):
    need(digest(here / "manifest.json") == expected, "exact reviewed source manifest")
    m = read(here / "manifest.json")
    for name, value in m["files"].items():
        p = here / name
        need(not p.is_symlink() and p.resolve().is_relative_to(here), "owned source path")
        need(digest(p) == value, "source drift: " + name)
    for name, value in m["references"].items():
        need(digest(name) == value, "historical authority drift: " + name)
    inputs = read(here / "inputs.json")
    need(Path(sys.executable).resolve() == Path(inputs["python"]["path"]), "pinned Python owner")
    need(digest(inputs["python"]["path"]) == inputs["python"]["sha256"], "pinned Python bytes")
    need(sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 9) and
         sys.flags.optimize == 0 and sys.dont_write_bytecode, "unchanged Python mode")
    return inputs


def identity(path):
    p = Path(path)
    with p.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 256 * 1024 * 1024, "finite regular identity owner")
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
        after = os.fstat(stream.fileno())
    current = p.stat()
    want = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    need(want == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) ==
         (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns), "one-fd/path identity stable")
    return dict(path=str(p), resolved=str(p.resolve(strict=True)), device=before.st_dev,
                inode=before.st_ino, size=before.st_size, sha256=h.hexdigest())


def epoch(here, expected, path, checksum):
    inputs = source(here, expected)
    need(digest(path) == checksum, "actual reviewed epoch bytes")
    value = read(path)
    need(value["source_manifest_sha256"] == expected and value["status"] == "PREPARED_REVIEW_REQUIRED_NO_WORKLOAD", "separate explicit epoch gate")
    need(set(value["files"]) == set(inputs["runtime_hashes"]), "complete fixed runtime file inventory")
    for name, row in value["files"].items():
        need(row["sha256"] == inputs["runtime_hashes"][name], "no changed runtime bytes admitted")
        need(identity(name) == row, "runtime identity/epoch changed: " + name)
    for name in inputs["absent"]:
        need(not Path(name).exists() and not Path(name).is_symlink(), "required absent preload")
    for name, names in inputs["directory_names"].items():
        need(sorted(p.name for p in Path(name).iterdir()) == names, "runtime configuration directory changed")
    need(not any(name.startswith("LD_") or name.startswith("PYTHON") and name != "PYTHONDONTWRITEBYTECODE" for name in os.environ), "no injected loader/Python environment")
    need(os.environ.get("LC_ALL") == "C" and os.environ.get("PATH") == "/usr/bin:/bin" and
         os.environ.get("PYTHONDONTWRITEBYTECODE") == "1", "fixed outer environment")
    return inputs, value
