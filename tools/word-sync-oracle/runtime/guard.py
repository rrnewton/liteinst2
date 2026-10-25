"""Authenticate a frozen active-build binding; never start a process."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import errno
import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUCCESS = b'{"exit": 0, "wall_timeout": false, "absence_proof": "ECHILD", "descendants": 0, "success": true}\n'


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(512 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def files(path):
    result = {}
    for p in sorted(Path(path).rglob("*")):
        assert not p.is_symlink(), str(p)
        if p.is_file():
            result[str(p.relative_to(path))] = sha(p)
    return result


def identity(row):
    path = Path(row["path"])
    assert path.is_absolute() and path.is_file()
    assert str(path.resolve()) == row["resolved_path"]
    stat = path.stat()
    assert [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mode & 0o777] == row["stat"]
    assert sha(path) == row["sha256"]


def configuration_presence(path):
    """Record only permission-denied observation, never infer absent contents."""
    try:
        return Path(path).exists()
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EACCES):
            raise
        return dict(kind="unreadable", operation="exists", errno=error.errno)


def verify():
    manifest = read(HERE / "manifest.json")
    for name, expected in manifest["files"].items():
        path = HERE / name
        assert path.resolve().is_relative_to(HERE) and not path.is_symlink()
        assert sha(path) == expected, name
    inputs = read(HERE / "inputs.json")
    for path, expected in inputs["references"].items():
        assert sha(path) == expected, path
    for path in inputs["absent_configuration"]:
        assert not Path(path).exists(), path
    for path, expected in inputs["unreadable_configuration"].items():
        assert configuration_presence(path) == expected, path
    for row in inputs["identities"]:
        identity(row)
    for row in inputs["tools"].values():
        identity(row)
    build = read(inputs["build_audit"])
    assert sha(inputs["build_audit"]) == inputs["build_audit_sha256"]
    assert build["status"] == "BUILT_REVIEW_REQUIRED_NO_EXECUTION"
    assert build["native_executed"] is False
    assert build["files"] == inputs["build_files"]
    for name, expected in build["files"].items():
        assert sha(Path(inputs["build_audit"]).parent / name) == expected
    binding = read(inputs["binary_binding"])
    assert sha(inputs["binary_binding"]) == inputs["binary_binding_sha256"]
    assert binding["binaries"] == inputs["binaries"]
    assert set(binding["binaries"]) == {"baseline", "native", "calibrations"}
    for row in binding["binaries"].values():
        identity(row)
    assert sha(inputs["review"]["path"]) == inputs["review"]["sha256"]
    inventory = read(HERE / "inventory.json")
    assert inventory["totals"]["native_modes"] == 13
    assert inventory["totals"]["case_lines"] == 838
    assert inventory["totals"]["total_calibrations"] == 26
    return inputs


def receipt(request_path, receipt_path, helper_hash):
    request = read(request_path)
    result = read(receipt_path)
    assert set(result) == {"request_sha256", "helper_sha256", "exit", "wall_timeout", "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256", "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
    assert result["request_sha256"] == sha(request_path)
    assert result["helper_sha256"] == helper_hash
    assert result["exit"] == 0 and result["wall_timeout"] is False
    assert result["unexpected_descendants"] == [] and result["cleanup_events"] == []
    assert result["absence_proof"] == "ECHILD" and result["cleanup_error"] is None
    assert result["aborted"] is None and result["inputs_unchanged"] is True
    assert math.isfinite(result["elapsed_seconds"]) and result["elapsed_seconds"] >= 0
    assert result["stdout_sha256"] == sha(request["stdout"])
    assert result["stderr_sha256"] == sha(request["stderr"])
    return result
