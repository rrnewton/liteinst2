#!/usr/bin/env python3
"""Materialize reviewed outer requests; exec the existing helper, never supervise.

Preparation only reads inputs and writes a fresh request/binding directory.
Launch authenticates that binding and replaces itself with bounded_command.py.
There is no process creation, signal handling, waiting, retry or cleanup logic
here: the unchanged helper owns the complete aggregate workload and descendants.
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

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HELPER_SHA = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
BOUNDS = {
    "freeze": (20, 30, 16 * 1024 * 1024),
    "build": (120, 180, 128 * 1024 * 1024),
    "runtime_generation": (20, 30, 16 * 1024 * 1024),
    "qualification": (120, 180, 16 * 1024 * 1024),
    "closed_export": (20, 30, 16 * 1024 * 1024),
}
FIELDS = {
    "freeze": {"toolchain", "toolchain_sha256", "admission", "admission_sha256"},
    "build": {"freeze_sha256"},
    "runtime_generation": {"freeze_sha256", "review", "review_sha256", "admission", "admission_sha256"},
    "qualification": {"manifest_sha256", "source_index_sha256"},
    "closed_export": {"manifest_sha256", "terminal", "terminal_sha256", "aggregate_binding", "aggregate_binding_sha256", "schema", "schema_sha256",
                      "metadata", "metadata_sha256", "export_output", "run_id"},
}


def sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(512 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def identity(path):
    path = Path(path)
    assert path.is_absolute() and path.is_file()
    resolved = path.resolve(strict=True)
    before = path.stat()
    digest = sha(path)
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    return dict(path=str(path), resolved=str(resolved), sha256=digest,
                stat=[before.st_dev, before.st_ino, before.st_size, before.st_mode & 0o777])


def coordinate(value):
    path = Path(value)
    assert path.is_absolute() and path.resolve() == path
    return path


def prepare(parameters, expected, output):
    assert sys.pycache_prefix is None
    parameters = coordinate(parameters)
    assert not parameters.is_symlink() and sha(parameters) == expected
    values = read(parameters)
    phase = values["phase"]
    assert phase in BOUNDS and set(values) == {"phase", "python", "home", "raw"} | FIELDS[phase]
    assert all(isinstance(v, str) and "\0" not in v for v in values.values())
    for key, value in values.items():
        if key.endswith("_sha256"):
            assert re.fullmatch(r"[0-9a-f]{64}", value), key
    raw = coordinate(values["raw"])
    home = coordinate(values["home"])
    assert raw.is_relative_to(ROOT / "ignored") and home.is_dir()
    output = coordinate(output)
    assert output.is_relative_to(ROOT / "ignored") and not output.exists()
    assert not output.is_relative_to(raw) and not raw.is_relative_to(output)
    python = identity(values["python"])
    assert Path(sys.executable).resolve(strict=True) == Path(python["resolved"])
    helper = identity(HERE / "bounded_command.py")
    assert helper["sha256"] == HELPER_SHA
    authenticated = {str(parameters): expected}

    def pin(path, checksum):
        path = coordinate(path)
        assert not path.is_symlink() and sha(path) == checksum
        if str(path) in authenticated:
            assert authenticated[str(path)] == checksum
        authenticated[str(path)] = checksum
        return str(path)

    argv = [python["path"], "-B"]
    if phase == "freeze":
        assert not raw.exists()
        toolchain = pin(values["toolchain"], values["toolchain_sha256"])
        assert identity(read(toolchain)["tools"]["helper_python"]) == python
        argv += [str(HERE / "adapter.py"), "freeze", "--output", str(raw),
                 "--toolchain", toolchain, "--admission", pin(values["admission"], values["admission_sha256"]),
                 "--admission-sha256", values["admission_sha256"]]
    elif phase in {"build", "runtime_generation"}:
        pin(raw / "freeze.json", values["freeze_sha256"])
        frozen = read(raw / "freeze.json")
        assert frozen["tools"]["helper_python"]["path"] == python["path"]
        assert frozen["tools"]["helper_python"]["sha256"] == python["sha256"]
        argv += [str(HERE / "adapter.py"), "build" if phase == "build" else "runtime",
                 "--output", str(raw), "--freeze-sha256", values["freeze_sha256"]]
        assert not (raw / ("build" if phase == "build" else "runtime")).exists()
        if phase == "runtime_generation":
            argv += ["--review", pin(values["review"], values["review_sha256"]),
                     "--review-sha256", values["review_sha256"],
                     "--admission", pin(values["admission"], values["admission_sha256"]),
                     "--admission-sha256", values["admission_sha256"]]
    else:
        runtime = raw / "runtime"
        pin(runtime / "manifest.json", values["manifest_sha256"])
        manifest = read(runtime / "manifest.json")
        for name, checksum in manifest["files"].items():
            pin(runtime / name, checksum)
        inputs = read(runtime / "inputs.json")
        assert inputs["tools"]["helper_python"]["path"] == python["path"]
        assert inputs["tools"]["helper_python"]["sha256"] == python["sha256"]
        if phase == "qualification":
            pin(runtime / "source-files.json", values["source_index_sha256"])
            assert all(not (runtime / name).exists() for name in ("run", "audit-output", "control"))
            argv += [str(runtime / "entry.py"), "run", values["source_index_sha256"],
                     "--manifest-sha256", values["manifest_sha256"]]
        else:
            assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", values["run_id"])
            export = coordinate(values["export_output"])
            assert export.is_relative_to(ROOT / "ignored") and not export.exists()
            assert not export.is_relative_to(raw) and not raw.is_relative_to(export)
            argv += [str(HERE / "export.py"), "--runtime", str(runtime),
                     "--manifest-sha256", values["manifest_sha256"]]
            for key in ("terminal", "aggregate_binding", "schema", "metadata"):
                flag = key.replace("_", "-")
                argv += ["--" + flag, pin(values[key], values[key + "_sha256"]),
                         "--" + flag + "-sha256", values[key + "_sha256"]]
            argv += ["--output", str(export), "--run-id", values["run_id"]]
    # This is an exact source inventory, not execution of imported controllers.
    sources = {str(p): sha(p) for p in sorted(HERE.rglob("*")) if p.is_file()}
    assert all(not Path(p).is_symlink() and Path(p).resolve(strict=True) == Path(p)
               and Path(p).suffix not in {".pyc", ".pyo"} for p in sources)
    cpu, wall, cap = BOUNDS[phase]
    environment = dict(PATH="/usr/bin:/bin", LC_ALL="C", HOME=str(home), PYTHONDONTWRITEBYTECODE="1")
    output.mkdir()
    request = dict(argv=argv, cwd=str(ROOT), env=environment, cpu_seconds=cpu, wall_seconds=wall,
                   file_bytes=cap, stdout=str(output / "outer.stdout"), stderr=str(output / "outer.stderr"))
    save(output / "request.json", request)
    binding = dict(status="OUTER_REQUEST_REVIEW_REQUIRED_NO_EXECUTION", phase=phase, root=str(ROOT),
                   generator=identity(Path(__file__).resolve()), python=python, helper=helper,
                   request=str(output / "request.json"), request_sha256=sha(output / "request.json"),
                   receipt=str(output / "receipt.json"), helper_stdout=str(output / "helper.stdout"),
                   helper_stderr=str(output / "helper.stderr"), environment=environment,
                   sources=sources, authenticated_inputs=authenticated,
                   helper_argv=[python["path"], "-B", helper["path"], "--request", str(output / "request.json"),
                                "--receipt", str(output / "receipt.json")], no_retries=True)
    for row in (python, helper, binding["generator"]):
        assert identity(row["path"]) == row
    assert all(sha(path) == digest for path, digest in {**sources, **authenticated}.items())
    save(output / "binding.json", binding)
    print("OUTER_REQUEST_REVIEW_REQUIRED_NO_EXECUTION", sha(output / "binding.json"), flush=True)


def launch(binding_path, expected):
    assert sys.pycache_prefix is None
    binding_path = coordinate(binding_path)
    assert not binding_path.is_symlink() and sha(binding_path) == expected
    value = read(binding_path)
    assert value["status"] == "OUTER_REQUEST_REVIEW_REQUIRED_NO_EXECUTION" and value["no_retries"] is True
    assert value["root"] == str(ROOT) and value["generator"]["path"] == str(Path(__file__).resolve())
    for row in (value["generator"], value["python"], value["helper"]):
        assert identity(row["path"]) == row
    assert value["helper"]["sha256"] == HELPER_SHA
    assert Path(sys.executable).resolve(strict=True) == Path(value["python"]["resolved"])
    for path, digest in {**value["sources"], **value["authenticated_inputs"]}.items():
        assert sha(path) == digest
    assert sha(value["request"]) == value["request_sha256"]
    request = read(value["request"])
    assert (request["cpu_seconds"], request["wall_seconds"], request["file_bytes"]) == BOUNDS[value["phase"]]
    assert request["cwd"] == str(ROOT) and request["env"] == value["environment"]
    assert set(value["environment"]) == {"PATH", "LC_ALL", "HOME", "PYTHONDONTWRITEBYTECODE"}
    assert value["environment"]["PATH"] == "/usr/bin:/bin" and value["environment"]["LC_ALL"] == "C"
    assert value["environment"]["PYTHONDONTWRITEBYTECODE"] == "1"
    argv = [value["python"]["path"], "-B", value["helper"]["path"], "--request", value["request"], "--receipt", value["receipt"]]
    assert value["helper_argv"] == argv
    for path in (request["stdout"], request["stderr"], value["receipt"], value["helper_stdout"], value["helper_stderr"]):
        assert Path(path).parent == binding_path.parent and not Path(path).exists() and not Path(path).is_symlink()
    os.chdir(ROOT)
    with Path(value["helper_stdout"]).open("xb") as stdout, Path(value["helper_stderr"]).open("xb") as stderr:
        os.dup2(stdout.fileno(), 1)
        os.dup2(stderr.fileno(), 2)
        os.execve(argv[0], argv, value["environment"])
    raise AssertionError("execve unexpectedly returned")


def main():
    parser = argparse.ArgumentParser()
    phases = parser.add_subparsers(dest="phase", required=True)
    prepare_args = phases.add_parser("prepare")
    prepare_args.add_argument("--parameters", type=Path, required=True)
    prepare_args.add_argument("--parameters-sha256", required=True)
    prepare_args.add_argument("--output", type=Path, required=True)
    launch_args = phases.add_parser("launch")
    launch_args.add_argument("--binding", type=Path, required=True)
    launch_args.add_argument("--binding-sha256", required=True)
    args = parser.parse_args()
    if args.phase == "prepare":
        prepare(args.parameters, args.parameters_sha256, args.output)
    else:
        launch(args.binding, args.binding_sha256)


if __name__ == "__main__":
    main()
