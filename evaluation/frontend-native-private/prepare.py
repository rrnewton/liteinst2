#!/usr/bin/env python3
"""Copy the fixed native v6 sources or render one original helper request.

No workload is launched. Source/tool/configuration, compiler artifacts and
complete captures require the existing separate launch and result reviews.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")

HERE = Path(__file__).resolve().parent
HELPER = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(524288), b""):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def relative(name):
    path = Path(name)
    assert name and not path.is_absolute() and ".." not in path.parts
    assert str(path) == name
    return path


def material(expected):
    assert re.fullmatch("[0-9a-f]{64}", expected)
    assert sha(HERE / "material.json") == expected
    for name, digest in read(HERE / "material.json").items():
        path = HERE / relative(name)
        assert path.resolve(strict=True) == path and sha(path) == digest, name
    return read(HERE / "reproduction.json")


def expand(value, coordinates):
    if isinstance(value, str):
        for name, path in coordinates.items():
            value = value.replace("${" + name + "}", path)
        assert "${" not in value, value
        return value
    if isinstance(value, list):
        return [expand(item, coordinates) for item in value]
    if isinstance(value, dict):
        return {expand(k, coordinates): expand(v, coordinates) for k, v in value.items()}
    return value


def source(workspace):
    rows = read(HERE / "source-files.json")
    assert len(rows) == 523
    actual = set()
    visited = 0
    for directory, names, files in os.walk(workspace, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            visited += 1
            assert visited <= 2048 and not path.is_symlink()
        for name in files:
            path = Path(directory) / name
            assert path.is_file()
            actual.add(str(path.relative_to(workspace)))
    assert actual == set(rows)
    for name, digest in rows.items():
        path = workspace / relative(name)
        assert path.resolve(strict=True) == path and sha(path) == digest, name
    return rows


def stage(args, contract):
    repo = args.repo.resolve(strict=True)
    base = args.base_root.resolve(strict=True)
    raw = args.raw.absolute()
    assert raw == raw.resolve() and raw.is_relative_to(repo / "ignored")
    assert raw != repo / "ignored" and raw.parent.is_dir()
    assert not raw.exists() and not raw.is_symlink()
    assert sha(repo / "tools/unwind-oracle/bounded_command.py") == HELPER
    coordinates = dict(REPO=str(repo), RAW=str(raw), WORKSPACE=str(raw / "workspace"),
          TOOLCHAIN=str(args.toolchain.resolve(strict=True)),
          MSRV_TOOLCHAIN=str(args.msrv_toolchain.resolve(strict=True)),
          USER_HOME=str(args.user_home.resolve(strict=True)),
          CARGO_HOME=str(args.cargo_home.resolve(strict=True)), CC=str(args.cc.absolute()))
    for name, value in coordinates.items():
        assert re.fullmatch(r"/[A-Za-z0-9_./+@-]+", value)
        if name not in ("RAW", "WORKSPACE", "CC"):
            assert Path(value).is_dir()
    assert Path(coordinates["CC"]).is_file() and os.access(coordinates["CC"], os.X_OK)
    rows = read(HERE / "source-files.json")
    assert len(rows) == 523
    overlay = set(contract["overlay_paths"])
    assert len(overlay) == 13 and overlay <= rows.keys()
    inputs = {}
    for name, digest in rows.items():
        path = (HERE / "overlay" if name in overlay else base) / relative(name)
        assert path.resolve(strict=True) == path and sha(path) == digest, name
        inputs[name] = path
    raw.mkdir()
    workspace = raw / "workspace"
    workspace.mkdir()
    for name, path in inputs.items():
        dest = workspace / relative(name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as stream:
            stream.write(path.read_bytes())
        assert sha(dest) == rows[name]
    for name in ("requests", "artifacts", "subject"):
        (raw / name).mkdir()
    assert source(workspace) == rows
    write(raw / "coordinates.json", coordinates)
    write(raw / "prepared.json", dict(status="SOURCE_COPY_ONLY_NOT_LAUNCH_ADMITTED",
          tested_revision=None, repo=str(repo), raw=str(raw), workspace=str(workspace),
          source_files=rows, material_sha256=args.materials_sha256,
          coordinates_sha256=sha(raw / "coordinates.json"), generator_sha256=sha(__file__)))
    print("SOURCE_COPY_ONLY_NOT_LAUNCH_ADMITTED", sha(raw / "prepared.json"))


def request(args, contract):
    raw = args.raw.resolve(strict=True)
    assert sha(raw / "prepared.json") == args.prepared_sha256
    prepared = read(raw / "prepared.json")
    assert prepared["status"] == "SOURCE_COPY_ONLY_NOT_LAUNCH_ADMITTED"
    assert prepared["raw"] == str(raw) and prepared["workspace"] == str(raw / "workspace")
    assert prepared["material_sha256"] == args.materials_sha256
    assert prepared["generator_sha256"] == sha(__file__)
    assert prepared["source_files"] == source(raw / "workspace")
    assert sha(raw / "coordinates.json") == prepared["coordinates_sha256"]
    coordinates = read(raw / "coordinates.json")
    assert set(coordinates) == {"REPO", "RAW", "WORKSPACE", "TOOLCHAIN",
                                "MSRV_TOOLCHAIN", "USER_HOME", "CARGO_HOME", "CC"}
    assert coordinates["REPO"] == prepared["repo"]
    assert coordinates["RAW"] == str(raw) and coordinates["WORKSPACE"] == prepared["workspace"]
    for name, value in coordinates.items():
        assert type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./+@-]+", value)
        path = Path(value)
        if name == "CC":
            assert path.is_file() and os.access(path, os.X_OK)
        else:
            assert path.resolve(strict=True) == path and path.is_dir()
    repo = Path(coordinates["REPO"])
    assert raw.is_relative_to(repo / "ignored") and raw != repo / "ignored"
    assert sha(repo / "tools/unwind-oracle/bounded_command.py") == HELPER
    requests = raw / "requests"
    assert not requests.is_symlink() and requests.resolve(strict=True) == requests and requests.is_dir()
    assert args.phase in contract["phases"]
    q = expand(read(HERE / "requests" / (args.phase + ".json")), coordinates)
    assert "CARGO_ENCODED_RUSTFLAGS" not in q["env"]
    directory = raw / args.phase
    assert not directory.exists() and not directory.is_symlink()
    for key in ("stdout", "stderr"):
        assert Path(q[key]).parent == directory
    assert q["env"]["TMPDIR"] == str(directory / "tmp")
    qp = raw / "requests" / (args.phase + ".json")
    ip = raw / "requests" / (args.phase + ".invocation.json")
    assert not qp.exists() and not qp.is_symlink() and not ip.exists() and not ip.is_symlink()
    directory.mkdir()
    (directory / "tmp").mkdir()
    write(qp, q)
    argv = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
            str(q["wall_seconds"] + 10) + "s", "/usr/bin/python3.9", "-B",
            str(repo / "tools/unwind-oracle/bounded_command.py"),
            "--request", str(qp), "--receipt", str(directory / "receipt.json")]
    write(ip, dict(status="REQUEST_ONLY_NOT_LAUNCH_ADMITTED", phase=args.phase,
          request_sha256=sha(qp), prepared_sha256=args.prepared_sha256,
          outer_argv=argv, cwd=coordinates["REPO"],
          env=dict(LC_ALL="C", PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1"),
          stdin="DEVNULL", stdout=str(directory / "helper.stdout"),
          stderr=str(directory / "helper.stderr"),
          parent_timeout_seconds=q["wall_seconds"] + 25,
          required_external_review="Original input/target/artifact and whole-output contracts remain mandatory; this renderer grants no execution or result authority."))
    assert source(raw / "workspace") == prepared["source_files"]
    print("REQUEST_ONLY_NOT_LAUNCH_ADMITTED", args.phase, sha(qp), sha(ip))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--materials-sha256", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("stage")
    for name in ("repo", "base-root", "raw", "toolchain", "msrv-toolchain",
                 "user-home", "cargo-home", "cc"):
        p.add_argument("--" + name, type=Path, required=True)
    p = commands.add_parser("request")
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--prepared-sha256", required=True)
    p.add_argument("--phase", required=True)
    args = parser.parse_args()
    contract = material(args.materials_sha256)
    if args.command == "stage":
        stage(args, contract)
    else:
        request(args, contract)


if __name__ == "__main__":
    main()
