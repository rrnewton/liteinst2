#!/usr/bin/env python3
"""Prepare fixed public generation requests without launching any command.

Compiler output and the fresh model executable require a separate actual-artifact
review before the model requests can be prepared. This is not a supervisor.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")

MATERIAL = Path(__file__).resolve().parent / "reproductions/generation-public-ed67f752"
MATERIAL_SHA256 = "528687f1e91ee69a0ed0602b21372dbb9fec3153759717902a555d7ea5f02f27"
REVISION = "ed67f7528184bf9ba33c05946ed8b07bef1bf41d"
HELPER_SHA256 = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
FLAGS = "-Dwarnings -Funsafe-op-in-unsafe-fn -Ccodegen-units=1"


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


def identity(path):
    path = Path(path).absolute()
    assert path.is_file()
    before = path.stat()
    row = dict(path=str(path), resolved=str(path.resolve()), sha256=sha(path),
               stat=[before.st_dev, before.st_ino, before.st_size, before.st_mode & 0o777])
    after = path.stat()
    assert [after.st_dev, after.st_ino, after.st_size, after.st_mode & 0o777] == row["stat"]
    return row


def configuration(path):
    """Same narrow exists observation as the public Word adapter; no absence inference."""
    try:
        present = Path(path).exists()
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EACCES):
            raise
        return dict(kind="unreadable", operation="exists", errno=error.errno)
    return identity(path) if present else None


def material():
    assert sha(MATERIAL / "files.json") == MATERIAL_SHA256
    rows = read(MATERIAL / "files.json")
    for name, expected in rows.items():
        assert Path(name).name == name and sha(MATERIAL / name) == expected
    source = read(MATERIAL / "source-files.json")
    assert len(source) == 189
    executable_hashes = read(MATERIAL / "tools.json")
    # The helper is authenticated source, not one of the executable roles.
    assert executable_hashes.pop("helper") == HELPER_SHA256
    assert set(executable_hashes) == {"cargo", "rustc", "rustdoc", "cargo_clippy", "clippy_driver",
                                      "msrv_cargo", "msrv_rustc", "helper_python", "timeout"}
    return source, executable_hashes, read(MATERIAL / "inventory.json")


def source_check(repo, source):
    for name, expected in source.items():
        relative = Path(name)
        assert not relative.is_absolute() and ".." not in relative.parts
        path = repo / relative
        assert path.resolve() == path and sha(path) == expected, name


def verify(raw, expected):
    assert sha(raw / "admission.json") == expected
    data = read(raw / "admission.json")
    assert data["raw"] == str(raw) and data["required_revision"] == REVISION
    source, tool_hashes, _ = material()
    assert data["material_sha256"] == MATERIAL_SHA256
    assert data["source_files"] == source and data["generator_sha256"] == sha(__file__)
    assert set(data["tools"]) == set(tool_hashes)
    source_check(Path(data["repo"]), source)
    for role, row in data["tools"].items():
        assert identity(row["path"]) == row and row["sha256"] == tool_hashes[role]
        assert os.access(row["path"], os.X_OK)
    assert sha(Path(data["repo"]) / "tools/word-sync-oracle/bounded_command.py") == HELPER_SHA256
    for path, row in data["cargo_configuration"].items():
        assert configuration(path) == row, path
        if row is not None and row.get("kind") != "unreadable":
            assert sha(raw / "cargo-configuration" / row["sha256"]) == row["sha256"]
    for row in data["requests"].values():
        assert sha(row["path"]) == row["sha256"]
    return data


def request(raw, name, argv, env, repo, compiler):
    directory = raw / name
    directory.mkdir()
    (directory / "tmp").mkdir()
    env = dict(env, TMPDIR=str(directory / "tmp"))
    assert "CARGO_ENCODED_RUSTFLAGS" not in env
    q = dict(argv=argv, cwd=str(repo), env=env,
             stdout=str(directory / "stdout.txt"), stderr=str(directory / "stderr.txt"),
             cpu_seconds=60 if compiler else 20, wall_seconds=90 if compiler else 30,
             file_bytes=134217728 if compiler else 1048576)
    path = directory / "request.json"
    write(path, q)
    return dict(path=str(path), sha256=sha(path))


def prepare(args):
    source, hashes, _ = material()
    repo, raw = args.repo.resolve(strict=True), args.raw.resolve()
    assert raw.is_relative_to(repo / "ignored") and raw != repo / "ignored"
    assert raw.parent.is_dir() and not raw.exists() and not args.raw.is_symlink()
    assert not any(c in str(repo) + str(raw) for c in "\n\r\t:")
    tc, ms = args.toolchain.resolve(strict=True), args.msrv_toolchain.resolve(strict=True)
    cargo_home, user_home = args.cargo_home.resolve(strict=True), args.user_home.resolve(strict=True)
    assert all(p.is_dir() for p in (repo, tc, ms, cargo_home, user_home))
    source_check(repo, source)
    assert sha(repo / "tools/word-sync-oracle/bounded_command.py") == HELPER_SHA256
    paths = {name: tc / "bin" / name.replace("_", "-")
             for name in ("cargo", "rustc", "rustdoc", "cargo_clippy", "clippy_driver")}
    paths.update(msrv_cargo=ms / "bin/cargo", msrv_rustc=ms / "bin/rustc",
                 helper_python=args.helper_python.absolute(), timeout=args.timeout.absolute())
    tools = {name: identity(path) for name, path in paths.items()}
    assert set(tools) == set(hashes)
    for role, row in tools.items():
        assert row["sha256"] == hashes[role] and os.access(row["path"], os.X_OK)
    directories = [p / ".cargo" for p in [repo] + list(repo.parents)]
    directories += [user_home / ".cargo", cargo_home]
    config = {str(directory / name): configuration(directory / name)
              for directory in directories for name in ("config", "config.toml")}
    env = dict(CARGO_BUILD_JOBS="4", CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true",
               CARGO_TARGET_DIR=str(repo / "target"), CARGO_HOME=str(cargo_home), HOME=str(user_home),
               LC_ALL="C", PATH=str(tc / "bin") + ":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1",
               RUSTC=tools["rustc"]["path"], RUSTDOC=tools["rustdoc"]["path"], RUST_TEST_THREADS="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="", RUSTFLAGS=FLAGS, RUSTDOCFLAGS="-Dwarnings",
               CARGO_PROFILE_DEV_CODEGEN_UNITS="1", CARGO_PROFILE_TEST_CODEGEN_UNITS="1")
    common = ["--manifest-path", str(repo / "Cargo.toml"), "-p", "rapid-profiler"]
    tail = ["--offline", "--locked", "--message-format=json"]
    raw.mkdir()
    (raw / "cargo-configuration").mkdir()
    for path, row in config.items():
        if row is not None and row.get("kind") != "unreadable":
            dest = raw / "cargo-configuration" / row["sha256"]
            if not dest.exists():
                with dest.open("xb") as stream:
                    stream.write(Path(path).read_bytes())
            assert sha(dest) == row["sha256"]
    requests = {}
    requests["compile"] = request(raw, "compile", [tools["cargo"]["path"], "test"] + common +
        ["--lib", "--no-run"] + tail, env, repo, True)
    requests["clippy"] = request(raw, "clippy", [tools["cargo"]["path"], "clippy"] + common +
        ["--all-targets", "--all-features"] + tail + ["--", "-D", "warnings"], env, repo, True)
    requests["docs"] = request(raw, "docs", [tools["cargo"]["path"], "test"] + common +
        ["--doc", "--offline", "--locked", "--", "--test-threads=1", "--show-output"], env, repo, False)
    msenv = dict(env, PATH=str(ms / "bin") + ":/usr/bin:/bin", RUSTC=tools["msrv_rustc"]["path"])
    del msenv["RUSTDOC"]
    requests["msrv"] = request(raw, "msrv", [tools["msrv_cargo"]["path"], "check"] + common +
        ["--all-targets", "--all-features"] + tail, msenv, repo, True)
    write(raw / "admission.json", dict(status="REQUESTS_PREPARED_NOT_EXECUTED", required_revision=REVISION,
        tested_revision=None, repo=str(repo), raw=str(raw), source_files=source,
        material_sha256=MATERIAL_SHA256, tools=tools, cargo_configuration=config, requests=requests,
        helper_sha256=HELPER_SHA256, generator_sha256=sha(__file__),
        scope="Source byte match and explicit executable/config observations only; no inferred transitive runtime identities. Root must bind actual Git HEAD and review launch/toolchain ownership."))
    verify(raw, sha(raw / "admission.json"))
    print(json.dumps(dict(admission_sha256=sha(raw / "admission.json"), requests=requests), sort_keys=True))


def models(args):
    raw = args.raw.resolve(strict=True)
    data = verify(raw, args.admission_sha256)
    repo = Path(data["repo"])
    compile_request = Path(data["requests"]["compile"]["path"])
    receipt_path = compile_request.parent / "receipt.json"
    q, r = read(compile_request), read(receipt_path)
    assert r["request_sha256"] == sha(compile_request) and r["helper_sha256"] == HELPER_SHA256
    assert r["exit"] == 0 and r["wall_timeout"] is False and r["inputs_unchanged"] is True
    assert r["unexpected_descendants"] == [] and r["absence_proof"] == "ECHILD"
    assert r["cleanup_events"] == [] and r["cleanup_error"] is None and r["aborted"] is None
    assert sha(q["stdout"]) == r["stdout_sha256"] and sha(q["stderr"]) == r["stderr_sha256"]
    rows = [json.loads(line) for line in Path(q["stdout"]).read_text().splitlines()]
    assert rows and rows[-1] == dict(reason="build-finished", success=True)
    assert all(row["reason"] in ("compiler-artifact", "build-script-executed") for row in rows[:-1])
    selected = [row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable")]
    assert len(selected) == 1
    row = selected[0]
    assert row["package_id"] == "path+file://" + str(repo / "tools/rapid-profiler") + "#rapid-profiler@0.1.0"
    assert Path(row["manifest_path"]) == repo / "tools/rapid-profiler/Cargo.toml"
    assert row["target"]["name"] == "rapid_profiler" and row["target"]["kind"] == ["lib"]
    assert row["target"]["crate_types"] == ["lib"] and row["target"]["edition"] == "2024"
    assert Path(row["target"]["src_path"]) == repo / "tools/rapid-profiler/src/lib.rs"
    assert row["profile"]["test"] is True and row["features"] == []
    binary = Path(row["executable"])
    assert binary.resolve() == binary and binary.is_relative_to(repo / "target/debug/deps")
    assert re.fullmatch(r"rapid_profiler-[0-9a-f]+", binary.name)
    assert binary == args.binary.absolute() and sha(binary) == args.binary_sha256
    assert str(binary) in row["filenames"] and os.access(binary, os.X_OK)
    review = args.artifact_admission.resolve(strict=True)
    assert sha(review) == args.artifact_admission_sha256
    admitted = read(review)
    # This external artifact review is an explicit trust boundary, never inferred
    # from an executable path or a Cargo record. It must follow actual build review.
    assert admitted["status"] == "APPROVED_FRESH_GENERATION_MODEL_ARTIFACT"
    assert admitted["source_admission_sha256"] == args.admission_sha256
    assert admitted["compile_request_sha256"] == sha(compile_request)
    assert admitted["compile_receipt_sha256"] == sha(receipt_path)
    assert admitted["cargo_stdout_sha256"] == r["stdout_sha256"]
    assert admitted["binary"] == dict(path=str(binary), sha256=args.binary_sha256)
    assert admitted["dependency_and_runtime_review_sha256"] == args.dependency_review_sha256
    dep_review = args.dependency_review.resolve(strict=True)
    assert sha(dep_review) == args.dependency_review_sha256
    copied = raw / "model-tests"
    with binary.open("rb") as old, copied.open("xb") as new:
        shutil.copyfileobj(old, new, length=524288)
    copied.chmod(0o700)
    assert sha(copied) == sha(binary) == args.binary_sha256
    env = dict(LC_ALL="C", PATH="/usr/bin:/bin", RUST_TEST_THREADS="1")
    requests = {name: request(raw, name, [str(copied), "generation::tests::", flag], env, repo, False)
                for name, flag in (("list", "--list"), ("models", "--test-threads=1"))}
    write(raw / "model-admission.json", dict(status="MODEL_REQUESTS_PREPARED_NOT_EXECUTED",
        source_admission_sha256=args.admission_sha256, cargo_record=row, binary_sha256=sha(copied),
        original_binary=str(binary), archived_binary=str(copied), requests=requests,
        artifact_admission=dict(path=str(review), sha256=sha(review)),
        dependency_and_runtime_review=dict(path=str(dep_review), sha256=sha(dep_review)),
        inventory_sha256=sha(MATERIAL / "inventory.json")))
    verify(raw, args.admission_sha256)
    print(json.dumps(requests, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare")
    for name in ("repo", "raw", "toolchain", "msrv-toolchain", "cargo-home", "user-home", "helper-python", "timeout"):
        p.add_argument("--" + name, type=Path, required=True)
    p = commands.add_parser("verify")
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--admission-sha256", required=True)
    p = commands.add_parser("models")
    for name in ("raw", "binary", "artifact-admission", "dependency-review"):
        p.add_argument("--" + name, type=Path, required=True)
    for name in ("admission-sha256", "binary-sha256", "artifact-admission-sha256", "dependency-review-sha256"):
        p.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "models":
        models(args)
    else:
        verify(args.raw.resolve(strict=True), args.admission_sha256)
        print("EXACT_SOURCE_TOOLS_CONFIGURATION_REQUESTS_MATCH")


if __name__ == "__main__":
    main()
