#!/usr/bin/env python3
"""Copy exact TLS sources and prepare requests; never launch a workload.

Actual compiler/dependency/artifact review is a separate trusted admission.
This program neither supplies that review nor qualifies a test result.
"""
import argparse
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import sys

if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")

MATERIAL = Path(__file__).resolve().parent
MATERIAL_SHA256 = "d7e8a8569701e97b60d3744b4f87cbacfaeb24bb3ba05a600aa3eea3db5513bc"
HELPER_SHA256 = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
PHASES = ["library", "compile", "list", "models", "clippy", "docs", "msrv"]


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


def safe_relative(name):
    p = Path(name)
    assert name and not p.is_absolute() and ".." not in p.parts
    return p


def material():
    assert sha(MATERIAL / "material.json") == MATERIAL_SHA256
    for name, expected in read(MATERIAL / "material.json").items():
        assert sha(MATERIAL / safe_relative(name)) == expected, name
    return read(MATERIAL / "attempts.json")


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


def identity(path):
    p = Path(path).absolute()
    before = p.stat()
    assert stat.S_ISREG(before.st_mode), str(p)
    fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    row = dict(path=str(p), resolved=str(p.resolve(strict=True)),
               sha256=sha(p), stat=fields(before))
    assert fields(p.stat()) == row["stat"], str(p)
    return row


def configuration(path):
    try:
        Path(path).stat()
    except OSError as error:
        assert error.errno in (errno.ENOENT, errno.EPERM, errno.EACCES)
        return dict(path=str(path), operation="stat", errno=error.errno,
                    kind="absent" if error.errno == errno.ENOENT else "permission_denied")
    return dict(identity(path), kind="file")


def source_map(attempt):
    rows = read(MATERIAL / "sources" / attempt / "source-files.json")
    assert len(rows) == 514
    return rows


def observe(coordinates, attempt):
    workspace = Path(coordinates["WORKSPACE"])
    sources = {}
    for name, expected in source_map(attempt).items():
        p = workspace / safe_relative(name)
        assert p.resolve(strict=True) == p and sha(p) == expected, name
        sources[str(p)] = identity(p)
    tool_bytes = expand(read(MATERIAL / "expected/selected-tool-bytes.json"), coordinates)
    registry_bytes = expand(read(MATERIAL / "expected/registry-byte-inventory.json"), coordinates)["files"]
    assert len(tool_bytes) == 209 and len(registry_bytes) == 995
    other = {}
    for path, expected in {**tool_bytes, **registry_bytes}.items():
        row = identity(path)
        assert row["sha256"] == expected["sha256"] and row["resolved"] == expected["resolved"], path
        other[path] = row
    roles = expand(read(MATERIAL / "expected/tool-role-bytes.json"), coordinates)
    assert len(roles) == 19
    for role, expected in roles.items():
        row = other[expected["path"]]
        assert all(row[k] == expected[k] for k in ("path", "resolved", "sha256"))
        assert role == "helper_source" or os.access(row["path"], os.X_OK)
    directories = {str(p / ".cargo") for p in [workspace] + list(workspace.parents)}
    directories.update([str(Path(coordinates["USER_HOME"]) / ".cargo"), coordinates["CARGO_HOME"]])
    configs = [configuration(Path(d) / n) for d in sorted(directories) for n in ("config", "config.toml")]
    lookups = []
    for toolchain in ("TOOLCHAIN", "MSRV_TOOLCHAIN"):
        path = coordinates[toolchain] + "/bin:/usr/bin:/bin"
        for command in ("clang", "cc", "ld"):
            selected = shutil.which(command, path=path)
            assert selected == roles[command]["path"]
            lookups.append(dict(PATH=path, command=command, selected=selected,
                                identity=identity(selected)))
    all_files = {**sources, **other}
    assert len(all_files) == 1718 and len(lookups) == 6
    return dict(files=all_files, configurations=configs, PATH_lookups=lookups)


def prepared(raw, expected):
    material()
    assert sha(raw / "prepared.json") == expected
    data = read(raw / "prepared.json")
    assert data["status"] == "PREPARED_NOT_LAUNCH_ADMITTED" and data["raw"] == str(raw)
    assert data["coordinates"]["RAW"] == str(raw)
    assert data["coordinates"]["WORKSPACE"] == str(raw / "workspace")
    assert raw.is_relative_to(Path(data["coordinates"]["REPO"]) / "ignored")
    assert data["source_files"] == source_map(data["attempt"])
    assert data["generator_sha256"] == sha(__file__) and data["material_sha256"] == MATERIAL_SHA256
    assert observe(data["coordinates"], data["attempt"]) == data["observations"]
    for phase, row in data["requests"].items():
        assert phase in ("library", "compile") and sha(row["path"]) == row["sha256"]
    return data


def request(raw, phase, coordinates):
    q = expand(read(MATERIAL / "requests" / (phase + ".json")), coordinates)
    directory = raw / phase
    directory.mkdir()
    (directory / "tmp").mkdir()
    assert "CARGO_ENCODED_RUSTFLAGS" not in q["env"]
    path = raw / "requests" / (phase + ".json")
    write(path, q)
    argv = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
            str(q["wall_seconds"] + 10) + "s", "/usr/bin/python3.9", "-B",
            coordinates["REPO"] + "/tools/unwind-oracle/bounded_command.py",
            "--request", str(path), "--receipt", str(directory / "receipt.json")]
    return dict(path=str(path), sha256=sha(path), outer_argv=argv,
                outer=dict(cwd=coordinates["WORKSPACE"], parent_timeout_seconds=q["wall_seconds"] + 25,
                           env=dict(LC_ALL="C", PATH=q["env"]["PATH"] if phase in ("library", "compile") else "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1",
                                    TMPDIR=str(directory / "tmp"))))


def prepare(args):
    attempts = material()
    repo, base = args.repo.resolve(strict=True), args.base_root.resolve(strict=True)
    raw = args.raw.absolute()
    assert raw == raw.resolve() and raw.is_relative_to(repo / "ignored") and raw != repo / "ignored"
    assert raw.parent.is_dir() and not raw.exists() and not raw.is_symlink()
    coordinates = dict(REPO=str(repo), RAW=str(raw), WORKSPACE=str(raw / "workspace"),
                       TOOLCHAIN=str(args.toolchain.resolve(strict=True)),
                       MSRV_TOOLCHAIN=str(args.msrv_toolchain.resolve(strict=True)),
                       USER_HOME=str(args.user_home.resolve(strict=True)),
                       CARGO_HOME=str(args.cargo_home.resolve(strict=True)))
    assert all(not any(c in s for c in "\n\r\t:") for s in coordinates.values())
    assert all(Path(coordinates[k]).is_dir() for k in ("REPO", "TOOLCHAIN", "MSRV_TOOLCHAIN", "USER_HOME", "CARGO_HOME"))
    assert sha(repo / "tools/unwind-oracle/bounded_command.py") == HELPER_SHA256
    source = source_map(args.attempt)
    inputs = {}
    for name, expected in source.items():
        p = (MATERIAL / "sources" / args.attempt / "overlay" / name
             if name in attempts["source_overlay_paths"] else base / safe_relative(name))
        assert p.resolve(strict=True) == p and sha(p) == expected, name
        inputs[name] = p
    raw.mkdir()
    (raw / "workspace").mkdir()
    (raw / "requests").mkdir()
    for name, p in inputs.items():
        dest = raw / "workspace" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as stream:
            stream.write(p.read_bytes())
        assert sha(dest) == source[name]
    observations = observe(coordinates, args.attempt)
    requests = {phase: request(raw, phase, coordinates) for phase in ("library", "compile")}
    write(raw / "prepared.json", dict(status="PREPARED_NOT_LAUNCH_ADMITTED", tested_revision=None,
          base_revision=attempts["base_revision"], attempt=args.attempt, raw=str(raw),
          coordinates=coordinates, source_files=source, observations=observations, requests=requests,
          material_sha256=MATERIAL_SHA256, generator_sha256=sha(__file__),
          scope="Fresh local observations only. Independent source/tool/config admission is required before any launch."))
    assert observe(coordinates, args.attempt) == observations
    print(json.dumps(dict(prepared_sha256=sha(raw / "prepared.json"), requests=requests), sort_keys=True))


def receipt(raw, phase):
    qp = raw / "requests" / (phase + ".json")
    rp = raw / phase / "receipt.json"
    q, r = read(qp), read(rp)
    contract = read(MATERIAL / "receipt-contract.json")
    assert set(r) == set(contract["exact_receipt_keys"])
    for k, value in contract["required_values"].items():
        assert type(r[k]) is type(value) and r[k] == value, k
    assert type(r["elapsed_seconds"]) in (int, float) and math.isfinite(r["elapsed_seconds"]) and r["elapsed_seconds"] >= 0
    assert r["request_sha256"] == sha(qp) and r["helper_sha256"] == HELPER_SHA256
    assert sha(q["stdout"]) == r["stdout_sha256"] and sha(q["stderr"]) == r["stderr_sha256"]
    rows = [json.loads(line) for line in Path(q["stdout"]).read_text().splitlines()]
    assert rows[-1] == dict(reason="build-finished", success=True)
    assert all(x["reason"] in ("compiler-artifact", "build-script-executed") for x in rows[:-1])
    return r, rows


def artifact_review(raw, prepared_hash, review_path, review_hash):
    data = prepared(raw, prepared_hash)
    assert sha(review_path) == review_hash
    review = read(review_path)
    assert review["status"] == "APPROVED_TLS_COMPILER_ARTIFACTS"
    assert review["prepared_sha256"] == prepared_hash and review["tested_revision"] is None
    library_record = None
    for phase in ("library", "compile"):
        r, rows = receipt(raw, phase)
        assert review[phase + "_receipt_sha256"] == sha(raw / phase / "receipt.json")
        assert review[phase + "_stdout_sha256"] == r["stdout_sha256"]
        workspace = data["coordinates"]["WORKSPACE"]
        package_id = "path+file://" + workspace + "/tools/rapid-profiler#0.1.0"
        if phase == "library":
            selected = [x for x in rows if x.get("package_id") == package_id
                        and x.get("target", {}).get("name") == "rapid_profiler"]
            assert len(selected) == 1
            library_record = selected[0]
        # Full dependency/depfile/source/link ownership remains the separately
        # admitted review's responsibility; this check does not replace it.
        if phase == "compile":
            executable = [x for x in rows if x.get("executable")]
            assert len(executable) == 1
            record = executable[0]
            assert record["package_id"] == package_id
            assert record["manifest_path"] == workspace + "/tools/rapid-profiler/Cargo.toml"
            assert record["target"] == expand(read(MATERIAL / "artifact-contract.json")["target"], data["coordinates"])
            assert record["profile"] == read(MATERIAL / "artifact-contract.json")["test_profile"]
            assert record["features"] == [] and record["executable"] in record["filenames"]
            assert sha(record["executable"]) == review["model_binary"]["sha256"]
            assert library_record["manifest_path"] == record["manifest_path"]
            assert library_record["target"] == record["target"]
            assert library_record["profile"] == dict(record["profile"], test=False)
            assert library_record["features"] == [] and library_record["executable"] is None
    assert review["model_binary"]["path"] == str(raw / "artifacts/model-tests")
    assert Path(review["model_binary"]["path"]).resolve(strict=True) == raw / "artifacts/model-tests"
    assert sha(review["model_binary"]["path"]) == review["model_binary"]["sha256"]
    assert os.access(review["model_binary"]["path"], os.X_OK)
    assert sha(review["dependency_review"]["path"]) == review["dependency_review"]["sha256"]
    assert review["archive_files"] and review["model_binary"]["path"] in review["archive_files"]
    for path, expected in review["archive_files"].items():
        assert Path(path).is_relative_to(raw) and sha(path) == expected
    ordinary = review["ordinary_library"]
    assert set(ordinary) == {"alias", "hashed_rlib", "hashed_rmeta"}
    assert len(library_record["filenames"]) == 2
    assert set(library_record["filenames"]) == {ordinary["alias"]["path"], ordinary["hashed_rmeta"]["path"]}
    assert ordinary["alias"]["path"] == data["coordinates"]["REPO"] + "/target/debug/librapid_profiler.rlib"
    rmeta = Path(ordinary["hashed_rmeta"]["path"])
    assert rmeta.parent == Path(data["coordinates"]["REPO"]) / "target/debug/deps"
    assert re.fullmatch(r"librapid_profiler-[0-9a-f]+\.rmeta", rmeta.name)
    assert str(rmeta.with_suffix(".rlib")) == ordinary["hashed_rlib"]["path"]
    for row in ordinary.values():
        assert Path(row["path"]).resolve(strict=True) == Path(row["path"])
        assert sha(row["path"]) == row["sha256"] == sha(row["archive"])
        assert review["archive_files"][row["archive"]] == row["sha256"]
    assert ordinary["alias"]["sha256"] == ordinary["hashed_rlib"]["sha256"]
    return data, review


def remaining(args):
    raw = args.raw.resolve(strict=True)
    data, review = artifact_review(raw, args.prepared_sha256, args.artifact_review, args.artifact_review_sha256)
    requests = {p: request(raw, p, data["coordinates"]) for p in PHASES[2:]}
    write(raw / "remaining.json", dict(status="REQUESTS_ONLY_NOT_EXECUTED", requests=requests,
          prepared_sha256=args.prepared_sha256, artifact_review_path=str(args.artifact_review.resolve(strict=True)),
          artifact_review_sha256=args.artifact_review_sha256))
    print(json.dumps(dict(remaining_sha256=sha(raw / "remaining.json"), requests=requests), sort_keys=True))


def verify(args):
    raw = args.raw.resolve(strict=True)
    prepared(raw, args.prepared_sha256)
    assert args.phase in ("library", "compile") or args.remaining_sha256
    if args.remaining_sha256:
        assert sha(raw / "remaining.json") == args.remaining_sha256
        r = read(raw / "remaining.json")
        artifact_review(raw, args.prepared_sha256, r["artifact_review_path"], r["artifact_review_sha256"])
        for row in r["requests"].values():
            assert sha(row["path"]) == row["sha256"]
    print(json.dumps(dict(status="EXACT_CURRENT_INPUTS_ONLY", workload_executed=False), sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--attempt", choices=("v1", "v2"), required=True)
    for name in ("repo", "base-root", "raw", "toolchain", "msrv-toolchain", "user-home", "cargo-home"):
        p.add_argument("--" + name, type=Path, required=True)
    p = sub.add_parser("remaining")
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--prepared-sha256", required=True)
    p.add_argument("--artifact-review", type=Path, required=True)
    p.add_argument("--artifact-review-sha256", required=True)
    p = sub.add_parser("verify")
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--phase", choices=PHASES, required=True)
    p.add_argument("--prepared-sha256", required=True)
    p.add_argument("--remaining-sha256")
    args = parser.parse_args()
    {"prepare": prepare, "remaining": remaining, "verify": verify}[args.command](args)


if __name__ == "__main__":
    main()
