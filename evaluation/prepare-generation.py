#!/usr/bin/env python3
"""Reconstruct the historical four-file generation crate and prepare requests.

This starts no compiler, model, formatter, helper, or supervisor. Each stage
requires review of the preceding actual artifacts before its requests run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys

if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")

MATERIAL = Path(__file__).resolve().parent / "reproductions/generation-private"
MATERIAL_SHA256 = "4f07ff95576debeeb8879e4b869cd47b0c9b719c9ae17d549cedbe77100bb9a6"
HELPER_SHA256 = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(524288), b""):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def material():
    manifest = MATERIAL / "files.json"
    assert sha(manifest) == MATERIAL_SHA256
    files = read(manifest)
    for name, expected in files.items():
        assert Path(name).name == name and sha(MATERIAL / name) == expected
    return read(MATERIAL / "reconstruction.json"), read(MATERIAL / "tools.json")


def apply_edits(text, rows):
    """Apply the exact, hash-bound line edits; no search or fuzzy matching."""
    lines = text.splitlines(keepends=True)
    output, cursor = [], 0
    for row in rows:
        start, end = row["start"], row["end"]
        assert type(start) is int and type(end) is int
        assert cursor <= start <= end <= len(lines)
        assert lines[start:end] == row["old"]
        output.extend(lines[cursor:start])
        output.extend(row["new"])
        cursor = end
    return "".join(output + lines[cursor:])


def verify_source(snapshot, expected):
    actual = {str(p.relative_to(snapshot)): sha(p)
              for p in snapshot.rglob("*") if p.is_file()}
    assert actual == expected
    assert all(p.resolve() == p and not p.is_symlink()
               for p in snapshot.rglob("*"))


def verify_tools(config, hashes):
    for role, row in config["tools"].items():
        path = Path(row["path"])
        assert path.is_file() and os.access(path, os.X_OK)
        assert sha(path) == row["sha256"] == hashes[role]
        assert str(path.resolve()) == row["resolved"]
    assert sha(Path(config["repo"]) / "tools/word-sync-oracle/bounded_command.py") == HELPER_SHA256


def config_at(raw, expected):
    path = raw / "config.json"
    assert sha(path) == expected
    config = read(path)
    assert config["raw"] == str(raw) and config["material_sha256"] == MATERIAL_SHA256
    reconstruction, hashes = material()
    verify_tools(config, hashes)
    return config, reconstruction


def request(config, name, binary=None):
    directory = Path(config["raw"]) / name
    assert not directory.exists()
    directory.mkdir()
    (directory / "tmp").mkdir()
    roles = dict(config["roles"], COMMAND_RAW=str(directory))
    if binary is not None:
        roles["MODEL_BINARY"] = str(binary)

    def expand(value):
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        if isinstance(value, str):
            for key, item in roles.items():
                value = value.replace("${" + key + "}", item)
            assert "${" not in value
        return value

    value = expand(read(MATERIAL / "request-templates.json")[name])
    path = directory / "request.json"
    write(path, value)
    return {"path": str(path), "sha256": sha(path)}


def successful_receipt(record):
    path = Path(record["path"])
    assert sha(path) == record["sha256"]
    q, receipt = read(path), read(path.parent / "receipt.json")
    assert receipt["request_sha256"] == record["sha256"]
    assert receipt["helper_sha256"] == HELPER_SHA256
    assert receipt["exit"] == 0 and receipt["wall_timeout"] is False
    assert receipt["unexpected_descendants"] == [] and receipt["absence_proof"] == "ECHILD"
    assert receipt["cleanup_events"] == [] and receipt["cleanup_error"] is None
    assert receipt["aborted"] is None and receipt["inputs_unchanged"] is True
    for kind in ("stdout", "stderr"):
        assert sha(q[kind]) == receipt[kind + "_sha256"]
    return q, receipt


def reconstruct(args):
    reconstruction, hashes = material()
    repo = args.repo.resolve(strict=True)
    raw = args.raw.resolve()
    assert raw.is_relative_to(repo / "ignored") and raw != repo / "ignored"
    assert raw.parent.is_dir() and not raw.exists() and not args.raw.is_symlink()
    # Closed reproduction geometry: make depfile separators unambiguous.
    assert all(c not in str(repo) + str(raw) for c in "\n\r:")
    source = {}
    for key, dest in (("source_module", "src/lib.rs"), ("source_tests", "src/tests.rs")):
        row = reconstruction[key]
        path = repo / row["repository_path"]
        assert path.resolve() == path and sha(path) == row["sha256"]
        source[dest] = path.read_text()
    source["src/lib.rs"] = apply_edits(source["src/lib.rs"], reconstruction["module_to_formatted"])
    for name in source:
        assert hashlib.sha256(source[name].encode()).hexdigest() == reconstruction["formatted"][name]
        source[name] = apply_edits(source[name], reconstruction["formatted_to_original"][name])
        assert hashlib.sha256(source[name].encode()).hexdigest() == reconstruction["before_format"][name]
    tc, ms = args.toolchain.resolve(strict=True), args.msrv_toolchain.resolve(strict=True)
    cargo_home, user_home = args.cargo_home.resolve(strict=True), args.user_home.resolve(strict=True)
    assert all(p.is_dir() for p in (repo, tc, ms, cargo_home, user_home))
    tool_paths = {name: tc / "bin" / name.replace("_", "-")
                  for name in ("rustfmt", "cargo", "rustc", "rustdoc", "cargo_clippy", "clippy_driver")}
    tool_paths.update(msrv_cargo=ms / "bin/cargo", msrv_rustc=ms / "bin/rustc",
                      helper_python=args.helper_python.resolve(strict=True), timeout=args.timeout.resolve(strict=True))
    config = {
        "status": "REQUEST_PREPARATION_ONLY", "tested_revision": None,
        "source_origin_revision": "7a4e5719ed06dfd55eaccb2236867f4d760e402c",
        "repo": str(repo), "raw": str(raw), "material_sha256": MATERIAL_SHA256,
        "tools": {name: {"path": str(path), "resolved": str(path.resolve()), "sha256": hashes[name]}
                  for name, path in tool_paths.items()},
        "roles": {"REPO": str(repo), "SNAPSHOT": str(raw / "snapshot"),
                  "TOOLCHAIN": str(tc), "MSRV_TOOLCHAIN": str(ms),
                  "CARGO_HOME": str(cargo_home), "USER_HOME": str(user_home)},
        "local_configuration": "Requires independent Cargo configuration, runtime/toolchain and launch review; executable hashes alone do not qualify these inputs.",
    }
    verify_tools(config, hashes)
    raw.mkdir()
    snapshot = raw / "snapshot"
    (snapshot / "src").mkdir(parents=True)
    for name, text in source.items():
        (snapshot / name).write_text(text)
    for name in ("Cargo.toml", "Cargo.lock"):
        (snapshot / name).write_bytes((MATERIAL / name).read_bytes())
    verify_source(snapshot, reconstruction["before_format"])
    config["format_request"] = request(config, "format")
    verify_tools(config, hashes)
    write(raw / "config.json", config)
    print("config_sha256=" + sha(raw / "config.json"))


def prepare_compilers(args):
    raw = args.raw.resolve(strict=True)
    config, reconstruction = config_at(raw, args.config_sha256)
    successful_receipt(config["format_request"])
    verify_source(raw / "snapshot", reconstruction["formatted"])
    plan = {name: request(config, name) for name in ("compile", "clippy", "docs", "msrv")}
    verify_tools(config, material()[1])
    verify_source(raw / "snapshot", reconstruction["formatted"])
    write(raw / "compiler-plan.json", {"status": "REQUESTS_NOT_EXECUTED", "config_sha256": args.config_sha256, "requests": plan})
    print("compiler_plan_sha256=" + sha(raw / "compiler-plan.json"))


def bind_models(args):
    raw = args.raw.resolve(strict=True)
    config, reconstruction = config_at(raw, args.config_sha256)
    assert sha(raw / "compiler-plan.json") == args.plan_sha256
    plan = read(raw / "compiler-plan.json")
    assert plan["config_sha256"] == args.config_sha256
    q, receipt = successful_receipt(plan["requests"]["compile"])
    snapshot = raw / "snapshot"
    verify_source(snapshot, reconstruction["formatted"])
    rows = [json.loads(line) for line in Path(q["stdout"]).read_text().splitlines()]
    assert len(rows) == 3 and rows[-1] == {"reason": "build-finished", "success": True}
    artifacts = rows[:-1]
    assert {row["profile"]["test"] for row in artifacts} == {False, True}
    for row in artifacts:
        assert row["reason"] == "compiler-artifact"
        assert row["package_id"] == "path+" + snapshot.as_uri() + "#liteinst2-generation-draft@0.1.0"
        assert row["manifest_path"] == str(snapshot / "Cargo.toml") and row["features"] == []
        assert row["target"] == {"kind": ["lib"], "crate_types": ["lib"], "name": "liteinst2_generation_draft", "src_path": str(snapshot / "src/lib.rs"), "edition": "2024", "doc": True, "doctest": True, "test": True}
        assert row["profile"] == {"opt_level": "0", "debuginfo": 2, "debug_assertions": True, "overflow_checks": True, "test": row["profile"]["test"]}
    row, = [row for row in artifacts if row["profile"]["test"]]
    binary = Path(row["executable"])
    assert row["filenames"] == [str(binary)]
    assert binary.parent == Path(config["repo"]) / "target/debug/deps"
    assert re.fullmatch(r"liteinst2_generation_draft-[0-9a-f]+", binary.name)
    assert binary.resolve() == binary and binary.is_file() and os.access(binary, os.X_OK)
    assert binary.read_bytes()[:4] == b"\x7fELF"
    depfile = binary.with_suffix(".d")
    rules = {}
    for line in depfile.read_text().splitlines():
        if not line:
            continue
        target, separator, deps = line.partition(":")
        targets = shlex.split(target)
        assert separator and len(targets) == 1 and targets[0] not in rules
        rules[targets[0]] = shlex.split(deps)
    expected_sources = ["src/lib.rs", "src/tests.rs"]
    assert rules == {str(depfile): expected_sources, str(binary): expected_sources,
                     "src/lib.rs": [], "src/tests.rs": []}
    saved = raw / "model-tests"
    assert not saved.exists()
    shutil.copyfile(binary, saved)
    saved.chmod(0o700)
    assert sha(saved) == sha(binary)
    requests = {name: request(config, name, saved) for name in ("list", "models")}
    verify_source(snapshot, reconstruction["formatted"])
    verify_tools(config, material()[1])
    write(raw / "model-plan.json", {"status": "REQUESTS_NOT_EXECUTED", "config_sha256": args.config_sha256,
          "compiler_plan_sha256": args.plan_sha256, "compile_receipt_sha256": sha(Path(plan["requests"]["compile"]["path"]).parent / "receipt.json"),
          "binary_sha256": sha(saved), "depfile_sha256": sha(depfile), "cargo_artifacts": artifacts, "requests": requests})
    print("model_plan_sha256=" + sha(raw / "model-plan.json"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="stage", required=True)
    init = sub.add_parser("reconstruct")
    for name in ("repo", "raw", "toolchain", "msrv-toolchain", "cargo-home", "user-home", "helper-python", "timeout"):
        init.add_argument("--" + name, type=Path, required=True)
    checks = sub.add_parser("prepare-compilers")
    models = sub.add_parser("bind-models")
    for command in (checks, models):
        command.add_argument("--raw", type=Path, required=True)
        command.add_argument("--config-sha256", required=True)
    models.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    {"reconstruct": reconstruct, "prepare-compilers": prepare_compilers, "bind-models": bind_models}[args.stage](args)


if __name__ == "__main__":
    main()
