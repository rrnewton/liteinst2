#!/usr/bin/env python3
"""Prepare the exact five-file historical promotion formatter input and request.

This copies authenticated source bytes and emits JSON only. It starts no
formatter, compiler, helper, shell, or other program.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")

RECIPE = Path(__file__).resolve().parent / "reproductions/generation-promotion-format.json"
RECIPE_SHA256 = "1eafaa9e93ca5fdf2c79b58c365aa73c2c7afbe40ae7e2b60de0ff7ee859a6c2"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "raw", "rustfmt", "user-home"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    assert sha(RECIPE) == RECIPE_SHA256
    recipe = json.loads(RECIPE.read_text())
    repo, raw = args.repo.resolve(strict=True), args.raw.resolve()
    assert raw.is_relative_to(repo / "ignored") and raw != repo / "ignored"
    assert raw.parent.is_dir() and not raw.exists() and not args.raw.is_symlink()
    user_home = args.user_home.resolve(strict=True)
    assert user_home.is_dir()
    rustfmt = args.rustfmt.absolute()
    assert rustfmt.is_file() and os.access(rustfmt, os.X_OK)
    assert sha(rustfmt) == recipe["tools"]["rustfmt"]["sha256"]
    helper = repo / recipe["tools"]["helper"]["repository_path"]
    assert sha(helper) == recipe["tools"]["helper"]["sha256"]
    source = {}
    for name, expected in recipe["after"].items():
        relative = Path(name)
        assert relative.parts[0] == "src" and ".." not in relative.parts
        path = repo / "tools/rapid-profiler" / relative
        assert path.resolve() == path and sha(path) == expected
        source[name] = path.read_bytes()
    assert len(source) == 5
    change = recipe["reversal"]
    old, new = change["old"].encode(), change["new"].encode()
    assert source[change["file"]].count(old) == change["occurrences"] == 1
    source[change["file"]] = source[change["file"]].replace(old, new)
    assert {name: hashlib.sha256(value).hexdigest() for name, value in source.items()} == recipe["before"]
    raw.mkdir()
    snapshot = raw / "snapshot"
    for name, value in source.items():
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(value)
    roles = {"${RUSTFMT}": str(rustfmt), "${RAW}": str(raw),
             "${SNAPSHOT}": str(snapshot), "${USER_HOME}": str(user_home)}

    def expand(value):
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        if isinstance(value, str):
            for role, actual in roles.items():
                value = value.replace(role, actual)
            assert "${" not in value
        return value

    request = expand(recipe["request_template"])
    assert (request["cpu_seconds"], request["wall_seconds"], request["file_bytes"]) == (20, 30, 16777216)
    write(raw / "request.json", request)
    assert {str(p.relative_to(snapshot)): sha(p) for p in snapshot.rglob("*") if p.is_file()} == recipe["before"]
    for name, expected in recipe["after"].items():
        assert sha(repo / "tools/rapid-profiler" / name) == expected
    assert sha(rustfmt) == recipe["tools"]["rustfmt"]["sha256"]
    assert sha(helper) == recipe["tools"]["helper"]["sha256"]
    assert sha(RECIPE) == RECIPE_SHA256
    write(raw / "admission.json", dict(status="REQUEST_PREPARED_NOT_EXECUTED",
        tested_revision=None, source_byte_origin_revision=recipe["source_revision"],
        input_files=recipe["before"], expected_formatted_files=recipe["after"],
        request_sha256=sha(raw / "request.json"), recipe_sha256=RECIPE_SHA256,
        script_sha256=sha(__file__), rustfmt=dict(path=str(rustfmt), resolved=str(rustfmt.resolve()), sha256=sha(rustfmt)),
        helper_sha256=sha(helper),
        remaining_admission="Review current helper interpreter/watchdog and launch bindings; this preparation does not infer historical Python/timeout identities or execute the formatter."))
    print(raw / "request.json")


if __name__ == "__main__":
    main()
