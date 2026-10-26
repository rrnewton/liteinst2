#!/usr/bin/env python3
"""Render five fixed requests for an already selected exact source checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

REVISION = "74aaf19a382461aa24c715cab5e17beeaa045e0a"
PHASES = ("native-compile", "native-straight", "native-budget",
          "native-generation", "native-refusals")
ROLE_NAMES = frozenset(("${REPO}", "${RAW}", "${RUST_TOOLCHAIN}",
                        "${USER_HOME}", "${CARGO_HOME}"))
ROLE_PATTERN = re.compile(r"\$\{[A-Z_]+\}")

def need(value, message):
    if not value:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)

def read_regular(path, limit, label):
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise ValueError(label + " missing") from None
    need(stat.S_ISREG(before.st_mode), label + " regular owner")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        need(identity(os.fstat(stream.fileno())) == identity(before),
             label + " opened owner")
        data = stream.read(limit + 1)
        need(identity(os.fstat(stream.fileno())) == identity(before),
             label + " changed owner")
    need(identity(path.lstat()) == identity(before), label + " changed path")
    need(len(data) <= limit, label + " size")
    return data, before

def directory(value, label):
    path = Path(value)
    need(path.is_absolute() and path == path.resolve() and path.is_dir(),
         label + " coordinate")
    return path

def fresh_raw(value, repo):
    path = Path(value)
    need(path.is_absolute() and path == path.resolve(), "raw coordinate")
    need(path != repo / "ignored" and path.is_relative_to(repo / "ignored"),
         "raw outside ignored")
    need(path.parent.is_dir(), "raw parent")
    need(not os.path.lexists(path), "raw already exists")
    return path

def verify_sources(repo, sources):
    for name, row in sorted(sources.items()):
        relative = Path(name)
        need(not relative.is_absolute() and ".." not in relative.parts,
             "source relative path")
        path = repo / relative
        need(path == path.resolve(), "source canonical owner")
        data, st = read_regular(path, row["bytes"], "source")
        need(len(data) == row["bytes"] and digest(data) == row["sha256"],
             "source digest")
        mode = "100755" if st.st_mode & 0o111 else "100644"
        need(mode == row["mode"], "source mode")

def expand(data, roles):
    need(set(roles) == ROLE_NAMES and all(isinstance(v, str) for v in roles.values()),
         "role allowlist")
    original = data.decode("utf-8")
    def value(match):
        need(match.group() in ROLE_NAMES, "unresolved role")
        return roles[match.group()]
    def expected(item):
        if isinstance(item, str):
            return ROLE_PATTERN.sub(value, item)
        if isinstance(item, list):
            return [expected(member) for member in item]
        if isinstance(item, dict):
            return {expected(key): expected(member) for key, member in item.items()}
        return item
    # One pass: JSON escaping preserves coordinate bytes; inserted role text
    # is literal data and is never expanded a second time.
    text = ROLE_PATTERN.sub(lambda match: json.dumps(value(match))[1:-1], original)
    need(json.loads(text) == expected(json.loads(original)), "coordinate reconstruction")
    return text.encode("utf-8")

def render(materials, material_sha256, repo_value, raw_value,
           toolchain_value, user_home_value, cargo_home_value):
    need(not sys.flags.optimize, "optimized Python")
    materials = directory(str(materials), "materials")
    repo = directory(repo_value, "repo")
    raw = fresh_raw(raw_value, repo)
    roles = {"${REPO}": str(repo), "${RAW}": str(raw),
             "${RUST_TOOLCHAIN}": str(directory(toolchain_value, "toolchain")),
             "${USER_HOME}": str(directory(user_home_value, "user home")),
             "${CARGO_HOME}": str(directory(cargo_home_value, "cargo home"))}
    data, unused = read_regular(materials / "material.json", 1048576, "material")
    need(digest(data) == material_sha256, "material sha256")
    material = json.loads(data)
    need(material["schema"] == 1 and material["tested_revision"] == REVISION
         and material["phases"] == list(PHASES), "fixed recipe")
    saved = {}
    for name, row in sorted(material["files"].items()):
        path = materials / name
        need(path == path.resolve() and path.is_relative_to(materials),
             "material member owner")
        body, unused = read_regular(path, row["bytes"], "material member")
        need(len(body) == row["bytes"] and digest(body) == row["sha256"],
             "material member digest")
        saved[name] = body
    need(saved["render.py"] == Path(__file__).read_bytes(), "renderer owner")
    sources = json.loads(saved["source-files.json"])
    need(len(sources) == material["source_count"] == 1008, "source inventory")
    verify_sources(repo, sources)
    outputs = {"requests/" + phase + ".json":
               expand(saved["requests/" + phase + ".json"], roles)
               for phase in PHASES}
    outputs["outer.json"] = expand(saved["outer.json"], roles)
    # Exclusive fresh owner, no source copies or product selection.
    raw.mkdir()
    (raw / "requests").mkdir()
    for name, body in sorted(outputs.items()):
        with (raw / name).open("xb") as stream:
            stream.write(body)
    verify_sources(repo, sources)
    for name, body in saved.items():
        again, unused = read_regular(materials / name, len(body), "material member")
        need(again == body, "material changed")
    again, unused = read_regular(materials / "material.json", len(data), "material")
    need(again == data, "material changed")
    result = {"schema": 1, "status": "RENDERED_REVIEW_REQUIRED_NO_EXECUTION",
              "source_bytes_match_revision": REVISION,
              "git_HEAD_observed_by_renderer": False,
              "material_sha256": material_sha256,
              "source_map_sha256": digest(saved["source-files.json"]),
              "files": {name: digest(body) for name, body in sorted(outputs.items())},
              "artifact_or_runtime_admission": False, "workloads_executed": 0}
    body = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    with (raw / "rendered.json").open("xb") as stream:
        stream.write(body)
    return digest(body)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("material-sha256", "repo", "raw", "toolchain", "user-home", "cargo-home"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = render(Path(__file__).resolve().parent, args.material_sha256,
                    args.repo, args.raw, args.toolchain, args.user_home, args.cargo_home)
    print("RENDERED_REVIEW_REQUIRED_NO_EXECUTION " + result)

if __name__ == "__main__":
    main()
