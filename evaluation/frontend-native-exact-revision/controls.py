#!/usr/bin/env python3
"""Finite request-rendering controls; never compile or launch a native program."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import sys


def check(value):
    if not value:
        raise AssertionError("control predicate")


def main():
    check(not sys.flags.optimize)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("material-sha256", "repo", "scratch", "toolchain", "user-home", "cargo-home"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    materials = Path(__file__).resolve().parent
    data = (materials / "material.json").read_bytes()
    check(hashlib.sha256(data).hexdigest() == args.material_sha256)
    contract = json.loads(data)
    source = (materials / "render.py").read_bytes()
    check(hashlib.sha256(source).hexdigest() == contract["files"]["render.py"]["sha256"])
    ns = runpy.run_path(str(materials / "render.py"), run_name="reviewed_renderer_controls")
    repo = ns["directory"](args.repo, "repo")
    scratch = ns["fresh_raw"](args.scratch, repo)
    scratch.mkdir()
    fixture = scratch / "source-fixture"
    fixture.mkdir()
    sample = fixture / "sample.txt"
    sample.write_bytes(b"abc")
    spec = {"sample.txt": {"bytes": 3, "mode": "100644",
                           "sha256": hashlib.sha256(b"abc").hexdigest()}}
    ns["verify_sources"](fixture, spec)
    print("PASS exact_source_fixture")
    actual = scratch / "rendered"
    def call(raw, material_hash=args.material_sha256):
        return ns["render"](materials, material_hash, args.repo, str(raw),
                            args.toolchain, args.user_home, args.cargo_home)
    call(actual)
    inverse = {str(actual): "${RAW}", args.repo: "${REPO}",
               args.toolchain: "${RUST_TOOLCHAIN}", args.user_home: "${USER_HOME}",
               args.cargo_home: "${CARGO_HOME}"}
    names = ["requests/" + phase + ".json" for phase in contract["phases"]] + ["outer.json"]
    for name in names:
        text = (actual / name).read_text()
        for value, token in sorted(inverse.items(), key=lambda row: -len(row[0])):
            text = text.replace(value, token)
        check(text.encode() == (materials / name).read_bytes())
    check(set(p.relative_to(actual).as_posix() for p in actual.rglob("*") if p.is_file())
          == set(names) | {"rendered.json"})
    print("PASS five_whole_requests_and_outer_inverse")
    def refusal(name, expected, operation):
        try:
            operation()
        except ValueError as error:
            check(str(error) == expected)
        else:
            raise AssertionError("missing refusal: " + name)
        print("PASS refusal " + name)
    missing = {"missing.txt": spec["sample.txt"]}
    refusal("missing_source", "source missing",
            lambda: ns["verify_sources"](fixture, missing))
    sample.write_bytes(b"xyz")
    refusal("wrong_source", "source digest",
            lambda: ns["verify_sources"](fixture, spec))
    refusal("existing_output_owner", "raw already exists", lambda: call(actual))
    refusal("outside_ignored", "raw outside ignored", lambda: call(repo / "outside-renderer-control"))
    link = scratch / "alias"
    link.symlink_to(fixture, target_is_directory=True)
    refusal("symlink_parent", "raw coordinate", lambda: call(link / "output"))
    refusal("relative_coordinate", "raw coordinate", lambda: call("relative-output"))
    refusal("wrong_material_digest", "material sha256",
            lambda: call(scratch / "wrong-material-output", "0" * 64))
    check(not (scratch / "wrong-material-output").exists())
    roles = {"${RAW}": str(scratch), "${REPO}": args.repo,
             "${RUST_TOOLCHAIN}": args.toolchain, "${USER_HOME}": args.user_home,
             "${CARGO_HOME}": args.cargo_home}
    template = b'{"argv":["${RAW}/item"],"cwd":"${REPO}"}\n'
    special = dict(roles)
    special["${RAW}"] = str(scratch) + '/quote"back\\slash\nline'
    check(json.loads(ns["expand"](template, special)) ==
          {"argv": [special["${RAW}"] + "/item"], "cwd": args.repo})
    print("PASS json_special_coordinate_expansion")
    literal = dict(roles)
    literal["${RAW}"] = str(scratch) + "/literal-${REPO}-${UNRECOGNIZED}"
    check(json.loads(ns["expand"](template, literal)) ==
          {"argv": [literal["${RAW}"] + "/item"], "cwd": args.repo})
    print("PASS literal_role_text_not_reexpanded")
    print("PASS renderer controls: 4 accepted, 7 expected refusals")

if __name__ == "__main__":
    main()
