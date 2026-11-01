#!/usr/bin/env python3
"""One prospective fresh --cases all producer at the self-hosting revision."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
SELF = Path(__file__).resolve()
REV = "10a778d6415e51c66dfdc122d1e019e5c8c94c3c"
HELPER = "69c7d87ecf8d249a0a7b325db78f05d770fad993994eba97a40bb8338c0c4f6a"
M = 1024**2


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def main():
    for key, value in ((resource.RLIMIT_CPU, 4800), (resource.RLIMIT_AS, 36*1024*M),
                       (resource.RLIMIT_FSIZE, 512*M), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (value, value))
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--corpus-scripts", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    a = parser.parse_args()
    scripts = a.corpus_scripts.absolute(); assert scripts == scripts.resolve()
    path = scripts/"run.py"; before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_size <= M
    data = path.read_bytes(); assert hashlib.sha256(data).hexdigest() == HELPER
    after = path.lstat()
    assert identity(before) == identity(after) and before.st_nlink == after.st_nlink
    spec = importlib.util.spec_from_file_location("fresh_first_generation", path)
    h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
    assert path.read_bytes() == data
    source = h.pin(SELF); helper = h.pin(path)
    # The sole imported-module change is the parent's exact-revision readiness
    # check. Native children enter the literal runner's child branch, which does
    # not call ready(). All cases, commands, bounds and comparisons stay literal.
    assert h.REV == "438954e0e1372fdb428b3446d69aca804ccd29ea"
    h.REV = REV
    original = sys.argv[:]
    sys.argv = [str(path), "--cpu", str(a.cpu), "--unit", a.unit,
                "--out", str(a.out.absolute()), "--cases", "all"]
    try:
        result = h.main()
    finally:
        sys.argv = original
    assert h.pin(SELF) == source and h.pin(path) == helper
    receipt = a.out.absolute()/"receipt.json"
    record = dict(revision=REV, child_source_revision="438954e0e1372fdb428b3446d69aca804ccd29ea",
                  result=result, source_unchanged=True, driver=source, child_script=helper,
                  command=["/usr/bin/python3.9", "-I", "-B", *original], receipt=h.pin(receipt),
                  revision_override_only=True, case_set="all", attempts=1)
    with receipt.with_name("first-generation-wrapper-closed.json").open("x") as f:
        json.dump(record, f, separators=(",", ":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
    return result


if __name__ == "__main__":
    raise SystemExit(main())
