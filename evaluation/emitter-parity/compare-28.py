#!/usr/bin/env python3
"""Compare exact Git-derived 28-case static captures without running images.

The original comparison body and old-output hashes remain mandatory. The caller
binds the fresh old capture before comparing candidate output.
"""
import hashlib
import json
import re
import subprocess
import sys
if sys.flags.optimize:
    raise SystemExit("proof script requires assertions; optimized Python is refused")
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


import argparse
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("old", type=Path)
parser.add_argument("new", type=Path)
parser.add_argument("--manifest", required=True, type=Path)
parser.add_argument("--old-capture-manifest", required=True, type=Path)
args = parser.parse_args()
prepared = json.loads(args.manifest.read_text())
here = Path(__file__).resolve().parent
for filename, digest in prepared["harness_sha256"].items():
    assert sha(here / filename) == digest
for side in ("old", "new"):
    directory = Path(prepared[side]["directory"])
    expected = prepared[side]["prepared_sha256"]
    assert {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()} == set(expected)
    for filename, digest in expected.items():
        assert sha(directory / filename) == digest
old_manifest = args.old_capture_manifest
manifest = json.loads(old_manifest.read_text())
assert manifest["head"] == prepared["old"]["revision"]
assert Path(manifest["harness_path"]).resolve() == (here / "capture-28.rs").resolve()
assert manifest["harness_sha256"] == prepared["harness_sha256"]["capture-28.rs"]
assert sha(manifest["harness_path"]) == manifest["harness_sha256"]
for path, expected in manifest["output_sha256"].items():
    assert sha(path) == expected, f"old output changed: {path}"
old = args.old
new = args.new
assert old.resolve() != new.resolve()
assert {Path(p).resolve() for p in manifest["output_sha256"]} == {p.resolve() for p in old.iterdir()}
assert all(p.is_file() and not p.is_symlink() for p in old.iterdir())
names = (old / "fixtures.txt").read_text().splitlines()
assert len(names) == len(set(names)) == 28
assert (new / "fixtures.txt").read_bytes() == (old / "fixtures.txt").read_bytes()
callback_count = 0
fixture_evidence = []
for name in names:
    # Metadata, source, complete maps, saved-state layout, allocation math and
    # canonical images must be byte-identical; there are no numeric tolerances.
    for suffix in ("source.bin", "metadata.txt", "canonical.bin"):
        assert (old / f"{name}.{suffix}").read_bytes() == (new / f"{name}.{suffix}").read_bytes(), (name, suffix)
    metadata = (old / f"{name}.metadata.txt").read_text()
    rows = re.findall(r"^callback_mov: logical=(\d+) route=(\d+) instruction_offset=(\d+) immediate_offset=(\d+) immediate_len=8 next_call_offset=(\d+)$", metadata, re.M)
    declared = int(re.search(r"^declared_callbacks=(\d+)$", metadata, re.M)[1])
    assert len(rows) == declared
    offsets = []
    for logical, route, instruction, immediate, call in rows:
        instruction, immediate, call = map(int, (instruction, immediate, call))
        assert immediate == instruction + 2
        assert call == instruction + 10
        offsets.append(immediate)
    assert len(offsets) == len(set(offsets))
    raw_old = (old / f"{name}.raw.bin").read_bytes()
    raw_new = (new / f"{name}.raw.bin").read_bytes()
    canonical = (old / f"{name}.canonical.bin").read_bytes()
    assert len(raw_old) == len(raw_new) == len(canonical)
    allowed = {i for offset in offsets for i in range(offset, offset + 8)}
    changed = [i for i, (a, b) in enumerate(zip(raw_old, raw_new)) if a != b]
    assert all(i in allowed for i in changed), name
    for raw in (raw_old, raw_new):
        normalized = bytearray(raw)
        for offset in offsets:
            assert raw[offset - 2:offset] == b"\x48\xb8"
            assert raw[offset + 8:offset + 10] == b"\xff\xd0"
            normalized[offset:offset + 8] = (0x1122334455667788).to_bytes(8, "little")
        assert bytes(normalized) == canonical
    callback_count += declared
    fixture_evidence.append({"name": name, "bytes": len(raw_new), "callback_operands": declared,
                             "changed_raw_bytes": len(changed), "canonical_sha256": sha(new / f"{name}.canonical.bin"),
                             "metadata_sha256": sha(new / f"{name}.metadata.txt")})
assert callback_count == 33
assert {p.name for p in new.iterdir() if p.is_file()} == {p.name for p in old.iterdir() if p.is_file()}
result = {"old_head": manifest["head"], "current_head": prepared["new"]["revision"],
          "harness_sha256": manifest["harness_sha256"], "old_manifest_sha256": sha(old_manifest),
          "fixtures": fixture_evidence, "callback_operands": callback_count,
          "all_non_callback_bytes_and_metadata_equal": True,
          "new_output_sha256": {str(p): sha(p) for p in new.iterdir() if p.is_file()}}
print(json.dumps(result, indent=2))
