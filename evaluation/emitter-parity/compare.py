#!/usr/bin/env python3
"""Read-only exact static parity comparison. Never builds or executes images."""
import argparse
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

if sys.flags.optimize:
    raise SystemExit("refusing optimized Python: every comparison is mandatory")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_inventory():
    rows = []
    for shape in ("b1", "b2", "t1", "t2", "t3", "upstream"):
        for semantics in ("observe", "replace"):
            for wrapper in ("leaf", "engine"):
                rows.append((f"{shape}_{semantics}_{wrapper}", "success", 2 if shape in ("t2", "t3") else 1, 1, 0, 0))
    for length in (2, 3, 4):
        for prefix in range(1, length):
            rows.append((f"t1_l{length}_p{prefix}", "success", 1, 1, 0, 0))
    for mask in range(8):
        rows.extend((f"controls_{mode}_mask{mask}", "success", 1, 0, 3, 3) for mode in ("direct", "coalesced"))
    rows.extend((f"controls_cfg_{distance}", "success", 1, 0, 3, 3) for distance in ("near", "far"))
    rows.extend((f"refuse_{shape}_budget", "refusal", 0, 0, 0, 0) for shape in ("b1", "b2", "t1", "t2", "t3"))
    rows.extend((name, "refusal", 0, 0, 0, 0) for name in (
        "refuse_b1_aggregate", "refuse_incomplete_entries", "refuse_coalesced_replace",
        "refuse_coalesced_duplicate_control", "refuse_coalesced_mid_instruction"))
    assert len(rows) == 58
    assert tuple(sum(row[i] for row in rows) for i in range(2, 6)) == (56, 30, 54, 54)
    return rows


INVENTORY = expected_inventory()
SUMMARY = ("fixtures=58\nsuccesses=48\nrefusals=10\nimages=56\n"
           "callback_operands=30\ndispatch_operands=54\ncontrol_operands=54\n").encode()
HEADER = "fixture\toutcome\timages\tcallback_operands\tdispatch_operands\tcontrol_operands\n"
EXPECTED_TSV = (HEADER + "".join("\t".join(map(str, row)) + "\n" for row in INVENTORY)).encode()


def authenticate(root, name, index):
    stem = f"{name}.image{index}"
    raw = (root / f"{stem}.raw.bin").read_bytes()
    canonical = (root / f"{stem}.canonical.bin").read_bytes()
    assert len(raw) == len(canonical) > 0, stem
    table = (root / f"{stem}.operands.tsv").read_text()
    reader = csv.DictReader(io.StringIO(table), delimiter="\t")
    assert reader.fieldnames == ["kind", "logical", "route", "instruction", "immediate", "actual", "canonical", "label"]
    rows = list(reader)
    normalized = bytearray(raw)
    allowed = set()
    signatures = []
    counts = {"callback": 0, "dispatch": 0, "control": 0}
    for row in rows:
        assert set(row) == set(reader.fieldnames) and all(v is not None for v in row.values())
        kind, label = row["kind"], row["label"]
        assert kind in counts
        numeric = {key: int(row[key]) for key in ("logical", "route", "instruction", "immediate", "actual", "canonical")}
        assert all(0 <= n < 1 << 64 for n in numeric.values())
        instruction, immediate = numeric["instruction"], numeric["immediate"]
        assert immediate == instruction + 2 and immediate + 8 <= len(raw)
        assert raw[instruction:immediate] == (b"\x48\xbe" if kind == "control" else b"\x48\xb8")
        if kind != "control":
            assert raw[immediate + 8:immediate + 10] == b"\xff\xd0"
        else:
            # The two declared producer operands are consecutive MOV RSI/block,
            # MOV RAX/dispatch, CALL RAX. No other pointer-like bytes qualify.
            assert raw[immediate + 8:immediate + 10] == b"\x48\xb8"
            assert raw[immediate + 18:immediate + 20] == b"\xff\xd0"
        assert raw[immediate:immediate + 8] == numeric["actual"].to_bytes(8, "little")
        if kind == "callback":
            assert label == "hook0" and numeric["canonical"] == 0x6100000000000000
        elif kind == "dispatch":
            assert label == "dispatch" and numeric["canonical"] == 0x6100000000000010
        else:
            assert label in ("control0", "control1", "control2")
            assert numeric["canonical"] == 0x7100000000000000 + int(label[-1])
        byte_set = set(range(immediate, immediate + 8))
        assert not (allowed & byte_set), stem
        allowed |= byte_set
        normalized[immediate:immediate + 8] = numeric["canonical"].to_bytes(8, "little")
        signatures.append(tuple(row[key] for key in reader.fieldnames if key != "actual"))
        counts[kind] += 1
    assert bytes(normalized) == canonical, stem
    # Record ordering and exact pair geometry are part of the comparison too.
    for index, row in enumerate(rows):
        if row["kind"] == "control":
            assert index + 1 < len(rows)
            following = rows[index + 1]
            assert following["kind"] == "dispatch"
            assert (following["logical"], following["route"]) == (row["logical"], row["route"])
            assert int(following["instruction"]) == int(row["instruction"]) + 10
    return raw, canonical, allowed, signatures, counts


def compare(old, new):
    assert old.resolve() != new.resolve()
    expected_files = {"fixtures.tsv", "complete.txt"}
    for root in (old, new):
        assert (root / "fixtures.tsv").read_bytes() == EXPECTED_TSV
        assert (root / "complete.txt").read_bytes() == SUMMARY
    evidence = []
    total_changed = 0
    for name, outcome, images, callbacks, dispatches, controls in INVENTORY:
        counts = {"callback": 0, "dispatch": 0, "control": 0}
        for suffix in ("source.bin", "inputs.txt", "result.txt"):
            filename = f"{name}.{suffix}"
            expected_files.add(filename)
            assert (old / filename).read_bytes() == (new / filename).read_bytes(), filename
        result = (old / f"{name}.result.txt").read_text()
        assert result.startswith("accepted\n" if outcome == "success" else "refused=")
        for image in range(images):
            stem = f"{name}.image{image}"
            for suffix in ("raw.bin", "canonical.bin", "metadata.txt", "operands.tsv"):
                expected_files.add(f"{stem}.{suffix}")
            assert (old / f"{stem}.metadata.txt").read_bytes() == (new / f"{stem}.metadata.txt").read_bytes(), stem
            left = authenticate(old, name, image)
            right = authenticate(new, name, image)
            assert left[1:] == right[1:], stem
            changed = {i for i, (a, b) in enumerate(zip(left[0], right[0])) if a != b}
            assert changed <= left[2], stem
            total_changed += len(changed)
            for key in counts:
                counts[key] += left[4][key]
            evidence.append({"image": stem, "bytes": len(left[0]), "raw_changed_bytes": len(changed),
                             "canonical_sha256": sha(new / f"{stem}.canonical.bin"), "operands": left[4]})
        assert counts == {"callback": callbacks, "dispatch": dispatches, "control": controls}, name
    assert len(expected_files) == 400
    for root in (old, new):
        assert {p.name for p in root.iterdir()} == expected_files, root
        assert all(p.is_file() and not p.is_symlink() for p in root.iterdir()), root
    return {"status": "EXACT_STATIC_PARITY", "fixtures": 58, "successes": 48, "refusals": 10,
            "images": evidence, "authenticated_operands": 138, "raw_changed_bytes": total_changed,
            "generated_code_executed": False,
            "old_output_sha256": {name: sha(old / name) for name in sorted(expected_files)},
            "new_output_sha256": {name: sha(new / name) for name in sorted(expected_files)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("--manifest", required=True, type=Path, help="frozen preparation manifest")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    here = Path(__file__).resolve().parent
    for filename in ("capture.rs", "compare.py"):
        assert sha(here / filename) == manifest["harness_sha256"][filename], filename
    for side in ("old", "new"):
        source = Path(manifest[side]["directory"])
        expected = manifest[side]["prepared_sha256"]
        assert {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()} == set(expected)
        for filename, digest in expected.items():
            assert sha(source / filename) == digest, (side, filename)
    result = compare(args.old, args.new)
    result["preparation_manifest_sha256"] = sha(args.manifest)
    result["harness_sha256"] = manifest["harness_sha256"]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
