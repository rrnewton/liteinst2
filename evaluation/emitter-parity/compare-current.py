#!/usr/bin/env python3
"""Finite current chain/frame parity using the unchanged image authenticator."""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

if sys.flags.optimize:
    raise SystemExit("optimized Python is refused: every comparison is mandatory")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    assert args.old.resolve() != args.new.resolve()
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("original_parity_comparator", here / "compare.py")
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    manifest = json.loads(args.manifest.read_text())
    for name, digest in manifest["harness_sha256"].items():
        assert original.sha(here / name) == digest
    for side in ("old", "new"):
        source = Path(manifest[side]["directory"])
        expected = manifest[side]["prepared_sha256"]
        assert {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()} == set(expected)
        for name, digest in expected.items():
            assert original.sha(source / name) == digest
    cases = [("chain_0", 4, 1, 0), ("chain_grouped", 4, 1, 0), ("chain_1", 5, 1, 0), ("chain_2", 4, 1, 0)]
    cases += [("frame_" + name, 1, count, 0) for name, count in (
        ("normal_near", 1), ("normal_far", 1), ("short_2", 1), ("short_3", 1), ("short_4", 1),
        ("upstream", 1), ("coalesced_static", 3))]
    cases += [("frame_coalesced_controlled", 1, 0, 3)]
    cases += [("frame_free_" + name, 1, 0, 0) for name in ("nop", "mov", "jcc", "ret")]
    cases += [("frame_" + name, 1, count, 0) for name, count in (
        ("refuse_replace", 1), ("refuse_syscall", 1), ("refuse_expanded", 0), ("limit_instructions", 1), ("limit_calls", 1))]
    assert len(cases) == 21 and tuple(sum(c[i] for c in cases) for i in (1, 2, 3)) == (34, 17, 3)
    expected_tsv = "fixture\toutcome\timages\tcallback_operands\tdispatch_operands\tcontrol_operands\n"
    expected_tsv += "".join(f"{name}\tsuccess\t{images}\t{callbacks}\t{controls}\t{controls}\n" for name, images, callbacks, controls in cases)
    complete = b"cases=21\nimages=34\ncallback_operands=17\ndispatch_operands=3\ncontrol_operands=3\nframe_metadata_successes=12\nframe_metadata_refusals=5\nindependent_refusals=2\n"
    files = {"fixtures.tsv", "complete.txt", "independent-refusals.txt"}
    trace_refusals = {"frame_refuse_replace": "ReplacementRequiresFrameContract", "frame_refuse_syscall": "ExactSyscallRequiresFrameContract", "frame_refuse_expanded": "ExpandedRelocation", "frame_limit_instructions": "ResourceLimit", "frame_limit_calls": "ResourceLimit"}
    images = []
    for root in (args.old, args.new):
        assert (root / "fixtures.tsv").read_bytes() == expected_tsv.encode()
        assert (root / "complete.txt").read_bytes() == complete
        assert (root / "independent-refusals.txt").read_text().startswith("ptrace=UnsupportedEntryOrigin\nptrace_origin=ControllerOwnedStack\noverflow=")
    assert (args.old / "independent-refusals.txt").read_bytes() == (args.new / "independent-refusals.txt").read_bytes()
    for name, count, callbacks, controls in cases:
        for suffix in ("source.bin", "inputs.txt", "result.txt"):
            filename = f"{name}.{suffix}"
            files.add(filename)
            assert (args.old / filename).read_bytes() == (args.new / filename).read_bytes(), filename
        assert (args.old / f"{name}.result.txt").read_text().startswith("accepted\n")
        if name.startswith("frame_"):
            filename = name + ".trace.txt"
            files.add(filename)
            left = (args.old / filename).read_bytes()
            assert left == (args.new / filename).read_bytes(), filename
            if name in trace_refusals:
                assert left.decode().splitlines() == ["origin=ApplicationStack", "refused=" + trace_refusals[name]]
            else:
                assert left.startswith(b"origin=ApplicationStack\ntrace_origin=ApplicationStack\n")
                assert "refused=" not in left.decode()
        totals = {"callback": 0, "dispatch": 0, "control": 0}
        for i in range(count):
            stem = f"{name}.image{i}"
            files.update(stem + "." + s for s in ("raw.bin", "canonical.bin", "metadata.txt", "operands.tsv"))
            assert (args.old / (stem + ".metadata.txt")).read_bytes() == (args.new / (stem + ".metadata.txt")).read_bytes()
            left = original.authenticate(args.old, name, i)
            right = original.authenticate(args.new, name, i)
            assert left[1:] == right[1:], stem
            changed = {j for j, (a, b) in enumerate(zip(left[0], right[0])) if a != b}
            assert changed <= left[2]
            for kind in totals:
                totals[kind] += left[4][kind]
            images.append({"image": stem, "bytes": len(left[0]), "canonical_sha256": original.sha(args.new / (stem + ".canonical.bin")), "raw_changed_bytes": len(changed)})
        assert totals == {"callback": callbacks, "dispatch": controls, "control": controls}, name
    assert len(files) == 219 and len(images) == 34
    for root in (args.old, args.new):
        assert {p.name for p in root.iterdir()} == files
        assert all(p.is_file() and not p.is_symlink() for p in root.iterdir())
    print(json.dumps({"status": "EXACT_CURRENT_FEATURE_STATIC_PARITY", "cases": 21,
                      "independent_refusals": 2, "images": images, "callback_operands": 17,
                      "dispatcher_operands": 3, "control_operands": 3,
                      "generated_code_executed": False, "preparation_sha256": original.sha(args.manifest),
                      "old_output_sha256": {n: original.sha(args.old / n) for n in sorted(files)},
                      "new_output_sha256": {n: original.sha(args.new / n) for n in sorted(files)}}, indent=2))


if __name__ == "__main__":
    main()
