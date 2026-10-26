#!/usr/bin/env python3
"""Audit a fresh reproduction's exact captures; never launch a process."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent


def sha(p):
    h = hashlib.sha256()
    with Path(p).open("rb") as f:
        for b in iter(lambda: f.read(512 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def read(p):
    def pairs(items):
        result = {}
        for k, v in items:
            assert k not in result
            result[k] = v
        return result
    return json.loads(Path(p).read_text(), object_pairs_hook=pairs,
        parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--bundle-sha256", required=True)
    p.add_argument("--inputs-sha256", required=True)
    p.add_argument("--init-receipt-sha256", required=True)
    p.add_argument("--review", type=Path, required=True)
    p.add_argument("--review-sha256", required=True)
    args = p.parse_args()
    assert sys.pycache_prefix is None and sha(HERE / "files.json") == args.bundle_sha256
    files = read(HERE / "files.json")
    source = HERE / "prepare.py"
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == files["prepare.py"]
    name = "_consumer_parity_reproduction_prepare"
    assert name not in sys.modules
    spec = importlib.util.spec_from_file_location(name, source)
    assert spec is not None and spec.origin == str(source)
    prep = importlib.util.module_from_spec(spec)
    sys.modules[name] = prep
    exec(compile(raw, str(source), "exec", dont_inherit=True, optimize=0), vars(prep))
    prep.EXPECTED_BUNDLE_SHA = args.bundle_sha256
    prep.EXPECTED_INPUTS_SHA, prep.EXPECTED_INIT_RECEIPT_SHA = args.inputs_sha256, args.init_receipt_sha256
    out = args.raw.resolve(strict=True)
    fixed, saved, owner, data, new_binding, authority = prep.state(out)
    bound = read(out / "binary-binding.json")
    assert bound["status"] == "INDEPENDENT_ACTUAL_BINARY_REVIEW_REQUIRED"
    assert bound["input_authority"] == authority
    assert bound["source_bundle_sha256"] == args.bundle_sha256
    assert sha(out / "parity") == bound["binary_sha256"]
    assert sha(out / "parity.d") == bound["depfile_sha256"]
    assert sha(out / "compile-inputs.json") == bound["compile_input_sha256"]
    assert sha(out / "compile.receipt.json") == bound["compile_receipt_sha256"]
    assert sha(out / "run-once.request.json") == bound["run_request_sha256"]
    assert bound["required_inventory"] == fixed["required_inventory"] and bound["generated_execution"] == 0
    assert sha(args.review) == args.review_sha256
    review = read(args.review)
    assert set(review) == {"schema", "status", "source_bundle_sha256", "binary_binding_sha256", "binary_sha256", "run_request_sha256", "input_authority", "report"}
    assert review["schema"] == "consumer-ordinary-parity-reproduction-binary-review-v1"
    assert review["status"] == "APPROVED_ACTUAL_BINARY_FOR_ONCE_ONLY_PARITY"
    assert review["source_bundle_sha256"] == args.bundle_sha256
    assert review["input_authority"] == authority
    assert review["binary_binding_sha256"] == sha(out / "binary-binding.json")
    assert review["binary_sha256"] == bound["binary_sha256"] and review["run_request_sha256"] == bound["run_request_sha256"]
    assert sha(prep.regular(review["report"]["path"])) == review["report"]["sha256"]
    repo = Path(saved["repository"])
    old_binding = prep.check_old(out, owner)
    assert old_binding["input_authority"] == authority
    control = out.with_name(out.name + "-control")
    init_argv = prep.phase_argv("init", out, data) + ["--repository", str(repo), "--baseline", saved["baseline"],
        "--consumer", saved["consumer_raw"], "--freeze-sha256", saved["consumer_freeze_sha256"],
        "--build-sha256", saved["consumer_build_sha256"]]
    init_q, _ = prep.receipt(control, "init", fixed["helper_sha256"], (20, 30, 16777216))
    assert init_q == prep.request_value(control, "init", init_argv, saved["consumer_environment"], repo, (20, 30, 16777216))
    assert Path(init_q["stdout"]).read_text() == prep.initial_result(args.inputs_sha256, authority["old_cargo_request_sha256"])
    assert Path(init_q["stderr"]).read_bytes() == b""
    for name, caps, expected in [
        ("archive-old", (20, 30, 134217728), "OLD_ARCHIVES_BOUND_NO_HARNESS_EXECUTION\n"),
        ("compile-request", (20, 30, 1048576), "FRESH_HARNESS_COMPILE_REQUEST_PREPARED_NO_EXECUTION\n"),
        ("bind", (20, 30, 1048576), "ACTUAL_BINARY_BOUND_REVIEW_REQUIRED_BEFORE_RUN\n")]:
        phase_q, _ = prep.receipt(out, name, fixed["helper_sha256"], caps)
        assert phase_q == prep.request_value(out, name, prep.phase_argv(name, out, data), saved["environment"], repo, caps)
        assert Path(phase_q["stdout"]).read_text() == expected and Path(phase_q["stderr"]).read_bytes() == b""
    old_q, _ = prep.receipt(out, "old-cargo", fixed["helper_sha256"], (60, 90, 134217728))
    assert old_q == prep.request_value(out, "old-cargo", prep.old_cargo_argv(out, data), saved["environment"], repo, (60, 90, 134217728))
    compile_q, _ = prep.receipt(out, "compile", fixed["helper_sha256"], (60, 90, 134217728))
    assert compile_q == prep.request_value(out, "compile", prep.compile_argv(out, saved, data, old_binding, new_binding), saved["environment"], repo, (60, 90, 134217728))
    assert Path(compile_q["stdout"]).read_bytes() == Path(compile_q["stderr"]).read_bytes() == b""
    q, _ = prep.receipt(out, "run-once", fixed["helper_sha256"], (20, 30, 16777216))
    assert q == prep.request_value(out, "run-once", [str(out / "parity"), str(out / "capture")], saved["environment"], repo, (20, 30, 16777216))
    inputs = {"parity_source": str(HERE / "harness")}
    # BEGIN EXACT PREDECESSOR CAPTURE PREDICATES
    assert (out / "run-once.helper.stdout").read_bytes() == b'{"exit": 0, "wall_timeout": false, "absence_proof": "ECHILD", "descendants": 0, "success": true}\n'
    assert (out / "run-once.helper.stderr").read_bytes() == b""
    cap = out / "capture"
    assert {p.name for p in cap.iterdir()} == {"complete.txt", "comparator-calibrations.txt", "inventory.tsv", "observer.txt", "old", "new"}
    assert not any(p.is_symlink() for p in cap.rglob("*"))
    expected = "cases=72\nsuccesses=45\nrefusals=27\nimages_per_library=59\nexact_record_comparisons=72\nshared_observer_bindings_per_library=45\nobserver_calls=0\ngenerated_code_execution=0\npointer_normalization=0\n"
    assert (cap / "complete.txt").read_text() == expected
    assert (cap / "comparator-calibrations.txt").read_text() == "positive=1\nnegative=11\nno_pointer_normalization=true\n"
    assert Path(q["stdout"]).read_text() == "legacy planner parity complete: 72 exact records, 45 successes, 27 refusals, 59 images per library; no generated code executed\n"
    rows = read(Path(inputs["parity_source"]) / "inventory.json")["rows"]
    assert Path(q["stderr"]).read_text() == "".join("parity required row " + str(index) + ": " + row["name"] + "\n" for index, row in enumerate(rows))
    inventory = "index\tname\tshape\tsemantics\tapi\tscenario\texpected\timages\n" + "".join(str(index) + "\t" + "\t".join(str(row[k]) for k in ("name", "shape", "semantics", "api", "scenario", "expected", "images")) + "\n" for index, row in enumerate(rows))
    assert (cap / "inventory.tsv").read_text() == inventory
    observer = re.fullmatch(r"shared_observer=([1-9][0-9]*)\n", (cap / "observer.txt").read_text())
    assert observer
    for side in ("old", "new"):
        assert {p.name for p in (cap / side).iterdir()} == {r["name"] for r in rows}
        for row in rows:
            directory = cap / side / row["name"]
            assert (directory / "inputs.txt").read_text().splitlines().count("observer=" + observer[1]) == 1
            assert {p.name for p in directory.iterdir()} == {"source.bin", "inputs.txt", "result.txt"} | {f"image{i}" + s for i in range(row["images"]) for s in (".bin", ".metadata.txt")}
    old = {str(p.relative_to(cap / "old")): sha(p) for p in (cap / "old").rglob("*") if p.is_file()}
    new = {str(p.relative_to(cap / "new")): sha(p) for p in (cap / "new").rglob("*") if p.is_file()}
    assert len(old) == len(new) == 334 and old == new
    captures = {str(p.relative_to(cap)): sha(p) for p in cap.rglob("*") if p.is_file()}
    assert len(captures) == 672
    # END EXACT PREDECESSOR CAPTURE PREDICATES
    for name in old:
        assert (cap / "old" / name).read_bytes() == (cap / "new" / name).read_bytes()
    compile_inputs = read(out / "compile-inputs.json")
    assert compile_inputs["input_authority"] == authority
    assert compile_inputs["source_bundle_sha256"] == args.bundle_sha256
    assert compile_inputs["request_sha256"] == sha(out / "compile.request.json")
    assert compile_inputs["old_binding_sha256"] == sha(out / "old-binding.json")
    assert compile_inputs["new_binding_sha256"] == sha(Path(saved["consumer_raw"]) / "build/cargo-binding.json")
    for name, digest in compile_inputs["old_archives"].items():
        assert sha(out / "old-archives" / name) == digest
    for name, digest in compile_inputs["new_archives"].items():
        assert sha(Path(saved["consumer_raw"]) / "build/archives" / name) == digest
    assert prep.check_old(out, owner) == old_binding
    assert owner.verify(Path(saved["consumer_raw"]), saved["consumer_freeze_sha256"]) == data
    assert prep.bundle() == fixed
    assert prep.read_authority(out, fixed) == (saved, authority)
    result = dict(status="FRESH_REPRODUCTION_ORDINARY_PARITY_PASS_FINAL_HELPER_CLOSURE_PENDING", input_authority=authority,
        rows=72, successes=45, exact_refusals=27, images_per_side=59, raw_pairs=334, capture_files=672,
        comparator_positive=1, comparator_negative=11, observer_calls=0, generated_execution=0,
        pointer_normalization=False, source_bundle_sha256=args.bundle_sha256, binary_sha256=bound["binary_sha256"],
        actual_review_sha256=args.review_sha256, captures=captures, historical_result_credit=False,
        baseline_original_revision=fixed["baseline_revision"], baseline_isolated_tested_revision=None,
        consumer_revision=fixed["consumer_revision"], old_records=read(out / "old-binding.json")["records"],
        actual_new_root_fresh=next(r["fresh"] for r in new_binding["records"] if r["target"]["name"] == "liteinst2"))
    prep.write(out / "capture-audit.json", result)
    assert prep.read_authority(out, fixed) == (saved, authority)
    print("PASS_FRESH_REPRODUCTION_ORDINARY_PARITY", sha(out / "capture-audit.json"))


if __name__ == "__main__":
    main()
