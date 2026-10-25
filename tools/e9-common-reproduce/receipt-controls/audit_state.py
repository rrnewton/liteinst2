#!/usr/bin/env python3
"""Audit the completed v4 state attempt with the unchanged four v3 audit modules.

No process creation, native execution, request generation, retry or supervisor.
The externally reviewed actual-data binding is created only after the commands.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OLD = ROOT / "ignored/a3/e9-common-corrected-implementation-v3"
STATE = ROOT / "ignored/a3/e9-common-state-hooktype-v4"
STATE_SHA = "8a836f5b595120e2547c3b2cf1db77357a61c63ebfea1f1fd4d623b36309bc8f"
OLD_SHA = "5f5c50629f8c2dbffcb2f96c69e818062c1f8d8a4929e0950331854bc9651a99"
HELPER_SHA = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
STATE_STDOUT = b"actual E9 passthru file state oracle: 6 outputs, two distinct common biases each, 48 original/48 rewritten/48 restored-original, zero hook events; manual fixture load; artifact qualification incomplete\n"
CONTROL_STDOUT = b"SPARSE_OWNERSHIP_CONTROLS_PASS positives=2 negatives=18\n"
RECEIPT_KEYS = set("request_sha256 helper_sha256 exit wall_timeout unexpected_descendants absence_proof stdout_sha256 stderr_sha256 elapsed_seconds cleanup_events cleanup_error aborted inputs_unchanged".split())
MODULES = [
    ("state_mapping_identity", "mapping_identity.py", "ec2da3360258de78fb259021058b0a1af9ae96cc3f27e864b54ee5df304c3b75"),
    ("state_ledger_schema", "ledger_schema.py", "e46cfa3bf7e15b980c85b400f4469490fe1d699e6da3aefdcaa5728eafe99bbc"),
    ("state_ownership_audit", "ownership_audit.py", "186804a51bf81ce146bdc0bf3473a92299bb03012aba5da82f9b959808c9a2a2"),
    ("state_audit", "audit.py", "c01d43607b3abb1129cf7e46eb89967f8a666a3aa078478452e34f3d6661feee"),
]
REFERENCE_ALIASES = {
    "/usr/bin/cc": "/usr/bin/gcc",
    "/usr/bin/ld": "/usr/bin/ld.bfd",
    "/usr/lib64/libgcc_s.so.1": "/usr/lib64/libgcc_s-11-20240719.so.1",
}


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path):
    path = Path(path)
    assert path.is_absolute() and path.resolve(strict=True) == path
    assert path.is_file() and not path.is_symlink()
    return path


def sha(path):
    h = hashlib.sha256()
    with regular(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(512 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def reference_sha(path):
    """Retain the three existing reference aliases with exact resolved owners."""
    path = Path(path)
    if str(path) in REFERENCE_ALIASES:
        resolved = path.resolve(strict=True)
        assert str(resolved) == REFERENCE_ALIASES[str(path)]
        return sha(resolved)
    return sha(path)


def checksum(value):
    assert type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
    return value


def pairs(items):
    result = {}
    for key, value in items:
        assert key not in result, "duplicate JSON key"
        result[key] = value
    return result


def read(path):
    raw = regular(path).read_bytes()
    assert len(raw) <= 16 * 1024 * 1024
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def pinned(row):
    assert type(row) is dict and set(row) == {"path", "sha256"}
    path = regular(row["path"])
    assert path.is_relative_to(ROOT / "ignored")
    assert sha(path) == checksum(row["sha256"])
    return path


def file_map(directory):
    directory = Path(directory)
    assert directory.is_absolute() and directory.resolve(strict=True) == directory
    assert directory.is_dir() and not directory.is_symlink()
    result = {}
    for path in sorted(directory.rglob("*")):
        assert not path.is_symlink()
        if path.is_file():
            result[str(path.relative_to(directory))] = sha(path)
        else:
            assert path.is_dir()
    return result


def manifest(path, expected):
    assert sha(path) == checksum(expected)
    value = read(path)
    for relative, digest in value["files"].items():
        name = Path(relative)
        assert not name.is_absolute() and ".." not in name.parts
        assert sha(path.parent / name) == checksum(digest)
    for name, digest in value["references"].items():
        assert reference_sha(name) == checksum(digest)
    return value


def receipt(value, request_sha, stdout, stderr):
    """Exact helper success grammar, including JSON types and whole output hashes."""
    assert type(value) is dict and set(value) == RECEIPT_KEYS
    assert value["request_sha256"] == request_sha
    assert value["helper_sha256"] == HELPER_SHA
    assert type(value["exit"]) is int and value["exit"] == 0
    assert value["wall_timeout"] is False and value["inputs_unchanged"] is True
    assert value["absence_proof"] == "ECHILD"
    assert value["unexpected_descendants"] == [] and value["cleanup_events"] == []
    assert value["cleanup_error"] is None and value["aborted"] is None
    elapsed = value["elapsed_seconds"]
    assert type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0
    assert value["stdout_sha256"] == sha_bytes(stdout)
    assert value["stderr_sha256"] == sha_bytes(stderr)


def command(row, expected_request, expected_stdout):
    assert set(row) == {"request", "receipt"}
    qp, rp = pinned(row["request"]), pinned(row["receipt"])
    q = read(qp)
    assert q == expected_request
    assert type(q["cpu_seconds"]) is int and type(q["wall_seconds"]) is int
    assert type(q["file_bytes"]) is int
    stdout, stderr = regular(q["stdout"]).read_bytes(), regular(q["stderr"]).read_bytes()
    assert stdout == expected_stdout and stderr == b""
    receipt(read(rp), sha(qp), stdout, stderr)
    return {str(x): sha(x) for x in (qp, rp, Path(q["stdout"]), Path(q["stderr"]))}


def run_audit(captures, inventory):
    """Fresh source-byte execution only; preserve all module/path ownership."""
    assert sys.flags.optimize == 0 and sys.pycache_prefix is None and sys.dont_write_bytecode
    names = [row[0] for row in MODULES]
    assert all(name not in sys.modules for name in names), "ambiguous audit module owner"
    previous = {name: sys.modules.get(name) for name in names}
    old_path = list(sys.path)
    modules = {}
    try:
        for name, filename, digest in MODULES:
            path = regular(OLD / "state" / filename)
            source = path.read_bytes()
            assert sha_bytes(source) == digest
            spec = importlib.util.spec_from_file_location(name, path)
            assert spec is not None and spec.origin == str(path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            modules[name] = module
            exec(compile(source, str(path), "exec", dont_inherit=True, optimize=0), module.__dict__)
            assert module.__name__ == name and module.__file__ == str(path)
            assert module.__spec__ is spec and sha(path) == digest
        assert modules["state_audit"].audit_ownership is modules["state_ownership_audit"].audit_ownership
        assert modules["state_audit"].backing_identity is modules["state_mapping_identity"].backing_identity
        assert modules["state_audit"].exact_rows is modules["state_ledger_schema"].exact_rows
        assert modules["state_ownership_audit"].exact_rows is modules["state_ledger_schema"].exact_rows
        result = modules["state_audit"].audit(captures, inventory)
        assert sys.path == old_path
        for name, filename, digest in MODULES:
            assert sys.modules[name] is modules[name] and sha(OLD / "state" / filename) == digest
        return result
    finally:
        sys.path[:] = old_path
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--binding-sha256", required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--review-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert sys.pycache_prefix is None
    own = manifest(HERE / "manifest.json", args.manifest_sha256)
    state = manifest(STATE / "manifest.json", STATE_SHA)
    manifest(OLD / "manifest.json", OLD_SHA)
    bp = pinned(dict(path=str(args.binding), sha256=args.binding_sha256))
    review_path = pinned(dict(path=str(args.review), sha256=args.review_sha256))
    binding, review = read(bp), read(review_path)
    assert set(binding) == {"schema", "status", "state_manifest_sha256", "artifact_manifest_sha256", "binary", "compile", "commands", "build_review", "native_binding", "evidence_files"}
    assert binding["schema"] == "a3-state-v4-audit-binding-v1"
    assert binding["status"] == "ACTUAL_STATE_COMMANDS_COMPLETE_AUDIT_PENDING"
    assert binding["state_manifest_sha256"] == STATE_SHA and binding["artifact_manifest_sha256"] == OLD_SHA
    assert set(review) == {"schema", "status", "binding_sha256", "wrapper_manifest_sha256", "state_manifest_sha256", "review_report"}
    assert review["schema"] == "a3-state-v4-audit-review-v1"
    assert review["status"] == "APPROVED_ACTUAL_BINDING_FOR_CAPTURE_AUDIT_ONLY"
    assert review["binding_sha256"] == args.binding_sha256 and review["wrapper_manifest_sha256"] == args.manifest_sha256
    assert review["state_manifest_sha256"] == STATE_SHA
    report = pinned(review["review_report"])
    build_review = pinned(binding["build_review"])
    run = STATE / "state-run-v1"
    assert not bp.is_relative_to(run) and not review_path.is_relative_to(run)
    assert pinned(binding["native_binding"]) == run / "binding.json"
    binary = binding["binary"]
    assert set(binary) == {"path", "sha256", "bytes"}
    assert Path(binary["path"]) == STATE / "build/oracle"
    assert type(binary["bytes"]) is int and binary["bytes"] > 0
    assert regular(binary["path"]).stat().st_size == binary["bytes"]
    assert sha(binary["path"]) == checksum(binary["sha256"])
    with regular(binary["path"]).open("rb") as stream:
        header = stream.read(64)
    assert header[:7] == b"\x7fELF\x02\x01\x01" and header[18:20] == b"\x3e\x00"
    compile_q = read(STATE / "requests/compile.json")
    assert binding["compile"]["request"] == dict(path=str(STATE / "requests/compile.json"), sha256=sha(STATE / "requests/compile.json"))
    evidence = command(binding["compile"], compile_q, b"")
    assert set(binding["commands"]) == {"ownership-controls", "state-native"}
    for name, argv, label, cpu, wall, cap, stdout in [
        ("ownership-controls", [binary["path"], "--ownership-controls"], "ownership-controls", 20, 30, 1048576, CONTROL_STDOUT),
        ("state-native", [binary["path"], str(run / "captures")], "native", 60, 90, 16777216, STATE_STDOUT),
    ]:
        row = binding["commands"][name]
        assert Path(row["request"]["path"]) == run / (label + ".request.json")
        assert Path(row["receipt"]["path"]) == run / (label + ".receipt.json")
        q = dict(argv=argv, cwd=compile_q["cwd"], env=compile_q["env"],
                 stdout=str(run / (label + ".stdout")), stderr=str(run / (label + ".stderr")),
                 cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
        evidence.update(command(row, q, stdout))
    assert {x.name for x in run.iterdir()} == {"binding.json", "captures", "native.request.json", "native.receipt.json", "native.stdout", "native.stderr", "ownership-controls.request.json", "ownership-controls.receipt.json", "ownership-controls.stdout", "ownership-controls.stderr"}
    expected_tree = file_map(run)
    capture_before = file_map(run / "captures")
    assert len(capture_before) == 2606
    assert type(binding["evidence_files"]) is dict and 1 <= len(binding["evidence_files"]) <= 8192
    for name, digest in binding["evidence_files"].items():
        assert reference_sha(name) == checksum(digest)
    assert evidence.items() <= binding["evidence_files"].items()
    assert all(binding["evidence_files"].get(str(run / name)) == digest for name, digest in expected_tree.items())
    for row in [binary, binding["build_review"], binding["native_binding"]]:
        assert binding["evidence_files"].get(row["path"]) == row["sha256"]
    output = args.output
    assert output.is_absolute() and output.resolve() == output and output.is_relative_to(ROOT / "ignored")
    assert not output.exists() and not output.is_symlink()
    assert not output.is_relative_to(STATE) and not output.is_relative_to(OLD) and not output.is_relative_to(HERE)
    assert not any(path.is_relative_to(output) for path in (STATE, OLD, HERE, bp, review_path))
    inventory = STATE / "source/input-inventory.json"
    result = run_audit(run / "captures", inventory)
    assert result["status"] == "EXACT_CAPTURE_AUDIT_PASS"
    assert result["manual_fixture_load"] is True and result["loader_admission"] is False and result["qualification_complete"] is False
    assert result["totals"] == dict(traces=144, points=360, hook_witnesses=0, file_pages=768)
    assert result["captured_sha256"] == capture_before and result["source_inventory_sha256"] == sha(inventory)
    assert len([n for n in capture_before if n.endswith("/ownership.tsv")]) == 36
    assert file_map(run) == expected_tree
    assert manifest(HERE / "manifest.json", args.manifest_sha256) == own
    assert manifest(STATE / "manifest.json", STATE_SHA) == state
    manifest(OLD / "manifest.json", OLD_SHA)
    for name, digest in binding["evidence_files"].items():
        assert reference_sha(name) == digest
    assert sha(bp) == args.binding_sha256 and sha(review_path) == args.review_sha256
    assert sha(report) == review["review_report"]["sha256"] and sha(build_review) == binding["build_review"]["sha256"]
    output.mkdir()
    with (output / "capture-audit.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    terminal = dict(status="COMPLETE_SEPARATE_E9_V4_BODY_STATE_ORACLE", wrapper_manifest_sha256=args.manifest_sha256,
                    state_manifest_sha256=STATE_SHA, state_main_sha256=state["files"]["source/main.rs"],
                    artifact_owner=read(STATE / "LINEAGE.json")["artifact_owner"],
                    binding_sha256=args.binding_sha256, review_sha256=args.review_sha256,
                    binary=binary, compile=binding["compile"], commands=binding["commands"],
                    carried_prerequisites=read(STATE / "LINEAGE.json")["completed_prerequisites"],
                    files={"capture-audit.json": sha(output / "capture-audit.json")},
                    closed_state_files=expected_tree, closed_evidence_files=binding["evidence_files"],
                    totals=result["totals"], ownership_ledgers=36, capture_files=2606,
                    retained_module_instances=12, reservation_roots=16, body_owned_bytes=425984, data_stack_owned_bytes=884736,
                    manual_fixture_load=True, mapped_bootstrap=False, loader_admission=False, qualification_complete=False,
                    audit_helper_receipt="separate root-owned receipt required; this terminal does not certify its own process cleanup")
    with (output / "complete.json").open("x") as stream:
        stream.write(json.dumps(terminal, indent=2, sort_keys=True) + "\n")
    assert {x.name for x in output.iterdir()} == {"capture-audit.json", "complete.json"}
    print("COMPLETE_SEPARATE_E9_V4_BODY_STATE_ORACLE", sha(output / "complete.json"), flush=True)


if __name__ == "__main__":
    main()
