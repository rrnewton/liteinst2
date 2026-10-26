#!/usr/bin/env python3
"""Pure synthetic authority/header controls; never launch a command or workload."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with path.open("x") as f:
        f.write(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--materials-sha256", required=True)
    ap.add_argument("--repository", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert sys.pycache_prefix is None
    assert sha(HERE / "files.json") == args.materials_sha256
    files = json.loads((HERE / "files.json").read_text())
    for name, digest in files.items():
        assert sha(HERE / name) == digest
    source = HERE / "prepare.py"
    code = source.read_bytes()
    assert hashlib.sha256(code).hexdigest() == files["prepare.py"]
    name = "_parity_authority_calibration_owner"
    assert name not in sys.modules
    spec = importlib.util.spec_from_file_location(name, source)
    assert spec is not None and spec.origin == str(source)
    p = importlib.util.module_from_spec(spec)
    sys.modules[name] = p
    exec(compile(code, str(source), "exec", dont_inherit=True, optimize=0), vars(p))
    repo, out = args.repository.resolve(strict=True), args.output.resolve()
    assert out.is_relative_to(repo / "ignored") and not out.exists()
    assert not out.is_relative_to(HERE) and not HERE.is_relative_to(out)
    out.mkdir()
    inventory = json.loads((HERE / "controls.json").read_text())
    rows = []
    fixed = {"helper_sha256": "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"}

    def observe(label, accept, fn):
        refused = False
        try:
            fn()
        except AssertionError:
            refused = True
        assert refused is (not accept), label
        rows.append(dict(id=label, expected="accept" if accept else "refuse",
                         observed="refuse" if refused else "accept"))

    def header(kind):
        b = bytearray(64)
        b[:7] = b"\x7fELF\x02\x01\x01"
        b[16:18] = kind.to_bytes(2, "little")
        b[18:20] = b"\x3e\x00"
        return bytes(b)

    observe("elf-exec", True, lambda: p.verify_elf_header(header(2)))
    observe("elf-dyn", True, lambda: p.verify_elf_header(header(3)))
    observe("elf-rel", False, lambda: p.verify_elf_header(header(1)))
    observe("elf-core", False, lambda: p.verify_elf_header(header(4)))

    def fixture(label):
        case = out / label
        case.mkdir()
        raw, control = case / "raw", case / "raw-control"
        raw.mkdir(); control.mkdir()
        # Deliberately synthetic records: no real consumer build or helper run is claimed.
        original = dict(repository=str(repo), consumer_raw=str(case / "epoch-a"),
                        consumer_freeze_sha256="a" * 64, consumer_build_sha256="b" * 64)
        save(raw / "inputs.json", original)
        save(raw / "old-cargo.request.json", {"synthetic": "old-cargo-never-executed"})
        digest = sha(raw / "inputs.json")
        q = p.request_value(control, "init", ["synthetic-init-never-executed"], {}, repo, (20, 30, 16777216))
        save(control / "init.request.json", q)
        Path(q["stdout"]).write_text(p.initial_result(digest, sha(raw / "old-cargo.request.json")))
        Path(q["stderr"]).write_bytes(b"")
        (control / "init.helper.stdout").write_bytes(p.SUCCESS)
        (control / "init.helper.stderr").write_bytes(b"")
        save(control / "init.receipt.json", dict(request_sha256=sha(control / "init.request.json"),
            helper_sha256=fixed["helper_sha256"], exit=0, wall_timeout=False, aborted=None,
            cleanup_error=None, unexpected_descendants=[], cleanup_events=[], absence_proof="ECHILD",
            inputs_unchanged=True, elapsed_seconds=0.0, stdout_sha256=sha(q["stdout"]), stderr_sha256=sha(q["stderr"])))
        p.EXPECTED_INPUTS_SHA = digest
        p.EXPECTED_INIT_RECEIPT_SHA = sha(control / "init.receipt.json")
        return raw, control, original

    def replace(raw, value):
        (raw / "inputs.json").write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

    raw, control, original = fixture("exact-initial-authority")
    observe("exact-initial-authority", True, lambda: p.read_authority(raw, fixed))

    for label, changes in [
        ("changed-coordinate", {"consumer_raw": "different-coordinate"}),
        ("changed-build-digest", {"consumer_build_sha256": "c" * 64}),
        ("replacement-epoch-original-digest", {"consumer_raw": "different-coordinate", "consumer_freeze_sha256": "d" * 64, "consumer_build_sha256": "e" * 64})]:
        raw, control, original = fixture(label)
        replace(raw, dict(original, **changes))
        observe(label, False, lambda: p.read_authority(raw, fixed))

    raw, control, original = fixture("refreshed-inputs-original-receipt")
    replace(raw, dict(original, consumer_build_sha256="f" * 64))
    p.EXPECTED_INPUTS_SHA = sha(raw / "inputs.json")
    observe("refreshed-inputs-original-receipt", False, lambda: p.read_authority(raw, fixed))

    raw, control, original = fixture("changed-during-read")
    actual_read = p.read
    def changing_read(path):
        value = actual_read(path)
        if Path(path) == raw / "inputs.json":
            replace(raw, dict(original, consumer_build_sha256="c" * 64))
        return value
    p.read = changing_read
    try:
        observe("changed-during-read", False, lambda: p.read_authority(raw, fixed))
    finally:
        p.read = actual_read

    raw, control, original = fixture("changed-after-phase")
    p.read_authority(raw, fixed)
    replace(raw, dict(original, consumer_build_sha256="c" * 64))
    observe("changed-after-phase", False, lambda: p.read_authority(raw, fixed))

    raw, control, original = fixture("changed-init-receipt")
    with (control / "init.receipt.json").open("a") as f:
        f.write(" ")
    observe("changed-init-receipt", False, lambda: p.read_authority(raw, fixed))

    raw, control, original = fixture("changed-init-request")
    with (control / "init.request.json").open("a") as f:
        f.write(" ")
    observe("changed-init-request", False, lambda: p.read_authority(raw, fixed))

    assert [{k: r[k] for k in ("id", "expected")} for r in rows] == inventory["cases"]
    assert all(r["observed"] == r["expected"] for r in rows)
    assert sum(r["observed"] == "accept" for r in rows) == 3
    assert sum(r["observed"] == "refuse" for r in rows) == 10
    assert sha(HERE / "files.json") == args.materials_sha256
    for name, digest in files.items():
        assert sha(HERE / name) == digest
    save(out / "controls-result.json", dict(status="PURE_SYNTHETIC_CONTROLS_PASS_HELPER_CLOSURE_PENDING",
        accepted=3, rejected=10, cases=rows, materials_sha256=args.materials_sha256,
        actual_consumer_builds=0, helper_invocations_inside_controls=0, native_or_planner_credit=0))
    print("parity-reproduction-authority-controls accepted=3 rejected=10")


if __name__ == "__main__":
    main()
