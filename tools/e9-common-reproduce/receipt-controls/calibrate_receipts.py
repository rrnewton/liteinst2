#!/usr/bin/env python3
"""Prospective pure checks of the new wrapper's exact receipt grammar only."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import copy
import hashlib
import json
from pathlib import Path
import types


def main():
    assert len(sys.argv) == 2 and sys.pycache_prefix is None
    here = Path(__file__).resolve().parent
    raw = (here / "manifest.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == sys.argv[1]
    manifest = json.loads(raw)
    for name in ("calibrate_receipts.py", "audit_state.py"):
        assert hashlib.sha256((here / name).read_bytes()).hexdigest() == manifest["files"][name]
    path = here / "audit_state.py"
    module = types.ModuleType("a3_state_wrapper_receipt_controls")
    module.__file__ = str(path)
    # This is authenticated source execution, never import or cached bytecode.
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True, optimize=0), module.__dict__)
    request_hash = "1" * 64
    stdout, stderr = b"complete\n", b""
    good = dict(request_sha256=request_hash, helper_sha256=module.HELPER_SHA,
                exit=0, wall_timeout=False, unexpected_descendants=[], absence_proof="ECHILD",
                stdout_sha256=module.sha_bytes(stdout), stderr_sha256=module.sha_bytes(stderr),
                elapsed_seconds=0.125, cleanup_events=[], cleanup_error=None, aborted=None,
                inputs_unchanged=True)
    module.receipt(good, request_hash, stdout, stderr)
    changes = [
        ("bool-exit", "exit", False),
        ("float-exit", "exit", 0.0),
        ("nonzero-exit", "exit", 1),
        ("missing-exit", "exit", None),
        ("wrong-request", "request_sha256", "2" * 64),
        ("wrong-helper", "helper_sha256", "2" * 64),
        ("wall-timeout", "wall_timeout", True),
        ("numeric-wall-timeout", "wall_timeout", 0),
        ("descendant", "unexpected_descendants", [1]),
        ("cleanup-event", "cleanup_events", ["kill"]),
        ("cleanup-error", "cleanup_error", "error"),
        ("abort", "aborted", "signal"),
        ("no-absence-proof", "absence_proof", None),
        ("wrong-stdout", "stdout_sha256", "2" * 64),
        ("wrong-stderr", "stderr_sha256", "2" * 64),
        ("bool-elapsed", "elapsed_seconds", True),
        ("negative-elapsed", "elapsed_seconds", -0.1),
        ("infinite-elapsed", "elapsed_seconds", float("inf")),
        ("nan-elapsed", "elapsed_seconds", float("nan")),
        ("inputs-changed", "inputs_unchanged", False),
        ("numeric-inputs-unchanged", "inputs_unchanged", 1),
    ]
    mutants = []
    for name, key, value in changes:
        row = copy.deepcopy(good)
        row[key] = value
        mutants.append((name, row))
    missing = copy.deepcopy(good)
    del missing["aborted"]
    extra = copy.deepcopy(good)
    extra["unknown"] = 1
    mutants.extend([("missing-field", missing), ("extra-field", extra)])
    assert len(mutants) == 23 and len({name for name, _ in mutants}) == 23
    refused = []
    for name, row in mutants:
        try:
            module.receipt(row, request_hash, stdout, stderr)
        except AssertionError:
            refused.append(name)
        else:
            raise AssertionError("accepted malformed receipt: " + name)
    assert refused == [name for name, _ in mutants]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest["files"]["audit_state.py"]
    print("STATE_AUDIT_RECEIPT_CONTROLS_PASS positives=1 negatives=23", flush=True)


if __name__ == "__main__":
    main()
