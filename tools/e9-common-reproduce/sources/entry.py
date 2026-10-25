#!/usr/bin/env python3
"""Execute authenticated source bytes; no cached authored-module admission."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import hashlib
import json
from pathlib import Path
import types


def main():
    here = Path(__file__).resolve().parent
    assert len(sys.argv) >= 3
    phase, expected = sys.argv[1:3]
    assert phase in {"prepare", "emit", "bind-native", "native", "audit-native", "calibrate", "supervisor_calibrate", "calibrate_prerequisites", "calibrate-common", "calibrate-sparse", "calibrate-ledgers", "bind-state", "bind-state-run", "audit-state", "calibrate-state-identity"}
    raw = (here / "manifest.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    manifest = json.loads(raw)
    assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == manifest["files"]["entry.py"]
    names = [("old_audit", "sources/old_audit.py"), ("bootstrap_validate", "sources/bootstrap_validate.py"),
             ("frozen_profile", "sources/frozen_profile.py"), ("sparse_geometry", "sources/sparse_geometry.py"), ("common", "sources/common.py"),
             ("mapping_identity", "sources/mapping_identity.py"), ("ownership", "sources/ownership.py"),
             ("bounded_stage1", "sources/bounded_stage1.py"), ("guard", "sources/guard.py"),
             ("pipeline", "sources/pipeline.py")]
    if phase in {"calibrate", "supervisor_calibrate", "calibrate_prerequisites"}:
        names += [("audit", "legacy/audit.py"), ("prerequisites", "legacy/prerequisites.py"),
                  ("runner", "legacy/runner.py"), (phase, "legacy/" + phase + ".py")]
    elif phase == "calibrate-common":
        names += [("calibrate_common", "sources/calibrate_common.py")]
    elif phase == "calibrate-sparse":
        names += [("calibrate_sparse", "sources/calibrate_sparse.py")]
    elif phase == "calibrate-ledgers":
        names += [("state_ledger_schema", "state/ledger_schema.py"), ("calibrate_ledgers", "sources/calibrate_ledgers.py")]
    elif phase == "native":
        names += [("trace_primitives", "sources/trace_primitives.py"), ("native", "sources/native.py")]
    elif phase in {"bind-state", "bind-state-run", "audit-state"}:
        names += [("state_join", "sources/state_join.py")]
        if phase == "audit-state":
            names += [("state_mapping_identity", "state/mapping_identity.py"), ("state_ledger_schema", "state/ledger_schema.py"), ("state_ownership_audit", "state/ownership_audit.py"), ("state_audit", "state/audit.py")]
    elif phase == "calibrate-state-identity":
        names += [("mapping_identity", "state/mapping_identity.py"), ("state_identity_calibration", "state/calibrate_identity.py")]
    previous = {name: sys.modules.get(name) for name, _ in names}
    try:
        for name, relative in names:
            path = here / relative
            assert not path.is_symlink() and path.resolve().is_relative_to(here)
            source = path.read_bytes()
            assert hashlib.sha256(source).hexdigest() == manifest["files"][relative]
            module = types.ModuleType(name)
            module.__file__ = str(path)
            module.__package__ = ""
            sys.modules[name] = module
            exec(compile(source, str(path), "exec", dont_inherit=True, optimize=0), module.__dict__)
        sys.modules["guard"].source(here, expected)
        if phase in {"calibrate", "supervisor_calibrate", "calibrate_prerequisites"}:
            print(json.dumps(sys.modules[phase].calibrate(), indent=2))
        elif phase == "calibrate-common":
            print(json.dumps(sys.modules["calibrate_common"].calibrate(here), indent=2))
        elif phase == "calibrate-sparse":
            print(json.dumps(sys.modules["calibrate_sparse"].calibrate(), indent=2))
        elif phase == "calibrate-ledgers":
            print(json.dumps(sys.modules["calibrate_ledgers"].calibrate(), indent=2))
        elif phase == "calibrate-state-identity":
            print(json.dumps(sys.modules["state_identity_calibration"].calibrate(), sort_keys=True))
        else:
            sys.modules["pipeline"].main(here, expected, phase, sys.argv[3:])
    finally:
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


if __name__ == "__main__":
    main()
