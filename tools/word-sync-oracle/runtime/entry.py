#!/usr/bin/env python3
"""Load exact authenticated local source bytes, never cached Python code."""
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
    assert phase in {"run", "auditor-calibrations"}
    raw = (here / "source-files.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    manifest = json.loads(raw)
    assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == manifest["entry.py"]
    names = ["guard", "audit", "execute" if phase == "run" else "auditor_calibrations"]
    previous = {name: sys.modules.get(name) for name in names}
    original_argv = sys.argv
    try:
        for name in names:
            path = here / (name + ".py")
            assert not path.is_symlink() and path.resolve().parent == here
            source = path.read_bytes()
            assert hashlib.sha256(source).hexdigest() == manifest[path.name]
            module = types.ModuleType(name)
            module.__file__ = str(path)
            module.__package__ = ""
            sys.modules[name] = module
            exec(compile(source, str(path), "exec", dont_inherit=True, optimize=0), module.__dict__)
        sys.modules["guard"].verify()
        sys.argv = [str(here / (names[-1] + ".py"))] + sys.argv[3:]
        sys.modules[names[-1]].main()
    finally:
        sys.argv = original_argv
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


if __name__ == "__main__":
    main()
