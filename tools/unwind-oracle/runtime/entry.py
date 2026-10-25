#!/usr/bin/env python3
"""Authenticate local source before loading; no cached or historical modules."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
from pathlib import Path


def main():
    assert sys.pycache_prefix is None
    here = Path(__file__).resolve().parent
    assert len(sys.argv) >= 3
    phase, expected = sys.argv[1:3]
    assert phase in {"run", "audit"}
    raw = (here / "source-files.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    sources = json.loads(raw)
    assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == sources["entry.py"]
    names = ["guard", "mapping_identity", "backing_records", "audit"]
    if phase == "run":
        names.append("execute")
    previous = {name: sys.modules.get(name) for name in names}
    assert all(module is None for module in previous.values()), "ambiguous local module owner"
    old_path, old_argv = list(sys.path), sys.argv
    try:
        for name in names:
            path = here / (name + ".py")
            assert path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path
            source = path.read_bytes()
            assert hashlib.sha256(source).hexdigest() == sources[path.name]
            spec = importlib.util.spec_from_file_location(name, path)
            assert spec is not None and spec.origin == str(path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            exec(compile(source, str(path), "exec", dont_inherit=True, optimize=0), vars(module))
            assert module.__file__ == str(path) and module.__spec__ is spec
            assert hashlib.sha256(path.read_bytes()).hexdigest() == sources[path.name]
            assert sys.path == old_path
        sys.modules["guard"].verify()
        sys.argv = [str(here / (names[-1] + ".py"))] + old_argv[3:]
        sys.modules[names[-1]].main()
        for name in names:
            assert hashlib.sha256((here / (name + ".py")).read_bytes()).hexdigest() == sources[name + ".py"]
        assert sys.path == old_path
    finally:
        sys.argv = old_argv
        # No path mutation is needed. Refuse one rather than silently hiding it.
        path_unchanged = sys.path == old_path
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old
        assert path_unchanged


if __name__ == "__main__":
    main()
