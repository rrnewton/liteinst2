#!/usr/bin/env python3
"""Run the unchanged pure backing-identity vectors from authenticated source."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
from pathlib import Path


def main():
    assert len(sys.argv) == 3 and sys.pycache_prefix is None
    here = Path(__file__).resolve().parent
    frozen, expected = Path(sys.argv[1]), sys.argv[2]
    raw = (frozen / "freeze.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    data = json.loads(raw)
    root = Path(data["root"])
    assert here == Path(data["adapter"])
    owners = {"_consumer_mapping_adapter": here / "adapter.py"}
    owners.update({name: here / "runtime" / (name + ".py") for name in
                   ("mapping_identity", "backing_records", "calibrate_identity", "calibrate_records")})
    assert all(name not in sys.modules for name in owners)
    path_before = list(sys.path)
    try:
        for name, path in owners.items():
            assert path.resolve(strict=True) == path and not path.is_symlink()
            source = path.read_bytes()
            assert hashlib.sha256(source).hexdigest() == data["source_files"][str(path.relative_to(root))]
            spec = importlib.util.spec_from_file_location(name, path)
            assert spec is not None and spec.origin == str(path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            exec(compile(source, str(path), "exec", dont_inherit=True, optimize=0), vars(module))
            assert module.__file__ == str(path) and module.__spec__ is spec
        assert sys.modules["_consumer_mapping_adapter"].verify(frozen, expected) == data
        sys.modules["calibrate_records"].main()
        assert sys.modules["_consumer_mapping_adapter"].verify(frozen, expected) == data
        assert sys.path == path_before
    finally:
        for name in owners:
            sys.modules.pop(name, None)
        assert sys.path == path_before


if __name__ == "__main__":
    main()
