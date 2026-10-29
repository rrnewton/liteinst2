#!/usr/bin/env python3
"""Source-bound whole-policy entry to the unchanged LeafSet child lifecycle."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SHARED = ROOT / 'evaluation/ordinary-leaf-set-session/produce.py'


def authenticate(plan_path, plan_sha):
    assert plan_path.is_absolute() and plan_path.resolve(strict=True) == plan_path
    assert plan_path.stat().st_size <= 1048576
    data = plan_path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == plan_sha
    plan = json.loads(data)
    paths = tuple(HERE / name for name in (
        'reproduce.py', 'produce.py', 'profile.py', 'catalog.py', 'profile_controls.py', 'README.md')) + tuple(
        SHARED.with_name(name) for name in ('reproduce.py', 'produce.py', 'catalog.py', 'output.py'))
    for path in paths:
        assert path.resolve(strict=True) == path and not path.is_symlink() and path.is_file()
        assert path.stat().st_size <= 1048576
        assert hashlib.sha256(path.read_bytes()).hexdigest() == plan['pins'][str(path)]
    return plan


def load(name, path, pins):
    assert path.resolve(strict=True) == path
    assert hashlib.sha256(path.read_bytes()).hexdigest() == pins[str(path)]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--plan', type=Path, required=True)
    ap.add_argument('--plan-sha', required=True)
    ap.add_argument('--raw', type=Path, required=True)
    a = ap.parse_args()
    plan = authenticate(a.plan, a.plan_sha)
    profile = load('_leaf_whole_producer_profile', HERE / 'profile.py', plan['pins'])
    binding = profile.whole_binding()
    binding.check_sources(ROOT, plan['pins'])
    binding.check_plan(plan)
    shared = load('_leaf_whole_shared_producer', SHARED, plan['pins'])
    return shared._main(binding=binding)


if __name__ == '__main__':
    raise SystemExit(main())
