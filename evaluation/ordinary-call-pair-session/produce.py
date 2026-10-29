#!/usr/bin/env python3
"""Authenticated fixed CallPair entry to the shared Module producer lifecycle."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'evaluation/ordinary-call-pair-session/'
SHARED = 'evaluation/ordinary-module-session/'
REQUIRED = tuple(PREFIX + n for n in ('produce.py', 'profile.py', 'output.py', 'producer_controls.py')) + tuple(
    SHARED + n for n in ('reproduce.py', 'produce.py', 'corpus.py', 'output.py'))


def authenticate(plan_path, plan_sha, root=ROOT):
    assert plan_path.is_absolute() and plan_path.resolve(strict=True) == plan_path
    assert type(plan_sha) is str and re.fullmatch('[0-9a-f]{64}', plan_sha)
    assert 0 < plan_path.stat().st_size <= 1048576
    data = plan_path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == plan_sha
    plan = json.loads(data)
    for relative in REQUIRED:
        path = root / relative
        assert path.resolve(strict=True) == path and not path.is_symlink() and path.is_file()
        assert 0 < path.stat().st_size <= 1048576
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
    profile = load('_call_pair_producer_profile', ROOT / PREFIX / 'profile.py', plan['pins'])
    binding = profile.call_pair_binding()
    binding.check_sources(ROOT, plan['pins'])
    binding.check_plan(plan)
    shared = load('_call_pair_shared_producer', ROOT / SHARED / 'produce.py', plan['pins'])
    return shared._main(call_pair=binding)


if __name__ == '__main__':
    raise SystemExit(main())
