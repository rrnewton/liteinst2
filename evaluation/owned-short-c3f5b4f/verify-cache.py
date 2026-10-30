"""Require real public inventory-cache misses and hits on the recorded host.

Run from the repository root. Unsupported Python builds fail this diagnostic;
the portable unit controls separately test their live fallback.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')

root = Path.cwd()
sys.path.insert(0, str(root / 'evaluation/admission'))
import core_813_inventory as inventory

syntax = inventory.inventory_syntax
cache = syntax._test_names
paths = sorted(inventory.MAINSHORTOWNERSHIP['python_methods'])
assert len(paths) == 3
inputs = {}
for path in paths:
    raw = (root / path).read_bytes()
    assert syntax._test_names_eligible(raw, inventory.ast,
                                      inventory._SHORT_OWNERSHIP_SYNTAX_CONTEXT)
    inputs[path] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                        methods=len(inventory.MAINSHORTOWNERSHIP['python_methods'][path]))
cache.cache_clear()
inventory.require_short_ownership_sources()
first = cache.cache_info()
assert (first.misses, first.hits, first.currsize) == (3, 0, 3)
inventory.require_short_ownership_sources()
second = cache.cache_info()
assert (second.misses, second.hits, second.currsize) == (3, 3, 3)
print(json.dumps(dict(schema=1, status='PASS',
    revision=subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip(),
    python_version=list(sys.version_info[:3]), public_guard_calls=2,
    first=dict(misses=first.misses, hits=first.hits, entries=first.currsize),
    second=dict(misses=second.misses, hits=second.hits, entries=second.currsize),
    inputs=inputs, implementation_sha256={
        path: hashlib.sha256((root / path).read_bytes()).hexdigest()
        for path in ('evaluation/admission/inventory_syntax.py',
                     'evaluation/admission/core_813_inventory.py',
                     'evaluation/admission/test_main813_inventory.py')},
    source_only=False, performance_claim=False), sort_keys=True))
