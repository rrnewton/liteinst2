#!/usr/bin/env python3
"""Bounded, source-extracted differential controls; no full-recorder credit."""
import ast
import builtins
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DONOR_REVISION = 'e6bc85380d732e1046cde162c8b26d1ef95b3461'
SOURCE = 'evaluation/admission/core_97ab_inventory.py'
DONOR_SHA = '99f3ef0f027a95d26de2a4aec6d3b9e365e29d1e028a713847cdec43100371df'
CANDIDATE_SHA = 'ee5b848be6e9e91409bcb29e0b703b8689b8f15807d1d1f18c8af49b1cec3289'


def load(path, expected, candidate, overrides=None):
    raw = (path.read_bytes() if candidate else subprocess.check_output(
        ['/usr/bin/git', '--no-replace-objects', 'show', f'{DONOR_REVISION}:{SOURCE}'], cwd=ROOT))
    assert hashlib.sha256(raw).hexdigest() == expected
    names = {'plain_catalog', '_plain_catalog_fallback'} if candidate else {'plain_catalog'}
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in nodes} == names
    namespace = {'__builtins__': builtins}
    namespace.update(overrides or {})
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


def main():
    old = ROOT/'evaluation/admission/core_97ab_inventory.py'
    new = ROOT/'evaluation/admission/core_97ab_inventory.py'
    donor = load(old, DONOR_SHA, False)
    candidate = load(new, CANDIDATE_SHA, True)
    events = []
    class PretendScalar(type):
        def __eq__(cls, other):
            events.append(('equal', other.__name__))
            return other is str
    class Pretend(metaclass=PretendScalar): pass
    class RaisingKind(type):
        def __eq__(cls, other):
            events.append(('raise', other.__name__))
            raise LookupError('live metaclass equality')
    class Raising(metaclass=RaisingKind): pass
    class Published(dict):
        def __deepcopy__(self, memo):
            raise AssertionError('a plain scan must not invoke deepcopy')
    def outcome(namespace, value):
        events.clear()
        try: result = ('value', namespace['plain_catalog'](value))
        except BaseException as error: result = ('error', type(error).__name__, str(error))
        return result, tuple(events)
    comparisons = 0
    def compare(left, right, value, expected=None):
        nonlocal comparisons
        a, b = outcome(left, value), outcome(right, value)
        assert a == b, (a, b)
        if expected is not None: assert a[0] == ('value', expected), a
        comparisons += 1
    scalar = ['', 0, False, 1.5, None, float('nan'), float('inf'), 1 << 4096]
    for value in scalar: compare(donor, candidate, value, True)
    shared = [1, {'a': (None, 2.5)}]
    values = [[], {}, (), [shared, shared], {('key', 3, None): shared, 7: True, 2.5: False, None: 1},
              {'nested': [scalar, shared]}, b'x', bytearray(b'x'), {1}, frozenset({1}),
              complex(1, 2), range(3), object(), Published(x=1), Pretend(), Raising()]
    cycle = []; cycle.append(cycle); values.append(cycle)
    mapping = {}; mapping['self'] = mapping; values.append(mapping)
    mixed = []; fixed = (mixed,); mixed.extend((fixed, {'cycle': mixed})); values.append(fixed)
    deep = None
    for _ in range(2000): deep = [deep]
    values.append(deep)
    for value in values: compare(donor, candidate, value)
    mutable = {'branch': [1]}
    compare(donor, candidate, mutable, True)
    mutable['branch'].append(Published())
    compare(donor, candidate, mutable, False)
    mutable['branch'].pop()
    compare(donor, candidate, mutable, True)
    metadata = json.loads((ROOT/'evaluation/admission/core_97ab_inventory.json').read_bytes())
    compare(donor, candidate, metadata, True)
    metadata['temporary_foreign'] = Published()
    compare(donor, candidate, metadata, False)
    del metadata['temporary_foreign']
    compare(donor, candidate, metadata, True)
    def live_type(value):
        events.append(('type', builtins.type(value).__name__)); return builtins.type(value)
    def live_id(value):
        events.append(('id', builtins.type(value).__name__)); return builtins.id(value)
    def live_set():
        events.append(('set',)); return builtins.set()
    hooks = [('type', live_type), ('id', live_id), ('set', live_set),
             ('str', Pretend), ('int', float), ('bool', int), ('float', int),
             ('dict', list), ('list', tuple), ('tuple', list)]
    for before_definition in (True, False):
        for name, replacement in hooks:
            overrides = {name: replacement}
            a = load(old, DONOR_SHA, False, overrides if before_definition else None)
            b = load(new, CANDIDATE_SHA, True, overrides if before_definition else None)
            if not before_definition: a.update(overrides); b.update(overrides)
            compare(a, b, {'a': [1, None, (False, 1.5)]})
            del a[name]; del b[name]
            compare(a, b, {'restored': [2, None]}, True)
    assert comparisons == 74
    class ForeignModule:
        def __eq__(self, other):
            events.append(('module_equal', other)); raise AssertionError('foreign metadata equality')
        def __ne__(self, other):
            events.append(('module_unequal', other)); raise AssertionError('foreign metadata inequality')
    class ModuleText(str):
        def __eq__(self, other):
            events.append(('text_equal', other)); raise AssertionError('foreign string equality')
        def __ne__(self, other):
            events.append(('text_unequal', other)); raise AssertionError('foreign string inequality')
    original_module = builtins.id.__module__
    metadata_comparisons = 0
    for module in (ForeignModule(), ModuleText('builtins'), 'changed', None):
        try:
            builtins.id.__module__ = module
            compare(donor, candidate, {'metadata': [1, None, (False, 1.5)]}, True)
            assert events == []
            metadata_comparisons += 1
        finally:
            builtins.id.__module__ = original_module
        compare(donor, candidate, {'restored': [2, None]}, True)
        metadata_comparisons += 1
    assert comparisons == 82 and metadata_comparisons == 8
    print(json.dumps(dict(status='passed_differential_only', comparisons=comparisons,
                          original_comparisons=74, metadata_comparisons=metadata_comparisons,
                          fresh_graph_per_call=True, qualification_credit=False)), flush=True)


if __name__ == '__main__': main()
