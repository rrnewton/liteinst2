#!/usr/bin/env python3
"""Private stdlib-only key feasibility probe, never a production validator."""
import _pickle
import collections
import hashlib
import io
import json
import math
import os
from pathlib import Path
import resource
import statistics
import sys
import time

LIMIT = 1048576
CACHE = collections.OrderedDict()
ENCODES = 0
CONTROLS = []


class NotKey(Exception):
    pass


class LimitedBytes(io.BytesIO):
    def write(self, data):
        if self.tell() + len(data) > LIMIT:
            raise NotKey
        return super().write(data)


class RefusingPickler(_pickle.Pickler):
    def reducer_override(self, obj):
        raise NotKey


def key(value):
    output = LimitedBytes()
    try:
        RefusingPickler(output, protocol=5).dump(value)
        return output.getvalue()
    except (NotKey, _pickle.PicklingError, RecursionError, TypeError, ValueError, OverflowError):
        return None


def canonical(value):
    global ENCODES
    ENCODES += 1
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def experimental(value, provider=canonical):
    # Probe-only: provider identity demonstrates the required foreign fallback.
    # A production implementation ALSO needs full JSON dependency authority.
    if provider is not canonical:
        return provider(value)
    raw = key(value)
    if raw is None:
        return provider(value)
    if raw in CACHE:
        CACHE.move_to_end(raw)
        return CACHE[raw]
    result = provider(value)
    if len(result) <= LIMIT:
        CACHE[raw] = result
        if len(CACHE) > 16:
            CACHE.popitem(last=False)
    return result


def outcome(call):
    try:
        return ('value', call())
    except Exception as error:
        return ('error', type(error), str(error))


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    CONTROLS.append(name)


def controls():
    for name, a, b in (
            ('bool_int', True, 1), ('int_float', 1, 1.0),
            ('tuple_list', (1, 2), [1, 2]), ('signed_zero', 0.0, -0.0),
            ('none_false', None, False), ('text_number', '1', 1)):
        check(name, key(a) != key(b) and experimental(a) == canonical(a)
              and experimental(b) == canonical(b))
    shared = [1]
    check('alias_key', key([shared, shared]) != key([[1], [1]]))
    for name, value in (
            ('alias_value', [shared, shared]), ('reordered', {'b': 2, 'a': 1}),
            ('unicode', {'x': '\u00e9\U0001f600\ud800'}),
            ('large_integer', [-(1 << 200), 1 << 200])):
        check(name, experimental(value) == canonical(value))
    value = {'nested': [1, False]}
    prior = key(value)
    first = experimental(value)
    value['nested'][0] = True
    check('mutation', key(value) != prior and experimental(value) == canonical(value)
          and experimental(value) != first)
    value['nested'][0] = 1
    check('restored_value', experimental(value) == first)
    cycle = []
    cycle.append(cycle)
    invalid = [('cycle', cycle), ('nan', math.nan), ('infinity', math.inf),
               ('bytes', b'x'), ('bytearray', bytearray(b'x')), ('set', {1}),
               ('frozen_set', frozenset({1})), ('mixed_keys', {'x': 1, 2: 3})]
    for name, value in invalid:
        CACHE.clear()
        expected = outcome(lambda: canonical(value))
        count = ENCODES
        check('uncached_' + name, expected[0] == 'error'
              and outcome(lambda: experimental(value)) == expected
              and outcome(lambda: experimental(value)) == expected
              and ENCODES == count + 2 and not CACHE)
    events = []

    class Foreign:
        def __getattribute__(self, name):
            events.append(('getattribute', name))
            return object.__getattribute__(self, name)

        def __reduce__(self):
            events.append('reduce')
            raise AssertionError('foreign reduction called')

        def __reduce_ex__(self, protocol):
            events.append('reduce_ex')
            raise AssertionError('foreign reduction called')

        def __buffer__(self, flags):
            events.append('buffer')
            return memoryview(b'x')

        def items(self):
            events.append('items')
            return [('x', 1)]

    class DictSubclass(dict):
        def items(self):
            events.append('items')
            return super().items()

    subclasses = [('dict', DictSubclass(x=1))]
    for cls, value in ((list, [1]), (tuple, (1,)), (int, 1), (float, 1.0), (str, 'x')):
        subclasses.append((cls.__name__, type('Subclass', (cls,), {})(value)))
    for name, value in [('foreign', Foreign()), *subclasses]:
        nested = {'nested': [value]}
        CACHE.clear()
        events.clear()
        refused = key(nested)
        check('refuse_' + name, refused is None and events == [])
        expected = outcome(lambda: canonical(nested))
        expected_events = list(events)
        events.clear()
        actual = outcome(lambda: experimental(nested))
        check('foreign_live_' + name, actual == expected and events == expected_events and not CACHE)
    events.clear()

    def stateful(value):
        events.append('provider')
        return str(len(events)).encode()

    check('stateful_provider', experimental(1, stateful) == b'1'
          and experimental(1, stateful) == b'2' and events == ['provider', 'provider'])
    events.clear()

    def failing(value):
        events.append('provider')
        raise RuntimeError(str(len(events)))

    check('failing_provider', outcome(lambda: experimental(1, failing))[2] == '1'
          and outcome(lambda: experimental(1, failing))[2] == '2' and len(events) == 2)
    oversized = 'x' * (LIMIT + 1)
    CACHE.clear()
    check('oversized_key', key(oversized) is None
          and experimental(oversized) == canonical(oversized) and not CACHE)
    for i in range(17):
        experimental({'bounded': i})
    check('bounded_entries', len(CACHE) == 16)
    check('bounded_blobs', all(type(k) is bytes and type(v) is bytes
          and len(k) <= LIMIT and len(v) <= LIMIT for k, v in CACHE.items()))


def main():
    if len(sys.argv) != 3 or len(os.sched_getaffinity(0)) != 1:
        raise ValueError('exact corpus path/SHA and reserved singleton required')
    if (resource.getrlimit(resource.RLIMIT_CPU) != (5, 5)
            or resource.getrlimit(resource.RLIMIT_AS) != (536870912, 536870912)
            or resource.getrlimit(resource.RLIMIT_FSIZE) != (16777216, 16777216)):
        raise ValueError('original 5CPU/512MiB/16MiB child limits required')
    raw = Path(sys.argv[1]).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != 230598 or digest != sys.argv[2]:
        raise ValueError('fixed corpus identity differs')
    value = json.loads(raw)
    controls()
    if len(CONTROLS) != 40:
        raise AssertionError(('literal control population', len(CONTROLS)))
    CACHE.clear()
    expected = canonical(value)
    if experimental(value) != expected:
        raise AssertionError('initial whole canonical value')
    rows = []
    for batch in range(8):
        order = ('json', 'key_cache') if batch % 2 == 0 else ('key_cache', 'json')
        for name in order:
            call = canonical if name == 'json' else experimental
            start_cpu, start_wall = time.process_time_ns(), time.perf_counter_ns()
            for _ in range(100):
                if call(value) != expected:
                    raise AssertionError('whole timed canonical value')
            rows.append({'batch': batch, 'operation': name, 'iterations': 100,
                         'wall_ns': time.perf_counter_ns() - start_wall,
                         'cpu_ns': time.process_time_ns() - start_cpu})
    medians = {name: statistics.median([r['wall_ns'] / 100 for r in rows
               if r['operation'] == name]) for name in ('json', 'key_cache')}
    print(json.dumps({'schema': 1, 'scope': 'stdlib key feasibility only; no production JSON authority or 366-test credit',
          'corpus': {'bytes': len(raw), 'sha256': digest}, 'controls': CONTROLS,
          'canonical': {'bytes': len(expected), 'sha256': hashlib.sha256(expected).hexdigest()},
          'cache_entries': len(CACHE), 'cache_key_bytes': sum(map(len, CACHE)),
          'key_has_no_unpickle': True, 'rows': rows, 'median_wall_ns_per_call': medians,
          'timing_scope': 'whole canonical bytes plus per-call equality; warmed cache; key construction included',
          'production_dependency_guard': 'unimplemented and required before production',
          'qualification_credit': False}, sort_keys=True))


if __name__ == '__main__':
    main()
