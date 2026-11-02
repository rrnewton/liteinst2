#!/usr/bin/env python3
"""Standalone pure canonical-byte controls; recorder discovery stays at366."""
import builtins
import codecs
import importlib.util
import json
import math
from pathlib import Path
import resource
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import inventory_json as fast
import core_813_inventory as owner

DUMPS = json.dumps
_SLOT_CHILD = None
if len(sys.argv) > 2 and sys.argv[1] == '--native-slot-child':
    _SLOT_CHILD = sys.argv[2]
    del sys.argv[1:3]


def original(value, dumps=DUMPS):
    return dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def outcome(call):
    try:
        return ('value', call())
    except Exception as error:
        return ('error', type(error), str(error))


def fresh():
    spec = importlib.util.spec_from_file_location('_isolated_inventory_json', fast.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CanonicalControls(unittest.TestCase):
    def setUp(self):
        fast._CACHE.clear()
        fast._CACHE_BYTES = 0
        self.assertTrue(fast._eligible(DUMPS), 'this bounded control requires its pinned known stdlib')

    def _native_slot_child(self):
        # The test below must prove the real post-restoration bug before exit.
        # CPython provides no supported restoration of that hidden native slot;
        # a bounded child keeps the other unchanged controls independent.
        name = self._testMethodName
        if _SLOT_CHILD is not None:
            self.assertEqual(_SLOT_CHILD, name)
            return False
        def bounds():
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        child = subprocess.run([sys.executable, '-B', __file__, '--native-slot-child', name,
                                'CanonicalControls.'+name, '-v'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=15, check=False, preexec_fn=bounds)
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        self.assertEqual(child.stdout, b'')
        lines = child.stderr.decode().splitlines()
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[:3], [name+' (__main__.CanonicalControls.'+name+') ... ok', '', '-'*70])
        self.assertRegex(lines[3], r'^Ran 1 test in [0-9]+\.[0-9]+s$')
        self.assertEqual(lines[4:], ['', 'OK'])
        return True

    def test_exact_types_aliases_and_whole_values(self):
        for a, b in ((True, 1), (1, 1.0), ((1, 2), [1, 2]), (0.0, -0.0),
                     (None, False), ('1', 1)):
            with self.subTest(a=a, b=b):
                self.assertNotEqual(fast._key(a), fast._key(b))
                self.assertEqual(fast.canonical_bytes(a, DUMPS), original(a))
                self.assertEqual(fast.canonical_bytes(b, DUMPS), original(b))
        shared = [1]
        self.assertNotEqual(fast._key([shared, shared]), fast._key([[1], [1]]))
        for value in ([shared, shared], {'b': 2, 'a': 1}, {'x': '\u00e9\U0001f600\ud800'},
                      [-(1 << 200), 1 << 200], {}, [], (), None):
            with self.subTest(value=value):
                first = fast.canonical_bytes(value, DUMPS)
                self.assertEqual(first, original(value))
                self.assertIs(fast.canonical_bytes(value, DUMPS), first)

    def test_nested_mutations_and_restoration_use_fresh_keys(self):
        value = {'nested': [1, False, {'zero': 0.0}]}
        key = fast._key(value)
        first = fast.canonical_bytes(value, DUMPS)
        for mutation in (True, 1.0, '1', None):
            value['nested'][0] = mutation
            self.assertNotEqual(fast._key(value), key)
            actual = fast.canonical_bytes(value, DUMPS)
            self.assertEqual(actual, original(value))
            self.assertNotEqual(actual, first)
        value['nested'][0] = 1
        self.assertEqual(fast.canonical_bytes(value, DUMPS), first)
        value['nested'][2]['zero'] = -0.0
        self.assertNotEqual(fast.canonical_bytes(value, DUMPS), first)
        self.assertEqual(fast.canonical_bytes(value, DUMPS), original(value))

    def test_exceptions_never_populate_cache(self):
        cycle = []; cycle.append(cycle)
        for value in (cycle, math.nan, math.inf, -math.inf, b'x', bytearray(b'x'),
                      {1}, frozenset({1}), {'x': 1, 2: 3}):
            with self.subTest(kind=type(value)):
                expected = outcome(lambda: original(value))
                self.assertEqual(expected[0], 'error')
                for _ in range(2):
                    self.assertEqual(outcome(lambda: fast.canonical_bytes(value, DUMPS)), expected)
                self.assertEqual(fast._CACHE, {})
                self.assertEqual(fast._CACHE_BYTES, 0)

    def test_foreign_and_subclass_protocols_are_not_used_for_keys(self):
        events = []
        class Foreign:
            def __getattribute__(self, name):
                events.append(('getattribute', name))
                return object.__getattribute__(self, name)
            def __reduce__(self):
                events.append('reduce'); raise AssertionError('unexpected reduce')
            def __reduce_ex__(self, protocol):
                events.append('reduce_ex'); raise AssertionError('unexpected reduce_ex')
            def __buffer__(self, flags):
                events.append('buffer'); return memoryview(b'x')
            def items(self):
                events.append('items'); return [('x', 1)]
        class DictSubclass(dict):
            def items(self):
                events.append('items'); return super().items()
        values = [Foreign(), DictSubclass(x=1)]
        values += [type('Subclass', (cls,), {})(value) for cls, value in
                   ((list, [1]), (tuple, (1,)), (int, 1), (float, 1.0), (str, 'x'))]
        for value in values:
            nested = {'nested': [value]}
            events.clear()
            self.assertIsNone(fast._key(nested))
            self.assertEqual(events, [])
            expected = outcome(lambda: original(nested)); expected_events = list(events)
            events.clear()
            self.assertEqual(outcome(lambda: fast.canonical_bytes(nested, DUMPS)), expected)
            self.assertEqual(events, expected_events)
            self.assertEqual(fast._CACHE, {})

    def test_stateful_and_identity_colliding_providers_before_and_after_import(self):
        class Provider:
            __hash__ = None
            def __init__(self): self.calls = []
            def __eq__(self, other): raise AssertionError('provider equality invoked')
            def __call__(self, value, **options):
                self.calls.append((value, options))
                if len(self.calls) == 3: raise LookupError('third actual call')
                return str(len(self.calls))
        for before in (False, True):
            provider = Provider()
            with patch.object(json, 'dumps', provider):
                module = fresh() if before else fast
                with patch.object(module, '_key', side_effect=AssertionError('foreign provider keyed')):
                    self.assertEqual(module.canonical_bytes(1, provider), b'1')
                    self.assertEqual(module.canonical_bytes(1, provider), b'2')
                    with self.assertRaisesRegex(LookupError, '^third actual call$'):
                        module.canonical_bytes(1, provider)
                self.assertEqual(provider.calls, [(1, {'sort_keys': True, 'separators': (',', ':'),
                                                       'allow_nan': False})] * 3)

    def test_dependency_substitutions_before_and_after_import_are_live(self):
        # Prewarm a real entry so a missed dependency guard would return stale bytes.
        value = {'x': 1}
        self.assertEqual(fast.canonical_bytes(value, DUMPS), b'{"x":1}')
        def changed_encode(self, value): return '"changed"'
        def fail(*args, **kwargs): raise LookupError('actual changed dependency')
        class ChangedEncoder(json.JSONEncoder):
            def encode(self, value): return '"changed-class"'
        changes = [(json, 'JSONEncoder', ChangedEncoder),
                   (json.JSONEncoder, 'encode', changed_encode),
                   (json.JSONEncoder, '__init__', fail),
                   (json.JSONEncoder, 'iterencode', fail),
                   (json.JSONEncoder, 'default', fail),
                   (json.encoder, 'c_make_encoder', fail),
                   (json.encoder, 'encode_basestring_ascii', fail),
                   (json.encoder, 'encode_basestring', fail),
                   (json.encoder, 'INFINITY', 1.0),
                   (json.encoder, 'JSONEncoder', ChangedEncoder)]
        for module, name, replacement in changes:
            for before in (False, True):
                with self.subTest(name=name, before=before), patch.object(module, name, replacement):
                    candidate = fresh() if before else fast
                    self.assertFalse(candidate._eligible(DUMPS))
                    expected = outcome(lambda: original(value))
                    with patch.object(candidate, '_key', side_effect=AssertionError('changed dependency keyed')):
                        self.assertEqual(outcome(lambda: candidate.canonical_bytes(value, DUMPS)), expected)

    def test_mutable_native_encoder_type_is_not_blessed(self):
        if self._native_slot_child():
            return
        value = {'warm': 1}
        expected = original(value)
        self.assertEqual(fast.canonical_bytes(value, DUMPS), expected)
        key = fast._key(value)
        self.assertEqual(fast._CACHE[key], expected)
        self.assertTrue(fast._constructor_healthy())
        constructor_events = []
        def changed_call(self, value, level): return ['"native-call-changed"']
        def changed_new(*args, **kwargs):
            constructor_events.append('actual changed constructor')
            raise LookupError('native constructor changed')
        maker = fast._json.make_encoder
        for name, replacement in (('__call__', changed_call), ('__new__', changed_new)):
            for before in (False, True):
                with self.subTest(name=name, before=before), patch.object(maker, name, replacement):
                    module = fresh() if before else fast
                    self.assertFalse(module._eligible(DUMPS))
                    expected = outcome(lambda: original({'x': 1}))
                    with patch.object(module, '_key', side_effect=AssertionError('changed C type keyed')):
                        self.assertEqual(outcome(lambda: module.canonical_bytes({'x': 1}, DUMPS)), expected)
                    if name == '__new__':
                        constructor_events.clear()
                        self.assertFalse(fast._constructor_healthy())
                        self.assertEqual(constructor_events, [], 'native probe must not dispatch Python __new__')
        # The field identity is restored, but the native slot is genuinely bad.
        self.assertIs(vars(maker)['__new__'], dict(fast._AUTHORITY[5])['__new__'])
        expected_error = ('error', TypeError,
                          '_json.Encoder.__new__(_json.Encoder) is not safe, use object.__new__()')
        self.assertEqual(outcome(lambda: original(value)), expected_error)
        self.assertFalse(fast._constructor_healthy())
        self.assertFalse(fast._eligible(DUMPS))
        for module in (fast, fresh()):
            self.assertFalse(module._eligible(DUMPS))
            with patch.object(module, '_key', side_effect=AssertionError('poisoned slot keyed')):
                self.assertEqual(outcome(lambda: module.canonical_bytes(value, DUMPS)), expected_error)
        self.assertEqual(fast._CACHE[key], b'{"warm":1}', 'warm entry remains, but is never accepted')

    def test_key_and_code_authority_providers_before_and_after_import(self):
        events = []
        class FakePickler:
            def __init_subclass__(cls): events.append('subclassed foreign Pickler')
            def __init__(self, output, **options): self.output = output
            def dump(self, value):
                events.append('foreign dump'); self.output.write(b'constant-key')
        class FakeBytesIO:
            def __init_subclass__(cls): events.append('subclassed foreign BytesIO')
        def fake_marshal(*args):
            events.append('foreign marshal'); return b'foreign-code-authority'
        for provider, name, replacement in ((fast._pickle, 'Pickler', FakePickler),
                (fast._pickle, 'Unpickler', FakePickler),
                (fast.io, 'BytesIO', FakeBytesIO), (fast.marshal, 'dumps', fake_marshal)):
            for before in (False, True):
                events.clear()
                with self.subTest(name=name, before=before), patch.object(provider, name, replacement):
                    module = fresh() if before else fast
                    self.assertFalse(module._eligible(DUMPS))
                    with patch.object(module, '_key', side_effect=AssertionError('foreign key authority')):
                        self.assertEqual(module.canonical_bytes({'x': 1}, DUMPS), b'{"x":1}')
                        self.assertEqual(module.canonical_bytes({'x': 2}, DUMPS), b'{"x":2}')
                    self.assertEqual(events, [])

    def test_initial_separator_data_descriptors_remain_live(self):
        value = {'a': [1, 2], 'b': 3}
        fast.canonical_bytes(value, DUMPS)
        class Separator:
            def __init__(self, fail): self.fail = fail; self.events = []; self.serial = 0
            def __set__(self, instance, value):
                self.serial += 1
                self.events.append(('set', value, self.serial))
                if self.fail and self.serial == 2:
                    raise LookupError('actual second separator assignment')
                instance.__dict__['_assigned_separator'] = value
            def __get__(self, instance, owner):
                if instance is None: return self
                self.events.append(('get', self.serial))
                return instance.__dict__['_assigned_separator'] + str(self.serial)
        for name in ('item_separator', 'key_separator'):
            for before in (False, True):
                for fail in (False, True):
                    descriptor = Separator(fail)
                    with self.subTest(name=name, before=before, fail=fail), patch.object(
                            json.JSONEncoder, name, descriptor):
                        module = fresh() if before else fast
                        self.assertFalse(module._eligible(DUMPS))
                        self.assertEqual(descriptor.events, [])
                        expected = [outcome(lambda: original(value)) for _ in range(2)]
                        expected_events = list(descriptor.events)
                        descriptor.events.clear(); descriptor.serial = 0
                        with patch.object(module, '_key', side_effect=AssertionError('descriptor keyed')):
                            actual = [outcome(lambda: module.canonical_bytes(value, DUMPS))
                                      for _ in range(2)]
                        self.assertEqual(actual, expected)
                        self.assertEqual(descriptor.events, expected_events)
                        self.assertNotEqual(actual[0], actual[1])

    def test_initial_instance_descriptors_must_belong_to_the_encoder(self):
        current = json.JSONEncoder
        for name in ('__dict__', '__weakref__'):
            namespace = {k: v for k, v in vars(current).items() if k not in ('__dict__', '__weakref__')}
            namespace[name] = property(lambda instance: {})
            changed = type('JSONEncoder', (object,), namespace)
            self.assertEqual(set(vars(changed)), set(vars(current)))
            with self.subTest(name=name), patch.object(json, 'JSONEncoder', changed), patch.object(
                    json.encoder, 'JSONEncoder', changed):
                module = fresh()
                self.assertIsNone(module._AUTHORITY)
                with patch.object(module, '_key', side_effect=AssertionError('foreign instance descriptor keyed')):
                    self.assertEqual(outcome(lambda: module.canonical_bytes({'x': 1}, DUMPS)),
                                     outcome(lambda: original({'x': 1})))

    def test_foreign_provider_metadata_never_runs_comparisons(self):
        events = []
        class Metadata:
            def __eq__(self, other): events.append('eq'); raise AssertionError('metadata equality')
            def __ne__(self, other): events.append('ne'); raise AssertionError('metadata inequality')
        class Text(str):
            def __eq__(self, other): events.append('text-eq'); raise AssertionError('metadata text equality')
            def __ne__(self, other): events.append('text-ne'); raise AssertionError('metadata text inequality')
        class FakePickler: pass
        class FakeEncoder: pass
        for metadata in (Metadata(), Text('_pickle')):
            FakePickler.__module__ = metadata
            FakeEncoder.__module__ = metadata
            for provider, name, replacement in ((fast._pickle, 'Pickler', FakePickler),
                                               (fast._json, 'make_encoder', FakeEncoder)):
                for before in (False, True):
                    events.clear()
                    with patch.object(provider, name, replacement):
                        module = fresh() if before else fast
                        self.assertFalse(module._eligible(DUMPS))
                        self.assertEqual(module.canonical_bytes({'x': 1}, DUMPS), original({'x': 1}))
                        self.assertEqual(events, [])
        # These real builtin providers remain callable when their ordinary
        # __module__ metadata is replaced; neither comparison hooks nor keys run.
        for provider in (fast.marshal.dumps, fast._json.encode_basestring_ascii):
            old = provider.__module__
            for before in (False, True):
                events.clear()
                try:
                    provider.__module__ = Metadata()
                    module = fresh() if before else fast
                    self.assertFalse(module._eligible(DUMPS))
                    with patch.object(module, '_key', side_effect=AssertionError('foreign metadata keyed')):
                        self.assertEqual(module.canonical_bytes({'x': 1}, DUMPS), original({'x': 1}))
                    self.assertEqual(events, [])
                finally:
                    provider.__module__ = old

    def test_same_function_code_defaults_and_class_shape_changes(self):
        def changed(self, value): return '"in-place-code"'
        fn = json.JSONEncoder.encode
        for before in (False, True):
            old_code = fn.__code__
            try:
                fn.__code__ = changed.__code__
                candidate = fresh() if before else fast
                self.assertFalse(candidate._eligible(DUMPS))
                self.assertEqual(candidate.canonical_bytes({'x': 1}, DUMPS), b'"in-place-code"')
            finally:
                fn.__code__ = old_code
            self.assertIs(fn.__code__, old_code)
        for fn, name, value in ((DUMPS, 'ensure_ascii', False),
                                (json.JSONEncoder.__init__, 'skipkeys', 0)):
            old = fn.__kwdefaults__[name]
            try:
                fn.__kwdefaults__[name] = value
                self.assertFalse(fast._eligible(DUMPS))
                self.assertIsNone(fresh()._AUTHORITY)
                self.assertEqual(outcome(lambda: fast.canonical_bytes({'x': '\u00e9'}, DUMPS)),
                                 outcome(lambda: original({'x': '\u00e9'})))
            finally:
                fn.__kwdefaults__[name] = old
        with patch.object(json.JSONEncoder, '__getattribute__', object.__getattribute__, create=True):
            self.assertFalse(fast._eligible(DUMPS))
            self.assertIsNone(fresh()._AUTHORITY)
            self.assertEqual(fast.canonical_bytes({'x': 1}, DUMPS), original({'x': 1}))

    def test_global_dependencies_and_integer_conversion_limit(self):
        # The native-health probe deliberately raises TypeError even for a
        # healthy constructor. A replaced Exception must not escape that guard
        # or suppress an otherwise successful original JSON operation.
        value = {'exception_guard': 1}
        expected = original(value)
        self.assertEqual(fast.canonical_bytes(value, DUMPS), expected)
        key = fast._key(value)
        self.assertEqual(fast._CACHE[key], expected)
        for before in (False, True):
            with self.subTest(exception_before_import=before), patch.object(builtins, 'Exception', LookupError):
                candidate = fresh() if before else fast
                self.assertFalse(candidate._eligible(DUMPS))
                if before:
                    self.assertIsNone(candidate._AUTHORITY)
                else:
                    # Captured authenticated base also survives replacement
                    # between the live guard and the deliberate native probe.
                    self.assertTrue(candidate._constructor_healthy())
                with patch.object(candidate, '_key', side_effect=AssertionError('changed exception base keyed')):
                    self.assertEqual(candidate.canonical_bytes(value, DUMPS), expected)
                    self.assertEqual(original(value), expected)
        self.assertTrue(fast._eligible(DUMPS))
        self.assertEqual(fast._CACHE[key], expected)
        def deny(*args): raise LookupError('live encoder builtin')
        with patch.dict(vars(json.encoder), {'isinstance': deny}):
            self.assertFalse(fast._eligible(DUMPS))
            self.assertEqual(outcome(lambda: fast.canonical_bytes([1], DUMPS)),
                             outcome(lambda: original([1])))
        with patch.object(fast._json, 'make_encoder', object()):
            self.assertFalse(fast._eligible(DUMPS))
            self.assertEqual(fast.canonical_bytes([1], DUMPS), original([1]))
        old = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(0)
            module = fresh(); value = 10 ** 1000
            self.assertEqual(module.canonical_bytes(value, DUMPS), original(value))
            sys.set_int_max_str_digits(640)
            self.assertFalse(module._eligible(DUMPS))
            self.assertEqual(outcome(lambda: module.canonical_bytes(value, DUMPS)),
                             outcome(lambda: original(value)))
        finally:
            sys.set_int_max_str_digits(old)
        with patch.object(sys, 'get_int_max_str_digits', side_effect=AssertionError('foreign getter')):
            self.assertFalse(fast._eligible(DUMPS))
            self.assertEqual(fast.canonical_bytes([1], DUMPS), original([1]))

    def test_surrogate_registry_and_recursion_changes_stay_live(self):
        value = {'surrogate': '\ud800'}
        old_handler = codecs.lookup_error('surrogatepass')
        events = []
        def foreign_handler(error):
            events.append(error); raise AssertionError('foreign key codec invoked')
        try:
            codecs.register_error('surrogatepass', foreign_handler)
            for module in (fast, fresh()):
                self.assertFalse(module._eligible(DUMPS))
                with patch.object(module, '_key', side_effect=AssertionError('changed codec keyed')):
                    self.assertEqual(module.canonical_bytes(value, DUMPS), original(value))
            self.assertEqual(events, [])
        finally:
            codecs.register_error('surrogatepass', old_handler)
        old_limit = sys.getrecursionlimit()
        value = 1
        for _ in range(500): value = [value]
        try:
            sys.setrecursionlimit(2500)
            module = fresh()
            expected = original(value)
            self.assertEqual(module.canonical_bytes(value, DUMPS), expected)
            sys.setrecursionlimit(400)
            self.assertFalse(module._eligible(DUMPS))
            expected_error = outcome(lambda: original(value))
            # Python3.12 has a separate C recursion guard: compare the actual
            # original result, rather than inventing a failure from this limit.
            self.assertEqual(outcome(lambda: module.canonical_bytes(value, DUMPS)), expected_error)
        finally:
            sys.setrecursionlimit(old_limit)

    def test_missing_optional_providers_fall_back_before_and_after_import(self):
        providers = ((fast._pickle, 'Pickler'), (fast._pickle, 'Unpickler'),
                     (fast.io, 'BytesIO'), (fast.marshal, 'dumps'),
                     (sys, 'get_int_max_str_digits'), (sys, 'getrecursionlimit'),
                     (fast._codecs, 'lookup_error'))
        for provider, name in providers:
            old = vars(provider)[name]
            for before in (False, True):
                try:
                    delattr(provider, name)
                    module = fresh() if before else fast
                    self.assertFalse(module._eligible(DUMPS))
                    with patch.object(module, '_key', side_effect=AssertionError('missing provider keyed')):
                        self.assertEqual(module.canonical_bytes({'x': 1}, DUMPS), b'{"x":1}')
                finally:
                    setattr(provider, name, old)

    def test_snapshot_prevents_durable_mutation_poisoning(self):
        value = {'nested': [1, False]}
        a = original(value); original_key = fast._key
        def mutate_after_key(item):
            key = original_key(item)
            item['nested'][0] = True
            return key
        with patch.object(fast, '_key', mutate_after_key):
            self.assertEqual(fast.canonical_bytes(value, DUMPS), original(value))
        self.assertEqual(fast._CACHE, {})
        b = original(value)
        self.assertNotEqual(a, b)
        self.assertEqual(fast.canonical_bytes(value, DUMPS), b)
        value['nested'][0] = 1
        self.assertEqual(fast.canonical_bytes(value, DUMPS), a)
        # The private snapshot preserves aliases and exact supported types.
        shared = [True, -0.0]
        snapshot = fast._snapshot(original_key({'a': shared, 'b': shared, 't': (1, 2)}))
        self.assertIs(snapshot['a'], snapshot['b'])
        self.assertIs(type(snapshot['t']), tuple)
        self.assertIs(type(snapshot['a'][0]), bool)
        self.assertEqual(original(snapshot), original({'a': shared, 'b': shared, 't': (1, 2)}))

    def test_literal_snapshot_rejects_external_object_opcodes_and_preserves_errors(self):
        for raw in (b'\x80\x05cbuiltins\nlen\n.', b'Pforeign\n.', b'\x80\x05\x97.'):
            with self.assertRaises((fast._NotKey, fast._pickle.UnpicklingError)):
                fast._snapshot(raw)
        with self.assertRaises(fast._NotKey):
            fast._snapshot(fast._key([1]) + b'trailing')
        for backing in (b'bytes', bytearray(b'mutable')):
            value = fast._pickle.PickleBuffer(backing)
            try:
                self.assertIsNone(fast._key(value), 'protocol4 refuses PickleBuffer')
                expected = outcome(lambda: original(value))
                self.assertEqual(expected[0], 'error')
                self.assertEqual(outcome(lambda: fast.canonical_bytes(value, DUMPS)), expected)
                self.assertEqual(fast._CACHE, {})
            finally:
                value.release()

    def test_dependency_change_during_key_keeps_original_provider_input(self):
        value = {'x': 1}; original_key = fast._key
        old = json.JSONEncoder.encode
        def changed(self, item):
            if item is not value: raise AssertionError('substituted provider saw snapshot')
            return '"changed-live"'
        def key_then_change(item):
            key = original_key(item)
            json.JSONEncoder.encode = changed
            return key
        try:
            with patch.object(fast, '_key', key_then_change):
                self.assertEqual(fast.canonical_bytes(value, DUMPS), b'"changed-live"')
        finally:
            json.JSONEncoder.encode = old
        self.assertEqual(fast._CACHE, {})

    def test_native_reference_has_exact_domain_and_readonly_members(self):
        self.assertIsNotNone(fast._REFERENCE)
        instance, call, markers = fast._REFERENCE
        maker = fast._AUTHORITY[4]
        fields = dict(fast._AUTHORITY[5])
        self.assertIs(type(instance), maker)
        self.assertIs(call, fields['__call__'])
        for name in ('markers', 'default', 'encoder', 'indent', 'key_separator',
                     'item_separator', 'sort_keys', 'skipkeys'):
            current = fast.MemberDescriptorType.__get__(fields[name], instance, maker)
            with self.subTest(name=name), self.assertRaises(AttributeError):
                fast.MemberDescriptorType.__set__(fields[name], instance, current)
        for value in (None, False, 1, 1.0, -0.0, 'text', (1, 2), {'x': [1, True]},
                      {None: 1}, {False: 1}, {1.5: 1}, {-(1 << 1999): 1}):
            self.assertTrue(fast._literal_domain(value))
            self.assertEqual(fast._reference_bytes(value), original(value))
            self.assertEqual(markers, {})
        cycle = []; cycle.append(cycle)
        for value in (cycle, math.nan, math.inf, b'x', bytearray(b'x'), {1},
                      frozenset({1}), {(): 1}, 1 << 2000, {1 << 2000: 1}):
            self.assertFalse(fast._literal_domain(value))
            self.assertIsNone(fast._reference_bytes(value))
            before = dict(fast._CACHE)
            self.assertEqual(outcome(lambda: fast.canonical_bytes(value, DUMPS)),
                             outcome(lambda: original(value)))
            self.assertEqual(fast._CACHE, before)
        with patch.object(fast, '_REFERENCE_ACTIVE', True):
            self.assertIsNone(fast._reference_bytes([1]))
            self.assertEqual(markers, {})

    def test_temporary_provider_changes_never_poison_native_reference(self):
        value = {'nested': [1]}
        expected = original(value)
        for target, name in ((json.JSONEncoder, 'encode'),
                             (fast._json.make_encoder, '__call__')):
            for error in (False, True):
                fast._CACHE.clear(); fast._CACHE_BYTES = 0
                old = vars(target)[name]
                original_eligible = fast._eligible
                calls = []
                def changed(*args):
                    setattr(target, name, old)
                    calls.append('actual temporary provider')
                    if error:
                        raise LookupError('actual temporary provider failure')
                    return '"temporary"' if name == 'encode' else ['"temporary"']
                checks = 0
                def eligible_then_change(dumps):
                    nonlocal checks
                    result = original_eligible(dumps)
                    checks += 1
                    if checks == 3:
                        setattr(target, name, changed)
                    return result
                try:
                    with patch.object(fast, '_eligible', eligible_then_change):
                        actual = outcome(lambda: fast.canonical_bytes(value, DUMPS))
                    self.assertEqual(actual, ('error', LookupError, 'actual temporary provider failure')
                                     if error else ('value', b'"temporary"'))
                    self.assertEqual(calls, ['actual temporary provider'])
                    self.assertEqual(fast._CACHE, {})
                finally:
                    setattr(target, name, old)
                self.assertEqual(fast.canonical_bytes(value, DUMPS), expected)
                self.assertEqual(fast._CACHE[fast._key(value)], expected)

    def test_temporary_provider_original_input_mutation_cannot_publish_wrong_key(self):
        value = {'nested': [1]}
        expected = original(value)
        old = json.JSONEncoder.encode
        original_eligible = fast._eligible
        checks = 0
        def changed(instance, actual):
            json.JSONEncoder.encode = old
            self.assertIs(actual, value)
            actual['nested'][0] = 2
            return old(instance, actual)
        def eligible_then_change(dumps):
            nonlocal checks
            result = original_eligible(dumps)
            checks += 1
            if checks == 3:
                json.JSONEncoder.encode = changed
            return result
        try:
            with patch.object(fast, '_eligible', eligible_then_change):
                self.assertEqual(fast.canonical_bytes(value, DUMPS), b'{"nested":[2]}')
            self.assertEqual(fast._CACHE, {})
            self.assertEqual(value, {'nested': [2]})
        finally:
            json.JSONEncoder.encode = old
        self.assertEqual(fast.canonical_bytes(value, DUMPS), original(value))
        value['nested'][0] = 1
        self.assertEqual(fast.canonical_bytes(value, DUMPS), expected)

    def test_reference_survives_late_constructor_and_digit_limit_changes(self):
        if self._native_slot_child():
            return
        old_new = vars(fast._json.make_encoder)['__new__']
        def changed_new(*args):
            raise AssertionError('reference used mutable constructor')
        old_limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            value = {1 << 1999: -(1 << 1999)}
            self.assertTrue(fast._literal_domain(value))
            self.assertEqual(fast._reference_bytes(value), original(value))
            self.assertFalse(fast._literal_domain(10 ** 1000))
            sys.set_int_max_str_digits(0)
            self.assertIsNone(fast._reference_bytes(10 ** 1000))
        finally:
            sys.set_int_max_str_digits(old_limit)
        value = {'x': 1}
        self.assertEqual(fast.canonical_bytes(value, DUMPS), b'{"x":1}')
        key = fast._key(value)
        with patch.object(fast._json.make_encoder, '__new__', changed_new):
            self.assertEqual(fast._reference_bytes({'x': 1}), b'{"x":1}')
            self.assertFalse(fast._constructor_healthy())
        self.assertIs(vars(fast._json.make_encoder)['__new__'], old_new)
        self.assertFalse(fast._eligible(DUMPS))
        expected = outcome(lambda: original(value))
        self.assertEqual(expected, ('error', TypeError,
                         '_json.Encoder.__new__(_json.Encoder) is not safe, use object.__new__()'))
        self.assertEqual(outcome(lambda: fast.canonical_bytes(value, DUMPS)), expected)
        self.assertEqual(fast._CACHE[key], b'{"x":1}')

    def test_bounds_and_deterministic_eviction(self):
        oversized = 'x' * (fast._LIMIT + 1)
        self.assertIsNone(fast._key(oversized))
        self.assertEqual(fast.canonical_bytes(oversized, DUMPS), original(oversized))
        self.assertEqual(fast._CACHE, {})
        for i in range(fast._ENTRIES + 1):
            fast.canonical_bytes({'key': i}, DUMPS)
        self.assertEqual(len(fast._CACHE), fast._ENTRIES)
        self.assertNotIn(fast._key({'key': 0}), fast._CACHE)
        fast._CACHE.clear(); fast._CACHE_BYTES = 0
        for i in range(40):
            fast.canonical_bytes({'i': i, 'value': 'x' * 450000}, DUMPS)
        self.assertLessEqual(fast._CACHE_BYTES, fast._TOTAL_LIMIT)
        self.assertLess(len(fast._CACHE), 40)
        self.assertEqual(fast._CACHE_BYTES, sum(len(k) + len(v) for k, v in fast._CACHE.items()))
        self.assertTrue(all(type(k) is bytes and type(v) is bytes and len(k) <= fast._LIMIT
                            and len(v) <= fast._LIMIT for k, v in fast._CACHE.items()))
        self.assertEqual((fast._LIMIT, fast._ENTRIES, fast._TOTAL_LIMIT), (1048576, 128, 33554432))

    def test_owner_hash_provider_and_original_json_options_remain_live(self):
        values = [{'x': 1}, {'x': 1}, {'x': True}]
        calls = []
        def sha(raw):
            calls.append(raw)
            return SimpleNamespace(hexdigest=lambda: 'actual-' + str(len(calls)))
        with patch.object(owner.inventory_digest.hashlib, 'sha256', sha):
            self.assertEqual([owner.digest(v) for v in values], ['actual-1', 'actual-2', 'actual-3'])
        self.assertEqual(calls, [original(v) for v in values])
        events = []
        def provider(value, **options):
            events.append(options)
            return DUMPS(value, **options)
        with patch.object(owner.json, 'dumps', provider):
            for value in values: owner.digest(value)
        self.assertEqual(events, [{'sort_keys': True, 'separators': (',', ':'), 'allow_nan': False}] * 3)


if __name__ == '__main__':
    unittest.main()
