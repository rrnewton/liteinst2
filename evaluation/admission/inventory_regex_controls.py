#!/usr/bin/env python3
"""Focused live-dispatch/value controls; outside recorder discovery."""
import builtins
import hashlib
from pathlib import Path
import re
from types import FunctionType
import unittest
from unittest.mock import patch

import inventory_regex as values
import core_97ab_inventory as inventory
from parsing import InvalidEvidence

FINDALL, COMPILE = re.findall, re._compile


class RegexValueControls(unittest.TestCase):
    def setUp(self):
        with values._LOCK:
            values._CACHE.clear()
            values._CACHE_BYTES = 0
        self.assertIsNotNone(values._AUTHORITY)

    def test_native_values_and_live_compile_on_every_hit(self):
        calls = []
        def live(pattern, flags):
            calls.append((pattern, flags))
            return COMPILE(pattern, flags)
        for pattern, text in ((r'(a)(b?)', 'a ab'), (r'a*', 'baa'),
                              (r'\w+', 'alpha beta'), (r'(?s)a.*b', 'a\nb')):
            expected = FINDALL(pattern, text)
            with patch.object(re, '_compile', live):
                self.assertEqual(values.with_findall(FINDALL, pattern, text), expected)
                self.assertEqual(values.with_findall(FINDALL, pattern, text), expected)
            self.assertEqual(calls[-2:], [(pattern, 0), (pattern, 0)])
        self.assertEqual(len(calls), 8)
        self.assertEqual(values.with_findall(FINDALL, 'a', 'b'), [])
        self.assertEqual(values.with_findall(FINDALL, 'b', 'b'), ['b'])

    def test_foreign_provider_is_called_once_and_not_compiled_by_helper(self):
        class Provider:
            __hash__ = None
            calls = 0
            def __eq__(self, other): raise AssertionError('provider comparison')
            def __call__(self, pattern, text):
                self.calls += 1
                if self.calls == 3: raise LookupError('third provider call')
                return [pattern, text, self.calls]
        provider = Provider()
        with patch.object(re, '_compile', side_effect=AssertionError('extra compile')):
            self.assertEqual(values.with_findall(provider, 'a', 'a'), ['a', 'a', 1])
            self.assertEqual(values.with_findall(provider, 'a', 'a'), ['a', 'a', 2])
            with self.assertRaises(LookupError) as error:
                values.with_findall(provider, 'a', 'a')
            self.assertEqual(str(error.exception), 'third provider call')
        self.assertEqual(provider.calls, 3)
        self.assertEqual(values._CACHE, {})

    def test_foreign_compile_result_and_errors_are_not_replayed(self):
        events = []
        class Compiled:
            calls = 0
            def findall(self, text):
                self.calls += 1; events.append(('findall', text, self.calls))
                if self.calls == 2: raise LookupError('second foreign result')
                return [text, self.calls]
        compiled = Compiled()
        def compile_now(pattern, flags):
            events.append(('compile', pattern, flags)); return compiled
        with patch.object(re, '_compile', compile_now):
            self.assertEqual(values.with_findall(FINDALL, 'a', 'a'), ['a', 1])
            with self.assertRaises(LookupError) as error:
                values.with_findall(FINDALL, 'a', 'a')
            self.assertEqual(str(error.exception), 'second foreign result')
        self.assertEqual(events, [('compile', 'a', 0), ('findall', 'a', 1),
                                  ('compile', 'a', 0), ('findall', 'a', 2)])
        with patch.object(re, '_compile', side_effect=LookupError('actual compiler')) as calls:
            for _ in range(2):
                with self.assertRaises(LookupError) as error:
                    values.with_findall(FINDALL, 'a', 'a')
                self.assertEqual(str(error.exception), 'actual compiler')
            self.assertEqual(calls.call_count, 2)
        self.assertEqual(values._CACHE, {})

    def test_provider_code_defaults_and_globals_keep_original_semantics(self):
        code, defaults, keywords = FINDALL.__code__, FINDALL.__defaults__, FINDALL.__kwdefaults__
        def replaced(pattern, string, flags=0): return [string, pattern, flags, 'changed code']
        try:
            FINDALL.__code__ = replaced.__code__
            self.assertEqual(values.with_findall(FINDALL, 'A', 'a'), FINDALL('A', 'a'))
            FINDALL.__code__ = code
            FINDALL.__defaults__ = (2,)
            self.assertEqual(values.with_findall(FINDALL, 'A', 'a'), ['a'])
            FINDALL.__defaults__ = (False,)
            observed = []
            def live(pattern, flags):
                observed.append(type(flags)); return COMPILE(pattern, flags)
            with patch.object(re, '_compile', live):
                self.assertEqual(values.with_findall(FINDALL, 'a', 'a'), ['a'])
            self.assertEqual(observed, [bool])
            FINDALL.__defaults__ = defaults; FINDALL.__kwdefaults__ = {}
            self.assertEqual(values.with_findall(FINDALL, 'a', 'a'), FINDALL('a', 'a'))
        finally:
            FINDALL.__code__, FINDALL.__defaults__, FINDALL.__kwdefaults__ = code, defaults, keywords
        self.assertEqual(values._CACHE, {})
        foreign = FunctionType(code, dict(FINDALL.__globals__, _compile=lambda p, f: COMPILE('z', f)),
                               'findall', defaults)
        self.assertEqual(values.with_findall(foreign, 'a', 'az'), ['z'])
        saved = re.__dict__.pop('_compile')
        try:
            with patch.dict(builtins.__dict__, {'_compile': lambda p, f: COMPILE('z', f)}):
                self.assertEqual(values.with_findall(FINDALL, 'a', 'az'), ['z'])
        finally:
            re.__dict__['_compile'] = saved
        self.assertEqual(values.with_findall(FINDALL, 'a', 'a'), ['a'])

    def test_foreign_text_pattern_and_native_pattern_metadata_bypass(self):
        events = []
        class Text(str):
            def __hash__(self): events.append('hash'); return super().__hash__()
            def __eq__(self, other): events.append('eq'); return super().__eq__(other)
        for pattern, text in ((Text('a'), 'a'), ('a', Text('a')), (b'a', b'a')):
            self.assertEqual(values.with_findall(FINDALL, pattern, text), FINDALL(pattern, text))
        self.assertEqual(values._CACHE, {})
        compiled = re._compiler.compile(Text('(a)'), 0)
        self.assertIs(type(compiled.pattern), Text)
        events.clear()
        with patch.object(re, '_compile', return_value=compiled) as calls:
            for _ in range(2):self.assertEqual(values.with_findall(FINDALL, 'ignored', 'a'), ['a'])
            self.assertEqual(calls.call_count, 2)
        self.assertEqual(events, [])
        self.assertEqual(values._CACHE, {})

    def test_native_pattern_identity_not_textual_pattern_equality(self):
        first, second = COMPILE('a', 0), COMPILE('b', 0)
        with patch.object(re, '_compile', side_effect=[first, second, first]) as calls:
            self.assertEqual(values.with_findall(FINDALL, 'actual input', 'ab'), ['a'])
            self.assertEqual(values.with_findall(FINDALL, 'actual input', 'ab'), ['b'])
            self.assertEqual(values.with_findall(FINDALL, 'actual input', 'ab'), ['a'])
            self.assertEqual(calls.call_count, 3)
        self.assertEqual(len(values._CACHE), 2)
        self.assertEqual({id(row[0]) for row in values._CACHE.values()}, {id(first), id(second)})

    def test_fresh_returned_containers_and_mutation_isolation(self):
        first = values.with_findall(FINDALL, '(a)(b)', 'ab ab')
        first[0] = ('changed', 'result'); first.append('extra')
        second = values.with_findall(FINDALL, '(a)(b)', 'ab ab')
        third = values.with_findall(FINDALL, '(a)(b)', 'ab ab')
        self.assertEqual(second, FINDALL('(a)(b)', 'ab ab'))
        self.assertEqual(third, second)
        self.assertIsNot(second, third)
        self.assertIsNot(second[0], third[0])

    def test_entry_byte_and_input_bounds_with_eviction(self):
        self.assertEqual((values._ENTRIES, values._TOTAL, values._LIMIT), (256, 32 << 20, 1 << 20))
        for i in range(257):
            text = 'value' + str(i)
            self.assertEqual(values.with_findall(FINDALL, 'never', text), [])
        self.assertEqual(len(values._CACHE), 256)
        self.assertFalse(any(key[1] == 'value0' for key in values._CACHE))
        with values._LOCK:
            values._CACHE.clear(); values._CACHE_BYTES = 0
        for i in range(70):
            self.assertEqual(values.with_findall(FINDALL, 'never', 'x' * (512 << 10) + str(i)), [])
        self.assertLess(len(values._CACHE), 70)
        self.assertLessEqual(values._CACHE_BYTES, values._TOTAL)
        self.assertEqual(values._CACHE_BYTES, sum(row[2] for row in values._CACHE.values()))
        before = (len(values._CACHE), values._CACHE_BYTES)
        self.assertEqual(values.with_findall(FINDALL, 'never', 'x' * ((1 << 20) + 1)), [])
        self.assertEqual((len(values._CACHE), values._CACHE_BYTES), before)

    def test_actual_source_reads_expected_hashes_and_method_rows_stay_live(self):
        raw = b'#[test]\nfn sample() {}\n'; other = b'#[test]\nfn different() {}\n'
        row = dict(all=['sample'], ignored=[], templates=[], macro_calls=[])
        metadata = dict(sources={'source': hashlib.sha256(raw).hexdigest()}, methods={'source': row},
            doctests={}, source_successor_abe7={'doctest_sources': {}}, module_chains={})
        def unchanged(path, data, error): return data
        with patch.object(inventory, 'DATA', metadata), \
                patch.object(inventory, 'source_before', unchanged), \
                patch.object(inventory, 'source_before_a8acec5', unchanged), \
                patch.object(inventory, 'source_before_79b34bc', unchanged), \
                patch.object(inventory, 'source_before_evaluation', unchanged), \
                patch.object(Path, 'read_bytes', side_effect=[raw, raw, other, other,
                    FileNotFoundError('gone')]) as reads:
            self.assertIsNone(inventory.require_sources('live_source'))
            row['all'] = ['wrong expectation']
            with self.assertRaisesRegex(InvalidEvidence, '^live_source$'):inventory.require_sources('live_source')
            row['all'] = ['sample']
            with self.assertRaisesRegex(InvalidEvidence, '^live_source$'):inventory.require_sources('live_source')
            metadata['sources']['source'] = hashlib.sha256(other).hexdigest()
            with self.assertRaisesRegex(InvalidEvidence, '^live_source$'):inventory.require_sources('live_source')
            with self.assertRaisesRegex(InvalidEvidence, '^live_source$'):inventory.require_sources('live_source')
            self.assertEqual(reads.call_count, 5)

    def test_caller_provider_lookup_precedes_live_decode(self):
        calls = []
        def substituted(pattern, text):
            calls.append((pattern, text)); return [('','wrong')]
        class Raw(bytes):
            def decode(self):
                re.findall = substituted
                return super().decode()
        raw = Raw(b'#[test]\nfn sample() {}\n')
        metadata = dict(sources={'source': hashlib.sha256(raw).hexdigest()},
            methods={'source':dict(all=['sample'],ignored=[],templates=[],macro_calls=[])},
            doctests={},source_successor_abe7={'doctest_sources':{}},module_chains={})
        def unchanged(path, data, error): return data
        try:
            with patch.object(inventory, 'DATA', metadata), \
                    patch.object(inventory, 'source_before', unchanged), \
                    patch.object(inventory, 'source_before_a8acec5', unchanged), \
                    patch.object(inventory, 'source_before_79b34bc', unchanged), \
                    patch.object(inventory, 'source_before_evaluation', unchanged), \
                    patch.object(Path, 'read_bytes', return_value=raw):
                self.assertIsNone(inventory.require_sources('provider_before_decode'))
                self.assertEqual(calls, [])
                with self.assertRaisesRegex(InvalidEvidence, '^provider_before_decode$'):
                    inventory.require_sources('provider_before_decode')
                self.assertEqual(len(calls), 1)
        finally:
            re.findall = FINDALL


if __name__ == '__main__':
    unittest.main(verbosity=2)
