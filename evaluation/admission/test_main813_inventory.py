"""Pure fixed-source and supplied-output controls for the main813 successor."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_813_inventory as main813
import core_5cda_inventory as main5c
import core_cc846_inventory as inventory
import precontext_native as protocol
import parsing
import run
from test_parsing import counts, header, summary

HEADER = '     Running tests/precontext_native.rs (target/debug/deps/precontext_native-0123456789abcdef)\n'


def terminal():
    # Independent supplied fixture, never output from a native process.
    return {'schema': 1, 'profile': 'precontext-v1', 'status': 'PASS',
            'scope': 'fixed-core-no-frontend-or-performance',
            'pairs': [dict(mode=mode, seed=seed, initial_selector=selected,
                ret_offset=27 if mode == 0 else 20, comparisons=18 if mode == 0 else 19,
                original_steps=100, candidate_steps=1000, callback_events=2 if selected else 0,
                observer_entries=2 if selected else 0, subject_returns=2, outer_returns=2,
                flip_acknowledgements=2, helper_joins=2)
                for seed in (0x1234567887654320, 0xfedcba9801234567)
                for mode in (0, 1) for selected in (False, True)],
            'malformed': [dict(tag=tag, sigill=True, local_ud2=True, original_heads=0,
                callback_events=0, observer_entries=0, subject_returns=0, outer_returns=0,
                cleanup='SIGKILL_REAP_ECHILD', steps=12) for tag in ('phase', 'choice')],
            'totals': dict(pairs=8, positive_children=16, malformed_children=2,
                comparisons=148, callback_events=8, subject_returns=16, outer_returns=16, helper_joins=16),
            'pure_controls': ['gate_displacement', 'scratch_layout', 'ack_fields',
                              'duplicate_ack_tail', 'slow_ret_log']}


def text(value=None):
    return HEADER + json.dumps(terminal() if value is None else value, separators=(',', ':')) + '\n'


class Main813InventoryTests(unittest.TestCase):
    def parse(self, raw, succeeded=True):
        return protocol.separate(raw, [protocol.specification()], succeeded)

    def test_exact_inventory_sources_docs_and_historical_denominators(self):
        # Cache only pure bytes-to-digest work; expectations and reads stay live.
        digest = main813.inventory_digest.hexdigest
        cache = main813.inventory_digest._hexdigest
        original_sha256 = hashlib.sha256
        cache.cache_clear()
        for raw in (b'', b'inventory', b'\x00\xff'):
            expected = original_sha256(raw).hexdigest()
            self.assertEqual(digest(raw), expected)
            self.assertEqual(digest(raw), expected)
            self.assertEqual(digest(raw + b'!'), original_sha256(raw + b'!').hexdigest())
        self.assertEqual(cache.cache_info().hits, 3)
        mutable = bytearray(b'first')
        before = cache.cache_info()
        self.assertEqual(digest(mutable), original_sha256(mutable).hexdigest())
        mutable[0] = ord('F')
        self.assertEqual(digest(mutable), original_sha256(mutable).hexdigest())
        self.assertEqual(digest(memoryview(mutable)), original_sha256(mutable).hexdigest())
        class BytesSubclass(bytes):
            pass
        self.assertEqual(digest(BytesSubclass(b'inventory')),
                         original_sha256(b'inventory').hexdigest())
        self.assertEqual(cache.cache_info(), before)
        for invalid in (None, 1, 'text', [1]):
            with self.assertRaises(TypeError):
                digest(invalid)
        with patch.object(hashlib, 'sha256', side_effect=[original_sha256(b'a'),
                original_sha256(b'b'), ValueError('live hash failure')]) as changed_hash:
            self.assertEqual(digest(b'inventory'), original_sha256(b'a').hexdigest())
            self.assertEqual(digest(b'inventory'), original_sha256(b'b').hexdigest())
            with self.assertRaisesRegex(ValueError, '^live hash failure$'):
                digest(b'inventory')
            self.assertEqual(changed_hash.call_count, 3)
        class UnhashableHash:
            __hash__ = None
            def __call__(self, raw):
                return original_sha256(raw + b'changed')
        with patch.object(hashlib, 'sha256', UnhashableHash()):
            self.assertEqual(digest(b'inventory'), original_sha256(b'inventorychanged').hexdigest())
        self.assertEqual(digest(b'inventory'), original_sha256(b'inventory').hexdigest())
        # A replacement present before importing the helper is never trusted.
        import importlib.util
        spec = importlib.util.spec_from_file_location('_inventory_digest_preimport',
            main813.inventory_digest.__file__)
        fresh = importlib.util.module_from_spec(spec)
        with patch.object(hashlib, 'sha256', side_effect=[original_sha256(b'a'),
                original_sha256(b'b'), ValueError('preimport hash failure')]) as changed_hash:
            spec.loader.exec_module(fresh)
            self.assertEqual(fresh.hexdigest(b'inventory'), original_sha256(b'a').hexdigest())
            self.assertEqual(fresh.hexdigest(b'inventory'), original_sha256(b'b').hexdigest())
            with self.assertRaisesRegex(ValueError, '^preimport hash failure$'):
                fresh.hexdigest(b'inventory')
            self.assertEqual(changed_hash.call_count, 3)
        self.assertEqual(fresh._hexdigest.cache_info().currsize, 0)
        self.assertEqual(fresh.hexdigest(b'inventory'), original_sha256(b'inventory').hexdigest())
        self.assertEqual(fresh.hexdigest(b'inventory'), original_sha256(b'inventory').hexdigest())
        with patch.object(hashlib, 'sha256', side_effect=[original_sha256(b'c'),
                original_sha256(b'd'), ValueError('warm hash failure')]) as changed_hash:
            self.assertEqual(fresh.hexdigest(b'inventory'), original_sha256(b'c').hexdigest())
            self.assertEqual(fresh.hexdigest(b'inventory'), original_sha256(b'd').hexdigest())
            with self.assertRaisesRegex(ValueError, '^warm hash failure$'):
                fresh.hexdigest(b'inventory')
            self.assertEqual(changed_hash.call_count, 3)
        self.assertEqual(fresh.hexdigest(b'inventory'), original_sha256(b'inventory').hexdigest())
        value = {'nested': [1]}
        first = main813.digest(value)
        value['nested'][0] = 2
        self.assertNotEqual(main813.digest(value), first)
        expected = original_sha256(json.dumps(value, sort_keys=True,
            separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        self.assertEqual(main813.digest(value), expected)
        with patch.object(main813.json, 'dumps', side_effect=['1', '2']) as serialize:
            self.assertEqual(main813.digest(value), original_sha256(b'1').hexdigest())
            self.assertEqual(main813.digest(value), original_sha256(b'2').hexdigest())
            self.assertEqual(serialize.call_count, 2)
        with self.assertRaises(ValueError):
            main813.digest(float('nan'))
        with self.assertRaises(TypeError):
            main813.digest(object())
        path, row = next(iter(main813.MAIN83B['projections'].items()))
        raw = (main813.ROOT / path).read_bytes()
        for _ in range(2):
            restored = main813.source_before_83b(path, raw, 'digest_control')
            self.assertEqual(original_sha256(restored).hexdigest(), row['previous_sha256'])
        for name in ('current_sha256', 'previous_sha256'):
            with patch.dict(row, {name: '0' * 64}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^digest_control$'):
                    main813.source_before_83b(path, raw, 'digest_control')
        for changed in (raw + b'\n', raw[:-1], restored):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^digest_control$'):
                main813.source_before_83b(path, changed, 'digest_control')
        for i in range(513):
            digest(str(i).encode())
        self.assertEqual(cache.cache_info().currsize, 512)
        cache.cache_clear()

        # Only immutable bounded splice results are reused; validation is live.
        splice = main813.inventory_splice.splice
        splice_cache = main813.inventory_splice._splice
        splice_cache.cache_clear()
        for args, expected in (((b'abcdef', 1, 3, 'XY'), b'aXYdef'),
                               ((b'abc', 0, 0, 'X'), b'Xabc'),
                               ((b'abc', 0, 3, ''), b'')):
            self.assertEqual(splice(*args), expected)
            self.assertEqual(splice(*args), expected)
        self.assertEqual(splice_cache.cache_info().hits, 3)
        self.assertEqual(splice(b'abcdeg', 1, 3, 'XY'), b'aXYdeg')
        self.assertEqual(splice(b'abcdef', 2, 3, 'XY'), b'abXYdef')
        self.assertEqual(splice(b'abcdef', 1, 4, 'XY'), b'aXYef')
        self.assertEqual(splice(b'abcdef', 1, 3, 'Z'), b'aZdef')
        uncached = splice_cache.cache_info()
        for args in ((b'abc', True, 2, 'X'), (b'abc', -1, 2, 'X'),
                     (b'abc', 2, 1, 'X'), (b'abc', 0, 9, 'X'),
                     (b'abc', 1, 2, '\u00e9'), (bytearray(b'abc'), 1, 2, 'X')):
            data, start, end, old = args
            self.assertEqual(splice(*args), data[:start] + old.encode() + data[end:])
        for _ in range(2):
            with self.assertRaises(UnicodeEncodeError):
                splice(b'abc', 1, 2, '\ud800')
        large = b'x' * 65537
        self.assertEqual(splice(large, 0, 0, ''), large)
        self.assertEqual(splice(b'a', 0, 1, 'x' * 26215), b'x' * 26215)
        self.assertEqual(splice_cache.cache_info(), uncached)
        events = []
        class SpliceBuffer:
            def __getitem__(self, key):
                events.append(('slice', key.start, key.stop))
                return b'abc'[key]
        class SpliceText:
            def encode(self):
                events.append('encode')
                return b'X'
        self.assertEqual(splice(SpliceBuffer(), 1, 2, SpliceText()), b'aXc')
        self.assertEqual(events, [('slice', None, 1), 'encode', ('slice', 2, None)])
        events.clear()
        with self.assertRaises(TypeError):
            splice(SpliceBuffer(), 1.5, 2, SpliceText())
        self.assertEqual(events, [('slice', None, 1.5)])
        class SpliceBytes(bytes):
            def __getitem__(self, key):
                events.append('subclass slice')
                return super().__getitem__(key)
        class SpliceString(str):
            def encode(self):
                events.append('subclass encode')
                if len(events) > 2:
                    raise ValueError('live splice encode')
                return b'Z'
        events.clear()
        self.assertEqual(splice(SpliceBytes(b'abc'), 1, 2, SpliceString('X')), b'aZc')
        self.assertEqual(events, ['subclass slice', 'subclass encode', 'subclass slice'])
        with self.assertRaisesRegex(ValueError, '^live splice encode$'):
            splice(SpliceBytes(b'abc'), 1, 2, SpliceString('X'))
        self.assertEqual(events[-2:], ['subclass slice', 'subclass encode'])
        self.assertEqual(splice_cache.cache_info(), uncached)
        # Mutation between live bounds checks remains visible to reversed(rows).
        edits = [[1, 2, 'B'], [4, 5, 'E']]
        row = {'current_sha256': hashlib.sha256(b'abcdef').hexdigest(),
               'previous_sha256': hashlib.sha256(b'aQcdEf').hexdigest(), 'edits': edits}
        original_require = main813.require
        calls = []
        def during_bounds(ok, error):
            calls.append(ok)
            if len(calls) == 2:
                edits[0][2] = 'Q'
            original_require(ok, error)
        self.assertEqual(splice(b'abcdef', 4, 5, 'E'), b'abcdEf')
        self.assertEqual(splice(b'abcdEf', 1, 2, 'B'), b'aBcdEf')
        with patch.dict(main813.MAIN2754['projections'], {'splice_control': row}):
            with patch.object(main813, 'require', during_bounds):
                self.assertEqual(main813.source_before_2754('splice_control', b'abcdef', 'splice_live'), b'aQcdEf')
            self.assertEqual(calls, [True, True, True, True])
            for key in ('current_sha256', 'previous_sha256'):
                with patch.dict(row, {key: '0' * 64}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^splice_live$'):
                        main813.source_before_2754('splice_control', b'abcdef', 'splice_live')
            with patch.dict(row, {'edits': [[1, 7, 'Q']]}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^splice_live$'):
                    main813.source_before_2754('splice_control', b'abcdef', 'splice_live')
            edits[0][2] = 'B'
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^splice_live$'):
                main813.source_before_2754('splice_control', b'abcdef', 'splice_live')
        splice_cache.cache_clear()
        for i in range(2049):
            splice(b'abc', 1, 2, str(i))
        self.assertEqual(splice_cache.cache_info().currsize, 2048)
        self.assertEqual(splice_cache.cache_parameters(), {'maxsize': 2048, 'typed': True})
        splice_cache.cache_clear()

        # Fresh exact trees are copied; unsupported copy semantics stay live.
        plain = main813.inventory_copy
        original_copy = copy.deepcopy
        copy_value = {'a': [1, True, None, {'b': 'text'}], 'b': {'c': [2.5]}}
        copy_first = plain.deepcopy(copy_value)
        copy_second = plain.deepcopy(copy_value)
        self.assertEqual(copy_first, original_copy(copy_value))
        self.assertEqual(copy_second, copy_value)
        for copy_path in ((), ('a',), ('a', 3), ('b',), ('b', 'c')):
            copy_input, copy_one, copy_two = copy_value, copy_first, copy_second
            for copy_key in copy_path:
                copy_input, copy_one, copy_two = (copy_input[copy_key],
                                                copy_one[copy_key], copy_two[copy_key])
            self.assertIsNot(copy_one, copy_input)
            self.assertIsNot(copy_two, copy_input)
            self.assertIsNot(copy_one, copy_two)
        copy_first['a'][3]['b'] = 'changed'
        self.assertEqual(copy_value['a'][3]['b'], 'text')
        self.assertEqual(copy_second['a'][3]['b'], 'text')
        copy_value['b']['c'].append(9)
        self.assertEqual(copy_second['b']['c'], [2.5])
        for copy_scalar in (None, True, False, 10**100, 'text', -0.0,
                            float('inf'), float('-inf'), float('nan')):
            self.assertIs(plain.deepcopy(copy_scalar), copy_scalar)
        for copy_shared in ([], {}):
            copy_alias = plain.deepcopy([copy_shared, copy_shared])
            self.assertIs(copy_alias[0], copy_alias[1])
            self.assertIsNot(copy_alias[0], copy_shared)
        copy_cycle = []; copy_cycle.append(copy_cycle)
        copy_result = plain.deepcopy(copy_cycle)
        self.assertIs(copy_result[0], copy_result)
        self.assertIsNot(copy_result, copy_cycle)
        copy_cycle = {}; copy_cycle['self'] = copy_cycle
        copy_result = plain.deepcopy(copy_cycle)
        self.assertIs(copy_result['self'], copy_result)
        copy_cycle = []; copy_cycle.append({'self': copy_cycle})
        copy_result = plain.deepcopy(copy_cycle)
        self.assertIs(copy_result[0]['self'], copy_result)
        copy_deep = []
        for _ in range(40):
            copy_deep = [copy_deep]
        self.assertEqual(plain.deepcopy(copy_deep), original_copy(copy_deep))
        for copy_base in (list, dict, str, int, float):
            CopySubclass = type('CopySubclass', (copy_base,), {})
            copy_special = CopySubclass()
            self.assertIs(type(plain.deepcopy(copy_special)), CopySubclass)
        for copy_special in (([1],), b'bytes', {1, 2}, {1: [2]}, {(1, 2): [3]}):
            self.assertEqual(plain.deepcopy(copy_special), original_copy(copy_special))
            self.assertIs(type(plain.deepcopy(copy_special)), type(copy_special))
        copy_events = []
        class CopyMeta(type):
            __hash__ = type.__hash__
            def __eq__(cls, other):
                raise AssertionError('speculative type equality')
        class CopyCustom(metaclass=CopyMeta):
            def __init__(self, label, fail=False):
                self.label, self.fail = label, fail
            def __deepcopy__(self, memo):
                copy_events.append(self.label)
                self_outer.assertIs(type(memo), dict)
                if self.fail:
                    raise ValueError('live custom copy failure')
                return ('copied', self.label)
        self_outer = self
        copy_input = {CopyCustom('key'): CopyCustom('value')}
        copy_expected = original_copy(copy_input)
        self.assertEqual(copy_events, ['value', 'key'])
        copy_events.clear()
        self.assertEqual(plain.deepcopy(copy_input), copy_expected)
        self.assertEqual(copy_events, ['value', 'key'])
        copy_events.clear()
        with self.assertRaisesRegex(ValueError, '^live custom copy failure$'):
            plain.deepcopy({'first': [1], 'last': CopyCustom('failure', True)})
        self.assertEqual(copy_events, ['failure'])
        copy_a, copy_b = object(), object()
        for copy_import_first in (False, True):
            copy_spec = importlib.util.spec_from_file_location('_inventory_copy_control',
                plain.__file__)
            copy_fresh = importlib.util.module_from_spec(copy_spec)
            if copy_import_first:
                copy_spec.loader.exec_module(copy_fresh)
            with patch.object(copy, 'deepcopy', side_effect=[copy_a, copy_b,
                    ValueError('live constructor failure')]) as copy_changed:
                if not copy_import_first:
                    copy_spec.loader.exec_module(copy_fresh)
                self.assertIs(copy_fresh.deepcopy(copy_value), copy_a)
                self.assertIs(copy_fresh.deepcopy(copy_value), copy_b)
                with self.assertRaisesRegex(ValueError, '^live constructor failure$'):
                    copy_fresh.deepcopy(copy_value)
                self.assertEqual(copy_changed.call_count, 3)
            self.assertEqual(copy_fresh.deepcopy(copy_value), original_copy(copy_value))
        for copy_import_first in (False, True):
            copy_spec = importlib.util.spec_from_file_location('_inventory_copy_dispatch',
                plain.__file__)
            copy_fresh = importlib.util.module_from_spec(copy_spec)
            if copy_import_first:
                copy_spec.loader.exec_module(copy_fresh)
            copy_events.clear()
            def copy_dispatch(value, memo):
                copy_events.append(value)
                if len(copy_events) == 3:
                    raise ValueError('live dispatch failure')
                return len(copy_events)
            with patch.dict(copy._deepcopy_dispatch, {list: copy_dispatch}):
                if not copy_import_first:
                    copy_spec.loader.exec_module(copy_fresh)
                self.assertEqual(copy_fresh.deepcopy([]), 1)
                self.assertEqual(copy_fresh.deepcopy([]), 2)
                with self.assertRaisesRegex(ValueError, '^live dispatch failure$'):
                    copy_fresh.deepcopy([])
            self.assertEqual(len(copy_events), 3)
        copy_original_defaults = original_copy.__defaults__
        for copy_import_first in (False, True):
            copy_spec = importlib.util.spec_from_file_location('_inventory_copy_defaults',
                plain.__file__)
            copy_fresh = importlib.util.module_from_spec(copy_spec)
            if copy_import_first:
                copy_spec.loader.exec_module(copy_fresh)
            try:
                original_copy.__defaults__ = ({}, [])
                if not copy_import_first:
                    copy_spec.loader.exec_module(copy_fresh)
                copy_memo_input = {'a': [1]}
                copy_one = copy_fresh.deepcopy(copy_memo_input)
                copy_memo_input['a'].append(2)
                self.assertIs(copy_fresh.deepcopy(copy_memo_input), copy_one)
                self.assertEqual(copy_one, {'a': [1]})
            finally:
                original_copy.__defaults__ = copy_original_defaults
        copy_spec = importlib.util.spec_from_file_location('_inventory_copy_unknown', plain.__file__)
        copy_fresh = importlib.util.module_from_spec(copy_spec)
        with patch.object(copy, '_deepcopy_list', None):
            copy_spec.loader.exec_module(copy_fresh)
            self.assertEqual(copy_fresh._AUTHORITY, ())
            self.assertEqual(copy_fresh.deepcopy(copy_value), original_copy(copy_value))
        with patch.object(plain, '_AUTHORITY', ()):
            self.assertEqual(plain.deepcopy(copy_value), original_copy(copy_value))
        with patch.object(copy, 'id', lambda value: 1, create=True):
            self.assertFalse(plain._eligible())
        self.assertEqual(plain.deepcopy(copy_value), original_copy(copy_value))

        declared = json.loads(Path(__file__).with_name('corpus.json').read_bytes())
        inventory.require_current(declared)
        # The early current-blob rejection never grants historical acceptance.
        with patch.object(inventory, 'before_cc846',
                          side_effect=RuntimeError('original history reached')) as history:
            with self.assertRaisesRegex(RuntimeError, '^original history reached$'):
                inventory.require_current(declared)
            self.assertEqual(history.call_args_list, [unittest.mock.call(declared)])
        with patch.object(main813, 'precheck_current_sources') as precheck:
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current({})
            self.assertEqual(precheck.call_count, 0)
        precheck_path = 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/session/tests.rs'
        precheck_target = main813.ROOT / precheck_path
        precheck_read = Path.read_bytes
        with patch.dict(main813.MAIN2754['sources'], {precheck_path: '0' * 64}):
            with patch.object(inventory, 'before_cc846') as history:
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_source_inventory_differs$'):
                    inventory.require_current(declared)
                self.assertEqual(history.call_count, 0)
        # A changed/missing first read refuses early; the same change after a
        # valid precheck is still rejected by the untouched original traversal.
        for late in (False, True):
            for missing in (False, True):
                precheck_reads = []
                def precheck_changed(candidate):
                    if candidate == precheck_target:
                        precheck_reads.append(candidate)
                        if not late or len(precheck_reads) > 1:
                            if missing:
                                raise OSError('PRIVATE_PRECHECK_SENTINEL')
                            return precheck_read(candidate) + b'\n'
                    return precheck_read(candidate)
                with patch.object(Path, 'read_bytes', precheck_changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_source_inventory_differs$'):
                        inventory.require_current(declared)
                self.assertEqual(len(precheck_reads), 2 if late else 1)
        # Unsupported metadata cannot run custom callbacks during the precheck.
        class PrecheckMap(dict):
            def items(self):
                raise RuntimeError('custom map reached')
        class PrecheckText(str):
            def __hash__(self):
                raise RuntimeError('custom key reached')
        class PrecheckKey(str):
            __hash__ = str.__hash__
            def __eq__(self, other):
                raise RuntimeError('custom key equality reached')
        for sources in (PrecheckMap(), {precheck_path: PrecheckText('hash')},
                        {PrecheckKey(precheck_path): '0' * 64}, None):
            with patch.dict(main813.MAIN2754, {'sources': sources}):
                with patch.object(Path, 'read_bytes', side_effect=AssertionError('early read')):
                    self.assertIsNone(main813.precheck_current_sources('precheck_control'))
        with patch.object(main813, 'MAIN2754', PrecheckMap()):
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('early read')):
                self.assertIsNone(main813.precheck_current_sources('precheck_control'))
            with patch.object(inventory, 'before_cc846',
                              side_effect=RuntimeError('fallback history reached')):
                with self.assertRaisesRegex(RuntimeError, '^fallback history reached$'):
                    inventory.require_current(declared)
        actual = plain.deepcopy(declared)
        declared = main813.before_e797(declared)
        live = plain.deepcopy(declared)
        declared = main813.before_c1(declared)
        newest = plain.deepcopy(declared)
        declared = main813.before_c0(declared)
        latest = plain.deepcopy(declared)
        declared = main813.before_690(declared)
        self.assertEqual(declared['recorder_tests'], 350)
        for cohort, wanted in [('workspace_tests', (101, 2678, 11)), ('serial_launch', (27, 1039, 0))]:
            rows = declared['harness_test_counts'][cohort]
            self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                              sum(x['ignored'] for x in rows.values())), wanted)
        self.assertEqual(sum(len(x['all']) for x in main813.DATA['methods'].values()), 54)
        self.assertEqual(sum(len(x['ignored']) for x in main813.DATA['methods'].values()), 2)
        self.assertEqual(sum(len(x) for p, x in main813.DATA['doctests'].items() if p.startswith('src/')), 8)
        self.assertEqual(sum(len(x) for p, x in main813.DATA['doctests'].items() if p.startswith('tools/')), 20)
        previous = main813.before_current(declared)
        self.assertEqual(main813.digest(previous), main5c.CURRENT)
        self.assertEqual(previous['harness_test_counts']['workspace_tests']['doc/rapid_profiler'], counts(15))
        self.assertEqual(len(previous['native_validation_fixtures']), 110)
        self.assertEqual(previous['native_validation_fixtures'], declared['native_validation_fixtures'])
        self.assertEqual(previous['backing_cleanup_harnesses'], declared['backing_cleanup_harnesses'])
        identities = main5c.python_identities(Path(__file__).parent)
        self.assertEqual(len(identities), 350)
        self.assertEqual(len(main813.peel_python(identities)), 345)
        self.assertEqual(len(inventory.peel_python(identities)), 330)
        for key in declared:
            changed = plain.deepcopy(declared); changed[key] = None
            with self.subTest(field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_current(changed)
        for old in (previous, main5c.before_current(previous)):
            with self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(old)
        read_bytes = Path.read_bytes
        for path in main813.DATA['sources']:
            mutation_target = main813.ROOT / path
            def changed(candidate):
                raw = read_bytes(candidate)
                return raw + b'\n' if candidate == mutation_target else raw
            with self.subTest(path=path), patch.object(Path, 'read_bytes', changed):
                with self.assertRaises(parsing.InvalidEvidence):
                    main813.before_current(declared)
        for path, row in main813.DATA['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before(path, bad, 'changed')

        # The live successor must be complete before any historical projection.
        self.assertEqual(latest['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'], counts(304, 7))
        rows = latest['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (101, 2694, 11))
        self.assertEqual(sum(len(x['all']) for x in main813.MAIN690['methods'].values()), 16)
        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN690['methods'].values()), 0)
        self.assertEqual(main813.digest(main813.before_690(latest)), main813.CURRENT)
        latest = actual  # Later live-source mutations must reach the current guard.
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(declared)
        for key in latest:
            changed = plain.deepcopy(latest); changed[key] = None
            with self.subTest(main690_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_690(changed)
        current_count = latest['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']['tests']
        for value in (288, 303, 305, True, 304.0):
            self.assertTrue(type(value) is not int or value != current_count)
            changed = plain.deepcopy(latest)
            changed['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']['tests'] = value
            with self.subTest(main690_count=value), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for path in main813.MAIN690['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main690_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(latest)
        for path, row in main813.MAIN690['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_690(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main690_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_690(path, bad, 'changed')

        self.assertEqual(main813.digest(main813.before_c0(newest)), main813.CURRENT690)
        rows = newest['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (101, 2716, 11))
        self.assertEqual(sum(len(x['all']) for x in main813.MAINC0['methods'].values()), 22)
        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINC0['methods'].values()), 0)
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_c0(newest))
        live = actual
        for name, change in main813.MAINC0['workspace_changes'].items():
            self.assertEqual(rows[name], change['current'])
            current_count = live['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (change['previous']['tests'], current_count - 1,
                          current_count + 1, True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(live)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(mainc0_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
        for key in newest:
            changed = plain.deepcopy(newest); changed[key] = None
            with self.subTest(mainc0_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_c0(changed)
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(newest)
        newest = actual  # Source mutation controls authenticate the actual current catalog.
        for path in main813.MAINC0['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainc0_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(newest)
        for path, row in main813.MAINC0['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_c0(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(mainc0_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_c0(path, bad, 'changed')

        live = plain.deepcopy(main813.before_e797(actual))
        self.assertEqual(main813.digest(main813.before_c1(live)), main813.CURRENTC0)
        rows = live['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (101, 2752, 11))
        self.assertEqual(sum(len(x['all']) for x in main813.MAINC1['methods'].values()), 31)
        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINC1['methods'].values()), 0)
        self.assertEqual(sum(len(main813.MAINC1['methods'][p]['all']) * len(v)
                             for p, v in main813.MAINC1['instances'].items()), 36)
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_c1(live))
        live = actual
        for name, change in main813.MAINC1['workspace_changes'].items():
            self.assertEqual(rows[name], change['current'])
            current_count = live['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (change['previous']['tests'], current_count - 1,
                          current_count + 1, True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(live)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(mainc1_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
        for key in live:
            changed = plain.deepcopy(live); changed[key] = None
            with self.subTest(mainc1_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_c1(changed)
        for path in main813.MAINC1['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainc1_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(live)
        for path, row in main813.MAINC1['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_c1(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(mainc1_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_c1(path, bad, 'changed')

        self.assertEqual(main813.digest(main813.before_e797(actual)), main813.CURRENTC1)
        current_rows = main813.before_f0ef(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2845, 12))
        self.assertEqual(sum(len(x['all']) for x in main813.MAINE797['methods'].values()), 64)
        self.assertEqual(sum(len(main813.MAINE797['methods'][p]['all']) * len(v)
                             for p, v in main813.MAINE797['instances'].items()), 75)
        self.assertEqual(sum(len(x) for x in main813.MAINE797['doctests'].values()), 18)
        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINE797['methods'].values()), 1)
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_e797(actual))
        for name, change in main813.MAINE797['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(maine797_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(maine797_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(maine797_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_e797(changed)
        for path in main813.MAINE797['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(maine797_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAINE797['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_e797(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(maine797_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_e797(path, bad, 'changed')

        self.assertEqual(main813.digest(main813.before_f0ef(actual)), main813.CURRENTE797)
        current_rows = main813.before_7cdc(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2854, 12))
        self.assertEqual(sum(len(x['all']) for x in main813.MAINF0EF['methods'].values()), 9)
        self.assertEqual(sum(len(main813.MAINF0EF['methods'][p]['all']) * len(v)
                             for p, v in main813.MAINF0EF['instances'].items()), 9)
        self.assertEqual(main813.MAINF0EF['declared_delta'],
                         {'rust_tests': 9, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_f0ef(actual))
        for name, change in main813.MAINF0EF['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(mainf0ef_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(mainf0ef_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(mainf0ef_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_f0ef(changed)
        for path in main813.MAINF0EF['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainf0ef_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAINF0EF['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_f0ef(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(mainf0ef_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_f0ef(path, bad, 'changed')

        self.assertEqual(main813.digest(main813.before_7cdc(actual)), main813.CURRENTF0EF)
        current_rows = main813.before_43d7(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2864, 12))
        self.assertEqual(sum(len(x['all']) for x in main813.MAIN7CDC['methods'].values()), 10)
        self.assertEqual(sum(len(main813.MAIN7CDC['methods'][p]['all']) * len(v)
                             for p, v in main813.MAIN7CDC['instances'].items()), 10)
        self.assertEqual(main813.MAIN7CDC['declared_delta'],
                         {'rust_tests': 10, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_7cdc(actual))
        for name, change in main813.MAIN7CDC['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main7cdc_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main7cdc_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main7cdc_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_7cdc(changed)
        for path in main813.MAIN7CDC['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main7cdc_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN7CDC['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_7cdc(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main7cdc_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_7cdc(path, bad, 'changed')

        self.assertEqual(main813.digest(main813.before_43d7(actual)), main813.CURRENT7CDC)
        current_rows = main813.before_0df8(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2910, 32))
        self.assertEqual(sum(len(x) for x in main813.MAIN43D7['added_methods'].values()), 39)
        self.assertEqual(sum(len(main813.MAIN43D7['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN43D7['instances'].items()), 39)
        self.assertEqual(main813.MAIN43D7['declared_delta'],
                         {'rust_tests': 39, 'doctests': 7, 'ignored': 20, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_43d7(actual))
        for name, change in main813.MAIN43D7['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main43d7_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main43d7_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main43d7_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_43d7(changed)
        for path in main813.MAIN43D7['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main43d7_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN43D7['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_43d7(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main43d7_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_43d7(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN43D7['doctests'].values()), 7)
        metadata = main813.MAIN43D7['python_metadata']
        self.assertEqual(len(metadata['assignments']['CALIBRATION_TESTS']), 94)
        self.assertEqual(len(metadata['previous_calibration_tests']), 82)
        self.assertEqual(len(metadata['added_calibration_tests']), 12)
        self.assertTrue(all(metadata['assignments']['CALIBRATION_TESTS'][k] == v
                            for k, v in metadata['previous_calibration_tests'].items()))

        self.assertEqual(main813.digest(main813.before_0df8(actual)), main813.CURRENT43D7)
        current_rows = main813.before_0a8(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2938, 33))
        self.assertEqual(sum(len(x) for x in main813.MAIN0DF8['added_methods'].values()), 28)
        self.assertEqual(sum(len(main813.MAIN0DF8['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN0DF8['instances'].items()), 28)
        self.assertEqual(main813.MAIN0DF8['declared_delta'],
                         {'rust_tests': 28, 'doctests': 0, 'ignored': 1, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_0df8(actual))
        for name, change in main813.MAIN0DF8['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main0df8_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main0df8_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main0df8_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_0df8(changed)
        for path in main813.MAIN0DF8['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main0df8_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN0DF8['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_0df8(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main0df8_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_0df8(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN0DF8['doctests'].values()), 0)
        metadata = main813.MAIN0DF8['python_metadata']['assignments']
        self.assertEqual((len(metadata['ADMISSION']), len(metadata['STATE_CONTROLS']),
                          len(metadata['WORK_CONTROLS'])), (24, 4, 7))

        self.assertEqual(main813.digest(main813.before_0a8(actual)), main813.CURRENT0DF8)
        current_rows = main813.before_09fe(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2964, 33))
        self.assertEqual(sum(len(x) for x in main813.MAIN0A8['added_methods'].values()), 19)
        self.assertEqual(sum(len(main813.MAIN0A8['methods'][p]['all']) * len(v)
                             for p, v in main813.MAIN0A8['instances'].items()), 26)
        self.assertEqual(main813.MAIN0A8['declared_delta'],
                         {'rust_tests': 26, 'rust_declarations': 19, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_0a8(actual))
        for name, change in main813.MAIN0A8['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main0a8_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main0a8_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main0a8_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_0a8(changed)
        for path in main813.MAIN0A8['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main0a8_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN0A8['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_0a8(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main0a8_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_0a8(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN0A8['doctests'].values()), 0)

        self.assertEqual(main813.digest(main813.before_09fe(actual)), main813.CURRENT0A8)
        current_rows = main813.before_727(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2990, 33))
        self.assertEqual(sum(len(x) for x in main813.MAIN09FE['added_methods'].values()), 24)
        self.assertEqual(sum(len(main813.MAIN09FE['methods'][p]['all']) * len(v)
                             for p, v in main813.MAIN09FE['instances'].items()), 24)
        self.assertEqual(main813.MAIN09FE['declared_delta'],
                         {'rust_tests': 24, 'rust_declarations': 24, 'doctests': 2, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_09fe(actual))
        for name, change in main813.MAIN09FE['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main09fe_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main09fe_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main09fe_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_09fe(changed)
        for path in main813.MAIN09FE['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main09fe_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN09FE['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_09fe(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main09fe_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_09fe(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN09FE['doctests'].values()), 2)

        self.assertEqual(main813.digest(main813.before_727(actual)), main813.CURRENT09FE)
        current_rows = main813.before_abab(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3023, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN727['added_methods'].values()), 33)
        self.assertEqual(sum(len(main813.MAIN727['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN727['instances'].items()), 33)
        self.assertEqual(main813.MAIN727['declared_delta'],
                         {'rust_tests': 33, 'rust_declarations': 33, 'doctests': 0, 'ignored': 3, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_727(actual))
        for name, change in main813.MAIN727['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main727_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main727_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main727_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_727(changed)
        for path in main813.MAIN727['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main727_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN727['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_727(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main727_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_727(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN727['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN727['methods'].values()), 3)

        self.assertEqual(main813.digest(main813.before_abab(actual)), main813.CURRENT727)
        current_rows = main813.before_83b(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3092, 36))
        self.assertEqual(sum(len(x) for x in main813.MAINABAB['added_methods'].values()), 54)
        self.assertEqual(sum(len(main813.MAINABAB['added_methods'][p]) * len(v)
                             for p, v in main813.MAINABAB['instances'].items()), 63)
        self.assertEqual(main813.MAINABAB['declared_delta'],
                         {'rust_tests': 69, 'rust_declarations': 54, 'new_instances_of_existing_declarations': 6, 'second_instances_of_new_declarations': 9, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_abab(actual))
        for name, change in main813.MAINABAB['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(mainabab_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(mainabab_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(mainabab_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_abab(changed)
        for path in main813.MAINABAB['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainabab_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAINABAB['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_abab(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(mainabab_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_abab(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAINABAB['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINABAB['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAINABAB['listed_additions'].items()},
                         {'test/frontend_native_calibrations': 29, 'unit/ordinary_interval/main': 40})

        self.assertEqual(main813.digest(main813.before_83b(actual)), main813.CURRENTABAB)
        current_rows = main813.before_850(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3124, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN83B['added_methods'].values()), 32)
        self.assertEqual(sum(len(main813.MAIN83B['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN83B['instances'].items()), 32)
        self.assertEqual(main813.MAIN83B['declared_delta'],
                         {'rust_tests': 32, 'rust_declarations': 32, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_83b(actual))
        for name, change in main813.MAIN83B['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main83b_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main83b_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main83b_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_83b(changed)
        for path in main813.MAIN83B['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main83b_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN83B['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_83b(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main83b_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_83b(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN83B['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN83B['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAIN83B['listed_additions'].items()},
                         {'unit/rapid_profiler/lib': 21, 'unit/ordinary_interval/main': 11})

        self.assertEqual(main813.digest(main813.before_850(actual)), main813.CURRENT83B)
        current_rows = main813.before_5a0(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3151, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN850['added_methods'].values()), 27)
        self.assertEqual(sum(len(main813.MAIN850['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN850['instances'].items()), 27)
        self.assertEqual(main813.MAIN850['declared_delta'],
                         {'rust_tests': 27, 'rust_declarations': 27, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_850(actual))
        for name, change in main813.MAIN850['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main850_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main850_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main850_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_850(changed)
        for path in main813.MAIN850['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main850_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN850['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_850(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main850_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_850(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN850['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN850['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAIN850['listed_additions'].items()},
                         {'unit/ordinary_interval/main': 27})

        self.assertEqual(main813.digest(main813.before_5a0(actual)), main813.CURRENT850)
        current_rows = main813.before_9950(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3172, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN5A0['added_methods'].values()), 21)
        self.assertEqual(sum(len(main813.MAIN5A0['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN5A0['instances'].items()), 21)
        self.assertEqual(main813.MAIN5A0['declared_delta'],
                         {'rust_tests': 21, 'rust_declarations': 21, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_5a0(actual))
        for name, change in main813.MAIN5A0['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main5a0_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main5a0_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main5a0_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_5a0(changed)
        for path in main813.MAIN5A0['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main5a0_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN5A0['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_5a0(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main5a0_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_5a0(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN5A0['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN5A0['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAIN5A0['listed_additions'].items()},
                         {'test/frontend_native_calibrations': 6, 'unit/ordinary_interval/main': 14, 'unit/rapid_profiler/lib': 1})

        self.assertEqual(main813.digest(main813.before_9950(actual)), main813.CURRENT5A0)
        current_rows = main813.before_2754(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3201, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN9950['added_methods'].values()), 29)
        self.assertEqual(sum(len(main813.MAIN9950['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN9950['instances'].items()), 29)
        self.assertEqual(main813.MAIN9950['declared_delta'],
                         {'rust_tests': 29, 'rust_declarations': 29, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_9950(actual))
        for name, change in main813.MAIN9950['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main9950_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main9950_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main9950_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_9950(changed)
        for path in main813.MAIN9950['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main9950_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAIN9950['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_9950(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main9950_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_9950(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN9950['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN9950['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAIN9950['listed_additions'].items()},
                         {'test/frontend_native_calibrations': 10, 'unit/ordinary_interval/main': 4, 'unit/rapid_profiler/lib': 15})

        self.assertEqual(main813.digest(main813.before_2754(actual)), main813.CURRENT9950)
        current_rows = main813.before_9c70(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3215, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN2754['added_methods'].values()), 14)
        self.assertEqual(sum(len(main813.MAIN2754['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN2754['instances'].items()), 14)
        self.assertEqual(main813.MAIN2754['declared_delta'],
                         {'rust_tests': 14, 'rust_declarations': 14, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_2754(actual))
        for name, change in main813.MAIN2754['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main2754_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main2754_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main2754_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_2754(changed)
        for path in main813.MAIN2754['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main2754_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_2754_sources()
        integration_path = 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/session/tests.rs'
        self.assertIn(integration_path, main813.MAIN2754['added_methods'])
        mutation_target = main813.ROOT / integration_path
        for missing in (False, True):
            def changed(candidate):
                if candidate == mutation_target:
                    if missing:
                        raise FileNotFoundError(integration_path)
                    return read_bytes(candidate) + b'\n'
                return read_bytes(candidate)
            with self.subTest(main2754_integration=integration_path, missing=missing), patch.object(Path, 'read_bytes', changed):
                with self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(actual)
        for path, row in main813.MAIN2754['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_2754(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main2754_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_2754(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN2754['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN2754['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAIN2754['listed_additions'].items()},
                         {'unit/rapid_profiler/lib': 14})

        self.assertEqual(main813.digest(main813.before_9c70(actual)), main813.CURRENT2754)
        current_rows = main813.before_0a088(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3232, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN9C70['added_methods'].values()), 17)
        self.assertEqual(sum(len(main813.MAIN9C70['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN9C70['instances'].items()), 17)
        self.assertEqual(main813.MAIN9C70['declared_delta'],
                         {'rust_tests': 17, 'rust_declarations': 17, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_9c70(actual))
        for name, change in main813.MAIN9C70['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main9c70_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main9c70_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main9c70_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_9c70(changed)
        for path in main813.MAIN9C70['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main9c70_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_9c70_sources()
        integration_path = 'tools/rapid-profiler/ordinary-interval/normal/module/session/input.rs'
        self.assertIn(integration_path, main813.MAIN9C70['added_methods'])
        mutation_target = main813.ROOT / integration_path
        for missing in (False, True):
            def changed(candidate):
                if candidate == mutation_target:
                    if missing:
                        raise FileNotFoundError(integration_path)
                    return read_bytes(candidate) + b'\n'
                return read_bytes(candidate)
            with self.subTest(main9c70_integration=integration_path, missing=missing), patch.object(Path, 'read_bytes', changed):
                with self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(actual)
        for path, row in main813.MAIN9C70['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_9c70(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main9c70_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_9c70(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN9C70['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN9C70['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAIN9C70['listed_additions'].items()},
                         {'test/frontend_native_calibrations': 4, 'unit/ordinary_interval/main': 13})

        self.assertEqual(main813.digest(main813.before_0a088(actual)), main813.CURRENT9C70)
        current_rows = main813.before_e11(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3266, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN0A088['added_methods'].values()), 34)
        self.assertEqual(sum(len(main813.MAIN0A088['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN0A088['instances'].items()), 34)
        self.assertEqual(main813.MAIN0A088['declared_delta'],
                         {'rust_tests': 34, 'rust_declarations': 34, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_0a088(actual))
        for name, change in main813.MAIN0A088['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main0a088_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main0a088_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main0a088_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_0a088(changed)
        for path in main813.MAIN0A088['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main0a088_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_0a088_sources()
        integration_path = 'tests/support/native_copied_rust/tests.rs'
        self.assertIn(integration_path, main813.MAIN0A088['added_methods'])
        mutation_target = main813.ROOT / integration_path
        for missing in (False, True):
            def changed(candidate):
                if candidate == mutation_target:
                    if missing:
                        raise FileNotFoundError(integration_path)
                    return read_bytes(candidate) + b'\n'
                return read_bytes(candidate)
            with self.subTest(main0a088_integration=integration_path, missing=missing), patch.object(Path, 'read_bytes', changed):
                with self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(actual)
        for path, row in main813.MAIN0A088['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_0a088(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main0a088_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_0a088(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN0A088['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN0A088['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAIN0A088['listed_additions'].items()},
                         {'test/frontend_native_calibrations': 16, 'unit/ordinary_interval/main': 12, 'unit/rapid_profiler/lib': 6})

        self.assertEqual(main813.digest(main813.before_e11(actual)), main813.CURRENT0A088)
        current_rows = main813.before_469(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3296, 36))
        self.assertEqual(sum(len(x) for x in main813.MAINE11['added_methods'].values()), 30)
        self.assertEqual(sum(len(main813.MAINE11['added_methods'][p]) * len(v)
                             for p, v in main813.MAINE11['instances'].items()), 30)
        self.assertEqual(main813.MAINE11['declared_delta'],
                         {'rust_tests': 30, 'rust_declarations': 30, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_e11(actual))
        for name, change in main813.MAINE11['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(maine11_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(maine11_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(maine11_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_e11(changed)
        for path in main813.MAINE11['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(maine11_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_e11_sources()
        integration_path = 'tools/rapid-profiler/src/frontend_native/always_on/normal/leaf_set/tests.rs'
        self.assertIn(integration_path, main813.MAINE11['added_methods'])
        mutation_target = main813.ROOT / integration_path
        for missing in (False, True):
            def changed(candidate):
                if candidate == mutation_target:
                    if missing:
                        raise FileNotFoundError(integration_path)
                    return read_bytes(candidate) + b'\n'
                return read_bytes(candidate)
            with self.subTest(maine11_integration=integration_path, missing=missing), patch.object(Path, 'read_bytes', changed):
                with self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(actual)
        for path, row in main813.MAINE11['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_e11(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(maine11_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_e11(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAINE11['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINE11['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAINE11['listed_additions'].items()},
                         {'unit/ordinary_interval/main': 12, 'unit/rapid_profiler/lib': 18})

        self.assertEqual(main813.digest(main813.before_469(actual)), main813.CURRENTE11)
        current_rows = main813.before_b66(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3320, 36))
        self.assertEqual(sum(len(x) for x in main813.MAIN469['added_methods'].values()), 24)
        self.assertEqual(sum(len(main813.MAIN469['added_methods'][p]) * len(v)
                             for p, v in main813.MAIN469['instances'].items()), 24)
        self.assertEqual(main813.MAIN469['declared_delta'],
                         {'rust_tests': 24, 'rust_declarations': 24, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_469(actual))
        for name, change in main813.MAIN469['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main469_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(main469_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(main469_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_469(changed)
        for path in main813.MAIN469['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main469_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_469_sources()
        integration_path = 'tests/support/native_leaf_set_copied/tests.rs'
        self.assertIn(integration_path, main813.MAIN469['added_methods'])
        mutation_target = main813.ROOT / integration_path
        for missing in (False, True):
            def changed(candidate):
                if candidate == mutation_target:
                    if missing:
                        raise FileNotFoundError(integration_path)
                    return read_bytes(candidate) + b'\n'
                return read_bytes(candidate)
            with self.subTest(main469_integration=integration_path, missing=missing), patch.object(Path, 'read_bytes', changed):
                with self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(actual)
        for path, row in main813.MAIN469['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_469(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main469_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_469(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAIN469['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN469['methods'].values()), 0)

        self.assertEqual({k: len(v) for k, v in main813.MAIN469['listed_additions'].items()},
                         {'test/frontend_native_calibrations': 20, 'unit/ordinary_interval/main': 4})

        self.assertEqual(main813.digest(main813.before_b66(actual)), main813.CURRENT469)
        current_rows = main813.before_12e(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3558, 37))
        self.assertEqual(sum(len(x) for x in main813.MAINB66['added_methods'].values()), 65)
        self.assertEqual(sum(len(main813.MAINB66['added_methods'][p]) * len(v)
                             for p, v in main813.MAINB66['instances'].items()), 74)
        self.assertEqual(main813.MAINB66['declared_delta'],
                         {'rust_tests': 238, 'rust_declarations': 65, 'new_instances_of_existing_declarations': 164, 'second_instances_of_new_declarations': 9, 'doctests': 0, 'ignored': 1, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_b66(actual))
        for name, change in main813.MAINB66['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            current_count = actual['harness_test_counts']['workspace_tests'][name]['tests']
            for value in (current_count - 1, current_count + 1,
                          True, float(current_count)):
                self.assertTrue(type(value) is not int or value != current_count)
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(mainb66_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(mainb66_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = plain.deepcopy(actual); changed[key] = None
            with self.subTest(mainb66_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_b66(changed)
        for path in main813.MAINB66['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainb66_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_b66_sources()
        integration_path = 'tests/support/native_call_pair/tests.rs'
        self.assertIn(integration_path, main813.MAINB66['added_methods'])
        mutation_target = main813.ROOT / integration_path
        for missing in (False, True):
            def changed(candidate):
                if candidate == mutation_target:
                    if missing:
                        raise FileNotFoundError(integration_path)
                    return read_bytes(candidate) + b'\n'
                return read_bytes(candidate)
            with self.subTest(mainb66_integration=integration_path, missing=missing), patch.object(Path, 'read_bytes', changed):
                with self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(actual)
        for path, row in main813.MAINB66['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_b66(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(mainb66_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_b66(path, bad, 'changed')

        self.assertEqual(sum(len(x) for x in main813.MAINB66['doctests'].values()), 0)

        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINB66['methods'].values()), 1)

        self.assertEqual({k: len(v) for k, v in main813.MAINB66['listed_additions'].items()},
                         {'test/frontend_native_calibrations': 9, 'unit/ordinary_interval/main': 190, 'unit/liteinst2/lib': 9, 'unit/rapid_profiler/lib': 30})

        self.assertEqual(len(main813.MAINB66['new_instances']), 164)
        self.assertEqual(sum(row['ignored'] for row in main813.MAINB66['new_instances']), 1)
        self.assertEqual(sum(map(len, main813.MAINB66['listed_additions'].values())), 238)
        self.assertEqual({row['harness'] for row in main813.MAINB66['new_instances']}, {'unit/ordinary_interval/main'})


        # Source-only8f622 changes no declared tests, corpus or historical pin.
        self.assertEqual(set(main813.MAIN8F622['sources']), {
            'evaluation/ordinary-call-pair-session/freeze.py',
            'evaluation/ordinary-call-pair-session/launch.py',
            'evaluation/ordinary-call-pair-session/owner_controls.py',
            'evaluation/ordinary-call-pair-session/receipt_controls.py',
            'evaluation/ordinary-call-pair-session/reproduce.py',
            'evaluation/ordinary-call-pair-session/runner_controls.py',
            'tests/support/quiescent_oracle.rs'})
        self.assertEqual(set(main813.MAIN8F622['sources']), set(main813.MAIN8F622['projections']))
        main813.require_8f622_sources()
        for path, row in main813.MAIN8F622['projections'].items():
            target = main813.ROOT / path
            raw = read_bytes(target)
            # The historical hash follows the exact current-to-8f622 adapter.
            projected = main813.source_at_8f622(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(projected).hexdigest(), row['current_sha256'])
            restored = main813.source_before_8f622(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main8f622_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_8f622(path, bad, 'changed')
            for index in range(len(row['edits'])):
                altered = plain.deepcopy(row)
                altered['edits'][index][2] += '\n'
                with patch.dict(main813.MAIN8F622['projections'], {path: altered}):
                    with self.subTest(main8f622_span=(path,index)), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                        main813.source_before_8f622(path, raw, 'changed')
            for missing in (False, True):
                def changed(candidate):
                    if candidate == target:
                        if missing:
                            raise FileNotFoundError(path)
                        return raw + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main8f622_source=(path,missing)), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_8f622_sources()
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)

        self.assertEqual(set(main813.MAIN8F622_CURRENT), {
            'evaluation/ordinary-call-pair-session/receipt_controls.py',
            'evaluation/ordinary-call-pair-session/reproduce.py'})
        for path, row in main813.MAIN8F622_CURRENT.items():
            raw = read_bytes(main813.ROOT / path)
            restored = main813.source_at_8f622(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['current_sha256'])
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            self.assertEqual(main813.source_before_8f622(path, raw, 'changed'),
                             main813.source_before_12e(path, raw, 'changed'))
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main8f622_current=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_at_8f622(path, bad, 'changed')
            for index in range(len(row['edits'])):
                altered = plain.deepcopy(row)
                altered['edits'][index][2] += '\n'
                with patch.dict(main813.MAIN8F622_CURRENT, {path: altered}):
                    with self.subTest(main8f622_current_span=(path,index)), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                        main813.source_before_12e(path, raw, 'changed')


        # The additive layer restores the exact historical catalog and source;
        # none of its current declarations can be supplied by the old blobs.
        self.assertEqual(main813.digest(main813.before_12e(actual)), main813.CURRENTB66)
        current_rows = main813.before_c6f(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3574, 37))
        self.assertEqual(main813.MAIN12E['declared_delta'],
                         {'rust_tests': 16, 'rust_declarations': 8, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_12e(actual))
        for name, change in main813.MAIN12E['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            self.assertEqual(change['previous'], main813.MAINB66['workspace_changes'][name]['current'])
            count = current_rows[name]['tests']
            for value in (count - 1, count + 1, True, float(count)):
                changed = plain.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(main12e_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = plain.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.assertRaises(parsing.InvalidEvidence):
                main813.before_12e(changed)
        for path in main813.MAIN12E['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main12e_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_12e_sources()
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        self.assertEqual(len(main813.MAIN12E['projections']), 20)
        for path, row in main813.MAIN12E['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_12e(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            historical_sources = (main813.MAINC0['sources'] if path == 'tests/support/quiescent_oracle.rs'
                                  else main813.MAINB66['sources'])
            self.assertEqual(row['previous_sha256'], historical_sources[path])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main12e_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_12e(path, bad, 'changed')
            # A coherent historical file cannot stand in for the current source.
            mutation_target = main813.ROOT / path
            def historical(candidate):
                return restored if candidate == mutation_target else read_bytes(candidate)
            with patch.object(Path, 'read_bytes', historical), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(actual)
        new_sources = {'tests/support/native_call_pair/trace_join.rs',
                       'tests/support/native_call_pair/trace_join/tests.rs',
                       'tests/support/native_call_pair/witness.rs',
                       'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/witness.rs'}
        self.assertEqual(set(main813.MAIN12E['sources']) - (set(main813.MAINB66['sources']) |
                         set(main813.MAINC0['sources'])), new_sources)
        direct = 'tests/support/native_call_pair/tests.rs'
        nested = 'tests/support/native_call_pair/trace_join/tests.rs'
        prefix = 'oracle::native_ordinary::normal_caller::call_pair::'
        self.assertEqual({p: len(row['all']) for p, row in main813.MAIN12E['methods'].items()},
                         {direct: 12, nested: 5})
        self.assertEqual({p: len(row) for p, row in main813.MAIN12E['added_methods'].items()},
                         {direct: 3, nested: 5})
        self.assertEqual([name for name in main813.MAIN12E['methods'][direct]['all']
                          if name not in main813.MAIN12E['added_methods'][direct]],
                         main813.MAINB66['methods'][direct]['all'])
        for harness in main813.MAIN12E['workspace_changes']:
            self.assertEqual(main813.MAIN12E['instances'][direct][harness], prefix + 'tests::')
            self.assertEqual(main813.MAIN12E['instances'][nested][harness], prefix + 'trace_join::tests::')
            complete = [main813.MAIN12E['instances'][p][harness] + name
                        for p, row in main813.MAIN12E['methods'].items() for name in row['all']]
            self.assertEqual(len(complete), 17)
            self.assertEqual(len(set(complete)), 17)
            additions = sorted(main813.MAIN12E['instances'][p][harness] + name
                               for p, names in main813.MAIN12E['added_methods'].items() for name in names)
            self.assertEqual(main813.MAIN12E['listed_additions'][harness], additions)
            self.assertEqual(len(additions), 8)
        # Coherent source pins alone do not replace declaration/module guards.
        for path, row in main813.MAIN12E['methods'].items():
            mutations = [dict(row, all=row['all'][:i] + row['all'][i + 1:])
                         for i in range(len(row['all']))]
            mutations += [dict(row, all=row['all'] + ['not_registered']),
                          dict(row, ignored=[row['all'][0]])]
            for changed in mutations:
                with patch.dict(main813.MAIN12E['methods'], {path: changed}), self.assertRaises(parsing.InvalidEvidence):
                    main813.require_12e_sources()
        for path, literals in main813.MAIN12E['module_chains'].items():
            for i in range(len(literals)):
                changed = list(literals)
                changed[i] += ' invalid_module_route'
                with patch.dict(main813.MAIN12E['module_chains'], {path: changed}), self.assertRaises(parsing.InvalidEvidence):
                    main813.require_12e_sources()


        # The disassembly importer adds eight library tests, no default example
        # harness. Old source/catalog checks receive exact pre-importer images.
        self.assertEqual(main813.digest(main813.before_c6f(actual)), main813.CURRENT12E)
        current_rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 3582, 37))
        self.assertEqual(main813.MAINC6F['declared_delta'],
                         {'rust_declarations': 8, 'rust_tests': 8, 'harnesses': 0, 'ignored': 0, 'doctests': 0})
        harness = 'unit/liteinst_rewrite/lib'
        self.assertEqual(current_rows[harness], {'tests': 94, 'ignored': 0})
        self.assertEqual(main813.before_c6f(actual)['harness_test_counts']['workspace_tests'][harness],
                         {'tests': 86, 'ignored': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_c6f(actual))
        for count in (93, 95, True, 94.0):
            changed = plain.deepcopy(actual)
            changed['harness_test_counts']['workspace_tests'][harness]['tests'] = count
            with self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        changed = plain.deepcopy(actual)
        del changed['harness_test_counts']['workspace_tests'][harness]
        with self.assertRaises(parsing.InvalidEvidence):
            main813.before_c6f(changed)
        for path in main813.MAINC6F['sources']:
            for missing in (False, True):
                mutation_target = main813.ROOT / path
                def changed(candidate):
                    if candidate == mutation_target:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainc6f_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        main813.require_c6f_sources()
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        self.assertEqual(len(main813.MAINC6F['sources']), 7)
        self.assertEqual(set(main813.MAINC6F['projections']),
                         {'src/emission.rs', 'tools/elf-rewrite/Cargo.toml', 'tools/elf-rewrite/src/lib.rs'})
        for path, row in main813.MAINC6F['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_c6f(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            # The full existing source helper chain must retain this inverse.
            self.assertEqual(main813.source_before(path, raw, 'changed'), restored)
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_c6f(path, bad, 'changed')
            mutation_target = main813.ROOT / path
            def historical(candidate):
                return restored if candidate == mutation_target else read_bytes(candidate)
            with patch.object(Path, 'read_bytes', historical), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(actual)
        test_source = 'tools/elf-rewrite/src/disassembly/tests.rs'
        methods = main813.MAINC6F['methods'][test_source]
        self.assertEqual(len(methods['all']), 8)
        self.assertEqual(methods['ignored'], [])
        self.assertEqual(main813.MAINC6F['instances'], {test_source: {harness: 'disassembly::tests::'}})
        self.assertEqual(main813.MAINC6F['listed_additions'][harness],
                         ['disassembly::tests::' + name for name in methods['all']])
        for changed in ([dict(methods, all=methods['all'][:i] + methods['all'][i + 1:])
                         for i in range(8)] +
                        [dict(methods, all=methods['all'] + ['not_registered']),
                         dict(methods, ignored=[methods['all'][0]])]):
            with patch.dict(main813.MAINC6F['methods'], {test_source: changed}), self.assertRaises(parsing.InvalidEvidence):
                main813.require_c6f_sources()
        for path, literals in main813.MAINC6F['module_chains'].items():
            for i in range(len(literals)):
                changed = list(literals)
                changed[i] += ' invalid_module_route'
                with patch.dict(main813.MAINC6F['module_chains'], {path: changed}), self.assertRaises(parsing.InvalidEvidence):
                    main813.require_c6f_sources()
        # Cargo examples are compiled by workspace tests but are not run as a
        # libtest target by default; this new declaration does not set test=true.
        self.assertEqual(main813.MAINC6F['example'],
                         {'name': 'disassembly_sites', 'path': 'examples/disassembly_sites.rs',
                          'test_field': 'absent; Cargo default false', 'workspace_test_harness': False})
        self.assertNotIn('unit/disassembly_sites/disassembly_sites', current_rows)
        changed = plain.deepcopy(actual)
        changed['harness_test_counts']['workspace_tests']['unit/disassembly_sites/disassembly_sites'] = {'tests': 0, 'ignored': 0}
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(changed)
        mutation_target = main813.ROOT / 'tools/elf-rewrite/Cargo.toml'
        def enabled_example(candidate):
            raw = read_bytes(candidate)
            if candidate == mutation_target:
                return raw.replace(b'path = "examples/disassembly_sites.rs"\n',
                                   b'path = "examples/disassembly_sites.rs"\ntest = true\n')
            return raw
        with patch.object(Path, 'read_bytes', enabled_example), self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(actual)

    def test_exact_precontext_header_scope_and_old_bytes(self):
        old = header('example') + '\nrunning 1 test\n' + summary(1) + '\n'
        for raw in (text() + old, old + text()):
            remaining, rows, error = self.parse(raw)
            self.assertIsNone(error)
            self.assertEqual(remaining, old)
            self.assertTrue(protocol.is_complete(rows[0]))
            self.assertFalse(rows[0]['qualified_run'])
            self.assertEqual(rows[0]['observations'], terminal())
        for raw in ('', text().removeprefix(HEADER), text() + text(),
                    text().replace('tests/precontext_native.rs', 'tests/wrong.rs'),
                    text().replace('precontext_native-0123', 'wrong-0123'),
                    text().replace('target/debug/deps/', 'target/release/deps/'),
                    text() + 'unexpected native diagnostic\n', HEADER + old):
            with self.subTest(raw=raw[:80]):
                _, rows, error = self.parse(raw)
                self.assertIsNotNone(error)
                self.assertFalse(protocol.is_complete(rows[0]))

    def test_core_parser_rejects_field_type_scope_population_and_partial_changes(self):
        good = terminal()
        for name in ('pairs', 'malformed', 'pure_controls'):
            for index in range(len(good[name])):
                changed = copy.deepcopy(good); changed[name].pop(index)
                _, rows, error = self.parse(text(changed))
                self.assertEqual(error, 'invalid_precontext_protocol')
                self.assertIsNone(rows[0]['observations'])
        for section in ('pairs', 'malformed'):
            for index, row in enumerate(good[section]):
                for key, value in row.items():
                    bad = None if type(value) is bool else True if type(value) is int else 'PRIVATE_SENTINEL'
                    changed = copy.deepcopy(good); changed[section][index][key] = bad
                    with self.subTest(section=section, index=index, key=key):
                        _, rows, error = self.parse(text(changed))
                        self.assertIsNotNone(error)
                        self.assertIsNone(rows[0]['observations'])
        for key in good['totals']:
            changed = copy.deepcopy(good); changed['totals'][key] -= 1
            self.assertIsNotNone(self.parse(text(changed))[2])
        for raw in (text()[:-1], text() + text().removeprefix(HEADER),
                    text().replace('"schema":1', '"schema":1,"schema":1'),
                    text().replace('"schema":1', '"schema":NaN'),
                    text().replace('"scope":"fixed-core-no-frontend-or-performance"', '"scope":"performance"'),
                    HEADER + '{"PRIVATE_SENTINEL":' + 'x' * 65536 + '\n'):
            _, rows, error = self.parse(raw)
            self.assertIsNotNone(error)
            self.assertFalse(protocol.is_complete(rows[0]))
            self.assertNotIn('PRIVATE_SENTINEL', json.dumps(rows))

    def test_whole_run_qualification_needs_exact_native_protocol_and_success(self):
        old = header('example') + '\nrunning 1 test\n' + summary(1) + '\n'
        corpus = {'harness_test_counts': {'workspace_tests': {'unit/example/lib': counts(1)}},
                  'precontext_native_harnesses': {'workspace_tests': [protocol.specification()]}}
        protocol.require_inventory(corpus)
        for missing in (None, {}, {'workspace_tests': []}):
            with self.assertRaises(parsing.InvalidEvidence):
                protocol.require_inventory(corpus | {'precontext_native_harnesses': missing})
        command = {'id': 'workspace_tests', 'status': 'passed', 'exit_code': 0}
        run.command_evidence(command, text() + old, corpus)
        self.assertEqual(command['status'], 'passed')
        record = {'source_unchanged': True, 'configuration_unchanged': True,
                  'precontext_native_required': True, 'commands': [command]}
        run.qualify(record)
        self.assertEqual(record['status'], 'passed')
        self.assertTrue(command['precontext_native_harnesses'][0]['qualified_run'])
        for key, value in (('source_unchanged', False), ('configuration_unchanged', False)):
            bad = copy.deepcopy(record); bad[key] = value
            run.qualify(bad)
            self.assertEqual(bad['status'], 'failed')
            self.assertFalse(bad['commands'][0]['precontext_native_harnesses'][0]['qualified_run'])
        for rows in ([], command['precontext_native_harnesses'] * 2):
            bad = copy.deepcopy(record); bad['commands'][0]['precontext_native_harnesses'] = rows
            run.qualify(bad); self.assertEqual(bad['status'], 'failed')
        for exit_code, raw in ((1, text()), (0, HEADER), (0, text().replace('"status":"PASS"', '"status":"FAILED"'))):
            item = {'id': 'workspace_tests', 'status': 'passed' if exit_code == 0 else 'failed', 'exit_code': exit_code}
            run.command_evidence(item, raw + old, corpus)
            bad = record | {'commands': [item]}
            run.qualify(bad)
            self.assertEqual(bad['status'], 'failed')
            self.assertFalse(item['precontext_native_harnesses'][0]['qualified_run'])

    def test_new_core_child_tuple_is_exact_and_old_shapes_survive(self):
        for total in (176, 184, 208, 213, 219, 227, 242, 248):
            raw = '\n'.join((header('liteinst2'), f'running {total} tests', 'running 1 test', summary(total - 1, ignored=1)))
            row = parsing.parse_harnesses(raw, {'unit/liteinst2/lib': counts(total, 1)}, 0)[0]
            self.assertEqual(row['outer']['passed'], total - 1)
            self.assertEqual(row['unmatched_nested_starts'], 1)
        for total, ignored, nested in ((247, 1, 1), (249, 1, 1), (248, 0, 1), (248, 1, 2)):
            raw = '\n'.join((header('liteinst2'), f'running {total} tests', f'running {nested} tests', summary(total - ignored, ignored=ignored)))
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(raw, {'unit/liteinst2/lib': counts(total, ignored)}, 0)

        # Exact new cohort: keep all old rows/assertions and refuse neighbors.
        raw = '\n'.join((header('liteinst2'), 'running 255 tests', 'running 1 test',
                         'test trampoline::tests::live::ptrace_stopped_hook_executes_on_owned_stack ... ok',
                         summary(254, ignored=1)))
        row = parsing.parse_harnesses(raw, {'unit/liteinst2/lib': counts(255, 1)}, 0)[0]
        self.assertEqual(row['outer']['passed'], 254)
        self.assertEqual(row['outer']['ignored'], 1)
        self.assertEqual(row['unmatched_nested_starts'], 1)
        for total, ignored, nested in ((254, 1, 1), (256, 1, 1), (255, 0, 1), (255, 1, 2)):
            bad = '\n'.join((header('liteinst2'), f'running {total} tests', f'running {nested} tests',
                             summary(total - ignored, ignored=ignored)))
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, {'unit/liteinst2/lib': counts(total, ignored)}, 0)

        # Exact whole-function core cohort: keep all old rows/assertions and refuse neighbors.
        raw = '\n'.join((header('liteinst2'), 'running 262 tests', 'running 1 test',
                         'test trampoline::tests::live::ptrace_stopped_hook_executes_on_owned_stack ... ok',
                         summary(261, ignored=1)))
        row = parsing.parse_harnesses(raw, {'unit/liteinst2/lib': counts(262, 1)}, 0)[0]
        self.assertEqual(row['outer']['passed'], 261)
        self.assertEqual(row['outer']['ignored'], 1)
        self.assertEqual(row['unmatched_nested_starts'], 1)
        for total, ignored, nested in ((261, 1, 1), (263, 1, 1), (262, 0, 1), (262, 1, 2)):
            bad = '\n'.join((header('liteinst2'), f'running {total} tests', f'running {nested} tests',
                             summary(total - ignored, ignored=ignored)))
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, {'unit/liteinst2/lib': counts(total, ignored)}, 0)

        # Exact b66 cohort: two summarized children and one authenticated
        # ptrace child exit. None of the nested rows adds to outer test counts.
        raw = '\n'.join((header('liteinst2'), 'running 271 tests',
                         'running 1 test', summary(1, filtered=270),
                         'running 1 test', summary(1, filtered=270),
                         'running 1 test',
                         'test trampoline::tests::live::ptrace_stopped_hook_executes_on_owned_stack ... ok',
                         summary(270, ignored=1)))
        expected = {'unit/liteinst2/lib': counts(271, 1)}
        row = parsing.parse_harnesses(raw, expected, 0)[0]
        self.assertEqual(row['outer']['passed'], 270)
        self.assertEqual(row['outer']['ignored'], 1)
        self.assertEqual([x['passed'] for x in row['nested']], [1, 1])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (3, 1))
        for total, ignored, nested in ((270, 1, 1), (272, 1, 1), (271, 0, 1),
                                       (271, 2, 1), (271, 1, 2)):
            bad = '\n'.join((header('liteinst2'), f'running {total} tests',
                             f'running {nested} tests', summary(total - ignored, ignored=ignored)))
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, {'unit/liteinst2/lib': counts(total, ignored)}, 0)
        changes = [raw.replace('liteinst2', 'other'),
                   raw.replace('running 271 tests', 'running 272 tests'),
                   raw.replace(summary(1, filtered=270), summary(1, filtered=269), 1),
                   raw.replace(summary(270, ignored=1), summary(270, ignored=1, filtered=1)),
                   raw.replace(summary(270, ignored=1), summary(269, ignored=1, measured=1)),
                   raw.replace(summary(270, ignored=1), summary(269, ignored=1, failed=1)),
                   raw.replace(summary(270, ignored=1), summary(270, ignored=1, result='FAILED')),
                   raw.replace('test trampoline::tests::live::ptrace',
                               'running 1 test\ntest trampoline::tests::live::ptrace'),
                   raw.replace(summary(270, ignored=1), ''),
                   raw + '\n' + summary(270, ignored=1)]
        for bad in changes:
            with self.subTest(core_b66=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)

        doc = '\n'.join(('   Doc-tests rapid_profiler', 'running 2 tests', summary(2),
                         'running 36 tests', summary(36),
                         'all doctests ran in 0.51s; merged doctests compilation took 0.21s'))
        expected = {'doc/rapid_profiler': counts(38)}
        row = parsing.parse_harnesses(doc, expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=38, failed=0, ignored=0, measured=0, filtered=0, result='ok'))
        self.assertEqual(row['declared_outer_tests'], 2)
        self.assertEqual([p['declared_tests'] for p in row['partitions']], [2, 36])
        self.assertEqual([p['summary']['passed'] for p in row['partitions']], [2, 36])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (0, 0))
        changes = [doc.replace('rapid_profiler', 'example'),
                   doc.replace('running 2 tests', 'running 3 tests'),
                   doc.replace('running 36 tests', 'running 35 tests'),
                   doc.replace('running 36 tests', 'running 37 tests'),
                   doc.replace(summary(2), summary(1)),
                   doc.replace(summary(36), summary(35)),
                   doc.replace(summary(2), summary(2, filtered=1)),
                   doc.replace(summary(36), summary(36, filtered=1)),
                   doc.replace(summary(36), summary(35, ignored=1)),
                   doc.replace(summary(36), summary(35, measured=1)),
                   doc.replace(summary(36), summary(35, failed=1)),
                   doc.replace(summary(36), summary(36, result='FAILED')),
                   doc.replace('running 36 tests', 'running 36 tests\nrunning 36 tests'),
                   doc.replace(summary(2), summary(2)+'\n'+summary(2)),
                   doc.replace(summary(36), ''),
                   doc.replace(summary(2), ''),
                   '\n'.join(doc.splitlines()[:-1]),
                   doc+'\n'+doc.splitlines()[-1],
                   doc+'\nrunning 1 test\n'+summary(1),
                   doc.replace('all doctests ran in 0.51s;', 'all doctests ran in NaNs;')]
        for bad in changes:
            with self.subTest(doc_partition=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)
        for total, ignored in ((37, 0), (39, 0), (38, 1)):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(doc, {'doc/rapid_profiler': counts(total, ignored)}, 0)
        failed = doc.replace(summary(36), summary(35, failed=1))
        row = parsing.parse_harnesses(failed, expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']), ('FAILED', 37, 1))
        self.assertEqual(row['partitions'][1]['summary']['failed'], 1)

        # Exact incoming 45-doc cohort; retain the complete 38-doc controls above.
        doc = '\n'.join(('   Doc-tests rapid_profiler', 'running 2 tests', summary(2),
                         'running 43 tests', summary(43),
                         'all doctests ran in 0.51s; merged doctests compilation took 0.21s'))
        expected = {'doc/rapid_profiler': counts(45)}
        row = parsing.parse_harnesses(doc, expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=45, failed=0, ignored=0, measured=0, filtered=0, result='ok'))
        self.assertEqual(row['declared_outer_tests'], 2)
        self.assertEqual([p['declared_tests'] for p in row['partitions']], [2, 43])
        self.assertEqual([p['summary']['passed'] for p in row['partitions']], [2, 43])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (0, 0))
        changes = [doc.replace('rapid_profiler', 'example'),
                   doc.replace('running 2 tests', 'running 3 tests'),
                   doc.replace('running 43 tests', 'running 42 tests'),
                   doc.replace('running 43 tests', 'running 44 tests'),
                   doc.replace(summary(2), summary(1)),
                   doc.replace(summary(43), summary(42)),
                   doc.replace(summary(2), summary(2, filtered=1)),
                   doc.replace(summary(43), summary(43, filtered=1)),
                   doc.replace(summary(43), summary(42, ignored=1)),
                   doc.replace(summary(43), summary(42, measured=1)),
                   doc.replace(summary(43), summary(42, failed=1)),
                   doc.replace(summary(43), summary(43, result='FAILED')),
                   doc.replace('running 43 tests', 'running 43 tests\nrunning 43 tests'),
                   doc.replace(summary(2), summary(2)+'\n'+summary(2)),
                   doc.replace(summary(43), ''),
                   doc.replace(summary(2), ''),
                   '\n'.join(doc.splitlines()[:-1]),
                   doc+'\n'+doc.splitlines()[-1],
                   doc+'\nrunning 1 test\n'+summary(1),
                   doc.replace('all doctests ran in 0.51s;', 'all doctests ran in NaNs;')]
        for bad in changes:
            with self.subTest(doc_partition=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)
        for total, ignored in ((44, 0), (46, 0), (45, 1)):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(doc, {'doc/rapid_profiler': counts(total, ignored)}, 0)
        failed = doc.replace(summary(43), summary(42, failed=1))
        row = parsing.parse_harnesses(failed, expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']), ('FAILED', 44, 1))
        self.assertEqual(row['partitions'][1]['summary']['failed'], 1)

        # Exact incoming 47-doc cohort; retain the complete 38-doc controls above.
        doc = '\n'.join(('   Doc-tests rapid_profiler', 'running 2 tests', summary(2),
                         'running 45 tests', summary(45),
                         'all doctests ran in 0.51s; merged doctests compilation took 0.21s'))
        expected = {'doc/rapid_profiler': counts(47)}
        row = parsing.parse_harnesses(doc, expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=47, failed=0, ignored=0, measured=0, filtered=0, result='ok'))
        self.assertEqual(row['declared_outer_tests'], 2)
        self.assertEqual([p['declared_tests'] for p in row['partitions']], [2, 45])
        self.assertEqual([p['summary']['passed'] for p in row['partitions']], [2, 45])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (0, 0))
        changes = [doc.replace('rapid_profiler', 'example'),
                   doc.replace('running 2 tests', 'running 3 tests'),
                   doc.replace('running 45 tests', 'running 44 tests'),
                   doc.replace('running 45 tests', 'running 46 tests'),
                   doc.replace(summary(2), summary(1)),
                   doc.replace(summary(45), summary(44)),
                   doc.replace(summary(2), summary(2, filtered=1)),
                   doc.replace(summary(45), summary(45, filtered=1)),
                   doc.replace(summary(45), summary(44, ignored=1)),
                   doc.replace(summary(45), summary(44, measured=1)),
                   doc.replace(summary(45), summary(44, failed=1)),
                   doc.replace(summary(45), summary(45, result='FAILED')),
                   doc.replace('running 45 tests', 'running 45 tests\nrunning 45 tests'),
                   doc.replace(summary(2), summary(2)+'\n'+summary(2)),
                   doc.replace(summary(45), ''),
                   doc.replace(summary(2), ''),
                   '\n'.join(doc.splitlines()[:-1]),
                   doc+'\n'+doc.splitlines()[-1],
                   doc+'\nrunning 1 test\n'+summary(1),
                   doc.replace('all doctests ran in 0.51s;', 'all doctests ran in NaNs;')]
        for bad in changes:
            with self.subTest(doc_partition=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)
        for total, ignored in ((46, 0), (48, 0), (47, 1)):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(doc, {'doc/rapid_profiler': counts(total, ignored)}, 0)
        failed = doc.replace(summary(45), summary(44, failed=1))
        row = parsing.parse_harnesses(failed, expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']), ('FAILED', 46, 1))
        self.assertEqual(row['partitions'][1]['summary']['failed'], 1)
