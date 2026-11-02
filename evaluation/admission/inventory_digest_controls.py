#!/usr/bin/env python3
"""Separate pure digest/inverse controls; not part of recorder discovery."""
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import inventory_digest as digest
import core_97ab_inventory
import core_981419_inventory
import core_d8d85_inventory
import core_34c47_inventory
import core_20cbe_inventory
import core_dd75_inventory
import core_acc247_inventory
import core_af81_inventory
from parsing import InvalidEvidence

MODULES = (core_97ab_inventory, core_981419_inventory, core_d8d85_inventory,
           core_34c47_inventory, core_20cbe_inventory, core_dd75_inventory,
           core_acc247_inventory, core_af81_inventory)
SHA = hashlib.sha256
CURRENT, PREVIOUS = b'abcNEWxyz', b'abcOLDxyz'


def row():
    return dict(current_sha256=SHA(CURRENT).hexdigest(),
                previous_sha256=SHA(PREVIOUS).hexdigest(), edits=[[3, 6, 'OLD']])


class DigestControls(unittest.TestCase):
    def setUp(self):
        digest._hexdigest.cache_clear()
        digest._large_hexdigest.cache_clear()

    def test_exact_bytes_and_original_cache_bounds(self):
        self.assertEqual(digest._hexdigest.cache_parameters(),
                         {'maxsize': 512, 'typed': True})
        self.assertEqual(digest._large_hexdigest.cache_parameters(),
                         {'maxsize': 64, 'typed': True})
        for size in (0, 1, 65536, 65537, 1048576):
            raw = b'a' * size
            self.assertEqual(digest.with_sha256(raw, SHA), SHA(raw).hexdigest())
            self.assertEqual(digest.with_sha256(raw, SHA), SHA(raw).hexdigest())
        supported = SHA is digest._SHA256
        self.assertEqual(digest._hexdigest.cache_info().hits, 3 if supported else 0)
        self.assertEqual(digest._large_hexdigest.cache_info().hits, 2 if supported else 0)
        before = (digest._hexdigest.cache_info(), digest._large_hexdigest.cache_info())
        oversized = b'a' * 1048577
        for _ in range(2):
            self.assertEqual(digest.with_sha256(oversized, SHA), SHA(oversized).hexdigest())
        self.assertEqual((digest._hexdigest.cache_info(), digest._large_hexdigest.cache_info()), before)

    def test_mutable_subclass_and_invalid_inputs_stay_live(self):
        class ForeignBytes(bytes):
            pass
        raw = bytearray(b'first')
        for data in (raw, memoryview(raw), ForeignBytes(raw)):
            self.assertEqual(digest.with_sha256(data, SHA), SHA(data).hexdigest())
        raw[:] = b'other'
        self.assertEqual(digest.with_sha256(raw, SHA), SHA(b'other').hexdigest())
        self.assertEqual(digest.with_sha256(memoryview(raw), SHA), SHA(b'other').hexdigest())
        self.assertEqual(digest._hexdigest.cache_info().currsize, 0)
        for data in (None, 1, 'text', [1]):
            with self.assertRaises(TypeError):
                digest.with_sha256(data, SHA)

    def test_stateful_and_identity_colliding_providers_are_not_cached(self):
        class Provider:
            __hash__ = None
            def __init__(self):
                self.calls = 0
            def __eq__(self, other):
                raise AssertionError('provider equality must not run')
            def __call__(self, data):
                self.calls += 1
                if self.calls == 3:
                    raise LookupError('third actual call')
                return SHA(data + bytes([self.calls]))
        provider = Provider()
        self.assertEqual(digest.with_sha256(CURRENT, provider), SHA(CURRENT + b'\1').hexdigest())
        self.assertEqual(digest.with_sha256(CURRENT, provider), SHA(CURRENT + b'\2').hexdigest())
        with self.assertRaisesRegex(LookupError, '^third actual call$'):
            digest.with_sha256(CURRENT, provider)
        self.assertEqual(provider.calls, 3)
        self.assertEqual(digest._hexdigest.cache_info().currsize, 0)
        # Global hashlib changes cannot replace an explicitly supplied provider.
        with patch.object(hashlib, 'sha256', side_effect=AssertionError('wrong provider')):
            self.assertEqual(digest.with_sha256(CURRENT, SHA), SHA(CURRENT).hexdigest())

    def test_all_eight_inverses_keep_live_bytes_metadata_and_edit_guards(self):
        for module in MODULES:
            with self.subTest(module=module.__name__):
                rows = {'source': row()}
                for _ in range(2):
                    self.assertEqual(module.inverse('source', CURRENT, rows, 'inverse_control'), PREVIOUS)
                sentinel = object()
                self.assertIs(module.inverse('absent', sentinel, rows, 'inverse_control'), sentinel)
                for raw in (b'abcBADxyz', CURRENT + b'!', bytearray(CURRENT)):
                    with self.assertRaisesRegex(InvalidEvidence, '^inverse_control$'):
                        module.inverse('source', raw, rows, 'inverse_control')
                mutations = [dict(row(), current_sha256='0' * 64),
                             dict(row(), previous_sha256='0' * 64),
                             dict(row(), edits=[])]
                mutations.extend(dict(row(), edits=[edit]) for edit in (
                    [-1, 6, 'OLD'], [3, 10, 'OLD'], [6, 3, 'OLD'],
                    [True, 6, 'OLD'], [3, 6.0, 'OLD'], [3, 6, b'OLD'],
                    [3, 6, 'BAD']))
                for changed in mutations:
                    with self.assertRaisesRegex(InvalidEvidence, '^inverse_control$'):
                        module.inverse('source', CURRENT, {'source': changed}, 'inverse_control')
                # Returning to the original metadata must still reconstruct.
                self.assertEqual(module.inverse('source', CURRENT, rows, 'inverse_control'), PREVIOUS)

    def test_each_inverse_uses_its_actual_current_hash_callable(self):
        for module in MODULES:
            calls = []
            def provider(raw):
                calls.append(raw)
                return SHA(raw) if len(calls) <= 2 else SHA(b'wrong')
            with self.subTest(module=module.__name__), patch.object(
                    module, 'hashlib', SimpleNamespace(sha256=provider)):
                self.assertEqual(module.inverse('source', CURRENT, {'source': row()},
                                                'provider_control'), PREVIOUS)
                with self.assertRaisesRegex(InvalidEvidence, '^provider_control$'):
                    module.inverse('source', CURRENT, {'source': row()}, 'provider_control')
                self.assertEqual(calls, [CURRENT, PREVIOUS, CURRENT])

    def test_live_source_reads_and_expected_hashes_are_never_cached(self):
        module = core_97ab_inventory
        metadata = dict(sources={'source': SHA(CURRENT).hexdigest()}, methods={},
                        doctests={}, source_successor_abe7={'doctest_sources': {}},
                        module_chains={})
        def unchanged(path, raw, error):
            return raw
        with patch.object(module, 'DATA', metadata), \
                patch.object(module, 'source_before', unchanged), \
                patch.object(module, 'source_before_a8acec5', unchanged), \
                patch.object(module, 'source_before_79b34bc', unchanged), \
                patch.object(module, 'source_before_evaluation', unchanged), \
                patch.object(Path, 'read_bytes', side_effect=[CURRENT, CURRENT,
                    b'abcBADxyz', FileNotFoundError('removed')]) as reads:
            self.assertIsNone(module.require_sources('read_control'))
            metadata['sources']['source'] = '0' * 64
            with self.assertRaisesRegex(InvalidEvidence, '^read_control$'):
                module.require_sources('read_control')
            metadata['sources']['source'] = SHA(CURRENT).hexdigest()
            for _ in range(2):
                with self.assertRaisesRegex(InvalidEvidence, '^read_control$'):
                    module.require_sources('read_control')
            self.assertEqual(reads.call_count, 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
