#!/usr/bin/env python3
"""Prospective pure source-correspondence/dispatch controls; never an admission."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import hashlib
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parent
PINS = {'payload/evaluation/e9-common-app/run_core_pairs.py': 'c2bbca05f9cf4c728f8d3f939588e027e53266109bc1185083ac0594a471e05e', 'payload/build.py': '5fbf13ecb2dd61316be9880af70ceaa7b8686365d894441405472f3e758df26a'}

def load(relative):
    p = ROOT / relative
    data = p.read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINS[relative]
    value = runpy.run_path(str(p), run_name='_pure_canonical_source_control_')
    assert p.read_bytes() == data
    return value

RUNNER = load('payload/evaluation/e9-common-app/run_core_pairs.py')
PRODUCER = load('payload/build.py')
OLD = (
    b'#[path = "../../../tests/support/e9_common_seed.rs"]',
    b'#[path = "support/common_core_foreign.rs"]',
    b'#[path = "../../../tests/support/e9_common_planning_profile.rs"]',
    b'#[path = "support/common_core_router.rs"]',
    b'#[path = "../../../tests/support/e9_common_router_contract.rs"]',
)
NEW = (
    b'#[path = "e9_common_seed.rs"]', b'#[path = "common_core_foreign.rs"]',
    b'#[path = "e9_common_planning_profile.rs"]', b'#[path = "common_core_router.rs"]',
    b'#[path = "e9_common_router_contract.rs"]',
)
ORIGINAL = b'// literal prefix\n' + b'\n'.join(OLD) + b'\nfn untouched() { assert!(true); }\n'
EXPECTED = b'// literal prefix\n' + b'\n'.join(NEW) + b'\nfn untouched() { assert!(true); }\n'

class CanonicalControls(unittest.TestCase):
    def test_complete_source_correspondence(self):
        for module in (RUNNER, PRODUCER):
            self.assertEqual(module['canonical_source'](ORIGINAL), EXPECTED)

    def test_missing_each_original_attribute_refuses(self):
        for old in OLD:
            for module in (RUNNER, PRODUCER):
                with self.assertRaises(AssertionError): module['canonical_source'](ORIGINAL.replace(old, b''))

    def test_duplicate_each_original_attribute_refuses(self):
        for old in OLD:
            for module in (RUNNER, PRODUCER):
                with self.assertRaises(AssertionError): module['canonical_source'](ORIGINAL + b'\n' + old)

    def test_preexisting_each_canonical_attribute_refuses(self):
        for new in NEW:
            for module in (RUNNER, PRODUCER):
                with self.assertRaises(AssertionError): module['canonical_source'](ORIGINAL + b'\n' + new)

    def test_near_spelling_is_not_a_path_exemption(self):
        for old in OLD:
            changed = ORIGINAL.replace(old, old.replace(b'path =', b'path='))
            for module in (RUNNER, PRODUCER):
                with self.assertRaises(AssertionError): module['canonical_source'](changed)

    def test_exact_seven_member_map(self):
        expected = {
            'src/verify_common_core.rs': 'tools/elf-rewrite/examples/verify_common_core.rs',
            'src/e9_common_seed.rs': 'tests/support/e9_common_seed.rs',
            'src/e9_common_seed.instructions.tsv': 'tests/support/e9_common_seed.instructions.tsv',
            'src/common_core_foreign.rs': 'tools/elf-rewrite/examples/support/common_core_foreign.rs',
            'src/e9_common_planning_profile.rs': 'tests/support/e9_common_planning_profile.rs',
            'src/common_core_router.rs': 'tools/elf-rewrite/examples/support/common_core_router.rs',
            'src/e9_common_router_contract.rs': 'tests/support/e9_common_router_contract.rs',
        }
        self.assertEqual(RUNNER['CANONICAL_MEMBERS'], expected)
        self.assertEqual(PRODUCER['MEMBERS'], expected)

    def test_fresh_epoch_is_one_explicit_direct_child(self):
        for module in (RUNNER, PRODUCER):
            epoch = module['canonical_epoch'](Path('/repo'), 'ignored/a3/fresh-canonical-epoch')
            self.assertEqual(epoch, Path('/repo/ignored/a3/fresh-canonical-epoch'))
            self.assertEqual(module['canonical_epoch_member'](epoch, str(epoch / 'build/source.json')),
                             epoch / 'build/source.json')

    def test_closed_historical_epoch_refuses(self):
        for module in (RUNNER, PRODUCER):
            with self.assertRaises(AssertionError):
                module['canonical_epoch'](Path('/repo'), 'ignored/a3/common-native-epoch-v1')

    def test_epoch_scope_ancestors_descendants_and_escape_refuse(self):
        for value in ('/repo/ignored/a3/fresh', 'ignored/a3', 'ignored/a3/fresh/nested',
                      'ignored/a3/common-native-epoch-v1/new', 'ignored/other',
                      'ignored/a3/../fresh', 'ignored/a3/./fresh'):
            for module in (RUNNER, PRODUCER):
                with self.assertRaises(AssertionError): module['canonical_epoch'](Path('/repo'), value)

    def test_raw_build_and_review_must_match_the_exact_new_root(self):
        epoch = Path('/repo/ignored/a3/fresh-canonical-epoch')
        for suffix in ('raw', 'build', 'build-review/binding.json'):
            for wrong in (Path('/repo/ignored/a3/other') / suffix,
                          Path('/repo/ignored/a3/common-native-epoch-v1') / suffix,
                          epoch, Path('/repo/target') / suffix):
                for module in (RUNNER, PRODUCER):
                    with self.assertRaises(AssertionError): module['canonical_epoch_member'](epoch, wrong)

    def test_unactivated_scope_refuses_before_any_read(self):
        function = RUNNER['canonical_verifier_product']
        self.assertIsNone(function.__globals__['CANONICAL_PRODUCER_SHA'])
        with self.assertRaisesRegex(SystemExit, 'awaits a reviewed final producer'):
            function(None, None, None, None, None, None, None)

    def test_explicit_dispatch_and_no_fallback_after_refusal(self):
        function = RUNNER['admitted_verifier_product']; namespace = function.__globals__
        keys = ('canonical_verifier_product', 'fresh_verifier_product', 'verifier_product')
        saved = {key: namespace[key] for key in keys}; calls = []
        def selected(name, fail=False):
            def call(*args):
                calls.append((name, args[1]['scope']))
                if fail: raise AssertionError('selected reader refuses')
                return name
            return call
        try:
            for key in keys: namespace[key] = selected(key)
            for scope, expected in (
                ('direct-rustc-canonical-input-epoch', keys[0]),
                ('fresh-verifier-build-and-archive-epoch', keys[1]),
                ('retained-verifier-build-and-fresh-archive-epoch', keys[2]),
            ):
                self.assertEqual(function(None, {'scope': scope}, None, None, None, None, None), expected)
            self.assertEqual(len(calls), 3)
            namespace[keys[0]] = selected(keys[0], True)
            with self.assertRaises(AssertionError):
                function(None, {'scope': 'direct-rustc-canonical-input-epoch'}, None, None, None, None, None)
            self.assertEqual(len(calls), 4)
        finally:
            namespace.update(saved)

if __name__ == '__main__':
    unittest.main()
