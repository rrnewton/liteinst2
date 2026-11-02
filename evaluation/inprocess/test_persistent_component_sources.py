"""Explicit source-qualification guard tests; no component/native execution.

Run this file after installation. Expected current/historical production facts
are literal, and historical bytes come independently from their Git objects.
No expectation is copied from the qualification helper or its inverse table.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SELECTED = ROOT / 'tools/page-entry/selected'
sys.path.insert(0, str(HERE))
import persistent_component_sources as subject

FACTS = {
    'persistent_group_compact.c': (
        47353, '7dc4e4af1bd9f20bdc930f249e19979c61c04ec971fb3a130f4a3c080a37214e',
        26769, '1ac0af7a2bb1a3621bd43754fac1173b0cf5ff16658c0be7b160088929ba5d2b'),
    'persistent_group_compact.h': (
        7608, '69586fc20db5ff1496b196ac006f54f7a9c0ce66eb7983791f6ecd84111ee96c',
        4113, '79d7b396a80bd426bc4e02721e1c6ed1cfa38c74617d470ef534e8bd6a2ddf32'),
    'persistent_group_plan.c': (
        59591, '049be2a5a7d9447fe23e93383be3b01f0086e808c30a01cf910fe4382272cb15',
        43305, '115fe0e64b7919674877bf7782c8bdc11bb3581fe41d766f373303fc4a7fb53b'),
    'persistent_group_plan.h': (
        12813, '1a8a0273efa7981bb11ecf33f5f1761ecce48095f17ca00055c25face81cfc5f',
        8235, '062c387640b35fba6b2634bc048eb627fd7ed51fb5e4b15cd25f66c8509a52f9'),
    'persistent_retained_two.inc': (
        12614, '4481e131f5de1f99b0f703626f38e0c2e5f6a8e3862a9f8cbc19295d8db409ed',
        12064, '905a1953f33fbc766ebbd058bc24dd64dad2793d5bc8e234b8f19ea406abe4d8'),
}
CALLERS = {'group': 'persistent_group.py', 'resident': 'persistent_resident.py',
           'retained': 'persistent_retained_two.py'}


def observed(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class ComponentSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = {}
        cls.historical = {}
        for name, (size, digest, old_size, old_digest) in FACTS.items():
            raw = (SELECTED / name).read_bytes()
            if observed(raw) != dict(bytes=size, sha256=digest):
                raise AssertionError('literal current source fact: ' + name)
            rev = ('fa8e1be006da964eb64118717b56fc21ca48bf4e' if name.endswith('.inc')
                   else '021da7f0e6395e27d348970c50ef7c23859c7995')
            row = subprocess.run(['git', '-c', 'index.threads=1', '-c', 'core.preloadIndex=false',
                                  '-C', str(ROOT), 'show', rev + ':tools/page-entry/selected/' + name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True)
            if row.stderr or observed(row.stdout) != dict(bytes=old_size, sha256=old_digest):
                raise AssertionError('literal historical Git source fact: ' + name)
            cls.current[name], cls.historical[name] = raw, row.stdout
        cls.expected = {}
        for profile, filename in CALLERS.items():
            tree = ast.parse((HERE / filename).read_bytes())
            nodes = [n for n in tree.body if isinstance(n, ast.Assign) and
                     any(isinstance(t, ast.Name) and t.id == 'COMPONENT_INPUTS' for t in n.targets)]
            if len(nodes) != 1:
                raise AssertionError('one original caller fixture table')
            cls.expected[profile] = ast.literal_eval(nodes[0].value)
            for name, value in cls.expected[profile].items():
                raw = cls.historical[name] if name in FACTS else (SELECTED / name).read_bytes()
                if observed(raw) != value:
                    raise AssertionError('original source-owned fixture or historical target: ' + name)

    def selected(self, directory, profile, historical=False):
        for name in self.expected[profile]:
            raw = (self.historical[name] if historical else self.current[name]) if name in FACTS else (SELECTED / name).read_bytes()
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return directory

    @staticmethod
    def pin(path):
        return Path(path).resolve(strict=True)

    def test_current_profiles_keep_exact_input_and_historical_facts(self):
        for profile in CALLERS:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                directory = self.selected(Path(temporary), profile)
                receipt = {}
                result = subject.qualify(self.expected[profile], directory, self.pin, receipt, profile)
                expected = {name: observed(self.current[name]) if name in FACTS else value
                            for name, value in self.expected[profile].items()}
                self.assertEqual(result, expected)
                self.assertEqual(receipt['component_source']['compiled_inputs'], expected)
                self.assertEqual(receipt['component_source']['historical_targets'], self.expected[profile])
                self.assertEqual(receipt['component_source']['reconstructed'],
                                 {name: observed(self.historical[name]) for name in expected if name in FACTS})
                self.assertEqual(receipt['component_source']['profile'], 'current-legacy-components-v1')
                self.assertIs(receipt['component_source']['component_execution_credit'], False)

    def test_historical_profiles_remain_exact(self):
        for profile in CALLERS:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                directory = self.selected(Path(temporary), profile, historical=True)
                receipt = {}
                self.assertEqual(subject.qualify(self.expected[profile], directory, self.pin, receipt, profile),
                                 self.expected[profile])
                self.assertEqual(receipt['component_source']['profile'], 'historical-legacy-components-v1')
                self.assertEqual(receipt['component_source']['compiled_inputs'], self.expected[profile])
                self.assertEqual(receipt['component_source']['reconstructed'], {})
                self.assertIs(receipt['component_source']['component_execution_credit'], False)

    def test_mixed_current_and_historical_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.selected(Path(temporary), 'group')
            (directory / 'persistent_group_plan.c').write_bytes(self.historical['persistent_group_plan.c'])
            receipt = {}
            with self.assertRaisesRegex(ValueError, 'whole exact current component roster'):
                subject.qualify(self.expected['group'], directory, self.pin, receipt, 'group')
            self.assertNotIn('component_source', receipt)

    def test_unknown_production_and_fixture_bytes_refuse(self):
        for name in ('persistent_group_plan.c', 'tests/persistent_group/metadata.c'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = self.selected(Path(temporary), 'group')
                path = directory / name
                path.write_bytes(path.read_bytes() + b'\n')
                receipt = {}
                with self.assertRaisesRegex(ValueError, 'whole exact current component roster'):
                    subject.qualify(self.expected['group'], directory, self.pin, receipt, 'group')
                self.assertNotIn('component_source', receipt)

    def test_changed_historical_caller_target_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.selected(Path(temporary), 'group')
            expected = copy.deepcopy(self.expected['group'])
            expected['persistent_group_plan.c']['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'original caller source target remains byte-exact'):
                subject.qualify(expected, directory, self.pin, {}, 'group')

    def test_corrupt_inverse_cannot_reconstruct_original(self):
        data = json.loads((HERE / 'persistent_component_sources.json').read_bytes())
        for name, raw in self.current.items():
            with self.subTest(name=name):
                row = copy.deepcopy(data['sources'][name])
                self.assertEqual(subject.original(raw, row), self.historical[name])
                row['inverse'][0][2] += 'x'
                with self.assertRaisesRegex(ValueError, 'exact original pinned whole component source'):
                    subject.original(raw, row)

    def test_corrupt_data_whole_is_refused_before_source_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.selected(Path(temporary) / 'selected', 'group')
            altered = Path(temporary) / 'inverse.json'
            altered.write_bytes((HERE / 'persistent_component_sources.json').read_bytes() + b'\n')
            receipt = {}
            with patch.object(subject, 'DATA', altered):
                with self.assertRaisesRegex(ValueError, 'exact source-owned component inverse table'):
                    subject.qualify(self.expected['group'], directory, self.pin, receipt, 'group')
            self.assertNotIn('component_source', receipt)


if __name__ == '__main__':
    unittest.main(verbosity=2)
