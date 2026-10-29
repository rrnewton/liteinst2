#!/usr/bin/env python3
"""Fabricated profile-seam controls; never start a campaign or application."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / 'evaluation/ordinary-leaf-set-session'


def load(name, path):
    spec = importlib.util.spec_from_file_location('_whole_control_' + name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


P = load('profile', HERE / 'profile.py')
C = load('catalog', HERE / 'catalog.py')
T = load('old_controls', OLD / 'runner_controls.py')
R, D, O = T.runner, T.producer, T.catalog
W = load('wrapper', HERE / 'reproduce.py')
Q = load('producer_wrapper', HERE / 'produce.py')


def leaves():
    return [dict(leaf, policy=C.POLICIES[i]) for i, leaf in enumerate(T.leaves())]


def plan(n=3):
    case = C.case(n, 10, 'budget')
    index = next(r['index'] for r in C.references() if (r['n'], r['k'], r['kind']) == (n, 10, 'budget'))
    value = dict(P.whole_binding().fields(), index=index, n=n, k=10, kind='budget', name=case['name'],
                 epochs=520, data_sha256=hashlib.sha256(case['data']).hexdigest(), cpus=[2, 4, 6],
                 table=leaves()[:n], caller=dict(extent=32, continuation=17),
                 binary='/not-executed/bin', candidate='/not-executed/candidate', trusted='/not-executed/trusted')
    value['argv'] = [value['binary'], 'normal-leaf-set-session', value['candidate'], value['trusted'], '10', '520', str(n)]
    for leaf in value['table']:
        value['argv'] += [str(leaf['function_id']), leaf['operation'], str(leaf['elf_va']), str(leaf['extent']), leaf['policy']]
    return value


class Controls(unittest.TestCase):
    def refuses(self, fn):
        with self.assertRaises((AssertionError, KeyError, ValueError, TypeError)):
            fn()

    def test_fixed_bindings_and_default_catalog_are_literal(self):
        binding = P.whole_binding()
        self.assertEqual(binding.policies, ('certified', 'whole', 'whole', 'whole'))
        self.assertEqual(binding.status, 'LEAF_SET_WHOLE_FUNCTIONAL_PASS')
        with self.assertRaises(AttributeError): binding.identity = 'other'
        for field in binding._fields:
            bad = binding._replace(**{field: ('whole',) * 4 if field == 'policies' else 'wrong'})
            self.refuses(lambda bad=bad: P.profile_fields(bad))
        self.assertEqual(hashlib.sha256((OLD / 'catalog.py').read_bytes()).hexdigest(), D.CATALOG)
        self.assertEqual(D.CATALOG, P.OLD_CATALOG)
        self.assertEqual(R.PASS, 'LEAF_SET_FUNCTIONAL_PASS')
        for fn in (R._main, R.freeze_campaign, R.campaign, D._main):
            self.assertIsNone(inspect.signature(fn).parameters['binding'].default)
        with mock.patch.object(R.time, 'monotonic', return_value=123), mock.patch.object(R, '_main', return_value=7) as main:
            self.assertEqual(R.main(), 7); main.assert_called_once_with(123)
        with mock.patch.object(D, '_main', return_value=8) as main:
            self.assertEqual(D.main(), 8); main.assert_called_once_with()

    def test_whole_catalog_keeps_all_24_and_120_bytes_and_counts(self):
        self.assertEqual(C.references(), O.references()); self.assertEqual(C.catalog(), O.catalog())
        self.assertEqual((len(C.references()), len(C.catalog())), (24, 120))
        self.assertEqual((C.OPERATIONS, C.SYMBOLS, C.FUNCTION_IDS, C.LITERALS),
                         (O.OPERATIONS, O.SYMBOLS, O.FUNCTION_IDS, O.LITERALS))
        records = calls = 0
        for row in C.references():
            case = C.case(row['n'], row['k'], row['kind'])
            self.assertEqual(case, O.case(row['n'], row['k'], row['kind']))
            records += len(case['records']); calls += row['n'] * len(case['records'])
        self.assertEqual((records, calls), (4064, 10160))
        self.assertEqual(hashlib.sha256((HERE / 'catalog.py').read_bytes()).hexdigest(), P.CATALOG)
        self.assertEqual(O.POLICIES, ('certified', 'whole', 'certified', 'certified'))

    def test_plan_profile_hash_paths_and_policies_before_import(self):
        binding = P.whole_binding(); good = plan()
        binding.check_plan(good); D.plan_arguments(good, C, T.checker)
        for field in binding.fields():
            for value in (None, 'wrong', []):
                bad = copy.deepcopy(good); bad[field] = value
                self.refuses(lambda bad=bad: binding.check_plan(bad))
            bad = copy.deepcopy(good); del bad[field]
            self.refuses(lambda bad=bad: binding.check_plan(bad))
        self.refuses(lambda: D.plan_arguments(good, O, T.checker))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pins = {}
            for relative in binding.required_sources():
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
                data = (ROOT / relative).read_bytes(); path.write_bytes(data)
                pins[str(path)] = hashlib.sha256(data).hexdigest()
            binding.check_sources(root, pins)
            for relative in binding.required_sources():
                bad = dict(pins); del bad[str(root / relative)]
                self.refuses(lambda bad=bad: binding.check_sources(root, bad))
            for relative in (binding.catalog_path, P.OLD + 'catalog.py'):
                bad = dict(pins); bad[str(root / relative)] = '0' * 64
                self.refuses(lambda bad=bad: binding.check_sources(root, bad))
            request = root / 'request.json'; request.write_text(json.dumps(dict(good, pins=pins)))
            digest = hashlib.sha256(request.read_bytes()).hexdigest()
            with mock.patch.object(Q, 'ROOT', root), mock.patch.object(Q, 'HERE', root / P.PREFIX), mock.patch.object(Q, 'SHARED', root / P.OLD / 'produce.py'):
                self.assertEqual(Q.authenticate(request, digest)['pins'], pins)
                self.refuses(lambda: Q.authenticate(request, '0' * 64))
                (root / binding.catalog_path).write_bytes(b'changed')
                self.refuses(lambda: Q.authenticate(request, digest))

    def test_table_policy_guard_covers_va_order_and_unselected_last(self):
        raw = leaves(); raw[0]['elf_va'], raw[3]['elf_va'] = raw[3]['elf_va'], raw[0]['elf_va']
        for n in range(1, 5):
            R.selected_table(raw, 4, C, T.checker)  # Same mandatory all-four preflight as main.
            table = R.selected_table(raw, n, C, T.checker)
            self.assertEqual([row['elf_va'] for row in table], sorted(row['elf_va'] for row in table))
            self.assertEqual({row['operation']: row['policy'] for row in table}, dict(zip(C.OPERATIONS[:n], C.POLICIES[:n])))
        for field, value in (('policy', 'certified'), ('function_id', 33), ('operation', 'length'), ('extent', 81), ('returns', (48,))):
            bad = copy.deepcopy(raw); bad[3][field] = value
            self.refuses(lambda bad=bad: R.selected_table(bad, 4, C, T.checker))
        value = plan(4); value['table'][3]['policy'] = 'certified'
        self.refuses(lambda: D.plan_arguments(value, C, T.checker))

    def test_receipt_identity_precedes_custody_release_and_closed_failure(self):
        binding = P.whole_binding(); fields = binding.fields(); actual = b'actual application stream'
        case = dict(name='fixture', n=2, k=10)
        checked = dict(rows={'READY': [dict(pid=123)]})
        result = dict(fields, normal_reaps=1, rescue=False, cleanup_error=None, child_pid=123, child_exit=0,
                      stdout_sha256=T.recipe.pin(actual)['sha256'], stderr_sha256=T.recipe.pin(b'')['sha256'],
                      index=0, name='fixture', n=2, k=10, status='PASS')
        def state():
            run = object.__new__(T.recipe.Run); run.safe = False
            run.budget = T.recipe.EvidenceBudget(); run.budget.reserve(8192)
            return run
        def accept(run, request, response, code=0):
            R.confirm_profile_custody(binding, request, run, response, code, json.dumps(response).encode(), b'',
                                      actual, b'', checked, case, 0, T.recipe.pin)
        for where in ('plan', 'result'):
            for key in fields:
                run = state(); request = dict(fields); response = copy.deepcopy(result)
                (request if where == 'plan' else response)[key] = 'wrong'
                self.refuses(lambda: accept(run, request, response))
                self.assertFalse(run.safe); self.assertTrue(run.budget.active); self.assertEqual(run.budget.held, 8192)
        run = state(); accept(run, fields, result)
        self.assertTrue(run.safe); self.assertFalse(run.budget.active)
        failed = dict(result, status='FAILED', child_exit=1)
        run = state(); accept(run, fields, failed, 1)
        self.assertTrue(run.safe); self.assertFalse(run.budget.active); self.assertEqual(failed['status'], 'FAILED')
        self.refuses(lambda: R.producer_join(failed, 1, actual, b'', dict(checked, expected_exit=0), case, T.recipe.pin))
        for key, value in (('child_pid', 124), ('stdout_sha256', '0' * 64), ('rescue', True)):
            run = state(); self.refuses(lambda: accept(run, fields, dict(result, **{key: value})))
            self.assertFalse(run.safe); self.assertTrue(run.budget.active)
        run = state(); run.budget.exceeded = True
        self.refuses(lambda: accept(run, fields, result)); self.assertFalse(run.safe); self.assertTrue(run.budget.active)

    def test_bootstrap_deadline_source_locality_and_inventory(self):
        order = []; binding = P.whole_binding()
        pins = {str(ROOT / name): hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in P.SOURCES}
        def auth(args): order.append('authenticate'); return pins
        def imported(name, path, pins):
            self.assertEqual(pins[str(HERE / 'catalog.py')], P.CATALOG)
            if path == W.HERE / 'profile.py':
                order.append('profile'); return SimpleNamespace(whole_binding=lambda: binding)
            self.assertEqual(path, W.SHARED); order.append('shared')
            return SimpleNamespace(_main=lambda started, **kwargs: (started, kwargs['binding']))
        argv = ['reproduce.py', '--revision', 'a' * 40, '--reservation-tag', 'fixture', '--raw', '/unused',
                '--toolchain', '/unused', '--user-home', '/unused', '--cargo-home', '/unused']
        with mock.patch.object(W.sys, 'argv', argv), mock.patch.object(W.time, 'monotonic', return_value=123), \
             mock.patch.object(W, 'authenticate', side_effect=auth), mock.patch.object(W, 'load', side_effect=imported):
            self.assertEqual(W.main(), (123, binding))
        self.assertEqual(order, ['authenticate', 'profile', 'shared'])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'source.py'; path.write_text('raise RuntimeError("must not import")\n')
            for wrapper in (W, Q):
                with mock.patch.object(wrapper.importlib.util, 'spec_from_file_location') as spec:
                    self.refuses(lambda: wrapper.load('fixture', path, {str(path): '0' * 64}))
                    spec.assert_not_called()
        self.assertEqual(set(P.CONTROLS), {name for name in dir(Controls) if name.startswith('test_')})
        self.assertEqual((len(P.CONTROLS), len(R.APP_CONTROLS), len(R.SDK_CONTROLS)), (6, 16, 18))
        self.assertEqual((len(T.recipe.PYTHON_CONTROLS), len(R.CHECKER_CONTROLS), len(R.RUNNER_CONTROLS), len(R.REFERENCE_CONTROLS)), (26, 14, 9, 6))


if __name__ == '__main__':
    unittest.main()
