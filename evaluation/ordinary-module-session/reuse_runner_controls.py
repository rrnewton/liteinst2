#!/usr/bin/env python3
"""Fabricated qualification-control tests; no native execution evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('_reuse_runner_controls', Path(__file__).resolve().with_name('owners.py'))
assert spec and spec.loader
owners = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owners)

GEOMETRY = dict(csv_va=4096, csv_length=126, length_va=4224, length_length=41)


class Run:
    def __init__(self, failure=None, uncertain=None):
        self.raw = Path('/qualification')
        self.cpus = [2, 4, 6]
        self.result = {'prerequisites': {'reuse': dict(status='UNRUN', attempts=0)}}
        self.events = []
        self.requests = []
        self.outcomes = []
        self.at = 0
        self.failure, self.uncertain = failure, uncertain
        self.m = {'reuse_output': SimpleNamespace(check=self.check)}

    def unchanged(self):
        self.events.append(('unchanged',))

    def request(self, directory, argv, cap):
        value = dict(argv=list(argv), file_bytes=cap)
        self.events.append(('request', directory.name, copy.deepcopy(value)))
        self.requests.append(value)
        return value

    def plan_bounded(self, name, directory, request):
        self.events.append(('plan', name, directory.name, copy.deepcopy(request)))

    def freeze(self, path, value):
        self.events.append(('freeze', path.name))
        if path.name == 'reuse-plan.json':
            self.frozen_plan = copy.deepcopy(value)
        else:
            self.outcomes.append(copy.deepcopy(value))

    def bounded(self, name, directory, request):
        self.at += 1
        self.events.append(('launch', name))
        if self.at == self.uncertain:
            raise RuntimeError('unknown custody')
        return (1 if self.at == self.failure else 0), b'actual stdout', b''

    def check(self, stdout, stderr, **kwargs):
        assert stdout == b'actual stdout' and stderr == b''
        assert kwargs['geometry'] is GEOMETRY and kwargs['cpus'] == (2, 4)
        self.events.append(('parse', kwargs['k'], kwargs['direction']))
        return dict(totals={'calls': kwargs['k']+5}, pid=100, worker_tid=101)


def gate(run):
    recipe = SimpleNamespace(MIB=1048576, bounded_ready=lambda r, req: r.events.append(('ready',)))
    owners.reuse_gate(run, Path('/application'), GEOMETRY, Path('/candidate'), Path('/trusted'), recipe)


class Controls(unittest.TestCase):
    def test_owner_default_and_reuse_profiles_have_distinct_fixed_stages(self):
        owner = owners.profile_spec('owner')
        reuse = owners.profile_spec('reuse')
        prefix = tuple('tool-'+n for n in ('cc1','collect2','as','ld')) + (
            'module-build','module-symbols','csv_fields-disassembly','strnlen-disassembly',
            'application-build','application-caller-disassembly','application-caller-symbols',
            'ordinary-build','ordinary-list','ordinary-controls','python-controls')
        self.assertEqual(owner['stages'], prefix+tuple(f'owner-{i}-outer' for i in range(1,5)))
        self.assertEqual(reuse['stages'], prefix+('reuse-python-controls','reuse-runner-controls')+tuple(f'reuse-{i}-outer' for i in range(1,5)))
        self.assertEqual(owner['case_pass'], 'OWNER_FUNCTIONAL_PASS')
        self.assertEqual(owner['qualification_pass'], 'OWNER_QUALIFICATION_PASS')
        self.assertEqual(reuse['case_pass'], 'REUSE_FUNCTIONAL_PASS')
        self.assertEqual(reuse['qualification_pass'], 'REUSE_QUALIFICATION_PASS')
        for value in ('', 'OWNER', 'state', 'schedule', None):
            with self.assertRaises(AssertionError): owners.profile_spec(value)

    def test_all_four_exact_requests_are_frozen_before_first_launch(self):
        run = Run(); gate(run)
        first = next(i for i,e in enumerate(run.events) if e[0] == 'launch')
        self.assertEqual(sum(e[0]=='request' for e in run.events[:first]),4)
        self.assertEqual(sum(e[0]=='plan' for e in run.events[:first]),4)
        self.assertIn(('freeze','reuse-plan.json'),run.events[:first])
        expected = [(k,d) for k in (10,1000) for d in ('csv-length','length-csv')]
        for request,(k,d) in zip(run.requests,expected):
            self.assertEqual(request,dict(argv=[Path('/application'),'normal-module-session-reuse',Path('/candidate'),Path('/trusted'),4096,126,4224,41,k,d],file_bytes=1048576))
        self.assertEqual([(r['k'],r['direction']) for r in run.frozen_plan],expected)
        self.assertTrue(all(r['status']=='UNRUN' and r['attempts']==0 for r in run.frozen_plan))
        self.assertEqual(run.at,4)
        self.assertEqual(len(run.outcomes),4)
        self.assertTrue(all(r['status']=='REUSE_FUNCTIONAL_PASS' and r['attempts']==1 for r in run.outcomes))
        self.assertEqual(run.result['prerequisites']['reuse']['status'],'REUSE_FUNCTIONAL_PASS')
        with self.assertRaises(AssertionError): gate(run)
        self.assertEqual(run.at,4)

    def test_closed_failure_is_retained_and_each_later_case_runs_once(self):
        run = Run(failure=2)
        with self.assertRaises(AssertionError): gate(run)
        gate_result = run.result['prerequisites']['reuse']
        self.assertEqual(gate_result['status'],'FAILED')
        self.assertEqual(gate_result['attempts'],1)
        self.assertEqual(run.at,4)
        self.assertEqual([r['status'] for r in run.outcomes],['REUSE_FUNCTIONAL_PASS','FAILED','REUSE_FUNCTIONAL_PASS','REUSE_FUNCTIONAL_PASS'])
        self.assertEqual([r['attempts'] for r in run.outcomes],[1,1,1,1])
        self.assertNotIn('totals',run.outcomes[1])
        self.assertEqual(sum(e[0]=='parse' for e in run.events),3)

    def test_uncertain_custody_preserves_remaining_unrun(self):
        run = Run(uncertain=2)
        with self.assertRaisesRegex(RuntimeError,'unknown custody'): gate(run)
        rows = run.result['prerequisites']['reuse']['rows']
        self.assertEqual([r['status'] for r in rows],['REUSE_FUNCTIONAL_PASS','FAILED','UNRUN','UNRUN'])
        self.assertEqual([r['attempts'] for r in rows],[1,1,0,0])
        self.assertEqual(run.at,2)
        self.assertEqual(len(run.outcomes),1)
        self.assertTrue(all(r['attempts']==0 for r in run.frozen_plan))


if __name__ == '__main__':
    unittest.main()
