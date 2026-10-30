#!/usr/bin/env python3
"""Fabricated campaign controls; none is a process/native custody witness."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import ast
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


R = load('_campaign_under_test', HERE/'reproduce.py')
Receipt = load('_campaign_receipt_controls', HERE/'receipt_controls.py')
Producer = load('_campaign_producer_controls', HERE/'producer_controls.py')
P, S, C = Producer.P, Producer.S, Producer.C


def fixture_result():
    _, rows, originals, installed = R.catalog(S, C)
    stages = [dict(name=n, status='UNRUN', reason='UN', attempts=0) for n in R.stage_names(Producer.R.malformed_frames())]
    result = dict(revision='f'*40, status='FAILED', custody_closed=True, retention_verified=True,
        originals=originals, installed=installed, planned_stages=stages,
        controls=[dict(name=n,status='UNRUN',reason='UN') for n,_ in Producer.R.malformed_frames()],
        native=dict(status='UNRUN',reason='UN'), references={n:dict(status='UNRUN',pin=None) for n in ('sources','tools','native')})
    result['qualifications']=R.qualifications(installed)
    result['overall']=dict(profile=R.PROFILE,revision=result['revision'],status=result['status'])
    return rows, result


class Controls(unittest.TestCase):
    # Separate campaign controls exercise actual scheduling and join helpers.
    def test_fixed_five_qualifications_all_32_cases_and_request_freeze(self):
        cases, catalog, originals, installed = R.catalog(S,C)
        self.assertEqual(len(originals),32); self.assertEqual(len(installed),320)
        self.assertEqual(sum(len(c['records']) for c in cases),10537)
        for row in installed:
            self.assertEqual(row['case'],installed.index(row)%32)
            self.assertEqual(row['status'],'UNRUN'); self.assertEqual(row['attempts'],0)
        self.assertEqual(len(R.stage_names(Producer.R.malformed_frames())),395)
        for mutation in (installed[:-1], installed+[installed[-1]], list(reversed(installed))):
            with self.assertRaises(AssertionError): R.qualifications(mutation)
        module = ast.parse((HERE/'reproduce.py').read_text())
        freeze = next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='freeze_subjects')
        calls = [n.func.attr for n in ast.walk(freeze) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
        self.assertIn('plan_bounded',calls); self.assertNotIn('bounded',calls)
        self.assertEqual([r['accepted'] for r in catalog], [[dict(hex=r.payload.hex(),fields=r.fields) for r in c['records']] for c in cases])

    def test_exact_source_native_geometry_and_original_receipt_joins(self):
        checked = dict(results=[dict(id=1,length=3,fnv=99,fields=2,packed=(3<<32)|2)])
        original = dict(status='CALL_PAIR_ORIGINAL_SCALAR_PASS',results=[[1,3,99,2,(3<<32)|2]])
        R.compare_reference(checked,original)
        for i in range(5):
            bad=copy.deepcopy(original);bad['results'][0][i]+=1
            with self.assertRaises(AssertionError):R.compare_reference(checked,bad)
        for value in ('PASS','NATIVE_PASS','CALL_PAIR_SESSION_FUNCTIONAL_PASS'):
            bad=dict(original,status=value)
            with self.assertRaises(AssertionError):R.compare_reference(checked,bad)
        source=(HERE/'reproduce.py').read_text(); tree=ast.parse(source)
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        calls=[n for n in ast.walk(main) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='accept_native']
        self.assertEqual(len(calls),1)
        expected=next(k.value for k in calls[0].keywords if k.arg=='expected')
        self.assertEqual({k.arg for k in expected.keywords},{'revision','protocol_pin','source_pins','tool_pins','module_pin','application_pin','geometry'})
        # The real inventory helper must retain the native owner's whole domain,
        # even when it is broader than the campaign's original explicit tuple.
        native = set(Receipt.L.COMMON + Receipt.L.EXTRA['call-pair-original-native'])
        self.assertIn('evaluation/ordinary-leaf-set-native/README.md', native)
        omitted = None
        def git(*args):
            self.assertEqual(args[:3], ('ls-files', '-z', '--'))
            if len(args) == 4:
                names = [args[3]+'/fabricated.py']
            else:
                names = list(args[args.index(':(glob)**/Cargo.toml')+1:])+['src/fabricated.rs', 'Cargo.toml']
            return ('\0'.join(sorted(set(names)-{omitted}))+'\0').encode()
        extra = {'fixture': 'evaluation/fabricated-extra.py'}
        required, names = R.source_inventory(git, Producer.R, Receipt.L, extra)
        self.assertTrue(native | {R.NATIVE_LAUNCHER} <= required <= set(names))
        self.assertTrue(set(R.REQUIRED_NATIVE) | set(R.HELPER_PINS) | set(Producer.R.MODULES.values()) | set(extra.values()) <= required)
        for omitted in sorted(native | {R.NATIVE_LAUNCHER}):
            with self.assertRaises(AssertionError): R.source_inventory(git, Producer.R, Receipt.L, extra)

    def test_actual_pid_stream_hash_json_profile_before_custody_release(self):
        plan, _, _ = Producer.plan(); result=dict(child_pid=12)
        row=['READY',P.call_pair_binding().application_profile]
        row += list(map(str,[10,520,10,2,64,2048,4,1,0x63700001,12,12,13,2,4,8192]))
        data=(','.join(row)+'\nFAILED,actual retained bytes\n').encode()
        self.assertEqual(R.ready_identity(P,plan,result,data),dict(rows=dict(READY=[dict(pid=12)])))
        for index,value in ((1,'normal-module-session-v1'),(2,'1000'),(11,'13'),(12,'13'),(13,'12'),(14,'4'),(15,'2'),(16,'0')):
            bad=list(row);bad[index]=value
            with self.assertRaises(AssertionError):R.ready_identity(P,plan,result,(','.join(bad)+'\n').encode())
        with self.assertRaises(AssertionError):R.ready_identity(P,plan,result,','.join(row).encode())
        with self.assertRaises(AssertionError):R.ready_identity(P,plan,dict(child_pid=99),data)

    def test_closed_failure_continues_unknown_custody_leaves_unrun(self):
        def simulate(unsafe=False, active=False, fail=True):
            saved=[]
            run=SimpleNamespace(safe=True,budget=SimpleNamespace(active=False,room=lambda n:None),raw=Path('/fabricated'),
                unchanged=lambda:None,freeze=lambda p,v,**kw:saved.append(copy.deepcopy(v)))
            row=dict(status='UNRUN',attempts=0,reason='UN'); stages={'one':dict(name='one',status='UNRUN',attempts=0,reason='UN')}
            recipe=SimpleNamespace(bounded_ready=lambda *a,**kw:None,bounded_growth=lambda *a,**kw:1048576)
            def closed(*args,**kwargs):
                stages['one'].update(status='FAILED',attempts=1)
                return 1,b'',b'actual failure'
            def action(*args):
                run.safe=not unsafe;run.budget.active=active
                if fail:raise AssertionError('functional refusal')
                return dict(status='accepted')
            with patch.object(R,'bounded',closed):
                if unsafe or active:
                    with self.assertRaises(AssertionError):R.subject(run,recipe,stages,row,'one',{'one':(Path('/fabricated/io'),{},None)},action)
                else:R.subject(run,recipe,stages,row,'one',{'one':(Path('/fabricated/io'),{},None)},action)
            self.assertEqual(row['status'],'FAILED' if fail else 'PASS')
            self.assertEqual(bool(saved),not(unsafe or active))
            return row
        simulate();simulate(unsafe=True);simulate(active=True);simulate(fail=False)
        _,result=fixture_result();result['installed'][0].update(status='FAILED',attempts=1)
        qs=R.qualifications(result['installed'])
        self.assertEqual(qs[0]['status'],'FAILED');self.assertEqual(qs[0]['unrun'],63)
        self.assertTrue(all(q['status']=='UNRUN' for q in qs[1:]))

    def test_history_pressure_and_deadlines_remain_literal(self):
        cases,_,_,_=R.catalog(S,C)
        self.assertEqual(len(cases[30]['records']),48);self.assertEqual(len(cases[31]['records']),2048)
        source=(HERE/'reproduce.py').read_text();tree=ast.parse(source)
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        plan=next(n for n in ast.walk(main) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='dict'
                  and {'arm_ns','period_ns','shutdown_ns'} <= {k.arg for k in n.keywords})
        values={k.arg:ast.literal_eval(k.value) for k in plan.keywords if k.arg in ('epochs','resident_banks','arm_ns','period_ns','shutdown_ns','outer_seconds','producer_seconds','cpu_seconds','wall_seconds','owner_seconds')}
        self.assertEqual(values,dict(epochs=520,resident_banks=3,arm_ns=2000000,period_ns=10000000,shutdown_ns=2000000000,outer_seconds=7200,producer_seconds=15,cpu_seconds=20,wall_seconds=30,owner_seconds=55))

    def test_exact_control_union_budget_first_pins_and_public_rows(self):
        self.assertEqual(len(R.SDK_CONTROLS),48);self.assertEqual(len(R.CORE_CONTROLS),8)
        self.assertIn('frontend_native::always_on::normal::call_pair::tests::compact_journal_validation_keeps_all_words_at_every_phase',R.SDK_CONTROLS)
        for wanted in (R.SDK_CONTROLS,R.CORE_CONTROLS):
            self.assertEqual(R.selected(list(wanted)+['unrelated::control'],wanted),wanted)
            for missing in wanted:
                with self.assertRaises(AssertionError):R.selected([n for n in wanted if n!=missing],wanted)
            for prefix in {n.rsplit('::',1)[0] for n in wanted}:
                with self.assertRaises(AssertionError):R.selected(list(wanted)+[prefix+'::unexpected'],wanted)
        rows,result=fixture_result();out,summary=R.projection(result,'a'*64,'b'*64,'c'*64)
        self.assertEqual(len(out.splitlines()),763);self.assertLess(len(out)+len(summary),80000)
        for family in ('planned_stages','originals','controls','installed'):
            bad=copy.deepcopy(result);bad[family].pop()
            with self.assertRaises(AssertionError):R.projection(bad,'a'*64,'b'*64,'c'*64)
        for key in ('custody_closed','retention_verified'):
            bad=copy.deepcopy(result);bad[key]=False
            with self.assertRaises(AssertionError):R.projection(bad,'a'*64,'b'*64,'c'*64)
        lines=[]
        for cls,names in (('Controls',R.RUNNER_CONTROLS),('ReceiptControls',R.RUNNER_CONTROLS),('ProducerControls',P.CONTROLS)):
            lines.extend(n+' (__main__.'+cls+'.'+n+') ... ok' for n in sorted(names))
        stderr=('\n'.join(lines)+'\n\n----------------------------------------------------------------------\nRan 17 tests in 0.001s\n\nOK\n').encode()
        R.runner_census(b'',stderr,P.CONTROLS)
        for name in (*R.RUNNER_CONTROLS,*P.CONTROLS):
            with self.assertRaises(AssertionError):R.runner_census(b'',b'\n'.join(line for line in stderr.split(b'\n') if not line.startswith(name.encode()+b' ')),P.CONTROLS)

        # Exercise the real shared census: every old ordinary control and each
        # newly required accuracy control must execute in this public recipe.
        leaf = load('_callpair_roster_leaf', R.ROOT/'evaluation/ordinary-leaf-set-session/reproduce.py')
        recipe = load('_callpair_roster_recipe', R.ROOT/'evaluation/ordinary-module-session/reproduce.py')
        single = load('_callpair_roster_single', R.ROOT/recipe.MODULES['single'])
        module = load('_callpair_roster_module', R.ROOT/recipe.MODULES['module'])
        modules = {'single': single, 'module': module}
        prior = (tuple(single.SESSION) + tuple(single.TRACE) + recipe.CONSUMER +
                 tuple(module.MODULE_TESTS) + tuple(module.CSV_TESTS) + recipe.OWNER_CONTROLS + recipe.REUSE_CONTROLS)
        inherited = prior + leaf.APP_CONTROLS
        wanted = inherited + R.APP_CONTROLS
        inventory = list(wanted) + ['unrelated::test']
        self.assertEqual(len(prior), 52)
        self.assertEqual(len(inherited), 79)
        self.assertEqual(len(leaf.ACCURACY_CONTROLS), 11)
        self.assertEqual(leaf.APP_CONTROLS[16:], leaf.ACCURACY_CONTROLS)
        self.assertEqual(len(R.APP_CONTROLS), 12)
        self.assertEqual(len(wanted), 91)
        with patch.object(leaf, 'ordinary_inventory', wraps=leaf.ordinary_inventory) as shared:
            self.assertEqual(R.ordinary_inventory(inventory, leaf, recipe, modules), wanted)
            shared.assert_called_once_with(
                [n for n in inventory if n not in R.APP_CONTROLS], recipe, single, module)
        for name in wanted:
            for changed in ([n for n in inventory if n != name], inventory + [name]):
                with self.assertRaises(AssertionError, msg=name):
                    R.ordinary_inventory(changed, leaf, recipe, modules)
        old = prior + leaf.APP_CONTROLS[:16] + R.APP_CONTROLS
        self.assertEqual(len(old), 80)
        with self.assertRaises(AssertionError):
            R.ordinary_inventory(list(old), leaf, recipe, modules)
        for prefix in (*leaf.ACCURACY_PREFIXES, 'normal::call_pair::tests::',
                       'normal::leaf_set::tests::', 'normal::session::io::tests::'):
            with self.assertRaises(AssertionError, msg=prefix):
                R.ordinary_inventory(inventory + [prefix + 'unregistered'], leaf, recipe, modules)
        for name in leaf.ACCURACY_CONTROLS:
            changed = [n if n != name else name.rsplit('::', 1)[0] + '::unregistered' for n in inventory]
            with self.assertRaises(AssertionError, msg=name):
                R.ordinary_inventory(changed, leaf, recipe, modules)


class ReceiptControls(Receipt.Controls):
    """The six immutable receipt controls retain their separate source identity."""


class ProducerControls(Producer.Controls):
    """The five immutable producer controls run in the same owned stage."""
    test_fixed_call_pair_plan_and_all_case_bytes = Producer.Controls.test_fixed_call_pair_plan_and_all_case_bytes
    test_ready_requires_actual_profile_pid_roles_before_input = Producer.Controls.test_ready_requires_actual_profile_pid_roles_before_input
    test_closed_envelope_precedes_custody_release = Producer.Controls.test_closed_envelope_precedes_custody_release
    test_projection_failure_and_literal_default_lifecycle = Producer.Controls.test_projection_failure_and_literal_default_lifecycle
    test_authenticated_imports_and_optimized_refusal = Producer.Controls.test_authenticated_imports_and_optimized_refusal


if __name__ == '__main__':
    suite=unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromTestCase(Controls),
                              unittest.defaultTestLoader.loadTestsFromTestCase(ReceiptControls),
                              unittest.defaultTestLoader.loadTestsFromTestCase(ProducerControls)))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
