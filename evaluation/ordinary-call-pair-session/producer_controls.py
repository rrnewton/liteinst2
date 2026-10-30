#!/usr/bin/env python3
"""Fabricated producer-boundary controls; no application or native invocation."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


P = load('_call_pair_profile_controls', HERE / 'profile.py')
W = load('_call_pair_wrapper_controls', HERE / 'produce.py')
S = load('_call_pair_shared_controls', ROOT / P.SHARED / 'produce.py')
C = load('_call_pair_corpus_controls', ROOT / P.SHARED / 'corpus.py')
R = load('_call_pair_owner_controls', ROOT / P.SHARED / 'reproduce.py')
B = P.call_pair_binding()


def pin(data):
    return hashlib.sha256(data).hexdigest()


def plan(index=0, k=10, attempt=1):
    case = S.case_spec(C, index)
    data = C.framed(case['records']) if index >= 30 else case['data']
    parent = dict(elf_va=4096, length=48, returns=[47], call_offset=16,
                  continuation_offset=21, child_delta=32, callee_entry=4352,
                  heads=[0, 16, 21, 47], edges=[[0, 16], [16, 21], [21, 47]], body_hex='00' * 48)
    child = dict(elf_va=4352, length=64, returns=[63], heads=[0, 63], edges=[[0, 63]])
    value = dict(profile=B.identity, application_profile=B.application_profile,
                 producer=B.producer_path, corpus_sha256=P.CORPUS, attempt=attempt,
                 case=index, name=case['name'], k=k, epochs=520, data_sha256=pin(data),
                 cpus=[2, 4, 6], geometry=dict(parent=parent, child=child),
                 caller=dict(elf_va=8192, length=32, continuation_offset=24),
                 binary='/fixture/ordinary', candidate='/fixture/candidate', trusted='/fixture/trusted', pins={})
    value['argv'] = [value['binary'], 'normal-call-pair-session', value['candidate'], value['trusted'],
                     str(k), '520', '501', '4096', '48', '502', '4352', '64']
    return value, case, data


def checked():
    # Only the projection/ownership envelope is fabricated here. These data do
    # not stand in for the independent nested parser or a native receipt.
    return dict(expected_exit=0, totals=dict(epochs=520), coverage={'sampled': 2},
                rows={'READY': [dict(pid=123)], 'DONE': [dict(history_end=521)],
                      'IO': [dict(write_blocked_count=7)],
                      'CALL': [dict(owner='sampled', history_prefix=513)]},
                results=[dict(id=0, length=0, fnv=14695981039346656037, fields=1, packed=1)])


class Owned:
    def __init__(self):
        self.safe = False
        self.budget = R.EvidenceBudget()
        self.budget.reserve(4096)
        self.bad_source = False
        self.rechecked = False
    def unchanged(self):
        self.rechecked = True
        assert not self.bad_source


def envelope(p, c):
    app_out, app_err = b'actual retained stream fixture\n', b''
    result = dict(B.fields(p), case=p['case'], name=p['name'], k=p['k'],
                  child_pid=123, child_exit=0, normal_reaps=1, rescue=False, cleanup_error=None,
                  sent_bytes=0, stdout_sha256=pin(app_out), stderr_sha256=pin(app_err))
    result.update(B.project(c))
    return result, app_out, app_err


class DefaultOnly(ast.NodeTransformer):
    """Remove only explicit CallPair selections to reconstruct the old function."""
    @staticmethod
    def branch(test):
        if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
                and test.left.id == 'call_pair' and len(test.ops) == 1
                and len(test.comparators) == 1 and isinstance(test.comparators[0], ast.Constant)
                and test.comparators[0].value is None):
            if isinstance(test.ops[0], ast.Is):
                return True
            if isinstance(test.ops[0], ast.IsNot):
                return False
        return None
    def visit_If(self, node):
        select = self.branch(node.test)
        if select is None:
            return self.generic_visit(node)
        return [self.visit(n) for n in (node.body if select else node.orelse)]
    def visit_IfExp(self, node):
        select = self.branch(node.test)
        return self.generic_visit(node) if select is None else self.visit(node.body if select else node.orelse)


def default_digest(tree):
    node = copy.deepcopy(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_main'))
    assert len(node.args.kwonlyargs) == 1 and node.args.kwonlyargs[0].arg == 'call_pair'
    assert len(node.args.kw_defaults) == 1 and node.args.kw_defaults[0].value is None
    node.name = 'main'
    node.args.kwonlyargs = []; node.args.kw_defaults = []
    node = DefaultOnly().visit(node)
    # Python 3.12 adds this empty grammar field; retain one historical AST
    # representation across interpreters and refuse actual type parameters.
    for child in ast.walk(node):
        if 'type_params' in child._fields:
            assert isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            assert type(child.type_params) is list and child.type_params == []
            child._fields = tuple(field for field in child._fields if field != 'type_params')
    return pin(ast.dump(node, include_attributes=False).encode())


class Controls(unittest.TestCase):
    def test_fixed_call_pair_plan_and_all_case_bytes(self):
        self.assertEqual(tuple(name for name in self.__class__.__dict__ if name.startswith('test_')), P.CONTROLS)
        self.assertEqual(pin((ROOT / P.SHARED / 'corpus.py').read_bytes()), P.CORPUS)
        records = 0
        for i in range(32):
            p, case, data = plan(i)
            records += len(case['records'])
            for k in (10, 1000):
                for attempt in range(1, 6):
                    p, case, data = plan(i, k, attempt)
                    B.arguments(p, case, C)
                    self.assertEqual(p['data_sha256'], pin(data))
            bad = copy.deepcopy(p); bad['data_sha256'] = '0' * 64
            with self.assertRaises(AssertionError): B.arguments(bad, case, C)
        self.assertEqual(records, 10537)
        p, case, _ = plan()
        for key, bad_value in (('profile', 'module'), ('application_profile', 'other'), ('producer', P.SHARED+'produce.py'),
                               ('corpus_sha256', '0'*64), ('attempt', 0), ('attempt', 6), ('attempt', True),
                               ('case', -1), ('case', 32), ('k', 16), ('k', True), ('epochs', 3),
                               ('name', ''), ('cpus', [2, 2, 6]), ('cpus', [2, 4, 1024]), ('cpus', [True, 4, 6])):
            bad = copy.deepcopy(p); bad[key] = bad_value
            with self.assertRaises(AssertionError): B.check_plan(bad)
        for i in range(len(p['argv'])):
            bad = copy.deepcopy(p); bad['argv'][i] += 'x'
            with self.assertRaises(AssertionError): B.check_plan(bad)
        for name, key, value in (('parent', 'length', 81), ('child', 'length', 257),
                                 ('child', 'elf_va', 4096), ('parent', 'returns', [48])):
            bad = copy.deepcopy(p); bad['geometry'][name][key] = value
            with self.assertRaises(AssertionError): B.check_plan(bad)
        bad = copy.deepcopy(p); bad['name'] = 'not_the_frozen_case'
        with self.assertRaises(AssertionError): B.arguments(bad, case, C)

    def test_ready_requires_actual_profile_pid_roles_before_input(self):
        p, _, _ = plan()
        row = ['READY', B.application_profile, '10', '520', '10', '2', '64', '2048', '4', '1',
               str(0x63700001), '123', '123', '124', '2', '4', '40960']
        raw = ','.join(row).encode()
        B.ready(raw, 123, p)
        for i in range(17):
            altered = row.copy(); altered[i] = 'wrong' if i < 2 else '00'
            with self.assertRaises(AssertionError): B.ready(','.join(altered).encode(), 123, p)
        for i, value in ((11, '125'), (12, '125'), (13, '123'), (14, '4'), (15, '2'), (16, '0')):
            altered = row.copy(); altered[i] = value
            with self.assertRaises(AssertionError): B.ready(','.join(altered).encode(), 123, p)
        for altered in (raw+b',1', b','.join(raw.split(b',')[:-1]), raw+b'\n', b'x'*350):
            with self.assertRaises(AssertionError): B.ready(altered, 123, p)
        with self.assertRaises(AssertionError): B.ready(raw, 125, p)
        for text in ('', '-1', '+1', '01', str(1 << 64), ' 1', '1\n'):
            with self.assertRaises(AssertionError): P.uint(text)
        self.assertEqual(P.uint(str((1 << 64)-1)), (1 << 64)-1)

    def test_closed_envelope_precedes_custody_release(self):
        p, _, _ = plan(); c = checked()
        result, app_out, app_err = envelope(p, c)
        def invoke(run, result=result, code=0, out=None, err=b'', stdout=app_out, stderr=app_err):
            P.confirm_custody(run, p, result, code, json.dumps(result).encode() if out is None else out,
                             err, stdout, stderr, c)
        for key, value in (('profile', 'other'), ('application_profile', 'other'), ('producer', 'other'),
                           ('corpus_sha256', '0'*64), ('attempt', 2), ('attempt', True), ('case', 1),
                           ('name', 'other'), ('k', 1000), ('child_pid', 124), ('child_pid', True),
                           ('child_exit', -6), ('child_exit', True), ('normal_reaps', 0), ('normal_reaps', True),
                           ('rescue', True), ('cleanup_error', 'unclosed'), ('status', 'UNKNOWN'),
                           ('stdout_sha256', '0'*64), ('stderr_sha256', '0'*64)):
            bad = copy.deepcopy(result); bad[key] = value
            run = Owned()
            with self.assertRaises(AssertionError): invoke(run, result=bad)
            self.assertIs(run.safe, False); self.assertIs(run.budget.active, True)
            self.assertEqual(run.budget.held, 4096)
        for kwargs in ({'code': -6}, {'code': True}, {'out': b'{}'}, {'err': b'error'},
                       {'stdout': app_out+b'x'}, {'stderr': b'x'}):
            run = Owned()
            with self.assertRaises(AssertionError): invoke(run, **kwargs)
            self.assertIs(run.safe, False); self.assertIs(run.budget.active, True)
        for field in ('bad_source', 'exceeded'):
            run = Owned()
            if field == 'bad_source': run.bad_source = True
            else: run.budget.exceeded = True
            with self.assertRaises(AssertionError): invoke(run)
            self.assertIs(run.safe, False); self.assertIs(run.budget.active, True)
            self.assertEqual(run.budget.held, 4096)
        run = Owned(); invoke(run)
        self.assertTrue(run.rechecked); self.assertIs(run.safe, True); self.assertIs(run.budget.active, False)
        bad = copy.deepcopy(result); bad.update(status='FAILED', error='closed functional refusal', child_exit=1)
        run = Owned(); invoke(run, result=bad, code=1)
        self.assertIs(run.safe, True)
        with self.assertRaises(AssertionError): P.join_pass(p, bad, 1, c, 0)

    def test_projection_failure_and_literal_default_lifecycle(self):
        p, case, data = plan(2); c = checked()
        class Checker:
            def check(self, stdout, stderr, **kwargs):
                self.seen = (stdout, stderr, kwargs)
                return c
        checker = Checker()
        self.assertIs(B.check(checker, b'wire', b'stderr', p, case), c)
        stdout, stderr, args = checker.seen
        self.assertEqual((stdout, stderr), (b'wire', b'stderr'))
        self.assertEqual(args['records'], tuple(r.payload for r in case['records']))
        self.assertIs(args['geometry'], p['geometry']); self.assertIs(args['caller'], p['caller'])
        self.assertEqual({k: args[k] for k in ('k','epochs','outcome','input_error','cpus')},
                         dict(k=10, epochs=520, outcome='eof', input_error='none', cpus=(2,4)))
        self.assertIs(B.project(c)['original_values'], c['results'])
        self.assertIs(B.project(c)['coverage'], c['coverage'])
        self.assertEqual(B.project(c)['write_blocked'], 7)
        result, _, _ = envelope(p, c); result['sent_bytes'] = len(data)
        P.join_pass(p, result, 0, c, len(data))
        for key in ('totals', 'done', 'write_blocked', 'original_values', 'coverage', 'sent_bytes', 'child_exit', 'status'):
            bad = copy.deepcopy(result); bad[key] = None
            with self.assertRaises(AssertionError): P.join_pass(p, bad, 0, c, len(data))
        # Exercise the real case30 adapter with the checker's arms-only shape.
        history_plan, history_case, _ = plan(30)
        history = copy.deepcopy(c)
        history['totals'] = dict(arms=520)
        self.assertNotIn('epochs', history['totals'])
        self.assertEqual((history_plan['case'], len(history_case['records'])), (30, 48))
        B.history_complete(history, 2)
        for phase in (0, 1, 3):
            with self.assertRaises(AssertionError): B.history_complete(history, phase)
        for arms in (519, 521):
            bad = copy.deepcopy(history); bad['totals']['arms'] = arms
            # A matching fabricated legacy alias cannot rescue wrong arms.
            bad['totals']['epochs'] = 520
            with self.assertRaises(AssertionError): B.history_complete(bad, 2)
        bad = copy.deepcopy(history); bad['totals'] = dict(epochs=520)
        with self.assertRaises(KeyError): B.history_complete(bad, 2)
        for end in (520, 522):
            bad = copy.deepcopy(history); bad['rows']['DONE'][0]['history_end'] = end
            with self.assertRaises(AssertionError): B.history_complete(bad, 2)
        for calls in ([], [dict(owner='sampled', history_prefix=512)],
                      [dict(owner='function_closed', history_prefix=513)]):
            bad = copy.deepcopy(history); bad['rows']['CALL'] = calls
            with self.assertRaises(AssertionError): B.history_complete(bad, 2)
        tree = ast.parse(Path(S.__file__).read_text())
        # Bind this guard to the actual shared case30 branch without a child.
        gates = [n for n in ast.walk(tree) if isinstance(n, ast.If)
                 and ast.unparse(n.test) == "plan['case'] == 30"
                 and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                         and isinstance(c.func.value, ast.Name) and c.func.value.id == 'call_pair'
                         and c.func.attr == 'history_complete' for c in ast.walk(n))]
        self.assertEqual(len(gates), 1)
        # Exact main from bab35bcde867688d2b980627bc4e08c3bdef296b,
        # with only absent/empty type_params canonicalized as above.
        expected = '68b2c373ae49fc0b2a9a0e0964fe7e10d1129a0d9642d79aeb6e121b4992f64a'
        self.assertEqual(default_digest(tree), expected)
        # Real old deadline/cap/cleanup statements survive extraction; changing
        # any selected old constant invalidates the independent old-body digest.
        for literal in (15, 350, 8192, .250):
            bad = copy.deepcopy(tree)
            node = next(n for n in ast.walk(bad) if isinstance(n, ast.Constant) and type(n.value) is type(literal) and n.value == literal)
            node.value = literal + 1
            self.assertNotEqual(default_digest(bad), expected)

        # Inject the same empty field on Python 3.9 as on Python 3.12, then
        # independently reject nonempty parameters on both owned functions.
        with_empty = copy.deepcopy(tree)
        main = next(n for n in with_empty.body if isinstance(n, ast.FunctionDef) and n.name == '_main')
        functions = [n for n in ast.walk(main) if isinstance(n, ast.FunctionDef)]
        self.assertEqual([n.name for n in functions], ['_main', 'line'])
        for node in functions:
            if 'type_params' not in node._fields:
                node._fields = (*node._fields, 'type_params')
            node.type_params = []
        self.assertEqual(default_digest(with_empty), expected)
        for name in ('_main', 'line'):
            bad = copy.deepcopy(with_empty)
            node = next(n for n in ast.walk(bad) if isinstance(n, ast.FunctionDef) and n.name == name)
            node.type_params = [ast.Name(id='T', ctx=ast.Load())]
            with self.assertRaises(AssertionError):
                default_digest(bad)

    def test_authenticated_imports_and_optimized_refusal(self):
        self.assertEqual(W.REQUIRED, P.SOURCES)
        scratch = ROOT / 'target/evaluation'
        assert scratch.resolve(strict=True) == scratch and scratch.is_dir()
        with tempfile.TemporaryDirectory(prefix='call-pair-producer-controls-', dir=scratch) as directory:
            root = Path(directory).resolve()
            pins = {}
            for relative in W.REQUIRED:
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
                data = (ROOT/P.SHARED/'corpus.py').read_bytes() if relative == P.SHARED+'corpus.py' else b'# source fixture\n'
                path.write_bytes(data); pins[str(path)] = pin(data)
            path = root/'plan.json'; path.write_text(json.dumps(dict(pins=pins)))
            expected = pin(path.read_bytes())
            self.assertEqual(W.authenticate(path, expected, root)['pins'], pins)
            B.check_sources(root, pins)
            with self.assertRaises(AssertionError): W.authenticate(path, '0'*64, root)
            for relative in W.REQUIRED:
                source = root/relative
                original = source.read_bytes()
                source.write_bytes(b'# mutated\n')
                with self.assertRaises(AssertionError): W.authenticate(path, expected, root)
                with self.assertRaises(AssertionError): W.load('_must_not_import', source, pins)
                with self.assertRaises(AssertionError): B.check_sources(root, pins)
                source.write_bytes(original)
            source = root/W.REQUIRED[0]; target = root/'shadow.py'; target.write_bytes(source.read_bytes())
            source.unlink(); source.symlink_to(target)
            with self.assertRaises(AssertionError): W.authenticate(path, expected, root)
        for path in (HERE/'produce.py', HERE/'profile.py', HERE/'producer_controls.py', Path(S.__file__)):
            reply = subprocess.run([sys.executable, '-B', '-O', str(path), '--help'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertNotEqual(reply.returncode, 0)
            self.assertEqual(reply.stdout, b''); self.assertEqual(reply.stderr, b'assertions required\n')


if __name__ == '__main__':
    unittest.main()
