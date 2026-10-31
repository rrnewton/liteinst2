#!/usr/bin/env python3
"""Source-fixture owner controls; no reservation, native or campaign acceptance."""
import sys
if sys.flags.optimize or not sys.flags.isolated:
    raise SystemExit('use Python -I -B with assertions enabled')
sys.dont_write_bytecode = True
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import types
import unittest

SHA = '4d93f5b99d8fe2993b6f4a1814972e04158d057d2d829cffe526dcbb118f064b'
PATH = Path(__file__).resolve().with_name('launch.py')
with os.fdopen(os.open(PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
    before = os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode) and before.st_size <= 1048576
    SOURCE = stream.read(1048577)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert len(SOURCE) == before.st_size and identity(before) == identity(os.fstat(stream.fileno())) == identity(PATH.lstat())
assert hashlib.sha256(SOURCE).hexdigest() == SHA
L = types.ModuleType('_call_pair_session_owner_controls'); L.__file__ = str(PATH)
exec(compile(SOURCE, str(PATH), 'exec'), L.__dict__)  # fixed native helpers only; never main
main = [n for n in ast.parse(SOURCE).body if isinstance(n, ast.FunctionDef) and n.name == 'main']
assert len(main) == 1 and isinstance(main[0].body[-1], ast.Return)
RETURN = compile(ast.Expression(main[0].body[-1].value), str(PATH), 'eval')


def terminal():
    return dict(profile=L.PROFILE, status=L.PASS, summary_sha256='a'*64, outcomes_sha256='b'*64)


def closed(exit_code=0):
    return dict(cleanup_complete=True, termination=None, exit_code=exit_code, reaped_descendants=0)


def wire(summary=None, cores=None, count=3, allowed='1,3,5'):
    assignment = dict(cores=[5, 1, 3] if cores is None else cores, count=count)
    return ('cpuset-alloc: run: reserved '+json.dumps(assignment, separators=(',', ':'))+
        '; running whole tree pinned via AllowedCPUs='+allowed+'\n'+
        json.dumps(terminal() if summary is None else summary, separators=(',', ':'))+'\n').encode('ascii')


def protocol():
    # Shape fixture only: no path is opened and no source/native authority follows.
    fp = lambda path: dict(path=path, bytes=1, sha256='0'*64)
    return dict(CLOSED=True, execution='UNRUN', version=1, profile=L.PROFILE,
        qualification=copy.deepcopy(L.QUALIFICATION), limits=dict(L.LIMITS), revision='a'*40, tag='fixture',
        hardware_label='source fixture', allocator_revision=L.ALLOCATOR_REVISION,
        allocator_sources=dict(L.F.ALLOCATOR_SOURCES), session_env={},
        paths=dict(root='/fixture', raw='/fixture/ignored/raw', capture='/fixture/ignored/owner',
            log_dir='/fixture/target/evaluation/outer', toolchain='/fixture/toolchain', user_home='/fixture/user',
            cargo_home='/fixture/cargo', allocator_root='/fixture/allocator'), launcher=fp('/fixture/launch.py'),
        tools={n: fp('/fixture/tools/'+n) for n in L.N.TOOLS},
        source_pins={n: dict(bytes=1, sha256=h) for n, h in
            ((L.N.OWNER, L.N.OWNER_SHA), (L.NATIVE_OWNER, L.NATIVE_SHA), (L.CAMPAIGN, L.CAMPAIGN_SHA))},
        native=dict(protocol=fp('/fixture/ignored/prior/protocol.json'), receipt=fp('/fixture/ignored/prior/receipt.json')))


class Controls(unittest.TestCase):
    def refuses(self, fn, *args):
        with self.assertRaises((AssertionError, KeyError, TypeError, ValueError)): fn(*args)

    def test_exact_summary_roles_nonzero_and_final_deadline(self):
        good = L.allocator_return(wire(), closed())
        self.assertEqual(good['cpu_roles'], dict(controller=1, worker=3, producer=5))
        self.assertEqual(good['count'], 3); self.assertIs(good['ledger_readback'], False)
        self.assertEqual(good['recipe_summary'], terminal()); self.assertEqual(good['recipe_exit'], 0)
        for status in (L.PASS, 'FAILED'):
            summary = terminal(); summary['status'] = status
            self.assertEqual(L.allocator_return(wire(summary), closed(1))['recipe_exit'], 1)
        for status, now, expected in (('CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED', 7199, 0),
                ('CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED', 7200, 1),
                ('CLOSED_EXIT_1_RECIPE_AUDIT_REQUIRED', 0, 1), ('FAILED', 0, 1)):
            # Actual authenticated return expression; no copied predicate or main invocation.
            self.assertEqual(eval(RETURN, {'result': dict(status=status), 'deadline': 7200,
                'time': types.SimpleNamespace(monotonic=lambda: now)}), expected)

    def test_summary_reservation_and_abnormal_closure_refusals(self):
        for key in terminal():
            v = terminal(); del v[key]; self.refuses(L.allocator_return, wire(v), closed())
            field = ('"'+key+'":').encode(); self.refuses(L.allocator_return, wire().replace(field, field+b'null,'+field), closed())
        for key, value in [('profile', 'wrong'), ('status', 'FAILED'), ('status', 'PASS'),
                ('summary_sha256', 'A'*64), ('summary_sha256', 'a'*63), ('outcomes_sha256', 'z'*64),
                ('outcomes_sha256', 0), ('custody_closed', True)]:
            v = terminal(); v[key] = value; self.refuses(L.allocator_return, wire(v), closed())
        for raw in (wire().replace(b'"profile":', b'"profile":"duplicate","profile":'),
                wire().replace(b'"count":3', b'"count":3,"count":3'),
                wire().replace(b'"count":3', b'"extra":0,"count":3'), wire()+b'\n', wire()+b'traceback\n',
                wire().replace(b'\n', b'\r\n'), wire()[:-1], b'\xff\n', b''):
            self.refuses(L.allocator_return, raw, closed())
        for cores in ([1, 1, 3], [1, 3], [-1, 1, 3], [1, 3, 1024], [True, 3, 5]):
            self.refuses(L.allocator_return, wire(cores=cores), closed())
        for count in (True, 2): self.refuses(L.allocator_return, wire(count=count), closed())
        for allowed in ('3,1,5', '1,3,3', '1,3'): self.refuses(L.allocator_return, wire(allowed=allowed), closed())
        for key, values in [('cleanup_complete', (False, 1)), ('termination', ('signal', 'timeout')),
                ('exit_code', (True, -9, 2)), ('reaped_descendants', (True, 1))]:
            for value in values:
                v = closed(); v[key] = value; self.refuses(L.allocator_return, wire(), v)

    def test_log_reader_requires_owned_cleanup_and_original_hash(self):
        calls = []; data = b'fabricated source fixture\n'
        reader = lambda: (calls.append(1), data)[1]
        v = dict(cleanup_complete=False, private_log_sha256=L.pin(data)['sha256'])
        for value in (False, 0, 1, None):
            v['cleanup_complete'] = value; self.refuses(L.closed_log, v, reader)
        self.assertEqual(calls, [])
        v['cleanup_complete'] = True; self.assertEqual(L.closed_log(v, reader), data); self.assertEqual(calls, [1])
        v['private_log_sha256'] = '0'*64; self.refuses(L.closed_log, v, reader); self.assertEqual(calls, [1, 1])

    def test_protocol_shape_fixed_domains_never_grant_authority(self):
        base = protocol(); self.assertEqual(L.validate_protocol(base), L.QUALIFICATION)
        for section in ('qualification', 'limits'):
            for key in base[section]:
                old = base[section][key]
                different = old+1 if type(old) is int else list(reversed(old)) if type(old) is list else old+'x'
                for bad in (None, True, different):
                    v = copy.deepcopy(base); v[section][key] = bad; self.refuses(L.validate_protocol, v)
        for key, values in [('revision', ('a'*39, 'a'*41, 'G'*40)), ('profile', ('wrong',)),
                ('CLOSED', (False, 1)), ('execution', ('RUN',)), ('version', (True, 2)),
                ('allocator_revision', ('b'*40,)), ('tag', ('', 'bad tag')), ('hardware_label', ('', '\n'))]:
            for value in values:
                v = copy.deepcopy(base); v[key] = value; self.refuses(L.validate_protocol, v)
        for name in ('protocol', 'receipt'):
            for key, values in [('bytes', (-1, True, 512*L.MIB+1)), ('sha256', ('0'*63, 'G'*64, 0)),
                    ('path', ('relative', '/fixture/../bad', '/fixture/ignored/raw/x', '/fixture/ignored/owner/x', '/other/x'))]:
                for value in values:
                    v = copy.deepcopy(base); v['native'][name][key] = value; self.refuses(L.validate_protocol, v)
            for key in base['native'][name]:
                v = copy.deepcopy(base); del v['native'][name][key]; self.refuses(L.validate_protocol, v)
            v = copy.deepcopy(base); v['native'][name]['extra'] = 1; self.refuses(L.validate_protocol, v)
            v = copy.deepcopy(base); del v['native'][name]; self.refuses(L.validate_protocol, v)
        v = copy.deepcopy(base); v['native']['receipt'] = v['native']['protocol']; self.refuses(L.validate_protocol, v)
        for key in base:
            v = copy.deepcopy(base); del v[key]; self.refuses(L.validate_protocol, v)
        v = copy.deepcopy(base); v['extra'] = 1; self.refuses(L.validate_protocol, v)


if __name__ == '__main__':
    unittest.main(verbosity=2)
