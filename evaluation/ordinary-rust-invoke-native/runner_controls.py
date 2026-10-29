"""Pure copied-body runner controls; no native or process-closure authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE/filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

G = load('_copied_runner_caller_controls', 'caller.py')
R = load('_copied_runner_controls', 'reproduce.py')
VA = 4096
BODY = [('53', 'push rbx'), ('4889cb', 'mov rbx,rcx'), ('4889f8', 'mov rax,rdi'),
        ('4889f7', 'mov rdi,rsi'), ('4889d6', 'mov rsi,rdx'), ('ffd0', 'call rax'),
        ('488903', 'mov QWORD PTR [rbx],rax'), ('5b', 'pop rbx'), ('c3', 'ret')]

def rows(body=BODY):
    result = []; pc = VA
    for code, asm in body:
        code = bytes.fromhex(code); result.append((pc, code, asm)); pc += len(code)
    return result, pc-VA


def request():
    raw = R.ROOT/'ignored'/'fabricated-copied-run'; cohort = raw/'native'
    argv = list(map(str, [R.ROOT/'target/release/frontend-native-oracle', 'normal-rust-invoke-state',
        raw/'module-candidate.so', raw/'module-trusted.so', 4096, 126, 4224, 41,
        raw/'application-candidate', raw/'application-trusted', cohort/'output']))
    return dict(argv=argv, cwd=str(R.ROOT), env={'LITEINST_EVALUATION': '1'},
        stdout=str(cohort/'stdout.txt'), stderr=str(cohort/'stderr.txt'), cpu=5,
        pins={str(R.HERE/'reproduce.py'): {}, argv[0]: {}, **{p: {} for p in argv[2:4]+argv[8:10]}})


class Controls(unittest.TestCase):
    def test_complete_caller_geometry_and_all_stack_operations(self):
        r, size = rows(); g = G.geometry(r, VA, size)
        self.assertEqual(g, dict(length=20, heads=[0,1,4,7,10,13,15,18,19], call_offset=13,
            continuation_offset=15, outer_ret_offset=19, subject_rsp_delta=16, elf_va=VA,
            body_hex=''.join(code for code, _ in BODY)))
        # A separately fabricated balanced frame covers LEA, ADD/SUB and aliases.
        frame = [('55','push rbp'),('4889e5','mov rbp,rsp'),('53','push rbx'),('4883ec08','sub rsp,0x8')]
        frame += BODY[1:-2]
        frame += [('4883c408','add rsp,0x8'),('5b','pop rbx'),('5d','pop rbp'),('c3','ret')]
        r, size = rows(frame); self.assertEqual(G.geometry(r, VA, size)['subject_rsp_delta'],32)
        frame[1] = ('488d2c24','lea rbp,[rsp]')
        r, size = rows(frame); self.assertEqual(G.geometry(r, VA, size)['subject_rsp_delta'],32)
        # Explicit restoration by a preserved stack-origin register.
        frame[-4] = ('488d65f8','lea rsp,[rbp-0x8]')
        r, size = rows(frame); self.assertEqual(G.geometry(r, VA, size)['subject_rsp_delta'],32)
        frame[1] = ('4889e5','mov rbp,rsp'); frame[-4] = ('4883c408','add rsp,0x8')
        r, size = rows(frame); self.assertEqual(G.geometry(r, VA, size)['length'],size)

    def test_caller_extent_flow_stack_and_geometry_refusals(self):
        r,size = rows()
        for n in (0,19,21,257):
            with self.assertRaises(AssertionError): G.geometry(r,VA,n)
        for i in range(len(r)):
            bad=list(r);pc,code,asm=bad[i];bad[i]=(pc+1,code,asm)
            with self.assertRaises(AssertionError): G.geometry(bad,VA,size)
        variants = [BODY[:-1], BODY+[('90','nop')], [('90','nop')]+BODY,
            BODY[:5]+[('ffd0','call rax')]+BODY[5:], BODY[1:],
            BODY[:6]+[('48890b','mov QWORD PTR [rbx],rcx')]+BODY[7:],
            [('4889c4','mov rsp,rax')]+BODY,
            [('4883ec10','sub rsp,0x108')]+BODY,
            BODY[:-1]+[('c20800','ret 0x8')]]
        for body in variants:
            r,size=rows(body)
            with self.assertRaises(AssertionError): G.geometry(r,VA,size)
        r,size=rows();self.assertEqual(len(G.geometry(r,VA,size)['heads']),len(BODY))

    def test_request_coordinates_and_cpu_are_exact(self):
        req=request(); cpus=[3,5,7]
        with patch.object(Path,'resolve',lambda p,strict=False:p):
            self.assertEqual(R.request_shape(req,cpus),Path(req['stdout']).parent)
            changes=[('cpu',3),('cpu',True),('cwd','/'),('stdout',req['stderr']),('stderr',req['stdout'])]
            for key,value in changes:
                bad=copy.deepcopy(req);bad[key]=value
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for index,value in [(1,'normal-module-state'),(4,'+4096'),(5,'257'),(6,'4097'),(7,'81'),(8,'wrong'),(10,'wrong')]:
                bad=copy.deepcopy(req);bad['argv'][index]=value
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for bad_cpus in ([3,5],[7,5,3],[3,3,7],[3,5,1024]):
                with self.assertRaises(AssertionError):R.request_shape(req,bad_cpus)
            for pin in tuple(req['pins']):
                bad=copy.deepcopy(req);del bad['pins'][pin]
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            bad=copy.deepcopy(req);bad['retry']=1
            with self.assertRaises(AssertionError):R.request_shape(bad,cpus)

    def test_fixed_plan_and_closure_cannot_relabel_failure(self):
        row=R.fixed_row();self.assertEqual(row['attempts'],0);self.assertEqual(row['status'],'UNRUN')
        self.assertEqual(row['required_pairs'],48)
        self.assertTrue(all(row[k]==96 for k in ('required_children','required_target_calls',
            'required_target_returns','required_outer_returns','required_normal_reaps')))
        closed=dict(exit_code=0,termination=None,cleanup_complete=True,reaped_descendants=0,
                    private_log_sha256=hashlib.sha256(b'').hexdigest())
        with self.assertRaises(AssertionError):R.accept_closure(row,closed,b'')
        row.update(status='FAILED',attempts=1);R.accept_closure(row,closed,b'')
        self.assertEqual(row['status'],'FAILED') # Only source/output acceptance may promote it.
        for key,value in [('exit_code',1),('termination','timeout'),('cleanup_complete',False),
                          ('reaped_descendants',1),('private_log_sha256','0'*64)]:
            bad=dict(closed);bad[key]=value
            with self.assertRaises(AssertionError):R.accept_closure(row,bad,b'')
        noisy=b'printed success';bad=dict(closed,private_log_sha256=hashlib.sha256(noisy).hexdigest())
        with self.assertRaises(AssertionError):R.accept_closure(row,bad,noisy)
        for attempts in (0,2):
            with self.assertRaises(AssertionError):R.accept_closure(dict(row,attempts=attempts),closed,b'')
        self.assertEqual(len(R.STAGES),len(set(R.STAGES)))
        self.assertEqual(R.STAGES[-1],'native-outer')


if __name__ == '__main__':
    unittest.main()
