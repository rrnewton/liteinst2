#!/usr/bin/env python3
"""Fabricated wire/control tests; no native, source-custody or Schedule credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


def load(name):
    path = Path(__file__).resolve().with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('_session_control_' + name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


output = load('output')
produce = load('produce')


def fixture(n=3, k=10, arms=1, prefix=1, outcome='eof', error='none'):
    records = tuple((b'a,b', 2) for _ in range(n))
    args = dict(records=records, k=k, epochs=max(arms, 1), outcome=outcome, input_error=error,
                lengths=(37, 41), returns=((36,), (34, 40)), continuation=17, cpus=(2, 4))
    rows = [['READY', 'module-session-v1', k, args['epochs'], 10, 2, 64, 2048, 4, 1,
             0x6d6f6401, 123, 123, 124, 2, 4, 4096, 4160, 4133, 4201, 8192],
            ['RET', 101, 36], ['RET', 202, 34], ['RET', 202, 40]]
    for i in range(1, arms + 1):
        rows.append(['HISTORY', i, i, 'published', i + 100])
    calls, samples = [], []
    completed = 0
    generation = prefix + 100
    for ordinal in range(1, 2 * n + 1):
        function = 101 if ordinal % 2 else 202
        rank = (ordinal - 1) // 2
        sampled = rank < k
        slot = completed + 1 if sampled else 0
        batch = (ordinal - 1) // 4 + 1
        checkpoint = ordinal % 4 == 0 or ordinal == 2 * n
        row = ['CALL', (ordinal + 1) // 2, function, ordinal,
               'sampled' if sampled else 'closed', generation, slot, prefix,
               36 if function == 101 else 34, 4104, 8209, ordinal, ordinal + 1, 0, 0,
               'checkpoint' if checkpoint else 'next', 0 if checkpoint else ordinal + 1, batch, completed]
        calls.append(row)
        rows.append(row)
        if sampled:
            samples.append(['SAMPLE', (ordinal + 1) // 2, function, generation, completed, rank, completed, ordinal, 'value', ordinal + 1])
            completed += 1
        if ordinal % 2 == 0:
            rows.append(['RESULT', ordinal // 2, 3, 0xe6169119046025e6, 2, 3, ordinal - 1, ordinal])
    # The checksum constant is deliberately derived from a separate literal below.
    for row in rows:
        if row[0] == 'RESULT':
            value = 0xcbf29ce484222325
            for byte in (97, 44, 98):
                value = ((value ^ byte) * 0x100000001b3) % (1 << 64)
            row[3] = value
    rows.append(['HISTORY', arms + 1, arms + 1, 'removed', arms + 100])
    for i in range(1, arms + 1):
        rows.append(['REPORT', i + 100, completed if i == prefix else 0])
    rows.extend(samples)
    for function, declared in ((101, 1), (202, 2)):
        rows.append(['COVERAGE', function, n, min(n, k), max(0, n - k), 0, 0, declared, 1 if n else 0])
    rows.append(['IO', 0])
    status = {'eof': 'COMPLETE', 'input_error': 'INPUT_REFUSED', 'input_incomplete': 'INPUT_INCOMPLETE'}[outcome]
    eof = int(outcome == 'eof' or error == 'unterminated')
    rows.append(['DONE', status, 'EpochLimit' if outcome == 'input_incomplete' else 'Requested', arms, arms + 1,
                 n, 2 * n, 2 * n, 2 * n, completed, 2 * n - completed, (2 * n + 3) // 4,
                 2 * n, 3 * n, eof, error, int(outcome == 'eof'), 1, 1])
    return rows, args


def encode(rows):
    return ('\n'.join(','.join(map(str, row)) for row in rows) + '\n').encode('ascii')


def check(rows, args):
    # Prospective fabricated fixture streams; production always passes actual stderr.
    stderr = b''
    if args['outcome'] == 'input_error':
        stderr = b'normal-module-session INPUT_REFUSED: ' + args['input_error'].encode('ascii') + b'\n'
    elif args['outcome'] == 'input_incomplete':
        stderr = b'normal-module-session INPUT_INCOMPLETE\n'
    return output.check(encode(rows), stderr, **args)



def owner_fixture(k=10, direction='csv-length'):
    geometry = dict(csv_va=4096, csv_length=37, length_va=4160, length_length=41,
                    returns=[[36], [34, 40]], continuation=17)
    args = dict(k=k, direction=direction, geometry=geometry, cpus=(2, 4))
    hot = 0 if direction == 'csv-length' else 1
    cold = 1-hot; a, b = 91, 92; h = (k+3)//4
    rows = [['META', 'run', 'module-session-owner-v1', 'session-absolute-v1', 'not-run', k, direction, 0x6d6f6401, 100, 100, 101, 2, 4, 1],
            ['META', 'code', '6f'*32, 4096, 1, 101, 202, 4096, 4133, 4160, 4201, 8192],
            ['META', 'memory', 12288, 16384, 8192, 12288], ['META', 'input', '612c622c63', 5, 3, 5],
            ['META', 'ret', 0, 36], ['META', 'ret', 1, 34], ['META', 'ret', 1, 40], ['HISTORY', 1, 1, 'published', a]]
    calls = []
    def pair(i, function, gen, owner, slot, prefix, batch, ack):
        expected = 3 if function == 0 else 5
        rows.append(['CALL', i, function, expected, expected, gen, owner, slot, prefix, batch])
        clock = ['RAW', i, 13064, 8209, 36 if function == 0 else 34, i, i+1, 0, 0, ack, i+1 if ack == 'next' else 0]
        rows.append(clock); calls.append((i, function, gen, owner, slot, clock))
    for i in range(1, k+1): pair(i, hot, a, 'sampled', i, 1, (i+3)//4, 'checkpoint' if i%4 == 0 or i == k else 'next')
    rows.append(['PHASE', 'hot-exhaust', k, k, k, k, 0, h, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, h, 0, 'not-checked', 0, 0])
    pair(k+1, cold, a, 'sampled', k+1, 1, h+1, 'checkpoint')
    rows.extend([['PHASE', 'cold-available', k+1, k+1, k+1, k+1, 0, h+1, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, h+1, 0, 'not-checked', 0, 0],
        ['PHASE', 'held', k+2, k+2, k+1, k+1, 0, h+1, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, h+1, 0, 'not-checked', 0, 0],
        ['HISTORY', 2, 2, 'published', b], ['META', 'epochs', a, b], ['REPORT', a, k+1],
        ['PHASE', 'refused-twice', k+2, k+2, k+1, k+1, 0, h+1, 1, b, 2, 1, 1, 2, 1, 1, 1, 1, h+1, 0, 'not-checked', 0, 0],
        ['HISTORY', 3, 3, 'removed', b],
        ['PHASE', 'released-before-checkpoint', k+3, k+3, k+2, k+1, 1, h+1, 2, 0, 3, 1, 1, 2, 0, 1, 0, 0, h+1, 1, 'pending', 0, 0]])
    pair(k+2, hot, a, 'closed', 0, 1, h+2, 'next'); pair(k+3, cold, b, 'sampled', 1, 2, h+2, 'checkpoint')
    rows.append(['REPORT', b, 1])
    for i, function, gen, owner, slot, clock in calls:
        if owner != 'sampled': continue
        rows.append(['SAMPLE', gen, function, slot-1, i-1 if i <= k else 0, min(i-1,k+1), clock[5], 'value', clock[6]])
    rows.append(['PHASE', 'finish', k+3, k+3, k+3, k+2, 1, h+2, 3, 0, 3, 2, 1, 2, 0, 0, 0, 0, h+3, 1, 'copied', 1, 1])
    rows.append([f'module-session-owner:profile=session-absolute-v1:schedule=not-run:k={k}:direction={direction}:calls={k+3}:confirmed={k+3}:sampled={k+2}:unsampled=1:batches={h+2}:reports=2:actions=3:banks=3:shared-owner-refusals=2:held-report-copies=1:reclaimed-before-checkpoint=1:worker-joins=1:complete'])
    return rows, args


def owner_bytes(rows):
    return encode(rows)


class Controls(unittest.TestCase):
    def test_caller_symbol_filter_keeps_all_matches_failures_and_literal_paths(self):
        runner=load('reproduce');repo=Path(__file__).resolve().parents[2]
        module=runner.load('symbol_control_module',repo/runner.MODULES['module'])
        parent=repo/'target/evaluation';parent.mkdir(parents=True,exist_ok=True)
        row='  7: 0000000000001000 20 FUNC GLOBAL DEFAULT 15 liteinst_csv_call_and_store\n'
        binary='literal path ; false $(false) `false`'
        with tempfile.TemporaryDirectory(prefix='module-symbol-controls-',dir=parent) as scratch:
            emitter=Path(scratch)/'readelf with spaces'
            tools=dict(bash=Path('/usr/bin/bash'),rg=Path('/usr/bin/rg'),readelf=emitter)
            for copies,code,error in ((1,0,''),(2,0,''),(3,0,''),(0,0,''),(1,42,''),(1,0,'readelf diagnostic\n')):
                emitter.write_text('#!'+sys.executable+'\nimport sys\n'
                    +'assert sys.argv[1:] == '+repr(['--wide','--syms',binary])+'\n'
                    +"sys.stdout.write(('unrelated '+ 'x'*200+'\\n')*8192)\n"
                    +'sys.stdout.write('+repr(row*copies)+')\n'
                    +'sys.stderr.write('+repr(error)+')\nraise SystemExit('+str(code)+')\n')
                emitter.chmod(0o700)
                command=list(map(str,runner.caller_symbol_command(tools,binary)))
                actual=subprocess.run(command,capture_output=True,timeout=5)
                self.assertEqual(actual.stdout,(row*copies).encode())
                self.assertEqual(actual.stderr,error.encode())
                self.assertEqual(actual.returncode,code if code else (0 if copies else 1))
                if copies in (1,2):
                    module.caller_symbols(actual.stdout.decode(),dict(elf_va=4096,length=20))
                else:
                    with self.assertRaises(AssertionError):
                        module.caller_symbols(actual.stdout.decode(),dict(elf_va=4096,length=20))

    def test_campaign_commands_freeze_exact_argv_before_owner_and_never_refresh(self):
        runner=load('reproduce')
        parent=Path(__file__).resolve().parents[2]/'target/evaluation'
        parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='module-session-source-controls-',dir=parent) as scratch:
            class Frozen:
                raw=Path(scratch);env={'LC_ALL':'C'}
                retained={}
                def freeze(self,path,value):
                    runner.save(path,value);self.retained[str(path)]=runner.pin(path.read_bytes())
            frozen=Frozen()
            path,command=runner.Run.command(frozen,'once',['/absolute/program','argument'],55)
            saved=dict(frozen.retained)
            self.assertEqual(runner.Run.command(frozen,'once',['/absolute/program','argument'],55),(path,command))
            self.assertEqual(frozen.retained,saved)
            for argv,wall in ((['/absolute/other','argument'],55),(['/absolute/program','argument'],56)):
                with self.assertRaises(AssertionError):runner.Run.command(frozen,'once',argv,wall)
            value=json.loads((path/'command.json').read_bytes());value['env']['LC_ALL']='changed'
            (path/'command.json').write_bytes(runner.canonical(value))
            with self.assertRaises(AssertionError):runner.Run.command(frozen,'once',['/absolute/program','argument'],55)
            self.assertEqual(frozen.retained,saved)

    def test_owner_four_cases_keep_full_raw_zero_max_and_unavailable(self):
        for k in (10, 1000):
            for direction in ('csv-length', 'length-csv'):
                rows, args = owner_fixture(k, direction)
                result = output.owner_check(owner_bytes(rows), b'', **args)
                self.assertEqual(result['totals']['calls'], k+3)
                self.assertEqual(len(result['raw']), k+3)
                self.assertEqual(len(result['samples']), k+2)
                self.assertEqual(result['stdout'], owner_bytes(rows))
        rows, args = owner_fixture()
        for start, end, aux0, aux1, kind, value in ((0,0,0,0,'value',0), ((1<<64)-1,(1<<64)-1,(1<<32)-1,(1<<32)-1,'value',(1<<64)-1),
                (9,3,7,7,'unavailable',2), (9,3,7,8,'unavailable',1)):
            changed = copy.deepcopy(rows)
            raw = next(r for r in changed if r[0] == 'RAW'); raw[5:9] = [start,end,aux0,aux1]
            sample = next(r for r in changed if r[0] == 'SAMPLE'); sample[6:] = [start,kind,value]
            output.owner_check(owner_bytes(changed), b'', **args)

    def test_owner_identity_phases_reports_raw_and_complete_order_refuse(self):
        rows, args = owner_fixture()
        def refuses(value, arguments=args, stderr=b''):
            with self.assertRaises((AssertionError, ValueError, UnicodeError, KeyError, IndexError)):
                output.owner_check(value, stderr, **arguments)
        for tag in ('CALL', 'RAW', 'HISTORY', 'REPORT', 'SAMPLE', 'PHASE'):
            index = next(i for i,r in enumerate(rows) if r[0] == tag)
            refuses(owner_bytes(rows[:index]+rows[index+1:]))
            refuses(owner_bytes(rows[:index]+[rows[index]]+rows[index:]))
            for position in range(1,len(rows[index])):
                changed = copy.deepcopy(rows)
                if type(changed[index][position]) is int: changed[index][position] += 1
                else: changed[index][position] = 'wrong'
                refuses(owner_bytes(changed))
        for index,row in enumerate(rows):
            if row[0] != 'PHASE': continue
            for position in range(1,len(row)):
                changed = copy.deepcopy(rows)
                changed[index][position] = row[position]+1 if type(row[position]) is int else 'wrong'
                refuses(owner_bytes(changed))
        for index in range(7):
            for position in range(2,len(rows[index])):
                changed = copy.deepcopy(rows)
                changed[index][position] = rows[index][position]+1 if type(rows[index][position]) is int else 'wrong'
                # A coherent nonzero namespace/base is not inferred: these one-field changes break joins.
                if index == 0 and position == 10: changed[index][position] = 100
                if index == 2 and position in (2,3,4,5):
                    changed[index][position] = (0,12288,8193,8209)[position-2]
                refuses(owner_bytes(changed))
        for rsp in (8,120,(1<<64)-1,13056,12296,16392):
            changed=copy.deepcopy(rows);next(r for r in changed if r[0]=='RAW')[2]=rsp
            refuses(owner_bytes(changed))
        changed=copy.deepcopy(rows);next(r for r in changed if r[0]=='RAW')[7]=1<<32
        refuses(owner_bytes(changed))
        changed=copy.deepcopy(rows);next(r for r in changed if r[0]=='CALL')[1]='01'
        refuses(owner_bytes(changed))
        for data in (owner_bytes(rows)[:-1],owner_bytes(rows)+b'\n',owner_bytes(rows).replace(b'\n',b'\r\n'),b'x'*629853): refuses(data)
        refuses(owner_bytes(rows),stderr=b'FAILED\n')
        for key,value in (('k',1000),('direction','length-csv'),('cpus',(4,2))):
            altered=copy.deepcopy(args);altered[key]=value;refuses(owner_bytes(rows),altered)
        altered=copy.deepcopy(args);altered['geometry']['continuation']+=1;refuses(owner_bytes(rows),altered)

    def test_campaign_fixed_catalog_frames_and_owner_status_join(self):
        runner=load('reproduce')
        originals,installed=runner.catalog()
        self.assertEqual([(r['attempt'],r['k'],r['case']) for r in installed],[(a,k,i) for a in range(1,6) for k in (10,1000) for i in range(32)])
        self.assertEqual([r['case'] for r in originals],list(range(32)))
        self.assertTrue(all(r['status']=='UNRUN' and r['attempts']==0 for r in originals+installed))
        self.assertEqual(runner.frame(((b'',1),(b'a,b',2))),b'MODCSV1\0\x02\0\0\0\0\x03a,b')
        self.assertEqual(tuple(n for n,_ in runner.malformed_frames()),output.ORIGINAL_REFUSALS)
        request=dict(sha256='a');helper=dict(sha256='b');out=dict(sha256='c');err=dict(sha256='d')
        closed=dict(cleanup_complete=True,reaped_descendants=0,termination=None,exit_code=1)
        receipt=dict(exit=2,absence_proof='ECHILD',inputs_unchanged=True,wall_timeout=False,unexpected_descendants=[],cleanup_events=[],
                     aborted=None,cleanup_error=None,request_sha256='a',helper_sha256='b',stdout_sha256='c',stderr_sha256='d')
        self.assertEqual(runner.bounded_join(receipt,closed,request,helper,out,err),2)
        for field,value in (('exit',1),('exit',0)):
            changed=copy.deepcopy(receipt);changed[field]=value
            if value==1: self.assertEqual(runner.bounded_join(changed,closed,request,helper,out,err),1)
            else:
                with self.assertRaises(AssertionError):runner.bounded_join(changed,closed,request,helper,out,err)
        for field,value in (('absence_proof','none'),('inputs_unchanged',False),('wall_timeout',True),('unexpected_descendants',[5]),
                ('cleanup_events',[1]),('aborted','interrupted'),('cleanup_error','lost'),('request_sha256','z'),('helper_sha256','z'),('stdout_sha256','z'),('stderr_sha256','z')):
            changed=copy.deepcopy(receipt);changed[field]=value
            with self.assertRaises(AssertionError):runner.bounded_join(changed,closed,request,helper,out,err)
        for field,value in (('cleanup_complete',False),('reaped_descendants',1),('termination','wall_timeout'),('exit_code',0)):
            changed=copy.deepcopy(closed);changed[field]=value
            with self.assertRaises(AssertionError):runner.bounded_join(receipt,changed,request,helper,out,err)

    def test_campaign_actual_producer_identity_and_all_failure_rows(self):
        runner=load('reproduce');rows,args=fixture();checked=check(rows,args);stdout=encode(rows)
        result=dict(status='PASS',normal_reaps=1,rescue=False,cleanup_error=None,sent_bytes=12,stdout_sha256=runner.pin(stdout)['sha256'],
                    stderr_sha256=runner.pin(b'')['sha256'],child_pid=123,child_exit=0,totals=checked['totals'],done=checked['rows']['DONE'][0],
                    original_values=[[r['id'],r['length'],r['checksum'],r['csv_value'],r['length_value']] for r in checked['rows']['RESULT']])
        runner.producer_join(result,0,stdout,b'',checked,12)
        for field,value in (('status','FAILED'),('normal_reaps',0),('rescue',True),('cleanup_error','lost'),('sent_bytes',11),
            ('child_pid',124),('child_exit',1),('stdout_sha256','wrong'),('stderr_sha256','wrong'),('totals',{}),('done',{}),('original_values',[])):
            changed=copy.deepcopy(result);changed[field]=value
            with self.assertRaises(AssertionError):runner.producer_join(changed,0,stdout,b'',checked,12)
        originals,installed=runner.catalog()
        result=dict(status='FAILED',revision='a'*40,originals=originals,installed=installed)
        projected=runner.public_projection(result)
        self.assertEqual(len(projected['rows']),352);self.assertFalse(projected['campaign_complete']);self.assertFalse(projected['all_qualified'])
        originals[0].update(status='FAILED',attempts=1,error='/private/secret')
        installed[0].update(status='PASS',attempts=1,calls=0)
        projected=runner.public_projection(result)
        self.assertEqual(projected['rows'][0]['status'],'FAILED');self.assertEqual(projected['rows'][32]['calls'],0)
        self.assertNotIn('/private/secret',json.dumps(projected))
        self.assertEqual(projected['attempts'][0],dict(attempt=1,passed=1,failed=0,unrun=63))

    def test_campaign_closed_functional_failure_continues_but_unknown_custody_stops(self):
        runner=load('reproduce')
        class FakeRun:
            def __init__(self,lose=False):
                self.safe=True;self.cpus=[2,4,6];self.raw=Path('/unused');self.lose=lose;self.seen=[];self.budget=runner.EvidenceBudget();self.deadline=1e30
                self.m={'output':output};self.result={'originals':[dict(leg='original',case=i,status='UNRUN',attempts=0,directory='/unused/o'+str(i),request={'file_bytes':runner.CAP,'wall_seconds':30}) for i in range(2)],'installed':[]}
            def unchanged(self):pass
            def freeze(self,path,value):self.seen.append(value['case'])
            def bounded(self,*args,**kwargs):
                if self.lose:self.safe=False;raise RuntimeError('unknown custody')
                if not self.seen:return 1,b'',b''
                return 0,b'ORIGINAL_READY,module-original-v1,123,123,4,4096,4133,4160,4201,8192,0\nORIGINAL_DONE,0,0,0\n',b''
        run=FakeRun();runner.campaign(run,[(),()],dict(csv_length=37,length_length=41))
        self.assertEqual([r['status'] for r in run.result['originals']],['FAILED','PASS'])
        self.assertEqual(run.seen,[0,1])
        run=FakeRun(True)
        with self.assertRaises(RuntimeError):runner.campaign(run,[(),()],dict(csv_length=37,length_length=41))
        self.assertEqual([r['status'] for r in run.result['originals']],['FAILED','UNRUN'])

    def test_campaign_native_profiles_census_and_complete_retained_counts(self):
        runner=load('reproduce')
        closed=dict(cleanup_complete=True,reaped_descendants=0,termination=None,exit_code=0)
        result=dict(status='NATIVE_SESSION_STATE_PASS',profile='session-absolute-v1',revision='a'*40,pending_owner_controls='UNRUN_SEPARATE_REQUIRED_GATE',
                    custody_closed=True,retention_verified=True,stages=[dict(name=n,status='CLOSED_EXIT_ZERO') for n in runner.NATIVE_STAGES],
                    native=[dict(k=k,status='NATIVE_SESSION_STATE_PASS',attempts=1,required_pairs=32,required_normal_reaps=64,required_target_calls=256,
                                 pairs=32,normal_reaps=64,target_calls=256,target_returns=256,outer_returns=64,rows=[{}]*32,coverage=[{}]*2,closed=closed) for k in (10,1000)])
        runner.native_summary(result,'a'*40,True)
        for field,value in (('status','NATIVE_STATE_PASS'),('profile','finite'),('revision','b'*40),('custody_closed',False),('retention_verified',False),('pending_owner_controls','PASS'),('stages',[])):
            changed=copy.deepcopy(result);changed[field]=value
            with self.assertRaises(AssertionError):runner.native_summary(changed,'a'*40,True)
        for field,value in (('k',16),('attempts',0),('status','FAILED'),('required_pairs',31),('normal_reaps',63),('target_calls',255),('target_returns',255),('outer_returns',63),('rows',[{}]*31),('coverage',[{}])):
            changed=copy.deepcopy(result);changed['native'][0][field]=value
            with self.assertRaises(AssertionError):runner.native_summary(changed,'a'*40,True)
        changed=copy.deepcopy(result);changed['native'].reverse()
        with self.assertRaises(AssertionError):runner.native_summary(changed,'a'*40,True)

    def test_campaign_exact_python_names_and_local_import_refusal(self):
        runner=load('reproduce')
        names=runner.PYTHON_CONTROLS
        self.assertEqual(set(names),{n for n in dir(Controls) if n.startswith('test_')})
        data=('\n'.join(n+' (__main__.Controls.'+n+') ... ok' for n in sorted(names))+'\n\n'+'-'*70+'\n'+f'Ran {len(names)} tests in 0.001s\n\nOK\n').encode('ascii')
        runner.python_controls(b'',data)
        for changed in (data.replace(names[0].encode(),b'wrong'),data.replace(b' ... ok',b' ... skipped',1),data.replace(b'OK\n',b'FAILED\n'),data+b'x'):
            with self.assertRaises(AssertionError):runner.python_controls(b'',changed)
        with self.assertRaises(AssertionError):runner.python_controls(b'x',data)
        completed=subprocess.run([sys.executable,'-B','-O',str(Path(__file__).with_name('reproduce.py')),'--help'],capture_output=True,timeout=5)
        self.assertNotEqual(completed.returncode,0);self.assertEqual(completed.stdout,b'')
        self.assertEqual(completed.stderr,b'assertions required\n')

    def test_campaign_storage_reserves_complete_stage_and_never_refreshes_charge(self):
        runner=load('reproduce');budget=runner.EvidenceBudget()
        budget.room(runner.NATIVE_GROWTH);budget.reserve(runner.NATIVE_GROWTH)
        budget.charge('/closed/first',17)
        self.assertEqual((budget.used,budget.held),(4096,runner.NATIVE_GROWTH-4096))
        budget.charge('/closed/first',17)
        self.assertEqual(budget.used,4096)
        with self.assertRaises(AssertionError):budget.charge('/closed/first',4097)
        budget.complete()
        budget.charge('/closed/large',runner.EVIDENCE_LIMIT-runner.FINAL_ALLOWANCE-4096)
        prior=dict(budget.files)
        with self.assertRaises(AssertionError):budget.reserve(1)
        self.assertEqual(budget.files,prior);self.assertEqual(budget.held,0)
        stopped=runner.EvidenceBudget();stopped.reserve(8192);stopped.charge('/closed/partial',1);stopped.stopped()
        self.assertEqual(stopped.used,8192);self.assertEqual(stopped.held,0)
        bad=runner.EvidenceBudget();bad.reserve(4096)
        with self.assertRaises(AssertionError):bad.charge('/closed/oversize',4097)
        self.assertTrue(bad.exceeded);self.assertIn('/closed/oversize',bad.files)
        exact=runner.EvidenceBudget();exact.reserve(4096);exact.charge('/closed/exact',1)
        with self.assertRaises(AssertionError):exact.charge('/closed/extra',1)
        self.assertTrue(exact.exceeded)
        self.assertEqual(runner.bounded_growth({'file_bytes':runner.CAP},app_files=True),30*runner.MIB)

    def test_campaign_missing_app_identity_stops_and_budget_stop_keeps_unrun(self):
        runner=load('reproduce')
        class FakeRun:
            def __init__(self):
                self.safe=True;self.cpus=[2,4,6];self.raw=Path('/unused');self.budget=runner.EvidenceBudget();self.deadline=1e30;self.m={}
                self.result=dict(originals=[],installed=[dict(leg='installed',case=i,status='UNRUN',attempts=0,
                    directory='/unused/i'+str(i),child_raw='/unused/c'+str(i),request={'file_bytes':runner.CAP,'wall_seconds':30}) for i in range(2)])
            def unchanged(self):pass
            def bounded(self,*args,**kwargs):return 1,b'',b''
            def remember(self,*args,**kwargs):raise FileNotFoundError('no invented APP witness')
        run=FakeRun()
        with self.assertRaises(FileNotFoundError):runner.campaign(run,[(),()],{})
        self.assertFalse(run.safe)
        self.assertEqual([r['status'] for r in run.result['installed']],['FAILED','UNRUN'])
        run=FakeRun();run.budget.charge('/already/retained',runner.EVIDENCE_LIMIT-runner.FINAL_ALLOWANCE)
        with self.assertRaises(AssertionError):runner.campaign(run,[(),()],{})
        self.assertEqual([r['status'] for r in run.result['installed']],['UNRUN','UNRUN'])
        self.assertEqual([r['attempts'] for r in run.result['installed']],[0,0])
        run=FakeRun();run.deadline=0
        with self.assertRaises(AssertionError):runner.campaign(run,[(),()],{})
        self.assertEqual([r['status'] for r in run.result['installed']],['UNRUN','UNRUN'])

    def test_campaign_exact_ordinary_namespaces_keep_unrelated_two_caller_inventory(self):
        runner=load('reproduce');repo=Path(__file__).resolve().parents[2]
        single=runner.load('control_single_inventory',repo/runner.MODULES['single'])
        module=runner.load('control_module_inventory',repo/runner.MODULES['module'])
        wanted=tuple(single.SESSION)+tuple(single.TRACE)+runner.CONSUMER+tuple(module.MODULE_TESTS)+tuple(module.CSV_TESTS)+runner.OWNER_CONTROLS+runner.REUSE_CONTROLS
        self.assertEqual(len(wanted),52)
        unrelated=(
            'normal::session::two::tests::partial_broadcast_full_acknowledgements_and_stop_keep_exact_custody',
            'normal::session::two::check::tests::global_slots_and_retained_ranks_accept_out_of_order_but_refuse_corruption',
            'normal::session::two::exact::tests::exact_subject_authenticates_every_byte_head_extent_and_return')
        inventory=wanted+unrelated
        self.assertEqual(runner.ordinary_inventory(inventory,single,module,runner.OWNER_CONTROLS),wanted)
        self.assertEqual(inventory[-3:],unrelated)
        for absent in wanted:
            with self.assertRaises(AssertionError):
                runner.ordinary_inventory(tuple(n for n in inventory if n!=absent),single,module,runner.OWNER_CONTROLS)
        prefixes=('normal::session::tests::','normal::session::check::tests::',
            'normal::session::epoch_storage::tests::','normal::session::io::tests::',
            'normal::session::io::csv_tests::','normal::session::io::history_tests::',
            'normal::session::loop_trace::tests::',
            'normal::session::protocol::tests::','normal::module::','normal::csv::')
        for prefix in prefixes:
            with self.assertRaises(AssertionError):
                runner.ordinary_inventory(inventory+(prefix+'unexpected_extra',),single,module,runner.OWNER_CONTROLS)

    def test_original_input_refusal_never_accepts_hard_failure(self):
        reasons = ('bad_magic', 'count_over_2048', 'truncated_length', 'truncated_payload',
                   'length_over_64', 'non_ascii_payload', 'malformed_csv', 'trailing_input_byte')
        self.assertEqual(output.ORIGINAL_REFUSALS, reasons)
        for reason in reasons:
            actual = b'module-session-original INPUT_REFUSED: ' + reason.encode('ascii') + b'\n'
            self.assertEqual(output.original_refusal(b'', actual, 2, reason)['reason'], reason)
            for code in (0, 1, -9, True, 3):
                with self.assertRaises(AssertionError): output.original_refusal(b'', actual, code, reason)
            for other in reasons:
                if other != reason:
                    with self.assertRaises(AssertionError): output.original_refusal(b'', actual, 2, other)
            for data in (b'', actual + b'FAILED\n', actual + b'\n', actual.replace(b'\n', b'\r\n'),
                         b'FAILED\n', actual[:-1], bytearray(actual)):
                with self.assertRaises(AssertionError): output.original_refusal(b'', data, 2, reason)
            with self.assertRaises(AssertionError): output.original_refusal(b'ORIGINAL_DONE,0,0,0\n', actual, 2, reason)
            with self.assertRaises(AssertionError): output.original_refusal(b'', actual, 2, 'unknown')

    def refuses(self, rows, args):
        with self.assertRaises((AssertionError, ValueError, UnicodeError, KeyError, IndexError)):
            check(rows, args)

    def test_complete_empty_closed_and_absolute_history_populations(self):
        for n, k, arms, prefix in ((0, 10, 1, 1), (13, 10, 1, 1), (2048, 1000, 520, 513)):
            rows, args = fixture(n, k, arms, prefix)
            result = check(rows, args)
            self.assertEqual(result['totals']['calls'], 2 * n)
            self.assertEqual(result['raw'], encode(rows))
            self.assertEqual(len(result['rows']['REPORT']), arms)

    def test_history_starts_at_one_and_preserves_multi_action_chunks(self):
        rows, args = fixture(1, 10, 520, 513)
        for width in (1, 8):
            grouped = copy.deepcopy(rows)
            for row in grouped:
                if row[0] == 'HISTORY':
                    row[1] = (row[2] - 1) // width + 1
            check(grouped, args)
            shifted = copy.deepcopy(grouped)
            for row in shifted:
                if row[0] == 'HISTORY':
                    row[1] -= 1
            self.refuses(shifted, args)
        oversized = copy.deepcopy(rows)
        for row in oversized:
            if row[0] == 'HISTORY':
                row[1] = (row[2] - 1) // 9 + 1
        self.refuses(oversized, args)

    def test_every_family_missing_duplicate_reorder_and_extra_refuses(self):
        rows, args = fixture()
        for tag in output.FIELDS:
            index = next(i for i, row in enumerate(rows) if row[0] == tag)
            for changed in (rows[:index] + rows[index + 1:], rows[:index] + [rows[index]] + rows[index:]):
                self.refuses(changed, args)
        changed = copy.deepcopy(rows)
        calls = [i for i, row in enumerate(changed) if row[0] == 'CALL']
        changed[calls[0]], changed[calls[1]] = changed[calls[1]], changed[calls[0]]
        self.refuses(changed, args)
        self.refuses(rows + [['UNKNOWN', 0]], args)

    def test_scalar_input_fingerprint_and_complete_results_are_independent(self):
        rows, args = fixture()
        for tag, positions in (('RESULT', range(1, 8)), ('COVERAGE', range(1, 9))):
            index = next(i for i, row in enumerate(rows) if row[0] == tag)
            for position in positions:
                changed = copy.deepcopy(rows); changed[index][position] += 1
                self.refuses(changed, args)
        wrong = dict(args, records=((b'a,b', 3),) * 3)
        self.refuses(rows, wrong)

    def test_global_slots_function_ranks_closed_budget_and_report_order(self):
        rows, args = fixture(13)
        for tag, positions in (('CALL', (1, 2, 3, 5, 6, 7, 18)), ('SAMPLE', (1, 2, 3, 4, 5, 6, 7, 9)), ('REPORT', (1, 2))):
            index = next(i for i, row in enumerate(rows) if row[0] == tag)
            for position in positions:
                changed = copy.deepcopy(rows); changed[index][position] += 1
                self.refuses(changed, args)
        changed = copy.deepcopy(rows)
        first = next(row for row in changed if row[0] == 'CALL')
        first[4], first[6] = 'closed', 0
        self.refuses(changed, args)
        changed = copy.deepcopy(rows)
        sample_rows = [i for i, row in enumerate(changed) if row[0] == 'SAMPLE']
        changed[sample_rows[0]], changed[sample_rows[1]] = changed[sample_rows[1]], changed[sample_rows[0]]
        self.refuses(changed, args)

    def test_stack_continuation_ack_and_batch_boundaries(self):
        rows, args = fixture()
        index = next(i for i, row in enumerate(rows) if row[0] == 'CALL')
        for position, value in ((8, 35), (9, 8), (9, 120), (9, (1 << 64) - 1), (9, 4096), (10, 8210), (16, 0), (17, 0)):
            changed = copy.deepcopy(rows); changed[index][position] = value
            self.refuses(changed, args)
        changed = copy.deepcopy(rows)
        changed[index][15:18] = ['checkpoint', 0, 1]
        changed[index + 1][17] = 2
        self.refuses(changed, args)
        for value in (136, (1 << 64) - 24):
            changed = copy.deepcopy(rows)
            for row in changed:
                if row[0] == 'CALL': row[9] = value
            check(changed, args)

    def test_zero_maximum_and_raw_unavailable_are_retained(self):
        rows, args = fixture()
        for start, end, a, b, kind, value in ((0, 0, 0, 0, 'value', 0),
                (output.U64, output.U64, output.U32, output.U32, 'value', output.U64),
                (output.U64, 0, 0, 0, 'unavailable', 2), (0, output.U64, 0, 1, 'unavailable', 1)):
            changed = copy.deepcopy(rows)
            for row in changed:
                if row[0] == 'CALL': row[11:15] = [start, end, a, b]
                if row[0] == 'SAMPLE': row[7:10] = [start, kind, value]
            check(changed, args)
            for row in changed:
                if row[0] == 'SAMPLE': row[9] = (value + 1) & output.U64; break
            self.refuses(changed, args)

    def test_eof_typed_refusal_and_incomplete_are_distinct(self):
        for outcome, error in (('eof', 'none'), ('input_incomplete', 'none'),
                               ('input_error', 'syntax'), ('input_error', 'unterminated'), ('input_error', 'record_limit')):
            rows, args = fixture(outcome=outcome, error=error)
            check(rows, args)
            changed = copy.deepcopy(rows); changed[-1][1] = 'COMPLETE' if outcome != 'eof' else 'INPUT_REFUSED'
            self.refuses(changed, args)
            if error == 'unterminated':
                changed = copy.deepcopy(rows); changed[-1][14] = 0
                self.refuses(changed, args)
        rows, args = fixture()
        for position in range(3, 19):
            if position == 15: continue
            changed = copy.deepcopy(rows); changed[-1][position] += 1
            self.refuses(changed, args)

    def test_numeric_framing_actual_stderr_and_caps(self):
        rows, args = fixture()
        index = next(i for i, row in enumerate(rows) if row[0] == 'CALL')
        for bad in ('', '+1', '-1', '01', ' 1', '1 ', str(1 << 64), '١'):
            changed = copy.deepcopy(rows); changed[index][1] = bad
            with self.assertRaises((AssertionError, ValueError, UnicodeError)):
                output.check(('\n'.join(','.join(map(str, row)) for row in changed) + '\n').encode(), b'', **args)
        data = encode(rows)
        for malformed in (data[:-1], data + b'\n', data.replace(b'\n', b'\r\n'), b'x' * (output.CAP + 1)):
            with self.assertRaises((AssertionError, ValueError, UnicodeError)):
                output.check(malformed, b'', **args)
        with self.assertRaises(AssertionError): output.check(data, b'real stderr', **args)

    def test_actual_stderr_requires_exact_finalized_outcome_and_no_hard_diagnostic(self):
        outcomes = (
            ('eof', 'none', b''),
            ('input_incomplete', 'none', b'normal-module-session INPUT_INCOMPLETE\n'),
            ('input_error', 'syntax', b'normal-module-session INPUT_REFUSED: syntax\n'),
            ('input_error', 'overlong', b'normal-module-session INPUT_REFUSED: overlong\n'),
            ('input_error', 'unterminated', b'normal-module-session INPUT_REFUSED: unterminated\n'),
            ('input_error', 'record_limit', b'normal-module-session INPUT_REFUSED: record_limit\n'),
        )
        hard = b'normal-module-session FAILED: final-output; task retirement pending\n'
        for outcome, error, stderr in outcomes:
            rows, args = fixture(outcome=outcome, error=error)
            data = encode(rows)
            self.assertEqual(output.check(data, stderr, **args)['raw'], data)
            wrong = [other for _, _, other in outcomes if other != stderr]
            wrong += [stderr + hard, hard + stderr, stderr + b'\n', b' ' + stderr,
                      stderr + b'\xff', stderr.decode('ascii'), bytearray(stderr)]
            if stderr:
                wrong += [stderr[:-1], stderr.replace(b'\n', b'\r\n')]
            for actual in wrong:
                with self.assertRaises((AssertionError, ValueError, UnicodeError)):
                    output.check(data, actual, **args)
            if outcome == 'input_error':
                # Coherent transcript+diagnostic changes still cannot change the
                # independently frozen expected reason passed by the producer.
                changed = copy.deepcopy(rows)
                other = 'overlong' if error == 'syntax' else 'syntax'
                changed[-1][15] = other
                actual = ('normal-module-session INPUT_REFUSED: ' + other + '\n').encode('ascii')
                with self.assertRaises(AssertionError):
                    output.check(encode(changed), actual, **args)
        original = encode([
            ['ORIGINAL_READY', 'module-original-v1', 9, 9, 4, 4096, 4133, 4160, 4201, 8192, 0],
            ['ORIGINAL_DONE', 0, 0, 0],
        ])
        output.original_check(original, b'', records=(), lengths=(37, 41), cpu=4)
        for actual in [hard] + [stderr for _, _, stderr in outcomes if stderr]:
            with self.assertRaises(AssertionError):
                output.original_check(original, actual, records=(), lengths=(37, 41), cpu=4)

    def test_original_reference_uses_all_values_and_exact_population(self):
        records = ((b'', 1), (b'a,b', 2))
        rows = [['ORIGINAL_READY', 'module-original-v1', 9, 9, 4, 4096, 4133, 4160, 4201, 8192, 2]]
        rows += [['ORIGINAL', i, len(data), output.fnv(data), count, len(data)] for i, (data, count) in enumerate(records, 1)]
        rows += [['ORIGINAL_DONE', 2, 4, 4]]
        output.original_check(encode(rows), b'', records=records, lengths=(37, 41), cpu=4)
        for index, positions in ((0, (2, 3, 4, 5, 6, 7, 8, 10)), (1, range(1, 6)), (3, range(1, 4))):
            for position in positions:
                changed = copy.deepcopy(rows); changed[index][position] += 1
                with self.assertRaises(AssertionError):
                    output.original_check(encode(changed), b'', records=records, lengths=(37, 41), cpu=4)

    def test_fixed_catalog_has_exact_special_inputs_and_error_classes(self):
        corpus = load('corpus')
        cases = [produce.case_spec(corpus, i) for i in range(32)]
        self.assertEqual(len({case['name'] for case in cases}), 32)
        self.assertEqual([case['input_error'] for case in cases[4:25]], ['syntax'] * 16 + ['overlong'] * 2 + ['unterminated'] * 3)
        self.assertEqual(cases[30]['records'], corpus.LITERALS * 3)
        self.assertEqual(len(cases[31]['records']), 2048)
        self.assertTrue(all(r.payload == b'x' * 64 and r.fields == 1 for r in cases[31]['records']))
        self.assertEqual([i for i, case in enumerate(cases) if not case['close']], [27, 28, 29])

    def test_optimization_refuses_before_production_checks(self):
        for name in ('output.py', 'produce.py', 'controls.py'):
            run = subprocess.run([sys.executable, '-O', '-B', str(Path(__file__).with_name(name))],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(run.returncode, 1)
            self.assertEqual(run.stdout, b'')
            self.assertEqual(run.stderr, b'assertions required\n')


if __name__ == '__main__':
    unittest.main()
