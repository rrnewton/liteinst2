"""Inert prospective controls. No project command, probe or population dispatch."""
import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import reproduce_preparation as D
import platform_inputs as P

BASE = Path(__file__).resolve().parent


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); (self.root/'ignored').mkdir()
        self.python = Path(sys.executable).resolve()

    def plan(self, stage, arguments=(), history=()):
        return dict(schema='LI2-PREPARATION-COMMAND-1', stage=stage, arguments=list(arguments), history=list(history))

    def file(self, name, raw=b'{}'):
        path = self.root/'ignored'/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        return dict(path=str(path), sha256=D.sha(raw))

    def producer(self):
        history = [self.file('history'+str(i)) for i in range(6)]
        values = {key:'value' for key in D.FLAGS['producer']}
        values['original-profile'] = 'startup-original-facts-readonly-headerpad-v1'
        return self.plan('producer', [v for k,x in values.items() for v in ('--'+k,x)], history)

    def test_controls_have_no_filter_or_native_followup(self):
        for stage in ('controls', 'profiler-controls', 'reproducer-controls'):
            actual = D.command(self.root, self.python, self.plan(stage))
            self.assertEqual(actual[:2], [str(self.python), '-B'])
            self.assertNotIn('observe', actual); self.assertNotIn('n01', actual)
            with self.assertRaises(ValueError): D.command(self.root, self.python, self.plan(stage, ['--output','x']))
        with self.assertRaises(ValueError): D.command(self.root, self.python, self.plan('unknown'))

    def test_exact_producer_history_and_flag_overrides(self):
        plan = self.producer(); actual = D.command(self.root, self.python, plan)
        self.assertEqual(actual.count('--failure-history'), 6)
        self.assertEqual(actual[-12::2], ['--failure-history']*6)
        self.assertEqual(actual[-11::2], [x['path'] for x in plan['history']])
        for flag in ('--original-pro', '--original-profile=other'):
            bad = json.loads(json.dumps(plan)); bad['arguments'][bad['arguments'].index('--original-profile')] = flag
            with self.assertRaises(ValueError): D.command(self.root, self.python, bad)
        full = [self.file('history'+str(i)) for i in range(64)]
        for history in ([], full[:5], full[:7], full):
            actual = D.command(self.root, self.python, dict(plan, history=history))
            self.assertEqual(actual.count('--failure-history'), len(history))
        for history in (full+[self.file('history64')], plan['history']+[plan['history'][0]],
                        [plan['history'][0]]*6, [{'path': plan['history'][0]['path']}]):
            with self.assertRaises(ValueError): D.command(self.root, self.python, dict(plan, history=history))
        with self.assertRaises(ValueError): D.command(self.root, self.python, self.plan('controls', history=full[:1]))
        missing = dict(plan); del missing['history']
        with self.assertRaises(ValueError): D.command(self.root, self.python, missing)
        Path(plan['history'][0]['path']).write_bytes(b'changed')
        with self.assertRaises(ValueError): D.command(self.root, self.python, plan)

    def test_native_is_separate_and_never_derives_acceptance(self):
        accepted = '1'*64
        profile = self.file('profile', json.dumps(dict(contract=dict(sha256=accepted))).encode())
        values = dict(root=str(self.root), **{'final-profile':profile['path'], 'final-profile-sha256':profile['sha256'],
                      'accept-contract-sha256':accepted, 'output':str(self.root/'ignored/native')})
        tail = [v for k,x in values.items() for v in ('--'+k,x)]
        for stage in ('observe','n01'):
            self.assertEqual(D.command(self.root,self.python,self.plan(stage,tail))[3],stage)
            removed = tail[:6]+tail[8:]
            with self.assertRaises(ValueError): D.command(self.root,self.python,self.plan(stage,removed))
            wrong = tail.copy(); wrong[wrong.index('--accept-contract-sha256')+1] = '2'*64
            with self.assertRaises(ValueError): D.command(self.root,self.python,self.plan(stage,wrong))
            with self.assertRaises(ValueError): D.command(self.root,self.python,self.plan(stage,tail+['--program','checksum']))
        Path(profile['path']).write_bytes(b'changed')
        with self.assertRaises(ValueError): D.command(self.root,self.python,self.plan('observe',tail))

    def test_revision_clean_source_and_new_output_refuse_exactly(self):
        with mock.patch.object(D,'git',return_value=b'other\n'):
            with self.assertRaisesRegex(ValueError,'exact committed revision'): D.snapshot(self.root,'a'*40)
        with mock.patch.object(D,'git',side_effect=[b'a'*40+b'\n',b'changed']):
            with self.assertRaisesRegex(ValueError,'clean tracked source'): D.snapshot(self.root,'a'*40)
        with mock.patch.object(D,'git',side_effect=[b'a'*40+b'\n',b'',b'untracked']):
            with self.assertRaisesRegex(ValueError,'untracked source'): D.snapshot(self.root,'a'*40)
        ref = self.file('existing',b'keep')
        with self.assertRaises(ValueError): D.private(self.root,Path(ref['path']))
        self.assertEqual(Path(ref['path']).read_bytes(),b'keep')

    def test_external_digest_and_symlink_refuse(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON key'): D.decode(b'{"stage":"controls","stage":"observe"}')
        with self.assertRaisesRegex(ValueError,'nonfinite JSON'): D.decode(b'{"value":NaN}')
        ref = self.file('input')
        self.assertEqual(D.read(ref['path'],ref['sha256']),b'{}')
        with self.assertRaises(ValueError): D.read(ref['path'],'0'*64)
        link = self.root/'ignored/link'; link.symlink_to(ref['path'])
        with self.assertRaises(ValueError): D.read(link,ref['sha256'])

    def references(self):
        for name in ('producer/originals/closed.json','producer/producer/receipt.json','producer/startup-binding.json',
                     'verifier/build/closed.json','joins/closed.json','bootstrap/closed.json','observer/closed.json'):
            self.file(name)
        lock = self.root/D.ARTIFACT/'Cargo.lock'; lock.parent.mkdir(parents=True); lock.write_bytes(b'lock')
        value = dict(schema='LI2-PREPARATION-REFERENCES-1', producer=str(self.root/'ignored/producer'),
            verifier=str(self.root/'ignored/verifier'), joins=str(self.root/'ignored/joins'), bootstrap=str(self.root/'ignored/bootstrap'),
            observer_plan=self.file('observer-plan')['path'], observer_build=str(self.root/'ignored/observer'),
            contract=self.file('contract',b'{"external_acceptance":"unchanged"}'),
            xstate={name:self.file('probe-'+name) for name in ('owner_source','owner_receipt','log','raw')})
        plan = self.file('references',json.dumps(value).encode())
        args = types.SimpleNamespace(root=self.root,revision='a'*40,plan=Path(plan['path']),plan_sha256=plan['sha256'],output=self.root/'ignored/inputs')
        return value,args

    def test_final_inputs_serialize_current_refs_not_approval(self):
        value,args = self.references()
        with mock.patch.object(D,'snapshot'),mock.patch.object(D,'git',return_value=Path(D.__file__).read_bytes()):
            self.assertEqual(D.final_inputs(args),0)
        result = json.loads(args.output.read_bytes())
        self.assertEqual(result['schema'],'LI2NATIVE-FINAL-PROFILE-INPUTS-1')
        self.assertEqual(result['contract'],value['contract']);self.assertEqual(result['xstate'],value['xstate'])
        self.assertEqual(result['arguments']['capture_sha256'],D.sha(b'{}'))
        self.assertNotIn('execution_authorized',result);self.assertNotIn('reviewed',result)

    def test_final_input_contract_and_late_drift_preserve_refusal(self):
        value,args = self.references(); Path(value['contract']['path']).write_bytes(b'changed')
        with mock.patch.object(D,'snapshot'),mock.patch.object(D,'git',return_value=Path(D.__file__).read_bytes()):
            with self.assertRaises(ValueError):D.final_inputs(args)
        self.assertFalse(args.output.exists())
        Path(value['contract']['path']).write_bytes(b'{"external_acceptance":"unchanged"}')
        real = D.read; seen = []
        def changed(path,expected=None):
            if str(path)==value['contract']['path']:
                seen.append(path)
                if len(seen)==2:Path(path).write_bytes(b'replaced')
            return real(path,expected)
        with mock.patch.object(D,'snapshot'),mock.patch.object(D,'git',return_value=Path(D.__file__).read_bytes()),mock.patch.object(D,'read',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'input changed'):D.final_inputs(args)
        self.assertFalse(args.output.exists())

    def test_platform_capture_keeps_commands_bounds_and_false_authority(self):
        files=[self.file('platform'+str(i),b'ELF')['path'] for i in range(5)]
        output=self.root/'ignored/platform'; calls=[]
        def inspect(argv,**kwargs):
            calls.append((argv,kwargs));return subprocess.CompletedProcess(argv,0,b'facts',b'')
        with mock.patch.object(P,'FILES',files),mock.patch.object(P,'resolution',return_value={'facts':'stable'}),mock.patch.object(P.subprocess,'run',side_effect=inspect):
            P.capture(output)
        receipt=json.loads((output/'receipt.json').read_bytes())
        self.assertEqual(len(calls),4);self.assertEqual([c[0][0] for c in calls],['/usr/bin/readelf']*3+['/sbin/ldconfig'])
        self.assertTrue(all(c[1]['timeout']==10 and c[1]['env']=={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'} for c in calls))
        self.assertFalse(receipt['qualification']);self.assertEqual(receipt['launches'],0)
        self.assertFalse((output/'contract.json').exists())

    def test_platform_failure_keeps_raw_error_without_success_receipt(self):
        files=[self.file('platform'+str(i))['path'] for i in range(5)];output=self.root/'ignored/failed'
        result=subprocess.CompletedProcess(['readelf'],1,b'partial',b'error')
        with mock.patch.object(P,'FILES',files),mock.patch.object(P,'resolution',return_value={}),mock.patch.object(P.subprocess,'run',return_value=result):
            with self.assertRaisesRegex(ValueError,'passive command failure'):P.capture(output)
        self.assertEqual((output/'readelf-0.stderr').read_bytes(),b'error')
        self.assertEqual(json.loads((output/'command-1.json').read_bytes())['exit'],1)
        self.assertFalse((output/'receipt.json').exists())

    def test_owner_preserves_phase_cleanup_and_source_failure(self):
        driver = self.root/D.CORPUS/'reproduce_preparation.py'; driver.parent.mkdir(parents=True)
        driver_raw = (BASE/'reproduce_preparation.py').read_bytes(); driver.write_bytes(driver_raw)
        helper = self.root/D.PROCESS
        fake = ("def run_command(argv, env, log, timeout, cap):\n"
                "    log.write_bytes(b'owned failure')\n"
                "    return dict(exit_code=1, termination=None, cleanup_complete=False, reaped_descendants=0, private_log_sha256='unread')\n").encode()
        plan = self.file('owner-plan',json.dumps(self.plan('controls')).encode())
        args = types.SimpleNamespace(root=self.root,revision='a'*40,plan=Path(plan['path']),plan_sha256=plan['sha256'],
            output=self.root/'ignored/owner',python=self.python,toolchain=self.root,cargo_home=self.root,user_home=self.root,temporary=self.root)
        real = D.read
        def read(path,expected=None): return fake if Path(path)==helper else real(path,expected)
        def git(_root,*arguments): return fake if arguments[-1].endswith(D.PROCESS) else driver_raw
        previous = Path.cwd()
        try:
            with mock.patch.object(D,'__file__',str(driver)),mock.patch.object(D,'read',side_effect=read), \
                 mock.patch.object(D,'git',side_effect=git),mock.patch.object(D,'snapshot',side_effect=[dict(base='a'*40,working_source_sha256={}),ValueError('source drift')]):
                self.assertEqual(D.run(args),1)
        finally: os.chdir(previous)
        record=json.loads((args.output/'owner.json').read_bytes())
        self.assertIsNone(record['closed'])
        self.assertEqual(record['command_closed']['exit_code'],1);self.assertFalse(record['command_closed']['cleanup_complete'])
        self.assertFalse(record['source_unchanged']);self.assertIn('source drift',record['errors'][0])
        self.assertFalse((args.output/'owner.log').exists())
        self.assertEqual(record['wall_limit_seconds'],1200);self.assertEqual(record['output_limit_bytes'],8*1048576)

    def probe_owner(self, fail_final_load):
        # Execute only the owner with an inert command helper. The real existing
        # reader below receives the actual receipt/log/raw files this path wrote.
        driver = self.root/D.CORPUS/'reproduce_preparation.py'; driver.parent.mkdir(parents=True)
        driver_raw = (BASE/'reproduce_preparation.py').read_bytes(); driver.write_bytes(driver_raw)
        checkout = BASE.parents[1]
        native = checkout/D.NATIVE
        spec = importlib.util.spec_from_file_location('_existing_probe_reader', native/'prepare_profile.py')
        reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
        probe = D.NATIVE+'probe_xstate.py'
        source_bytes = {probe:(checkout/probe).read_bytes(), D.PROCESS:(checkout/D.PROCESS).read_bytes()}
        raw = bytes(576); raw_path = self.root/'ignored/probe.raw'
        report = dict(schema='LI2HOST-XSTATE-1', hardware='AMD EPYC Zen 5 dev host',
            probe_sha256=D.sha(source_bytes[probe]), platform='linux-x86_64', request_bytes=16384,
            xstate_bytes=len(raw), xstate_sha256=D.sha(raw), initial_status=(signal.SIGSTOP<<8)|0x7f,
            terminal_status=signal.SIGKILL, child_started=True, child_reaped=True, kill_sent=True,
            absence_proof='ECHILD', raw_saved=True, observation_complete=True,
            command_seconds=15, cleanup_seconds=5, errors=[], exec_dispatches=0,
            candidate_dispatches=0, native_dispatches=0, qualification_complete=False,
            performance_eligible=False, elapsed_seconds=0.0)
        logfile = (json.dumps(report)+'\n').encode()
        child = dict(exit_code=0, termination=None, cleanup_complete=True, reaped_descendants=0,
                     private_log_sha256=D.sha(logfile))
        fake = ("from pathlib import Path\n"
                "def run_command(argv, env, log, timeout, cap):\n"
                "    assert timeout == 1200 and cap == 8*1048576\n"
                "    raw = Path(argv[-1])\n"
                "    raw.write_bytes("+repr(raw)+")\n"
                "    raw.chmod(0o400)\n"
                "    log.write_bytes("+repr(logfile)+")\n"
                "    return "+repr(child)+"\n").encode()
        plan = self.file('probe-plan', json.dumps(self.plan('probe', ['--raw-output', str(raw_path)])).encode())
        args = types.SimpleNamespace(root=self.root,revision='a'*40,plan=Path(plan['path']),plan_sha256=plan['sha256'],
            output=self.root/'ignored/probe-owner',python=self.python,toolchain=self.root,cargo_home=self.root,
            user_home=self.root,temporary=self.root)
        actual_read = D.read
        def read(path,expected=None):
            return fake if Path(path)==self.root/D.PROCESS else actual_read(path,expected)
        def git(_root,*arguments):
            return fake if arguments[-1].endswith(D.PROCESS) else driver_raw
        samples = [0]
        def load(_path,*_args,**_kwargs):
            self.assertEqual(_path,Path('/proc/loadavg')); samples[0] += 1
            if fail_final_load and samples[0]==2: raise OSError('final load unavailable')
            return '0.0 0.0 0.0 1/1 1\n'
        previous = Path.cwd()
        try:
            with mock.patch.object(D,'__file__',str(driver)),mock.patch.object(D,'read',side_effect=read), \
                 mock.patch.object(D,'git',side_effect=git),mock.patch.object(D,'snapshot',return_value=dict(base='a'*40,working_source_sha256={})), \
                 mock.patch.object(Path,'read_text',load),mock.patch.object(D.os,'sched_getaffinity',return_value={0}):
                code = D.run(args)
        finally: os.chdir(previous)
        record = json.loads((args.output/'owner.json').read_bytes())
        self.assertEqual(samples[0],2)
        self.assertEqual(record['command_closed'],child)
        self.assertTrue(record['source_unchanged'])
        self.assertEqual((args.output/'owner.log').read_bytes(),logfile)
        self.assertEqual(raw_path.read_bytes(),raw)
        def ref(path): return dict(path=str(path),sha256=D.sha(path.read_bytes()))
        references = dict(owner_source=ref(driver),owner_receipt=ref(args.output/'owner.json'),
                          log=ref(args.output/'owner.log'),raw=ref(raw_path))
        # Keep real Sources.reference/read, all report predicates and all file
        # checks; only the repository/tool queries use these inert fixtures.
        sources = object.__new__(reader.Sources)
        sources.root=self.root; sources.held={}; sources.pins={probe:D.sha(source_bytes[probe])}
        captured=dict(tools=dict(python=dict(path=str(self.python))))
        context=types.SimpleNamespace(B=types.SimpleNamespace(identity=lambda _path:captured['tools']['python']))
        def source_git(root,*arguments):
            self.assertEqual(root,self.root); self.assertEqual(arguments[0],'show')
            revision,relative=arguments[1].split(':',1); self.assertEqual(revision,'a'*40)
            return source_bytes[relative]
        return code,record,report,reader,sources,references,captured,context,source_git

    def test_successful_owner_reaches_actual_probe_reader(self):
        code,record,report,reader,sources,refs,captured,context,source_git = self.probe_owner(False)
        self.assertEqual(code,0); self.assertEqual(record['errors'],[])
        self.assertEqual(record['closed'],record['command_closed'])
        with mock.patch.object(reader,'git',side_effect=source_git):
            self.assertEqual(reader.probe_measurement(sources,refs,captured,context),report)

    def test_owner_only_failure_refuses_actual_probe_reader(self):
        code,record,report,reader,sources,refs,captured,context,source_git = self.probe_owner(True)
        self.assertEqual(code,1); self.assertIsNone(record['closed'])
        self.assertEqual(record['errors'],['OSError: final load unavailable'])
        self.assertEqual(record['command_closed']['exit_code'],0)
        with mock.patch.object(reader,'git',side_effect=source_git):
            with self.assertRaises(TypeError): reader.probe_measurement(sources,refs,captured,context)

    def test_absolute_final_profile_stage_is_explicit_and_has_exact_flags(self):
        tail=['--inputs','/private/inputs','--inputs-sha256','1'*64,'--output','/private/new']
        for stage in ('final-profile','final-profile-absolute-prerequisites'):
            actual=D.command(self.root,self.python,self.plan(stage,tail))
            self.assertEqual(actual,[str(self.python),'-B',D.NATIVE+'prepare_profile.py',stage,*tail])
            self.assertNotIn('observe',actual);self.assertNotIn('n01',actual)
            with self.assertRaises(ValueError):D.command(self.root,self.python,self.plan(stage,tail+['--accept-contract-sha256','2'*64]))
            with self.assertRaises(ValueError):D.command(self.root,self.python,self.plan(stage,tail[:-2]))

    def test_preserved_profiler_methods_are_exact(self):
        new=(BASE/'profile_preflight_controls.py').read_text()
        before="Path(__file__).parent / 'after/evaluation/offline-router-corpus/profile_preflight.py'"
        after="Path(__file__).with_name('profile_preflight.py')"
        self.assertEqual(new.count(after),1)
        restored=new.replace(after,before).encode()
        self.assertEqual(hashlib.sha256(restored).hexdigest(),
                         '29721af24aea6b3c00cb1414cf36d4bea93b42da4e75486199c872b120d5ea52')
        self.assertEqual(new.count('    def test_'),10)


if __name__=='__main__':unittest.main()
