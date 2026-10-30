#!/usr/bin/env python3
"""Bounded source proposal controls; author has not executed them."""
import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('prepare_profile',Path(__file__).with_name('prepare_profile.py'))
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)


def encoded(value):return (json.dumps(value,sort_keys=True)+'\n').encode()


class Fixture:
    def __init__(self):
        self.root=Path('/review-root');self.probe=P.NATIVE+'probe_xstate.py'
        self.raw=bytes(576);self.probe_hash=P.sha(b'reviewed probe')
        self.report=dict(schema='LI2HOST-XSTATE-1',hardware='AMD EPYC Zen 5 dev host',
            probe_sha256=self.probe_hash,platform='linux-x86_64',request_bytes=16384,
            xstate_bytes=len(self.raw),xstate_sha256=P.sha(self.raw),initial_status=4991,
            terminal_status=9,child_started=True,child_reaped=True,kill_sent=True,
            absence_proof='ECHILD',raw_saved=True,observation_complete=True,
            command_seconds=15,cleanup_seconds=5,errors=[],exec_dispatches=0,
            candidate_dispatches=0,native_dispatches=0,qualification_complete=False,
            performance_eligible=False,elapsed_seconds=0.01)
        self.tool=dict(path='/review-python',sha256='1'*64)
        self.owner=dict(base='2'*40,working_source_sha256={self.probe:self.probe_hash,
            'evaluation/admission/processes.py':P.PROCESS_SHA},source_unchanged=True,attempts=1,
            command=[self.tool['path'],'-B',self.probe,'--raw-output','/review/raw'],
            env={'CARGO_TARGET_DIR':str(self.root/'target')},wall_limit_seconds=1200,
            output_limit_bytes=8*P.MIB,hardware='AMD EPYC Zen 5 dev host',
            closed=dict(exit_code=0,cleanup_complete=True,reaped_descendants=0,termination=None))

    def run(self,log_suffix=b'',corrupt_log_pin=False):
        log=encoded(self.report)+log_suffix
        self.owner['closed']['private_log_sha256']='0'*64 if corrupt_log_pin else P.sha(log)
        values=dict(owner_source=b'reviewed external owner',owner_receipt=encoded(self.owner),log=log,raw=self.raw)
        refs={name:dict(path='/review/'+name.replace('owner_source','owner.py'),sha256=P.sha(raw))
              for name,raw in values.items()}
        mapping={refs[name]['path']:raw for name,raw in values.items()}
        def reference(ref,cap=P.MIB):
            raw=mapping[ref['path']]
            P.need(len(raw)<=cap and P.sha(raw)==ref['sha256'],'fixture frozen reference')
            return raw
        sources=types.SimpleNamespace(root=self.root,pins={self.probe:self.probe_hash},reference=reference,
            held={refs['raw']['path']:(self.raw,{'stat':[1,2,stat.S_IFREG|0o400,len(self.raw),3,4]})})
        context=types.SimpleNamespace(B=types.SimpleNamespace(identity=lambda _:copy.deepcopy(self.tool)))
        return P.probe_measurement(sources,refs,{'tools':{'python':self.tool}},context)


class MeasurementControls(unittest.TestCase):
    def test_exact_closed_measurement_positive(self):
        self.assertEqual(Fixture().run()['xstate_bytes'],576)

    def test_failed_old_owner_never_promoted(self):
        f=Fixture();f.owner['closed']['exit_code']=1
        with self.assertRaisesRegex(ValueError,'successful unchanged-source'):f.run()

    def test_owner_cleanup_and_source_change_refuse(self):
        for key in ('cleanup_complete','source_unchanged'):
            with self.subTest(key=key):
                f=Fixture();(f.owner['closed'] if key=='cleanup_complete' else f.owner)[key]=False
                with self.assertRaisesRegex(ValueError,'successful unchanged-source'):f.run()

    def test_log_binding_and_wrapper_output_refuse(self):
        with self.assertRaisesRegex(ValueError,'exact child stdout'):Fixture().run(corrupt_log_pin=True)
        with self.assertRaisesRegex(ValueError,'single child JSON'):Fixture().run(log_suffix=b'wrapper\n')

    def test_raw_hash_and_short_coherent_extent_refuse(self):
        f=Fixture();f.raw=bytes([1])*576
        with self.assertRaisesRegex(ValueError,'raw xstate length/hash'):f.run()
        f=Fixture();f.raw=bytes(511);f.report.update(xstate_bytes=511,xstate_sha256=P.sha(f.raw))
        with self.assertRaisesRegex(ValueError,'raw xstate length/hash'):f.run()

    def test_full_request_buffer_remains_required(self):
        f=Fixture();f.report['request_bytes']=576
        with self.assertRaisesRegex(ValueError,'unchanged probe bounds'):f.run()

    def test_terminal_cleanup_and_absence_are_exact(self):
        for key,value in (('terminal_status',0),('child_reaped',False),('absence_proof','empty-directory')):
            with self.subTest(key=key):
                f=Fixture();f.report[key]=value
                with self.assertRaisesRegex(ValueError,'stopped/killed/reaped'):f.run()

    def test_probe_source_is_actual_committed_source(self):
        f=Fixture();f.report['probe_sha256']='3'*64
        with self.assertRaisesRegex(ValueError,'exact observed probe'):f.run()

    def test_no_candidate_or_qualification_promotion(self):
        for key,value in (('candidate_dispatches',1),('qualification_complete',True),('performance_eligible',True)):
            with self.subTest(key=key):
                f=Fixture();f.report[key]=value
                with self.assertRaisesRegex(ValueError,'no execution/qualification promotion'):f.run()

    def test_same_bytes_replacement_cannot_reset_held_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input';path.write_bytes(b'fixed')
            sources=P.Sources.__new__(P.Sources);sources.held={}
            ref=dict(path=str(path),sha256=P.sha(b'fixed'))
            self.assertEqual(sources.reference(ref),b'fixed')
            pin=sources.held[str(path)][1];changed=copy.deepcopy(pin);changed['stat'][1]+=1
            with mock.patch.object(P,'read',return_value=(b'fixed',changed)):
                with self.assertRaisesRegex(ValueError,'original identity'):sources.reference(ref)


if __name__=='__main__':unittest.main()
