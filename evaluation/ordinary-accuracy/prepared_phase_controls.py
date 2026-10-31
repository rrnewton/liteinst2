#!/usr/bin/env python3
"""Pure full-population prepared-wire mutants; no application or clock reads."""
import copy
import sys
import unittest
from pathlib import Path

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import prepared_phase_output as output

saved = sys.modules.get('output')
sys.modules['output'] = output.base
try:
    old = output.base._load('_prepared_old_fixtures', Path(__file__).with_name('reader_controls.py'))
finally:
    if saved is None:
        del sys.modules['output']
    else:
        sys.modules['output'] = saved


def fixture(kind='locked', late_periods=0, period=10, prefixes=None):
    rows, args = old.fixture(phase=kind, arms=2, period=period, prefixes=prefixes)
    rows[0][1] = output.VERSION
    period = args['policy']['period_ms'] * 1000000
    delay = args['policy']['delay_ns']
    opened = period + max(delay,20) + 100 + late_periods * period
    out = []
    for row in rows:
        if row[:2] == ['ARM','1']:
            out.append(['PREPARED','1','41','17'])
        elif row[:2] == ['ARM','2']:
            out.append(['TARGET_ARM',*row[1:6]])
        out.append(row)
        if row[0] == 'RET':
            out.append(['PREPARED_PHASE',kind,str(delay),'1',str(period+delay)])
        if row[0] == 'PMU' and row[3] == '1':
            ordinal = int(row[1])
            if ordinal == 1:
                out.extend([['GATE','1','41','5',str(opened)],['RELEASE','1','41',str(opened),str(opened)]])
            before = opened + ordinal * 100
            out.append(['CALLTIME',str(ordinal),str(ordinal),'41',str(before),str(before+10)])
    return out, args


def check(rows,args):
    return output.check(old.encode(rows),b'',**args)


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows,cls.args = fixture()

    def copy(self):
        return copy.deepcopy(self.rows),copy.deepcopy(self.args)

    def refuses(self,rows,args,reason=None):
        raw=old.encode(rows)
        with self.assertRaises(output.Refused) as caught:
            output.check(raw,b'',**args)
        self.assertEqual((caught.exception.raw,caught.exception.stderr),(raw,b''))
        if reason is not None:self.assertIn(reason,caught.exception.reason)

    def test_all_2048_identities_actual_arm2_and_original_phase_fields(self):
        for kind in ('locked','random'):
            rows,args=fixture(kind);result=check(rows,args)
            observed=result['prepared_phase_observations']
            self.assertEqual(result['wire_rows'],rows)
            self.assertEqual(result['raw'],old.encode(rows))
            self.assertEqual(result['totals']['calls'],2048)
            self.assertEqual(len(result['calls']),2048)
            self.assertEqual(observed['prepared'],dict(record_id=1,function_id=41,ready_before_origin_ns=17))
            self.assertEqual(observed['target_epoch'],1)
            self.assertEqual(observed['target_ns'],10000000+args['policy']['delay_ns'])
            self.assertEqual(observed['target_arm']['generation'],102)
            self.assertEqual(observed['target_publication_history_prefix'],2)
            self.assertEqual(observed['target_arm'],{k:result['arms'][1][k] for k in observed['target_arm']})
            for i,call in enumerate(result['calls'],1):
                timing=call['call_timing']
                self.assertEqual((timing['ordinal'],timing['record_id'],timing['function_id']),(i,i,41))
                self.assertEqual((call['call']['record_id'],call['result']['record_id']),(i,i))
                self.assertEqual(timing['before_requested_error_ns'],timing['before_invoke_ns']-args['policy']['delay_ns'])
                self.assertEqual(timing['before_target_error_ns'],timing['before_requested_error_ns']-10000000)
            self.assertEqual(result['phase_observations']['requested'],dict(phase=kind,delay_ns=args['policy']['delay_ns']))
            self.assertEqual(result['phase_observations']['clock'],'shared in-process Instant origin')
            self.assertEqual(observed['phase_realization_status'],'UNRESOLVED')
            self.assertEqual(result['hardware_status'],'UNRESOLVED')

    def test_whole_period_late_complete_population_stays_unresolved(self):
        rows,args=fixture('locked',3);result=check(rows,args)
        observed=result['prepared_phase_observations']
        self.assertEqual((observed['release_target_lateness_ns'],observed['release_target_whole_periods_late']),(30000120,3))
        self.assertEqual(result['phase_observations']['release']['absolute_lateness_ns'],40000120)
        self.assertEqual(result['phase_observations']['release']['epoch_index'],4)
        self.assertEqual(result['calls'][0]['call_timing']['before_target_whole_periods_late'],3)
        self.assertEqual(result['totals']['calls'],2048)
        self.assertEqual(result['requested_phase_status'],'UNRESOLVED')
        self.assertEqual(observed['phase_realization_status'],'UNRESOLVED')
        self.assertEqual(observed['calibration_status'],'UNRESOLVED')

    def test_old_and_new_versions_and_metadata_are_mutually_refused(self):
        rows,args=old.fixture();old.check(rows,args);self.refuses(rows,args)
        for checker in (output.base,output.phase):
            with self.assertRaises(checker.Refused):checker.check(old.encode(self.rows),b'',**self.args)
        for version in ('selected-accuracy-session-v1','selected-accuracy-phase-session-v1','selected-accuracy-prepared-phase-session-v2'):
            rows,args=self.copy();rows[0][1]=version;self.refuses(rows,args)
        rows,args=self.copy();rows[3]=['PHASE','locked','0'];self.refuses(rows,args)

    def test_every_prepared_family_required_once_in_exact_position(self):
        for tag in ('PREPARED_PHASE','PREPARED','TARGET_ARM','GATE','RELEASE','CALLTIME'):
            at=old.first(self.rows,tag)
            self.refuses(self.rows[:at]+self.rows[at+1:],self.args)
            self.refuses(self.rows[:at]+[self.rows[at]]+self.rows[at:],self.args)
            rows,args=self.copy();row=rows.pop(at);rows.insert(at+1,row);self.refuses(rows,args)
        rows,args=self.copy();a,b=old.first(rows,'PREPARED'),old.first(rows,'TARGET_ARM')
        rows[a],rows[b]=rows[b],rows[a];self.refuses(rows,args)

    def test_prepared_gate_release_and_all_timing_identities_are_exact(self):
        for tag,col,value in (('PREPARED',1,'2'),('PREPARED',2,'42'),('TARGET_ARM',1,'1'),
                ('GATE',1,'2'),('GATE',2,'42'),('RELEASE',1,'2'),('RELEASE',2,'42'),
                ('CALLTIME',1,'2'),('CALLTIME',2,'2'),('CALLTIME',3,'42')):
            rows,args=self.copy();rows[old.first(rows,tag)][col]=value;self.refuses(rows,args)
        rows,args=self.copy();last=next(r for r in rows if r[:2]==['CALLTIME','2048'])
        last[2]='2047';self.refuses(rows,args)

    def test_header_delay_epoch_target_and_policy_cannot_be_redefined(self):
        for column,value in ((1,'calibration'),(1,'random'),(2,'1'),(3,'0'),(3,'2'),(4,'0'),(4,'10000001')):
            rows,args=self.copy();rows[3][column]=value;self.refuses(rows,args)
        rows,args=fixture('random');args['policy']['delay_ns']+=1
        rows[3][2]=str(args['policy']['delay_ns']);rows[3][4]=str(10000000+args['policy']['delay_ns'])
        self.refuses(rows,args)
        rows,args=self.copy();args['policy']['target_epoch']=1;self.refuses(rows,args)
        rows,args=self.copy();args['policy']['epochs']=1;rows[0][3]='1';self.refuses(rows,args)

    def test_target_arm_joins_every_actual_field_and_keeps_two_ms_gate(self):
        for col in range(1,6):
            rows,args=self.copy();r=rows[old.first(rows,'TARGET_ARM')];r[col]=str(int(r[col])+1);self.refuses(rows,args)
        rows,args=self.copy();arm=next(r for r in rows if r[:2]==['ARM','2']);target=rows[old.first(rows,'TARGET_ARM')]
        arm[5]='12000000';target[5]=arm[5]
        opened=12000100
        rows[old.first(rows,'GATE')][4]=str(opened)
        rows[old.first(rows,'RELEASE')][3:]=[str(opened)]*2
        for r in rows:
            if r[0]=='CALLTIME':r[4:]=[str(opened+int(r[1])*100),str(opened+int(r[1])*100+10)]
        self.assertTrue(check(rows,args)['recorded_arm_deadlines_satisfied'])
        for accepted in ('0','1'):
            bad=copy.deepcopy(rows);a=next(r for r in bad if r[:2]==['ARM','2'])
            a[5:]=['12000001',accepted];bad[old.first(bad,'TARGET_ARM')][5]='12000001'
            self.refuses(bad,args)

        for prefix in (0,1):
            bad,args=fixture(prefixes=[prefix]*2048)
            self.refuses(bad,args,'prepared first call precedes actual target publication')
        rows,args=fixture(prefixes=[3]*2048)
        self.assertEqual(check(rows,args)['calls'][0]['call']['history_prefix'],3)

    def test_target_gate_admission_samples_and_clock_regressions_refuse(self):
        for tag,col,value in (('GATE',3,'10000121'),('GATE',4,'9999999'),('GATE',4,'10000019'),
                ('GATE',4,'10000119'),('RELEASE',3,'10000119'),('RELEASE',4,'10000121'),
                ('CALLTIME',4,'10000119'),('CALLTIME',5,'0')):
            rows,args=self.copy();rows[old.first(rows,tag)][col]=value;self.refuses(rows,args)
        rows,args=self.copy();r=next(r for r in rows if r[:2]==['CALLTIME','2']);r[4]='10000209';self.refuses(rows,args)

    def test_first_admission_original_end_and_all_return_fences_are_strict(self):
        rows,args=self.copy();end=args['policy']['epochs']*10000000
        rows[old.first(rows,'GATE')][4]=str(end)
        rows[old.first(rows,'RELEASE')][3:]=[str(end)]*2
        for r in rows:
            if r[0]=='CALLTIME':r[4:]=[str(end+int(r[1])*100),str(end+int(r[1])*100+10)]
        self.refuses(rows,args,'actual admission samples before original end')
        rows,args=self.copy();r=next(r for r in rows if r[:2]==['CALLTIME','2048']);r[5]=str(end+2000000000)
        self.refuses(rows,args,'original call safety fence')
        rows,args=self.copy();r=rows[old.first(rows,'CALLTIME')];r[4:]=[str(end),str(end+10)]
        self.refuses(rows,args)

    def test_partial_populations_and_cancelled_done_never_become_success(self):
        for tag in ('CALL','RESULT','PMU','CALLTIME'):
            rows,args=self.copy();at=old.first(rows,tag);del rows[at];self.refuses(rows,args)
        rows,args=self.copy();rows=[r for r in rows if not (r[0]=='CALLTIME' and r[1]=='2048')];self.refuses(rows,args)
        cancellation=['CANCELLED','1','41','never_invoked','10000000','1','0']
        self.refuses(self.rows+[cancellation],self.args,'cancellation')
        self.refuses(self.rows[:old.first(self.rows,'CALL')]+[cancellation,self.rows[-1]],self.args,'cancellation')
        for tag,col in (('HISTORY',2),('CALL',3),('RESULT',4),('SAMPLE',5),('COVERAGE',2),('DONE',6)):
            rows,args=self.copy();r=rows[old.first(rows,tag)];r[col]=str(int(r[col])+1);self.refuses(rows,args)

    def test_all_new_clock_fields_require_canonical_u64_words(self):
        for tag,cols in (('PREPARED',(3,)),('TARGET_ARM',(2,3,4,5)),('GATE',(3,4))):
            for col in cols:
                for value in ('01','+1','-1',str(1<<64),'','1.0'):
                    rows,args=self.copy();rows[old.first(rows,tag)][col]=value;self.refuses(rows,args)

    def test_raw_pmu_unavailability_is_retained_without_qualification(self):
        rows,args=self.copy();rows[old.first(rows,'PMUOPEN')][3:]=['-1','13']
        for row in rows:
            if row[0]=='PMUCTL':row[2:]=old.ABSENT
            elif row[0]=='PMU':row[11],row[12:]='-',old.ABSENT
        result=check(rows,args)
        self.assertEqual(result['acquisition']['open'],dict(result=-1,errno=13))
        self.assertEqual(len(result['calls']),2048)
        self.assertTrue(all(c['counter_arithmetic']['kind']=='missing' for c in result['calls']))
        self.assertTrue(all('open_failed' in c['observed_limitations'] for c in result['calls']))
        self.assertEqual(result['prepared_phase_observations']['phase_realization_status'],'UNRESOLVED')
        self.assertEqual(result['hardware_status'],'UNRESOLVED')

    def test_finite_new_envelope_is_derived_and_old_caps_unchanged(self):
        self.assertEqual(output.row_limit(520),6*2048+3*520+25)
        self.assertEqual((output.row_limit(520),output.envelope_limit(520),output.phase.row_limit(520)),(13873,13874,13870))
        self.assertEqual((output.CAP,output.LINE),(8*1048576,350))
        self.assertLess(output.envelope_limit(520)*350,output.CAP)
        for epochs in (0,1,521,True):
            with self.assertRaises(ValueError):output.row_limit(epochs)
        for raw in (b'x'*(output.CAP+1),b'x'*350+b'\n',b'x\n'*(13873+1)):
            with self.assertRaises(output.Refused) as caught:output.check(raw,b'',**self.args)
            self.assertEqual(caught.exception.raw,raw)
        with self.assertRaises(output.Refused) as caught:output.check(old.encode(self.rows),b'failure',**self.args)
        self.assertEqual(caught.exception.stderr,b'failure')

    def test_complete_original_inputs_geometry_and_caller_still_required(self):
        for key in ('manifest_bytes','input_bytes','selected_bytes','truth_bytes','body_bytes'):
            rows,args=self.copy();args[key]=args[key][:-1];self.refuses(rows,args)
        for key,value in (('abi','guessed'),('caller',dict(extent=19,continuation=15)),
                ('table',(dict(self.args['table'][0],policy='certified'),))):
            rows,args=self.copy();args[key]=value;self.refuses(rows,args)


if __name__ == '__main__':
    unittest.main()
