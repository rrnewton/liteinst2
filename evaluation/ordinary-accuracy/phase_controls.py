#!/usr/bin/env python3
"""Pure complete-wire phase mutants; no application or clock observations."""
import copy
import sys
import unittest
from pathlib import Path

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import phase_output as output

saved = sys.modules.get('output')
sys.modules['output'] = output.base
try:
    old = output.base._load('_phase_old_fixtures', Path(__file__).with_name('reader_controls.py'))
finally:
    if saved is None:
        del sys.modules['output']
    else:
        sys.modules['output'] = saved


def fixture(kind='locked', late_periods=0, arms=1, period=10):
    rows, args = old.fixture(phase=kind, arms=arms, period=period)
    rows[0][1] = output.VERSION
    period = args['policy']['period_ms'] * 1000000
    release = max(args['policy']['delay_ns'], 20) + 100 + late_periods * period
    out = []
    for row in rows:
        out.append(row)
        if row[0] == 'RET':
            out.append(['PHASE', kind, str(args['policy']['delay_ns'])])
        if row[:1] == ['PMU'] and row[3] == '1':
            ordinal = int(row[1])
            if ordinal == 1:
                enter = release if args['policy']['delay_ns'] <= 20 or late_periods else 20
                out.append(['RELEASE','1','41',str(enter),str(release)])
            before = release + ordinal * 100
            out.append(['CALLTIME',str(ordinal),str(ordinal),'41',str(before),str(before+10)])
    return out, args


def check(rows, args):
    return output.check(old.encode(rows), b'', **args)


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.args = fixture()

    def copy(self):
        return copy.deepcopy(self.rows), copy.deepcopy(self.args)

    def refuses(self, rows, args, reason=None):
        raw = old.encode(rows)
        with self.assertRaises(output.Refused) as caught:
            output.check(raw, b'', **args)
        self.assertEqual((caught.exception.raw,caught.exception.stderr),(raw,b''))
        if reason is not None:self.assertIn(reason,caught.exception.reason)

    def test_complete_raw_2048_identity_join_and_shared_clock_scope(self):
        rows, args = fixture('random')
        result = check(rows,args)
        self.assertEqual(result['wire_rows'],rows)
        self.assertEqual(result['raw'],old.encode(rows))
        self.assertEqual(len(result['calls']),2048)
        self.assertEqual(result['totals']['calls'],2048)
        for i, call in enumerate(result['calls'],1):
            timing = call['call_timing']
            self.assertEqual((timing['ordinal'],timing['record_id'],timing['function_id']),(i,i,41))
            self.assertEqual(call['call']['record_id'],i)
            self.assertEqual(call['result']['record_id'],i)
            self.assertEqual(timing['after_return_ns']-timing['before_invoke_ns'],10)
        self.assertEqual(result['manifest']['phase'],'calibration')
        self.assertEqual(result['phase_observations']['requested']['phase'],'random')
        self.assertEqual(result['hardware_status'],'UNRESOLVED')
        self.assertEqual(result['requested_phase_status'],'UNRESOLVED')
        self.assertEqual(result['phase_observations']['phase_realization_status'],'UNRESOLVED')
        self.assertTrue(result['phase_observations']['clock_transform'].startswith('NONE:'))

    def test_old_new_and_unknown_versions_mutually_refuse(self):
        rows,args = old.fixture()
        old.output.check(old.encode(rows),b'',**args)
        self.refuses(rows,args)
        with self.assertRaises(output.base.Refused):
            output.base.check(old.encode(self.rows),b'',**self.args)
        for value in ('selected-accuracy-session-v1','selected-accuracy-phase-session-v2','selected-session-v1'):
            rows,args = self.copy();rows[0][1] = value;self.refuses(rows,args)

    def test_phase_request_matches_exact_manifest_not_population_phase(self):
        for kind,delay in (('calibration','0'),('random','0'),('locked','1')):
            rows,args = self.copy();rows[3] = ['PHASE',kind,delay];self.refuses(rows,args)
        rows,args = fixture('random');args['policy']['delay_ns'] += 1
        rows[3][2] = str(args['policy']['delay_ns']);self.refuses(rows,args)

    def test_each_family_is_required_once_in_its_exact_position(self):
        for tag in ('PHASE','RELEASE','CALLTIME'):
            at = old.first(self.rows,tag)
            self.refuses(self.rows[:at]+self.rows[at+1:],self.args)
            self.refuses(self.rows[:at]+[self.rows[at]]+self.rows[at:],self.args)
            rows,args = self.copy();row=rows.pop(at);rows.insert(at+1,row);self.refuses(rows,args)
        rows,args = self.copy();rows.append(['CALLTIME','2049','2049','41','1','2']);self.refuses(rows,args)

    def test_all_timing_and_release_identity_fields_are_exact(self):
        for tag,col,value in (('RELEASE',1,'2'),('RELEASE',2,'42'),('CALLTIME',1,'2'),
                              ('CALLTIME',2,'2'),('CALLTIME',3,'42')):
            rows,args=self.copy();rows[old.first(rows,tag)][col]=value;self.refuses(rows,args)
        rows,args=self.copy();at=next(i for i,r in enumerate(rows) if r[:2]==['CALLTIME','2048'])
        del rows[at];self.refuses(rows,args)

    def test_clock_order_and_original_safety_fence_are_strict(self):
        for tag,col,value in (('RELEASE',3,'19'),('RELEASE',3,'119'),('RELEASE',4,'19'),('CALLTIME',4,'119'),
                              ('CALLTIME',5,'0')):
            rows,args=self.copy();rows[old.first(rows,tag)][col]=value;self.refuses(rows,args)
        rows,args=self.copy();at=next(i for i,r in enumerate(rows) if r[:2]==['CALLTIME','2'])
        rows[at][4:]=['200','210'];self.refuses(rows,args)
        rows,args=fixture('random');rows[old.first(rows,'RELEASE')][4]='20';self.refuses(rows,args)
        rows,args=self.copy();rows[next(i for i,r in enumerate(rows) if r[:2]==['CALLTIME','2048'])][5]='7200000000'
        self.refuses(rows,args,'original call safety fence')

    def test_noncanonical_and_oversized_clock_words_refuse(self):
        for word in ('01','+1','-1',str(1<<64),'','1.0'):
            for tag,col in (('RELEASE',3),('RELEASE',4),('CALLTIME',4),('CALLTIME',5)):
                rows,args=self.copy();rows[old.first(rows,tag)][col]=word;self.refuses(rows,args)

    def test_absolute_lateness_retains_skipped_epochs_not_modulo_pass(self):
        rows,args=fixture('locked',3);result=check(rows,args)
        release=result['phase_observations']['release']
        self.assertEqual(release['epoch_index'],3)
        self.assertEqual(release['remainder_ns'],120)
        self.assertEqual(release['absolute_lateness_ns'],30000120)
        self.assertEqual(result['phase_observations']['phase_realization_status'],'UNRESOLVED')
        self.assertEqual(result['calls'][0]['call_timing']['before_epoch_index'],3)
        self.assertEqual(result['calls'][0]['call']['generation'],101)

    def test_arm_overlap_is_enclosure_not_generation_or_clock_transform(self):
        rows,args=self.copy()
        at=old.first(rows,'ARM');rows[at][5]='250'
        r=rows[old.first(rows,'RELEASE')];r[3:]=['250','250']
        # Shift every enclosure after the accepted first ARM, leaving its original due unchanged.
        for row in rows:
            if row[0]=='CALLTIME':row[4:]=[str(int(v)+200) for v in row[4:]]
        result=check(rows,args)
        self.assertEqual(result['arms'][0]['due_ns'],0)
        self.assertEqual(result['calls'][0]['call_timing']['overlapping_arm_count'],0)
        self.assertEqual(result['calls'][0]['call']['generation'],101)
        rows,args=fixture(arms=2)
        for row in rows:
            if row[0]=='CALLTIME':
                before=9999999 if row[1]=='1' else 10000010+(int(row[1])-1)*100
                row[4:]=[str(before),str(10000030 if row[1]=='1' else before+20)]
        result=check(rows,args)
        timing=result['calls'][0]['call_timing']
        self.assertEqual((timing['overlapping_arm_count'],timing['first_overlapping_arm'],timing['last_overlapping_arm']),(1,2,2))
        self.assertEqual((timing['enclosed_due_count'],timing['first_enclosed_due'],timing['last_enclosed_due']),(1,2,2))
        self.assertEqual((timing['before_epoch_index'],timing['after_epoch_index']),(0,1))
        self.assertEqual((timing['before_requested_error_ns'],timing['after_requested_error_ns']),(9999999,10000030))
        self.assertEqual(result['calls'][0]['call']['generation'],102)
        self.assertEqual(result['phase_observations']['phase_realization_status'],'UNRESOLVED')

        # At P=1ms the original inclusive 2ms due windows overlap; actual
        # controller operations remain serial, and no modulo rule assigns owner.
        rows,args=fixture(arms=2,period=1)
        arms=[r for r in rows if r[0]=='ARM']
        arms[0][5]='1500000';arms[1][4:6]=['1500010','1500020']
        rows[old.first(rows,'RELEASE')][3:]=['1500000','1500000']
        for row in rows:
            if row[0]=='CALLTIME':
                before=1500005+(int(row[1])-1)*100;row[4:]=[str(before),str(before+30)]
        result=check(rows,args)
        self.assertEqual(result['calls'][0]['call_timing']['overlapping_arm_count'],1)
        self.assertEqual(result['calls'][0]['call']['generation'],102)
        self.assertEqual(result['requested_phase_status'],'UNRESOLVED')

    def test_original_arm_2ms_and_all_numeric_history_guards_remain(self):
        rows,args=self.copy();rows[old.first(rows,'ARM')][5]='2000000'
        rows[old.first(rows,'RELEASE')][3:]=['2000000','2000000']
        for row in rows:
            if row[0]=='CALLTIME':row[4:]=[str(int(v)+2000000) for v in row[4:]]
        self.assertTrue(check(rows,args)['recorded_arm_deadlines_satisfied'])
        rows,args=self.copy();r=rows[old.first(rows,'ARM')];r[5:]=['2000001','0'];self.refuses(rows,args)
        for tag,col in (('HISTORY',2),('CALL',3),('RESULT',4),('SAMPLE',5),('COVERAGE',2),('DONE',6)):
            rows,args=self.copy();at=old.first(rows,tag);rows[at][col]=str(int(rows[at][col])+1);self.refuses(rows,args)

    def test_failed_pmu_and_attributes_preserve_raw_unavailability(self):
        rows,args=self.copy();rows[old.first(rows,'PMUOPEN')][3:]=['-1','13']
        for row in rows:
            if row[0]=='PMUCTL':row[2:]=old.ABSENT
            elif row[0]=='PMU':row[11],row[12:]='-',old.ABSENT
        result=check(rows,args)
        self.assertEqual(result['acquisition']['open'],dict(result=-1,errno=13))
        self.assertEqual(len(result['calls']),2048)
        self.assertTrue(all(c['counter_arithmetic']['kind']=='missing' for c in result['calls']))
        self.assertTrue(all('open_failed' in c['observed_limitations'] for c in result['calls']))
        self.assertEqual(result['requested_phase_status'],'UNRESOLVED')

    def test_zero_multiplexed_short_id_aux_and_error_are_never_accuracy_passes(self):
        for mode in ('zero','multiplexed','short','error','id','aux'):
            rows,args=self.copy();at=old.first(rows,'PMU')
            if mode=='zero':old.set_read(rows[at+1],values=(1000,1000,1000,77))
            elif mode=='multiplexed':old.set_read(rows[at+1],values=(1100,1200,1100,77))
            elif mode=='short':old.set_read(rows[at],result=7,data=bytes(range(32)))
            elif mode=='error':old.set_read(rows[at],result=-1,errno=5,data=bytes(range(32)))
            elif mode=='id':old.set_read(rows[at],values=(1000,1000,1000,88))
            else:rows[at][9]='1'
            result=check(rows,args)
            self.assertTrue(result['calls'][0]['observed_limitations'])
            self.assertEqual(result['hardware_status'],'UNRESOLVED')
            self.assertEqual(result['phase_observations']['calibration_status'],'UNRESOLVED')

    def test_finite_8mib_350byte_and_one_leaf_row_bounds(self):
        self.assertEqual(output.row_limit(520),13870)
        self.assertEqual(output.row_limit(520)*350,4854500)
        self.assertLess(output.row_limit(520)*350,output.CAP)
        for raw in (b'x'*(output.CAP+1),b'x'*350+b'\n',b'x\n'*(13870+1)):
            with self.assertRaises(output.Refused) as caught:output.check(raw,b'',**self.args)
            self.assertEqual(caught.exception.raw,raw)
        with self.assertRaises(output.Refused) as caught:output.check(old.encode(self.rows),b'failure',**self.args)
        self.assertEqual(caught.exception.stderr,b'failure')

    def test_full_external_inputs_geometry_and_caller_remain_required(self):
        for key in ('manifest_bytes','input_bytes','selected_bytes','truth_bytes','body_bytes'):
            rows,args=self.copy();args[key]=args[key][:-1];self.refuses(rows,args)
        for key,value in (('abi','guessed'),('caller',dict(extent=19,continuation=15)),
                          ('table',(dict(self.args['table'][0],policy='certified'),))):
            rows,args=self.copy();args[key]=value;self.refuses(rows,args)


if __name__ == '__main__':
    unittest.main()
