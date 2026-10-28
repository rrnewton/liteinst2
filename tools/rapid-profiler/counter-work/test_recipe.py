"""Corruption controls for raw probe exports; synthetic data, no PMU execution."""
import csv
import importlib.util
import io
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('counter_check', Path(__file__).with_name('check_output.py'))
check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)

def encode(header, rows):
    out = io.StringIO(); writer = csv.DictWriter(out, header.split(','), lineterminator='\n')
    writer.writeheader(); writer.writerows(rows); return out.getvalue().encode('ascii')

def fixtures():
    p, c, o = [], [], []
    attr = bytearray(128)
    for at, n, word in ((0,4,4),(4,4,128),(8,8,0x0964),(32,8,7),(40,8,0x100065)):
        attr[at:at+n] = word.to_bytes(n, 'little')
    for i in range(12):
        label, seed, case = i+1, check.SEEDS[i//6], i % 6
        value = check.scalar(seed, case)
        p.append(dict(zip(check.P.split(','), map(str, (label,seed,check.CASES[case],'OBSERVED_FULL_RUNNING','true',value,value,32768,32768,'')))))
        row = {k:'' for k in check.C.split(',')}; row.update(external_id=str(label), event_id=str(1000+label),
            start_value='0',start_enabled='0',start_running='0',end_value=str(i),end_enabled='100',end_running='100',
            delta_value=str(i),delta_enabled='100',delta_running='100',requested_attributes=attr.hex(),attributes_after_open=attr.hex(),issues='[]')
        for leg in ('before','after'):
            for name, word in zip(('cpu','pid','tid','vendor','family','model','stepping'),(4,12,12,b'AuthenticAMD'.hex(),26,17,0)):
                row[leg+'_'+name] = str(word)
        c.append(row)
        start = b''.join(x.to_bytes(8,'little') for x in (0,0,0,1000+label))
        end = b''.join(x.to_bytes(8,'little') for x in (i,100,100,1000+label))
        for n, (op, result, data) in enumerate((('Open',3,b''),('Id',0,(1000+label).to_bytes(8,'little')),
                ('ReadDisabledStart',32,start),('Enable',0,b''),('Disable',0,b''),('ReadDisabledEnd',32,end),('Close',0,b''))):
            o.append(dict(zip(check.O.split(','), map(str,(label,n,op,result,'',len(data),data.hex())))))
    return p,c,o

def terminal(invoked=12, observed=12, failed=False):
    return (f'counter-probe required=12 invoked={invoked} observed_full_running={observed} status={"FAILED" if failed else "OBSERVED"} scope=whole-original-api hardware_accuracy=unqualified model11h_semantics=unqualified\n').encode()

def run(p,c,o,stdout=None):
    return check.check(encode(check.P,p),encode(check.C,c),encode(check.O,o),terminal() if stdout is None else stdout,b'')

class Recipe(unittest.TestCase):
    def test_complete_population_keeps_raw_zero_with_full_running(self):
        r = run(*fixtures())
        self.assertEqual((r['status'],r['required'],r['invoked'],r['observed_full_running'],r['unrun']),('OBSERVED',12,12,12,0))
        self.assertEqual(r['hardware_accuracy'],'unqualified')

    def test_each_population_identity_value_and_actual_return_is_required(self):
        for key, bad in (('external_id','13'),('seed','0'),('case','other'),('expected','0'),('value','0'),
                         ('invoked','false'),('resumed_rsp','32776'),('status','PASS'),('invocation_error','refused')):
            p,c,o = fixtures(); p[4][key] = bad
            with self.subTest(key=key), self.assertRaises(AssertionError): run(p,c,o)
        p,c,o = fixtures(); p.reverse()
        with self.assertRaises(AssertionError): run(p,c,o)
        with self.assertRaises(AssertionError): run(p[:-1],c,o)

    def test_no_read_or_schedule_identity_can_be_relabelled_successful(self):
        for key,bad in (('event_id','7'),('start_value','1'),('end_value','999'),('end_running','99'),
                        ('delta_enabled','101'),('delta_running','0'),('after_cpu','5'),('after_tid','13'),
                        ('before_family','25'),('issues','[Arithmetic]')):
            p,c,o = fixtures(); c[3][key] = bad
            with self.subTest(key=key), self.assertRaises(AssertionError): run(p,c,o)
        p,c,o = fixtures(); c[0]['requested_attributes'] = '00'*128
        with self.assertRaises(AssertionError): run(p,c,o)

    def test_operations_are_exact_and_no_short_read_or_retry_disappears(self):
        for index,key,bad in ((0,'errno','13'),(1,'result','-1'),(2,'result','24'),(4,'result','-1'),
                              (5,'data_hex','00'*32),(6,'result','-1'),(6,'operation','Disable')):
            p,c,o = fixtures(); o[index][key] = bad
            with self.subTest(index=index,key=key), self.assertRaises(AssertionError): run(p,c,o)
        p,c,o = fixtures(); o.insert(6,o[5].copy())
        with self.assertRaises(AssertionError): run(p,c,o)
        p,c,o = fixtures(); o.pop()
        with self.assertRaises(AssertionError): run(p,c,o)

    def test_open_refusal_is_retained_and_all_remaining_cases_are_unrun(self):
        p,c,o = fixtures()
        for i,row in enumerate(p):
            row.update(status='FAILED' if i == 0 else 'UNRUN', invoked='false',value='',pre_call_rsp='',resumed_rsp='')
        c = c[:1]
        for key in c[0]:
            if key.startswith(('start_','end_','delta_','after_')) or key == 'event_id': c[0][key] = ''
        c[0]['issues'] = '[Operation(Open)]'
        o = o[:1]; o[0].update(result='-1',errno='13')
        result = run(p,c,o,terminal(0,0,True))
        self.assertEqual((result['status'],result['attempted'],result['invoked'],result['unrun']),('FAILED',1,0,11))
        with self.assertRaises(AssertionError): run(p,c,o,terminal())
        for collection, key, bad in ((o,'operation','NotAProbeOperation'),(c,'event_id','garbage'),
                (c,'start_value','garbage'),(c,'issues','[Operation(Close)]'),(c,'after_cpu','4')):
            original = collection[0][key]; collection[0][key] = bad
            with self.subTest(key=key), self.assertRaises(AssertionError): run(p,c,o,terminal(0,0,True))
            collection[0][key] = original
        p[0]['invoked'] = 'true'
        with self.assertRaises(AssertionError): run(p,c,o,terminal(1,0,True))
        p[0]['invoked'] = 'false'
        p[1]['status'] = 'OBSERVED_FULL_RUNNING'
        with self.assertRaises(AssertionError): run(p,c,o,terminal(0,0,True))

    def test_failed_end_read_still_requires_preflight_identity_and_actual_prefix(self):
        p,c,o = fixtures(); c=c[:1]; o=o[:7]
        for i,row in enumerate(p):
            row['status'] = 'FAILED' if i == 0 else 'UNRUN'
            if i: row.update(invoked='false',value='',pre_call_rsp='',resumed_rsp='')
        for key in c[0]:
            if key.startswith(('end_','delta_')): c[0][key] = ''
        c[0]['issues'] = '[ReadSize(ReadDisabledEnd), Arithmetic]'
        o[5].update(result='31',data_len='31',data_hex=o[5]['data_hex'][:-2])
        self.assertEqual(run(p,c,o,terminal(1,0,True))['status'],'FAILED')
        for collection,index,key,bad in ((o,1,'data_hex','00'*8),(o,3,'operation','Disable'),
                (o,5,'data_len','30'),(c,0,'start_value','1'),(c,0,'delta_value','0'),
                (c,0,'issues','[Arithmetic]')):
            old=collection[index][key]; collection[index][key]=bad
            with self.subTest(key=key), self.assertRaises(AssertionError): run(p,c,o,terminal(1,0,True))
            collection[index][key]=old

    def test_cpu_refusals_require_the_named_syscall_to_have_failed(self):
        p,c,_ = fixtures(); c=c[:1]
        for i,row in enumerate(p):
            row.update(status='FAILED' if i == 0 else 'UNRUN', invoked='false',
                       value='',pre_call_rsp='',resumed_rsp='')
        for key in c[0]:
            if key not in ('external_id','requested_attributes','issues'): c[0][key]=''
        for reason in ('NotSingleton','UnsupportedVendorOrFamily',
                'Affinity(Syscall { result: -1, errno: Some(22) })',
                'CurrentCpu(Syscall { result: -1, errno: Some(38) })',
                'Identity(Syscall { result: 0, errno: None })',
                'Identity(Syscall { result: 2147483648, errno: None })'):
            c[0]['issues'] = '[CpuBefore('+reason+')]'
            with self.subTest(reason=reason):
                self.assertEqual(run(p,c,[],terminal(0,0,True))['status'],'FAILED')
        for reason in ('Affinity(Syscall { result: 0, errno: None })',
                'CurrentCpu(Syscall { result: 0, errno: None })',
                'Identity(Syscall { result: 1, errno: None })',
                'Identity(Syscall { result: 2147483647, errno: None })',
                'Affinity(Syscall { result: -1, errno: None })'):
            c[0]['issues'] = '[CpuBefore('+reason+')]'
            with self.subTest(reason=reason), self.assertRaises(AssertionError):
                run(p,c,[],terminal(0,0,True))

        # The same cause guard applies after an actual invocation and full read.
        p,c,o=fixtures(); c=c[:1]; o=o[:7]
        for i,row in enumerate(p):
            row['status']='FAILED' if i == 0 else 'UNRUN'
            if i: row.update(invoked='false',value='',pre_call_rsp='',resumed_rsp='')
        for key in c[0]:
            if key.startswith(('after_','delta_')): c[0][key]=''
        c[0]['issues']='[CpuAfter(CurrentCpu(Syscall { result: -1, errno: Some(38) }))]'
        self.assertEqual(run(p,c,o,terminal(1,0,True))['status'],'FAILED')
        c[0]['issues']='[CpuAfter(CurrentCpu(Syscall { result: 0, errno: None }))]'
        with self.assertRaises(AssertionError): run(p,c,o,terminal(1,0,True))

    def test_byte_protocol_refuses_alternative_line_delimiters_and_extra_rows(self):
        p,c,o = fixtures(); raw = [encode(h,r) for h,r in zip((check.P,check.C,check.O),(p,c,o))]
        for index in range(3):
            for delimiter in (b'\r',b'\r\n',b'\v',b'\f',b'\x00'):
                changed = raw.copy(); changed[index] = changed[index].replace(b'\n',delimiter)
                with self.subTest(index=index,delimiter=delimiter), self.assertRaises(AssertionError):
                    check.check(*changed,terminal(),b'')
        with self.assertRaises(AssertionError): check.check(*raw,terminal()+b'extra\n',b'')
        with self.assertRaises(AssertionError): check.check(*raw,terminal(),b'warning\n')

if __name__ == '__main__': unittest.main()
