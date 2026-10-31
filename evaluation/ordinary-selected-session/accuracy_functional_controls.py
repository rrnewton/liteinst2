#!/usr/bin/env python3
"""Pure protocol and injected pipe controls; no candidate or hardware execution."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


producer = load('_functional_pipe_controls',HERE/'accuracy_produce.py')
recipe = load('_functional_recipe_controls',HERE/'accuracy_functional.py')
owner = load('_functional_owner_controls',HERE/'accuracy_functional_owner.py')
legacy = load('_functional_legacy_owner_controls',HERE/'owner.py')
checker = load('_functional_reader_controls',HERE.parent/'ordinary-accuracy/output.py')
# This existing fixture explicitly imports its adjacent output module by name.
# Keep that import local to fixture loading, with no production dispatch changes.
saved = sys.modules.get('output')
sys.modules['output'] = checker
try:
    fixture = load('_functional_full_wire_fixture',HERE.parent/'ordinary-accuracy/reader_controls.py')
finally:
    if saved is None:
        del sys.modules['output']
    else:
        sys.modules['output'] = saved


def ready():
    return ('READY,selected-accuracy-session-v1,10,520,10,2,64,2048,1,1,'+
        str(checker.shared.INSTALL)+',123,123,124,0,1,65536,1,1').encode()


def options(phase):
    value = {k:'/tmp/'+k for k in owner.COMMON+owner.EXTRAS[phase]}
    value.update(phase=phase,revision='1'*40,**{'reservation-tag':'accuracy-first-1','hardware':'test'})
    for key in value:
        if key.endswith('-sha'):
            value[key] = '2'*64
    return value


class Pipe:
    def __init__(self, fd):
        self.fd, self.closed = fd, False
    def fileno(self):
        return self.fd
    def close(self):
        self.closed = True


class Child:
    def __init__(self, code):
        self.pid, self.returncode, self.code = 123, None, code
        self.stdin,self.stdout,self.stderr = Pipe(10),Pipe(11),Pipe(12)
        self.killed = False
    def wait(self, timeout):
        self.returncode = -9 if self.killed else self.code
        return self.returncode
    def poll(self):
        return self.returncode
    def kill(self):
        self.killed = True


class Selector:
    def __init__(self):
        self.mapping = {}
        self.turn = 0
    def register(self, pipe, events, role):
        self.mapping[pipe.fd] = SimpleNamespace(fd=pipe.fd,fileobj=pipe,data=role)
    def unregister(self, pipe):
        del self.mapping[pipe.fd]
    def get_map(self):
        return self.mapping
    def select(self, timeout):
        fd = (11,12,11)[min(self.turn,2)]
        self.turn += 1
        return [(self.mapping[fd],1)]
    def close(self):
        self.mapping.clear()


class Controls(unittest.TestCase):
    def test_owner_has_only_two_exact_phases_and_canonical_options(self):
        for phase in owner.EXTRAS:
            value = options(phase)
            invocation, child = owner.commands(value,'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))
            self.assertEqual(child[2],str(owner.HERE/'accuracy_functional.py'))
            self.assertEqual(child[3:5],['--phase',phase])
            self.assertNotIn('--owner',child)
            self.assertEqual(len(invocation),3+2*len(value))
            for mutate in (lambda x:x.update(command='/bin/true'),lambda x:x.update(phase='campaign'),
                           lambda x:x.update(profile='selected-session-functional-v1'),
                           lambda x:x.update(**{'build-sha':'a'*63}),lambda x:x.update(raw='relative')):
                bad = dict(value);mutate(bad)
                with self.assertRaises(AssertionError):
                    owner.commands(bad,'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))

    def test_old_owner_mutually_refuses_new_phases_and_new_owner_old_profile(self):
        for phase in owner.EXTRAS:
            with self.assertRaises(AssertionError):
                legacy.commands(options(phase),'/usr/bin/python3',str(legacy.HERE/'owner.py'))
        value = options('accuracy-functional')
        for phase in ('products','tests','controls','campaign','sdk-cohort','accuracy-cohort'):
            with self.assertRaises(AssertionError):
                owner.commands(dict(value,phase=phase),'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))

    def test_accuracy_inventory_rejects_missing_extra_and_changed_source_bytes(self):
        builder = load('_functional_inventory_controls',HERE/'build.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            originals = {name:('source '+name).encode() for name in builder.ACCURACY_SOURCES}
            for name,raw in originals.items():
                path = root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            names = list(builder.ACCURACY_SOURCES)
            def git(argv,timeout):
                if 'show' in argv:
                    return originals[argv[-1].split(':',1)[1]]
                return ('\0'.join(names)+'\0').encode()
            with mock.patch.object(builder,'ROOT',root),mock.patch.object(builder.subprocess,'check_output',side_effect=git):
                value = builder.accuracy_source_additions('1'*40)
                self.assertEqual(set(value),set(originals))
                for name,raw in originals.items():
                    self.assertEqual(value[name],dict(bytes=len(raw),sha256=producer.sha(raw)))
                names.pop()
                with self.assertRaises(AssertionError): builder.accuracy_source_additions('1'*40)
                names[:] = [*builder.ACCURACY_SOURCES,'evaluation/ordinary-accuracy/extra.py']
                with self.assertRaises(AssertionError): builder.accuracy_source_additions('1'*40)
                names[:] = builder.ACCURACY_SOURCES
                (root/names[0]).write_bytes(b'changed')
                with self.assertRaises(AssertionError): builder.accuracy_source_additions('1'*40)

    def test_preparation_uses_literal_commands_and_unmodified_bounds(self):
        tools = {k:Path('/tools')/k for k in ('python','gcc','readelf','objdump')}
        commands = recipe.phase_commands(Path('/raw'),tools,producer)
        self.assertEqual(len(commands),4)
        self.assertEqual(commands[0][-8:],['--phase','calibration','--trial','1','--workload','late_expensive','--output','/raw/truth-data'])
        self.assertEqual(commands[1][1:16],['-O2','-fPIC','-shared','-nostdlib','-fno-builtin','-fno-stack-protector',
            '-fomit-frame-pointer','-fno-tree-vectorize','-fno-tree-slp-vectorize','-fno-asynchronous-unwind-tables',
            '-fno-unwind-tables','-fcf-protection=none','-Wl,-z,now','-Wl,-z,noexecstack',str(recipe.ROOT/'tools/rapid-profiler/exact-work/exact_work.S')])
        self.assertEqual(producer.CAP,8*1048576)
        old = load('_functional_old_producer',HERE/'produce.py')
        self.assertEqual(old.CAP,4*1048576)
        self.assertEqual(owner.EXTRAS['accuracy-prepare'],owner.BUILD+owner.CONTROLS)

    def test_fixed_original_population_manifest_and_whole_geometry(self):
        files, manifest = checker.truth.artifacts(producer.MASTER,'calibration',1,'late_expensive')
        args = dict(manifest_bytes=checker.truth.canonical(manifest),input_bytes=files['input.csv'],
            selected_bytes=files['selected.txt'],truth_bytes=files['truth.csv'],
            table=(dict(function_id=41,operation='exact_work_nonempty',policy='whole',elf_va=4096,extent=37,returns=(36,)),),
            caller=dict(extent=20,continuation=15),body_bytes=producer.BODY,abi=producer.ABI,
            policy=producer.POLICY,cpus=(0,1))
        _, original, records, _ = checker.authority(**args)
        self.assertEqual(len(original),2048)
        self.assertEqual(tuple(map(len,records)),(1,)*1024+(64,)*1024)
        self.assertEqual(len(files['input.csv']),68608)
        for key in ('manifest_bytes','input_bytes','selected_bytes','truth_bytes','body_bytes'):
            bad = dict(args);bad[key] = bad[key][:-1]
            with self.assertRaises((AssertionError,ValueError)):
                checker.authority(**bad)
        for key,value in (('table',(dict(args['table'][0],policy='certified'),)),('caller',dict(extent=19,continuation=20)),
                          ('abi','guessed'),('policy',dict(producer.POLICY,k=9))):
            with self.assertRaises((AssertionError,ValueError)):
                checker.authority(**dict(args,**{key:value}))

    def test_external_geometry_binding_requires_exact_facts_scope_and_all_premises(self):
        facts = {'observed':'immutable whole files and caller review fixture'}
        accepted = dict(kind='selected-accuracy-functional-geometry-acceptance-v1',
            status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION',scope=recipe.PROFILE,revision='1'*40,
            preparation_sha256='2'*64,facts=facts,premises={k:True for k in recipe.PREMISES},
            review='Fabricated gate fixture; no native authority.',native_state='UNRUN_SEPARATE_REQUIRED')
        recipe.accept_geometry(accepted,facts,'2'*64,'1'*40)
        for key,value in (('scope','selected-session-whole-functional-v1'),('facts',{}),('preparation_sha256','3'*64),
                          ('revision','4'*40),('review',''),('native_state','PASS'),('premises',{})):
            with self.assertRaises(AssertionError):
                recipe.accept_geometry(dict(accepted,**{key:value}),facts,'2'*64,'1'*40)
        for premise in recipe.PREMISES:
            bad = copy.deepcopy(accepted);bad['premises'][premise] = False
            with self.assertRaises(AssertionError):
                recipe.accept_geometry(bad,facts,'2'*64,'1'*40)

    def test_ready_requires_exact_pid_policy_cpus_version_and_first_header(self):
        producer.ready_row(ready(),123,[0,1,2],checker)
        for index,value in ((0,'CALL'),(1,'selected-session-v1'),(2,'100'),(3,'519'),(4,'1'),(5,'3'),
                            (6,'65'),(7,'2047'),(8,'2'),(9,'2'),(10,'0'),(11,'125'),(12,'124'),
                            (13,'123'),(14,'1'),(15,'0'),(16,'0'),(17,'2'),(18,'2')):
            row = ready().decode().split(',');row[index] = value
            with self.assertRaises((AssertionError,ValueError)):
                producer.ready_row(','.join(row).encode(),123,[0,1,2],checker)

    def test_consumed_cap_plus_one_is_retained_exactly_without_accepted_expansion(self):
        prefix = bytearray(b'x'*producer.CAP);overflow = {}
        with self.assertRaisesRegex(ValueError,'consumed offending chunk retained'):
            producer.append_observed(prefix,b'y','out',overflow)
        self.assertEqual(bytes(prefix),b'x'*producer.CAP)
        self.assertEqual(overflow,dict(stream='out',prefix_bytes=producer.CAP,chunk=b'y'))
        self.assertEqual(len(prefix)+len(overflow['chunk']),producer.CAP+1)
        for key in ('metric_qualified','native_state_qualified','performance_qualified','matrix_complete'):
            self.assertIs(recipe.qualifications()[key],False)

    def test_overflow_at_crossing_read_retains_entire_bounded_chunk_and_stream_role(self):
        prefix = bytearray(b'e'*(producer.CAP-10));data = b'Z'*8192;overflow = {}
        with self.assertRaises(ValueError):
            producer.append_observed(prefix,data,'err',overflow)
        self.assertEqual(len(prefix),producer.CAP-10)
        self.assertEqual(overflow['stream'],'err')
        self.assertEqual(overflow['chunk'],data)
        with self.assertRaises(AssertionError):
            producer.append_observed(bytearray(),b'z'*8193,'out',{})

    def test_partial_writes_account_every_consumed_byte_and_broken_pipe_is_not_progress(self):
        outgoing = bytearray(b'abcdef');writes = [];clock = iter((10,11,12,13)).__next__
        sent = producer.write_input(10,outgoing,0,writes,clock,lambda fd,data:2)
        self.assertEqual((sent,bytes(outgoing),writes),(2,b'cdef',[[10,11,2,2]]))
        sent = producer.write_input(10,outgoing,sent,writes,clock,lambda fd,data:len(data))
        self.assertEqual((sent,bytes(outgoing),writes),(6,b'',[[10,11,2,2],[12,13,6,4]]))
        outgoing.extend(b'x');before = copy.deepcopy(writes)
        def broken(fd,data):
            raise BrokenPipeError('closed')
        with self.assertRaises(BrokenPipeError):
            producer.write_input(10,outgoing,sent,writes,lambda:14,broken)
        self.assertEqual((bytes(outgoing),writes),(b'x',before))

    def injected_exchange(self, code=1, writer=None, stop_after_ready=False):
        child = Child(code); selector = Selector();reads = {11:[ready()+b'\n',b''],12:[b'']}
        plan = dict(revision='1'*40,cpus=[0,1,2],argv=['/inert'])
        count = [0]
        def remaining(deadline):
            count[0] += 1
            if stop_after_ready and count[0] >= 4:
                raise AssertionError('producer absolute 15-second deadline')
            return 1
        with mock.patch.object(producer.subprocess,'Popen',return_value=child), \
             mock.patch.object(producer.selectors,'DefaultSelector',return_value=selector), \
             mock.patch.object(producer.os,'sched_setaffinity'),mock.patch.object(producer.os,'sched_getaffinity',return_value={2}), \
             mock.patch.object(producer.os,'set_blocking'),mock.patch.object(producer.os,'read',side_effect=lambda fd,n:reads[fd].pop(0)), \
             mock.patch.object(producer,'write_input',side_effect=writer or (lambda fd,out,sent,w: self.fake_write(out,sent,w))), \
             mock.patch.object(producer,'remaining',side_effect=remaining):
            value = producer.exchange(plan,{'input_bytes':b'x\n'},checker)
        return child,value

    @staticmethod
    def fake_write(outgoing,sent,writes):
        size = len(outgoing);outgoing.clear();writes.append([1,2,sent+size,size]);return sent+size

    def test_nonzero_exit_retains_raw_bytes_and_normal_reap_without_reader_credit(self):
        child,(result,out,err,overflow,_) = self.injected_exchange()
        self.assertEqual(result['status'],'FAILED')
        self.assertEqual((result['child_exit'],result['normal_reaps'],result['rescue']),(1,1,False))
        self.assertEqual((out,err,overflow),(ready()+b'\n',b'',b''))
        self.assertEqual(result['sent_bytes'],2)
        self.assertFalse(child.killed)

    def test_broken_pipe_preserves_ready_and_requires_rescue_failure(self):
        def broken(*args):
            raise BrokenPipeError('closed')
        child,(result,out,_,_,_) = self.injected_exchange(writer=broken)
        self.assertEqual(result['status'],'FAILED')
        self.assertEqual(out,ready()+b'\n')
        self.assertIn('BrokenPipeError',result['error'])
        self.assertEqual((result['normal_reaps'],result['sent_bytes'],result['rescue']),(0,0,True))
        self.assertTrue(child.killed)

    def test_absolute_deadline_preserves_consumed_ready_and_never_releases_later_input(self):
        child,(result,out,_,_,_) = self.injected_exchange(stop_after_ready=True)
        self.assertEqual(result['status'],'FAILED')
        self.assertEqual(out,ready()+b'\n')
        self.assertIn('15-second deadline',result['error'])
        self.assertEqual((result['sent_bytes'],result['normal_reaps'],result['rescue']),(0,0,True))
        self.assertTrue(child.killed)

    def test_delivery_join_never_infers_realized_phase_or_drops_partial_write(self):
        value = dict(normal_reaps=1,rescue=False,cleanup_error=None,child_pid=123,child_exit=0,sent_bytes=6,
            overflow=None,ready_receipt_ns=10,eof_close_ns=20,writes=[[11,12,2,2],[13,14,6,4]])
        recipe.delivery(value,6)
        self.assertEqual(recipe.qualifications()['requested_phase_status'],'UNRESOLVED')
        for key,v in (('child_exit',1),('rescue',True),('sent_bytes',5),('normal_reaps',0),
                      ('writes',[[9,12,6,6]]),('writes',[[11,12,5,6]]),('eof_close_ns',12)):
            with self.assertRaises(AssertionError):
                recipe.delivery(dict(value,**{key:v}),6)

    def test_missing_duplicate_tail_endpoint_and_late_arm_keep_full_failed_wire(self):
        rows,args = fixture.fixture()
        for mode in ('tail','duplicate','endpoint','late'):
            bad = copy.deepcopy(rows)
            if mode == 'tail':
                at = next(i for i,r in enumerate(bad) if r[:2] == ['CALL','2048'])
                del bad[at:at+4]
            elif mode == 'duplicate':
                at = next(i for i,r in enumerate(bad) if r[:2] == ['RESULT','2048'])
                bad.insert(at,list(bad[at]))
            elif mode == 'endpoint':
                del bad[next(i for i,r in enumerate(bad) if r[:2] == ['PMU','2048'])]
            else:
                row = bad[fixture.first(bad,'ARM')];row[5] = str(int(row[3])+2000001);row[6] = '0'
            raw = fixture.encode(bad)
            with self.assertRaises(checker.Refused) as caught:
                checker.check(raw,b'',**args)
            self.assertEqual(caught.exception.raw,raw)
            self.assertEqual(caught.exception.stderr,b'')

    def test_joined_json_preserves_all_counter_bytes_and_unavailable_values(self):
        original = dict(raw=bytes(range(128)),endpoint={'raw':b'\x00\xff','value':None,'errno':5},
            phase='UNRESOLVED',complete=False)
        converted = recipe.json_records(original)
        self.assertEqual(bytes.fromhex(converted['raw']['bytes_hex']),bytes(range(128)))
        self.assertEqual(converted['endpoint'],dict(raw={'bytes_hex':'00ff'},value=None,errno=5))
        self.assertEqual(converted['phase'],'UNRESOLVED')
        self.assertIs(converted['complete'],False)


if __name__ == '__main__':
    unittest.main()
