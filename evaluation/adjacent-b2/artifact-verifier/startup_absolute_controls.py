#!/usr/bin/env python3
"""Additive class controls only; no producer, build, loader or native dispatch."""
import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import startup_custody as C
import startup_produce as D
import startup_saved as S
import startup_completed as K
import startup_saved_controls as OLD

P = S.ABSOLUTE_PROFILE
INPUTS = dict(original=b'original', ledger=b'ledger', policy=b'LI2DISASM-POLICY 6\nstrict\n')
DATA = {'/objects/alpha': b'gcc', '/objects/beta': b'libc', '/objects/loader': b'loader'}
DEPS = {path: dict(sha256=S.sha(raw)) for path, raw in DATA.items()}
ROLES = dict(libgcc='/objects/alpha', libc='/objects/beta')


def policy(program='checksum', **changes):
    values = dict(inputs=INPUTS, interpreter='/objects/loader', bootstrap='/package/'+program+'.so',
                  dependencies=DEPS, contract='1'*64, profile=P, absolute_prerequisites=ROLES)
    values.update(changes)
    return D.startup_policy(program, **values)


def parsed(raw, program='checksum', inputs=INPUTS, profile=P):
    return S.policy(raw, program, inputs['original'], inputs['ledger'], inputs['policy'], C, profile=profile)


def products():
    product, expected, originals = OLD.products()
    policies = {}
    for program in S.PROGRAMS:
        inputs = dict(INPUTS, original=originals[program])
        raw = policy(program, inputs=inputs)
        expected[program]['startup-policy.txt'] = raw
        product[program]['startup-policy.txt'] = raw
        policies[program] = parsed(raw, program, inputs)
        product[program]['startup-profile.tsv'] = S.encode([
            ['LI2STARTUP-PRODUCER','1'],['profile',P],['runtime_profile',S.ABSOLUTE_RUNTIME_PROFILE],
            ['planning_profile',OLD.A.ROUTED.importer],['program',program],
            ['original_heads',str(S.COUNTS[program][0])],['selected_sites',str(S.COUNTS[program][1])],
            ['runtime_policy_sha256',S.sha(raw)],['qualification_complete','false'],['execution_authority','none']])
    return product, expected, originals, policies


def seal(root, product, originals, marker_profile=P):
    OLD.seal_products(root, product, originals)
    marker = root/'COMPLETE'
    marker.write_bytes(marker.read_bytes().replace(S.PROFILE.encode(), marker_profile.encode()))
    store = C.Store()
    try:
        names = store.members(root)
        return dict(path=str(root),directory=names,files={n:store.pin(root/n,16*S.MIB) for n in names['members']})
    finally:
        store.close()


class AbsoluteStartup(unittest.TestCase):
    def test_both_policy_roles_and_caps_are_exact_not_basename_guesses(self):
        for program in S.PROGRAMS:
            raw = policy(program); value = parsed(raw, program)
            self.assertEqual(raw.splitlines()[:3], [b'LI2BOOTSTRAP-POLICY 2',
                ('profile '+S.ABSOLUTE_RUNTIME_PROFILE).encode(), ('program '+program).encode()])
            self.assertEqual(raw.splitlines()[7], ('absolute-prerequisites /objects/alpha /objects/beta /package/'+program+'.so').encode())
            self.assertEqual(value['absolute_prerequisites'], ['/objects/alpha','/objects/beta'])
            self.assertEqual(value['bootstrap'], '/package/'+program+'.so')
            self.assertEqual(value['caps'], (4096,4096,4097,144,16384,4096,65536,1048576))
            self.assertEqual(set(value), {'interpreter','bootstrap','dependencies','contract','caps','absolute_prerequisites'})
            self.assertEqual(S.dependency_roster(value,list(DATA.values())),S.encode([
                [path,str(len(raw)),S.sha(raw)] for path,raw in DATA.items()]))
        self.assertEqual(sum(n[0] for n in S.COUNTS.values()),187)
        self.assertEqual(sum(n[1] for n in S.COUNTS.values()),42)

    def test_old_and_new_profiles_cannot_substitute_for_each_other(self):
        old = D.startup_policy('checksum',INPUTS,'/objects/loader','/package/checksum.so',DEPS,'1'*64)
        self.assertNotIn('absolute_prerequisites', parsed(old,profile=S.PROFILE))
        with self.assertRaisesRegex(ValueError,'profile/program'): parsed(old)
        with self.assertRaisesRegex(ValueError,'profile/program'): parsed(policy(),profile=S.PROFILE)
        with self.assertRaisesRegex(ValueError,'supported startup profile'): parsed(policy(),profile='unknown')
        with self.assertRaisesRegex(ValueError,'old startup has no'): policy(profile=D.PROFILE)
        with self.assertRaisesRegex(ValueError,'explicit inventory role'): policy(absolute_prerequisites=None)
        self.assertEqual(S.verifier_flag(S.PROFILE),'--startup')
        self.assertEqual(S.verifier_flag(P),'--startup-absolute-prerequisites')

    def test_role_membership_order_tokens_and_aggregate_caps_reject(self):
        raw = policy()
        cases = [(b'POLICY 2',b'POLICY 1'),(b' 144 ',b' 112 '),(b' 144 ',b' 145 '),
            (b'/objects/alpha /objects/beta',b'/objects/alpha /objects/alpha'),
            (b'/objects/alpha /objects/beta',b'/objects/loader /objects/beta'),
            (b'/objects/alpha /objects/beta',b'/objects/missing /objects/beta'),
            (b'/objects/alpha',b'/objects/alpha$'),(b'/objects/loader',b'/objects/load$er'),
            (b'/package/checksum.so',b'/package/checksum$.so')]
        for old,new in cases:
            with self.subTest(old=old,new=new),self.assertRaises(ValueError): parsed(raw.replace(old,new))
        with self.assertRaises(ValueError): parsed(raw+raw.splitlines(keepends=True)[-1])
        for roles in ({'libgcc':'/objects/alpha'},dict(ROLES,extra='/objects/loader'),
                      dict(libgcc='/objects/beta',libc='/objects/beta'),dict(libgcc='/absent',libc='/objects/beta')):
            with self.assertRaises(ValueError): policy(absolute_prerequisites=roles)
        extra=dict(DEPS,**{'/objects/z$extra':dict(sha256='2'*64)})
        with self.assertRaisesRegex(ValueError,'loader token'): policy(dependencies=extra)

    def test_same_aggregate_needed_limit_equal_and_over(self):
        gcc,libc,boot = '/'+'g'*1350,'/'+'c'*1350,'/'+'b'*1390
        deps={path:dict(sha256='1'*64) for path in sorted([gcc,libc,'/objects/loader'])}
        self.assertEqual(sum(len(p)+1 for p in (gcc,libc,boot)),4096)
        raw=policy(bootstrap=boot,dependencies=deps,absolute_prerequisites=dict(libgcc=gcc,libc=libc))
        self.assertEqual(parsed(raw)['caps'][1:3],(4096,4097))
        with self.assertRaisesRegex(ValueError,'aggregate absolute'):
            policy(bootstrap=boot+'b',dependencies=deps,absolute_prerequisites=dict(libgcc=gcc,libc=libc))
        with self.assertRaisesRegex(ValueError,'resource ceilings'):
            parsed(raw.replace(boot.encode(),(boot+'b').encode()))

    def test_actual_inventory_input_role_mapping_survives_unrelated_basenames(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve(); store=C.Store()
            try:
                rows=[]
                for label,name,data in [('/lib64/libgcc_s.so.1','zebra',b'gcc'),
                    ('/lib64/ld-linux-x86-64.so.2','middle',b'loader'),('/lib64/libc.so.6','aardvark',b'libc')]:
                    path=root/name;path.write_bytes(data);pin=store.pin(path,S.MIB)
                    dev,ino,mode,size,mtime,ctime=pin['stat']
                    rows.append(dict(input=label,canonical=str(path),readelf_exit=0,bytes=size,sha256=pin['sha256'],
                                     device=dev,inode=ino,mode=mode,mtime_ns=mtime,ctime_ns=ctime))
                value=dict(kind='PASSIVE_HOST_INPUT_INVENTORY_ONLY',qualification=False,launches=0,files=rows)
                path=root/'inventory';path.write_text(json.dumps(value));h=S.sha(path.read_bytes())
                interpreter,deps,roles=D.inventory_roles(store,path,h)
                self.assertEqual(interpreter,str(root/'middle'))
                self.assertEqual(roles,dict(libgcc=str(root/'zebra'),libc=str(root/'aardvark')))
                self.assertEqual(list(deps),sorted([str(root/name) for name in ('zebra','middle','aardvark')]))
            finally:store.close()

    def test_both_program_argv_has_exact_one_explicit_mode_and_eight_copies(self):
        groups={p:{k:dict(path='/copies/'+p+'-'+k,sha256='1'*64) for k in C.INPUTS} for p in C.PROGRAMS}
        old=dict(inputs=groups,output='/out')
        before=C.producer_argv(Path('/producer'),old)
        after=C.producer_argv(Path('/producer'),dict(old,profile=P))
        self.assertEqual(len(before),16);self.assertEqual(len(after),17)
        self.assertEqual(after,[before[0],'--absolute-prerequisites',*before[1:]])
        self.assertEqual(C.producer_argv(Path('/producer'),dict(old,profile=S.PROFILE)),before)
        with self.assertRaisesRegex(ValueError,'explicit producer'): C.producer_argv(Path('/producer'),dict(old,profile='unknown'))
        with self.assertRaisesRegex(ValueError,'both ordered'): C.producer_argv(Path('/producer'),dict(old,inputs={'checksum':groups['checksum']},profile=P))
        with self.assertRaisesRegex(ValueError,'four input'): C.producer_argv(Path('/producer'),dict(old,inputs={p:{'original':groups[p]['original']} for p in C.PROGRAMS},profile=P))

    def test_transport_writer_and_saved_reconstruction_agree_without_dispatch(self):
        with tempfile.TemporaryDirectory() as t:
            for program in S.PROGRAMS:
                expected={n:b'expected-'+n.encode() for n in S.EXPECTED}
                expected['startup-policy.txt']=policy(program)
                product={'candidate.elf':b'candidate','catalog.li2boot':b'catalog'}
                path=Path(t)/program
                h=S.pack(path,program,b'original',expected,product,list(DATA.values()),profile=P)
                raw=K.transport(program,b'original',expected,product,list(DATA.values()),S,profile=P)
                self.assertEqual(path.read_bytes(),raw);self.assertEqual(h,S.sha(raw))
                self.assertTrue(raw.startswith(('LI2W01-INPUT\t2\t'+P+'\t'+program+'\t').encode()))
                self.assertNotEqual(raw,K.transport(program,b'original',expected,product,list(DATA.values()),S))
        self.assertEqual((S.MAX_MEMBERS,S.BODY_BYTES,S.FRAMING_BYTES,S.TRANSPORT_BYTES),
                         (279,198*S.MIB+65536,71936,198*S.MIB+65536+71936))

    def test_new_response_keeps_all_fifteen_rows_and_false_gates(self):
        products_value,_,_,_=products()
        for program in S.PROGRAMS:
            product=products_value[program]
            raw=OLD.response(program,product,'a'*64).replace(S.PROFILE.encode(),P.encode())
            row=S.result_row(program,raw,b'',0,product,'a'*64,profile=P)
            self.assertEqual(row['status'],'STARTUP_MAIN_JOINS_COMPLETE_PENDING_PACKAGE')
            self.assertEqual(row['verifier_calls'],1)
            with self.assertRaisesRegex(ValueError,'15-row'): S.result_row(program,raw,b'',0,product,'a'*64)
            for line in raw.splitlines(keepends=True):
                with self.assertRaises(ValueError): S.result_row(program,raw.replace(line,b'',1),b'',0,product,'a'*64,profile=P)
            for code in (1,2,-9):
                with self.assertRaisesRegex(ValueError,'raw refusal'): S.result_row(program,raw,b'',code,product,'a'*64,profile=P)
            with self.assertRaises(ValueError): S.result_row(program,raw.replace(b'false',b'true',1),b'',0,product,'a'*64,profile=P)

    def test_flat_publication_class_mixing_repaired_indices_and_both_programs(self):
        for mutation,reason in [('none',None),('old-profile','exact additive startup profile'),
            ('old-marker','exact actual startup COMPLETE'),('mixed-policy','same selected startup class'),
            ('missing-policy','both absolute startup policy programs')]:
            with tempfile.TemporaryDirectory() as t:
                product,expected,originals,policies=products()
                if mutation=='old-profile':
                    product['rle-roundtrip']['startup-profile.tsv']=product['rle-roundtrip']['startup-profile.tsv'].replace(P.encode(),S.PROFILE.encode())
                if mutation=='mixed-policy': policies['rle-roundtrip'].pop('absolute_prerequisites')
                if mutation=='missing-policy': policies.pop('rle-roundtrip')
                frozen=seal(Path(t)/'products',product,originals,S.PROFILE if mutation=='old-marker' else P)
                store=C.Store()
                try:
                    if reason is None:
                        result=S.publication(store,OLD.A,frozen,originals,expected,policies,profile=P)
                        self.assertEqual(tuple(result),S.PROGRAMS)
                        with self.assertRaisesRegex(ValueError,'same selected startup class'):
                            S.publication(store,OLD.A,frozen,originals,expected,policies)
                    else:
                        with self.assertRaisesRegex(ValueError,reason):
                            S.publication(store,OLD.A,frozen,originals,expected,policies,profile=P)
                finally:store.close()

    def test_binding_selects_one_class_without_reinterpreting_legacy_history(self):
        for bound_profile,plan_profile,reason in [(P,P,None),(S.PROFILE,P,'prospective startup plan'),
                                                  (P,S.PROFILE,'prospective startup plan'),('unknown',P,'binding schema')]:
            with tempfile.TemporaryDirectory() as t:
                root=Path(t).resolve();diagnostic=root/'diagnostic';diagnostic.mkdir()
                store=C.Store()
                try:
                    controls={}
                    for name in C.CONTROL:
                        path=diagnostic/name;path.write_bytes(b'raw closed control');controls[name]=store.pin(path,S.MIB)
                    args=types.SimpleNamespace(startup_binding=root/'binding',source_profile=root/'source',source_profile_sha256='1'*64,
                        capture=root/'capture',capture_sha256='2'*64,diagnostic=diagnostic,diagnostic_sha256=controls['receipt.json']['sha256'])
                    plan=dict(schema='LI2STARTUP-SAVED-PLAN-1',profile=plan_profile,capture=dict(directory=str(args.capture),sha256=args.capture_sha256),
                        source_revision='3'*40,env={},tools={},configuration_profile='frozen',configurations={},producer_build={},inputs={},dependencies={},
                        producer_directory=str(diagnostic),output=str(root/'out'),source_profile=dict(path=str(args.source_profile),sha256=args.source_profile_sha256))
                    path=root/'plan';path.write_text(json.dumps(plan));plan_pin=store.pin(path,S.MIB)
                    history=root/'failed';history.write_text(json.dumps(dict(status='FAILED',configuration_complete=False,W01=False)))
                    bound=dict(schema='LI2STARTUP-SAVED-BINDING-1',profile=bound_profile,plan=plan_pin,producer_controls=controls,
                               publication=None,failure_history=[store.pin(history,S.MIB)],input_after={})
                    args.startup_binding.write_text(json.dumps(bound));args.startup_binding_sha256=S.sha(args.startup_binding.read_bytes())
                    if reason is None:
                        _,actual,retained=S.load_binding(store,args,C)
                        self.assertEqual(actual['profile'],P)
                        self.assertEqual(retained[0]['original'],dict(status='FAILED',configuration_complete=False,W01=False))
                    else:
                        with self.assertRaisesRegex(ValueError,reason): S.load_binding(store,args,C)
                finally:store.close()

    def test_new_class_partial_main_results_never_grant_package_or_execution(self):
        report=dict(profile=P,configuration_complete=True,custody_complete=True,expected_programs=2,expected_heads=187,expected_selected=42,
            producer=dict(status='PRODUCER_COMPLETE_UNVERIFIED'),programs={p:dict(status='STARTUP_MAIN_JOINS_COMPLETE_PENDING_PACKAGE',
            expected_heads=h,expected_selected=n,verifier_calls=1,runtime_handoff=dict(required_routes_empty=False)) for p,(h,n) in S.COUNTS.items()})
        self.assertEqual(S.aggregate(report),0)
        self.assertTrue(report['startup_main_joins_complete'])
        self.assertTrue(all(report[k] is False for k in S.FALSE_FLAGS));self.assertEqual(report['N01'],'UNRUN')
        for status in ('PRODUCER_FAILED','PRODUCER_REFUSED','UNRUN'):
            bad=copy.deepcopy(report);bad['producer']['status']=status
            self.assertEqual(S.aggregate(bad),1);self.assertFalse(bad['startup_main_joins_complete'])
            self.assertEqual(bad['producer']['status'],status)
            self.assertTrue(all(bad[k] is False for k in S.FALSE_FLAGS))

    def test_absolute_failed_producer_keeps_raw_labels_and_zero_verifier_dispatches(self):
        for code,status in ((1,'PRODUCER_FAILED'),(2,'PRODUCER_REFUSED')):
            with tempfile.TemporaryDirectory() as t:
                root=Path(t);(root/'ignored').mkdir();owner=root/'ignored/owner';owner.mkdir()
                sources={}
                for program in S.PROGRAMS:
                    sources[program]={}
                    for key in C.INPUTS:
                        path=owner/(program+'-'+key);path.write_bytes(b'frozen');sources[program][key]=path
                copies=C.copy_inputs(sources,owner/'inputs')
                diagnostic=owner/'producer';diagnostic.mkdir();output=owner/'product';output.mkdir()
                (output/'COMPLETE').write_bytes(b'candidate_complete\ttrue\n')
                captured=dict(env={},tools={n:dict(path='/tools/'+n) for n in ('python','timeout','helper')})
                plan=dict(profile=P,inputs=copies,output=str(output),producer_directory=str(diagnostic),env={},tools=captured['tools'],
                    source_revision='1'*40,configuration_profile='fixed',configurations={},producer_build={},capture={})
                args=types.SimpleNamespace(output=root/'ignored/w01',capture=owner/'originals',diagnostic=diagnostic,
                    verifier_build=root/'ignored/no-verifier-build',startup_binding=owner/'binding.json')
                ctx=types.SimpleNamespace(ROOT=root,PINS={},B=types.SimpleNamespace(HELPER_SHA='h'*64,
                    write=lambda path,value:path.write_text(json.dumps(value)),identity=mock.Mock(side_effect=AssertionError('unexpected pin'))),
                    invoke=mock.Mock(side_effect=AssertionError('no verifier/producer dispatch')),
                    load=mock.Mock(side_effect=AssertionError('no material recomputation after failed producer')))
                request,command=OLD.W.request_and_command(ctx,captured,diagnostic,C.producer_argv(Path('/bound/producer'),plan),(20,30,16))
                OLD.closed_files(diagnostic,request,command,'h'*64,code=code,stdout=b'failed producer bytes',stderr=b'failure kept')
                observed=C.Store()
                try:
                    bound=dict(plan=dict(path=str(owner/'startup-plan.json')),input_after=copies,
                        producer_controls={n:observed.pin(diagnostic/n,16*S.MIB) for n in C.CONTROL},
                        publication=dict(path=str(output),directory=observed.members(output),files={'COMPLETE':observed.pin(output/'COMPLETE',S.MIB)}))
                finally:observed.close()
                originals=types.SimpleNamespace(authenticate=mock.Mock(return_value=dict(inputs={},summary=dict(configuration_complete=True),stable=lambda:None)))
                pins=types.SimpleNamespace(SOURCE_REVISION='1'*40)
                rooted=types.SimpleNamespace(COMMENT_PROFILE='fixed',configurations=lambda *a,**k:{})
                def only_producer(*values):
                    self.assertEqual(values[5],'producer')
                    return Path('/bound/producer'),{}
                with mock.patch.object(S,'load_binding',return_value=(bound,plan,[dict(original=dict(status='FAILED',configuration_complete=False,W01=False))])), \
                     mock.patch.object(C,'environment'),mock.patch.object(C,'source_profile',return_value='1'*40), \
                     mock.patch.object(C,'build',side_effect=only_producer) as build,mock.patch.object(OLD.W,'rooted_module',return_value=rooted):
                    self.assertEqual(S.run(args,ctx,OLD.A,OLD.W,C,pins,originals),1)
                report=json.loads((args.output/'closed.json').read_bytes())
                self.assertEqual(report['profile'],P)
                self.assertEqual(report['producer']['status'],status);self.assertEqual(report['producer']['exit'],code)
                self.assertEqual([r['status'] for r in report['programs'].values()],[status,status])
                self.assertEqual([r['verifier_calls'] for r in report['programs'].values()],[0,0])
                self.assertTrue(report['custody_complete']);self.assertFalse(report['startup_main_joins_complete'])
                self.assertEqual(report['original_producer_receipt']['exit'],code)
                self.assertFalse(report['retained_history'][0]['original']['configuration_complete'])
                build.assert_called_once();ctx.invoke.assert_not_called();ctx.load.assert_not_called()

    def test_absolute_verifier_dispatch_is_two_calls_max_with_fixed_flags_and_budgets(self):
        for fault in ('none','refusal','closure','transport'):
            with tempfile.TemporaryDirectory() as t:
                root=Path(t);out=root/'output';out.mkdir();store=C.Store()
                captured=dict(env={},tools={n:dict(path='/tools/'+n) for n in ('python','timeout','helper')})
                ctx=types.SimpleNamespace(ROOT=root,B=types.SimpleNamespace(HELPER_SHA='h'*64))
                calls=[]
                def invoke(directory,argv,env,tools):
                    self.assertEqual(argv[:2],['/bound/verifier','--startup-absolute-prerequisites']);calls.append(argv)
                    request,command=OLD.W.request_and_command(ctx,captured,directory,argv,(20,30,16))
                    if fault=='closure':raise RuntimeError('uncertain child closure')
                    if fault=='transport':Path(argv[2]).write_bytes(b'replaced transport')
                    p=directory.parent.name
                    OLD.closed_files(directory,request,command,'h'*64,code=1 if fault=='refusal' else 0,
                        stdout=OLD.response(p,product_by_program[p],'d'*64,images=S.COUNTS[p][1]).replace(S.PROFILE.encode(),P.encode()))
                ctx.invoke=invoke; product_by_program={}
                try:
                    for program in S.PROGRAMS:
                        raw,selection=OLD.OLD.handoff_fixture(program)
                        product_by_program[program]={'candidate.elf':b'candidate','catalog.li2boot':b'catalog',
                            'startup-policy.txt':b'policy','plan-ledger.tsv':raw,
                            **{'image-%04d.bin'%i:b'image' for i in range(S.COUNTS[program][1])}}
                        expected={name:b'expected' for name in S.EXPECTED};expected['selection.txt']=selection
                        row=dict(verifier_calls=0)
                        if fault in ('closure','transport'):
                            with self.assertRaises(OLD.A.CustodyFailure if fault=='closure' else ValueError):
                                S.verify_program(ctx,OLD.A,OLD.W,C,store,captured,Path('/bound/verifier'),out,program,b'original',expected,
                                    product_by_program[program],[b'dep'],'d'*64,row,store.verify,profile=P)
                            self.assertEqual(row['verifier_calls'],1);break
                        S.verify_program(ctx,OLD.A,OLD.W,C,store,captured,Path('/bound/verifier'),out,program,b'original',expected,
                            product_by_program[program],[b'dep'],'d'*64,row,store.verify,profile=P)
                        self.assertEqual(row['status'],'VERIFIER_REFUSED' if fault=='refusal' else 'STARTUP_MAIN_JOINS_COMPLETE_PENDING_PACKAGE')
                        with self.assertRaisesRegex(ValueError,'one verifier call'):
                            S.verify_program(ctx,OLD.A,OLD.W,C,store,captured,Path('/bound/verifier'),out,program,b'o',expected,
                                product_by_program[program],[b'd'],'d'*64,row,store.verify,profile=P)
                    self.assertEqual(len(calls),1 if fault in ('closure','transport') else 2)
                finally:store.close()


if __name__=='__main__':
    unittest.main()
