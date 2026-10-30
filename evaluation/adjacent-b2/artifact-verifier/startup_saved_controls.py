#!/usr/bin/env python3
"""Prospective startup custody/transport controls; synthetic data is not W01."""
import copy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import verify_saved as W
import verify_saved_controls as OLD
import startup_saved as S
import startup_custody as C
import startup_cargo_from_root as LAUNCH

A = OLD.A
LEGACY_BODIES_SHA256 = '98c56dc61d328213448b7f6f6407ca808dbea00c76e0f96a627b7149cc376017'


def response(program, product, dependency_hash, images=1):
    return S.encode([['LI2W01-PROGRAM','2'],['profile',S.PROFILE],['program',program],
        ['original_heads',str(S.COUNTS[program][0])],['selected',str(S.COUNTS[program][1])],['images',str(images)],
        ['candidate_sha256',S.sha(product['candidate.elf'])],['catalog_sha256',S.sha(product['catalog.li2boot'])],
        ['startup_policy_sha256',S.sha(product['startup-policy.txt'])],['dependency_roster_sha256',dependency_hash],
        ['structural_joins_complete','true'],['qualification_complete','false'],['classification_complete','false'],
        ['native_correctness_complete','false'],['performance_eligible','false']])


def policy(program, original=b'original', ledger=b'ledger', planning=b'planning'):
    rows = ['LI2BOOTSTRAP-POLICY 1','profile '+S.RUNTIME_PROFILE,'program '+program,
        'original '+S.sha(original),'disassembly '+S.sha(ledger),'planning-policy '+S.sha(planning),
        'interpreter /loader','bootstrap /private/'+program+'.so','app-stack 4481024 65536',
        'qualification-contract '+'1'*64,'startup-limits 4096 4096 4097 112 16384 4096 65536 1048576',
        'dependency /loader '+S.sha(b'loader')]
    return ('\n'.join(rows)+'\n').encode()


def products():
    result, expected, originals = {}, {}, {}
    for program in S.PROGRAMS:
        original = ('original-'+program).encode(); originals[program] = original
        expected[program] = {name:(name+'-'+program).encode() for name in W.EXPECTED_NAMES}
        expected[program]['startup-policy.txt'] = policy(program,original)
        names = A.PRODUCT-{'adjacent-b2-evidence.txt'} | {A.ROUTED.evidence} | A.COMPLETE_ONLY | {
            'startup-policy.txt','startup-profile.tsv','catalog.li2boot','image-0000.bin'} | {
            'site-%d.diagnostics.txt'%i for i in range(1,S.COUNTS[program][1]+1)}
        p = {name:('contents-'+name).encode() for name in names}; p.update(expected[program])
        p['startup-profile.tsv'] = S.encode([['LI2STARTUP-PRODUCER','1'],['profile',S.PROFILE],
            ['runtime_profile',S.RUNTIME_PROFILE],['planning_profile',A.ROUTED.importer],['program',program],
            ['original_heads',str(S.COUNTS[program][0])],['selected_sites',str(S.COUNTS[program][1])],
            ['runtime_policy_sha256',S.sha(p['startup-policy.txt'])],['qualification_complete','false'],['execution_authority','none']])
        result[program] = p
    return result,expected,originals


def seal_products(root, p, originals, *, extra=None, marker=None):
    full = {}
    for program,product in p.items():
        rows = [['LI2BUNDLE','1'],['original_sha256',S.sha(originals[program])],['qualification_complete','false'],
                ['consumer_action','RuntimeScan-while-gated-until-qualified']]
        rows += [['file',name,str(len(raw)),S.sha(raw)] for name,raw in sorted(product.items()) if name!='bundle-index.tsv']
        product['bundle-index.tsv'] = S.encode(rows)
        full.update((program+'-'+name,raw) for name,raw in product.items())
        full[program+'-original.elf'] = originals[program]
    full.update(extra or {})
    rows = [['LI2BOOTSTRAP-DIRECTORY','1'],['profile',S.PROFILE],
        ['checksum_original_sha256',S.sha(originals['checksum'])],['rle_original_sha256',S.sha(originals['rle-roundtrip'])],
        ['required_original_heads','187'],['required_selected_sites','42'],['candidate_complete','true'],
        ['qualification_complete','false'],['execution_authority','none']]
    rows += [['file',name,str(len(raw)),S.sha(raw)] for name,raw in sorted(full.items())]
    full['COMPLETE'] = S.encode(rows) if marker is None else marker
    root.mkdir()
    for name,raw in full.items(): (root/name).write_bytes(raw)
    store = C.Store()
    try:
        return dict(path=str(root),directory=store.members(root),files={name:store.pin(root/name,16*S.MIB) for name in full})
    finally:
        store.close()


def closed_files(root, request, command, helper, *, code=0, stdout=b'', stderr=b''):
    request_raw = (json.dumps(request)+'\n').encode()
    receipt = dict(absence_proof='ECHILD',cleanup_error=None,helper_sha256=helper,
        request_sha256=S.sha(request_raw),inputs_unchanged=True,exit=code,wall_timeout=False,aborted=None,
        cleanup_events=[],unexpected_descendants=[],stdout_sha256=S.sha(stdout),stderr_sha256=S.sha(stderr),elapsed_seconds=0.01)
    values = {'request.json':request_raw,'command.json':json.dumps(command).encode(),
        'parent-closed.json':json.dumps(dict(wait_returned=True,error=None,exit=0 if code==0 else 1)).encode(),
        'receipt.json':json.dumps(receipt).encode(),'stdout.txt':stdout,'stderr.txt':stderr,'helper.stderr':b'',
        'helper.stdout':(json.dumps(dict(exit=code,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=code==0))+'\n').encode()}
    for name,raw in values.items(): (root/name).write_bytes(raw)
    return values


class Controls(unittest.TestCase):
    def test_legacy_bodies_unchanged_and_new_flags_are_paired(self):
        raw = Path(W.__file__).read_bytes()
        body = raw[raw.index(b'def need('):raw.index(b'\ndef startup_modules(')]
        self.assertEqual(S.sha(body),LEGACY_BODIES_SHA256)
        common = ['verify_saved.py','--capture','/no-capture','--diagnostic','/no-diagnostic',
            '--verifier-build','/no-build','--output','/no-output','--capture-sha256','0'*64,
            '--diagnostic-sha256','0'*64,'--verifier-build-sha256','0'*64,'--verifier-lock-sha256','0'*64]
        for extra in (['--startup-binding','/binding'],['--startup-binding-sha256','0'*64]):
            with mock.patch('sys.argv',common+extra),mock.patch.object(W,'context',side_effect=AssertionError('no context on half-pair')):
                with self.assertRaisesRegex(ValueError,'paired explicit'): W.main()
        with mock.patch.object(W,'STARTUP_MODULES',{}):
            with self.assertRaisesRegex(ValueError,'UNBOUND'): W.startup_modules(None)

    def test_startup_policy_exact_inputs_paths_roster_stack_and_caps(self):
        for program in S.PROGRAMS:
            raw = policy(program)
            p = S.policy(raw,program,b'original',b'ledger',b'planning',C)
            self.assertEqual(p['dependencies'],[('/loader',S.sha(b'loader'))])
            self.assertEqual(S.dependency_roster(p,[b'loader']),('/loader\t6\t'+S.sha(b'loader')+'\n').encode())
            mutants = [raw.replace(b'65536',b'65535',1),raw.replace(b'4481024',b'4481025'),
                raw.replace(b'4096 4096',b'4097 4096'),raw.replace(b' 112 ',b' 113 '),raw.replace(b'/loader',b'/x/../loader'),
                raw.replace(b'program '+program.encode(),b'program wrong'),raw.replace(b'\n',b'\r\n'),raw[:-1],
                raw.replace(b'profile ',b'profile  '),raw.replace(b'1'*64,b'0'*64),
                raw+raw.splitlines(keepends=True)[-1],raw.replace(b'dependency /loader',b'dependency /other'),
                raw.replace(b'dependency /loader',('dependency /private/'+program+'.so').encode())]
            for bad in mutants:
                with self.subTest(program=program,bad=bad),self.assertRaises(ValueError):
                    S.policy(bad,program,b'original',b'ledger',b'planning',C)
            with self.assertRaisesRegex(ValueError,'independent input identity'):
                S.policy(raw,program,b'changed',b'ledger',b'planning',C)
            with self.assertRaisesRegex(ValueError,'dependency bytes'):
                S.dependency_roster(p,[b'substitute'])

    def test_transport_separate_equal_and_over_cap_bounds(self):
        expected = {n:65536 if n=='startup-policy.txt' else S.MIB for n in S.EXPECTED}
        product = {str(i):16*S.MIB for i in range(4)}
        dependencies = [16*S.MIB]*8
        self.assertEqual(S.pack_sizes('checksum',S.MIB,expected,product,dependencies),S.BODY_BYTES)
        self.assertEqual(S.MAX_MEMBERS,279); self.assertEqual(S.FRAMING_BYTES,71936)
        cases = [(S.MIB+1,expected,product,dependencies),
            (S.MIB,dict(expected,**{'startup-policy.txt':65537}),product,dependencies),
            (S.MIB,dict(expected,**{'selection.txt':S.MIB+1}),product,dependencies),
            (S.MIB,expected,dict(product,extra=1),dependencies),
            (S.MIB,expected,{'x':16*S.MIB+1},dependencies),
            (S.MIB,expected,{str(i):0 for i in range(257)},dependencies),
            (S.MIB,expected,product,[16*S.MIB+1]),(S.MIB,expected,product,dependencies+[1]),
            (S.MIB,expected,product,[0]*17),(S.MIB,expected,product,[])]
        for o,e,p,d in cases:
            with self.assertRaises(ValueError): S.pack_sizes('checksum',o,e,p,d)
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); expected={n:b'x' for n in S.EXPECTED}
            good=root/'transport'; h=S.pack(good,'checksum',b'o',expected,{'candidate.elf':b'c'},[b'd'])
            raw=good.read_bytes();self.assertEqual(S.sha(raw),h)
            self.assertTrue(raw.startswith(('LI2W01-INPUT\t2\t'+S.PROFILE+'\tchecksum\t9\n').encode()))
            self.assertTrue(raw.endswith(b'END\n'))
            for product in ({'../x':b'x'},{'original.elf':b'o'},{'COMPLETE':b'x'},{'bad\nname':b'x'}):
                with self.assertRaises(ValueError): S.pack(root/'bad','checksum',b'o',expected,product,[b'd'])
                self.assertFalse((root/'bad').exists())

    def test_response_every_row_order_identity_and_denial_is_exact(self):
        p,_,_=products()
        for program in S.PROGRAMS:
            good=response(program,p[program],'a'*64)
            row=S.result_row(program,good,b'',0,p[program],'a'*64)
            self.assertEqual(row['status'],'STARTUP_MAIN_JOINS_COMPLETE_PENDING_PACKAGE')
            for line in good.splitlines(keepends=True):
                with self.assertRaises(ValueError):S.result_row(program,good.replace(line,b'',1),b'',0,p[program],'a'*64)
            rows=good.splitlines(keepends=True);rows[2],rows[3]=rows[3],rows[2]
            mutants=[b''.join(rows),good+b'extra\tfalse\n',good.replace(b'false',b'true',1),good[:-1],
                good.replace(b'images\t1',b'images\t01'),good.replace(b'\t2\n',b'\t1\n',1),
                good.replace(b'a'*64,b'b'*64),response(program,p[program],'a'*64,images=2)]
            for bad in mutants:
                with self.assertRaises(ValueError):S.result_row(program,bad,b'',0,p[program],'a'*64)
            for stderr,code in ((b'noise',0),(b'',1),(b'',2)):
                with self.assertRaises(ValueError):S.result_row(program,good,stderr,code,p[program],'a'*64)

    def test_flat_publication_repaired_indices_reach_intended_checks(self):
        for mutation,reason in [('none',None),('selection','independent full expected bytes'),
            ('profile','exact additive startup profile'),('image-gap','contiguous bounded image roster'),
            ('extra-product','exact complete per-program'),('cross-prefix','unknown/cross-prefix/failure'),
            ('failed-product','unknown/cross-prefix/failure'),('legacy-marker','exact actual startup COMPLETE')]:
            with tempfile.TemporaryDirectory() as t:
                p,e,o=products();extra=None;marker=None
                if mutation=='selection':p['checksum']['selection.txt']=b'changed semantic input'
                if mutation=='profile':p['checksum']['startup-profile.tsv']=b'old-profile\n'
                if mutation=='image-gap':p['checksum']['image-0001.bin']=p['checksum'].pop('image-0000.bin')
                if mutation=='extra-product':p['checksum']['unknown']=b'indexed extra'
                if mutation=='cross-prefix':extra={'checksumx-candidate.elf':b'x'}
                if mutation=='failed-product':extra={'program-failure.tsv':b'failure'}
                if mutation=='legacy-marker':marker=b'LI2DISASSEMBLY-DIRECTORY\t1\n'
                frozen=seal_products(Path(t)/'product',p,o,extra=extra,marker=marker)
                store=C.Store()
                try:
                    if reason is None:
                        result=S.publication(store,A,frozen,o,e,{})
                        self.assertEqual(tuple(result),S.PROGRAMS)
                        self.assertTrue(all('original.elf' not in value and 'COMPLETE' not in value for value in result.values()))
                    else:
                        with self.assertRaisesRegex(ValueError,reason):S.publication(store,A,frozen,o,e,{})
                finally:store.close()

    def test_actual_reader_replacement_symlink_fifo_and_membership(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);path=root/'file';path.write_bytes(b'original')
            store=C.Store()
            try:
                pin=store.pin(path,8);self.assertEqual(store.read(path,8,pin),b'original')
                path.rename(root/'old');path.write_bytes(b'original')
                with self.assertRaisesRegex(ValueError,'cached file changed'):store.verify()
            finally:store.close()
            for kind in ('symlink','fifo'):
                target=root/kind
                if kind=='symlink':target.symlink_to(path)
                else:os.mkfifo(target)
                store=C.Store()
                try:
                    with self.assertRaises((ValueError,OSError)):store.read(target,8)
                finally:store.close()
            store=C.Store()
            try:
                before=store.members(root);(root/'extra').write_bytes(b'x')
                self.assertNotEqual(store.members(root),before)
            finally:store.close()

    def test_real_eight_copies_inode_modes_and_all_after_mutants(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);sources={}
            for program in S.PROGRAMS:
                sources[program]={}
                for name in C.INPUTS:
                    path=root/(program+'-'+name);path.write_bytes((program+name).encode());sources[program][name]=path
            copies=C.copy_inputs(sources,root/'inputs')
            for program in S.PROGRAMS:
                for name,pin in copies[program].items():
                    self.assertEqual(os.stat(pin['path']).st_mode & 0o777,0o400)
                    self.assertNotEqual(os.stat(sources[program][name]).st_ino,pin['stat'][1])
                    self.assertEqual(Path(pin['path']).read_bytes(),sources[program][name].read_bytes())
            store=C.Store()
            try:self.assertEqual(tuple(C.frozen_inputs(store,dict(inputs=copies))),S.PROGRAMS)
            finally:store.close()
            for program in S.PROGRAMS:
                for name in C.INPUTS:
                    bad=copy.deepcopy(copies);bad[program][name]['sha256']='0'*64
                    store=C.Store()
                    try:
                        with self.assertRaisesRegex(ValueError,'frozen file content/identity'):C.frozen_inputs(store,dict(inputs=bad))
                    finally:store.close()
            bad=copy.deepcopy(copies);bad['checksum']['ledger']=bad['checksum']['original']
            store=C.Store()
            try:
                with self.assertRaisesRegex(ValueError,'eight distinct'):C.frozen_inputs(store,dict(inputs=bad))
            finally:store.close()

    def test_raw_closure_failure_and_cleanup_are_not_true_boolean_acceptance(self):
        for mutation,reason in [('none',None),('exit',None),('request','exact bounded request'),
            ('terminal','exact bounded helper terminal'),('cleanup','raw exit/cleanup'),('timeout','raw exit/cleanup'),
            ('elapsed','strict raw helper deadline'),('stream','raw stream identity')]:
            with tempfile.TemporaryDirectory() as t:
                root=Path(t);request=dict(file_bytes=16*S.MIB,wall_seconds=30);command=dict(argv=['verifier'])
                closed_files(root,request,command,'h'*64,code=2 if mutation=='exit' else 0,stdout=b'output')
                if mutation=='request':(root/'request.json').write_text('{}')
                if mutation=='terminal':(root/'helper.stdout').write_text('claimed success\n')
                if mutation=='stream':(root/'stdout.txt').write_bytes(b'substituted')
                if mutation in ('cleanup','timeout','elapsed'):
                    p=root/'receipt.json';value=json.loads(p.read_bytes())
                    if mutation=='cleanup':value['cleanup_events']=['not empty']
                    elif mutation=='timeout':value['wall_timeout']=True
                    else:value['elapsed_seconds']=30.001
                    p.write_text(json.dumps(value))
                store=C.Store()
                try:
                    if reason is None:self.assertEqual(C.closed(store,root,request,command,'h'*64)[0],2 if mutation=='exit' else 0)
                    else:
                        with self.assertRaisesRegex(ValueError,reason):C.closed(store,root,request,command,'h'*64)
                finally:store.close()

    def test_one_verifier_call_per_program_and_transport_stability(self):
        for fault in ('none','refusal','closure','transport'):
            with tempfile.TemporaryDirectory() as t:
                root=Path(t);out=root/'output';out.mkdir();store=C.Store()
                captured=dict(env={},tools={n:dict(path='/tools/'+n) for n in ('python','timeout','helper')})
                ctx=types.SimpleNamespace(ROOT=root,B=types.SimpleNamespace(HELPER_SHA='h'*64))
                calls=[]
                def invoke(directory,argv,env,tools):
                    self.assertEqual(argv[:2],['/bound/verifier','--startup']);calls.append(argv)
                    request,command=W.request_and_command(ctx,captured,directory,argv,(20,30,16))
                    if fault=='closure':raise RuntimeError('uncertain child closure')
                    if fault=='transport':Path(argv[2]).write_bytes(b'replaced transport')
                    p=directory.parent.name
                    closed_files(directory,request,command,'h'*64,code=1 if fault=='refusal' else 0,
                        stdout=response(p,product_by_program[p],'d'*64,images=S.COUNTS[p][1]))
                ctx.invoke=invoke; product_by_program={}
                try:
                    for program in S.PROGRAMS:
                        raw,selection=OLD.handoff_fixture(program)
                        product_by_program[program]={'candidate.elf':b'candidate','catalog.li2boot':b'catalog',
                            'startup-policy.txt':b'policy','plan-ledger.tsv':raw,
                            **{'image-%04d.bin'%i:b'image' for i in range(S.COUNTS[program][1])}}
                        expected={name:b'expected' for name in S.EXPECTED};expected['selection.txt']=selection
                        row=dict(verifier_calls=0)
                        if fault in ('closure','transport'):
                            with self.assertRaises(A.CustodyFailure if fault=='closure' else ValueError):
                                S.verify_program(ctx,A,W,C,store,captured,Path('/bound/verifier'),out,program,b'original',expected,
                                    product_by_program[program],[b'dep'],'d'*64,row,store.verify)
                            self.assertEqual(row['verifier_calls'],1);break
                        S.verify_program(ctx,A,W,C,store,captured,Path('/bound/verifier'),out,program,b'original',expected,
                            product_by_program[program],[b'dep'],'d'*64,row,store.verify)
                        self.assertEqual(row['status'],'VERIFIER_REFUSED' if fault=='refusal' else 'STARTUP_MAIN_JOINS_COMPLETE_PENDING_PACKAGE')
                        with self.assertRaisesRegex(ValueError,'one verifier call'):
                            S.verify_program(ctx,A,W,C,store,captured,Path('/bound/verifier'),out,program,b'o',expected,
                                product_by_program[program],[b'd'],'d'*64,row,store.verify)
                    self.assertEqual(len(calls),1 if fault in ('closure','transport') else 2)
                finally:store.close()

    def test_partial_aggregate_never_promotes_old_failure_or_package_native(self):
        def report():
            return dict(expected_programs=2,expected_heads=187,expected_selected=42,
                configuration_complete=True,custody_complete=True,producer=dict(status='PRODUCER_COMPLETE_UNVERIFIED'),
                retained_history=[dict(original=dict(status='FAILED',configuration_complete=False,W01=False))],
                programs={p:dict(status='STARTUP_MAIN_JOINS_COMPLETE_PENDING_PACKAGE',expected_heads=h,expected_selected=n,
                    verifier_calls=1,runtime_handoff=dict(required_routes_empty=False)) for p,(h,n) in S.COUNTS.items()})
        good=report();self.assertEqual(S.aggregate(good),0);self.assertTrue(good['startup_main_joins_complete'])
        self.assertTrue(all(good[k] is False for k in S.FALSE_FLAGS));self.assertEqual(good['N01'],'UNRUN')
        self.assertEqual(good['retained_history'],report()['retained_history'])
        for program in S.PROGRAMS:
            for failure in ('UNRUN','FAILED','PRODUCER_FAILED','PRODUCER_REFUSED','VERIFIER_REFUSED'):
                value=report();value['programs'][program]['status']=failure
                self.assertEqual(S.aggregate(value),1);self.assertFalse(value['startup_main_joins_complete'])
                self.assertTrue(all(value[k] is False for k in S.FALSE_FLAGS))
        for key in ('configuration_complete','custody_complete'):
            value=report();value[key]=False;self.assertEqual(S.aggregate(value),1)
        for key in ('expected_programs','expected_heads','expected_selected'):
            value=report();value[key]-=1
            with self.assertRaises(ValueError):S.aggregate(value)

    def test_failed_producer_with_complete_marker_never_reaches_material_or_verifier(self):
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
                plan=dict(inputs=copies,output=str(output),producer_directory=str(diagnostic),env={},tools=captured['tools'],
                    source_revision='1'*40,configuration_profile='fixed',configurations={},producer_build={},capture={})
                args=types.SimpleNamespace(output=root/'ignored/w01',capture=owner/'originals',diagnostic=diagnostic,
                    verifier_build=root/'ignored/no-verifier-build',startup_binding=owner/'binding.json')
                ctx=types.SimpleNamespace(ROOT=root,PINS={},B=types.SimpleNamespace(HELPER_SHA='h'*64,
                    write=lambda path,value:path.write_text(json.dumps(value)),identity=mock.Mock(side_effect=AssertionError('unexpected pin'))),
                    invoke=mock.Mock(side_effect=AssertionError('no verifier/producer dispatch')),
                    load=mock.Mock(side_effect=AssertionError('no material recomputation after failed producer')))
                request,command=W.request_and_command(ctx,captured,diagnostic,C.producer_argv(Path('/bound/producer'),plan),(20,30,16))
                closed_files(diagnostic,request,command,'h'*64,code=code,stdout=b'failed producer bytes',stderr=b'failure kept')
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
                     mock.patch.object(C,'build',side_effect=only_producer) as build,mock.patch.object(W,'rooted_module',return_value=rooted):
                    self.assertEqual(S.run(args,ctx,A,W,C,pins,originals),1)
                report=json.loads((args.output/'closed.json').read_bytes())
                self.assertEqual(report['producer']['status'],status);self.assertEqual(report['producer']['exit'],code)
                self.assertEqual([r['status'] for r in report['programs'].values()],[status,status])
                self.assertEqual([r['verifier_calls'] for r in report['programs'].values()],[0,0])
                self.assertTrue(report['custody_complete']);self.assertFalse(report['startup_main_joins_complete'])
                self.assertEqual(report['original_producer_receipt']['exit'],code)
                self.assertFalse(report['retained_history'][0]['original']['configuration_complete'])
                build.assert_called_once();ctx.invoke.assert_not_called();ctx.load.assert_not_called()

    def test_new_build_role_feature_and_unbound_profile_refuse(self):
        p=LAUNCH.argv(['launcher','/tool/cargo','/repo','producer'])
        self.assertIn('--features',p);self.assertIn('offline-router',p)
        self.assertEqual(p[-3:],['--example','offline_router_sites','--message-format=json'])
        v=LAUNCH.argv(['launcher','/tool/cargo','/repo','verifier'])
        self.assertEqual(v[-3:],['--bin','adjacent-b2-artifact-verifier','--message-format=json'])
        for role in ('native','bootstrap','old-producer'):
            with self.assertRaises(ValueError):LAUNCH.argv(['launcher','/tool/cargo','/repo',role])
        with self.assertRaisesRegex(ValueError,'source profile UNBOUND'):
            C.source_profile(None,types.SimpleNamespace(SOURCE_REVISION=None,SOURCE_PINS={}),{})


    def test_refused_output_targets_preserve_all_membership_and_bytes(self):
        def snapshot(directory):
            result = {}
            for path in sorted(directory.iterdir()):
                if path.is_symlink():
                    result[path.name] = ('symlink', os.readlink(path))
                elif path.is_dir():
                    result[path.name] = ('directory', snapshot(path))
                else:
                    result[path.name] = ('file', path.read_bytes())
            return result
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); ignored=root/'ignored'; ignored.mkdir(); owner=ignored/'owner'; owner.mkdir()
            for name in ('capture','diagnostic','inputs','build'):
                directory=owner/name;directory.mkdir();(directory/'sentinel').write_bytes(b'exact retained '+name.encode())
            (owner/'binding.json').write_bytes(b'untouched binding')
            empty=ignored/'existing-empty';empty.mkdir()
            link=ignored/'link';link.symlink_to(owner/'diagnostic',target_is_directory=True)
            outside=root/'outside';outside.mkdir();(outside/'sentinel').write_bytes(b'outside unchanged')
            args=types.SimpleNamespace(capture=owner/'capture',diagnostic=owner/'diagnostic',
                verifier_build=owner/'build',startup_binding=owner/'binding.json')
            ctx=types.SimpleNamespace(ROOT=root,invoke=mock.Mock(),load=mock.Mock(),B=types.SimpleNamespace(write=mock.Mock()))
            targets=(empty,owner/'diagnostic',owner/'inputs',owner/'capture',owner,link,outside,
                     root/'new-outside',owner/'new-under-binding')
            for target in targets:
                with self.subTest(target=target):
                    args.output=target; before=snapshot(root)
                    with mock.patch.object(S,'load_binding') as load, mock.patch.object(C,'build') as build:
                        self.assertEqual(S.run(args,ctx,A,W,C,None,None),1)
                    self.assertEqual(snapshot(root),before)
                    load.assert_not_called();build.assert_not_called()
                    ctx.invoke.assert_not_called();ctx.load.assert_not_called();ctx.B.write.assert_not_called()

    def test_owned_new_output_keeps_honest_later_failure_receipt(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'ignored').mkdir();owner=root/'ignored/owner';owner.mkdir()
            sentinel=owner/'sentinel';sentinel.write_bytes(b'input unchanged')
            args=types.SimpleNamespace(output=root/'ignored/new-owned',capture=owner/'capture',
                diagnostic=owner/'diagnostic',verifier_build=owner/'build',startup_binding=owner/'binding.json')
            ctx=types.SimpleNamespace(ROOT=root,invoke=mock.Mock(),load=mock.Mock(),B=types.SimpleNamespace(write=mock.Mock()))
            with mock.patch.object(S,'load_binding',side_effect=ValueError('controlled later refusal')) as load, \
                 mock.patch.object(C,'build') as build:
                self.assertEqual(S.run(args,ctx,A,W,C,None,None),1)
            self.assertEqual(sorted(p.name for p in args.output.iterdir()),['closed.json'])
            self.assertEqual(args.output.stat().st_mode & 0o777,0o700)
            self.assertEqual((args.output/'closed.json').stat().st_mode & 0o777,0o600)
            report=json.loads((args.output/'closed.json').read_bytes())
            self.assertEqual(report['error'],dict(type='ValueError',detail='controlled later refusal'))
            self.assertFalse(report['custody_complete']);self.assertFalse(report['startup_main_joins_complete'])
            self.assertTrue(all(report[key] is False for key in S.FALSE_FLAGS))
            self.assertEqual([row['verifier_calls'] for row in report['programs'].values()],[0,0])
            self.assertEqual(sentinel.read_bytes(),b'input unchanged')
            self.assertEqual(sorted(p.name for p in owner.iterdir()),['sentinel'])
            load.assert_called_once();build.assert_not_called()
            ctx.invoke.assert_not_called();ctx.load.assert_not_called();ctx.B.write.assert_not_called()

    def test_mkdir_race_never_claims_existing_output(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'ignored').mkdir();owner=root/'ignored/owner';owner.mkdir()
            args=types.SimpleNamespace(output=root/'ignored/raced',capture=owner/'capture',
                diagnostic=owner/'diagnostic',verifier_build=owner/'build',startup_binding=owner/'binding.json')
            ctx=types.SimpleNamespace(ROOT=root,invoke=mock.Mock(),load=mock.Mock(),B=types.SimpleNamespace(write=mock.Mock()))
            original_mkdir=os.mkdir
            def racing_mkdir(name, mode, *, dir_fd):
                original_mkdir(name, mode, dir_fd=dir_fd)
                (args.output/'sentinel').write_bytes(b'other owner')
                raise FileExistsError('created by a different invocation')
            with mock.patch.object(S.os,'mkdir',side_effect=racing_mkdir), \
                 mock.patch.object(S,'load_binding') as load,mock.patch.object(C,'build') as build:
                self.assertEqual(S.run(args,ctx,A,W,C,None,None),1)
            self.assertEqual(sorted(p.name for p in args.output.iterdir()),['sentinel'])
            self.assertEqual((args.output/'sentinel').read_bytes(),b'other owner')
            load.assert_not_called();build.assert_not_called()
            ctx.invoke.assert_not_called();ctx.load.assert_not_called();ctx.B.write.assert_not_called()

    def test_owned_output_replacement_and_existing_closure_cannot_redirect_write(self):
        for replacement in ('directory','symlink','closed-file'):
            with self.subTest(replacement=replacement),tempfile.TemporaryDirectory() as t:
                root=Path(t);(root/'ignored').mkdir();owner=root/'ignored/owner';owner.mkdir()
                target=owner/'diagnostic';target.mkdir();(target/'sentinel').write_bytes(b'retained diagnostic')
                moved=root/'ignored/moved-owned'
                args=types.SimpleNamespace(output=root/'ignored/new-owned',capture=owner/'capture',
                    diagnostic=target,verifier_build=owner/'build',startup_binding=owner/'binding.json')
                ctx=types.SimpleNamespace(ROOT=root,invoke=mock.Mock(),load=mock.Mock(),B=types.SimpleNamespace(write=mock.Mock()))
                def replace_then_refuse(*values):
                    if replacement == 'closed-file':
                        (args.output/'closed.json').write_bytes(b'preexisting closure stays exact')
                    else:
                        args.output.rename(moved)
                        if replacement == 'directory':
                            args.output.mkdir();(args.output/'sentinel').write_bytes(b'replacement unchanged')
                        else:
                            args.output.symlink_to(target,target_is_directory=True)
                    raise ValueError('controlled later refusal')
                with mock.patch.object(S,'load_binding',side_effect=replace_then_refuse) as load, \
                     mock.patch.object(C,'build') as build:
                    self.assertEqual(S.run(args,ctx,A,W,C,None,None),1)
                self.assertEqual(sorted(p.name for p in target.iterdir()),['sentinel'])
                self.assertEqual((target/'sentinel').read_bytes(),b'retained diagnostic')
                if replacement == 'closed-file':
                    self.assertEqual(sorted(p.name for p in args.output.iterdir()),['closed.json'])
                    self.assertEqual((args.output/'closed.json').read_bytes(),b'preexisting closure stays exact')
                else:
                    self.assertEqual(list(moved.iterdir()),[])
                    if replacement == 'directory':
                        self.assertEqual(sorted(p.name for p in args.output.iterdir()),['sentinel'])
                        self.assertEqual((args.output/'sentinel').read_bytes(),b'replacement unchanged')
                    else:
                        self.assertTrue(args.output.is_symlink());self.assertEqual(os.readlink(args.output),str(target))
                load.assert_called_once();build.assert_not_called()
                ctx.invoke.assert_not_called();ctx.load.assert_not_called();ctx.B.write.assert_not_called()



if __name__ == '__main__':
    unittest.main()
