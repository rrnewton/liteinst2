#!/usr/bin/env python3
"""Synthetic complete ELF/closure controls; no native, build or probe dispatch.

The pinned real-host loader premise is replaced only inside explicit fixture
patches. Every tested main/table/namespace is parsed from complete ELF bytes.
These controls establish no real corpus or host qualification.
"""
import copy
import hashlib
from contextlib import ExitStack
import json
from pathlib import Path
import stat
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

import dependency_constructors as C
import dependency_constructor_controls as H
import final_admission as A
import final_controls as F
import final_platform as P
import package as R
import prepare_profile as Q

D = H.D
NAMES = ('/platform/libgcc', '/platform/libc', '/private/bootstrap.so')
EDGES = ['libgcc_s.so.1', 'libc.so.6', 'ld-linux-x86-64.so.2']


def main_image(names=NAMES):
    raw=H.image('main');interpreter=b'/platform/loader0\0'
    strings=b'\0'+b''.join(name.encode('ascii')+b'\0' for name in names)
    interp=H.STR;strtab=interp+len(interpreter);symtab=(strtab+len(strings)+7)&~7
    hash_at=symtab+24;dynamic=(hash_at+16+7)&~7;end=dynamic+144
    raw[interp:end]=bytes(end-interp)
    raw[interp:interp+len(interpreter)]=interpreter;raw[strtab:strtab+len(strings)]=strings
    raw[hash_at:hash_at+16]=struct.pack('<IIII',1,1,0,0)
    offsets=[1,2+len(names[0]),3+len(names[0])+len(names[1])]
    rows=[*((1,at) for at in offsets),(5,strtab),(10,len(strings)),(6,symtab),(11,24),(4,hash_at),(0,0)]
    for i,row in enumerate(rows):struct.pack_into('<QQ',raw,dynamic+16*i,*row)
    struct.pack_into('<H',raw,56,6)
    struct.pack_into('<IIQQQQQQ',raw,64+3*56,2,4,dynamic,dynamic,dynamic,144,144,8)
    struct.pack_into('<IIQQQQQQ',raw,64+5*56,3,4,interp,interp,interp,len(interpreter),len(interpreter),1)
    struct.pack_into('<QQ',raw,64+32,end,end)
    raw[H.SECTIONS:H.SECTIONS+10*64]=bytes(10*64)
    struct.pack_into('<IIQQQQIIQQ',raw,H.SECTIONS+7*64,0,1,6,H.CODE,H.CODE,0x1000,0,0,16,0)
    return raw,dict(interp=interp,strtab=strtab,symtab=symtab,hash=hash_at,dynamic=dynamic,end=end)


def check_main(raw,names=NAMES):
    elf=R.Elf(bytes(raw));tags,needed=D.dynamic(elf)
    return C.main_namespace_absolute(elf,tags,needed,D,tuple(names))


def namespace(raw,names=NAMES,**overrides):
    blobs=H.objects(main=raw,bootstrap=H.image('bootstrap',edges=EDGES),**overrides)
    return C.Namespace(blobs,R,D,absolute_prerequisites=tuple(names))


class Held:
    def __init__(self,blobs):self.blobs=blobs;self.calls=[];self.closed=False
    def retain(self,pin,cap):
        self.calls.append(pin['path']);raw=self.blobs[pin['path']]
        P.need(len(raw)<=cap and len(raw)==pin['bytes'] and P.sha(raw)==pin['sha256'],'fixture actual retained bytes')
        return raw
    def verify(self):P.need(not self.closed,'fixture live custody')
    def close(self):self.closed=True


class Graph:
    def __init__(self):
        self.objects={role:bytes(H.image(role)) for role in P.ROLES}
        paths={'loader':'/platform/loader0','libc':'/platform/libc','libgcc':'/platform/libgcc'}
        self.files={role:F.pin(paths[role],stat.S_IFREG|0o755,i+1,self.objects[role]) for i,role in enumerate(P.ROLES)}
        self.blobs={paths[role]:self.objects[role] for role in P.ROLES}
        self.basis=dict(P.ABSOLUTE_LOADER_BASIS,binary_sha256=P.sha(self.objects['loader']))
        self.directory=dict(path='/platform',state='PRESENT',identity=[1,10,stat.S_IFDIR|0o755],entries_sha256='3'*64)
        self.value=dict(schema='LI2STARTUP-PLATFORM-CONTRACT-2',authority='EXPLICIT_UNSAFE_GNU_ABSOLUTE_PREREQUISITES_V1',
            platform='linux-x86_64-gnu-4096',files=self.files,sonames=P.SONAMES,
            loader_inputs=dict(preload=dict(path='/etc/ld.so.preload',state='ABSENT',file=None)),
            search_directories=[self.directory],aliases=[],obligations=P.ABSOLUTE_OBLIGATIONS,
            loader_basis=self.basis,review_basis='Explicit synthetic fixture, not real host authority. '*8,
            environment={},programs=list(P.PROGRAMS),datasets_per_program=10,N01_program_dataset_pairs=20,N01_invocations=40)
        self.programs={};self.refresh()

    def refresh(self):
        self.raw=P.canonical(self.value);self.digest=P.sha(self.raw)
        for index,program in enumerate(P.PROGRAMS):
            boot_path='/private/'+program+'-bootstrap.so'
            names=(self.files['libgcc']['path'],self.files['libc']['path'],boot_path)
            raw,_=main_image(names);original=bytearray(raw)
            for ph in (3,5):struct.pack_into('<I',original,64+ph*56,0)
            boot=bytes(H.image('bootstrap',edges=EDGES))
            boot_pin=F.pin(boot_path,stat.S_IFREG|0o400,index+20,boot)
            main_pin=F.pin('/private/'+program+'.elf',stat.S_IFREG|0o400,index+30,bytes(raw))
            self.blobs[boot_path]=boot;self.blobs[main_pin['path']]=bytes(raw)
            policy=dict(interpreter=self.files['loader']['path'],bootstrap=boot_path,
                dependencies=sorted((pin['path'],pin['sha256']) for pin in self.files.values()),contract=self.digest,
                caps=(4096,4096,4097,144,16384,4096,65536,1048576),absolute_prerequisites=list(names[:2]))
            rows=['LI2BOOTSTRAP-POLICY 2','profile '+P.ABSOLUTE_RUNTIME_PROFILE,'program '+program,
                'original '+P.sha(bytes(original)),'disassembly '+'1'*64,'planning-policy '+'2'*64,
                'interpreter '+policy['interpreter'],'absolute-prerequisites '+' '.join(names),'app-stack 4481024 65536',
                'qualification-contract '+self.digest,'startup-limits '+' '.join(map(str,policy['caps']))]
            rows+=['dependency '+path+' '+digest for path,digest in policy['dependencies']]
            self.programs[program]=dict(main=dict(product={'candidate.elf':bytes(raw),'startup-policy.txt':('\n'.join(rows)+'\n').encode()},
                original=bytes(original),policy=policy,main_pin=main_pin),bootstrap=boot,bootstrap_pin=boot_pin,
                linked=dict(notes=[],needed=list(EDGES),rpath=None,runpath=None,
                            completion=dict(address=H.ARRAY+128,file_offset=H.ARRAY+128)))
        self.held=Held(self.blobs)

    def context(self):
        stack=ExitStack()
        stack.enter_context(mock.patch.object(P,'ABSOLUTE_LOADER_BASIS',self.basis))
        stack.enter_context(mock.patch.object(P.os.path,'lexists',return_value=False))
        stack.enter_context(mock.patch.object(P,'directory_observation',return_value=self.directory))
        return stack

    def check(self):
        return P.contract_absolute(self.raw,self.digest,R,self.held,self.programs,D,C)


class AbsoluteGrammar(unittest.TestCase):
    def test_exact_main_complete_namespace_and_versioned_constructor(self):
        raw,layout=main_image();facts=check_main(raw);ns=namespace(raw)
        self.assertEqual(facts['needed'],list(NAMES));self.assertEqual(facts,ns.main_namespace)
        self.assertEqual(facts['metadata']['bytes'],layout['end']-H.STR)
        self.assertEqual(ns.absolute_resolution['derived_breadth_first_lookup'],['main','libgcc','libc','bootstrap','loader'])
        proof=ns.constructors('libgcc',H.records(ns))['init_array'][0]['binding_proof']
        self.assertEqual(proof['main_namespace'],facts);self.assertEqual(proof['absolute_resolution'],ns.absolute_resolution)
        self.assertEqual(proof['target_relative'],H.CODE)

    def test_old_and_new_classes_never_fall_back(self):
        old,_=H.canonical_main();new,_=main_image()
        with self.assertRaises(ValueError):check_main(old)
        elf=R.Elf(bytes(new));tags,needed=D.dynamic(elf)
        with self.assertRaisesRegex(ValueError,'canonical empty main'):C.main_namespace(elf,tags,needed,D)
        self.assertEqual(H.namespace().main_namespace['profile'],'main-no-symbol-table-v1')

    def test_order_offsets_missing_extra_and_dynamic_size_refuse(self):
        for mutate in ('order','offset','missing','extra','size','terminator'):
            raw,layout=main_image();at=layout['dynamic']
            if mutate=='order':raw[at:at+32]=raw[at+16:at+32]+raw[at:at+16]
            elif mutate=='offset':struct.pack_into('<Q',raw,at+24,2)
            elif mutate=='missing':struct.pack_into('<Q',raw,at,0)
            elif mutate=='extra':struct.pack_into('<QQ',raw,at+8*16,1,1)
            elif mutate=='size':struct.pack_into('<QQ',raw,64+3*56+32,112,112)
            else:struct.pack_into('<Q',raw,at+8*16+8,1)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):check_main(raw)

    def test_aggregate_names_boundary_literal_paths_and_role_identity(self):
        names=('/a','/b','/'+'c'*4088);raw,_=main_image(names)
        self.assertEqual(check_main(raw,names)['needed'],list(names))
        for names in (('/a','/b','/'+'c'*4089),('libgcc','/b','/c'),('/$ORIGIN/g','/b','/c'),
                      ('/a/../b','/b','/c'),('/a','/a','/c'),('/platform/loader0','/b','/c')):
            raw,_=main_image(names)
            with self.subTest(names=names),self.assertRaises(ValueError):check_main(raw,names)
        raw,_=main_image()
        with self.assertRaises(ValueError):check_main(raw,(NAMES[1],NAMES[0],NAMES[2]))

    def test_null_hash_padding_owners_and_aliases_remain_exact(self):
        for offset in range(24):
            raw,layout=main_image();raw[layout['symtab']+offset]=1
            with self.subTest(offset=offset),self.assertRaisesRegex(ValueError,'entire null symbol'):check_main(raw)
        for offset in (0,4,8,12):
            raw,layout=main_image();raw[layout['hash']+offset]^=1
            with self.assertRaisesRegex(ValueError,'entire SysV'):check_main(raw)
        raw,layout=main_image();strings_end=layout['strtab']+1+sum(len(n)+1 for n in NAMES)
        self.assertLess(strings_end,layout['symtab']);raw[strings_end]=1
        with self.assertRaisesRegex(ValueError,'zero alignment'):check_main(raw)
        raw,_=main_image();struct.pack_into('<I',raw,64+4,6)
        with self.assertRaisesRegex(ValueError,'readonly LOAD'):check_main(raw)
        raw,layout=main_image();struct.pack_into('<IIQQQQIIQQ',raw,H.SECTIONS+64,0,1,2,H.STR,H.STR,1,0,0,1,0)
        with self.assertRaisesRegex(ValueError,'section alias'):check_main(raw)

    def test_changed_outgoing_edges_sonames_and_competing_exports_refuse(self):
        raw,_=main_image()
        for role,bad in [('bootstrap',H.image('bootstrap',edges=EDGES[:2])),
                         ('libc',H.image('libc',edges=[])),('loader',H.image('loader',edges=['libc.so.6']))]:
            blobs=H.objects(main=raw,bootstrap=H.image('bootstrap',edges=EDGES));blobs[role]=bytes(bad)
            with self.subTest(role=role),self.assertRaises(ValueError):C.Namespace(blobs,R,D,absolute_prerequisites=NAMES)
        ns=namespace(raw,libc=H.image('libc',definitions=[(H.NAME,0x12,0,7,H.CODE,32)]))
        with self.assertRaisesRegex(ValueError,'unique same-basename'):ns.constructors('libgcc',H.records(ns))
        bad=H.image('libgcc');struct.pack_into('<Q',bad,H.tag_offset(bad,14)+8,1)
        with self.assertRaisesRegex(ValueError,'edge/SONAME'):namespace(raw,libgcc=bad)
        ns=namespace(raw,libgcc=H.image('libgcc',version=1))
        with self.assertRaisesRegex(ValueError,'strong defined explicit symbol version'):ns.constructors('libgcc',H.records(ns))


class AbsoluteContract(unittest.TestCase):
    def test_both_complete_graphs_required_and_only_cache_is_omitted(self):
        g=Graph()
        with g.context():
            value,files,proofs,recheck=g.check();recheck()
        self.assertEqual(value,g.value);self.assertEqual(set(files),set(P.ROLES));self.assertEqual(set(proofs),set(P.PROGRAMS))
        self.assertNotIn('/etc/ld.so.cache',g.held.calls)
        self.assertEqual(proofs['checksum']['entry']['entry'],H.CODE)
        self.assertNotEqual(proofs['checksum']['namespace'].identities['main'],proofs['rle-roundtrip']['namespace'].identities['main'])
        with g.context():
            facts=P.library_facts_absolute(files['libgcc'],'libgcc',R,D,proofs['checksum']['namespace'])
        self.assertEqual(facts['schema'],'LI2STARTUP-PLATFORM-LIBRARY-FACTS-3')
        self.assertEqual(facts['absolute_resolution'],proofs['checksum']['namespace'].absolute_resolution)
        del g.programs['rle-roundtrip']
        with g.context(),self.assertRaisesRegex(ValueError,'both complete programs'):g.check()

    def test_contract1_new_main_and_contract2_old_main_refuse(self):
        g=Graph();item=g.programs['checksum'];legacy,_=F.ContractShape.fixture()
        legacy['files']=g.files;legacy['search_directories']=[g.directory]
        g.blobs['/etc/ld.so.cache']=b'cache'
        legacy['loader_inputs']['cache']=F.pin('/etc/ld.so.cache',raw=b'cache')
        legacy_raw=P.canonical(legacy);legacy_sha=P.sha(legacy_raw)
        item['main']['policy']['contract']=legacy_sha
        item['main']['product']['startup-policy.txt']=item['main']['product']['startup-policy.txt'].replace(g.digest.encode(),legacy_sha.encode())
        with g.context():
            checked,_=P.contract(legacy_raw,legacy_sha,R,g.held)
            with self.assertRaisesRegex(ValueError,'canonical empty main'):
                P.main_facts(item,checked,legacy_sha,R,D,dependency=C)
        g=Graph();item=g.programs['checksum']
        old,_=H.canonical_main();item['main']['product']['candidate.elf']=bytes(old)
        with g.context(),self.assertRaisesRegex(ValueError,'absolute prerequisite main'):g.check()
        with g.context(),self.assertRaisesRegex(ValueError,'absolute main requires contract2'):
            P.main_facts_absolute(item,legacy,legacy_sha,R,D,C)

    def test_old_missing_cache_and_new_extra_cache_refuse(self):
        old,directory=F.ContractShape.fixture();del old['loader_inputs']['cache']
        with mock.patch.object(P,'directory_observation',return_value=directory),self.assertRaisesRegex(ValueError,'loader input roster'):
            P.contract(P.canonical(old),P.sha(P.canonical(old)),R,types.SimpleNamespace(retain=lambda _pin,_cap:b'ELF'))
        g=Graph();g.value['loader_inputs']['cache']=F.pin('/etc/ld.so.cache');g.refresh()
        with g.context(),self.assertRaisesRegex(ValueError,'preload only'):g.check()

    def test_loader_basis_preload_search_lifetime_and_authority_stay_strict(self):
        for field in ('loader_basis','obligations','authority','environment'):
            g=Graph();g.value[field]=({'LD_PRELOAD':'forbidden'} if field=='environment' else
                'PASSIVE_INVENTORY_ONLY' if field=='authority' else {});g.refresh()
            with g.context(),self.subTest(field=field),self.assertRaises(ValueError):g.check()
        g=Graph()
        with g.context(),mock.patch.object(P.os.path,'lexists',return_value=True),self.assertRaisesRegex(ValueError,'preload remains absent'):g.check()
        g=Graph()
        with g.context():
            _,_,_,recheck=g.check()
            with mock.patch.object(P,'directory_observation',return_value={}):
                with self.assertRaisesRegex(ValueError,'search directory state'):recheck()
        g=Graph()
        with g.context():
            _,_,_,recheck=g.check();g.blobs[g.files['libgcc']['path']]+=b'changed'
            with self.assertRaisesRegex(ValueError,'retained bytes'):recheck()

    def test_coherently_rebound_policy_role_contract_and_second_program_refuse(self):
        for field in ('roles','contract','policy_bytes','bootstrap_edges','second_program'):
            g=Graph();item=g.programs['rle-roundtrip' if field=='second_program' else 'checksum']
            if field=='roles':
                item['main']['policy']['absolute_prerequisites'].reverse()
                rows=item['main']['product']['startup-policy.txt'].splitlines()
                rows[7]=('absolute-prerequisites '+' '.join(item['main']['policy']['absolute_prerequisites']+[item['bootstrap_pin']['path']])).encode()
                item['main']['product']['startup-policy.txt']=b'\n'.join(rows)+b'\n'
            elif field=='contract':
                item['main']['policy']['contract']='5'*64
                item['main']['product']['startup-policy.txt']=item['main']['product']['startup-policy.txt'].replace(g.digest.encode(),b'5'*64)
            elif field=='policy_bytes':item['main']['product']['startup-policy.txt']=item['main']['product']['startup-policy.txt'].replace(b'POLICY 2',b'POLICY 1')
            elif field=='bootstrap_edges':
                item['bootstrap']=bytes(H.image('bootstrap',edges=EDGES[:2]));item['linked']['needed']=EDGES[:2]
                item['bootstrap_pin']=F.pin(item['bootstrap_pin']['path'],raw=item['bootstrap'])
                g.blobs[item['bootstrap_pin']['path']]=item['bootstrap']
            else:
                raw=bytearray(item['main']['product']['candidate.elf']);elf=R.Elf(bytes(raw));tags,_=D.dynamic(elf);raw[tags[6]+23]=1
                item['main']['product']['candidate.elf']=bytes(raw)
                item['main']['main_pin']=F.pin(item['main']['main_pin']['path'],raw=bytes(raw))
                g.blobs[item['main']['main_pin']['path']]=bytes(raw)
            with g.context(),self.subTest(field=field),self.assertRaises(ValueError):g.check()

    def test_explicit_builder_mode_and_producer_class_have_no_inference(self):
        for mode,absolute in [('final-profile',False),('final-profile-absolute-prerequisites',True)]:
            argv=['prepare_profile.py',mode,'--inputs','/private/inputs','--inputs-sha256','1'*64,'--output','/private/new']
            with mock.patch.object(sys,'argv',argv),mock.patch.object(Q,'final_profile') as call:
                Q.main();self.assertEqual(call.call_args.kwargs,dict(absolute_prerequisites=absolute))
            profile=P.ABSOLUTE_STARTUP_PROFILE if absolute else P.STARTUP_PROFILE
            self.assertEqual(P.selected_startup_profile({'plan':{'profile':profile}},absolute_prerequisites=absolute),profile)
            with self.assertRaisesRegex(ValueError,'exact authenticated producer plan'):
                P.selected_startup_profile({'plan':{'profile':profile}},absolute_prerequisites=not absolute)

class AdmissionPath(unittest.TestCase):
    def admission(self, mutate=None, after_open=None):
        # The actual open_session owns class selection, both graph/namespace
        # checks, reviewed-fact comparison, Session construction and stability.
        # Existing W01/build/source I/O seams are inert, consistently pinned
        # fixtures; no reported success is used as a new graph oracle.
        g=Graph()
        with g.context():
            _,deps,proofs,_=g.check()
            reviewed=dict(dependencies={program:{role:P.sha(P.canonical(P.library_facts_absolute(
                deps[role],role,R,D,proofs[program]['namespace']))) for role in P.ROLES} for program in P.PROGRAMS},
                bootstraps={program:P.sha(P.canonical(g.programs[program]['linked'])) for program in P.PROGRAMS},xstate_bytes=576)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'ignored').mkdir()
            records={};next_inode=[100]
            def put(path,raw,mode=0o400):
                next_inode[0]+=1
                pin=F.pin(str(path),stat.S_IFREG|mode,next_inode[0],raw);records[str(path)]=(raw,pin)
                return dict(path=str(path),sha256=P.sha(raw))
            source_map={};native_raw={};common_raw={};modules={}
            actual={A.NATIVE+'final_admission.py':Path(A.__file__).read_bytes(),
                A.NATIVE+'final_platform.py':Path(P.__file__).read_bytes(),
                A.NATIVE+'dependency_constructors.py':Path(C.__file__).read_bytes(),
                A.NATIVE+'package.py':Path(R.__file__).read_bytes()}
            names=A.REQUIRED_NATIVE|{A.NATIVE+'dependency_constructors.py',A.NATIVE+'dependency_constructor_controls.py',
                A.NATIVE+'absolute_profile_controls.py'}
            for relative in names:
                raw=actual.get(relative,('# fixture '+relative).encode());native_raw[relative]=raw
                source_map[relative]=put(root/relative,raw)['sha256']
            running=root/A.NATIVE/'final_admission.py';running.parent.mkdir(parents=True);running.write_bytes(actual[A.NATIVE+'final_admission.py'])
            common_names=['verify_saved','startup_custody','startup_pins','startup_originals','startup_saved',
                          'startup_completed','startup_produce','startup_bootstrap','startup_dso']
            for name in common_names:
                relative=A.CRATE+name+'.py';raw=Path(D.__file__).read_bytes() if name=='startup_dso' else ('# fixture '+name).encode()
                common_raw[relative]=raw;put(root/relative,raw)
            old=dict(sources={name:P.sha(raw) for name,raw in common_raw.items()})
            source_profile=put(root/'ignored/source-profile.json',P.canonical(old))
            plan=dict(profile=P.ABSOLUTE_STARTUP_PROFILE,configuration_profile='fixture-config')
            saved=dict(programs=g.programs,completed=dict(plan=plan,captured=dict(env={}),configurations={}),stable=lambda:None)
            observer_dir=root/'ignored/observer';observer=F.pin(str(root/'ignored/observer.bin'),stat.S_IFREG|0o700,90,b'fixture observer')
            g.blobs[observer['path']]=b'fixture observer'
            observer_raw=b'{}';contract=put(root/'ignored/contract.json',g.raw)
            arguments={name:('1'*64 if name.endswith('_sha256') else str(root/'ignored'/name)) for name in A.ARGUMENTS}
            profile=dict(schema='LI2STARTUP-FINAL-PROFILE-3',native_revision='a'*40,native_sources=source_map,
                artifact_source_profile=source_profile,arguments=arguments,bootstrap=dict(directory=str(root/'ignored/bootstrap'),sha256='2'*64),
                contract=contract,reviewed=reviewed,observer=dict(binary=observer,build=dict(directory=str(observer_dir),sha256=P.sha(observer_raw))))
            if mutate:mutate(g,profile,saved)
            profile_path=root/'ignored/final.json';profile_ref=put(profile_path,P.canonical(profile))
            self.closed=[]
            store=types.SimpleNamespace(read=lambda path,cap:observer_raw,verify=lambda:None,close=lambda:self.closed.append('store'))
            package=types.SimpleNamespace(Elf=R.Elf,Custody=lambda:g.held)
            self.native_checks=0;self.native_batches=[];self.native_reads=[]
            def batch(batch_root,revision,ordered,env,*,expected_lengths):
                self.assertEqual(batch_root,root);self.assertEqual(revision,'a'*40);self.assertEqual(env,{})
                self.assertEqual(ordered,sorted(source_map.items()))
                self.assertEqual(expected_lengths,[len(records[str(root/name)][0]) for name,_ in ordered])
                self.native_batches.append((list(ordered),list(expected_lengths)))
                decoder=F.C.SourceBatch([digest for _,digest in ordered],expected_lengths=expected_lengths)
                for name,_ in ordered:
                    raw=native_raw[name];framing=b'blob '+str(len(raw)).encode()+b'\0'
                    oid=hashlib.sha1(framing+raw).hexdigest().encode()
                    decoder.feed(oid+b' blob '+str(len(raw)).encode()+b'\n'+raw+b'\n')
                decoder.finish()
            custody=types.SimpleNamespace(absolute=lambda path:Path(path),Store=lambda cap:store,source_batch=batch)
            legacy=types.SimpleNamespace(context=lambda _root:(None,None),STARTUP_MODULES={
                name:old['sources'][A.CRATE+name] for name in ('startup_custody.py','startup_pins.py','startup_originals.py','startup_saved.py')})
            modules.update(final_platform=P,dependency_constructors=C,package=package,
                final_bootstrap=types.SimpleNamespace(authenticate=lambda *args:saved),verify_saved=legacy,
                startup_custody=custody,startup_pins=types.SimpleNamespace(load=lambda *args:None),startup_dso=D)
            for name in common_names:modules.setdefault(name,types.SimpleNamespace())
            def read(path,cap=A.MIB):
                if str(path).startswith(str(root/A.NATIVE)+'/'):self.native_reads.append(str(Path(path).relative_to(root)))
                raw,pin=records[str(path)];self.assertLessEqual(len(raw),cap);return raw,copy.deepcopy(pin)
            def git(argv,**kwargs):
                command=argv[3:];self.assertEqual(argv[:3],['/usr/bin/git','-C',str(root)])
                self.assertEqual(command,['ls-tree','-r','--name-only','a'*40,'--',A.NATIVE])
                self.assertEqual(kwargs,dict(env={},timeout=15));self.native_checks+=1
                return ('\n'.join(sorted(source_map))+'\n').encode()
            with g.context(),mock.patch.object(A,'__file__',str(running)),mock.patch.object(A,'read_file',side_effect=read), \
                 mock.patch.object(A,'load_source',side_effect=lambda raw,path:modules[path.stem]), \
                 mock.patch.object(A,'no_capabilities'),mock.patch.object(A.subprocess,'check_output',side_effect=git):
                session=A.open_session(root,profile_path,profile_ref['sha256'],g.digest)
                self.assertIsInstance(session,A.Session)
                self.assertEqual(set(session.programs),set(P.PROGRAMS))
                self.assertEqual(session.profile['schema'],'LI2STARTUP-FINAL-PROFILE-3')
                self.assertEqual(session.programs['checksum']['entry'],H.CODE)
                if after_open:after_open(session,types.SimpleNamespace(root=root,records=records,
                    native_raw=native_raw,source_map=source_map))
                # Public summaries cannot redirect private stability inputs.
                session.profile['reviewed'].clear();session.programs['checksum']['main_bytes']=b'changed export'
                session.stable();session.close()
                self.assertTrue(g.held.closed);self.assertEqual(self.closed,['store'])
            return g

    def test_actual_final_admission_builds_both_programs_only_after_graph(self):
        g=self.admission();self.assertNotIn('/etc/ld.so.cache',g.held.calls)

    def test_actual_final_admission_refuses_old_mode_and_coherent_second_main(self):
        def old_profile(g,profile,saved):profile['schema']='LI2STARTUP-FINAL-PROFILE-2'
        with self.assertRaisesRegex(ValueError,'exact authenticated producer plan'):self.admission(old_profile)
        def second(g,profile,saved):
            item=saved['programs']['rle-roundtrip'];raw,_=H.canonical_main()
            item['main']['product']['candidate.elf']=bytes(raw)
            pin=F.pin(item['main']['main_pin']['path'],stat.S_IFREG|0o400,31,bytes(raw))
            item['main']['main_pin']=pin;g.blobs[pin['path']]=bytes(raw)
        with self.assertRaisesRegex(ValueError,'absolute prerequisite main'):self.admission(second)


    def test_native_batches_are_fresh_at_every_existing_boundary(self):
        self.admission()
        self.assertEqual(self.native_checks,4);self.assertEqual(len(self.native_batches),4)
        self.assertTrue(all(batch==self.native_batches[0] for batch in self.native_batches))
        names=[name for name,_ in self.native_batches[0][0]]
        self.assertEqual(sorted(self.native_reads),sorted(names*4))

    def test_next_native_boundary_refuses_changed_committed_size_or_same_size_bytes(self):
        def faults(session,f):
            name=sorted(f.native_raw)[0];original=f.native_raw[name]
            self.assertEqual(len(self.native_batches),2)
            for changed,message in ((original+b'X','exact committed source size'),
                                    (bytes([original[0]^1])+original[1:],'committed source bytes')):
                try:
                    f.native_raw[name]=changed
                    with self.assertRaisesRegex(ValueError,message):session.stable()
                finally:f.native_raw[name]=original
            self.assertEqual(len(self.native_batches),4)
        self.admission(after_open=faults)
        self.assertEqual(self.native_checks,6);self.assertEqual(len(self.native_batches),6)

    def test_next_native_boundary_refuses_missing_or_extra_inventory_before_batch(self):
        def faults(session,f):
            name=sorted(f.source_map)[0];original=f.source_map[name]
            for missing in (True,False):
                batches=len(self.native_batches)
                try:
                    if missing:del f.source_map[name]
                    else:f.source_map[A.NATIVE+'extra.py']='0'*64
                    with self.assertRaisesRegex(ValueError,'complete separately committed native inventory'):session.stable()
                    self.assertEqual(len(self.native_batches),batches)
                finally:
                    f.source_map[name]=original;f.source_map.pop(A.NATIVE+'extra.py',None)
        self.admission(after_open=faults)
        self.assertEqual(self.native_checks,6);self.assertEqual(len(self.native_batches),4)

    def test_next_native_boundary_keeps_live_bytes_and_identity_checks(self):
        def faults(session,f):
            name=sorted(f.native_raw)[0];path=str(f.root/name);raw,pin=f.records[path]
            changed_pin=copy.deepcopy(pin);changed_pin['stat'][1]+=1
            for record in ((bytes([raw[0]^1])+raw[1:],pin),(raw,changed_pin)):
                try:
                    f.records[path]=record
                    with self.assertRaisesRegex(ValueError,'final checker/input source identity drift'):session.stable()
                finally:f.records[path]=(raw,pin)
        self.admission(after_open=faults)
        self.assertEqual(self.native_checks,6);self.assertEqual(len(self.native_batches),6)

    def test_exported_graph_facts_cannot_rebind_stable_checks(self):
        g=Graph()
        with g.context():
            value,files,proofs,recheck=g.check()
            value['files'].clear();files.clear();proofs['checksum']['namespace'].identities.clear()
            recheck()
            g.blobs[g.files['libgcc']['path']]+=b'drift'
            with self.assertRaisesRegex(ValueError,'retained bytes'):recheck()


if __name__=='__main__':unittest.main()
