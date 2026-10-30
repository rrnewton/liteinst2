#!/usr/bin/env python3
"""Source controls for the additive final checker. All UNRUN in author packet.

These unit controls do not execute any original, candidate, DSO or observer.
Existing package, saved-reader, bootstrap and observer controls remain unchanged.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

import final_admission as A
import final_bootstrap as B
import final_platform as P
import package as R


def pin(path='/private/output.so', mode=stat.S_IFREG | 0o400, inode=2, raw=b'ELF'):
    return dict(path=path, bytes=len(raw), sha256=P.sha(raw), stat=[1, inode, mode, len(raw), 2, 3])


def copy_receipt():
    before = pin('/private/target.so', stat.S_IFREG | 0o755, 1)
    destination = pin()
    return dict(source_before=before, source_after=copy.deepcopy(before), destination=destination, bytes_equal=True)


class TemporalCopy(unittest.TestCase):
    def test_historical_source_can_be_gone(self):
        value = copy_receipt()
        B.historical_copy(value, Path('/private/target.so'), value['destination'])
        self.assertEqual(value['source_before'], value['source_after'])

    def test_source_changed_during_copy_refuses(self):
        value = copy_receipt(); value['source_after']['stat'][1] += 1
        with self.assertRaisesRegex(ValueError, 'temporal copy'):
            B.historical_copy(value, Path('/private/target.so'), value['destination'])

    def test_claimed_byte_equality_cannot_hide_mismatch(self):
        value = copy_receipt(); value['destination']['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'historical built bytes'):
            B.historical_copy(value, Path('/private/target.so'), value['destination'])

    def test_alias_of_temporary_inode_refuses(self):
        value = copy_receipt(); value['destination']['stat'][1] = 1
        with self.assertRaisesRegex(ValueError, 'distinct immutable copy'):
            B.historical_copy(value, Path('/private/target.so'), value['destination'])

    def test_wrong_original_target_refuses(self):
        value = copy_receipt()
        with self.assertRaisesRegex(ValueError, 'historical built bytes'):
            B.historical_copy(value, Path('/private/other.so'), value['destination'])

    def test_writable_retained_copy_refuses(self):
        value = copy_receipt(); value['destination']['stat'][2] = stat.S_IFREG | 0o600
        with self.assertRaisesRegex(ValueError, 'immutable copy'):
            B.historical_copy(value, Path('/private/target.so'), value['destination'])

    def test_boolean_size_is_not_integer_size(self):
        value = copy_receipt(); value['source_before']['bytes'] = True; value['source_after']['bytes'] = True
        with self.assertRaisesRegex(ValueError, 'regular copy pin'):
            B.historical_copy(value, Path('/private/target.so'), value['destination'])


class CustodyAndAuthority(unittest.TestCase):
    def test_regular_file_exact_bytes_and_identity(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'input'; path.write_bytes(b'exact')
            raw, found = A.read_file(path)
            self.assertEqual(raw, b'exact')
            self.assertEqual(found['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(found['stat'], A.stamp(path.stat()))

    def test_symlink_file_and_parent_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'dir').mkdir(); (root/'dir/input').write_bytes(b'exact')
            (root/'alias').symlink_to('dir', target_is_directory=True)
            (root/'file').symlink_to('dir/input')
            for path in (root/'alias/input', root/'file'):
                with self.subTest(path=path), self.assertRaises(OSError): A.read_file(path)

    def test_read_bound_not_extended(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'input'; path.write_bytes(b'12')
            with self.assertRaisesRegex(ValueError, 'bounded regular'): A.read_file(path, 1)

    def test_duplicate_and_nonfinite_json_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): A.decode(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError): P.decode(raw)

    def test_arbitrary_receipt_or_digest_has_no_safe_authority(self):
        for supplied in (b'{"complete":true}', b'0'*64, b'sealed immutable bytes'):
            with self.subTest(supplied=supplied), self.assertRaisesRegex(ValueError, 'NO_SUPPORTED_SAFE_AUTHORITY'):
                A.safe_admit(supplied, '1'*64)

    def test_directory_names_and_aliases_are_exact(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'file').write_bytes(b'x'); (root/'alias').symlink_to('file')
            before = P.directory_observation(R, td)
            self.assertEqual(before['state'], 'PRESENT')
            self.assertEqual(P.alias_observation(R, str(root/'alias'))['target'], 'file')
            (root/'new').write_bytes(b'x')
            self.assertNotEqual(before['entries_sha256'], P.directory_observation(R, td)['entries_sha256'])
            self.assertEqual(P.directory_observation(R, str(root/'missing/child'))['state'], 'ABSENT')

    def test_directory_symlink_is_not_an_absent_search_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'alias').symlink_to('missing', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'real directory'):
                P.directory_observation(R, str(root/'alias/child'))

    def test_execution_capability_attribute_never_exempted(self):
        value = pin()
        for raw in (b'', b'capability'):
            with patch.object(A.os, 'getxattr', return_value=raw), self.assertRaisesRegex(ValueError, 'no file capability'):
                A.no_capabilities(value)


class PageFacts(unittest.TestCase):
    @staticmethod
    def fixture():
        raw = b'A'*4096 + b'B'*4096
        owners = [dict(start=4096, end=8192, flags=5, file_end=8192, file_offset=0, file_zero_tail=None),
                  dict(start=8192, end=16384, flags=6, file_end=12288, file_offset=4096,
                       file_zero_tail=[12288,12288])]
        ph = [(0x6474e552,4,4096,8192,0,4096,4096,1)]
        elf = types.SimpleNamespace(raw=raw, ph=ph)
        package = types.SimpleNamespace(Elf=lambda _:elf)
        dso = types.SimpleNamespace(load_pages=lambda _:owners)
        return raw, pin(raw=raw), owners, ph, package, dso

    def test_full_immutable_bytes_rw_relro_and_bss_owners(self):
        raw, record, owners, ph, package, dso = self.fixture()
        result = P.object_pages(raw, record, package, dso)
        self.assertEqual(result['pages'], [
            dict(relative=4096,file_offset=0,permissions_at_exec='r-xp',permissions_at_entry='r-xp',file_backed=True,bytes=(b'A'*4096).hex()),
            dict(relative=8192,file_offset=4096,permissions_at_exec='rw-p',permissions_at_entry='r--p',file_backed=True,bytes=None),
            dict(relative=12288,file_offset=0,permissions_at_exec='rw-p',permissions_at_entry='rw-p',file_backed=False,bytes=None)])

    def test_partial_relro_end_is_not_rounded_up(self):
        raw, record, owners, ph, package, dso = self.fixture()
        ph[0] = (0x6474e552,4,4096,8192,0,4097,4097,1)
        result = P.object_pages(raw, record, package, dso)
        self.assertEqual(result['pages'][-1]['permissions_at_entry'], 'rw-p')

    def test_readonly_bss_has_no_guessed_file_image(self):
        raw, record, owners, ph, package, dso = self.fixture()
        owners[0]['file_zero_tail'] = [8000,8192]
        with self.assertRaisesRegex(ValueError, 'without loader zero writes'):
            P.object_pages(raw, record, package, dso)

    def test_relro_cannot_claim_executable_page(self):
        raw, record, owners, ph, package, dso = self.fixture()
        ph[0] = (0x6474e552,4,0,4096,0,4096,4096,1)
        with self.assertRaisesRegex(ValueError, 'writable LOAD owner'):
            P.object_pages(raw, record, package, dso)

    def test_page_denominator_not_widened(self):
        raw, record, owners, ph, package, dso = self.fixture()
        owners[0]['end'] = 4096 + 65537*4096
        with self.assertRaisesRegex(ValueError, 'page-count bound'):
            P.object_pages(raw, record, package, dso)

    def test_cet_marked_main_or_bootstrap_refuses(self):
        for flag in (1,2,3):
            notes = [dict(properties=[dict(kind=0xc0000002,bytes=flag.to_bytes(4,'little').hex())])]
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, 'no IBT or SHSTK'): P.no_cet(notes)
        P.no_cet([dict(properties=[])])


class ContractShape(unittest.TestCase):
    @staticmethod
    def fixture():
        files = {role:pin('/platform/'+role, stat.S_IFREG|0o755, index+1)
                 for index,role in enumerate(P.ROLES)}
        directory = dict(path='/platform',state='PRESENT',identity=[1,4,stat.S_IFDIR|0o755],entries_sha256='3'*64)
        value = dict(schema='LI2STARTUP-PLATFORM-CONTRACT-1',authority='EXPLICIT_UNSAFE_GNU_STATIC_EXEC_V1',
            platform='linux-x86_64-gnu-4096',files=files,sonames=P.SONAMES,
            loader_inputs=dict(cache=pin('/etc/ld.so.cache'),preload=dict(path='/etc/ld.so.preload',state='ABSENT',file=None)),
            search_directories=[directory],aliases=[],obligations=P.OBLIGATIONS,review_basis='Concrete reviewed basis. '*8,
            environment={},programs=list(P.PROGRAMS),datasets_per_program=10,N01_program_dataset_pairs=20,N01_invocations=40)
        return copy.deepcopy(value), directory

    def check(self, value, directory):
        raw = P.canonical(value)
        held = types.SimpleNamespace(retain=lambda record, cap:b'ELF')
        with patch.object(P.os.path,'lexists',return_value=False), patch.object(P,'directory_observation',return_value=directory):
            return P.contract(raw, P.sha(raw), R, held)

    def test_explicit_contract_shape_positive(self):
        value, directory = self.fixture()
        actual, files = self.check(value,directory)
        self.assertEqual(actual,value); self.assertEqual(set(files),set(P.ROLES))

    def test_obligation_or_complete_population_cannot_be_changed(self):
        for key, changed in (('N01_invocations',39),('N01_program_dataset_pairs',True),('programs',['checksum']),
                             ('obligations',{}),('authority','PASSIVE_INVENTORY_ONLY'),('environment',{'LD_PRELOAD':'anything'})):
            value, directory = self.fixture(); value[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(value,directory)

    def test_search_drift_does_not_relabel_inventory_as_accepted(self):
        value, directory = self.fixture(); directory = dict(directory,entries_sha256='4'*64)
        with self.assertRaisesRegex(ValueError, 'search directory state'): self.check(value,directory)

    def test_whole_contract_digest_is_required(self):
        value, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, 'externally frozen'):
            P.contract(P.canonical(value),'0'*64,R,None)

class SavedBootstrap(unittest.TestCase):
    """Exercise the new composition, with old independently tested readers at
    explicit boundaries. The actual copied-source pathname never exists here.
    All control and closure bytes are constructed, sealed and reread separately.
    """
    def fixture(self, root, mutation=None):
        run_dir = root/'ignored/builds'; run_dir.mkdir(parents=True)
        destination_parent = root/'ignored/copies'; destination_parent.mkdir()
        data, modes = {}, {}
        def put(path, value, mode=0o600):
            data[str(path)] = value if type(value) is bytes else P.canonical(value)
            modes[str(path)] = mode
        class Store:
            def read(self, path, cap, expected=None):
                raw = data[str(path)]; B.need(len(raw)<=cap,'fixture cap')
                if expected is not None: B.need(B.exact(self.pin(path,cap),expected),'fixture exact current pin')
                return raw
            def pin(self, path, cap):
                raw = self.read(path,cap)
                return dict(path=str(path),bytes=len(raw),sha256=P.sha(raw),
                    stat=[1,100+sorted(data).index(str(path)),stat.S_IFREG|modes[str(path)],len(raw),2,3])
            def directory(self,path): return os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            def verify(self): pass
        # Stable identities must not depend on the incremental map's ordering.
        identities = {}; next_inode = [100]
        def observed(path,cap):
            raw = store.read(path,cap)
            if str(path) not in identities:
                identities[str(path)] = next_inode[0]; next_inode[0] += 1
            return dict(path=str(path),bytes=len(raw),sha256=P.sha(raw),
                stat=[1,identities[str(path)],stat.S_IFREG|modes[str(path)],len(raw),2,3])
        store=Store(); store.pin=observed
        args=types.SimpleNamespace(source_profile=root/'ignored/profile.json',source_profile_sha256='1'*64,
            main_joins=root/'ignored/main',main_joins_sha256='2'*64,startup_binding=root/'ignored/binding.json')
        complete=dict(programs={},captured=dict(env={},tools={}),configurations={},
            plan=dict(configuration_profile='rooted-offline-neutral-toml-comments-v1'),
            reference=dict(directory=str(args.main_joins),sha256=args.main_joins_sha256),stable=lambda:None)
        builds={}
        for name in B.PROGRAMS:
            destination=destination_parent/(name+'.so')
            complete['programs'][name]=dict(product={'catalog.li2boot':name.encode()})
            builds[name]=dict(directory=str(run_dir/name),env={},argv=['fixed-builder',name],
                limits=[120,180,128],destination=str(destination),catalog=dict(sha256=P.sha(name.encode())))
        source_profile=dict(path=str(args.source_profile),sha256=args.source_profile_sha256)
        source_map={'checked':'source'}
        put(args.startup_binding,b'binding')
        put(root/'package.py',b'package')
        put(root/'crates/liteinst-bootstrap/Cargo.lock',b'lock')
        pins=types.SimpleNamespace(SOURCE_REVISION='a'*40,SOURCE_PINS={'crates/liteinst-bootstrap/Cargo.lock':P.sha(b'lock')})
        ctx=types.SimpleNamespace(ROOT=root,B=types.SimpleNamespace(HELPER_SHA='3'*64,identity=lambda path:path))
        def request_and_command(_ctx,capture,directory,argv,limits):
            return dict(argv=argv,env=capture['env'],limits=list(limits)),dict(helper='3'*64)
        def closed(_store,directory,request,command,_hash):
            B.need(P.decode(store.read(directory/'request.json',B.MIB))==request,'fixture raw request join')
            B.need(P.decode(store.read(directory/'command.json',B.MIB))==command,'fixture raw command join')
            return 0,dict(stdout=b'artifact',stderr=b'')
        custody=types.SimpleNamespace(absolute=lambda path:Path(path),digest=P.digest,json_value=P.decode,
            source_profile=lambda *args:'a'*40,stamp=A.stamp,closed=closed)
        legacy=types.SimpleNamespace(request_and_command=request_and_command)
        driver=types.SimpleNamespace(source_snapshot=lambda *args:source_map)
        bootstrap=types.SimpleNamespace(build_plan=lambda *args:builds,artifact=lambda *args:root/'target/release/libliteinst_bootstrap.so')
        dso=types.SimpleNamespace(PACKAGE='package.py',PACKAGE_SHA=P.sha(b'package'),resolver=lambda _:None,
            inspect=lambda raw,catalog,package:dict(sha256=P.sha(raw),catalog=P.sha(catalog)))
        completed_reader=types.SimpleNamespace(authenticate=lambda *args:complete)
        parents={str(destination_parent):A.stamp(destination_parent.stat())[:3]}
        plan=dict(schema='LI2STARTUP-BOOTSTRAP-PLAN-1',revision='a'*40,source_revision=pins.SOURCE_REVISION,
            source_profile=source_profile,main_joins=complete['reference'],startup_binding=store.pin(args.startup_binding,B.MIB),
            sources=source_map,resolver_source=store.pin(root/'package.py',B.MIB),
            lock=store.pin(root/'crates/liteinst-bootstrap/Cargo.lock',B.MIB),tools={},configurations={},
            configuration_profile=complete['plan']['configuration_profile'],cargo_cwd='/',builds=builds,
            destination_parents=parents,hardware='fixture',cpus=[0],load_average=['0','0','0'],
            producer_dispatches=0,verifier_dispatches=0,native_dispatches=0,qualification_complete=False)
        put(run_dir/'planned.json',plan); planned_pin=store.pin(run_dir/'planned.json',B.MIB)
        rows={}
        for index,name in enumerate(B.PROGRAMS):
            spec=builds[name]; directory=Path(spec['directory']); raw=('DSO-'+name).encode()
            put(spec['destination'],raw,0o400); destination=store.pin(spec['destination'],B.MIB)
            before=dict(path=str(root/'target/release/libliteinst_bootstrap.so'),bytes=len(raw),sha256=P.sha(raw),
                stat=[1,index+1,stat.S_IFREG|0o755,len(raw),2,3])
            copied=dict(source_before=before,source_after=copy.deepcopy(before),destination=destination,bytes_equal=True)
            if mutation=='copy-mismatch' and index==0:
                copied['source_before']['sha256']='0'*64;copied['source_after']['sha256']='0'*64
            put(directory/'copy.json',copied); copy_pin=store.pin(directory/'copy.json',B.MIB)
            request,command=request_and_command(ctx,dict(env={}),directory,spec['argv'],tuple(spec['limits']))
            for control in B.CONTROL: put(directory/control,b'control')
            put(directory/'request.json',request);put(directory/'command.json',command)
            inspected=dso.inspect(raw,complete['programs'][name]['product']['catalog.li2boot'],None)
            put(directory/'linked-facts.json',inspected);facts_pin=store.pin(directory/'linked-facts.json',B.MIB)
            files={str(directory/n):store.pin(directory/n,B.MIB) for n in B.CONTROL}
            files[str(directory/'linked-facts.json')]=facts_pin;files[str(directory/'copy.json')]=copy_pin
            closure=dict(schema='LI2STARTUP-BOOTSTRAP-BUILD-1',program=name,revision=plan['revision'],plan=planned_pin,
                source_revision=pins.SOURCE_REVISION,source_profile=source_profile,main_joins=complete['reference'],
                sources=source_map,resolver_source=plan['resolver_source'],lock=plan['lock'],catalog=spec['catalog'],
                destination=destination,copy=copied,files=files,env={},tools={},configurations={},
                configuration_profile='rooted-offline-neutral-toml-comments-v1',cargo_cwd='/',
                status='BUILT_INSPECTED_PENDING_FINAL_PACKAGE',qualification_complete=False,execution_authorized=False)
            if mutation=='omitted-raw-control' and index==0: del closure['files'][str(directory/'stderr.txt')]
            put(directory/'closed.json',closure)
            rows[name]=dict(status='BUILT_INSPECTED_PENDING_FINAL_PACKAGE',attempts=1,build_dispatches=1,error=None,exit=0,
                destination=destination,copy=copy_pin,closure=store.pin(directory/'closed.json',B.MIB),facts=facts_pin)
        run=dict(schema='LI2STARTUP-BOOTSTRAP-RUN-1',source_revision=pins.SOURCE_REVISION,programs=rows,plan=planned_pin,
            producer_dispatches=0,verifier_dispatches=0,native_dispatches=0,observer_dispatches=0,ordinary_n01_invocations=0,
            bootstrap_builds_complete=True,platform_contract_accepted=False,artifact_complete=False,
            qualification_complete=False,execution_authorized=False,performance_eligible=False,error=None,load_average_end=['0','0','0'])
        if mutation=='second-attempt':run['programs']['checksum']['attempts']=2
        if mutation=='reported-authority':run['execution_authorized']=True
        put(run_dir/'closed.json',run)
        ref=dict(directory=str(run_dir),sha256=P.sha(data[str(run_dir/'closed.json')]))
        return lambda:B.authenticate(ctx,None,legacy,custody,pins,None,None,completed_reader,driver,bootstrap,dso,args,store,ref)

    def test_complete_two_build_closures_reconstruct(self):
        with tempfile.TemporaryDirectory() as td:
            result=self.fixture(Path(td))()
            self.assertEqual(tuple(result['programs']),B.PROGRAMS)
            self.assertEqual(result['programs']['checksum']['bootstrap'],b'DSO-checksum')
            self.assertEqual(result['programs']['rle-roundtrip']['bootstrap'],b'DSO-rle-roundtrip')
            result['stable']()

    def test_resealed_semantic_copy_mutant_reaches_copy_checker(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError,'historical built bytes'):
                self.fixture(Path(td),'copy-mismatch')()

    def test_resealed_omitted_raw_control_refuses_at_closure_join(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError,'complete reconstructed bootstrap closure'):
                self.fixture(Path(td),'omitted-raw-control')()

    def test_retry_or_reported_authority_never_promoted(self):
        for mutation,reason in (('second-attempt','one successful saved build'),('reported-authority','cannot grant execution')):
            with tempfile.TemporaryDirectory() as td:
                with self.subTest(mutation=mutation),self.assertRaisesRegex(ValueError,reason):
                    self.fixture(Path(td),mutation)()

class SessionCopies(unittest.TestCase):
    def fixture(self, root):
        directory=root/'ignored';directory.mkdir()
        source=directory/'source';source.write_bytes(b'complete candidate')
        raw,source_pin=A.read_file(source)
        dataset=directory/'dataset';dataset.write_bytes(b'')
        _,dataset_pin=A.read_file(dataset)
        profile=dict(_root=str(root),native_sources={'caller.py':'1'*64},reviewed=dict(xstate_bytes=832))
        item=dict(main_pin=source_pin,main_bytes=raw,original_bytes=b'original',bootstrap_pin=pin(),
            bootstrap_bytes=b'ELF',linked_facts={},observer_objects=dict(main=dict(file=source_pin,pages=[]),
            loader={},bootstrap={},dependencies=[]),entry=0x401000,entry_bytes='90',
            completion_relative=0x2000,completion_file_offset=None)
        held=R.Custody();held.retain(source_pin,1024)
        store=types.SimpleNamespace(close=lambda:None)
        session=A.Session(A._CONSTRUCTION,profile,dict(checksum=item),dict(env={},tools={}),R,held,store,lambda:None)
        candidate=directory/'copy';candidate.write_bytes(raw);candidate.chmod(0o700)
        _,copy_pin=A.read_file(candidate)
        return session,dataset_pin,copy_pin

    def test_request_requires_actual_execution_copy(self):
        with tempfile.TemporaryDirectory() as td:
            session,dataset,_=self.fixture(Path(td))
            try:
                with self.assertRaisesRegex(ValueError,'executable copy required'):session.request('checksum',dataset)
            finally:session.close()

    def test_bound_copy_preserves_bytes_and_immutable_request(self):
        with tempfile.TemporaryDirectory() as td:
            session,dataset,copy_pin=self.fixture(Path(td))
            try:
                session.bind_main_copy('checksum',copy_pin)
                session.profile['reviewed']['xstate_bytes']=1
                session.programs['checksum']['entry']=0
                request=session.request('checksum',dataset)
                self.assertEqual(request['main']['file'],copy_pin)
                self.assertEqual(request['entry'],0x401000)
                self.assertEqual(request['entry_bytes'],'90')
                self.assertEqual(request['xstate_bytes'],832)
                self.assertEqual(session.execution_inputs(),dict(env={},tools={}))
                request['entry']=0
                self.assertEqual(session.request('checksum',dataset)['entry'],0x401000)
            finally:session.close()

    def test_changed_copy_and_second_copy_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            session,dataset,copy_pin=self.fixture(Path(td))
            try:
                path=Path(copy_pin['path']);path.write_bytes(b'changed');path.chmod(0o700)
                _,changed=A.read_file(path)
                with self.assertRaisesRegex(ValueError,'distinct exact owned'):session.bind_main_copy('checksum',changed)
            finally:session.close()
        with tempfile.TemporaryDirectory() as td:
            session,dataset,copy_pin=self.fixture(Path(td))
            try:
                session.bind_main_copy('checksum',copy_pin)
                with self.assertRaisesRegex(ValueError,'one executable copy'):session.bind_main_copy('checksum',copy_pin)
            finally:session.close()

    def test_closed_session_cannot_issue_request(self):
        with tempfile.TemporaryDirectory() as td:
            session,dataset,copy_pin=self.fixture(Path(td))
            session.bind_main_copy('checksum',copy_pin);session.close()
            with self.assertRaisesRegex(ValueError,'live final admission owners'):session.stable()
            with self.assertRaisesRegex(ValueError,'live final admission owners'):session.request('checksum',dataset)


if __name__ == '__main__':
    unittest.main()
