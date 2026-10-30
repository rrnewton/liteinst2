#!/usr/bin/env python3
"""Pure saved-input, copy and linked-ELF controls; no subprocess dispatch."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import types
import unittest


def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
B=module(HERE/'startup_bootstrap.py','bootstrap_control_driver')
D=module(HERE/'startup_dso.py','bootstrap_control_dso')
C=module(HERE/'startup_completed.py','bootstrap_control_completed')
L=module(HERE/'startup_bootstrap_from_root.py','bootstrap_control_launcher')
K=module(HERE/'startup_custody.py','bootstrap_control_custody')
S=module(HERE/'startup_saved.py','bootstrap_control_saved')
P=module(ROOT/'evaluation/offline-router-native/package_controls.py','bootstrap_control_fixture')
CATALOG=b'LI2-FROZEN-CATALOG-TEST-ONLY-0001\0'


def dso_fixture():
    raw=P.dynamic_image()
    struct.pack_into('<Q',raw,0x2020,0x800)
    struct.pack_into('<Q',raw,0x2520,0x800)
    struct.pack_into('<QQ',raw,0x30c0+16,0x800,0x800)
    struct.pack_into('<H',raw,56,6)
    struct.pack_into('<IIQQQQQQ',raw,64,1,6,0,0,0,0x2000,0x2000,4096)
    struct.pack_into('<IIQQQQQQ',raw,176,1,4,0x2000,0x2000,0x2000,0x1000,0x1000,4096)
    struct.pack_into('<IIQQQQQQ',raw,232,1,5,0x3000,0x3000,0x3000,0x1000,0x1000,4096)
    struct.pack_into('<IIQQQQQQ',raw,288,0x6474e551,6,0,0,0,0,0,16)
    struct.pack_into('<IIQQQQQQ',raw,344,0x6474e552,4,0x1800,0x1800,0x1800,0x800,0x800,1)
    names=b'\0'+P.pkg.SYMBOL+b'\0libc.so.6\0'
    raw[0x2600:0x2600+len(names)]=names
    struct.pack_into('<Q',raw,0x3140+32,len(names))
    # Preserve the original generic relocation; append a real loader-relative
    # init-array store, with coherent section and dynamic table extents.
    struct.pack_into('<QQq',raw,0x2418,0x1900,8,0x3800)
    struct.pack_into('<Q',raw,0x3180+32,48)
    tags=[(5,0x2600),(6,0x2500),(10,len(names)),(11,24),(7,0x2400),(8,48),(9,24),
          (1,len(P.pkg.SYMBOL)+2),(0x6ffffffb,0x49),(25,0x1900),(27,8),(0,0)]
    struct.pack_into('<QQ',raw,120+32,len(tags)*16,len(tags)*16)
    for i,row in enumerate(tags):struct.pack_into('<qQ',raw,0x2300+i*16,*row)
    struct.pack_into('<Q',raw,0x1900,0x3800)
    raw[0x3800]=0xc3
    raw[0x2a00:0x2a00+len(CATALOG)]=CATALOG
    return raw


def artifact_rows(root):
    return [dict(reason='compiler-artifact',manifest_path=str(root/'crates/liteinst-bootstrap/Cargo.toml'),
        target=dict(name='liteinst_bootstrap',kind=['cdylib'],crate_types=['cdylib'],
            src_path=str(root/'crates/liteinst-bootstrap/src/lib.rs')),
        profile=dict(B.PROFILE),filenames=[str(root/'target/release/libliteinst_bootstrap.so')],executable=None),
        dict(reason='build-finished',success=True)]


def encode(rows):
    return ('\n'.join(json.dumps(row) for row in rows)+'\n').encode()


class BuildContracts(unittest.TestCase):
    def test_fixed_rooted_standalone_locked_release_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();catalog=root/'ignored/catalog';catalog.parent.mkdir();catalog.write_bytes(b'catalog')
            env=dict(RUSTC='/tools/rustc',CARGO_TARGET_DIR=str(root/'target'),LITEINST_BOOTSTRAP_CATALOG=str(catalog))
            self.assertEqual(L.command(['launcher','/tools/cargo',str(root)],env),
                ['/tools/cargo','build','--release','--locked','--offline','--manifest-path',
                 str(root/'crates/liteinst-bootstrap/Cargo.toml'),'--lib','--message-format=json'])
            with self.assertRaises(ValueError):L.command(['launcher','/tools/cargo',str(root),'extra'],env)
            env['CARGO_TARGET_DIR']=str(root/'ignored/other-target')
            with self.assertRaises(ValueError):L.command(['launcher','/tools/cargo',str(root)],env)

    def test_whole_two_build_plan_keeps_one_target_and_distinct_catalogs(self):
        complete=dict(captured=dict(env={'CARGO_TARGET_DIR':'/repo/target'},tools=dict(python={'path':'/python'},cargo={'path':'/cargo'})),programs={})
        for name in B.PROGRAMS:
            complete['programs'][name]=dict(catalog_pin={'path':'/repo/ignored/'+name+'.catalog'},policy={'bootstrap':'/repo/ignored/'+name+'.so'})
        plans=B.build_plan(Path('/repo'),complete,Path('/repo/ignored/build'))
        self.assertEqual(tuple(plans),B.PROGRAMS)
        self.assertEqual(plans['checksum']['argv'],plans['rle-roundtrip']['argv'])
        for name,row in plans.items():
            self.assertEqual(row['limits'],[120,180,128]);self.assertEqual(row['attempts'],1)
            self.assertEqual(row['env']['CARGO_TARGET_DIR'],'/repo/target')
            self.assertEqual(row['env']['LITEINST_BOOTSTRAP_CATALOG'],'/repo/ignored/'+name+'.catalog')
            self.assertEqual(row['cargo_cwd'],'/')

    def test_actual_cdylib_artifact_accepts_without_executable_field_value(self):
        root=Path('/repo')
        self.assertEqual(B.artifact(encode(artifact_rows(root)),root),root/'target/release/libliteinst_bootstrap.so')

    def test_binary_relabelling_wrong_source_and_extra_products_refuse(self):
        root=Path('/repo')
        for change in ('executable','source','filenames','kind'):
            rows=artifact_rows(root)
            if change=='executable':rows[0]['executable']='/repo/target/release/tool'
            elif change=='source':rows[0]['target']['src_path']='/repo/other.rs'
            elif change=='filenames':rows[0]['filenames'].append('/repo/other.so')
            else:rows[0]['target']['kind']=['bin']
            with self.subTest(change=change),self.assertRaises(ValueError):B.artifact(encode(rows),root)

    def test_profile_relaxation_and_failed_terminal_refuse(self):
        root=Path('/repo')
        for key in ('debug_assertions','overflow_checks','opt_level','test','success'):
            rows=artifact_rows(root)
            if key=='success':rows[1]['success']=False
            else:rows[0]['profile'][key]={'debug_assertions':False,'overflow_checks':False,'opt_level':'0','test':True}[key]
            with self.subTest(key=key),self.assertRaises(ValueError):B.artifact(encode(rows),root)

    def test_two_temporal_copies_survive_reused_target_without_rebinding_old_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'target.so';source.write_bytes(b'first')
            store=K.Store()
            try:
                raw,first,receipt=B.copy_artifact(K,source,root/'first.so',store)
                self.assertEqual(raw,b'first');self.assertEqual(receipt['source_before'],receipt['source_after'])
                self.assertEqual(stat.S_IMODE(first['stat'][2]),0o400)
                source.write_bytes(b'second')
                raw,second,receipt=B.copy_artifact(K,source,root/'second.so',store)
                self.assertEqual(raw,b'second');self.assertNotEqual(first['sha256'],second['sha256'])
                store.verify();self.assertEqual(store.read(root/'first.so',16),b'first')
            finally:store.close()

    def test_destination_never_overwrites_existing_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.write_bytes(b'new');target=root/'target';target.write_bytes(b'old')
            store=K.Store()
            try:
                with self.assertRaises(FileExistsError):B.copy_artifact(K,source,target,store)
                self.assertEqual(target.read_bytes(),b'old')
            finally:store.close()

    def test_transport_reconstruction_contains_every_exact_input(self):
        expected={name:('expected-'+name).encode() for name in S.EXPECTED}
        product={'candidate.elf':b'main','catalog.li2boot':b'catalog'}
        raw=C.transport('checksum',b'original',expected,product,[b'loader',b'libc'],S)
        self.assertTrue(raw.startswith(('LI2W01-INPUT\t2\t'+S.PROFILE+'\tchecksum\t11\n').encode()))
        self.assertTrue(raw.endswith(b'END\n'))
        for name,value in [('input/original',b'original'),*[(f'expected/{n}',v) for n,v in expected.items()],
                           ('product/candidate.elf',b'main'),('product/catalog.li2boot',b'catalog'),
                           ('dependency/0000',b'loader'),('dependency/0001',b'libc')]:
            self.assertIn(('%s\t%d\t%s\n'%(name,len(value),C.sha(value))).encode()+value,raw)
        changed=dict(product);changed['unknown/name']=b'x'
        with self.assertRaises(ValueError):C.transport('checksum',b'original',expected,changed,[b'loader'],S)


class LinkedFacts(unittest.TestCase):
    def inspect(self,raw):return D.inspect(bytes(raw),CATALOG,P.pkg)

    def test_actual_catalog_completion_constructors_and_protection_facts(self):
        facts=self.inspect(dso_fixture())
        self.assertEqual(facts['completion']['address'],0x800)
        self.assertEqual(facts['catalog']['address'],0x2a00)
        self.assertEqual(facts['needed'],['libc.so.6'])
        self.assertEqual(facts['constructors']['init_array'][0]['resolved_relative'],0x3800)
        self.assertFalse(facts['platform_contract_accepted']);self.assertFalse(facts['execution_authorized'])
        self.assertFalse(facts['qualification_complete'])

    def test_nonzero_completion_remains_refused(self):
        raw=dso_fixture();raw[0x800]=1
        with self.assertRaises(P.pkg.Refused):self.inspect(raw)

    def test_writable_catalog_owner_refuses(self):
        raw=dso_fixture();struct.pack_into('<I',raw,176+4,6)
        with self.assertRaisesRegex(ValueError,'catalog is wholly'):self.inspect(raw)

    def test_each_required_linked_lifetime_flag_is_checked(self):
        for value in (0x48,0x41,0x09):
            raw=dso_fixture();struct.pack_into('<Q',raw,0x2300+8*16+8,value)
            with self.subTest(flags=value),self.assertRaisesRegex(ValueError,'linked NOW/NODELETE/NODLOPEN'):self.inspect(raw)

    def test_unknown_dynamic_protocol_refuses(self):
        raw=dso_fixture();struct.pack_into('<q',raw,0x2300+8*16,0x60000001)
        with self.assertRaisesRegex(ValueError,'supported unique dynamic tag'):self.inspect(raw)

    def test_text_relocation_declaration_refuses(self):
        raw=dso_fixture();struct.pack_into('<qQ',raw,0x2300+11*16,22,0)
        struct.pack_into('<qQ',raw,0x2300+12*16,0,0)
        struct.pack_into('<QQ',raw,120+32,13*16,13*16)
        with self.assertRaisesRegex(ValueError,'no dynamic text relocations'):self.inspect(raw)

    def test_missing_application_initializer_refuses(self):
        raw=dso_fixture();struct.pack_into('<Q',raw,0x2300+10*16+8,0)
        with self.assertRaisesRegex(ValueError,'actual resolved nonempty bootstrap init array'):self.inspect(raw)

    def test_actual_relocation_cannot_write_catalog(self):
        raw=dso_fixture();struct.pack_into('<Q',raw,0x2400,0x2a00)
        with self.assertRaisesRegex(ValueError,'dynamic relocation target must be writable non-executable LOAD'):self.inspect(raw)

    def test_relro_must_own_real_writable_file_bytes(self):
        raw=dso_fixture();struct.pack_into('<Q',raw,344+16,0x2800)
        with self.assertRaisesRegex(ValueError,'actual writable file-backed RELRO owner'):self.inspect(raw)

    def test_size_dependent_copy_relocation_is_not_assumed_eight_bytes(self):
        # The null symbol reaches the store-width guard without triggering
        # the independent completion-name relocation guard first.
        raw=dso_fixture();struct.pack_into('<Q',raw,0x2408,5)
        with self.assertRaisesRegex(ValueError,'supported bounded DSO relocation store'):self.inspect(raw)

    def test_tlsdesc_pair_cannot_partially_overwrite_constructor_slot(self):
        raw=dso_fixture();struct.pack_into('<QQq',raw,0x2400,0x18f8,36,0)
        with self.assertRaisesRegex(ValueError,'unique whole constructor relocation'):self.inspect(raw)

    def test_completion_must_remain_writable_after_actual_relro(self):
        raw=dso_fixture()
        struct.pack_into('<Q',raw,0x2020,0x1000);struct.pack_into('<Q',raw,0x2520,0x1000)
        struct.pack_into('<QQ',raw,0x30c0+16,0x1000,0x1000)
        with self.assertRaisesRegex(ValueError,'completion store remains writable after RELRO'):self.inspect(raw)

    def test_constructor_array_must_be_in_actual_protected_pages(self):
        raw=dso_fixture();struct.pack_into('<Q',raw,0x2300+9*16+8,0x900)
        struct.pack_into('<Q',raw,0x900,0x3800)
        with self.assertRaisesRegex(ValueError,'constructor array is actually page-protected by RELRO'):self.inspect(raw)

    def test_executable_stack_refuses(self):
        raw=dso_fixture();struct.pack_into('<I',raw,288+4,7)
        with self.assertRaisesRegex(ValueError,'explicit RW/non-executable GNU stack'):self.inspect(raw)


def symbol_constructor_fixture(*,binding=1,visibility=2,kind=2,section_index=7):
    raw=dso_fixture()
    # Preserve both completion definitions; add a third actual DYNSYM entry.
    names_size=struct.unpack_from('<Q',raw,0x3140+32)[0]
    name=b'initializer\0'
    raw[0x2600+names_size:0x2600+names_size+len(name)]=name
    struct.pack_into('<Q',raw,0x3140+32,names_size+len(name))
    struct.pack_into('<Q',raw,0x2300+2*16+8,names_size+len(name))
    struct.pack_into('<Q',raw,0x3100+32,72)
    struct.pack_into('<H',raw,60,8)
    struct.pack_into('<IIQQQQIIQQ',raw,0x31c0,0,1,6,0x37f0,0x37f0,0x20,0,0,1,0)
    struct.pack_into('<IBBHQQ',raw,0x2530,names_size,(binding<<4)|kind,visibility,section_index,0x37f0,0x20)
    symbol_index=2
    if binding==0:
        # ELF local symbols precede globals; retain the completion definition
        # while moving this local initializer before it and repair sh_info.
        completion=bytes(raw[0x2518:0x2530])
        raw[0x2518:0x2530]=raw[0x2530:0x2548]
        raw[0x2530:0x2548]=completion
        struct.pack_into('<I',raw,0x3100+44,2)
        symbol_index=1
    struct.pack_into('<QQq',raw,0x2418,0x1900,(symbol_index<<32)|1,0x10)
    return raw


def alias_fixture(*,executable=False,flags=6,different_file_page=False):
    raw=dso_fixture()
    headers=[list(struct.unpack_from('<IIQQQQQQ',raw,64+56*i)) for i in range(6)]
    first,dynamic,ro,rx,stack,relro=headers
    # Complete valid program-header roster, sorted LOAD VAs and coherent sizes.
    # The added byte range is disjoint; only the rounded page is shared.
    if executable:
        rx[5]=rx[6]=0xf00
        extra=[1,flags,0x3f00,0x3f00,0x3f00,0x100,0x100,4096]
        ordered=[first,ro,rx,extra,dynamic,stack,relro]
    else:
        ro[5]=ro[6]=0xf00
        extra=[1,flags,0x3f00 if different_file_page else 0x2f00,0x2f00,0x2f00,0x100,0x100,4096]
        ordered=[first,ro,extra,rx,dynamic,stack,relro]
    struct.pack_into('<H',raw,56,len(ordered))
    for i,header in enumerate(ordered):
        struct.pack_into('<IIQQQQQQ',raw,64+56*i,*header)
    return raw


def counted_fixture(raw,count,tag=0x6ffffff9):
    struct.pack_into('<qQ',raw,0x2300+11*16,tag,count)
    struct.pack_into('<qQ',raw,0x2300+12*16,0,0)
    struct.pack_into('<QQ',raw,120+32,13*16,13*16)
    return raw


class LoaderSemantics(unittest.TestCase):
    def inspect(self,raw):return D.inspect(bytes(raw),CATALOG,P.pkg)

    def test_relative_initializer_uses_actual_rela_addend_not_file_pointer(self):
        raw=dso_fixture()
        struct.pack_into('<Q',raw,0x1900,0xdeadbeef)
        item=self.inspect(raw)['constructors']['init_array'][0]
        self.assertEqual(item['file_pointer'],0xdeadbeef)
        self.assertEqual(item['resolved_relative'],0x3800)
        self.assertEqual([(r['target'],r['kind'],r['symbol'],r['addend']) for r in item['relocations']],
                         [(0x1900,8,0,0x3800)])

    def test_old_unrelocated_initializer_is_retained_as_negative(self):
        raw=dso_fixture()
        struct.pack_into('<Q',raw,0x3180+32,24)
        struct.pack_into('<Q',raw,0x2300+5*16+8,24)
        self.assertEqual(struct.unpack_from('<Q',raw,0x1900)[0],0x3800)
        with self.assertRaisesRegex(ValueError,'constructor slot requires load-bias-producing relocation'):
            self.inspect(raw)

    def test_none_relocation_does_not_turn_raw_pointer_into_relative_address(self):
        raw=dso_fixture();struct.pack_into('<Q',raw,0x2420,0)
        with self.assertRaisesRegex(ValueError,'constructor slot requires load-bias-producing relocation'):
            self.inspect(raw)

    def test_hidden_defined_symbol_and_nonzero_addend_produce_relative_initializer(self):
        item=self.inspect(symbol_constructor_fixture())['constructors']['init_array'][0]
        self.assertEqual(item['resolved_relative'],0x3800)
        self.assertEqual((item['relocations'][0]['kind'],item['relocations'][0]['addend']),(1,0x10))

    def test_local_defined_symbol_produces_relative_initializer(self):
        item=self.inspect(symbol_constructor_fixture(binding=0,visibility=0))['constructors']['init_array'][0]
        self.assertEqual(item['resolved_relative'],0x3800)

    def test_defined_default_visible_symbol_cannot_be_assumed_unpreempted(self):
        with self.assertRaisesRegex(ValueError,'constructor symbol must be local or hidden without preemption'):
            self.inspect(symbol_constructor_fixture(visibility=0))

    def test_absolute_common_reserved_undefined_and_out_of_table_indices_refuse(self):
        for index in (0,8,0xff00,0xfff1,0xfff2,0xffff):
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,'ordinary defined section index'):
                self.inspect(symbol_constructor_fixture(section_index=index))

    def test_ifunc_and_tls_symbols_are_not_plain_bias_plus_symbol(self):
        for kind in (6,10):
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'ordinary code, not IFUNC/TLS'):
                self.inspect(symbol_constructor_fixture(kind=kind))

    def test_symbol_addend_cannot_escape_owned_section_even_into_executable_load(self):
        raw=symbol_constructor_fixture();struct.pack_into('<q',raw,0x2428,0x30)
        with self.assertRaisesRegex(ValueError,'symbol and addend remain in their owned code section'):
            self.inspect(raw)

    def test_ordinary_disjoint_page_backing_is_explicit(self):
        facts=self.inspect(dso_fixture())
        self.assertEqual([(r['start'],r['end'],r['flags'],r['file_offset'],r['file_end'])
                          for r in facts['page_owners']],
                         [(0,0x2000,6,0,0x2000),(0x2000,0x3000,4,0x2000,0x3000),
                          (0x3000,0x4000,5,0x3000,0x4000)])
        self.assertTrue(all(r['anonymous'] is None and r['file_zero_tail'] is None for r in facts['page_owners']))

    def test_byte_disjoint_catalog_ro_rw_page_alias_refuses(self):
        raw=alias_fixture();elf=P.pkg.Elf(bytes(raw))
        self.assertEqual([(p[3],p[3]+p[6]) for p in elf.loads],
                         [(0,0x2000),(0x2000,0x2f00),(0x2f00,0x3000),(0x3000,0x4000)])
        self.assertEqual(elf.at(0x2a00,len(CATALOG)),CATALOG)
        with self.assertRaisesRegex(ValueError,'page-rounded LOAD ownership overlap/order'):
            self.inspect(raw)

    def test_byte_disjoint_executable_rw_page_alias_refuses(self):
        raw=alias_fixture(executable=True)
        self.assertEqual(P.pkg.Elf(bytes(raw)).at(0x3800,1),b'\xc3')
        with self.assertRaisesRegex(ValueError,'page-rounded LOAD ownership overlap/order'):
            self.inspect(raw)

    def test_equal_permission_page_alias_is_outside_explicit_disjoint_page_profile(self):
        with self.assertRaisesRegex(ValueError,'page-rounded LOAD ownership overlap/order'):
            self.inspect(alias_fixture(flags=4))

    def test_alias_with_different_file_page_cannot_replace_catalog_backing(self):
        raw=alias_fixture(different_file_page=True)
        elf=P.pkg.Elf(bytes(raw))
        self.assertEqual(elf.at(0x2a00,len(CATALOG)),CATALOG)
        self.assertEqual((elf.loads[2][2],elf.loads[2][3]),(0x3f00,0x2f00))
        with self.assertRaisesRegex(ValueError,'page-rounded LOAD ownership overlap/order'):
            self.inspect(raw)

    def test_counted_relative_prefix_preserves_actual_relative_initializer(self):
        facts=self.inspect(counted_fixture(dso_fixture(),2))
        self.assertEqual(facts['constructors']['init_array'][0]['resolved_relative'],0x3800)
        self.assertEqual(facts['dynamic_tags'][str(0x6ffffff9)],2)

    def test_relative_fast_path_count_cannot_exceed_actual_table(self):
        with self.assertRaisesRegex(ValueError,'relative fast-path count within actual table'):
            self.inspect(counted_fixture(dso_fixture(),3))

    def test_relative_fast_path_cannot_reinterpret_hidden_symbol_initializer(self):
        with self.assertRaisesRegex(ValueError,'relative fast-path prefix contains only symbol-zero RELATIVE records'):
            self.inspect(counted_fixture(symbol_constructor_fixture(),2))

    def test_relative_fast_path_requires_its_own_complete_table(self):
        with self.assertRaisesRegex(ValueError,'relative fast-path count requires complete table'):
            self.inspect(counted_fixture(dso_fixture(),1,tag=0x6ffffffa))


if __name__=='__main__':
    unittest.main()
