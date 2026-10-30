#!/usr/bin/env python3
"""Additive source controls; no original, candidate, observer or DSO dispatch.

Fixtures are complete ELF byte images parsed by the unchanged package and DSO
readers. No mocked symbol/hash/version/relocation result supplies acceptance.
They test this finite resolver, not startup readiness or native execution.
"""
import importlib.util
from pathlib import Path
import struct
import unittest

import dependency_constructors as C
import final_platform as P
import package as R

HERE = Path(__file__).resolve().parent
DSO = HERE.parent/'adjacent-b2/artifact-verifier/startup_dso.py'
spec = importlib.util.spec_from_file_location('_dependency_controls_dso', DSO)
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

STR = 0x800
SYM = 0x1000
HASH = 0x1400
VERSYM = 0x1800
VERDEF = 0x1900
VERNEED = 0x1a00
RELA = 0x1c00
DYNAMIC = 0x2000
CODE = 0x3000
ARRAY = 0x4000
SECTIONS = 0x5000
NAME = '__cpu_indicator_init'
SONAMES = {'loader':'ld-linux-x86-64.so.2', 'libc':'libc.so.6', 'libgcc':'libgcc_s.so.1'}
EDGES = {'main':['/private/bootstrap.so'], 'bootstrap':['libgcc_s.so.1','libc.so.6'],
         'loader':[], 'libc':['ld-linux-x86-64.so.2'], 'libgcc':['libc.so.6']}


def image(role, *, definitions=None, hash_kind='gnu', flags=0, flags1=0,
          edges=None, addend=0, version=0x800c, verdef_flags=0, required_index=None,
          global_version_label='GCC_4.8.0'):
    """Three disjoint LOADs; real dynsym/hash/version/RELA/array bytes.

    Each symbol spec is (name, info, other, section, value, size). Undefined
    references carry version1; every definition carries the selected version.
    Main deliberately has no dynamic symbol namespace, matching the carrier.
    """
    if definitions is None:
        definitions = [(NAME if role=='libgcc' else role+'_function',0x12,0,7,CODE,32)]
    edges = list(EDGES[role] if edges is None else edges)
    strings=bytearray(b'\0'); offsets={}
    def text(value):
        if value not in offsets:
            offsets[value]=len(strings);strings.extend(value.encode('ascii')+b'\0')
        return offsets[value]
    for name, *_ in definitions:text(name)
    for name in edges:text(name)
    soname=SONAMES.get(role,'fixture-'+role+'.so');text(soname)
    text(global_version_label);text('NEEDED_VERSION')
    symbols=[(0,0,0,0,0,0)]+[(text(name),info,other,section,value,size)
        for name,info,other,section,value,size in definitions]
    raw=bytearray(0x6000)
    raw[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH',raw,16,2 if role=='main' else 3,62,1,
        CODE if role=='main' else 0,64,SECTIONS,0,64,56,5,64,10,0)
    headers=[(1,4,0,0,0,0x3000,0x3000,4096),
             (1,5,CODE,CODE,CODE,0x1000,0x1000,4096),
             (1,6,ARRAY,ARRAY,ARRAY,0x1000,0x1000,4096),
             (2,4,DYNAMIC,DYNAMIC,DYNAMIC,0,0,8),
             (0x6474e551,6,0,0,0,0,0,16)]
    for i,row in enumerate(headers):struct.pack_into('<IIQQQQQQ',raw,64+56*i,*row)
    raw[STR:STR+len(strings)]=strings
    for i,symbol in enumerate(symbols):struct.pack_into('<IBBHQQ',raw,SYM+24*i,*symbol)
    raw[CODE:CODE+32]=b'\x90'*31+b'\xc3'
    # The stored array pointer is deliberately unrelated: RELA determines it.
    struct.pack_into('<Q',raw,ARRAY,0xfeedface)
    struct.pack_into('<QQq',raw,RELA,ARRAY,(1<<32)|1,addend)
    if hash_kind=='gnu':
        hashes=[C.gnu_hash(name.encode('ascii')) for name,*_ in definitions]
        bloom=0
        for h in hashes:bloom|=(1<<(h%64))|(1<<((h>>5)%64))
        hash_raw=struct.pack('<IIIIQ',1,1,1,5,bloom)+struct.pack('<I',1)
        hash_raw+=b''.join(struct.pack('<I',(h&~1)|(i==len(hashes)-1)) for i,h in enumerate(hashes))
        hash_type,hash_tag=0x6ffffff6,0x6ffffef5
    else:
        hash_raw=struct.pack('<II',1,len(symbols))+struct.pack('<I',1)
        chain=[0]+list(range(2,len(symbols)))+[0]
        hash_raw+=struct.pack('<'+'I'*len(chain),*chain)
        hash_type,hash_tag=5,4
    raw[HASH:HASH+len(hash_raw)]=hash_raw
    numbers=[0]+[version if s[3] else 1 for s in symbols[1:]]
    struct.pack_into('<'+'H'*len(numbers),raw,VERSYM,*numbers)
    # A canonical base definition followed by the ordinary named definition.
    struct.pack_into('<HHHHIII',raw,VERDEF,1,1,1,1,C.elf_hash(soname.encode()),20,28)
    struct.pack_into('<II',raw,VERDEF+20,text(soname),0)
    struct.pack_into('<HHHHIII',raw,VERDEF+28,1,verdef_flags,12,1,C.elf_hash(global_version_label.encode()),20,0)
    struct.pack_into('<II',raw,VERDEF+48,text(global_version_label),0)
    need_size=0
    if required_index is not None:
        # Actual dependency/version pair, used to test overlaps and missing refs.
        dependency=edges[0]
        struct.pack_into('<HHIII',raw,VERNEED,1,1,text(dependency),16,0)
        struct.pack_into('<IHHII',raw,VERNEED+16,C.elf_hash(b'NEEDED_VERSION'),0,required_index,text('NEEDED_VERSION'),0)
        need_size=32
    tags=[(5,STR),(10,len(strings))]+[(1,text(name)) for name in edges]
    if role!='main':
        tags += [(6,SYM),(11,24),(hash_tag,HASH),(0x6ffffff0,VERSYM),
                 (0x6ffffffc,VERDEF),(0x6ffffffd,2),(14,text(soname))]
        if flags:tags.append((30,flags))
        if flags1:tags.append((0x6ffffffb,flags1))
        if required_index is not None:tags += [(0x6ffffffe,VERNEED),(0x6fffffff,1)]
        if role=='libgcc':tags += [(7,RELA),(8,24),(9,24),(25,ARRAY),(27,8)]
    tags.append((0,0))
    struct.pack_into('<QQ',raw,64+3*56+32,16*len(tags),16*len(tags))
    for i,row in enumerate(tags):struct.pack_into('<qQ',raw,DYNAMIC+16*i,*row)
    sections=[(0,0,0,0,0,0,0,0,0,0),
        (0,3,2,STR,STR,len(strings),0,0,1,0),
        (0,11,2,SYM,SYM,24*len(symbols),1,1,8,24),
        (0,hash_type,2,HASH,HASH,len(hash_raw),2,0,8,0),
        (0,0x6fffffff,2,VERSYM,VERSYM,2*len(symbols),2,0,2,2),
        (0,0x6ffffffd,2,VERDEF,VERDEF,56,1,2,4,0),
        (0,0x6ffffffe,2,VERNEED,VERNEED,need_size,1,1 if need_size else 0,4,0),
        (0,1,6,CODE,CODE,0x1000,0,0,16,0),
        (0,4,2,RELA,RELA,24,2,0,8,24),
        (0,14,3,ARRAY,ARRAY,8,0,0,8,8)]
    for i,row in enumerate(sections):struct.pack_into('<IIQQQQIIQQ',raw,SECTIONS+64*i,*row)
    return raw


def objects(**overrides):
    return {role:bytes(overrides.get(role,image(role))) for role in C.ROLES}


def namespace(**overrides):
    return C.Namespace(objects(**overrides),R,D)


def records(ns,role='libgcc'):
    obj=ns.objects[role]
    return D.relocations(obj['elf'],obj['tags'])


def tag_offset(raw,tag):
    length=struct.unpack_from('<Q',raw,64+3*56+32)[0]
    return next(DYNAMIC+i for i in range(0,length,16)
                if struct.unpack_from('<q',raw,DYNAMIC+i)[0]==tag)


class CompleteNamespace(unittest.TestCase):
    def test_actual_global_nondefault_version_positive(self):
        ns=namespace(); item=ns.constructors('libgcc',records(ns))['init_array'][0]
        proof=item['binding_proof']
        self.assertEqual(item['resolved_relative'],CODE)
        self.assertEqual(item['file_pointer'],0xfeedface)
        self.assertEqual(proof['symbol'],1)
        self.assertEqual(proof['name'],NAME)
        self.assertEqual(proof['version'],dict(index=12,nondefault=True,name='GCC_4.8.0',
            hash=C.elf_hash(b'GCC_4.8.0'),flags=0,parents=[]))
        self.assertEqual(proof['lookup'],dict(kind='gnu',hash=C.gnu_hash(NAME.encode()),symbol=1))
        self.assertEqual(proof['namespace'],{role:dict(bytes=len(raw),sha256=C.sha(raw))
            for role,raw in objects().items()})

    def test_default_explicit_version_is_not_unversioned_fallback(self):
        ns=namespace(libgcc=image('libgcc',version=12))
        value=ns.constructors('libgcc',records(ns))['init_array'][0]['binding_proof']
        self.assertFalse(value['version']['nondefault']);self.assertEqual(value['version']['index'],12)

    def test_old_bootstrap_and_old_platform_rules_still_refuse(self):
        ns=namespace(); obj=ns.objects['libgcc']
        with self.assertRaisesRegex(ValueError,'local or hidden without preemption'):
            D.constructors(obj['elf'],obj['tags'],records(ns),obj['symbols'])
        with self.assertRaisesRegex(ValueError,'local or hidden without preemption'):
            P.library_facts(obj['elf'].raw,'libgcc',R,D)
        new=P.library_facts_v2(obj['elf'].raw,'libgcc',R,D,ns)
        self.assertEqual(new['schema'],'LI2STARTUP-PLATFORM-LIBRARY-FACTS-2')
        self.assertEqual(new['constructor_profile'],C.PROFILE)
        self.assertEqual(new['constructors']['init_array'][0]['resolved_relative'],CODE)

    def test_competing_definition_in_every_other_dynamic_object_refuses(self):
        for role in ('bootstrap','loader','libc'):
            for info,other,version in ((0x12,0,12),(0x22,0,12),(0x12,2,0x800c),(0x1a,0,12)):
                raw=image(role,definitions=[(NAME,info,other,7,CODE,32)],version=version,
                          global_version_label='DIFFERENT_VERSION')
                ns=namespace(**{role:raw})
                with self.subTest(role=role,info=info,other=other),self.assertRaisesRegex(ValueError,'unique same-basename'):
                    ns.constructors('libgcc',records(ns))

    def test_second_definition_in_same_object_refuses(self):
        ns=namespace(libgcc=image('libgcc',definitions=[(NAME,0x12,0,7,CODE,32),(NAME,0x12,2,7,CODE+32,16)]))
        with self.assertRaisesRegex(ValueError,'unique same-basename'):ns.constructors('libgcc',records(ns))

    def test_undefined_references_are_not_competing_definitions(self):
        ns=namespace(bootstrap=image('bootstrap',definitions=[(NAME,0x12,0,0,0,0)]))
        self.assertEqual(ns.constructors('libgcc',records(ns))['init_array'][0]['resolved_relative'],CODE)

    def test_main_dynamic_export_cannot_be_hidden_by_static_symbol_inventory(self):
        raw=image('main');at=tag_offset(raw,0)
        struct.pack_into('<qQqQqQ',raw,at,6,SYM,11,24,0,0)
        length=at-DYNAMIC+48
        struct.pack_into('<QQ',raw,64+3*56+32,length,length)
        with self.assertRaisesRegex(ValueError,'main has no exported'):namespace(main=raw)

    def test_missing_or_extra_namespace_object_refuses(self):
        for role in C.ROLES:
            raw=objects();del raw[role]
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'complete fixed five-object'):
                C.Namespace(raw,R,D)
        raw=objects();raw['preload']=image('loader')
        with self.assertRaisesRegex(ValueError,'complete fixed five-object'):C.Namespace(raw,R,D)

    def test_actual_dependency_edges_and_soname_are_not_inventory_booleans(self):
        for role,edges in (('bootstrap',['libc.so.6']),('libgcc',['libc.so.6','extra.so']),('loader',['libc.so.6'])):
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'lookup graph|namespace edge/SONAME'):
                namespace(**{role:image(role,edges=edges)})
        raw=image('libgcc');struct.pack_into('<Q',raw,tag_offset(raw,14)+8,1)
        with self.assertRaisesRegex(ValueError,'namespace edge/SONAME'):namespace(libgcc=raw)

    def test_symbolic_group_direct_interpose_and_search_injection_refuse(self):
        for flags,flags1 in ((2,0),(0,4),(0,0x100),(0,0x400)):
            with self.subTest(flags=flags,flags1=flags1),self.assertRaisesRegex(ValueError,'no symbolic/direct'):
                namespace(libgcc=image('libgcc',flags=flags,flags1=flags1))
        for tag in (16,15,29):
            raw=image('libgcc');at=tag_offset(raw,0)
            struct.pack_into('<qQqQ',raw,at,tag,1,0,0)
            length=at-DYNAMIC+32;struct.pack_into('<QQ',raw,64+3*56+32,length,length)
            with self.subTest(tag=tag),self.assertRaisesRegex(ValueError,'no symbolic/direct|RPATH/RUNPATH'):
                namespace(libgcc=raw)

    def test_mutable_lookup_load_refuses_even_with_readonly_section_flags(self):
        raw=image('libgcc');struct.pack_into('<I',raw,64+4,6)
        with self.assertRaisesRegex(ValueError,'immutable actual LOAD owner'):namespace(libgcc=raw)

    def test_dependency_profile_cannot_be_used_as_bootstrap_resolver(self):
        ns=namespace()
        with self.assertRaisesRegex(ValueError,'only for dependencies'):ns.global_target('bootstrap',records(ns)[0])
        with self.assertRaisesRegex(ValueError,'dependency constructor role'):ns.constructors('bootstrap',[])


class ExactSymbolAndRelocation(unittest.TestCase):
    def test_special_ifunc_tls_weak_unique_and_visibility_classes_refuse(self):
        for info,other,section in ((0x1a,0,7),(0x16,0,7),(0x22,0,7),(0xa2,0,7),
                                   (0x12,3,7),(0x12,1,7),(0x12,0,0xfff1),(0x12,0,0xfff2),(0x12,0,0xffff)):
            ns=namespace(libgcc=image('libgcc',definitions=[(NAME,info,other,section,CODE,32)]))
            with self.subTest(direct=True,info=info,other=other,section=section),self.assertRaisesRegex(ValueError,'ordinary GLOBAL DEFAULT'):
                ns.global_target('libgcc',records(ns)[0])
            with self.subTest(info=info,other=other,section=section),self.assertRaisesRegex(ValueError,
                 'ordinary GLOBAL DEFAULT|local or hidden|ordinary code|ordinary defined section'):
                ns.constructors('libgcc',records(ns))

    def test_undefined_global_symbol_is_not_resolved_from_inventory(self):
        ns=namespace(libgcc=image('libgcc',definitions=[(NAME,0x12,0,0,0,0)]))
        with self.assertRaisesRegex(ValueError,'ordinary GLOBAL DEFAULT'):ns.constructors('libgcc',records(ns))

    def test_entire_symbol_range_and_size_are_checked(self):
        for address,size in ((CODE-1,32),(CODE+4095,2),(CODE,0)):
            ns=namespace(libgcc=image('libgcc',definitions=[(NAME,0x12,0,7,address,size)]))
            with self.subTest(address=address,size=size),self.assertRaisesRegex(ValueError,'whole actual ordinary code'):
                ns.constructors('libgcc',records(ns))

    def test_addend_never_escapes_to_nearby_code(self):
        for addend in (-1,1,32):
            ns=namespace(libgcc=image('libgcc',addend=addend))
            with self.subTest(addend=addend),self.assertRaisesRegex(ValueError,'finite zero-addend'):
                ns.constructors('libgcc',records(ns))

    def test_rel_without_explicit_addend_is_not_assumed_zero(self):
        raw=image('libgcc')
        for old,new,value in ((7,17,RELA),(8,18,16),(9,19,16)):
            struct.pack_into('<qQ',raw,tag_offset(raw,old),new,value)
        struct.pack_into('<IIQQQQIIQQ',raw,SECTIONS+8*64,0,9,2,RELA,RELA,16,2,0,8,16)
        ns=namespace(libgcc=raw)
        with self.assertRaisesRegex(ValueError,'finite zero-addend'):ns.constructors('libgcc',records(ns))

    def test_no_relocation_duplicate_and_partial_overwrite_refuse(self):
        for variant in ('missing','duplicate','partial'):
            raw=image('libgcc')
            if variant=='missing':struct.pack_into('<Q',raw,tag_offset(raw,8)+8,0)
            elif variant=='duplicate':
                struct.pack_into('<QQq',raw,RELA+24,ARRAY,(1<<32)|1,0)
                struct.pack_into('<Q',raw,tag_offset(raw,8)+8,48)
                struct.pack_into('<Q',raw,SECTIONS+8*64+32,48)
            else:
                # The entire store remains in its RW LOAD, but covers only
                # four bytes of the constructor slot; no stale owner refusal.
                struct.pack_into('<QQq',raw,RELA,ARRAY+4,(1<<32)|1,0)
            ns=namespace(libgcc=raw)
            with self.subTest(variant=variant),self.assertRaisesRegex(ValueError,'unique whole actual constructor'):
                ns.constructors('libgcc',records(ns))

    def test_relative_fast_path_cannot_relabel_global_record(self):
        raw=image('libgcc');at=tag_offset(raw,0)
        struct.pack_into('<qQqQ',raw,at,0x6ffffff9,1,0,0)
        length=at-DYNAMIC+32;struct.pack_into('<QQ',raw,64+3*56+32,length,length)
        ns=namespace(libgcc=raw)
        with self.assertRaisesRegex(ValueError,'prefix contains only symbol-zero'):records(ns)

    def test_existing_relative_and_hidden_paths_stay_exact(self):
        for variant in ('relative','hidden'):
            raw=image('libgcc',definitions=[(NAME,0x12,2,7,CODE,32)])
            if variant=='relative':struct.pack_into('<QQq',raw,RELA,ARRAY,8,CODE)
            ns=namespace(libgcc=raw);item=ns.constructors('libgcc',records(ns))['init_array'][0]
            self.assertEqual(item['resolved_relative'],CODE);self.assertNotIn('binding_proof',item)

    def test_constructor_array_bound_and_preinit_are_preserved(self):
        raw=image('libgcc');struct.pack_into('<Q',raw,tag_offset(raw,27)+8,520)
        ns=namespace(libgcc=raw)
        with self.assertRaisesRegex(ValueError,'unchanged bounded'):ns.constructors('libgcc',records(ns))
        raw=image('libgcc')
        struct.pack_into('<q',raw,tag_offset(raw,25),32);struct.pack_into('<q',raw,tag_offset(raw,27),33)
        ns=namespace(libgcc=raw)
        with self.assertRaisesRegex(ValueError,'no dependency-owned main preinit'):ns.constructors('libgcc',records(ns))


class ActualLookupTables(unittest.TestCase):
    def check(self,raw):
        ns=namespace(libgcc=raw)
        return ns.constructors('libgcc',records(ns))['init_array'][0]

    def test_sysv_lookup_positive(self):
        item=self.check(image('libgcc',hash_kind='sysv'))
        self.assertEqual(item['binding_proof']['lookup'],dict(kind='sysv',hash=C.elf_hash(NAME.encode()),symbol=1))
        self.assertEqual(item['resolved_relative'],CODE)

    def test_gnu_bloom_empty_bucket_chain_and_hash_refuse_at_lookup(self):
        for variant in ('bloom','bucket','hash','termination'):
            raw=image('libgcc')
            if variant=='bloom':struct.pack_into('<Q',raw,HASH+16,0)
            elif variant=='bucket':struct.pack_into('<I',raw,HASH+24,0)
            elif variant=='hash':struct.pack_into('<I',raw,HASH+28,(C.gnu_hash(NAME.encode())^2)|1)
            else:struct.pack_into('<I',raw,HASH+28,C.gnu_hash(NAME.encode())&~1)
            with self.subTest(variant=variant),self.assertRaisesRegex(ValueError,
                'GNU hash bloom|selected bucket|exact unique defined symbol|terminated in actual dynsym'):
                self.check(raw)

    def test_sysv_cycle_wrong_bucket_and_population_refuse(self):
        for variant in ('cycle','bucket','population'):
            raw=image('libgcc',hash_kind='sysv')
            if variant=='cycle':struct.pack_into('<I',raw,HASH+16,1)
            elif variant=='bucket':struct.pack_into('<I',raw,HASH+8,0)
            else:struct.pack_into('<I',raw,HASH+4,3)
            with self.subTest(variant=variant),self.assertRaisesRegex(ValueError,
                'acyclic SysV|exact unique defined symbol|whole bounded SysV'):
                self.check(raw)

    def test_section_offset_copy_cannot_replace_actual_loader_table(self):
        raw=image('libgcc');size=struct.unpack_from('<Q',raw,SECTIONS+3*64+32)[0]
        raw[0x2800:0x2800+size]=raw[HASH:HASH+size]
        struct.pack_into('<Q',raw,SECTIONS+3*64+24,0x2800)
        with self.assertRaisesRegex(R.Refused,'table file offset/LOAD owner'):self.check(raw)

    def test_version_missing_unversioned_and_unknown_index_refuse(self):
        for version in (0,1,2):
            with self.subTest(version=version),self.assertRaisesRegex(ValueError,
                'exact strong defined explicit|every symbol version'):
                self.check(image('libgcc',version=version))
        raw=image('libgcc');struct.pack_into('<qQ',raw,tag_offset(raw,0x6ffffff0),30,0)
        with self.assertRaisesRegex(ValueError,'actual DT_VERSYM'):self.check(raw)

    def test_version_hash_and_definition_index_must_really_join(self):
        raw=image('libgcc');struct.pack_into('<I',raw,VERDEF+28+8,0)
        with self.assertRaisesRegex(ValueError,'actual version-name ELF hash'):self.check(raw)
        raw=image('libgcc');struct.pack_into('<H',raw,VERDEF+28+4,13)
        with self.assertRaisesRegex(ValueError,'every symbol version'):self.check(raw)

    def test_zero_name_hash_cannot_turn_explicit_version_into_fallback(self):
        # Five '<' bytes followed by two '@' bytes have the ELF hash zero.
        # Both the string and VERDEF hash are rebuilt, so this reaches the
        # explicit-version guard, not a stale-name/hash mismatch.
        with self.assertRaisesRegex(ValueError,'exact strong defined explicit'):
            self.check(image('libgcc',global_version_label='<<<<<@@'))

    def test_weak_version_cannot_be_promoted_to_strong(self):
        with self.assertRaisesRegex(ValueError,'exact strong defined explicit'):
            self.check(image('libgcc',verdef_flags=2))

    def test_version_definition_requirement_index_collision_refuses(self):
        with self.assertRaisesRegex(ValueError,'unique actual version requirement identity'):
            self.check(image('libgcc',required_index=12))
        self.assertEqual(self.check(image('libgcc',required_index=13))['resolved_relative'],CODE)

    def test_version_requirement_cannot_reference_absent_dependency(self):
        raw=image('libgcc',required_index=13)
        name_offset=struct.unpack_from('<I',raw,VERDEF+48)[0]
        struct.pack_into('<I',raw,VERNEED+4,name_offset)
        with self.assertRaisesRegex(ValueError,'VERNEED actual dependency'):self.check(raw)

    def test_version_count_chain_and_auxiliary_ownership_refuse(self):
        for variant in ('count','backstep','aux','last-next'):
            raw=image('libgcc')
            if variant=='count':struct.pack_into('<Q',raw,tag_offset(raw,0x6ffffffd)+8,3)
            elif variant=='backstep':struct.pack_into('<I',raw,VERDEF+16,1)
            elif variant=='aux':struct.pack_into('<I',raw,VERDEF+12,0)
            else:struct.pack_into('<I',raw,VERDEF+52,8)
            with self.subTest(variant=variant),self.assertRaisesRegex(ValueError,
                'count agree|forward exact count|canonical bounded VERDEF|auxiliary chain'):
                self.check(raw)

    def test_version_section_link_and_count_are_exact(self):
        for offset,value in ((SECTIONS+4*64+40,1),(SECTIONS+5*64+44,1)):
            raw=image('libgcc');struct.pack_into('<I',raw,offset,value)
            with self.subTest(offset=offset),self.assertRaisesRegex(ValueError,'linked section|count agree'):
                self.check(raw)

    def test_new_facts_are_bound_to_each_actual_program_and_bootstrap(self):
        ns=namespace();raw=ns.objects['libgcc']['elf'].raw
        first=P.library_facts_v2(raw,'libgcc',R,D,ns)
        changed=image('bootstrap');changed[CODE+64]=0x90
        second=P.library_facts_v2(raw,'libgcc',R,D,namespace(bootstrap=changed))
        self.assertNotEqual(P.sha(P.canonical(first)),P.sha(P.canonical(second)))
        altered=image('libgcc');altered[CODE+64]=0x90
        with self.assertRaisesRegex(ValueError,'actual namespace dependency bytes'):
            P.library_facts_v2(bytes(altered),'libgcc',R,D,ns)


class CompleteForeignPopulations(unittest.TestCase):
    def test_every_dynamic_object_has_complete_hash_and_version_population(self):
        ns=namespace()
        self.assertEqual(set(ns.populations),{'bootstrap','loader','libc','libgcc'})
        for role in ns.populations:
            self.assertEqual(ns.populations[role],dict(symbols=2,hash_counts={'gnu':2},selected_hash='gnu',
                versioning=dict(present=True,entries=2,definitions=2,requirements=0)))
        proof=ns.constructors('libgcc',records(ns))['init_array'][0]['binding_proof']
        self.assertEqual(proof['populations'],ns.populations)

    def test_foreign_gnu_export_cannot_hide_by_truncating_dynsym_section(self):
        for role in ('bootstrap','loader','libc'):
            raw=image(role,definitions=[(NAME,0x12,0,7,CODE,32)])
            actual_tables=bytes(raw[STR:DYNAMIC])
            struct.pack_into('<Q',raw,SECTIONS+2*64+32,24)
            self.assertEqual(bytes(raw[STR:DYNAMIC]),actual_tables)
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'complete loader-visible symbol population'):
                namespace(**{role:raw})

    def test_foreign_sysv_export_cannot_hide_by_truncating_dynsym_section(self):
        for role in ('bootstrap','loader','libc'):
            raw=image(role,definitions=[(NAME,0x12,0,7,CODE,32)],hash_kind='sysv')
            actual_tables=bytes(raw[STR:DYNAMIC])
            struct.pack_into('<Q',raw,SECTIONS+2*64+32,24)
            self.assertEqual(bytes(raw[STR:DYNAMIC]),actual_tables)
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'complete loader-visible symbol population'):
                namespace(**{role:raw})

    def test_coherent_section_truncation_cannot_hide_actual_gnu_bucket_index(self):
        for role in ('bootstrap','loader','libc'):
            raw=image(role,definitions=[(NAME,0x12,0,7,CODE,32)])
            actual_tables=bytes(raw[STR:DYNAMIC])
            # Claims agree on a null-only table, but the actual loader bucket
            # still reaches symbol1 and its unchanged complete chain/version.
            struct.pack_into('<Q',raw,SECTIONS+2*64+32,24)
            struct.pack_into('<Q',raw,SECTIONS+3*64+32,28)
            struct.pack_into('<Q',raw,SECTIONS+4*64+32,2)
            self.assertEqual(bytes(raw[STR:DYNAMIC]),actual_tables)
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'complete loader-visible symbol population'):
                namespace(**{role:raw})

    def test_foreign_version_population_is_checked_for_both_hash_forms(self):
        for role in ('bootstrap','loader','libc'):
            for kind in ('gnu','sysv'):
                raw=image(role,hash_kind=kind)
                original=bytes(raw[STR:DYNAMIC])
                struct.pack_into('<Q',raw,SECTIONS+4*64+32,2)
                self.assertEqual(bytes(raw[STR:DYNAMIC]),original)
                with self.subTest(role=role,kind=kind),self.assertRaisesRegex(ValueError,'whole actual VERSYM population'):
                    namespace(**{role:raw})

    def test_secondary_sysv_population_cannot_contradict_gnu(self):
        raw=image('loader')
        # A genuine second LOAD-backed table claims only symbol0. GNU still
        # reaches symbol1. No version, symbol, or GNU-chain bytes are damaged.
        struct.pack_into('<IIII',raw,VERNEED,1,1,0,0)
        struct.pack_into('<IIQQQQIIQQ',raw,SECTIONS+6*64,0,5,2,VERNEED,VERNEED,16,2,0,4,4)
        at=tag_offset(raw,0);struct.pack_into('<qQqQ',raw,at,4,VERNEED,0,0)
        length=at-DYNAMIC+32;struct.pack_into('<QQ',raw,64+3*56+32,length,length)
        with self.assertRaisesRegex(ValueError,'complete loader-visible symbol population'):
            namespace(loader=raw)
        # Repair the complete actual SysV table; both views now agree.
        struct.pack_into('<IIIII',raw,VERNEED,1,2,1,0,0)
        struct.pack_into('<Q',raw,SECTIONS+6*64+32,20)
        ns=namespace(loader=raw)
        self.assertEqual(ns.populations['loader']['hash_counts'],{'gnu':2,'sysv':2})
        self.assertEqual(ns.populations['loader']['selected_hash'],'gnu')

    def test_foreign_unterminated_hash_chain_refuses_before_uniqueness(self):
        for role in ('bootstrap','loader','libc'):
            raw=image(role)
            struct.pack_into('<I',raw,HASH+28,C.gnu_hash((role+'_function').encode())&~1)
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'complete loader-visible symbol population'):
                namespace(**{role:raw})

    def test_coherently_owned_zero_function_address_still_refuses(self):
        raw=image('libgcc')
        # VA0 is now truly backed by an RX LOAD and the positive AX code
        # section. GNU hash/version/RELA/name/size remain exact and nonzero.
        struct.pack_into('<I',raw,64+4,5)
        struct.pack_into('<QQ',raw,SECTIONS+7*64+16,0,0)
        struct.pack_into('<Q',raw,SYM+24+8,0)
        ns=namespace(libgcc=raw)
        self.assertEqual(ns.populations['libgcc']['symbols'],2)
        with self.assertRaisesRegex(ValueError,'positive bounded ordinary constructor address'):
            ns.constructors('libgcc',records(ns))
        # The old hidden-symbol path retains its positive-address discipline.
        raw[SYM+24+5]=2
        ns=namespace(libgcc=raw)
        with self.assertRaisesRegex(ValueError,'constructor relative address bound'):
            ns.constructors('libgcc',records(ns))


def canonical_main(*, populated=False):
    """Actual emitter grammar, including sectionless dynamic metadata.

    The original fixture/helper is unchanged. This complete ELF adds the
    interpreter, writes exact adjacent carrier metadata, removes unused dynamic
    section claims and ends the R-only LOAD at the dynamic terminator.
    """
    raw=image('main')
    interpreter=b'/platform/loader0\0';strings=b'\0/private/bootstrap.so\0'
    interp=STR;strtab=interp+len(interpreter);symtab=(strtab+len(strings)+7)&~7
    count=2 if populated else 1
    hash_at=symtab+24*count
    hash_raw=struct.pack('<IIII',1,1,0,0) if not populated else struct.pack('<IIIII',1,2,1,0,0)
    dynamic=(hash_at+len(hash_raw)+7)&~7
    raw[interp:dynamic+112]=bytes(dynamic+112-interp)
    raw[interp:interp+len(interpreter)]=interpreter;raw[strtab:strtab+len(strings)]=strings
    if populated:struct.pack_into('<IBBHQQ',raw,symtab+24,1,0x12,0,7,CODE,32)
    raw[hash_at:hash_at+len(hash_raw)]=hash_raw
    rows=[(1,1),(5,strtab),(10,len(strings)),(6,symtab),(11,24),(4,hash_at),(0,0)]
    for i,row in enumerate(rows):struct.pack_into('<QQ',raw,dynamic+16*i,*row)
    struct.pack_into('<H',raw,56,6)
    struct.pack_into('<IIQQQQQQ',raw,64+3*56,2,4,dynamic,dynamic,dynamic,112,112,8)
    struct.pack_into('<IIQQQQQQ',raw,64+5*56,3,4,interp,interp,interp,len(interpreter),len(interpreter),1)
    struct.pack_into('<QQ',raw,64+32,dynamic+112,dynamic+112)
    raw[SECTIONS:SECTIONS+10*64]=bytes(10*64)
    struct.pack_into('<IIQQQQIIQQ',raw,SECTIONS+7*64,0,1,6,CODE,CODE,0x1000,0,0,16,0)
    return raw,dict(interp=interp,strtab=strtab,symtab=symtab,hash=hash_at,dynamic=dynamic,end=dynamic+112)


def canonical_main_inputs(raw):
    original=bytearray(raw)
    for index in (3,5):struct.pack_into('<I',original,64+56*index,0)
    files={role:dict(path='/platform/'+role,sha256='11'*32) for role in P.ROLES}
    files['loader']['path']='/platform/loader0'
    contract=dict(files=files);contract_sha='22'*32
    policy=dict(bootstrap='/private/bootstrap.so',interpreter='/platform/loader0',contract=contract_sha,
                dependencies=sorted((pin['path'],pin['sha256']) for pin in files.values()))
    item=dict(main=dict(product={'candidate.elf':bytes(raw)},original=bytes(original),policy=policy),
              bootstrap_pin=dict(path='/private/bootstrap.so'),linked=dict(notes=[],
              needed=['libgcc_s.so.1','libc.so.6'],rpath=None,runpath=None))
    return item,contract,contract_sha


class CanonicalEmptyMain(unittest.TestCase):
    def check(self, raw):
        ns=namespace(main=raw)
        return ns,ns.constructors('libgcc',records(ns))['init_array'][0]['binding_proof']

    def test_canonical_null_symbol_sysv_actual_bytes_join_namespace(self):
        raw,layout=canonical_main();ns,proof=self.check(raw)
        self.assertEqual(ns.main_namespace['profile'],'canonical-null-sysv-main-v1')
        self.assertEqual(ns.main_namespace['symbols'],1)
        self.assertEqual(ns.main_namespace['needed'],['/private/bootstrap.so'])
        self.assertEqual(ns.main_namespace['null_symbol_sha256'],C.sha(bytes(24)))
        self.assertEqual(ns.main_namespace['sysv_sha256'],C.sha(struct.pack('<IIII',1,1,0,0)))
        self.assertEqual(ns.objects['main']['symbols'],[])
        self.assertEqual(proof['main_namespace'],ns.main_namespace)
        self.assertEqual(proof['target_relative'],CODE)
        self.assertEqual(ns.main_namespace['metadata'],dict(file_offset=STR,address=STR,
            bytes=layout['end']-STR,sha256=C.sha(bytes(raw[STR:layout['end']]))))

    def test_old_no_symbol_class_and_old_controls_keep_the_same_proof(self):
        ns=namespace();proof=ns.constructors('libgcc',records(ns))['init_array'][0]['binding_proof']
        self.assertEqual(ns.main_namespace,dict(profile='main-no-symbol-table-v1',
            needed=['/private/bootstrap.so'],symbols=0))
        self.assertNotIn('main_namespace',proof)

    def test_actual_profile2_main_facts_rederive_new_class_and_default_stays_strict(self):
        raw,_=canonical_main();item,contract,digest=canonical_main_inputs(raw)
        self.check(raw)
        with self.assertRaisesRegex(ValueError,'main carrier has only readonly strings'):
            P.main_facts(item,contract,digest,R,D)
        self.assertEqual(P.main_facts(item,contract,digest,R,D,dependency=C),
            dict(entry=CODE,entry_bytes=bytes(raw[CODE:CODE+15]).hex()))
        changed,layout=canonical_main();changed[layout['symtab']+23]=1
        item,contract,digest=canonical_main_inputs(changed)
        with self.assertRaisesRegex(ValueError,'entire null symbol'):
            P.main_facts(item,contract,digest,R,D,dependency=C)

    def test_every_nonzero_null_symbol_byte_refuses(self):
        for offset in range(24):
            raw,layout=canonical_main();raw[layout['symtab']+offset]=1
            with self.subTest(offset=offset),self.assertRaisesRegex(ValueError,'entire null symbol'):
                self.check(raw)

    def test_sysv_header_bucket_chain_and_coherent_export_population_refuse(self):
        for offset,value in ((0,0),(0,2),(4,0),(4,2),(8,1),(12,1)):
            raw,layout=canonical_main();struct.pack_into('<I',raw,layout['hash']+offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaisesRegex(ValueError,'entire SysV table'):
                self.check(raw)
        raw,_=canonical_main(populated=True)
        with self.assertRaisesRegex(ValueError,'entire SysV table'):self.check(raw)

    def test_dynamic_order_terminator_width_extra_tag_and_padding_refuse(self):
        for variant in ('order','width','extra','tail','needed','padding'):
            raw,layout=canonical_main();dynamic=layout['dynamic']
            if variant=='order':
                a=bytes(raw[dynamic+16:dynamic+32]);raw[dynamic+16:dynamic+32]=raw[dynamic+32:dynamic+48];raw[dynamic+32:dynamic+48]=a
            elif variant=='width':struct.pack_into('<Q',raw,dynamic+4*16+8,16)
            elif variant=='extra':struct.pack_into('<Q',raw,dynamic+5*16,0x6ffffef5)
            elif variant=='tail':
                struct.pack_into('<QQ',raw,64+3*56+32,128,128)
                struct.pack_into('<QQ',raw,64+32,layout['end']+16,layout['end']+16)
                raw[layout['end']:layout['end']+16]=bytes(16)
            elif variant=='needed':struct.pack_into('<Q',raw,dynamic+8,2)
            else:
                end=layout['strtab']+len(b'\0/private/bootstrap.so\0')
                self.assertLess(end,layout['symtab']);raw[end]=1
            with self.subTest(variant=variant),self.assertRaisesRegex(ValueError,
                'canonical empty main|main has no exported'):
                self.check(raw)

    def test_whole_null_and_hash_extents_cannot_use_cross_owner_prefix(self):
        for tag_index,size in ((3,24),(5,16)):
            raw,layout=canonical_main()
            struct.pack_into('<QQ',raw,64+32,CODE,CODE)
            pointer=CODE-size//2
            struct.pack_into('<Q',raw,layout['dynamic']+tag_index*16+8,pointer)
            raw[pointer:CODE]=bytes(CODE-pointer)
            with self.subTest(size=size),self.assertRaisesRegex(R.Refused,'one file-backed virtual owner'):
                self.check(raw)

    def test_readonly_carrier_and_no_other_load_file_alias_are_required(self):
        for permissions in (5,6):
            raw,_=canonical_main();struct.pack_into('<I',raw,64+4,permissions)
            with self.subTest(permissions=permissions),self.assertRaisesRegex(ValueError,'one readonly LOAD owner'):
                self.check(raw)
        for filesize in (0x1000,0x100):
            raw,_=canonical_main();struct.pack_into('<Q',raw,64+2*56+8,0)
            struct.pack_into('<Q',raw,64+2*56+32,filesize)
            # The shorter declared file prefix still maps its complete file
            # page; it must not hide an alias to later metadata in that page.
            with self.subTest(filesize=filesize),self.assertRaisesRegex(ValueError,'other LOAD file alias'):
                self.check(raw)

    def test_dynamic_section_claim_and_static_section_alias_cannot_hide_exports(self):
        for kind in (5,6,11,0x6ffffff6):
            raw,layout=canonical_main()
            struct.pack_into('<IIQQQQIIQQ',raw,SECTIONS+2*64,0,kind,2,
                layout['symtab'],layout['symtab'],24,0,0,8,24)
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'only static section classes'):
                self.check(raw)
        raw,layout=canonical_main()
        struct.pack_into('<IIQQQQIIQQ',raw,SECTIONS+2*64,0,1,2,
            layout['symtab'],layout['symtab'],24,0,0,8,0)
        with self.assertRaisesRegex(ValueError,'section alias'):self.check(raw)

    def test_zero_copies_at_wrong_pointers_do_not_replace_canonical_layout(self):
        raw,layout=canonical_main()
        # The copied full null symbol is still genuinely RO/LOAD-backed; only
        # its canonical adjacency/ordering has changed, so no prefix exemption.
        struct.pack_into('<Q',raw,layout['dynamic']+3*16+8,0x700)
        raw[0x700:0x718]=bytes(24)
        with self.assertRaisesRegex(ValueError,'ordered disjoint metadata layout'):self.check(raw)


if __name__ == '__main__':
    unittest.main()
