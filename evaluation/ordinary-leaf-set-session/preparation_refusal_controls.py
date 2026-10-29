#!/usr/bin/env python3
"""Fabricated format/custody controls only; never launch the application or fixture."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
import os
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

path=Path(__file__).resolve().with_name('preparation_refusal.py')
spec=importlib.util.spec_from_file_location('_preparation_refusal_controls',path)
assert spec and spec.loader
P=importlib.util.module_from_spec(spec); spec.loader.exec_module(P)


def fixture():
    """Small, independently laid out ELF container; never a loaded/native owner."""
    data=bytearray(0x1100)
    struct.pack_into('<16sHHIQQQIHHHHHH',data,0,b'\x7fELF\x02\x01\x01'+bytes(9),3,62,1,0,64,0x300,0,64,56,3,64,4,2)
    struct.pack_into('<IIQQQQQQ',data,64,1,5,0x1000,0x1000,0x1000,4,4,4096)
    struct.pack_into('<IIQQQQQQ',data,120,2,6,0x200,0x200,0x200,32,32,8)
    struct.pack_into('<IIQQQQQQ',data,176,0x6474e551,6,0,0,0,0,0,16)
    struct.pack_into('<qQqQ',data,0x200,30,8,0,0)
    struct.pack_into('<IIQQQQIIQQ',data,0x340,0,1,6,0x1000,0x1000,4,0,0,1,0)
    names=b'\0leaf_preparation_refusal\0'; data[0x240:0x240+len(names)]=names
    struct.pack_into('<IIQQQQIIQQ',data,0x380,0,3,0,0,0x240,len(names),0,0,1,0)
    struct.pack_into('<IIQQQQIIQQ',data,0x3c0,0,2,0,0,0x280,48,2,2,8,24)
    struct.pack_into('<IBBHQQ',data,0x298,1,2,0,1,0x1000,4)
    data[0x1000:0x1004]=bytes.fromhex('4889f0c3')
    return bytes(data)


class Controls(unittest.TestCase):
    def test_complete_four_byte_elf_and_identity_refusals(self):
        good=fixture(); geometry=P.elf_geometry(good)
        self.assertEqual((geometry['elf_va'],geometry['extent'],geometry['file_offset']),(4096,4,4096))
        self.assertEqual((geometry['heads'],geometry['returns'],geometry['bytes_hex']),([0,3],[3],'4889f0c3'))
        # Actual parser seams: full extent, binding, type, duplicate name, section,
        # RX owner, offset correspondence, bytes, constructors, NOW and relocation.
        for offset,fmt,value in (
            (0x2a8,'Q',3),(0x2a8,'Q',5),(0x29c,'B',18),(0x29c,'B',1),
            (0x280,'I',1),(0x29e,'H',0),(0x348,'Q',7),(68,'I',7),
            (72,'Q',0x1001),(0x1000,'B',0x90),(0x200,'q',12),
            (0x208,'Q',0),(0x344,'I',4)):
            bad=bytearray(good);struct.pack_into('<'+fmt,bad,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises((AssertionError,struct.error)):
                P.elf_geometry(bytes(bad))
        for cut in (0,63,0x1003):
            with self.assertRaises((AssertionError,struct.error)):P.elf_geometry(good[:cut])

    def test_raw_wait_core_bit_and_every_acceptance_join(self):
        sha='1'*64; cpus=[2,7]
        for raw in (6,134):
            record=P.raw_wait(101,101,raw,99,cpus,sha)
            P.check_wait(record,b'',P.EXPECTED,request_sha=sha,cpus=cpus)
            self.assertEqual(record['core_dump'],raw==134)
            for key,value in (('child_pid',102),('waited_pid',102),('parent_pid',101),
                ('child_pid',True),('raw_status',0),('raw_status',11),('raw_status',262),
                ('signaled',False),('signal',11),('core_dump',not record['core_dump']),
                ('core_dump',int(record['core_dump'])),('normal_reaps',0),('normal_reaps',True),
                ('absence_proof','UNPROVED'),('cpus',[7,2]),('request_sha256','2'*64)):
                bad=copy.deepcopy(record);bad[key]=value
                with self.subTest(key=key,value=value),self.assertRaises(AssertionError):
                    P.check_wait(bad,b'',P.EXPECTED,request_sha=sha,cpus=cpus)
            for bad in (dict(record,extra=0),{k:v for k,v in record.items() if k!='core_dump'}):
                with self.assertRaises(AssertionError):P.check_wait(bad,b'',P.EXPECTED,request_sha=sha,cpus=cpus)
            for out,err in ((b'READY\n',P.EXPECTED),(b'',b''),(b'',P.EXPECTED[:-1]),(b'',P.EXPECTED+b'x')):
                with self.assertRaises(AssertionError):P.check_wait(record,out,err,request_sha=sha,cpus=cpus)
        for raw in (0,256,11,9,19<<8|127,65535):
            with self.assertRaises(AssertionError):
                P.check_wait(P.raw_wait(101,101,raw,99,cpus,sha),b'',P.EXPECTED,request_sha=sha,cpus=cpus)

    def test_first_pins_and_regular_file_capture_custody(self):
        # Temporary paths use the inherited workspace TMPDIR, never /tmp literals.
        with tempfile.TemporaryDirectory() as name:
            d=Path(name); p=d/'source';p.write_bytes(b'original')
            pins={str(p):P.pin(P.read(p))};P.unchanged(pins)
            p.write_bytes(b'changed!')
            with self.assertRaises(AssertionError):P.unchanged(pins)
            self.assertEqual(pins[str(p)],P.pin(b'original'))
            ids={str(p):P.artifact_identity(p)};P.unchanged_artifacts(ids)
            replacement=d/'replacement';replacement.write_bytes(b'changed!');replacement.replace(p)
            with self.assertRaises(AssertionError):P.unchanged_artifacts(ids)
            alias=d/'alias';alias.symlink_to(p)
            with self.assertRaises(OSError):P.read(alias)
            for q in (p,alias):
                with self.assertRaises(OSError):P.capture(q)
            q=d/'capture';fd,ident=P.capture(q)
            self.assertEqual(ident,(q.stat().st_dev,q.stat().st_ino));os.close(fd)
            self.assertEqual(P.read(q),b'')
            os.link(q,d/'second-link')
            with self.assertRaises(AssertionError):P.artifact_identity(q)


    def test_shared_cargo_product_and_independent_executable_copy(self):
        native_path=P.ROOT/P.NATIVE
        N=P.load_checked('_preparation_native_controls',native_path,{str(native_path):P.pin(P.read(native_path))})
        with tempfile.TemporaryDirectory() as name:
            root=Path(name); release=root/'target/release';release.mkdir(parents=True)
            source=release/'ordinary-interval';source.write_bytes(b'fabricated executable bytes');source.chmod(0o755)
            (release/'deps').mkdir();os.link(source,release/'deps/ordinary_interval-1234')
            record=dict(reason='compiler-artifact',manifest_path=str(root/'tools/rapid-profiler/Cargo.toml'),
                target=dict(name='ordinary-interval',src_path=str(root/'tools/rapid-profiler/ordinary-interval/main.rs'),
                            kind=['bin'],crate_types=['bin']),
                profile=dict(opt_level='3',debuginfo=0,test=False,debug_assertions=True,overflow_checks=True),
                fresh=False,executable=str(source))
            def encoded(rows):
                return b''.join((json.dumps(row)+'\n').encode() for row in rows+[dict(reason='build-finished',success=True)])
            with mock.patch.object(N,'ROOT',root):
                for fresh in (False,True):
                    good=copy.deepcopy(record);good['fresh']=fresh
                    path,actual=P.product(N,encoded([good]));self.assertEqual(path,source);self.assertEqual(actual,good)
                for location,key,value in ((None,'fresh',0),(None,'fresh',1),(None,'fresh','false'),
                    ('profile','opt_level','2'),('profile','debuginfo',False),('profile','test',True),
                    ('profile','debug_assertions',False),('profile','overflow_checks',False),
                    ('profile','debug_assertions',1),('profile','overflow_checks',1),
                    ('target','name','different'),('target','kind',['lib']),('target','crate_types',['lib']),
                    ('target','src_path',str(root/'other.rs')),(None,'manifest_path',str(root/'other.toml')),
                    (None,'executable',str(source.parent/'deps/ordinary_interval-1234'))):
                    bad=copy.deepcopy(record);(bad if location is None else bad[location])[key]=value
                    with self.subTest(location=location,key=key,value=value),self.assertRaises(AssertionError):
                        P.product(N,encoded([bad]))
                for data in (encoded([record,record]),encoded([record]).replace(b'"success": true',b'"success": false')):
                    with self.assertRaises(AssertionError):P.product(N,data)
            expected=P.pin(P.read(source));destination=root/'retained-app'
            exact=P.retain_executable(source,destination,expected)
            self.assertEqual(source.stat().st_nlink,2);self.assertEqual(destination.stat().st_nlink,1)
            self.assertNotEqual(exact[:2],list(P.identity(source.stat()))[:2])
            self.assertEqual(destination.stat().st_mode & 0o777,0o500)
            self.assertEqual(P.read(source),P.read(destination));self.assertEqual(P.pin(P.read(source)),expected)
            pins={str(source):expected,str(destination):expected};ids={str(destination):exact}
            P.unchanged(pins);P.unchanged_artifacts(ids)
            with self.assertRaises(OSError):P.retain_executable(source,destination,expected)
            destination.chmod(0o700)
            with self.assertRaises(AssertionError):P.unchanged_artifacts(ids)
            destination.write_bytes(b'changed')
            with self.assertRaises(AssertionError):P.unchanged(pins)
            self.assertEqual(pins[str(source)],expected);self.assertEqual(ids[str(destination)],exact)
            source.write_bytes(b'changed product')
            with self.assertRaises(AssertionError):P.retain_executable(source,root/'bad-copy',expected)
            self.assertFalse((root/'bad-copy').exists())
            alias=root/'symlink';alias.symlink_to(source)
            with self.assertRaises(AssertionError):P.retain_executable(alias,root/'bad-alias',P.pin(b'changed product'))


if __name__=='__main__':unittest.main()
