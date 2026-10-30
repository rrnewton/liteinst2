#!/usr/bin/env python3
"""Additive complete-ELF RELRO controls; no build, subprocess or ELF execution."""
import hashlib
import struct
import unittest

import startup_bootstrap_controls as F

D=F.D
P=F.P.pkg


def zero_tail_fixture(start=0x1000):
    raw=F.dso_fixture()
    first,dynamic,ro,rx,stack,_=[list(struct.unpack_from('<IIQQQQQQ',raw,64+56*i)) for i in range(6)]
    first[5]=first[6]=0x1000
    owner=[1,6,start,start,start,0x1a00-start,0x2000-start,4096]
    relro=[0x6474e552,4,start,start,start,0x1a00-start,0x2000-start,1]
    headers=[first,owner,dynamic,ro,rx,stack,relro]
    struct.pack_into('<H',raw,56,len(headers))
    for i,p in enumerate(headers):struct.pack_into('<IIQQQQQQ',raw,64+56*i,*p)
    # These bytes are physically present but outside the owning LOAD's filesz.
    # The loader zeros the suffix; seeing zeros in the file is not our proof.
    raw[0x1a00:0x2000]=b'\xa5'*0x600
    return raw


OWNER=120
RELRO=400


class RelroFileZeroTail(unittest.TestCase):
    def inspect(self,raw):return D.inspect(bytes(raw),F.CATALOG,P)

    def test_old_complete_file_backed_class_has_identical_fact_shape(self):
        facts=self.inspect(F.dso_fixture())
        self.assertNotIn('relro_storage',facts)
        self.assertEqual(facts['relro_protected'],[0x1000,0x2000])
        self.assertEqual(facts['constructors']['init_array'][0]['resolved_relative'],0x3800)
        self.assertFalse(facts['execution_authorized']);self.assertFalse(facts['qualification_complete'])

    def test_full_inspect_authenticates_exact_file_prefix_and_load_zero_tail(self):
        raw=zero_tail_fixture();facts=self.inspect(raw);proof=facts['relro_storage']
        owner=[1,6,0x1000,0x1000,0x1000,0xa00,0x1000,4096]
        relro=[0x6474e552,4,0x1000,0x1000,0x1000,0xa00,0x1000,1]
        self.assertEqual(proof,dict(schema='LI2STARTUP-RELRO-LOAD-FILE-ZERO-TAIL-1',load_index=1,
            load=owner,relro=relro,
            file_prefix=dict(address=0x1000,file_offset=0x1000,bytes=0xa00,
                             sha256=hashlib.sha256(raw[0x1000:0x1a00]).hexdigest()),
            zero_fill=[0x1a00,0x2000],protected=[0x1000,0x2000],
            page_owner=dict(load_index=1,start=0x1000,end=0x2000,flags=6,file_end=0x2000,
                file_offset=0x1000,file_zero_tail=[0x1a00,0x2000],anonymous=None)))
        self.assertEqual(raw[0x1a00:0x2000],b'\xa5'*0x600)
        self.assertEqual(facts['relro_protected'],[0x1000,0x2000])
        self.assertEqual(facts['completion']['address'],0x800)
        self.assertEqual(facts['constructors']['init_array'][0]['resolved_relative'],0x3800)
        self.assertFalse(facts['platform_contract_accepted']);self.assertFalse(facts['execution_authorized'])
        self.assertFalse(facts['qualification_complete'])

    def test_unaligned_load_owns_every_rounded_protected_page(self):
        raw=zero_tail_fixture(0x1080);proof=self.inspect(raw)['relro_storage']
        self.assertEqual(proof['file_prefix'],dict(address=0x1080,file_offset=0x1080,bytes=0x980,
            sha256=hashlib.sha256(raw[0x1080:0x1a00]).hexdigest()))
        self.assertEqual(proof['zero_fill'],[0x1a00,0x2000])
        self.assertEqual(proof['protected'],[0x1000,0x2000])
        self.assertEqual((proof['page_owner']['start'],proof['page_owner']['end']),(0x1000,0x2000))

    def test_prefix_digest_binds_previously_unused_file_bytes(self):
        raw=zero_tail_fixture();first=self.inspect(raw)['relro_storage']
        raw[0x1100]^=1;second=self.inspect(raw)['relro_storage']
        self.assertNotEqual(first['file_prefix']['sha256'],second['file_prefix']['sha256'])
        self.assertEqual(second['file_prefix']['sha256'],hashlib.sha256(raw[0x1000:0x1a00]).hexdigest())
        self.assertEqual(first['zero_fill'],second['zero_fill'])

    def test_readonly_or_executable_memory_owner_refuses(self):
        for flags in (4,5):
            raw=zero_tail_fixture();struct.pack_into('<I',raw,OWNER+4,flags)
            with self.subTest(flags=flags),self.assertRaisesRegex(ValueError,'actual RW/non-executable LOAD'):
                self.inspect(raw)

    def test_wrong_file_offset_cannot_select_an_identical_copy(self):
        raw=zero_tail_fixture();raw.extend(raw[0x1000:0x1a00])
        self.assertEqual(raw[0x4000:0x4a00],raw[0x1000:0x1a00])
        struct.pack_into('<Q',raw,RELRO+8,0x4000)
        with self.assertRaisesRegex(ValueError,'exactly match whole LOAD offset/file/memory extent'):
            self.inspect(raw)

    def test_short_or_long_declared_prefix_cannot_replace_full_load_prefix(self):
        for size in (0x9f8,0xa08):
            raw=zero_tail_fixture();struct.pack_into('<Q',raw,RELRO+32,size)
            with self.subTest(size=size),self.assertRaisesRegex(ValueError,'exactly match whole LOAD offset/file/memory extent'):
                self.inspect(raw)

    def test_truncated_or_cross_owner_zero_suffix_refuses(self):
        for size,reason in ((0xf00,'exactly match whole LOAD offset/file/memory extent'),
                            (0x1008,'one whole memory owner')):
            raw=zero_tail_fixture();struct.pack_into('<Q',raw,RELRO+40,size)
            with self.subTest(size=size),self.assertRaisesRegex(ValueError,reason):self.inspect(raw)

    def test_missing_file_prefix_is_not_a_new_anonymous_relro_profile(self):
        raw=zero_tail_fixture();struct.pack_into('<Q',raw,RELRO+32,0)
        with self.assertRaisesRegex(ValueError,'nonempty file prefix and zero suffix'):self.inspect(raw)

    def test_complete_owner_without_a_protected_page_refuses(self):
        raw=zero_tail_fixture()
        for at in (OWNER,RELRO):struct.pack_into('<QQ',raw,at+32,0x980,0xa00)
        with self.assertRaisesRegex(ValueError,'nonempty protected pages in that LOAD owner'):self.inspect(raw)

    def test_completion_exclusion_remains_enforced_for_zero_tail_class(self):
        raw=zero_tail_fixture()
        struct.pack_into('<Q',raw,0x2020,0x1700);struct.pack_into('<Q',raw,0x2520,0x1700)
        struct.pack_into('<QQ',raw,0x30c0+16,0x1700,0x1700)
        with self.assertRaisesRegex(ValueError,'completion store remains writable after RELRO'):self.inspect(raw)

    def test_constructor_protection_and_relocation_owner_checks_remain_enforced(self):
        raw=zero_tail_fixture()
        struct.pack_into('<Q',raw,0x2300+9*16+8,0x900)
        struct.pack_into('<Q',raw,0x2418,0x900);struct.pack_into('<Q',raw,0x900,0x3800)
        with self.assertRaisesRegex(ValueError,'constructor array is actually page-protected by RELRO'):self.inspect(raw)
        raw=zero_tail_fixture();struct.pack_into('<Q',raw,0x2400,0x2a00)
        with self.assertRaisesRegex(ValueError,'dynamic relocation target must be writable non-executable LOAD'):
            self.inspect(raw)


if __name__=='__main__':
    unittest.main()
