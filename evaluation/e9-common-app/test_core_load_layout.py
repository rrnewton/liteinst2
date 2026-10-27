#!/usr/bin/env python3
"""Pure synthetic ELF geometry controls; no application or audit main."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

def module(name):
 p=Path(__file__).with_name(name+'.py');s=importlib.util.spec_from_file_location(name,p)
 m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
r,a=module('run_core_pairs'),module('audit_core_pairs')
LOADS=[(0,0x400000,0x8b0,0x8b0,4),(0x1000,0x401000,0xa51,0xa51,5),
       (0x2000,0x402000,0xe1c,0xe1c,4),(0x3e00,0x403e00,0x20358,0x20390,6)]
LOW,HIGH=(0x26000,0x10000,0x1000,0x1000,5),(0x27000,0x440000,0x1010,0x1080,4)
def elf(loads):
 b=bytearray((i*17^(i>>8))&255 for i in range(0x30000));b[:16]=b'\x7fELF\x02\x01\x01'+bytes(9)
 struct.pack_into('<HHIQQQIHHHHHH',b,16,2,62,1,0x401000,64,0,0,64,56,len(loads),0,0,0)
 for i,(off,va,fs,ms,flags) in enumerate(loads):struct.pack_into('<IIQQQQQQ',b,64+56*i,1,flags,off,va,va,fs,ms,4096)
 return bytes(b)

class LayoutControls(unittest.TestCase):
 def test_interleaved_full_bytes_bss_order_and_generated_count(self):
  for loads in ([LOW,LOADS[0],HIGH,*LOADS[1:]],[HIGH,*LOADS[:2],LOW,*LOADS[2:]],[*LOADS,HIGH,LOW]):
   b=elf(loads);plan,size=r.load_plan(elf(LOADS),b);actual,pages,base=a.image(b)
   self.assertEqual(plan,list(map(list,loads)));self.assertEqual(actual,loads)
   self.assertEqual(size,12288);self.assertEqual(len(pages),40)
   self.assertEqual(base,b[:0x24158]+bytes(0x25000-0x24158))
   self.assertEqual(pages[0x10000],(5,b[0x26000:0x27000]))
   self.assertEqual(pages[0x440000],(4,b[0x27000:0x28000]))
   self.assertEqual(pages[0x441000],(4,b[0x28000:0x28010]+bytes(4080)))
 def test_original_fields_membership_order_and_overlap_refuse(self):
  valid=[LOW,*LOADS,HIGH];bad=[]
  for i in range(1,5):
   bad.append(valid[:i]+valid[i+1:])
   for field in range(5):
    rows=list(valid);v=list(rows[i]);v[field]+=4096 if field in (0,1) else 1;rows[i]=tuple(v);bad.append(rows)
  bad += [[LOW,LOADS[1],LOADS[0],*LOADS[2:],HIGH],valid+[LOADS[3]],
          valid+[(0x27000,0x424000,4096,4096,4)],valid+[(0x27800,0x3ff800,0x801,0x801,5)],valid+[LOW]]
  original=elf(LOADS)
  for rows in bad:
   b=elf(rows)
   with self.subTest(rows=rows):
    with self.assertRaises(AssertionError):r.load_plan(original,b)
    with self.assertRaises(AssertionError):a.image(b)
  with self.assertRaises(AssertionError):a.image(elf([(0x26000,0x10000,1,1,6),*LOADS]))

if __name__=='__main__':
 if sys.flags.optimize:raise SystemExit('optimized Python is unsupported; assertions are required')
 unittest.main()
