"""Fixed warm publication-overlap stimulus; no native or effect acceptance here."""
import importlib.util,sys,types
from pathlib import Path
from page_selected import need
sys.dont_write_bytecode=True
_spec=importlib.util.spec_from_file_location('cwo_old_lease',Path(__file__).resolve().parent.parent/'tf_same_page/check.py')
old=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(old)
MAIN,BODY,GUARD,DATA,WORD=old.MAIN,old.BODY,old.GUARD,old.DATA,old.WORD


def program(case=5):
 need(type(case)is int and case==5,'only explicit warm-overlap case5')
 return [(BODY+32,3,'add_rax_rbx'),(BODY+35,4,'add_rax'),
         (BODY+39,3,'overlap'),(BODY+42,1,'nop'),(BODY+43,5,'jump_guard')]


def _literal_program(function):
 # Reuse the entire source-bound pure function. Only its literal program table
 # differs, in a separate globals dictionary; the old module is not modified.
 namespace=dict(function.__globals__);namespace['program']=program
 return types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)


_elf=_literal_program(old.elf)
_states=_literal_program(old.states)


def elf(data,interpreter,case,native_policy):
 need(type(case)is int and case==5,'fixed new overlap ELF identity')
 image=_elf(data,interpreter,case,native_policy)
 raw=bytes.fromhex(image['source_hex']);at=BODY-MAIN+32
 need(raw[at:at+11]==bytes.fromhex('4801d84883c00148890790'),
      'literal ADD;ADD;publication MOV;old NOP; no instruction substitution')
 return image


def states(image,cpuid=None):
 need(image['case']==5 and cpuid is None,'fixed overlap has no CPUID input')
 rows=_states(image,cpuid)
 need(len(rows)==2 and [x['pc']for x in rows]==[BODY+32,BODY+35]and
      rows[0]['next']==BODY+35 and rows[1]['next']==BODY+39 and
      all(x['before'][0][7]==x['after'][0][7]==WORD and x['after'][3]==0 for x in rows),
      'two actual retired ADDs, then refused MOV; no published word or synthetic retirement')
 return rows


memory=old.memory
literal=old.literal
# Gated acceptance belongs to the separate custody consumer: exactly one real
# committed transfer, then unchanged1205 overlap refusal and actual cleanup.
# The old case5 reader is never called with this two-event stimulus.
