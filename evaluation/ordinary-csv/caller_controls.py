"""Finite synthetic disassembly controls; no binary or subject execution."""
import importlib.util
from pathlib import Path
import sys
p=Path(sys.argv[1]) if len(sys.argv)==2 else Path(__file__).with_name('reproduce.py')
spec=importlib.util.spec_from_file_location('csv_reproducer_source',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
text='''0000000000001000 <liteinst_csv_call_and_store>:
  1000:\t53\tpush rbx
  1001:\t48 89 cb\tmov rbx,rcx
  1004:\t48 89 f8\tmov rax,rdi
  1007:\t48 89 f7\tmov rdi,rsi
  100a:\t48 89 d6\tmov rsi,rdx
  100d:\tff d0\tcall rax
  100f:\t48 89 03\tmov QWORD PTR [rbx],rax
  1012:\t5b\tpop rbx
  1013:\tc3\tret
'''
assert m.caller_geometry(text)==dict(elf_va=4096,length=20,continuation_offset=15,call_bytes='ffd0',store_bytes='488903')
bad=[text.replace('call rax','jmp rax'),text.replace('call rax','call 0x2000'),
 text.replace('mov QWORD PTR [rbx],rax','mov QWORD PTR [rbx],rcx'),
 text.replace('100f:', '1010:'),text.replace('  1013:\tc3\tret\n',''),
 text.replace('mov rax,rdi','call rax'),text.replace('<liteinst_csv_call_and_store>','<other>'),
 text.replace('mov rax,rdi','ret 0x8'),text.replace('\tc3\tret\n','\tc3\tret 0x8\n')]
for i,case in enumerate(bad):
 try:m.caller_geometry(case)
 except AssertionError:continue
 raise AssertionError(('accepted invalid emitted shape',i))
print('caller_geometry: 1 valid shape and 9 required refusals passed; no native execution')
