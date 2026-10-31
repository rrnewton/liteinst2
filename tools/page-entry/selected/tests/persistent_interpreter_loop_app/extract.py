"""Extract both whole pinned interpreter pages without rewriting any byte."""
import hashlib,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
assert len(sys.argv)==3
original=Path(sys.argv[1]);out=Path(sys.argv[2]);data=original.read_bytes()
assert len(data)==939216 and hashlib.sha256(data).hexdigest()=='34c232018a619b0091e97add6805072d00db3250937fc049a1ef968cecfa99c9'
e=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
assert e[0][:7]==b'\x7fELF\x02\x01\x01' and e[1:3]==(3,62)
relocations=0
for i in range(e[12]):
 s=struct.unpack_from('<IIQQQQIIQQ',data,e[6]+i*e[11])
 if s[1] in (4,9):
  assert s[9] in (16,24) and not s[5]%s[9]
  for at in range(s[4],s[4]+s[5],s[9]):
   target=struct.unpack_from('<Q',data,at)[0];relocations+=1;assert not 0x10000<=target<0x12000
assert relocations==143
pair=data[0x10000:0x12000]
assert len(pair)==8192 and hashlib.sha256(pair).hexdigest()=='d581910c998f52887ed76623d2280e52d178a4d25d46001d64586bd2c8ddf7ab'
p=out/'interpreter-pair.bin'
with p.open('xb') as f:f.write(pair)
asm='.section .text.ra_region,"ax",@progbits\n.balign 4096\n.globl region_app_page,region_app_source_end,region_app_head,region_app_predecessor,region_app_second_page\nregion_app_page:\n.incbin '+json.dumps(str(p.resolve()))+'\nregion_app_source_end:\n.set region_app_predecessor,region_app_page+0x2c1\n.set region_app_head,region_app_page+0x2c8\n.set region_app_second_page,region_app_page+4096\n.type region_app_head,@function\n.size region_app_head,4\n.section .note.GNU-stack,"",@progbits\n'
with (out/'pair.S').open('x') as f:f.write(asm)
