"""Finite actual-file E9 passthru validator. No backend or code is executed.

Unknown encodings and unsupported layouts are required refusals, never passing
rows. The ABI driver consumes the returned exact mapping/syscall ledger.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path
if sys.flags.optimize:
    raise SystemExit('optimized Python is unsupported')
PAGE=4096
LOADER=0x20fedc000
MASK=(1<<64)-1
MAX_FILE=64<<20
SAVE=bytes.fromhex('4157415641554154415341524151415051525657')
POPS={
    'original':bytes.fromhex('5f5e5a594159415a415b415c415d415e415f4158'),
    'corrected':bytes.fromhex('5f5e5a5941584159415a415b415c415d415e415f'),
}
class Invalid(ValueError): pass

def need(value, message):
    if not value: raise Invalid(message)

def sha(data): return hashlib.sha256(data).hexdigest()
def up(n): return (n+PAGE-1)&-PAGE

def bound_file(record):
    need(set(record)=={'path','sha256','size'}, 'file identity fields')
    p=Path(record['path']).resolve(strict=True)
    need(str(p)==record['path'] and p.is_file(), 'absolute ordinary file')
    need(0<=record['size']<=MAX_FILE, 'file resource limit')
    b=p.read_bytes()
    need(len(b)==record['size'] and sha(b)==record['sha256'], 'file identity')
    return p,b

class Elf:
    def __init__(self,b):
        self.b=b
        need(64<=len(b)<=MAX_FILE and b[:9]==b'\x7fELF\x02\x01\x01\x00\x00', 'ELF64 LE SYSV')
        h=struct.unpack_from('<HHIQQQIHHHHHH',b,16)
        self.type,machine,version,self.entry,self.phoff,self.shoff,flags,ehsz,phsz,phnum,shsz,shnum,self.shstr=h
        need(self.type in (2,3) and machine==62 and version==1 and flags==0 and ehsz==64,'ELF architecture')
        need(phsz==56 and 0<phnum<=128 and shsz==64 and 0<shnum<=256 and self.shstr<shnum,'ELF finite tables')
        self.slice(self.phoff,phnum*56);self.slice(self.shoff,shnum*64)
        self.ph=[]
        for i in range(phnum):
            t,f,o,v,p,fs,ms,a=struct.unpack_from('<IIQQQQQQ',b,self.phoff+i*56)
            need(fs<=MAX_FILE and ms<=MAX_FILE and v+ms<=MASK,'segment bound')
            if fs:self.slice(o,fs)
            if t==1:
                need(fs<=ms and a in (0,1,PAGE,0x200000) and o%PAGE==v%PAGE,'LOAD geometry')
                need(f in (4,5,6) and fs>0,'finite file-backed LOAD; no RWX')
            self.ph.append(dict(index=i,type=t,flags=f,offset=o,vaddr=v,paddr=p,filesz=fs,memsz=ms,align=a))
        loads=self.loads()
        for i,x in enumerate(loads):
            for y in loads[i+1:]:
                need(up(x['vaddr']+x['memsz'])<=y['vaddr']//PAGE*PAGE or up(y['vaddr']+y['memsz'])<=x['vaddr']//PAGE*PAGE,'overlapping LOAD pages')
        self.sh=[struct.unpack_from('<IIQQQQIIQQ',b,self.shoff+i*64) for i in range(shnum)]
        for x in self.sh:
            if x[1]!=8 and x[5]:self.slice(x[4],x[5])
        self.symbols={}
        for x in self.sh:
            if x[1] not in (2,11):continue
            need(x[9]==24 and x[5]%24==0 and x[5]//24<=8192 and x[6]<shnum,'symbol table bounds')
            s=self.sh[x[6]];strings=self.slice(s[4],s[5])
            for off in range(x[4],x[4]+x[5],24):
                name,info,other,section,value,size=struct.unpack_from('<IBBHQQ',b,off)
                need(name<len(strings),'symbol string offset')
                end=strings.find(b'\0',name);need(end>=0,'symbol terminator')
                n=strings[name:end].decode('ascii')
                if n and section!=0:
                    item=(value,size,info,other)
                    if n in self.symbols:need(self.symbols[n]==item,'ambiguous symbol')
                    self.symbols[n]=item
    def slice(self,o,n):
        need(0<=o<=len(self.b) and 0<=n<=len(self.b)-o,'file bounds')
        return self.b[o:o+n]
    def loads(self):return [x for x in self.ph if x['type']==1]
    def storage(self,v,n):
        matches=[x for x in self.loads() if x['vaddr']<=v and v+n<=x['vaddr']+x['filesz']]
        need(n>0 and len(matches)==1,'unique file-backed virtual extent')
        x=matches[0];return x['offset']+v-x['vaddr']
    def virtual(self,v,n):return self.slice(self.storage(v,n),n)
    def symbol(self,n):
        need(n in self.symbols,'missing symbol '+n);return self.symbols[n][0]
    def dynamic(self):
        ds=[x for x in self.ph if x['type']==2]
        need(len(ds)<=1,'dynamic inventory')
        if not ds:return []
        x=ds[0];need(x['filesz']%16==0 and x['filesz']//16<=4096,'dynamic bounds')
        rows=[]
        for o in range(x['offset'],x['offset']+x['filesz'],16):
            t,v=struct.unpack_from('<qQ',self.b,o);rows.append((t,v,o))
            if t==0:return rows
        raise Invalid('unterminated dynamic table')
    def no_runtime_fixups(self):
        # The fixture itself has no external calls, TLS, constructor arrays or
        # loader relocation work. This is NOT an arbitrary-ELF qualification.
        need(not any(x['type'] in (3,7,0x6474e553) for x in self.ph),'INTERP/TLS/property unsupported')
        need(all(p['filesz']==p['memsz'] for p in self.loads()),'manual fixture requires no BSS')
        need(sum(up(p['vaddr']+p['memsz'])//PAGE-p['vaddr']//PAGE for p in self.loads())<=64,'manual initial LOAD page budget')
        for t,v,o in self.dynamic():
            need(t not in (1,22,25,26,32) and not(t in (2,8,18,35) and v),'dynamic runtime work unsupported')

def note_payload(e,p):
    data=e.slice(p['offset'],p['filesz']);i=0;records=[]
    while i<len(data):
        need(i+12<=len(data),'note header')
        ns,ds,t=struct.unpack_from('<III',data,i);i+=12
        need(ns<=len(data)-i,'note name');name=data[i:i+ns];i+=(ns+3)&-4
        need(ds<=len(data)-i,'note desc');desc=data[i:i+ds];i+=(ds+3)&-4
        need(not(name==b'GNU\0' and t==5),'cannot sacrifice GNU property')
        records.append((name,t,desc))
    need(i==len(data) and records,'note partition');return data,records

class Bytes:
    def __init__(self,b):self.b=b;self.i=0
    def is_(self,x):return self.b.startswith(x,self.i)
    def take(self,x):
        need(self.is_(x),'unknown bootstrap encoding at '+str(self.i));self.i+=len(x)
    def num(self,n,signed=False):
        need(self.i+n<=len(self.b),'bootstrap field bounds')
        x=int.from_bytes(self.b[self.i:self.i+n],'little',signed=signed);self.i+=n;return x

def compiled_loader(bin_b,elf_b,variant):
    e=Elf(elf_b)
    start=e.symbol('_entry');c=e.symbol('e9entry')
    need(e.virtual(start,len(bin_b))==bin_b,'compiled loader exact text')
    need(bin_b.startswith(SAVE),'compiled loader save sequence')
    off=len(SAVE)
    if variant=='corrected':
        need(bin_b[off:off+8]==bytes.fromhex('554889e54883e4f0'),'corrected stack anchor')
        off+=8
    need(bin_b[off]==0xe8,'loader C CALL')
    target=start+off+5+struct.unpack_from('<i',bin_b,off+1)[0]
    need(target==c and start<=c<start+len(bin_b),'actual e9entry CALL/symbol')
    if variant=='corrected':need(bin_b[off+5:off+9]==bytes.fromhex('4889ec5d'),'anchor restoration')
    return dict(c_offset=c-start,call_offset=off,prefix_size=len(bin_b))

def decode_loader(raw,prefix,variant,pic,old_entry):
    need(raw.startswith(prefix),'exact compiled bootstrap prefix')
    c=Bytes(raw);c.i=len(prefix);c.take(bytes.fromhex('ba0500000041ba12000000'))
    rows=[];length=None;prot=5;offset=None
    close=bytes.fromhex('4c89c7b8030000000f05')
    while not c.is_(close):
        need(len(rows)<32,'bootstrap mapping count')
        begin=c.i
        if c.is_(b'\xbf'):c.take(b'\xbf');addr=c.num(4)
        else:c.take(b'\x48\xbf');addr=c.num(8,True)
        relative=c.is_(bytes.fromhex('4c01e7'))
        if relative:c.take(bytes.fromhex('4c01e7'))
        need(relative==pic,'fixed corpus forbids absolute PIC mapping')
        if c.is_(b'\xbe'):c.take(b'\xbe');length=c.num(4)
        if c.is_(b'\xba'):c.take(b'\xba');prot=c.num(4)
        if c.is_(bytes.fromhex('41b9')):c.take(bytes.fromhex('41b9'));offset=c.num(4)
        elif c.is_(bytes.fromhex('49b9')):c.take(bytes.fromhex('49b9'));offset=c.num(8)
        need(length is not None and offset is not None and 0<length<=16*PAGE and prot==5,'finite RX mapping')
        need(addr%PAGE==offset%PAGE==length%PAGE==0,'mapping alignment')
        c.take(bytes.fromhex('4489e8'));syscall=c.i;c.take(bytes.fromhex('0f054839f8740341ffe6'))
        rows.append(dict(address=addr,length=length,offset=offset,prot=prot,flags=0x12,relative=relative,begin=begin,syscall=syscall))
    c.take(close);close_pc=c.i-2
    if c.is_(b'\xb8'):c.take(b'\xb8');entry=c.num(4)
    else:c.take(bytes.fromhex('48b8'));entry=c.num(8)
    if pic:c.take(bytes.fromhex('4c01e0'))
    need(entry==old_entry,'unchanged original continuation')
    c.take(POPS[variant]);c.take(bytes.fromhex('ffe0'))
    need(c.i==len(raw),'no init calls/custom mmap/unparsed loader suffix')
    need(rows,'required refactoring/mapping ledger')
    return rows,close_pc

def validate_rewrite(original,output,prefix,loader_elf,mode,site,variant,note_sha):
    need(mode in ('dso','kernel') and variant in POPS,'mode/variant')
    old=Elf(original);new=Elf(output)
    need(old.type==new.type,'ELF type preservation')
    pic=old.type==3
    need(len(old.ph)==len(new.ph) and old.phoff==new.phoff,'unchanged PHDR count/location')
    changed=[i for i,(x,y) in enumerate(zip(old.ph,new.ph)) if x!=y]
    need(len(changed)==1,'exact one converted NOTE')
    idx=changed[0];note=old.ph[idx];loader=new.ph[idx]
    need(note['type']==4,'converted header originally NOTE')
    payload,records=note_payload(old,note);need(sha(payload)==note_sha,'exact declared inert NOTE identity')
    need(loader==dict(index=idx,type=1,flags=5,offset=loader['offset'],vaddr=LOADER,paddr=0,filesz=loader['filesz'],memsz=loader['filesz'],align=PAGE),'loader PHDR shape')
    need(loader['offset']%PAGE==0 and loader['offset']>=up(len(original)) and loader['offset']+loader['filesz']==len(output),'loader appended final extent')
    allowed=[(old.phoff+idx*56,56)]
    if mode=='kernel':
        entry=old.entry;need(new.entry==LOADER,'kernel e_entry replacement');allowed.append((24,8))
    else:
        od=[x for x in old.dynamic() if x[0]==12];nd=[x for x in new.dynamic() if x[0]==12]
        need(len(od)==len(nd)==1 and od[0][2]==nd[0][2] and nd[0][1]==LOADER,'exact DT_INIT replacement')
        entry=od[0][1];allowed.append((od[0][2]+8,8))
    copy=bytearray(output[:len(original)])
    for o,n in allowed:copy[o:o+n]=original[o:o+n]
    need(bytes(copy)==original,'all original bytes unchanged except declared loader fields')
    need(output[len(original):up(len(original))]==bytes(up(len(original))-len(original)),'zero initial alignment padding')
    need(old.virtual(site,5)[0]==0xb8,'fixed MOV EAX,imm32 passthru input')
    info=compiled_loader(prefix,loader_elf,variant)
    raw=new.slice(loader['offset'],loader['filesz'])
    rows,close_pc=decode_loader(raw,prefix,variant,pic,entry)
    # Ordered rows are both syscall and ownership dependencies. Last row alone
    # rewrites the source page; all earlier pages are previously unoccupied.
    source_page=site//PAGE*PAGE
    need(rows[-1]['address']==source_page and rows[-1]['length']==PAGE,'one final source-page refactor')
    source_owner=[p for p in old.loads() if p['flags']==5 and p['vaddr']//PAGE*PAGE==source_page and p['vaddr']+p['filesz']<=source_page+PAGE]
    need(len(source_owner)==1,'finite one-page RX original ownership')
    p=source_owner[0];original_offset=p['offset']//PAGE*PAGE
    source=output[rows[-1]['offset']:rows[-1]['offset']+PAGE]
    expected=original[original_offset:original_offset+PAGE].ljust(PAGE,b'\0')
    need(len(source)==PAGE and source[site-source_page]==0xe9,'actual source E9')
    at=site-source_page;target=site+5+struct.unpack_from('<i',source,at+1)[0]
    restored=bytearray(source);restored[at:at+5]=expected[at:at+5]
    need(bytes(restored)==expected,'exact unchanged source page outside MOV5')
    generated=[r for r in rows[:-1] if r['address']<=target and target+10<=r['address']+r['length']]
    need(len(generated)==1,'one generated target owner')
    r=generated[0];off=r['offset']+target-r['address']
    need(output[off:off+5]==old.virtual(site,5) and output[off+5]==0xe9,'exact MOV5/E9 trampoline')
    need(target+10+struct.unpack_from('<i',output,off+6)[0]==site+5,'exact trampoline rejoin')
    for i,r in enumerate(rows):
        need(up(len(original))<=r['offset'] and r['offset']+r['length']<=loader['offset'],'mapped bytes within appended page region')
        for q in rows[:i]:need(r['address']+r['length']<=q['address'] or q['address']+q['length']<=r['address'],'nonoverlapping mapped virtual pages')
        if i<len(rows)-1:
            need(all(r['address']+r['length']<=p['vaddr']//PAGE*PAGE or up(p['vaddr']+p['memsz'])<=r['address'] for p in new.loads()),'generated mapping overlaps loaded bytes')
            data=bytearray(output[r['offset']:r['offset']+r['length']])
            if r is generated[0]:data[off-r['offset']:off-r['offset']+10]=b'\xcc'*10
            need(data==b'\xcc'*r['length'],'no hidden executable payload in trampoline backing')
    covered=sorted(set((r['offset'],r['offset']+r['length']) for r in rows));cursor=up(len(original))
    for a,b in covered:need(a==cursor,'complete appended physical-page partition');cursor=b
    need(cursor==loader['offset'],'no unaccounted appended bytes')
    return dict(mode=mode,variant=variant,site=site,site_file_offset=old.storage(site,5),source_page=source_page,original_source_offset=original_offset,entry=entry,target=target,loader=loader,compiled=info,rows=rows,close_pc=close_pc,note_sha256=note_sha,old_sha256=sha(original),output_sha256=sha(output))
