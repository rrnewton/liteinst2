"""Finite same-CPU seed admission; never normalizes an architectural byte."""
import hashlib,struct
SIZE=5792
SEED=bytes.fromhex('dbe3d9e8d9eb')
def need(ok,why):
    if not ok:raise ValueError(why)
def q(b):return struct.unpack('<'+'Q'*(len(b)//8),b)
def labels(data):
    need(type(data)is bytes and 64<=len(data)<16<<20,'bounded emitted seed ELF')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\2\1\1'and h[1:4]==(2,62,1)and h[8:11]==(64,56,h[10])and
         h[11]==64 and 0<h[10]<=64 and 0<h[12]<=4096,'exact native x86-64 ET_EXEC tables')
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,'complete ELF span')
        return data[at:at+n]
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56))for i in range(h[10])]
    sh=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64))for i in range(h[12])]
    tables=[s for s in sh if s[1]==2];need(len(tables)==1,'unique complete ELF symbols')
    table=tables[0];need(table[9]==24 and table[5]%24==0 and table[6]<len(sh),'complete symbol extent')
    strings=sh[table[6]];names=take(strings[4],strings[5]);wanted={}
    for i in range(table[5]//24):
        name,info,other,section,value,n=struct.unpack('<IBBHQQ',take(table[4]+24*i,24))
        need(name<len(names)and b'\0'in names[name:],'complete symbol name')
        text=names[name:names.index(0,name)]
        if text in(b'psp_begin_a',b'psp_fip_a',b'psp_begin_b',b'psp_fip_b'):
            need(section!=0 and text not in wanted,'unique defined actual seed label')
            wanted[text]=value
    need(len(wanted)==4 and wanted[b'psp_fip_a']!=wanted[b'psp_fip_b'],'two independent actual seed PCs')
    for suffix in(b'a',b'b'):
        begin=wanted[b'psp_begin_'+suffix];need(wanted[b'psp_fip_'+suffix]==begin+4,'exact source label edge')
        loads=[p for p in ph if p[0]==1 and p[1]==5 and p[3]<=begin and 6<=p[5]and begin-p[3]<=p[5]-6]
        need(len(loads)==1,'one RX seed extent');p=loads[0]
        need(take(p[2]+begin-p[3],6)==SEED,'actual emitted FNINIT/FLD1/FLDPI bytes')
    return wanted

def read(raw,elf,format_facts,xstate,*,cpu,pid):
    """Caller binds exact source/compiler/ELF, exit0/reap, stdout/stderr and
    reserved CPU; xstate is the unchanged authenticated B2 format authority."""
    need(type(raw)is bytes and len(raw)==SIZE and type(cpu)is int and cpu>=0 and
         type(pid)is int and pid>0,'complete actual seed output and identity')
    need(q(raw[:128])==(0x3150444545534150,1,SIZE,pid,1,1,2,0,0,0,1,0,0,0,0,0),
         'two actual complete seeds and singleton before/after affinity')
    loc=labels(elf);at=128
    for i in range(2):
        h=q(raw[at:at+128]);cp=[struct.unpack_from('<6I',raw,at+128+24*j)for j in range(67)];at+=1736
        need(h[:5]==(i,1,1,0,0)and h[7]==1 and h[9]==h[11]==h[13]==0 and
             h[5]==h[14]==cpu and h[6]==h[15],'complete actual machine query prefix')
        actual=xstate.profile(cp,h[8],h[10],h[12],h[5],h[6])
        need(actual==format_facts,'same CPU and complete independent CPUID/XCR0/permission profile')
    snapshots=[]
    for i,suffix in enumerate((b'a',b'b')):
        h=q(raw[at:at+64]);code=raw[at+64:at+72]
        need(h==(i,loc[b'psp_begin_'+suffix],loc[b'psp_fip_'+suffix],1,1,0x37f,0x3000,0)and
             code==SEED+b'\0\0','actual distinct emitted seed, completion and x87 controls')
        for phase in range(2):
            fp=raw[at+72+phase*512:at+72+(phase+1)*512]
            need(fp[:6]==bytes.fromhex('7f030030c000')and not int.from_bytes(fp[6:8],'little')&~0x7ff,
                 'nonempty exact x87 TOP/tags/control and reserved opcode bits')
            need(fp[8:24]==bytes(16),'independently observed exact zero FIP and FDP, no wildcard')
            need(fp[32:42]==bytes.fromhex('35c26821a2da0fc90040')and
                 fp[48:58]==bytes.fromhex('0000000000000080ff3f'),
                 'actual nonzero PI and one extended-precision payloads')
            need(all(not any(fp[32+16*j+10:32+16*(j+1)])for j in range(8))and
                 not any(fp[416:]),'zero initialized FXSAVE reserved storage')
            snapshots.append(fp)
        at+=1096
    need(at==len(raw)and snapshots[1:]==[snapshots[0]]*3,
         'all four complete actual FXSAVE buffers byte-exact across labels/control capture')
    return dict(profile='x87-seed-zero-fip-v1',accepted=True,cpu=cpu,pid=pid,
        record_bytes=len(raw),record_sha256=hashlib.sha256(raw).hexdigest(),
        elf_sha256=hashlib.sha256(elf).hexdigest(),seed_bytes=SEED.hex(),
        seed_pcs=[loc[b'psp_fip_a'],loc[b'psp_fip_b']],fip=0,fdp=0,
        full_fxsave_sha256=hashlib.sha256(snapshots[0]).hexdigest(),
        format=facts_digest(format_facts),architectural_bytes_normalized=0)

def facts_digest(facts):
    import json
    return hashlib.sha256(json.dumps(facts,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def require(profile,format_facts,*,cpu):
    """The caller must supply the result of read() bound to its real captures,
    never a free-form selector. This is an additional prerequisite only."""
    need(type(profile)is dict and set(profile)=={'profile','accepted','cpu','pid','record_bytes',
         'record_sha256','elf_sha256','seed_bytes','seed_pcs','fip','fdp','full_fxsave_sha256','format',
         'architectural_bytes_normalized'}and profile.get('accepted')is True and
         profile.get('profile')=='x87-seed-zero-fip-v1'and type(profile.get('cpu'))is int and
         type(cpu)is int and profile['cpu']==cpu==format_facts['cpu']and
         type(profile['pid'])is int and profile['pid']>0 and type(profile['record_bytes'])is int and
         profile['record_bytes']==SIZE and type(profile['fip'])is int and type(profile['fdp'])is int and
         profile['fip']==profile['fdp']==0 and type(profile['seed_pcs'])is list and len(profile['seed_pcs'])==2 and
         all(type(v)is int and 0<v<1<<64 for v in profile['seed_pcs'])and profile['seed_pcs'][0]!=profile['seed_pcs'][1]and
         all(type(profile[k])is str and len(profile[k])==64 and all(c in '0123456789abcdef'for c in profile[k])
             for k in('record_sha256','elf_sha256','full_fxsave_sha256','format'))and
         profile.get('seed_bytes')==SEED.hex()and profile.get('format')==facts_digest(format_facts)and
         type(profile['architectural_bytes_normalized'])is int and profile['architectural_bytes_normalized']==0,
         'authenticated exact same-CPU zero-pointer seed prerequisite')
    return bytes(16)
