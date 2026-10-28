"""Pure inspection of both actual linked builtin fixture images.

Interpreter addresses remain ELF-relative until joined to its observed bias by
the complete record reader. No generated instruction bytes replace a link.
"""
import hashlib
import struct
from page_selected import need

H=lambda b:hashlib.sha256(b).hexdigest()
MAIN=0x200401000
MARKER=b'LI2-BUILTINS-OK!'


def tables(data,callback_only=False):
    need(type(data)is bytes and 64<=len(data)<=16<<20,'complete bounded ELF file')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[2:4]==(62,1) and
         h[8:10]==(64,56) and h[11]==64 and 1<=h[10]<=32 and 1<=h[12]<=4096,
         'actual ELF64 x86-64 tables')
    def extent(off,n):
        need(0<=off<=len(data) and 0<=n<=len(data)-off,'complete ELF file extent')
        return data[off:off+n]
    ph=[struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56))for i in range(h[10])]
    need(all(p[2]<=len(data) and p[5]<=len(data)-p[2] and p[5]<=p[6]for p in ph),'all actual segment extents')
    loads=[p for p in ph if p[0]==1]
    ss=[struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64))for i in range(h[12])]
    if not callback_only:
        need(not any(s[1]in(4,9)and s[5]for s in ss),'no fixture source fixups or relocations')
    ts=[s for s in ss if s[1]==2]
    need(len(ts)==1 and ts[0][9]==24 and ts[0][5]%24==0 and ts[0][6]<len(ss),'one complete actual symbol table')
    t=ts[0];strings=ss[t[6]];names=extent(strings[4],strings[5]);symbols={}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,index,value,size=struct.unpack('<IBBHQQ',extent(at,24))
        if not n:continue
        need(n<len(names)and b'\0'in names[n:],'actual symbol name extent')
        name=names[n:names.index(b'\0',n)].decode()
        # The production bridge legitimately has multiple local names from
        # different TUs and relative relocations. Its unchanged bridge_check
        # validates those; this branch selects only two unique actual labels.
        if callback_only and name not in ('pb_clock_fault','pb_syscall_fault'):continue
        need(name not in symbols,'unique actual symbol '+name)
        symbols[name]=(value,size,info,index)
    def read(address,n):
        out=bytearray()
        while n:
            owners=[p for p in loads if p[3]<=address<p[3]+p[5]]
            need(len(owners)==1,'unique complete file-backed address owner')
            p=owners[0];take=min(n,p[3]+p[5]-address)
            out+=extent(p[2]+address-p[3],take);address+=take;n-=take
        return bytes(out)
    return h,ph,loads,symbols,read,extent


def inspect(data,role,variant,negative,interpreter,native_policy,parse):
    need(role in ('main','interpreter')and type(variant)is int and variant in(1,2)and
         type(negative)is int and 0<=negative<=12,'exact finite image parameters')
    h,ph,loads,syms,read,extent=tables(data)
    base=0x200400000 if role=='main'else 0;entry=base+4096;data_start=base+12288
    need(h[1]==(2 if role=='main'else 3)and h[4]==entry,'actual image role/first entry')
    need(len(loads)==3 and [p[1]for p in loads]==[4,5,6]and
         loads[0][2:4]==(0,base)and loads[0][5]<=4096 and
         loads[1][2:4]==(4096,entry)and loads[1][5:7]==(8192,8192)and
         loads[2][2:4]==(12288,data_start)and loads[2][5]>=16384 and
         all(p[7]==4096 and p[5]<=p[6]for p in loads)and
         all(a[3]+a[6]<=b[3]for a,b in zip(loads,loads[1:]))and
         not any(p[0]==7 for p in ph),'complete R/RX/RW domains; no TLS or overlap')
    stacks=[p for p in ph if p[0]==0x6474e551]
    need(len(stacks)==1 and stacks[0][1]==6,'actual nonexecutable stack')
    ip=[p for p in ph if p[0]==3]
    need((len(ip)==1 and extent(ip[0][2],ip[0][5])==str(interpreter).encode()+b'\0')if role=='main'else not ip,
         'actual custom interpreter, no interpreter chaining')
    dynamic=parse(data)
    need(dynamic['needed']==([interpreter.name]if role=='main'else [])and
         dynamic['soname']==(None if role=='main'else interpreter.name)and
         dynamic['interpreter']==(interpreter if role=='main'else None),
         'complete actual DT_NEEDED/SONAME/interpreter identities')
    symbols={name:value[0]for name,value in syms.items()}
    required={'_start':entry,'pl_seed':entry+4096,'pl_data':data_start,'pl_data_end':data_start+16384,
              'pl_output':data_start+128,'pb_negative':data_start+104,'pl_vectors':data_start+512,
              'pl_masks':data_start+2560,'pl_live_vectors':data_start+4096,'pl_live_masks':data_start+6144,
              'pl_live_gpr':data_start+6208,'pl_live_flags':data_start+6336,
              'pl_live_selectors':data_start+6344,'pl_stack_top':data_start+16320}
    need(all(symbols.get(k)==v for k,v in required.items()),'all emitted source/data/capture/stack symbols')
    need(entry+4096<symbols['pl_capture']<symbols['pl_capture_entry']<data_start,
         'actual separate seeded and inherited-entry live captures')
    first=6 if role=='interpreter'and variant==2 else 5
    spec=[('_start',first,None)]
    if role=='interpreter':
        spec += [('site_i_rdtsc',5,None),('site_i_rdtscp',6,None),
                 ('site_i_getpid',7,157 if negative==12 else 39),('site_i_gettid',7,186),
                 ('site_i_write',7,1),('site_i_ebadf',7,1)]
    else:
        spec += [('site_m_rdtscp',6,None),('site_m_rdtsc',5,None),('site_m_getpid',7,39),
                 ('site_m_gettid',7,186),('site_m_write_self',7,1),('site_m_write_clock',7,1),
                 ('site_m_write_output',7,1),('site_m_exit',7,231)]
    rows=[];sites=[]
    for name,kind,number in spec:
        pc=symbols[name];code=bytes.fromhex({5:'0f31',6:'0f01f9',7:'0f05'}[kind])
        need(entry<=pc<=entry+4096-5 and read(pc,len(code))==code,'actual literal selected site '+name)
        if kind!=6 or name=='_start':need(read(pc,5)==code+b'\x90'*(5-len(code)),'literal five-byte source window '+name)
        if role=='main'and kind!=6:sites.append(pc)
        rows.append(dict(name=name,pc=pc,kind=kind,number=number,encoding=code.hex(),seeded=name!='_start'))
    need(len({r['pc']for r in rows})==len(rows)and len(sites)==(8 if role=='main'else 0),'all distinct required effects/publication windows')
    need(native_policy(read(entry+4096-14,4096+28))==0 and native_policy(read(entry,4096))!=0,
         'whole emitted helper and halos pass unchanged native policy; selected page remains dirty')
    initial=bytearray(16384)
    struct.pack_into('<2Q',initial,0,0x31504c5244565250,variant)
    struct.pack_into('<Q',initial,104,negative);initial[128:144]=MARKER
    initial[512:2560]=bytes(1+(r*17+i*13)%255 for r in range(32)for i in range(64))
    initial[2560:2624]=b''.join(struct.pack('<Q',0x1020304050607080+r*0x0101010101010101)for r in range(8))
    initial[6356:]=b'\xa5'*(16384-6356)
    need(read(data_start,16384)==bytes(initial),'entire independent initial data/seed/negative word/stack image')
    source=read(entry,8192)
    return dict(entry=entry,source_hex=source.hex(),source_sha256=H(source),data_hex=initial.hex(),
                data_sha256=H(initial),symbols=symbols,rows=rows,sites=sites,elf_sha256=H(data))


def callback_symbols(data):
    _,_,loads,symbols,read,_=tables(data,callback_only=True)
    result={}
    for name in ('pb_clock_fault','pb_syscall_fault'):
        need(name in symbols,'retained real callback fault symbol '+name)
        pc=symbols[name][0]
        need(sum(p[1]==5 and p[3]<=pc<pc+2<=p[3]+p[5]for p in loads)==1 and read(pc,2)==b'\x0f\x0b',
             'actual private executable UD2 callback label '+name)
        result[name]=pc
    need(len(set(result.values()))==2,'distinct actual nested-fault locations')
    return result
