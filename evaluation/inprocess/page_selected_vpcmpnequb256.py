"""Literal immediate4-only Code3884 catalogue and actual-before EA reader."""
import hashlib,struct
from page_selected import fact,need
from page_selected_generic import digest
from page_selected_register_time_compare import decode

MASK=(1<<64)-1
ACTUAL=((0x16bac6,'62f375203e0f04'),(0x16bae6,'62f36d203e4f0104'),
        (0x16bb0e,'62f365203e4f0204'),(0x16bb29,'62f35d203e4f0304'),
        (0x16bd28,'62f375203e4c17fe04'),(0x16bd48,'62f375203e4c17ff04'),
        (0x16bce0,'62f365203e4a0204'),(0x16bcf8,'62f375203e4a0304'))

def catalogue(fixture,json_sha,c_sha):
    need(fact(fixture/'cases3884.json')['sha256']==json_sha and
         fact(fixture/'cases3884.inc')['sha256']==c_sha,'exact compiled and independently parsed catalogue')
    table=decode((fixture/'cases3884.json').read_bytes());rows=table['rows']
    need((table['schema'],table['code'],table['predicate'],table['width'],table['groups'],table['pairs_per_group'])==
         (1,3884,4,32,5,18)and len(rows)==90,'only explicit NEQ256 five-cohort profile')
    src=bytes([0,1,0x7f,0x80,0x81,0xfe,0xff,0x55]*4)
    patterns=[src,bytes(v^255 for v in src),bytes(v^1 if i%3==0 else v for i,v in enumerate(src))]
    need(table['source']==src.hex()and table['patterns']==[p.hex()for p in patterns]and
         table['expected']==[0,0xffffffff,0x49249249]and
         [sum((a!=b)<<i for i,(a,b)in enumerate(zip(src,p,strict=True)))for p in patterns]==table['expected'],
         'independent complete unsigned-byte NEQ masks including zero/full/mixed and edge values')
    sections={s:[r for r in rows if r['section']==s]for s in ('roles','fetch','libc','edge')}
    need({s:len(v)for s,v in sections.items()}==dict(roles=32,fetch=47,libc=8,edge=3),
         'compact exact structural sections')
    need([r['source']for r in sections['roles']]==list(range(32))and
         [r['destination']for r in sections['roles']]==[i%8 for i in range(32)],
         'all32 sources and all8 K destinations with nonzero high halves in the actual C seed')
    need({r['base']for r in rows if r['base']is not None}==set(range(16))and
         {r['index']for r in rows if r['index']is not None}==set(range(16))-{4}and
         {r['scale']for r in rows if r['index']is not None}=={1,2,4,8},
         'all GPR bases,usable index roles and scales')
    need([(r['length'],r['tail'])for r in sections['fetch']]==
         [(n,t)for n in(7,8,9,11,12)for t in range(1,n+1)],'every admitted length/tail')
    need([(r['elf_offset'],r['encoding'])for r in sections['libc']]==list(ACTUAL)and
         table['libc_sha256']=='4fe244b698006f2a5cc7d1e6008c195dfb3ac4038ea79a6500bdde4205efb523',
         'original ELF source sites, not a claim they executed in the failed application')
    for i,r in enumerate(rows):
        b=bytes.fromhex(r['encoding']);n=len(b)
        need((r['case_index'],r['group'],r['slot'],r['length'])==(i,i//18,i%18,n)and
             n in(7,8,9,11,12)and 1<=r['tail']<=n and r['pattern']in(0,1,2),
             'fixed identity/length/fetch geometry')
        need(b[0]==0x62 and b[1]&0x9f==0x93 and b[2]&0x87==5 and
             b[3]&0xf7==0x20 and b[4]==0x3e and b[-1]==4 and b[5]&0xc0!=0xc0,
             'memory-only map3/W0/66/VL256/no mask,z,b/K-extension and immediate4')
        src=((~b[2]>>3)&15)|(((~b[3]>>3)&1)<<4);dst=(b[5]>>3)&7
        X=(~b[1]>>6)&1;B=(~b[1]>>5)&1;mod=b[5]>>6;rm=b[5]&7
        at=6;base=index=None;scale=1;disp=0;disp_bytes=0;disp_at=None;rip=False
        if rm==4:
            sib=b[at];at+=1;scale=1<<(sib>>6);ri=(sib>>3)&7;rb=sib&7
            if ri!=4 or X:index=ri+8*X
            if mod or rb!=5:base=rb+8*B
            else:disp_bytes=4
        elif not mod and rm==5:rip=True;disp_bytes=4
        else:base=rm+8*B
        if mod==1:disp_bytes=1
        elif mod==2:disp_bytes=4
        if disp_bytes:
            disp_at=at;disp=int.from_bytes(b[at:at+disp_bytes],'little',signed=True);at+=disp_bytes
            if disp_bytes==1:disp*=32
        need(at+1==n and(src,dst,base,index,scale,disp,disp_bytes,disp_at)==
             (r['source'],r['destination'],r['base'],r['index'],r['scale'],r['displacement'],r['disp_bytes'],r['disp_offset']),
             'independent full EVEX/ModRM/SIB/disp8*32/disp32/immediate interpretation')
        role='rip'if rip else'absolute'if base is None else'stack'if base==4 else'data'
        need(r['memory_kind']==role and index!=4 and(base!=index or index is None),'source-defined operand role')
        if role=='rip':need(disp in(-256,256),'RIP operand separated from endpoints')
        elif role=='absolute':need(r['absolute_target']==0x20000100 and disp==0x20000100 and index is None,'literal low arena')
        elif role=='stack':need(index is None and disp==0,'actual unmodified subject RSP')
        else:need(r['offset']in(0,257,4064),'unaligned and both32-byte operand page edges')
    need([r['base']for r in rows[:4]]==[7]*4 and[r['index']for r in rows[:4]]==[None,None,0,1],
         'four actual fault instructions,ordinary then indexed')
    need(sum(r['tail']==r['length']for r in rows)==16 and
         sum(r['tail']<r['length']for r in rows)==74 and len(table['refusals'])==33,
         'complete geometry and strict immediate4-neighbor population')
    # The immutable literal table binds every new refusal, including all seven
    # other low predicates; no constant-result instruction is promoted.
    need([r['bytes']for r in table['refusals'][:9]]==
         ['62f375203e0f'+format(i,'02x')for i in(0,1,2,3,5,6,7,8,255)],'other predicates stay negative')
    return rows

def queries(data,header,rows,kind,group):
    need(len(data)==10304,'complete actual-before GPR/FS/GS/NONE and EA trailer')
    count=2 if kind else 36
    need(struct.unpack_from('<8Q',data)==(0x31514e435056324c,1,10304,group,count,0,0,0),
         'exact query identity/count and no synthetic controls')
    values=[]
    for index in range(count//2):
        pair=[];case=rows[18*group+(kind-1 if kind else index)]
        for lane in (0,1):
            at=64+256*(2*index+lane)
            attempted,result,identity,actual_lane=struct.unpack_from('<4Q',data,at)
            before=struct.unpack_from('<18Q',data,at+32);value=struct.unpack_from('<4Q4I',data,at+176)
            pc,next_pc,first,end,abi,policy,code,length=value
            need((attempted,result,identity,actual_lane,first,end,abi,policy,code,length)==
                 (1,0,5000+18*group+(kind-1 if kind else index),lane,0,0,1,1,3884,case['length'])and
                 0<pc<1<<47 and pc%4096==4096-case['tail']and next_pc==pc+length,
                 'exact real before-frame NONE and original-PC/fetch/length')
            ea,obj,offset,role=struct.unpack_from('<4Q',data,at+224)
            expected=(next_pc+case['displacement'])&MASK if case['memory_kind']=='rip'else(
                (before[case['base']]if case['base']is not None else 0)+
                (before[case['index']]*case['scale']if case['index']is not None else 0)+case['displacement'])&MASK
            need(ea==expected and role=={'data':1,'stack':2,'rip':3,'absolute':4}[case['memory_kind']]and
                 0<obj<1<<47 and ea>=obj and offset==ea-obj,'independent actual full64-bit effective address')
            if kind:
                need(role==1 and offset==(4080 if kind%2==0 else 4096)and obj%4096==0,
                     'actual ordinary/indexed full or16+16 inaccessible operand')
            elif role==1:need(offset==case['offset']and obj%4096==0 and offset+32<=4096,'actual data-page operand')
            elif role==2:need(ea==before[4]and offset==4096 and offset+32<=8192,'actual retained private stack operand')
            elif role==3:need(obj==pc-(4096-case['tail'])and offset==4096-case['tail']+length+case['displacement'],
                             'actual immutable source-image RIP operand')
            else:need(obj==0x20000000 and ea==0x20000100,'collision-refusing low mapping')
            if case['index']is not None:need(before[case['index']]==case['index_value'],'actual fixed index input')
            pair.append(dict(before=list(before),value=list(value),ea=[ea,obj,offset,role]))
        need(pair[0]==pair[1],'whole native/TF before-query/EA equality')
        values.append(pair)
    need(not any(data[64+256*count:]),'unattempted query rows remain zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),actual_before_queries=count,
                values_sha256=digest(values),memory_write_ranges=0)
