"""Literal Code3848 catalogue and complete capture framing; no candidate execution at authoring."""
import hashlib,struct
from page_selected import fact,need
from page_selected_generic import digest
from page_selected_register_time_compare import decode
from page_selected_vpxorq256_record import catalogue as catalogue256
from page_selected_vptestnmb_promotions import promotions as vtn_promotions
from page_selected_vpxorq256_promotions import promotions as vpx256_promotions

MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')
CASES_SHA='8ee3500c56807be70473d201e4816dc603142ca1e0e7764115cf4d3b1fe004d6'
CASES_C_SHA='15ac96c58fb6a023e947cee805af93b1ea0de24a8fbc0b9eff942f432e0abdaa'
OUTCOMES_SHA='3f891fb3ad6508f10f1836a586b03572243eafd69ecb1e83614d9f74d51451c6'
NEIGHBORS_SHA='85d02cba910efb76f5b475065a6616f2a9a0ee98f51d819b26adf5a4b60913db'
REFUSALS=222
QUERY_REFUSALS=175 # common generic47 refusals are outside the query counter
GROUP_COUNTS=(16,)*140+(10,)
FAULT_NAMES=('full-read-fault','cross-read-fault','indexed-full-read-fault','indexed-cross-read-fault','constant-zero-read-fault','constant-one-read-fault')
FAULT_CASES=(2144,2144,2160,2160,2248,2249)


def catalogue(fixture, donor):
    need(fact(fixture/'cases.json')['sha256']==CASES_SHA and
         fact(fixture/'cases.inc')['sha256']==CASES_C_SHA and
         fact(fixture/'neighbors.inc')['sha256']==NEIGHBORS_SHA,'exact literal truth/geometry and supplied-neighbor source')
    t=decode((fixture/'cases.json').read_bytes());rows=t['rows']
    need((t['schema'],t['code'],t['vector_bits'],t['total_cases'],t['truth_cases'],t['groups'],t['register_cases'],t['memory_cases'])==
         (1,3848,256,2250,2048,141,2146,104) and t['group_counts']==list(GROUP_COUNTS) and
         t['group_starts']==list(range(0,2250,16)) and len(rows)==2250 and
         (t['old_refusal_rows'],t['old_vpx_refusal_rows'],t['old_vpx256_refusal_rows'])==(73,37,35),
         'closed truth table, role, memory, fetch and old supplied populations')
    old=catalogue256(donor)
    for i,r in enumerate(rows):
        b=bytes.fromhex(r['encoding']);n=len(b)
        need((r['id'],r['group'],r['slot'],r['length'])==(i,i//16,i%16,n) and
             n in (7,8,9,11,12) and 1<=r['tail']<=n and r['pattern']in(0,1,2) and
             type(r['imm'])is int and 0<=r['imm']<256 and b[-1]==r['imm'],
             'literal identity, complete immediate and original fetch extent')
        need(b[0]==0x62 and b[1]&15==3 and b[2]&0x87==5 and b[3]&0xf7==0x20 and b[4]==0x25,
             'canonical EVEX map3/W0/66/LL256/unmasked/unbroadcast source form')
        R=(~b[1]>>7)&1;X=(~b[1]>>6)&1;B=(~b[1]>>5)&1;Rp=(~b[1]>>4)&1
        m=b[5];mod=m>>6;rm=m&7;at=6
        dest=((m>>3)&7)+8*R+16*Rp;src1=((~b[2]>>3)&15)+16*((~b[3]>>3)&1)
        src2=base=index=-1;scale=1;disp=0;disp_bytes=0;disp_at=None;rip=False
        if mod==3:src2=rm+8*B+16*X
        else:
            if rm==4:
                sib=b[at];at+=1;scale=1<<(sib>>6);ix=(sib>>3)&7;bs=sib&7
                if ix!=4 or X:index=ix+8*X
                if mod or bs!=5:base=bs+8*B
                else:disp_bytes=4
            elif mod==0 and rm==5:rip=True;disp_bytes=4
            else:base=rm+8*B
            if mod==1:disp_bytes=1
            elif mod==2:disp_bytes=4
            if disp_bytes:
                disp_at=at;disp=int.from_bytes(b[at:at+disp_bytes],'little',signed=True);at+=disp_bytes
                if disp_bytes==1:disp*=32
        kind=0 if mod==3 else 3 if rip else 4 if base<0 else 2 if base==4 else 1
        need(at+1==n and (dest,src1,src2,base,index,scale,disp,disp_bytes,disp_at,kind)==
             (r['destination'],r['src1'],r['src2'],r['base'],r['index'],r['scale'],r['displacement'],r['disp_bytes'],r['disp_offset'],r['kind']),
             'independent EVEX/ModRM/SIB register extensions and displacement32 with trailing immediate')
        a,bv,c=[bytes.fromhex(r[k])for k in('input_a','input_b','input_c')]
        need(len(a)==len(bv)==len(c)==32 and (dest!=src1 or a==bv) and
             (src2<0 or dest!=src2 or a==c) and (src2<0 or src1!=src2 or bv==c),
             'complete old-destination/source bytes and physically coherent register aliases')
        expected=[]
        for x,y,z in zip(a,bv,c):
            value=0
            for triple in range(8):
                if r['imm']>>triple&1:
                    value|=(x if triple&4 else x^255)&(y if triple&2 else y^255)&(z if triple&1 else z^255)
            expected.append(value)
        need(bytes(expected).hex()==r['expected'],'independent ternary minterm model with old destination as input A')
        if i<2048:
            triple=i%8
            need(r['section']=='truth' and r['imm']==i//8 and r['truth']==triple and kind==0 and
                 len({dest,src1,src2})==3 and
                 (a,bv,c)==tuple(bytes([255 if triple&v else 0])*32 for v in(4,2,1)) and
                 r['expected']==bytes([255 if r['imm']>>triple&1 else 0]).hex()*32,
                 'every immediate and every input triple at each bit of every dword lane')
        if 2048<=i<2241:
            d=old[i-2048];wire=bytearray.fromhex(d['encoding']);wire[1]=(wire[1]&240)|3;wire[2]&=127;wire[4]=0x25;wire.append(0xde if d['id']==112 else (0xde,0xfe,0x96)[d['id']%3])
            keys=('src1','destination','src2','base','index','scale','displacement','disp_bytes','disp_offset','offset','index_value','absolute_target','kind','pattern','section')
            need(b==bytes(wire) and r['tail']==d['tail']+1 and all(r[k]==d[k]for k in keys),
                 'all193 old role/address geometries retained as literal ternary analogues, with unchanged nextPC/RIP target')
        if kind==1:need(r['offset']in(0,257,4064) and base!=index,'guarded complete memory placement and independent index')
        if kind==2:need(base==4 and index==-1 and not disp,'real unchanged subject stack pointer')
        if kind==3:need(disp in(-256,256,4080),'closed source-relative data palettes')
        if kind==4:need(r['absolute_target']==0x20000100 and (r['index_value']*scale+disp)&MASK==0x20000100,'literal collision-refusing mapping')
    need(all({r[k]for r in rows[2048:2144]}==set(range(32))for k in('destination','src1','src2')) and
         [r['base']for r in rows[2144:2160]]==list(range(16)) and
         {r['index']for r in rows[2160:2176]}==set(range(16))-{4} and
         {r['scale']for r in rows[2160:2176]}=={1,2,4,8},'all32 roles, aliases,16 bases,15 indices and all scales')
    need({(r['length'],r['tail'])for r in rows if r['section']in('fetch','fetch_extra')}==
         {(n,j)for n in(7,8,9,11,12)for j in range(1,n+1)} and
         rows[2246]['encoding']=='62e37520256703de' and rows[2247]['encoding']=='62a3652025e2fe' and
         [(r['kind'],r['imm'])for r in rows[2248:]]==[(1,0),(1,255)],
         'all47 length/fetch tails, two source-consistent libc literals, and constant-result memory cases')
    need(t['faults']==[dict(case_index=FAULT_CASES[k-1],expected_error=4,expected_si_code=2,expected_signal=11,
         expected_trapno=14,instruction_completed=False,kind=k,name=name,operand_bytes=32,owner_trace=0,
         prefix_bytes=16 if k in(2,4)else 0)for k,name in enumerate(FAULT_NAMES,1)],
         'six genuine full/cross/indexed and constant-result memory faults, never completed instructions')
    return rows

def observations(data, group, header, fault_kind=0):
    need(len(data) == 5000, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (0x315432425056324c, 1, 5000, group, 1 if fault_kind else GROUP_COUNTS[group]+1, header['xcr0'], header['xsave_bytes']),
         'exact trailer identity and observed input joins')
    tuples = [struct.unpack_from('<6Q', data, 64+48*i) for i in range(68)]
    basic, components = tuples[:4], tuples[4:]
    need([x[:2] for x in basic] == [(0, 0), (1, 0), (7, 0), (13, 0)] and
         all(all(v < 1 << 32 for v in q) for q in tuples), 'actual CPUID tuple identities and register width')
    need(basic[0][2] >= 13 and basic[1][4] & 0x1c000000 == 0x1c000000 and
         basic[2][3] & 0xc0010000 == 0xc0010000, 'actual XSAVE/OSXSAVE/AVX/AVX512F/BW prerequisites')
    supported = basic[3][2] | basic[3][5] << 32
    need(xcr0 & 0xe7 == 0xe7 and not xcr0 & ~supported and not xcr0 >> 63 and
         basic[3][3] == size <= basic[3][4], 'actual enabled standard XSAVE capacity')
    active = [i for i in range(2, 63) if xcr0 >> i & 1]
    need(count == 4+len(active), 'every enabled extended component queried exactly once')
    regions = []
    for i, q in enumerate(components):
        if i not in active:
            need(not any(q), 'unqueried component remains absent')
            continue
        leaf, index, n, offset, flags, reserved = q
        need((leaf, index) == (13, i) and n > 0 and 576 <= offset <= size and
             n <= size-offset and not flags & 1, 'user standard-layout tuple and bounds')
        need(all(offset >= end or start >= offset+n for start, end in regions), 'all enabled components disjoint')
        regions.append((offset, offset+n))
    need([components[i][2] for i in (2, 5, 6, 7)] == [256, 64, 512, 1024],
         'architectural YMM/opmask/ZMM_Hi256/Hi16_ZMM extents')
    ids = list(struct.unpack_from('<19Q', data, 3328))
    need(ids == ([0]*19 if fault_kind else [0]+list(range(20000+16*group,20000+16*group+GROUP_COUNTS[group]))+[0]*(18-GROUP_COUNTS[group])),
         'actual retained completed pair identities')
    bvs = [list(struct.unpack_from('<10Q', data, 3480+80*i)) for i in range(19)]
    need(not any(v for row in bvs[checked:] for v in row), 'all uncompleted pair BV fields remain absent')
    for row in bvs[:checked]:
        need(all(v & 0xe7 == 0xe7 and not v & ~xcr0 for v in row), 'real non-init seed components present')
        need(len(set(row[:6])) == len(set(row[6:])) == 1,
             'exact kernel and live before/after XSTATE_BVs, separately observed without normalization')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), checked=checked,
                query_count=count, cpuid_basic=[list(x) for x in basic],
                components=[dict(index=i, raw=list(components[i])) for i in active],
                kernel_xstate_bv=sorted({r[0] for r in bvs[:checked]}), live_xstate_bv=sorted({r[6] for r in bvs[:checked]}),
                xcr0=xcr0, xsave_bytes=size, all_bvs_sha256=digest(bvs), pair_ids_sha256=digest(ids))


def fault_observations(data, kind, header):
    need(len(data) == 96, 'complete actual fault trailer')
    fields = ('kind', 'checked', 'operand', 'address', 'prefix_bytes', 'owner_trace',
              'native_before_bv', 'native_after_bv', 'owner_before_bv', 'owner_after_bv',
              'live_before_bv', 'live_after_bv')
    raw = struct.unpack('<12Q', data)
    if not kind:
        need(not any(raw), 'no invented fault observations on completed cohort')
        return None
    row = dict(zip(fields, raw))
    need(row['kind'] == kind and row['checked'] == 1 and row['owner_trace'] == 0 and
         row['address'] > 4096 and row['address'] % 4096 == 0 and
         row['prefix_bytes'] == (16 if kind in (2,4) else 0) and
         row['operand'] == row['address']-row['prefix_bytes'], 'actual fault operand/guard geometry')
    need(all(v & 0xe7 == 0xe7 and not v & ~header['xcr0'] for v in raw[6:]) and
         len(set(raw[6:10])) == len(set(raw[10:])) == 1,
         'fault native/owner kernel BVs and live BVs unchanged separately')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), **row)




def queries(data,header,rows,group,kind,failed):
    need(len(data)==7680,'complete actual-before NONE query trailer')
    count=2 if kind else 2*GROUP_COUNTS[group]
    need(struct.unpack_from('<8Q',data)==(0x315132545056324c,1,7680,group,count,QUERY_REFUSALS,0,0),
         'exact actual query counts/refusals and zero failure fields')
    values=[]
    for i in range(count//2):
        c=rows[FAULT_CASES[kind-1]if kind else 16*group+i];pair=[]
        for lane in (0,1):
            at=64+224*(2*i+lane);a=struct.unpack_from('<4Q',data,at)
            before=struct.unpack_from('<18Q',data,at+32);v=struct.unpack_from('<4Q4I',data,at+176)
            pc,next_pc,first,end,abi,policy,code,length=v
            need(a==(1,0,20000+c['id'],lane) and pc>4096 and pc<1<<47 and
                 pc%4096==4096-c['tail'] and next_pc==pc+c['length'] and
                 (first,end,abi,policy,code,length)==(0,0,1,1,3848,c['length']),
                 'exact actual-PC, Code3848 and no-write result from each original before frame')
            role=c['kind'];ea=0
            if role==3:ea=(next_pc+c['displacement'])&MASK
            elif role:
                ea=((before[c['base']]if c['base']>=0 else 0)+
                    (before[c['index']]*c['scale']if c['index']>=0 else 0)+c['displacement'])&MASK
            if role:
                need(4096<ea<ea+32<1<<47,'full operand arithmetic is a positive low userspace interval')
                if kind:need(role==1 and ea==failed['operand'],'query reconstructed EA is actual failed operand')
                elif role==1:need(ea%4096==c['offset'],'actual before-register data offset')
                elif role==2:need(ea==before[4] and not ea%16,'genuine aligned subject RSP')
                elif role==3:need(ea==pc-(4096-c['tail'])+4096-c['tail']+length+c['displacement'],
                                  'original source-relative data address')
                else:need(ea==c['absolute_target']==0x20000100,'actual low operand address')
                if c['index']>=0:need(before[c['index']]==c['index_value'],'actual independent index value')
            pair.append((before,v,ea))
        need(pair[0]==pair[1],'entire native/TF actual-before GPR/FS/GS tuple, PC and NONE results agree')
        values.append(pair)
    need(not any(data[64+224*count:]),'all unattempted actual-before query rows remain zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),actual_before_queries=count,
                values_sha256=digest(values),memory_write_ranges=0)


def record(data,expected,sample_bytes,rows):
    need(352+3232<len(data)<16<<20,'complete mandatory promotion trailers within unchanged cap')
    p256=vpx256_promotions(data[-352:]);data=data[:-352]
    p2791=vtn_promotions(data[-3232:],'vpxorq128');data=data[:-3232]
    need(len(data)>=136,'complete retained header')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()) and h['refusals']==REFUSALS,
         'exact finite outcome; real fault never relabelled completed')
    need(h['sample_bytes']==sample_bytes>0 and len(data)==136+22*sample_bytes+40+5000+96+7680<16<<20,
         'complete actual ELF-sized record with every initialized state and memory byte retained')
    need(576<=h['xsave_bytes']<=65536 and h['xcr0']&3==3,'qualified initialized XSAVE extent')
    group=expected['group'];kind=expected['fault_kind'];count=GROUP_COUNTS[group];positive=not kind
    need(h['pairs']==count+1 and h['completed']==(count+1 if positive else 1),
         'all completed positive pairs or exact startup-only failure prefix')
    if positive:need(not any(data[136+(count+1)*sample_bytes:136+22*sample_bytes]),'every unused and negative sample zero')
    else:need(not any(data[136+sample_bytes:136+21*sample_bytes]),'all unstarted positive samples zero')
    obs=observations(data[-12776:-7776],group,h,kind)
    failed=fault_observations(data[-7776:-7680],kind,h)
    q=queries(data[-7680:],h,rows,group,kind,failed)
    return dict(operation='completed'if positive else 'failed_memory_read',pairs=count+1 if positive else 0,
        new_pairs=count if positive else 0,startup_pairs=1,verified_memory_failures=int(not positive),
        refusals=h['refusals'],actual_before_queries=q['actual_before_queries'],
        ending_pairs=sum(r['tail']==r['length']for r in rows[16*group:16*group+count])if positive else 0,
        crossing_pairs=sum(r['tail']<r['length']for r in rows[16*group:16*group+count])if positive else 0,
        vtn_promotions=p2791,vtn_typed_promotions=10,vtn_supplied_none_queries=10,
        vpx256_promotions=p256,vpx256_typed_promotions=1,vpx256_supplied_none_queries=1,
        promoted_encoding_checks=1,promoted_footprint_queries=1,header=h,observations=obs,
        fault_observations=failed,footprint=q,
        architecture='Authenticated C oracle compares complete native/TF state, full low256 ternary old-destination/source semantics plus upper256 zeroing and whole memory/source, including six genuine failed reads. Reader checks complete ELF-sized records, CPUID, actual query/EA and failure prefixes; this is not a second full architectural replay.')
