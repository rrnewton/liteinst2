"""Two exact EVEX512 store families; full architecture remains C-owned."""
import hashlib,struct
from pathlib import Path
from page_selected import fact,need
from page_selected_generic import digest
from page_selected_register_time_compare import decode
from page_selected_vmovdqu128_promotions import promotions
from page_selected_vpcmpeqb_memory_promotions import promotions as vpcm_promotions
from page_selected_vpcmpeqb_register_promotions import promotions as vpe_promotions
from page_selected_vmovdqu64_promotions import promotions as vm64_promotions
from page_selected_vmovdqu64_256_promotions import promotions as vm256_promotions
from page_selected_vmovdqu64_store_promotions import promotions as vdq_store_promotions
ROOT=Path(__file__).resolve().parents[2]
FIXTURE=ROOT/'tools/page-entry/selected/tests/vmovdqa64_store'
MASK=(1<<64)-1;PAGE=4096;MEMORY_ROW=32888;MEMORY_BYTES=64+18*MEMORY_ROW
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')
FAULT_NAMES=('full-noaccess','full-readonly','cross-alignment','indexed-cross-alignment','indexed-readonly',
             'stack-readonly','base-source','rip-source')
FAULT_NAMES1847=('full-noaccess','full-readonly','cross-noaccess','cross-readonly','indexed-readonly',
                'stack-readonly','base-source','rip-source','indexed-cross-noaccess','indexed-cross-readonly')
FAMILIES={
 1838:dict(code=1838,prefix='fd487f',suffix='',base=14000,total=161,starts=tuple(range(0,160,16)),
    counts=(16,)*9+(17,),faults=FAULT_NAMES,refusals=32,
    obs_magic=0x315341363456324c,query_magic=0x315741363456324c,memory_magic=0x314d41363456324c,range_magic=0x315241363456324c,
    cases_sha='b008f715c3393dcc823dd60bc6f3e732bc3734f451af719ecc03c2cdc30707ef',compiled_sha='444c271a0a865c0fb69bda8c12d1aafa918d51fda94a8beff5bb2150d996b24e'),
 1847:dict(code=1847,prefix='fe487f',suffix='1847',base=16000,total=178,starts=tuple(range(0,160,16))+(161,),
    counts=(16,)*9+(17,17),faults=FAULT_NAMES1847,refusals=64,
    obs_magic=0x315355363456324c,query_magic=0x315755363456324c,memory_magic=0x314d55363456324c,range_magic=0x315255363456324c,
    cases_sha='4501eaf89d01db4f6a8e383cc0804d1e42f43dc93f88c8edbcd1f96b123c6f6a',compiled_sha='e99257b73dec40ac8c2c396f3c5cb0dd61bc0a0a0832a6aef52a1d4801d3f5a1')}
def profile(family):
    need(type(family)is int and family in(1838,1847),'one explicit exact store family')
    return FAMILIES[family]
def fault_geometry(kind,family):
    p=profile(family);need(type(kind)is int and 1<=kind<=len(p['faults']),'one named genuine failed store')
    return dict(indexed=kind in((4,5)if family==1838 else(5,9,10)),
        source=kind in(7,8),stack=kind==6,
        crossing=kind in((3,4)if family==1838 else(3,4,9,10)),
        alignment=family==1838 and kind in(3,4),
        noaccess=kind in((1,)if family==1838 else(1,3,9)))

def catalogue(family=1838):
    p=profile(family);case_path=FIXTURE/('cases'+p['suffix']+'.json');compiled=FIXTURE/('cases'+p['suffix']+'.inc')
    need(fact(case_path)['sha256']==p['cases_sha'] and
         fact(compiled)['sha256']==p['compiled_sha'],'exact literal JSON and compiled C catalogues')
    table=decode(case_path.read_bytes());rows=table['cases']
    need((table['schema'],table['code'],table['groups'],table['pairs_per_group'],table['total_cases'])==
         (1,family,len(p['counts']),16,p['total']) and len(rows)==p['total'],'closed explicit family cohort structure')
    if family==1847:need(table['group_starts']==list(p['starts'])and table['group_counts']==list(p['counts']),
        'explicit new group starts preserve the existing17-row final cohort')
    need(table['patterns_hex']==[bytes(64).hex(),bytes([255]*64).hex(),
         bytes((0x43+17*i)&255 for i in range(64)).hex()],'independent complete 64-byte memory literals')
    sections={k:[r for r in rows if r['section']==k]for k in ('register','base','indexed','palette','fetch','extra','observed','unaligned','observed1847')}
    need({k:len(v)for k,v in sections.items()}==dict(register=64,base=16,indexed=16,palette=7,fetch=42,extra=15,observed=1,unaligned=16 if family==1847 else 0,observed1847=int(family==1847)),
         'every declared structural section retained')
    need([(r['src_reg'],r['dest'])for r in sections['register']]==
         [((i+13)%32,i)for i in range(32)]+[(i,i)for i in range(32)],'all32 sources/destinations and self-copies')
    need([r['base']for r in sections['base']]==list(range(16)),'all sixteen GPR bases including actual RSP')
    need({r['index']for r in sections['indexed']}==set(range(16))-{4} and
         {r['scale']for r in sections['indexed']}=={1,2,4,8},'all usable indices and four scales')
    need([r['hex']for r in sections['palette']]==[x.replace('fd487f',p['prefix'])for x in ['62e1fd487f6f04','62e1fd487f7705','62a1fd487ffd','6221fd487fc6','62e1fd487f0e','62e1fd487f17','62e1fd487fcf']],
         'seven literal reverse-copy/store analogues of the original load palette')
    need([(r['length'],r['tail'])for r in sections['fetch']]==
         [(length,tail)for length in (6,7,8,10,11)for tail in range(1,length+1)],
         'every fetch tail at every admitted instruction length')
    need(sections['extra'][0]['hex']=='62e1'+p['prefix']+'5701' and
         (sections['extra'][0]['src_reg'],sections['extra'][0]['base'],sections['extra'][0]['displacement'])==(18,7,64),
         'literal store-role analogue uses compressed disp8*64')
    need(sum(r['dest']is not None for r in rows)==67 and sum(r['dest']is None for r in rows)==94+17*(family==1847),
         'all67 reverse copies and exact family memory-store population')
    for i,r in enumerate(rows):
        b=bytes.fromhex(r['hex']);n=len(b)
        group=next(g for g,(start,count)in enumerate(zip(p['starts'],p['counts']))if start<=i<start+count)
        need((r['case_index'],r['group'],r['slot'],r['length'])==(i,group,i-p['starts'][group],n) and
             n in (6,7,8,10,11) and 1<=r['tail']<=n and r['pattern']in (0,1,2),'literal identity/fetch geometry')
        need(b[0]==0x62 and b[1]&15==1 and b[2:5]==bytes.fromhex(p['prefix']),
             'exact family EVEX map1/W1/reserved vvvv/pp/L512/no mask/no zeroing/no broadcast/reserved Vprime')
        R=(~b[1]>>7)&1;X=(~b[1]>>6)&1;B=(~b[1]>>5)&1;Rp=(~b[1]>>4)&1
        at=6;m=b[5];mod=m>>6;rm=m&7;src=((m>>3)&7)+8*R+16*Rp
        dest=base=index=None;scale=1;disp=0;disp_bytes=0;disp_at=None;rip=False
        if mod==3:dest=rm+8*B+16*X
        else:
            if rm==4:
                sib=b[at];at+=1;scale=1<<(sib>>6);raw_index=(sib>>3)&7;raw_base=sib&7
                if raw_index!=4 or X:index=raw_index+8*X
                if mod or raw_base!=5:base=raw_base+8*B
                else:disp_bytes=4
            elif mod==0 and rm==5:rip=True;disp_bytes=4
            else:base=rm+8*B
            if mod==1:disp_bytes=1
            elif mod==2:disp_bytes=4
            if disp_bytes:
                disp_at=at;disp=int.from_bytes(b[at:at+disp_bytes],'little',signed=True);at+=disp_bytes
                if disp_bytes==1:disp*=64
        need(at==n and (dest,src,base,index,scale,disp,disp_bytes,disp_at)==
             (r['dest'],r['src_reg'],r['base'],r['index'],r['scale'],r['displacement'],r['disp_bytes'],r['disp_offset']),
             'independent EVEX extension/ModRM/SIB/disp8 scaling interpretation')
        kind='register'if dest is not None else 'rip'if rip else 'absolute'if base is None else 'stack'if base==4 else 'data'
        need(r['memory_kind']==kind and index!=4,'literal memory role; RSP is not an index')
        if kind=='rip':need(disp in (-16128,12544) and r['operand_offset']==256 and
            r['rip_target_delta']==4096-r['tail']+n+disp and r['rip_target_delta'] in(-3*PAGE+256,4*PAGE+256),'literal aligned separate writable RIP target')
        if kind=='absolute':need(r['absolute_target']==0x20000100 and
            ((r['index_value']or 0)*scale+disp)&MASK==0x20000100,'literal guarded low operand')
        if kind=='stack':need(base==4 and index is None and disp in((0,)if family==1838 else(0,7,31)),
            'actual subject RSP remains unchanged; literal per-family displacement')
        if kind=='data':need(r['operand_offset']in((0,256,4032)if family==1838 or i<161 else(1,2,3,8,15,16,32,33,63,256,4033,4064,4080,4088,4095)) and
            (index is None or base!=index),'literal64-byte data and independent base/index')
    need(rows[160]['hex']=='62e1'+p['prefix']+'0f' and rows[160]['src_reg']==17 and rows[160]['dest']is None and
         (rows[160]['base'],rows[160]['operand_offset'],rows[160]['pattern'],rows[160]['tail'])==(7,256,2,6),
         'exact original promoted role retained without replacing any structural case')
    if family==1847:
        extra=rows[161:177];offsets=[1,2,3,7,8,15,16,31,32,33,63,4033,4064,4080,4088,4095]
        need([r['operand_offset']for r in extra]==offsets and all(r['src_reg']==17 and r['dest']is None and
            r['pattern']==i%3 and r['tail']==r['length']for i,r in enumerate(extra)),
            'sixteen exact unaligned/page-crossing literal stores')
        for i,r in enumerate(extra):
            need((r['base'],r['index'],r['scale'],r['displacement'],r['memory_kind'])==
                ((4,None,1,offsets[i],'stack')if offsets[i]in(7,31)else
                 (7,1,2,0,'data')if offsets[i]==4088 else(7,None,1,0,'data')),
                 'real RSP+disp and independent indexed unaligned cases')
        r=rows[177];need(r['hex']=='62e1fe487f6a03'and(r['src_reg'],r['dest'],r['base'],r['index'],r['displacement'],r['operand_offset'],r['pattern'],r['tail'])==
            (21,None,2,None,192,256,2,7),'exact actual1847 failure bytes and disp8*64 geometry')
    return rows


def observations(data, group, header, fault_kind=0, family=1838):
    p=profile(family);count_expected=p['counts'][group];start=p['starts'][group]
    need(len(data) == 5000, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (p['obs_magic'], 1, 5000, group, 1 if fault_kind else count_expected+1, header['xcr0'], header['xsave_bytes']),
         'exact trailer identity and observed input joins')
    tuples = [struct.unpack_from('<6Q', data, 64+48*i) for i in range(68)]
    basic, components = tuples[:4], tuples[4:]
    need([x[:2] for x in basic] == [(0, 0), (1, 0), (7, 0), (13, 0)] and
         all(all(v < 1 << 32 for v in q) for q in tuples), 'actual CPUID tuple identities and register width')
    need(basic[0][2] >= 13 and basic[1][4] & 0x1c000000 == 0x1c000000 and
         basic[2][3] & 0x40010000 == 0x40010000, 'actual XSAVE/OSXSAVE/AVX/AVX512F/BW prerequisites')
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
    need(ids == ([0]*19 if fault_kind else [0]+list(range(p['base']+start,p['base']+start+count_expected))+[0]*(18-count_expected)),
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


def fault_case(kind,family=1838):
    f=fault_geometry(kind,family);prefix='62f1'+profile(family)['prefix']
    code=prefix+('044f'if f['indexed']else '0424'if f['stack']else '0500f1ffff'if kind==8 else '07')
    b=bytes.fromhex(code)
    return dict(case_index=200+kind,hex=code,length=len(b),tail=len(b),dest=None,src_reg=0,pattern=0,
        memory_kind='stack'if f['stack']else 'rip'if kind==8 else 'data',base=4 if f['stack']else None if kind==8 else 7,
        index=1 if f['indexed']else None,scale=2 if f['indexed']else 1,
        displacement=-3840 if kind==8 else 0,index_value=37 if f['indexed']else None)

def queries(data,rows,group,kind,family=1838):
    p=profile(family);f=fault_geometry(kind,family)if kind else None
    need(len(data)==10304,'complete actual-before query trailer');count=2 if kind else 2*p['counts'][group]
    need(struct.unpack_from('<8Q',data)==(p['query_magic'],1,10304,group,count,p['refusals'],0,0),'exact query header/count')
    pairs=[];kinds={'register':0,'data':1,'stack':2,'rip':3,'absolute':4}
    for i in range(count//2):
        case=fault_case(kind,family)if kind else rows[p['starts'][group]+i];pair=[]
        for lane in (0,1):
            at=64+256*(2*i+lane);attempt,result,identity,actual_lane=struct.unpack_from('<4Q',data,at)
            before=struct.unpack_from('<18Q',data,at+32);value=struct.unpack_from('<4Q4I',data,at+176)
            pc,npc,first,end,abi,policy,code,length=value;ea,obj,offset,role=struct.unpack_from('<4Q',data,at+224)
            need((attempt,result,identity,actual_lane,abi,code,length)==(1,0,p['base']+case['case_index'],lane,1,family,case['length']) and
                 pc>4096 and pc%4096==4096-case['tail'] and npc==pc+length,'actual original-PC/identity/fetch geometry')
            expected=0 if case['dest']is not None else (npc+case['displacement'])&MASK if case['memory_kind']=='rip' else (
                (before[case['base']]if case['base']is not None else 0)+
                (before[case['index']]*case['scale']if case['index']is not None else 0)+case['displacement'])&MASK
            need(ea==expected and role==kinds[case['memory_kind']],'EA from all actual-before registers')
            if case['dest']is not None:need((policy,first,end,ea,obj,offset)==(1,0,0,0,0,0),'register reverse-copy NONE')
            else:
                need(policy==2 and first==ea and end==ea+64<=MASK and obj>4096 and not obj%4096 and (obj+offset)&MASK==ea,'complete64-byte RANGE/object join')
                if case['index']is not None:need(before[case['index']]==case['index_value'],'actual independent index seed')
                if family==1838:need(ea%64==(32 if kind in(3,4)else 0),'actual aligned operand or exact #GP misalignment')
                if kind:
                    if not f['source']and not f['stack']:need(offset==PAGE-(32 if f['crossing']else 0),'exact fault page geometry')
                    elif f['stack']:need(obj==before[4]-PAGE and offset==PAGE,'actual read-only RSP page')
                    else:need(obj==pc-(PAGE-case['tail']) and offset==256,'aligned protected source destination')
                if not kind:
                    if role==1:need(offset==case['operand_offset'],'literal data target')
                    elif role==2:need(obj==before[4]-4096 and ea==before[4]+case['displacement'],'genuine subject RSP target')
                    elif role==3:need(obj==pc-(4096-case['tail'])-3*PAGE,'separate RIP lower data page')
                    else:need(obj==0x20000000 and ea==case['absolute_target'],'actual fixed low data')
            pair.append(dict(before=list(before),value=list(value),ea=ea,object=obj,offset=offset,role=role,case=case))
        need(pair[0]==pair[1],'complete native/TF actual-before and footprint equality');pairs.append(pair[0])
    need(not any(data[64+256*count:]),'unused query capacity zero')
    return pairs,dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),actual_before_queries=count,
        memory_write_ranges=2*sum(p['role']!=0 for p in pairs),values_sha256=digest(pairs))


def memory(data,pairs,kind,group,family=1838):
    profile_row=profile(family);f=fault_geometry(kind,family)if kind else None
    need(len(data)==MEMORY_BYTES,'complete actual two-page images')
    need(struct.unpack_from('<8Q',data)==(profile_row['memory_magic'],1,MEMORY_BYTES,1 if kind else profile_row['counts'][group],0,0,0,0),'exact memory observation count')
    changes=[]
    for slot in range(18):
        block=data[64+slot*MEMORY_ROW:64+(slot+1)*MEMORY_ROW]
        if (kind and slot!=17)or(not kind and not 1<=slot<=profile_row['counts'][group]):need(not any(block),'unused memory slots zero');continue
        q=pairs[0 if kind else slot-1];case=q['case'];pc=q['value'][0];ea=q['ea'];subject=q['before'][4]-4096
        head=struct.unpack_from('<15Q',block);identity=head[0];attempt=head[1:5];complete=head[5:9];pages=head[9:11];actual_ea,failed=head[11:13];changed=head[13:15]
        need(identity==profile_row['base']+case['case_index'] and attempt==complete==(1,1,1,1) and actual_ea==ea and failed==bool(kind),'four actual bounded memory snapshots')
        mapping=pc-(4096-case['tail']);role=q['role']
        if kind and f['source']:expected_pages=(mapping,mapping+PAGE)
        elif role==3:expected_pages=(mapping-3*PAGE,mapping+4*PAGE)
        elif role==2:expected_pages=(subject,subject+PAGE)
        elif role==4:expected_pages=(0x20000000,0x20001000)
        elif role:expected_pages=(q['object'],q['object']+PAGE)
        else:expected_pages=(q['before'][6],q['before'][6]+PAGE)
        need(pages==expected_pages and pages[0]>4096 and pages[0]!=pages[1] and all(not p%PAGE for p in pages),'actual independently located operand pages')
        images=[block[120+8192*i:120+8192*(i+1)]for i in range(4)]
        need(images[0]==images[2] and images[1]==images[3],'full native/TF before and actual post-memory equality')
        if kind and f['alignment']:need(images[0]==images[1] and changed==(0,0),'alignment #GP has no retired memory effect')
        literal=bytes(64)if case['pattern']==0 else bytes([255]*64)if case['pattern']==1 else bytes((0x43+17*i)&255 for i in range(64))
        enc=bytes.fromhex(case['hex']);mask=0
        for p,page in enumerate(pages):
            for off in range(PAGE):
                at=page+off;inside=bool(ea and ea<=at<ea+64)
                if kind and f['source']:before=enc[at-pc]if pc<=at<pc+len(enc)else 0xcc
                elif role==2:before=((at-subject)*29+11)&255
                elif role in (3,4):before=(off*11+0x59)&255
                else:before=((off*17+3)if p==0 else(off*11+0x59))&255
                if inside and not(kind and f['source']):before=literal[at-ea]^255
                a,b=images[0][p*PAGE+off],images[1][p*PAGE+off]
                need(a==before,'independently seeded complete before image')
                if not inside or(kind and f['source']):need(b==a,'no memory changes outside64-byte potential write range')
                elif not kind:need(b==literal[at-ea],'complete successful literal store')
                else:need(b==a or b==literal[at-ea],'partial fault byte is old byte or corresponding source byte')
                if b!=a:mask|=1<<(at-ea)
        need(changed==(mask,mask),'retained actual changed-byte masks');changes.append(mask)
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),checked=len(changes),changed_masks=changes,
        comparison='Complete native/TF post-images; every outside-range byte unchanged; fault in-range bytes old or literal source, without atomicity assumption.')


def ranges(data,family=1838):
    p=profile(family)
    need(len(data)==800 and struct.unpack_from('<4Q',data)==(p['range_magic'],1,800,3),'three exact supplied end-overflow controls')
    for i,first in enumerate((MASK-64,MASK-63,MASK-7)):
        at=32+256*i;need(struct.unpack_from('<4Q',data,at)==(1,0,i,0),'supplied control identity')
        need(struct.unpack_from('<18Q',data,at+32)==tuple(first if j==6 else 0 for j in range(18)),'supplied RSI only')
        need(struct.unpack_from('<4Q4I',data,at+176)==(0x1000,0x1006,first if not i else 0,MASK if not i else 0,1,2 if not i else 0,family,6),'checked64-byte end; overflow never NONE/RANGE')
        need(not any(data[at+224:at+256]),'unused supplied control fields zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),supplied_range_end_controls=3)


def fault_observations(data,kind,h,pairs,family=1838):
    need(len(data)==96,'complete actual fault prefix');v=struct.unpack('<12Q',data)
    if not kind:need(not any(v),'no invented fault on successful cohorts');return None
    f=fault_geometry(kind,family);q=pairs[0];ea=q['ea'];address=ea if f['source']or f['stack']else q['object']+PAGE
    need(v[:6]==(kind,1,ea,address,address-ea,0),'actual original operand/fault address/zeroTRACE')
    need(all(x&0xe7==0xe7 and not x&~h['xcr0']for x in v[6:])and len(set(v[6:10]))==len(set(v[10:]))==1,'complete unchanged fault kernel/live BVs')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),kind=kind,owner_trace=0,prefix_bytes=address-ea,
        expected_trap=13 if f['alignment']else 14,expected_error=0 if f['alignment']else 6 if f['noaccess']else 7)


def record(data,expected,sample_bytes,rows,*,family=1838):
    p=profile(family)
    need(640<len(data)<16<<20,'complete two-index Code1847 typed trailer within unchanged cap')
    vdq_promoted=vdq_store_promotions(data[-640:],indices=(16,5));data=data[:-640]
    need(352<len(data)<16<<20,'complete Code1604 promotion trailer within unchanged cap')
    vm256_promoted=vm256_promotions(data[-352:]);data=data[:-352]
    need(1216<len(data)<16<<20,'complete register-promotion trailer under old cap')
    vpe_promoted=vpe_promotions(data[-1216:],'vmovdqu128_store');data=data[:-1216]
    need(2080<len(data)<16<<20,'complete seven Code1605 promotions within old cap')
    vm64_promoted=vm64_promotions(data[-2080:]);data=data[:-2080]
    need(1504<len(data)<(16<<20),'complete additional typed-promotion trailer within unchanged cap')
    memory_promoted=vpcm_promotions(data[-1504:]);data=data[:-1504]
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()),'exact outcome; failed stores remain failed')
    base=136+22*sample_bytes+40;extent=base+5000+96+10304+3808+MEMORY_BYTES+800
    need(h['sample_bytes']==sample_bytes>0 and len(data)==extent<16<<20,'actual ELF-sized full record below unchanged cap')
    kind=expected['fault_kind'];group=expected['group'];positive=not kind;count=p['counts'][group];start=p['starts'][group]
    need(h['pairs']==count+1 and h['completed']==(count+1 if positive else 1),'complete prefix; no fault operation completion')
    if positive:need(not any(data[136+(count+1)*sample_bytes:136+22*sample_bytes]),'all unused positive samples and negative sample zero')
    else:need(not any(data[136+sample_bytes:136+21*sample_bytes]),'unstarted positive slots zero')
    obs=observations(data[base:base+5000],group,h,kind,family);base+=5000
    failed_raw=data[base:base+96];base+=96
    pairs,foot=queries(data[base:base+10304],rows,group,kind,family);base+=10304
    promoted=promotions(data[base:base+3808]);base+=3808
    mem=memory(data[base:base+MEMORY_BYTES],pairs,kind,group,family);base+=MEMORY_BYTES
    supplied=ranges(data[base:],family);failed=fault_observations(failed_raw,kind,h,pairs,family)
    return dict(vdq_store_promotions=vdq_promoted,vdq_store_typed_promotions=2,vdq_store_supplied_range_queries=2,vm256_promotions=vm256_promoted,vm256_typed_promotions=1,vm256_supplied_none_queries=1,vpe_promotions=vpe_promoted,vpe_typed_promotions=1,vpe_supplied_none_queries=1,vm64_promotions=vm64_promoted,operation='completed'if positive else 'failed_alignment'if fault_geometry(kind,family)['alignment']else 'failed_memory_write',
        pairs=count+1 if positive else 0,new_pairs=count if positive else 0,
        startup_pairs=1,verified_memory_failures=int(not positive),refusals=h['refusals'],actual_before_queries=foot['actual_before_queries'],
        actual_range_queries=foot['memory_write_ranges'],actual_none_queries=foot['actual_before_queries']-foot['memory_write_ranges'],
        typed_promotions=13,supplied_none_queries=12,supplied_range_queries=1,
        vpcm_promotions=memory_promoted,vpcm_typed_promotions=5,vpcm_supplied_none_queries=5,supplied_range_end_controls=3,
        ending_pairs=sum(c['tail']==c['length']for c in rows[start:start+count])if positive else 0,
        crossing_pairs=sum(c['tail']<c['length']for c in rows[start:start+count])if positive else 0,
        header=h,observations=obs,footprint=foot,promotions=promoted,memory=mem,range_controls=supplied,fault_observations=failed,
        architecture='Authenticated unchanged common C native/TF full-state comparison plus complete literal store/register effects. Reader independently binds all generated bytes, actual-before EA/RANGE/NONE, full initialized two-page memory snapshots and failed prefixes; no second full FP replay claim.')
