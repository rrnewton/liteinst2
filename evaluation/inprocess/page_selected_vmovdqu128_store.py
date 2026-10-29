#!/usr/bin/env python3
"""Canonical VEX128 VMOVDQU store/reverse-copy; bounded full-state and memory oracle."""
import argparse
from datetime import datetime,timezone
import hashlib,json,os,platform,re,shutil,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import ENV,fact,need,save,elf
from page_selected_generic import digest
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_vpcmpeqb_register_promotions import promotions as vpe_promotions
from page_selected_vmovdqu64_promotions import promotions as vm64_promotions
from page_selected_vmovdqu64_256_promotions import promotions as vm256_promotions
from page_selected_vmovdqu128_store_rseq import registered_controls,summary as registered_summary
from page_selected_components import plain_executable
from page_selected_register_time_build import recipe,expand,headers
from page_selected_register_time_compare import decode

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/vmovdqu128_store'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='c5c04029c3b771fb4fd2ed03332ffbcefaf8f1b61ff4f65de49955cb795251f5'
GENERATED_COMMON={'bytes': 34886, 'sha256': 'f946f5d3018d7072a481f94bd749d7a02c01c18a616ff87020282fd9c8235acc'}
GENERATED_JSON={'bytes': 52800, 'sha256': '5cf89bd95f4128970f167bfcb88c0ef3e41f17e723b34ff424da27574407f1c4'}
GENERATED_C={'bytes': 12562, 'sha256': 'e1208c844924b75b9be2eabf7d3e6f7e80c8185eae71193f91cf4c742ef6a1ae'}
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


"""Independent structural, footprint and complete memory-image replay."""
import hashlib,json,struct
from page_selected import fact,need
from page_selected_generic import digest
from page_selected_register_time_compare import decode
from page_selected_vmovdqu128_family import observations
from page_selected_vmovdqu128_promotions import promotions
from page_selected_vpcmpeqb_memory_promotions import promotions as vpcm_promotions

MASK=(1<<64)-1;PAGE=4096
MEMORY_ROW=32888;MEMORY_BYTES=64+18*MEMORY_ROW
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')
FAULT_NAMES=('full-noaccess','full-readonly','cross-noaccess','cross-readonly','readonly-cross',
             'stack-readonly','base-source','rip-source')

def catalogue(path,compiled):
    need(fact(path)==GENERATED_JSON and fact(compiled)==GENERATED_C,'exact generated literal C/JSON')
    table=decode(path.read_bytes());rows=table['cases']
    need((table['schema'],table['code'],table['groups'],table['pairs_per_group'],table['total_cases'])==
         (1,1840,8,16,128) and len(rows)==128,'closed eight-cohort store structure')
    need(table['patterns_hex']==[bytes(16).hex(),bytes([255]*16).hex(),
         bytes((0x43+17*i)&255 for i in range(16)).hex()],'independent literal source bytes')
    groups={k:[r for r in rows if r['section']==k]for k in ('register','base','indexed','write_geometry','fetch','extra')}
    need({k:len(v)for k,v in groups.items()}==dict(register=32,base=16,indexed=16,write_geometry=12,fetch=49,extra=3),'every structural section')
    need([(r['src_reg'],r['dest'])for r in groups['register']]==[( (i+5)%16,i)for i in range(16)]+[(i,i)for i in range(16)],'reversed register roles/all registers/self-alias')
    need([r['base']for r in groups['base']]==list(range(16)) and
         {r['index']for r in groups['indexed']}==set(range(16))-{4} and
         {r['scale']for r in groups['indexed']}=={1,2,4,8},'all bases/usable indices/scales')
    need([(r['length'],r['tail'])for r in groups['fetch']]==[(n,t)for n in range(4,11)for t in range(1,n+1)],'all49 fetch geometries')
    need([r['operand_offset']for r in rows[64:70]]==[4095,4094,4092,4088,4084,4081] and
         [r['displacement']for r in rows[70:72]]==[-16,7] and
         [r['hex']for r in rows[72:74]]==['c5fa7f06','c5fa7f07'] and
         rows[125]['hex']=='c5fa7f4c17f0','write crossings, actual RSP, exact promoted/observed/static-lookahead bytes')
    for i,r in enumerate(rows):
        b=bytes.fromhex(r['hex']);n=len(b)
        need((r['case_index'],r['group'],r['slot'],r['length'])==(i,i//16,i%16,n) and 4<=n<=10 and 1<=r['tail']<=n and r['pattern']in (0,1,2),'literal identity/length/tail')
        if b[0]==0xc5:
            need(b[1]&0x7f==0x7a and b[2]==0x7f,'VEX2 reserved-vvvv/L0/F3/7F')
            R=(~b[1]>>7)&1;X=B=0;at=3;wig=0
        else:
            need(b[0]==0xc4 and b[1]&31==1 and b[2]&0x7f==0x7a and b[3]==0x7f,'VEX3 map1/reserved-vvvv/L0/F3/7F')
            R=(~b[1]>>7)&1;X=(~b[1]>>6)&1;B=(~b[1]>>5)&1;at=4;wig=b[2]>>7
        need((r['vex_bytes'],r['wig'])==(at-1,wig),'literal VEX length/WIG')
        m=b[at];at+=1;mod=m>>6;rm=m&7;src=((m>>3)&7)+8*R
        dest=base=index=None;scale=1;disp=0;disp_bytes=0;disp_at=None;rip=False
        if mod==3:dest=rm+8*B
        else:
            if rm==4:
                sib=b[at];at+=1;scale=1<<(sib>>6);ri=(sib>>3)&7;rb=sib&7
                if ri!=4 or X:index=ri+8*X
                if mod or rb!=5:base=rb+8*B
                else:disp_bytes=4
            elif not mod and rm==5:rip=True;disp_bytes=4
            else:base=rm+8*B
            if mod==1:disp_bytes=1
            elif mod==2:disp_bytes=4
            if disp_bytes:disp_at=at;disp=int.from_bytes(b[at:at+disp_bytes],'little',signed=True);at+=disp_bytes
        need(at==n and (dest,src,base,index,scale,disp,disp_bytes,disp_at)==
             (r['dest'],r['src_reg'],r['base'],r['index'],r['scale'],r['displacement'],r['disp_bytes'],r['disp_offset']),'independent7F operand/address interpretation')
        kind='register'if dest is not None else 'rip'if rip else 'absolute'if base is None else 'stack'if base==4 else 'data'
        need(r['memory_kind']==kind and index!=4,'literal memory role/RSP is not index')
        if kind=='rip':need(disp in (-16384,12288) and r['operand_offset']==n-r['tail'],'distinct writable RIP target')
        if kind=='absolute':need(r['absolute_target']==0x20000100 and ((r['index_value']or 0)*scale+disp)&MASK==0x20000100,'collision-refusing absolute target')
        if kind=='stack':need(index is None and disp in (-16,0,7) and r['operand_offset']==disp,'actual subject RSP offset')
        if kind=='data':need(0<=r['operand_offset']<=4095 and (index is None or base!=index),'bounded two-page destination/independent base-index')
    return rows

def fault_case(kind):
    need(1<=kind<=8,'named failed store')
    b=bytes.fromhex('c5fa7f0424'if kind==6 else 'c5fa7f05f8ffffff'if kind==8 else 'c5fa7f07')
    return dict(case_index=200+kind,hex=b.hex(),length=len(b),tail=len(b),dest=None,src_reg=0,pattern=0,
        memory_kind='stack'if kind==6 else 'rip'if kind==8 else 'data',base=4 if kind==6 else None if kind==8 else 7,
        index=None,scale=1,displacement=-8 if kind==8 else 0,index_value=None)

def queries(data,rows,group,kind):
    need(len(data)==10304,'complete actual-before query trailer');count=2 if kind else 32
    need(struct.unpack_from('<8Q',data)==(0x315738323156324c,1,10304,group,count,0,0,0),'exact query header/count')
    pairs=[];kinds={'register':0,'data':1,'stack':2,'rip':3,'absolute':4}
    for i in range(count//2):
        case=fault_case(kind)if kind else rows[16*group+i];pair=[]
        for lane in (0,1):
            at=64+256*(2*i+lane);attempt,result,identity,actual_lane=struct.unpack_from('<4Q',data,at)
            before=struct.unpack_from('<18Q',data,at+32);value=struct.unpack_from('<4Q4I',data,at+176)
            pc,npc,first,end,abi,policy,code,length=value;ea,obj,offset,role=struct.unpack_from('<4Q',data,at+224)
            need((attempt,result,identity,actual_lane,abi,code,length)==(1,0,6000+case['case_index'],lane,1,1840,case['length']) and
                 pc>4096 and pc%4096==4096-case['tail'] and npc==pc+length,'actual original-PC/identity/fetch geometry')
            expected=0 if case['dest']is not None else (npc+case['displacement'])&MASK if case['memory_kind']=='rip' else (
                (before[case['base']]if case['base']is not None else 0)+
                (before[case['index']]*case['scale']if case['index']is not None else 0)+case['displacement'])&MASK
            need(ea==expected and role==kinds[case['memory_kind']],'EA from all actual-before registers')
            if case['dest']is not None:need((policy,first,end,ea,obj,offset)==(1,0,0,0,0,0),'register reverse-copy NONE')
            else:
                need(policy==2 and first==ea and end==ea+16<=MASK and obj>4096 and not obj%4096 and (obj+offset)&MASK==ea,'complete16-byte RANGE/object join')
                if case['index']is not None:need(before[case['index']]==case['index_value'],'actual independent index seed')
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

def memory(data,pairs,kind):
    need(len(data)==MEMORY_BYTES,'complete actual two-page images')
    need(struct.unpack_from('<8Q',data)==(0x31534d383231564c,1,MEMORY_BYTES,1 if kind else 16,0,0,0,0),'exact memory observation count')
    changes=[]
    for slot in range(18):
        block=data[64+slot*MEMORY_ROW:64+(slot+1)*MEMORY_ROW]
        if (kind and slot!=17)or(not kind and not 1<=slot<=16):need(not any(block),'unused memory slots zero');continue
        q=pairs[0 if kind else slot-1];case=q['case'];pc=q['value'][0];ea=q['ea'];subject=q['before'][4]-4096
        head=struct.unpack_from('<15Q',block);identity=head[0];attempt=head[1:5];complete=head[5:9];pages=head[9:11];actual_ea,failed=head[11:13];changed=head[13:15]
        need(identity==6000+case['case_index'] and attempt==complete==(1,1,1,1) and actual_ea==ea and failed==bool(kind),'four actual bounded memory snapshots')
        mapping=pc-(4096-case['tail']);role=q['role']
        if kind>=7:expected_pages=(mapping,mapping+PAGE)
        elif role==3:expected_pages=(mapping-3*PAGE,mapping+4*PAGE)
        elif role==2:expected_pages=(subject,subject+PAGE)
        elif role==4:expected_pages=(0x20000000,0x20001000)
        elif role:expected_pages=(q['object'],q['object']+PAGE)
        else:expected_pages=(q['before'][6],q['before'][6]+PAGE)
        need(pages==expected_pages and pages[0]>4096 and pages[0]!=pages[1] and all(not p%PAGE for p in pages),'actual independently located operand pages')
        images=[block[120+8192*i:120+8192*(i+1)]for i in range(4)]
        need(images[0]==images[2] and images[1]==images[3],'full native/TF before and actual post-memory equality')
        literal=bytes(16)if case['pattern']==0 else bytes([255]*16)if case['pattern']==1 else bytes((0x43+17*i)&255 for i in range(16))
        enc=bytes.fromhex(case['hex']);mask=0
        for p,page in enumerate(pages):
            for off in range(PAGE):
                at=page+off;inside=bool(ea and ea<=at<ea+16)
                if kind>=7:before=enc[at-pc]if pc<=at<pc+len(enc)else 0xcc
                elif role==2:before=((at-subject)*29+11)&255
                elif role in (3,4):before=(off*11+0x59)&255
                else:before=((off*17+3)if p==0 else(off*11+0x59))&255
                if inside and kind<7:before=literal[at-ea]^255
                a,b=images[0][p*PAGE+off],images[1][p*PAGE+off]
                need(a==before,'independently seeded complete before image')
                if not inside or kind>=7:need(b==a,'no memory changes outside16-byte potential write range')
                elif not kind:need(b==literal[at-ea],'complete successful literal store')
                else:need(b==a or b==literal[at-ea],'partial fault byte is old byte or corresponding source byte')
                if b!=a:mask|=1<<(at-ea)
        need(changed==(mask,mask),'retained actual changed-byte masks');changes.append(mask)
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),checked=len(changes),changed_masks=changes,
        comparison='Complete native/TF post-images; every outside-range byte unchanged; fault in-range bytes old or literal source, without atomicity assumption.')

def ranges(data):
    need(len(data)==800 and struct.unpack_from('<4Q',data)==(0x31524d383231564c,1,800,3),'three exact supplied end-overflow controls')
    for i,first in enumerate((MASK-16,MASK-15,MASK-7)):
        at=32+256*i;need(struct.unpack_from('<4Q',data,at)==(1,0,i,0),'supplied control identity')
        need(struct.unpack_from('<18Q',data,at+32)==tuple(first if j==6 else 0 for j in range(18)),'supplied RSI only')
        need(struct.unpack_from('<4Q4I',data,at+176)==(0x1000,0x1004,first if not i else 0,MASK if not i else 0,1,2 if not i else 0,1840,4),'checked16-byte end; overflow never NONE/RANGE')
        need(not any(data[at+224:at+256]),'unused supplied control fields zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),supplied_range_end_controls=3)

def fault_observations(data,kind,h,pairs):
    need(len(data)==96,'complete actual fault prefix');v=struct.unpack('<12Q',data)
    if not kind:need(not any(v),'no invented fault on successful cohorts');return None
    q=pairs[0];ea=q['ea'];address=q['object']+PAGE if kind<=4 else ea
    need(v[:6]==(kind,1,ea,address,address-ea,0),'actual original operand/fault address/zeroTRACE')
    need(all(x&0xe7==0xe7 and not x&~h['xcr0']for x in v[6:])and len(set(v[6:10]))==len(set(v[10:]))==1,'complete unchanged fault kernel/live BVs')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),kind=kind,owner_trace=0,prefix_bytes=address-ea,
        expected_trap=14,expected_error=6 if kind in (1,3)else 7)

def record(data,expected,sample_bytes,rows):
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
    kind=expected['fault_kind'];group=expected['group'];positive=not kind
    need(h['pairs']==17 and h['completed']==(17 if positive else 1),'complete prefix; no fault operation completion')
    if positive:need(not any(data[136+17*sample_bytes:136+22*sample_bytes]),'four unused samples and negative sample zero')
    else:need(not any(data[136+sample_bytes:136+21*sample_bytes]),'unstarted positive slots zero')
    obs=observations(data[base:base+5000],group,h,kind);base+=5000
    failed_raw=data[base:base+96];base+=96
    pairs,foot=queries(data[base:base+10304],rows,group,kind);base+=10304
    promoted=promotions(data[base:base+3808]);base+=3808
    mem=memory(data[base:base+MEMORY_BYTES],pairs,kind);base+=MEMORY_BYTES
    supplied=ranges(data[base:]);failed=fault_observations(failed_raw,kind,h,pairs)
    return dict(vm256_promotions=vm256_promoted,vm256_typed_promotions=1,vm256_supplied_none_queries=1,vpe_promotions=vpe_promoted,vpe_typed_promotions=1,vpe_supplied_none_queries=1,vm64_promotions=vm64_promoted,operation='completed'if positive else 'failed_memory_write',pairs=17 if positive else 0,new_pairs=16 if positive else 0,
        startup_pairs=1,verified_memory_failures=int(not positive),refusals=h['refusals'],actual_before_queries=foot['actual_before_queries'],
        typed_promotions=13,supplied_none_queries=12,supplied_range_queries=1,
        vpcm_promotions=memory_promoted,vpcm_typed_promotions=5,vpcm_supplied_none_queries=5,supplied_range_end_controls=3,
        ending_pairs=sum(c['tail']==c['length']for c in rows[16*group:16*group+16])if positive else 0,
        crossing_pairs=sum(c['tail']<c['length']for c in rows[16*group:16*group+16])if positive else 0,
        header=h,observations=obs,footprint=foot,promotions=promoted,memory=mem,range_controls=supplied,fault_observations=failed,
        architecture='Authenticated unchanged common C native/TF full-state comparison plus complete literal store/register effects. Reader independently binds all generated bytes, actual-before EA/RANGE/NONE, full initialized two-page memory snapshots and failed prefixes; no second full FP replay claim.')


def publish(path,r,private):
    b=r.get('build',{})
    public={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','started_utc',
        'cpu','source','source_unchanged','hardware','totals','reproduce','bounds','cleanup_complete','catalogue')}
    public.update(environment=ENV,private_receipt=fact(private/'receipt.json'),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),
        inputs_sha256=digest(r['inputs_before']),binaries_sha256=digest(r['binaries_before']),
        aliases_sha256=digest(r['aliases']),build_status=b.get('status'),
        tool_versions=b.get('numeric_versions'),tool_hashes={k:{a:v[a]for a in ('bytes','sha256')}
          for k,v in b.get('tools',{}).items()},fixture_build=r.get('fixture_build'),
        cases=r['cases'],registered_controls=registered_summary(r) if 'store_rseq' in r else None,failure_type=r['error'].split(':',1)[0]if r['error']else None,
        final_error_count=len(r['final_errors']),
        command_recipe=dict(product=['sh','tools/page-entry/selected/build.sh'],
          fixture=['sh','tools/page-entry/selected/tests/vmovdqu128_store/build.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group0..7>'],
          native=[['vmovdqu128-store-'+str(g)]for g in range(8)]+[['vmovdqu128-store-0']]*8,
          selectors=[{}]*8+[{'LI2_VM128S_CONTROL':x}for x in FAULT_NAMES]))
    text=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-location guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision) and
         len(os.sched_getaffinity(0))==1,'assertions, exact revision and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-vmovdqu128-store-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-vmovdqu128-store-v1',status='failed',
        scope='Canonical VEX128 Code1840 store/reverse-copy structural family:128 pairs, eight failed writes with complete actual post-memory, exact13 original typed promotions plus5 additional supplied Code1720/NONE promotions, before-frame RANGE16/NONE and supplied overflow controls. Full C architectural oracle with independent structural/memory replay; no real completion or performance claim. Exact retained vl256 row12 (62e1fe286f0f) additionally requires Code1604/FALLTHROUGH/SIMD and supplied NONE in a separate352-byte trailer in every success/fault record. All seven Code1605 records and other remaining refusals stay exact; native Code1604 coverage is separately mandatory in vmovdqu64_family width256. No native coverage or completed operation is inferred from supplied tuples.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_vmovdqu128_store.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(vm256_typed_promotions=0,vm256_supplied_none_queries=0,vpe_typed_promotions=0,vpe_supplied_none_queries=0,pairs=0,new_pairs=0,startup_pairs=0,verified_memory_failures=0,
                    refusals=0,actual_before_queries=0,ending_pairs=0,crossing_pairs=0,typed_promotions=0,supplied_none_queries=0,supplied_range_queries=0,vpcm_typed_promotions=0,vpcm_supplied_none_queries=0,supplied_range_end_controls=0))
    pins,binaries,aliases={},{},{}
    def pin(path):
        lexical=str(Path(path).absolute());p=Path(path).resolve(strict=True);value=fact(p)
        need(lexical not in aliases or aliases[lexical]==str(p),'input resolution changed');aliases[lexical]=str(p)
        need(str(p)not in pins or pins[str(p)]==value,'input changed');pins[str(p)]=value;return p
    def artifact(path):return dict(fact(path),mode=Path(path).stat().st_mode&0o777)
    def binary(path):
        p=Path(path).resolve(strict=True);value=artifact(p)
        need(str(p)not in binaries or binaries[str(p)]==value,'artifact changed');binaries[str(p)]=value;return p
    def closure():
        need(all(fact(p)==v for p,v in pins.items()) and all(artifact(p)==v for p,v in binaries.items()) and
             all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'actual source/artifact/alias closure')
    def run(label,argv,expected=0,profile='native',env=None,record=None):
        closure();native=profile=='native'
        row=dict(name=label,argv=list(map(str,argv)),bounds=PROFILES[profile],profile=profile,
            expected_exit=expected,capture_limit=65536 if native else 4<<20,environment=dict(ENV if env is None else env))
        r['commands'].append(row);capture=native if record is None else record;out,err=invoke(row,private,cpu,record=capture,step=capture)
        need(type(row['exit'])is int and row['exit']==expected,'exact process exit '+label);return row,out,err
    builder=Build(r,private,pin,binary,run)
    states={};r['private_fixture_build']=states
    fixture_outputs=[private/'vmovdqu128-store'/f'group{group}'/f'vmovdqu128-store-{group}'for group in range(8)]
    generated_outputs=[p.parent/name for p in fixture_outputs for name in ('cases.json','cases.inc','common.inc')]
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        r['hardware']=hardware(cpu)
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'],profile='metadata')
        need(not err,'source enumeration stderr')
        for raw in out.split(b'\0'):
            if raw and not os.fsdecode(raw).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(raw))
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        need(fact(pin(FIXTURE/'OUTCOMES.json'))['sha256']==OUTCOMES_SHA,'exact sixteen-command store/fault protocol')
        protocol=decode((FIXTURE/'OUTCOMES.json').read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==16 and [c['exit']for c in commands]==[0]*8+[125]*8 and
          [c['name']for c in commands]==['group'+str(g)for g in range(8)]+list(FAULT_NAMES) and
          [c['argv']for c in commands]==[['vmovdqu128-store-'+str(g)]for g in range(8)]+[['vmovdqu128-store-0']]*8 and
          [c['environment_delta']for c in commands]==[{}]*8+[{'LI2_VM128S_CONTROL':name}for name in FAULT_NAMES] and
          [c['group']for c in commands]==list(range(8))+[0]*8 and
          [c['fault_kind']for c in commands]==[0]*8+list(range(1,9)),
          'closed actual processes, selectors, failed exits and unchanged bounds')
        cases=None
        products=builder.prepare();output=private/'vmovdqu128-store';output.mkdir()
        recipe_path=pin(FIXTURE/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        generators=recipe(recipe_path,'"$python_bin"');need(len(generators)==2,'exact two source generators')
        r['fixture_build']={};samples={};paths={}
        for group in range(8):
            name=f'vmovdqu128-store-{group}';group_output=output/('group'+str(group));group_output.mkdir()
            values={'$cc_bin':builder.tools['cc'],'$python_bin':builder.tools['python'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
                '$parent_dir':SELECTED.parent,'$decoder_archive':products['archive'],'$output_dir':group_output,'$group':group}
            for gi,words in enumerate(generators):
                _,gout,gerr=run(name+'-generate-'+str(gi),expand(words,values),profile='metadata',env=builder.environment)
                need(not gerr,'exact generator stderr')
                observed=decode(gout)
                if gi==0:need(observed=={'cases.json':GENERATED_JSON,'cases.inc':GENERATED_C},'exact complete generated literal case artifacts')
                else:need(observed==GENERATED_COMMON,'exact full common adapter bytes')
            for generated in ('cases.json','cases.inc','common.inc'):binary(group_output/generated);pin(group_output/generated)
            actual_cases=catalogue(group_output/'cases.json',group_output/'cases.inc')
            need(cases is None or cases==actual_cases,'identical eight generated case tables');cases=actual_cases
            r['catalogue']=dict(source=GENERATED_JSON,compiled=GENERATED_C,rows_sha256=digest(cases),new_pairs=128)
            argv=expand(lines[0],values);path=group_output/name;paths[name]=path
            need(argv[-2:]==['-o',str(path)] and all(x in argv for x in ('-O2','-g','-nostdlib','-static','-no-pie','-Werror')),
                 'exact optimized bounded fixture recipe')
            sources=[SELECTED/'step_owner.c',SELECTED/'lifecycle_loader.c',SELECTED/'tests/generic/tf_controls.c',FIXTURE/'fixture.c',SELECTED/'tests/vmovdqu64/fixture.S']
            state={};states[name]=state
            headers(name+'-headers',argv,list(map(str,sources)),products['archive'],builder,pin,aliases,run,state)
            run(name+'-link',argv,profile='fixture_link',env=builder.environment);binary(path);state['artifact']=artifact(path)
            state['elf']=plain_executable(path)
            _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
            need(out==err==b'','no unresolved fixture imports')
            _,out,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual symbol inspection stderr');roots={'vm256_promotions','vpe_promotions','samples','negative_sample','result','refused_last','vm64_promotions','vpb_observations','v64_fault','vpc_queries','v128_promotions','vpcm_promotions','store_memory','store_ranges'}
            symbols={};counts={k:0 for k in roots};_,_,segments=elf(path)
            for line in out.decode().splitlines():
                w=line.split()
                if w and w[-1]in roots:counts[w[-1]]+=1
                if len(w)!=4 or w[-1]not in roots:continue
                at,n,kind,key=w;at,n=int(at,16),int(n,16)
                need(kind in ('b','B','d','D') and key not in symbols and n>0 and
                    sum(s[0]==1 and s[1]==6 and s[3]<=at<at+n<=s[3]+s[6]for s in segments)==1,'whole unique actual writable NX record symbol')
                symbols[key]=dict(address=at,bytes=n)
            need(set(symbols)==roots and all(n==1 for n in counts.values()),'all required record symbols')
            intervals=sorted((v['address'],v['address']+v['bytes'])for v in symbols.values())
            need(all(a[1]<=b[0]for a,b in zip(intervals,intervals[1:])),'all record objects disjoint')
            state['symbols']=symbols;sample=symbols['negative_sample']['bytes']
            need(symbols['samples']['bytes']==21*sample and symbols['result']['bytes']==136 and
                symbols['vpe_promotions']['bytes']==1216 and symbols['vm256_promotions']['bytes']==352 and symbols['vm64_promotions']['bytes']==2080 and symbols['refused_last']['bytes']==40 and symbols['vpb_observations']['bytes']==5000 and symbols['v64_fault']['bytes']==96 and
                symbols['vpc_queries']['bytes']==10304 and symbols['v128_promotions']['bytes']==3808 and symbols['vpcm_promotions']['bytes']==1504 and
                symbols['store_memory']['bytes']==MEMORY_BYTES and symbols['store_ranges']['bytes']==800 and
                352+1216+2080+136+22*sample+40+5000+96+10304+3808+MEMORY_BYTES+800+1504<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=352+1216+2080+136+22*sample+40+5000+96+10304+3808+MEMORY_BYTES+800+1504,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[paths[expected['argv'][0]]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases)
            need(value['operation']==('completed'if expected['exit']==0 else 'failed_memory_write'),
                 'no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(vm256_typed_promotions=16,vm256_supplied_none_queries=16,vpe_typed_promotions=16,vpe_supplied_none_queries=16,pairs=136,new_pairs=128,startup_pairs=16,verified_memory_failures=8,
            refusals=2176,actual_before_queries=272,ending_pairs=85,crossing_pairs=43,typed_promotions=208,
            supplied_none_queries=192,supplied_range_queries=16,vpcm_typed_promotions=80,vpcm_supplied_none_queries=80,supplied_range_end_controls=48) and
            len(r['cases'])==16 and all(c['status']=='accepted_observation'for c in r['cases']),
            'eight complete17-pair cohorts and eight genuine failed writes')
        registered_controls(builder,products,private,pin,binary,run,r,cpu)
        need(r['store_rseq']['status']=='passed_three_store_controls','all actual registered store guards')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        for path in generated_outputs:
            try:
                if path.exists()or path.is_symlink():binary(path)
            except BaseException as exc:r['final_errors'].append('generated artifact closure: '+repr(exc))
        for path in fixture_outputs:
            try:
                if path.exists()or path.is_symlink():
                    state=states.setdefault(path.name,{})
                    state['artifact_after']=artifact(path);binary(path)
            except BaseException as exc:r['final_errors'].append('fixture artifact closure: '+str(path)+': '+repr(exc))
        for row in r['commands']:
            for capture in row.get('captures',{}).values():
                try:
                    path=private/capture['file'];need(path.parent==private and fact(path)=={k:capture[k]for k in ('bytes','sha256')},'retained capture closure');binary(path)
                except BaseException as exc:r['final_errors'].append('capture closure: '+repr(exc))
        r['inputs_before'],r['binaries_before'],r['aliases']=pins,binaries,aliases
        for name,before,observe in (('inputs_after',pins,fact),('binaries_after',binaries,artifact)):
            after=r[name]={}
            for p,value in before.items():
                try:after[p]=observe(p);need(after[p]==value,'final exact identity')
                except BaseException as exc:r['final_errors'].append(p+': '+repr(exc))
        try:closure()
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        try:r['source_unchanged']=source()==r['source'];need(r['source_unchanged'],'source closure')
        except BaseException as exc:r['final_errors'].append('source closure: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')and not x.get('timed_out')and not x.get('error')and
            not x.get('cleanup_errors')and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']or r['build']['status']!='passed':r['status']='failed'
        save(private/'receipt.json',r);publish(public,r,private)
    print(json.dumps(dict(status=r['status'],totals=r['totals'],receipt=str(public.relative_to(ROOT)))))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
