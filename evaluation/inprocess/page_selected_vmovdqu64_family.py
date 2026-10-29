#!/usr/bin/env python3
"""Canonical EVEX512 W1 VMOVDQU64 load/register-copy; full-state structural family oracle."""
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
from page_selected_components import plain_executable
from page_selected_register_time_build import recipe,expand,headers
from page_selected_register_time_compare import decode
from page_selected_vmovdqu64_promotions import PROMOTED,promotions
from page_selected_vmovdqu64_256_promotions import promotions as promotions256

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/vmovdqu64_family'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='8e6757b01a1bb804f9562837cb27d939adbb47db89cf444582cc440526de2c9e'
CASES_SHA='f1dfbd43f81757bd583589dd71be3cdd8d25b588d912fdfefa9f5b7623d296eb'
CASES_C_SHA='9a4c5c51a1ee72a2cfd0128f0af960c4c6c7781fc3d00b8d03f000a36e811259'
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def configuration(vector_bits):
    need(type(vector_bits)is int and vector_bits in (512,256),'exact requested VMOVDQU64 width')
    if vector_bits==512:
        return dict(code=1605,width=64,prefix=32,p2=0x48,cpu_mask=0x40010000,
            obs_magic=0x314636343156324c,query_magic=0x314736343156324c,refusals=72,
            cases_json='cases.json',cases_inc='cases.inc',cases_sha=CASES_SHA,cases_c_sha=CASES_C_SHA,
            outcomes='OUTCOMES.json',outcomes_sha=OUTCOMES_SHA,build='build.sh',
            name='vmovdqu64-family',profile='page-selected-vmovdqu64-family-v1')
    return dict(code=1604,width=32,prefix=16,p2=0x28,cpu_mask=0xc0010000,
        obs_magic=0x314632333156324c,query_magic=0x314732333156324c,refusals=97,
        cases_json='cases256.json',cases_inc='cases256.inc',cases_sha='22a97810689ed0a8503fa6226d686e2fee09f5c27f3812b25396d528dc007b5b',cases_c_sha='24ef9eeb99c07aba087db74dddad2ef26d13ad42a4fd494ee42ce3267a8310ac',
        outcomes='OUTCOMES256.json',outcomes_sha='c8b2905263bcd5068199acb4ae91f8688503bb49e4465e0b7d73f3efae432de1',build='build256.sh',
        name='vmovdqu64-256-family',profile='page-selected-vmovdqu64-256-family-v1')


def catalogue(vector_bits=512):
    cfg=configuration(vector_bits)
    need(fact(FIXTURE/cfg['cases_json'])['sha256']==cfg['cases_sha'] and
         fact(FIXTURE/cfg['cases_inc'])['sha256']==cfg['cases_c_sha'],'exact literal JSON and compiled C catalogues')
    table=decode((FIXTURE/cfg['cases_json']).read_bytes());rows=table['cases']
    need((table['schema'],table['code'],table['groups'],table['pairs_per_group'],table['total_cases'])==
         (1,cfg['code'],10,16,160) and len(rows)==160,'closed ten-cohort structure')
    need(table['patterns_hex']==[bytes(cfg['width']).hex(),bytes([255]*cfg['width']).hex(),
         bytes((0x43+17*i)&255 for i in range(cfg['width'])).hex()],'independent complete requested-width memory literals')
    structural='promotion'if vector_bits==512 else 'structural'
    sections={k:[r for r in rows if r['section']==k]for k in ('register','base','indexed',structural,'fetch','extra')}
    need({k:len(v)for k,v in sections.items()}==dict(register=64,base=16,indexed=16,fetch=42,extra=15,**{structural:7}),
         'every declared structural section retained')
    need([(r['src_reg'],r['dest'])for r in sections['register']]==
         [(i,(i+13)%32)for i in range(32)]+[(i,i)for i in range(32)],'all32 sources/destinations and self-copies')
    need([r['base']for r in sections['base']]==list(range(16)),'all sixteen GPR bases including actual RSP')
    need({r['index']for r in sections['indexed']}==set(range(16))-{4} and
         {r['scale']for r in sections['indexed']}=={1,2,4,8},'all usable indices and four scales')
    need([r['hex']for r in sections[structural]]==[h if vector_bits==512 else h[:6]+'28'+h[8:]for _,h in PROMOTED],
         'each exact closed structural byte row has its own native pair')
    need([(r['length'],r['tail'])for r in sections['fetch']]==
         [(length,tail)for length in (6,7,8,10,11)for tail in range(1,length+1)],
         'every fetch tail at every admitted instruction length')
    if vector_bits==512:
        need(sections['extra'][0]['hex']=='62e1fe486f5701' and
             (sections['extra'][0]['dest'],sections['extra'][0]['base'],sections['extra'][0]['displacement'])==(18,7,64),
             'literal real libc load uses compressed disp8*64')
    else:
        need([r['hex']for r in sections['extra'][:4]]==['62e1fe286f0f','62e1fe286f5601','62e1fe286f5e02','62e1fe286f6603'] and
             sections[structural][4]['hex']=='62e1fe286f0e',
             'exact old negative, real failed libc RSI load and three compressed disp8*32 successors')
    for i,r in enumerate(rows):
        b=bytes.fromhex(r['hex']);n=len(b)
        need((r['case_index'],r['group'],r['slot'],r['length'])==(i,i//16,i%16,n) and
             n in (6,7,8,10,11) and 1<=r['tail']<=n and r['pattern']in (0,1,2),'literal identity/fetch geometry')
        need(b[0]==0x62 and b[1]&15==1 and b[2:5]==bytes((0xfe,cfg['p2'],0x6f)),
             'EVEX map1/W1/reserved vvvv/F3/L512/no mask/no zeroing/no broadcast/reserved Vprime')
        R=(~b[1]>>7)&1;X=(~b[1]>>6)&1;B=(~b[1]>>5)&1;Rp=(~b[1]>>4)&1
        at=6;m=b[5];mod=m>>6;rm=m&7;dest=((m>>3)&7)+8*R+16*Rp
        src=base=index=None;scale=1;disp=0;disp_bytes=0;disp_at=None;rip=False
        if mod==3:src=rm+8*B+16*X
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
                if disp_bytes==1:disp*=cfg['width']
        need(at==n and (dest,src,base,index,scale,disp,disp_bytes,disp_at)==
             (r['dest'],r['src_reg'],r['base'],r['index'],r['scale'],r['displacement'],r['disp_bytes'],r['disp_offset']),
             'independent EVEX extension/ModRM/SIB/disp8 scaling interpretation')
        kind='register'if src is not None else 'rip'if rip else 'absolute'if base is None else 'stack'if base==4 else 'data'
        need(r['memory_kind']==kind and index!=4,'literal memory role; RSP is not an index')
        if kind=='rip':need(disp in (-256,256),'literal RIP data separated from instruction and endpoint')
        if kind=='absolute':need(r['absolute_target']==0x20000100 and
            ((r['index_value']or 0)*scale+disp)&MASK==0x20000100,'literal guarded low operand')
        if kind=='stack':need(base==4 and index is None and not disp,'actual subject RSP remains unchanged')
        if kind=='data':need(r['operand_offset']in (0,257,4096-cfg['width']) and
            (index is None or base!=index),'literal64-byte data and independent base/index')
    return rows


def observations(data, group, header, fault_kind=0, vector_bits=512):
    cfg=configuration(vector_bits)
    need(len(data) == 5000, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (cfg['obs_magic'], 1, 5000, group, 1 if fault_kind else 17, header['xcr0'], header['xsave_bytes']),
         'exact trailer identity and observed input joins')
    tuples = [struct.unpack_from('<6Q', data, 64+48*i) for i in range(68)]
    basic, components = tuples[:4], tuples[4:]
    need([x[:2] for x in basic] == [(0, 0), (1, 0), (7, 0), (13, 0)] and
         all(all(v < 1 << 32 for v in q) for q in tuples), 'actual CPUID tuple identities and register width')
    need(basic[0][2] >= 13 and basic[1][4] & 0x1c000000 == 0x1c000000 and
         basic[2][3] & cfg['cpu_mask'] == cfg['cpu_mask'], 'actual XSAVE/OSXSAVE/AVX/AVX512F/BW prerequisites')
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
    need(ids == ([0]*19 if fault_kind else [0]+list(range(9000+16*group, 9016+16*group))+[0]*2),
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


def fault_observations(data, kind, header, vector_bits=512):
    cfg=configuration(vector_bits)
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
         row['prefix_bytes'] == (cfg['prefix'] if kind in (2,4) else 0) and
         row['operand'] == row['address']-row['prefix_bytes'], 'actual fault operand/guard geometry')
    need(all(v & 0xe7 == 0xe7 and not v & ~header['xcr0'] for v in raw[6:]) and
         len(set(raw[6:10])) == len(set(raw[10:])) == 1,
         'fault native/owner kernel BVs and live BVs unchanged separately')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), **row)


def queries(data,header,rows,group,kind,vector_bits=512):
    cfg=configuration(vector_bits)
    need(len(data)==10304,'complete actual-before query and EA trailer')
    count=2 if kind else 32
    need(struct.unpack_from('<8Q',data)==(cfg['query_magic'],1,10304,group,count,0,0,0),
         'exact query identity/count and no fabricated control results')
    values=[];kinds={'register':0,'data':1,'stack':2,'rip':3,'absolute':4}
    for index in range(count//2):
        pair=[];case=rows[(64 if kind<=2 else 80)if kind else 16*group+index]
        for lane in (0,1):
            at=64+256*(2*index+lane)
            attempted,result,identity,actual_lane=struct.unpack_from('<4Q',data,at)
            before=struct.unpack_from('<18Q',data,at+32)
            value=struct.unpack_from('<4Q4I',data,at+176)
            ea,obj,offset,role=struct.unpack_from('<4Q',data,at+224)
            pc,next_pc,first,end,abi,policy,code,length=value
            need((attempted,result,identity,actual_lane,first,end,abi,policy,code,length)==
                 (1,0,9000+case['case_index'],lane,0,0,1,1,cfg['code'],case['length']) and
                 pc>4096 and pc%4096==4096-case['tail'] and next_pc==pc+length,
                 'actual original-PC NONE query and exact source fetch geometry')
            if case['src_reg']is not None:expected=0
            elif case['memory_kind']=='rip':expected=(next_pc+case['displacement'])&MASK
            else:expected=((before[case['base']]if case['base']is not None else 0)+
                (before[case['index']]*case['scale']if case['index']is not None else 0)+case['displacement'])&MASK
            need(ea==expected and role==kinds[case['memory_kind']],'EA independently reconstructed from actual before-frame registers')
            if role==0:need((ea,obj,offset)==(0,0,0),'register-copy has no invented memory operand')
            else:
                need(obj>4096 and obj%4096==0 and ea==obj+offset,'actual operand/object join')
                if kind:need(role==1 and offset==(4096-cfg['prefix'] if kind in (2,4)else 4096),'real failed operand boundary')
                elif role==1:need(offset==case['operand_offset'],'literal guarded data offset')
                elif role==2:need(offset==4096 and ea==before[4],'real subject stack pointer, no alternate stack seed')
                elif role==3:need(obj==pc-(4096-case['tail']) and offset==4096-case['tail']+length+case['displacement'],'literal source-image RIP operand')
                else:need(obj==0x20000000 and ea==case['absolute_target']==0x20000100,'actual collision-refusing low mapping')
                if case['index']is not None:need(before[case['index']]==case['index_value'],'declared index input retained in actual frame')
            pair.append(dict(before=list(before),value=list(value),ea=[ea,obj,offset,role]))
        need(pair[0]==pair[1],'complete native/TF actual-before and effective-address agreement')
        values.append(pair)
    need(not any(data[64+256*count:]),'unattempted query slots remain zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),actual_before_queries=count,
                values_sha256=digest(values),memory_write_ranges=0)


def record(data,expected,sample_bytes,rows,vector_bits=512):
    cfg=configuration(vector_bits)
    need(352<len(data)<16<<20,'complete mandatory Code1604 promotion below original cap')
    new_promoted=promotions256(data[-352:]);data=data[:-352]
    need(2080<len(data)<(16<<20),'complete typed-promotion trailer within unchanged cap')
    promoted=promotions(data[-2080:]);data=data[:-2080]
    need(len(data)>=136,'complete retained header')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()) and h['refusals']==cfg['refusals'],
         'exact finite outcome; failed operations stay failed')
    need(h['sample_bytes']==sample_bytes>0 and
         len(data)==136+22*sample_bytes+40+5000+96+10304<16<<20,'actual ELF-bound complete record extent')
    need(576<=h['xsave_bytes']<=65536 and h['xcr0']&3==3,'qualified XSAVE extent')
    group=expected['group'];kind=expected['fault_kind'];positive=kind==0
    need(h['pairs']==17 and h['completed']==(17 if positive else 1),'complete expected prefix; fault is never completion')
    if positive:
        need(not any(data[136+17*sample_bytes:136+22*sample_bytes]),'four unused slots and negative sample remain zero')
    else:
        need(not any(data[136+sample_bytes:136+21*sample_bytes]),'unstarted positive slots remain zero')
    obs=observations(data[-15400:-10400],group,h,kind,vector_bits)
    failed=fault_observations(data[-10400:-10304],kind,h,vector_bits)
    footprint=queries(data[-10304:],h,rows,group,kind,vector_bits)
    return dict(operation='completed'if positive else 'failed_memory_read',
        promotions=promoted,typed_promotions=7,supplied_none_queries=7,
        vm256_promotions=new_promoted,vm256_typed_promotions=1,vm256_supplied_none_queries=1,vector_bits=vector_bits,
        pairs=17 if positive else 0,new_pairs=16 if positive else 0,startup_pairs=1,
        verified_memory_failures=int(not positive),refusals=h['refusals'],actual_before_queries=footprint['actual_before_queries'],
        ending_pairs=sum(c['tail']==c['length']for c in rows[16*group:16*group+16])if positive else 0,
        crossing_pairs=sum(c['tail']<c['length']for c in rows[16*group:16*group+16])if positive else 0,
        header=h,observations=obs,fault_observations=failed,footprint=footprint,
        architecture='Authenticated C oracle compares complete native/TF state,literal memory/register loads and complete all512 selected-destination bits (upper256 exactly zero in VL256), including actual faults. Reader independently checks complete ELF-sized records, CPUID, prefix and actual-before queries; it is not a second full architectural replay.')


def publish(path,r,private):
    cfg=configuration(r['vector_bits']);b=r.get('build',{})
    public={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','started_utc',
        'cpu','source','source_unchanged','hardware','totals','reproduce','bounds','cleanup_complete','catalogue','vector_bits')}
    public.update(environment=ENV,private_receipt=fact(private/'receipt.json'),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),
        inputs_sha256=digest(r['inputs_before']),binaries_sha256=digest(r['binaries_before']),
        aliases_sha256=digest(r['aliases']),build_status=b.get('status'),
        tool_versions=b.get('numeric_versions'),tool_hashes={k:{a:v[a]for a in ('bytes','sha256')}
          for k,v in b.get('tools',{}).items()},fixture_build=r.get('fixture_build'),
        cases=r['cases'],failure_type=r['error'].split(':',1)[0]if r['error']else None,
        final_error_count=len(r['final_errors']),
        command_recipe=dict(product=['sh','tools/page-entry/selected/build.sh'],
          fixture=['sh','tools/page-entry/selected/tests/vmovdqu64_family/'+cfg['build'],'<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group0..9>'],
          native=[[cfg['name']+'-'+str(g)]for g in range(10)]+[[cfg['name']+'-0']]*4,
          selectors=[{}]*10+[{'LI2_VM64F_CONTROL':x}for x in ('full-read-fault','cross-read-fault','indexed-full-read-fault','indexed-cross-read-fault')]))
    text=json.dumps(public,sort_keys=True,indent=2,allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-location guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--vector-bits',type=int,choices=(512,256),default=512);args=ap.parse_args()
    cfg=configuration(args.vector_bits)
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision) and
         len(os.sched_getaffinity(0))==1,'assertions, exact revision and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-'+cfg['name']+'-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile=cfg['profile'],vector_bits=args.vector_bits,status='failed',
        scope='Canonical EVEX512.W1 Code1605 load/register family.160 structural pairs in10 cohorts, all32 ZMM source/destination roles, all16 bases/all15 indices/scales, original64-bit ModRM/SIB/RIP/disp8*64 and all42 length/tail combinations. Complete unchanged native/TF state/source/stack/data/flags comparisons; four genuine full/cross32-byte ordinary/indexed read failures. All25 remaining original negative neighbors and47 common refusals remain, seven exact old rows remain mandatory Code1605/NONE promotions and native pairs; the exact former vl256 negative is a separate mandatory Code1604/NONE promotion with native coverage in the separately required256 cohort. No other width/mask/store/prefix, exhaustive numerical address, application completion or performance claim.'if args.vector_bits==512 else 'Canonical EVEX256.W1 Code1604 load/register family.160 structural pairs in10 cohorts, all32 YMM source/destination roles/self-copies, all16 bases/all15 indices/scales, original64-bit ModRM/SIB/RIP/disp8*32 and all42 length/tail combinations. Complete unchanged native/TF state/source/stack/data/flags comparisons; exact low256 result and mandatory zero upper256 destination bits. Four genuine full/cross16-byte ordinary/indexed failed reads retain full original state. All47 common and25 remaining original neighbors plus25 VL256 neighbors refuse; seven prior Code1605 and one Code1604 positive promotions remain mandatory. No other width/mask/store/prefix, numerical-address exhaustiveness, application completion or performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_vmovdqu64_family.py','--expect-revision',args.expect_revision]+([]if args.vector_bits==512 else ['--vector-bits','256']),
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(pairs=0,new_pairs=0,startup_pairs=0,verified_memory_failures=0,
                    refusals=0,actual_before_queries=0,ending_pairs=0,crossing_pairs=0,typed_promotions=0,supplied_none_queries=0,vm256_typed_promotions=0,vm256_supplied_none_queries=0))
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
    def run(label,argv,expected=0,profile='native',env=None):
        closure();native=profile=='native'
        row=dict(name=label,argv=list(map(str,argv)),bounds=PROFILES[profile],profile=profile,
            expected_exit=expected,capture_limit=65536 if native else 4<<20,environment=dict(ENV if env is None else env))
        r['commands'].append(row);out,err=invoke(row,private,cpu,record=native,step=native)
        need(type(row['exit'])is int and row['exit']==expected,'exact process exit '+label);return row,out,err
    builder=Build(r,private,pin,binary,run)
    states={};r['private_fixture_build']=states
    fixture_outputs=[private/cfg['name']/(cfg['name']+'-'+str(group))for group in range(10)]
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
        need(fact(pin(FIXTURE/cfg['outcomes']))['sha256']==cfg['outcomes_sha'],'exact fourteen-command family/fault protocol')
        protocol=decode((FIXTURE/cfg['outcomes']).read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==14 and [c['exit']for c in commands]==[0]*10+[125]*4 and
          [c['name']for c in commands]==['group'+str(g)for g in range(10)]+['full-read-fault','cross-read-fault','indexed-full-read-fault','indexed-cross-read-fault'] and
          [c['argv']for c in commands]==[[cfg['name']+'-'+str(g)]for g in range(10)]+[[cfg['name']+'-0']]*4 and
          [c['environment_delta']for c in commands]==[{}]*10+[{'LI2_VM64F_CONTROL':name}for name in ('full-read-fault','cross-read-fault','indexed-full-read-fault','indexed-cross-read-fault')] and
          [c['group']for c in commands]==list(range(10))+[0]*4 and
          [c['fault_kind']for c in commands]==[0]*10+[1,2,3,4],
          'closed actual processes, selectors, failed exits and unchanged bounds')
        cases=catalogue(args.vector_bits);r['catalogue']=dict(source=fact(FIXTURE/cfg['cases_json']),compiled=fact(FIXTURE/cfg['cases_inc']),rows_sha256=digest(cases),new_pairs=160)
        products=builder.prepare();output=private/cfg['name'];output.mkdir()
        recipe_path=pin(FIXTURE/cfg['build']);lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(10):
            name=cfg['name']+'-'+str(group);values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
                '$parent_dir':SELECTED.parent,'$decoder_archive':products['archive'],'$output_dir':output,'$group':group}
            argv=expand(lines[0],values);path=output/name
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
            need(not err,'actual symbol inspection stderr');roots={'samples','negative_sample','result','refused_last','vpb_observations','v64_fault','vpc_queries','vm64_promotions','vm256_promotions'}
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
                symbols['refused_last']['bytes']==40 and symbols['vpb_observations']['bytes']==5000 and symbols['v64_fault']['bytes']==96 and
                symbols['vpc_queries']['bytes']==10304 and symbols['vm64_promotions']['bytes']==2080 and symbols['vm256_promotions']['bytes']==352 and 136+22*sample+40+5000+96+10304+2080+352<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=136+22*sample+40+5000+96+10304+2080+352,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases,args.vector_bits)
            need(value['operation']==('completed'if expected['exit']==0 else 'failed_memory_read'),
                 'no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(pairs=170,new_pairs=160,startup_pairs=14,verified_memory_failures=4,
            refusals=14*cfg['refusals'],actual_before_queries=328,ending_pairs=123,crossing_pairs=37,typed_promotions=98,supplied_none_queries=98,vm256_typed_promotions=14,vm256_supplied_none_queries=14) and
            len(r['cases'])==14 and all(c['status']=='accepted_observation'for c in r['cases']),
            'ten complete17-pair cohorts and four genuine failed-read controls')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
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
