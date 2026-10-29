#!/usr/bin/env python3
"""Canonical EVEX512 W1 VMOVDQA64 load/register-copy; full-state structural family oracle."""
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

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/vmovdqa64_family'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='7b374e73bff6de0b0a308d1ba3ed468693e15594a8fe830127c854d5487fb283'
CASES_SHA='a9bf4c9ad25ba467e016528b2d0dbb016af05878e041995610091c5e8d9138f2'
CASES_C_SHA='069d35ae2d5eee62b5f8fba68773a9af686c8f14b551a5d0f809221e62655ff3'
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def catalogue():
    need(fact(FIXTURE/'cases.json')['sha256']==CASES_SHA and
         fact(FIXTURE/'cases.inc')['sha256']==CASES_C_SHA,'exact literal JSON and compiled C catalogues')
    table=decode((FIXTURE/'cases.json').read_bytes());rows=table['cases']
    need((table['schema'],table['code'],table['groups'],table['pairs_per_group'],table['total_cases'])==
         (1,1596,10,16,160) and len(rows)==160,'closed ten-cohort structure')
    need(table['patterns_hex']==[bytes(64).hex(),bytes([255]*64).hex(),
         bytes((0x43+17*i)&255 for i in range(64)).hex()],'independent complete 64-byte memory literals')
    sections={k:[r for r in rows if r['section']==k]for k in ('register','base','indexed','palette','fetch','extra')}
    need({k:len(v)for k,v in sections.items()}==dict(register=64,base=16,indexed=16,palette=7,fetch=42,extra=15),
         'every declared structural section retained')
    need([(r['src_reg'],r['dest'])for r in sections['register']]==
         [(i,(i+13)%32)for i in range(32)]+[(i,i)for i in range(32)],'all32 sources/destinations and self-copies')
    need([r['base']for r in sections['base']]==list(range(16)),'all sixteen GPR bases including actual RSP')
    need({r['index']for r in sections['indexed']}==set(range(16))-{4} and
         {r['scale']for r in sections['indexed']}=={1,2,4,8},'all usable indices and four scales')
    need([r['hex']for r in sections['palette']]==['62e1fd486f6f04', '62e1fd486f7705', '62a1fd486ffd', '6221fd486fc6', '62e1fd486f0e', '62e1fd486f17', '62e1fd486fcf'],
         'four actual libc instructions and three fixed operand-role analogues')
    need([(r['length'],r['tail'])for r in sections['fetch']]==
         [(length,tail)for length in (6,7,8,10,11)for tail in range(1,length+1)],
         'every fetch tail at every admitted instruction length')
    need(sections['extra'][0]['hex']=='62e1fd486f5701' and
         (sections['extra'][0]['dest'],sections['extra'][0]['base'],sections['extra'][0]['displacement'])==(18,7,64),
         'literal real libc load uses compressed disp8*64')
    for i,r in enumerate(rows):
        b=bytes.fromhex(r['hex']);n=len(b)
        need((r['case_index'],r['group'],r['slot'],r['length'])==(i,i//16,i%16,n) and
             n in (6,7,8,10,11) and 1<=r['tail']<=n and r['pattern']in (0,1,2),'literal identity/fetch geometry')
        need(b[0]==0x62 and b[1]&15==1 and b[2:5]==bytes.fromhex('fd486f'),
             'EVEX map1/W1/reserved vvvv/66/L512/no mask/no zeroing/no broadcast/reserved Vprime')
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
                if disp_bytes==1:disp*=64
        need(at==n and (dest,src,base,index,scale,disp,disp_bytes,disp_at)==
             (r['dest'],r['src_reg'],r['base'],r['index'],r['scale'],r['displacement'],r['disp_bytes'],r['disp_offset']),
             'independent EVEX extension/ModRM/SIB/disp8 scaling interpretation')
        kind='register'if src is not None else 'rip'if rip else 'absolute'if base is None else 'stack'if base==4 else 'data'
        need(r['memory_kind']==kind and index!=4,'literal memory role; RSP is not an index')
        if kind=='rip':need(disp in (-256,256),'literal RIP data separated from instruction and endpoint')
        if kind=='absolute':need(r['absolute_target']==0x20000100 and
            ((r['index_value']or 0)*scale+disp)&MASK==0x20000100,'literal guarded low operand')
        if kind=='stack':need(base==4 and index is None and not disp,'actual subject RSP remains unchanged')
        if kind=='data':need(r['operand_offset']in (0,256,4032) and
            (index is None or base!=index),'literal64-byte data and independent base/index')
    return rows


def observations(data, group, header, fault_kind=0):
    need(len(data) == 5000, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (0x314641343156324c, 1, 5000, group, 1 if fault_kind else 17, header['xcr0'], header['xsave_bytes']),
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
    need(ids == ([0]*19 if fault_kind else [0]+list(range(12000+16*group, 12016+16*group))+[0]*2),
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
         row['prefix_bytes'] == (32 if kind in (2,4) else 0) and
         row['operand'] == row['address']-row['prefix_bytes'], 'actual fault operand/guard geometry')
    need(all(v & 0xe7 == 0xe7 and not v & ~header['xcr0'] for v in raw[6:]) and
         len(set(raw[6:10])) == len(set(raw[10:])) == 1,
         'fault native/owner kernel BVs and live BVs unchanged separately')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), **row)


def queries(data,header,rows,group,kind):
    need(len(data)==10304,'complete actual-before query and EA trailer')
    count=2 if kind else 32
    need(struct.unpack_from('<8Q',data)==(0x314741343156324c,1,10304,group,count,27,0,0),
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
                 (1,0,12000+case['case_index'],lane,0,0,1,1,1596,case['length']) and
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
                if kind:need(role==1 and offset==(4064 if kind in (2,4)else 4096),'real failed operand boundary')
                elif role==1:need(offset==case['operand_offset'],'literal guarded data offset')
                elif role==2:need(offset==4096 and ea==before[4],'real subject stack pointer, no alternate stack seed')
                elif role==3:need(obj==pc-(4096-case['tail']) and offset==4096-case['tail']+length+case['displacement'],'literal source-image RIP operand')
                else:need(obj==0x20000000 and ea==case['absolute_target']==0x20000100,'actual collision-refusing low mapping')
                if case['index']is not None:need(before[case['index']]==case['index_value'],'declared index input retained in actual frame')
                need(ea%64==(32 if kind in(2,4)else 0),'exact actual operand alignment or deliberate misalignment')
            pair.append(dict(before=list(before),value=list(value),ea=[ea,obj,offset,role]))
        need(pair[0]==pair[1],'complete native/TF actual-before and effective-address agreement')
        values.append(pair)
    need(not any(data[64+256*count:]),'unattempted query slots remain zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),actual_before_queries=count,
                values_sha256=digest(values),memory_write_ranges=0)


def record(data,expected,sample_bytes,rows):
    need(2080<len(data)<(16<<20),'complete typed-promotion trailer within unchanged cap')
    promoted=promotions(data[-2080:]);data=data[:-2080]
    need(len(data)>=136,'complete retained header')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()),'exact finite outcome; failed operations stay failed')
    need(h['sample_bytes']==sample_bytes>0 and
         len(data)==136+22*sample_bytes+40+5000+96+10304<16<<20,'actual ELF-bound complete record extent')
    need(576<=h['xsave_bytes']<=65536 and h['xcr0']&3==3,'qualified XSAVE extent')
    group=expected['group'];kind=expected['fault_kind'];positive=kind==0
    need(h['pairs']==17 and h['completed']==(17 if positive else 1),'complete expected prefix; fault is never completion')
    if positive:
        need(not any(data[136+17*sample_bytes:136+22*sample_bytes]),'four unused slots and negative sample remain zero')
    else:
        need(not any(data[136+sample_bytes:136+21*sample_bytes]),'unstarted positive slots remain zero')
    obs=observations(data[-15400:-10400],group,h,kind)
    failed=fault_observations(data[-10400:-10304],kind,h)
    footprint=queries(data[-10304:],h,rows,group,kind)
    return dict(operation='completed'if positive else ('failed_alignment'if kind in(2,4)else 'failed_memory_read'),
        promotions=promoted,typed_promotions=7,supplied_none_queries=7,
        pairs=17 if positive else 0,new_pairs=16 if positive else 0,startup_pairs=1,
        verified_memory_failures=int(not positive),refusals=h['refusals'],actual_before_queries=footprint['actual_before_queries'],
        ending_pairs=sum(c['tail']==c['length']for c in rows[16*group:16*group+16])if positive else 0,
        crossing_pairs=sum(c['tail']<c['length']for c in rows[16*group:16*group+16])if positive else 0,
        header=h,observations=obs,fault_observations=failed,footprint=footprint,
        architecture='Authenticated C oracle compares complete native/TF state,literal memory/register loads and complete all512 selected-destination bits, including actual faults. Reader independently checks complete ELF-sized records, CPUID, prefix and actual-before queries; it is not a second full architectural replay.')


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
        cases=r['cases'],failure_type=r['error'].split(':',1)[0]if r['error']else None,
        final_error_count=len(r['final_errors']),
        command_recipe=dict(product=['sh','tools/page-entry/selected/build.sh'],
          fixture=['sh','tools/page-entry/selected/tests/vmovdqa64_family/build.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group0..9>'],
          native=[['vmovdqa64-family-'+str(g)]for g in range(10)]+[['vmovdqa64-family-0']]*4,
          selectors=[{}]*10+[{'LI2_VQA64F_CONTROL':x}for x in ('full-read-fault','alignment-fault','indexed-full-read-fault','indexed-alignment-fault')]))
    text=json.dumps(public,sort_keys=True,indent=2,allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-location guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision) and
         len(os.sched_getaffinity(0))==1,'assertions, exact revision and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-vmovdqa64-family-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-vmovdqa64-family-v1',status='failed',
        scope='Canonical unmasked EVEX512.W1 VMOVDQA64 Code1596 aligned load/register family;160 pairs and four genuine failed operations. Two aligned unavailable-page #PF14/error4 controls, two misaligned crossing ordinary/indexed #GP13/error0 controls. Every old supplied neighbor retained, with existing VMOVDQU64 typed promotions unchanged. All32 ZMM sources/destinations,16 bases,15 usable indices,4 scales and all42 instruction length/fetch-tail combinations. Full native/TF/GPR/flags/kernelFP/liveXSAVE/memory/source comparison. No other width/mask/store/prefix, application completion or performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_vmovdqa64_family.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(pairs=0,new_pairs=0,startup_pairs=0,verified_memory_failures=0,
                    refusals=0,actual_before_queries=0,ending_pairs=0,crossing_pairs=0,typed_promotions=0,supplied_none_queries=0))
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
    fixture_outputs=[private/'vmovdqa64-family'/f'vmovdqa64-family-{group}'for group in range(10)]
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
        need(fact(pin(FIXTURE/'OUTCOMES.json'))['sha256']==OUTCOMES_SHA,'exact fourteen-command family/fault protocol')
        protocol=decode((FIXTURE/'OUTCOMES.json').read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==14 and [c['exit']for c in commands]==[0]*10+[125]*4 and
          [c['name']for c in commands]==['group'+str(g)for g in range(10)]+['full-read-fault','alignment-fault','indexed-full-read-fault','indexed-alignment-fault'] and
          [c['argv']for c in commands]==[['vmovdqa64-family-'+str(g)]for g in range(10)]+[['vmovdqa64-family-0']]*4 and
          [c['environment_delta']for c in commands]==[{}]*10+[{'LI2_VQA64F_CONTROL':name}for name in ('full-read-fault','alignment-fault','indexed-full-read-fault','indexed-alignment-fault')] and
          [c['group']for c in commands]==list(range(10))+[0]*4 and
          [c['fault_kind']for c in commands]==[0]*10+[1,2,3,4],
          'closed actual processes, selectors, failed exits and unchanged bounds')
        cases=catalogue();r['catalogue']=dict(source=fact(FIXTURE/'cases.json'),compiled=fact(FIXTURE/'cases.inc'),rows_sha256=digest(cases),new_pairs=160)
        products=builder.prepare();output=private/'vmovdqa64-family';output.mkdir()
        recipe_path=pin(FIXTURE/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(10):
            name=f'vmovdqa64-family-{group}';values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
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
            need(not err,'actual symbol inspection stderr');roots={'samples','negative_sample','result','refused_last','vpb_observations','v64_fault','vpc_queries','vm64_promotions'}
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
                symbols['vpc_queries']['bytes']==10304 and symbols['vm64_promotions']['bytes']==2080 and 136+22*sample+40+5000+96+10304+2080<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=136+22*sample+40+5000+96+10304+2080,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases)
            need(value['operation']==('completed'if expected['exit']==0 else ('failed_alignment'if expected['fault_kind']in(2,4)else 'failed_memory_read')),
                 'no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(pairs=170,new_pairs=160,startup_pairs=14,verified_memory_failures=4,
            refusals=1400,actual_before_queries=328,ending_pairs=123,crossing_pairs=37,typed_promotions=98,supplied_none_queries=98) and
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
