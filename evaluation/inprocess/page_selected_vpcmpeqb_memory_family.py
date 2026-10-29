#!/usr/bin/env python3
"""Canonical unmasked W0 VPCMPEQB K0..7,ZMM0..31,[RDI] family oracle."""
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
from page_selected_components import plain_executable
from page_selected_register_time_build import recipe,expand,headers
from page_selected_register_time_compare import decode
from page_selected_vpcmpeqb_memory_promotions import PROMOTED,promotions

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/vpcmpeqb_memory_family'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='1f2596cb5bec826c1a9befe3e45444372e12532c85ac78b05f0674e1f7dffc82'
CASES_SHA='c52803ae9714a0c9c637fd59f8247ed57d9a15a89b3d619e60af46b06a178a5e'
CASES_JSON_SHA='302cb353b2090168f83297040f273433a41ac666069222d95ccec8111f9bac3e'
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def catalogue():
    need(fact(FIXTURE/'cases.inc')['sha256']==CASES_SHA and
         fact(FIXTURE/'cases.json')['sha256']==CASES_JSON_SHA,'exact reviewed C/JSON family catalogue')
    table=decode((FIXTURE/'cases.json').read_bytes())
    need(set(table)=={'patterns','source','rows','promoted','refusals'},'closed family table schema')
    rows=table['rows'];seed=table['source'];patterns=table['patterns']
    need(seed==[1+(17*17+i*13)%255 for i in range(64)] and len(patterns)==3 and
         all(len(p)==64 and all(type(v)is int and 0<=v<256 for v in p)for p in patterns) and
         [sum(1<<i for i,(a,b)in enumerate(zip(seed,p,strict=True))if a==b)for p in patterns]==
         [0,MASK,0x9249249249249249],'independent complete source/memory and all64 literal equality bits')
    need(len(rows)==108 and len({r['name']for r in rows})==108,'six complete18-case cohorts')
    for row in rows:
        need(set(row)=={'name','pattern','offset','tail','source','destination','encoding'} and
             all(type(row[k])is int for k in ('pattern','offset','tail','source','destination')) and
             0<=row['source']<32 and 0<=row['destination']<8 and 0<=row['pattern']<3 and
             row['offset']in(0,257,4032) and 1<=row['tail']<=6,'closed register/operand/fetch row')
        src,dst=row['source'],row['destination']
        literal=bytes((0x62,0xf1,5|((15-(src&15))<<3),0x40|((1-(src>>4))<<3),0x74,7|(dst<<3)))
        need(row['encoding']==literal.hex(),'independent source/destination encoding')
    need([(r['pattern'],r['source'],r['destination'],r['offset'],r['tail'])for r in rows[:96]]==
         [(p,s,(s+p)%8,(0,257,4032)[p],1+(s+p)%6)for p in range(3)for s in range(32)],
         'all32 sources/all8 destinations and three patterns in the structural cohort')
    need([(p['old_index'],p['encoding'])for p in table['promoted']]==list(PROMOTED),
         'all five retained old neighbor identities')
    for p in table['promoted']:
        need(len(p['case_indices'])==2 and [rows[i]['pattern']for i in p['case_indices']]==[0,2] and
             all(rows[i]['encoding']==p['encoding'] and rows[i]['source']==p['source'] and
                 rows[i]['destination']==p['destination']for i in p['case_indices']),
             'each exact old row has two mandatory native cases')
    need(sum(r['tail']==6 for r in rows)==21 and sum(r['tail']<6 for r in rows)==87 and
         len(table['refusals'])==9,'complete declared geometry and additional closed-bit controls')
    return rows


def observations(data, group, header, fault_kind=0):
    need(len(data) == 5000, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (0x31584d435056324c, 1, 5000, group, 1 if fault_kind else 19, header['xcr0'], header['xsave_bytes']),
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
    need(ids == ([0]*19 if fault_kind else [0]+list(range(5000+18*group, 5018+18*group))),
         'actual retained completed pair identities')
    bvs = [list(struct.unpack_from('<10Q', data, 3480+80*i)) for i in range(19)]
    need(not fault_kind or not any(v for row in bvs[1:] for v in row), 'uncompleted pair BV fields remain absent')
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
         row['prefix_bytes'] == (32 if kind == 2 else 0) and
         row['operand'] == row['address']-row['prefix_bytes'], 'actual fault operand/guard geometry')
    need(all(v & 0xe7 == 0xe7 and not v & ~header['xcr0'] for v in raw[6:]) and
         len(set(raw[6:10])) == len(set(raw[10:])) == 1,
         'fault native/owner kernel BVs and live BVs unchanged separately')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), **row)


def queries(data,header,rows,kind,group):
    need(len(data)==9024,'complete actual-before query trailer')
    count=2 if kind else 36
    need(struct.unpack_from('<8Q',data)==(0x31514d435056324c,1,9024,group,count,0,0,0),
         'exact query identity/count and no fabricated control results')
    values=[]
    for index in range(count//2):
        pair=[];case=rows[18*group+(kind-1 if kind else index)]
        for lane in (0,1):
            at=64+224*(2*index+lane)
            attempted,result,identity,actual_lane=struct.unpack_from('<4Q',data,at)
            before=struct.unpack_from('<18Q',data,at+32)
            value=struct.unpack_from('<4Q4I',data,at+176)
            pc,next_pc,first,end,abi,policy,code,length=value
            need((attempted,result,identity,actual_lane,first,end,abi,policy,code,length)==
                 (1,0,5000+18*group+(kind-1 if kind else index),lane,0,0,1,1,1720,6) and
                 0<pc<1<<47 and pc%4096==4096-case['tail'] and next_pc==pc+6,
                 'actual original-PC NONE query and fetch geometry')
            need(before[7]>4096 and before[7]%4096==(4064 if kind==2 else 0 if kind else case['offset']),
                 'actual before-RDI read operand geometry')
            pair.append(dict(before=list(before),value=list(value)))
        need(pair[0]==pair[1],'complete native/TF actual-before query agreement')
        values.append(pair)
    need(not any(data[64+224*count:]),'unattempted query slots remain zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),actual_before_queries=count,
                values_sha256=digest(values),memory_write_ranges=0)


def record(data,expected,sample_bytes,rows):
    need(1216<len(data)<16<<20,'complete register-promotion trailer under old cap')
    vpe_promoted=vpe_promotions(data[-1216:],'vpcmpeqb_memory_family');data=data[:-1216]
    need(2080<len(data)<16<<20,'complete seven Code1605 promotions within old cap')
    vm64_promoted=vm64_promotions(data[-2080:]);data=data[:-2080]
    need(1504+136<=len(data)<16<<20,'complete bounded record with mandatory promotions')
    promoted=promotions(data[-1504:]);data=data[:-1504]
    need(len(data)>=136,'complete retained header')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()),'exact finite outcome; failed operations stay failed')
    need(h['sample_bytes']==sample_bytes>0 and
         len(data)==136+22*sample_bytes+40+5000+96+9024<16<<20,'actual ELF-bound complete record extent')
    need(576<=h['xsave_bytes']<=65536 and h['xcr0']&3==3,'qualified XSAVE extent')
    positive=expected['exit']==0;group=expected['group'];kind=0 if positive else 1 if expected['name']=='full-read-fault'else 2
    need(type(group)is int and 0<=group<6 and (positive or group==0),'exact bounded cohort identity')
    need(h['pairs']==19 and h['completed']==(19 if positive else 1),'complete expected prefix; fault is never completion')
    if positive:
        need(not any(data[136+19*sample_bytes:136+22*sample_bytes]),'two unused slots and negative sample remain zero')
    else:
        need(not any(data[136+sample_bytes:136+21*sample_bytes]),'unstarted positive slots remain zero')
    obs=observations(data[-14120:-9120],group,h,kind)
    failed=fault_observations(data[-9120:-9024],kind,h)
    footprint=queries(data[-9024:],h,rows,kind,group)
    return dict(vpe_promotions=vpe_promoted,vpe_typed_promotions=1,vpe_supplied_none_queries=1,vm64_promotions=vm64_promoted,operation='completed'if positive else 'failed_memory_read',
        pairs=19 if positive else 0,new_pairs=18 if positive else 0,startup_pairs=1,
        verified_memory_failures=int(not positive),refusals=h['refusals'],actual_before_queries=footprint['actual_before_queries'],
        ending_pairs=sum(r['tail']==6 for r in rows[18*group:18*group+18])if positive else 0,
        crossing_pairs=sum(r['tail']<6 for r in rows[18*group:18*group+18])if positive else 0,
        header=h,observations=obs,fault_observations=failed,footprint=footprint,promotions=promoted,
        typed_promotions=promoted['typed_promotions'],supplied_none_queries=promoted['supplied_none_queries'],
        architecture='Authenticated C oracle compares complete native/TF state,64-byte literal operands and selected K0..7 results, including actual faults. Reader independently checks complete ELF-sized records, CPUID, prefix and actual-before queries; it is not a second full architectural replay.')


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
          fixture=['sh','tools/page-entry/selected/tests/vpcmpeqb_memory_family/build.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group 0..5>'],
          native=[[f'vpcmpeqb-memory-family-{g}']for g in range(6)]+[['vpcmpeqb-memory-family-0']]*2,selectors=[{}]*6+[{'LI2_VPCM_CONTROL':'full-read-fault'}, {'LI2_VPCM_CONTROL':'cross-read-fault'}]))
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
    stem=stamp+'-page-selected-vpcmpeqb-memory-family-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-vpcmpeqb-memory-family-v1',status='failed',
        scope='Canonical W0 unmasked EVEX512 VPCMPEQB K0..7,ZMM0..31,[RDI]/Code1720, preserving exact original register form.108 structural comparisons in six18-case cohorts, all source/destination roles, three literal equality patterns and six fetch geometries; two genuine full/cross-page failed reads. Full GPR/flags/kernelFP/liveXSAVE/all32ZMM/all8K/source/stack/data comparisons,220 actual-before NONE queries;109 refusals plus one separately recorded Code1720 register promotion plus seven mandatory Code1605/NONE promotions and five mandatory typed/NONE promotions per process. Structural coverage is not exhaustive256 native execution. No application completion or performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_vpcmpeqb_memory_family.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(vpe_typed_promotions=0,vpe_supplied_none_queries=0,pairs=0,new_pairs=0,startup_pairs=0,verified_memory_failures=0,
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
    fixture_outputs=[private/'vpcmpeqb-memory-family'/f'vpcmpeqb-memory-family-{group}'for group in range(6)]
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
        need(fact(pin(FIXTURE/'OUTCOMES.json'))['sha256']==OUTCOMES_SHA,'exact eight-command family/fault protocol')
        protocol=decode((FIXTURE/'OUTCOMES.json').read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==8 and [c['exit']for c in commands]==[0]*6+[125,125] and
          [c['name']for c in commands]==[f'group{g}'for g in range(6)]+['full-read-fault','cross-read-fault'] and
          [c['group']for c in commands]==list(range(6))+[0,0] and
          [c['argv']for c in commands]==[[f'vpcmpeqb-memory-family-{g}']for g in range(6)]+[['vpcmpeqb-memory-family-0']]*2 and
          [c['environment_delta']for c in commands]==[{}]*6+[{'LI2_VPCM_CONTROL':'full-read-fault'}, {'LI2_VPCM_CONTROL':'cross-read-fault'}],
          'closed actual processes, selectors, failed exits and unchanged bounds')
        cases=catalogue();r['catalogue']=dict(source=fact(FIXTURE/'cases.inc'),rows_sha256=digest(cases),new_pairs=108)
        products=builder.prepare();output=private/'vpcmpeqb-memory-family';output.mkdir()
        recipe_path=pin(FIXTURE/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(6):
            name=f'vpcmpeqb-memory-family-{group}';values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
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
            need(not err,'actual symbol inspection stderr');roots={'vpe_promotions','samples','negative_sample','result','refused_last','vm64_promotions','vpb_observations','v64_fault','vpc_queries','vpcm_promotions'}
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
                symbols['vpe_promotions']['bytes']==1216 and symbols['vm64_promotions']['bytes']==2080 and symbols['refused_last']['bytes']==40 and symbols['vpb_observations']['bytes']==5000 and symbols['v64_fault']['bytes']==96 and
                symbols['vpc_queries']['bytes']==9024 and symbols['vpcm_promotions']['bytes']==1504 and
                1216+2080+136+22*sample+40+5000+96+9024+1504<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=1216+2080+136+22*sample+40+5000+96+9024+1504,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases)
            need(value['operation']==('completed'if expected['exit']==0 else 'failed_memory_read'),
                 'no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(vpe_typed_promotions=8,vpe_supplied_none_queries=8,pairs=114,new_pairs=108,startup_pairs=8,verified_memory_failures=2,
            refusals=872,actual_before_queries=220,ending_pairs=21,crossing_pairs=87,typed_promotions=40,supplied_none_queries=40) and
            len(r['cases'])==8 and all(c['status']=='accepted_observation'for c in r['cases']),
            'six complete19-pair cohorts and two genuine failed-read controls')
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
