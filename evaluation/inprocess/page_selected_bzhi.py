#!/usr/bin/env python3
"""Exact BZHI RBX,RDX,R11 with complete native/TF flag and state comparison."""
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
from page_selected_vptestnmb_promotions import promotions as vtn_promotions
from page_selected_vpxorq256_promotions import promotions as vpx256_promotions
from page_selected_components import plain_executable
from page_selected_register_time_build import recipe,expand,headers
from page_selected_register_time_compare import decode

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/bzhi'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='cb0a3619efb0389b5c4e55a089c80f6523fcf5445396d4f4c78a0bebdea01c32'
CASES_SHA='83b322f6ad23e2d66ba61dfe9b5089fa8baee3e265e6de2dd83d9efe5b074061'
TABLE_SHA='4d20fc3983ee22db56f0e82c2205d7edbfa91cb868e080a04b4a7145e87be7d4'
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def catalogue():
    need(fact(FIXTURE/'cases.inc')['sha256']==CASES_SHA and
         fact(FIXTURE/'cases.json')['sha256']==TABLE_SHA,'exact reviewed C and literal case table')
    table=decode((FIXTURE/'cases.json').read_bytes());rows=table['rows']
    patterns=((0xfedcba9876543210,0x0123456789abcd00,0,0x40),
              (0xfedcba9876543211,0x0123456789abcd01,1,0),
              (0xffffffffffffffff,0x0123456789abcd3f,0x7fffffffffffffff,0),
              (0xffffffffffffffff,0x0123456789abcd40,0xffffffffffffffff,0x81),
              (0,0xffffffffffffffff,0,0x41))
    need(len(rows)==25 and table['retained_donor_refusal_rows']==110 and
         len(table['refusals'])==31,'closed positive and retained/additive refusal tables')
    for i,r in enumerate(rows):
        p,tail=divmod(i,5);tail+=1;src,index,value,flags=patterns[p]
        need(r==dict(id=i,name=f'bzhi_pattern{p}_tail{tail}',pattern=p,tail=tail,
             source=src,index=index,initial_rbx=value^0x5555aaaa5555aaaa,expected=value,
             defined_flags=flags,initial_flags=0xed7 if i%2 else 0x202,encoding='c4e2a0f5da'),
             'exact independent literals and complete five-tail geometry')
        n=index&255;actual=src if n>=64 else src&((1<<n)-1)
        need(value==actual and flags==int(n>=64)|(int(value==0)<<6)|((value>>63)<<7),
             'independent low-byte-index result and defined flag algebra')
    return rows

def observations(data, group, header):
    need(group in (0,1) and header['pairs']==(16,11)[group],'closed BZHI cohort')
    pairs=header['pairs'];first=(0,15)[group]
    need(len(data) == 4824, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (0x315852425056324c, 1, 4824, group, pairs, header['xcr0'], header['xsave_bytes']),
         'exact trailer identity and observed input joins')
    tuples = [struct.unpack_from('<6Q', data, 64+48*i) for i in range(68)]
    basic, components = tuples[:4], tuples[4:]
    need([x[:2] for x in basic] == [(0, 0), (1, 0), (7, 0), (13, 0)] and
         all(all(v < 1 << 32 for v in q) for q in tuples), 'actual CPUID tuple identities and register width')
    need(basic[0][2] >= 13 and basic[1][4] & 0x1c000000 == 0x1c000000 and
         basic[2][3] & 0xc0010100 == 0xc0010100, 'actual XSAVE/OSXSAVE/AVX/AVX512F/BW/VL/BMI2 prerequisites')
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
    ids = list(struct.unpack_from('<17Q', data, 3328))
    need(ids == [0]+list(range(9000+first,9000+first+pairs-1))+[0]*(17-pairs),
         'actual retained pair identities and all unused IDs zero')
    bvs = [list(struct.unpack_from('<10Q', data, 3464+80*i)) for i in range(17)]
    need(not any(v for row in bvs[pairs:]for v in row),'all unused observations zero')
    for row in bvs[:pairs]:
        need(all(v & 0xe7 == 0xe7 and not v & ~xcr0 for v in row), 'real non-init seed components present')
        need(len(set(row[:6])) == len(set(row[6:])) == 1,
             'exact kernel and live before/after XSTATE_BVs, separately observed without normalization')
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), checked=checked,
                query_count=count, cpuid_basic=[list(x) for x in basic],
                components=[dict(index=i, raw=list(components[i])) for i in active],
                kernel_xstate_bv=sorted({r[0] for r in bvs[:pairs]}), live_xstate_bv=sorted({r[6] for r in bvs[:pairs]}),
                xcr0=xcr0, xsave_bytes=size, all_bvs_sha256=digest(bvs), pair_ids_sha256=digest(ids))



def record(data,expected,sample_bytes,rows):
    need(352<len(data)<16<<20,'complete mandatory Code2460 trailer within unchanged cap')
    vpx256=vpx256_promotions(data[-352:]);data=data[:-352]
    need(3232<len(data)<16<<20,'complete typed Code2791 promotions within unchanged cap')
    promoted=vtn_promotions(data[-3232:],'bzhi');data=data[:-3232]
    count=(15,10)[expected['group']];start=(0,15)[expected['group']]
    need(len(rows)==count,'exact cohort row count')
    need(len(data)>=136,'complete retained header')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()),'exact finite outcome, no alternate success')
    need(h['sample_bytes']==sample_bytes>0 and
         len(data)==136+22*sample_bytes+40+4824+7232<16<<20,'actual ELF-bound complete record extent')
    need(576<=h['xsave_bytes']<=65536 and h['xcr0']&3==3,'qualified XSAVE extent')
    need(h['completed']==h['pairs']==count+1 and not any(data[136+(count+1)*sample_bytes:136+22*sample_bytes]),
         'all declared positive slots occupied; every unused slot and whole negative sample zero')
    obs=observations(data[-12056:-7232],expected['group'],h)
    q=data[-7232:];need(struct.unpack_from('<8Q',q)==(0x315158565056324c,1,7232,expected['group'],2*count,129,0,0),
         'actual-before query trailer identity, completion and refusal counts')
    need(not any(q[64+448*count:]),'all unused actual-before query rows zero')
    queries=[]
    for i,c in enumerate(rows):
        pair=[]
        for lane in (0,1):
            at=64+224*(2*i+lane)
            attempted,result,identity,actual_lane=struct.unpack_from('<4Q',q,at)
            before=struct.unpack_from('<18Q',q,at+32)
            pc,next_pc,first,end,version,policy,code,length=struct.unpack_from('<4Q4I',q,at+176)
            need((attempted,result,identity,actual_lane)==(1,0,9000+start+i,lane) and
                 0<pc<1<<47 and pc%4096==4096-c['tail'] and next_pc==pc+5 and
                 (first,end,version,policy,code,length)==(0,0,1,1,3680,5),
                 'actual original PC geometry and exact closed typed zero-write effect')
            need(before[2]==c['source'] and before[3]==c['initial_rbx'] and before[11]==c['index'],
                 'actual source/index/destination inputs match independent literals')
            pair.append((before,pc,next_pc,first,end,version,policy,code,length))
        need(pair[0]==pair[1],'native and stepped actual-before registers and NONE results agree completely')
        queries.append(pair[0])
    return dict(operation='completed',pairs=count+1,new_pairs=count,refusals=h['refusals'],vpx256_promotions=vpx256,vpx256_typed_promotions=1,vpx256_supplied_none_queries=1,vtn_promotions=promoted,vtn_typed_promotions=10,vtn_supplied_none_queries=10,
        promoted_encoding_checks=1,promoted_footprint_queries=1,actual_before_queries=2*count,
        ending_pairs=sum(c['tail']==5 for c in rows),crossing_pairs=sum(c['tail']<5 for c in rows),
        header=h,observations=obs,query_bytes=len(q),query_sha256=hashlib.sha256(q).hexdigest(),
        query_values_sha256=digest(queries),
        architecture='Authenticated C oracle compares complete native/TF state and literal effects; this reader checks complete records, actual ELF extents, CPUID and actual query observations, not a second full-state replay.')


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
          fixture=['sh','tools/page-entry/selected/tests/bzhi/build.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group 0..1>'],
          native=[[f'bzhi-{g}']for g in range(2)],selectors=[{}]*2))
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
    stem=stamp+'-page-selected-bzhi-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-bzhi-v1',status='failed',
        scope='Exactc4e2a0f5da/Code3680 BZHI RBX,RDX,R11;25 boundary/high-index-bit cases plus2 startup pairs across all five fetch tails. Literal full64-bit RBX and defined flags; unchanged native/TF flags include undefined AF/PF. Complete GPR/FP/XSAVE/vector/mask/stack/data/source comparisons and50 actual-before NONE queries. All145 donor refusals plus the mandatory supplied Code2460 typed/NONE row and its typed2785 promotion retained;31 additive neighbors and10 separately recorded Code2791/NONE promotions. No other register/memory/width authority, application completion or performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_bzhi.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(vpx256_typed_promotions=0,vpx256_supplied_none_queries=0,vtn_typed_promotions=0,vtn_supplied_none_queries=0,pairs=0,new_pairs=0,startup_pairs=0,refusals=0,promoted_encoding_checks=0,
                    promoted_footprint_queries=0,actual_before_queries=0,ending_pairs=0,crossing_pairs=0))
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
    fixture_outputs=[private/'bzhi'/f'bzhi-{group}'for group in range(2)]
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
        need(fact(pin(FIXTURE/'OUTCOMES.json'))['sha256']==OUTCOMES_SHA,'exact two-command protocol')
        protocol=decode((FIXTURE/'OUTCOMES.json').read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==2 and [c['exit']for c in commands]==[0]*2 and
          [c['group']for c in commands]==list(range(2)) and [c['name']for c in commands]==[f'group{g}'for g in range(2)] and
          [c['argv']for c in commands]==[[f'bzhi-{g}']for g in range(2)] and
          [c['environment_delta']for c in commands]==[{}]*2 and
          all(c['promoted_encoding_checks']==c['promoted_footprint_queries']==1 and c['actual_before_queries']==(30,20)[c['group']] for c in commands),
          'closed cases, actual selectors, exits, query counts and unchanged bounds')
        cases=catalogue();r['catalogue']=dict(source=fact(FIXTURE/'cases.inc'),table=fact(FIXTURE/'cases.json'),rows_sha256=digest(cases),pairs=25,input_patterns=5,fetch_positions=5,exact_encoding=True)
        products=builder.prepare();output=private/'bzhi';output.mkdir()
        recipe_path=pin(FIXTURE/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(2):
            name=f'bzhi-{group}';values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
                '$parent_dir':SELECTED.parent,'$decoder_archive':products['archive'],'$output_dir':output,'$group':group}
            argv=expand(lines[0],values);path=output/name
            need(argv[-2:]==['-o',str(path)] and all(x in argv for x in ('-O2','-g','-nostdlib','-static','-no-pie','-Werror')),
                 'exact optimized bounded fixture recipe')
            sources=[SELECTED/'step_owner.c',SELECTED/'lifecycle_loader.c',SELECTED/'tests/generic/tf_controls.c',FIXTURE/'fixture.c',SELECTED/'tests/vpxorq128/fixture.S']
            state={};states[name]=state
            headers(name+'-headers',argv,list(map(str,sources)),products['archive'],builder,pin,aliases,run,state)
            run(name+'-link',argv,profile='fixture_link',env=builder.environment);binary(path);state['artifact']=artifact(path)
            state['elf']=plain_executable(path)
            _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
            need(out==err==b'','no unresolved fixture imports')
            _,out,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual symbol inspection stderr');roots={'vpx256_promotions','vtn_promotions','samples','negative_sample','result','refused_last','vpb_observations','vpc_queries'}
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
                symbols['refused_last']['bytes']==40 and symbols['vpb_observations']['bytes']==4824 and
                symbols['vpx256_promotions']['bytes']==352 and symbols['vtn_promotions']['bytes']==3232 and symbols['vpc_queries']['bytes']==7232 and 352+3232+136+22*sample+40+4824+7232<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=352+3232+136+22*sample+40+4824+7232,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            group=expected['group'];value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases[0:15]if group==0 else cases[15:25])
            need(value['operation']=='completed','no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=1 if key=='startup_pairs'else value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(vpx256_typed_promotions=2,vpx256_supplied_none_queries=2,vtn_typed_promotions=20,vtn_supplied_none_queries=20,pairs=27,new_pairs=25,startup_pairs=2,refusals=352,promoted_encoding_checks=2,
            promoted_footprint_queries=2,actual_before_queries=50,ending_pairs=5,crossing_pairs=20) and
            len(r['cases'])==2 and all(c['status']=='accepted_observation'for c in r['cases']),'whole exact two-command cohort')
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
