#!/usr/bin/env python3
"""Canonical BMI1 BLSMSK/ANDN registers with complete native/TF flag and state comparison."""
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
from page_selected_components import plain_executable
from page_selected_register_time_build import recipe,expand,headers
from page_selected_register_time_compare import decode

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/bmi1_register'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='6abdfab2ce863ff7e9d9911dfd32e85054b390a388aeac41b9ca0164a67eaee2'
CASES_SHA='5538eeec76cac2e0dad6a7885671812e6247234401a76c812888375fed7aa589'
TABLE_SHA='efb97f2fd3c5414bce0179e0025f431b00e9a8891bc6399cef8791fd959b0a7e'
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def catalogue():
    need(fact(FIXTURE/'cases.inc')['sha256']==CASES_SHA and
         fact(FIXTURE/'cases.json')['sha256']==TABLE_SHA,'exact reviewed C and literal case table')
    table=decode((FIXTURE/'cases.json').read_bytes());rows=table['rows']
    need(len(rows)==96 and table['codes']==[3676,3672] and table['retained_refusals']==177 and
         len(table['refusals'])==47,'closed exact BMI1 case/refusal table')
    for i,r in enumerate(rows):
        b=bytes.fromhex(r['encoding']);op=int(i>=48)
        need(r['id']==i and r['op']==op and r['code']==(3676,3672)[op] and len(b)==5 and
             r['destination']in(set(range(16))-{4})and 0<=r['src1']<16 and
             (0<=r['src2']<16 if op else r['src2']==16)and 1<=r['tail']<=5,
             'literal source table domain and non-RSP destination')
        if op:
            d=((~b[1]>>7)&1)*8+(b[4]>>3&7);x=(~b[2]>>3)&15;y=((~b[1]>>5)&1)*8+(b[4]&7)
            need(b[0]==196 and b[1]&0x5f==0x42 and b[2]&0x87==0x80 and b[3]==242 and b[4]&0xc0==0xc0,
                 'independent exact ANDN field decoding')
        else:
            d=(~b[2]>>3)&15;x=((~b[1]>>5)&1)*8+(b[4]&7);y=16
            need(b[0]==196 and b[1]in(194,226)and b[2]&0x87==0x80 and b[3]==243 and b[4]&0xf8==0xd0,
                 'independent exact BLSMSK field decoding')
        need((d,x,y)==(r['destination'],r['src1'],r['src2']),'independent encoding operand identities')
        a,z=table['patterns'][r['pattern']];z=a if x==y else z
        need((r['a'],r['b'])==(a,z)and r['initial_flags']==(0xed7 if i%2 else 0x202),'fixed input patterns and flags')
        value=None if x==4 or(op and y==4)else ((~a&z)&MASK if op else ((a-1)^a)&MASK)
        flags=None if value is None else ((int(value==0)<<6 if op else int(a==0))|((value>>63)<<7))
        need((r['expected'],r['defined_flags'])==(value,flags),'independent result/flag algebra; actual RSP is never fabricated')
    for op in(0,1):
        group=rows[48*op:48*(op+1)]
        need({r['destination']for r in group}==set(range(16))-{4} and
             {r['src1']for r in group}==set(range(16))and
             (not op or {r['src2']for r in group}==set(range(16))), 'every admitted operand role represented')

    return rows

def observations(data, group, header):
    need(group in range(6) and header['pairs']==17,'closed BMI1 cohort')
    pairs=header['pairs'];first=16*group
    need(len(data) == 4824, 'complete actual CPUID/XSAVE trailer')
    head = struct.unpack_from('<8Q', data)
    magic, version, extent, actual_group, count, checked, xcr0, size = head
    need((magic, version, extent, actual_group, checked, xcr0, size) ==
         (0x3158524d4950324c, 1, 4824, group, pairs, header['xcr0'], header['xsave_bytes']),
         'exact trailer identity and observed input joins')
    tuples = [struct.unpack_from('<6Q', data, 64+48*i) for i in range(68)]
    basic, components = tuples[:4], tuples[4:]
    need([x[:2] for x in basic] == [(0, 0), (1, 0), (7, 0), (13, 0)] and
         all(all(v < 1 << 32 for v in q) for q in tuples), 'actual CPUID tuple identities and register width')
    need(basic[0][2] >= 13 and basic[1][4] & 0x1c000000 == 0x1c000000 and
         basic[2][3] & 0xc0010008 == 0xc0010008, 'actual XSAVE/OSXSAVE/AVX/AVX512F/BW/VL/BMI1 prerequisites')
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
    need(3232<len(data)<16<<20,'complete typed Code2791 promotions within unchanged cap')
    promoted=vtn_promotions(data[-3232:],'bzhi');data=data[:-3232]
    count=16;start=16*expected['group']
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
    q=data[-7232:];need(struct.unpack_from('<8Q',q)==(0x3151524d4950324c,1,7232,expected['group'],2*count,177,0,0),
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
                 (first,end,version,policy,code,length)==(0,0,1,1,c['code'],5),
                 'actual original PC geometry and exact closed typed zero-write effect')
            need(0<before[4]<1<<47 and before[4]%16==0 and
                 (c['src1']==4 or before[c['src1']]==c['a'])and
                 (not c['op']or c['src2']==4 or before[c['src2']]==c['b']),
                 'actual source literals and genuine aligned seeded RSP')
            pair.append((before,pc,next_pc,first,end,version,policy,code,length))
        need(pair[0]==pair[1],'native and stepped actual-before registers and NONE results agree completely')
        queries.append(pair[0])
    return dict(operation='completed',pairs=count+1,new_pairs=count,refusals=h['refusals'],vtn_promotions=promoted,vtn_typed_promotions=10,vtn_supplied_none_queries=10,
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
          fixture=['sh','tools/page-entry/selected/tests/bmi1_register/build.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group 0..5>'],
          native=[[f'bmi1-register-{g}']for g in range(6)],selectors=[{}]*6))
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
    stem=stamp+'-page-selected-bmi1-register-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-bmi1-register-v1',status='failed',
        scope='Canonical W1 register BMI1 BLSMSK/ANDN;96 original-PC native/TF pairs plus6 startup pairs. All15 non-RSP destinations and16 sources, actual RSP sources, aliases, zeros/high bits and all five fetch tails. Literal algebra supplements unchanged complete hardware flags including undefined AF/PF; complete GPR/FP/XSAVE/vector/mask/memory/source. Original177 refusals plus47 new neighbors and unchanged2785/2791 typed promotions. No memory/32-bit or program/performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_bmi1_register.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(vtn_typed_promotions=0,vtn_supplied_none_queries=0,pairs=0,new_pairs=0,startup_pairs=0,refusals=0,promoted_encoding_checks=0,
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
    fixture_outputs=[private/'bmi1-register'/f'bmi1-register-{group}'for group in range(6)]
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
        need(fact(pin(FIXTURE/'OUTCOMES.json'))['sha256']==OUTCOMES_SHA,'exact six-command protocol')
        protocol=decode((FIXTURE/'OUTCOMES.json').read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==6 and [c['exit']for c in commands]==[0]*6 and
          [c['group']for c in commands]==list(range(6)) and [c['name']for c in commands]==[f'group{g}'for g in range(6)] and
          [c['argv']for c in commands]==[[f'bmi1-register-{g}']for g in range(6)] and
          [c['environment_delta']for c in commands]==[{}]*6 and
          all(c['promoted_encoding_checks']==c['promoted_footprint_queries']==1 and c['actual_before_queries']==32 for c in commands),
          'closed cases, actual selectors, exits, query counts and unchanged bounds')
        cases=catalogue();r['catalogue']=dict(source=fact(FIXTURE/'cases.inc'),table=fact(FIXTURE/'cases.json'),rows_sha256=digest(cases),pairs=96,input_patterns=5,fetch_positions=5,exact_encoding=False,canonical_families=[3676,3672])
        products=builder.prepare();output=private/'bmi1-register';output.mkdir()
        recipe_path=pin(FIXTURE/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(6):
            name=f'bmi1-register-{group}';values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
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
            need(not err,'actual symbol inspection stderr');roots={'vtn_promotions','samples','negative_sample','result','refused_last','vpb_observations','vpc_queries'}
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
                symbols['vtn_promotions']['bytes']==3232 and symbols['vpc_queries']['bytes']==7232 and 3232+136+22*sample+40+4824+7232<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=3232+136+22*sample+40+4824+7232,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            group=expected['group'];value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases[16*group:16*(group+1)])
            need(value['operation']=='completed','no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=1 if key=='startup_pairs'else value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(vtn_typed_promotions=60,vtn_supplied_none_queries=60,pairs=102,new_pairs=96,startup_pairs=6,refusals=1344,promoted_encoding_checks=6,
            promoted_footprint_queries=6,actual_before_queries=192,ending_pairs=24,crossing_pairs=72) and
            len(r['cases'])==6 and all(c['status']=='accepted_observation'for c in r['cases']),'whole exact six-command cohort')
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
