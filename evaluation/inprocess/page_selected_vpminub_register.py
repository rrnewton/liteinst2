#!/usr/bin/env python3
"""Canonical unmasked EVEX512.W0 VPMINUB; six bounded full-state cohorts."""
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
from page_selected_vpbroadcast_register import observations

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/vpminub_register'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='7ff7ee347cc57e8469d9f92ba70a6b54ed3cb2eab3ff9087111643237d865f79'
CASES_SHA='34c0dfd6dd8646952f1ac21b3b35b769a1d4d206ae6fbf770eeaf6662568f222'
TABLE_SHA='55b23a49867e26ab073e9fab208bb74a2e3b3618d6d3ecd0fb34cd03a393fa73'
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def catalogue():
    need(fact(FIXTURE/'cases.inc')['sha256']==CASES_SHA and
         fact(FIXTURE/'cases.json')['sha256']==TABLE_SHA,'exact reviewed C and literal case table')
    table=decode((FIXTURE/'cases.json').read_bytes());rows=table['rows'];patterns=table['patterns']
    need(len(rows)==96 and len(patterns)==3 and all(len(p)==2 and all(len(s)==64 and
         all(type(v)is int and 0<=v<=255 for v in s)for s in p)for p in patterns),'complete literal unsigned64-byte minimum inputs')
    # This independent decoder checks each encoded register rather than calling
    # the production decoder or reusing its family predicate as the oracle.
    triples=[(i,(i+1)%32,(i+17)%32)for i in range(32)]
    triples += [(i,i,(i+9)%32)for i in range(16)]
    triples += [(d,22,21)for d in(23,20)for p in range(3)for t in range(1,7)]
    triples += [(i,i,i)for i in(0,7,8,15,16,23,24,31)]+[(3,3,20),(9,12,9),(24,1,1),(31,0,31)]
    for i,(r,t)in enumerate(zip(rows,triples)):
        raw=bytes.fromhex(r['encoding']);need(len(raw)==6,'complete six-byte case')
        lead,p0,p1,p2,opcode,m=raw
        d=((m>>3)&7)|((1-(p0>>7&1))<<3)|((1-(p0>>4&1))<<4)
        a=((p1>>3)^15)&15;a|=(1-(p2>>3&1))<<4
        b=(m&7)|((1-(p0>>5&1))<<3)|((1-(p0>>6&1))<<4)
        need((lead,p0&15,p1&135,p2&247,opcode,m>>6)==(98,1,5,64,218,3) and
             (d,a,b)==t==(r['destination'],r['src1'],r['src2']) and r['id']==i and r['pattern']==((i-48)//6%3 if 48<=i<84 else i%3) and
             r['tail']==((i-48)%6+1 if 48<=i<84 else i%6+1),'literal operands, structural order and fetch geometry')
        x,y=patterns[r['pattern']];y=x if a==b else y
        need(r['expected']==bytes(min(u,v)for u,v in zip(x,y)).hex(),'independent complete64-byte unsigned minimum')
    need(all({r[k]for r in rows}==set(range(32))for k in ('destination','src1','src2')) and
         {r['tail']for r in rows}==set(range(1,7)) and
         all([r['encoding']for r in rows[start:start+18]]==[encoding]*18 and
             [(r['pattern'],r['tail'])for r in rows[start:start+18]]==[(p,t)for p in range(3)for t in range(1,7)]
             for start,encoding in((48,'62a14d40dafd'),(66,'62a14d40dae5'))),
         'all register roles, all fetch positions and actual observed triple')
    need(table['old_refusal_rows']==110 and len(table['refusals'])==28,'old rows retained and additive neighbors')
    return rows


def record(data,expected,sample_bytes,rows):
    need(3232<len(data)<16<<20,'complete typed Code2791 promotions within unchanged cap')
    promoted=vtn_promotions(data[-3232:],'vpxorq128');data=data[:-3232]
    need(len(data)>=136,'complete retained header')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()),'exact finite outcome, no alternate success')
    need(h['sample_bytes']==sample_bytes>0 and
         len(data)==136+22*sample_bytes+40+4824+7232<16<<20,'actual ELF-bound complete record extent')
    need(576<=h['xsave_bytes']<=65536 and h['xcr0']&3==3,'qualified XSAVE extent')
    need(h['completed']==h['pairs']==17 and not any(data[136+17*sample_bytes:136+22*sample_bytes]),
         'all17 positive slots occupied; four unused slots and whole negative sample zero')
    obs=observations(data[-12056:-7232],expected['group'],h)
    need(obs['cpuid_basic'][2][3]&(1<<31),'actual AVX512VL prerequisite in addition to unchanged F/BW')
    q=data[-7232:];need(struct.unpack_from('<8Q',q)==(0x31514e4d5056324c,1,7232,expected['group'],32,127,0,0),
         'actual-before query trailer identity, completion and refusal counts')
    queries=[]
    for i,c in enumerate(rows):
        pair=[]
        for lane in (0,1):
            at=64+224*(2*i+lane)
            attempted,result,identity,actual_lane=struct.unpack_from('<4Q',q,at)
            before=struct.unpack_from('<18Q',q,at+32)
            pc,next_pc,first,end,version,policy,code,length=struct.unpack_from('<4Q4I',q,at+176)
            need((attempted,result,identity,actual_lane)==(1,0,8000+16*expected['group']+i,lane) and
                 0<pc<1<<47 and pc%4096==4096-c['tail'] and next_pc==pc+6 and
                 (first,end,version,policy,code,length)==(0,0,1,1,2285,6),
                 'actual original PC geometry and exact closed typed zero-write effect')
            pair.append((before,pc,next_pc,first,end,version,policy,code,length))
        need(pair[0]==pair[1],'native and stepped actual-before registers and NONE results agree completely')
        queries.append(pair[0])
    return dict(operation='completed',pairs=17,new_pairs=16,refusals=h['refusals'],vtn_promotions=promoted,vtn_typed_promotions=10,vtn_supplied_none_queries=10,
        promoted_encoding_checks=1,promoted_footprint_queries=1,actual_before_queries=32,
        ending_pairs=sum(c['tail']==6 for c in rows),crossing_pairs=sum(c['tail']<6 for c in rows),
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
          fixture=['sh','tools/page-entry/selected/tests/vpminub_register/build.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group 0..5>'],
          native=[[f'vpminub-register-{g}']for g in range(6)],selectors=[{}]*6))
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
    stem=stamp+'-page-selected-vpminub-register-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-vpminub-register-v1',status='failed',
        scope='Canonical unmasked EVEX512.W0 register-only VPMINUB Code2285,96 complete64-byte minimum pairs+6startup. All32 source/destination roles, alias classes and every six-byte fetch tail for both actual libc triples. Full unchanged native/TF/GPR/flags/kernelFP/liveXSAVE/memory comparisons and192 actual-before NONE queries.174 supplied refusals per process retain all prior110 rows and47 common controls with mandatory old2785/2791 positives;28 new neighbors. No memory or application/performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_vpminub_register.py','--expect-revision',args.expect_revision],
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
    fixture_outputs=[private/'vpminub-register'/f'vpminub-register-{group}'for group in range(6)]
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
          [c['argv']for c in commands]==[[f'vpminub-register-{g}']for g in range(6)] and
          [c['environment_delta']for c in commands]==[{}]*6 and
          all(c['promoted_encoding_checks']==c['promoted_footprint_queries']==1 and c['actual_before_queries']==32 for c in commands),
          'closed cases, actual selectors, exits, query counts and unchanged bounds')
        cases=catalogue();r['catalogue']=dict(source=fact(FIXTURE/'cases.inc'),table=fact(FIXTURE/'cases.json'),rows_sha256=digest(cases),pairs=96,registers_per_role=32,alias_classes=5,fetch_positions=6,exhaustive=False)
        products=builder.prepare();output=private/'vpminub-register';output.mkdir()
        recipe_path=pin(FIXTURE/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(6):
            name=f'vpminub-register-{group}';values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
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
        need(r['totals']==dict(vtn_typed_promotions=60,vtn_supplied_none_queries=60,pairs=102,new_pairs=96,startup_pairs=6,refusals=1044,promoted_encoding_checks=6,
            promoted_footprint_queries=6,actual_before_queries=192,ending_pairs=16,crossing_pairs=80) and
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
