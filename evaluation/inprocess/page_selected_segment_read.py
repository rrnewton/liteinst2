#!/usr/bin/env python3
"""Canonical MOV r16,Sreg with complete native/TF register, selector, flag and FP comparison."""
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

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/segment_read'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='dc3e041954ae85cd583469bf3c6bae5365ce3705c9c931e2c117008cb82d12c2'
CASES_SHA='b132bbec02cf1b8b1b8320257774d527d17a5f2fb91df4ee5fc006d92e112bdb'
TABLE_SHA='f46151e822e95aae581a8b450e2f365abf4683f19d4a73808351c5a46e0bbbb2'
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def catalogue():
    need(fact(FIXTURE/'cases.inc')['sha256']==CASES_SHA and
         fact(FIXTURE/'cases.json')['sha256']==TABLE_SHA,'exact reviewed C and literal case table')
    table=decode((FIXTURE/'cases.json').read_bytes());rows=table['rows']
    need(table['schema']==1 and table['code']==287 and table['old_refusals']==47 and
         table['selector_order']==['ES','CS','SS','DS','FS','GS'] and
         table['live_indices']==[3,0,1,2,4,5] and len(rows)==90 and
         len(table['refusals'])==63,'closed selector, live-observer and refusal domains')
    destinations=[i for i in range(16)if i!=4]
    seen=set()
    for i,r in enumerate(rows):
        b=bytes.fromhex(r['encoding']);selector=i//15;destination=destinations[i%15]
        need(set(r)=={'id','selector','destination','length','tail','encoding'} and
             r['id']==i and r['selector']==selector and r['destination']==destination and
             r['length']==len(b)==(3 if destination<8 else 4) and r['tail']==1+i%len(b),
             'every exact selector/destination form and fixed ending/crossing position')
        opcode=1 if len(b)==3 else 2
        need(b[0]==0x66 and (len(b)==3 or b[1]==0x41) and b[opcode]==0x8c and
             b[opcode+1]&0xc0==0xc0 and (b[opcode+1]>>3)&7==selector and
             (b[opcode+1]&7)+(8 if len(b)==4 else 0)==destination,
             'independent canonical66, optional REX.B-only and register ModRM decoding')
        need((selector,destination)not in seen,'no duplicated operand form');seen.add((selector,destination))
    need(seen=={(s,d)for s in range(6)for d in destinations},'all90 forms, no missing selector or register')
    need({r['tail']for r in rows if r['length']==3}=={1,2,3} and
         {r['tail']for r in rows if r['length']==4}=={1,2,3,4},'all legal ending/crossing tails of both lengths')
    refusals=set()
    for r in table['refusals']:
        b=bytes.fromhex(r['encoding']);need(0<len(b)<=15 and b not in refusals,'unique bounded negative encoding');refusals.add(b)
        canonical=(len(b)==3 and b[:2]==b'\x66\x8c' and b[2]&0xc0==0xc0 and
                   (b[2]>>3)&7<6 and b[2]&7!=4) or (
                   len(b)==4 and b[:3]==b'\x66\x41\x8c' and b[3]&0xc0==0xc0 and (b[3]>>3)&7<6)
        need(not canonical,'no admitted form hidden in negative table')
    return rows


def record(data,expected,sample_bytes,rows):
    need(136<len(data)<16<<20 and len(rows)==18,'complete bounded18-form cohort record')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()),'exact finite outcome, no alternate success')
    need(h['sample_bytes']==sample_bytes>0 and len(data)==136+22*sample_bytes+40+8704,
         'actual ELF-bound complete record extent')
    need(576<=h['xsave_bytes']<=65536 and h['xcr0']&3==3,'qualified XSAVE extent')
    need(h['completed']==h['pairs']==19 and not any(data[136+19*sample_bytes:136+22*sample_bytes]),
         'all19 declared slots occupied; every unused slot and whole negative sample zero')
    group=expected['group'];q=data[-8704:]
    need(group in range(5) and struct.unpack_from('<8Q',q)==
         (0x315247455332494c,1,8704,group,36,63,0,0),
         'complete actual-before query header, counts and reserved bytes')
    queries=[]
    for i,c in enumerate(rows):
        pair=[]
        for lane in (0,1):
            at=64+240*(2*i+lane)
            attempted,result,identity,actual_lane=struct.unpack_from('<4Q',q,at)
            before=struct.unpack_from('<18Q',q,at+32)
            pc,next_pc,first,end,version,policy,code,length=struct.unpack_from('<4Q4I',q,at+176)
            selector,actual=struct.unpack_from('<2Q',q,at+224)
            need((attempted,result,identity,actual_lane)==(1,0,10000+18*group+i,lane) and
                 0<pc<1<<47 and pc%4096==4096-c['tail'] and next_pc==pc+c['length'] and
                 (first,end,version,policy,code,length)==(0,0,1,1,287,c['length']),
                 'genuine original PC/fetch geometry and exact typed NONE result')
            need(0<before[4]<1<<47 and before[4]%16==0 and 0<before[6]<1<<47 and
                 before[6]%4096==0 and before[7]==before[6]+8 and
                 all(before[r]==0x123456789abcdef+0x101010101010101*r for r in range(16)if r not in(4,6,7)),
                 'actual seeded full GPR inputs and genuine stack/data pointers')
            initial=before[c['destination']]
            need(0<=selector<=0xffff and initial&~0xffff and actual==(initial&~0xffff)|selector,
                 'actual selector result and exact preserved upper48 GPR bits')
            pair.append((before,pc,next_pc,first,end,version,policy,code,length,selector,actual))
        need(pair[0]==pair[1],'complete native/TF actual-before inputs, selector and literal output agree')
        queries.append(pair[0])
    return dict(operation='completed',pairs=19,new_pairs=18,refusals=h['refusals'],actual_before_queries=36,
        ending_pairs=sum(c['tail']==c['length']for c in rows),crossing_pairs=sum(c['tail']<c['length']for c in rows),
        header=h,query_bytes=len(q),query_sha256=hashlib.sha256(q).hexdigest(),query_values_sha256=digest(queries),
        architecture='The unchanged authenticated C oracle compares complete native/TF frames, live registers/selectors/flags, full FP/XSAVE, memory/source and release. Added literal checks require unchanged upper GPR bits/flags/full FP. This reader checks full capture extent, actual ELF sizes and complete query observations; it does not claim independent full-frame replay.')


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
          fixture=['sh','tools/page-entry/selected/tests/segment_read/build.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group 0..4>'],
          native=[[f'segment-read-{g}']for g in range(5)],selectors=[{}]*5))
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
    stem=stamp+'-page-selected-segment-read-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-segment-read-v1',status='failed',
        scope='Canonical MOV r16,Sreg:90 exact original-PC native/TF pairs plus5 startup pairs. All6 actual selectors and15 non-SP destinations; upper48 GPR bits, all flags, full FP/XSAVE, memory, source and closure preserved. Ending/crossing geometry, original47 refusals plus63 new neighbors. No memory destination, selector load, interrupt-shadow,32/64-bit form, application or performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_segment_read.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(pairs=0,new_pairs=0,startup_pairs=0,refusals=0,actual_before_queries=0,ending_pairs=0,crossing_pairs=0))
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
    fixture_outputs=[private/'segment-read'/f'segment-read-{group}'for group in range(5)]
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
        need(fact(pin(FIXTURE/'OUTCOMES.json'))['sha256']==OUTCOMES_SHA,'exact five-command protocol')
        protocol=decode((FIXTURE/'OUTCOMES.json').read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==5 and [c['exit']for c in commands]==[0]*5 and
          [c['group']for c in commands]==list(range(5)) and [c['name']for c in commands]==[f'group{g}'for g in range(5)] and
          [c['argv']for c in commands]==[[f'segment-read-{g}']for g in range(5)] and
          [c['environment_delta']for c in commands]==[{}]*5 and
          all(c['actual_before_queries']==36 for c in commands),
          'closed cases, actual selectors, exits, query counts and unchanged bounds')
        cases=catalogue();r['catalogue']=dict(source=fact(FIXTURE/'cases.inc'),table=fact(FIXTURE/'cases.json'),rows_sha256=digest(cases),pairs=90,selectors=6,destinations=15,canonical_family=287)
        products=builder.prepare();output=private/'segment-read';output.mkdir()
        recipe_path=pin(FIXTURE/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(5):
            name=f'segment-read-{group}';values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
                '$parent_dir':SELECTED.parent,'$decoder_archive':products['archive'],'$output_dir':output,'$group':group}
            argv=expand(lines[0],values);path=output/name
            need(argv[-2:]==['-o',str(path)] and all(x in argv for x in ('-O2','-g','-nostdlib','-static','-no-pie','-Werror')),
                 'exact optimized bounded fixture recipe')
            sources=[SELECTED/'step_owner.c',SELECTED/'lifecycle_loader.c',SELECTED/'tests/generic/tf_controls.c',FIXTURE/'fixture.c',SELECTED/'tests/generic/fixture.S']
            state={};states[name]=state
            headers(name+'-headers',argv,list(map(str,sources)),products['archive'],builder,pin,aliases,run,state)
            run(name+'-link',argv,profile='fixture_link',env=builder.environment);binary(path);state['artifact']=artifact(path)
            state['elf']=plain_executable(path)
            _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
            need(out==err==b'','no unresolved fixture imports')
            _,out,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual symbol inspection stderr');roots={'samples','negative_sample','result','refused_last','segment_queries'}
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
                symbols['refused_last']['bytes']==40 and symbols['segment_queries']['bytes']==8704 and
                136+22*sample+40+8704<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=136+22*sample+40+8704,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            group=expected['group'];value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases[18*group:18*(group+1)])
            need(value['operation']=='completed','no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=1 if key=='startup_pairs'else value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(pairs=95,new_pairs=90,startup_pairs=5,refusals=550,
            actual_before_queries=180,ending_pairs=24,crossing_pairs=66) and
            len(r['cases'])==5 and all(c['status']=='accepted_observation'for c in r['cases']),'whole exact five-command cohort')
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
