#!/usr/bin/env python3
"""Canonical KMOVQ64 (default) or explicit KMOVD32; eight bounded full-state cohorts."""
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
from page_selected_kmovq import observations
from page_selected_kmovd_promotions import promotions as kd32_promotions

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/kmovq_register'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='258e66f5f7426318d16f76e5a471891451e82de35bfc9401d7df34f6ffe3f61e'
OUTCOMES32_SHA='9be39a319dacb968137544a7c9bcec9bde30eebbf20760df718d101daf2aad89'
CASES32_SHA='b2e82b5c65ce3891af8d15faaf47238c61d7369b797cd3d21b499cc48028fd13'
CASES_SHA='65e78baefa5bbdace91b9ffbad0265cbf6e854870dd753ed030900723d6c1d95'
MASK=(1<<64)-1
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def configuration(register_bits):
    need(type(register_bits)is int and register_bits in (32,64),'literal register width profile')
    if register_bits==32:
        return dict(name='kmovd-register',outcomes='OUTCOMES32.json',outcomes_sha=OUTCOMES32_SHA,
            cases='cases32.inc',build='build32.sh',code=1932,length=4,refusals=128,ending=40,crossing=120,
            scope='Canonical Code1932 non-ESP r32,K only.120 register pairings and40 endpoint/seed cases plus8 startup pairs. Complete64-bit GPR zero-extension, all other GPR/K/ZMM/flags/kernelFP/liveXSAVE/selectors/FS/GS/stack/data exact.320 actual-before typed NONE observations.38 new width32 neighbors and all old supplied literals remain checked. No memory operand, ESP, reverse form, real-program completion or performance claim. Supplied KD32 promotion is separate from native pairs.')
    return dict(name='kmovq-register',outcomes='OUTCOMES.json',outcomes_sha=OUTCOMES_SHA,
        cases='cases.inc',build='build.sh',code=1933,length=5,refusals=90,ending=32,crossing=128,
        scope='Canonical Code1933 non-RSP r64,K only.120 register pairings and40 endpoint width/geometry cases plus8 startup pairs. Original complete native/TF GPR/flags/kernelFP/liveXSAVE/all32ZMM/all8K/selectors/FS/GS/stack/data comparison and actual-before typed NONE queries. Every previous supplied byte remains checked; five old Q promotions and one exact D promotion require typed encoding and NONE acceptance, all8 RSP forms remain refused. No memory operand, reverse form, real-program completion or performance claim; the supplied D row is not native D evidence.')


def catalogue32():
    path=FIXTURE/'cases32.inc';need(fact(path)['sha256']==CASES32_SHA,'exact reviewed width32 literal matrix')
    rows=[]
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):continue
        m=re.fullmatch(r'  \{"([a-z0-9_]+)",(\d+),(\d+),([1-4]),\{((?:0x[0-9a-f]{2},){3}0x[0-9a-f]{2})\},UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\)\},',line)
        need(m is not None,'complete literal width32 case row')
        rows.append(dict(name=m[1],destination=int(m[2]),source=int(m[3]),tail=int(m[4]),
            encoding=bytes(int(v,16)for v in m[5].split(',')).hex(),value=int(m[6],16),initial=int(m[7],16)))
    # Independent complete destination-byte table; no production decoder or result supplies expected values.
    registers=[0,1,2,3,5,6,7,8,9,10,11,12,13,14,15]
    prefixes=['fb']*7+['7b']*8
    modrm=[0xc0,0xc8,0xd0,0xd8,0xe8,0xf0,0xf8,0xc0,0xc8,0xd0,0xd8,0xe0,0xe8,0xf0,0xf8]
    expected=[]
    def add(name,d,k,t,v,pre,mod):
        expected.append(dict(name=name,destination=d,source=k,tail=t,
            encoding='c5'+pre+'93'+format(mod+k,'02x'),value=v,
            initial=0xa5a55a5a00000000|((v^0xffffffff)&0xffffffff)))
    for d,pre,mod in zip(registers,prefixes,modrm,strict=True):
        for k in range(8):
            add(f'matrix_r{d}_k{k}',d,k,1+len(expected)%4,
                0x8001020304050607^((d+1)<<32)^((k+1)<<12),pre,mod)
    for d,k,pre,mod in ((0,0,'fb',0xc0),(15,7,'7b',0xf8)):
        for p,v in enumerate((0,MASK,0xffffffff00000000,0x80000001,0x0123456789abcdef)):
            for t in (4,1,2,3):add(f'width32_r{d}_k{k}_p{p}_t{t}',d,k,t,v,pre,mod)
    need(rows==expected and len({r['name']for r in rows})==160 and
         len({(r['destination'],r['source'])for r in rows[:120]})==120 and
         all(r['destination']!=4 and r['initial']>>32 and
             r['initial']!=r['value'] and r['initial']!=(r['value']&0xffffffff)for r in rows),
         'all120 pairings and40 width32 endpoint geometries with stale upper32 destination')
    return rows


def catalogue(register_bits=64):
    configuration(register_bits)
    if register_bits==32:return catalogue32()
    path=FIXTURE/'cases.inc';need(fact(path)['sha256']==CASES_SHA,'exact reviewed literal matrix')
    rows=[]
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):continue
        m=re.fullmatch(r'  \{"([a-z0-9_]+)",(\d+),(\d+),([1-5]),\{((?:0x[0-9a-f]{2},){4}0x[0-9a-f]{2})\},UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\)\},',line)
        need(m is not None,'complete literal case row')
        rows.append(dict(name=m[1],destination=int(m[2]),source=int(m[3]),tail=int(m[4]),
            encoding=bytes(int(v,16)for v in m[5].split(',')).hex(),value=int(m[6],16),initial=int(m[7],16)))
    # Independent destination-byte table, not the production classifier.
    prefixes=['e1']*7+['61']*8
    registers=[0,1,2,3,5,6,7,8,9,10,11,12,13,14,15]
    modrm=[0xc0,0xc8,0xd0,0xd8,0xe8,0xf0,0xf8,0xc0,0xc8,0xd0,0xd8,0xe0,0xe8,0xf0,0xf8]
    expected=[]
    def add(name,d,k,t,v,pre,mod):
        expected.append(dict(name=name,destination=d,source=k,tail=t,
            encoding='c4'+pre+'fb93'+format(mod+k,'02x'),value=v,initial=v^MASK))
    for d,pre,mod in zip(registers,prefixes,modrm,strict=True):
        for k in range(8):
            add(f'matrix_r{d}_k{k}',d,k,1+len(expected)%5,
                0x8001020304050607^((d+1)<<32)^((k+1)<<12),pre,mod)
    for d,k,pre,mod in ((0,0,'e1',0xc0),(15,7,'61',0xf8)):
        for p,v in enumerate((0,MASK,0x8000000000000001,0x0123456789abcdef)):
            for t in (5,1,2,3,4):add(f'width_r{d}_k{k}_p{p}_t{t}',d,k,t,v,pre,mod)
    need(rows==expected and len({r['name']for r in rows})==160 and
         len({(r['destination'],r['source'])for r in rows[:120]})==120 and
         all(r['destination']!=4 and r['initial']!=r['value']for r in rows),'all120 pairings and40 full-width endpoint geometries')
    return rows


def record(data,expected,sample_bytes,rows,register_bits=64):
    cfg=configuration(register_bits)
    need(352<=len(data)<16<<20,'complete record within unchanged cap')
    promotion=kd32_promotions(data[-352:]);data=data[:-352]
    need(len(data)>=136,'complete retained header')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()),'exact finite outcome, no alternate success')
    need(h['sample_bytes']==sample_bytes>0 and
         len(data)==136+22*sample_bytes+40+5176+2048<16<<20,'actual ELF-bound complete record extent')
    need(576<=h['xsave_bytes']<=65536 and h['xcr0']&3==3,'qualified XSAVE extent')
    need(h['completed']==h['pairs']==21 and not any(data[136+21*sample_bytes:136+22*sample_bytes]),
         'all21 positive slots occupied and whole negative sample zero')
    obs=observations(data[-7224:-2048],expected['group'],h)
    q=data[-2048:];need(struct.unpack_from('<4Q',q)==(0x3151524d4b56324c,1,2048,40),
         'actual-before query trailer identity and completion count')
    need(not any(q[32:128]),'startup has no invented footprint query')
    queries=[]
    for i,c in enumerate(rows):
        pair=[struct.unpack_from('<4Q4I',q,32+96*(i+1)+48*lane)for lane in (0,1)]
        need(pair[0]==pair[1],'native and stepped actual-before NONE results agree completely')
        pc,next_pc,first,end,version,policy,code,length=pair[0]
        need(0<pc<1<<47 and pc%4096==4096-c['tail'] and next_pc==pc+cfg['length'] and
             (first,end,version,policy,code,length)==(0,0,1,1,cfg['code'],cfg['length']),
             'actual original PC geometry and exact closed typed zero-write effect')
        queries.append(pair[0])
    return dict(operation='completed',pairs=21,new_pairs=20,refusals=h['refusals'],
        promoted_encoding_checks=5,promoted_footprint_queries=5,actual_before_queries=40,
        kd32_typed_promotions=promotion['typed_promotions'],
        kd32_supplied_none_queries=promotion['supplied_none_queries'],kd32_promotion=promotion,
        ending_pairs=sum(c['tail']==cfg['length']for c in rows),
        crossing_pairs=sum(c['tail']<cfg['length']for c in rows),
        header=h,observations=obs,query_bytes=len(q),query_sha256=hashlib.sha256(q).hexdigest(),
        query_values_sha256=digest(queries),
        architecture='Authenticated C oracle compares complete native/TF state and literal effects; this reader checks complete records, actual ELF extents, CPUID and actual query observations, not a second full-state replay.')


def publish(path,r,private):
    b=r.get('build',{});cfg=configuration(r['register_bits'])
    public={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','started_utc',
        'cpu','source','source_unchanged','hardware','totals','reproduce','bounds','cleanup_complete','catalogue','register_bits')}
    public.update(environment=ENV,private_receipt=fact(private/'receipt.json'),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),
        inputs_sha256=digest(r['inputs_before']),binaries_sha256=digest(r['binaries_before']),
        aliases_sha256=digest(r['aliases']),build_status=b.get('status'),
        tool_versions=b.get('numeric_versions'),tool_hashes={k:{a:v[a]for a in ('bytes','sha256')}
          for k,v in b.get('tools',{}).items()},fixture_build=r.get('fixture_build'),
        cases=r['cases'],failure_type=r['error'].split(':',1)[0]if r['error']else None,
        final_error_count=len(r['final_errors']),
        command_recipe=dict(product=['sh','tools/page-entry/selected/build.sh'],
          fixture=['sh','tools/page-entry/selected/tests/kmovq_register/'+cfg['build'],'<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected'],
          native=[[cfg['name']+f'-{g}']for g in range(8)],selectors=[{}]*8))
    text=json.dumps(public,sort_keys=True,indent=2,allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-location guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--register-bits',type=int,choices=(64,32),default=64);args=ap.parse_args()
    cfg=configuration(args.register_bits)
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision) and
         len(os.sched_getaffinity(0))==1,'assertions, exact revision and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-'+cfg['name']+'-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-'+cfg['name']+'-v1',status='failed',
        scope=cfg['scope'],register_bits=args.register_bits,
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_kmovq_register.py','--expect-revision',args.expect_revision,'--register-bits',str(args.register_bits)],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(pairs=0,new_pairs=0,startup_pairs=0,refusals=0,promoted_encoding_checks=0,
                    promoted_footprint_queries=0,actual_before_queries=0,ending_pairs=0,crossing_pairs=0,
                    kd32_typed_promotions=0,kd32_supplied_none_queries=0))
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
    fixture_outputs=[private/cfg['name']/(cfg['name']+f'-{group}')for group in range(8)]
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
        need(fact(pin(FIXTURE/cfg['outcomes']))['sha256']==cfg['outcomes_sha'],'exact eight-command protocol')
        protocol=decode((FIXTURE/cfg['outcomes']).read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==8 and [c['exit']for c in commands]==[0]*8 and
          [c['group']for c in commands]==list(range(8)) and [c['name']for c in commands]==[f'group{g}'for g in range(8)] and
          [c['argv']for c in commands]==[[cfg['name']+f'-{g}']for g in range(8)] and
          [c['environment_delta']for c in commands]==[{}]*8 and
          all(c['promoted_encoding_checks']==c['promoted_footprint_queries']==5 and c['actual_before_queries']==40 and
              c['kd32_typed_promotions']==c['kd32_supplied_none_queries']==1 for c in commands),
          'closed cases, actual selectors, exits, query counts and unchanged bounds')
        cases=catalogue(args.register_bits);r['catalogue']=dict(source=fact(FIXTURE/cfg['cases']),rows_sha256=digest(cases),pairs=160,unique_pairings=120)
        products=builder.prepare();output=private/cfg['name'];output.mkdir()
        recipe_path=pin(FIXTURE/cfg['build']);lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(8):
            name=cfg['name']+f'-{group}';values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
                '$parent_dir':SELECTED.parent,'$decoder_archive':products['archive'],'$output_dir':output,'$group':group}
            argv=expand(lines[0],values);path=output/name
            need(argv[-2:]==['-o',str(path)] and all(x in argv for x in ('-O2','-g','-nostdlib','-static','-no-pie','-Werror')),
                 'exact optimized bounded fixture recipe')
            sources=[SELECTED/'step_owner.c',SELECTED/'lifecycle_loader.c',SELECTED/'tests/generic/tf_controls.c',FIXTURE/'fixture.c',FIXTURE/'fixture.S']
            need(('-DKMV_REGISTER_BITS=32'in argv)==(args.register_bits==32),
                 'actual recipe selects the exact fixed register width')
            state={};states[name]=state
            headers(name+'-headers',argv,list(map(str,sources)),products['archive'],builder,pin,aliases,run,state)
            run(name+'-link',argv,profile='fixture_link',env=builder.environment);binary(path);state['artifact']=artifact(path)
            state['elf']=plain_executable(path)
            _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
            need(out==err==b'','no unresolved fixture imports')
            _,out,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual symbol inspection stderr');roots={'samples','negative_sample','result','refused_last','vpb_observations','kmr_queries','kd32_promotions'}
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
                symbols['refused_last']['bytes']==40 and symbols['vpb_observations']['bytes']==5176 and
                symbols['kmr_queries']['bytes']==2048 and symbols['kd32_promotions']['bytes']==352 and
                136+22*sample+40+5176+2048+352<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=136+22*sample+40+5176+2048+352,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            group=expected['group'];value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases[20*group:20*(group+1)],args.register_bits)
            need(value['operation']=='completed','no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=1 if key=='startup_pairs'else value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(pairs=168,new_pairs=160,startup_pairs=8,refusals=8*cfg['refusals'],promoted_encoding_checks=40,
            promoted_footprint_queries=40,actual_before_queries=320,ending_pairs=cfg['ending'],crossing_pairs=cfg['crossing'],
            kd32_typed_promotions=8,kd32_supplied_none_queries=8) and
            len(r['cases'])==8 and all(c['status']=='accepted_observation'for c in r['cases']),'whole exact eight-command cohort')
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
