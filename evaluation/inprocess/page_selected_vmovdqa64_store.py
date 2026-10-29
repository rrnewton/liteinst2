#!/usr/bin/env python3
"""One current-source store/load/rseq qualification; unchanged per-process bounds."""
import argparse
from datetime import datetime,timezone
import hashlib,json,os,platform,re,shutil,sys
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
import page_selected_vmovdqa64_family as load
import page_selected_vmovdqa64_store_record as store
from page_selected_vmovdqa64_store_rseq import registered_controls
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/vmovdqa64_store'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='b8ac14eb15f4ce0957c8b54cfc03cbb23d711d5cad64876424c5778242e1d044'
GENERATED_COMMON={'bytes':35305,'sha256':'74ed49741f7712f0defb06108735a971d9d409156836ef111789a8481a1d1c90'}
EXPECTED={
 'store':dict(vm256_typed_promotions=18,vm256_supplied_none_queries=18,vpe_typed_promotions=18,vpe_supplied_none_queries=18,
    pairs=171,new_pairs=161,startup_pairs=18,verified_memory_failures=8,refusals=2736,actual_before_queries=338,actual_range_queries=204,actual_none_queries=134,
    ending_pairs=124,crossing_pairs=37,typed_promotions=234,supplied_none_queries=216,supplied_range_queries=18,
    vpcm_typed_promotions=90,vpcm_supplied_none_queries=90,supplied_range_end_controls=54),
 'load':dict(vqa_store_typed_promotions=14,vqa_store_supplied_range_queries=14,vm256_typed_promotions=14,
    vm256_supplied_none_queries=14,pairs=170,new_pairs=160,startup_pairs=14,verified_memory_failures=4,
    refusals=1372,actual_before_queries=328,ending_pairs=123,crossing_pairs=37,typed_promotions=98,supplied_none_queries=98)}


def protocol(family,pin):
    fixture=FIXTURE if family=='store'else load.FIXTURE
    path=pin(fixture/'OUTCOMES.json')
    need(fact(path)['sha256']==(OUTCOMES_SHA if family=='store'else load.OUTCOMES_SHA),'exact full cohort protocol')
    p=decode(path.read_bytes());commands=p['commands']
    faults=store.FAULT_NAMES if family=='store'else('full-read-fault','alignment-fault','indexed-full-read-fault','indexed-alignment-fault')
    stem='vmovdqa64-store-'if family=='store'else'vmovdqa64-family-'
    selector='LI2_VQA64S_CONTROL'if family=='store'else'LI2_VQA64F_CONTROL'
    n=len(faults)
    need(p['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
      and p['record_header_fields']==list(store.NAMES) and p['record_header_format']=='<17Q'
      and len(commands)==10+n and [c['exit']for c in commands]==[0]*10+[125]*n
      and [c['name']for c in commands]==['group'+str(g)for g in range(10)]+list(faults)
      and [c['argv']for c in commands]==[[stem+str(g)]for g in range(10)]+[[stem+'0']]*n
      and [c['environment_delta']for c in commands]==[{}]*10+[{selector:name}for name in faults]
      and [c['group']for c in commands]==list(range(10))+[0]*n
      and [c['fault_kind']for c in commands]==[0]*10+list(range(1,n+1)),
      'every original/new process, selector, failed exit and unchanged bound')
    return fixture,commands,stem


def symbol_layout(path,text,family):
    sizes=dict(result=136,refused_last=40,vpb_observations=5000,v64_fault=96,vpc_queries=10304,
               vm64_promotions=2080,vm256_promotions=352)
    if family=='store':sizes.update(vpe_promotions=1216,v128_promotions=3808,vpcm_promotions=1504,
                                   store_memory=store.MEMORY_BYTES,store_ranges=800)
    else:sizes['vqa_store_promotions']=352
    roots=set(sizes)|{'samples','negative_sample'}
    symbols={};counts={k:0 for k in roots};_,_,segments=elf(path)
    for line in text.decode().splitlines():
        w=line.split()
        if w and w[-1]in roots:counts[w[-1]]+=1
        if len(w)!=4 or w[-1]not in roots:continue
        at,n,kind,key=w;at,n=int(at,16),int(n,16)
        need(kind in('b','B','d','D')and key not in symbols and n>0 and
             sum(s[0]==1 and s[1]==6 and s[3]<=at<at+n<=s[3]+s[6]for s in segments)==1,
             'whole unique actual writable NX record symbol')
        symbols[key]=dict(address=at,bytes=n)
    need(set(symbols)==roots and all(n==1 for n in counts.values()),'all required record symbols')
    intervals=sorted((v['address'],v['address']+v['bytes'])for v in symbols.values())
    need(all(a[1]<=b[0]for a,b in zip(intervals,intervals[1:])),'all record objects disjoint')
    sample=symbols['negative_sample']['bytes'];extent=sum(v['bytes']for v in symbols.values())
    need(symbols['samples']['bytes']==21*sample and all(symbols[k]['bytes']==n for k,n in sizes.items())and
         extent<16<<20,'actual ELF-sized complete sample array/trailers below unchanged cap')
    return symbols,sample,extent


def publish(path,r,private):
    columns=['name','expected_exit','actual_exit','duration_ns','pid','record_bytes','record_sha256','declared_pairs','completed_prefix','refusals','actual_before_queries']
    outcomes={family+'-'+case['name']:case.get('outcome',{})for family,cohort in r['cohorts'].items()for case in cohort['cases']}
    rows=[]
    for c in r['commands']:
        if c['profile']!='native':continue
        capture=c.get('captures',{}).get('record',{});value=outcomes.get(c['name'],{});head=value.get('header',{})
        rows.append([c['name'],c['expected_exit'],c.get('exit'),c.get('duration_ns'),c.get('pid'),capture.get('bytes'),capture.get('sha256'),
                     head.get('pairs'),head.get('completed'),value.get('refusals'),value.get('actual_before_queries')])
    b=r.get('build',{});registered=r.get('store_rseq',{})
    public={k:r.get(k)for k in('schema','profile','status','scope','expected_revision','started_utc','cpu','source','source_unchanged','hardware','bounds','reproduce','cleanup_complete')}
    public.update(private_receipt=fact(private/'receipt.json'),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
        inputs_sha256=digest(r['inputs_before']),binaries_sha256=digest(r['binaries_before']),aliases_sha256=digest(r['aliases']),
        build_status=b.get('status'),tool_versions=b.get('numeric_versions'),tools_sha256=digest(b.get('tools',{})),
        archive={k:b.get('artifacts',{}).get('decoder.a',{}).get(k)for k in('bytes','sha256')},
        cohorts={k:dict(accepted_processes=sum(x['status']=='accepted_observation'for x in v['cases']),totals=v['totals'])for k,v in r['cohorts'].items()},
        rseq=dict(status=registered.get('status','not_started'),accepted_cases=sum(c.get('accepted',False)for c in registered.get('cases',[])),
                  completed_operations=sum(c.get('outcome')=='completed'for c in registered.get('cases',[])),
                  required_refusals=sum(c.get('outcome')=='required_refusal'for c in registered.get('cases',[])),
                  guard_columns=['operation_exit','code','policy','length','first','end','guard_result','actual_trap','guard_calls','raw_calls_during_guard','rx_calls_during_guard'],
                  guards=[[c.get('operation_exit')]+[c.get('store_guard',{}).get(k)for k in('code','policy','length','first','end','guard_result','actual_trap','guard_calls','raw_calls_during_guard','rx_calls_during_guard')]for c in registered.get('cases',[])]),
        process_columns=columns,processes=rows,final_error_count=len(r['final_errors']),failure_type=r['error'].split(':',1)[0]if r['error']else None)
    text=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<16<<10,'compact public receipt below16KiB')
    need(not any(x and len(x)>1 and x in text for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-location guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,
         'assertions, exact revision and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-vmovdqa64-store-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-vmovdqa64-store-v1',status='failed',
        scope='Exact unmasked Code1838:161 native/TF pairs plus8 genuine failed stores; all14 old aligned-load processes and3 registered-store applications mandatory. Full C architectural oracle plus independent literal source, actual-before footprint and complete memory replay. Typed promotions and overflow tuples are supplied controls. No Code1847, late-DSO completion or performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_vmovdqa64_store.py','--expect-revision',args.expect_revision],
        commands=[],cohorts={},error=None,final_errors=[],totals={})
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
    fixture_outputs=[];generated_outputs=[]
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
        specs={name:protocol(name,pin)for name in('store','load')}
        tables=dict(store=store.catalogue(),load=load.catalogue())
        r['catalogues']={name:dict(source=fact(fixture/'cases.json'),compiled=fact(fixture/'cases.inc'),rows_sha256=digest(tables[name]))for name,(fixture,_,_)in specs.items()}
        products=builder.prepare();r['fixture_build']={}
        for family in('store','load'):
            fixture,commands,stem=specs[family];cases=tables[family]
            cohort=r['cohorts'][family]=dict(cases=[],totals={k:0 for k in EXPECTED[family]})
            recipe_path=pin(fixture/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
            generators=recipe(recipe_path,'"$python_bin"');need(len(generators)==int(family=='store'),'exact source-generator population')
            samples={};paths={}
            for group in range(10):
                name=stem+str(group);output=private/family/('group'+str(group));output.mkdir(parents=True)
                path=output/name;fixture_outputs.append(path);paths[name]=path
                values={'$cc_bin':builder.tools['cc'],'$python_bin':builder.tools['python'],'$source_dir':fixture,'$selected_dir':SELECTED,
                    '$parent_dir':SELECTED.parent,'$decoder_archive':products['archive'],'$output_dir':output,'$group':group}
                if family=='store':
                    prepared=output/'common.inc';generated_outputs.append(prepared)
                    pin(fixture/'prepare.py')
                    _,gout,gerr=run(name+'-prepare',expand(generators[0],values),profile='metadata',env=builder.environment)
                    need(not gerr and decode(gout)==GENERATED_COMMON and fact(binary(prepared))==GENERATED_COMMON,
                         'exact generator observation and inverse-prepared full generic fixture')
                argv=expand(lines[0],values)
                need(argv[-2:]==['-o',str(path)]and all(x in argv for x in('-O2','-g','-nostdlib','-static','-no-pie','-Werror')),
                     'exact optimized bounded fixture recipe')
                sources=[SELECTED/'step_owner.c',SELECTED/'lifecycle_loader.c',SELECTED/'tests/generic/tf_controls.c',fixture/'fixture.c',SELECTED/'tests/vmovdqu64/fixture.S']
                state={};states[name]=state
                headers(name+'-headers',argv,list(map(str,sources)),products['archive'],builder,pin,aliases,run,state)
                run(name+'-link',argv,profile='fixture_link',env=builder.environment);binary(path);state['artifact']=artifact(path)
                state['elf']=plain_executable(path)
                _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
                need(out==err==b'','no unresolved fixture imports')
                _,out,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
                need(not err,'actual symbol inspection stderr')
                symbols,sample,extent=symbol_layout(path,out,family);state['symbols']=symbols;samples[name]=sample
                r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),record_bytes=extent,headers_sha256=digest(state['headers']))
            for expected in commands:
                item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);cohort['cases'].append(item)
                row,out,err=run(family+'-'+expected['name'],[paths[expected['argv'][0]]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
                item['actual_exit']=row['exit'];need(out==expected['stdout'].encode()and err==expected['stderr'].encode(),'exact finite output')
                captured=row['captures']['record'];path=binary(private/captured['file'])
                need(fact(path)=={k:captured[k]for k in('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
                reader=store if family=='store'else load
                value=reader.record(path.read_bytes(),expected,samples[expected['argv'][0]],cases)
                align=expected['fault_kind']in((3,4)if family=='store'else(2,4))
                need(value['operation']==('completed'if expected['exit']==0 else 'failed_alignment'if align else 'failed_memory_write'if family=='store'else 'failed_memory_read'),
                     'no failed operation relabelled completed')
                for key in cohort['totals']:cohort['totals'][key]+=value[key]
                item.update(status='accepted_observation',outcome=value)
            need(cohort['totals']==EXPECTED[family]and len(cohort['cases'])==len(commands)and
                 all(c['status']=='accepted_observation'for c in cohort['cases']),'complete exact cohort with all required failed operations')
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
    print(json.dumps(dict(status=r['status'],cohorts={k:v['totals']for k,v in r['cohorts'].items()},receipt=str(public.relative_to(ROOT)))))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
