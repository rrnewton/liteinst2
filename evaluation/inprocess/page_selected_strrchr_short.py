#!/usr/bin/env python3
"""Three exact leaves and two original-PC native/all-NX/chained return blocks."""
import argparse
from datetime import datetime,timezone
import json,os,platform,re,shutil,sys
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
from page_selected_strrchr_short_record import leaf,connected

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/strrchr_short'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
OUTCOMES_SHA='44f8b7f287fa6d2a8199fecdcdc96a39326d487643e7933e4c557fad5b3e94c4'


def publish(path,r,private):
    b=r.get('build',{})
    public={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','started_utc',
        'cpu','source','source_unchanged','hardware','totals','reproduce','bounds','cleanup_complete')}
    public.update(environment=ENV,private_receipt=fact(private/'receipt.json'),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),
        inputs_sha256=digest(r['inputs_before']),binaries_sha256=digest(r['binaries_before']),
        aliases_sha256=digest(r['aliases']),build_status=b.get('status'),
        tool_versions=b.get('numeric_versions'),tool_hashes={k:{a:v[a]for a in ('bytes','sha256')}
          for k,v in b.get('tools',{}).items()},fixture_build=r.get('fixture_build'),
        cases=r['cases'],failure_type=r['error'].split(':',1)[0]if r['error']else None,
        final_error_count=len(r['final_errors']),
        command_recipe=dict(product=['sh','tools/page-entry/selected/build.sh'],
          fixture=['sh','tools/page-entry/selected/tests/strrchr_short/build.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected'],
          native=[['short-leaf-0'],['short-leaf-1'],['short-leaf-2'],['short-connected'],['short-connected']],
          selectors=[{},{},{},{'LI2_CHAIN_CASE':'12'},{'LI2_CHAIN_CASE':'13'}]))
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
    stem=stamp+'-page-selected-strrchr-short-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile='page-selected-strrchr-short-v1',status='failed',
        scope='Only three exact register encodings and two literal29-byte return programs.61 original-PC native/TF pairs and two three-lane programs, including five startup pairs total. Existing full-state C predicates and old80 KMOV refusals remain. No general EVEX/VEX/BMI, memory-form, rseq, longer path, real-program completion or performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_strrchr_short.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(individual_pairs=0,new_instruction_pairs=0,connected_programs=0,connected_lanes=0,
                    startup_pairs=0,refusal_checks=0,route_checks=0,genuine_trace_handoffs=0))
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
          and len(commands)==5 and [c['exit']for c in commands]==[0]*5 and
          [c['argv']for c in commands]==[['short-leaf-0'],['short-leaf-1'],['short-leaf-2'],['short-connected'],['short-connected']] and
          [c['environment_delta']for c in commands]==[{},{},{},{'LI2_CHAIN_CASE':'12'},{'LI2_CHAIN_CASE':'13'}],
          'closed cases, actual selectors, exits and unchanged bounds')
        products=builder.prepare();output=private/'short';output.mkdir()
        _,out,err=run('short-support',[builder.tools['python'],pin(FIXTURE/'prepare.py'),SELECTED,output],
                      profile='metadata',env=builder.environment)
        need(not err,'exact generation stderr');generated=decode(out)
        need([x['name']for x in generated]==['chain_support.inc','connected_body.inc'],'exact generated names')
        for row in generated:need(fact(pin(output/row['name']))=={k:row[k]for k in ('bytes','sha256')},'generated source binding')
        recipe_path=pin(FIXTURE/'build.sh');lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==2,'one leaf and one connected recipe')
        states={};r['fixture_build']={};layouts={};samples={}
        for group,name in enumerate(('short-leaf-0','short-leaf-1','short-leaf-2','short-connected')):
            chain=group==3;values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
                '$parent_dir':SELECTED.parent,'$decoder_archive':products['archive'],'$output_dir':output,'$group':group}
            argv=expand(lines[int(chain)],values);path=output/name
            need(argv[-2:]==['-o',str(path)] and all(x in argv for x in ('-O2','-g','-nostdlib','-static','-no-pie','-Werror')),
                 'exact optimized bounded fixture recipe')
            sources=([SELECTED/'tests/trace_chain/owner_wrapper.c',SELECTED/'lifecycle_loader.c',SELECTED/'tests/generic/tf_controls.c',
                SELECTED/'tests/trace_chain/route_controls.c',FIXTURE/'connected.c',FIXTURE/'fixture.S']if chain else
                [SELECTED/'step_owner.c',SELECTED/'lifecycle_loader.c',SELECTED/'tests/generic/tf_controls.c',FIXTURE/'fixture.c',FIXTURE/'fixture.S'])
            state={};states[name]=state
            headers(name+'-headers',argv,list(map(str,sources)),products['archive'],builder,pin,aliases,run,state)
            run(name+'-link',argv,profile='fixture_link',env=builder.environment);binary(path);state['artifact']=artifact(path)
            state['elf']=plain_executable(path)
            _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
            need(out==err==b'','no unresolved fixture imports')
            _,out,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual symbol inspection stderr');roots={'li2_chain_record','samples','ctl'}if chain else {'samples','negative_sample','result','refused_last','vpb_observations'}
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
            state['symbols']=symbols
            if not chain:
                sample=symbols['negative_sample']['bytes'];need(symbols['samples']['bytes']==21*sample and
                    symbols['result']['bytes']==136 and symbols['refused_last']['bytes']==40 and symbols['vpb_observations']['bytes']==5176,
                    'actual whole header/sample/negative/observer extents');samples[name]=sample
            else:
                builder.tools['gdb']=pin(shutil.which('gdb',path=ENV['PATH']))
                _,version,error=run('version-gdb',[builder.tools['gdb'],'--version'],profile='metadata',env=builder.environment)
                need(version and not error,'actual file-only GDB version');r['build']['tools']['gdb']=dict(path=str(builder.tools['gdb']),**fact(builder.tools['gdb']))
                _,out,err=run('short-dwarf',[builder.tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
                    '-iex','set debuginfod enabled off','-iex','maintenance set worker-threads 1','--readnow',
                    '--se='+str(path),'-x',pin(HERE/'page_selected_chain_dwarf.py')],profile='metadata',env=builder.environment)
                need(not err,'actual file-only DWARF stderr');layout=decode(out)
                need(set(layout)==roots and all(layout[k]['bytes']==symbols[k]['bytes']for k in roots),'actual ELF/DWARF extent agreement')
                layouts[name]=layout;state['layout']=layout
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),headers_sha256=digest(state['headers']))
        r['private_fixture_build']=states
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            value=leaf(path.read_bytes(),expected,samples[expected['argv'][0]])if expected['kind']=='leaf'else connected(path.read_bytes(),layouts['short-connected'],expected)
            need(value['operation']=='completed','no failed operation relabelled completed')
            if expected['kind']=='leaf':r['totals']['individual_pairs']+=value['pairs'];r['totals']['new_instruction_pairs']+=value['new_pairs']
            else:
                r['totals']['connected_programs']+=1;r['totals']['connected_lanes']+=3;r['totals']['route_checks']+=15
                r['totals']['genuine_trace_handoffs']+=value['genuine_trace_handoffs']
            r['totals']['startup_pairs']+=1;r['totals']['refusal_checks']+=value['refusals']
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(individual_pairs=61,new_instruction_pairs=58,connected_programs=2,connected_lanes=6,
            startup_pairs=5,refusal_checks=499,route_checks=30,genuine_trace_handoffs=12) and
            len(r['cases'])==5 and all(c['status']=='accepted_observation'for c in r['cases']),'whole exact five-command cohort')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
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
