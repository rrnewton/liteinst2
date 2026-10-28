#!/usr/bin/env python3
"""Full existing finite cohorts linked to the exact opt-in bridge memset."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys

sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_register_time_compare import decode
import page_selected_fast_zero_cases as cases
import page_selected_fast_zero_link as link

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])
COUNTS={'generic':4,'chain':23,'register':4,'controls':14,'repeat':2}


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def publish(path,r,receipt):
    result={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','source','source_unchanged',
        'started_utc','cpu','hardware','bounds','reproduce','cleanup_complete')}
    result.update(environment=ENV,required_native_processes=47,
        attempted_native_processes=sum(c['profile']=='native'for c in r['commands']),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),private_receipt=fact(receipt),
        inputs_sha256=digest(r['inputs_before']),artifacts_sha256=digest(r['artifacts_before']),
        aliases_sha256=digest(r['aliases']),extraction_sha256=digest(r.get('extraction')),
        primitive_reference=r.get('configuration',{}).get('primitive_reference'),
        build_status=r.get('build',{}).get('status'),tool_versions=r.get('build',{}).get('numeric_versions'),
        tool_hashes={k:{n:v[n]for n in ('bytes','sha256')}for k,v in r.get('build',{}).get('tools',{}).items()},
        extraction_status=r.get('extraction',{}).get('status'),
        failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
        cohorts=[dict(name=g['name'],status=g['status'],required_processes=COUNTS[g['name']],
            attempted_processes=sum(x['profile']=='native'for x in g['commands']),totals=g['totals'],
            cases_sha256=digest(g['cases']),build_sha256=digest(g.get('build')),
            cases=[{k:c[k]for k in ('name','accepted','status','actual_exit','exit','process_outcome',
                    'attempted_operation_status','operation_completed','actual_failed_operation','header',
                    'outcome','record','sections','control_prefix','control_expected_failure_verified',
                    'expected_operation','environment_delta')if k in c}for c in g['cases']],
            processes=[{k:x.get(k)for k in ('name','exit','expected_exit','reaped','timed_out')}
                       for x in g['commands']if x['profile']=='native'])for g in r['cohorts']],
        interpretation='Exact existing full-state C comparators and existing saved-record readers, linked to actual fast bridge memset. Required failed operations remain failed. No default enablement, real-program completion, performance, full-B2 or full-B3 claim.')
    text=json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+'\n'
    need(len(text.encode())<=90000 and not any(x and len(x)>1 and x in text for x in
         (str(ROOT),str(Path.home()),platform.node(),'/home/')),'bounded private-location-free public projection')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    a=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',a.expect_revision)and
         len(os.sched_getaffinity(0))==1,'assertions, exact revision and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-fast-zero-'+a.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique publication path')
    r=dict(schema=1,profile='page-selected-fast-zero-qualification-v1',status='failed',
        scope='Actual opt-in bridge memset in unchanged generic, TRACE, register positive/capacity/control and REP finite oracles. All47 native commands required; raw state private. No default/runtime profile enablement or performance credit.',
        expected_revision=a.expect_revision,source=None,source_unchanged=False,started_utc=stamp,cpu=cpu,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_fast_zero.py','--expect-revision',a.expect_revision],
        commands=[],cohorts=[dict(name=k,status='not_started',commands=[],cases=[],totals=copy.deepcopy(cases.INITIAL_TOTALS[k]))for k in COUNTS],
        error=None,final_errors=[])
    pins,binaries,aliases={},{},{};pending=[]
    def pin(path):
        lexical=str(Path(path).absolute());p=Path(path).resolve(strict=True);value=fact(p)
        need(lexical not in aliases or aliases[lexical]==str(p),'input lexical alias changed')
        aliases[lexical]=str(p)
        need(str(p)not in pins or pins[str(p)]==value,'pinned input changed')
        pins[str(p)]=value;return p
    def observation(path):
        p=Path(path);return dict(fact(p),mode=p.stat().st_mode&0o777)
    def binary(path):
        p=Path(path).resolve(strict=True);v=observation(p)
        need(str(p)not in binaries or binaries[str(p)]==v,'retained artifact changed')
        binaries[str(p)]=v;return p
    def closure():
        need(all(fact(p)==v for p,v in pins.items())and all(observation(p)==v for p,v in binaries.items()),'input/artifact closure')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'input alias closure')
    def runner(directory,cohort=None):
        def run(label,argv,expected=0,profile='native',env=None,record=False,step=False):
            closure();native=profile=='native'
            row=dict(name=label,cohort=cohort['name']if cohort else 'build',argv=list(map(str,argv)),profile=profile,
                expected_exit=expected,bounds=PROFILES[profile],capture_limit=(65536 if cohort and cohort['name']=='chain' else 8192) if native else (4<<20 if cohort and cohort['name']=='chain' else 1<<20),
                environment=dict(ENV,**(env or {})),record_requested=native,standalone_signal_preparation=native,
                directory=str(directory))
            r['commands'].append(row)
            if cohort is not None:cohort['commands'].append(row)
            out,err=invoke(row,directory,cpu,record=native,step=native)
            need(type(row['exit'])is int and row['exit']==expected,'exact process outcome: '+label)
            return row,out,err
        return run
    run=runner(private);builder=Build(r,private,pin,binary,run)
    try:
        r['source']=source();need(r['source']['revision']==a.expect_revision,'exact clean committed revision')
        r['hardware']=hardware(cpu)
        configuration=decode(pin(HERE/'page_selected_fast_zero_inputs.json').read_bytes());r['configuration']=configuration
        need(configuration['schema']==1 and configuration['native_processes']==COUNTS and configuration['native_bounds']==PROFILES['native'],
             'closed exact cohort and bounds')
        for item in configuration['sources']:
            need(fact(pin(ROOT/item['path']))=={k:item[k]for k in ('bytes','sha256')},'exact reviewed source input')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'],profile='metadata')
        need(not err,'source enumeration stderr')
        for name in out.split(b'\0'):
            if name and not os.fsdecode(name).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        for module in tuple(sys.modules.values()):
            name=getattr(module,'__file__',None)
            if name and Path(name).resolve().is_relative_to(ROOT):pin(name)
        products=builder.prepare()
        gdb_environment=dict(builder.environment,XDG_CACHE_HOME=str(private/'gdb-cache'))
        for key in ('gdb','objdump','objcopy'):
            builder.tools[key]=pin(shutil.which(key,path=ENV['PATH']))
            _,out,err=run('version-'+key,[builder.tools[key],'--version'],profile='metadata',
                env=gdb_environment if key=='gdb' else builder.environment)
            need(out and not err,'actual inspection tool version')
            r['build']['versions'][key]=out.decode().strip();r['build']['tools'][key]=dict(path=str(builder.tools[key]),**fact(builder.tools[key]))
            version=re.search(r'\b([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',out.decode())
            need(version is not None,'actual numeric inspection tool version')
            r['build']['numeric_versions'][key]=[int(version[1]),int(version[2]),int(version[3] or 0)]
        leaf,body=link.extract(builder,products,ROOT,private,pin,binary,run,r,pending)
        reference=configuration['primitive_reference']['fast_function']
        need(body.hex()==reference['code_hex'] and len(body)==reference['bytes'] and
             hashlib.sha256(body).hexdigest()==reference['sha256'],
             'exact actual previously qualified primitive body, not a substituted implementation')
        for group in r['cohorts']:
            kind=group['name'];group['status']='failed';directory=private/kind;directory.mkdir()
            invoke_group=runner(directory,group);state=group['build']={}
            fixtures,FIXTURE=link.build_group(kind,builder,products,ROOT,directory,pin,binary,invoke_group,state,leaf,body,pending,r['final_errors'])
            fixture=next(iter(fixtures.values()));group['layouts']=state['layouts']
            if kind=='generic':cases.generic(group,directory,invoke_group,fixture,FIXTURE)
            elif kind=='chain':
                path,layout=link.chain_layout(fixture,builder,binary,invoke_group,state,pin,ROOT,gdb_environment)
                cases.chain(group,directory,invoke_group,path,layout,builder,binary,pin,ROOT)
            elif kind=='register':cases.register(group,directory,invoke_group,fixtures,FIXTURE)
            elif kind=='controls':
                group['layout']=state['layouts'][fixture.name]
                cases.controls(group,directory,invoke_group,fixture,FIXTURE)
            else:cases.repeat(group,directory,invoke_group,fixture,FIXTURE,0)
            need(len(group['cases'])==COUNTS[kind] and sum(x['profile']=='native'for x in group['commands'])==COUNTS[kind],
                 'every required original native command attempted once')
            group['status']='passed'
        need(all(g['status']=='passed'for g in r['cohorts'])and sum(c['profile']=='native'for c in r['commands'])==47,'all five complete cohorts')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        for path in pending:
            try:
                if path.is_file():binary(path)
            except BaseException as exc:r['final_errors'].append('partial output retention: '+repr(exc))
        for command in r['commands']:
            for capture in command.get('captures',{}).values():
                try:
                    path=Path(command['directory'])/capture['file']
                    need(path.parent==Path(command['directory'])and fact(path)=={k:capture[k]for k in ('bytes','sha256')},'capture extent/hash closure')
                    binary(path)
                except BaseException as exc:r['final_errors'].append('capture closure: '+repr(exc))
        r['inputs_before'],r['artifacts_before'],r['aliases']=pins,binaries,aliases
        for key,before,observe in (('inputs_after',pins,fact),('artifacts_after',binaries,observation)):
            after=r[key]={}
            for path,value in before.items():
                try:after[path]=observe(path);need(after[path]==value,'final byte/mode identity')
                except BaseException as exc:r['final_errors'].append(path+': '+repr(exc))
        try:closure()
        except BaseException as exc:r['final_errors'].append('alias/input closure: '+repr(exc))
        try:r['source_unchanged']=source()==r['source'];need(r['source_unchanged'],'source closure')
        except BaseException as exc:r['final_errors'].append('source closure: '+repr(exc))
        r['cleanup_complete']=bool(r['commands'])and all(c.get('reaped')and not c.get('error')and not c.get('timed_out')and
            not c.get('cleanup_errors')and all(d['closed']for d in c.get('descriptors',[]))for c in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']or r['build']['status']!='passed':r['status']='failed'
        receipt=private/'receipt.json';save(receipt,r);publish(public,r,receipt)
    print(json.dumps(dict(status=r['status'],native_commands=sum(c['profile']=='native'for c in r['commands']),
                         failure_type=r['error'].split(':',1)[0]if r['error']else None)))
    return 0 if r['status']=='passed'else 1


if __name__=='__main__':raise SystemExit(main())
