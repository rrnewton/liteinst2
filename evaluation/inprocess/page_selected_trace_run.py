#!/usr/bin/env python3
"""Additive genuine predecessor TRACE to MOV-run oracle; no application or timing claim."""
import argparse
from datetime import datetime,timezone
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
from page_selected import ENV,fact,need,save
from page_selected_generic import digest
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_register_time_compare import decode
from page_selected_trace_run_record import check,controls
import page_selected_trace_run_build as link

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])


def publish(path,r,private):
    build=r.get('build',{})
    result={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','started_utc',
        'cpu','hardware','source','source_unchanged','bounds','reproduce','totals','cleanup_complete')}
    result.update(environment=ENV,cases=[dict(name=x['name'],status=x['status'],exit=x.get('exit'),
        expected_operation=x['expected_operation'],environment_delta=x['environment_delta'],outcome=x.get('outcome'),record=x.get('record'))for x in r['cases']],
        required_native_processes=7,attempted_native_processes=sum(x['profile']=='native'for x in r['commands']),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),cases_sha256=digest(r['cases']),
        private_receipt=fact(private/'receipt.json'),inputs_sha256=digest(r['inputs_before']),
        artifacts_sha256=digest(r['artifacts_before']),aliases_sha256=digest(r['header_aliases']),
        build_status=build.get('status'),finite_build_status=r.get('finite_build',{}).get('status'),
        build_sha256=digest(build),finite_build_sha256=digest(r.get('finite_build')),
        configuration_sha256=digest(r.get('configuration')),tool_versions=build.get('numeric_versions'),
        tool_hashes={k:{a:v[a]for a in ('bytes','sha256')}for k,v in build.get('tools',{}).items()},
        fixture=r.get('finite_build',{}).get('artifact'),
        failure_type=r['error'].split(':',1)[0] if r['error'] else None,final_error_count=len(r['final_errors']),
        interpretation='One completed fixed predecessor/block/whole native program and two genuine TRACE-run miss/hit executions; six required failed operations. Supplied proof mutations are named separately. Existing 4 run, 14 run-control and 23 chain processes remain separate obligations. No production-controller, rseq, capacity, application or timing claim.')
    text=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<10<<10,'compact public projection below10KiB')
    need(not any(x and len(x)>1 and x in text for x in
        (str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-location guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    args=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and
         re.fullmatch('[0-9a-f]{40}',args.expect_revision),'assertions, exact revision and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-trace-run-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    r=dict(schema=1,profile='page-selected-trace-run-v1',status='failed',
        scope='Fixed ADD predecessor and two dependent MOVs with independent predecessor/block/whole native observations, genuine TRACE miss/hit and six required failed prefixes. Standalone owner/proof API only; no runtime controller, rseq, geometry/capacity or performance credit.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_trace_run.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],totals=dict(completed_programs=0,completed_runs=0,verified_failed_operations=0,
            old_startup_pairs=0,old_refusal_checks=0,native_completed=0,native_failed=0,
            supplied_mutations=0,real_signals=0,genuine_predecessor_traces=0,generated_traces=0,reader_refusals=0),
        error=None,final_errors=[])
    pins,binaries,aliases={},{},{}
    def pin(path):
        lexical=str(Path(path).absolute());p=Path(path).resolve(strict=True);value=fact(p)
        need(lexical not in aliases or aliases[lexical]==str(p),'input resolution changed')
        aliases[lexical]=str(p)
        need(str(p)not in pins or pins[str(p)]==value,'input changed')
        pins[str(p)]=value;return p
    def artifact(path):
        p=Path(path);return dict(fact(p),mode=p.stat().st_mode&0o777)
    def binary(path):
        p=Path(path).resolve(strict=True);value=artifact(p)
        need(str(p)not in binaries or binaries[str(p)]==value,'artifact changed')
        binaries[str(p)]=value;return p
    def closure():
        need(all(fact(p)==v for p,v in pins.items())and all(artifact(p)==v for p,v in binaries.items()),
             'input/artifact changed before command')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'input alias changed')
    stage='build'
    def run(label,argv,expected=0,profile='native',env=None,record=False,step=False):
        closure()
        row=dict(name=label,stage=stage,profile=profile,argv=list(map(str,argv)),bounds=PROFILES[profile],
            capture_limit=8192 if profile=='native'else 4<<20,expected_exit=expected,
            environment=dict(ENV if env is None else env),record_requested=record,standalone_signal_preparation=step)
        r['commands'].append(row)
        out,err=invoke(row,private,cpu,record=record,step=step)
        need(type(row['exit'])is int and row['exit']==expected,'actual process outcome')
        return row,out,err
    builder=Build(r,private,pin,binary,run)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact committed source')
        r['hardware']=hardware(cpu)
        r['configuration']=dict(profile='fixed-trace-run-v1',programs=1,modes=list(range(7)),
            predecessor='4883c001',copied='b87856341289c1',guard='01c0',
            prior_suites_unchanged=dict(register_run=4,register_run_controls=14,trace_chain=23))
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'],profile='metadata')
        need(not err,'source enumeration stderr')
        for value in out.split(b'\0'):
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(value))
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT):pin(p)
        products=builder.prepare()
        cache=private/'gdb-cache';cache.mkdir()
        builder.environment=dict(builder.environment,XDG_CACHE_HOME=str(cache))
        builder.tools['gdb']=pin(shutil.which('gdb',path=ENV['PATH']))
        _,out,err=run('version-gdb',[builder.tools['gdb'],'--version'],profile='metadata',env=builder.environment)
        need(not err and out,'actual file-only GDB identity')
        r['build']['versions']['gdb']=out.decode().strip()
        r['build']['tools']['gdb']=dict(path=str(builder.tools['gdb']),**fact(builder.tools['gdb']))
        path,layout=link.build(builder,products,ROOT,private,pin,binary,aliases,run,r,r['configuration'])
        outcomes=decode(pin(ROOT/'tools/page-entry/selected/tests/trace_run/OUTCOMES.json').read_bytes())
        need(outcomes['schema']==1 and outcomes['cardinality']==dict(processes=7,completed_programs=1,
            completed_runs=2,required_failed_operations=6,native_completed=18,native_failed=1,
            old_encoding_refusals_per_process=47,old_startup_pairs_per_process=1) and
            outcomes['bounds']==dict(core_bytes=0,cores=1,file_bytes=16<<20,
                native_address_bytes=512<<20,native_cpu_seconds=5,wall_seconds=15) and
            len(outcomes['commands'])==7,'all seven exact observations and unchanged original bounds')
        names=['trace-miss-hit','null-origin','changed-frame','consumed-origin','released-source','nested-tgkill','predecessor-read-fault']
        need([x['name']for x in outcomes['commands']]==names and
             [x['mode']for x in outcomes['commands']]==list(range(7)), 'closed fixed control identity/order')
        stage='qualification'
        for mode,expected in enumerate(outcomes['commands']):
            operation='failed' if mode else 'completed'
            output='LI2_TRACE_RUN_EXPECTED_FAILURE\n' if mode else 'LI2_TRACE_RUN_PASS native=3 miss=1 hit=1 predecessor=2 run=2\n'
            need(expected==dict(name=names[mode],mode=mode,operation=operation,
                 env={'LI2_TRACE_RUN_MODE':str(mode)},exit=125 if mode else 0,stdout=output),
                 'fixed real process outcome; no supplied catalogue can broaden acceptance')
            item=dict(name=expected['name'],status='failed',expected_operation=operation,
                      environment_delta=dict(expected['env']));r['cases'].append(item)
            command,out,err=run(expected['name'],[path],expected=expected['exit'],profile='native',
                env=dict(builder.environment,**expected['env']),record=True,step=True)
            item['exit']=command['exit'];need(out==output.encode() and err==b'','exact finite output')
            capture=command['captures']['record'];record_path=binary(private/capture['file'])
            need(fact(record_path)=={k:capture[k]for k in ('bytes','sha256')},'whole retained real state capture')
            item['record']=fact(record_path);data=record_path.read_bytes();value=check(data,layout,mode,command['pid'])
            if mode==0:r['totals']['reader_refusals']=controls(data,layout,command['pid'])
            need(value['operation']==operation and value['old_startup_pairs']==1 and value['refusal_bytes']==47 and
                 value['completed_runs']==(0 if mode else 2) and value['native_completed']==(0 if mode==6 else 3) and
                 value['native_failed']==int(mode==6) and value['expected_failure_verified']==bool(mode),
                 'exact independent native/failed/gated distinctions')
            r['totals']['completed_programs']+=int(not mode)
            r['totals']['verified_failed_operations']+=int(bool(mode))
            for key in ('completed_runs','native_completed','native_failed','supplied_mutations','real_signals',
                        'genuine_predecessor_traces','generated_traces'):
                r['totals'][key]+=value[key]
            r['totals']['old_startup_pairs']+=1;r['totals']['old_refusal_checks']+=47
            item.update(status='accepted_observation',outcome=value)
        need(len(r['cases'])==7 and all(x['status']=='accepted_observation'for x in r['cases']) and
            r['totals']==dict(completed_programs=1,completed_runs=2,verified_failed_operations=6,
                old_startup_pairs=7,old_refusal_checks=329,native_completed=18,native_failed=1,
                supplied_mutations=2,real_signals=1,genuine_predecessor_traces=7,generated_traces=0,reader_refusals=8),
            'whole finite cohort; failed operations never acquire completion credit')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        for command in r['commands']:
            for capture in command.get('captures',{}).values():
                try:
                    path=private/capture['file']
                    need(path.parent==private and fact(path)=={k:capture[k]for k in ('bytes','sha256')},'retained capture closure')
                    binary(path)
                except BaseException as exc:r['final_errors'].append('capture closure: '+repr(exc))
        r['inputs_before'],r['artifacts_before'],r['header_aliases']=pins,binaries,aliases
        for name,before,observe in (('inputs_after',pins,fact),('artifacts_after',binaries,artifact)):
            after=r[name]={}
            for p,value in before.items():
                try:after[p]=observe(p);need(after[p]==value,'final exact byte/mode identity')
                except BaseException as exc:r['final_errors'].append(p+': '+repr(exc))
        try:closure()
        except BaseException as exc:r['final_errors'].append('input/alias closure: '+repr(exc))
        try:r['source_unchanged']=source()==r['source'];need(r['source_unchanged'],'source closure')
        except BaseException as exc:r['final_errors'].append('source closure: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')and not x.get('timed_out')and not x.get('error')and
            not x.get('cleanup_errors')and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']or r['build']['status']!='passed' or r.get('finite_build',{}).get('status')!='passed':
            r['status']='failed'
        save(private/'receipt.json',r);publish(public,r,private)
    print(json.dumps(dict(status=r['status'],attempted=len(r['cases']),receipt=str(public.relative_to(ROOT)))))
    return 0 if r['status']=='passed'else 1


if __name__=='__main__':raise SystemExit(main())
