#!/usr/bin/env python3
"""Finite same-PC native/all-NX/TRACE-chain qualification; no performance claim."""
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
from page_selected_chain_record import check
import page_selected_chain_fixture_build as link

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])


def publish(path,r,private):
    build=r.get('build',{})
    result={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','started_utc',
        'cpu','hardware','source','source_unchanged','bounds','reproduce','totals','cleanup_complete')}
    result.update(environment=ENV,cases=[dict(name=x['name'],status=x['status'],exit=x.get('exit'),
        expected_operation=x['expected_operation'],environment_delta=x['environment_delta'],outcome=x.get('outcome'),record=x.get('record'))for x in r['cases']],
        required_native_processes=23,attempted_native_processes=sum(x['profile']=='native'for x in r['commands']),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),cases_sha256=digest(r['cases']),
        private_receipt=fact(private/'receipt.json'),inputs_sha256=digest(r['inputs_before']),
        artifacts_sha256=digest(r['artifacts_before']),aliases_sha256=digest(r['header_aliases']),
        build_status=build.get('status'),finite_build_status=r.get('finite_build',{}).get('status'),
        build_sha256=digest(build),finite_build_sha256=digest(r.get('finite_build')),
        configuration_sha256=digest(r.get('configuration')),tool_versions=build.get('numeric_versions'),
        tool_hashes={k:{a:v[a]for a in ('bytes','sha256')}for k,v in build.get('tools',{}).items()},
        fixture=r.get('finite_build',{}).get('artifact'),
        failure_type=r['error'].split(':',1)[0] if r['error'] else None,final_error_count=len(r['final_errors']),
        interpretation='Accepted observations comprise12 completed three-lane programs and11 genuine failed operations; failed operations are never counted as completed. No production-dispatch, real-program or timing qualification.')
    text=json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+'\n'
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
    stem=stamp+'-page-selected-chain-oracle-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    r=dict(schema=1,profile='page-selected-chain-oracle-v1',status='failed',
        scope='Finite original-PC native/all-NX/chained full-state oracle;12 programs and11 failed operations. Existing cache/maps cohorts remain separate. No default enable, fullB2/B3, production dispatcher or performance claim.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_chain_oracle.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],totals=dict(completed_programs=0,completed_lanes=0,verified_failed_operations=0,
            old_startup_pairs=0,old_refusal_checks=0,route_checks=0,native_failed_observations=0),
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
            capture_limit=65536 if profile=='native'else 4<<20,expected_exit=expected,
            environment=dict(ENV if env is None else env),record_requested=record,standalone_signal_preparation=step)
        r['commands'].append(row)
        out,err=invoke(row,private,cpu,record=record,step=step)
        need(type(row['exit'])is int and row['exit']==expected,'actual process outcome')
        return row,out,err
    builder=Build(r,private,pin,binary,run)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact committed source')
        r['hardware']=hardware(cpu)
        inputs=decode(pin(HERE/'page_selected_chain_inputs.json').read_bytes());r['configuration']=inputs
        need(inputs['schema']==1 and inputs['finite_manifest_sha256']==
            'bd1b3b0f5d3d0d853b6e07914c54a747534c1c78cb61430237ef44b07302ec28' and
            inputs['report_route_manifest_sha256']=='36c9c9782193659a10e16f4a1811040651f35d323ab63a7bf3ef23766e34aef4',
            'reviewed immutable fixture and explicit qualified route successor')
        for row in inputs['sources']:
            need(fact(pin(ROOT/row['path']))=={k:row[k]for k in ('bytes','sha256')},'exact finite source/context input')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'],profile='metadata')
        need(not err,'source enumeration stderr')
        for value in out.split(b'\0'):
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(value))
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT):pin(p)
        products=builder.prepare()
        builder.tools['gdb']=pin(shutil.which('gdb',path=ENV['PATH']))
        _,out,err=run('version-gdb',[builder.tools['gdb'],'--version'],profile='metadata',env=builder.environment)
        need(not err and out,'actual file-only GDB identity')
        r['build']['versions']['gdb']=out.decode().strip()
        r['build']['tools']['gdb']=dict(path=str(builder.tools['gdb']),**fact(builder.tools['gdb']))
        path,layout=link.build(builder,products,ROOT,private,pin,binary,aliases,run,r,inputs)
        outcomes=decode(pin(ROOT/'tools/page-entry/selected/tests/trace_chain/OUTCOMES.json').read_bytes())
        need(outcomes['cardinality']==dict(failed_operation_processes=11,old_encoding_refusals_per_process=47,
            old_startup_pairs_per_process=1,positive_processes=12,route_controls_per_process=15,
            three_lane_programs=12,total_native_processes=23) and outcomes['bounds']==dict(core_bytes=0,cores=1,
            file_bytes=16<<20,native_address_bytes=512<<20,native_cpu_seconds=5,wall_seconds=15) and
            len(outcomes['commands'])==23,'all23 exact outcomes and unchanged bounds')
        stage='qualification'
        for expected in outcomes['commands']:
            item=dict(name=expected['name'],status='failed',expected_operation=expected['operation'],environment_delta=dict(expected['env']));r['cases'].append(item)
            command,out,err=run(expected['name'],[path],expected=expected['exit'],profile='native',
                env=dict(builder.environment,**expected['env']),record=True,step=True)
            item['exit']=command['exit']
            need(out==expected['stdout'].encode() and err==b'','exact finite output')
            capture=command['captures']['record'];record_path=binary(private/capture['file'])
            need(fact(record_path)=={k:capture[k]for k in ('bytes','sha256')},'complete actual retained state record')
            item['record']=fact(record_path)
            value=check(record_path.read_bytes(),layout,expected['case'],expected['mode'])
            need(value['operation']==expected['operation'] and value['old_startup_pairs']==1 and
                value['refusal_bytes']==47 and value['route_controls']==15,'actual operation and old controls')
            if expected['operation']=='completed':
                need(value['programs']==1 and value['lanes']==3 and value['nx']==expected['nx'] and
                    value['trace']==expected['trace'] and value['selected_callbacks']==expected['selected'],
                    'exact native/reference/chained event counts')
                r['totals']['completed_programs']+=1;r['totals']['completed_lanes']+=3
            else:
                for key in ('completed','owner_error','native_failed_observations','nonissued_negative_returns'):
                    need(value[key]==expected[key],'exact failed-operation field '+key)
                need(value['expected_failure_verified']is True and value['real_effects']==expected['actual_effects'] and
                     value['real_signals']==expected['actual_signals'],'genuine effects/signals versus named nonissued negatives')
                r['totals']['verified_failed_operations']+=1
                r['totals']['native_failed_observations']+=value['native_failed_observations']
            r['totals']['old_startup_pairs']+=1;r['totals']['old_refusal_checks']+=47;r['totals']['route_checks']+=15
            item.update(status='accepted_observation',outcome=value)
        need(len(r['cases'])==23 and all(x['status']=='accepted_observation'for x in r['cases']) and
            r['totals']==dict(completed_programs=12,completed_lanes=36,verified_failed_operations=11,
                old_startup_pairs=23,old_refusal_checks=1081,route_checks=345,native_failed_observations=2),
            'whole exact finite cohort, failures never counted as completions')
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
