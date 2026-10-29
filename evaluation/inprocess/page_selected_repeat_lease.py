#!/usr/bin/env python3
"""Additive retained REP lease oracle; full native state, genuine faults and named supplied controls."""
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
from page_selected_repeat_lease_record import check,controls
import page_selected_repeat_lease_build as link

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])


def publish(path,r,private):
    build=r.get('build',{})
    result={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','started_utc',
        'cpu','hardware','source','source_unchanged','bounds','reproduce','totals','cleanup_complete')}
    columns=['name','status','exit','operation','evidence','completed_pairs','native_completed','native_failed',
             'actual_traces','retained_transfers','owner_error','record_bytes','record_sha256']
    cases=[]
    for x in r['cases']:
        o=x.get('outcome',{});f=x.get('record',{})
        cases.append([x['name'],x['status'],x.get('exit'),x['expected_operation'],x['evidence'],
            *[o.get(k)for k in columns[5:11]],f.get('bytes'),f.get('sha256')])
    result.update(environment=ENV,case_columns=columns,cases=cases,
        required_native_processes=46,attempted_native_processes=sum(x['profile']=='native'for x in r['commands']),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),cases_sha256=digest(r['cases']),
        private_receipt=fact(private/'receipt.json'),inputs_sha256=digest(r['inputs_before']),
        artifacts_sha256=digest(r['artifacts_before']),aliases_sha256=digest(r['header_aliases']),
        build_status=build.get('status'),finite_build_status=r.get('finite_build',{}).get('status'),
        build_sha256=digest(build),finite_build_sha256=digest(r.get('finite_build')),
        configuration_sha256=digest(r.get('configuration')),tool_versions=build.get('numeric_versions'),
        tools_sha256=digest(build.get('tools',{})),fixture=r.get('finite_build',{}).get('artifact'),
        failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
        interpretation='Required component cohort: 24 completed native/owner pairs, two genuine later-store faults, four real nested deliveries and 28 separately supplied negative operations; actual accepted counts are in totals/cases. Full per-TRACE UC/FP/data and two-side no-borrow base observations stay private. Crossing fallback compares architectural effects with separately exact native INT3 versus owner NX events. Original D/Q four processes remain separate unchanged obligations; no application, throughput or arbitrary restart claim.')
    text=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<20<<10,'compact 46-process public projection below20KiB')
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
    stem=stamp+'-page-selected-repeat-lease-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    r=dict(schema=1,profile='page-selected-repeat-lease-v1',status='failed',
        scope='Retained one-page sealed original-PC REP D/Q owner/custody, actual registered/unregistered and fallback paths, full native architectural state and required failed prefixes. No application/performance qualification.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_repeat_lease.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],totals=dict(completed_programs=0,completed_pairs=0,verified_failed_operations=0,
            old_startup_pairs=0,old_refusal_checks=0,native_completed=0,native_failed=0,
            supplied_mutations=0,real_signals=0,actual_traces=0,retained_transfers=0,
            actual_lease_closes=0,actual_lease_releases=0,reader_refusals=0),error=None,final_errors=[])
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
        r['configuration']=dict(profile='fixed-repeat-lease-v1',modes=list(range(46)),widths=[4,8],
            counts=[0,1,3,24],directions=[0,1],source_pages=3,retained_source_pages=1,
            native_completed=24,actual_faults=2,actual_signals=4,supplied_negative_processes=28,
            old_regressions_required_separately=dict(repeat_q=2,repeat_d=2))
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
        outcomes=decode(pin(ROOT/'tools/page-entry/selected/tests/repeat_lease/OUTCOMES.json').read_bytes())
        need(outcomes['schema']==1 and outcomes['cardinality']=={'processes': 46, 'successful_processes': 12, 'actual_failed_operations': 6, 'supplied_negative_processes': 28, 'native_completed': 24, 'native_failed': 2, 'startup_pairs': 46, 'old_refusals_per_process': 47} and
             outcomes['bounds']=={'core_bytes': 0, 'cores': 1, 'native_cpu_seconds': 5, 'wall_seconds': 15, 'native_address_bytes': 536870912, 'file_bytes': 16777216, 'capture_bytes': 8192} and len(outcomes['commands'])==46,
             'all46 exact observations and unchanged original native/resource bounds')
        names=['lease-4-df0-short', 'lease-4-df0-24', 'lease-4-df1-short', 'lease-4-df1-24', 'lease-8-df0-short', 'lease-8-df0-24', 'lease-8-df1-short', 'lease-8-df1-24', 'anonymous-fallback', 'crossing-fallback', 'two-borrow-fallback', 'unregistered', 'later-store-df0', 'later-store-df1', 'nested-seeding', 'nested-entry', 'nested-return', 'nested-revoking', 'copied-owner', 'replayed-ticket', 'changed-source-descriptor', 'supplied-fstat-identity', 'nonzero-rseq-word', 'changed-pin-snapshot', 'protected-rseq-overlap', 'remaining-overflow', 'revoke-result', 'sync-result', 'query-result', 'release-result', 'private-partial-registered-4-df0', 'private-overflow-registered-4-df0', 'private-partial-registered-4-df1', 'private-overflow-registered-4-df1', 'private-partial-registered-8-df0', 'private-overflow-registered-8-df0', 'private-partial-registered-8-df1', 'private-overflow-registered-8-df1', 'private-partial-unregistered-4-df0', 'private-overflow-unregistered-4-df0', 'private-partial-unregistered-4-df1', 'private-overflow-unregistered-4-df1', 'private-partial-unregistered-8-df0', 'private-overflow-unregistered-8-df0', 'private-partial-unregistered-8-df1', 'private-overflow-unregistered-8-df1']
        need([x['name']for x in outcomes['commands']]==names and
             [x['mode']for x in outcomes['commands']]==list(range(46)),'closed exact identities and order')
        stage='qualification'
        for mode,expected in enumerate(outcomes['commands']):
            operation='completed'if mode<12 else 'failed'
            evidence='real-pair'if mode<12 else 'real-fault'if mode<14 else 'real-signal'if mode<18 else 'supplied-negative'
            output='LI2_REPEAT_LEASE_PASS\n'if mode<12 else 'LI2_REPEAT_LEASE_EXPECTED_FAILURE\n'
            need(expected==dict(name=names[mode],mode=mode,operation=operation,evidence=evidence,
                 env={'LI2_REPEAT_LEASE_MODE':str(mode)},exit=0 if mode<12 else 125,stdout=output),
                 'fixed actual outcomes, never supplied success or broadened table acceptance')
            item=dict(name=expected['name'],mode=mode,status='failed',expected_operation=operation,
                      evidence=evidence,environment_delta=dict(expected['env']));r['cases'].append(item)
            command,out,err=run(expected['name'],[path],expected=expected['exit'],profile='native',
                env=dict(builder.environment,**expected['env']),record=True,step=True)
            item['exit']=command['exit'];need(out==output.encode()and err==b'','exact finite output')
            capture=command['captures']['record'];record_path=binary(private/capture['file'])
            need(fact(record_path)=={k:capture[k]for k in ('bytes','sha256')},'whole retained real capture')
            item['record']=fact(record_path);data=record_path.read_bytes();value=check(data,layout,mode,command['pid'])
            refused=controls(data,layout,mode,command['pid']);need(refused==2+13*int(mode==0)+int(mode in(1,12,26)),'two per-record refusals plus16 representative seam/prefix controls')
            r['totals']['reader_refusals']+=refused
            count=(1 if mode&1 else 3)if mode<8 else 2 if mode<12 else 0
            need(value['operation']==operation and value['old_startup_pairs']==1 and value['refusal_bytes']==47 and
                 value['completed_pairs']==count and value['native_completed']==count and
                 value['native_failed']==int(mode in(12,13))and value['expected_failure_verified']==bool(mode>=12)and
                 value['supplied_mutations']==int(mode>=18)and value['real_signals']==int(14<=mode<=17),
                 'exact actual native/signal versus supplied/failed denominators')
            r['totals']['completed_programs']+=int(mode<12);r['totals']['verified_failed_operations']+=int(mode>=12)
            for key in ('completed_pairs','native_completed','native_failed','supplied_mutations','real_signals',
                        'actual_traces','retained_transfers','actual_lease_closes','actual_lease_releases'):
                r['totals'][key]+=value[key]
            r['totals']['old_startup_pairs']+=1;r['totals']['old_refusal_checks']+=47
            item.update(status='accepted_observation',outcome=value,reader_refusals=refused)
        need(len(r['cases'])==46 and all(x['status']=='accepted_observation'for x in r['cases'])and
             all(r['totals'][k]==v for k,v in dict(completed_programs=12,completed_pairs=24,
                 verified_failed_operations=34,old_startup_pairs=46,old_refusal_checks=2162,
                 native_completed=24,native_failed=2,supplied_mutations=28,real_signals=4,reader_refusals=108,actual_lease_closes=20,actual_lease_releases=18).items()),
             'whole46process cohort with no incomplete or failed operation counted as completed')
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
