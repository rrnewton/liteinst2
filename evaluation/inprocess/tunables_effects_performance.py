#!/usr/bin/env python3
"""Fixed60 native/plain mixed12/13/11/DR times, then two untimed maps DIFF cases.

Install before running any prerequisites: every receipt and this collector must
have the exact same clean source, reserved CPU and hardware. No old failed run,
counted duration, finite-only proof, or partial sample set is a benchmark result.
"""
import argparse
import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import re
import statistics
import sys

sys.dont_write_bytecode=True
from page_selected import ENV,fact,need,save
from checks import source
from run import hardware
from persistent_dynamic import BOUNDS,digest,imported_sources
from persistent_loop_effects_archive import Build
from persistent_loop_effects_build_default import before_loop_effects_default
from persistent_loop_effects_build import build_bridge,FEATURES
from persistent_loop_effects_performance_build import differential_bridge
from persistent_loop_effects_performance_counted import authenticate as counted_prerequisite
from persistent_loop_performance_qualification import authenticate as original_qualification
from page_selected_process import invoke
from page_cost_compare import ORDER as TIMED_ORDER,PROGRAM_ENV,program_invoke,build_dr,dr_diagnostics
from page_native_pair_performance import prepare_workload,namespace_join
from page_selected_effect_ls import finalize
import persistent_loop_effects_performance_reports as reports
import maps_view as maps
import namespace

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
TARGET=[30,512<<20,16<<20,60]
DR_TARGET=[30,16<<30,16<<20,60]
LANES=('native','release','dynamorio','differential')
ORDER=tuple((k,n,'release' if lane=='gated' else lane) for k,n,lane in TIMED_ORDER)+(
    ('ls',0,'differential'),('true',0,'differential'))
NAMES=tuple(k+'-'+str(n)+'-'+lane for k,n,lane in ORDER)
PROGRAMS=(('ls','/bin/ls',('-d','.'),b'.\n'),('true','/bin/true',(),b''))
FILES=('tunables_effects_performance.py','persistent_loop_effects_performance_build.py',
    'persistent_loop_effects_performance_counted.py','persistent_loop_effects_performance_counted_build.py',
    'persistent_loop_performance_qualification.py',
    'persistent_loop_effects_performance_reports.py')


def cohort(builder,products,private,pin,binary,aliases,run,r,sdk,counted_inputs):
    need(len(TIMED_ORDER)==60 and len(ORDER)==len(set(NAMES))==62,'original rotated60 plus two separate DIFF subjects')
    states={}; builds=r['release_builds']={}; roots={}
    (private/'external-inputs').mkdir()
    for kind,program,args,expected_stdout in PROGRAMS:
        original=pin(program)
        for lane in ('release','differential'):
            key=kind+'-'+lane; root=private/key; root.mkdir(); roots[kind,lane]=root
            holder=builds[key]={}
            def labelled(name,argv,**kwargs): return run(key+'-'+name,argv,**kwargs)
            if lane=='release':
                bridge=build_bridge(builder,products,root,pin,binary,aliases,labelled,holder,original,
                                    capture=False,retained_counters=False,differential=False)
            else:
                bridge=differential_bridge(builder,products,root,pin,binary,aliases,labelled,holder,original)
            built=holder['release_build']
            need(built['status']=='passed' and built['profile']=='persistent-loop-effects-release-v1' and
                 built['archive']==r['archive'] and built['capture'] is False and
                 'capture_config' not in built and 'counter_schema' not in built and
                 'counters' not in built and 'retained_counters' not in built and
                 built['active_domain']['differential']==(lane=='differential') and
                 built['persistent_binding']['mode']=='release' and
                 built['persistent_binding']['capture_version'] is None,
                 'actual plain release with no capture/counter instrumentation; separate maps diagnostic only')
            states[kind,lane]=prepare_workload(key,original,args,bridge,builder,private,pin,binary,run,r,namespace)
        normal=builds[kind+'-release']['release_build']; diagnostic=builds[kind+'-differential']['release_build']
        normal_output=roots[kind,'release']/'persistent-loop-effects-release'
        diagnostic_output=roots[kind,'differential']/'persistent-loop-effects-release-differential'
        need([x.replace(str(diagnostic_output),str(normal_output)) for x in diagnostic['argv']
              if x!='-DLI2_MAPS_DIFFERENTIAL=1']==normal['argv'] and
             diagnostic['argv'].count('-DLI2_MAPS_DIFFERENTIAL=1')==1,
             'actual compiled recipes differ only by MAPS_DIFFERENTIAL and output directory')
        a,b=normal['persistent_binding'],diagnostic['persistent_binding']
        need({k:v for k,v in a.items() if k not in ('header_paths','manifest')}==
             {k:v for k,v in b.items() if k not in ('header_paths','manifest')} and
             all(pin(a['header_paths'][n]['path']).read_bytes()==pin(b['header_paths'][n]['path']).read_bytes()
                 for n in a['header_paths']), 'whole identical release policy/archive/image headers in both maps modes')
        need(all(r[k][kind+'-release']==r[k][kind+'-differential'] for k in
                 ('system_inputs','namespace_plans','external_inputs')) and
             r['system_inputs'][kind+'-release']==counted_inputs[kind],
             'same actual workload/interpreter/dependencies in counted, release and DIFF cases')
    drrun,client,dr_env=build_dr(sdk,builder,private,pin,binary,run,r)
    dr_diagnostics(drrun,client,{k:states[k,'release'] for k in ('ls','true')},private,pin,binary,run,r,dr_env)
    need(len(r['dr_diagnostics'])==3 and all(x['status']=='passed' for x in r['dr_diagnostics']),
         'actual null-client/target mappings and zero/nonzero target exit propagation')
    for ordinal,(kind,repeat,lane) in enumerate(ORDER):
        name=NAMES[ordinal]; s=states[kind,'differential' if lane=='differential' else 'release']
        case=r['cases'][ordinal]; case['status']='failed'; env=PROGRAM_ENV; ns=None
        if lane=='native': argv=s['argv']
        elif lane=='dynamorio':
            argv=[drrun,'-quiet','-64','-root',drrun.parent.parent,'-c',client,'--',*s['argv']]; env=dr_env
        else:
            ns=private/(name+'-namespace')
            argv=[builder.tools['python'],'-B',s['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
                  '--namespace',ns,s['carrier'],s['original'],'--',*s['argv']]
        start=len(r['commands'])
        try:
            row,out,err=run(name,argv,profile='program_dr' if lane=='dynamorio' else 'program',env=env)
            need(out==(b'.\n' if kind=='ls' else b''),'exact full real-program stdout')
            if ns is None: need(not err,'exact empty native/DR stderr')
            else:
                namespace_join(s,ns,binary,r,namespace)
                args=(row['pid'],row['exit'],row['stdout_provenance_before'],s['images'],s['image_bytes'],
                      fact(s['carrier']),s['carrier_bytes'])
                case['observed']=reports.check(out,err,args,kind,lane)
                case['controls']=reports.controls(out,err,args,kind,lane)
            case['status']='passed'
        except Exception as error:
            case['error']=type(error).__name__+': '+str(error)
            if r['error'] is None: r['error']=case['error']
            actual=r['commands'][start:]
            need(len(actual)==1 and actual[0]['name']==name and type(actual[0].get('exit')) is int and
                 actual[0].get('reaped') is True and actual[0].get('cleanup_errors')==[] and
                 all(d.get('closed') is True for d in actual[0].get('descriptors',[])),
                 'continue the fixed schedule only after actual complete process/descriptor cleanup')
        finally:
            attempted=[c for c in r['commands'][start:] if c['name']==name]
            if attempted:
                row=attempted[-1]
                case.update({k:row.get(k) for k in ('exit','process_ns','timed_out','reaped','user_cpu_ns','system_cpu_ns',
                    'minor_faults','major_faults','voluntary_switches','involuntary_switches')})
                case['captures']={k:{f:v[f] for f in ('bytes','sha256')} for k,v in row.get('captures',{}).items()}
            print(json.dumps({k:case.get(k) for k in ('ordinal','workload','lane','status','exit','process_ns','error')}),flush=True)
    need(len(r['cases'])==62 and all(c['status']=='passed' for c in r['cases']) and r['error'] is None,
         'all62 original fixed attempts; no replacement, timeout exemption, dropped run or partial median')


def publish(path,r,private):
    fields='ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()
    stream=io.StringIO(); writer=csv.writer(stream,lineterminator='\n'); writer.writerow(fields)
    for case in r['cases']: writer.writerow([case.get(k) for k in fields])
    csv_bytes=stream.getvalue().encode()
    complete=r['status']=='passed' and r['source_unchanged'] and r['cleanup_complete'] and not r['final_errors'] and \
        len(r['cases'])==62 and all(c['status']=='passed' for c in r['cases'])
    stats={}
    for kind in ('ls','true'):
        stats[kind]={}
        for lane in LANES:
            cases=[c for c in r['cases'] if c['workload']==kind and c['lane']==lane]
            times=[c['process_ns'] for c in cases if c['status']=='passed']
            value=stats[kind][lane]=dict(planned=1 if lane=='differential' else 10,passed=len(times),
                                       timing_credit=bool(complete and lane!='differential'))
            if value['timing_credit']:
                need(len(times)==10 and all(type(t) is int and t>0 for t in times),'ten actual whole-process intervals')
                q=statistics.quantiles(times,n=4,method='inclusive')
                value.update(median_ns=statistics.median(times),q1_ns=q[0],q3_ns=q[2],iqr_ns=q[2]-q[0])
        if complete:
            ratios=stats[kind]['release_ratios']={lane:stats[kind]['release']['median_ns']/stats[kind][lane]['median_ns']
                for lane in ('native','dynamorio')}
            stats[kind]['within_10x_dynamorio']=ratios['dynamorio']<=10
    hw=dict(r['hardware']); flags=hw.pop('isa_flags')
    hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    value={k:r.get(k) for k in ('schema','profile','status','revision','source','source_unchanged','cleanup_complete','cpu',
        'bounds','reproduce','archive','prerequisite_archive','original_qualification','counted_prerequisite','counted_events')}
    value.update(hardware=hw,statistics=stats,private_receipt=fact(private/'receipt.json'),
        performance_target_met=all(stats[k]['within_10x_dynamorio'] for k in ('ls','true')) if complete else None,
        comparison_complete=bool(complete),whole_profile_qualified=False,
        csv=dict(file=path.with_suffix('.csv').name,bytes=len(csv_bytes),sha256=maps.H(csv_bytes)),
        rows=[{k:c.get(k) for k in fields} for c in r['cases']],
        case_error_types={str(c['ordinal']):c['error'].split(':',1)[0] for c in r['cases'] if c.get('error')},
        error_type=r['error'].split(':',1)[0] if r['error'] else None,final_error_count=len(r['final_errors']),
        commands=len(r['commands']),commands_sha256=digest(r['commands']),
        new_and_old_prerequisites={k:r.get(k) for k in ('direct_prerequisite','block_prerequisite','fused_prerequisite',
            'loop_component_prerequisite','effects_component_prerequisite','loop_native_prerequisite','loop_owner_prerequisite','loop_lifecycle_prerequisite')},
        reader_controls={NAMES[i]:dict(count=len(c['controls']['refusals']),sha256=digest(c['controls']))
            for i,c in enumerate(r['cases']) if 'controls' in c},
        maps_component=[{k:c.get(k) for k in ('mode','expected_exit','status','qualified_case','exit','duration_ns','captures')}
            for c in r['finite_cases']],
        maps_differential={c['workload']:c.get('observed') for c in r['cases'] if c['lane']=='differential'},
        dynamorio_client=r.get('dynamorio_client'),sdk_files=len(r.get('dynamorio_sdk',{})),
        sdk_manifest_sha256=digest(r.get('dynamorio_sdk',{})),
        dynamorio_build_commands_sha256=r.get('dynamorio_build_commands_sha256'),
        dr_diagnostics=[{k:v for k,v in item.items() if k!='error'} for item in r.get('dr_diagnostics',[])],
        tool_versions=r.get('build',{}).get('numeric_versions'),
        timing_scope='Actual monotonic pre-Popen through reap, including Python carrier/namespace startup and terminal output. Ten samples for each native/plain-release/null-client-DR lane/workload; medians and inclusive IQR only after all62 and final closure pass. Offline builds, counted cases, maps DIFF and DR identity diagnostics excluded. No cache-cold claim.',
        count_scope='Separate actual ABI4 four-subject receipt only. Linked ingress is not every kernel trap. actual_entries12 and actual_entries13 count their authenticated policy redirects, not inner iterations; entries_with12 and entries_with13 are membership. Overlapping route counters are not summed. No counted time substitutes for release time.',
        qualification_scope='All original392/522 and native41/PB/PF proofs plus five original components plus effects40/native28/focal56/lifecycle12 gates remain mandatory on identical source/CPU/hardware and their respective archives. This bounded LS/true result is not unrestricted application qualification.',
        order='Original page_cost_compare60: ten rounds, alternating workload order and all six lane permutations; then one separate DIFF subject per workload. No resampling.',
        limits_scope='Native/release/DIFF 30 CPU seconds,60 wall seconds,512MiB AS,16MiB file; original DR allowance16GiB AS with all other bounds equal.')
    payload=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    need(len(payload)<=96<<10 and len(csv_bytes)<=32<<10 and all(x.encode() not in payload+csv_bytes
        for x in (str(ROOT),str(Path.home()),'/home/',platform.node()) if len(x)>1),
        'bounded public numbers and portable reproduction; no host paths or raw logs')
    with path.with_suffix('.csv').open('xb') as f: f.write(csv_bytes)
    with path.open('xb') as f: f.write(payload)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    for name in ('counted','qualification'):
        ap.add_argument('--'+name+'-receipt',type=Path,required=True)
        ap.add_argument('--'+name+'-receipt-sha256',required=True)
    ap.add_argument('--sdk',type=Path,required=True)
    a=ap.parse_args(); os.chdir(ROOT)
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',a.expect_revision) and
         len(os.sched_getaffinity(0))==1,'exact revision, assertions and externally reserved singleton CPU')
    for name in ('counted','qualification'):
        key=name+'_receipt'; setattr(a,key,getattr(a,key).resolve(strict=True))
        need(getattr(a,key).is_relative_to(ROOT) and re.fullmatch('[0-9a-f]{64}',getattr(a,key+'_sha256')),
             'portable exact prerequisite identity')
    a.sdk=a.sdk.resolve(strict=True); cpu=next(iter(os.sched_getaffinity(0)))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-tunables-effects-performance-'+a.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem; private.mkdir(mode=0o700)
    public=HERE/'results'/(stem+'.json'); need(not public.exists() and not public.with_suffix('.csv').exists(),'fresh result paths')
    bounds=dict(BOUNDS,program_dr=DR_TARGET)
    need(bounds['program']==TARGET,'unchanged ordinary whole-process bounds')
    r=dict(schema=1,profile='tunables-effects-performance-v1',revision=a.expect_revision,expected_revision=a.expect_revision,
        status='failed',source=None,source_unchanged=False,cleanup_complete=False,cpu=cpu,hardware=hardware(cpu),bounds=bounds,
        commands=[],cases=[dict(ordinal=i,workload=k,repeat=n,lane=lane,status='not_run') for i,(k,n,lane) in enumerate(ORDER)],
        error=None,final_errors=[],namespace_aliases={},qualification_credit=False,whole_profile_qualified=False,
        finite_cases=[dict(mode=i,expected_exit=exit,status='not_run',qualified_case=0,
            supplied_return_control=(i==4),performance_credit=False) for i,exit in enumerate((0,125,125,125,125,0))],
        reproduce=['cpuset-alloc','run','--cores','1','--','python3','-B','evaluation/inprocess/tunables_effects_performance.py',
            '--expect-revision',a.expect_revision,'--counted-receipt',str(a.counted_receipt.relative_to(ROOT)),
            '--counted-receipt-sha256',a.counted_receipt_sha256,'--qualification-receipt',str(a.qualification_receipt.relative_to(ROOT)),
            '--qualification-receipt-sha256',a.qualification_receipt_sha256,'--sdk','${SDK}'])
    pins={}; aliases={}; artifacts={}; presence={}
    def pin(path,want=None):
        alias=Path(os.path.abspath(path)); p=alias.resolve(strict=True); value=fact(p)
        need(want is None or value=={k:want[k] for k in ('bytes','sha256')},'whole requested input')
        need(str(alias) not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p) not in pins or pins[str(p)]==value,'stable input bytes')
        aliases[str(alias)]=str(p); pins[str(p)]=value; return p
    def binary(path):
        p=Path(path).resolve(strict=True); value=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p) not in artifacts or artifacts[str(p)]==value,'stable artifact bytes/mode')
        artifacts[str(p)]=value; return p
    def closure():
        need(os.sched_getaffinity(0)=={cpu},'same reserved CPU')
        need(all(fact(p)==v for p,v in pins.items()),'whole unchanged inputs')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'whole unchanged artifacts/modes')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'whole unchanged aliases')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'unchanged loader configuration presence')
        finalize(r)
    def run(name,argv,profile='metadata',expected=0,env=None,record=False,step=False):
        closure(); need(not r['final_errors'] and not any(c['name']==name for c in r['commands']),'clean unique command')
        need(record is False and step is False,'plain release has no protected capture or step instrumentation')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=bounds[profile],capture_limit=16<<20,
                 environment=dict(ENV if env is None else env),expected_exit=expected)
        r['commands'].append(row)
        try:
            if name in NAMES:
                lane=ORDER[NAMES.index(name)][2]
                need(profile==('program_dr' if lane=='dynamorio' else 'program') and
                     row['bounds']==(DR_TARGET if lane=='dynamorio' else TARGET),'original fixed timing bounds')
            out,err=(program_invoke if name in NAMES else invoke)(row,private,cpu,record=record,step=step)
            need(type(row['exit']) is int and (expected is None or row['exit']==expected),'actual command outcome '+name)
            return row,out,err
        finally:
            for stream in ('stdout','stderr','record','preparation'):
                path=private/(name+'.'+stream); observed=row.get('captures',{}).get(stream)
                try:
                    if path.exists() or path.is_symlink():
                        value=fact(binary(path))
                        if observed is not None:
                            need(observed['file']==path.name and value=={k:observed[k] for k in ('bytes','sha256')},'actual retained capture')
                    else: need(observed is None,'missing actual capture')
                except BaseException as error: r['final_errors'].append('capture '+name+': '+repr(error))
            try:
                path=private/(name+'.json')
                if path.exists(): need(json.loads(binary(path).read_bytes())==row,'whole retained command JSON')
            except BaseException as error: r['final_errors'].append('command '+name+': '+repr(error))
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_loop_effects_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,env=env,expected=expected)
    builder=Build(r,private,pin,binary,build_run,('region.rs',),scalar_span=True,linked_epoch=True,mov_guard=True)
    try:
        r['source']=source(); need(r['source']['revision']==a.expect_revision,'exact clean final source; no historical seam')
        _,names,err=run('tracked-input-list',['git','-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
        required={('evaluation/inprocess/'+name).encode() for name in FILES}|{
            b'tools/page-entry/selected/build-persistent-loop-effects-release-differential.sh'}
        need(not err and required<=set(names.split(b'\0')),'all new adapter sources tracked before qualification')
        for name in names.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'): pin(ROOT/os.fsdecode(name))
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload'); imported_sources(pin)
        products=builder.prepare()
        need(builder.decoder_features==FEATURES and builder.extra_decoder_sources==('region.rs','mov_guard.rs','scalar_read.rs','loop_scalar.rs','byte_mov_guard.rs') and
             builder.record['status']=='passed' and builder.record['command_completed'] is True,'fresh exact mixed12/13/11 archive')
        r['archive']=fact(products['archive'])
        proof,counts,prerequisites,system_inputs=counted_prerequisite(a.counted_receipt,a.counted_receipt_sha256,r,pin,binary,products['archive'])
        r['counted_prerequisite']=proof; r['counted_events']=counts
        for key,value in prerequisites.items():
            if key.endswith('_prerequisite') or key=='prerequisite_archive': r[key]=value
        r['original_qualification']=original_qualification(a.qualification_receipt,a.qualification_receipt_sha256,r,pin,binary,r['prerequisite_archive'])
        maps.finite(builder,private,pin,binary,aliases,run,r)
        cohort(builder,products,private,pin,binary,aliases,run,r,a.sdk,system_inputs)
        need(not r['final_errors'],'complete retained command custody')
        r['status']='passed'
    except BaseException as error:
        if r['error'] is None: r['error']=type(error).__name__+': '+str(error)
    finally:
        try: r['final_errors'].extend(builder.finish())
        except BaseException as error: r['final_errors'].append('build finalization: '+repr(error))
        try: imported_sources(pin)
        except BaseException as error: r['final_errors'].append('imported closure: '+repr(error))
        for path in sorted(private.rglob('*')):
            if path.is_file() and not path.is_symlink():
                try: binary(path)
                except BaseException as error: r['final_errors'].append('artifact closure: '+repr(error))
        r.update(inputs=pins,artifacts=artifacts,aliases=aliases,presence=presence)
        try:
            closure(); need(source()==r['source'],'exact source unchanged after every child')
            r['source_unchanged']=True
        except BaseException as error: r['final_errors'].append('final closure: '+repr(error))
        r['cleanup_complete']=bool(r['commands']) and all(type(c.get('exit')) is int and c.get('reaped') is True and
            c.get('timed_out') is False and not c.get('error') and c.get('cleanup_errors')==[] and
            all(d.get('closed') is True for d in c.get('descriptors',[])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']: r['status']='failed'
        save(private/'receipt.json',r); publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)))))
    return int(r['status']!='passed')


if __name__=='__main__': raise SystemExit(main())
