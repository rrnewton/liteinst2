#!/usr/bin/env python3
"""One canonical bounded two-image group LS observation, never qualification.

Run after separate fixed5, dynamic5 and group native-loop validation. A fresh exact-source release
build and mandatory byte oracle precede one /bin/ls -d . subject under the old
30 CPU-second/60 wall-second/512 MiB/16 MiB limits. No retry, native baseline,
aggregate or speedup is produced. This does not replace any fixed or dynamic profile check or qualify group faults.
"""
import argparse,csv,io,json,os,re,sys,types,shutil
from pathlib import Path
sys.dont_write_bytecode=True
from linked_frontier_census import need,fact,git,git_bytes,source_paths,H,D
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SCRIPT='evaluation/inprocess/persistent_group_experiment.py'
PROGRAM=[30,512<<20,16<<20,60]
SHORT=[5,512<<20,16<<20,15]
REQUIRED=(SCRIPT,'evaluation/inprocess/linked_frontier_census.py',
    'evaluation/inprocess/persistent_group_build.py',
    'tools/page-entry/selected/build-persistent-group.sh',
    'tools/page-entry/selected/persistent_group_binding.py',
    'tools/page-entry/selected/persistent_group_controller.inc',
    'tools/page-entry/selected/persistent_group_plan.h',
    'tools/page-entry/selected/persistent_group_plan.c',
    'tools/page-entry/selected/persistent_group_compact.h',
    'tools/page-entry/selected/persistent_group_compact.c',
    'tools/page-entry/selected/persistent_group_source.inc',
    'tools/page-entry/selected/persistent_group_rseq.inc',
    'tools/page-entry/selected/persistent_group_runtime.h',
    'tools/page-entry/selected/persistent_group_lifetime.h')
MISS_REASONS=('none','root_unsupported','source_invalid','source_truncated','source_overlap',
    'outside_pair','head_limit','exit_limit','queue_limit','no_exit','rip_reach',
    'branch_reach','fallthrough_reach','guard_rip_reach','guard_follow_reach','root_selected','single_member','link_limit')
GROUP_KEYS=('version','status','failure_code','detail_abs','detail_negative','phase','serial',
    'generation','build_serial','offers','cold_attempts','publications','hits','cancelled','retirements',
    'permit_claims','entries','completed','unexpected','permit','opened_pages','closed_pages',
    'anchor_released','registration_rechecked','guest_data_fault','recovery_complete','first_error',
    'active','busy','misses')


def counters(stderr):
    """Whole actual numeric rows, retained even if a later outcome check fails."""
    def pairs(items):
        need(len(items)==len(dict(items)), 'no duplicate actual terminal keys')
        return dict(items)
    def uint(x):return type(x)is int and 0<=x<1<<64
    result={}
    for label in ('LI2_PERSISTENT_GROUP','LI2_LINKED_EPOCH','LI2_MAPS_VIEW','LI2_NATIVE'):
        prefix=(label+' ').encode();rows=[x for x in stderr.splitlines()if x.startswith(prefix)]
        need(len(rows)==1 and len(rows[0])<=4096, 'one complete '+label)
        value=json.loads(rows[0][len(prefix):],object_pairs_hook=pairs)
        need(type(value)is dict and value and all(uint(v)or type(v)is list and all(uint(x)for x in v)
             for v in value.values()), 'typed unsigned actual row '+label)
        need(prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()==rows[0],
             'canonical complete actual row '+label)
        need(value.get('version')==1, 'explicit version1 row '+label)
        result[label]=value
    d=result['LI2_PERSISTENT_GROUP'];l=result['LI2_LINKED_EPOCH']
    need(tuple(d)==GROUP_KEYS and type(d['misses'])is list and len(d['misses'])==len(MISS_REASONS),
         'exact group owner schema and source-classified reasons')
    need(type(l.get('signals'))is list and len(l['signals'])==5 and
         type(l.get('refusals'))is list and len(l['refusals'])==4,
         'actual old linked ingress buckets and refusal counters')
    need(not any(x.startswith((b'LI2_PERSISTENT_EPOCH ',b'LI2_PERSISTENT_DYNAMIC ',b'LI2_LINKED_PREEDGE ',
         b'LI2_LINKED_NATIVE_HINT ',b'LI2_LINKED_FRONTIER_CENSUS '))for x in stderr.splitlines()),
         'no fixed, preedge, hint or observer population substituted for group release')
    return result


def completed(raw):
    """Successful diagnostic arithmetic only; no full release acceptance claim."""
    d=raw['LI2_PERSISTENT_GROUP'];l=raw['LI2_LINKED_EPOCH'];v=raw['LI2_MAPS_VIEW'];n=raw['LI2_NATIVE']
    need(all(row.get('status')==row.get('failure_code')==0 for row in (d,l,n)),
         'actual exit-zero terminal outcomes')
    need(d['detail_abs']==d['detail_negative']==d['first_error']==d['active']==d['busy']==
         d['unexpected']==d['guest_data_fault']==0, 'successful quiet group observation')
    need(l.get('first_error')==l.get('active')==l.get('busy')==l.get('decoding')==
         l.get('closing')==l.get('resuming')==0 and l.get('events')==sum(l['signals']),
         'actual completed ingress census and quiet inherited owner')
    need(v.get('enabled')==1 and v.get('differential')==v.get('poisoned')==v.get('mismatches')==
         v.get('comparisons')==v.get('reserved')==0 and v.get('queries')==v.get('hits',0)+v.get('refreshes',0),
         'actual nondifferential maintained-map counters')
    need(d['offers']==d['serial']==d['entries']+d['cancelled'] and
         d['entries']==d['completed']==d['publications']+d['hits'] and
         d['cold_attempts']==d['publications']+d['cancelled'] and
         d['misses'][0]==0 and sum(d['misses'])==d['cancelled'],
         'exact completed, cold and genuinely cancelled group partitions')
    need(d['generation']==d['publications'] and d['retirements']==max(d['publications']-1,0) and
         d['permit_claims']==d['hits']+d['retirements'] and
         d['permit']==int(d['publications']>0), 'one resident generation and actual completed permit accounting')
    if d['publications']:
        need(0<d['build_serial']<=d['serial'], 'actual immutable build serial is a prior chosen epoch')
    else:
        need(d['build_serial']==0, 'no invented generation build serial')
    if not d['offers']:
        need(d['phase']==d['opened_pages']==d['closed_pages']==d['anchor_released']==
             d['registration_rechecked']==d['recovery_complete']==0, 'actual unused group owner')
    else:
        need(d['phase']in(13,14)and d['anchor_released']==d['registration_rechecked']==1,
             'last chosen epoch is actually closed or fully cancelled')
        need((d['opened_pages'],d['closed_pages'],d['recovery_complete'])==
             ((17,17,1)if d['phase']==13 else(0,0,0)), 'exact executed versus unentered terminal extent')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision',required=True)
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and exactly one externally reserved CPU')
    need(Path(__file__).resolve()==ROOT/SCRIPT and re.fullmatch('[0-9a-f]{40}',a.revision)is not None and
         git('rev-parse','HEAD').decode().strip()==a.revision,'canonical committed observer and exact revision')
    need(git('diff','--name-only',a.revision,'--','tools/page-entry','evaluation/inprocess',
             'evaluation/admission','evaluation/precontext/verify.py')==b'','no tracked source edits')
    code,compiled=source_paths(a.revision);actual=git_bytes(a.revision,code|compiled)
    current={p:dict(bytes=len(b),sha256=H(b))for p,b in actual.items()}
    need(set(REQUIRED) <= set(current), 'complete committed group/runtime/build source population')
    need(all((ROOT/p).read_bytes()==b for p,b in actual.items()),'all whole committed local source/data')
    need((ROOT/SCRIPT).read_bytes()==actual[SCRIPT],'whole committed collector identity')
    manifest=dict(driver=current[SCRIPT],revision=a.revision,code={p:current[p]for p in code},
                  compiled={p:current[p]for p in compiled},required={p:current[p]for p in REQUIRED})
    out=a.output.resolve();out.relative_to(ROOT/'target/page-region-next');out.mkdir(mode=0o700)
    cpu=next(iter(os.sched_getaffinity(0)))
    sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(ROOT/'tools/page-entry')]
    from page_selected import ENV,save
    from page_selected_process import invoke
    from page_selected_generic_build import Build,PROFILES
    from page_selected_oneshot_build import before_default
    from page_native_pair_performance import program_invoke
    import page_native_pair_performance as pair
    import persistent_group_build as persistent_build
    import namespace
    from run import hardware
    r=dict(schema=1,scope='UNQUALIFIED_GROUP_PERSISTENT_LS_ONLY',qualification_credit=False,
        timing_credit=False,aggregate_credit=False,source_revision=a.revision,cpu=cpu,hardware=hardware(cpu),
        bounds=dict(PROFILES,metadata=PROGRAM,build_metadata=PROFILES['metadata'],program=PROGRAM,
                    release_build=PROGRAM,finite=SHORT),commands=[],inputs={},artifacts={},aliases={},namespace_aliases={},
        case=dict(name='group-ls',status='not_run'),error=None,final_errors=[],source_unchanged=False,cleanup_complete=False)

    def pin(path):
        alias = Path(os.path.abspath(path)); path = alias.resolve(strict=True)
        value = fact(path)
        need(str(alias) not in r['aliases'] or r['aliases'][str(alias)] == str(path), 'stable input alias')
        need(str(path) not in r['inputs'] or r['inputs'][str(path)] == value, 'stable input bytes')
        r['aliases'][str(alias)] = str(path); r['inputs'][str(path)] = value
        return path

    def binary(path):
        path = pin(path); value = dict(fact(path), mode=path.stat().st_mode & 0o7777)
        need(str(path) not in r['artifacts'] or r['artifacts'][str(path)] == value, 'stable artifact')
        r['artifacts'][str(path)] = value
        return path

    def imports():
        # Include dynamically loaded modules referenced by module objects, not
        # just sys.modules: checks.admission is loaded through exec_module().
        queue = [v for v in sys.modules.values() if isinstance(v, types.ModuleType)]
        seen = set()
        while queue:
            module = queue.pop()
            if id(module) in seen: continue
            seen.add(id(module)); need(len(seen) <= 8192, 'bounded module closure')
            queue.extend(v for v in vars(module).values() if isinstance(v, types.ModuleType))
            p = getattr(module, '__file__', None)
            if not p or not Path(p).is_file(): continue
            p = Path(p).resolve()
            if p == ROOT / SCRIPT:
                need(fact(p) == manifest['driver'], 'executed diagnostic identity')
                pin(p)
                continue
            if p.is_relative_to(ROOT):
                rel = str(p.relative_to(ROOT))
                need(rel in manifest['code'] and fact(p) == manifest['code'][rel],
                     'actual executed local module is in baseline closure: ' + rel)
            pin(p)

    def stable():
        imports()
        need(all(Path(k).resolve(strict=True) == Path(v) for k,v in r['aliases'].items()), 'all aliases unchanged')
        need(all(fact(p) == v for p,v in r['inputs'].items()), 'whole input byte closure')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o7777) == v
                 for p,v in r['artifacts'].items()), 'whole artifact byte/mode closure')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p,value in
                 r['namespace_aliases'].items()), 'sealed namespace aliases unchanged')

    def run(name,argv,profile='metadata',expected=0,env=None,record=False,step=False):
        stable();need(name not in [x['name']for x in r['commands']],'unique retained command')
        executable=str(argv[0]);resolved=executable if '/'in executable else shutil.which(executable,path=(ENV if env is None else env)['PATH'])
        need(resolved is not None,'resolved actual command executable');binary(resolved)
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=r['bounds'][profile],
                 expected_exit=expected,capture_limit=16<<20,environment=dict(ENV if env is None else env))
        r['commands'].append(row)
        try:stdout,stderr=(program_invoke if name=='group-ls'else invoke)(row,out,cpu,record=record,step=step)
        finally:
            for value in row.get('captures',{}).values():binary(out/value['file'])
            save(out/'receipt.json',r)
        need(type(row['exit'])is int and (expected is None or row['exit']==expected),'actual required command outcome: '+name)
        return row,stdout,stderr

    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,r['aliases'],run,r)
        return run(name,argv,profile='build_metadata'if profile=='metadata'else profile,env=env,expected=expected)

    builder=Build(r,out,pin,binary,build_run,extra_decoder_sources=('region.rs',),scalar_span=True,linked_epoch=True,mov_guard=True)
    try:
        pin(ROOT/SCRIPT);save(out/'source-manifest.json',manifest);binary(out/'source-manifest.json')
        for path in current:pin(ROOT/path)
        products=builder.prepare()
        need(builder.decoder_features==('scalar-region','scalar-span','linked-epoch','mov-guard'), 'fresh exact registered persistent archive')
        archive=binary(products['archive']);r['archive']=fact(archive)
        original=pin('/bin/ls')
        bridge=persistent_build.build_bridge(builder,products,out,pin,binary,r['aliases'],run,r,
                                             original,capture=False)
        need(r['release_build']['profile']=='persistent-group-two-image-v1' and r['release_build'].get('capture') is False,
             'actual distinct group release build; no fixed entry or capture')
        (out/'external-inputs').mkdir()
        state=pair.prepare_workload('group-ls','/bin/ls',['-d','.'],bridge,builder,out,pin,binary,run,r,namespace)
        need(fact(state['original'])==r['release_build']['persistent_binding']['original']['image'],
             'actual launched original is the exact group build image')
        ns=out/'group-ls-namespace';tools=builder.tools
        argv=[tools['python'],'-B',state['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
              '--namespace',ns,state['carrier'],state['original'],'--',*state['argv']]
        case=r['case'];case['status']='failed';start=len(r['commands'])
        try:
            row,stdout,stderr=run('group-ls',argv,profile='program',expected=None,env=pair.PROGRAM_ENV)
            case['raw_counters']=raw=counters(stderr)
            need(row['exit']==0,'actual diagnostic subject must exit zero')
            need(stdout==b'.\n','exact full LS stdout')
            pair.namespace_join(state,ns,binary,r,namespace)
            completed(raw)
            case.update(status='observed_unqualified')
        except Exception as error:case['error']=type(error).__name__+': '+str(error)
        finally:
            if len(r['commands'])>start:
                row=r['commands'][start]
                case.update({k:row.get(k)for k in ('pid','exit','process_ns','duration_ns','timed_out','reaped')})
                case['captures']=row.get('captures',{})
            save(out/'receipt.json',r)
    except BaseException as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:r['final_errors'].extend(builder.finish())
        except BaseException as error:r['final_errors'].append('build finish: '+type(error).__name__+': '+str(error))
        try:
            stable()
            need(git('rev-parse','HEAD').decode().strip()==a.revision,'invocation revision unchanged')
            need(all(fact(ROOT/path)==value for path,value in current.items()),'all committed sources unchanged')
            r['source_unchanged']=True
        except BaseException as error:r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete']=all(c.get('reaped')is True and c.get('cleanup_errors')==[] and
            all(d.get('closed')is True for d in c.get('descriptors',[]))for c in r['commands'])
        r['status']=('complete_unqualified'if r['error']is None and not r['final_errors']and
            r['cleanup_complete']and r['case']['status']=='observed_unqualified'else'failed')
        save(out/'receipt.json',r)
        c=r['case'];raw=c.get('raw_counters',{});d=raw.get('LI2_PERSISTENT_GROUP',{})
        l=raw.get('LI2_LINKED_EPOCH',{});v=raw.get('LI2_MAPS_VIEW',{});n=raw.get('LI2_NATIVE',{})
        row=dict(name=c['name'],status=c['status'],exit=c.get('exit'),process_ns=c.get('process_ns'),
            whole_capture_ns=c.get('duration_ns'),timed_out=c.get('timed_out'),events=l.get('events'))
        row.update({name:l.get('signals',[None]*5)[i]for i,name in enumerate(('segv','trap','ill','sys','other'))})
        row.update({name:d.get(name)for name in ('offers','cold_attempts','hits','publications','cancelled',
            'entries','completed','retirements','permit_claims','generation','serial','build_serial','phase','first_error')})
        row.update({'miss_'+name:d.get('misses',[None]*len(MISS_REASONS))[i]for i,name in enumerate(MISS_REASONS)})
        row.update({'maps_'+name:v.get(name)for name in ('queries','hits','refreshes','comparisons','updates',
            'invalidations','stack_probes','mismatches','unexplained','poisoned')})
        row.update({'native_'+name:n.get(name)for name in ('attempts','admissions','closed','blocked','low_address_refusals')})
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
        subjects=[x for x in r['commands']if x['name']=='group-ls']
        need(len(subjects)<=1, 'one subject, never retried')
        subject=subjects[0]if subjects else None
        command=[] if subject is None else [str(x).replace(str(out),'${OUTPUT}').replace(str(ROOT),'${REPO}')
                                           for x in subject['argv']]
        if command:command[0]='${PYTHON}'
        summary=dict(scope=r['scope'],status=r['status'],source_revision=a.revision,cpu=cpu,hardware=hw,
            qualification_credit=False,timing_credit=False,aggregate_credit=False,bounds=r['bounds'],row=row,
            subject_argv=command,subject_stdout=(c.get('captures',{}).get('stdout')),
            subject_stderr=(c.get('captures',{}).get('stderr')),
            reproduction_argv=['python3','-B',SCRIPT,'--revision',a.revision,'--output','${PRIVATE_OUTPUT}'],
            reproduction_environment='One externally reserved CPU; original hard bounds on every child.',
            driver=manifest['driver'],source_manifest=fact(out/'source-manifest.json'),archive=r.get('archive'),
            policy_sha256=r.get('release_build',{}).get('persistent_binding',{}).get('policy_sha256'),
            input_count=len(r['inputs']),inputs_sha256=D(r['inputs']),artifact_count=len(r['artifacts']),artifacts_sha256=D(r['artifacts']),
            command_count=len(r['commands']),commands_sha256=D(r['commands']),cleanup_complete=r['cleanup_complete'],
            source_unchanged=r['source_unchanged'],receipt=fact(out/'receipt.json'),
            count_scope='Actual two-member group chosen epochs only; cancelled means full unentered source/rseq release plus ordinary resume. Signals are actual inherited ingress buckets after early owner guards. Failure may retain partial rows. Zero-use is recorded, never qualification. process_ns is Popen-to-reap wall time; whole_capture_ns includes capture closure. No baseline, aggregate, opcode coverage, saved-event or speedup credit.')
        text=json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(row),lineterminator='\n');writer.writeheader();writer.writerow(row)
        need(len(text.encode())<=32<<10 and len(stream.getvalue().encode())<=8<<10 and
             all(x not in text+stream.getvalue()for x in(str(ROOT),str(Path.home()),'/home/')),
             'bounded sanitized numeric diagnostic summary')
        (out/'summary.json').write_text(text);(out/'summary.csv').write_text(stream.getvalue())
    return int(r['status']!='complete_unqualified')


if __name__=='__main__':
    raise SystemExit(main())
