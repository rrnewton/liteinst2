#!/usr/bin/env python3
"""Bounded read-only replay of a closed user-DWARF capture; never run its target."""
import argparse,csv,io,json,os,platform,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SCRIPT='evaluation/inprocess/persistent_dynamic_profile_replay.py'
from linked_frontier_census import need,fact,git,git_bytes,source_paths,H,D
from page_selected import save
from page_selected_process import invoke
from page_cost_profile import PERF,TARGET
from persistent_dynamic_profile_read import summarize,script_argv,attribute,mapping_index_check
from run import hardware


def child(action,context):
    c=json.loads(Path(context).read_bytes());o=c['owner'];dest=Path(c['analysis']);bridge=Path(c['bridge'])
    try:
        if action=='map-index':value=mapping_index_check()
        elif action=='summarize':
            value=summarize(Path(c['raw']),bridge,o['target']['pid'],o['cpu'],dest,
                o['release_ns'],o['target_exit_ready_ns'],bridge_identity=o['bridge_identity_before'])
        else:
            need(action=='attribute','exact reader action')
            value=attribute(dest,bridge,Path(c['unwind']).read_bytes(),o['target']['pid'])
        save(dest/(action+'.json'),value);print(json.dumps(dict(status='passed')));return 0
    except BaseException as exc:
        print(json.dumps(dict(status='failed',error=type(exc).__name__+': '+str(exc))));return 1


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt',type=Path,required=True);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and one externally reserved CPU')
    need(Path(__file__).resolve()==ROOT/SCRIPT,'canonical committed replay entrypoint')
    out=a.output.resolve();out.relative_to(ROOT/'target/page-region-next');out.mkdir(mode=0o700)
    cpu=next(iter(os.sched_getaffinity(0)));current={};pins={};aliases={};modes={};source=None
    r=dict(schema=1,profile='persistent-dynamic-user-dwarf-replay-v1',status='failed',qualification=False,
        performance_credit=False,native_executions=0,source_revision=a.expect_revision,replay_cpu=cpu,
        replay_hardware=hardware(cpu),reader_bounds=list(PERF),commands=[],error=None,final_errors=[],
        source_unchanged=False,cleanup_complete=False)
    def pin(path,want=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);v=fact(p)
        need(want is None or v=={k:want[k]for k in('bytes','sha256')},'exact retained replay input '+str(alias))
        need(str(p)not in pins or pins[str(p)]==v,'unchanged replay input')
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'unchanged replay alias')
        pins[str(p)]=v;aliases[str(alias)]=str(p);return p
    def imports():
        queue=[m for m in sys.modules.values()if isinstance(m,types.ModuleType)];seen=set()
        while queue:
            m=queue.pop()
            if id(m)in seen:continue
            seen.add(id(m));need(len(seen)<=8192,'bounded reachable replay module closure')
            queue.extend(v for v in vars(m).values()if isinstance(v,types.ModuleType))
            p=getattr(m,'__file__',None)
            if not p or not Path(p).is_file():continue
            p=Path(p).resolve()
            if p.is_relative_to(ROOT):need(str(p.relative_to(ROOT))in current and fact(p)==current[str(p.relative_to(ROOT))],
                'actual replay module equals current committed bytes')
            pin(p)
    def stable():
        imports();need(all(fact(p)==v for p,v in pins.items()),'all retained and replay input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'all actual input aliases unchanged')
        need(all(Path(p).stat().st_mode&0o7777==v for p,v in modes.items()),'all retained artifact modes unchanged')
        if source:
            need(all(os.path.lexists(p)==v for p,v in source['configuration_presence'].items()),'loader configuration presence unchanged')
            need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in source['namespace_aliases'].items()),'retained guest namespace aliases unchanged')
    def run(name,argv,env):
        stable();pin(argv[0]);need(name not in [x['name']for x in r['commands']],'no replay command retry')
        row=dict(name=name,argv=list(map(str,argv)),environment=dict(env),bounds=list(PERF),capture_limit=16<<20)
        r['commands'].append(row)
        try:stdout,stderr=invoke(row,out,cpu)
        finally:save(out/'receipt.json',r)
        for item in row['captures'].values():pin(out/item['file'],item)
        return row,stdout,stderr
    try:
        need(git('rev-parse','HEAD').decode().strip()==a.expect_revision and len(a.expect_revision)==40,'exact current replay revision')
        code,compiled=source_paths(a.expect_revision);blobs=git_bytes(a.expect_revision,code|compiled)
        current={p:dict(bytes=len(v),sha256=H(v))for p,v in blobs.items()}
        need(SCRIPT in code and all((ROOT/p).read_bytes()==v for p,v in blobs.items()),'whole committed replay source closure')
        for p,v in current.items():pin(ROOT/p,v)
        origin=pin(a.receipt);source=json.loads(origin.read_bytes());old=source;bd=origin.parent
        need(old['profile']=='persistent-dynamic-user-dwarf-v1'and old['source_unchanged']is True and
             old['cleanup_complete']is True and old['final_errors']==[],'closed original profile process and source')
        manifest_path=bd/'source-manifest.json';pin(manifest_path,old['artifacts'][str(manifest_path)])
        manifest=json.loads(manifest_path.read_bytes());need(manifest['revision']==old['source_revision'],'actual producer revision')
        historical=manifest['code']|manifest['compiled'];got=git_bytes(old['source_revision'],historical)
        need(all(dict(bytes=len(got[p]),sha256=H(got[p]))==v for p,v in historical.items()),'whole producer Git source identity')
        for path,want in old['inputs'].items():
            p=Path(path);rel=str(p.relative_to(ROOT))if p.is_relative_to(ROOT)else None
            if rel in historical:need(want==historical[rel],'old input exactly joins its historical source')
            else:pin(p,want)
        for alias,resolved in old['aliases'].items():
            need(str(Path(alias).resolve(strict=True))==resolved,'original input alias retained');aliases[alias]=resolved
        for path,want in old['artifacts'].items():
            p=pin(path,want);need(p.stat().st_mode&0o7777==want['mode'],'original artifact mode');modes[str(p)]=want['mode']
        owner_path=pin(bd/'capture/owner.json',old['artifacts'][str(bd/'capture/owner.json')]);owner=json.loads(owner_path.read_bytes())
        need(owner==old['diagnostic']and owner['closed']is True and owner['cleanup_errors']==[] and
             owner['children_after']=='ECHILD'and owner['adopted']==[]and owner['inputs_before']==owner['inputs_after'],
             'literal actual owner and complete original process/input closure')
        need(owner['format']==old['profile']and owner['user_dwarf']is True and owner['target']==old['target']and
             owner['cpu']==old['cpu']and owner['target_bounds']==list(TARGET)and owner['perf']['bounds']==list(PERF),
             'original target identity, CPU and unchanged producer bounds')
        target=owner['target'];perf=owner['perf']
        need(target['reaped']is True and not target['timed_out']and target['error']is None and target['cleanup_errors']==[]and
             perf['exit']==0 and perf['reaped']is True and owner['enable_acknowledgement_hex']=='61636b0a00'and
             owner['enabled_ns']<=owner['release_ns']<owner['target_exit_ready_ns'], 'actual acknowledged capture and target exit')
        need(owner['error']is None or owner['error'].startswith('sampling: '),'no ignored owner process error')
        for name,want in owner['captures'].items():pin(bd/'capture'/name,want)
        bridge=pin(owner['bridge_identity_before']['before']['pathname'],old['bridge'])
        need(owner['bridge_identity_before']==owner['bridge_identity_after'],'literal stable observed bridge identity')
        raw=pin(bd/'capture/perf.data',owner['captures']['perf.data']);tool=pin(perf['argv'][0],old['observer_tools']['perf'])
        for path,want in old['observer_libraries'].items():pin(path,want)
        r.update(origin=dict(receipt=fact(origin),owner=fact(owner_path),producer_revision=old['source_revision'],
            original_status=old['status'],original_error=old['error'],target_exit=target['exit']),
            target=target,producer_cpu=old['cpu'],producer_hardware=old['hardware'],bridge=old['bridge'],perf_data=fact(raw),
            observer_tools=old['observer_tools'],reader=fact(ROOT/'evaluation/inprocess/persistent_dynamic_profile_read.py'))
        analysis=out/'analysis';analysis.mkdir();unwind=out/'user-dwarf-unwind.stdout'
        context=out/'context.json';save(context,dict(owner=owner,bridge=str(bridge),raw=str(raw),analysis=str(analysis),unwind=str(unwind)));pin(context)
        python=pin(sys.executable);r['replay_python']=fact(python);env=dict(perf['environment'])
        for key,name in [('PERF_BUILDID_DIR','buildids'),('XDG_CACHE_HOME','cache'),('TMPDIR','tmp'),('DEBUGINFOD_CACHE_PATH','debuginfod')]:
            (out/name).mkdir();env[key]=str(out/name)
        def read(action):
            row,stdout,stderr=run('reader-'+action,[python,'-B',ROOT/SCRIPT,'--child',action,context],env)
            result=json.loads(stdout);need(row['exit']==0 and not stderr and result=={'status':'passed'},
                'bounded '+action+' reader: '+str(result))
            p=pin(analysis/(action+'.json'));return json.loads(p.read_bytes())
        r['map_index_check']=read('map-index')
        need(r['map_index_check']['cases']==8 and r['map_index_check']['operations']==286 and
             r['map_index_check']['explicit_split_cases']==1 and r['map_index_check']['native_operations']==0,
             'complete bounded independent mapping-history oracle')
        r['sampling']=read('summarize')
        for name in ('samples.json','maps.json','samples.csv'):pin(analysis/name)
        need(r['sampling']['full_exec_exit_envelope']and r['sampling']['loss_free'],'complete loss-free captured envelope')
        symfs=out/'symfs';copy=symfs/str(bridge).lstrip('/');copy.parent.mkdir(parents=True);copy.write_bytes(bridge.read_bytes());copy.chmod(0o444);pin(copy,old['bridge'])
        row,stdout,stderr=run('user-dwarf-unwind',script_argv(tool,raw,symfs),env)
        need(row['exit']==0,'actual bounded perf script completion')
        r['unwinder_stderr']=fact(out/'user-dwarf-unwind.stderr');r['attribution']=read('attribute')
        for name in ('attribution.json','unwound.json'):pin(analysis/name)
        r['status']='observed_unqualified'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:
            stable();need(git('rev-parse','HEAD').decode().strip()==a.expect_revision and
                all(fact(ROOT/p)==v for p,v in current.items()),'complete replay source closure');r['source_unchanged']=True
        except BaseException as exc:r['final_errors'].append('source/input closure: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')is True and not x.get('timed_out')and x.get('error')is None and
            x.get('cleanup_errors')==[]and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['source_unchanged']or not r['cleanup_complete']:r['status']='failed'
        r['inputs']=pins;r['aliases']=aliases;save(out/'receipt.json',r);publish(out,r)
    return int(r['status']!='observed_unqualified')


def publish(out,r):
    ranking=r.get('attribution',{});sample=r.get('sampling',{});target=r.get('target',{});hw=dict(r['replay_hardware'])
    flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
    value={k:r.get(k)for k in('profile','status','qualification','performance_credit','native_executions','source_revision',
        'replay_cpu','reader_bounds','origin','producer_cpu','bridge','perf_data','reader','observer_tools','source_unchanged','cleanup_complete')}
    if value['origin']:
        value['origin']=dict(value['origin']);error=value['origin'].pop('original_error')
        value['origin']['original_error_type']=error.split(':',1)[0]if error else None
    produced=dict(r.get('producer_hardware',{}))
    if produced:
        flags=produced.pop('isa_flags');produced.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
    value.update(replay_hardware=hw,producer_hardware=produced,target_exit=target.get('exit'),target_wall_ns=target.get('process_ns'),target_usage=target.get('usage'),
        final_error_count=len(r['final_errors']),error_type=r['error'].split(':',1)[0]if r['error']else None,
        samples=ranking.get('samples'),sampled_period=ranking.get('period'),unknown_leaf_samples=ranking.get('unknown_leaf_samples'),
        unknown_leaf_period=ranking.get('unknown_leaf_period'),unwind_states=ranking.get('unwind_states'),unwind_complete=False,
        all_recorded_samples=sample.get('samples'),all_recorded_period=sample.get('sampled_period_total'),
        map_index_check=r.get('map_index_check'),replay_python=r.get('replay_python'),receipt=fact(out/'receipt.json'),reproduce=['python3','-B',SCRIPT,'--receipt','${CLOSED_PROFILE_RECEIPT}',
            '--expect-revision',r['source_revision'],'--output','${FRESH_PRIVATE_OUTPUT}'],
        scope='Reader replay only. Original target outcome and failed producer receipt are unchanged. First same-PID exec through exit includes carrier startup. Period-weighted user samples include unknowns; no complete-stack, wall-time, qualification or speedup claim.')
    value['commands']=[]
    for row in r['commands']:
        argv=[str(x).replace(str(out),'${OUTPUT}').replace(str(ROOT),'${REPO}')for x in row['argv']]
        argv[0]='${EXECUTABLE}'
        value['commands'].append(dict(name=row['name'],argv=argv,bounds=row['bounds'],exit=row.get('exit'),
            duration_ns=row.get('duration_ns'),environment_sha256=D(row['environment']),captures=row.get('captures',{})))
    stream=io.StringIO();w=csv.writer(stream,lineterminator='\n');w.writerow(['kind','rank','key','samples','sampled_period'])
    for key in ('functions','paths'):
        rows=ranking.get(key,[]);tail=rows[3:];rest=dict(groups=len(tail),samples=sum(x['samples']for x in tail),period=sum(x['period']for x in tail))
        value[key]=dict(top3=rows[:3],remaining=rest)
        for i,x in enumerate(rows[:3],1):w.writerow([key,i,json.dumps(x['key'],separators=(',',':')),x['samples'],x['period']])
        w.writerow([key,'remaining',str(rest['groups'])+' groups',rest['samples'],rest['period']])
    data=stream.getvalue().encode();value['csv']=dict(bytes=len(data),sha256=H(data));text=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(text)<=32<<10 and len(data)<=16<<10 and all(x.encode()not in text+data for x in
        (str(ROOT),str(Path.home()),'/home/',platform.node())if len(x)>1),'bounded sanitized replay projection')
    (out/'summary.json').write_bytes(text);(out/'summary.csv').write_bytes(data)
    print(json.dumps(dict(status=r['status'],target_exit=target.get('exit'),error=r['error'],summary=str(out/'summary.json'))))


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--child':raise SystemExit(child(sys.argv[2],sys.argv[3]))
    raise SystemExit(main())
