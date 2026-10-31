#!/usr/bin/env python3
"""One retained maintained startup capture under the unchanged strict perf owner."""
import argparse,json,os,platform,re,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path.cwd().resolve();HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(HERE),str(ROOT/'tools/page-entry')]
from linked_frontier_census import need,fact,git,git_bytes,source_paths,H,D
from page_selected import save,interpreter,ENV
from page_selected_process import invoke
from page_selected_register_time_build import recipe,expand
from persistent_resident_profile import observer_libraries,phase_timeline
from persistent_dynamic_profile_read import script_argv,attribute
from startup_loop_helpers import preparation
from capture_profile import profile,TARGET,PERF
from run import hardware
import namespace

REVISION='3ce8218f1f73821251ef6aad687adf469b2b451f'
LABEL='subject-maintained-2-0'


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--origin-receipt',type=Path,required=True)
    ap.add_argument('--expect-origin-sha256',required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and one reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact current revision')
    need(re.fullmatch('[0-9a-f]{64}',a.expect_origin_sha256),'exact expected origin digest')
    evidence=ROOT/'target/evaluation/inprocess'
    origin=a.origin_receipt.resolve(strict=True);origin.relative_to(evidence)
    out=a.output.resolve();out.relative_to(evidence);need(out!=evidence,'fresh private result directory')
    out.mkdir(mode=0o700)
    cpu=next(iter(os.sched_getaffinity(0)))
    r=dict(schema=1,profile='startup-maintained-capture-per-thread-v1',status='failed',
        qualification=False,performance_credit=False,source_revision=a.expect_revision,cpu=cpu,hardware=hardware(cpu),
        bounds=dict(target=list(TARGET),profiler=list(PERF),unwinder=list(PERF)),commands=[],inputs={},aliases={},
        artifacts={},namespace_aliases={},error=None,final_errors=[],source_unchanged=False,cleanup_complete=False,
        namespace_complete=False,target_outcome='not_run')
    current={};private={};row=None;context=None
    def pin(path,want=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);v=fact(p)
        need(want is None or v=={k:want[k]for k in('bytes','sha256')},'exact retained input '+str(alias))
        need(str(p)not in r['inputs']or r['inputs'][str(p)]==v,'same input across complete attempt')
        need(str(alias)not in r['aliases']or r['aliases'][str(alias)]==str(p),'same lexical input alias')
        r['inputs'][str(p)]=v;r['aliases'][str(alias)]=str(p);return p
    def binary(path,want=None):
        p=pin(path,want);v=dict(fact(p),mode=p.stat().st_mode&0o7777)
        need(want is None or 'mode'not in want or v['mode']==want['mode'],'exact retained artifact mode')
        need(str(p)not in r['artifacts']or r['artifacts'][str(p)]==v,'same artifact bytes and mode')
        r['artifacts'][str(p)]=v;return p
    def imports():
        queue=[m for m in sys.modules.values()if isinstance(m,types.ModuleType)];seen=set()
        while queue:
            m=queue.pop()
            if id(m)in seen:continue
            seen.add(id(m));need(len(seen)<=8192,'bounded complete reachable module closure')
            queue.extend(v for v in vars(m).values()if isinstance(v,types.ModuleType))
            p=getattr(m,'__file__',None)
            if not p or not Path(p).is_file():continue
            p=Path(p).resolve()
            if p.is_relative_to(ROOT):
                rel=str(p.relative_to(ROOT));want=private.get(str(p),current.get(rel))
                need(want is not None and fact(p)==want,'exact committed or frozen private local module')
            pin(p)
    def stable():
        imports()
        need(all(fact(p)==v for p,v in r['inputs'].items()),'all input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in r['aliases'].items()),'all input aliases unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o7777)==v for p,v in r['artifacts'].items()),'all artifacts unchanged')
        need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),'all namespace aliases unchanged')
        need(all(os.path.lexists(p)==v for p,v in r.get('configuration_presence',{}).items()),'loader configuration presence unchanged')
    def run(name,argv,env=ENV,bounds=PERF):
        stable();binary(argv[0]);need(name not in [c['name']for c in r['commands']],'no command retry')
        command=dict(name=name,argv=list(map(str,argv)),environment=dict(env),bounds=list(bounds),capture_limit=16<<20)
        r['commands'].append(command)
        try:stdout,stderr=invoke(command,out,cpu)
        finally:
            for c in command.get('captures',{}).values():binary(out/c['file'])
            save(out/'receipt.json',r)
        need(command['exit']==0 and command['reaped']and not command['timed_out']and not command['error']and
             not command['cleanup_errors'],'actual bounded auxiliary command completion')
        return command,stdout,stderr
    try:
        need(git('rev-parse','HEAD').decode().strip()==a.expect_revision and not git('status','--porcelain','-uno'),
             'exact clean committed source before observation')
        packet=pin(HERE/'SOURCE.json');s=json.loads(packet.read_bytes());r['observer_packet']=fact(packet)
        for name,want in s['files'].items():
            p=pin(HERE/name,want);private[str(p)]=fact(p)
        need(set(private)=={str(HERE/'run.py'),str(HERE/'capture_profile.py')},'exact two frozen executable leaves')
        for path,want in s['inputs'].items():pin(ROOT/path,want)
        code,compiled=source_paths(a.expect_revision);blobs=git_bytes(a.expect_revision,code|compiled)
        current={p:dict(bytes=len(v),sha256=H(v))for p,v in blobs.items()}
        need(all((ROOT/p).read_bytes()==v for p,v in blobs.items()),'whole current source closure')
        for p in current:pin(ROOT/p)
        r['current_source']=dict(revision=a.expect_revision,files=len(current),sha256=D(current))
        base=pin(origin);need(fact(base)['sha256']==a.expect_origin_sha256,'exact whole failed origin receipt')
        b=json.loads(base.read_bytes());bd=base.parent
        need(b['revision']==REVISION and b['source']['revision']==REVISION and
             b['source']['tracked_clean']is True and b['source']['head_sources_match']is True and
             b['source']['tree']==git('rev-parse',REVISION+'^{tree}').decode().strip() and
             b['source_unchanged']is True and b['cleanup_complete']is True and b['final_errors']==[] and
             b['status']=='failed' and b['error']=='ValueError: all three actual loop outcomes required without skipped or relabelled failures',
             'original exact failed startup diagnostic and whole closure retained')
        need([(c['lane'],c['mode'],c['control'],c['exit'],c['status'])for c in b['cases']]==[
             ('native',2,0,0,'observed_native_startup_loop'),('maintained',2,0,-9,'failed'),
             ('differential',2,0,-9,'failed')]and all(c['launched']is True and c['timed_out']is False for c in b['cases']),
             'original native result and both failed generated outcomes remain distinct')
        # This standalone origin has no earlier five-cohort prerequisite receipts
        # and retained no global lexical alias/source_after map. Bind all facts it
        # actually retained, then independently join every source to both Git revisions.
        for path,want in b['inputs'].items():pin(path,want)
        for path,want in b['artifacts'].items():binary(path,want)
        for path,target in b['namespace_aliases'].items():
            need(Path(path).is_symlink()and os.readlink(path)==target,'original sealed namespace alias')
            r['namespace_aliases'][path]=target
        native={str(Path(p).relative_to(ROOT)):v for p,v in b['inputs'].items()
            if Path(p).is_relative_to(ROOT)and not Path(p).is_relative_to(ROOT/'target')}
        for rev in (REVISION,a.expect_revision):
            source=git_bytes(rev,native)
            need(all(dict(bytes=len(source[p]),sha256=H(source[p]))==v for p,v in native.items()),
                 'all original source inputs match old and current Git')
        r['origin_source']=dict(files=len(native),sha256=D(native))
        old=[c for c in b['commands']if c['name']==LABEL];need(len(old)==1,'one exact failed maintained startup subject');old=old[0]
        need(old['exit']==-9 and old['reaped']is True and old['timed_out']is False and old['error']is None and
             old['cleanup_errors']==[] and old['bounds']==list(TARGET) and old['capture_limit']==16<<20 and
             old['environment']==ENV and all(x['closed']for x in old['descriptors']),
             'actual failed subject has unchanged limits and closed process/descriptors')
        need(set(old['captures'])=={'stdout','stderr','record'}and all(c['bytes']==0 for c in old['captures'].values()),
             'original failed maintained capture contains no terminal or focal evidence')
        for c in old['captures'].values():binary(bd/c['file'],c)
        r['origin']=dict(file=str(base.relative_to(ROOT)),receipt=fact(base),revision=REVISION,cpu=b['cpu'],status=b['status'],
            target_exit=old['exit'],duration_ns=old['duration_ns'],captures=old['captures'])
        lane=b['lanes']['maintained'];rb=lane['release_build'];build=b['build']
        need(build['status']=='passed'and build['command_completed']is True and build['configuration_unchanged']is True and
             build['final_errors']==[] and build['decoder_features']==['scalar-region','scalar-span','linked-epoch','mov-guard'] and
             rb['status']=='passed'and rb['capture']is True and rb['profile']=='persistent-startup-capture-v1'and
             rb['active_domain']['differential']is False and rb['active_domain']['unregistered']is True and
             rb['capture_extents']['wire']==1823616 and rb['capture_extents']['stream']==1823680 and
             rb['capture_extents']['record_limit']==4<<20 and rb['persistent_binding']['version']==1 and
             rb['persistent_binding']['unregistered']is True and rb['persistent_binding']['mode']=='capture',
             'actual exact maintained startup capture build')
        archive=binary(build['artifacts']['decoder.a']['path'],build['artifacts']['decoder.a'])
        bridge=binary(rb['argv'][-1],b['artifacts'][rb['argv'][-1]])
        need(fact(archive)==rb['archive']==rb['persistent_binding']['archive']and fact(bridge)==rb['bridge'],
             'same actual archive, header binding and complete release ELF')
        recipe_path=pin(ROOT/'tools/page-entry/selected/build-persistent-startup-capture.sh',rb['recipe'])
        recipes=recipe(recipe_path,'"$cc_bin"');need(len(recipes)==1,'one complete actual compile recipe')
        expected=expand(recipes[0],{'$cc_bin':build['tools']['cc']['path'],'$selected_dir':ROOT/'tools/page-entry/selected',
            '$parent_dir':ROOT/'tools/page-entry','$archive':archive,'$output':bridge.parent})
        linked=[c for c in b['commands']if c['argv']==expected]
        need(expected==rb['argv']and len(linked)==1 and linked[0]['exit']==0 and linked[0]['reaped']and
             not linked[0]['error']and not linked[0]['cleanup_errors'],'actual retained build command; no rebuild')
        for c in linked[0]['captures'].values():binary(bd/c['file'],c)
        for p,v in rb['headers'].items():pin(p,v)
        for item in rb['persistent_binding']['header_paths'].values():pin(item['path'],item)
        item=rb['persistent_binding']['manifest'];pin(item['path'],item)
        for item in (rb['capture_config']['header'],rb['capture_config']['script']):pin(item['path'],item)
        original=binary(old['argv'][old['argv'].index('--original')+1],b['artifacts'][old['argv'][old['argv'].index('--original')+1]])
        need(fact(original)==b['application_build']['artifact'],'same actual application build artifact')
        carrier=binary(old['argv'][old['argv'].index('--carrier')+1],b['artifacts'][old['argv'][old['argv'].index('--carrier')+1]])
        interp=pin(interpreter(original),lane['subject_artifacts']['interpreter'])
        need(fact(original)==lane['subject_artifacts']['original']==rb['capture_config']['original']['image'] and
             fact(carrier)==lane['subject_artifacts']['carrier']and interpreter(carrier)==bridge,
             'exact original app and carrier bound to actual maintained startup ELF')
        python=pin(build['tools']['python']['path'],build['tools']['python'])
        launcher=pin(ROOT/'tools/page-entry/selected/tests/persistent_interpreter_loop_app/launch.py')
        roots=[original.parent,Path('/usr/lib64')]
        exact=[str(python),'-B',str(launcher),'--root',str(ROOT),'--role','gated','--mode','2','--control','0',
            '--original',str(original),'--preparation',str(bd/LABEL/'preparation.json'),
            '--library-root',str(roots[0]),'--library-root',str(roots[1]),'--carrier',str(carrier),
            '--namespace',str(bd/LABEL/'namespace'),'--record-fd','3']
        need(old['argv']==exact,'whole exact original failed subject argv')
        objects,description=namespace.plan(original,roots,bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
        need(description==lane['namespace_plan'],'same complete original namespace source plan')
        for item in objects:pin(item['path'],dict(bytes=len(item['bytes']),sha256=H(item['bytes'])))
        for item in lane['runtime_libraries'].values():pin(item['path'],item)
        need({name:dict(path=str(item['path']),bytes=len(item['bytes']),sha256=H(item['bytes']))
            for item in objects for name in item['names']}==lane['runtime_libraries'],'same complete retained SONAME closure')
        r['configuration_presence']={p:os.path.lexists(p)for p in('/etc/ld.so.preload','/etc/ld.so.cache')}
        need(not r['configuration_presence']['/etc/ld.so.preload'],'no host preload')
        if r['configuration_presence']['/etc/ld.so.cache']:pin('/etc/ld.so.cache')
        perf=binary('/usr/bin/perf');perfinterp=pin(interpreter(perf))
        _,listed,errors=run('perf-libraries',[perfinterp,'--list',perf]);need(not errors,'observer loader listing stderr')
        libs=observer_libraries(listed,perfinterp,pin)
        r['observer_tools']=dict(perf=fact(perf),python=fact(python),libraries={str(p):fact(p)for p in libs})
        r['kernel_controls']={name:Path('/proc/sys/kernel/'+name).read_text().strip()for name in
            ('perf_event_paranoid','perf_event_max_sample_rate','perf_event_mlock_kb')}
        fresh=out/'subject';fresh.mkdir();argv=list(exact)
        for flag,value in (('--preparation',fresh/'preparation.json'),('--namespace',fresh/'namespace'),('--record-fd','{record_fd}')):
            argv[argv.index(flag)+1]=str(value)
        row=dict(name=LABEL+'-observed',argv=argv,environment=dict(ENV),cwd=str(bd),bounds=list(TARGET),capture_limit=16<<20)
        r.update(target=row,bridge=fact(bridge),archive=fact(archive),carrier=fact(carrier),original=fact(original),
            policy_sha256=rb['persistent_binding']['policy_sha256'])
        context=(dict(lane='maintained',mode=2,control=0),row,fresh,original,roots,objects,description,carrier,out,binary,r)
        stable();stdout,stderr,owned=profile(row,out/'capture',cpu,bridge,rb['bridge'],perf=str(perf),user_dwarf=True,capture_per_thread=True)
        r['diagnostic']=owned
        p=binary(out/'capture/owner.json');need(D(json.loads(p.read_bytes()))==D(owned),'whole returned closed owner receipt')
        for name,want in owned['captures'].items():
            need(Path(name).name==name,'exact owner capture basename')
            capture=binary(out/'capture'/name,{k:want[k]for k in('bytes','sha256')});cs=capture.stat()
            need(dict(fact(capture),mode=cs.st_mode,device=cs.st_dev,inode=cs.st_ino)==want,
                 'whole actual owner capture bytes and full stat identity')
        preparation(*context);r['namespace_complete']=True
        need(owned['sampling']['loss_free']and owned['sampling']['full_exec_exit_envelope'],'unchanged loss-free full exec envelope')
        symfs=out/'symfs';copy=symfs/str(bridge).lstrip('/');copy.parent.mkdir(parents=True);copy.write_bytes(bridge.read_bytes());copy.chmod(0o444);binary(copy,rb['bridge'])
        env=dict(owned['perf']['environment'],DEBUGINFOD_CACHE_PATH=str(out/'capture/cache'))
        _,text,err=run('user-dwarf-unwind',script_argv(perf,out/'capture/perf.data',symfs),env=env)
        r['unwinder_stderr']=fact(out/'user-dwarf-unwind.stderr')
        r['attribution']=attribute(out/'capture',bridge,text,row['pid'])
        p=binary(out/'capture/attribution.json');binary(out/'capture/unwound.json')
        need(D(json.loads(p.read_bytes()))==D(r['attribution']),'whole returned attribution output')
        stable();r['phases']=phase_timeline(out/'capture',bridge,r['attribution'],owned['sampling'])
        r['status']='observed_unqualified'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        owner=out/'capture/owner.json'
        if owner.exists():
            try:r['diagnostic']=json.loads(owner.read_bytes())
            except BaseException as exc:r['final_errors'].append('owner: '+repr(exc))
        if context and not r['namespace_complete'] and row.get('reaped'):
            try:preparation(*context);r['namespace_complete']=True
            except BaseException as exc:r['final_errors'].append('actual namespace/preparation: '+repr(exc))
        try:
            stable();need(git('rev-parse','HEAD').decode().strip()==a.expect_revision and not git('status','--porcelain','-uno')and
                all(fact(ROOT/p)==v for p,v in current.items()),'whole committed source remained unchanged')
            r['source_unchanged']=True
        except BaseException as exc:r['final_errors'].append('source/input closure: '+repr(exc))
        r['target_outcome']=('exit_zero'if row.get('exit')==0 else'failed_prefix')if row and row.get('pid')else'not_run'
        r['cleanup_complete']=r.get('diagnostic',{}).get('closed')is True and all(c.get('reaped')is True and
            c.get('cleanup_errors')==[]and all(d.get('closed')is True for d in c.get('descriptors',[]))for c in r['commands'])
        for p in sorted(out.rglob('*')):
            if p.is_file()and not p.is_symlink()and p.name!='receipt.json':
                try:binary(p)
                except BaseException as exc:r['final_errors'].append('artifact: '+repr(exc))
        if r['error']or r['final_errors']or not r['cleanup_complete']or not r['source_unchanged']or not r['namespace_complete']:r['status']='failed'
        save(out/'receipt.json',r)
        # Full private ranking remains available; this small projection never invents terminal/counter evidence.
        owned=r.get('diagnostic',{});hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
        summary=dict(schema=1,profile=r['profile'],status=r['status'],qualification=False,performance_credit=False,
            source_revision=r['source_revision'],observer_packet=r.get('observer_packet'),origin=r.get('origin'),cpu=cpu,hardware=hw,
            reproduce=['cpuset-alloc','run','--cores','1','--','python3','-B',str(Path(__file__).relative_to(ROOT)),
                '--expect-revision',a.expect_revision,'--origin-receipt',str(origin.relative_to(ROOT)),
                '--expect-origin-sha256',a.expect_origin_sha256,'--output','${FRESH_PRIVATE_OUTPUT}'],
            bounds=r['bounds'],target_exit=(row or{}).get('exit'),target_outcome=r['target_outcome'],target_usage=(row or{}).get('usage'),
            target_wall_ns=(row or{}).get('process_ns'),record=owned.get('captures',{}).get('target.record'),
            bridge=r.get('bridge'),archive=r.get('archive'),original=r.get('original'),carrier=r.get('carrier'),
            sample_count=owned.get('sampling',{}).get('samples'),loss_free=owned.get('sampling',{}).get('loss_free'),
            exec_envelope=owned.get('sampling',{}).get('full_exec_exit_envelope'),source_unchanged=r['source_unchanged'],
            cleanup_complete=r['cleanup_complete'],namespace_complete=r['namespace_complete'],private_receipt=fact(out/'receipt.json'),
            top_functions=r.get('attribution',{}).get('functions',[])[:12],phases=r.get('phases'),
            error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            scope='One same-CPU user-only observation of the whole maintained startup command, including launch Python. '
                'Target exit remains independent and failed if nonzero. No counter protocol, terminal proof, qualification, kernel attribution or speedup.')
        data=(json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
        need(len(data)<=32<<10 and all(x.encode()not in data for x in(str(ROOT),str(Path.home()),'/home/',platform.node())if len(x)>1),
             'small sanitized diagnostic projection')
        (out/'summary.json').write_bytes(data)
        print(json.dumps(dict(status=r['status'],target_exit=(row or{}).get('exit'),output=str(out))))
    return int(r['status']!='observed_unqualified')


if __name__=='__main__':raise SystemExit(main())
