#!/usr/bin/env python3
"""Profile an explicitly authenticated failed LS origin; no qualification or speedup credit."""
import argparse,json,os,platform,re,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path.cwd().resolve();HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(HERE),str(ROOT/'tools/page-entry')]
from linked_frontier_census import need,fact,git,git_bytes,source_paths,H,D
from page_selected import save,interpreter,ENV
from page_selected_process import invoke
from page_selected_register_time_build import recipe,expand
from persistent_resident_profile import observer_libraries,phase_timeline,PHASE_NAMES
from persistent_dynamic_profile_read import script_argv,attribute
from page_native_pair_performance import PROGRAM_ENV
import persistent_group_counter_process as counter_process
from capture_profile import profile,TARGET,PERF
from run import hardware
import namespace
from direct_frontier_program import direct_prerequisite

LABEL='subject-ls-counted'


def leaf_costs(bridge,ranking):
    """Disjoint exact ELF leaf labels; ancestors never become sampled leaf costs."""
    from page_cost_profile_read import elf
    obj=elf(bridge);groups={'pe_bytes':('pe_bytes',),'planning_decode':PHASE_NAMES['planning_decode'],'project':('project',)}
    labels={};bindings=[]
    for group,names in groups.items():
        for name in names:
            intervals={(lo,hi)for lo,hi,n in obj['symbols']if n==name}
            if group in ('pe_bytes','project'):need(len(intervals)==1,'one exact required sampled leaf interval '+name)
            if len(intervals)!=1:continue
            lo,hi=next(iter(intervals));aliases=sorted({n for a,z,n in obj['symbols']if(a,z)==(lo,hi)})
            if not all(n in names for n in aliases):continue
            key='bridge:'+hex(lo)+'-'+hex(hi)+':'+'|'.join(aliases)
            need(key not in labels or labels[key]==group,'disjoint exact sampled leaf labels')
            labels[key]=group;bindings.append(dict(group=group,name=name,start=lo,end=hi))
    rows=ranking['functions'];total=ranking['samples'];period=ranking['period']
    need(total>0 and period>0 and sum(x['samples']for x in rows)==total and
         sum(x['period']for x in rows)==period,'whole leaf denominator includes unknown and other mappings')
    values={name:[0,0]for name in (*groups,'other_unknown')}
    for row in rows:
        item=values[labels.get(row['key'],'other_unknown')];item[0]+=row['samples'];item[1]+=row['period']
    need(sum(n for n,p in values.values())==total and sum(p for n,p in values.values())==period,
         'complete disjoint leaf sample and period conservation')
    return dict(total_samples=total,total_period=period,bindings=bindings,
        rows=[dict(group=name,samples=n,period=p,sample_fraction=n/total,period_fraction=p/period)
              for name,(n,p)in values.items()],
        scope='Exact sampled user-IP leaf partition, including all unknowns. Planning names are explicit, not an exhaustive cost category. '
              'No ancestor substitution, wall-time attribution, throughput, completion or speedup inference.')


def main():
    sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
    from page_selected_maps_sources import historical, bind as bind_maps_sources
    ap=argparse.ArgumentParser(description=__doc__,allow_abbrev=False);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--expect-origin-revision',required=True)
    ap.add_argument('--origin-receipt',type=Path,required=True)
    ap.add_argument('--expect-origin-sha256',required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and one reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact current revision')
    need(re.fullmatch('[0-9a-f]{40}',a.expect_origin_revision)and
         re.fullmatch('[0-9a-f]{64}',a.expect_origin_sha256),'explicit exact origin revision and whole receipt digest')
    evidence=ROOT/'target/evaluation/inprocess'
    origin=a.origin_receipt.resolve(strict=True);origin.relative_to(evidence)
    out=a.output.resolve();out.relative_to(evidence);need(out!=evidence,'fresh private result directory')
    out.mkdir(mode=0o700)
    cpu=next(iter(os.sched_getaffinity(0)))
    r=dict(schema=1,profile='real-ls-input-bound-per-thread-counters-v1',status='failed',
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
        bind_maps_sources(pin)
        for name,want in s['files'].items():
            p=binary(HERE/name)
            need(historical(p,want,fact(p))=={k:want[k]for k in('bytes','sha256')},'whole static observer file inverse')
            need('mode'not in want or p.stat().st_mode&0o7777==want['mode'],'exact retained artifact mode')
            private[str(p)]=fact(p)
        need(set(private)=={str(HERE/'run.py'),str(HERE/'capture_profile.py')},'exact two frozen executable leaves')
        for path,want in s['inputs'].items():
            actual=pin(ROOT/path)
            need(historical(actual,want,fact(actual))=={k:want[k]for k in('bytes','sha256')},'whole static observer source inverse')
        pin(HERE/'README.md',s['readme'])
        code,compiled=source_paths(a.expect_revision);blobs=git_bytes(a.expect_revision,code|compiled)
        current={p:dict(bytes=len(v),sha256=H(v))for p,v in blobs.items()}
        need(all((ROOT/p).read_bytes()==v for p,v in blobs.items()),'whole current source closure')
        for p in current:pin(ROOT/p)
        r['current_source']=dict(revision=a.expect_revision,files=len(current),sha256=D(current))
        base=pin(origin);need(fact(base)['sha256']==a.expect_origin_sha256,'exact whole failed origin receipt')
        b=json.loads(base.read_bytes());bd=base.parent
        need(b['revision']==a.expect_origin_revision and b['source']['revision']==a.expect_origin_revision and
             b['source']['tracked_clean']is True and b['source']['head_sources_match']is True and
             b['source']['tree']==git('rev-parse',a.expect_origin_revision+'^{tree}').decode().strip() and
             b['source_unchanged']is True and b['cleanup_complete']is True and b['final_errors']==[] and
             b['status']=='failed' and b['error']=='ValueError: all four original bounded subjects must complete; prefixes remain failures' and
             b['whole_profile_qualified']is b['qualification_credit']is b['performance_credit']is False,
             'original failed real-program result and whole closure retained')
        need([(c['program'],c['lane'],c['exit'],c['status'])for c in b['cases']]==[
             ('ls','native',0,'completed_native_reference'),('ls','counted',-9,'failed'),
             ('true','native',0,'completed_native_reference'),('true','counted',-9,'failed')] and
             all(c['launched']is True and c['timed_out']is False for c in b['cases']),
             'original two native results and both failed generated outcomes remain distinct')
        need(cpu==b['cpu'] and r['hardware']==b['hardware'],'same actual reserved CPU and complete hardware as retained LS')
        for path,want in b['inputs'].items():pin(path,want)
        for path,want in b['artifacts'].items():binary(path,want)
        for path,target in b['aliases'].items():
            need(str(Path(path).resolve(strict=True))==target,'every original lexical input alias')
            pin(path,b['inputs'][target])
        for path,target in b['namespace_aliases'].items():
            need(Path(path).is_symlink()and os.readlink(path)==target,'original sealed namespace alias')
            r['namespace_aliases'][path]=target
        evidence_pair={b['direct_prerequisite']['file'],str(Path(b['direct_prerequisite']['file']).with_suffix('.csv'))}
        need(len(evidence_pair)==2 and all(Path(path).parent==Path('evaluation/inprocess/results')for path in evidence_pair) and
             Path(b['direct_prerequisite']['file']).suffix=='.json',
             'exact two retained native41 public evidence files, never a broad source exemption')
        retained_evidence={}
        for path in sorted(evidence_pair):
            want=dict(b['inputs'][str(ROOT/path)],mode=0o644)
            binary(ROOT/path,want);retained_evidence[path]=want
        need(fact(ROOT/b['direct_prerequisite']['file'])==
             {k:b['direct_prerequisite'][k]for k in('bytes','sha256')},'whole exact origin native41 public receipt')
        native={str(Path(p).relative_to(ROOT)):v for p,v in b['inputs'].items()
            if Path(p).is_relative_to(ROOT)and not Path(p).is_relative_to(ROOT/'target')and
               str(Path(p).relative_to(ROOT))not in evidence_pair}
        for rev in (a.expect_origin_revision,a.expect_revision):
            source=git_bytes(rev,native)
            need(all(dict(bytes=len(source[p]),sha256=H(source[p]))==v for p,v in native.items()),
                 'all original source inputs match old and current Git')
        r['origin_source']=dict(files=len(native),sha256=D(native),retained_evidence=retained_evidence)
        old=[c for c in b['commands']if c['name']==LABEL];need(len(old)==1,'one exact failed real-LS subject');old=old[0]
        need(old['exit']==-9 and old['reaped']is True and old['timed_out']is False and old['error']is None and
             old['cleanup_errors']==[] and old['bounds']==list(TARGET) and old['capture_limit']==16<<20 and
             old['environment']==PROGRAM_ENV and all(x['closed']for x in old['descriptors']),
             'actual failed subject has unchanged limits and closed process/descriptors')
        need(set(old['captures'])=={'stdout','stderr','counters'} and
             all(old['captures'][k]['bytes']==0 for k in ('stdout','stderr')) and old['captures']['counters']['bytes']==4096,
             'original failed LS has only a separate post-reap counter prefix')
        for c in old['captures'].values():binary(bd/c['file'],c)
        r['origin']=dict(file=str(base.relative_to(ROOT)),receipt=fact(base),revision=a.expect_origin_revision,cpu=b['cpu'],status=b['status'],
            target_exit=old['exit'],duration_ns=old['duration_ns'],captures=old['captures'])
        rb=b['program_builds']['ls']['release_build'];build=b['build']
        need(build['status']=='passed'and build['command_completed']is True and build['configuration_unchanged']is True and
             build['final_errors']==[] and build['decoder_features']==['scalar-region','scalar-span','linked-epoch','mov-guard'] and
             rb['status']=='passed'and rb['capture']is False and rb['counters']is rb['retained_counters']is True and
             rb['profile']=='persistent-direct-frontier-counters-v1' and
             rb['counter_schema']==dict(version=2,bytes=752,page=4096,initial_seals=6,final_seals=23) and
             rb['active_domain']['slots']==rb['active_domain']['source_pairs_max']==2 and
             rb['active_domain']['differential']is False and rb['dispatch']['shared_boundaries']==8 and
             rb['direct_frontier']==dict(version=1,policy_version=5,conditions=16,shared_boundaries=8,
                 typed_external_arms=True,unknown_target='original branch-before full drain') and
             rb['persistent_binding']['version']==1 and rb['persistent_binding']['mode']=='counters' and
             all(rb['active_domain'][k]is True and rb['persistent_binding'][k]is True for k in
                 ('unregistered','subentry','cross_pair','direct_frontier','native_probe','parse_memo')),
             'exact actual per-LS direct counter build and unchanged ABI2')
        archive=binary(build['artifacts']['decoder.a']['path'],build['artifacts']['decoder.a'])
        # Existing producer's pure metadata/capture validator: no reader mutation replay or child execution.
        prior_context=dict(revision=b['revision'],source=b['source'],cpu=cpu,hardware=r['hardware'],
                           namespace_aliases=r['namespace_aliases'])
        exact_prior=direct_prerequisite(ROOT/b['direct_prerequisite']['file'],prior_context,pin,binary,archive)
        need(exact_prior==b['direct_prerequisite'],'whole exact original native41 public/private/CSV and typed prerequisite joins')
        r['direct_prerequisite']=exact_prior
        bridge=binary(rb['argv'][-1],b['artifacts'][rb['argv'][-1]])
        need(fact(archive)==b['archive']==rb['archive']==rb['persistent_binding']['archive']and fact(bridge)==rb['bridge'],
             'same actual archive, header binding and complete release ELF')
        recipe_path=pin(ROOT/'tools/page-entry/selected/build-persistent-direct-frontier-counters.sh',rb['recipe'])
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
        original=binary('/usr/bin/ls',b['system_inputs']['ls']['original'])
        carrier=binary(bd/'ls-build/ls-carrier',b['carriers']['ls'])
        interp=pin(interpreter(original),b['system_inputs']['ls']['interpreter'])
        need(fact(original)==rb['persistent_binding']['original']['image'] and interpreter(carrier)==bridge and
             b['program_builds']['ls']['original']==fact(original) and b['program_builds']['ls']['carrier']==fact(carrier) and
             b['program_builds']['ls']['bridge']==fact(bridge),'exact original LS/carrier/bound release ELF')
        python=pin(build['tools']['python']['path'],build['tools']['python'])
        need(python==Path(sys.executable).resolve(),'same actual Python executable for held launch wrapper')
        launcher=pin(ROOT/'tools/page-entry/carrier.py');roots=[Path('/usr/lib64')]
        ci=old['counter_input']
        exact=[str(python),'-B',str(launcher),'exec-loader','--counter-fd',str(ci['child_fd']),
            '--counter-nonce',str(ci['nonce']),'--library-root',str(roots[0]),'--namespace',str(bd/(LABEL+'-namespace')),
            str(carrier),str(original),'--',str(original),'-d','.']
        need(old['argv']==exact,'whole exact original failed LS argv')
        objects,description=namespace.plan(original,roots,bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
        need(description==b['namespace_plans']['ls'],'same complete original namespace source plan')
        for item in objects:pin(item['path'],dict(bytes=len(item['bytes']),sha256=H(item['bytes'])))
        need([dict(names=x['names'],**fact(x['path']))for x in objects]==b['system_inputs']['ls']['dependencies'],
             'same complete ordered retained dependency closure')
        state=dict(original=original,carrier=carrier,argv=[str(original),'-d','.'],objects=objects,description=description)
        counter_process.namespace_join(state,bd/(LABEL+'-namespace'),binary,r,namespace,ci)
        initial=(counter_process.MAGIC,2,752,4096,ci['nonce'],ci['parent'],ci['device'],ci['inode'])
        observed=old['counter_observation'];raw=(bd/old['captures']['counters']['file']).read_bytes()
        prefix=counter_process.final_counter_prefix(raw,initial,old['pid'],observed['final_seals'])
        need(observed['usable']is True and observed['raw']==fact(bd/old['captures']['counters']['file']) and
             all(observed[k]==v for k,v in prefix.items()),'old post-reap cells independently rejoin without transaction inference')
        r['configuration_presence']={p:os.path.lexists(p)for p in('/etc/ld.so.preload','/etc/ld.so.cache')}
        need(r['configuration_presence']==b['presence'] and not r['configuration_presence']['/etc/ld.so.preload'],
             'same original host loader configuration presence and no preload')
        if r['configuration_presence']['/etc/ld.so.cache']:pin('/etc/ld.so.cache')
        perf=binary('/usr/bin/perf');perfinterp=pin(interpreter(perf))
        _,listed,errors=run('perf-libraries',[perfinterp,'--list',perf]);need(not errors,'observer loader listing stderr')
        libs=observer_libraries(listed,perfinterp,pin)
        r['observer_tools']=dict(perf=fact(perf),python=fact(python),libraries={str(p):fact(p)for p in libs})
        r['kernel_controls']={name:Path('/proc/sys/kernel/'+name).read_text().strip()for name in
            ('perf_event_paranoid','perf_event_max_sample_rate','perf_event_mlock_kb')}
        fresh=out/'subject-namespace';argv=list(exact)
        for flag,value in (('--namespace',fresh),('--counter-fd','{counter_fd}'),('--counter-nonce','{counter_nonce}')):
            argv[argv.index(flag)+1]=str(value)
        row=dict(name=LABEL+'-observed',argv=argv,environment=dict(PROGRAM_ENV),cwd=str(bd),bounds=list(TARGET),capture_limit=16<<20)
        r.update(target=row,bridge=fact(bridge),archive=fact(archive),carrier=fact(carrier),original=fact(original),
            policy_sha256=rb['persistent_binding']['policy_sha256'])
        context=(state,fresh,binary,r,namespace)
        stable();stdout,stderr,owned=profile(row,out/'capture',cpu,bridge,rb['bridge'],perf=str(perf),
            user_dwarf=True,resident_counters=True,resident_per_thread=True)
        r['diagnostic']=owned
        p=binary(out/'capture/owner.json');need(D(json.loads(p.read_bytes()))==D(owned),'whole returned closed owner receipt')
        for name,want in owned['captures'].items():
            need(Path(name).name==name,'exact owner capture basename')
            capture=binary(out/'capture'/name,{k:want[k]for k in('bytes','sha256')});cs=capture.stat()
            need(dict(fact(capture),mode=cs.st_mode,device=cs.st_dev,inode=cs.st_ino)==want,
                 'whole actual owner capture bytes and full stat identity')
        counter_process.namespace_join(*context,row['counter_input']);r['namespace_complete']=True
        observed=row['counter_observation'];ci=row['counter_input']
        initial=(counter_process.MAGIC,2,752,4096,ci['nonce'],ci['parent'],ci['device'],ci['inode'])
        raw=binary(out/'capture/target.counters')
        prefix=counter_process.final_counter_prefix(raw.read_bytes(),initial,row['pid'],observed['final_seals'])
        need(row['reaped']is True and observed['usable']is True and observed['raw']==fact(raw) and
             all(observed[k]==v for k,v in prefix.items()),'exact actual post-wait4 counter prefix, never terminal arithmetic')
        r['counts']=prefix
        need(owned['sampling']['loss_free']and owned['sampling']['full_exec_exit_envelope'],'unchanged loss-free full exec envelope')
        symfs=out/'symfs';copy=symfs/str(bridge).lstrip('/');copy.parent.mkdir(parents=True);copy.write_bytes(bridge.read_bytes());copy.chmod(0o444);binary(copy,rb['bridge'])
        env=dict(owned['perf']['environment'],DEBUGINFOD_CACHE_PATH=str(out/'capture/cache'))
        _,text,err=run('user-dwarf-unwind',script_argv(perf,out/'capture/perf.data',symfs),env=env)
        r['unwinder_stderr']=fact(out/'user-dwarf-unwind.stderr')
        r['attribution']=attribute(out/'capture',bridge,text,row['pid'])
        p=binary(out/'capture/attribution.json');binary(out/'capture/unwound.json')
        need(D(json.loads(p.read_bytes()))==D(r['attribution']),'whole returned attribution output')
        stable();r['phases']=phase_timeline(out/'capture',bridge,r['attribution'],owned['sampling'])
        r['leaf_costs']=leaf_costs(bridge,r['attribution'])
        r['status']='observed_unqualified'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        owner=out/'capture/owner.json'
        if owner.exists():
            try:r['diagnostic']=json.loads(owner.read_bytes())
            except BaseException as exc:r['final_errors'].append('owner: '+repr(exc))
        if context and not r['namespace_complete'] and row.get('reaped'):
            try:counter_process.namespace_join(*context,row['counter_input']);r['namespace_complete']=True
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
            reproduce=['env','PYTHONDONTWRITEBYTECODE=1','python3','-B',
                str((HERE/'exact_cpu/run_exact_cpu.py').relative_to(ROOT)),
                '--tool-root','${AGENT_UTILS_ROOT}','--cpu',str(cpu),
                '--expect-revision',a.expect_revision,'--expect-origin-revision',a.expect_origin_revision,
                '--origin-receipt',str(origin.relative_to(ROOT)),
                '--expect-origin-sha256',a.expect_origin_sha256,'--output','${FRESH_PRIVATE_OUTPUT}'],
            bounds=r['bounds'],target_exit=(row or{}).get('exit'),target_outcome=r['target_outcome'],target_usage=(row or{}).get('usage'),
            target_wall_ns=(row or{}).get('process_ns'),counter_record=owned.get('captures',{}).get('target.counters'),counts=r.get('counts'),
            bridge=r.get('bridge'),archive=r.get('archive'),original=r.get('original'),carrier=r.get('carrier'),
            sample_count=owned.get('sampling',{}).get('samples'),exec_user_samples=r.get('attribution',{}).get('samples'),
            exec_user_period=r.get('attribution',{}).get('period'),sample_window='First same-PID COMM_EXEC after release through actual EXIT, including launch Python; not an LS-only interval.',loss_free=owned.get('sampling',{}).get('loss_free'),
            exec_envelope=owned.get('sampling',{}).get('full_exec_exit_envelope'),source_unchanged=r['source_unchanged'],
            cleanup_complete=r['cleanup_complete'],namespace_complete=r['namespace_complete'],private_receipt=fact(out/'receipt.json'),
            top_functions=r.get('attribution',{}).get('functions',[])[:12],phases=r.get('phases'),leaf_costs=r.get('leaf_costs'),
            error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            scope='One same-CPU 99Hz user-only observation of exact retained real LS, including launch Python. '
                'Target exit remains independent and failed if nonzero. Counter cells are a post-reap possibly split prefix, not completed transactions. '
                'No terminal proof, qualification, kernel/wall attribution, throughput or speedup.')
        data=(json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
        need(len(data)<=32<<10 and all(x.encode()not in data for x in(str(ROOT),str(Path.home()),'/home/',platform.node())if len(x)>1),
             'small sanitized diagnostic projection')
        (out/'summary.json').write_bytes(data)
        print(json.dumps(dict(status=r['status'],target_exit=(row or{}).get('exit'),output=str(out))))
    return int(r['status']!='observed_unqualified')


if __name__=='__main__':raise SystemExit(main())
