#!/usr/bin/env python3
"""One held-target user-DWARF diagnostic from an exact closed dynamic release.

No native baseline, target retry, qualification or speedup. Target failure stays
failure; a complete loss-free profiler envelope can still describe that prefix.
"""
import argparse,csv,io,json,os,platform,re,sys,types
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SCRIPT='evaluation/inprocess/persistent_dynamic_profile.py'
from linked_frontier_census import need,fact,git,git_bytes,source_paths,H,D
from page_selected import save,interpreter
from page_selected_process import invoke
from page_native_pair_performance import PROGRAM_ENV,namespace_join,resolved_libraries
from page_selected_register_time_build import recipe,expand
from page_cost_profile import profile,TARGET,PERF
from persistent_dynamic_profile_read import script_argv,attribute
import persistent_dynamic_experiment as diagnostic
from run import hardware
sys.path.insert(0,str(ROOT/'tools/page-entry'))
import namespace


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt',type=Path,required=True)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and one externally reserved CPU')
    need(Path(__file__).resolve()==ROOT/SCRIPT and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'canonical committed profiler and exact revision')
    out=a.output.resolve();out.relative_to(ROOT/'target/page-region-next');out.mkdir(mode=0o700)
    cpu=next(iter(os.sched_getaffinity(0)))
    r=dict(schema=1,profile='persistent-dynamic-user-dwarf-v1',status='failed',qualification=False,
        performance_credit=False,source_revision=a.expect_revision,cpu=cpu,hardware=hardware(cpu),
        bounds=dict(target=list(TARGET),profiler=list(PERF),unwinder=list(PERF)),
        commands=[],inputs={},aliases={},artifacts={},namespace_aliases={},error=None,final_errors=[],
        source_unchanged=False,cleanup_complete=False)
    current={};manifest=None
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
                rel=str(p.relative_to(ROOT));need(rel in current and fact(p)==current[rel],
                    'every executed local module is an exact committed input')
            pin(p)
    def stable():
        imports()
        need(all(fact(p)==v for p,v in r['inputs'].items()),'all input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in r['aliases'].items()),'all input aliases unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o7777)==v for p,v in r['artifacts'].items()),
             'all artifacts unchanged')
        need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),
             'all retained namespace aliases unchanged')
        need(all(os.path.lexists(p)==v for p,v in r.get('configuration_presence',{}).items()),
             'loader configuration presence unchanged')
    def run(name,argv,env=PROGRAM_ENV,bounds=PERF):
        stable();binary(argv[0]);need(name not in [c['name']for c in r['commands']],'no command retry')
        row=dict(name=name,argv=list(map(str,argv)),environment=dict(env),bounds=list(bounds),capture_limit=16<<20)
        r['commands'].append(row)
        try:stdout,stderr=invoke(row,out,cpu)
        finally:
            for c in row.get('captures',{}).values():binary(out/c['file'])
            save(out/'receipt.json',r)
        need(row['exit']==0 and row['reaped']and not row['timed_out']and not row['error']and
             not row['cleanup_errors'],'actual bounded auxiliary command completion')
        return row,stdout,stderr
    try:
        need(git('rev-parse','HEAD').decode().strip()==a.expect_revision,'exact current committed revision')
        code,compiled=source_paths(a.expect_revision);blobs=git_bytes(a.expect_revision,code|compiled)
        current={p:dict(bytes=len(v),sha256=H(v))for p,v in blobs.items()}
        need(SCRIPT in code and all((ROOT/p).read_bytes()==v for p,v in blobs.items()),'whole current source closure')
        manifest=dict(revision=a.expect_revision,code={p:current[p]for p in code},compiled={p:current[p]for p in compiled})
        save(out/'source-manifest.json',manifest);binary(out/'source-manifest.json')
        for p in current:pin(ROOT/p)
        base=pin(a.receipt);b=json.loads(base.read_bytes());bd=base.parent
        need(b['scope']=='UNQUALIFIED_DYNAMIC_PERSISTENT_LS_ONLY'and b['source_unchanged']is True and
             b['cleanup_complete']is True and b['final_errors']==[] and b['error']is None,
             'closed original diagnostic retained exactly, with no qualification inference')
        need(re.fullmatch('[0-9a-f]{40}',b['source_revision'])and all(c['reaped']and not c['error']and
             not c['timed_out']and not c['cleanup_errors']and all(d['closed']for d in c.get('descriptors',[]))
             for c in b['commands']),'original command/source/process closure')
        r['origin']=dict(receipt=fact(base),runtime_revision=b['source_revision'],status=b['status'],
                         target_exit=b['case']['exit'])
        # Every compiled source is equal in old receipt, its actual Git revision,
        # current checkout and current Git. Python observer changes are separate.
        native={}
        for path,want in b['inputs'].items():
            p=Path(path);rel=str(p.relative_to(ROOT))if p.is_relative_to(ROOT)else None
            if rel is not None and (rel.startswith(('tools/page-entry/','src/','crates/'))or rel in('Cargo.toml','Cargo.lock')):
                pin(p,want);native[rel]=want
            elif rel is None or rel.startswith('target/'):
                pin(p,want)
        need(native,'nonempty exact native source input population')
        for rev in (b['source_revision'],a.expect_revision):
            got=git_bytes(rev,native)
            need(all(dict(bytes=len(got[p]),sha256=H(got[p]))==v for p,v in native.items()),
                 'same whole compiled source at actual old and current revisions')
        r['compiled_source_count']=len(native);r['compiled_source_sha256']=D(native)
        for alias,resolved in b['aliases'].items():
            if resolved in r['inputs']:pin(alias,r['inputs'][resolved])
        rb=b['release_build'];build=b['build']
        need(build['status']=='passed'and build['command_completed']is True and build['configuration_unchanged']is True and
             build['final_errors']==[] and build['decoder_features']==['scalar-region','scalar-span','linked-epoch','mov-guard'] and
             rb['status']=='passed'and rb['profile']=='persistent-dynamic-adjacent-two-page-v1'and
             rb['dynamic']is True and rb['capture']is False,'complete actual dynamic release and exact decoder features')
        archive=binary(build['artifacts']['decoder.a']['path'],build['artifacts']['decoder.a'])
        bridge=binary(rb['argv'][-1],b['artifacts'][rb['argv'][-1]])
        need(fact(archive)==b['archive']==rb['archive']==rb['persistent_binding']['archive']and
             fact(bridge)==rb['bridge'],'same actual archive/binding/release ELF')
        recipe_path=pin(ROOT/'tools/page-entry/selected/build-persistent-dynamic.sh',rb['recipe'])
        recipes=recipe(recipe_path,'"$cc_bin"');need(len(recipes)==1,'one complete dynamic release recipe')
        expected=expand(recipes[0],{'$cc_bin':build['tools']['cc']['path'],
            '$selected_dir':ROOT/'tools/page-entry/selected','$parent_dir':ROOT/'tools/page-entry',
            '$archive':archive,'$output':bridge.parent})
        need(expected==rb['argv']and sum(c['argv']==expected and c['exit']==0 for c in b['commands'])==1,
             'exact actual committed release command; no private rebuild or substituted profile')
        for header,want in rb['headers'].items():pin(header,want)
        for item in rb['persistent_binding']['header_paths'].values():pin(item['path'],item)
        pin(rb['persistent_binding']['manifest']['path'],rb['persistent_binding']['manifest'])
        need(rb['fast_bytes']['status']=='passed','actual mandatory byte oracle completed')
        oracle=[c for c in b['commands']if c['name']==rb['fast_bytes']['command']]
        need(len(oracle)==1 and oracle[0]['exit']==0,'one actual retained byte-oracle process')
        for c in [oracle[0],next(c for c in b['commands']if c['argv']==expected)]:
            for value in c['captures'].values():binary(bd/value['file'],value)
        old=[c for c in b['commands']if c['name']=='dynamic-ls'];need(len(old)==1,'one exact original LS command')
        old=old[0];need(old['bounds']==list(TARGET)and old['capture_limit']==16<<20 and
            old['environment']==PROGRAM_ENV,'unchanged actual target bounds/environment')
        original=pin('/bin/ls',b['system_inputs']['dynamic-ls']['original'])
        interp=pin(interpreter(original),b['system_inputs']['dynamic-ls']['interpreter'])
        python=pin(build['tools']['python']['path'],build['tools']['python']);carrier_tool=pin(ROOT/'tools/page-entry/carrier.py')
        need(old['argv']==[str(python),'-B',str(carrier_tool),'exec-loader','--library-root','/usr/lib64',
            '--namespace',str(bd/'dynamic-ls-namespace'),str(bd/'dynamic-ls-carrier'),str(original),'--',str(original),'-d','.'],
            'exact original full LS argv, not a shorter workload')
        objects,description=namespace.plan(original,[Path('/usr/lib64')],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
        need(description==b['namespace_plans']['dynamic-ls'],'fresh complete namespace plan equals actual original')
        deps=[dict(names=x['names'],**fact(pin(x['path'],dict(bytes=len(x['bytes']),sha256=H(x['bytes'])))))for x in objects]
        need(deps==b['system_inputs']['dynamic-ls']['dependencies'],'same complete actual library closure')
        r['configuration_presence']={p:os.path.lexists(p)for p in('/etc/ld.so.preload','/etc/ld.so.cache')}
        need(not r['configuration_presence']['/etc/ld.so.preload'],'no host preload')
        if r['configuration_presence']['/etc/ld.so.cache']:pin('/etc/ld.so.cache')
        carrier=out/'carrier';_,stdout,stderr=run('carrier',[python,'-B',carrier_tool,'make',original,bridge,carrier],bounds=TARGET)
        need(not stderr,'actual carrier creation stderr');binary(carrier);made=json.loads(stdout)
        need(all(made[k+'_sha256']==fact(p)['sha256']for k,p in
            (('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and
            fact(carrier)==b['carriers']['dynamic-ls'] and interpreter(carrier)==bridge,
            'fresh carrier has all four exact original content identities')
        state=dict(objects=objects,description=description,argv=[str(original),'-d','.'],carrier=carrier)
        perf=binary('/usr/bin/perf');perfinterp=pin(interpreter(perf))
        pobj,pdesc=namespace.plan(perf,[Path('/usr/lib64')],bytes.fromhex(fact(perf)['sha256']),bytes.fromhex(fact(perfinterp)['sha256']))
        pexpected={perfinterp:set()}
        for item in pobj:
            p=pin(item['path'],dict(bytes=len(item['bytes']),sha256=H(item['bytes'])))
            pexpected.setdefault(p,set()).update(item['names'])
        _,listed,errors=run('perf-libraries',[perfinterp,'--list',perf])
        need(not errors,'actual observer loader dependency listing');resolved_libraries(listed,pexpected,perfinterp,pin)
        r['observer_libraries']={str(p):fact(p)for p in pexpected}
        wrapper_python=pin(Path(sys.executable).resolve())
        r['observer_tools']=dict(perf=fact(perf),target_python=fact(python),wrapper_python=fact(wrapper_python),
            libraries_count=len(pexpected),libraries_sha256=D(r['observer_libraries']))
        r['kernel_controls']={name:Path('/proc/sys/kernel/'+name).read_text().strip()for name in
            ('perf_event_paranoid','perf_event_max_sample_rate','perf_event_mlock_kb')}
        ns=out/'namespace';argv=list(old['argv']);argv[7]=str(ns);argv[8]=str(carrier)
        row=dict(name='dynamic-ls-profile',argv=argv,environment=dict(PROGRAM_ENV),cwd=str(bd),bounds=list(TARGET),capture_limit=16<<20)
        r.update(target=row,bridge=fact(bridge),archive=fact(archive),carrier=fact(carrier),policy_sha256=rb['persistent_binding']['policy_sha256'])
        stable();stdout,stderr,owned=profile(row,out/'capture',cpu,bridge,rb['bridge'],perf=str(perf),user_dwarf=True)
        r['diagnostic']=owned;namespace_join(state,ns,binary,r,namespace)
        need(owned['sampling']['full_exec_exit_envelope']and owned['sampling']['loss_free'],
             'complete loss-free actual profiling envelope; no truncated capture ranks')
        symfs=out/'symfs';copy=symfs/str(bridge).lstrip('/');copy.parent.mkdir(parents=True)
        copy.write_bytes(bridge.read_bytes());copy.chmod(0o444);binary(copy,rb['bridge'])
        env=dict(owned['perf']['environment'],DEBUGINFOD_CACHE_PATH=str(out/'capture/cache'))
        _,text,err=run('user-dwarf-unwind',script_argv(perf,out/'capture/perf.data',symfs),env=env)
        # Missing libraries/debug frames are an observation limit, not a reason
        # to fabricate stacks. stderr is retained whole; header/sample bijection
        # and exact pinned-map resolution determine what is actually reported.
        r['unwinder_stderr']=fact(out/'user-dwarf-unwind.stderr')
        r['attribution']=attribute(out/'capture',bridge,text,row['pid'])
        r['target_outcome']='exit_zero'if row['exit']==0 else'failed_prefix'
        if stderr:
            try:r['terminal_counters']=diagnostic.counters(stderr)
            except ValueError as exc:r['terminal_counter_error']=str(exc)
        r['status']='observed_unqualified'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        owner=out/'capture/owner.json'
        if owner.exists():
            try:r['diagnostic']=json.loads(owner.read_bytes())
            except BaseException as exc:r['final_errors'].append('owner: '+repr(exc))
        try:
            stable();need(git('rev-parse','HEAD').decode().strip()==a.expect_revision and
                all(fact(ROOT/p)==v for p,v in current.items()),'whole committed source remained unchanged')
            r['source_unchanged']=True
        except BaseException as exc:r['final_errors'].append('source/input closure: '+repr(exc))
        r['cleanup_complete']=r.get('diagnostic',{}).get('closed')is True and all(c.get('reaped')is True and
            c.get('cleanup_errors')==[] and all(d.get('closed')is True for d in c.get('descriptors',[]))for c in r['commands'])
        for p in sorted(out.rglob('*')):
            if p.is_file()and not p.is_symlink()and p.name!='receipt.json':
                try:binary(p)
                except BaseException as exc:r['final_errors'].append('artifact: '+repr(exc))
        if r['error']or r['final_errors']or not r['cleanup_complete']or not r['source_unchanged']:r['status']='failed'
        save(out/'receipt.json',r);publish(out,r)
    return int(r['status']!='observed_unqualified')


def publish(out,r):
    owned=r.get('diagnostic',{});sample=owned.get('sampling',{});ranking=r.get('attribution',{})
    hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
    def top(name):
        rows=ranking.get(name,[]);first=rows[:3];rest=rows[3:]
        return dict(top3=first,remaining=dict(groups=len(rest),samples=sum(x['samples']for x in rest),period=sum(x['period']for x in rest)))
    target=r.get('target',{});caps=owned.get('captures',{})
    def command(argv):
        ans=[]
        for x in argv:
            x=str(x).replace(str(out),'${OUTPUT}').replace(str(ROOT),'${REPO}')
            ans.append(x)
        if ans:ans[0]='${EXECUTABLE}'
        if '--pid'in ans:ans[ans.index('--pid')+1]='${TARGET_PID}'
        ans=['--control=fd:${CONTROL},${ACK}'if x.startswith('--control=fd:')else x for x in ans]
        return ans
    value=dict(schema=1,profile=r['profile'],status=r['status'],qualification=False,performance_credit=False,
        source_revision=r['source_revision'],runtime_origin=r.get('origin'),cpu=r['cpu'],hardware=hw,bounds=r['bounds'],
        target_exit=target.get('exit'),target_outcome=r.get('target_outcome'),target_wall_ns=target.get('process_ns'),
        target_usage=target.get('usage'),target_stdout=caps.get('target.stdout'),target_stderr=caps.get('target.stderr'),
        profiler_exit=owned.get('perf',{}).get('exit'),observer_tools=r.get('observer_tools'),
        target_argv=command(target.get('argv',[])),observer_argv=command(owned.get('perf',{}).get('argv',[])),
        bridge=r.get('bridge'),archive=r.get('archive'),policy_sha256=r.get('policy_sha256'),
        full_exec_exit_envelope=sample.get('full_exec_exit_envelope'),loss_free=sample.get('loss_free'),
        all_recorded_samples=sample.get('samples'),exec_user_samples=ranking.get('samples'),exec_user_period=ranking.get('period'),
        pre_exec_samples=(sample['samples']-ranking['samples']if sample and ranking else None),
        pre_exec_period=(sample['sampled_period_total']-ranking['period']if sample and ranking else None),
        sample_window='First same-PID COMM_EXEC after release through actual EXIT, including Python carrier startup; not an LS-only interval.',
        unknown_leaf_samples=ranking.get('unknown_leaf_samples'),unknown_leaf_period=ranking.get('unknown_leaf_period'),
        unwind_states=ranking.get('unwind_states'),unwind_complete=False,functions=top('functions'),paths=top('paths'),
        source_unchanged=r['source_unchanged'],cleanup_complete=r['cleanup_complete'],final_error_count=len(r['final_errors']),
        error_type=r['error'].split(':',1)[0]if r['error']else None,private_receipt=fact(out/'receipt.json'),
        reproduce=['python3','-B',SCRIPT,'--receipt','${CLOSED_DYNAMIC_LS_RECEIPT}','--expect-revision',r['source_revision'],'--output','${FRESH_PRIVATE_OUTPUT}'],
        scope='One same-CPU user-only statistical observation. Target failure remains failed. '
        'Ranks use period weights over the full command exec window, including carrier startup and unknowns. Pre-exec held-wrapper samples remain separately counted. Only the pinned bridge is symbolized; '
        'library/generated frames stay unknown. Bounded observed paths are not proved complete stacks. '
        'No baseline, wall-time attribution, qualification, aggregate or speedup.')
    # identity() includes no paths; publish only complete numeric capture facts.
    for key in ('target_stdout','target_stderr'):
        if value[key]:value[key]={k:value[key][k]for k in('bytes','sha256')}
    stream=io.StringIO();writer=csv.writer(stream,lineterminator='\n');writer.writerow(['kind','rank','key','samples','sampled_period'])
    for kind in ('functions','paths'):
        for i,item in enumerate(value[kind]['top3'],1):writer.writerow([kind,i,json.dumps(item['key'],separators=(',',':')),item['samples'],item['period']])
        x=value[kind]['remaining'];writer.writerow([kind,'remaining',str(x['groups'])+' groups',x['samples'],x['period']])
    data=stream.getvalue().encode();value['csv']=dict(bytes=len(data),sha256=H(data))
    text=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    need(len(text)<=32<<10 and len(data)<=16<<10 and all(x.encode()not in text+data for x in
         (str(ROOT),str(Path.home()),'/home/',platform.node())if len(x)>1),'bounded sanitized public projection')
    (out/'summary.json').write_bytes(text);(out/'summary.csv').write_bytes(data)
    print(json.dumps(dict(status=r['status'],target_exit=target.get('exit'),summary=str(out/'summary.json'))))


if __name__=='__main__':raise SystemExit(main())
