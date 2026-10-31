#!/usr/bin/env python3
"""One startup counter-release diagnostic; a killed prefix is not a completed run."""
import argparse,json,os,platform,re,struct,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path.cwd().resolve();HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(ROOT/'tools/page-entry')]
from linked_frontier_census import need,fact,git,git_bytes,source_paths,H,D
from page_selected import ENV,save,interpreter
from page_selected_process import invoke
from persistent_dynamic import BOUNDS
from persistent_epoch_build import FEATURES
from persistent_startup_build import build_bridge
from unrolled_hash_owner import prepare_inputs
from run import hardware
import persistent_group_counter_process as counter_process
import namespace

ORIGIN_REVISION='3ce8218f1f73821251ef6aad687adf469b2b451f'
ORIGIN_SHA='d30ba4f0f241e62071d6432c5ce1ee1e97aae709d8356d6d3921fc8bc33be820'
ORIGIN_LABEL='subject-maintained-2-0'
TARGET=[30,512<<20,16<<20,60]
MISS_NAMES=('NONE','ROOT_UNSUPPORTED','SOURCE_INVALID','SOURCE_TRUNCATED','SOURCE_OVERLAP','OUTSIDE_PAIR',
    'HEAD_LIMIT','EXIT_LIMIT','QUEUE_LIMIT','NO_EXIT','RIP_REACH','BRANCH_REACH','FALLTHROUGH_REACH',
    'GUARD_RIP_REACH','GUARD_FOLLOW_REACH','ROOT_SELECTED','SINGLE_MEMBER','LINK_LIMIT')


def preparation(row,directory,original,objects,description,carrier,binary,r):
    """Exact original mode2 launch plus the separately authenticated counter channel."""
    prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']=='gated'and
         prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==prep['launch_mask']==0 and
         prep['argv']==[str(original),'2','gated']and prep['default_rseq']is False and
         prep['mode']==2 and prep['control']==0 and prep['observer']is None and
         [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and
         all(x['after']==0 for x in prep['dispositions']), 'actual exact mode2 signal/argv preparation')
    counter=row['counter_input']
    need(prep['counter']==dict(fd=counter['child_fd'],nonce=counter['nonce'],parent=counter['parent'],
         device=counter['device'],inode=counter['inode'],bytes=4096,logical_bytes=752,initial_seals=6),
         'actual same counter descriptor/header identity across fork and in-place exec')
    ns=directory/'namespace'
    observed=json.loads(binary(ns/'namespace.json').read_bytes())
    launch=json.loads(binary(ns/'launch.json').read_bytes())
    need(all(observed[k]==v for k,v in description.items())and len(observed['objects'])==len(objects)and
         observed['schema_version']==1 and observed['scope']=='explicit_sealed_dependency_namespace'and
         observed['status']=='prepared_not_executed'and observed['directory']==str(ns)and
         observed['search_policy']=='explicit roots; no RPATH/RUNPATH/cache emulation'and
         observed['identity_policy']=='sealed copies and private paths; not filesystem transparency',
         'whole actual namespace equals independently planned source namespace')
    fds=[]
    for obj,item in zip(observed['objects'],objects,strict=True):
        need(obj['names']==item['names']and obj['needed']==item['info']['needed']and
             obj['source']==str(item['path'])and obj['descriptive_pt_interp']==
             (str(item['info']['interpreter'])if item['info']['interpreter']else None)and
             obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and obj['seals']==namespace.SEALS and
             type(obj['fd'])is int and obj['fd']>2 and obj['fd']not in fds and obj['fd']!=counter['child_fd']and
             type(obj['device'])is int and obj['device']>0 and type(obj['inode'])is int and obj['inode']>0,
             'actual complete sealed dependency identity and separate counter descriptor')
        fds.append(obj['fd'])
        for name in item['names']:
            p=ns/name;value='/proc/self/fd/'+str(obj['fd'])
            need(p.is_symlink()and os.readlink(p)==value,'actual sealed namespace alias')
            r['namespace_aliases'][str(p)]=value
    environment=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',
        LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),GLIBC_TUNABLES='glibc.pthread.rseq=0',
        LI2_PERSISTENT_INTERPRETER_LOOP_APP_MODE='2',LI2_GROUP_COUNTER_FD=str(counter['child_fd']),
        LI2_GROUP_COUNTER_NONCE=str(counter['nonce']))
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
         argv=prep['argv'],dependency_fds=fds,carrier_sha256=fact(carrier)['sha256'],
         carrier_size=fact(carrier)['bytes'],environment=environment)and prep['late_sonames']==[]and
         prep['environment_source']==str(ns/'launch.json'), 'exact original startup environment plus counter FD/nonce')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--origin-receipt',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and one reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact committed revision')
    evidence=ROOT/'target/evaluation/inprocess'
    origin=a.origin_receipt.resolve(strict=True);origin.relative_to(evidence)
    out=a.output.resolve();out.relative_to(evidence);need(out!=evidence,'fresh private result directory')
    out.mkdir(mode=0o700);cpu=next(iter(os.sched_getaffinity(0)))
    r=dict(schema=1,profile='startup-final-counter-diagnostic-v1',status='failed',qualification=False,
        performance_credit=False,source_revision=a.expect_revision,cpu=cpu,hardware=hardware(cpu),
        bounds=dict(target=TARGET,release_build=BOUNDS['release_build'],finite=BOUNDS['finite']),
        commands=[],inputs={},aliases={},artifacts={},namespace_aliases={},error=None,final_errors=[],
        source_unchanged=False,cleanup_complete=False,namespace_complete=False,target_outcome='not_run',
        terminal=None,subentry_opportunities=None)
    current={};private={};row=None;context=None
    def pin(path,want=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);v=fact(p)
        need(want is None or v=={k:want[k]for k in('bytes','sha256')},'exact input '+str(alias))
        need(str(p)not in r['inputs']or r['inputs'][str(p)]==v,'same input throughout attempt')
        need(str(alias)not in r['aliases']or r['aliases'][str(alias)]==str(p),'same lexical input alias')
        r['inputs'][str(p)]=v;r['aliases'][str(alias)]=str(p);return p
    def binary(path,want=None):
        p=pin(path,want);v=dict(fact(p),mode=p.stat().st_mode&0o7777)
        need(want is None or 'mode'not in want or v['mode']==want['mode'],'same actual artifact mode')
        need(str(p)not in r['artifacts']or r['artifacts'][str(p)]==v,'same artifact bytes/mode')
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
                want=private.get(str(p),current.get(str(p.relative_to(ROOT))))
                need(want is not None and fact(p)==want,'exact committed or frozen private module')
            pin(p)
    def stable():
        imports()
        need(all(fact(p)==v for p,v in r['inputs'].items()),'all input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in r['aliases'].items()),'all input aliases unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o7777)==v for p,v in r['artifacts'].items()),'all artifacts unchanged')
        need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),'all namespace aliases unchanged')
        need(all(os.path.lexists(p)==v for p,v in r.get('configuration_presence',{}).items()),'loader configuration presence unchanged')
    def run(name,argv,profile='metadata',expected=0,env=None,record=False):
        need(record is False and profile in ('metadata','inspect','release_build','program','finite'),
             'only existing bounded auxiliary and target profiles; no capture')
        stable();binary(argv[0]);need(name not in [c['name']for c in r['commands']],'no command retry')
        command=dict(name=name,argv=list(map(str,argv)),environment=dict(ENV if env is None else env),
            profile=profile,bounds=list(BOUNDS[profile]),expected_exit=expected,capture_limit=16<<20)
        r['commands'].append(command)
        try:stdout,stderr=invoke(command,out,cpu)
        finally:
            for c in command.get('captures',{}).values():binary(out/c['file'])
            save(out/'receipt.json',r)
        need(command['exit']==expected and command['reaped']and not command['timed_out']and
             not command['error']and not command['cleanup_errors'],'actual bounded auxiliary command completion')
        return command,stdout,stderr
    try:
        need(git('rev-parse','HEAD').decode().strip()==a.expect_revision and not git('status','--porcelain','-uno'),
             'exact clean committed source before diagnostic')
        packet=pin(HERE/'SOURCE.json');s=json.loads(packet.read_bytes());r['packet']=fact(packet)
        need(set(s['files'])=={'counts.py','launch_counts.py'},'exact two frozen diagnostic leaves')
        for name,want in s['files'].items():
            p=pin(HERE/name,want);private[str(p)]=fact(p)
        for path,want in s['inputs'].items():pin(ROOT/path,want)
        code,compiled=source_paths(a.expect_revision);blobs=git_bytes(a.expect_revision,code|compiled)
        current={p:dict(bytes=len(v),sha256=H(v))for p,v in blobs.items()}
        need(all((ROOT/p).read_bytes()==v for p,v in blobs.items()),'whole current source closure')
        for p in current:pin(ROOT/p)
        r['current_source']=dict(revision=a.expect_revision,files=len(current),sha256=D(current))
        base=pin(origin);need(fact(base)['sha256']==ORIGIN_SHA,'exact whole original failed startup receipt')
        b=json.loads(base.read_bytes());bd=base.parent
        need(b['revision']==ORIGIN_REVISION and b['source']['revision']==ORIGIN_REVISION and
             b['source']['tracked_clean']is True and b['source']['head_sources_match']is True and
             b['source']['tree']==git('rev-parse',ORIGIN_REVISION+'^{tree}').decode().strip()and
             b['source_unchanged']is True and b['cleanup_complete']is True and b['final_errors']==[]and
             b['status']=='failed'and b['error']=='ValueError: all three actual loop outcomes required without skipped or relabelled failures',
             'original failed startup outcome and complete source/cleanup closure')
        need([(c['lane'],c['mode'],c['control'],c['exit'],c['status'])for c in b['cases']]==[
             ('native',2,0,0,'observed_native_startup_loop'),('maintained',2,0,-9,'failed'),
             ('differential',2,0,-9,'failed')]and all(c['launched']is True and c['timed_out']is False for c in b['cases']),
             'original successful native and both killed generated cases remain distinct')
        for path,want in b['inputs'].items():pin(path,want)
        for path,want in b['artifacts'].items():binary(path,want)
        for path,target in b['namespace_aliases'].items():
            need(Path(path).is_symlink()and os.readlink(path)==target,'original namespace alias')
            r['namespace_aliases'][path]=target
        old_sources={str(Path(p).relative_to(ROOT)):v for p,v in b['inputs'].items()
            if Path(p).is_relative_to(ROOT)and not Path(p).is_relative_to(ROOT/'target')}
        for rev in (ORIGIN_REVISION,a.expect_revision):
            source=git_bytes(rev,old_sources)
            need(all(dict(bytes=len(source[p]),sha256=H(source[p]))==v for p,v in old_sources.items()),
                 'all actual origin source inputs match original and current Git')
        r['origin_source']=dict(files=len(old_sources),sha256=D(old_sources))
        candidates=[c for c in b['commands']if c['name']==ORIGIN_LABEL]
        need(len(candidates)==1,'one exact failed maintained command');old=candidates[0]
        need(old['exit']==-9 and old['reaped']is True and old['timed_out']is False and old['error']is None and
             old['cleanup_errors']==[]and old['bounds']==TARGET and old['capture_limit']==16<<20 and
             old['environment']==ENV and all(x['closed']for x in old['descriptors'])and
             set(old['captures'])=={'stdout','stderr','record'}and all(c['bytes']==0 for c in old['captures'].values()),
             'actual failed subject retains exact bounds and no terminal/focal evidence')
        for c in old['captures'].values():binary(bd/c['file'],c)
        r['origin']=dict(file=str(base.relative_to(ROOT)),receipt=fact(base),revision=ORIGIN_REVISION,cpu=b['cpu'],
            status=b['status'],target_exit=old['exit'],duration_ns=old['duration_ns'])
        build=b['build'];lane=b['lanes']['maintained'];old_release=lane['release_build']
        need(build['status']=='passed'and build['command_completed']is True and build['configuration_unchanged']is True and
             build['final_errors']==[]and build['decoder_features']==list(FEATURES)and
             old_release['status']=='passed'and old_release['profile']=='persistent-startup-capture-v1'and
             old_release['capture']is True and old_release['active_domain']['unregistered']is True and
             old_release['active_domain']['differential']is False,'closed original decoder and maintained capture build')
        archive=binary(build['artifacts']['decoder.a']['path'],build['artifacts']['decoder.a'])
        need(fact(archive)==old_release['archive']==old_release['persistent_binding']['archive'],
             'same retained archive and original policy binding')
        for tool in build['tools'].values():binary(tool['path'],tool)
        for path,want in build['dep_info'].items():
            pin(ROOT/path if not Path(path).is_absolute()else path,want)
        original=binary(old['argv'][old['argv'].index('--original')+1])
        old_carrier=binary(old['argv'][old['argv'].index('--carrier')+1])
        old_bridge=binary(old_release['argv'][-1])
        need(fact(original)==b['application_build']['artifact']==lane['subject_artifacts']['original']and
             fact(old_carrier)==lane['subject_artifacts']['carrier']and fact(old_bridge)==old_release['bridge']and
             interpreter(old_carrier)==old_bridge,'actual original app, original carrier and original bridge identities')
        python=binary(build['tools']['python']['path'],build['tools']['python'])
        roots=[original.parent,Path('/usr/lib64')]
        original_launcher=pin(ROOT/'tools/page-entry/selected/tests/persistent_interpreter_loop_app/launch.py')
        need(old['argv']==list(map(str,[python,'-B',original_launcher,'--root',ROOT,'--role','gated','--mode','2',
             '--control','0','--original',original,'--preparation',bd/ORIGIN_LABEL/'preparation.json',
             '--library-root',roots[0],'--library-root',roots[1],'--carrier',old_carrier,
             '--namespace',bd/ORIGIN_LABEL/'namespace','--record-fd','3'])),'whole original target command')
        # This is an authenticated retained decoder archive, never a claimed new Rust build.
        builder=types.SimpleNamespace(mov_guard=True,linked_epoch=True,scalar_span=True,
            extra_decoder_sources=('region.rs','mov_guard.rs'),decoder_features=FEATURES,record=build,
            environment=dict(build['environment']),tools={k:v['path']for k,v in build['tools'].items()},
            paths={'archive':archive},retained=archive.parent)
        r['decoder_archive']=dict(reused=True,origin_receipt=fact(base),archive=fact(archive),features=list(FEATURES))
        r['configuration_presence']={p:os.path.lexists(p)for p in('/etc/ld.so.preload','/etc/ld.so.cache')}
        need(not r['configuration_presence']['/etc/ld.so.preload'],'no host preload')
        if r['configuration_presence']['/etc/ld.so.cache']:pin('/etc/ld.so.cache')
        # The same finite protocol oracle proves split updates remain raw per-cell values.
        _,protocol_out,protocol_err=run('counter-protocol',[python,'-B',ROOT/'evaluation/inprocess/persistent_group_counter_protocol.py'],profile='finite')
        refusals=['truncated','extended']+['header_'+str(i)for i in range(16)]+[
            'tail','wrong_seals','typed_pid','native_padding','nonce','parent','cloexec','read_only',
            'write_seal_with_writer','already_sealed','pwrite_sealed','new_shared_writer','read_only_writer',
            'grow','shrink','add_after_seal']
        prefix=dict(events=9,signals=[2,3,1,0,0],group=dict(zip(counter_process.GROUP_NAMES,(5,2,1,4,1,1,2,2,1,0),strict=True)),
            misses=[0,3]+[0]*16,maps={k:0 for k in counter_process.MAP_NAMES},view={k:0 for k in counter_process.VIEW_NAMES},
            native=dict(attempts=101,admissions=5,closed=4,blocked=89,low_address_refusals=7))
        expected=dict(scope='counter_protocol_only',guest_executions=0,parser_prefix=prefix,refusal_count=34,refusals=refusals)
        need(protocol_err==b''and len(refusals)==34 and protocol_out==(json.dumps(expected,sort_keys=True)+'\n').encode(),
             'whole unchanged split-prefix parser and actual memfd protocol oracle')
        r['counter_protocol']=expected
        holder=r['counter_build']={}
        bridge=build_bridge(builder,{'archive':archive},out,pin,binary,r['aliases'],run,holder,original,
            capture=False,retained_counters=True,differential=False)
        rb=holder['release_build']
        need(rb['status']=='passed'and rb['profile']=='persistent-startup-counters-v1'and rb['capture']is False and
             rb['counters']is True and rb['retained_counters']is True and rb['active_domain']['unregistered']is True and
             rb['active_domain']['differential']is False and rb['persistent_binding']['mode']=='counters'and
             rb['counter_schema']==dict(version=2,bytes=752,page=4096,initial_seals=6,final_seals=23),
             'distinct exact release-only startup counter profile and unchanged counter ABI')
        interp,roots,objects,description,images,raws,carrier=prepare_inputs(original,bridge,builder,out,pin,binary,run,holder)
        need(fact(interp)==lane['subject_artifacts']['interpreter']and description==lane['namespace_plan']and
             holder['runtime_libraries']==lane['runtime_libraries'],'same original interpreter and complete dependency namespace')
        enum=pin(ROOT/'tools/page-entry/selected/persistent_group_plan.h').read_text()
        block=re.search(r'enum li2_pg_reason\s*\{(.*?)\};',enum,re.S)
        need(block is not None and re.findall(r'LI2_PGD_([A-Z_]+)',block[1])==list(MISS_NAMES)+['REASON_COUNT'],
             'exact typed counter refusal index names')
        fresh=out/'subject';fresh.mkdir()
        argv=[python,'-B',pin(HERE/'launch_counts.py'),'--root',ROOT,'--role','gated','--mode','2','--control','0',
            '--original',original,'--preparation',fresh/'preparation.json','--library-root',roots[0],
            '--library-root',roots[1],'--carrier',carrier,'--namespace',fresh/'namespace',
            '--counter-fd','{counter_fd}','--counter-nonce','{counter_nonce}']
        row=dict(name='startup-mode2-counters',argv=list(map(str,argv)),environment=dict(ENV),profile='program',
            bounds=TARGET,capture_limit=16<<20,expected_exit=None)
        r['commands'].append(row);r['target']=row
        r.update(bridge=fact(bridge),archive=fact(archive),original=fact(original),carrier=fact(carrier),
            policy_sha256=rb['persistent_binding']['policy_sha256'])
        context=(row,fresh,original,objects,description,carrier,binary,r)
        stable()
        try:stdout,stderr=counter_process.program_invoke(row,out,cpu)
        finally:
            for c in row.get('captures',{}).values():binary(out/c['file'])
            save(out/'receipt.json',r)
        preparation(*context);r['namespace_complete']=True
        observed=row['counter_observation'];need(observed['usable']is True,'actual authoritative post-reap counter prefix')
        counter=row['counter_input'];raw=binary(out/row['captures']['counters']['file'],observed['raw']).read_bytes()
        initial=(counter_process.MAGIC,2,752,4096,counter['nonce'],counter['parent'],counter['device'],counter['inode'])
        exact=counter_process.final_counter_prefix(raw,initial,row['pid'],observed['final_seals'])
        need(all(observed[k]==v for k,v in exact.items()),'whole unchanged parser rejoin to actual retained counter bytes')
        r['counts']=dict(exact,miss_reasons=dict(zip(MISS_NAMES,exact['misses'],strict=True)),subentry_opportunities=None,
            planner_return_successes=None,terminal=None)
        r['status']='observed_unqualified'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        if context and not r['namespace_complete']and row.get('reaped'):
            try:preparation(*context);r['namespace_complete']=True
            except BaseException as exc:r['final_errors'].append('namespace/preparation: '+repr(exc))
        try:
            stable();need(git('rev-parse','HEAD').decode().strip()==a.expect_revision and not git('status','--porcelain','-uno')and
                 all(fact(ROOT/p)==v for p,v in current.items()),'whole committed source unchanged')
            r['source_unchanged']=True
        except BaseException as exc:r['final_errors'].append('source/input closure: '+repr(exc))
        r['target_outcome']=('exit_zero'if row.get('exit')==0 else'failed_prefix')if row and row.get('pid')else'not_run'
        r['cleanup_complete']=bool(r['commands'])and all(c.get('reaped')is True and c.get('cleanup_errors')==[]and
            all(d.get('closed')is True for d in c.get('descriptors',[]))for c in r['commands'])
        for p in sorted(out.rglob('*')):
            if p.is_file()and not p.is_symlink()and p.name!='receipt.json':
                try:binary(p)
                except BaseException as exc:r['final_errors'].append('artifact: '+repr(exc))
        if r['error']or r['final_errors']or not r['source_unchanged']or not r['cleanup_complete']or not r['namespace_complete']:
            r['status']='failed'
        save(out/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
        summary=dict(schema=1,profile=r['profile'],status=r['status'],qualification=False,performance_credit=False,
            source_revision=r['source_revision'],packet=r.get('packet'),origin=r.get('origin'),cpu=cpu,hardware=hw,bounds=r['bounds'],
            target_exit=(row or{}).get('exit'),target_outcome=r['target_outcome'],target_wall_ns=(row or{}).get('process_ns'),
            counts=r.get('counts'),terminal=None,subentry_opportunities=None,bridge=r.get('bridge'),archive=r.get('archive'),
            original=r.get('original'),carrier=r.get('carrier'),policy_sha256=r.get('policy_sha256'),
            source_unchanged=r['source_unchanged'],cleanup_complete=r['cleanup_complete'],namespace_complete=r['namespace_complete'],
            private_receipt=fact(out/'receipt.json'),error_type=r['error'].split(':',1)[0]if r['error']else None,
            final_error_count=len(r['final_errors']),
            reproduce=['cpuset-alloc','run','--cores','1','--','python3','-B',str(Path(__file__).relative_to(ROOT)),
                '--expect-revision',a.expect_revision,'--origin-receipt',str(origin.relative_to(ROOT)),
                '--output','${FRESH_PRIVATE_OUTPUT}'],
            scope='One counter-release run of the same original startup mode2 fixture. Every cell is an incomplete prefix after actual reap. '
                'Publications are published cold certificates, hits are accepted exact-root binds, misses are validated refusal decisions; '
                'cancelled/completed count completed close paths. No cross-cell transaction arithmetic, inferred planner successes, '
                'subentry opportunities, terminal proof, completed-work comparison, qualification or speedup claim.')
        data=(json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
        need(len(data)<=32<<10 and all(x.encode()not in data for x in(str(ROOT),str(Path.home()),'/home/',platform.node())if len(x)>1),
             'small sanitized diagnostic projection')
        (out/'summary.json').write_bytes(data)
        print(json.dumps(dict(status=r['status'],target_exit=(row or{}).get('exit'),output=str(out))))
    return int(r['status']!='observed_unqualified')


if __name__=='__main__':raise SystemExit(main())
