#!/usr/bin/env python3
"""Portable paired maps counters for one unchanged-budget default-rseq ls operation."""
import argparse, hashlib, json, os, platform, re, resource, select, shlex, signal, subprocess, sys, time
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SUPPORT = ROOT/'tools/page-entry/selected/tests/default_ls_cost'
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
import native_pages_compare as compare
from page_selected_fast_memset import body_check
from page_selected_fast_zero_link import headers, compile_retained
from page_selected_rseq_time import hidden_memset
from run import hardware
import shutil
import importlib.util
from checks import source, admission
from page_default_ls_cost_inputs import replay, namespace_plan, native_libraries
def support(name):
    spec=importlib.util.spec_from_file_location('ls_cost_'+name,SUPPORT/(name+'.py'))
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module
progress=support('parse_progress').progress
prepare_runtime=support('prepare').prepare_runtime
BOUNDS = [30, 512 << 20, 16 << 20, 60]
def need(ok, message):
    if not ok: raise ValueError(message)
def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
def unique(pairs):
    result = {}
    for key,value in pairs:
        need(key not in result, 'duplicate JSON key'); result[key] = value
    return result
def decode(raw): return json.loads(raw, object_pairs_hook=unique)
def save(path, data): path.write_text(json.dumps(data, sort_keys=True, separators=(',',':'))+'\n')

def namespace_identity(data):
    return dict(original=data['original'], original_sha256=data['original_sha256'], roots=data['roots'],
        interpreter=data['interpreter'], interpreter_sha256=data['interpreter_sha256'],
        objects=[{k:r[k] for k in ('source','names','needed','size','sha256','seals')}
                 for r in data['objects']])

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def summary(r):
    p=r.get('progress')or{};first=p.get('first');last=p.get('last')
    counters=('chain_steps','rseq_instruction_checks','maps_fresh_calls','maps_acquisitions',
              'maps_reuses','maps_invalidations')
    observed={k:last[k]-first[k]for k in counters}if first and last else None
    hw=r['hardware'];hkeys=('architecture','vendor_id','cpu family','model','stepping','microcode',
                           'kernel_version','kernel_release_sha256')
    return dict(schema=1,scope='private counter diagnostic; real operation outcome retained',
        revision=r['expected_revision'],cpuid_profile=r['cpuid_profile'],bounds=r['bounds'],
        source=r.get('candidate_source'),archive=r.get('retained_archive'),bridge=r.get('bridge'),
        hardware={k:hw[k]for k in hkeys},reserved_cpu_count=1,status=r['status'],
        operation_completed=r['operation_completed'],operation_exit=r.get('operation_exit'),
        wall_timeout=r.get('operation_wall_timeout'),output_equal=r.get('output_equal'),
        commands=len(r['commands']),actual_processes=len({x['pid']for x in r['commands']if type(x.get('pid'))is int and x['pid']>0}),
        completed_processes=sum(type(x.get('pid'))is int and x['pid']>0 and x.get('reaped')is True and type(x.get('exit'))is int for x in r['commands']),
        command_rows_sha256=digest(r['commands']),
        capture_count=sum(len(c.get('captures',{}))for c in r['commands']),
        capture_bytes=sum(v['bytes']for c in r['commands']for v in c.get('captures',{}).values()),
        capture_manifest_sha256=digest([(c.get('name'),c.get('captures',{}))for c in r['commands']]),
        input_manifest_sha256=digest(r.get('inputs',{})),
        artifact_manifest_sha256=digest(r.get('artifacts',{})),alias_manifest_sha256=digest(r.get('aliases',{})),
        prerequisite=r.get('prerequisite_summary'),namespace_sha256=digest(r.get('namespace_identity')),
        native_libraries_sha256=digest(r.get('native_libraries')),
        processes=[{k:c.get(k)for k in ('name','profile','pid','exit','timed_out','reaped','elapsed_ns')}for c in r['commands']],
        reproduce=r.get('reproduce'),
        progress_lines=p.get('lines',0),sampled_returns=p.get('paired_samples',0),
        unreturned_sample=p.get('unreturned_sample',False),observed_counter_growth=observed,
        observed_cpu_ns=last['cpu_ns']-first['cpu_ns']if observed else None,
        observed_wall_ns=last['wall_ns']-first['wall_ns']if observed else None,
        native_wall_ns=r.get('native_wall_ns'),gated_wall_ns=r.get('gated_wall_ns'),
        source_unchanged=r.get('source_unchanged',False),kill_cause_proven=False,
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_errors=len(r['final_errors']))

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--cpuid-nx',action='store_true',help='explicit raw CPUID NX-only diagnostic profile')
    ap.add_argument('--archive-receipt',type=Path,required=True,
        help='full private footprint receipt under target/evaluation/inprocess/RUN/receipt.json')
    ap.add_argument('--library-root',type=Path,default=Path('/usr/lib64'))
    args=ap.parse_args();os.chdir(ROOT)
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision) and
         len(os.sched_getaffinity(0))==1, 'exact revision, checks enabled and one reserved CPU')
    private=args.output.resolve();need(private.is_relative_to(ROOT/'target') and not private.exists(), 'new private output only')
    private.mkdir(parents=True);cpu=next(iter(os.sched_getaffinity(0)))
    public=ROOT/'evaluation/inprocess/results'/(private.name+'.json')
    need(not public.exists(),'new public result')
    pins,aliases,artifacts,pending={},{},{},[private/'namespace/namespace.json',private/'namespace/launch.json'];relevant=[];presence={};roots={};namespace_links={}
    r=dict(schema=1,scope='Private instrumented progress prefix; no production or performance qualification.',
        expected_revision=args.expect_revision,cpu=cpu,bounds=BOUNDS,commands=[],
        status='diagnostic_failed',operation_completed=False,error=None,final_errors=[],progress=None,
        cpuid_profile='nx-only-raw'if args.cpuid_nx else 'legacy-faulted',kill_cause_proven=False,
        timing_scope='existing sampled whole-handler clocks; no stage-duration claim',hardware=hardware(cpu))
    r['reproduce']=['python3','evaluation/inprocess/page_default_ls_cost.py','--expect-revision',args.expect_revision,
        '--archive-receipt','${PASSED_SAME_REVISION_FOOTPRINT_RECEIPT}','--output','${NEW_PRIVATE_OUTPUT}']
    r['reproduce']+=['--library-root','${LIBRARY_ROOT}']
    if args.cpuid_nx:r['reproduce'].append('--cpuid-nx')
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1')
    def pin(path):
        alias=str(Path(path).absolute());p=Path(alias).resolve(strict=True);value=fact(p)
        need(alias not in aliases or aliases[alias]==str(p),'stable lexical alias');aliases[alias]=str(p)
        need(str(p) not in pins or pins[str(p)]==value,'immutable input');pins[str(p)]=value;return p
    def binary(path):
        p=Path(path);need(p.is_file() and not p.is_symlink(),'regular retained output')
        value=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p) not in artifacts or artifacts[str(p)]==value,'immutable artifact');artifacts[str(p)]=value;return p
    def closure():
        if 'prerequisite_configuration'in r:
            config=r['prerequisite_configuration']
            need(admission.cargo_configuration(config['environment'])==config['configuration'],'prerequisite configuration unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in roots.items()),'library root aliases unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in namespace_links.items()),'namespace links unchanged')
        need(all(str(Path(a).resolve(strict=True))==p for a,p in aliases.items()),'input aliases unchanged')
        need(all(fact(p)==v for p,v in pins.items()),'all input bytes unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all artifacts unchanged')
    def prepare():
        os.sched_setaffinity(0,{cpu})
        for key,value in ((resource.RLIMIT_CPU,30),(resource.RLIMIT_AS,512<<20),
                          (resource.RLIMIT_FSIZE,16<<20),(resource.RLIMIT_CORE,0)):
            resource.setrlimit(key,(value,value))
    def run(name,argv,profile='metadata',env=env):
        closure();need(not any(c['name']==name for c in r['commands']),'unique command')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS,exit=None,
                 timed_out=False,reaped=False,cleanup_errors=[],environment=dict(env))
        r['commands'].append(row);p=None;pidfd=None;start=time.monotonic_ns()
        out=private/(name+'.stdout');err=private/(name+'.stderr')
        try:
            with out.open('xb') as of,err.open('xb') as ef:
                p=subprocess.Popen(row['argv'],cwd=ROOT,env=env,stdout=of,stderr=ef,
                                   start_new_session=True,preexec_fn=prepare)
                row['pid']=p.pid;pidfd=os.pidfd_open(p.pid)
                row['timed_out']=not bool(select.select([pidfd],[],[],60)[0])
        finally:
            if p is not None:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except BaseException as exc:row['cleanup_errors'].append('kill: '+repr(exc))
                try:row['exit']=p.wait(timeout=5);row['reaped']=True
                except BaseException as exc:row['cleanup_errors'].append('wait: '+repr(exc))
            if pidfd is not None:
                try:os.close(pidfd)
                except BaseException as exc:row['cleanup_errors'].append('pidfd: '+repr(exc))
            row['elapsed_ns']=time.monotonic_ns()-start
            row['captures']={}
            for key,path in (('stdout',out),('stderr',err)):
                try:row['captures'][key]=dict(fact(path),file=path.name)
                except BaseException as exc:row['cleanup_errors'].append(key+': '+repr(exc))
            for path in (out,err):
                try:
                    if os.path.lexists(path):binary(path)
                except BaseException as exc:row['cleanup_errors'].append('capture custody: '+repr(exc))
            try:save(private/(name+'.json'),row);binary(private/(name+'.json'))
            except BaseException as exc:row['cleanup_errors'].append('command receipt: '+repr(exc))
        need(row['reaped'] and not row['cleanup_errors'],'actual child custody')
        need(all(v['bytes']<=16<<20 for v in row['captures'].values()),'unchanged per-file cap')
        if profile!='native':need(not row['timed_out'] and row['exit']==0,'actual metadata/build exit '+name)
        return row,out.read_bytes(),err.read_bytes()
    def observe_namespace():
        directory=private/'namespace'
        if not directory.exists():return
        path=directory/'namespace.json';binary(path);ns=decode(path.read_bytes())
        need(namespace_identity(ns)==namespace_identity(r['namespace_plan']),'fresh exact namespace plan and contents')
        need(ns['schema_version']==1 and ns['status']=='prepared_not_executed' and
             ns['scope']=='explicit_sealed_dependency_namespace' and
             ns['directory']==str(directory) and ns['search_policy']=='explicit roots; no RPATH/RUNPATH/cache emulation' and
             ns['identity_policy']=='sealed copies and private paths; not filesystem transparency','original namespace policy')
        expected={'namespace.json','launch.json'};fds=[]
        for obj in ns['objects']:
            need(type(obj['fd'])is int and obj['fd']>2 and obj['fd']not in fds,'distinct actual prepared dependency descriptor')
            fds.append(obj['fd'])
            for name in obj['names']:
                path=directory/name;target='/proc/self/fd/'+str(obj['fd'])
                need(path.is_symlink() and os.readlink(path)==target,'actual sealed namespace link')
                namespace_links[str(path)]=target;expected.add(name)
        need({p.name for p in directory.iterdir()}==expected,'complete private namespace entry set')
        launch=directory/'launch.json';binary(launch);v=decode(launch.read_bytes())
        need(v['schema_version']==1 and v['status']=='prepared_not_executed' and v['scope']=='first_entry_loader_candidate' and
             v['carrier_sha256']==fact(private/'ls-carrier')['sha256'] and v['carrier_size']==(private/'ls-carrier').stat().st_size and
             v['argv']==['/bin/ls','-d','.'] and v['dependency_fds']==fds and
             v['environment']==dict(env,LD_LIBRARY_PATH=str(directory),LI2_DEPENDENCY_FDS=','.join(map(str,fds))),
             'actual default-rseq closed launch environment; no optional policy or tunable')
        r['namespace_identity']=namespace_identity(ns)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean invocation revision')
        r['revision']=args.expect_revision;relevant=['tools/page-entry','evaluation/inprocess']
        names=subprocess.check_output(['git','ls-files','-z','--',*relevant]).split(b'\0')
        for name in names:
            if name and not name.startswith(b'evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        r['candidate_source']={str(p.relative_to(ROOT)):fact(pin(p))for p in
            [Path(__file__),Path(__file__).with_name('page_default_ls_cost_inputs.py'),*sorted(SUPPORT.iterdir())]if p.is_file()}
        tools,archive,prerequisite=replay(args.archive_receipt,ROOT,r['source'],pin)
        r['prerequisite_summary']={k:prerequisite[k]for k in ('receipt','archive','commands','result','source')}
        r['retained_archive']=fact(archive)
        r['prerequisite_configuration']={k:prerequisite[k]for k in ('configuration','environment')}
        tools['objdump']=pin(shutil.which('objdump',path=env['PATH']))
        tools['app_python']=tools['python'];need(pin(sys.executable)==tools['python'],'same actual Python tool')
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        for path in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[path]=os.path.lexists(path)
            if presence[path]:pin(path)
        need(not presence['/etc/ld.so.preload'],'no global loader preload')
        roots[str(args.library_root.absolute())]=str(args.library_root.resolve(strict=True))
        namespace,planned=namespace_plan(ROOT,args.library_root,pin)
        r['namespace_plan']=planned
        nx_compare=None
        if args.cpuid_nx:
            path=pin(ROOT/'tools/page-entry/selected/tests/cpuid_nx/reports.py')
            spec=importlib.util.spec_from_file_location('progress_cpuid_nx_reports',path)
            nx_compare=importlib.util.module_from_spec(spec);spec.loader.exec_module(nx_compare)
            for module in tuple(sys.modules.values()):
                p=getattr(module,'__file__',None)
                if p and Path(p).resolve().is_relative_to(ROOT):pin(p)
        adapted=private/'runtime_loader.c';pending.extend((adapted,private/'progress.inc'))
        r['runtime_adapter']=prepare_runtime(pin(ROOT/'tools/page-entry/selected/runtime_loader.c'),adapted,
                                             pin(SUPPORT/'progress.inc'),private/'progress.inc')
        for p in (adapted,private/'progress.inc'):binary(p);pin(p)
        recipe_path='tools/page-entry/selected/build-cpuid-nx.sh'if args.cpuid_nx else 'tools/page-entry/selected/build-native-pages.sh'
        recipe=pin(ROOT/recipe_path).read_text();r['recipe']=dict(path=recipe_path,**fact(ROOT/recipe_path))
        rows=[shlex.split(line) for line in recipe.replace('\\\n',' ').splitlines() if line.startswith('"$cc_bin" ')]
        need(len(rows)==3 and rows[0]==['$cc_bin','--version','>','$output_dir/cc-version.txt'] and '-shared' in rows[1],
             'exact release recipe selection')
        bridge=private/'bridge-native-progress.so'
        values={'$cc_bin':str(tools['cc']),'$parent_dir':str(ROOT/'tools/page-entry'),
                '$source_dir':str(ROOT/'tools/page-entry/selected'),
                '$output_dir/decoder.a':str(archive),
                '$output_dir/'+('bridge-cpuid-nx.so'if args.cpuid_nx else 'bridge-native-pages.so'):str(bridge)}
        argv=[]
        for word in rows[1]:
            for old,new in values.items():word=word.replace(old,new)
            need('$' not in word and '`' not in word,'closed release argument');argv.append(word)
        original=str(ROOT/'tools/page-entry/selected/runtime_loader.c');adapted=str(adapted)
        need(argv.count(original)==1 and argv[-2:]==['-o',str(bridge)] and
             len([x for x in argv if x.endswith(('.c','.S'))])==15,'complete unchanged15-TU release link')
        macros={x for x in argv if x.startswith('-D')}
        expected_macros={'-DLI2_'+x+'=1'for x in('TF_HANDOFF','REGISTER_RUN','MAPS_PHASE_REUSE','RSEQ_INACTIVE','NATIVE_PAGES','FAST_MEMSET','FAST_EQUAL')}
        if args.cpuid_nx:expected_macros.add('-DLI2_CPUID_NX_ONLY=1')
        need(macros==expected_macros and len([x for x in argv if x.startswith('-D')])==len(expected_macros),
             'exact original profile macros plus only explicit CPUID NX selection')
        argv[argv.index(original)]=adapted;r['compile_argv']=argv
        builder=SimpleNamespace(tools=tools,environment=env)
        headers('compiler-dependencies',argv,builder,pin,run,r,required=[Path(adapted),private/'progress.inc'])
        _,out,err=compile_retained('compile',argv,run,binary,builder,pending,r['final_errors'])
        need(not out and not err,'quiet actual release link')
        _,symbols,err=run('memset-symbols',[tools['nm'],'-S','-n',bridge]);need(not err,'nm stderr')
        _,assembly,err=run('memset-body',[tools['objdump'],'-d','--disassemble=memset',bridge]);need(not err,'objdump stderr')
        r['runtime_memset']=body_check(bridge,symbols,assembly,'fast',symbol_name='memset')
        r['hidden_memset']=hidden_memset(bridge,r['runtime_memset']);r['bridge']=fact(bridge)
        carrier=private/'ls-carrier';pending.append(carrier)
        _,out,err=run('carrier',[tools['app_python'],'-B',ROOT/'tools/page-entry/carrier.py','make','/bin/ls',bridge,carrier])
        binary(carrier);need(not err,'carrier stderr');r['carrier']=decode(out)
        need(r['carrier']['original_sha256']==planned['original_sha256'] and
             r['carrier']['interpreter_sha256']==planned['interpreter_sha256'],'actual carrier identities')
        _,listing,lerr=run('native-libraries',[pin(planned['interpreter']),'--list','/bin/ls'])
        need(not lerr,'actual native loader listing stderr')
        r['native_libraries']=native_libraries(namespace,planned,listing,pin)
        native,nout,nerr=run('ls-default-native',['/bin/ls','-d','.'],profile='native')
        need(native['exit']==0 and not native['timed_out'] and not nerr,'actual native baseline')
        gated,gout,gerr=run('ls-default-gated',[tools['app_python'],'-B',ROOT/'tools/page-entry/carrier.py','exec-loader',
            '--library-root',args.library_root,'--namespace',private/'namespace',carrier,
            '/bin/ls','--','/bin/ls','-d','.'],profile='native')
        r['operation_exit']=gated['exit'];r['operation_wall_timeout']=gated['timed_out'];r['output_equal']=nout==gout
        r['native_wall_ns']=native['elapsed_ns'];r['gated_wall_ns']=gated['elapsed_ns']
        r['progress'],terminal=progress(gerr);r['terminal_report_error']=None
        observe_namespace()
        need('namespace_identity'in r,'actual fresh namespace was prepared')
        try:
            if args.cpuid_nx:
                parsed=nx_compare.reports(terminal,True,False);nx_compare.completed(parsed,gated['pid'])
                nx=parsed['cpuid_nx']
                need(nx['status']==nx['failure_code']==0 and nx['hardware_entered']==nx['hardware_returned']==1 and
                     nx['phase']==3 and nx['attempts']==nx['samples']==nx['commits']==parsed['loader']['cpuid']>0 and
                     2<=nx['next_pc']-nx['pc']<=15 and nx['raw']==nx['result'],'actual complete raw NX sample/commit')
            else:
                parsed=compare.reports(terminal);compare.completed(parsed,gated['pid'])
            r['operation_completed']=gated['exit']==0 and not gated['timed_out'] and nout==gout
        except (ValueError,KeyError,TypeError) as exc:r['terminal_report_error']=type(exc).__name__+': '+str(exc)
        need([c['name']for c in r['commands']]==['compiler-dependencies','compile','memset-symbols','memset-body',
             'carrier','native-libraries','ls-default-native','ls-default-gated'],'all eight original-budget commands retained')
        r['status']='diagnostic_operation_completed' if r['operation_completed'] else 'diagnostic_operation_failed'
    except BaseException as exc:
        r['error']=type(exc).__name__+': '+str(exc);r['status']='diagnostic_failed';r['operation_completed']=False
    finally:
        try:
            gated=next((c for c in r['commands']if c['name']=='ls-default-gated'),None)
            if gated is not None:
                r['operation_exit']=gated.get('exit');r['operation_wall_timeout']=gated.get('timed_out')
                r['gated_wall_ns']=gated.get('elapsed_ns')
                capture=private/'ls-default-gated.stderr'
                if r['progress']is None and capture.is_file():r['progress'],_=progress(capture.read_bytes())
        except BaseException as exc:r['final_errors'].append('partial diagnostic observation: '+repr(exc))
        try:observe_namespace()
        except BaseException as exc:r['final_errors'].append('namespace observation: '+repr(exc))
        for path in pending:
            try:
                if os.path.lexists(path):binary(path)
            except BaseException as exc:r['final_errors'].append('partial artifact: '+repr(exc))
        try:
            closure();need(source()==r.get('source'),'complete committed source unchanged');r['source_unchanged']=True
        except BaseException as exc:r['source_unchanged']=False;r['final_errors'].append('closure: '+repr(exc))
        try:need(subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==args.expect_revision,'revision unchanged')
        except BaseException as exc:r['final_errors'].append('revision: '+repr(exc))
        try:
            subprocess.run(['git','diff','--exit-code','HEAD','--',*relevant],check=True,stdout=subprocess.DEVNULL)
        except BaseException as exc:r['final_errors'].append('tracked source: '+repr(exc))
        r['inputs']=pins;r['aliases']=aliases;r['artifacts']=artifacts
        r['configuration_presence']=presence;r['root_aliases']=roots;r['namespace_links']=namespace_links
        if r['final_errors']:r['operation_completed']=False;r['status']='diagnostic_failed'
        save(private/'receipt.json',r)
    value=summary(r);value['private_receipt']=fact(private/'receipt.json')
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<=64<<10 and not any(x and len(x)>1 and x in text for x in
         (str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact private-location-free public diagnostic')
    save(private/'public.json',value);public.parent.mkdir(parents=True,exist_ok=True)
    with public.open('x')as out:out.write(text)
    print(json.dumps(dict(receipt=str(public.relative_to(ROOT)),status=r['status'],operation_exit=r.get('operation_exit')),sort_keys=True))
    return 0 if r['status']=='diagnostic_operation_completed' else 1

if __name__=='__main__':raise SystemExit(main())
