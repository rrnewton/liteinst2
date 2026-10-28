#!/usr/bin/env python3
"""Five fixed native/gated release ls pairs after exact finite qualification.

Process launch-through-reap latency and narrower admission-work intervals are
separate measurements. Neither admission timer covers full first-touch latency
or steady-state native execution. No observer or injected runtime is used.
"""
import argparse, csv, hashlib, json, os, platform, re, resource, select, shlex, signal, statistics, subprocess, sys, time
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SUPPORT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
from run import hardware
import shutil
import importlib.util
from checks import source, admission
from page_default_ls_cost_inputs import namespace_plan, native_libraries
def support(name):
    spec=importlib.util.spec_from_file_location('ls_cost_'+name,SUPPORT/(name+'.py'))
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module
reader=support('page_default_ls_release_reports')
provenance=support('page_default_ls_release_provenance')
BOUNDS = [30, 512 << 20, 16 << 20, 60]
ORDER = tuple((i,lane) for i in range(5) for lane in (('native','gated') if i%2==0 else ('gated','native')))
SAMPLE_NAMES = ['ls-'+str(i)+'-'+lane for i,lane in ORDER]
HARDWARE_KEYS = ('architecture','vendor_id','cpu family','model','stepping','microcode','kernel_version','kernel_release_sha256')
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
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
def decode(raw): return json.loads(raw, object_pairs_hook=unique,parse_constant=lambda x: need(False,'nonfinite JSON constant'))
def save(path, data): path.write_text(json.dumps(data, sort_keys=True, separators=(',',':'))+'\n')

def namespace_identity(data):
    return dict(original=data['original'], original_sha256=data['original_sha256'], roots=data['roots'],
        interpreter=data['interpreter'], interpreter_sha256=data['interpreter_sha256'],
        objects=[{k:r[k] for k in ('source','names','needed','size','sha256','seals')}
                 for r in data['objects']])

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def summary(r):
    need(len(r['samples'])<=10 and [(x['sample'],x['lane'])for x in r['samples']]==list(ORDER[:len(r['samples'])])and
         all(type(x['sample'])is int and type(x['order'])is int and x['order']==i and type(x['accepted'])is bool
             for i,x in enumerate(r['samples'])),'exact typed fixed attempted sample prefix')
    accepted=[]
    for sample in r['samples']:
        if not sample['accepted']:continue
        found=[c for c in r['commands'] if c['name']=='ls-'+str(sample['sample'])+'-'+sample['lane']]
        need(len(found)==1,'one actual command per accepted measurement')
        c=found[0]
        need(type(c.get('pid'))is int and c['pid']>0 and type(c.get('exit'))is int and c['exit']==0 and
             c['reaped']is True and c['timed_out']is False and not c.get('error')and not c['cleanup_errors']and
             type(sample.get('pid'))is int and sample['pid']==c['pid']and type(sample.get('exit'))is int and sample['exit']==0 and
             sample['reaped']is True and sample['timed_out']is False and sample['process_path_ns']==c['process_path_ns']and
             all(type(c[k])is int for k in('process_path_ns','process_reaped_ns','process_start_ns'))and
             c['process_path_ns']==c['process_reaped_ns']-c['process_start_ns']>0,
             'accepted sample joins one real successful reaped invocation and exact executable timing boundaries')
        accepted.append(sample)
    complete=r['status']=='passed' and len(accepted)==10
    if r['status']=='passed':
        need(complete and [(x['sample'],x['lane'])for x in r['samples']]==list(ORDER)and
             [c['name']for c in r['commands']]==['carrier','native-libraries']+SAMPLE_NAMES and
             r['source_unchanged']is True and r['error']is None and not r['final_errors'],
             'fixed complete sample population and final custody before performance credit')
    aggregates=None
    if complete:
        aggregates={}
        for lane in ('native','gated'):
            values=[x['process_path_ns'] for x in r['samples'] if x['lane']==lane]
            need(len(values)==5 and all(type(x)is int and x>0 for x in values),'all five unfiltered process measurements')
            aggregates[lane]=dict(min_ns=min(values),median_ns=int(statistics.median(values)),max_ns=max(values))
    captures=[(c['name'],k,v) for c in r['commands'] for k,v in c.get('captures',{}).items()]
    return dict(schema=1,profile='page-default-ls-release-performance-v1',status=r['status'],
        revision=r['expected_revision'],hardware={k:r['hardware'][k] for k in HARDWARE_KEYS},reserved_cpu_count=1,
        bounds=BOUNDS,planned_pairs=5,actual_subjects=sum(type(c.get('pid'))is int and c['pid']>0 for c in r['commands'] if c['profile']=='native'),
        accepted_subjects=len(accepted),all_samples_accepted=complete,
        samples=r['samples'],process_path_aggregates=aggregates,
        process_interval='Parent monotonic clock immediately before Popen through successful leader reap, including launch/exec, target, gated namespace/carrier and terminal reports. Parent FD queries and custody checks are outside this interval.',
        admission_interval='Existing runtime first successful admission-work and same-page/allocation/generation revisit-work intervals: inside native_admit through verified RX/maps/source checks; exclude fault/handler entry, final registered publication hook, native execution and close. Raw clock queries invalidate maps reuse.',
        limits='Five fixed fresh processes per lane, alternating order; no discarded warmup or failed sample, no cache-cold guarantee. Admission-work is not complete first-touch or steady-state execution latency; no low-overhead or full B2/B3 claim.',
        qualification=(r.get('qualification')or{}).get('receipt'),bridge=r.get('bridge'),archive=(r.get('qualification')or{}).get('archive'),
        source_unchanged=r.get('source_unchanged',False),commands=len(r['commands']),command_rows_sha256=digest(r['commands']),
        capture_count=len(captures),capture_bytes=sum(x['bytes'] for _,_,x in captures),capture_manifest_sha256=digest(captures),
        inputs_sha256=digest(r.get('inputs',{})),artifacts_sha256=digest(r.get('artifacts',{})),
        error_type=r['error'].split(':',1)[0] if r['error'] else None,final_errors=len(r['final_errors']),
        performance_credit=complete,full_b2_complete=False,full_b3_complete=False,reproduce=r['reproduce'])

def qualified(path,sha,current,pin,binary,record):
    """Authenticate the already qualified exact release artifact; do not requalify."""
    import page_selected_rseq_native as registered
    import page_selected_rseq_native_boundary as boundary
    import page_selected_rseq_tcgets_btrfs as queries
    from page_selected_generic_build import package_check,ARTIFACTS,PROFILES
    from page_selected import ENV
    from page_selected_oneshot_build import commands as recipe_commands,UNITS,MACROS
    from page_selected_register_time_build import bridge_check
    path=pin(path);need(fact(path)['sha256']==sha,'explicit finite qualification receipt hash')
    q=decode(path.read_bytes());directory=path.parent
    need(q['profile']=='page-selected-rseq-tiocgwinsz-btrfs-v1' and q['status']=='passed' and
         q['expected_revision']==current['revision'] and q['source']==q['source_after']==current and
         q['source_unchanged']is True and q['error']is None and not q['final_errors'],
         'successful finite qualification at this exact committed source')
    need(q['bounds']==dict(PROFILES,**registered.BOUNDS,**boundary.BOUNDS,**queries.BOUNDS,**queries.WINSZ_BOUNDS),
         'all finite source-defined bounds remain exact')
    hkeys=(*HARDWARE_KEYS,'isa_flags','runner_euid','runner_cap_eff','runner_seccomp_mode')
    need(all(q['hardware'][k]==record['hardware'][k]for k in hkeys),'same actually observed qualified hardware/kernel/process envelope')
    for key in ('inputs','aliases','artifacts'):
        need(q[key+'_before']==q[key+'_after'] and q[key+'_before'],'complete finite final custody '+key)
    need(all(q['inputs_before'].get(p)==v for p,v in record['required_source_inputs'].items()),
         'complete current tracked runtime/evaluator source membership in qualification')
    need(q['configuration_presence']=={p:os.path.lexists(p)for p in('/etc/ld.so.cache','/etc/ld.so.preload')},
         'same actual qualified loader configuration presence')
    for p,want in q['inputs_before'].items():need(fact(pin(p))==want,'actual qualified input')
    for p,target in q['aliases_before'].items():need(str(pin(p))==target,'actual qualified lexical alias')
    for p,want in q['artifacts_before'].items():
        b=binary(pin(p));need(dict(fact(b),mode=b.stat().st_mode&0o777)==want,'actual qualified artifact')
    rows=q['commands'];names=[c['name']for c in rows]
    need(len(names)==len(set(names)) and rows,'unique retained finite command inventory')
    actual={c['name']:c for c in rows}
    def capture(name,stream):
        c=actual[name]['captures'][stream];p=directory/c['file']
        need(c['file']==name+'.'+stream and fact(pin(p))=={k:c[k]for k in('bytes','sha256')},'actual finite capture')
        return p.read_bytes()
    for c in rows:
        need(type(c['pid'])is int and c['pid']>0 and type(c['exit'])is int and
             c['reaped']is True and c['timed_out']is False and not c['error'] and not c['cleanup_errors'] and
             (c['expected_exit']is None or c['exit']==c['expected_exit']) and
             c['bounds']==q['bounds'][c['profile']] and c['capture_limit']==(4096 if c['profile']=='rseq_native_contender'else 16<<20) and
             all(d['closed']is True for d in c['descriptors']), 'actual finite command supervision/outcome')
        observed=c['profile']in('rseq_native','rseq_native_boundary','rseq_tcgets_btrfs','rseq_tiocgwinsz_btrfs')
        need(set(c['captures'])==({'stdout','stderr','record'}if observed else{'stdout','stderr'})and
             (c['descriptors']==[dict(name='record',fd=3,closed=True)]if observed else c['descriptors']==[]),
             'exact source-defined retained record descriptor/capture inventory')
        need(decode(pin(directory/(c['name']+'.json')).read_bytes())==c,'retained finite command row')
        need({'stdout','stderr'}<=set(c['captures'])<= {'stdout','stderr','record','preparation'},'complete finite capture domains')
        for stream in c['captures']:capture(c['name'],stream)
    summaries=dict(registered=registered.summary(q),boundary=boundary.summary(q),tcgets=queries.summary(q),winsz=queries.summary_winsz(q))
    need(all(v['full_finite_profile']is True for v in summaries.values()),'all16+4+20+16+17+1 finite cohorts')
    companions=load('release_companions',ROOT/'tools/page-entry/selected/tests/oneshot_registered/companions.py')
    companion_state={}
    companions.replay(ROOT,{k:Path(v['path'])for k,v in q['companions']['receipts'].items()},current,
        lambda p,want=None: pin(p) if want is None else checked_pin(p,want,pin),binary,companion_state)
    need(companion_state['companions']==q['companions'],'unchanged complete6/49/17 prerequisite replay')
    record['qualified_namespace_aliases']={}
    for key in('companion_namespace_aliases','rseq_native_namespace_aliases','rseq_native_boundary_namespace_aliases','rseq_tcgets_btrfs_namespace_aliases'):
        need(q.get(key),'actual finite dependency namespace rows required')
        record['qualified_namespace_aliases'].update(q[key])
    b=q['build'];need(b['status']=='passed' and b['started']is True and b['command_completed']is True and
         b['configuration_unchanged']is True and not b['final_errors'] and b['registry_before']==b['registry_after'] and
         set(b['artifacts'])==set(ARTIFACTS)|{'generic-observe'},'successful complete retained release Build')
    for package in b['registry_before']:need(package_check(package)==package,'actual immutable archive source package')
    need(admission.cargo_configuration(b['environment'])==b['cargo_configuration'],'actual finite compiler configuration')
    controls={'LI2_CC','LI2_CARGO','LI2_PYTHON','RUSTC','CARGO_TARGET_DIR','CARGO_INCREMENTAL','CARGO_BUILD_JOBS','CARGO_NET_OFFLINE','RUSTFLAGS'}
    optional=set(b['environment'])&{'HOME','CARGO_HOME','RUSTUP_HOME'}
    need(set(b['environment'])==set(ENV)|controls|optional and all(b['environment'][k]==v for k,v in ENV.items())and
         b['environment']['RUSTFLAGS']=='-C relocation-model=pic -C panic=abort -C force-unwind-tables=no'and
         b['environment']['CARGO_INCREMENTAL']=='0'and b['environment']['CARGO_BUILD_JOBS']=='1'and
         b['environment']['CARGO_NET_OFFLINE']=='true'and b['environment']['CARGO_TARGET_DIR']==str(ROOT/'target'),
         'exact closed qualified build environment, no encoded flags override')
    expected_tools={'cc','sh','nm','readelf','git','cp','mkdir','python','rustup','cargo','rustc','cc1','collect2','as','ld'}
    need(set(b['tools'])==expected_tools and set(q['tools'])==expected_tools|{'objdump'},'complete actual finite tool inventory')
    tools={k:pin(v['path'])for k,v in q['tools'].items()}
    need(all(fact(tools[k])=={x:v[x]for x in('bytes','sha256')}for k,v in q['tools'].items()),'actual finite tools')
    need(all(q['tools'][k]==b['tools'][k]for k in expected_tools)and
         all(b['environment'][k]==str(tools[t])for k,t in(('LI2_CC','cc'),('LI2_CARGO','cargo'),('LI2_PYTHON','python'),('RUSTC','rustc'))),
         'actual Build tools and selected compiler identities')
    archive=pin(b['artifacts']['decoder.a']['path']);need(fact(archive)==q['archive'],'same qualified decoder archive')
    decoder={str('tools/page-entry/selected/decoder/src/'+n)for n in
             ('lib.rs','abi.rs','arena.rs','decode.rs','scan.rs','tf.rs','write_footprint.rs','admission_oneshot.rs')}
    need(set(b['dep_info'])==decoder and all(fact(pin(ROOT/k))==v for k,v in b['dep_info'].items()),'complete eight-source decoder binding')
    dep=pin(b['artifacts']['decoder.d']['path']).read_text().strip();prefix=str(ROOT/'target/release/libli2_page_selected_decoder.a')+': '
    need(dep.startswith(prefix)and '\n'not in dep and len(shlex.split(dep[len(prefix):]))==8 and
         set(shlex.split(dep[len(prefix):]))=={str(ROOT/k)for k in decoder},'actual retained decoder archive dep-info')
    state=q['rseq_tiocgwinsz_btrfs_fixture'];name='rseq-tiocgwinsz-btrfs-unobserved'
    builds=[x for x in state['builds']if x['name']==name];need(len(builds)==1,'one actual unobserved release bridge')
    build=builds[0];bridge=binary(pin(build['inspection']['path']));bridge_check(bridge)
    need(bridge==directory/'rseq-tiocgwinsz-btrfs/unobserved.so' and
         fact(bridge)==build['artifact']=={k:build['inspection'][k]for k in('bytes','sha256')} and
         build['archive']==state['archive']==fact(archive),'actual finite release bridge/archive identity')
    selected=ROOT/'tools/page-entry/selected';recipe=pin(selected/'build-rseq-tiocgwinsz-btrfs.sh')
    builder=SimpleNamespace(tools=tools,environment=b['environment'])
    argv=recipe_commands(recipe,builder,bridge.parent,archive,pin)[0];argv[-1]=str(bridge)
    units=[str(selected.parent/p)for p in UNITS[:-1]]
    macros=(MACROS-{'-DLI2_ONESHOT_PUBLICATION=1'})|{'-DLI2_CPUID_NX_ONLY=1','-DLI2_RSEQ_NATIVE=1',
        '-DLI2_RSEQ_NATIVE_BOUNDARY=1','-DLI2_RSEQ_TCGETS_BTRFS=1','-DLI2_RSEQ_TIOCGWINSZ_BTRFS=1'}
    need(build['recipe']==fact(recipe) and build['argv']==argv==actual[name+'-link']['argv'] and
         build['translation_units']==len(units)==15 and [v for v in argv if v.endswith(('.c','.S'))]==units and
         {v for v in argv if v.startswith('-DLI2_')}==macros and sum(v.startswith('-DLI2_')for v in argv)==12 and
         all(v in argv for v in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact unobserved release recipe, no diagnostic or injected observation')
    flags=[v for v in argv[1:-2]if v not in units and v!=str(archive)and not v.startswith('-Wl,')]
    need(actual[name+'-headers']['argv']==[str(tools['cc']),*flags,'-M','-MT','li2_timing',*units] and
         actual[name+'-headers']['environment']==actual[name+'-link']['environment']==b['environment'],
         'actual complete compiler include/link argv and environment')
    rules=capture(name+'-headers','stdout').decode().replace('\\\n',' ').splitlines()
    need(len(rules)==15 and all(v.startswith('li2_timing: ')for v in rules) and
         not capture(name+'-headers','stderr'),'complete actual fifteen-unit compiler include closure')
    included={str(pin(p)):fact(p)for line in rules for p in shlex.split(line.split(': ',1)[1])}
    need(included==build['headers'] and set(units)<=set(included),'every actual conditional header and source')
    need(actual[name+'-undefined']['argv']==[str(tools['nm']),'-u',str(bridge)] and
         not capture(name+'-undefined','stdout') and not capture(name+'-undefined','stderr'),'actual no-import ELF')
    need(actual[name+'-symbols']['argv']==[str(tools['nm']),'-S','--defined-only',str(bridge)] and
         actual[name+'-memset']['argv']==[str(tools['objdump']),'-d','-w','-M','att','--disassemble=memset',str(bridge)] and
         not capture(name+'-symbols','stderr') and not capture(name+'-memset','stderr'),'actual release helper inspection')
    reset=hidden_memset(bridge,body_check(bridge,capture(name+'-symbols','stdout'),capture(name+'-memset','stdout'),'fast',symbol_name='memset'))
    need(reset==build['inspection']['reset'],'same actual qualified release reset body')
    registered.finalize(q);boundary.finalize(q);queries.finalize(q);companions.finalize(q)
    record['qualification']=dict(receipt=fact(path),summaries=summaries,companions=q['companion_summary'],
        bridge=fact(bridge),archive=fact(archive),build=build,commands=len(rows),
        qualification_credit='inherited exact finite receipt, not a new qualification run')
    record['prerequisite_configuration']={k:b[k]for k in('environment','cargo_configuration')}
    return tools,bridge


def checked_pin(path,want,pin):
    p=pin(path);need(fact(p)=={k:want[k]for k in('bytes','sha256')},'exact prerequisite bytes');return p

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--qualification-receipt',type=Path,required=True)
    ap.add_argument('--qualification-sha256',required=True,help='reviewed closed finite receipt SHA256, at this exact revision')
    ap.add_argument('--library-root',type=Path,default=Path('/usr/lib64'))
    args=ap.parse_args();os.chdir(ROOT)
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision) and
         re.fullmatch('[0-9a-f]{64}',args.qualification_sha256) and
         len(os.sched_getaffinity(0))==1, 'exact revision/hash, checks enabled and one reserved CPU')
    private=args.output.resolve();need(private.is_relative_to(ROOT/'target') and not private.exists(), 'new private output only')
    private.mkdir(parents=True);cpu=next(iter(os.sched_getaffinity(0)))
    public=private/'public-projection.json'
    need(not public.exists(),'new public result')
    pins,aliases,artifacts,pending={},{},{},[];relevant=[];presence={};roots={};namespace_links={};namespaces=[]
    r=dict(schema=1,profile='page-default-ls-release-performance-v1',expected_revision=args.expect_revision,
        cpu=cpu,bounds=BOUNDS,commands=[],samples=[],status='failed',error=None,final_errors=[],hardware=hardware(cpu))
    r['reproduce']=['python3','evaluation/inprocess/page_default_ls_release_performance.py','--expect-revision',args.expect_revision,
        '--qualification-receipt','${SAME_REVISION_FINITE_RECEIPT}','--qualification-sha256',args.qualification_sha256,
        '--output','${NEW_PRIVATE_OUTPUT}','--library-root','${LIBRARY_ROOT}']
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
            need(admission.cargo_configuration(config['environment'])==config['cargo_configuration'],'prerequisite configuration unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in r.get('qualified_namespace_aliases',{}).items()),'all qualified namespace aliases unchanged')
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
        closure();need(len(r['commands'])<12 and name not in [c['name']for c in r['commands']] and name==(['carrier','native-libraries']+SAMPLE_NAMES)[len(r['commands'])],'twelve exact ordered bounded commands')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS,exit=None,
                 timed_out=False,reaped=False,cleanup_errors=[],environment=dict(env))
        r['commands'].append(row);p=None;pidfd=None;of=None;ef=None;start=time.monotonic_ns()
        out=private/(name+'.stdout');err=private/(name+'.stderr')
        try:
            of=out.open('xb');ef=err.open('xb')
            if profile=='native':row['stdout_provenance_before']=provenance.observe(of.fileno())
            row['process_start_ns']=time.monotonic_ns()
            p=subprocess.Popen(row['argv'],cwd=ROOT,env=env,stdout=of,stderr=ef,
                               start_new_session=True,preexec_fn=prepare)
            row['pid']=p.pid;pidfd=os.pidfd_open(p.pid)
            row['timed_out']=not bool(select.select([pidfd],[],[],60)[0])
        finally:
            if p is not None:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except BaseException as exc:row['cleanup_errors'].append('kill: '+repr(exc))
                try:
                    row['exit']=p.wait(timeout=5);row['reaped']=True
                    row['process_reaped_ns']=time.monotonic_ns()
                    row['process_path_ns']=row['process_reaped_ns']-row['process_start_ns']
                except BaseException as exc:row['cleanup_errors'].append('wait: '+repr(exc))
            if pidfd is not None:
                try:os.close(pidfd)
                except BaseException as exc:row['cleanup_errors'].append('pidfd: '+repr(exc))
            if of is not None and profile=='native':
                try:
                    row['stdout_provenance_after']=provenance.observe(of.fileno())
                    provenance.same(row['stdout_provenance_before'],row['stdout_provenance_after'])
                except BaseException as exc:row['cleanup_errors'].append('parent descriptor identity: '+repr(exc))
            for key,stream in (('stdout',of),('stderr',ef)):
                if stream is not None:
                    try:stream.close();row[key+'_parent_closed']=stream.closed
                    except BaseException as exc:row['cleanup_errors'].append('parent descriptor close: '+repr(exc))
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
    def observe_namespace(directory):
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
        r.setdefault('namespace_identities',{})[str(directory)]=namespace_identity(ns)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean invocation revision')
        r['revision']=args.expect_revision;relevant=['tools/page-entry','evaluation/inprocess']
        names=subprocess.check_output(['git','ls-files','-z','--',*relevant]).split(b'\0')
        for name in names:
            if name and not name.startswith(b'evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        r['candidate_source']={str(p.relative_to(ROOT)):fact(pin(p))for p in
            sorted(SUPPORT.iterdir())if p.is_file()}
        r['required_source_inputs']={str((ROOT/os.fsdecode(n)).resolve()):fact(ROOT/os.fsdecode(n))for n in names if n and not n.startswith(b'evaluation/inprocess/results/')}
        tools,bridge=qualified(args.qualification_receipt,args.qualification_sha256,r['source'],pin,binary,r)
        r['bridge']=fact(bridge)
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
        original_reports=reader.old_reader(ROOT)
        carrier=private/'ls-carrier';pending.append(carrier)
        _,out,err=run('carrier',[tools['app_python'],'-B',ROOT/'tools/page-entry/carrier.py','make','/bin/ls',bridge,carrier])
        binary(carrier);need(not err,'carrier stderr');r['carrier']=decode(out)
        need(r['carrier']['original_sha256']==planned['original_sha256'] and
             r['carrier']['interpreter_sha256']==planned['interpreter_sha256'],'actual carrier identities')
        _,listing,lerr=run('native-libraries',[pin(planned['interpreter']),'--list','/bin/ls'])
        need(not lerr,'actual native loader listing stderr')
        r['native_libraries']=native_libraries(namespace,planned,listing,pin)
        st=os.fstat(0);r['inherited_stdin']=dict(mode=st.st_mode,device=st.st_dev,inode=st.st_ino,rdev=st.st_rdev)
        outputs={}
        for sample,lane in ORDER:
            name='ls-'+str(sample)+'-'+lane
            row=dict(sample=sample,lane=lane,order=len(r['samples']),accepted=False)
            r['samples'].append(row)
            if lane=='native':argv=['/bin/ls','-d','.']
            else:
                directory=private/('namespace-'+str(sample));namespaces.append(directory)
                pending.extend([directory/'namespace.json',directory/'launch.json'])
                argv=[tools['app_python'],'-B',ROOT/'tools/page-entry/carrier.py','exec-loader',
                    '--library-root',args.library_root,'--namespace',directory,carrier,'/bin/ls','--','/bin/ls','-d','.']
            command,out,err=run(name,argv,profile='native')
            row.update(pid=command['pid'],exit=command['exit'],timed_out=command['timed_out'],reaped=command['reaped'],
                       process_path_ns=command['process_path_ns'],stdout_bytes=len(out),stdout_sha256=hashlib.sha256(out).hexdigest())
            need(command['exit']==0 and not command['timed_out'] and out==b'.\n','actual complete ls result and exact original output')
            outputs[sample,lane]=out
            if lane=='native':need(not err,'native stderr empty')
            else:
                observe_namespace(directory)
                gate,reports,observed=reader.check(err,command['pid'],command['exit'],command['stdout_provenance_before'],original_reports)
                need(observed['application_completed']is True,'unchanged full old completion and actual two-request ENOTTY proof')
                n=reports['native']
                row.update(admissions=n['admissions'],closed=n['closed'],first_admission_work_ns=n['first_admission_ns'],
                    revisit_work_ns=n['revisit_ns'],revisit_count=n['revisit_count'],
                    tcgets_result_validations=observed['tcgets_result_validations'],tiocgwinsz_result_validations=observed['tiocgwinsz_result_validations'])
                r.setdefault('terminal_reports',{})[name]=reports
                r.setdefault('query_reports',{})[name]=gate
                need(type(row['first_admission_work_ns'])is int and row['first_admission_work_ns']>0 and
                     row['revisit_count']==len(row['revisit_work_ns'])<=16 and
                     all(type(v)is int and v>0 for v in row['revisit_work_ns']),'actual bounded production admission-work samples')
            if (sample,'native')in outputs and(sample,'gated')in outputs:
                need(outputs[sample,'native']==outputs[sample,'gated'],'full unmodified native/gated output comparator')
            row['accepted']=True
        need([c['name']for c in r['commands']]==['carrier','native-libraries']+SAMPLE_NAMES and
             len(r['samples'])==10 and all(x['accepted']for x in r['samples']),'all fixed samples accepted; no filtering or skips')
        r['status']='passed'
    except BaseException as exc:
        r['error']=type(exc).__name__+': '+str(exc);r['status']='failed'
    finally:
        for row in r['samples']:
            command=next((c for c in r['commands']if c['name']=='ls-'+str(row['sample'])+'-'+row['lane']),None)
            if command is not None:
                row.update({k:command.get(k)for k in('pid','exit','timed_out','reaped','process_path_ns')})
        for directory in namespaces:
            try:observe_namespace(directory)
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
        if r['final_errors']:r['status']='failed'
        save(private/'receipt.json',r)
    value=summary(r);value['private_receipt']=fact(private/'receipt.json')
    columns=('sample','order','lane','pid','exit','timed_out','reaped','accepted','process_path_ns','admissions','closed','first_admission_work_ns','revisit_count')
    with (private/'samples.csv').open('x',newline='')as stream:
        writer=csv.DictWriter(stream,fieldnames=columns);writer.writeheader()
        writer.writerows({k:row.get(k)for k in columns}for row in r['samples'])
    value['samples_csv']=fact(private/'samples.csv')
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<=64<<10 and not any(x and len(x)>1 and x in text for x in
         (str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact private-location-free release measurement')
    save(private/'public.json',value);public.parent.mkdir(parents=True,exist_ok=True)
    with public.open('x')as out:out.write(text)
    print(json.dumps(dict(receipt=str(public.relative_to(ROOT)),status=r['status'],accepted_subjects=value['accepted_subjects']),sort_keys=True))
    return 0 if r['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
